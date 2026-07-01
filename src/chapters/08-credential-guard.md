# Credential Guard

::: trust-ledger

- **Inherits:** VTL1 isolation. A secure world whose pages no VTL0 token can map, enforced by the hypervisor's SLAT (Chapter 6, The Secure Kernel); and HVCI's separate signature / W^X gate for VTL0 kernel-mode code (Chapter 8, Code Integrity).
- **Promise:** An attacker with SYSTEM and `SeDebugPrivilege` in VTL0 cannot read a signed-in user's protected credential material (the NTLM hash, Kerberos long-term key, and Kerberos TGT) because that material is held by `LsaIso.exe`, reachable solely across the serviced VTL0→VTL1 boundary.
- **TCB:** The hypervisor, the Secure Kernel, and the `LsaIso.exe` trustlet (VTL1). The NT kernel the attacker can own is explicitly *outside* it.
- **Adversary → Break:** Pass-the-Challenge. An attacker who owns `lsass.exe` cannot read the key, but can ask the trustlet to *use* it and harvest the derived NTLM response. Separately, Kerberos service tickets minted for the session remain outside Credential Guard's storage promise. The Promise ends at *storage*, not *use*.
- **Residual:** Service-ticket replay → Kerberos (Chapter 17) and KRBTGT (Chapter 18); token / Potato escalation → Windows Access Control (Chapter 22) and The SeImpersonate Primitive (Chapter 24); cloud bearer-token theft → Zero Trust (Chapter 26) and Continuous Access Evaluation (Chapter 27).
- **Bequeaths:** "Long-term secrets are out of VTL0 reach". The signed-in NTLM hash, Kerberos long-term key, and TGT can no longer be read from any VTL0 process, the floor that the Death of NTLM chapter (Chapter 16) builds on. Does NOT provide: service-ticket isolation, token binding, or protection for anything outside the endpoint trustlet boundary (generic Credential Manager entries, the domain-controller `NTDS.dit`, typed plaintext).
- **Proof:** 🟢 `deviceguard.txt`, 🟢 `lsass-ssp.txt`. Live lab VM, hash-gated at the point of claim; 🔵 documented for the trustlet internals (Microsoft Learn, Lyak, Ionescu).
:::

> **The Reasoner's question.** After Credential Guard, what can an attacker who owns this machine no longer get, and what can they still get anyway?

---

> **Foundations: what you need before this chapter.**
>
> - **VTL0 / VTL1.** Virtualization-Based Security splits the machine into two
> *Virtual Trust Levels*. VTL0 is the "normal world" where Windows, your shell,
> and your malware all run. VTL1 is the "secure world", a second, smaller
> kernel the hypervisor isolates from VTL0 with hardware page-table permissions
> (SLAT). VTL0 cannot map VTL1's memory, *regardless of privilege*.
> - **Trustlet.** A binary signed at Signature Level 12 carrying two Microsoft
> Extended Key Usages: a Windows System Component Verification EKU
> (`1.3.6.1.4.1.311.10.3.6`) and an Isolated User Mode EKU
> (`1.3.6.1.4.1.311.10.3.37`) that no commercial CA can issue. The Secure
> Kernel loads it into VTL1 at boot. `LsaIso.exe` is Trustlet ID 1. The dual-EKU
> gate is what stops an attacker dropping a counterfeit `LsaIso.exe`.
> - **NTOWF.** The "NT One-Way Function", the MD4 of the user's password, a.k.a.
> the NTLM hash. Possessing it lets you authenticate *as* the user without the
> password (Pass-the-Hash).
> - **Long-term key vs. session key.** A user's *long-term* Kerberos key (derived
> from the password) authenticates to the KDC. Each ticket request returns a
> *service ticket* carrying a fresh session key, which the agent must hold to
> put on the wire. Credential Guard isolates the former and, as we will see,
> *not* the latter.
> - **SSP / `lsass.exe`.** The Local Security Authority Subsystem hosts the
> Security Support Providers (NTLM, Kerberos, `cloudap`, Schannel…) that speak
> authentication protocols. Historically it also *held the keys* those protocols
> consume, which is why dumping `lsass.exe` was the canonical credential theft.

---

## The 3:14 a.m. Mimikatz that returned an empty hash

It is 3:14 a.m. on a 2026 Windows 11 24H2 box. The operator has SYSTEM and `SeDebugPrivilege`. The operator has bypassed Protected Process Light the way PPLdump [449] did in 2021, has dumped `lsass.exe` with `sekurlsa::logonpasswords` from Mimikatz [261], and is staring at the screen.

For the seven years before mid-2015, the next line on that screen would have been the user's NTLM hash. Tonight, the next line is something else entirely.

> 🔵 **DOCUMENTED**: *schematic* Pypykatz output on a Credential-Guard-on box;
> field names per the PassTheChallenge README · not captured on our lab VM

```text
[LSA Isolated Data]
    NtlmHash
      Is NT Present : True
      Context Handle: 0x0000000000c8...     # opaque per-logon trustlet reference
      Proxy Info    : <pointer into lsass-side session state>
      Encrypted blob: a000000000000000 0800000064000000 ...   # AES-GCM, key only in VTL1
      DPAPI         : <16-byte GUID prefix + wrapped blob>     # ties the record to the per-user DPAPI chain
```

This schematic block is structurally identical to the PassTheChallenge README [667] example, with identity details removed. Hex prefix, field names, and embedded `NtlmHash` ASCII tag are the artifact that tells the operator the architectural shift happened.

The literal string `[LSA Isolated Data]` sits where the NTLM hash used to sit. In the PassTheChallenge README example, the protected record begins with the recognizable prefix `a000000000000000`, and the visible ASCII tag `4e746c6d48617368` decodes to `NtlmHash`: serialized metadata survives, the value does not.

This is the deep look at the canonical VBS trustlet responsible for that empty hash. The VBS Trustlets chapter (Chapter 7) uses `LsaIso.exe` as its running example; this chapter unfolds the things that matter most about it: the extraction history that motivated the design; what `LsaIso.exe` actually computes and what every field of the encrypted blob means; Pass-the-Challenge, the residual class Credential Guard was never going to close; and the honest, Microsoft-documented limits [311], enumerated.

A note on intent and verification: this is defensive research. Every primary source was verified live on 2026-05-11, against the public web; every command and tool named is in the open-source security canon, used today by Microsoft's own product teams, by enterprise red teams, and by every blue team that takes the storage-versus-use distinction seriously.

The hash is not in the dump because the hash is no longer in the process. Where it went, and why Microsoft moved it, is thirty-three years of `lsass.exe` history.

## Why LSASS became the single highest-value memory dump on Windows (1993 to 2014)

Thirty-three years before the empty hash, `lsass.exe` shipped in Windows NT 3.1. It was not, at first, the most-attacked process on Windows. It became that, slowly, over the course of a public tool lineage and one architectural realization. This is the tradition the trustlet was built to break.

> **Definition: lsass.exe (Local Security Authority Subsystem Service).** The user-mode Windows service that handles interactive logon, NTLM challenge-response, Kerberos AS/TGS exchanges, security-policy enforcement, password changes, and the loading of every Security Support Provider DLL the system uses for authentication. Until Credential Guard, it also held every long-lived authentication secret for every signed-in user in its own process memory, because the protocols it implemented required the secret to be present when the network talked to it. See the canonical LSA Authentication [668] reference.

The architectural reason `lsass.exe` had to hold the secret is structural to the protocols it speaks. NTLM and Kerberos are challenge-response protocols: the client proves possession of a value *derived* from the password every time it authenticates: the NTOWF (the MD4 of the UTF-16-LE password) for NTLM, or a long-term key for Kerberos. With respect to the network, that derived value *is* the credential. How the response is computed, and why holding the NTOWF is equivalent to holding the password (Pass-the-Hash), is developed in The Death of NTLM chapter (Chapter 16). What matters here is the consequence: for single-sign-on to work (the user types the password once, the OS uses it transparently for every later authentication that day) something has to remember that derived value, in clear, in a process that wakes up whenever a remote service asks the kernel to authenticate. That something is `lsass.exe`. Until 2015, "remembers" meant "holds the bytes in process memory."

## The eleven-year road from hash to LSASS dump

The path from "the hash is the password" to "dump it from `lsass.exe`" took eleven years, and it is told in full elsewhere: the Pass-the-Hash framing in The Death of NTLM chapter (Chapter 16), and the tool lineage (Pass-the-Hash Toolkit, Windows Credential Editor, Mimikatz) in the Mimikatz chapter (Chapter 14). Only the beats that forced the architecture matter here. In 1997 Paul Ashton showed that a client proving possession of the hash makes the hash the credential [666]. In 2008 Hernan Ochoa's Pass-the-Hash Toolkit [669] turned "dump the hash from `lsass.exe` memory" into a public, repeatable post-exploitation primitive: no cracking, just `OpenProcess(VM_READ)` on `lsass.exe` and a parser. From 2011 Mimikatz [617] industrialized the trail, and its `sekurlsa::logonpasswords` added plaintext recovery from WDigest: a digest SSP that kept the encrypted password and its encryption key in `lsass.exe` memory at once so it could answer challenges on demand.

> **Quoted source.** It's like storing a password-protected secret in an email with the password in the same email. (Benjamin Delpy, on the WDigest plaintext-cache architecture)

On April 6, 2014, at 22:02:03, Delpy committed Mimikatz 2.0 to GitHub as open source [261]; the compile timestamp is in the README banner, verbatim, and Microsoft's lead time on every WDigest-class disclosure dropped from "months" to "the next minute any attacker reads the README." On May 13, 2014, KB2871997 [670] shipped: on Windows 8.1 and Server 2012 R2 and later, the registry value `WDigest\UseLogonCredential` defaults to `0` and WDigest no longer caches plaintext credentials in `lsass.exe` memory. The plaintext leg closed. The hash leg could not, because the protocol required it.

![Figure: The LSASS extraction lineage that motivated Credential Guard: from Ashton's 1997 Pass-the-Hash proof through Mimikatz to KB2871997 (1997–2014). Full tool mechanics belong to Chapter 14.](diagrams/08-credential-guard-extraction-timeline.svg)

By May 2014, Microsoft had patched what could be patched. Mimikatz 2.0 was on GitHub. The hash was still in the process, because it had to be. The next move had to be architectural. But before Microsoft made that move, they tried four other things.

## What Microsoft tried before trustlets (1993 to 2014)

If you cannot move the secret, what can you do? Microsoft tried four answers between 1997 and 2014. Each is in production today. None of them moves the secret.

## Generation 0: LSASS as an ordinary NT process (1993)

The baseline generation was no protection at all: `lsass.exe` ran as an ordinary user-mode system process, and the NT kernel that an administrator or driver could control owned the address space holding the credentials.

## Generation 1: SYSKEY and on-disk hardening (1997)

SYSKEY moved part of the SAM protection story into boot-time key material, hardening at-rest password-verifier storage without changing the live-session fact that `lsass.exe` still had to hold usable secrets in memory.

## Generation 2: Vista's Protected Process (2007)

In Windows Vista, Microsoft introduced the Protected Process [671] primitive: a binary signed under a designated Microsoft media-protection certificate could run in a process whose memory other Windows processes, including processes running as administrator, could not read or modify. The reason was DRM. Audio and video pipelines wanted a way to keep AACS and PlayReady decryption keys out of debuggers. The Protected Process primitive was not, in 2007, applied to `lsass.exe`. Six years passed before Microsoft generalized it.

## Generation 3: LSA Protection / `RunAsPPL` (2013)

In Windows 8.1, Microsoft generalized Protected Process into Protected Process Light (PPL) [328], a signer-level lattice that allowed multiple signer "kinds" to live alongside the original DRM kind, and the `RunAsPPL` registry value lit up `lsass.exe` as a PPL (the Protected Process Light chapter, Chapter 10, develops the primitive in full).

> **Definition: Protected Process Light (PPL).** A Windows process that runs at a signer-level higher than ordinary administrator processes, such that ordinary administrators cannot open it for memory read or for code injection. Created in Windows 8.1 as a generalization of the Vista Protected Process primitive. Enforcement is done by the NT kernel: `OpenProcess` with `PROCESS_VM_READ` from a non-PPL caller returns `ERROR_ACCESS_DENIED` (0x5) [328] regardless of the caller's token privileges.

itm4n's reference write-up of `RunAsPPL` [328] reproduces what Mimikatz sees on a PPL-protected `lsass.exe`: the call to `OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, lsass_pid)`, the verbatim opener of `kuhl_m_sekurlsa_acquireLSA()`, fails with `0x00000005`, `ERROR_ACCESS_DENIED`. The hash extraction routine never runs, because the attacker cannot read the page.

itm4n's writeup is also the canonical source for what `RunAsPPL` is *not*. The same NT kernel that enforces PPL is the kernel the attacker is trying to subvert. Two bypass classes exist in the public record. The first is kernel-mode: an attacker who loads a signed driver, including Delpy's own `mimidrv.sys` [328], can suspend PPL enforcement from kernel-space because the kernel is the enforcement mechanism. This is the *bring your own vulnerable driver* bypass class.

> **Definition: BYOVD (Bring-Your-Own-Vulnerable-Driver).** A privilege-escalation pattern in which an attacker with administrator privilege loads a signed-but-vulnerable third-party driver, then exploits a known vulnerability in the driver to run arbitrary code at kernel mode. Because the driver is signed, the kernel loads it; because the kernel loaded the driver, the driver can disable any defense the kernel enforces, including PPL. Microsoft's recommended vulnerable-driver block-list shrinks the BYOVD inventory; it does not eliminate the class. Delpy's own `mimidrv.sys` is the canonical reference exploit driver [328] for this class against `lsass.exe`.

The second is userland: itm4n's PPLdump (April 2021) [449] exploited a structural weakness in the PPL section-validation logic. A new Windows process loads NTDLL, then asks the image loader to load other DLLs. PPLs are allowed to load DLLs from the `\KnownDlls` directory, and the digital signature of a `\KnownDlls` entry is checked when the section is created, not when it is mapped into the address space of a PPL process. PPLdump used `DefineDosDevice` to swap the symbolic link of a `\KnownDlls` entry; a freshly spawned PPL process (launched from a Microsoft-signed image permitted to run as a PPL) then mapped the swapped-in attacker DLL into its own address space, giving the attacker code execution inside a PPL, which could in turn open and read `lsass.exe` with PPL enforcement nominally intact. The SCRT writeup [434] is the canonical 2021 reference. Microsoft closed the userland weakness in build 19044.1826, the July 2022 update [331], with an `LdrpInitializeProcess` patch in NTDLL gated by a `Feature_Servicing_2206c_38427506__private_IsEnabled` feature flag. On Windows 8.1 and Server 2012 R2, PPLdump's behavior is unstable per the project README [449]: itm4n notes the exploit fails on fully updated machines for an unidentified earlier patch. The userland weakness is therefore closed across the modern estate; legacy boxes that have lapsed on cumulative updates remain the practical exposure.

> **Aside.** itm4n is explicit about the architectural framing: LSA Protection is "a true quick win [328]" because attackers "will have to use some relatively advanced tricks if they want to work around it, which ultimately increases their chance of being detected." But in the same post: "[LSA Protection] tends to be confused with [Credential Guard], which is completely different... Credential Guard and LSA Protection are actually complementary." That confusion is the most common architectural error in defensive-security reviews of Windows endpoints.

## Generation 4: KB2871997 + the compensating-control playbook (2014)

KB2871997 [670] shipped on May 13, 2014 and rolled up three behavioral changes: WDigest cache disabled by default in Windows 8.1 / Server 2012 R2 and later (`UseLogonCredential = 0`); the `TokenLeakDetectDelaySecs` registry default; and Restricted Admin mode for Remote Desktop Connection on Windows 7 / Server 2008 R2. The same broader 2013 to 2014 credential-protection initiative also delivered the Protected Users group [672] (an Active Directory feature shipped in Windows 8.1 [673] / Server 2012 R2 [674], October 2013). Protected Users is the device-side mitigation: members cannot use credential delegation (CredSSP), Windows Digest, NTLM cached credentials or NTOWFs, DES or RC4 in Kerberos preauthentication, or offline cached verifiers; their TGT lifetime is capped at four hours. That AES-only behavior belongs to Protected Users, not to Credential Guard by itself.

> **Aside: Compliance note.** Protected Users membership requires AES-only Kerberos. Estates with legacy applications that rely on RC4 service tickets cannot enable Protected Users broadly without modernizing their Kerberos client and server inventory. In practice, that compatibility work is one reason many enterprises deploy Protected Users selectively rather than universally.

## Generation 4.5: Tier 0 isolation, jump-server architecture, AdminSDHolder hygiene

The *Mitigating Pass-the-Hash* v1 (2012) and v2 (2014) playbooks [619] layered organizational changes on top of the per-host technical changes: tier the administrative model so that Tier 0 credentials never log on to Tier 1 or Tier 2 hosts; require every Tier 0 administrative session to traverse a dedicated jump server; clean up AdminSDHolder so that orphaned high-privilege accounts cannot be re-used. The playbooks are still cited in 2026 deployment guides because the underlying recommendations remain correct.

![Figure: The defensive generation chain. Generations 0–4 all share one TCB (the NT kernel the attacker is trying to subvert) so each is bypassed in turn; Generation 5 (Credential Guard) is the only one that changes the TCB.](diagrams/08-credential-guard-generation-chain.svg)

> **Key idea.** As long as the secret lives in a process whose address space is governed by the same NT kernel that the attacker can compromise, the secret is extractable. Generations 0 to 4 add layers inside the NT-kernel TCB. The 2014 conclusion, that you cannot patch your way out of the storage problem, is structural to that TCB argument; the chain Gen 0 → Gen 4 above traces it explicitly.

Each of these layers shrinks the attack surface. None of them changes where the hash physically lives. The 2014 conclusion was unavoidable: the only fix is to move the hash out of the kernel that the attacker can compromise. So Microsoft did.

## Credential Guard lands, then hardens, then defaults on (May 2015 to November 2024)

On May 4, 2015, Brad Anderson stood at Microsoft Ignite [276] and said *"more than 75 percent of all these attacks come down to weak credentials or compromised identities."* Eighty-six days later, Windows 10 Enterprise RTM shipped with `LsaIso.exe` running in VTL1.

> **Aside.** The 75-percent figure is the verbatim Anderson keynote quote and tracks Microsoft's own internal incident-response telemetry from the 2014 to 2015 period. The keynote explicitly demonstrates Device Guard at length; the *Credential Guard* announcement at the same event is corroborated by ITPro Today's same-day recap (Wayback snapshot) [675] and Microsoft's own subsequent blog posts.

## The 2015–2024 chronology

On May 4, 2015, the Anderson Ignite keynote announced Virtualization-Based Security, Device Guard, and Credential Guard alongside the Hello and Microsoft Passport identity story. On July 29, 2015, Windows 10 RTM [87] shipped with `LsaIso.exe` as Trustlet ID 1 on Enterprise and Education SKUs. On August 5 and 6, 2015, Alex Ionescu reverse-engineered the trustlet model at Black Hat USA and published the slide deck [671] that documents the dual-EKU + Signature Level 12 constraint and names `LSAISO.EXE` as Trustlet ID 1 verbatim.

From 2016 to 2020, Server 2016 brought Credential Guard to server installs [676], and the VSM master key + TPM 2.0 binding [311] hardened the persistent-state path.

On September 20, 2022, Windows 11 22H2 became generally available with Credential Guard default-on for eligible, domain-joined, non-DC devices in supported editions [87], shipped without UEFI Lock. On December 26, 2022, Oliver Lyak published Pass-the-Challenge [677]: the trustlet itself was faithful, but its RPC output became the new attack surface. On November 1, 2024, Windows Server 2025 became generally available [678] and extended the default-on stance to eligible domain-joined servers with the same domain-controller carve-out: "Enabling Credential Guard on domain controllers isn't recommended. Credential Guard doesn't provide any added security to domain controllers, and can cause application compatibility issues on domain controllers." [87]

> **Definition: Trustlet.** A binary signed at Signature Level 12 with both the Windows System Component Verification EKU (1.3.6.1.4.1.311.10.3.6) and the Isolated User Mode EKU (1.3.6.1.4.1.311.10.3.37), exporting an `s_IumPolicyMetadata` structure from a `.tpolicy` PE section, loaded by the Secure Kernel into VTL1 user mode at boot via `NtCreateUserProcess` with the `PsAttributeSecureProcess` attribute. Documented verbatim in Alex Ionescu's Black Hat USA 2015 deck [671], which is still the load-bearing reverse-engineering primary on the trustlet model.

> **Definition: VTL0 / VTL1 (Virtual Trust Levels).** Two privilege levels enforced by the Hyper-V hypervisor on top of the host CPU's existing ring 0 / ring 3 split. VTL0 is the Normal World: Ring 3 user mode and Ring 0 NT kernel mode. VTL1 is the Secure World: Ring 3 user mode runs trustlets like `LsaIso.exe`, Ring 0 runs the Secure Kernel (`securekernel.exe`). The hypervisor uses Second-Level Address Translation (SLAT) to ensure VTL0 page tables cannot map physical pages that VTL1 has marked private. The Hypervisor TLFS Virtual Secure Mode reference [322] defines `#define HV_NUM_VTLS 2` and notes that "Architecturally, up to 16 levels of VTLs are supported; however a hypervisor may choose to implement fewer than 16 VTLs. Currently, only two VTLs are implemented."

> **Definition: IUM (Isolated User Mode).** The Ring-3 user mode component of VTL1. IUM hosts trustlets (signed user-mode binaries) that the Secure Kernel loads at boot. IUM processes have no device drivers, no third-party modules, and no normal-world IPC except via the explicitly-marshalled secure-call interface that the Secure Kernel mediates. Quarkslab's IUM debugging walkthrough [312] names "the isolated version of LSASS (`LSAIso.exe`) when Credential Guard is enabled" as the canonical IUM example.

> **Aside.** The four shipping trustlets per Ionescu's 2015 reverse-engineering [671]: Trustlet ID 0 is the Secure Kernel Process (Device Guard); Trustlet ID 1 is `LSAISO.EXE` (Credential Guard); Trustlet ID 2 is `vmsp.exe` (Virtual Secure Mode provisioning / vTPM worker); Trustlet ID 3 is the vTPM provisioning trustlet. In the public reverse-engineering and documentation cited here, that list remains the relevant Credential Guard-era set, with ID 1 still the most-discussed.

On eligible domain-joined Windows 11 22H2+ Enterprise/Education devices where the feature has not been explicitly disabled, `LsaIso.exe` is the default state today [87]. What that small binary actually is, what it computes, and what an attacker who has SYSTEM on the box now sees is the load-bearing technical question.

## What `LsaIso.exe` actually is

The trustlet is a small binary that sits inside a separate kernel from the one your shell is running under. Its identity is precise, its API is small, and its memory is unreadable from the side of the boundary you are on. Microsoft's documentation gives the one-sentence shape:

> **Quoted source.** With Credential Guard enabled, the LSA process in the operating system talks to a component called the isolated LSA process that stores and protects those secrets, LSAIso.exe. Data stored by the isolated LSA process is protected using VBS and isn't accessible to the rest of the operating system. (Microsoft Learn, *How Credential Guard works* [311])

That one sentence hides everything interesting.

## Identity in the trustlet model

`LsaIso.exe` passes the five-gate trustlet definition [671] by construction: Trustlet ID 1; signed at Signature Level 12; carries both the Windows System Component Verification EKU (1.3.6.1.4.1.311.10.3.6) and the Isolated User Mode EKU (1.3.6.1.4.1.311.10.3.37); exports the `s_IumPolicyMetadata` structure from a `.tpolicy` PE section; and is loaded by SMSS / wininit at boot through `NtCreateUserProcess` with the `PsAttributeSecureProcess` attribute, which routes through the Secure Kernel (Chapter 6) rather than the NT kernel.

> **Definition: Authenticode EKU.** An Extended Key Usage object identifier embedded in an Authenticode signature that constrains what the signed binary is allowed to do. The Windows kernel and Secure Kernel inspect EKUs at load time. The dual-EKU requirement on trustlets means a signature legitimate for ordinary kernel-mode driver loading is *not* sufficient to load a binary as a trustlet; both the WSCV and the IUM EKU must be present, both signed by Microsoft.

The two EKUs together are the identity gate. A binary that has only the WSCV EKU is a normal Microsoft-signed component.

> **Note.** The IUM EKU is not a publicly issuable Authenticode EKU; only Microsoft can mint it, per the Trustlet identity model documented verbatim in Ionescu's Black Hat USA 2015 deck [671].
 A binary that has only the IUM EKU does not exist in the wild. A binary that has both, and is signed by Microsoft, is admissible as a trustlet. The IUM EKU is not issued by any commercial CA; it is a Microsoft-internal OID with a Microsoft-internal issuance policy.

That identity check is not a decorative signature policy. It is the load contract that decides whether the process is created as an ordinary user-mode process under the NT kernel or as a secure process whose execution belongs to the isolated user-mode world. `PsAttributeSecureProcess` is the visible process-creation switch: SMSS / wininit asks for a secure process, the Secure Kernel participates in the create path, and the `.tpolicy` metadata tells the secure side what the trustlet is allowed to be. The trustlet ID is therefore not discovered by scanning `lsass.exe`; it is established at boot by a signed image, a policy section, and a secure-process attribute that ordinary administrators cannot mint.

The practical consequence for an attacker is subtle but important. Replacing `LsaIso.exe` is not analogous to dropping a new SSP DLL into `lsass.exe`, because the replacement would need Microsoft's IUM EKU and policy metadata to be admitted as a trustlet. Debugging it is not analogous to attaching WinDbg to a normal service, because the pages and scheduler state live behind the Secure Kernel. PPL can be bypassed by attacking code-signing policy or kernel callbacks inside VTL0; the trustlet identity path moves the admission decision into the VTL1 loader. That is why the chapter keeps separating PPL from Credential Guard: PPL hardens an NT process; Credential Guard changes which kernel owns the secret-bearing process.

## The agent / trustlet split

Credential Guard splits `lsass.exe` (the historical agent) into two cooperating processes:

- **`lsass.exe` in VTL0** holds protocol state, network I/O, and every Security Support Provider DLL the system loads: `msv1_0.dll` (NTLM), `kerberos.dll` (Kerberos), `negoexts.dll` (SPNEGO extensions), `cloudap.dll` (the Microsoft Entra cloud authentication package), `wdigest.dll` (Digest, with caching disabled), `tspkg.dll` (Terminal Services / CredSSP), `livessp.dll` (Microsoft account / Live), `pku2u.dll` (peer-to-peer Kerberos), and `schannel.dll` (TLS). The core SSP/AP set (Negotiate, Kerberos, NTLM, Digest, CredSSP, Schannel) is enumerated in Microsoft's SSP Packages Provided by Microsoft [679] reference; CloudAP, NegoExts, TSPkg, LiveSSP, and PKU2U are documented under the broader LSA Authentication [668] reference. `lsass.exe` does *not* hold the long-lived NTOWF or Kerberos long-term keys.
- **`LsaIso.exe` in VTL1** holds the long-lived NTLM hashes and Kerberos long-term key material, plus a narrow RPC API that lets the agent compute responses against those secrets without ever exposing them.

![Figure: Pre-Credential-Guard architecture. lsass.exe runs in the VTL0 NT kernel; the NTOWF, Kerberos long-term keys, and (until KB2871997) WDigest plaintext sit in process memory any kernel-mode-privileged process can read.](diagrams/08-credential-guard-pre-cg-memory.svg)

![Figure: Post-Credential-Guard architecture: the signature image. The NTOWF and Kerberos long-term keys move to the LsaIso.exe trustlet in VTL1; the hypervisor's SLAT forbids VTL0 page tables from mapping it, and the only VTL0↔VTL1 path is the LSA_ISO_RPC_SERVER ALPC channel.](diagrams/08-credential-guard-vtl-boundary.svg)

The architectural pivot is that the `mimikatz`-style memory dump still reaches `lsass.exe`, but it no longer reaches the long-term key. The key has moved across a boundary the hypervisor (Chapter 9, Above Ring Zero) enforces with hardware page-table-permission bits, and no VTL0 process, regardless of token, regardless of privilege, can map the page.

Think of the split as a storage-vs-use redesign rather than a parser rewrite. `msv1_0.dll` still parses NTLM messages, `kerberos.dll` still owns Kerberos protocol state, CloudAP still brokers cloud authentication, and the logon session still has handles, tickets, package state, and network-facing code in VTL0. What changed is the custody rule for material that remains valuable after the current protocol exchange: the NTOWF, Kerberos long-term keys, and Kerberos TGT material move into VTL1. The agent may ask, "derive the response for this challenge with this context handle"; it may not ask, "give me the NTOWF bytes." That one-way API shape is why an empty hash is success rather than breakage.

The split also explains the residuals that survive later in the chapter. Pass-the-Ticket survives because Kerberos service tickets and their use path still exist on the agent side; Microsoft explicitly says service tickets are not protected, while the TGT is [311]. Pass-the-Challenge exists because the trustlet must return NTLM responses if the enterprise still speaks NTLM. Third-party SSP breakage happens because an SSP that expected to query supplemental long-term material from LSASS is now asking the wrong process. Credential Guard is therefore best described as isolating long-lived credential *storage* while preserving enough credential *use* to keep Windows logon and SSO functional.

## The encrypted-blob format and the IUM API

The visible artifact of the move is the `[LSA Isolated Data]` block in the opening Pypykatz-style dump. The structure of that block is documented byte-by-byte in the PassTheChallenge README [667]: an opaque encrypted payload, a `Context Handle` (an opaque RPC handle that identifies the per-logon session inside the trustlet), a `Proxy Info` field that points to the protocol-side session metadata in `lsass.exe`, and a `DPAPI` GUID that ties the encrypted blob to the per-user DPAPI master-key chain.

> **Definition: DPAPI (Data Protection API).** The Windows API for protecting per-user secrets at rest. The DPAPI master-key chain is keyed off the user's password (or NTOWF for Pass-the-Hash-resistant variants), and is the canonical persistence layer for credentials and certificates that need to survive process restarts. In the Credential Guard architecture, the per-user DPAPI keys are themselves derived from material the trustlet has access to; the GUID in the `[LSA Isolated Data]` block links the in-memory trustlet record to the on-disk DPAPI chain.

The public PassTheChallenge tooling exposes the four operation classes that
matter for NTLM authentication [667]:

1. **Wrap / unwrap protected data**: opaque blobs can be round-tripped through
   `lsass.exe` memory without `lsass.exe` seeing the cleartext.
2. **Protect a credential**: the `protect` command converts an NT hash into an
   encrypted blob, modeling the post-logon ingestion path where the trustlet
   internalizes the NTOWF.
3. **Compute an NTLMv1 response**: the `nthash` command asks for a response from
   encrypted credentials and accepts an optional server challenge.
4. **Compute an NTLMv2 response**: the `challenge` command asks for an NTLMv2
   response using encrypted credentials and supplied challenge metadata.

The Pypykatz fork output structure carries the exact byte layout for all of this: *Is NT Present*, *Context Handle*, *Proxy Info*, *Encrypted blob*, *DPAPI*. The verbatim hex prefix `a000000000000000080000006400000001000000010100000100000036` is a length-prefixed serialization header. The literal string `4e746c6d48617368`, which decodes from hex to the ASCII string `NtlmHash`, is visible serialized metadata in the protected record. The opaque payload is the wrapped NTOWF; the tag tells you what the protected value represents without exposing the value itself.

> **Aside.** The fact that the field-name tag remains visible is not a bug and should not be read as plaintext leaking from inside the ciphertext. The serializer keeps routing metadata beside the opaque protected payload so the trustlet can interpret the agent's later call. The name tag is therefore evidence about the record's type, not evidence that the NTOWF bytes are visible.

Read as bytes rather than as a secret, the identifying prefix decomposes into a
small serialized header: protection level `0xa0`, fixed-width little-endian
length fields, version `0x01`, cipher identifier `0x01`, and a short tag-length
field before the encrypted payload. The source documents the hex-dump shape and
the embedded `NtlmHash` ASCII tag, but does not name every byte field; that
decomposition is illustrative rather than a captured Microsoft structure. The
load-bearing fact is simpler and stronger: the blob starts with the same
recognizable protected-record prefix, and deeper in the serialized
record the literal hex `4e746c6d48617368` decodes to `NtlmHash`.

The four fields around the blob tell you which side of the boundary owns which fact. *Is NT Present* is the agent-side statement that this logon session has an NTLM credential at all. *Context Handle* is not the hash; it is an opaque capability that lets `lsass.exe` refer back to the trustlet's per-logon record without learning the record. *Proxy Info* points to the VTL0 session metadata the SSP needs for protocol bookkeeping. *DPAPI* ties the isolated in-memory record to the per-user protection chain so that secrets that must be protected at rest can be re-associated with the user's key hierarchy. That is the whole design in one dump: identifiers and routing data remain visible, while the long-term credential is an opaque protected payload only the trustlet can unwrap.

The operation names are equally revealing. Protecting a credential is a
post-logon ingestion step: the user has typed a password, the VTL0 package has
briefly derived the NTOWF, and the trustlet immediately wraps and internalizes
the value. The NTLMv1 and NTLMv2 operations are use calls: given a context and a
challenge, return the derived response. The wrapper operations are the generic
"round trip through LSASS, never reveal cleartext to LSASS" property. The public
reverse-engineering surface is narrow because every extra verb would become an
extra way to ask dangerous questions about the secret.

## The `LSA_ISO_RPC_SERVER` ALPC port

The agent reaches the trustlet through a secure-call route exposed to the LSA side as `LSA_ISO_RPC_SERVER` (terminology per Lyak's writeup [677]). Microsoft documents the fact of RPC communication between LSA and isolated LSA [311]; Lyak and Ionescu document the route and reverse-engineered mechanics [671], [677]. Treat the exact marshalling sequence as reverse-engineered implementation detail rather than a Microsoft-stated contract: a VTL0 caller submits an IUM Base API request, secure-world code validates and dispatches it, and only marshalled inputs and outputs cross the boundary.

> **Definition: ALPC (Advanced Local Procedure Call).** The undocumented Windows IPC primitive that succeeds the older LPC. ALPC ports support multiple message-passing modes, fast handles, and direct shared-memory regions. In Credential Guard, public tooling and writeups name the LSA-side endpoint `LSA_ISO_RPC_SERVER`; the supported Microsoft statement is narrower: LSA uses remote procedure calls to communicate with isolated LSA, and VBS prevents VTL0 from accessing isolated-LSA memory [311].

For credential use, this endpoint is the externally visible surface attackers have documented. There is no supported debugger or driver-load path into `LsaIso.exe`; claims about the absence of every possible internal channel should be read as a statement about the documented and publicly reverse-engineered attack surface, not a complete Microsoft interface inventory.

The mechanics matter because they turn the port into both the protection boundary and the attack boundary. The remote SMB server sends an eight-byte challenge; `msv1_0.dll` receives it in VTL0; LSASS packages the context handle and challenge into the IUM Base API call; secure-world code validates and dispatches the marshalled request; `LsaIso.exe` retrieves the isolated NTOWF for that handle; the trustlet computes the protocol response; and the Secure Kernel copies back the derived response, not the key. If the host is forced into NTLMv1, that returned value is the crackable 24-byte DESL response exploited by Pass-the-Challenge. If the host uses NTLMv2, the response still leaves the trustlet, but the offline attack economics are different. The interface therefore shrinks theft of a reusable hash into abuse of a protocol-specific output.

That is also why DLL injection into `lsass.exe` is sufficient for Pass-the-Challenge but insufficient for hash dumping. An injected SSP can stand next to the legitimate agent code and call the same `LSA_ISO_RPC_SERVER` route, because the route exists to keep SSO working. It cannot read VTL1 pages or ask the endpoint to export the NTOWF, because neither operation is in the API. This is the core operational pattern defenders should remember: Credential Guard removes the memory-read primitive; it does not remove every possible authenticated computation over the protected key.

![Figure: The per-authentication NTLM round-trip across the agent / trustlet boundary. msv1_0.dll in lsass.exe is the network-side parser; the Secure Kernel mediates the hypercall; LsaIso.exe in VTL1 holds the key and returns only the derived response: the NTOWF never crosses back to VTL0.](diagrams/08-credential-guard-ntlm-roundtrip.svg)

## The `MSV1_0\IsolatedCredentialsRootSecret` registry sentinel

One registry artifact correlates with default-on Credential Guard activation: the value `Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\IsolatedCredentialsRootSecret`. Microsoft documents this value on the Credential Guard overview page [87] as the way to detect the Pro / Pro Education Enterprise-carry-over state; it is a detection check, not a general configuration API like `LsaCfgFlags` or `Get-CimInstance Win32_DeviceGuard`. Its presence on a Windows 11 22H2+ Pro / Pro Education box is consistent with default-on having activated the feature. Absence does not by itself prove a problem: the device may simply never have been in the Enterprise carry-over state, or Credential Guard may be disabled by policy, or the hardware may not meet the VBS and Secure Boot requirements.

## TPM binding and the VSM master key

Persistent state in Credential Guard is rare. The trustlet does not normally persist the NTOWF or TGT material across reboots; the next user logon re-derives both. When persistence is needed, the data is sealed under what Microsoft calls the *VSM master key*:

> "On recent supported hardware with TPM 2.0, VSM data that is persisted will be protected by a key called the *VSM master key*, which is protected by device firmware protections.... The VSM master key is protected by the TPM, ensuring that the key and secrets protected by Credential Guard can only be accessed in a trusted environment." [311]

> **Definition: VSM master key.** A symmetric key, generated and stored only in VTL1, that wraps any persistent state the trustlets need to survive reboots. The VSM master key is itself sealed by the TPM under PCR-bound policy, so an attacker who pulls the disk and reboots into a different OS cannot unseal the VSM master key without also reproducing the platform's pristine measured boot state. The TPM chapter (Chapter 2) covers the full seal / unseal primitive.

The key hierarchy is intentionally boring from the attacker's point of view. Pulling the disk gives ciphertext. Booting another OS changes the measured-boot state and loses the TPM unseal policy. Owning the VTL0 NT kernel gives scheduling, drivers, and ordinary kernel memory, but not the VTL1-only key bytes. The remaining path is to make the legitimate booted system perform legitimate operations for you, which is why the later sections emphasize protocol outputs, token abuse, and supplied plaintext rather than mythical "dump the VSM master key from LSASS" steps. The master key is a persistence wrapper for rare VSM state, not a convenient universal password vault.

> **Key idea.** Credential Guard removes the NT kernel from the TCB for the long-lived NTOWF and the Kerberos long-term keys, by moving them into a process whose pages no other VTL can map. The trustlet still answers queries about the keys; what changed is who can touch the bytes.

Where the hash physically lives, in 2026, is in pages of `LsaIso.exe` that the VTL0 NT kernel cannot map. What an attacker on a default-on Credential Guard box actually sees, what the verification surface for defenders is, and what the operational reality looks like in production are now operational questions, not architectural ones.

## The operational reality of default-on Credential Guard

Default-on means specifics. Specifically: an eligible domain-joined Windows 11
22H2+ Enterprise / Education device that meets the hardware and software
requirements and has not been explicitly configured to disable Credential Guard
should have Virtualization-Based Security up, `LsaIso.exe` running, and
`Credential Guard` present in the `SecurityServicesRunning` array of
`Win32_DeviceGuard`. Pro and Pro Education boxes are not ordinary default-on
targets; the special case where a Pro/Pro Edu device previously ran Credential
Guard on Enterprise is the carry-over path, and Microsoft documents the
`HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\IsolatedCredentialsRootSecret`
sentinel as the way to detect that state [87].

## Default-on scope and the no-UEFI-lock choice

Microsoft's Credential Guard overview page [87] is precise about scope: Windows 11 22H2 and later (Enterprise, Education), Windows Server 2025, domain-joined non-DC, hardware-eligible (Hyper-V Generation 2 VM with IOMMU on virtual hardware; UEFI Secure Boot and virtualization extensions required on physical hardware, with a TPM (1.2 or 2.0) and IOMMU recommended for additional protection). Pro and Pro Education hold the license entitlement only via the Enterprise-to-Pro carry-over case. The default-on policy ships "without UEFI Lock" [87], which is a deliberate trade-off.

> **Aside.** "Without UEFI Lock" means an administrator can disable Credential Guard remotely (via Group Policy, Intune, or a registry change) without first sending someone to the box's UEFI menu. The trade-off: an attacker who has already obtained the level of privilege required to write the registry can also undo the same setting. Microsoft chose remote-disable convenience over the in-principle attacker-disable hardening because compatibility incidents (a rolled-out third-party SSP that breaks under CG) are an operational reality, and not being able to disable the feature remotely turns an SSP regression into a desk-side support ticket. The overview page [87] documents the rationale verbatim.

## The three supported verification surfaces

Microsoft's configuration guide [664] names three supported ways to verify Credential Guard is running, and explicitly disrecommends a fourth:

1. **`msinfo32`**: opens the System Information UI; the line "Virtualization-based Security Services Running" includes "Credential Guard" when the trustlet is up.
2. **PowerShell `Get-CimInstance Win32_DeviceGuard`**: returns a `SecurityServicesRunning` array of service identifiers, not a bitmask.
3. **WinInit Event ID 13** in the System log: "Credential Guard (LsaIso.exe) was started and will protect LSA credentials." [664]

The disrecommended approach is "look for `LsaIso.exe` in Task Manager."
Microsoft's words: "Checking Task Manager if LsaIso.exe is running isn't a
recommended method for determining whether Credential Guard is running." [664]
Task Manager is a weak administrative signal because it runs in VTL0 and queries
ordinary process enumeration. The three supported surfaces are better
configuration and health checks, but they are not remote attestation and should
not be treated as tamper-proof forensic proof after a SYSTEM or kernel
compromise.

> **Note: Verifying Credential Guard is actually running.** Use the supported surfaces, not Task Manager. The PowerShell one-liner is `(Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard).SecurityServicesRunning`. The returned `uint32[]` array contains `1` when Credential Guard is running; `2` denotes Hypervisor-Enforced Code Integrity (HVCI) per the broader `Win32_DeviceGuard` schema [680]. The corresponding WinInit Event IDs are 13 (Credential Guard started), 14 (configuration loaded), 15 (warning: secure kernel not running), 16 (failed to launch), and 17 (UEFI configuration error), per the configuration guide [664].

Read the PowerShell value as an array of service IDs. `1` means Credential Guard;
`2` means Hypervisor-enforced Code Integrity; `3` means System Guard Secure
Launch; `4` means SMM Firmware Measurement; `5` and `6` are kernel-mode
hardware-enforced stack protection in enforce and audit modes; `7` is
Hypervisor-Enforced Paging Translation. MBEC is not part of this array at all:
it is a CPU capability advertised in the separate `AvailableSecurityProperties`
array. A healthy default-on endpoint commonly reports `[1, 2]`, which should be
read as "Credential Guard and HVCI are running," not as a bitwise sum.

## Proof on a live machine

The claims above are architecture; a Reasoner should not take them on faith. The following are verbatim captures from our lab VM, each tagged and hash-stamped. The build gate re-hashes every block against the capture manifest, so these bytes cannot have been edited to fit the prose.

First, that Virtualization-Based Security is actually running and Credential
Guard is one of the services it hosts:

> 🟢 **CAPTURED**. `explab-win` · Win11 25H2 (build 26200) · 2026-06-07T05:30:49Z
> probe: `Win32_DeviceGuard` (WMI/CIM) · sha256 `c17d18ef37ab…`
> reproduce: `Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard | Format-List *`

<!--evidence file="deviceguard.txt" sha256="c17d18ef37ab6963c272fdbefaf8bd39dd22ebcdc9de606d03beade4428bde98"-->
```text
VirtualizationBasedSecurityStatus = 2  # Running
SecurityServicesConfigured        = CredentialGuard, HypervisorEnforcedCodeIntegrity
SecurityServicesRunning           = CredentialGuard, HypervisorEnforcedCodeIntegrity
LsaIso_process_present = True
LsaIso_pid             = 1008
Scenarios\CredentialGuard\Enabled = 1
```

`VirtualizationBasedSecurityStatus = 2` is the hypervisor reporting VBS *running*,
not just configured. `SecurityServicesRunning` is a `uint32[]` **array** (not a
bitmask) whose presence of `CredentialGuard` is what the supported verification
surfaces ultimately read. (A raw `Get-CimInstance` returns these enum codes as integers, e.g. `{1, 2}` for Credential Guard and HVCI; the capture maps them to names for readability.) And `LsaIso_process_present = True` with a live PID is
the trustlet itself, the process whose pages VTL0 cannot map.

Second, the agent/trustlet split as two distinct, co-resident processes:

> 🟢 **CAPTURED**. `explab-win` · Win11 25H2 (build 26200) · 2026-06-07T05:30:49Z
> probe: process + LSA isolation state · sha256 `51e0a94ad87a…`
> reproduce: `Get-Process lsass,LsaIso,SecureSystem; (Get-CimInstance Win32_DeviceGuard …).SecurityServicesRunning`

<!--evidence file="lsass-ssp.txt" sha256="51e0a94ad87a8a8b465ac5ef7c9d16038ac9cc68cdfbd121647ba3b4a87a672d"-->
```text
pid             = 1016
CredentialGuard_running = True
LsaIso_trustlet_present = True
LsaIso_pid              = 1008   # secrets live here, isolated from lsass in VTL1
SecureSystem_present    = True   # the secure kernel host process
```

Read this as a Reasoner: `lsass.exe` (pid 1016) is the agent you *can* reach;
`LsaIso.exe` (pid 1008) is the vault you *cannot*; `SecureSystem` is the VTL1 host
that mediates between them.

Third, the on-box configuration sentinels that say this state is policy, not
accident:

> 🟢 **CAPTURED**. `explab-win` · Win11 25H2 (build 26200) · 2026-06-07T05:30:49Z
> probe: LSA configuration registry · sha256 `1e09245b5c84…`
> reproduce: `LsaCfgFlags`/`RunAsPPL` from `HKLM:\SYSTEM\CurrentControlSet\Control\Lsa`; `CachedLogonsCount` from `HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`

<!--evidence file="credential-stores.txt" sha256="1e09245b5c8408b977eec9b5fae6c897cbf0887a0b6492393244533a311fc74a"-->
```text
LsaCfgFlags (Cred Guard) = 2
RunAsPPL (LSASS protected process) = 2
CachedLogonsCount   = 10  # # of cached domain logons
```

`LsaCfgFlags = 2` is the policy register's own read-back: Credential Guard
**enabled, without UEFI lock**. `RunAsPPL = 2` carries the *same* scheme
(`1` = enabled with UEFI lock, `2` = without), but it is a **different feature**,
and conflating them is the most common architectural error in defensive reviews:

> **PPL is not Credential Guard.** `RunAsPPL` keeps `lsass.exe` wrapped as a
> Protected Process Light *inside the same NT kernel an attacker is trying to
> subvert*; it is bypassable from kernel via a signed-but-vulnerable driver
> (Delpy's own `mimidrv.sys`) and was bypassable from userland via PPLdump until
> 2022. Credential Guard moves the secret across a TCB boundary
> an NT-kernel attacker cannot cross. Both should be on; neither replaces the
> other.
>
> **Honest labeling.** These captures are 🟢 from a *single lab VM* with
> Credential Guard explicitly enabled, not a claim about your fleet's default-on
> state, and not physical silicon (the vTPM under this VM is host-provided; see
> Part I's 🟡/🔵 discussion). What they prove is narrow and real: *when Credential
> Guard is running, this is the exact runtime and configuration shape you can
> verify*. And the PID-presence lines, useful for confirming a known-good lab
> baseline, are exactly the ones this chapter tells you *not* to trust in adversarial
> conditions.

## What changes for the protocols

When Credential Guard is enabled, four SSPs lose the ability to use signed-in credentials: "NTLMv1, MS-CHAPv2, Digest, and CredSSP can't use the signed-in credentials" [311]. For NTLMv1 and Digest the practical effect is small (NTLMv1 is end-of-life: see The Death of NTLM chapter (Chapter 16); Digest is essentially unused outside legacy HTTP digest authentication). For MS-CHAPv2 and CredSSP the effect is real: any single-sign-on path that depended on those protocols breaks with Credential Guard on. The considerations page [681] calls out PEAP-MSCHAPv2 / EAP-MSCHAPv2 WiFi and VPN configurations explicitly: "If you're using WiFi and VPN endpoints that are based on MS-CHAPv2, they're subject to similar attacks as for NTLMv1." [681] The recommended remediation is to migrate the endpoints to PEAP-TLS / EAP-TLS (certificate-based authentication).

For Kerberos, Credential Guard "doesn't allow unconstrained Kerberos delegation or DES encryption, not only for signed-in credentials, but also prompted or saved credentials" [311]. Constrained Delegation and Resource-Based Constrained Delegation continue to work. Credential Guard itself does not make the estate AES-only; RC4 is handled by Kerberos policy and account configuration, while Protected Users is the feature in this chapter that forbids RC4 for its members [672].

## What doesn't change

The agent surface still exposes every SSP that loads inside `lsass.exe`. The trustlet isolates the secret the SSP uses; it does not isolate the *parser* that the SSP runs against an attacker-controlled wire format. A bug in `msv1_0.dll`'s NTLM parser is exactly as exploitable on a 2026 Credential-Guard-on box as it was on a 2015 Credential-Guard-off box. The trustlet does not guard the agent; the trustlet guards the key.

> **Definition: HVCI (Hypervisor-Enforced Code Integrity).** A VBS-based feature that uses the hypervisor's SLAT enforcement to ensure that any kernel-mode page that is executable is also signed and immutable, and any writable kernel-mode page is non-executable. HVCI enforces signed, immutable executable kernel pages and blocks unsigned kernel-code paths, but BYOVD is specifically the signed-but-vulnerable-driver case; that residual belongs to the vulnerable-driver blocklist and driver hygiene, not HVCI alone. HVCI is orthogonal to Credential Guard; the overview page [87] recommends running both.

Credential Guard is on; the surface is documented; the verification is one PowerShell line. So what other things claim to "protect LSASS," and how do they fit together with Credential Guard?

## The other things that "protect LSASS"

Six other things in the Microsoft security stack get called "LSASS protection" in someone's marketing. None of them is a substitute for Credential Guard. Most of them are complements. The difference matters because the choice between them is not a choice; the answer is *all of them, layered*.

| Feature | Enforcement TCB | Attacker bar to defeat | Residual class it leaves open |
|---------|-----------------|------------------------|-------------------------------|
| LSA Protection (`RunAsPPL`) | NT kernel (signer-level lattice) | Signed kernel driver (BYOVD via `mimidrv.sys` [328]); userland on legacy via PPLdump [449] | Trustlet RPC outputs; non-LSA process credentials |
| Credential Guard / `LsaIso.exe` | Hypervisor + Secure Kernel + VTL1 trustlet | Hypervisor escape; VTL1 code-execution bug | Pass-the-Challenge [677]; credential *use*; tokens; supplied creds |
| HVCI / Memory Integrity | Hypervisor-enforced kernel page W^X | Signed-and-vulnerable driver; vulnerable-driver blocklist gap | Kernel-mode logic bugs in signed drivers |
| Defender for Identity LSASS read-monitoring [682] | Behavioral detection (no TCB) | Stealth tradecraft that does not trip the canonical signatures | Anything not yet patterned |
| Hello for Business | Per-device TPM-bound asymmetric key (no shared secret on the wire) | TPM compromise; on-device keylogger before sign-in | Not a substitute: it reduces password replay; PRT storage/use details belong to the cloud-token path |
| Restricted Admin / Protected Users | Protocol-level credential-delegation suppression | Per-protocol; does not move where the secret lives | Everything Credential Guard already covers, plus the four-hour TGT cap |

LSA Protection's kernel-driver-loader bypass class is closed by HVCI for unsigned drivers but not for signed-and-vulnerable ones. Defender for Identity is a detection layer, not a TCB boundary. The Windows Hello chapter (Chapter 20) develops Hello for Business, which replaces the password with a TPM-bound asymmetric key [253]: the Hello for Business overview [253] row in the Security comparison table reads "It uses **key-based** or **certificate-based** authentication. There's no symmetric secret (password) which can be stolen from a server or phished from a user and used remotely." The Microsoft Entra ID Primary Refresh Token (PRT) inside `cloudap.dll` is the cloud-joined analog of the on-prem identity problem: Microsoft documents device/TPM binding for PRT protection [683], while this chapter should not imply that the PRT itself is necessarily in `LsaIso.exe` custody. Restricted Admin and Protected Users [672] suppress credential delegation at the protocol layer; on a Credential-Guard-on box they are *additionally* effective because they remove the prompt path, but they are not a substitute for the storage-isolation primitive.

> **Aside: Cross-OS comparison.** The structural model differs in interesting ways across general-purpose desktop operating systems. macOS uses the Apple Secure Enclave [62]: a separate coprocessor "isolated from the main processor" running an Apple-customized L4 microkernel, with its own attestation chain and a constrained API surface that does not require a "secure call" from the application processor to be tunnelled through a trusted broker. Linux deployments commonly rely on Kerberos credential caches and user-session secret stores (for example SSSD KCM [684], GNOME Keyring, or KWallet). Those components improve containment and usability, but they are not the same architectural claim as Windows' VTL1 isolated LSA; the exact dump path is distribution- and desktop-stack-specific. ChromeOS uses cryptohome [685] plus per-user U2F keys, structurally close to the Hello-for-Business model. Windows is the only general-purpose desktop OS that combines a TPM-bound long-term key (Hello), a hypervisor-isolated derived-secret store (Credential Guard / LsaIso), and a behavioral detection layer (Defender for Identity). It is also the only one that accumulated the largest deployed base of password-equivalent secrets in process memory before it found the architectural answer.

Credential Guard closes the storage class. Layering closes the adjacent classes. But there are residual classes the layers cannot close: things Credential Guard was never going to close, by documented design.

## What Credential Guard was never going to close

Microsoft's own *How Credential Guard works* [311] page lists what Credential Guard *does not* protect, in plain English. Each class has a publicly disclosed worked example. Each worked example is in 2026 production attacker tradecraft. This is the honest accounting.

## Pass-the-Challenge: the trustlet's RPC output as the new attack surface

On December 26, 2022, Oliver Lyak published Pass-the-Challenge [677]. The technique is exactly the lesson of the agent/trustlet split: the trustlet's pages are unreadable, but the trustlet's RPC output is exactly the response the attacker wants, and the attacker can ask for it.

The attack flow, end to end:

1. The attacker has SYSTEM and `SeDebugPrivilege` on a Credential-Guard-on box (the pre-trustlet bypass paths still apply for getting to that point; Credential Guard does not change them).
2. The attacker injects a security-package DLL named `SecurityPackage.dll` (per the PassTheChallenge tool's source [667]) into `lsass.exe`. Inside `lsass.exe`, that DLL inherits the established ALPC channel to the trustlet, because it is now part of the agent.
3. The attacker uses the Pypykatz fork [686] to extract the per-logon `Context Handle` and `Proxy Info` from the `[LSA Isolated Data]` block of an existing user session.
4. The attacker uses the established agent/trustlet route to run the `nthash`
   operation, supplying the `Context Handle`, `Proxy Info`, encrypted blob, and
   "the static challenge `1122334455667788`" when no server challenge is
   provided [667].
5. The trustlet faithfully returns the NTLMv1 response. No memory of the trustlet is read. No bug in the trustlet is exploited. The trustlet does what it was built to do.
6. The attacker submits the response to `crack.sh`; the PassTheChallenge README describes this as the easy path for recovering the NTLM hash from the generated NTLMv1 response and says to wait around 30 seconds for the result [667].

There is also a v2-shaped path in the public tooling: the README exposes a `challenge` command to calculate an NTLMv2 response using encrypted credentials [667]. The broader AD CS relay chain is described in Lyak's article [677], but the load-bearing claim for this chapter is narrower and README-verifiable: the trustlet can be asked for derived NTLM output without exporting the NTOWF.

![Figure: The Pass-the-Challenge attack flow. The trustlet is faithful (no page is read and no bug is exploited) but its RPC output is exactly the NTLMv1 response the attacker asked for, and crack.sh recovers the NT hash in ≈30 seconds.](diagrams/08-credential-guard-pass-the-challenge.svg)

Microsoft's response landed in two phases. First, Microsoft removed the NTLMv1 protocol in Windows 11 24H2 / Server 2025 (the subject of The Death of NTLM chapter, Chapter 16), which removes the `crack.sh` rainbow-table leg specifically. Second, Microsoft is tightening the remaining NTLMv1-derived SSO paths through the `BlockNtlmv1SSO` audit/enforce rollout; the support note says these changes do not apply when Credential Guard is enabled because Credential Guard already provides the broader protection [687]. The *class*, "use the trustlet to mint derived material", remains structural to the agent / trustlet split, because closing it requires removing either the agent's ability to call the trustlet (which would defeat single-sign-on) or the attacker's ability to compromise the agent (which is the point of every other layer in the stack).

> **Aside: Why the agent / trustlet split has a use surface.** Pass-the-Challenge is not a Microsoft bug. It is a class property of any agent / trustlet split where the agent owns the protocol code. If `lsass.exe` could not call the trustlet, the trustlet would be useless: there would be no path from the wire challenge to a response. If `lsass.exe` *can* call the trustlet, then an attacker who compromises `lsass.exe` can call it too. Closing this gap structurally requires rewriting the SSP loading model so that protocol code, too, runs inside the trustlet, which would put parsers for arbitrary attacker-controlled wire formats inside VTL1 and dramatically expand the trustlet TCB. Microsoft has not announced an intent to do that. The honest read of the architecture is that the storage surface is closed and the use surface is structurally open.

## Credential *use* without theft

Three named techniques in 2026 production tradecraft do not require reading the memory of any Credential-Guard-protected machine. They request derived material from the network and do offline cryptography on the response.

**Kerberoasting.** Tim Medin disclosed Kerberoasting at DerbyCon 4 in September 2014 [688] under the talk title *Attacking Microsoft Kerberos: Kicking the Guard Dog of Hades*. The mechanism, per the MITRE ATT&CK technique page [689]: any authenticated domain user requests a TGS-REP ticket for any registered Service Principal Name. "Portions of these tickets may be encrypted with the RC4 algorithm, meaning the Kerberos 5 TGS-REP etype 23 hash of the service account associated with the SPN is used as the private key and is thus vulnerable to offline Brute Force attacks that may expose plaintext credentials." [689] The ticket arrives on the attacker's machine; the cracking happens on the attacker's GPUs; no memory of any Credential-Guard-protected box is ever read.

> **Definition: Kerberoasting.** The class of attack in which any authenticated domain user requests a Kerberos TGS-REP ticket for any registered Service Principal Name and submits the encrypted portion of the response to offline cracking, recovering the service-account password if it is weak. Documented as MITRE ATT&CK T1558.003 [689]. Kerberoasting reads no memory of the targeted host; it consumes only network responses to entirely-legitimate Kerberos requests.

**AS-REP Roasting.** The same class for accounts with `DONT_REQ_PREAUTH` set [690]: the attacker requests a Kerberos AS-REP without sending preauthentication, the KDC returns a ticket portion encrypted with the user's long-term key, and the attacker cracks offline.

**Resource-Based Constrained Delegation (RBCD).** Originally described by Elad Shamir in *Wagging the Dog* (January 2019) [691]; refined by James Forshaw's "Exploiting RBCD using a normal user" (May 2022) [692]; turned into a turnkey LPE by Dec0ne's KrbRelayUp (2022) [693], which the README describes, accurately, as "essentially a universal no-fix local privilege escalation in windows domain environments where LDAP signing is not enforced (the default settings)." [693] The attack abuses the `msDS-AllowedToActOnBehalfOfOtherIdentity` LDAP attribute: if the attacker can write that attribute on a target computer object, they can mint a Kerberos service ticket *as anyone* against the target. Forshaw's 2022 contribution removed the precondition that the attacker must control a computer account (it used to require a `MachineAccountQuota`-bypass); after Forshaw, *any* authenticated domain user with write access to the attribute is enough.

> **Definition: Resource-Based Constrained Delegation (RBCD).** A Kerberos delegation feature in which the resource (server) lists which principals are allowed to delegate to it via the `msDS-AllowedToActOnBehalfOfOtherIdentity` LDAP attribute on the resource's computer object. RBCD enables S4U2Self and S4U2Proxy chains where the configured principal can request a service ticket *as any user* against the resource, including Domain Administrators. The Microsoft constrained-delegation overview documents the resource-owned delegation model and S4U2Proxy extension [694], and the schema reference names `msDS-AllowedToActOnBehalfOfOtherIdentity` as the access-check attribute [695]; abuse is documented in Wagging the Dog [691], refined in tiraniddo.dev [692], and weaponised in KrbRelayUp [693].

## The SeImpersonatePrivilege Potato chain

The Potato family is a chain of escalations from a low-privilege service user (anyone with `SeImpersonatePrivilege` or `SeAssignPrimaryTokenPrivilege`) to NT AUTHORITY\SYSTEM: coerce an inbound SYSTEM authentication to a local listener, impersonate the resulting token, and `CreateProcessWithToken` finishes the job. The `breenmachine` Hot Potato writeup is verbatim: "Hot Potato (aka: Potato) takes advantage of known issues in Windows to gain local privilege escalation in default configurations, namely NTLM relay (specifically HTTP→SMB relay) and NBNS spoofing." [696] The full lineage (Hot, Rotten, Juicy, PrintSpoofer, RoguePotato, GodPotato) and the `SeImpersonatePrivilege` primitive it abuses are developed in The SeImpersonate Primitive chapter (Chapter 24); each link survives because it abuses a Windows feature (DCOM marshalling, RPC, named-pipe impersonation, the Print Spooler) with a legitimate use Microsoft cannot remove. The load-bearing fact here is the boundary it crosses: the Potato chain exploits *tokens*, not credentials. Credential Guard does not protect tokens; Credential Guard protects credentials.

## Plaintext-secret protocols and supplied credentials

"When Credential Guard is enabled, NTLMv1, MS-CHAPv2, Digest, and CredSSP can't use the signed-in credentials" [311], but they *can* still be used with prompted or saved credentials. In every such case the cleartext password (or a symmetric secret derived from it) is supplied to `lsass.exe` from outside the trustlet, so the trustlet has nothing to protect at the moment of use.

The considerations page [681] names PEAP-MSCHAPv2 / EAP-MSCHAPv2 WiFi and VPN configurations as the most consequential remaining surface in 2026: a corporate WiFi or VPN endpoint that authenticates users with MS-CHAPv2 still cracks under the same offline tradecraft as the original NTLMv1 attacks, because the protocol itself uses MD4 + DES against the user's NT hash. The recommendation: "organizations move away from passwords to other authentication methods, such as Windows Hello for Business, FIDO 2 security keys, or smart cards" [681], or migrate the WiFi / VPN endpoint to certificate-based PEAP-TLS / EAP-TLS.

## Out-of-LSA credential storage

Four storage locations are out of scope for Credential Guard by Microsoft's own design:

- **Generic Credential Manager entries.** Web passwords, browser-stored credentials, the Windows Credential Manager's "Web Credentials" tab. "Generic credentials, such as user names and passwords that you use to sign in websites, aren't protected since the applications require your clear-text password." [681]
- **Non-Microsoft Security Support Providers.** "Some non-Microsoft Security Support Providers (SSPs and APs) might not be compatible with Credential Guard because it doesn't allow non-Microsoft SSPs to ask for password hashes from LSA.... For example, using the KerbQuerySupplementalCredentialsMessage API isn't supported." [681] Third-party SSPs that depend on hash retrieval through that API simply break under Credential Guard.
- **The Active Directory database on domain controllers.** "Credential Guard doesn't protect the Active Directory database running on Windows Server domain controllers." [311] The most-attacked LSASS on the network (`lsass.exe` on the domain controller, holding `NTDS.dit` and the `krbtgt` long-term key) is explicitly out of Credential Guard's scope. Microsoft's stated rationale is that domain controllers do not benefit from the same isolation, because the entire AD database is, by design, available to the LSA process on a DC.
- **Credential-input pipelines such as Remote Desktop Gateway and Just-In-Time admin access tooling**, where the typed cleartext is supplied to `lsass.exe` over an inbound network protocol and is in clear at the moment of arrival.

> **Quoted source.** Doesn't prevent an attacker with malware on the PC from using the privileges associated with any credential. We recommend using dedicated PCs for high value accounts. (Microsoft Learn, *How Credential Guard works* [311])

![Figure: The four-class residual taxonomy Credential Guard was never going to close: credential use (not theft), tickets already in lsass, token attacks, and off-box replay, each routed to the chapter that owns it.](diagrams/08-credential-guard-residual-taxonomy.svg)

> **Key idea.** The trustlet is the storage layer; the agent is the use layer; an attacker who controls the agent can request derived material the trustlet was never going to refuse. This is the structural reason Credential Guard was never going to close the use surface.

The documented residual classes and their worked examples explain the current boundary. What is *not yet* documented (the open problems where the research is still in progress) is what remains.

> **The Reasoner's one-line model.** *Credential Guard moves the long-term key out
> of reach; it does not move the key's **usefulness** out of reach.* Storage is
> closed; **use** is structurally open. Every residual is a use, a token, a
> ticket, or a store Credential Guard never claimed.

## Open problems

Five things the Credential Guard architecture has not yet closed. One of them is structural; four are deployment frontiers.

**Trustlet IUM API surface fuzzing.** Pass-the-Challenge proved one corner of the agent-callable RPC surface remains usable by an attacker who controls the agent: the static `1122334455667788` challenge path produced crackable NTLMv1-derived material in the public workflow [667]. A systematic public audit of the IUM API entry points has not been published. A blue-team-friendly fuzzer that exercises the channel from a controlled VTL0 agent against a controlled VTL1 target is on the public to-do list of several research groups.

**Domain-controller LSASS / `NTDS.dit` / `krbtgt` protection.** Microsoft documents the DC carve-out as out of scope [311]. An architectural fix would require a DC-resident trustlet model that can answer Kerberos AS-REP and TGS-REP queries against the entire `NTDS.dit` without compromising AD replication semantics. That model is not on the public roadmap, and the practical recommendation, the dedicated-Tier-0-PAW model from the *Mitigating Pass-the-Hash* v2 playbook [619], still applies in 2026.

**TGT and service-ticket lifetime in `lsass.exe` after the trustlet mints them.** Pass-the-Ticket on the agent targets Kerberos service tickets and related per-session material, not the protected TGT. Credential Guard isolates the long-term key and the TGT; Microsoft states the service-ticket limit verbatim: "Kerberos service tickets aren't protected by Credential Guard, but the Kerberos Ticket Granting Ticket (TGT) is protected" [311]. A 2026 attacker with `SeDebugPrivilege` who dumps `lsass.exe` should be modeled as looking for service tickets and access tokens, not the underlying NTOWF or protected TGT.

**Pass-the-Cookie / token-lift class against derived material.** Microsoft Entra Primary Refresh Token (PRT) session material [683] and application cookies become bearer-token targets until the session ends. Per-token device binding raises the bar (the cookie is bound to a TPM-bound device key, so use of the cookie outside the device is detectable by the cloud), but it does not close the class for an attacker who has on-device persistence and can replay the cookie from the same device.

**Compatibility and observability frontier.** The third-party SSP / MS-CHAPv2 / CredSSP behavior-change surface keeps showing up in real-estate compatibility reports. Microsoft's *Considerations* page [681] is updated routinely; the practical operational pattern in 2026 is "pilot Credential Guard via Intune on a representative ring for 30 days, harvest the compatibility errors, fix or replace the affected SSPs, then broaden enforcement." That pattern is now well-trodden but the per-estate inventory is real work.

Open problems are interesting; daily practice is more interesting. What does a 2026 administrator, researcher, red-team operator, and detection engineer actually do with Credential Guard?

## Residual-control map

| Residual | Class | Credential Guard buys you | You still need |
|---|---|---|---|
| Pass-the-Challenge | use | NTLMv1 path closed on 24H2+ | disable NTLM; monitor SSP-DLL loads into LSASS |
| Pass-the-Ticket (service tickets) | ticket | TGT protected; service tickets not protected | short ticket lifetimes where feasible; Protected Users for high-value accounts; 4769/4624 ticket-anomaly hunting |
| Use without theft (Kerberoast/RBCD) | use | nothing | gMSA / strong SPN passwords; AS-REP/Kerberoast hunting; LDAP signing |
| Token / Potato | token | nothing | least-privilege service identities; remove `SeImpersonate` where possible |
| Plaintext protocols | supplied | signed-in creds blocked | migrate Wi-Fi/VPN to EAP-TLS; passwordless |
| Out-of-LSA storage | store | nothing | vault hardening; FIDO2/passkeys; third-party-SSP inventory |
| Domain controllers | store | nothing on DCs | Tier-0 isolation; PAWs; `krbtgt` rotation; delegation hygiene |

## Practical guide

Four audiences; four operational checklists. Each is short because each builds on a section we have already walked.

## For an administrator or platform engineer

Verify Credential Guard is running using the three supported surfaces [664]: `(Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard).SecurityServicesRunning` should contain `1`; `msinfo32` should list "Credential Guard" under Virtualization-based Security Services Running; the System event log should show WinInit Event 13. Deploy via Intune Settings Catalog or GPO with "Enabled without lock" [664]. Inventory NTLMv1, MS-CHAPv2, Digest, CredSSP, and non-Microsoft SSP usage *before* enabling, because those are the protocols that will lose SSO under Credential Guard.

> **Lab note. Lab-only: how to verify Credential Guard is currently running.** On a Credential-Guard-on box, the following one-liner returns `True`:
>
> ```powershell
> (Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard).SecurityServicesRunning -contains 1
> ```
>
> The `1` corresponds to Credential Guard in the `SecurityServicesRunning` array [664]. Pair with the System event log filter `EventID=13, Source=Wininit` to confirm the boot-time launch event. Use these to verify, not Task Manager: Microsoft explicitly disrecommends the Task Manager check.

> **Note: Enable Credential Guard before domain join.** "Credential Guard should be enabled before a device is joined to a domain or before a domain user signs in for the first time. If Credential Guard is enabled after domain join, the user and device secrets may already be compromised." [664] On a default-on Windows 11 22H2+ deployment this is automatic; on legacy estates being migrated, a re-image or other clean-provisioning path is the safest way to get that guarantee.

## For a security researcher

The verifiable trustlet artifacts are: the `.tpolicy` PE section in `LsaIso.exe`; the `s_IumPolicyMetadata` export; the dual-EKU signature with the IUM EKU 1.3.6.1.4.1.311.10.3.37 visible in the certificate chain. The IUM-side enumeration approach is `NtQuerySystemInformation` with the `SystemIsolatedUserModeInformation` class. Quarkslab's IUM-debugging walkthrough [312] documents the nested-virt setup (VMware L1 + Hyper-V L2), the GDB-stub attach on `hvix64.exe`, the patch on `SecureKernel!SkpsIsProcessDebuggingEnabled` to force-return 1, and the walk to `SecureKernel.exe` from `HvCallVtlReturn` at hypercall ID 0x12. Lyak's PassTheChallenge methodology [667] is the canonical worked example for the agent-side trustlet RPC interaction.

## For a red-team operator

Assume the long-term hash and TGT are not in `lsass.exe`. Assume the trustlet's RPC output is. The first branch in the decision tree is verification: confirm whether the host is actually Credential-Guard-on with the same supported surfaces defenders use: `SecurityServicesRunning` contains `1`, `msinfo32` lists Credential Guard under VBS services, and WinInit Event 13 exists. Do not treat `LsaIso.exe` in Task Manager as proof. Also confirm PPL separately: PPL and Credential Guard are complementary, and bypassing PPL does not collapse the VTL1 boundary. If LSASS is not protected, the old dump path may still be in scope; if Credential Guard is running, a memory dump should be expected to show `[LSA Isolated Data]`, context handles, proxy metadata, and DPAPI GUIDs rather than reusable NTOWF bytes.

The second branch is protocol exposure. If NTLMv1 is enabled anywhere reachable, Pass-the-Challenge is the cleanest proof that the storage boundary is not the same as a use boundary: inject or load an SSP into `lsass.exe`, call the established `LSA_ISO_RPC_SERVER` route, request a response to a controlled challenge, and crack the returned NTLMv1 material offline. The prerequisites are high (code execution capable of loading into LSASS, an established logon context, and a host configuration that still permits the NTLMv1 response calculation), and every prerequisite is observable. The blocked path is equally important: do not promise the client a recovered hash. The output is a protocol response produced by the trustlet, and the two-phase Microsoft fix for NTLMv1 closed the easy path by first blocking the vulnerable calculation shape and then tightening the agent/trustlet behavior so the old challenge-selection trick no longer yielded reusable material.

If NTLMv1 is gone, pivot to credential *use* rather than credential *theft*. Kerberoast weak service accounts; AS-REP Roast accounts with `DONT_REQ_PREAUTH`; test RBCD with KrbRelayUp-style prerequisites [693]; enumerate AD CS ESC misconfigurations; and abuse application paths that still ask a user to type a password. These attacks do not contradict Credential Guard because none requires reading the protected NTOWF out of LSASS. Their failure modes are different: Kerberoasting fails against long random managed-service-account keys; AS-REP roast fails when pre-authentication is required; RBCD fails without a relayable authentication path and writeable delegation edge; AD CS abuse fails when templates remove enrollee-supplied subject names and dangerous EKUs. A masterclass operator documents those prerequisites before touching LSASS.

The third branch is token and session abuse. If the foothold has `SeImpersonatePrivilege`, the Hot/Rotten/Juicy/PrintSpoofer lineage [696], [697], [698], [699] remains relevant because it steals or manufactures a token, not a stored credential. If the target user is already logged on, current-session Kerberos service tickets and access tokens may be enough for lateral movement even though the TGT and long-term key are isolated. The tradecraft change is noisy but honest: instead of one quiet LSASS read that yields reusable material, the operator needs protocol requests, service-ticket use, coercion, relays, or DLL load events. On a Credential-Guard-on host, the best report is often a matrix of blocked theft paths and viable use paths, not a screenshot of an empty Mimikatz table.

## For a detection engineer

Start with a state baseline. The `Microsoft-Windows-Wininit` provider in the System log is the boot-time truth source named by Microsoft's configuration guidance [664]: Event 13 means Credential Guard started; Event 14 records loaded configuration; Events 15, 16, and 17 mean configured-but-not-running states such as secure-kernel launch failure or UEFI configuration trouble. Alert only after joining those events to asset intent. A lab kiosk not expected to run Credential Guard should not page anyone for Event 16; a domain-joined Windows 11 Enterprise endpoint in the default-on ring should. Pair this with periodic `root\Microsoft\Windows\DeviceGuard:Win32_DeviceGuard` collection and treat `SecurityServicesRunning` as an array: `1` present means Credential Guard; `2` present means HVCI; absence of `1` on an expected-on asset is a drift ticket.

For LSASS attack surface, split detections by primitive. A raw LSASS dump attempt is still worth detecting (suspicious `PROCESS_VM_READ`, dump-file creation, handle duplication, or minidump patterns), but on a Credential-Guard-on host it may produce only isolated blobs. A Pass-the-Challenge-style path needs code inside the agent process or an authentication package loaded where it can reach the ALPC channel. Watch for LSA security package configuration changes under the LSA registry keys, unexpected DLL paths loaded by `lsass.exe`, unsigned or oddly-signed modules in the LSASS address space, and AMSI / antimalware engine events that flag security-package load or script-assisted injection [700]. The expected false positives are EDR sensors, smart-card middleware, credential providers, and legacy VPN/SSO agents; tune by publisher, file path, change window, and whether the package was present before the Credential Guard rollout.

For protocol output abuse, network telemetry matters more than memory telemetry. Flag NTLMv1 negotiation and LMCompatibility downgrades; look for repeated NTLM challenges using the static `1122334455667788` value associated with NTLMv1 downgrade and crack.sh rainbow-table workflows; and correlate SMB, HTTP, LDAP, MS-SQL, and Exchange front-end authentication failures that share challenge patterns or originate from an endpoint that just loaded a new SSP. On the Kerberos side, keep the normal roast detections: abnormal TGS-REQ volume for RC4 service tickets, AS-REQs without pre-authentication, RBCD write events, and AD CS template-enrollment anomalies. Those detections belong in a Credential Guard chapter because they are exactly where attackers go after hash theft fails.

Response should be playbooked by branch. If WinInit says Credential Guard stopped running, preserve boot logs, collect DeviceGuard CIM state, check policy and firmware drift, and re-enable with the intended Intune/GPO setting. If LSASS package load is suspicious, isolate the host, collect module inventory and LSA registry state, and assume any trustlet RPC outputs generated during the dwell window may have been abused even if no hash was dumped. If protocol telemetry shows NTLMv1 or Pass-the-Challenge indicators, disable NTLMv1, rotate exposed service-account secrets, and hunt for the same static-challenge pattern across the estate. If detections are Kerberoast/RBCD/AD CS rather than LSASS, treat Credential Guard as intact and fix the directory-control failure that replaced memory theft.

A book-native way to test whether the model has stuck is to walk three artifacts by hand. First, take the opening `[LSA Isolated Data]` record and label what each visible field can and cannot prove: the prefix proves a protected record, `Context Handle` proves a trustlet-side session reference, `Proxy Info` proves VTL0 still has protocol metadata, the DPAPI GUID proves linkage to the user's protection chain, and none of those fields is the NTOWF. Second, take the `SecurityServicesRunning` array from the captured DeviceGuard output and read it as an array, not a bitmask: `1` and `2` together mean Credential Guard and HVCI are both running; they do not combine into a mysterious service `3`. Third, take the LSASS package list and classify each entry as parser, protocol bridge, cloud broker, or legacy compatibility package. That exercise explains why some SSO paths survive and others break.

For an operator tabletop, use a five-question worksheet. Is Credential Guard actually running, and how do you know without Task Manager? Is PPL also enabled, and what would bypassing it still fail to give you? Does any reachable service negotiate NTLMv1, MS-CHAPv2, Digest, CredSSP, or a third-party SSP path that depends on supplemental credentials? Is the target value a long-lived secret, a current-session ticket, a token, a protocol response, or a typed plaintext? What telemetry would your action leave: WinInit drift, module load, LSA registry change, NTLM challenge pattern, TGS volume, RBCD write, or AD CS enrollment? If the answer to the fourth question is "long-lived secret from LSASS," the plan is probably pre-2015 thinking. If the answer is "use a remaining protocol or token surface," the plan belongs in the residual-control map.

For a defender tabletop, invert the same worksheet into assertions. Every managed endpoint should have an intended Credential Guard state; every intended-on endpoint should produce Event 13 or an explained exception; every LSA package should have an owner, signer, and deployment ticket; every NTLMv1 observation should open a migration item; every roastable service account should have a password or managed-service-account remediation; every AD CS template that can mint authentication certificates should have an explicit risk owner. These are not generic hardening chores. They are the places the attacker goes after the empty hash tells them the old memory-theft path is closed.

## Closing

The empty hash from the opening scene is, in 2026, the expected property of eligible domain-joined Windows 11 22H2+ and Windows Server 2025 systems where Credential Guard is enabled by default or policy [87]. Eleven years of `lsass.exe` extraction history made the architectural pivot inevitable; eight years of trustlet maturation have made the pivot a mainstream default rather than a niche hardening option. What remains (the use surface, the protocol surface, the token surface, the typed-credential surface, the third-party-SSP surface) is the next eleven years of work.

> **Bequeaths.** Credential Guard hands the next link one guarantee, narrow and load-bearing: on a correctly configured box the protected credential material (the NTOWF, Kerberos long-term keys, and TGT) is out of VTL0 reach, unreadable by any VTL0 process regardless of SYSTEM or `SeDebugPrivilege`. That guarantee is what The Death of NTLM chapter (Chapter 16) builds on when it argues the password itself can finally be retired. But the bequest stops at *storage*: Credential Guard does not isolate Kerberos *service tickets* minted for the current session, service-ticket replay belongs to the Kerberos chapter (Chapter 17) and the KRBTGT chapter (Chapter 18); it does not protect *tokens*, the SeImpersonate / Potato class belongs to the Windows Access Control chapter (Chapter 22) and the SeImpersonate Primitive chapter (Chapter 24); and it makes no claim outside the endpoint trustlet boundary: cloud token theft and replay belong to the Zero Trust chapter (Chapter 26) and the Continuous Access Evaluation chapter (Chapter 27). The chain moves the secret out of reach; it does not yet move the secret's *usefulness* out of reach.
