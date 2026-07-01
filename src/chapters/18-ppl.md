# Protected Process Light

::: trust-ledger

- **Inherits:** Authenticode binds a file hash to a Microsoft-issued certificate chain and the EKU it carries, so the kernel can resolve which protected-process rung a binary may claim (Chapter 12, Authenticode and Catalog Files); kernel signature-level enforcement decides which binaries a process may map, verified by `ci.dll` at section creation (Chapter 8, Code Integrity).
- **Promise:** A VTL0 caller (even a local administrator running as SYSTEM with `SeDebugPrivilege`) cannot obtain a memory-read, memory-write, thread-inject, or (at the top rungs) terminate handle to a process protected at an equal-or-higher signer rung, because `NtOpenProcess` consults a one-byte `EPROCESS.Protection` lattice *before* `SeAccessCheck` ever weighs the token.
- **TCB:** The NT-kernel process-open path (`PspProcessOpen`, `PspCheckForInvalidAccessByProtection`, `RtlTestProtectedAccess`, and the `RtlProtectedAccess[]` table baked into `ntoskrnl.exe`) plus the one-time Authenticode/EKU parse at `NtCreateUserProcess` and the `ci.dll` signature check that fixes each process's rung at create time.
- **Adversary → Break:** The kernel verifies the *channel* a binary entered through (a signature, an EKU, a `\KnownDlls` section identity), never the *behavior* of code once mapped. The public bypasses surveyed here (JScript-into-PPL, PPLdump, PPLFault, BYOVDLL) all run attacker-influenced data through a legitimately signed channel. The Promise ends at *admission*, not *conduct*.
- **Residual:** A kernel-mode attacker who can write `EPROCESS.Protection` erases the lattice, and on systems without Credential Guard some credential material can still live in VTL0 `lsass.exe`; the companion answer is Credential Guard (Chapter 15), which moves specified long-lived secrets into the `LsaIso.exe` trustlet in VTL1 (Chapter 7, VBS Trustlets). Per-process injection hardening beyond the protection byte belongs to Process Mitigation Policies (Chapter 11).
- **Bequeaths:** "`lsass.exe` is protected from admin-from-user-mode memory reads". The floor Credential Guard (Chapter 15) builds on when it argues the secret must leave VTL0 entirely. Does NOT provide: a security boundary (MSRC classifies PPL as defense in depth), protection against a kernel-mode attacker, or any third-party opt-in outside the ELAM/MVI-gated Antimalware rung.
- **Proof:** 🔵 documented. Ionescu's "Evolution of Protected Processes" for the byte and the `RtlProtectedAccess[]` lattice [431] [432] [433]; itm4n for `RunAsPPL` and the bypass record [328] [434] [331] [435]; Microsoft Learn for ELAM/MVI and the servicing criteria [436] [327] [437] [301]. No fresh 🟢 lab capture in this chapter.
:::

> **The Reasoner's question.** When even a SYSTEM administrator cannot read LSASS, what is doing the denying, what does that denial actually buy, and why is it complementary to (not a substitute for) the VTL1 isolation the Secure Kernel chapter (Chapter 6) built?

---

> **Foundations. What you need before this chapter.**
>
> - **VTL0 / VTL1 (established in Chapter 6, The Secure Kernel).** VTL0 is the normal Windows world: the NT kernel, ordinary user-mode processes, LSASS, EDR daemons, and administrator shells. VTL1 is the secure world Virtualization-Based Security introduced, where the Secure Kernel and trustlets such as `LsaIso.exe` run behind a hypervisor-enforced memory boundary.
> - **PPL vs. Credential Guard.** PPL is an NT-kernel handle-access lattice in VTL0. Credential Guard is a VBS design that moves credential material into VTL1. PPL can keep administrators out of `lsass.exe`; it cannot keep a VTL0 kernel attacker out of VTL0 memory. Credential Guard answers that next layer by putting the long-lived secrets elsewhere.
> - **`EPROCESS`.** The kernel object that represents a process. PPL's key state is a byte in `EPROCESS` named `Protection`, interpreted as Type, Audit, and Signer fields.
> - **Signer rung.** A four-bit trust tier derived from Microsoft-controlled signing policy: Antimalware, Lsa, Windows, WinTcb, and related values. The rung determines which protected process may obtain full access to another.
> - **Full vs. limited process access.** PPL does not make a process invisible. It gates dangerous rights such as memory read/write, thread creation, handle duplication, and (at higher rungs) termination. Limited query rights can still succeed when the normal DACL permits them.

---

> **Chapter thesis.** **Windows Protected Process Light (PPL) re-asks the question of who can touch whom one level below the token model.** A single byte in `EPROCESS` packs a process's protection type, audit bit, and signer rung; the kernel's lattice check inside `NtOpenProcess` rejects memory-read attempts from below the target's rung even when the caller is SYSTEM with `SeDebugPrivilege` enabled. The public bypasses surveyed in this chapter live in one structural class (the kernel verifies the channel by which code enters a PPL, not the behavior of that code once mapped) which is why Microsoft classifies PPL as defense in depth rather than a security boundary, and why Credential Guard / `LsaIso.exe` is its necessary VBS-anchored companion.

## Mimikatz on a protected box

A red team operator has done everything right. The shell is SYSTEM-integrity. `SeDebugPrivilege` is enabled in the token. `whoami /priv` shows every privilege Windows defines. The operator types `mimikatz.exe`, then `privilege::debug`, *OK*. Then `sekurlsa::logonpasswords`, and Mimikatz answers:

```text
ERROR kuhl_m_sekurlsa_acquireLSA ; Handle on memory : (0x00000005) Access is denied
```

The mechanism that just denied them is not a privilege check at all. It is not an ACL decision. It is not the integrity-level mediator. itm4n recreated exactly this failure in 2021 against a vanilla Windows install with one registry value set [328]. The error code `0x00000005` is `ERROR_ACCESS_DENIED`, the Win32 surface that `GetLastError` exposes for the kernel's NTSTATUS `STATUS_ACCESS_DENIED` (`0xC0000022`). The kernel returns the NTSTATUS out of `NtOpenProcess` before the security descriptor of `lsass.exe` has been consulted; `RtlNtStatusToDosError` then maps it to the Win32 `0x5` that surfaces in `kuhl_m_sekurlsa.c`.

> **Definition. Protected Process Light (PPL)**
> A kernel-enforced gating model that decorates a process with a *protection level* (a structured byte combining a type field, an audit bit, and a signer rung) and rejects `OpenProcess` requests from callers whose protection level is below the target's, regardless of token privileges or security-descriptor ACLs.

Picture the scenario concretely. A 2026 red-team engagement against a hardened Windows 11 24H2 endpoint. Audit mode for added LSA protection is often already on after the Windows 11 22H2 rollout, but audit mode is only telemetry; the denial requires `lsass.exe` to have actually launched as PPL, either because `RunAsPPL` was configured or because automatic LSA-protection enablement applied to an eligible new enterprise-joined, HVCI-capable install [436]. A third-party EDR daemon is already running, signed at the Antimalware rung via the vendor's Microsoft Virus Initiative enrollment. The operator owns local administrator. The operator has SYSTEM. The operator holds every privilege Windows defines. They still cannot read a single byte of LSASS memory.

The denial trace, walked carefully, looks like this. Mimikatz calls `OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, lsass_pid)`. The Win32 thunk lands on `NtOpenProcess`, which dispatches to the object-manager callback `PspProcessOpen`. That callback calls `PspCheckForInvalidAccessByProtection`, which calls `RtlTestProtectedAccess` against the caller's `EPROCESS.Protection` byte and the target's `EPROCESS.Protection` byte. The lattice test fails. Both `PROCESS_VM_READ` and `PROCESS_QUERY_INFORMATION` are full-access bits, outside the limited subset the lattice leaves intact for a `None` caller against `PPL/Lsa`, so the kernel strips both. Nothing Mimikatz asked for survives the pruning, and the open resolves to `STATUS_ACCESS_DENIED`: exactly the path that produces `0x00000005` in `kuhl_m_sekurlsa.c` (Note: The relevant commit is `fe4e98405589e96ed6de5e05ce3c872f8108c0a0`, cited by itm4n as the source for the exact failure path that yields `0x00000005` [438].).

> **Walkthrough: The Mimikatz `OpenProcess` denial trace.** Start at the user-mode request, not at the error string. Mimikatz asks Win32 for a process handle containing memory-read and query rights against `lsass.exe`. The request crosses into `NtOpenProcess`, resolves the target `EPROCESS`, and reaches the process-open path before the ordinary DACL calculation is useful. At that moment the kernel compares the caller's protection byte with LSASS's `PPL/Lsa` byte (`0x41`). An unprotected administrator has signer `None`, so the PPL lattice removes the rights that would let the caller read, write, duplicate, or create threads in the target. Only after that pruning would `SeAccessCheck` consider the token and its privileges. `SeDebugPrivilege` can help with discretionary access; it cannot move the caller upward in the protection lattice.
>
> **The thesis, stated as a question.** If every privilege Windows defines is held by the caller, what is doing the denying? The answer is a kernel structure that the token model does not see and the security descriptor does not influence: a byte in `EPROCESS` named `Protection`, mediating a lattice the access check consults *before* it ever asks `SeAccessCheck` about privileges.

This is not a workaround pattern. It is a new dimension. The token model is unchanged. The integrity level is unchanged. The security descriptor on `lsass.exe` is unchanged. What changed is that the kernel now answers a question it did not ask before: *what kind of trust does the caller have to manipulate the address space of the callee?*

> PPL re-asks the question of who can touch whom one level below the token model.

That mechanism has a name (Protected Process Light), an encoding (a single `UCHAR`), and a history that does not begin where you would expect. To understand the byte, we have to understand why Microsoft built it in the first place.

## Historical origins: Vista, DRM, and the first Protected Process

The kernel mechanism that today denies admins access to LSASS was invented in 2006 to keep Hollywood happy. The cover page of Microsoft's `process_vista.doc` whitepaper opens with a sentence almost no one quotes today:

> The Microsoft Windows Vista operating system introduces a new type of process known as a protected process to enhance support for Digital Rights Management functionality in Windows Vista.

The whitepaper was published November 27, 2006, two months before Vista's GA, and it is the architectural seed of the byte we will be staring at for the rest of this chapter [439]. The motivation was not credential theft. It was HD-DVD and Blu-ray content protection. Studio licensing agreements required that even an administrator on the local machine could not read the audio device graph isolation host's memory while protected content was playing. The Protected Media Path required a kernel-enforced barrier between admin user-mode and the media pipeline.

> **Definition. Protected Media Path (PMP)**
> The Vista-era set of components that decrypt and render high-definition video and audio content under DRM. PMP requires kernel-enforced isolation of `audiodg.exe` and a small set of related processes so that local administrators cannot dump intermediate content keys from process memory.

The Vista design was minimal. A single bit in `EPROCESS` marks a process as protected. At `NtCreateUserProcess`, the kernel parses the main image's Authenticode signature and looks for a specific Microsoft EKU OID that only the PMP signing root can issue [440]. If the EKU is present and the chain resolves to that root, the kernel flips the bit. On every subsequent `NtOpenProcess` against that process, the kernel strips a fixed set of access rights from the mask, no matter who is asking.

Alex Ionescu, then a Windows internals researcher, enumerated the denials in 2007 [441]:

> A typical process cannot perform operations such as the following on a protected process: Inject a thread into a protected process; Access the virtual memory of a protected process; Debug an active protected process; Duplicate a handle from a protected process; Change the quota or working set of a protected process.

Five denials. One bit. One certificate root. Ionescu's same essay, titled "Why Protected Processes Are A Bad Idea," made a structural argument that aged well: putting a DRM mechanism in the kernel is a category error. The mechanism is too narrow for non-DRM use because the only certificate accepted is Microsoft's PMP signing root, and the only operations gated are the ones Hollywood cared about. Third parties cannot opt in, and Microsoft itself cannot graduate the level of trust. (Note: Ionescu's 2007 critique remains worth reading on its own merits. The argument that DRM-shaped kernel features tend to be reused for security mitigations and that this reuse changes their threat-model semantics is exactly what plays out over the next seven years [441].)

The seven-year pause is its own story. Vista shipped, Vista was followed by Windows 7, and Windows 7 was followed by Windows 8, and through all of it, the access-check primitive that protects `audiodg.exe` from administrators remained a DRM artifact. The primitive existed; the *graduated trust dimension* did not. Two parallel failures pushed Microsoft toward widening the encoding.

The first was Mimikatz. Benjamin Delpy's own project page describes the tool as able to extract plaintext passwords, hashes, PINs, and Kerberos tickets from memory [261]; by the Windows 8.1 design window, that capability had made the primitive gap unmistakable. The countermeasure of restricting `SeDebugPrivilege` was useless; an attacker who has SYSTEM has every privilege. What Mimikatz exploited was a primitive gap: the kernel had no way to say "lsass is protected against administrators but reachable from privileged Microsoft services."

The second was the CSRSS-gating weakness that Mateusz Jurczyk exposed in 2013. Jurczyk (who writes as `j00ru`) cataloged more than seventy Win32k system calls that the kernel guarded with the pattern `if (PsGetCurrentProcess() != gpepCsrss) return STATUS_ACCESS_DENIED;` [442]. That gating mechanism worked only as long as nobody could inject code into `csrss.exe`. On Windows 8 RT, an attacker who could inject into `csrss.exe` could bypass Microsoft's locked-down Surface RT shell. Ionescu later observed that "In Windows 8.1 RT, this jailbreak is 'fixed', by virtue that code can no longer be injected into Csrss.exe for the attack" [432]. The fix made `csrss.exe` a PPL at the `WinTcb` rung, and the same machinery was generalized to `lsass.exe` and the Antimalware tier.

> **Two failures, one fix.** Mimikatz proved Microsoft needed a graduated trust dimension for `lsass.exe`. The j00ru CSRSS-gating weakness proved Microsoft needed it for `csrss.exe` too. The same widening of the encoding answered both.
>
> **Walkthrough: From Vista's single bit to Windows 8.1's structured byte.** Vista's protected process model answered one narrow DRM question: is this process admitted to the Protected Media Path, and therefore should ordinary user-mode processes be denied dangerous handles to it? Windows 8.1 generalized that yes/no answer into a byte. The low bits say what kind of protection applies (`None`, `ProtectedLight`, or `Protected`), the middle audit bit records a policy knob, and the high nibble says *which signer class* admitted the process. That last field is what made the mechanism useful outside DRM: antimalware, LSA, Windows, and WinTcb could now be ordered rather than merely marked protected or not protected.
>
> **Aside. Why this matters historically.** The DRM-to-credentials repurposing is not unique to PPL. The same pattern recurs across this chain: HVCI began as a Hyper-V kernel-mode integrity feature and was generalized into the code-integrity enforcer the Code Integrity chapter (Chapter 8) dissects, and the trustlet model began as Credential Guard plumbing and became the VTL1 execution substrate the VBS Trustlets chapter (Chapter 7) catalogs. Kernel mechanisms born in one threat model rarely stay confined to it. Which is why reading any one link of this chain in isolation under-predicts where its primitive ends up.

Microsoft already had the access-check primitive. What it didn't have, in 2007, was a way to ask "how much trust does this process carry?" The fix would not arrive until Windows 8.1 in October 2013, and when it arrived, it would fit in a single byte.

## `_PS_PROTECTION`: The single-byte encoding

The 8.1 fix is so compact it fits in a single byte. Ionescu's Part 1 of the "Evolution of Protected Processes" series, published November 22, 2013, gives the kernel structure verbatim [431]:

```c
typedef struct _PS_PROTECTION {
    union {
        UCHAR Level;
        struct {
            UCHAR Type   : 3;
            UCHAR Audit  : 1;
            UCHAR Signer : 4;
        };
    };
} PS_PROTECTION, *PPS_PROTECTION;
```

Three fields. One byte. The union with `Level:UCHAR` exists so that two `_PS_PROTECTION` values can be compared with a single byte load and a single byte compare. The kernel does this on every `NtOpenProcess`. Speed matters; this is the hot path of the security model.

> **Definition, `_PS_PROTECTION` byte**
> The kernel structure that encodes a process's protection state in eight bits: three bits of Type (`None`, `ProtectedLight`, `Protected`), one bit of Audit (intended as a forensic side-channel hint, although the exact runtime semantics are not enumerated in the public sources cited here), and four bits of Signer rung. Stored as `EPROCESS.Protection`.

The Type field has three values. `PsProtectedTypeNone = 0` marks a regular process. `PsProtectedTypeProtectedLight = 1` marks a PPL: the graduated path introduced in 8.1. `PsProtectedTypeProtected = 2` marks a "heavy" Vista-style PP. Heavy PPs still exist; they retain the original DRM semantics where almost nothing from below the protection level may touch them. PPLs are the new general-purpose path where the *signer rung* mediates a graduated lattice.

The Audit bit is the least documented of the three fields. Ionescu Part 1 lists it as `Audit: Pos 3, 1 Bit` with no semantic gloss; itm4n's RunAsPPL header annotates it as `// Reserved`; Microsoft Learn enumerates CodeIntegrity events `3033`, `3063`, `3065`, and `3066`, but those are triggered by the `AuditLevel` configuration under `Image File Execution Options\LSASS.exe` and concern DLL-load failures, not per-process `OpenProcess` denials [431] [328] [436]. The field's name implies a forensic side-channel, and the bit-position is reserved; the precise runtime emission shape is not enumerated in the public sources cited here.

The Signer field is the structurally interesting one. Ionescu's 2013 enumeration names eight values [431]:

| Signer constant | Value | Used for |
|---|---|---|
| `PsProtectedSignerNone` | 0 | Non-protected (no rung) |
| `PsProtectedSignerAuthenticode` | 1 | Generic third-party Authenticode (early PPL guests) |
| `PsProtectedSignerCodeGen` | 2 | .NET native runtime code generators |
| `PsProtectedSignerAntimalware` | 3 | EDR / AV daemons admitted via ELAM |
| `PsProtectedSignerLsa` | 4 | `lsass.exe` under `RunAsPPL` |
| `PsProtectedSignerWindows` | 5 | Microsoft Windows components below TCB |
| `PsProtectedSignerWinTcb` | 6 | `csrss.exe`, `WerFaultSecure.exe`: the inbox TCB |
| `PsProtectedSignerMax` | 7 | Sentinel in Ionescu's 2013 baseline; later builds insert `WinSystem` (7) and `App` (8) and push the sentinel to 9 (see the note below) |

> **The enumeration is not closed.** Ionescu's 2013 list is the authoritative *baseline* enumeration. It is not a permanent enumeration. By 2018, James Forshaw's PowerShell tooling (`NtApiDotNet`) was enumerating an additional `App = 8` signer used for AppContainer / TruePlay scenarios [440]. Newer builds of Windows extend the enumeration further. This chapter names `WinTcb` (Microsoft's documented inbox-TCB rung) and `Antimalware` (the only non-Microsoft-admissible rung) repeatedly, because they are the load-bearing ones. The intermediate values evolve.

 (Note: Adjacent to `EPROCESS.Protection` are two related fields, `EPROCESS.SignatureLevel` and `EPROCESS.SectionSignatureLevel`, which Ionescu introduces in Part 3 [433]. These fields encode the *binary integrity* the kernel demands at process creation and at every subsequent section load, and they are filled in from a 16-entry Signing Level table that runs from `Unchecked = 0` up to `Windows TCB = 14`. The Signer rung in `Protection` answers "what kind of trust does this process hold?" The SignatureLevel pair answers "what binaries is this process allowed to map?" They are not the same question.)

Now the worked decode. Given the byte value `0x41`, the encoding falls out by hand:

- Low three bits (Type): `0x41 & 0x07 = 0x01`, `PsProtectedTypeProtectedLight`.
- Bit 3 (Audit): `(0x41 >> 3) & 0x01 = 0`, Audit off.
- High four bits (Signer): `(0x41 >> 4) & 0x0F = 0x04`, `PsProtectedSignerLsa`.

A process with `EPROCESS.Protection = 0x41` is a PPL signed at the `Lsa` rung. That is exactly what `lsass.exe` looks like on a host with `RunAsPPL = 1`. Ionescu's blog explicitly states: "it's easy to read 0x41 as Lsa (0x4) + PPL (0x1)" [431]. The Defender service `MsMpEng.exe`, signed at the Antimalware rung, has `Protection = 0x31`. The Client/Server Runtime Subsystem `csrss.exe`, signed at WinTcb, has `Protection = 0x61`.

> **Walkthrough: Decoding `_PS_PROTECTION` by hand.** Treat the byte as three questions. First, mask with `0x07`: a result of `1` means Protected Process Light. Second, shift right three and mask with `1`: that is the audit bit. Third, shift right four: the high nibble is the signer rung. The common values now become readable without a debugger extension: `0x31` is signer `3` plus type `1`, so `PPL/Antimalware`; `0x41` is `PPL/Lsa`; `0x61` is `PPL/WinTcb`. If the byte is `0x00`, no PPL lattice is in force for that process.

> **The encoding in one sentence.** One byte, three fields, eight signer rungs. The kernel reads it on every `OpenProcess`, before any token check, before any ACL evaluation. The encoding is the entire vocabulary the kernel has for asking *how trusted* a process is.

The encoding tells the kernel *what kind* of trust a process holds. It says nothing about *who can touch whom* across rungs. That rule (the lattice) is the structure imposed on top of the bytes.

## The signer lattice. who can open whom

itm4n's 2021 walkthrough states the three rules verbatim, and they have the rare quality of being short enough to memorise [434]:

> A PP can open a PP or a PPL with full access if its signer type is greater or equal. A PPL can open a PPL with full access if its signer type is greater or equal. A PPL cannot open a PP with full access, regardless of its signer type.

Three rules. They settle every cross-process access question PPL gates. Let us name them and then read off their consequences.

**Rule 1.** A PP at signer $S_c$ may open with full access a PP or PPL at signer $S_t$ if and only if $S_c \ge S_t$.

**Rule 2.** A PPL at signer $S_c$ may open with full access a PPL at signer $S_t$ if and only if $S_c \ge S_t$.

**Rule 3.** A PPL cannot open a PP with full access, regardless of signer.

The qualifier "with full access" is load-bearing. PPL's lattice gates the *full* mask: `PROCESS_VM_READ`, `PROCESS_VM_WRITE`, `PROCESS_CREATE_THREAD`, `PROCESS_DUP_HANDLE`, `PROCESS_ALL_ACCESS`. A separate *limited* mask (`SYNCHRONIZE`, `PROCESS_QUERY_LIMITED_INFORMATION`, `PROCESS_SET_LIMITED_INFORMATION`, `PROCESS_SUSPEND_RESUME`, and sometimes `PROCESS_TERMINATE`) is allowed when the security descriptor permits. The target rung matters. Ionescu's verbatim `RtlProtectedAccess[]` table widens the deny mask from `0xFC7FE` to `0xFC7FF` for `Antimalware`, `Lsa`, and `WinTcb` targets: one extra bit, bit 0, which is `PROCESS_TERMINATE` [432]. So an administrator can still call `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,...)` against a protected `lsass.exe` to enumerate threads, but cannot terminate a `PPL/Antimalware`, `PPL/Lsa`, or `PPL/WinTcb` target via a direct kill. The lattice does not lock the process; it locks the *interesting* access, and for those target rungs it also locks the kill.

![Figure: The signer lattice as a 6×6 dominance grid: caller signer rung (rows) against target signer rung (columns). A caller opens a target with full access if and only if its rung is greater-or-equal to the target's, so the grant region is the lower-left triangle (green ✓) and the denied region is the upper-right (oxblood ✗: where only the limited mask still applies per the target's DACL). The gold-outlined diagonal marks equal-rung peers: the ≥ boundary, where every PPL can open another at its own rung.](diagrams/18-ppl-signer-lattice.svg)

| Caller signer \ Target signer | None | Authenticode (1) | Antimalware (3) | Lsa (4) | Windows (5) | WinTcb (6) |
|---|---|---|---|---|---|---|
| None (admin, integrity SYSTEM) | full | denied | denied | denied | denied | denied |
| PPL/Authenticode (1) | full | full | denied | denied | denied | denied |
| PPL/Antimalware (3) | full | full | full | denied | denied | denied |
| PPL/Lsa (4) | full | full | full | full | denied | denied |
| PPL/Windows (5) | full | full | full | full | full | denied |
| PPL/WinTcb (6) | full | full | full | full | full | full |

Where "denied" means the *full* mask is rejected; the limited mask continues to apply per the target's security descriptor. CodeGen (`PsProtectedSignerCodeGen = 2`) is omitted from the teaching grid for clarity; it follows the same greater-or-equal dominance rule between Authenticode and Antimalware.

> **Walkthrough: Reading the signer lattice.** Put unprotected processes at the floor. Above them are Authenticode, CodeGen, Antimalware, Lsa, Windows, and WinTcb. Now ask only two questions: what signer rung does the caller carry, and what signer rung does the target carry? Equal or higher callers can receive the dangerous access bits to lower or peer targets. Lower callers cannot receive memory-read, memory-write, duplicate-handle, create-thread, or termination-style rights upward. The rule is deliberately independent of group membership and token privilege: local administrators, SYSTEM services, and debug-privileged tools remain at signer `None` unless they themselves launched as a protected process with an admitted signer.

The Enhanced Key Usage side of the design holds the lattice together. Microsoft's EKU OID arc `1.3.6.1.4.1.311.10.3.*` defines sub-OIDs per signer rung [443] [444], and at process creation the kernel parses the main image's Authenticode signature and walks its EKU extensions to determine which rung the binary is entitled to claim. If the certificate chain resolves cleanly to a Microsoft-issued root *and* carries the rung's sub-OID, the kernel records the rung. Otherwise the process either starts unprotected or refuses to start at all.

> **Definition: Enhanced Key Usage (EKU)**
> An X.509 v3 certificate extension that asserts what specific purposes a certificate is allowed to certify. Microsoft uses sub-OIDs under `1.3.6.1.4.1.311.10.3.*` to encode protected-process signer rungs as EKU values [443] [444]. The kernel checks the EKU at process creation; the certificate chain anchors which Microsoft-issued sub-CA may issue at each rung. (Note: The IANA Private Enterprise Number `311` is registered to Microsoft under the PEN prefix `1.3.6.1.4.1.` [443], so `1.3.6.1.4.1.311.*` is the catch-all namespace for Microsoft-specific X.509 extensions; the `10.3.*` arc within it is the Microsoft Enhanced Key Usage (purpose) sub-tree [444], and `10.3.<n>` slots map to specific signer purposes including protected-process rungs.)

The most important property of this design is the resolution point. The kernel parses the EKU exactly once, at `NtCreateUserProcess`. It stores the resulting rung in `EPROCESS.Protection`. On every subsequent `OpenProcess` against that process, the kernel consults the byte, not the certificate. This makes the access check fast (one byte load, one byte compare) and decouples policy at runtime from policy at signing time. It also creates the structural seam that every public bypass since 2018 has exploited, because the kernel's confidence in the byte is exactly the confidence it had in the certificate at process-create time, projected forward indefinitely.

Ionescu's Part 2 names the implementation directly. The lattice is not code; it is a data table named `RtlProtectedAccess[]` baked into `ntoskrnl.exe` [432]. Each row of that table corresponds to a (signer, target-type) pair and encodes which access bits are allowed in the full mask. The relevant runtime routines are `PspProcessOpen` and `PspThreadOpen` (the object-manager open callbacks), `PspCheckForInvalidAccessByProtection` (which performs the check), `RtlTestProtectedAccess` (which applies the lattice row), and `RtlValidProtectionLevel` (which sanity-checks the encoded byte for consistency).

> **The lattice is data, not code.** The decision of who can touch whom is encoded in a table inside `ntoskrnl.exe`. Changing the lattice means changing a table; widening or narrowing it does not require new code. This is why Microsoft can add `App = 8` to the enumeration over time without touching the access-check routine.

Note one symmetry that becomes important later. "Greater or equal" means that within a rung, every PPL can read every other PPL. Two co-resident `PPL/Antimalware` daemons (Microsoft Defender's `MsMpEng.exe` and a third-party EDR's agent) can call `PROCESS_VM_READ` on each other. Within-rung peers leak to each other by design. The lattice prevents *escalation*, not *peer access*.

The lattice settles the rule. The next question is admission: who decides which binaries are allowed to claim the Antimalware rung, and how does Microsoft admit third-party code into it at all? The answer is a driver.

## The Antimalware rung: ELAM and third-party code at PPL

PPL is interesting only if it admits non-Microsoft code at *some* rung. The Vista PP design admitted nobody outside Microsoft's protected-media path; eligibility was tied to the PMP signing chain. PPL inherited that constraint at every rung except one. The Antimalware rung (signer value `3`) is the only rung where third-party vendors can ship their own user-mode binaries as protected processes. The admission mechanism is the Early Launch Anti-Malware driver.

> **Definition: Early Launch Anti-Malware (ELAM)**
> A specially signed Microsoft-certified kernel driver shipped by an anti-malware vendor that loads before any other boot-start driver. The ELAM driver participates in trusted-boot measurement, vouches for follow-on drivers, and (critical to PPL) carries an embedded resource section enumerating the vendor's user-mode signing certificate hashes. The kernel uses that resource section to admit the vendor's user-mode daemon binaries to `PPL/Antimalware` at service start.

Microsoft Learn's "Protecting Anti-Malware Services" page describes the boot-time admission flow in two sentences [327]:

> The driver must have an embedded resource section containing the information of the certificates used to sign the user mode service binaries. During the boot process, this resource section will be extracted from the ELAM driver to validate the certificate information and register the anti-malware service.

Two consequences. First, the third-party signer set is bounded by a *kernel-readable resource section*, not by an open EKU. Microsoft, not the vendor, controls which user-mode binaries are admissible. Second, the signing-certificate information is baked into the driver at signing time and re-validated at every service start. A vendor cannot widen the admissible signing-certificate set after the fact; an attacker cannot admit their own user-mode binary unless it is signed by a certificate already registered in the driver's resource section and it satisfies the protected-service code-integrity policy.

The gate that decides which vendors get ELAM drivers in the first place is the Microsoft Virus Initiative. Microsoft Learn's MVI criteria page enumerates the requirement explicitly [437]:

> Your security solution must be certified within the last 12 months by at least one of the organizations listed below: AV-Comparatives, AVLab Cybersecurity Foundation, AV-Test, MRG Effitas, SE Labs, SKD Labs, VB 100, West Coast Labs.

The same page requires "use of Trusted Signing," Microsoft's cloud-managed code signing service. The implications are operational. To ship code at `PPL/Antimalware`, a vendor must (a) hold MVI membership, (b) maintain independent-lab certification, (c) author an ELAM driver, (d) get the driver through Microsoft WHQL and have it Microsoft co-signed, and (e) embed the user-mode certificate hashes in the driver's resource section.

> **Definition: Microsoft Virus Initiative (MVI)**
> A Microsoft program for anti-malware vendors that gates access to ELAM driver signing and to specific Defender APIs. Membership requires independent-lab certification (renewed annually) and Trusted Signing usage; in practical terms, MVI membership is the entry ticket to deploying user-mode binaries at `PPL/Antimalware`.
>
> **Aside. Hobbyist tooling cannot join the Antimalware rung.** The implication of MVI is that an indie security tool, however technically sound, cannot deploy as `PPL/Antimalware`. The gate is not technical but commercial: independent-lab certification fees, annual renewals, and the engineering investment of building a production-grade ELAM driver. The signer rung is *signed*; the signing program is *gated*.
>
> **Walkthrough: ELAM admission to `PPL/Antimalware`.** The vendor cannot simply set a registry value and become protected. At boot, Windows loads the vendor's Early Launch Antimalware driver early enough to establish trust before ordinary services start. Code Integrity reads the driver's embedded resource section, extracts the user-mode signing-certificate hashes that Microsoft accepted through the MVI / WHQL path, and caches those hashes as the vendor's admission list. Later, when the Service Control Manager starts the antimalware daemon, CI compares the daemon's signature chain to that cached ELAM material. Only a match launches at signer rung `3`, type `1`: the `0x31` byte defenders should verify.

By 2024, major commercial EDR products commonly ship through this path. Microsoft Defender's `MsMpEng.exe` uses the inbox `WdBoot.sys` ELAM driver (Note: `WdBoot.sys` ("Windows Defender Boot Driver") is Microsoft's inbox first-party ELAM driver; it ships in every Windows install and is loaded before any third-party ELAM driver. The canonical reference implementation of the ELAM resource-section pattern is Microsoft's `Windows-driver-samples/security/elam` repository [445], which also documents the Early Launch EKU `1.3.6.1.4.1.311.61.4.1` verbatim.). Third-party members of Microsoft's Virus Initiative (the cohort gated by the MVI criteria quoted above [437]) ship their own vendor ELAM drivers and run their main user-mode daemons at `PPL/Antimalware`. Microsoft Learn's "Early Launch Antimalware" page is the canonical confirmation [42]:

> Because an ELAM service runs as a PPL (Protected Process Light), you need to debug using a kernel debugger.

One Microsoft-signed sentence and a billion endpoints. EDR vendors get protection against administrator-level tampering for free, on top of the kernel telemetry their drivers already collect. Microsoft gets a viable third-party security market without widening the EKU gates beyond a controllable set of vendors.

ELAM admits the *daemon*. The next operational question is what Microsoft does for `lsass.exe` itself: the canonical credential store, the original Mimikatz target. The mechanism is called `RunAsPPL`.

## RunAsPPL, hardening LSASS

The registry value that produced the Mimikatz failure in the opening section is a single DWORD. itm4n's walkthrough names it verbatim [328]:

> Open the key `HKLM\SYSTEM\CurrentControlSet\Control\Lsa`; add the DWORD value `RunAsPPL` and set it to 1; reboot.

After reboot, `lsass.exe` launches at `PPL/Lsa`, signer rung 4, protection byte `0x41`. Mimikatz running with full SYSTEM-integrity and `SeDebugPrivilege` then receives `0x00000005` on `OpenProcess(PROCESS_VM_READ, lsass.exe)`. The registry knob is one DWORD; the consequences are large.

> **Definition: Local Security Authority Subsystem Service (LSASS)**
> The Windows user-mode process that holds NTLM password hashes, Kerberos Ticket Granting Tickets, MSV1_0 credential caches, DPAPI master keys, and (on legacy builds before Microsoft's 2014 KB2871997 update [446]) WDigest plaintext passwords. The canonical target of credential-theft tooling since 2011.

The threat being mitigated is simple. Mimikatz reads LSASS memory via `OpenProcess(PROCESS_VM_READ, lsass.exe)`, walks the internal key-store structures, and extracts NTLM hashes, Kerberos session keys, and (on older configurations) cached plaintext. Restricting `SeDebugPrivilege` does not work, because an attacker with SYSTEM has every privilege. Restricting the security descriptor on `lsass.exe` does not work either, because legitimate services need to interact with it. PPL is the right primitive: it gates the *full* mask irrespective of token state, and the kernel admits only Microsoft-signed code into the `Lsa` rung.

`RunAsPPL = 1` is the stronger form of the setting on Secure Boot-capable machines. On the next boot, the kernel automatically mirrors the policy into a Secure Boot-anchored UEFI variable; once set, the protection survives registry rollback. An attacker who removes the registry key finds that LSASS still launches as PPL on the next boot. The only path to remove the protection is to disable Secure Boot at the firmware level, which requires physical access and which trips other defenses. Microsoft Learn's documentation describes it verbatim [436]:

> You can achieve further protection when you use Unified Extensible Firmware Interface (UEFI) lock and Secure Boot. When these settings are enabled, disabling the `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa` registry key has no effect.

This is `RunAsPPL = 1`. For environments that need admin-removable protection without the UEFI lock, `RunAsPPL = 2` (available on Win11 22H2 and later) omits the UEFI variable. The policy lives in the registry only and is removable by any administrator (or by malware running as administrator) who simply deletes the registry value before reboot.

| `RunAsPPL` value | Behavior | Removable by? | Persistence |
|---|---|---|---|
| `0` (or absent) | LSASS runs unprotected | n/a | none |
| `1` | LSASS runs as PPL/Lsa; policy mirrored to UEFI variable on Secure Boot machines | Physical access + Secure Boot disable | Firmware-anchored |
| `2` | LSASS runs as PPL/Lsa; registry only (Win11 22H2+ only) | Any admin who deletes the key | Registry only |

> **UEFI lock survives registry rollback.** The `RunAsPPL = 1` setting is the practical answer to "what stops an attacker who is willing to reboot?" Once the UEFI variable is set, neither registry rollback nor PE-based offline attacks on the registry hive can disable LSA protection on the next boot.

The deployment cost of `RunAsPPL` is compatibility with third-party authentication modules. LSASS hosts a set of plug-ins: smart-card middleware, third-party Cryptographic Service Providers (CSPs), password-filter DLLs, alternative authentication packages. Under `RunAsPPL`, the kernel demands that every DLL loaded into LSASS carry a Microsoft signature with the appropriate EKU. The enforcement comes from LSASS's section signing-level (the `SectionSignatureLevel` from the earlier decode), not from the process Signer rung. Vendor DLLs that lack the right EKU are rejected at section creation. The rejections surface as CodeIntegrity events in the system event log. Microsoft Learn enumerates the two relevant event IDs [436]:

> Event 3065 occurs when a code integrity check determines that a process, usually LSASS.exe, attempts to load a driver that doesn't meet the security requirements for shared sections.
>
> Event 3066 occurs when a code integrity check determines that a process, usually LSASS.exe, attempts to load a driver that doesn't meet the Microsoft signing level requirements.

In these Code Integrity event templates, "driver" is Microsoft's wording for the user-mode DLL or image being validated: LSASS is a user-mode process and loads user-mode modules (SSPs, authentication packages), not kernel-mode drivers.

This is why Microsoft recommends running the setting in *audit mode* before enforcement. Audit mode is enabled by setting a separate `AuditLevel` DWORD to `8`, but (critically) under a *different* registry key from the one that hosts `RunAsPPL`. Microsoft Learn places `AuditLevel` under the Image File Execution Options hive for `LSASS.exe` and names the path verbatim [436]:

> Open the Registry Editor, or enter RegEdit.exe in the Run dialog, and then go to the `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe` registry key. Open the `AuditLevel` value. Set its data type to `dword` and its data value to `00000008`.
>
> **Two values, two hives: read this twice.** `RunAsPPL` sits under `HKLM\SYSTEM\CurrentControlSet\Control\Lsa`. `AuditLevel = 8` sits under `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe`. A defender who edits "the same key" silently sets the wrong value and audit mode never engages. The deployment looks correct from the registry; the log surface is empty; the rollout breaks production on enforcement day. Two values. Two hives. Read this twice.

In audit mode, the kernel emits the same 3065 / 3066 events for would-be load rejections but allows the loads to proceed. Two months of audit-mode telemetry typically surfaces every smart-card middleware DLL, every password-filter, every third-party CSP on a corporate fleet. Once the audit log is clean (every vendor's modules have been re-signed at the LSA level or replaced), enforcement mode can be turned on without breaking production logins.

> **Audit before enabling.** Skipping audit mode is the most common cause of LSA protection rollouts being rolled back after a wave of authentication failures. See the deployment checklist below for the full audit-then-enforce-then-UEFI-lock recipe.

The deployment cadence has been deliberately glacial. `RunAsPPL` shipped in Windows 8.1 in October 2013, *opt-in*. It remained opt-in for nine years. Microsoft Learn records the inflection [436]:

> Audit mode for added LSA protection is enabled by default on devices running Windows 11 version 22H2 and later.

Audit mode default-on. Not enforcement. Microsoft documents a separate automatic-enablement path for added LSA protection on new Windows 11 22H2+ client installs that are enterprise joined and HVCI-capable, and it explicitly says that automatic path does not set the UEFI variable [436]. The Windows 11 24H2 release expanded the rollout further. Eleven years from opt-in to audit default, and then to conditional automatic enforcement. The pace reflects the compatibility risk: every domain with a single non-Microsoft-signed LSASS plug-in would have surfaced as a support call.

The registry knob is simple. The *kernel* check that enforces it is not: the structural reason `SeDebugPrivilege` cannot help an attacker is the order in which the kernel asks its questions.

## Proof you can reproduce on a live machine

This chapter does not contain a lab capture. Instead, this section is a reproducibility harness: it tells you exactly which Windows observations prove that PPL is active, what each observation means, and where a false conclusion can enter. The evidence grade remains 🔵 **DOCUMENTED** because the outputs are expected shapes from the cited Windows interfaces, not bytes captured from the author's VM. The gatekeeping point is still concrete: a reader can run the probes on a Windows host and tie each result to the `_PS_PROTECTION` byte, the LSASS deployment knobs, and the user-mode denial symptom.

> 🔵 **DOCUMENTED**: `RunAsPPL` policy location and interpretation; reproducible on a Windows host.

```powershell
reg query HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL
```

Expected output when LSASS is configured to run as PPL with the Secure Boot / UEFI lock:

```text
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa
RunAsPPL REG_DWORD 0x1
```

Expected output for the softer Windows 11 22H2+ registry-only mode:

```text
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa
RunAsPPL REG_DWORD 0x2
```

The registry value proves policy intent, not runtime state. `0x1` means the kernel should persist LSA protection through a UEFI variable on Secure Boot-capable systems. `0x2` means enable the protection without the firmware lock. Neither value alone proves that this boot's `lsass.exe` actually carries signer `Lsa` and type `ProtectedLight`; a failed boot-time policy application, unsupported platform, or disabled Secure Boot can still leave the runtime byte at `0x00`. That is why the next probe reads the process state rather than the deployment knob.

> 🔵 **DOCUMENTED**: runtime protection byte for LSASS; reproducible with kernel debugging or a trusted process-inspection tool.

```text
kd> !process 0 7 lsass.exe
...
Protection: PsProtectedSignerLsa-Light
```

The string form decodes to the byte discussed earlier: signer `Lsa` (`4`) in the high nibble and type `ProtectedLight` (`1`) in the low bits, therefore `0x41`. Process Explorer and System Informer expose the same fact through a "Protection" column; WinDbg exposes it closest to the kernel object. Treat this as the decisive proof that the running process is protected. A host with `RunAsPPL` configured but `Protection: None` has a deployment failure. A host with `Protection: PsProtectedSignerLsa-Light` but no audit history may be protected and still at risk of a future outage when an unsigned or incorrectly signed authentication plug-in is introduced.

> 🔵 **DOCUMENTED**: audit-mode compatibility check for LSASS plug-ins; reproducible before enforcement.

```powershell
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe" /v AuditLevel
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-CodeIntegrity/Operational'; Id=3065,3066} -MaxEvents 20 |
Select-Object TimeCreated, Id, ProviderName, Message
```

Expected output shape during a clean audit period is `AuditLevel REG_DWORD 0x8` and no recurring 3065 / 3066 events for production authentication plug-ins. If events appear, the payload names the image that would fail once enforcement is enabled. Event 3065 points at the shared-section requirement; event 3066 points at the Microsoft signing-level requirement. The common mistake is to confuse this `AuditLevel` hive with `RunAsPPL`: the first asks Code Integrity to warn about LSASS plug-ins, while the second asks the kernel to launch LSASS as PPL.

> 🔵 **DOCUMENTED**: user-mode symptom when `lsass.exe` is protected; reproducible with any tool that requests forbidden memory access.

```text
mimikatz # privilege::debug
Privilege '20' OK
mimikatz # sekurlsa::logonpasswords
ERROR kuhl_m_sekurlsa_acquireLSA; Handle on memory: (0x00000005) Access is denied
```

This proves the user-mode symptom, not the root cause by itself. The same Win32 error can be produced by other access-denial paths. In the PPL case the explanation is the ordered kernel path: the process-open logic compares the caller's and target's protection bytes before `SeAccessCheck` can let `SeDebugPrivilege` rescue the request. A complete proof therefore has three legs: the policy exists (`RunAsPPL`), the runtime byte is `PPL/Lsa` (`0x41` or `PsProtectedSignerLsa-Light`), and a lower-signer memory-read handle fails while ordinary administrative access elsewhere still works.

A useful lab notebook records the three observations in one table:

| Observation | Expected protected value | What it proves | What it does not prove |
|---|---|---|---|
| `HKLM\...\Lsa\RunAsPPL` | `0x1` or `0x2` | Deployment intent | Runtime protection on this boot |
| `EPROCESS.Protection` / tool "Protection" column | `PsProtectedSignerLsa-Light` / `0x41` | LSASS is `PPL/Lsa` | Credential material is outside LSASS |
| Mimikatz or equivalent memory-read attempt | `ERROR_ACCESS_DENIED` after debug privilege succeeds | Lower-signer handle denial | Absence of kernel or PPL-bypass risk |
| CodeIntegrity 3065 / 3066 audit stream | No recurring production plug-in failures | Compatibility readiness | That future plug-ins will remain compliant |

That table is the reason this chapter keeps PPL separate from Credential Guard. `0x41` proves LSASS is protected from lower-signing VTL0 user-mode processes. It does not prove the secrets have moved to VTL1. The latter requires Credential Guard state, which belongs to the companion boundary section.

## The kernel access check: What happens inside `NtOpenProcess`

Recall the trace from the opening section. The denial happens before `SeAccessCheck` runs. The reason `SeDebugPrivilege` does not help is not that the kernel decided to override the privilege; it is that the kernel never asked about the privilege. The order matters. Let us walk it.

The Win32 caller invokes `OpenProcess`, which thunks through `kernel32.dll` to the syscall `NtOpenProcess`. `NtOpenProcess` does its handle-lookup and dispatches to the process-type object-manager open callback, `PspProcessOpen`. Ionescu's Part 2 names the path verbatim [432]:

> Access to protected processes (and their threads) is gated by the `PspProcessOpen` and `PspThreadOpen` object manager callback routines, which perform two checks. The first, done by calling `PspCheckForInvalidAccessByProtection` (which in turn calls `RtlTestProtectedAccess` and `RtlValidProtectionLevel`)...

`PspCheckForInvalidAccessByProtection` does two things. First, it splits the caller's requested access mask into two subsets:

- The **limited mask**. A fixed set of bits (`SYNCHRONIZE`, `PROCESS_QUERY_LIMITED_INFORMATION`, and a small handful of others) that the lattice never forbids. The limited mask is subject only to the standard `SeAccessCheck` against the target's DACL.
- The **full mask**. Everything else, including `PROCESS_VM_READ`, `PROCESS_VM_WRITE`, `PROCESS_CREATE_THREAD`, `PROCESS_DUP_HANDLE`, and `PROCESS_ALL_ACCESS`. The full mask is subject to the lattice rule.

> **Definition: Limited Access Mask**
> The subset of `PROCESS_*` access rights that the PPL lattice allows the standard `SeAccessCheck` to evaluate after the protection check has pruned the dangerous bits. Includes `SYNCHRONIZE`, `PROCESS_QUERY_LIMITED_INFORMATION`, `PROCESS_SET_LIMITED_INFORMATION`, and `PROCESS_SUSPEND_RESUME`. `PROCESS_TERMINATE` depends on the target's protected-access row: Ionescu's table uses deny mask `0xFC7FE` where termination remains outside the denied set, but widens the deny mask to `0xFC7FF` for `Antimalware`, `Lsa`, and `WinTcb` targets (bit 0, `PROCESS_TERMINATE`) making those target rungs unkillable except from peers or higher.

Second, it indexes into `RtlProtectedAccess[]` using the caller's signer rung and the target's type, retrieves the row of permissible access bits, and ANDs the row with the full mask. If the result is non-empty, the access proceeds; if the result is zero, the kernel strips the full-mask bits from the request and returns either the limited subset (if the caller asked for any limited bits) or `STATUS_ACCESS_DENIED`. `RtlValidProtectionLevel` runs alongside as a sanity check on the encoded byte to catch malformed `EPROCESS.Protection` values that would otherwise let the lattice walk off the end of the table.

![Figure: The ordering inside NtOpenProcess that makes PPL work. OpenProcess → NtOpenProcess → PspProcessOpen → PspCheckForInvalidAccessByProtection, which splits the requested mask: the full mask (PROCESS_VM_READ / WRITE / CREATE_THREAD) is run through RtlTestProtectedAccess (indexing RtlProtectedAccess[] by the caller's signer rung and the target's type) and is stripped when the caller's rung is below the target's, so it never reaches SeAccessCheck; only the limited mask survives. SeDebugPrivilege is weighed only at the SeAccessCheck box, after the lattice has already pruned the dangerous bits. Which is why a SYSTEM administrator still receives STATUS_ACCESS_DENIED on the read.](diagrams/18-ppl-access-check.svg)

> **Walkthrough: `NtOpenProcess` in the order that matters.** The caller supplies a desired access mask. The object manager resolves the target process object and enters the process-specific open path. Before the DACL can grant the requested mask, the PPL guard computes whether the caller's `_PS_PROTECTION` can dominate the target's `_PS_PROTECTION`. If not, `PspCheckForInvalidAccessByProtection` and the `RtlTestProtectedAccess` logic remove or reject the rights that would pierce the target. Only the remaining mask is eligible for ordinary `SeAccessCheck`. That ordering is the whole feature: privileges can satisfy the security descriptor, but they do not rewrite the signer/type byte used by the lattice.
>
> **Key idea.** The protection check runs *before* `SeAccessCheck`. Privileges are evaluated by `SeAccessCheck`. The reason `SeDebugPrivilege` does not help is structural. It is not consulted at the moment of denial.

Four worked traces make this concrete.

**Case (a): admin → lsass with `PROCESS_ALL_ACCESS`.** The caller's `EPROCESS.Protection.Type` is `PsProtectedTypeNone` (`None`). The target is `PPL/Lsa`. The lattice forbids the full mask. The kernel strips every bit of `PROCESS_ALL_ACCESS` except the limited subset. The caller wanted to write memory; the limited subset cannot write memory; the operation effectively fails. This is the Mimikatz scenario.

**Case (b): admin → lsass with `PROCESS_QUERY_LIMITED_INFORMATION`.** Same caller, same target, but the requested mask sits entirely in the limited subset. The lattice does not gate the limited mask. `SeAccessCheck` evaluates the DACL on `lsass.exe`, finds that administrators are permitted to query basic process information, and the call succeeds. This is why Process Explorer can still enumerate `lsass.exe` and show its threads even when LSA protection is enabled.

**Case (c): `MsMpEng.exe` (PPL/Antimalware, rung 3) → `lsass.exe` (PPL/Lsa, rung 4) with `PROCESS_VM_READ`.** The lattice rule: caller rung 3 < target rung 4, so the full mask is denied. Defender cannot read LSASS memory. Defender does not need to; the cross-rung isolation prevents one Microsoft service from reading another Microsoft service's secrets even within the same trusted system.

**Case (d): hypothetical `PPL/WinTcb` (rung 6) → `lsass.exe` (PPL/Lsa, rung 4) with `PROCESS_VM_READ`.** The lattice rule: caller rung 6 >= target rung 4, so the full mask is allowed. A process signed at the WinTcb rung can read LSASS memory by design. This is how `WerFaultSecure.exe`, the WinTcb-signed Windows Error Reporting dumper, can still read protected `lsass.exe` to produce a crash dump.

| Caller | Target | Mask | Lattice rule | Outcome |
|---|---|---|---|---|
| Admin, no Protection | PPL/Lsa | PROCESS_ALL_ACCESS | Caller has no rung | Full mask stripped (denied) |
| Admin, no Protection | PPL/Lsa | PROCESS_QUERY_LIMITED_INFORMATION | Limited mask | Allowed (DACL permitting) |
| PPL/Antimalware (3) | PPL/Lsa (4) | PROCESS_VM_READ | 3 < 4 | Denied |
| PPL/WinTcb (6) | PPL/Lsa (4) | PROCESS_VM_READ | 6 >= 4 | Allowed |

The Audit bit revisits the table from a different angle. The bit is annotated `Reserved` in itm4n's public structure definition and named without semantic gloss in Ionescu Part 1; the precise runtime emission shape on an `OpenProcess` denial is not enumerated in any of Ionescu Part 1, Forshaw 2018, itm4n's RunAsPPL writeup, or Microsoft Learn's RunAsPPL page (whose CodeIntegrity events 3033/3063/3065/3066 are scoped to `AuditLevel` under `IFEO\LSASS.exe` and to DLL-load failures, not per-process Audit-bit denials) [431] [328] [436]. The field name and bit position imply a forensic side-channel; the exact event shape is not in the public record. (Note: Two adjacent kernel mechanisms exist in the same neighborhood but mediate different threat models. `PROCESS_TRUST_LABEL_ACE` (a Trust SID ACL entry, introduced in Windows 8.1 alongside PPL) is an ACL-side companion that runs *inside* `SeAccessCheck`. It adds a token-style trust label that interacts with the security descriptor in the standard way. Code Integrity Guard (`ProcessSignaturePolicy`) is a per-process *signed-image* enforcer settable at `CreateProcess` time via the `PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY` attribute. Neither is part of PPL; both interact with the same problem space.)

The kernel verifies who is asking, what they are asking for, and at what rung the target sits. What the kernel *cannot* verify is the behavior of code that arrives through a signed channel and then executes against attacker-controlled data. That structural seam is the entire premise of the bypass arms race.

## Where this link breaks: The bypass arms race

If the kernel only verifies the channel by which code enters a PPL, bypasses should attack the seam between channel and behavior. Test that prediction against the public record surveyed here: since 2018, four named bypass acts have hit major Microsoft research blogs, and all four sit in that structural class.

> **Key idea.** The public bypasses surveyed here attack one seam: what the channel proves (a signature, an EKU, a section identity) can diverge from what the code does once mapped.

### Act I (2018): Forshaw and JScript-into-PPL

James Forshaw, then at Google Project Zero, published "Injecting Code into Windows Protected Processes Using COM" in October 2018 [440]. The mechanism: a PPL can be made to instantiate a COM object whose CLSID resolves to `scrobj.dll`, the Microsoft-signed Windows Script Component scripting host. Once loaded into the PPL, the script object accepts attacker-supplied source code and executes it inside the protected process. The DLL is signed. The kernel admits it. The kernel cannot reason about the JScript source it then runs.

Microsoft's fix in Windows 10 1803 (April 2018, deployed broadly through that year) was a hardcoded deny-list in `CI.DLL`. Forshaw's own writeup gives the source verbatim [440]:

```c
UNICODE_STRING g_BlockedDllsForPPL[] = {
    DECLARE_USTR("scrobj.dll"),
    DECLARE_USTR("scrrun.dll"),
    DECLARE_USTR("jscript.dll"),
    DECLARE_USTR("jscript9.dll"),
    DECLARE_USTR("vbscript.dll")
};

NTSTATUS CipMitigatePPLBypassThroughInterpreters(
    PEPROCESS Process, LPBYTE Image, SIZE_T ImageSize)
{
    if (!PsIsProtectedProcess(Process)) return STATUS_SUCCESS;
    // walk g_BlockedDllsForPPL; if any match, return STATUS_DYNAMIC_CODE_BLOCKED
    ...
}
```

Five DLLs, hardcoded. Microsoft Learn corroborates the policy on the user-facing side [327]:

> The following scripting DLLs are forbidden by CodeIntegrity inside a protected process: scrobj.dll, scrrun.dll, jscript.dll, jscript9.dll, and vbscript.dll.

Channel: a Microsoft-signed DLL. Behavior: arbitrary attacker script. The fix narrows the channel by name-listing the five DLLs known to admit attacker behavior. The class survives. (Note: The mechanism was previewed at Recon Montreal 2018 in the joint Forshaw-Ionescu talk "Unknown Known DLLs and other Code Integrity Trust Violations" (June 15-17, 2018) [447]. Forshaw's August 2017 "Bypassing VirtualBox Process Hardening" essay [448] is the structural precursor. It makes the same channel-vs-behavior argument against a different kernel-supported process-hardening regime.)

### Act II (2018-2021): DefineDosDevice and PPLdump

In his August 2018 post on object-directory exploits [326], Forshaw added a single throwaway sentence that the security community would spend three years productising. itm4n quotes it verbatim in his 2021 SCRT walkthrough [434]:

> Abusing the DefineDosDevice API actually has a second use, it's an Administrator to Protected Process Light (PPL) bypass.

The mechanism, fully worked out by itm4n in April 2021, is structural and uses that same primitive. In gap-analysis terms, the bug was a confused-deputy path through `\KnownDlls\`: an administrator-controlled request reached `csrss.exe`, which runs at PPL/WinTcb (rung 6) and therefore had lattice authority over protected object directories. The administrator did not need to become a PPL; the administrator needed a higher-signer deputy to create a trusted object-manager name. A later PPL load then trusted the vouched-for `\KnownDlls\` section identity instead of re-validating the underlying image as though the administrator had supplied it directly.

The safe mechanical summary is five steps. First, the attacker controls the request, but not the signer rung. Second, CSRSS performs the object-directory operation from `PPL/WinTcb`, so the namespace write has a legitimacy the original caller lacked. Third, the loader in a newly created PPL consults the known-DLL namespace as a fast path. Fourth, that fast path supplies a section object rather than a fresh file-open-and-signature-verification path. Fifth, code becomes mapped inside a PPL even though the meaningful security question, "are these the bytes CI would have admitted from disk for this protected process?", was no longer checked at the point of use. The important lesson is the asymmetry, not the operator recipe: a trusted section-discovery channel outlived the signature property defenders thought it represented.

itm4n's PPLdump tool, published April 2021, automated the attack. The README test matrix lists every Windows version it ran against [449]. For fifteen months, an administrator could dump any PPL's memory, including `lsass.exe`, despite `RunAsPPL`.

Microsoft's fix arrived in build 19044.1826 (the July 2022 update to Windows 10 21H2). itm4n's "End of PPLdump" writeup describes the patch and the BinDiff diff verbatim [331]:

> The conclusion is that PPLs now appear to be behaving just like PPs and therefore no longer rely on Known DLLs.

The fix patched `LdrpInitializeProcess` in NTDLL to skip `\KnownDlls\` for PPL processes, behind a Velocity feature flag (`Feature_Servicing_2206c_38427506__private_IsEnabled`). PPLdump's repository README now opens with [449]:

> 2022-07-24 - As of Windows 10 21H2 10.0.19044.1826 (July 2022 update), the exploit implemented in PPLdump no longer works. A patch in NTDLL now prevents PPLs from loading Known DLLs.

itm4n's structural finding (that *PPLs honored `\KnownDlls\` while PPs did not*) is the most interesting failure in the eight-year run, because the asymmetry sat in plain sight from 2013 to 2022 and nobody had asked "why are PPs and PPLs loading sections differently?" The fix closes one asymmetry. The structural class survives. (Note: PPLdump's substitution chain uses NTFS transactions and Forrest Orr's "phantom DLL hollowing" technique to materialize the attacker-controlled section on disk in a way the kernel section creator will accept [450]. Orr's writeup is the original publication of the hollowing primitive; PPLdump composes it with the `\KnownDlls\` redirection trick.)

### Act III (2022-2024): Landau's PPLFault CI TOCTOU

Gabriel Landau, then at Elastic, presented "PPLdump Is Dead. Long Live PPLdump!" at Black Hat Asia 2023 [451]. The mechanism is a Time-Of-Check / Time-Of-Use bug at the section-creation layer.

> **Definition, TOCTOU (Time-Of-Check / Time-Of-Use)**
> A class of bug in which a security property is verified at one point in time but the underlying object is mutable between the check and the use. The protected resource passes its check, then changes between check and access, and the operation proceeds against the changed state without re-verification.

The TOCTOU here is subtle. When a PPL calls `NtCreateSection` on a Microsoft-signed DLL, the kernel's memory manager calls `MiValidateSectionCreate`, which calls into `ci.dll` to verify the file's Authenticode signature. The check succeeds. The section is created. But the memory manager does not page in the file contents at section-create time; it pages them in lazily, on demand, when threads first touch the mapped pages. If an attacker can keep the section's backing file *unsubstituted* during the signature check and substituted during the lazy page-in, the kernel will execute attacker bytes through a section whose signature it already verified.

Landau's exploit uses Windows' CloudFilter API. An attacker holds an exclusive oplock on a Microsoft-signed DLL during the section-create signature check. After the check passes, the attacker's CloudFilter `FetchDataCallback` provides different bytes (the payload) when the kernel pages in the section. The PPL maps and executes the payload. Landau's Elastic post documents the chain verbatim [452]:

> The internal memory manager function `MiValidateSectionCreate` relies on the Code Integrity module `ci.dll` to handle the requisite cryptography and PKI policy.

Microsoft's fix shipped in Windows Insider Canary build 25941 on September 1, 2023 [452]:

> On September 1, 2023, Microsoft released a new build of Windows Insider Canary, version 25941... Build 25941 includes improvements to the Code Integrity (CI) subsystem that mitigate a long-standing issue that enables attackers to load unsigned code into Protected Process Light (PPL) processes.

The fix narrows the immediate channel by extending page-hash validation to PPL-loaded images that reside on *remote* (SMB redirector) paths: the precise surface that PPLFault required to drive its CloudFilter `FetchDataCallback` substitution [452]. Locally-cached PPL DLL loads continue to rely on the section-create signature check, so the structural seam survives. The GA patch shipped on February 13, 2024 [453]:

> 2024-02 UPDATE: Microsoft patched PPLFault on 2024-02-13.

Channel: a signed Microsoft DLL whose hash matched at section create. Behavior: attacker payload mapped via the lazy page-in. The fix narrows the channel by widening the verification surface from "the file at section-create time" to "every page at fault time." The class survives.

### Act IV (2022-2024): BYOVDLL and itm4n's KeyIso chain

Bring Your Own Vulnerable DLL. Coined by Gabriel Landau on Twitter in October 2022 (itm4n screenshots the original tweet [435]; tweet status 1580067594568364032). Productised by itm4n in August 2024 in "Ghost in the PPL Part 1."

> **Definition, BYOVDLL (Bring Your Own Vulnerable DLL)**
> A bypass class against a signature-gated security mechanism in which the attacker loads a *legitimately signed but historically vulnerable* binary and exploits the known vulnerability inside it. The signature check passes; the vulnerability does the work. The structural property that makes the class hard to fix is compatibility: Microsoft can patch, revoke, block, or policy-deny specific files, but broad denial of older signed Microsoft DLLs risks breaking deployments that still depend on them.

itm4n's specific chain targets the CNG Key Isolation service ("KeyIso"), which runs in `lsass.exe` and so inherits its PPL/Lsa protection. At the level appropriate for this book, the chain is precise [435]:

1. An administrator-controlled configuration surface (the KeyIso service parameter `HKLM\SYSTEM\CurrentControlSet\Services\KeyIso\Parameters\ServiceDll`) selects which KeyIso service DLL LSASS will load.
2. The chosen DLL is an older `keyiso.dll` extracted from Microsoft update KB5023778, so the file is genuinely Microsoft-signed and belongs to the expected service family.
3. LSASS restarts the KeyIso service and admits the older DLL into the already protected `PPL/Lsa` process because the channel check succeeds.
4. The older DLL contains CVE-2023-36906, an out-of-bounds read information disclosure, which supplies an address leak needed to make the later memory-corruption step reliable.
5. The same older DLL contains CVE-2023-28229, one of six related use-after-free bugs, which itm4n describes as reaching control of a `CALL` target through the `RAX` register.
6. The attacker-controlled behavior now executes inside LSASS at `PPL/Lsa` even though every admission check saw Microsoft-signed code.

The channel therefore passes: the file is Microsoft-signed and belongs to the service family. The behavior fails: once admitted, historical code exposes an out-of-bounds read and a use-after-free that can be composed into code execution at PPL/Lsa. That is the BYOVDLL gap in its cleanest form: the signer lattice answers who may enter; it does not answer whether an older admitted body contains yesterday's memory-safety bug.

The CVEs are real and tracked. k0shl's writeup is the primary root-cause analysis [454]:

> Microsoft patched vulnerabilities I reported in CNG Key Isolation service, assigned CVE-2023-28229 and CVE-2023-36906, the CVE-2023-28229 included 6 use after free vulenrabilities with similar root cause and the CVE-2023-36906 is a out of bound read information disclosure.

NVD records both [455] [456]. Y3A's GitHub repository [457] provides a public PoC for CVE-2023-28229 that itm4n's chain composes.

Channel: an actually-Microsoft-signed DLL. Behavior: the memory-safety vulnerability inside it. No single public, class-wide fix has been announced for the BYOVDLL pattern. Microsoft fixed the specific CVEs by shipping a newer `keyiso.dll`; older signed DLLs can remain obtainable from update packages or enterprise images, but revocation, block rules, WDAC policy, servicing changes, and per-DLL mitigations mean the right claim is narrower than "every old Microsoft DLL is always admissible." The durable lesson is that signature admission alone does not prove historical code is still safe.

> **No public class-wide fix announced.** BYOVDLL is mitigated CVE by CVE and policy by policy. Microsoft can service a vulnerable DLL, block a known-bad image, revoke trust, or let defenders use WDAC-style policy, but the general compatibility problem remains: a PPL admission check that accepts a legitimately signed historical DLL still has to trust the memory-safety of that historical code.
>
> **Walkthrough: Reading the four-act bypass table.** Read each row left to right as an admission story. The channel column names what the kernel or loader believed: a Microsoft-signed scripting DLL, a CSRSS-blessed `\KnownDlls` section, a signed DLL at section creation, or an older signed `keyiso.dll`. The behavior column names what that belief failed to constrain: script source, substituted section bytes, lazy page-in bytes, or vulnerable historical code. The fix column then shows Microsoft's recurring move: narrow the channel just enough to block the known behavior. The table is not four unrelated exploits; it is one repeated mismatch between channel proof and runtime behavior.

| Act | Year | Channel verified | Behavior exploited | Microsoft fix | Fix date |
|---|---|---|---|---|---|
| I | 2018 | Microsoft-signed `scrobj.dll` | JScript source executed by COM object | `g_BlockedDllsForPPL` deny-list of 5 DLLs | Apr 2018 (1803) |
| II | 2021 | `\KnownDlls\` symlink (CSRSS-blessed) | Attacker section mapped without re-validation | NTDLL `LdrpInitializeProcess` patch | Jul 2022 (19044.1826) |
| III | 2023 | Signed DLL passed `MiValidateSectionCreate` | CloudFilter substitutes bytes on lazy page-in | Page-hash validation for remote-backed PPL image loads | Feb 2024 (GA) |
| IV | 2024 | Legitimately-signed older `keyiso.dll` | Use-after-free + OOB read (CVE-2023-28229, CVE-2023-36906) | None (CVE-by-CVE) | open |

> **Walkthrough: itm4n's BYOVDLL / KeyIso chain.** The chain begins with administrative control over service configuration, not with unsigned code. It then selects an older Microsoft-signed KeyIso DLL, so Code Integrity sees a legitimate publisher and a plausible service binary. LSASS loads that DLL inside its `PPL/Lsa` address space. Only after admission does the exploit matter: CVE-2023-36906 supplies an information leak, CVE-2023-28229 supplies the use-after-free control primitive, and the resulting execution inherits the protection context of the host process. The signer lattice did its job on the channel; the vulnerability lived inside the signed body it admitted.
>
> **Aside: Why itm4n credits Landau.** itm4n explicitly attributes the BYOVDLL framing to Landau's October 2022 tweet, even though itm4n's KeyIso chain is the first public productisation. The attribution chain matters because it documents how a one-line research observation (Twitter status 1580067594568364032, screenshot preserved in [435]) became a working exploit two years later. The pattern repeats in this domain: Forshaw's one-sentence DefineDosDevice comment to PPLdump (3 years); Landau's BYOVDLL tweet to itm4n's KeyIso chain (2 years). The structural class outlives its discoverer.

Four acts, one class. In this surveyed corpus, each bypass has the same narrow shape: code becomes part of a PPL through a trusted channel and then executes attacker-influenced data once mapped. Each generation of fix narrows what the channel admits: name-list five DLLs; ignore `\KnownDlls\`; page-hash every section; CVE-patch or policy-block vulnerable older DLLs. The class survives because the kernel cannot reason about behavior. By Rice's theorem it cannot reason about behavior in general; in practice, it has nowhere even to start.

If `lsass.exe` code execution is reachable through BYOVDLL on a Credential Guard-enabled host, where are the protected long-lived *secrets*? Not in the VTL0 `lsass.exe` process. Not in memory the VTL0 kernel can directly read.

## The companion boundary: Credential Guard, VBS, and `LsaIso.exe`

itm4n opens his RunAsPPL walkthrough with a warning [328]:

> I noticed that this protection tends to be confused with Credential Guard, which is completely different.

The confusion is understandable. Both run on Windows. Both protect LSASS. Both are configured by domain administrators. Both yield "ACCESS_DENIED" to Mimikatz when working correctly. They are nonetheless answering different questions, and they stack rather than replace each other.

PPL stops an *administrator* from reading kernel-trusted user-mode memory. It does nothing against a kernel-mode attacker who can simply zero the `Protection` byte in the target `EPROCESS`. The kernel-mode attacker is the next threat-model rung up, and Credential Guard answers the credential-theft part of that rung by moving specified long-lived secrets out of `lsass.exe` when VBS is enabled and intact.

Both VBS (Virtualization-Based Security) and the trustlet model belong to earlier links: the Secure Kernel chapter (Chapter 6) owns the VTL0/VTL1 split, and the VBS Trustlets chapter (Chapter 7) owns the trustlet that holds the secrets. The one fact PPL needs from them is this: on a Credential Guard-enabled host, `lsass.exe` still runs in VTL0 user-mode and still protects itself with PPL/Lsa, but it no longer *holds* the NTLM hashes, Kerberos TGT keys, or Credential Manager domain credentials. Those live in `LsaIso.exe`, a VTL1 trustlet that performs each cryptographic operation inside VTL1 and returns only the result, so the keys never enter VTL0.

Microsoft's documentation states the threat model directly [87]:

> Credential Guard prevents credential theft attacks by protecting NTLM password hashes, Kerberos Ticket Granting Tickets (TGTs), and credentials stored by applications as domain credentials.
>
> Credential Guard uses Virtualization-based security (VBS) to isolate secrets so that only privileged system software can access them.
>
> Malware running in the operating system with administrative privileges can't extract secrets that are protected by VBS.

The third sentence is the load-bearing one. *Malware running with administrative privileges* maps cleanly to a PPL bypass that achieves code execution at PPL/Lsa. On a Credential Guard-enabled host, the protected NTLM, Kerberos TGT, and Credential Manager domain secrets are not in the VTL0 broker; LSASS still has security-relevant state and still mediates authentication, but the long-lived protected keys live behind the VBS boundary.

> **Walkthrough: PPL versus Credential Guard in one request path.** Without either feature, a debug-privileged administrator can ask for an LSASS handle and read credential material directly. With PPL alone, that handle is denied because LSASS is `PPL/Lsa`; the secrets may still live in the VTL0 process if an attacker later gains kernel power or PPL-level code execution. With Credential Guard, the long-lived secrets are moved into isolated `LsaIso.exe` in VTL1. LSASS becomes a broker in VTL0 rather than the vault. A PPL bypass can reach the broker; the VBS/VTL boundary is what keeps the vault outside ordinary kernel reach.

The two mechanisms stack rather than overlap. PPL prevents an admin from `OpenProcess(PROCESS_VM_READ, lsass)` at the user-mode lattice level. Credential Guard limits what a kernel-mode attacker or PPL-level code-execution bug can extract by putting specified long-lived secrets in VTL1 memory that the VTL0 kernel cannot directly read, assuming VBS remains enabled and uncompromised. itm4n's "complementary" framing in the RunAsPPL writeup is the right operational summary [328]: deploy both wherever licensing, hardware, and compatibility allow.

> **Stacked, not redundant.** PPL gates user-mode admins out of LSASS process memory. Credential Guard gates the specified long-lived secrets away from VTL0 (including from many consequences of kernel-mode attackers or BYOVDLL execution-at-PPL/Lsa) by moving those secrets to VTL1. It does not make LSASS irrelevant, and it does not protect every transient authentication artifact; each mechanism answers a layer of the threat model the other does not.

| Dimension | PPL (LSA protection) | Credential Guard |
|---|---|---|
| Threat model | Administrator → user-mode LSASS | VTL0 kernel + admin → credential material |
| Layer | VTL0 user-mode lattice | VTL0 / VTL1 VBS boundary |
| Kernel-mode attacker | Does not stop them | Protects specified secrets if VBS is enabled and intact |
| MSRC classification | Defense in depth | Security boundary |
| Default-on (consumer) | Audit mode, Win11 22H2 | n/a (enterprise) |
| Default-on (enterprise) | Audit mode, Win11 22H2 | Enabled, Win11 22H2 / Win Server 2025 (domain-joined non-DC) |

> **Aside: The deep treatment of `LsaIso` lives in the VBS Trustlets chapter (Chapter 7).** The architecture of `LsaIso.exe` (its Trustlet ID, its IUM EKU, and the hypercall plumbing between `lsass.exe` and the trustlet) is owned by the VBS Trustlets chapter (Chapter 7), and the credential-isolation design that stands on it is owned by the Credential Guard chapter (Chapter 15). The cross-link is deliberate: PPL and Credential Guard are paired in practice, but the architectural depth of VTL1 is its own subject.

Credential Guard's default-on rollout, recorded in Microsoft Learn [87]:

> Starting in Windows 11, 22H2 and Windows Server 2025, Credential Guard is enabled by default on domain-joined, non-DC systems that meet hardware requirements.

Two stacked mechanisms; one classified as a security boundary, one not.

## Where PPL isn't a security boundary: Microsoft's servicing criteria

Gabriel Landau's "Inside Microsoft's Plan to Kill PPLFault" essay states the classification in one sentence [452]:

> Microsoft does not consider PPL to be a security boundary, meaning they won't prioritize security patches for code-execution vulnerabilities discovered therein, but they have historically addressed some such vulnerabilities on a less-urgent basis.

Microsoft's "Windows Security Servicing Criteria" defines the term *security boundary* directly [301]:

> A security boundary provides a logical separation between the code and data of security domains with different levels of trust. For example, the separation between kernel mode and user mode is a classic [...] security boundary.
>
> **Definition: Security boundary (MSRC sense)**
> A logical separation between code and data of security domains with different levels of trust. Microsoft commits to servicing security boundary violations with out-of-band patches when the severity bar is met. The kernel-mode / user-mode separation is the canonical example. Per Microsoft's published servicing criteria, PPL is *not* on the security-boundary list.
>
> **Definition: Defense in depth**
> A security feature that raises the cost of an attack without guaranteeing prevention. Microsoft treats defense-in-depth features as servicing targets on the standard cumulative-update cadence, not as out-of-band patch priorities. PPL falls into this category per Microsoft's published classification.

The relevant excerpts of the criteria page enumerate which surfaces are and are not boundaries. The live MSRC page renders that enumeration table client-side via JavaScript; the raw HTML returned by automated fetchers contains only the React shell. The text of the enumeration is preserved in the Wayback Machine capture at archive date 2023-05-06 [458], and Landau's follow-on Elastic post quotes the relevant administrative-process row verbatim [365]:

> Administrative processes and users are considered part of the Trusted Computing Base (TCB) for Windows and are therefore not strong[ly] isolated from the kernel boundary.

The corresponding row for PPL is the same shape: administrative-process-to-PPL is not isolated as a security boundary. Landau filed VULN-074311 with MSRC in September 2022 disclosing both an admin-to-PPL and a PPL-to-kernel zero-day. The Elastic post records MSRC's classification of the disclosure verbatim [365]:

> MSRC similarly does not consider admin-to-PPL a security boundary, instead classifying it as a defense-in-depth security feature.
>
> **Aside: The MSRC enumeration table is JavaScript-rendered.** The MSRC servicing-criteria page's *definition* of "security boundary" is retrievable from raw HTML and verified against the live page. The *enumeration* of which Windows surfaces are or are not boundaries lives in a client-side rendered table and is not present in the raw HTML payload. The verifiable trail for "PPL is excluded from the boundary list" is the Wayback Machine capture combined with Elastic's verbatim quotation of MSRC's classification.

The operational consequence is direct. A published PPL bypass does not trigger an out-of-band patch. It is fixed on the next major-release cadence, sometimes faster if Microsoft has internal motivation. The disclosure-to-fix half-lives are public record:

| Bypass | Disclosed | Microsoft fix | Disclosure-to-fix |
|---|---|---|---|
| Forshaw 2018 JScript-into-PPL | Oct 2018 | Apr 2018 (1803, pre-disclosure) | ~0 months (Microsoft fixed first) |
| itm4n 2021 PPLdump (KnownDlls) | Apr 2021 | Jul 2022 (build 19044.1826) | ~15 months |
| Landau 2023 PPLFault (CI TOCTOU) | Apr-Sep 2023 | Feb 2024 (GA) | ~5-11 months |
| itm4n 2024 BYOVDLL (KeyIso chain) | Aug 2024 | none (open, CVE-by-CVE) | open |

> **Plan for bypasses.** A correctly classified PPL bypass is fixed on the standard cumulative-update cadence, not out-of-band. The implication for defenders is operational: PPL is exactly as strong as the engineering velocity Microsoft chooses to invest in it. Treat detection (the practical guide) and the Credential Guard companion (the companion-boundary section) as load-bearing.

The takeaway is structural. PPL is real, kernel-enforced, structurally elegant, and demonstrably effective against the threat it was designed for (administrator-from-user-mode reads of LSASS). It is also explicitly *not* a security boundary per Microsoft's own published servicing policy, and that classification is the most important fact about it. Plan for bypasses. Stack with Credential Guard. Treat detection as primary, not secondary.

## What it means for you

For a Reasoner, the operating model is a three-layer decision tree. First ask whether the attacker is still in VTL0 user mode. If yes, PPL is a strong kernel-enforced speed bump: a local administrator, a SYSTEM service, and a token with `SeDebugPrivilege` still do not acquire LSASS memory-read rights unless the caller is admitted at an equal or higher protected signer. Second ask whether the attacker can write kernel memory or load a driver. If yes, PPL itself is only metadata in `EPROCESS`; the meaningful controls become driver block rules, HVCI, Secure Boot, and the operational work of preventing BYOVD paths. Third ask whether the credential material still lives in the VTL0 LSASS process. If yes, a PPL bypass can still be decisive. If Credential Guard has moved the long-lived secrets to `LsaIso.exe` in VTL1, the same bypass reaches a broker rather than the vault.

The practical conclusion follows from those layers. Deploy `RunAsPPL` because it changes the economics of commodity credential theft and administrator-context tampering. Confirm that your EDR daemon is actually at `PPL/Antimalware`; a marketing "protected service" without signer rung `3` is not the same kernel guarantee. Audit LSASS plug-ins before enforcement, because smart-card middleware and authentication packages fail at service time, not at architecture-review time. Pair the design with Credential Guard so that a successful PPL bypass, BYOVDLL chain, or vulnerable driver does not automatically expose the reusable secrets the attacker came for.

The verify-it-yourself probe is intentionally mundane: read `RunAsPPL`, read the LSASS audit hive, and decode the `_PS_PROTECTION` byte. Those three observations answer three different questions: policy, compatibility, and runtime state. A mature fleet collects all three continuously. A weak fleet has a registry value in a baseline document and no proof that this boot's `lsass.exe` actually launched as `PPL/Lsa`.

## Practical guide: Configuring, verifying, and monitoring PPL

If you are deploying PPL on a corporate fleet, run this checklist. The order is deliberate: audit before enforce, verify before trust the verifier, monitor because protected configuration drifts, and stack the control with Credential Guard because PPL and VBS answer different layers of the attack.

### Deploy

> **Item 1: AuditLevel before RunAsPPL, RunAsPPL before UEFI lock.** Enable `AuditLevel = 8` under `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe` for two months [436]. This is a *different* registry hive from `RunAsPPL` (which lives under `HKLM\SYSTEM\CurrentControlSet\Control\Lsa`); mixing the two values up is the most common Stage 0 deployment error (see the RunAsPPL section). Collect CodeIntegrity events 3065 and 3066 to enumerate every LSASS plug-in that would fail enforcement: smart-card middleware, third-party CSPs, password-filter DLLs, and legacy authentication packages. Re-sign or replace the failing modules. Set `RunAsPPL = 1` on Secure Boot-capable machines; the kernel automatically stores the policy in a UEFI variable. `RunAsPPL = 2` (Win11 22H2+) is the softer option that omits the UEFI variable for environments requiring admin-removable protection.

A deployment wave should therefore have four gates: audit hive configured, two clean monthly patch cycles with no unresolved 3065 / 3066 events, pilot enforcement on a hardware slice that includes smart-card and VPN users, then broad enforcement. Do not start with the UEFI lock on the first pilot. Use the registry-only mode where available, prove the authentication estate survives, and then move Secure Boot-capable production systems to the firmware-backed value. The cost of this patience is weeks; the cost of skipping it is an authentication outage that trains operators to disable the control.

> **Item 2: Confirm your EDR daemon runs at PPL/Antimalware.** For third-party EDR, confirm the agent daemon runs at `PPL/Antimalware` (signer rung 3, byte `0x31`). Process Explorer exposes this via View → Select Columns → Protection. System Informer (the modern Process Hacker fork that itm4n recommends in his BYOVDLL writeup [435]) shows the same field in its process list. If your EDR is *not* running at `PPL/Antimalware`, it does not have the kernel's protection against admin tampering even when its vendor claims "protected" in marketing material.
>
> (Note: Process Explorer's "Protection" column ships in the canonical Sysinternals distribution [459]; it reads `EPROCESS.Protection` via the `NtQueryInformationProcess` entry point [460], although the specific `ProcessProtectionInformation` information-class value is not enumerated in the public Learn `PROCESSINFOCLASS` table. The value is community-documented from Windows headers and reverse engineering rather than from a Microsoft Learn API reference.)

For EDR procurement, make the byte a requirement rather than an adjective. Ask the vendor which signer rung their service enters, how the ELAM resource is maintained, how certificate rollover is handled, and how quickly they can ship a new ELAM driver if the user-mode signing chain changes. A product that can protect its service only with ACLs, a watchdog, or a kernel callback may still be useful, but it is not taking the PPL/Antimalware path described in this chapter.

### Verify

> **Item 3: Decode the byte by hand in WinDbg.** On a host you suspect of misconfiguration, attach WinDbg to the kernel and run `!process 0 7 lsass.exe`. The output includes the `_PS_PROTECTION` byte. Decode it with the formula from the `_PS_PROTECTION` section above: `((value & 0xF0) >> 4)` is the signer rung; `value & 0x07` is the type; `(value >> 3) & 1` is the audit bit. A `RunAsPPL = 1` host yields `0x41` (PPL + Lsa). The Defender service yields `0x31` (PPL + Antimalware). `csrss.exe` yields `0x61` (PPL + WinTcb). If `lsass.exe` shows `0x00`, the registry policy did not take effect on this boot.

Use the decoder from the `_PS_PROTECTION` section above rather than carrying a second copy of it in your runbook. The verification utility should recognize three benchmark values by sight: `0x31` for Defender at `PPL/Antimalware`, `0x41` for `lsass.exe` under RunAsPPL, and `0x61` for `csrss.exe` at `PPL/WinTcb`.

Verification should be sampled after reboot, after cumulative updates, and after EDR upgrades. The reason is that all three operations change inputs to the admission path: boot policy, Code Integrity policy, and signing chain. Store the decoded value, not merely the raw screenshot. A useful asset record says `Host X, boot Y, lsass 0x41, EDR service 0x31, csrss 0x61`; that triple catches both LSASS misconfiguration and antimalware agents that silently lost PPL admission.

### Monitor

> **Item 4: ETW events to watch.** The CodeIntegrity provider emits four event IDs that matter for PPL monitoring [436]:
>
> | Event ID | Provider | What it tells you | Typical first question |
> |---|---|---|---|
> | 3033 | Microsoft-Windows-CodeIntegrity | Enforcement-mode: an image load was blocked for failing the signing-level requirement (PPL or otherwise) | Which process tried to load which image? |
> | 3063 | Microsoft-Windows-CodeIntegrity | Enforcement-mode: LSASS plug-in failed the shared-section security requirement | Did a production plug-in just break under enforcement? |
> | 3065 | Microsoft-Windows-CodeIntegrity | Audit-mode: LSASS plug-in would fail the shared-section requirement | Is this an expected legacy DLL during rollout? |
> | 3066 | Microsoft-Windows-CodeIntegrity | Audit-mode: LSASS plug-in would fail the Microsoft signing-level requirement | Is the module unsigned, vendor-signed only, or signed with the wrong EKU? |
>
> Sysmon Event 10 (ProcessAccess) captures `OpenProcess` attempts with the requested access mask and is the cheapest detection for a Mimikatz-shaped attempt against a `RunAsPPL`-protected `lsass.exe`. A burst of 3033 events showing `lsass.exe` (or another PPL) attempting to load images that fail the signing-level requirement is the canonical signal that a PPL bypass attempt or broken plug-in load is under way.

Concrete collection examples make the monitoring claim testable:

```powershell
# Code Integrity failures relevant to LSASS/PPL deployment and bypass attempts
Get-WinEvent -FilterHashtable @{
  LogName = 'Microsoft-Windows-CodeIntegrity/Operational'
  Id      = 3033,3063,3064,3065,3066
} -MaxEvents 100 |
  Select-Object TimeCreated, Id, ProviderName, MachineName, Message
```

```powershell
# Sysmon ProcessAccess attempts against LSASS, if Sysmon Event ID 10 is enabled
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=10} -MaxEvents 200 |
  Where-Object { $_.Message -match 'TargetImage:.*\lsass\.exe' } |
  Select-Object TimeCreated, ProviderName, Message
```

```kusto
// Microsoft Sentinel / Defender-style normalization: CodeIntegrity events by host and image text
Event
| where Source == "Microsoft-Windows-CodeIntegrity"
| where EventID in (3033, 3063, 3064, 3065, 3066)
| extend MessageText = tostring(RenderedDescription)
| summarize Count=count(), FirstSeen=min(TimeGenerated), LastSeen=max(TimeGenerated) by Computer, EventID, MessageText
| order by LastSeen desc
```

```spl
index=wineventlog (source="Microsoft-Windows-CodeIntegrity/Operational" OR source="XmlWinEventLog:Microsoft-Windows-CodeIntegrity/Operational") (EventCode=3033 OR EventCode=3063 OR EventCode=3065 OR EventCode=3066)
| stats count min(_time) as first max(_time) as last by host EventCode Message
| sort - last
```

Expected fields are boring but important: time, host, event ID, process or image name when present, and the rendered message naming the failing module. False positives cluster around rollouts: smart-card middleware updates, VPN authentication plug-ins, credential providers, EDR self-updates, and golden images that still carry audit mode. Treat a single 3065 during a pilot as a compatibility ticket. Treat a sudden 3033 / 3063 burst on an already-enforced production host as an incident until proven to be a signed vendor upgrade. Treat Sysmon Event 10 against LSASS as higher signal when the source image is an interactive admin tool, a scripting host, an archive extractor, or a renamed binary outside managed software paths.

Monitoring should also look for control drift:

```powershell
# Registry-state drift: collect policy and audit hives together
Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RunAsPPL -ErrorAction SilentlyContinue |
  Select-Object PSComputerName, RunAsPPL
Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe' -Name AuditLevel -ErrorAction SilentlyContinue |
  Select-Object PSComputerName, AuditLevel
```

The registry drift query is not proof of runtime PPL, but it catches the two mistakes defenders actually make at scale: setting the value in the wrong hive and leaving audit mode configured forever. Pair it with periodic runtime byte sampling from trusted tooling on a representative fleet slice.

> **Item 5: Stack PPL with Credential Guard.** PPL prevents admin-from-user-mode reads of LSASS. Credential Guard prevents direct VTL0 reads of specified protected credentials and limits the blast radius of BYOVDLL-style execution at `PPL/Lsa`. Deploy both where the platform supports it. itm4n's "complementary" framing in his RunAsPPL writeup [328] is the right operational model. On Win11 22H2 and Windows Server 2025, Credential Guard is default-on for domain-joined non-DC systems with VBS-capable hardware [87]; on older fleets, enable it explicitly via Group Policy or the Device Guard / Credential Guard configuration script. Together where feasible: either mechanism alone leaves a layer of the threat model uncovered.

The operational test for "both" is also layered. PPL evidence is the `0x41` LSASS byte and failed lower-signer handle opens. Credential Guard evidence is VBS state plus the presence of isolated LSA operation. Do not accept one as proof of the other. If Credential Guard is absent, BYOVDLL or kernel compromise can still make LSASS memory valuable. If PPL is absent, Credential Guard may protect long-lived secrets while leaving the VTL0 broker and many short-lived materials exposed to ordinary admin-context tools.

> **Item 6: For EDR vendors. The ELAM admission checklist.** If you are an EDR vendor wanting your daemon to run at `PPL/Antimalware`, the path is fixed [437] [327]:
>
> 1. Hold Microsoft Virus Initiative membership; maintain independent-lab certification (AV-Comparatives, AV-Test, SE Labs, MRG Effitas, SKD Labs, VB 100, West Coast Labs, AVLab Cybersecurity Foundation).
> 2. Author an ELAM driver with an embedded `<ELAM>` resource section enumerating your user-mode binary signing-certificate hashes.
> 3. Submit the driver through WHQL for Microsoft co-signing.
> 4. Use Trusted Signing for your user-mode binaries.
> 5. Verify with Process Explorer that the service launches at `PPL/Antimalware` after install.

Practitioners who follow the checklist still need to know the common misconceptions.

## Closing

The arc has run from a single Mimikatz error code to a kernel-enforced lattice, a third-party admission path mediated by ELAM and MVI, an arms race shaped by a single structural insight that the kernel verifies the channel and not the behavior, and a stacked companion boundary that lives in VTL1 because VTL0 has run out of places to hide a key. PPL is not a security boundary. That classification is not a footnote; it is the most important fact about it, because it tells defenders that the mechanism is exactly as strong as the engineering velocity Microsoft chooses to invest. Deploy it. Stack it with Credential Guard. Monitor for the next bypass.

> **Key idea.** The bypass history above is one repeated seam: each fix narrows admission, but static signature verification still cannot prove the future behavior of admitted code.
>
> **Bequeaths.** Protected Process Light hands the next link one narrow, kernel-enforced guarantee: on a `RunAsPPL` host, `lsass.exe` carries `PPL/Lsa` (`0x41`), and no VTL0 caller at a lower signer rung (not a local administrator, not SYSTEM, not a token with `SeDebugPrivilege`) can obtain a memory-read handle to it. That floor is exactly what the Credential Guard chapter (Chapter 15) builds on when it argues the long-lived secret must leave VTL0 altogether, because PPL's guarantee evaporates the moment an attacker reaches kernel mode and can zero the `Protection` byte. The bequest is deliberately small. PPL does NOT provide a security boundary: MSRC classifies it as defense in depth, so its bypasses are serviced on the cumulative-update cadence, not out-of-band; it does NOT stop a kernel-mode attacker; and it offers NO third-party opt-in outside the ELAM/MVI-gated Antimalware rung. The chain has learned to protect the *process*; it has not yet protected the *secret*. That is the next link's burden.
