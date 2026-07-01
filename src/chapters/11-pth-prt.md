# Pass-the-Hash to Pass-the-PRT

::: trust-ledger

- **Inherits:** the NTOWF / NTLM challenge-response credential model. A stored function of the password that the verifier recomputes, so the hash *is* the password (Chapter 16, The Death of NTLM); the Kerberos TGT-and-session-key model and its replay surface (Chapter 17, Kerberos), with the signing key behind it owned by KRBTGT (Chapter 18); long-term secrets relocated off the box into `LsaIso` in VTL1 (Chapter 15, Credential Guard), a guarantee that itself rests on the Secure Kernel (Chapter 6). The artifact this chapter centers on, the PRT, is minted by a Windows Hello or password sign-in (Chapter 20) and spent against the cloud control plane (Chapter 26, Zero Trust).
- **Promise:** Each defensive generation makes one reusable credential artifact unreadable from the process that uses it: Credential Guard for the NT hash and TGT, KB5014754 for certificate-to-SID mapping, Token Protection for the PRT cookie. Serviced boundary: local-admin / SYSTEM in VTL0 → the isolated store (VTL1 `LsaIso`, the TPM, or the KDC's strong mapping).
- **TCB:** Whatever holds *and uses* the artifact. `LsaIso`/the Credential Guard protected store for the long-lived PRT and session-key state where that posture applies, CloudAP in VTL0 for the in-use SSO-cookie derivation, the KDC for certificate mapping, the Entra token endpoint for cookie acceptance. The NT kernel the attacker owns is outside it; CloudAP's VTL0 broker path is the seam inside it.
- **Adversary → Break:** Use, not necessarily theft. With local administrator the attacker may recover raw PRT/session-key material on less protected systems, abuse a legitimate CloudAP/broker signing path on protected systems, or replay an already completed `x-ms-RefreshTokenCredential` cookie. The Promise ends at *storage*; unsupported or unbound verifier paths can still accept proof produced elsewhere.
- **Residual:** the token/Potato escalation that supplies the local admin this whole family assumes → Windows Access Control (Chapter 22) and The SeImpersonate Primitive (Chapter 24); ticket replay below the PRT → Kerberos (Chapter 17) and KRBTGT (Chapter 18); cloud-side dwell time and revocation → Continuous Access Evaluation (Chapter 27); detecting the LSASS / CloudAP access → ETW (Chapter 25); the un-rechecked inherited token that crosses a tenant boundary → When the Chain Snaps: Storm-0558 (Chapter 29).
- **Bequeaths:** the lesson that isolating where a credential is *stored* is not isolating where it is *used*: the floor the phishing-resistant successors build on when they try to retire the replayable artifact entirely: Windows Hello (Chapter 20) and WebAuthn / passkeys (Chapter 21). Does NOT provide: isolation of CloudAP's in-use derivation, token binding for browser or third-party SaaS, or any cover for non-human and legacy software-extractable secrets.
- **Proof:** 🔵 documented: `dsregcmd /status`, `Win32_DeviceGuard`, and Microsoft's Entra / Credential Guard / Token Protection documentation, plus Mollema and Delpy's public PRT research and ROADtools. No captured replay is claimed on our lab VM.
:::

> **The Reasoner's question.** Which reusable artifact did each defense move out of reach, and which artifact did attackers move to next?

---

> **Foundations. What you need before this chapter.**
>
> - **NTOWF / NT hash (recap).** The MD4 of the user's password as UTF-16LE: a stored value the verifier recomputes, so possession of it functions as the password. Full mechanics live in Foundations and the The Death of NTLM chapter (Chapter 16); this chapter treats it as a settled primitive.
> - **Kerberos ticket material (recap).** A TGT is only useful with its associated session key; Pass-the-Ticket and Overpass-the-Hash are two routes to usable Kerberos material. The ticket model is owned by the Kerberos chapter (Chapter 17).
> - **LSASS and LsaIso.** `lsass.exe` in VTL0 brokers authentication packages and SSO flows. With Credential Guard (Chapter 15), selected long-lived secrets move to `LsaIso.exe` in VTL1, where VTL0 code cannot read them directly.
> - **Storage versus use.** A protected root secret can still have an exposed use path. Microsoft documents the PRT/CloudAP/WAM broker model and says the PRT session key is encrypted to the device transport key, protected by the TPM where available, and inaccessible to other OS components. It does not document every private CloudAP field placement. This chapter therefore treats the long-lived PRT/session-key storage posture on Credential-Guard-on Entra-joined devices as Microsoft-documented device/TPM binding plus a Credential Guard storage model where that posture applies; the documented residual is CloudAP's in-use SSO-cookie path in VTL0.
> - **Primary Refresh Token (PRT).** A Microsoft Entra refresh token issued to a signed-in user on a joined device. It is valid for 90 days and is continuously renewed while the user remains active on the device.
> - **Device binding / Token Protection.** A verifier-side control that reduces replay by requiring device-bound sign-in session tokens for supported resources. Its support is important but partial.

---

Twenty-nine years of Windows credential-replay attacks (Pass-the-Hash, Pass-the-Ticket, Overpass-the-Hash, Pass-the-Certificate, Pass-the-PRT) are a single lineage, not five techniques. Each generation finds the next authentication artifact that the latest boundary does not fully cover, then commoditises replay in tooling that runs anywhere with local administrator. Credential Guard (2015) and KB5014754 (2022) bought years but not closure; Pass-the-PRT (Mollema + Delpy, 2020) shows the modern storage-versus-use gap. On Credential-Guard-on Entra-joined devices, the long-lived PRT/session-key state should be read as part of the protected storage model rather than as a directly documented per-field layout; CloudAP in VTL0 still performs the in-use SSO-cookie derivation. That derivation or brokered signing path, not flat theft of the isolated root, is the replay surface. The next decade of Windows credential theft turns on whether every in-use cloud-token derivation receives a boundary as strong as the storage boundary.

## Two afternoons, twenty-nine years apart

On the afternoon of Tuesday, April 8, 1997, between 5:27 p.m. and 8:57 p.m. (a window we can narrow to about three and a half hours from the file timestamps preserved in the patch he posted), a researcher named Paul Ashton sat down with the Samba source tree and made the smallest possible change to `smbclient`. (Side note: The bracketing mtimes `Tue Apr 8 17:27:29 1997` and `Tue Apr 8 20:57:43 1997` are preserved verbatim in the unified diff's `***` and `---` header lines on Exploit-DB advisory 19197 [818]. You can still download the diff today and confirm the timestamps yourself.) Where the unpatched client computed a network response from a typed-in password, his version read the password's LM hash from `smbpasswd` on disk and fed it straight to the same encryption primitive, skipping the password entirely.

He posted the diff to NTBugtraq the same evening with a five-line advisory: "A modified SMB client can mount shares on an SMB host by passing the username and corresponding LanMan hash of an account that is authorized to access the host and share. The modified SMB client removes the need for the user to 'decrypt' the password hash into its clear-text equivalent." [818]

Twenty-nine years later, every Windows credential-replay attack in commodity offensive tooling is a direct descendant of that afternoon.

Fast-forward to 2026. A Windows 11 24H2 laptop, hardened to Microsoft's published baseline. Credential Guard on. KB5014754 strong certificate mapping in full enforcement. Conditional Access enabled, with Token Protection where supported. An attacker has local admin: the same starting position the 1997 attack assumed.

Two commands run on that machine, in the same paragraph. Mimikatz `sekurlsa::logonpasswords` returns empty NT hash and TGT buffers; Credential Guard has done its job. Then CloudAP can be driven through the Mollema/Delpy path to produce PRT-derived proof material usable for SSO-cookie replay [819]. On a *different* machine across the internet, the attacker pastes that material into Dirk-jan Mollema's `roadtx prt`, mints an `x-ms-RefreshTokenCredential` cookie, and authenticates to Entra ID as the laptop's user [820] [821] when the target client/resource path accepts that unbound proof. Every Microsoft defense shipped in 2015, 2022, and 2024 may be running; the attack still wins against unsupported browser paths, third-party SaaS, legacy integrations, or controls outside the verifier path.

> **Two scenes, one architectural property.**
> The empty buffer from `sekurlsa::logonpasswords` is the artifact of twenty-nine years of architectural lessons. The PRT-derived cookie replay from the CloudAP path is the architecture of the *next* five-to-ten years. Both scenes are the same attack class. The credential changed; the protocol that consumes it changed; the long-term storage location changed; the lineage did not.

You will meet the eight researchers at the center of this lineage. Paul Ashton (1997, the patch). Hernan Ochoa (2008, the toolkit that put the technique inside Windows itself). Benjamin Delpy (2011, Mimikatz; and the Kerberos generations that followed). Sean Metcalf (2014, whose adsecurity.org reference became the canonical practitioner explainer of Overpass-the-Hash and taught a generation of red and blue teams).

Will Schroeder and Lee Christensen (2021, "Certified Pre-Owned," the AD CS catalog that became Pass-the-Certificate). Oliver Lyak (2022, Certifried, the CVE that forced Microsoft to ship KB5014754). And Dirk-jan Mollema (2020, the Primary Refresh Token research this chapter argues is the most consequential credential-theft work since 2008). The cast is small. The lineage they built is the load-bearing structure of every Windows penetration test in 2026.

How is it possible that the same attack works in 1997 and 2026? The answer is structural, not coincidental, and once you see it, you cannot unsee it.

## The architectural property the family shares

NTLM authentication never asks for the password as a string. It asks for a function of the hash. The hash *is* the password.

That sentence is this chapter's load-bearing claim, and the rest of the lineage is its consequence. The mechanics behind it. How `NTOWF = MD4(UNICODE(password))` is computed, how NTLMv1's informal `DESL` shorthand (three DES encryptions over the challenge) and NTLMv2's `HMAC_MD5` turn that key into a challenge response, and why the verifier recomputes the same value from the stored hash in the SAM or NTDS.dit: belong to Foundations and the The Death of NTLM chapter (Chapter 16), which own the NTLM challenge-response primitive in full [716] [646]. The one fact this chapter inherits and builds on is the consequence: the cleartext password appears in exactly one place in the entire protocol, the input to the hash on the client, so a stolen hash skips only the typing step and produces an `NTLM_AUTHENTICATE` message the verifier cannot distinguish from a genuine logon. This is what Microsoft means when its institutional documentation says Pass-the-Hash "cannot be patched at the protocol level." There is nothing to patch. (Margin note: the same property holds for any challenge-response protocol whose verifier stores a determinable function of the password rather than the password itself: Kerberos with stored long-term keys, CHAP with shared secrets, OAuth client_credentials with shared secrets, every HMAC-based proof-of-possession scheme.)

The protocol takes a stored hash and produces a response. Supply the victim user's hash instead of the victim user's password, and the protocol still produces a valid response, signed by the substituted key. The bug is not a bug; it is a documented property.

> **Key idea.**
> The hash is the password. Any long-term proof secret reachable by the process that uses it is replayable in the protocol that accepts that proof, and every credential type the rest of this chapter discusses (Kerberos TGT/session key, certificate private key, Primary Refresh Token-derived proof material) is a different instance of this same property. Defenses can isolate one artifact at a time; the property is intrinsic to the architecture.

Ashton's 1997 patch was the protocol-disclosure proof. He swapped a single function call (`SMBencrypt(pass, cryptkey, pword)` became `E_P24(p21, cryptkey, pword)`, where `p21` is the user's LM hash read directly from `smbpasswd`) and Samba's `smbclient` authenticated to NT 3.51 and NT 4.0 file servers without ever knowing the user's password [818]. You can read the patch in five minutes. It is also, in a precise sense, the first proof that NTLM's response computation is hash-equivalent: if substituting the hash works, then mathematically the hash is what the protocol wanted all along.

And then nothing happened for eleven years.

That gap deserves its own explanation, because the eleven-year interregnum is the cleanest failure mode in the lineage.

Wikipedia's modern summary of the pre-2008 limitation reads: "even after performing NTLM authentication successfully using the pass the hash technique, tools like Samba's SMB client might not have implemented the functionality the attacker might want to use. This meant that it was difficult to attack Windows programs that use DCOM or RPC. Also, because attackers were restricted to using third-party clients when carrying out attacks, it was not possible to use built-in Windows applications, like Net.exe or the Active Directory Users and Computers tool among others, because they asked the attacker or user to enter the cleartext password to authenticate, and not the corresponding password hash value." [822]

> **Why this did not catch on for eleven years.**
> Inside Microsoft the 1997 patch was treated as confirming a known property of LSASS-resident credentials, not as a new attack class. The institutional position was that any compromise yielding the hash already implied SYSTEM-equivalent access, and that the realistic chain was "exfiltrate the hash and crack it offline," not "replay the hash." The architectural counter-claim (that *replaying* the hash from inside a Windows process bypasses every native-tool obstacle) took a decade to land in the practitioner literature. The 2012 Duckwall + Campbell Black Hat USA paper named the lag in its title: "Still Passing the Hash 15 Years Later." [823]

If the obstacle is "built-in Windows tools ask for cleartext," the architectural answer is to put the substituted hash *inside* the Windows process that those tools rely on. That insight took eleven years to operationalise. The person who operationalised it was Hernan Ochoa, in 2008.

## From patch to Toolkit: The Windows-Native pivot

By 2008, Ashton's 1997 patch had been sitting on NTBugtraq for eleven years. Hernan Ochoa had a different idea: instead of patching the client, patch the *credential cache*.

The artifact Ochoa shipped at CanSecWest 2008 and Black Hat USA 2008 was called the *Pass-the-Hash Toolkit*, distributed through Core Security Technologies' open-source projects page [824]. It contained two principal executables. `whosthere.exe` read the NTLM credentials cached in LSASS for the active logon sessions, and `iam.exe` opened the LSASS process with `PROCESS_VM_WRITE`, located the cached credential block for the current interactive logon session, and overwrote the username, domain, and NT hash fields with attacker-supplied values in place (a companion `genhash.exe` computed hashes).

Once the substitution was in place, every native Windows SSO consumer (`net.exe`, `wmic`, `mstsc` once Restricted Admin RDP shipped years later, SMB, RPC, DCOM) transparently picked up the attacker-supplied hash, because the OS handed them what it believed were the legitimate user's credentials.

Wikipedia summarizes the architectural pivot in one paragraph: "It allowed the user name, domain name, and password hashes cached in memory by the Local Security Authority to be changed at runtime *after* a user was authenticated. This made it possible to 'pass the hash' using standard Windows applications, and thereby to undermine fundamental authentication mechanisms built into the operating system." [822] The eleven-year limitation was gone. Pass-the-Hash was now a Windows-native attack that worked against any tool that read its credentials from LSASS: which in practice meant *every* Windows tool.

> **Definition: LSASS, and the one fact this chapter adds.**
> `lsass.exe` is the VTL0 process that brokers interactive logon and Single Sign-On; its full treatment lives in Foundations and the Credential Guard chapter (Chapter 15). The fact this chapter adds is that the *using* process holds the in-use credential material for the session: NT hashes for NTLM, Kerberos TGTs and session keys, certificate handles, and (since Azure AD / Entra ID device join) CloudAP-derived Primary Refresh Token working material. Credential Guard's documented scope is NTLM hashes, Kerberos TGTs, and domain credentials; it does not cover the CloudAP-held PRT, so the PRT and its session key live in VTL0 LSASS and are reachable with local administrative control. The TPM protects the device and transport keys at rest, not the PRT's in-process use. Every credential-replay technique in this chapter reaches its target by reading or driving LSASS in some form.

The 2012 retrospective is where the security industry stopped pretending Pass-the-Hash was solved. Alva Duckwall and Christopher Campbell shipped a Black Hat USA 2012 paper titled, unambiguously, "Still Passing the Hash 15 Years Later." [823] The title is the load-bearing pull-quote: it named Ashton 1997 as the origin, Ochoa 2008 as the Windows-native pivot, and the industry's continued failure to ship a structural fix as the central fact. From this point onwards Microsoft itself acknowledged Pass-the-Hash as a structural property of NTLM rather than a fixable bug.

(Side note: Hernan Ochoa's Windows Credentials Editor (WCE), released about two years after the Pass-the-Hash Toolkit, developed the same LSASS-injection primitive on a separate code base. Two independent implementations converging on the same memory-access pattern in the same window is the clearest indication that the architectural insight ("the credential is sitting in a process you can write to") was overdetermined once anyone went looking for it.)

What did Ashton's 1997 patch leave on the table? The other long-term credentials that LSASS held. The NT hash was the first. There would be more.

If you can read the NT hash from LSASS, you can read the Kerberos TGT from LSASS. The same memory-access primitive that animates `IAM.EXE` is one commit away from animating `sekurlsa::tickets`. That commit shipped in May 2011. Its author was a twenty-five-year-old French programmer named Benjamin Delpy.

## Mimikatz and the Kerberos turn

In May 2011, Benjamin Delpy posted his first public release of a program he had been writing as a side project to learn C. He was twenty-five, working as an IT manager at an institution he has never publicly named. Andy Greenberg's Wired profile records the date: "He released it publicly in May 2011, but as a closed source program." [617] Wikipedia corroborates: "He released the first version of the software in May 2011 as closed source software." [461] The program was called Mimikatz.

What made Mimikatz architecturally different from Ochoa's toolkit was that it was *modular*: named command groups each retargeted the same LSASS reachability at a different artifact: `sekurlsa::logonpasswords` for NT hashes, `sekurlsa::tickets` for Kerberos tickets, `kerberos::ptt` to inject a stolen ticket through the documented `LsaCallAuthenticationPackage` API [825], and `lsadump::dcsync` to impersonate a domain controller and pull the krbtgt hash by directory replication [653]. The module-by-module mechanics (and the DCSync replication-RPC abuse in particular) are owned by the Mimikatz and the Credential-Theft Decade chapter (Chapter 14); what matters to the lineage here is that one tool made retargeting routine.

Same LSASS, different artifact, different protocol surface. The architectural property named earlier had two artifacts to work with on Windows: the NT hash, and the Kerberos TGT.

This is **Pass-the-Ticket** (Generation 2). The stolen TGT plus its session key authenticates the holder as the original principal for the ticket's lifetime, which on a default AD deployment is ten hours, renewable for seven days. Time complexity per replay: O(1). The TGT session key is the load-bearing piece: without it, the ticket is opaque encrypted bytes that the holder cannot decrypt, sign, or present back to the KDC. Mimikatz's `sekurlsa::tickets /export` writes the ticket as a `.kirbi` file on disk; `kerberos::ptt` re-injects a chosen ticket on any machine where the user has a Kerberos credentials cache.

> **Definition: Kerberos TGT (recap).**
> The long-lived credential the KDC issues in an AS-REP, encrypted under the krbtgt account's key and carrying a session key the client needs to request service tickets from the TGS; default Windows lifetime 10 hours, renewable to 7 days (RFC 4120 §3 [741]). The ticket model and its replay surface are owned by the Kerberos chapter (Chapter 17), and the signing key behind every TGT by KRBTGT (Chapter 18).
>
> **Definition, Pass-the-Ticket.**
> The technique of extracting a Kerberos TGT (and its session key) from one machine's LSASS-resident Kerberos cache and injecting it into another machine's cache, so that subsequent service-ticket requests authenticate as the ticket's original principal. Tool of record: Mimikatz `sekurlsa::tickets` + `kerberos::ptt`; equivalent functionality in Rubeus and Impacket.
>
> **Walkthrough, Pass-the-Ticket.**
> The step-by-step injection path (export the TGT and its session key, submit the `.kirbi` through `LsaCallAuthenticationPackage`, then request service tickets against the KDC with the injected ticket [825]) is Kerberos mechanics owned by the Kerberos chapter (Chapter 17). The lineage point alone matters here: the TGT was the *second* artifact reachable in the same address space, so the same memory-access primitive simply pointed somewhere new.
>
> **Causal arrow correction.**
> A common shorthand says that Microsoft's Credential Guard isolated NT hashes, so attackers shifted to TGTs. That arrow runs backwards in time. Pass-the-Ticket predates Credential Guard by years: the Mimikatz Kerberos primitives developed between the May 2011 closed-source release and the April 6, 2014 open-source commit (the earliest verifiable source-level evidence for `sekurlsa::tickets` and `kerberos::ptt`), and were presented in detail at Black Hat USA 2014 by Duckwall and Delpy [801] [826]. Pass-the-Ticket exists because TGTs are also in LSASS, not as a defensive response. The shift to a new artifact happened because the *architectural property* of credential extraction generalized, not because Credential Guard pushed attackers there.

The third generation followed shortly. **Overpass-the-Hash** observes that for the RC4-HMAC Kerberos encryption type (long accepted for Windows Kerberos compatibility and often selected in estates that had not forced AES-only policy before the 2022 hardening work), the user's long-term Kerberos key is the unchanged NT hash.

RFC 4757, authored by K. Jaganathan, L. Zhu, and J. Brezak of Microsoft and published as informational in December 2006, specifies the RC4-HMAC enctype's long-term key as the existing NT hash without modification [759]. An attacker who holds the NT hash can drive a legitimate Kerberos AS-REQ to the KDC, encrypt the timestamp pre-auth blob with the NT hash as the RC4-HMAC key, and receive a real TGT signed by the real krbtgt.

The economic effect is large. Pass-the-Hash gets you NTLM-based services: SMB, RPC, and any protocol over them. Overpass-the-Hash gets you the entire Kerberos surface: Kerberos-only services, services that require Kerberos for delegation, services with NTLM disabled at the GPO level. Same NT hash. Different downstream protocol. Strictly larger attack surface.

> **Definition, Overpass-the-Hash.**
> The technique of presenting a stolen NT hash to the KDC as the user's long-term RC4-HMAC Kerberos key (per RFC 4757 [759]), obtaining a real TGT signed by the real krbtgt, and operating as a real Kerberos client for the ticket's lifetime. Tool of record: Mimikatz `sekurlsa::pth /user: /domain: /ntlm: /run:` and Rubeus `asktgt /user: /rc4:`. Per Sean Metcalf's adsecurity.org reference, the technique is named "over" because the hash is promoted one notch up the protocol stack from NTLM into Kerberos [827] [767].
>
> **Walkthrough, Overpass-the-Hash.**
>
> 1. The attacker starts with the NT hash rather than a Kerberos ticket.
> 2. In Microsoft RC4-HMAC Kerberos, that NT hash is the user's RC4 long-term key [759].
> 3. The attacker sends an AS-REQ with pre-authentication encrypted under that key.
> 4. The KDC successfully decrypts the timestamp, concludes the client knows the long-term key, and issues a fresh TGT.
> 5. From that point forward the traffic is ordinary Kerberos: TGS-REQ, TGS-REP, AP-REQ. The replayed hash has become a real ticket-granting workflow.

The naming has its own story. The Mimikatz capability is Delpy's; the term "Overpass-the-Hash" and the taxonomic framing that distinguishes it from straight Pass-the-Hash spread through the practitioner community via Sean Metcalf's adsecurity.org reference [827] and the Duckwall + Delpy Black Hat USA 2014 talk and whitepaper [801] [826]. The earliest archived snapshot of the adsecurity.org reference is October 1, 2014; the talk timestamp is August 7, 2014. The two sources are essentially contemporaneous, and Metcalf's later "Red vs. Blue" Black Hat USA 2015 whitepaper consolidates the practitioner taxonomy [828].

(Side note: The "Overpass" coinage is a deliberate semantic argument that the technique is one notch *above* Pass-the-Hash on the protocol stack: the NT hash, which began life as an NTLM response key, is being promoted into Kerberos as a long-term encryption key. The naming credit is socially distributed (Metcalf, Delpy, Duckwall, and Mimikatz's own command group all carry traces of it) so this chapter uses Metcalf's reference as the canonical practitioner explainer rather than as a single inventor citation.)

The DigiNotar incident in September 2011 is the earliest public criminal-use attribution this chapter can source for Mimikatz, but the attribution is single-source and should be read with that caveat. The Dutch certificate authority DigiNotar (founded 1998, acquired by VASCO in January 2011, hacked in June 2011, declared bankrupt in September 2011 [829]) was used to issue hundreds of fraudulent certificates that were then used in man-in-the-middle attacks on Iranian Gmail users [829] [830].

Greenberg's Wired profile records that Delpy was told by the breach investigators that Mimikatz had been used during the intrusion [617]. The single-source attribution warrants a hedge (Greenberg's source is Delpy himself, quoting investigators) but the underlying breach timeline is solid.

> **The Moscow hotel.**
> The decision to open-source Mimikatz on April 6, 2014 is dated by the GitHub repository banner: `mimikatz 2.0 alpha (x86) release "Kiwi en C" (Apr 6 2014 22:02:03)` [261]. The precipitating event, as Delpy told Wired, was a trip to Moscow: he returned to his hotel room to find a stranger at his laptop; a second man approached him in the lobby that evening and demanded source code on a USB stick. He decided defenders needed the source as much as the attackers already did, and pushed it to GitHub when he got home [617].

By 2014, the credential-replay family had three generations (Pass-the-Hash, Pass-the-Ticket, Overpass-the-Hash) and Microsoft's only documented response was a forty-page PDF. The next section is what that PDF said, and why documentation alone cannot end an attack class.

## Documentation is not defense

By December 2012, Microsoft had a problem. Duckwall and Campbell had just shipped a Black Hat USA paper titled "Still Passing the Hash 15 Years Later" [823]. Mimikatz was eighteen months old. The institutional position that Pass-the-Hash was a "post-compromise issue" (the line Microsoft had held since 1997) was no longer survivable in public.

The institutional response came in two waves. *Mitigating Pass-the-Hash Attacks and Other Credential Theft*, version 1, shipped in late 2012 (most practitioner secondaries place it in December 2012; no primary Microsoft URL with a verifiable v1 timestamp survives today).

Version 2 followed in July 2014, extending the v1 playbook with the new defensive surfaces that shipped in Windows 8.1 and Windows Server 2012 R2: Protected Users as a deployable security group, Restricted Admin RDP as a default-available feature, LSA Protection (RunAsPPL) as a registry-toggleable defense, and Authentication Policies and Silos as KDC-side restrictions [619]. The two whitepapers are the closest thing the industry got to an institutional Microsoft acknowledgment that Pass-the-Hash was a load-bearing operational problem requiring a defensive playbook rather than a patch.

What did the playbook recommend? Three orthogonal stopgaps, each with a published bypass.

**Protected Users** (Windows Server 2012 R2). A security group whose membership bans, on the DC side, NTLM authentication, DES and RC4 Kerberos pre-authentication, and Kerberos unconstrained delegation; and, on the device side, NTLM caching of the user's plaintext credentials or NTOWF and Kerberos DES/RC4 long-term keys. Member TGTs are capped at 240 minutes (four hours) with no renewal [672]. Documented bypasses: requires explicit opt-in per account, breaks any service that depended on unconstrained delegation, does not apply to computer accounts or service accounts by default, and has no effect on Kerberos AES-key extraction from LSASS (since AES keys are not banned; only RC4 is).

**Restricted Admin RDP** (introduced in Windows 8.1 / Server 2012 R2 RTM, October 2013; backported to Windows 7 / Server 2008 R2 in the May 13, 2014 KB2871997 credential-protection wave and completed for older RDP client/server combinations through the October 2014 follow-on servicing path [831]). An opt-in RDP mode that authenticates to the target without sending credentials, so a compromised target cannot harvest the RDP user's hash from its own LSASS. Documented bypass: opt-in per session, applies only to RDP, leaves SMB, WMI, and RPC unprotected. And it *enables* Pass-the-Hash for RDP: the BloodHound `CanRDP` edge documents the abuse path with the exact Mimikatz command for injecting a stolen NT hash into `mstsc.exe /restrictedadmin` [832].

**LSA Protection / RunAsPPL** (Windows 8.1). A registry toggle that marks LSASS as a Protected Process Light, so non-PPL processes (including unsigned admin tools) cannot open it with `PROCESS_VM_READ`. Documented bypass: any signed kernel driver (including loadable third-party drivers) can still read PPL memory, and an attacker with local admin can load such a driver. The itm4n analysis includes the verbatim Mimikatz output where `sekurlsa::logonpasswords` returns access-denied against a PPL-marked LSASS, and shows that an attacker who loads a signed driver via the BYOVD pattern ("bring your own vulnerable driver") or escalates to kernel mode bypasses the marking. itm4n's framing ("Credential Guard and LSA Protection are actually complementary" [328]) is also the prediction: PPL is part of the answer, but only when paired with the architectural pivot still to come.

> **Definition. Protected Users security group.**
> A Windows Server 2012 R2 security group whose membership applies a set of restrictions, enforced jointly by the device and the domain controller, that block the most commonly extracted long-term credential material: no NTLM, no Kerberos RC4 or DES pre-auth, no unconstrained delegation, no NT-hash caching, and a 240-minute TGT lifetime with no renewal [672].

The structural point is this. Documentation tells administrators *what to do*. It does not prevent the underlying LSASS-resident credential extraction. Every defense documented in v1 and v2 of the Mitigating-PtH whitepapers is bypassable, with a known and published technique, on any system where the attacker already has local administrator, and local administrator is exactly what Pass-the-Hash exploitation *already implies*. The defender's win condition is to keep the attacker from ever getting to local admin in the first place; once they have it, every documented mitigation is a speed bump rather than a wall.

> **What documentation does not isolate.**
> The 2012-2014 era's load-bearing failure mode was assuming that telling administrators where credentials *should* live would prevent extraction from where they *do* live. Protected Users, Restricted Admin RDP, RunAsPPL, and Authentication Silos are all useful, and stacked together they raise the cost of post-admin exploitation. None of them moves the credential out of the address space the attacker can read.
>
> **The Mitigating-PtH v3 that never shipped.**
> A common secondary characterization cites a "v3 2017" of the whitepaper alongside v1 and v2. That document does not exist in Microsoft Download Center ID 36036; the page lists Version 2.0; the 2023 Wayback snapshot of the same Download Center page records Date Published 7/7/2014, while the live page now shows a 2024 republication date for the same Version 2.0 PDF without a version bump [619]. The Download Center page carries v2 metadata only: v1's late-2012 date is sourced through contemporary practitioner literature rather than a primary Microsoft timestamp. After 2014 the post-v2 institutional documentation moves to the Microsoft Learn Credential Guard page rather than to a third whitepaper revision: a structural choice, because by 2015 the architectural answer has shifted from prose to code.

By mid-2014 Microsoft's institutional position was that the protocol-level fix was unavailable and the architectural answer would need to *relocate the credentials*. If credentials cannot stay in LSASS where every admin process can read them, the credentials have to be moved to a place admin processes cannot read. That insight produces Credential Guard.

## Credential Guard and the architectural pivot

On July 29, 2015, Microsoft shipped Windows 10 Enterprise [833]. Hidden in the RTM build was the first defense in the credential-replay lineage that wasn't documentation: hardware-rooted isolation. They called it Credential Guard.

The architecture is worth unpacking carefully, because every later generation of the family is best read as "what does this attack do to the assumptions Credential Guard makes?"

Credential Guard is the first defense in this lineage that isn't documentation, and its architecture is owned in full by the Credential Guard chapter (Chapter 15). In one paragraph: it runs on Virtualization-Based Security, which the Secure Kernel chapter (Chapter 6) splits into a normal VTL0 and an isolated VTL1; it moves the covered secrets into the LSAISO trustlet, one of the signed VTL1 processes the VBS Trustlets chapter (Chapter 7) describes, where no VTL0 process or driver can read them; and HVCI from the Code Integrity chapter (Chapter 8) closes the kernel-mode bypass that would otherwise map VTL1 memory directly. The one fact this chapter needs from that architecture: NT hashes, Kerberos TGT session keys, and "credentials stored by applications as domain credentials" leave VTL0 LSASS for the VTL1 LSAISO trustlet, default-enabled on hardware-eligible domain-joined non-DC systems since Windows 11 22H2 [87].

What does Credential Guard isolate? The Microsoft Learn page is unambiguous: "Credential Guard prevents credential theft attacks by protecting NTLM password hashes, Kerberos Ticket Granting Tickets (TGTs), and credentials stored by applications as domain credentials." [87] Those three categories are also the three categories the previous three generations of the family targeted. Pass-the-Hash hits NTLM password hashes. Pass-the-Ticket hits Kerberos TGTs. Overpass-the-Hash hits NTLM password hashes promoted into Kerberos. Credential Guard moves all three out of VTL0 LSASS into VTL1 LSAISO. On a hardware-eligible domain-joined Windows 10/11 system with Credential Guard enabled, all three attacks return empty buffers.

The institutional importance of the change is that under Microsoft's own *Windows Security Servicing Criteria*, Credential Guard is a *security boundary*. Which means a bypass is a CVE-class vulnerability rather than a documentation gap.

The criteria's load-bearing definitions: "A security boundary provides a logical separation between the code and data of security domains with different levels of trust" and "Does the vulnerability violate the goal or intent of a security boundary or a security feature?" [301] Pre-2015 Pass-the-Hash defenses were documentation; Credential Guard is the first defense the criteria treats as CVE-class under the boundary "admin → VBS (LSAISO trustlet)."

> **Walkthrough: Credential Guard's boundary (recap).**
> `lsass.exe` stays in VTL0 as the broker; the covered secrets move into `LsaIso.exe` in VTL1; VTL0 LSASS asks for authorized operations across an RPC channel instead of reading the bytes; and the hypervisor stops even a VTL0 kernel compromise from mapping VTL1 memory [87]. The full boundary analysis is the Credential Guard chapter's (Chapter 15). The consequence this chapter uses: classic hash and TGT dumping returns empty buffers on supported non-DC endpoints, while every credential category outside Credential Guard's scope stays a separate residual.

What does Credential Guard *not* isolate? This is the load-bearing question for the rest of this chapter. The same Microsoft Learn page enumerates four caveats, each verbatim.

First, the Active Directory database and the SAM. "Credential Guard doesn't provide protections for the Active Directory database or the Security Accounts Manager (SAM)." [87] This is the DCSync gap: an attacker with the right replication privileges can ask a DC to hand over every hash in the directory, and Credential Guard cannot intervene because the data is being released through a legitimate, authorized API rather than being read from LSASS.

Second, domain controllers. "Enabling Credential Guard on domain controllers isn't recommended. Credential Guard doesn't provide any added security to domain controllers." [87] The KDC must read the krbtgt account's long-term key in cleartext to issue tickets; the architectural exception is intrinsic to Kerberos rather than a Microsoft oversight.

Third, application credentials outside the "domain credentials" scope. Certificate private keys held by CryptoAPI key containers, third-party authentication package secrets, and (the one this chapter eventually argues is the most consequential) the Primary Refresh Token material held by the CloudAP authentication plug-in, are all out of scope by construction.

Fourth, and most importantly, the institutional acknowledgment of the supersession pattern. Microsoft Learn reproduces it verbatim on the same page, the prophecy the rest of this chapter spends its time documenting being fulfilled:

> **Quoted source.**
> While Credential Guard is a powerful mitigation, persistent threat attacks will likely shift to new attack techniques, and you should also incorporate other security strategies and architectures.: Microsoft Learn, *Credential Guard overview* [87]

That sentence, written about the 2015 Credential Guard architecture, accurately predicts the 2021-2022 shift to Pass-the-Certificate and the 2020-present shift to Pass-the-PRT. It is Microsoft's own structural prediction that the family will continue to evolve to the next artifact Credential Guard's verbatim scope does not cover. The rest of this chapter reads as the unfolding of that prediction.

> **Why DCs do not get Credential Guard.**
> The Kerberos KDC must read the krbtgt account's long-term key to encrypt the TGT issued in every AS-REP. That key has to be available to the LSA process in cleartext, on every DC, on every ticket issuance, by protocol. Putting krbtgt behind LSAISO would mean issuing every TGT through an inter-trust-level RPC call (a non-trivial performance penalty on every authentication in an Active Directory forest) and would not actually close the architectural gap, because the trustlet itself would still need to do the cleartext work that LSASS does today. The exception is honest about an architectural reality rather than concealing it.

PPL and Credential Guard are *complementary*, not alternatives. itm4n's analysis [328] makes the case carefully: RunAsPPL raises the bar from "any admin process can read LSASS" to "any signed driver can read LSASS," and Credential Guard closes the signed-driver bypass with hardware-rooted hypervisor isolation. They stack. The 2026 best-practice Windows endpoint has both turned on.

The default-enablement window shows how long this took to land. Credential Guard shipped enabled-by-policy in Windows 10 RTM in 2015, but did not become *default-enabled on hardware-eligible domain-joined non-DC systems* until Windows 11 22H2 in September 2022 [87]. Seven years of uneven deployment.

> **What Credential Guard does not cover.**
> Four residuals from the Microsoft Learn page: the Active Directory database and the SAM are out of scope; domain controllers are out of scope by recommendation; application credentials outside the "domain credentials" category (certificates, CloudAP material, third-party authentication packages) are out of scope by construction; and persistent threats are *expected* to shift to new attack techniques. Each residual maps to a later generation in this chapter: AD database → DCSync; certificates → Pass-the-Certificate; CloudAP → Pass-the-PRT.

Each new credential type needs its own isolation boundary. Credential Guard isolates NT hashes and TGT session keys. It does not isolate certificate private keys, because in 2015 nobody was replaying certificates at scale. And it does not isolate the Primary Refresh Token, because in 2015 the Primary Refresh Token did not yet exist.

> **Key idea.**
> Each new credential type needs its own isolation boundary. The pattern is reusable but does not transfer automatically, and the gap between "what fits in the boundary" and "what credentials Windows actually uses" is exactly the territory where the next attack generation grows.

## Pass-the-certificate: The predictable response

If the NT hash is isolated and RC4-HMAC is banned, what is the next long-term credential Windows accepts? The answer was hiding in plain sight: many mature Active-Directory-integrated enterprises had been running Microsoft's PKI for years, and Schroeder and Christensen found template-level catastrophes in nearly every AD CS environment they examined.

On June 17, 2021, Will Schroeder and Lee Christensen posted "Certified Pre-Owned" on Medium, with the accompanying 143-page whitepaper [709] [834]. The post named ESC1 through ESC8 in a single document, with paired DETECT and PREVENT recommendations, and shipped three pieces of tooling at the same Black Hat USA 2021 cycle: Certify (offensive enrollment), ForgeCert (golden-certificate forging using a stolen CA private key), and PSPKIAudit (defensive enumeration). The Medium post's tone was unsubtle:

> **Quoted source.**
> Of note, nearly every environment with AD CS that we've examined for domain escalation misconfigurations has been vulnerable. It's hard for us to overstate what a big deal these issues are.. Will Schroeder and Lee Christensen, *Certified Pre-Owned* [709]

The ESC catalog organizes certificate misconfigurations by the abuse primitive they enable. ESC1 is the canonical example: a published certificate template that allows the enrollee to supply the Subject Alternative Name, contains a client-authentication Extended Key Usage, has permissive enrollment rights, and has no effective approval gates.

An attacker who can enroll for such a template requests a certificate naming a victim principal (say, the domain administrator) in the SAN. The certificate's private key is now the attacker's. PKINIT-authenticate to the KDC with that certificate, and the KDC issues a TGT for the named principal. Domain escalation, in three commands.

> **Definition: Active Directory Certificate Services (AD CS).**
> Microsoft's enterprise PKI. Issues X.509 certificates from administrator-defined templates that pin a certificate's permitted uses (Extended Key Usages), its enrollment authorization rules, its subject and SAN generation policy, and its revocation behavior. Ships as a Windows Server role; widespread in mature Active Directory estates, but not universal.
>
> **Definition, PKINIT.**
> Kerberos pre-authentication using a certificate's private key in place of a long-term symmetric key. Specified by RFC 4556 (L. Zhu and B. Tung, Microsoft and Aerospace, June 2006) [749]. The certificate's UPN SAN (or its dNSHostName for computer accounts) maps the certificate to the principal whose TGT the KDC will issue. PKINIT is the protocol surface most commonly exercised by Pass-the-Certificate against domain controllers that support certificate-based authentication.
>
> **Definition, Schannel.**
> The Windows TLS implementation. Supports TLS client-certificate authentication, which authenticated LDAPS uses. When a domain controller does not support PKINIT (Schroeder + Christensen documented this case in the original catalog; AlmondOffSec built tooling for it), an attacker can authenticate to LDAPS over Schannel with a stolen client certificate and perform high-privilege LDAP operations without traversing the KDC.
>
> **Definition, Pass-the-Certificate.**
> The technique of authenticating to Active Directory with a stolen X.509 certificate's private key, via PKINIT to the KDC or via Schannel client-certificate authentication to LDAPS. Named in this form by Yannick Méheut's PassTheCert tool and blog post (May 2022) [835] [836], though the technique class was cataloged by Schroeder and Christensen eleven months earlier [709]. Tool of record: Certify (C#), Certipy (Python, ESC1-ESC16 [837]), and Rubeus PKINIT mode.
>
> **Walkthrough: ESC1 / Certifried-style certificate replay.**
>
> 1. A certificate template lets the enrollee supply a subject alternative name or otherwise map the certificate to a different principal.
> 2. The attacker enrolls and receives a real X.509 certificate plus private key from the enterprise CA.
> 3. The attacker uses PKINIT in an AS-REQ, proving possession of the private key rather than a password [749].
> 4. If the KDC maps the certificate to the victim principal, it returns a TGT for that victim.
> 5. KB5014754 changes this mapping decision for the Certifried class by requiring strong binding to the account SID, but template and CA misconfiguration classes outside that mapping bug remain administrative hardening work [770] [837].

The CVE-class case lands on May 10, 2022. Oliver Lyak of IFCR discloses Certifried, CVE-2022-26923, an Active Directory Domain Services elevation-of-privilege vulnerability in which the combination of three Microsoft defaults: `ms-DS-MachineAccountQuota = 10` (any authenticated user can add up to 10 computer accounts to the domain), the default Machine template (which a computer account can enroll for), and the KDC's permissive `dNSHostName`-to-SAN binding logic, lets any authenticated user obtain a certificate that maps to a computer account, including a domain controller.

PKINIT-authenticate as a domain controller, and the KDC issues you a TGT for the DC; from there, DCSync extracts the krbtgt key and the domain is yours. Domain escalation from any authenticated user, with the only required misconfiguration being *Microsoft's defaults* [769] [838].

The defensive response shipped the same day. Microsoft published KB5014754 on May 10, 2022 (coordinated disclosure, with the patch shipping in the same window as the CVE) introducing a new X.509 extension `szOID_NTDS_CA_SECURITY_EXT` (OID `1.3.6.1.4.1.311.25.2`) that carries the requesting principal's SID at certificate issuance.

The KDC's new strong-mapping logic refuses certificates that fail one of four conditions: the SID extension is present and matches; an issuer-serial mapping is present; a Subject Key Identifier mapping is present; or a SHA1-public-key mapping is present. The KB's load-bearing sentence: "In Full Enforcement mode, if a certificate fails the strong (secure) mapping criteria (see Certificate mappings), authentication will be denied." [770]

 (Side note: The KB5014754 change-log preserves a forensic artifact of the coordinated-disclosure timeline that is easy to miss. The current change-log row reads, verbatim: "9/10/2025 - Corrected the Enforcement mode date from September 10, 2025, to September 9, 2025." [770] An off-by-one date correction, captured in the public KB. The kind of detail that only shows up when a small team has had to ship a date repeatedly against a multi-year audit-to-enforcement schedule.)

The enforcement timeline tells you how long even a CVE-class fix took to drive through deployment. Audit mode (May 10, 2022). Enforcement mode with a registry escape that admins could use to revert to compatibility (February 11, 2025). Final cutover with no escape (September 9, 2025) [770]. Three years and four months between the patch and the day Microsoft stopped accepting non-strong certificate mappings. Faster than the Credential Guard default-enablement window, but still measured in years.

The naming history deserves a disambiguation. The *catalog* (ESC1 through ESC8, the full taxonomy of AD CS misconfigurations) is Schroeder and Christensen, June 2021 [709]. The *wire-level technique name* "Pass-the-Certificate" is popularised by AlmondOffSec's PassTheCert PoC (Yannick Méheut, May 4, 2022), which targets LDAP/S via Schannel client-cert authentication when PKINIT is unavailable, as a fallback path for environments where domain controllers do not support certificate-based Kerberos pre-authentication [835] [836]. Méheut's write-up documents the `KDC_ERR_PADATA_TYPE_NOSUPP` error path that diverts the PKINIT-blocked attacker into Schannel.

 (Side note: The AlmondOffSec blog post acknowledges the social attribution of the term: "Note for Googlers: this tool extends the notion of Pass the Certificate, thus dubbed by @_nwodtuhs in his Twitter thread on AD CS and PKINIT." [836] The technique name is socially attributed; the catalog framing is editorial.)

> **Causal arrow correction.**
> A common shorthand says that KB5014754 bound NTOWFs to Kerberos, and that this is what forced attackers to shift to certificates. That arrow runs backwards in time. KB5014754 is the *response* to Certifried, not the cause of Pass-the-Certificate. The technique class was cataloged by Schroeder and Christensen in June 2021, eleven months before KB5014754 shipped, and the PassTheCert tool that gave the technique its wire-level name appeared six days before Certifried's disclosure. The shift to certificates happened because certificates were the next long-term credential type Credential Guard did not isolate.

What does KB5014754 actually close? Three specific CVEs in the Certifried family: CVE-2022-26923 (the original SID-spoof Certifried disclosure), CVE-2022-26931 (UPN / sAMAccountName collision spoof), and CVE-2022-34691 (the certificate-pre-dating-account-creation case) [770]. What does it *not* close? The broader ESC2 through ESC8 catalog, which is administrative hardening rather than CVE-class control. And it does not close ESC9 through ESC16, which were enumerated *after* KB5014754 shipped and include cases like the `CT_FLAG_NO_SECURITY_EXTENSION` template flag that *exempts* a template from the very SID extension the patch introduced [839] [837].

The current state of the catalog: as of the 2025 Certipy 5.x documentation, ESC1 through ESC16 is the practitioner enumeration, with each technique characterized by a template-level, ACL-level, CA-administrator-level, NTLM-relay-level, SID-extension-level, or mapping-level abuse primitive [837]. Microsoft Defender for Identity's certificates posture assessment tracks nine distinct ESC numbers as of the 2025 documentation: ten posture assessments, because ESC4 owner and ESC4 ACL are tracked as separate sub-cases (ESC1, ESC2, ESC3, ESC4 owner, ESC4 ACL, ESC6 preview, ESC7, ESC8, ESC11, ESC15) [840]. Same pattern as Pass-the-Hash in 2012-2014: documentation tells administrators what to do; the structural exposure is downstream of how each enterprise built its templates years earlier.

| ESC ID | Class | Closed by KB5014754 |
| -: | -: | -: |
| ESC1 | Template: enrollee supplies SAN, client-auth EKU, permissive enrollment | Partial: SID extension binds requester at issuance; ESC1 still works if the SID extension is absent |
| ESC2 | Template: enrollee supplies SAN, Any-Purpose or no EKU | No: administrative hardening |
| ESC3 | Template: Certificate Request Agent enrollment-agent abuse | No: administrative hardening |
| ESC4 | ACL: writeable template configuration | No: administrative hardening |
| ESC6 | CA: `EDITF_ATTRIBUTESUBJECTALTNAME2` flag set on the CA | No: CA-level hardening, separately patched |
| ESC8 | NTLM relay: HTTP enrollment endpoints reachable from low-privilege contexts | No: relay-defense hardening |
| ESC9 | Template: `CT_FLAG_NO_SECURITY_EXTENSION` exempts template from the SID extension | No: by design |
| ESC11 | NTLM relay: ICPR RPC endpoint without sign / seal | No: relay-defense hardening |
| ESC16 | CA: security-extension disabled at the CA level | No: CA-level hardening |

*Table 1. A representative slice of the ESC1-ESC16 catalog showing what KB5014754 closes and what remains administrative hardening [841] [837] [839].*

KB5014754 is a CVE-class fix for one sub-case. The broader ADCS catalog is administrative hardening. And the *next* credential type (the one that defeats Credential Guard, Protected Users, and KB5014754 simultaneously) was already shipping in commodity Mimikatz code by August 2020.

## Pass-the-PRT: The CloudAP frontier

By August 2020, the architectural defense against credential replay that the security industry actually trusted was Credential Guard, which isolated local Active Directory credentials in VTL1. (KB5014754, the fix for the certificate-replay class, was still nearly two years away; it shipped in May 2022.) Then a Dutch security researcher named Dirk-jan Mollema published a 21-minute read that went around Credential Guard entirely, by replaying a different credential type it never isolated.

The credential is the Primary Refresh Token. The two foundational write-ups are Mollema's "Abusing Azure AD SSO with the Primary Refresh Token" [820] and its follow-on "Digging further into the Primary Refresh Token" [819], both posted in August 2020. The second post is the single most-cited primary source in the fifth generation of the family. Read it once and you understand why Pass-the-PRT is structurally different from everything that came before.

A PRT is an opaque refresh-token artifact issued by Microsoft Entra ID (formerly Azure AD) to a broker on Entra-joined or Hybrid-joined Windows devices, paired with a session key (an HMAC-SHA256 secret) used for proof-of-possession and bound to the device keys registered at device join.

The Microsoft Entra documentation describes the artifact precisely: "A Primary Refresh Token (PRT) is a key artifact of Microsoft Entra authentication... Once issued, a PRT is valid for 90 days and is continuously renewed as long as the user actively uses the device." [683] On Windows the PRT is refreshed during active sign-in use. The device-key registration binds the PRT to the device that owns it, and is what an attacker has to work around to replay PRT-derived material from a different context.

> **Definition: Primary Refresh Token (PRT).**
> The Microsoft Entra-issued long-lived refresh token for SSO on Entra-joined or Hybrid-joined Windows devices. Carries a session key (HMAC-SHA256) used to sign per-request `x-ms-RefreshTokenCredential` cookies, and binds to a device transport key registered at device join. It is valid for 90 days and is continuously renewed while the user actively uses the device [683]. The PRT is the load-bearing artifact for Single Sign-On to Entra-integrated resources, subject to client context, Conditional Access, token binding, and resource support.

Where the PRT *lives* is what makes the rest of the architecture work, and what makes it vulnerable. The PRT is *hybrid*: issued and revoked cloud-side by Entra ID, protected on Credential-Guard-on Entra-joined devices under the `LsaIso`/Credential Guard storage model as far as this public source corpus lets us infer, and used client-side through the **CloudAP** authentication plug-in, which is loaded into LSASS like any other Windows authentication package.

The load-bearing structural fact is a storage-versus-use distinction. On Credential-Guard-on Entra-joined devices, this chapter treats the long-lived PRT/session-key state as protected by the `LsaIso`/Credential Guard storage model; Microsoft documents the protected-secret categories and PRT broker model, while the exact private placement is inferred from that scope plus public Mollema/Delpy behavior. CloudAP is still loaded in VTL0 `lsass.exe`, however, because Windows must use the PRT for SSO. The replay seam Mollema documented is the in-use SSO-cookie derivation that CloudAP performs in VTL0: the attacker does not need to read the isolated long-lived root if they can cause the local broker to mint or expose a derivative that Entra accepts [820] [819].

> **Definition, CloudAP (Cloud Authentication Provider).**
> The Windows authentication package (`cloudap.dll`, loaded into LSASS) that handles authentication against Microsoft Entra ID for Entra-joined and Hybrid-joined devices. Brokers use of the device's Primary Refresh Token and the derived material used to sign per-request PRT cookies. On Credential-Guard-on Entra-joined devices, the long-lived PRT/session-key state is treated here as protected by Microsoft-documented device/TPM binding and, where applicable, Credential Guard storage posture; CloudAP's VTL0 role is the in-use derivation and SSO-broker path, which remains the replay surface.

The mechanism, as Mollema and Delpy developed it through the second half of 2020, is best read as a storage-versus-use attack. On systems without the modern isolation posture, tooling could recover PRT-associated material from CloudAP's working memory. On Credential-Guard-on Entra-joined devices, the claim is not raw export of the protected root. The residual is that CloudAP in VTL0 still has to ask for, receive, sign, or handle PRT-derived SSO-cookie material so the user can sign in without retyping a password.

The attacker constructs or obtains an `x-ms-RefreshTokenCredential` JWT whose payload carries `is_primary: true`, a fresh `request_nonce`, and either the opaque PRT refresh-token claim or a brokered equivalent. ROADtools' `roadtx prt` implements the server-challenge nonce pattern by posting `grant_type=srv_challenge` to the Entra ID v1 token endpoint and using the returned `Nonce` value [821]. The signature is HMAC-SHA256 over the JWT under PRT-associated proof material produced through the local SSO path. The completed cookie is then accepted or rejected in the normal Entra authorize/token flow: cookie acceptance proves PRT-derived possession, and access or refresh tokens are issued only for the requested client/resource subject to Conditional Access, device binding, Token Protection support, and downstream verifier policy. Mollema's second post describes the collaboration that built the tooling:

> **Quoted source.**
> Around the same time Benjamin Delpy took up my 'challenge' of recovering PRT data from `lsass` with mimikatz. We combined forces and ended up with tooling that is not only able to extract the PRT and associated cryptographic keys (such as the session key) from memory, but can also use these keys to create new SSO cookies or modify existing ones.: Dirk-jan Mollema, *Digging further into the Primary Refresh Token* [819]

The operational tooling closed quickly. Mollema's `roadtx prt` (part of ROADtools [821]) automates the full chain end-to-end: exercise the local broker, recovered raw material, or an already completed cookie; complete the OAuth dance for a particular client/resource; and hand the attacker the resulting token only if policy and binding checks allow it. The Mimikatz `dpapi::cloudapkd` command landed in the open-source repository the same window. Pass-the-PRT moved from research artifact to commodity tooling in months, not years.

> **Walkthrough: Pass-the-PRT without confusing storage and use.**
>
> 1. Establish the posture: on a Credential-Guard-on Entra-joined endpoint, treat the long-lived PRT/session-key state as protected by the `LsaIso`/Credential Guard storage model; CloudAP remains the VTL0 broker that turns that state into SSO cookies for normal user sign-in.
> 2. The attacker with local administrator does not have to prove that the isolated root secret was copied out of VTL1. The operational proof is weaker and more important: the attacker causes or observes the VTL0 broker path that produces PRT-derived cookie proof material during legitimate SSO use [820] [819].
> 3. The attacker asks Entra ID for a fresh server challenge by posting `grant_type=srv_challenge` to the v1 token endpoint. ROADtools' `roadtx prt` implements this nonce step [821].
> 4. The attacker builds an `x-ms-RefreshTokenCredential` JWT: header declaring HMAC-SHA256, payload carrying `is_primary: true`, the opaque PRT refresh-token claim, a brokered equivalent, or an already completed cookie captured from the local SSO path, and the fresh `request_nonce`.
> 5. The attacker signs the JWT with PRT-associated proof material produced through the local CloudAP path, or reuses a completed cookie, and sends it to `login.microsoftonline.com` from a different context.
> 6. Entra ID validates the signature and nonce in the relevant authorize/token flow. For clients or resources not enforcing device-bound Token Protection, the result is the same architectural outcome as 1997: a reusable proof produced on one machine authenticates somewhere else.

Now the analytical core. Pass-the-PRT can bypass three Microsoft defenses *simultaneously* when the target resource path does not enforce device-bound token protection.

First, **Credential Guard** isolates NTLM hashes and Kerberos TGTs, but its documented scope does not include the CloudAP-held PRT. The PRT and its session key live in VTL0 LSASS; the TPM seals the device and transport keys at rest, but Mollema's work shows that with local administrative control an attacker can extract the PRT and session key from CloudAP and replay them on another device [87] [819].

Second, **KB5014754** is out of scope. The PRT cookie does not traverse the KDC's certificate-mapping logic at all; it is a JWT signed by an HMAC and authenticated at the Entra ID token endpoint. The strong certificate mapping that Microsoft drove through five years of audit-to-enforcement timeline has no relevance to a credential that never touches the KDC [770].

Third, **Protected Users** is out of scope. Protected Users is an Active-Directory-only construct, enforced on Windows Server domain controllers and on AD-joined member devices. Entra ID is a separate identity provider with separate enforcement; the 240-minute TGT cap, the NTLM ban, and the RC4 ban that Protected Users enforces simply do not apply [672].

The TPM-sealing finding is where the architectural pattern becomes most precise. Microsoft began sealing the PRT session key to a TPM-bound key on TPM-2.0-eligible hardware: a defense that, in principle, makes the raw session key cryptographically non-exportable. Mollema's finding in the August 2020 second post is that the seal does not close the attack, because the local SSO broker still obtains or handles *derived* PRT-cookie-signing material during normal use, and the attacker only needs that derivative:

> **Quoted source.**
> despite the session key of the PRT is stored in the TPM whenever possible, this doesn't prevent us from extracting the PRT and the required information to create SSO cookies. The result of this is that regardless of whether the PRT is protected by the TPM or not, with Administrator access it is possible to extract the PRT from LSASS and use the PRT on a different device than it was issued to.: Dirk-jan Mollema, *Digging further into the Primary Refresh Token* [819]

The structural reason the standard hardware-rooted defense pattern does not transfer: the attacker does not need the raw session key out of the TPM or LsaIso. They need the in-use derivative CloudAP causes to be signed or handled in VTL0 so that an SSO cookie can be accepted elsewhere.

The TPM and LsaIso-class storage protections protect the root where that posture applies. CloudAP uses the root through a brokered SSO path. Whatever derivative CloudAP can legitimately ask for or handle in VTL0 becomes the replay surface for an attacker with administrator-level control. The defense pattern that worked for NT hashes must therefore cover both storage and use; storage alone is a speed bump rather than a wall.

**Cookie anatomy, in prose.** The `x-ms-RefreshTokenCredential` object is a JWT-like proof: a header declaring HMAC-SHA256, a payload that marks the assertion as primary and carries a fresh server nonce, and a signature produced with PRT-associated proof material. The security question is not how to build one by hand; it is whether the endpoint lets an attacker obtain or induce the proof material outside the intended user session.

The current partial mitigations are worth enumerating, because none of them universally closes the gap across clients and resources.

**Token Protection** (a Conditional Access session control) attempts to ensure that only device-bound sign-in session tokens are accepted at the Entra ID token endpoint for protected resources. The Microsoft Learn page is explicit about both the design intent and the deployment limits: "Token Protection is a Conditional Access session control that attempts to reduce token replay attacks by ensuring only device bound sign-in session tokens, like Primary Refresh Tokens (PRTs), are accepted by Microsoft Entra ID when applications request access to protected resources." [842] As of the current documentation the *supported resources* are five named applications: Exchange Online, SharePoint Online, Microsoft Teams, Azure Virtual Desktop, and Windows 365. Browser applications are out of scope; "Token Protection currently supports native applications only. Browser-based applications are not supported." [842] Most Entra-integrated SaaS is unbound.

**Continuous Access Evaluation** (CAE) can reduce the usefulness of downstream access tokens and sessions for CAE-capable client/resource combinations after triggering signals such as password change, account disablement, risk detection, or policy change [124]. CAE is evaluation-time, not isolation. It can shrink post-replay dwell time; it does not prevent proof extraction, bind every resource, or directly invalidate a copied PRT.

**Hybrid-joined PRT renewal binding** partially closes the cross-tenant case for hybrid Azure AD Join configurations, but does not address the same-tenant Pass-the-PRT case that Mollema's original 2020 posts described [843].

The institutional acknowledgment of the supersession pattern is the verbatim Microsoft Learn sentence already quoted in the Credential Guard discussion [87]: written about the 2015 Credential Guard architecture, it accurately predicts the 2020 Pass-the-PRT shift. The credential-replay family has reached the point where the on-prem stack can be correctly deployed and still be irrelevant to an Entra token proof accepted by an unsupported or unbound cloud resource.

> **Key idea.**
> Pass-the-PRT bypasses the practical protection delivered by Credential Guard, KB5014754, and Protected Users when the target verifier path accepts unbound PRT-derived proof, because each defense was designed around a different artifact or verifier path, while the replay seam is CloudAP's in-use SSO-cookie derivation. The architectural property (a long-term authentication artifact reachable from the using process is replayable) is unchanged. The artifact moved.

Six years after Mollema's disclosure, the TPM-resilience finding still matters. CloudAP still has a VTL0 SSO-broker role. Credential Guard can protect the long-lived PRT/session-key storage model on CG-on Entra-joined devices, but the in-use cookie derivation and verifier-binding path remain the operational frontier in 2026.

## Verify it yourself (documented): the PRT population and Credential Guard posture

Honesty about evidence is part of the argument here. This chapter has no private VM capture, no hash of a recovered token, and no claim that the author replayed a PRT in a lab. It therefore must not dress a documentation probe up as exploit evidence. The live proof below establishes the endpoint's membership in the relevant population: Entra join state, user PRT state, refresh timing, and whether the device key is hardware-backed. The replay proof remains Mollema and Delpy's public research and tooling, not an unpublished capture in this book [820] [819] [821].

> 🔵 **DOCUMENTED**: Microsoft Learn, *Primary Refresh Token* and `dsregcmd /status`.
> Reproduce on a Windows endpoint: `dsregcmd /status`.

```text
+----------------------------------------------------------------------+
| Device State                                                         |
+----------------------------------------------------------------------+
    AzureAdJoined : YES        # Entra-joined device population
    DomainJoined  : YES/NO     # hybrid state depends on deployment
    DeviceAuthStatus : SUCCESS # device object is usable by Entra ID

+----------------------------------------------------------------------+
| SSO State                                                            |
+----------------------------------------------------------------------+
    AzureAdPrt : YES           # signed-in user has a PRT
    AzureAdPrtUpdateTime : <timestamp of last refresh>
    AzureAdPrtExpiryTime : <timestamp if present on this build>

+----------------------------------------------------------------------+
| Device Details / Key State                                           |
+----------------------------------------------------------------------+
    KeyProvider  : Microsoft Platform Crypto Provider
    TpmProtected : YES         # device key is TPM-protected where available
```

Read those lines as a chain of necessary conditions, not a proof of compromise.

1. `AzureAdJoined: YES` means Windows has a tenant-side device identity and the CloudAP path is in scope. If this is `NO`, the Pass-the-PRT discussion may still matter for hybrid or workplace-joined variants, but this specific endpoint is not the clean Entra-joined specimen.
2. `AzureAdPrt: YES` means the signed-in user has the artifact class this chapter is about. If it is `NO`, there is no local user PRT to reason about at that moment, and a replay chain must first explain why the PRT is absent.
3. `AzureAdPrtUpdateTime` tells you the PRT is being refreshed through normal use. The correct timer is inactivity: Microsoft documents that a PRT is valid for 90 days and continuously renewed while the user actively uses the device [683]. Do not import older inactivity-window assumptions into the investigation.
4. `KeyProvider: Microsoft Platform Crypto Provider` and `TpmProtected: YES` tell you the device key is hardware-backed where the platform supports it: TPM-protected key storage as established in the TPM chapter (Chapter 2). That is a real control; it does not prove every CloudAP in-use derivative is isolated from VTL0.
5. `DeviceAuthStatus: SUCCESS` matters because a stale or disabled device object breaks different things than PRT replay. If the device is not healthy, failed SSO is not evidence of Token Protection or Credential Guard success.

The same proof needs a Credential Guard posture check. The supported Windows query is:

```powershell
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard | Format-List
```

The fields to preserve in a lab notebook are `SecurityServicesConfigured` and `SecurityServicesRunning`. A running value that includes `1` means Credential Guard is actively running; a configured value without a running value is only policy intent. This distinction matters for the chapter's core claim. If Credential Guard is not running, raw LSASS extraction failures or successes say little about the modern storage/use boundary. If Credential Guard is running and `AzureAdPrt: YES`, you have the interesting specimen: the long-lived PRT/session-key storage boundary should be treated as part of the protected LsaIso model, while the CloudAP SSO-broker path remains the use surface under discussion [87] [683].

A careful lab record for this chapter would therefore have four tiers of evidence:

| Tier | Evidence | What it proves | What it does not prove |
| -: | -: | -: | -: |
| 1 | `dsregcmd /status` with `AzureAdJoined: YES` and `AzureAdPrt: YES` | The endpoint/user is in the PRT SSO population | Theft or replay |
| 2 | `TpmProtected: YES` and Platform Crypto Provider | Device-key hardware backing | Isolation of every PRT-derived SSO-cookie use path |
| 3 | `Win32_DeviceGuard` showing Credential Guard running | VBS/LSAISO posture for covered secrets | That CloudAP's in-use derivative never appears in VTL0 |
| 4 | Public Mollema/Delpy/ROADtools chain | Replay feasibility and tooling lineage | This book's own captured replay |

That is the evidence boundary. The chapter's argument is not "I secretly stole a PRT." The argument is: Microsoft documents the PRT population and timer [683]; Microsoft documents Credential Guard's protected categories and VBS model [87]; Mollema documents that PRT-derived SSO-cookie material could be created and replayed even when TPM protection existed [820] [819]; ROADtools operationalises the nonce and cookie flow [821]; and Token Protection's documented scope remains a closed list of supported native-app resources rather than universal verifier binding [842]. The intersection of those documented facts is enough to identify the residual architectural gap without fabricating a lab capture.

## Where this link breaks: Residual map

The residual is not that Credential Guard is useless. It is that Credential Guard's storage guarantee, CloudAP's broker guarantee, and Entra's verifier guarantee are three different guarantees. A control can be excellent at one layer and irrelevant at the next.

| Residual | Source anchor | Observable | Control | Failure mode |
| -: | -: | -: | -: | -: |
| Covered AD secrets moved out of VTL0 | Credential Guard protects NTLM hashes, Kerberos TGTs, and domain credentials [87] | `Win32_DeviceGuard` shows Credential Guard running; classic `sekurlsa` buffers are empty | Credential Guard, VBS, LsaIso | Does not by itself isolate every CloudAP SSO-cookie derivation path |
| PRT exists and refreshes with use | Microsoft Entra PRT documentation [683] | `dsregcmd /status` shows `AzureAdPrt: YES` and update time | Device join health, Conditional Access, sign-in risk policy | Presence is not compromise; absence changes the hypothesis |
| Root storage and use path differ | Mollema's CloudAP/PRT work plus Microsoft Credential Guard scope [820] [819] [87] | CG-on endpoint with PRT population and CloudAP-loaded SSO behavior | Protect root storage where supported; reduce local admin; monitor broker path | Attacker targets the derivative or brokered proof, not necessarily the root secret |
| TPM binding raises key-export cost | PRT device-key model and Mollema's TPM observation [819] [683] | `TpmProtected: YES`; Platform Crypto Provider | TPM 2.0, attested device join | Non-exportable keys can still be asked to sign; proof material can be abused if exposed through the using process |
| Token Protection is verifier-side and partial | Microsoft Token Protection supported-resource list [842] | CA policy evaluation; sign-in logs for protected apps; resource list review | Token Protection for Exchange Online, SharePoint Online, Teams, Azure Virtual Desktop, Windows 365 | Unsupported browser paths, third-party SaaS, and legacy integrations accept unbound tokens |
| CAE shortens revocation latency | Continuous Access Evaluation docs [124] | Sign-in/risk events followed by token invalidation | CAE-capable resources and risk signals | Does not prevent the first derivation or first replay before revocation |
| AD CS remains a sibling residual | Certified Pre-Owned, KB5014754, Certipy/Certify catalogs [709] [770] [837] [841] | Template flags, EKUs, enrollment ACLs, security extension state | Strong mapping enforcement; recurring ESC audit | ESC template/ACL/relay/mapping errors survive the Certifried CVE fix |

The operational threshold is local administrative control. Most of the family starts there because the attacker must read or drive an authentication broker that the operating system intentionally protects from ordinary users. That premise should not be hand-waved away. If an enterprise's endpoint hardening, EDR, application control, and privilege model prevent local admin, the Pass-the-PRT path is much harder. If the attacker has local admin, the question changes from "can they read every secret?" to "which legitimate authentication use path can they coerce, observe, or replay?" That is the exact same pivot Ochoa made in 2008 when he stopped patching Samba and started patching LSASS-resident credential state [824].

The residual map also gives defenders the right failure labels. A stolen PRT-derived cookie used successfully against an unprotected SaaS app is not a Credential Guard failure if the long-lived PRT/session-key root remained protected. It is a verifier-binding failure at the resource and token endpoint. A successful replay before CAE revokes the session is not proof that CAE is useless. It is proof that CAE is a dwell-time control rather than an extraction control. A certificate-authentication bypass after KB5014754 enforcement is not necessarily a Microsoft patch failure; it may be an ESC template or CA ACL failure. The family persists because teams collapse these layers into one word ("credential") and then buy a control that only protects one layer.

The structural reading is therefore: ask four questions for every row. Where is the root stored? Where is the proof produced? Which verifier accepts the proof? Which resource enforces binding? A row is closed only when all four answers point to a boundary stronger than the compromised host.

## The 5×5 matrix and the irregular cadence

Five generations of attack. Five generations of defense. They map onto each other unevenly; the gaps are not five years.

The matrix below consolidates the lineage at a glance. Rows are the attack generations (in the order they entered the practitioner literature). Columns are the defense generations (in the order they shipped). Each cell records whether that defense closes that attack's covered local-extraction or verifier path on a fully-deployed hardware-eligible 2026 Windows 11 endpoint with the control turned on. "Closed" means local extraction on that protected endpoint returns empty buffers or authentication fails for that defense's covered path; "Partial" means the defense increases attacker cost or closes one sub-case; "Open" means the defense's design scope does not include that attack.

| Attack \\ Defense | Mitigating-PtH whitepapers (2012/2014) | Protected Users + RunAsPPL + Restricted Admin (2013-2014) | Credential Guard / LSAISO (2015) | KB5014754 strong mapping (2022) | Token Protection + CAE (2023-2025) |
| -: | -: | -: | -: | -: | -: |
| Pass-the-Hash (Ashton 1997, Ochoa 2008) | Open (documentation) | Partial (Protected Users members) | Closed for local extraction on enabled endpoints | Open (not in scope) | Open (not in scope) |
| Pass-the-Ticket (Delpy 2011, Duckwall+Delpy 2014) | Open (documentation) | Partial (4-hour TGT cap for Protected Users) | Closed for local extraction (TGT session key in LSAISO) | Open (not in scope) | Open (not in scope) |
| Overpass-the-Hash (Delpy / Metcalf 2014) | Open (documentation) | Partial (RC4 banned for Protected Users) | Closed for local extraction (NT hash in LSAISO) | Open (not in scope) | Open (not in scope) |
| Pass-the-Certificate (Schroeder + Christensen 2021, Méheut 2022) | Open (documentation) | Open (cert keys outside scope) | Open (cert keys outside scope) | Partial (closes Certifried sub-case; ESC2-ESC16 remain) | Open (not in scope) |
| Pass-the-PRT (Mollema + Delpy 2020) | Open (Entra ID is separate IDP) | Open (Entra ID is separate IDP) | Open for unbound verifier paths (in-use CloudAP derivation in VTL0) | Open (not in scope) | Partial (5 named resources; browser apps out of scope) |

*Table 2. The 5×5 attack/defense matrix. The union of every cell in the rightmost column of "Closed" entries is the set of local-extraction paths Microsoft's published 2026 defenses close on hardware-eligible non-DC endpoints with every control turned on; that set is precisely the first three rows, not replay of material obtained from SAM/NTDS.dit, DCSync, a DC, or another host.*

![Figure: The 5×5 attack/defense matrix as a heatmap. Five attack generations (rows) against five defense generations (columns), each cell graded Closed (returns empty buffers or fails authentication), Partial (one sub-case or raised cost), or Open (outside the defense's design scope) on a hardware-eligible 2026 Windows 11 endpoint with every control on. The fully-Closed cells form a single green block in the Credential Guard column, confined to Generations 1–3; Pass-the-Certificate and Pass-the-PRT reach only Partial, so the staircase of closed cells never reaches the cloud era.](diagrams/11-pth-prt-attack-defense-matrix.svg)

The matrix makes the structure visible. No single defense closes all attacks, and no single attack is closed by all defenses. The union of every defense closes *local extraction of covered material for* Pass-the-Hash, Pass-the-Ticket, and Overpass-the-Hash on hardware-eligible non-DC Windows 10/11 systems with all controls enabled. It partially closes Pass-the-Certificate (for the Certifried sub-case) and partially closes Pass-the-PRT (for five named resources). Both of the most recent generations remain operationally open against any deployment that does not run those specific controls. Which is most deployments.

The cadence is just as uneven as the matrix. A popular shorthand claims that "every Windows defense against credential replay buys about five years before the attack class evolves to the next credential type." Memorable. Also wrong. The actual timeline produces gaps from eleven months to eleven years, with one negative interval:

- **1997 → 2008** (eleven years) for the Samba-patch → Windows-native pivot. Pass-the-Hash existed for over a decade as a Unix-side novelty before Ochoa's LSASS-injection insight made it Windows-native.
- **2008 → 2011** (three years) for the Mimikatz Pass-the-Ticket extension. The same memory-access primitive that animated `IAM.EXE` was retargeted at a different artifact.
- **2012/2014 → 2015** (one to three years) for the Mitigating-PtH whitepapers → Credential Guard pivot. Documentation took a year and a half to ship; the architectural counter took another.
- **2021 → 2022** (eleven months) for the AD CS catalog → KB5014754 response. Coordinated disclosure compressed this gap; Certifried's CVE-class status forced a CVE-class response.
- **2020 → 2025+** (open-ended) for Pass-the-PRT with no Credential-Guard-equivalent for the CloudAP use path shipped. As of the source corpus reviewed for this chapter, I found no public Microsoft roadmap for VBS-class isolation of every CloudAP SSO-cookie derivation path.

The most striking gap is the 2020/2021 *negative* interval. Pass-the-PRT (Mollema, August 2020) and the AD CS catalog (Schroeder + Christensen, June 2021) are siblings rather than sequential; Pass-the-PRT predates the Pass-the-Certificate tooling/name popularisation by about twenty-one months, even though this chapter treats them as Generation 4 and Generation 5 in narrative order. The Generation N → N+1 framing is *taxonomic*, not strictly chronological. The reader needs this distinction to read the lineage accurately: the attack class evolves along the architectural property, not along the calendar.

> **The five-year drumbeat was selection bias.**
> The "every Windows defense buys five years" framing is what you see if you select the cleanest pairings (Mitigating-PtH 2012/2014 to Credential Guard 2015 plus an artificial 2020-targeted "next attack"). When you look at the actual intervals, you see eleven years (1997-2008), three years (2008-2011), eleven months (2021-2022), and an open-ended interval (2020 onwards). The pattern is the architectural property persisting across artifact changes, not a calendar drumbeat.

The storage-class progression is the cleanest way to see the property hold across the lineage. Each row names the long-term artifact, where it lives, and which defense moved or shielded that storage class.

| Generation | Long-term artifact | Storage location | Defense that isolated it | Status 2026 |
| -: | -: | -: | -: | -: |
| 1A (1997 Samba) | NT hash (and LM hash) | Attacker-supplied hash (Samba `smbpasswd`) | "Do not store LAN Manager hash" policy (Vista default-on); SAM hash extraction still works | LM hash retired; NT hash extraction still works |
| 1B (2008 Windows-native) | NT hash | LSASS credential cache | Credential Guard relocates to LSAISO | Closed for local extraction on Credential-Guard-enabled endpoints |
| 2 (2011 Mimikatz) | Kerberos TGT plus session key | LSASS Kerberos package | Credential Guard relocates to LSAISO | Closed for local extraction on Credential-Guard-enabled endpoints |
| 3 (2014) | NT hash promoted to RC4-HMAC Kerberos key | LSASS, same buffer as Pass-the-Hash | Credential Guard relocates to LSAISO; KB5021131 makes AES the default | Closed for local extraction on Credential-Guard-enabled endpoints; RC4 remains compatibility-supported but Microsoft recommends AES-only hardening where possible [756] |
| 4 (2021 AD CS catalog) | X.509 certificate private key | CryptoAPI key container, TPM, or smart card | TPM-resident or VSC-resident keys are cryptographically non-exportable; KB5014754 binds certificates to SIDs at issuance | Partial; ESC2-ESC16 misconfigurations remain administrative hardening |
| 5 (2020 Pass-the-PRT) | PRT session key plus derived signing material | PRT and session key held by CloudAP in VTL0 LSASS (outside Credential Guard's scope); device/transport keys TPM-sealed at rest | TPM seals device/transport keys at rest, but the PRT and session key are extractable from LSASS with local admin; Token Protection partially shields named resources | Open for unbound paths |

*Table 3. Storage-and-use progression. Each attack generation targets the next authentication artifact whose storage location, use path, or verifier binding is not fully covered by the previous generation's defense.*

![Figure: The storage-class progression as a layered staircase, read as gap analysis. Each defense relocates the long-term secret inward to a stronger boundary: on-disk SAM → the lsass.exe cache → the LsaIso VTL1 trustlet → a TPM/VSC key container, and the family targets the next artifact just outside it. The bottom rung is the crux: the CloudAP-held PRT and its session key live in VTL0 LSASS outside Credential Guard's scope, with only the device/transport keys TPM-sealed at rest, so an attacker with local admin can extract and replay them. The boundary the staircase never reached, and the seam where Generation 6 (Pass-the-DeviceKey) is forecast.](diagrams/11-pth-prt-storage-class-ladder.svg)

The matrix and the storage/use table jointly produce the structural prediction: each generation shifts to the next available authentication artifact whose storage class, use path, or verifier binding the latest defense does not fully cover. The graph-based formalization of these transitions is the BloodHound edge catalog: the `HasSession`, `AdminTo`, and `CanRDP` family that operationalises "which principal can reach which credential from where" as a queryable property of an enterprise's directory [844]. The pattern predicts a Generation 6 outside whatever isolation scope arrives next.

The most credible forecast candidate today is a **Pass-the-DeviceKey**-style family: extraction or abuse of the device transport key the PRT binds to, or of the CloudAP-derived material the cookie-signing process produces from it [845]. Mollema's 2023-2025 continuation work documents the underlying device-transport-key primitives in detail; the September 2025 Actor-tokens disclosure (CVE-2025-55241) demonstrated a fully operational cross-tenant impersonation primitive, responsibly disclosed and patched before any in-the-wild abuse, an adjacent cloud-token-validation failure rather than a device-key primitive [846] [847].

> **Walkthrough: reading the family tree without being fooled by dates.**
> Start with the artifact, not the year. Ashton proves that a stored hash can satisfy the verifier. Ochoa moves the substitution into Windows so native tools inherit it. Delpy retargets the same LSASS reachability at Kerberos tickets. Metcalf and Duckwall/Delpy show that the NT hash can also be promoted into a Kerberos long-term key through RC4-HMAC. Schroeder, Christensen, Lyak, and Méheut move the family to certificate private keys and KDC mapping. Mollema and Delpy move it to Entra's PRT and CloudAP's SSO-cookie path. Chronologically, Pass-the-PRT was published before the AD CS catalog; taxonomically, both are children of the same post-Credential-Guard search for the next artifact outside the closed boundary.

![Figure: Twenty-nine years of credential replay as a family tree on a strictly chronological spine: Pass-the-Hash (Ashton 1997 → Ochoa 2008) → Pass-the-Ticket (Delpy 2011) → Overpass-the-Hash (2014) → Pass-the-PRT (Mollema 2020) → Pass-the-Certificate (Schroeder + Christensen 2021). Each node names the artifact it targets and the defense that closed the prior generation. The right-hand family-order axis crosses the spine between 2020 and 2021: Pass-the-PRT is the family's fifth branch but shipped before the fourth (Pass-the-Certificate), so taxonomic order is visibly distinct from chronological order.](diagrams/11-pth-prt-family-tree-timeline.svg)

If the pattern holds, the ingredients for a possible Generation 6 are already visible in research literature. Mollema's 2023-2025 continuation work [845] [847] [846] documents device-identity and transport-key-adjacent primitives. The name, commodity tool, and operational center of gravity have not arrived; the forecast is that attackers will keep testing that substrate before VBS-class CloudAP use-path isolation is universal.

## Open problems and the 2026-2030 forecast

The credential-replay family has six load-bearing open problems in 2026. Each is structural rather than mathematical; the cryptographic primitives that would close them already exist.

The architectural lower bound (the only configuration that closes the family in principle) is the union of three things.

**Universal hardware-rooted non-extractable keys**: every long-term authentication artifact lives in a TPM, secure enclave, FIDO2 authenticator, or smart card, with key attestation, and is never released to software memory. **Universal protocol-layer token binding**: every issued token (Kerberos service ticket, OAuth refresh token, OIDC ID token, SAML assertion) is cryptographically bound to the device that requested it, and a verifier rejects any presentation from a non-bound device. **Universal continuous evaluation**: every protected resource queries the issuer in near-real-time and revokes within minutes of a triggering signal. Each component is deployed *somewhere*; none is deployed *everywhere*; no single vendor controls all three layers.

The six concrete open problems flow from that lower bound.

**The CloudAP isolation problem.** On modern Entra-joined devices the CloudAP-held PRT and session key are not within Credential Guard's documented scope, and Mollema's research shows they are extractable from LSASS with local administrative control. The open question is whether Microsoft will extend VBS-class protection to CloudAP's PRT storage and its in-use SSO-cookie derivation path, so that VTL0 code cannot read, derive, or reuse the proof material. No public roadmap in the source corpus answers that question. Until that path receives a boundary as strong as the VBS trustlet protecting NTLM hashes and TGTs, Pass-the-PRT remains the live edge of the family for endpoints where an attacker obtains local administrative control [820] [819] [87].

**The token-binding adoption problem.** The "five percent" shorthand for unprotected SaaS is too brittle to rely on, because SaaS portfolios vary wildly by enterprise. The durable, cited fact is narrower and stronger: Microsoft documents Token Protection as a Conditional Access session control for a closed set of supported native-app resources (Exchange Online, SharePoint Online, Microsoft Teams, Azure Virtual Desktop, and Windows 365) and states that browser-based applications are not supported [842]. That is enough. Whether those five resources represent five percent or fifty percent of a given user's daily work is an estate measurement, not a universal claim. The architectural forecast is that replay remains viable anywhere the resource server accepts bearer-style tokens without device-bound proof. RFC 9449 standardizes OAuth DPoP at the protocol layer [848], but standardization is not deployment, and deployment must happen at the issuer, client, and resource server.

**The Pass-the-DeviceKey forecast.** Mollema's 2023-2025 continuation work shifts attention from PRT cookies to the device-identity substrate around them: PRT phishing, device transport keys, federated credentials on Entra applications and managed identities, and Actor-token abuse with cross-tenant consequences [845] [847] [846]. The pattern of every previous generation predicts that whichever primitive becomes easiest to operate will receive the next name. This is not a claim that a public "Pass-the-DeviceKey" commodity technique already exists. It is a forecast from the family tree: when the PRT cookie path becomes harder, attackers will look for the next device-bound artifact whose proof path can be driven from software.

**The ESC9-ESC16 hardening problem.** The AD CS catalog has grown from the eight Certified Pre-Owned classes to the current ESC1-ESC16 practitioner enumeration in Certipy and Certify documentation [709] [834] [837] [841]. KB5014754 closed specific Certifried-shaped mapping failures; it did not audit every certificate template, CA ACL, enrollment-agent chain, NTLM relay path, or security-extension exception in an enterprise [770] [839]. The forecast here is mundane and therefore likely: certificate replay stays alive less because of new cryptography and more because enterprises carry decades of template inheritance, legacy compatibility flags, and unclear CA ownership.

**Hardware-backed identity ubiquity.** Human interactive sign-in can already move toward FIDO2 and platform authenticators, and device join can use TPM-backed keys. The hard part is the tail: service accounts, scheduled tasks, daemon credentials, on-prem Kerberos dependencies, break-glass accounts, legacy thick clients, and vendor appliances. Every one of those exceptions creates pressure to keep a software-extractable artifact somewhere. The 2026-2030 forecast is not that hardware-backed identity fails; it is that the migration succeeds first for humans, then stalls around non-human and legacy workflows unless procurement and application-architecture policy force the issue.

**The non-Microsoft sibling lineages.** The family is not Windows-specific. Okta session-cookie theft, Google identity-provider refresh-token reuse, Apple ASWebAuthSession token replay, AWS STS session-token theft, and GitHub or other SaaS refresh-token compromise all instantiate the same property: a long-term or renewable software-accessible artifact can be used away from the ceremony that first issued it unless the verifier demands fresh device-bound proof. The chapter stays Windows-specific because Windows gives us the cleanest twenty-nine-year chain from NTLM to CloudAP. The forecast generalizes because every identity provider is converging on the same three controls: hardware-backed keys, token binding, and continuous evaluation.

The institutional position is that a protocol-level patch is unavailable for the original NTLM case; that framing generalizes. A universal fix would require replacing every long-term software-extractable artifact globally with hardware-bound primitives, enforcing token binding at every issuer and every resource server, and continuously reevaluating every session. Each step is incrementally closable. The union has not closed.

> **The architectural lower bound.**
> Universal hardware-rooted non-extractable keys, universal protocol-layer token binding, universal continuous evaluation. Each component is deployed somewhere; none is deployed everywhere. No single vendor controls all three layers.

The most likely 2030 estate is therefore mixed: Credential Guard and strong certificate mapping broadly deployed on managed Windows endpoints; Token Protection or DPoP-like binding expanding across first-party native apps; browser and third-party SaaS coverage improving but not universal; service-account and legacy workflow exceptions still numerous enough to supply the next replay family. The open question is whether CloudAP use-path isolation arrives before commodity tooling makes PRT-derived replay as routine as NT-hash replay was after 2008.

## What it means for you: The 2026 Defender playbook

Architectural humility does not mean defensive passivity. The 2026 estate is defensible against generations 1 through 3 and partially against generation 4; generation 5 demands a detection-and-containment workflow because the public controls do not yet close every CloudAP use path. The playbook is a layered engineering plan, not a slogan.

1. **Credential Guard everywhere it can run.** Scope it to hardware-eligible non-DC Windows 10/11 endpoints, then verify running state rather than configuration state with `Win32_DeviceGuard`. Document the four residuals for the SOC: offline AD database theft, domain controllers, certificate private keys and templates, and CloudAP's in-use SSO-cookie derivation [87]. The validation query belongs in every endpoint baseline review:

   ```powershell
   Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard |
     Select-Object SecurityServicesConfigured, SecurityServicesRunning
   ```

2. **LSA Protection (RunAsPPL), UEFI-anchored, below Credential Guard.** Treat RunAsPPL as complementary, not equivalent. Credential Guard moves covered secrets to VTL1; PPL makes user-mode tampering with LSASS harder. The UEFI-anchored configuration resists the easy registry downgrade that itm4n documents in the ordinary configuration [328]. Validate with process-protection telemetry and baseline exceptions for legitimate security tools that open LSASS.

3. **Authentication Silos and Protected Users for Tier-0 accounts.** Use Protected Users where operationally possible: no NTLM, no DES/RC4 pre-auth, no unconstrained delegation, no cached NTOWF, and a 240-minute non-renewable TGT [672]. Expect breakage. The breakage is the control discovering legacy dependencies. Fix those dependencies instead of quietly removing privileged accounts from the group.

4. **KB5014754 strong-mapping enforcement plus AD CS audit.** The September 9, 2025 enforcement milestone closes the Certifried-shaped mapping failures only if certificates and DCs are in enforcement mode [770]. It does not close ESC template mistakes. Run a recurring ESC1-ESC16 review with Certipy, Certify, PSPKIAudit, or equivalent, and separately inventory the `CT_FLAG_NO_SECURITY_EXTENSION` exception path because it can re-open the SID-extension class by design [837] [841] [839].

5. **Conditional Access with Token Protection where supported.** Apply Token Protection to the supported native-app resources Microsoft names: Exchange Online, SharePoint Online, Microsoft Teams, Azure Virtual Desktop, and Windows 365 [842]. Do not summarize that as "PRT replay solved." Browser apps are out of scope in the cited documentation, and third-party SaaS coverage depends on resource support. For privileged users, combine Token Protection with phishing-resistant sign-in, compliant-device requirements, sign-in risk, and strict unmanaged-device policy.

6. **Concrete PRT-extraction telemetry.** Build detections around behavior, not tool names. The minimum Windows signal set is:

   | Layer | Signal | Why it matters | Tuning note |
   | -: | -: | -: | -: |
   | Process creation | Security 4688 or Sysmon 1 for `mimikatz`, `roadtx`, Python invoking ROADtools, suspicious PowerShell, unsigned binaries near LSASS | Captures commodity tooling and operator staging | High false positives for admin shells; correlate with LSASS handle access |
   | LSASS access | Sysmon 10 (`ProcessAccess`) targeting `lsass.exe`; Security 4656/4663 if object-access auditing and SACLs are configured | Pass-the-Hash, ticket dumping, and CloudAP inspection all need unusual LSASS access | Baseline EDR, backup, AV, and credential-provider products; alert on new images, unsigned images, and `PROCESS_VM_READ`/`PROCESS_VM_WRITE` patterns |
   | Module context | Sysmon 7 image-load telemetry for unusual processes loading authentication, crypto, or DPAPI-related DLLs | Helps distinguish normal Windows sign-in from operator tooling | Sysmon 7 is noisy; restrict to high-risk paths and unsigned publishers |
   | Entra/device state | `dsregcmd /status`; Microsoft-Windows-User Device Registration/Admin; Microsoft-Windows-AAD/Operational | Validates PRT population, device join state, and SSO failures | Treat as state and troubleshooting telemetry, not theft proof |
   | Cloud token use | Entra sign-in logs: resource, client app, device ID, compliance state, Token Protection result where available, impossible travel, new user agent | Replay often appears as a token accepted from a context that does not match the device/user baseline | Requires identity/SOC join between endpoint and cloud logs |
   | Network endpoint | Connections to `login.microsoftonline.com` token endpoints from unusual tools or unmanaged hosts | `roadtx prt` needs nonce and token endpoint traffic [821] | Browser and Office traffic are normal; look for process lineage and unmanaged source |

   A starter Microsoft Defender hunting shape is: find non-Microsoft or newly-seen processes that opened `lsass.exe`, join to process creation within five minutes, then join to sign-in events for the same user where device compliance or Token Protection state is absent or unexpected. The exact table names differ by tenant and product tier; the logic does not.

   ```text
   suspicious_process → opens lsass.exe → near dsregcmd/AAD/CloudAP state → token endpoint traffic → Entra sign-in from mismatched device context
   ```

7. **Validation procedure for the detection.** Do not test by stealing a real PRT. Test each leg safely. First, run `dsregcmd /status` on a managed endpoint and confirm your collector ingests the join/PRT fields. Second, generate a benign LSASS-access canary using an approved internal test binary or EDR simulation that opens a handle without dumping memory, and verify Sysmon 10 or equivalent EDR telemetry. Third, run a controlled token-endpoint request from an approved lab host and confirm proxy or endpoint telemetry sees `login.microsoftonline.com`. Fourth, trigger a Conditional Access report-only policy for a test user and confirm the SOC can join cloud sign-in context back to endpoint identity. If any join fails, the Pass-the-PRT detection will fail in production.

8. **Privilege reduction as the real preventive control.** Every replay generation becomes dramatically easier after local admin. Remove standing local admin, enforce Just Enough/Just In Time administration, require phishing-resistant MFA for elevation, and use application control to block unsigned credential tools. This is not glamorous, but it attacks the premise common to Ochoa 2008, Delpy 2011, Mollema 2020, and most commodity replay chains.

9. **Mental model: assume the PRT is the next NT hash.** Architect today as if Credential Guard for CloudAP shipped tomorrow. That means TPM-attested device joins as standard, FIDO2 or equivalent phishing-resistant authenticators for human sign-in, hardware-backed identity for service accounts wherever vendors support it, and conditional-access policies that treat unmanaged or non-attested devices as hostile by default.

> **Verify the PRT population before reasoning about it.**
> On the endpoint, run the supported registration probe:
>
> `dsregcmd /status`
>
> Preserve `AzureAdJoined`, `DomainJoined`, `DeviceAuthStatus`, `AzureAdPrt`, `AzureAdPrtUpdateTime`, `AzureAdPrtExpiryTime` if present, `KeyProvider`, and `TpmProtected`. They tell you whether the user/device is in the PRT SSO population and whether the device key is hardware-backed. They do not prove replay or full use-path isolation.
>
> **If you implement nothing else, do this.**
> Turn on Credential Guard wherever it can run, enforce KB5014754 strong mapping, audit AD CS templates against ESC1-ESC16, deploy Token Protection on the supported resources, and build a joined endpoint/cloud detection for unusual LSASS/CloudAP access followed by token use from a mismatched device context. The first four reduce known attack classes. The last is the only practical signal for the class that the published controls do not yet close.

None of this universally closes Pass-the-PRT. Token Protection can block or constrain cross-device replay for supported native-app/resource paths; the rest reduces the population, raises the privilege threshold, improves detection, and shortens downstream session dwell time.

## The pattern that outlived five defenses

The 1997 patch and the 2026 attack are the same attack because the architectural property the family shares is unchanged. The artifact moved; the property did not.

A long-term authentication artifact reachable by the using process is replayable. The NT hash sat in LSASS on Windows NT 4.0 and replayed against SMB. The Kerberos TGT sat in LSASS on Windows Server 2003 and replayed against Kerberos services. The NT hash sat in LSASS on Windows Server 2008 and replayed against the KDC's RC4-HMAC authentication path as a real Kerberos client.

The X.509 certificate abuse path might involve an exportable CryptoAPI key container, an enrollment or relay path, a stolen CA key, or a misbinding/mapping failure; when the attacker can prove possession of usable private-key material, it replays against PKINIT-supporting domain controllers as the principal in the SAN. The Primary Refresh Token root is treated here as protected by Microsoft-documented device/TPM binding and, where applicable, Credential Guard storage posture on Entra-joined Windows devices, while CloudAP performs the VTL0 in-use derivation that can yield SSO-cookie material accepted by unbound Entra resource paths.

Each defense relocated the artifact to a harder-to-reach storage class. The "Do not store LAN Manager hash" policy retired LM. RunAsPPL marked LSASS as a Protected Process Light. Credential Guard moved NT hashes and TGT session keys out of LSASS in VTL0 into the LSAISO trustlet in VTL1. KB5014754 bound certificates to SIDs at issuance, so that a certificate without the SID extension fails strong mapping at the KDC. Token Protection binds supported sign-in session tokens to devices for supported native-app resources, so cross-device replay is materially constrained when that verifier path enforces the binding.

Each defense was real. Each closed a generation. The family did not close.

The reason the family does not close is structural. Every generation finds the next long-term artifact whose storage class, use path, or verifier binding the latest defense did not fully cover. Pass-the-Hash worked because the NT hash was reachable. Pass-the-Ticket worked because the TGT was reachable. Overpass-the-Hash worked because the NT hash was reachable *and* the KDC accepted RC4-HMAC. Pass-the-Certificate worked because certificate templates were misconfigured and the SID extension did not exist. Pass-the-PRT works where CloudAP's in-use derivation path can be driven or observed from VTL0 and the target client/resource path does not enforce device-bound Token Protection.

The architectural lower bound (universal hardware-rooted non-extractable keys plus universal token binding plus universal continuous evaluation) is the only configuration that closes the family, and it is not deployed anywhere as a complete stack.

The playbook above is what to do today. The forecast is what to architect for next. The closing observation is the one this chapter exists to register: when you read about the next named "Pass-the-X" technique, you already know what it will look like. A long-term authentication artifact, reachable from the process that holds it, replayed from a different machine, defeating the latest defense because that defense was designed for a different artifact.

If the pattern repeats, the next generation is already hinted at in research literature. The name is still a forecast, not a fact.

> **Bequeaths.** This chapter hands the rest of the book one hard-won invariant: isolating where a credential is *stored* is not the same as isolating where it is *used*. Every defense in the lineage moved the artifact to a harder storage class (the LAN Manager policy, RunAsPPL, Credential Guard's LSAISO, KB5014754's SID binding, Token Protection's device binding) and every generation found the next artifact whose *use* path still crossed an un-isolated boundary. The successors that try to break the pattern are the next links: Windows Hello for Business (Chapter 20) and WebAuthn and passkeys (Chapter 21) replace the replayable shared secret with a hardware-bound private key that never leaves the authenticator, and Zero Trust (Chapter 26) with Continuous Access Evaluation (Chapter 27) shrinks a stolen token's dwell time by re-checking every presentation instead of trusting it for a full lifetime. What this chapter explicitly does **not** bequeath is a closed boundary: it provides no VBS-class isolation for CloudAP's in-use SSO-cookie derivation, no token binding for browser sessions or third-party SaaS, and nothing for the service-account and legacy software-extractable secrets that have no authenticator to move into. Those residuals are precisely where an inherited token crosses a boundary that was never re-checked: the failure the finale dissects in *When the Chain Snaps* (Chapter 29).
