# Mimikatz and the Credential-Theft Decade

::: trust-ledger

- **Inherits:** Code-trust, never credential-trust. Authenticode made binaries verifiable (Chapter 12, Authenticode and Catalog Files); HVCI made kernel code immutable (Chapter 8, Code Integrity); Protected Process Light gave `lsass.exe` a signer-gated boundary enforced by the NT kernel against user-mode callers (Chapter 10, Protected Process Light); App Control gave a kernel-enforced execution policy (Chapter 13, AppLocker vs App Control for Business). Every inherited guarantee governs *which code runs*, not *what secrets the running code may read*.
- **Promise:** This chapter proves a negative with a precise scope. Per-binary controls and same-ring (VTL0) hardening cannot, by themselves, structurally stop an attacker who already has local administrator/SYSTEM authority or kernel reach on the host from reading recoverable credential material `lsass.exe` must cache for single sign-on. The boundary at stake: the credential layer inside LSASS, which, in 2009–2014, is not yet isolated from that privilege domain.
- **TCB:** The single-privilege-domain model itself. `lsass.exe` is a user-mode process with its own virtual address space, while the NT kernel and loaded drivers share kernel address space and can map or copy process memory inside VTL0. The single-sign-on contract forces LSASS to hold NT hashes, Kerberos tickets, and, on affected configurations, WDigest plaintext in recoverable form.
- **Adversary → Break:** A SYSTEM + `SeDebugPrivilege` operator calls `OpenProcess(PROCESS_VM_READ)` on `lsass.exe` and walks off with the reusable credential material exposed in that logon session; RunAsPPL can be cleared from kernel mode by an attacker who already has kernel execution (Delpy's own `mimidrv.sys`, loadable only once Driver Signature Enforcement is bypassed, or a separate bring-your-own-vulnerable-driver exploit) and zeroes the `EPROCESS` protection byte. This is *the right code* reading credential memory, not *the wrong code* executing, so the per-binary playbook never sees it.
- **Residual:** Long-term-secret isolation → Credential Guard (Chapter 15); NTLM hash-equivalence and relay → The Death of NTLM (Chapter 16); Kerberos ticket replay: Pass-the-Ticket, Overpass-the-Hash → Kerberos (Chapter 17); Golden Ticket / krbtgt forgery → KRBTGT (Chapter 18); the Pass-the-Hash-to-Pass-the-PRT lineage → Pass-the-Hash to Pass-the-PRT (Chapter 19); token / Potato escalation → Windows Access Control (Chapter 22) and The SeImpersonate Primitive (Chapter 24).
- **Bequeaths:** A precisely named problem. *an administrator or kernel-capable attacker can read the recoverable reusable credential material LSASS keeps in VTL0, and in-VTL0 controls can only add friction rather than isolation*. The brief that forces Credential Guard (Chapter 15) and motivates retiring NTLM (Chapter 16). Does NOT provide: any fix. This is the attack that opens the credential-protection arc, not a control on it.
- **Proof:** 🔵 documented throughout. Historical gap analysis plus defensive-state probes (WDigest, RunAsPPL, Credential Guard) an administrator can run on their own estate; no credential theft is reproduced. <!--EVIDENCE-NEEDED: capture the defensive-state probes (WDigest UseLogonCredential, RunAsPPL, Win32_DeviceGuard) on the Credential-Guard lab VM to upgrade this Proof line to 🟢-->
:::

> **Evidence labels.** 🔵 means documented/reproducible from public sources or local commands; 🟡 means emulated; 🟢 means captured from this book's lab with hash-stamped artifacts.

> **The Reasoner's question.** What happens when trusted code, running with administrator privilege, can read the memory where Windows keeps reusable credentials?

---

> **Foundations. What you need before this chapter.**
>
> - **LSASS.** The Local Security Authority Subsystem Service is the long-lived user-mode process that coordinates Windows logon, NTLM, Kerberos, security packages, and single sign-on. In the pre-Credential-Guard model it also held reusable credential material in memory.
> - **NT hash / NTOWF.** The MD4 of the UTF-16LE password, consumed by NTLM-derived protocols as a reusable bearer secret. If a protocol accepts proof derived from the hash, possessing the hash can be equivalent to possessing the password for replay purposes. The full NTLMv2 challenge-response derivation is owned by The Death of NTLM chapter (Chapter 16); here it is enough that the hash is a bearer secret.
> - **Kerberos ticket.** A TGT or service ticket is also a bearer object: the domain accepts the ticket because the KDC signed it. If an attacker obtains a usable ticket, the attacker can often use the ticket without knowing the password that originally produced it.
> - **Pass-the-Hash, Pass-the-Ticket, Overpass-the-Hash, Golden Ticket.** These names describe historically documented credential-replay classes. This chapter treats them as gap analysis: each shows where Windows credential storage and protocol design placed reusable authority in memory or in domain secrets.
> - **PPL versus VBS.** Protected Process Light is a VTL0 same-kernel signer gate around a process. Virtualization-Based Security creates VTL0/VTL1 isolation below the Windows kernel with the hypervisor. The distinction is the reason PPL could reduce LSASS dumping but could not structurally solve it.
> - **Reasoner’s lens.** For every control, ask which layer it protects. AppLocker protects file execution; Secure Boot protects the boot chain; ELAM protects early driver loading; AppContainer protects sandboxed user-mode apps. Mimikatz attacked the credential material those layers still had to trust.

---

> **Chapter thesis.** **2009-2014 was Windows security's parallel-revolution decade.** Microsoft shipped AppLocker, Secure Boot, ELAM, AppContainer, and in-box Defender [616,27,42], materially raising the cost of unsigned bootloaders, pre-antimalware drivers, and commodity rootkit tradecraft. In the same window, Stuxnet burned four Windows zero-days [512] against Iranian centrifuges and Benjamin Delpy released Mimikatz, which exposed recoverable LSASS credential material through a compact operator interface [261,617,618]. The defensive playbook closed per-binary attack surface while attackers pivoted up the trust stack to the credential layer that hardened binaries still had to trust. By November 11, 2014, Microsoft had acknowledged in product (Restricted Admin RDP, LSA Protected Process, and KB2871997's WDigest control surface) [446,436] and in print (the Mitigating Pass-the-Hash whitepaper v1 December 2012 and v2 July 2014) [619,620] that the in-VTL0 LSASS model was structurally indefensible against an admin-privileged attacker on the same host. The architectural answer (Virtualization-Based Security and Credential Guard in Windows 10 1507 [621]) ships eight months outside the window and is the subject of the next chapter (Chapter 15, Credential Guard).

## Two continents, eleven months apart

June 17, 2010. An antivirus analyst at VirusBlokAda in Minsk named Sergey Ulasen receives a sample from an Iranian customer whose Windows boxes are rebooting on their own [622]. The dropper carries valid Authenticode signatures from Realtek Semiconductor and JMicron Technology [512]. The worm propagates via a previously unknown LNK shortcut bug that fires when Windows merely *displays* the icon of a crafted file [623]. Eleven months later, public accounts date Benjamin Delpy's first Mimikatz release to May 2011, and Delpy-controlled blog snapshots show the 1.0 alpha public by September: a closed-source proof-of-concept that could pull NT hashes and Kerberos tickets out of LSASS process memory on vulnerable Windows configurations and print them to the operator's console [617,624,618]. The conventional history puts these two events on different pages of different books. This chapter argues they are the two visible faces of a single structural shift.

The shift is easy to state and easy to underrate. *Defensive success at one layer reliably produces attacker innovation at the next layer up.* Microsoft spent the 2009-2014 window shipping the most ambitious per-binary hardening program of any commercial operating system in history: AppLocker, ASLR improvements, BitLocker To Go, UEFI Secure Boot, Measured Boot, Early Launch Antimalware, AppContainer, the WinRT sandbox, and in-box Windows Defender [616,27,42,625]. The program worked, but with scope. It materially narrowed the unsigned-bootloader rootkit class, the pre-antivirus-launch malware class, and the browser-renderer ambient-authority class on systems that deployed the features correctly. None of those primitives would have stopped Stuxnet on a Windows 7 host with USB enabled, and none of them stopped Mimikatz once an attacker already had administrative execution on the host.

The reason is structural, not engineering. Every per-binary mitigation prevents the *wrong* code from running. Mimikatz's `sekurlsa::logonpasswords` command did not need to be wrong code. It needed to be the *right* code (code an administrator chose to run, or a signed driver the system allowed to load) running where the credentials lived. The credentials lived in the memory of a long-lived user-mode service called LSASS, and they lived there by design because the single sign-on contract requires the operating system to re-authenticate the user to network servers without re-prompting [626]. The mitigation surface and the attack surface were not at the same layer.

| Date | Defender rail | Attacker rail |
|---|---|---|
| Oct 22, 2009 | Windows 7 GA: AppLocker, ASLR improvements, BitLocker To Go | |
| Jan 12, 2010 | | Operation Aurora disclosed: a single IE zero-day used for espionage |
| Jun 17, 2010 | | VirusBlokAda identifies Stuxnet from an Iranian customer sample |
| Dec 27, 2010 | | Dang and Ferrie present Stuxnet analysis at 27C3 Berlin |
| May 2011 | | Delpy releases Mimikatz, initially closed source |
| Oct 26, 2012 | Windows 8 GA: Secure Boot, ELAM, AppContainer, in-box Defender | |
| Aug 1, 2013 | | Duckwall and Campbell present *Pass-the-Hash 2* at Black Hat USA |
| Oct 17, 2013 | Windows 8.1: Restricted Admin RDP and LSA Protected Process | |
| Apr 6, 2014 | | Mimikatz GitHub repository created |
| May 13, 2014 | KB2871997: WDigest control surface and Restricted Admin back-port | |
| Aug 7, 2014 | | Delpy and Duckwall present the Golden Ticket at Black Hat USA |
| Nov 11, 2014 | MS14-066 Schannel patch closes the window | |

Read the split screen as two rails moving in parallel. The defender rail hardens code-loading, boot, and sandbox boundaries. The attacker rail moves to the credential material those hardened components still have to trust.

![Figure: The 2009–2014 split screen. A central time spine carries the defender rail (per-binary, boot, and sandbox hardening) on the left, and the attacker rail (credential-layer tradecraft) on the right. The two rails run in parallel because hardening *which code may run* pushed the adversary up to the credentials that hardened code still had to cache.](diagrams/22-mimikatz-split-screen.svg)

If both events were faces of the same shift, what was the shift? To see it, we have to start with what Microsoft was actually shipping.

## The hardening decade: What Microsoft was doing 2009-2014

The popular story of 2009-2014 is that Microsoft was asleep while the Russians ate their lunch. That story is wrong. Microsoft shipped, in a single five-year window, more new platform-security primitives than the company had shipped in the previous decade combined. The problem was not the engineering. The problem was that the entire program was orthogonal to the credential layer.

### 2.1 Windows 7 (October 22, 2009): per-binary control, finally

Windows 7 was the first Microsoft client operating system shipped after the Trustworthy Computing memo had finished one full Secure Development Lifecycle revolution. The headline platform addition was **AppLocker**, an application-control framework that let administrators allow or deny executables, scripts, MSI installers, DLLs, and packaged apps by publisher, file hash, or path [616]. Rules were authored in Group Policy and enforced by the Application Identity service. The rule-collection design was the first time a Microsoft Windows shipped a coherent allowlisting story rather than a bag of registry knobs.

AppLocker carried two structural gaps that took years to live down. First, the DLL rule collection was off by default. Enabling it broke application compatibility on almost every real estate. Second, the Application Identity service ran as a normal Windows service, which meant an attacker who reached LocalSystem could `sc stop AppIDSvc` and degrade enforcement open until the next reboot.

> **Note.** This admin-stoppable-service gap is the design lesson that becomes the brief for Windows Defender Application Control's kernel-enforced policy model, the subject of the AppLocker vs App Control for Business chapter (Chapter 13).
 A third structural gap matters for the credential-theft era this chapter documents. AppLocker's publisher- and path-rule design decisions assume the file-system DACL stack enforces a clean read-allow / write-deny split for low-privileged users [627]. It does not.

As a historical gap analysis, the well-known operator bypass on a default Windows 7 install had four moving parts: a directory whose path matched the AppLocker default `%WINDIR%\*` allow rule for non-administrators (`%WINDIR%\Tasks` is the canonical example because it shipped with permissive ACLs for Task Scheduler child files); an unsigned payload placed where the path rule, not the file's effective DACL, was decisive; invocation by full path; and an allow decision because AppLocker evaluated the configured path policy rather than the writeability that made the child file attacker-controlled. The bypass exists because AppLocker's rule evaluation and NTFS's DACL stack live on two independent rails that disagree about which paths a non-administrator may write; the cleanup that closes this class of bypass landed in Windows Defender Application Control, which is the App Control for Business chapter's story (Chapter 13).

AppLocker killed the per-binary "double-click an unsigned EXE on a managed desktop" attack class on estates that deployed and maintained it, but deployment was never universal even in large enterprises.

Windows 7 also tightened the in-process mitigation surface. Address Space Layout Randomisation got a new opt-in *ForceASLR* flag callable via the loader's `MitigationOptions` field, letting administrators force randomisation even on EXEs and DLLs that had been compiled without the `/DYNAMICBASE` linker switch [625].

**BitLocker To Go for removable media** finally gave administrators a defensible answer to the lost-USB-stick incident report. The on-disk format is a Full Volume Encryption v2 (FVE2) volume encrypted with plain AES-CBC; unlike fixed-disk BitLocker on Vista and original-release Windows 7, BitLocker To Go *disables* the Elephant Diffuser on removable drives so the small unencrypted *discovery volume* at the start of the device can ship `BitLockerToGo.exe`, the Windows XP / Vista *BitLocker To Go Reader* that supports plain AES-CBC only [193]. The Reader unlocks the volume with a password or a recovery key (the recovery key escrowable by Group Policy to Active Directory); smart-card and automatic-unlock protectors require native BitLocker on Windows 7 or later. The discovery-volume design is the operational concession that lets a 2009 administrator hand a BitLocker-To-Go stick to a vendor running Windows XP SP3 without giving the vendor a usable plaintext copy; the diffuser drop is the cryptographic concession that makes the Reader compatibility story possible. The threat-model concession that BitLocker To Go does not cover is the unattended-laptop / cold-boot attack class against the *primary* disk's TPM-released VMK [105], which is the Evil-Maid territory Joanna Rutkowska and Alex Tereshkin demonstrated against TrueCrypt full-disk encryption in October 2009 [628] and which BitLocker would not fully answer until pre-boot PIN enforcement matured.

**DirectAccess** shipped as an always-on, certificate-anchored, IPsec-over-IPv6 tunnelled successor to traditional VPNs. The architectural design used a dual-tunnel model [629]: an *infrastructure tunnel* established at machine boot using a machine certificate, which gave the client reach-back to domain controllers, DNS, and management infrastructure *before* any user had logged on; and an *intranet tunnel* established at user logon using user credentials, which carried application traffic to the internal corporate network.

Because DirectAccess required end-to-end IPv6 in an era when public IPv6 was a rounding error, the design layered three transition technologies in priority order: 6to4 (for clients with a public IPv4 address), Teredo (for clients behind NAT), and IP-HTTPS (a TLS-encapsulated IPv6 transport that worked across any environment that allowed outbound HTTPS, included specifically as the fallback for hotel and conference networks that blocked native IPv6 and UDP-Teredo). The always-on-before-logon property is what made DirectAccess operationally distinct from a traditional VPN: a help-desk-recoverable password reset, a Group Policy push, or a software-distribution job could reach a remote machine the instant it had Internet connectivity, with no user action required.

> **Note.** DirectAccess was later quietly deprecated in favor of Always On VPN and Microsoft Tunnel; the architectural lesson it carries is that certificate-anchored client trust scales operationally only when the certificate lifecycle is automated end-to-end.

What this narrowed sharply: the per-binary "unsigned EXE on a managed desktop" class on managed estates that deployed it. What it did not touch: anything inside an LSASS-holding process tree.

### 2.2 Windows 8 (October 26, 2012): the boot chain and the sandbox

Windows 8 is the year the per-binary playbook reached architectural maturity. Four primitives shipped at once, and they all aim at distinct points on the trust stack.

**UEFI Secure Boot** anchors the boot chain in firmware. The Platform Key, signed Key Exchange Keys, and the signature database `db` together require the firmware to verify the signature of every UEFI driver, every option ROM, and the operating-system loader before transferring control [27,623]. A revocation database `dbx` lets Microsoft retire keys and binaries that have been compromised. Windows 8 was the first Microsoft client operating system whose Logo certification required Secure Boot enablement by default; the chain is anchored to the UEFI 2.3.1 Errata C specification (June 2012). The Secure Boot chapter (Chapter 1) owns this primitive in full.

**Measured Boot** complements Secure Boot. Each stage of the boot chain extends measurements into Trusted Platform Module Platform Configuration Registers: classically PCRs 0 through 7 for the boot path, with SHA-1 banks common in TPM 1.2-era Windows 8 deployments and SHA-256 banks becoming the cleaner TPM 2.0-era story, and the TPM event log records what was measured [625]. BitLocker can then bind its Volume Master Key release to a specific PCR profile, so a tampered bootloader will not yield the disk key on next boot. Secure Boot decides whether the code is allowed to run; Measured Boot decides whether to release secrets to the code that ran. The Measured Boot chapter (Chapter 4) develops the PCR and event-log mechanism.

**Early Launch Antimalware (ELAM)** is the first boot-start driver loaded after the kernel. ELAM gets to inspect, classify, and refuse subsequent boot-start drivers via the `BDCB_CLASSIFICATION` enumeration, which returns Good, Bad, Unknown, or BadButCritical [42].

> **Note.** Microsoft's own ELAM driver, WdBoot.sys, ships with Windows Defender; third-party antivirus vendors such as McAfee, Symantec, CrowdStrike, and SentinelOne ship their own ELAM drivers post-2014.
 ELAM services themselves run as a Protected Process Light, which prevents lower-signer-level code from injecting into the antimalware engine. ELAM materially narrowed the rootkit-loaded-before-AV class that had defined kernel-mode malware tradecraft since the early 2000s.

**AppContainer** introduces the LowBox access token. Each Modern (Metro) Windows Runtime app receives a token with a per-package security identifier and a vector of capability SIDs; resource access checks intersect the capability set with the resource's discretionary access control list [625]. The model is structurally similar to iOS entitlements: the kernel refuses any access the manifest did not declare. Windows 8 also ships the in-box Windows Defender (replacing the optional Microsoft Security Essentials). Modern/Metro Internet Explorer used AppContainer as part of the Windows Runtime sandbox, while desktop IE10's Enhanced Protected Mode brought AppContainer-style isolation when enabled and compatible; together they reduced the ambient-authority browser-renderer class that had dominated browser-borne malware for a decade.

A word on branding discipline. Windows 8's sandbox is correctly named WinRT plus AppContainer plus Modern (Metro) apps. *UWP* (Universal Windows Platform) is the Windows 10 brand introduced July 29, 2015; calling any Windows 8 deliverable UWP is a category error.

What this narrowed sharply: unsigned-bootloader rootkits (Secure Boot), pre-AV-launch malware (ELAM), and browser-renderer ambient authority (AppContainer plus Enhanced Protected Mode where deployed). What it did not touch: LSASS.

### 2.3 Windows 8.1 and Server 2012 R2 (October 17, 2013): the first counter-pivot

Windows 8.1 is where Microsoft first lands product-level controls that *directly* answer credential-replay tradecraft.

**Restricted Admin RDP** changes the protocol so that the client never sends the user's plaintext password to the server's LSASS [446]. Instead, through the CredSSP / Network Level Authentication exchange, the client proves possession of its credential material from the client side rather than sending the plaintext password for the server to cache. The classic credential-disclosure-at-server failure mode (a foothold on the RDP server learns every administrator's plaintext password as they log in) is closed. The replay failure mode is not, but Section 6 evaluates that honestly.

**LSA Protected Process** loads the LSASS process as a Protected Process Light (the Protected Process Light chapter, Chapter 10, owns the mechanism) with the signer level `PsProtectedSignerLsa`. Once Protected, even a process running as NT AUTHORITY\SYSTEM cannot call `OpenProcess(PROCESS_VM_READ)` against LSASS [436]. The flag is enabled by setting `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL` to `1`. The architectural intuition is right; the bypass class lives in kernel mode and gets evaluated in Section 6.

> **The first defensive counter-pivot.** Restricted Admin RDP and LSA Protected Process are the first product-level Microsoft acknowledgments that the credential layer needed its own defensive rail, distinct from the per-binary playbook. Together they foreshadow the architectural pivot that ships in Windows 10 1507 as Virtualization-Based Security and Credential Guard [621]. The full evaluation of both controls (what they accomplish, what they leave open, and why) is the subject of Section 6.

Every primitive above stops the wrong code from running. The threat model is about to move on.

## Stuxnet: The nation-state zero-day reveal

### 3.1 Discovery timeline

Sergey Ulasen's June 17, 2010 sample at VirusBlokAda is the public discovery date [622]. The worm had been operating in the wild since at least 2009. Within weeks, Kaspersky, Symantec, and ESET independently confirmed the family. By September 2010, Ralph Langner at Langner Communications had identified the payload's specific target: Siemens Step 7 industrial-control software running on S7-300 programmable logic controllers, programmed to manipulate the rotor speeds of cascade-mounted gas centrifuges at the Natanz uranium enrichment facility in Iran [630].

On December 27, 2010, Bruce Dang of Microsoft's Security Response Center and Peter Ferrie co-presented "Adventures in Analyzing Stuxnet" at the 27th Chaos Communication Congress (27C3) in Berlin [631].

> **Note.** The venue is 27C3, not 29C3, and Dang's affiliation is Microsoft MSRC, not Symantec; the talk is the canonical engineering primary for the win32k.sys keyboard-layout kernel exploit.
 Their first-hand engineering walkthrough of the win32k.sys keyboard-layout exploit is the canonical record of how Stuxnet escalated privilege on Windows 2000 and XP systems (on Windows Vista and 7, Stuxnet used the Task Scheduler zero-day CVE-2010-3338 instead). In February 2011, Nicolas Falliere, Liam O Murchu, and Eric Chien of Symantec Security Response published the v1.4 W32.Stuxnet Dossier, which enumerated the four Windows zero-days, the two stolen Authenticode certificates, and the Step 7 / S7-300 payload [512]. Ralph Langner's November 2013 "To Kill a Centrifuge" closed the analytical loop by identifying not one but two distinct centrifuge-attacks bundled into the same worm: an earlier rotor-overpressure attack and the later rotor-speed manipulation attack [630].

### 3.2 The four zero-days

The Symantec dossier's accounting of Stuxnet's Windows zero-days is the canonical inventory. There were four, used across the worm's propagation and escalation surfaces, **not** chained in a single sequential exploit.

| Bulletin | CVE | Role in the worm | Patch date |
|---|---|---|---|
| MS10-046 | CVE-2010-2568 | LNK shortcut RCE; propagation via USB without autorun [623] | August 2, 2010 |
| MS10-061 | CVE-2010-2729 | Print Spooler RCE; network-layer propagation [632] | September 14, 2010 |
| MS10-073 | CVE-2010-2743 | win32k.sys keyboard-layout local privilege escalation [633] | October 12, 2010 |
| MS10-092 | CVE-2010-3338 | Task Scheduler local privilege escalation [634] | December 14, 2010 |

The LNK bug (MS10-046) is the propagation-by-USB primitive that gave Stuxnet its air-gap-jumping reputation: merely displaying the icon of a crafted shortcut, which Windows Explorer did automatically when the user opened the USB drive, triggered code execution [623]. The Print Spooler RCE (MS10-061) addressed a Spooler permissions-validation bug that let Stuxnet propagate over the network as a printer-share request [632].

> **Note.** The Print Spooler attack surface returned a decade later as CVE-2021-34527 PrintNightmare, demonstrating that a sufficiently complex local-privilege-escalation surface tends to be re-discoverable across architectural rewrites.
The keyboard-layout LPE (MS10-073) was the one Dang and Ferrie walked at 27C3: the kernel indexed a table of function pointers when loading a keyboard layout from disk, and Stuxnet supplied a layout that pointed the index at attacker memory [633]. The Task Scheduler LPE (MS10-092) corrected the way Task Scheduler conducted integrity checks to validate that tasks ran with their intended user privileges [634]. Stuxnet also re-used the older MS08-067 NetAPI worm bug on unpatched hosts as a non-zero-day propagation path [635]. This is the Conficker bug from October 2008, not a 2010 zero-day, and any four-zero-day count that includes it is wrong.

In prose, Stuxnet separated propagation from escalation. The LNK shortcut bug and Print Spooler bug moved the worm onto machines. The win32k.sys keyboard-layout bug and the Task Scheduler bug raised local privilege when the host required it. Either escalation path could lead to the Siemens Step 7 / S7-300 payload. The four bugs were not a single linear chain; they were a menu of propagation and escalation primitives selected by the local host's patch level and exposure.

### 3.3 The stolen Authenticode certificates

The worm's dropper was signed by two real, valid Authenticode certificates issued to Realtek Semiconductor and JMicron Technology [512]. Both certificates were revoked within weeks of disclosure, but during the operational window of Stuxnet, every signature check Windows performed against the dropper returned a clean verdict.

> **Note.** The Realtek and JMicron certificates were not merely stolen out of an email inbox; the corresponding hardware security modules were almost certainly accessed in person at the original equipment manufacturers' facilities in the Hsinchu Science Park, Taiwan: the long-form reconstruction in Kim Zetter's *Countdown to Zero Day* lays out the physical-access logistics that the wire-only theft hypothesis cannot satisfy [622]. This prefigured the supply-chain attack class that becomes SolarWinds a decade later.
This was the first publicly analyzed kinetic-effect proof that the code-signing trust root (Authenticode and the kernel-mode driver signing PKI that depended on it) was an adversary target rather than a structural defense.

### 3.4 Architectural lessons

Two structural lessons emerged from the disclosure cycle. First, USB as an attack surface acquired its own discipline. In February 2011, Microsoft re-released the autorun update covered by Microsoft Security Advisory 967940 / KB971029 as an automatic update via Windows Update, having previously offered it as an optional patch in February 2009 [636]. Second, IT and operational-technology (OT) cross-domain trust collapsed as a defensible perimeter. Natanz was an air-gapped network that a USB stick crossed, and every CISO with operational-technology assets had to re-ask the question of whether a nation-state would burn a Windows zero-day to break their plant.

### 3.5 Did Stuxnet defeat any defender primitive Windows 7 shipped?

The narrow answer is no, the worm did not need to. Stuxnet's propagation primitives carried their own attack code (the LNK bug ran from Explorer, the Spooler bug ran from the printer-share RPC interface) so they did not need to defeat AppLocker (AppLocker only blocks executions a configured rule denies; an explorer.exe rendering a crafted shortcut was not a denied execution) or ASLR or DEP. The win32k.sys local privilege escalation, however, foreshadowed the Section 5 argument neatly: the per-binary mitigations Windows 7 shipped (AppLocker, ASLR, DEP, ForceASLR) did nothing for a kernel-mode bug, because kernel-mode is where those mitigations are enforced from.

### 3.6 Was Stuxnet really the *first* nation-state Windows zero-day operation?

Only with two qualifiers. Operation Aurora (the espionage campaign Google publicly disclosed on January 12, 2010 [637,638]) pre-dates Stuxnet's June 2010 public identification by roughly five months and used a single Windows / Internet Explorer zero-day, the IE use-after-free cataloged as CVE-2010-0249 [639], for cyber-espionage. Google's own disclosure stated that "at least twenty other large companies from a wide range of businesses (including the Internet, finance, technology, media and chemical sectors) have been similarly targeted" [638]. The publicly named subset that emerged across the January 12-15, 2010 disclosure window included Adobe Systems (acknowledged on the Adobe corporate blog January 12, 2010) [640], Juniper Networks, Rackspace [641], plus Yahoo, Symantec, Northrop Grumman, Dow Chemical, and Morgan Stanley named in Ariana Eunjung Cha and Ellen Nakashima's Washington Post coverage on January 14, 2010 [642]. Dmitri Alperovitch of McAfee Labs named the campaign "Operation Aurora" on January 14, 2010 based on a `\..\Aurora_Src\AuroraVNC\` file-path string recovered from the malware binaries [643]. Microsoft patched the IE bug out-of-band as MS10-002 on January 21, 2010 [644].

> **Operation Aurora and the 'first nation-state' framing.** Aurora is the necessary disambiguation. The popular framing of Stuxnet as the first nation-state Windows zero-day operation is *false* without qualifiers. Aurora used one zero-day for espionage in January 2010; Stuxnet used four zero-days for kinetic effect in June 2010. The defensible framing is: *Stuxnet is the first publicly analyzed nation-state Windows operation that burned multiple zero-days for kinetic, physical effect* [512,637,639]. Both qualifiers ("multi-zero-day" and "kinetic / physical") are load-bearing. Drop either and Aurora falsifies the framing.

Stuxnet showed nation-states would burn four Windows zero-days for a single operation. But four zero-days is an expensive way to compromise a credential, and as it turned out, a French engineer was about to make zero-days irrelevant for the credential-theft problem.

## Mimikatz: The credential layer demolition

Benjamin Delpy describes Mimikatz, in Andy Greenberg's Wired profile, as "a side project to learn C" [617]. The reader's natural reaction: a side project that broke a decade of Microsoft's most ambitious hardening program? That is precisely the point.

### 4.1 Delpy, LSASS, and the may 2011 release

Delpy was at the time an IT manager at a French government institution he declines to name [617]. He had become curious about an architectural quirk: Windows could prompt for his password at logon, then later authenticate him to remote servers (IIS via HTTP Digest, SMB via NTLM or Kerberos) without ever asking again. Something inside the OS had to hold a recoverable form of his password. He started reverse-engineering the Local Security Authority Subsystem Service (LSASS) and the authentication packages and security support providers loaded into it.

> **Definition: LSASS (Local Security Authority Subsystem Service).** A long-lived user-mode Windows process that holds the secrets the operating system needs to satisfy single sign-on across SMB, RPC, HTTP, RDP, IIS, and MS-SQL without re-prompting the user. By design, LSASS caches NT hashes, Kerberos Ticket-Granting Tickets, and (depending on the loaded security packages) recoverable plaintext credentials [626]. It is the load-bearing target of every credential-extraction tool the next decade produces.

The architectural quirk was structural, not accidental. The single sign-on contract requires the operating system to *re-authenticate* the user to network services, and the network protocols of the 1990s and 2000s (NTLM, Kerberos, HTTP Digest, MS-CHAP) all required either a hash, a ticket, or a recoverable plaintext to do that re-authentication [626]. LSASS held all three. There was no way to satisfy the contract without holding the secret in some recoverable form inside an LSASS-controlled memory region.

Public secondary accounts date the first Mimikatz release to May 2011 as closed-source software [617,624]; Delpy's archived September 2011 page independently confirms a public 1.0 alpha with LSASS-oriented modules by that year [618].

> **Note.** Delpy describes Mimikatz as "a side project to learn C" in the Wired profile; the framing matters because it underlines that breaking Windows credential security at this depth did not require nation-state resources: a single engineer with a debugger could do it.
Microsoft's response to his initial private disclosure had been, in his telling, that "you don't want to fix it"; he made the tool public to force the conversation. The GitHub repository `gentilkiwi/mimikatz` was created on April 6, 2014: a date readers can verify from the GitHub repository metadata [261]. Any "Mimikatz first released in 2007" claim refers to Delpy's pre-release private experimentation, not a public release.

### 4.2 Four primitives that broke the credential layer

The Mimikatz module set Delpy authored over 2011-2014 contains four primitives that together explain why every per-binary mitigation Microsoft had shipped was insufficient.

> **Definition: Pass-the-Hash (PtH).** Replay an NT hash as a bearer credential against any service that accepts NTLM authentication, *without* ever knowing the user's plaintext password [261,645]. The NTLM protocol authenticates by proof-of-possession of the NT hash, not proof-of-knowledge of the password.

Pass-the-Hash is the load-bearing primitive. NTLM authentication on the wire authenticates by proof-of-possession of the NT hash, not proof-of-knowledge of the password. The NT hash is computed exactly once, at logon, from the plaintext via `MD4(UTF16LE(password))`; after that the operating system never needs the cleartext again for NTLM. The full NTLMv2 challenge-response derivation, the two-stage HMAC-MD5 construction of `NTOWFv2` and `NTProofStr` per MS-NLMP §3.3.2 [646], is owned by The Death of NTLM chapter (Chapter 16). The only property this chapter needs is the one Pass-the-Hash exploits: every response is a deterministic function of the NT hash and never of the cleartext, so whoever reads the hash out of LSASS can authenticate as the user against any NTLM-accepting service until the password changes.

> **The NT hash is the bearer credential.** The plaintext password is not the secret. Once the operating system has derived the hash at logon, anyone who reaches LSASS and reads that hash can authenticate as the user against any NTLM-accepting service for as long as that hash remains valid, which is until the user next changes the password. The credential-replay class is a corollary of this single insight applied to different bearer credentials.
>
> **Definition: Pass-the-Ticket (PtT).** Extract a Kerberos Ticket-Granting Ticket or service ticket from LSASS and re-import it into another logon session for replay. Mimikatz exposes both halves: `sekurlsa::tickets /export` extracts; `kerberos::ptt` re-imports [261].

Pass-the-Ticket is the Kerberos analog of Pass-the-Hash. A Kerberos TGT is a bearer credential by design (it proves the holder authenticated to the Key Distribution Center) and like the NT hash, anyone holding the ticket can replay it. Mimikatz's `kerberos::ptt` injects a ticket blob into the local session's ticket cache; the next call to `klist` shows it as if the local logon had earned it.

> **Definition. Overpass-the-Hash.** Use a stolen NT hash as the Kerberos RC4-HMAC key to request a *fresh* TGT from the Key Distribution Center: the bridge from an NTLM-recovered hash to a Kerberos-issued ticket. It works where the KDC still accepts RC4-HMAC; AES-only domains require the separately-derived AES key instead [261].

Overpass-the-Hash is the bridge primitive. Estates that disabled NTLM in 2012-2014 in response to early Pass-the-Hash discussion believed they had closed the credential-replay door. Overpass-the-Hash re-opened it by using the NT hash directly as the RC4-HMAC Kerberos key to encrypt the pre-authentication timestamp, then sending a normal Kerberos AS-REQ. Where the KDC still accepted RC4, it issued a TGT keyed on the same secret the NTLM stack had used. From there, every subsequent Kerberos service ticket request was a legitimate Kerberos exchange backed by a stolen secret.

**WDigest plaintext-in-memory** is the fourth primitive, and the one that surprised even Microsoft's own teams when Delpy demonstrated it. Microsoft's WDigest Security Support Provider, which implemented HTTP Digest authentication on the server side and Digest single sign-on on the client side, held the user's plaintext password in LSASS memory by design, recoverable as long as the user's session was active.

> **Note.** WDigest predates the modern web; HTTP Digest authentication had been essentially deprecated by the time Mimikatz operationalised the plaintext-recovery primitive, which is why disabling WDigest plaintext storage has low operational downside on most post-2010 estates after legacy-use inventory.
Mimikatz's `sekurlsa::logonpasswords` enumerated the loaded authentication packages and security support providers, located their logon-session structures in LSASS memory, and printed cached secrets it could decrypt. Including, on many pre-2014 or explicitly re-enabled WDigest configurations, the user's plaintext password in clear text.

(One discipline note. Skeleton Key is *not* one of this chapter's four Mimikatz primitives. Skeleton Key was disclosed by Dell SecureWorks Counter Threat Unit on January 12, 2015 [647] and Delpy added `misc::skeleton` to Mimikatz on January 17, 2015, both outside this chapter's 2009–2014 window. They belong to the post-2014 era the Credential Guard chapter (Chapter 15) opens.)

🔵 **DOCUMENTED**: historical gap-analysis mechanism, not a procedure to reproduce. The 2011-2014 LSASS extraction path can be described without treating it as an operator recipe: an administrator-context process enabled debug privilege, obtained a read handle to `lsass.exe`, read the security-package state that LSASS already maintained for single sign-on, and used keys available in the same address space to recover credential material. The important architectural fact is that every step occurred inside VTL0 using interfaces the operating system intentionally exposed to sufficiently privileged code; AppLocker, ASLR, DEP, and Authenticode were not in that memory-read path.

### 4.3 The 2013 inflection: graph-walking offensive Active Directory

In August 2013, Skip Duckwall and Chris Campbell delivered "Pass-the-Hash 2: The Admin's Revenge" at Black Hat USA [645]. The talk did not invent the primitives Mimikatz had already shipped. It made offensive Active Directory tradecraft a public, named discipline by formalizing the graph-walking insight: every Windows host an administrator logs into caches a credential for that administrator; every credential cached on a compromised host is a stolen credential; every stolen credential is a new starting node for the next lateral movement. On poorly tiered estates, the attack graph often closed on the domain controller within hops measured in single digits.

As gap analysis, the discipline can be modeled as a four-part historical loop on any Windows estate with cached domain credentials [645]. First, session-enumeration surfaces (`NetSessionEnum`, `NetWkstaUserEnum` before KB4480964, and interactive-logon views such as `quser` / `qwinsta`) exposed the `(user, host)` tuple set representing credentials likely cached in LSASS. Second, those tuples could be compared with local Administrators membership and domain groups to identify where a recovered credential would carry higher-tier administrative reach. Third, Pass-the-Hash converted a recovered NT hash into a new authenticated context on that higher-tier host without requiring the cleartext password [261]. Fourth, the new host's LSASS became another credential cache to analyze. The loop terminated when one recovered credential reached Domain Admin. The point is not a recipe; it is the structural graph: `HasSession`, `AdminTo`, and `MemberOf` edges turned cached credentials into lateral movement.

This four-step loop is the *implicit* graph an attack-graph diagram makes explicit: vertices are users and hosts, edges are `MemberOf` (user is a group member), `AdminTo` (user has administrative access to a host), and `HasSession` (a host currently caches a credential for a user). Three years later, Andy Robbins, Will Schroeder, and Rohan Vazarkar productized this graph at DEF CON 24 in Las Vegas on August 6, 2016 as BloodHound, which uses the `SharpHound` collector to enumerate every vertex and edge, loads them into a Neo4j database, and runs Cypher shortest-path queries from any compromised principal to the `Domain Admins` group [648]. BloodHound is a 2016 artifact beyond this chapter's window; for the 2009-2014 window, the graph existed only in operator notebooks and on Duckwall and Campbell's whiteboard, but many Windows estates already had it: the attacker just had to walk it.

![Figure: The cached-credential lateral-movement graph. Typed vertices (host, user, and group) are joined by the three BloodHound relationships (`HasSession`, `MemberOf`, `AdminTo`); one walk reuses a credential each host already cached, closing on Domain Admin in single-digit hops. The graph already exists on many poorly tiered estates: Duckwall and Campbell whiteboarded it in 2013, and BloodHound automated walking it in 2016. Structure, not a recipe.](diagrams/22-mimikatz-attack-graph.svg)

### 4.4 the 2014 inflection: The Golden Ticket

In August 2014, Benjamin Delpy and Skip Duckwall jointly presented "Abusing Microsoft Kerberos: Sorry You Guys Don't Get It" at Black Hat USA [649].

> **Note.** The dual authorship matters: Delpy and Duckwall presented the talk together, and any single-author attribution misses the collaboration that produced the Golden Ticket walkthrough.
 The headline reveal was the **Golden Ticket**: a forged Kerberos Ticket-Granting Ticket signed with the domain's stolen `krbtgt` key (classically the NT hash, which is the RC4-HMAC key, or the krbtgt AES keys on AES-enabled domains).

> **Definition: Golden Ticket.** A forged Kerberos Ticket-Granting Ticket signed with the domain's stolen krbtgt key material (the RC4-HMAC key equal to the NT hash, or the krbtgt AES keys). Grants arbitrary user, arbitrary group, and arbitrary lifetime impersonation accepted by domain controllers for that domain; forest-wide impact follows when trust paths or privileged groups make that domain authority transitive. Survives every password reset *except* the krbtgt account's own [649,650].

The krbtgt account is the master signing key for the domain's Kerberos infrastructure. Every TGT a domain controller issues is encrypted and signed with a krbtgt long-term key (RC4-HMAC, which is the NT hash, or AES), and the domain trusts any TGT that verifies against that key. If an attacker holding domain-admin privileges has ever extracted the krbtgt hash from a domain controller's LSASS, they can forge a TGT for any user, with any group membership, with any lifetime they choose, and the domain controllers will accept it as if it had been legitimately issued. The forged ticket survives every routine password reset on the domain because routine password resets do not rotate the krbtgt account. Sean Metcalf's ADSecurity walkthrough remains the practitioner-grade canonical reference [650].

### 4.5 What this proved

By the end of 2014, the Mimikatz codebase had operationalised pass-the-hash, pass-the-ticket, overpass-the-hash, WDigest plaintext recovery, and the Golden Ticket on many default-configured 2011-2014 Windows hosts. Every credential the LSA process held in memory in a recoverable form was structurally exposed to an attacker with sufficient local privilege.

The scope of that claim matters. TPM-bound keys, smart-card private keys behind a hardware boundary, and Kerberos service keys on Windows servers whose LSASS the attacker had not yet compromised were *not* exposed by Mimikatz. The precise statement is *every credential the LSA process held in memory in a recoverable form*, not "every Windows credential primitive ever," and the precise statement is the one Microsoft eventually acknowledged in the Mitigating Pass-the-Hash whitepaper series [620].

> Mimikatz did not need to defeat AppLocker, ASLR, DEP, or Authenticode. It ran as an administrator, called OpenProcess on LSASS, and walked away with the reusable cached credential material LSASS held in recoverable form. The defender's playbook had been answering the wrong question.

Stuxnet was a four-zero-day operation that ran once. By 2014, Mimikatz was a free, open-source tool that could be reused wherever the credential material remained exposed. The offensive economics of attacking Windows fleets shifted decisively away from zero-day-burning and toward credential replay. *Why* did this happen, and what does it mean for the next decade of Windows defense?

## The causal link: Hardening birthed the credential-theft class

After two parallel narratives, the reader has the evidence to follow the argument. This is the chapter's intellectual center.

### 5.1 The pivot up the trust stack

While Microsoft was closing per-binary attack surface (Authenticode, kernel-mode code signing, ASLR, DEP, AppLocker, AppContainer, ELAM, Secure Boot) attackers pivoted up the trust stack to what those hardened binaries still had to trust: the credentials in LSASS memory, the Kerberos tickets in the LSA cache, and the LSA process address space itself. The mitigation surface and the attack surface are not at the same layer. This is the chapter's structural insight, and it is the single sentence the rest of the argument exists to defend.

The trust stack across the window is easiest to read vertically. At the bottom sit the hardware root, TPM measurements, UEFI Secure Boot databases, and the bootloader signature chain. Above them sit kernel-mode code controls such as kernel-mode code signing, ELAM, and PatchGuard; then user-mode signed-binary controls such as Authenticode and AppLocker; then sandboxed renderers such as AppContainer, Enhanced Protected Mode, and WinRT. LSASS process memory sits above all of those layers, holding NT hashes, Kerberos tickets, and the krbtgt-derived domain secrets that authenticated software still has to consume. Mimikatz targeted that upper layer directly. The defender controls protected the layers below it.

Read the trust stack as a vertical walk rather than as a flat checklist:

| Layer, bottom to top | 2009-2014 defender primitive | What the primitive can guarantee | Why it does not answer Mimikatz |
|---|---|---|---|
| Hardware and firmware root | TPM measurements, UEFI Secure Boot databases, BitLocker platform validation [27,193,105] | The machine boots the measured, signed boot path the owner intended. | A correctly booted Windows instance can still cache reusable credentials after logon. |
| Bootloader and early kernel path | Secure Boot, Measured Boot, ELAM [42,27] | Unsigned bootkits and late-loading boot-start drivers lose their easiest foothold. | LSASS is a legitimate signed user-mode process created after the boot chain succeeds. |
| Kernel-mode code integrity | Kernel-mode code signing, PatchGuard, ELAM driver classification [42] | The unsigned rootkit class becomes materially more expensive. | An administrator who can load a vulnerable signed driver, or who reaches the kernel through another path, is still operating in the enforcement domain. |
| User-mode application control | Authenticode, AppLocker publisher/path/hash rules, DEP/ASLR [616] | Known-bad or unsigned binaries are harder to launch; memory-corruption exploitation is less reliable. | Credential dumping is not a memory-corruption exploit against LSASS; it is a read of a trusted process by an already privileged caller. |
| Sandboxed application surface | AppContainer, Enhanced Protected Mode, WinRT capability SIDs [625] | Browser and Store-app compromise loses ambient file-system and registry authority. | A sandbox escape is not required once the attacker has administrative execution elsewhere in the estate. |
| Credential layer | LSASS memory: NT hashes, Kerberos TGTs, WDigest plaintexts, krbtgt-derived domain trust | The operating system holds reusable proof so single sign-on works. | This is the layer Mimikatz reads. The previous controls protect the route to Windows; they do not remove Windows' need to remember secrets. |
| Attacker primitive | Mimikatz `sekurlsa` modules [261,651] | Historical gap analysis: once the operator has local admin or kernel reach, the tool demonstrates what the credential layer exposed. | It does not need to defeat the lower controls; it asks a trusted, running Windows instance for memory the trust model already made reachable. |

The walkthrough is the missing diagram's point. Start at the TPM and climb upward: each Microsoft primitive narrows a real class of attack, and none of those wins is cosmetic. Secure Boot makes the pre-OS tamper path harder; ELAM moves antimalware into the earliest driver window; AppLocker gives enterprises a policy language for which binaries may execute; AppContainer strips broad ambient authority from modern apps. Then the climb reaches LSASS. At that height the defender's question changes from *which binary may execute?* to *which already-executing, already-trusted process must hold credentials so the user is not prompted every time they touch SMB, LDAP, RPC, HTTP Negotiate, or RDP?* Mimikatz was devastating because it answered the second question while most 2009-2014 controls were built for the first.

This is why the trust-stack picture is causal rather than decorative. Every defender control below LSASS can succeed and the credential layer can still fail. Every boot measurement can verify, every AppLocker rule can pass, every sandbox boundary can hold, and a domain administrator's interactive logon can still leave a reusable TGT in an address space readable by the same privilege domain. The offensive innovation was not a clever bypass of AppLocker; it was the recognition that AppLocker had become less interesting than the material the approved process kept in memory.

### 5.2 The Mimikatz codebase as the consolidation node

Mimikatz did not invent the whole credential-replay class; Paul Ashton, Hernan Ochoa, the Pass-the-Hash Toolkit, and WCE are real predecessors. Its importance is that it became the consolidation and generalization node: Pass-the-Hash, Pass-the-Ticket, Overpass-the-Hash, and Golden Ticket all landed in `gentilkiwi/mimikatz`, with Delpy's August 2014 commits showing Golden Ticket work immediately after the Black Hat disclosure [261,652]. After the GitHub repository creation on April 6, 2014 [261], the same codebase later grew its post-2014 modules (Skeleton Key and DCSync) [647,653]. There was no comparable single codebase on the defender side. Microsoft's countermeasures landed across at least three product teams (Active Directory, Windows Defender, Hyper-V), and the architectural answer required a hypervisor.

> Because you don't want to fix it, I'll show it to the world to make people aware of it.: Benjamin Delpy [617]

Delpy's framing converted a defender's blind spot into a public, weaponised primitive. Microsoft's initial dismissal of his private disclosure (that the credential model was "by design") was true, in the most damaging possible sense. The model *was* by design. The single sign-on contract required it. Closing the gap required a different design.

### 5.3 The economic argument

The shift was economic as much as architectural. A reliable Windows zero-day exploit chain commanded scarce-market prices in the early 2010s and lost value once disclosed and patched. A Mimikatz invocation, by contrast, was free, repeatedly reusable on hosts whose credential material remained in VTL0, and could run as the operator the attacker already compromised. The asymmetry is not subtle, even without pretending every zero-day market or every estate priced risk the same way.

| Property | Stuxnet (June 2010) | Mimikatz (May 2011 onward) |
|---|---|---|
| Attacker cost | Four Windows zero-days + two stolen Authenticode certificates + ICS payload [512] | Free tool (open-sourced 2014) [261] |
| Reusability | Loses value once disclosed and patched [623,632,633,634] | Reusable on hosts whose relevant secrets remain readable from VTL0 |
| On-disk footprint | Multi-megabyte signed dropper + Step 7 / S7 payloads | Single executable; can run in memory |
| Detection footprint | Symantec / Kaspersky / ESET signatures within weeks of disclosure [512] | Initially harder for signature-based AV; later detected through LSASS access telemetry and credential-abuse analytics |
| Target population | Specific ICS estate (Natanz) | Windows AD estates with reusable credentials exposed on compromised hosts |
| Threat-model implication | Nation-states will burn zero-days for kinetic effect | An admin-level compromise can become credential replay if recoverable secrets remain in LSASS |

> **Key idea.** Defensive success at one layer reliably produces attacker innovation at the next layer up. The 2009-2014 window proves it: Microsoft narrowed rootkit, bootkit, and unsigned-bootloader paths; attackers responded by reading the credentials in LSASS memory that hardened binaries still had to trust. The mitigation surface and the attack surface were not at the same layer.

If the credential layer was structurally broken, why didn't Microsoft just fix it? They tried. The next section is the honest evaluation of Microsoft's counter-pivot through November 2014.

## Microsoft's Counter-Pivot: 2013-2014

Microsoft was not asleep. By Windows 8.1 General Availability on October 17, 2013, three controls landed that were *directly* a response to Mimikatz. They were partial wins, all of them; the architectural acknowledgment that LSASS-in-VTL0 was unsalvageable would arrive only with Virtualization-Based Security and Credential Guard in Windows 10 1507 [621], outside this chapter's window. This section is the honest evaluation of what shipped, what it accomplished, and why none of it was enough.

### 6.1 Restricted Admin RDP

Restricted Admin RDP changes the Remote Desktop Protocol so that the client never sends the user's plaintext password to the server's LSASS [446]. In the CredSSP / Network Level Authentication exchange, the client proves possession of credential material from the client side (using Kerberos or NTLM as negotiated) and the resulting session is a network logon rather than a full interactive logon with reusable credentials delegated to the server. Critical plaintext credential material is not present on the RDP server.

The bug Restricted Admin closes is the credential-disclosure failure mode: a foothold on the RDP server used to learn every administrator's plaintext password as they logged in. The bug it leaves open is replay. A Restricted Admin RDP session is a *network* logon, and an attacker who already holds reusable NTLM material for an administrative account can pair Pass-the-Hash with a Restricted Admin RDP client invocation from a compromised host and authenticate to the target RDP server without knowing the plaintext password. Restricted Admin reduced disclosure; it did not close replay.

Protocol detail matters, but the security accounting is simple: Restricted Admin is a disclosure mitigation, not a replay mitigation. It keeps reusable administrator secrets from being newly delegated to the RDP server; it does not make a previously stolen hash or ticket cease to be a bearer credential.

Server-side Restricted Admin shipped at Windows 8.1 / Server 2012 R2 General Availability on October 17, 2013. The client-side back-port to Windows 7, Server 2008 R2, Windows 8, and Server 2012 followed via KB2871997 on May 13, 2014 [446], which is also where the WDigest control and TokenLeakDetectDelaySecs primitives shipped.

### 6.2 LSA Protected Process (RunAsPPL)

LSA Protected Process loads LSASS as a Protected Process Light with the signer level `PsProtectedSignerLsa`. Once Protected, the Windows kernel refuses any `OpenProcess(PROCESS_VM_READ)` call against LSASS from a process running at a lower signer level. Including a process running as NT AUTHORITY\SYSTEM with `SeDebugPrivilege` [436]. The flag is enabled by setting `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL` to `1`. RunAsPPL is the strongest credential-protection primitive Microsoft shipped inside Windows 8.1.

> **Definition. Protected Process Light (PPL) / PsProtectedSignerLsa.** A kernel-enforced signer level that prevents OpenProcess(PROCESS_VM_READ) and CreateRemoteThread against the protected process from any process running at a lower signer level, regardless of token privileges or session [328,436]. The Lsa variant requires every LSA plug-in DLL (SSPs, Authentication Packages, and LSA Notification Packages) to itself be signed at a compatible signer level, which is why enabling RunAsPPL on real estates requires an LSA plug-in audit.

The bypass class is Bring Your Own Vulnerable Driver. A malicious kernel-mode driver, loaded through a vulnerable but Microsoft-signed third-party driver that the attacker has placed on disk, can clear the `Protection` byte in the kernel `EPROCESS` structure for LSASS, after which the `OpenProcess(PROCESS_VM_READ)` call succeeds. Mimikatz ships its own kernel driver, `mimidrv.sys`, that performs exactly this manipulation [261]. The structural problem is that RunAsPPL is enforced by the same kernel an attacker is compromising to bypass it; the protection cannot be made strictly stronger inside the same privilege ring than the kernel that enforces it.

> **Why PPL and Credential Guard are complementary, not competing.** A common misreading is that PPL is a partial Credential Guard, or that Credential Guard replaces PPL. The most useful framing is itm4n's: *"I noticed that this protection tends to be confused with Credential Guard, which is completely different"* [328]. PPL is a same-privilege-domain gate inside VTL0: LSASS remains a user-mode process, but the VTL0 kernel decides whether to grant a process handle, and a kernel-mode attacker can alter that decision point. Credential Guard is a cross-privilege isolation between VTL0 and VTL1 (the Virtual Trust Levels Hyper-V introduces in Windows 10 1507) [621]: the credential material lives in a Virtual Secure Mode trustlet (LSAISO) that the VTL0 kernel cannot read because the hypervisor's Second-Level Address Translation tables deny the mapping. The two controls are complementary: PPL hardens LSASS against in-VTL0 attackers; Credential Guard moves the high-value secret out of VTL0 entirely. §8.3 develops the cross-privilege isolation argument formally.

### 6.3 The Mitigating Pass-the-Hash whitepaper series

Microsoft published the Mitigating Pass-the-Hash and Other Credential Theft whitepaper in two versions: v1 in December 2012 from the Trustworthy Computing group [619] and v2 in July 2014 [620]. There is no v3. Post-2014 guidance migrated into the *Securing Privileged Access* online documentation rather than appearing as a numbered v3 PDF, and any "v3 2017" reference is incorrect.

The v1 paper introduced the tier 0 / tier 1 / tier 2 administrative-account model: separate the accounts that manage the forest (tier 0: domain controllers, AD), the accounts that manage server applications (tier 1: file servers, Exchange, SQL), and the accounts that manage end-user workstations (tier 2: helpdesk, desktop support). The rule is that a tier-N credential must never be exposed on a tier-(N+1) host. The model is sound. The problem is that v1 was recommendations-only with no enforcement primitive inside the operating system, and operators routinely violated tiering (the helpdesk technician fixing the CEO's laptop with a tier-2 credential and then RDPing to a tier-1 file server exposes the credential at the laptop's LSASS). The v2 paper integrated the technical D5 controls (RunAsPPL, Restricted Admin, KB2871997) precisely because v1 alone could not move the needle on real estates.

### 6.4 KB2871997 and the WDigest control

The May 13, 2014 update KB2871997 is the single most operationally impactful credential-protection control of the entire window [446]. It carried three deliverables. First, the Restricted Admin client back-port to Windows 7 / Server 2008 R2 / Windows 8 / Server 2012, which Section 6.1 covers. Second, it introduced the `HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential` control: Windows 8.1 / Server 2012 R2 and later are the clean disabled-by-default story, while Windows 7 / Server 2008 R2-era down-level systems generally required administrators to set `UseLogonCredential = 0` explicitly after installing the update. Third, it added the `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\TokenLeakDetectDelaySecs` (default 30 seconds) cleanup of leaked logon-session credentials.

> **Always apply KB2871997, then verify WDigest state.** On Windows 8.1 / Server 2012 R2 and later, WDigest plaintext storage is disabled by default unless an administrator re-enables it. On Windows 7 / Server 2008 R2-era down-level systems, the safe operational guidance is to install the update and explicitly set `UseLogonCredential = 0` [446]. The compatibility risk is low on most post-2010 enterprise estates because HTTP Digest authentication is rare, but legacy exceptions should be found by inventory rather than assumed away.
>
> **Note.** The WDigest control was easy to miss because the headline framing was Restricted Admin RDP; many 2014-era administrators applied the patch for the RDP fix without auditing whether WDigest plaintext storage had actually been disabled on their down-level hosts [446].

### 6.5 the seeds of Credential Guard

By late 2014 Microsoft was already prototyping the Hyper-V-as-security-boundary architecture that becomes Virtualization-Based Security, Credential Guard, and Hypervisor-protected Code Integrity in Windows 10 1507 on July 29, 2015 [621]. For the reader of this chapter, the key observation is that Microsoft had already accumulated the evidence by mid-2014 that in-VTL0 hardening could add friction but not isolation against kernel-capable attackers, and that the architectural answer required moving high-value credential material to a different privilege domain than the kernel attackers compromise.

> **Key idea.** Restricted Admin reduced disclosure but not replay. RunAsPPL stopped a Mimikatz invocation only until BYOVD. The Pass-the-Hash tiering model named the problem but had no enforcement primitive inside the operating system. Microsoft's counter-pivot in this chapter's window was correct in direction and *insufficient by construction*: because the architecture was the problem, not the engineering.

Microsoft shipped the right primitives. None of them was sufficient by construction, because the architecture was the problem. To see why, we have to look at the one orthogonal thing the window left open: the SChannel attack surface, before turning to the impossibility argument behind credential isolation.

## The SChannel coda: WinShock (MS14-066, November 11, 2014)

The window closes on November 11, 2014 with one of the last major pre-cloud TLS-stack remote-code-execution scares in Windows. WinShock is a counterpoint that reinforces the chapter's thesis rather than contradicting it: even with every credential-layer control of 2013-2014 deployed, an unrelated per-binary defect in the Schannel TLS stack could still hand an attacker remote code execution before any application code ran. The credential-layer hardening Microsoft spent the year shipping could not have prevented this bug, and the bug's existence is part of the evidence that hardening one layer leaves orthogonal layers exposed.

A note up front, because the popular framing got this wrong. The bulletin itself was *not* silent. MS14-066 was published on the November 11, 2014 Patch Tuesday with a Critical severity rating, an explicit CVE assignment (CVE-2014-6321), contemporary Brian Krebs coverage [654], and public proof-of-concept walkthroughs within months [655]. The "silent" framing applies only to the additional Schannel hardening fixes Microsoft bundled into the same update without separate disclosures.

### 7.1 The mechanism

A crafted TLS handshake triggered a memory-corruption path inside `schannel.dll`, the Windows Secure Channel security package that implements TLS for every in-box TLS consumer [656,655]. The bug allowed remote code execution before any application code ran: the handshake itself was the attack. The NVD entry catalogs the affected platforms as Windows Server 2003 SP2, Windows Vista SP2, Windows Server 2008 SP2 and R2 SP1, Windows 7 SP1, Windows 8, Windows 8.1, Windows Server 2012 Gold and R2, and Windows RT Gold and 8.1: essentially every supported Windows of the era [655].

The attack surface was broad across the Windows enterprise estate of late 2014. IIS hosts terminating HTTPS, RDP-over-TLS listeners, Exchange ActiveSync endpoints, Active Directory Federation Services endpoints, and other services terminating TLS in Schannel inherited the vulnerable stack when exposed to untrusted handshakes. A defensible writer-side abstraction (which this chapter takes) is that a crafted handshake triggered a memory-corruption path; the precise internal type and function family Microsoft fixed are not safely attributable without a primary-source walkthrough beyond the bulletin's published abstract.

### 7.2 The bundled extras

Microsoft bundled additional Schannel hardening into MS14-066 without separate bulletins. The chapter does not name specific CVE IDs for those bundled extras because prior pipeline runs found such attributions factually wrong (those CVE IDs belong to other bulletins or are REJECTED in NVD). The defensible framing is that Microsoft bundled additional Schannel hardening into the same update without separate bulletins, anchored to contemporary coverage of the patch cycle [654]. The substantive point survives without speculative CVE attribution.

> **Note.** The "no public exploitation" framing of MS14-066 is wrong. BeyondTrust's "Triggering MS14-066" blog post and the SecuritySift "Exploiting MS14-066 (CVE-2014-6321) aka 'Winshock'" walkthrough are both referenced from the NVD entry as Exploit Third Party Advisory [655]. The CVE was patched, and the exploitation tradecraft was public; only the bundled hardening extras went unannotated.

### 7.3 Strategic significance

WinShock is a bookend on an era when the Windows Schannel stack was often the front door for Windows-hosted enterprise services. After 2014, TLS termination for many Internet-facing Windows estates increasingly moved to Azure Front Door, Akamai, Cloudflare, AWS Application Load Balancer, or other managed edge layers rather than sitting exclusively at the Windows Schannel layer. Microsoft's own first-party services (Exchange Online, SharePoint Online, the Office 365 ingress fleet) terminated TLS at Azure-managed edge appliances, the topology documented in Microsoft's *Microsoft 365 network connectivity principles* as the recommended "connect locally to the Microsoft global network" architecture in which the customer's traffic enters Microsoft's network as close to the user as possible and TLS is terminated at the nearest edge node [657]. The architectural lesson is not that Schannel was uniquely fragile; it is that monolithic TLS stacks across hundreds of in-box consumers were a brittle design that the industry stopped accepting as the default deployment topology for enterprise services.

WinShock closed the window with a per-binary patch. But the bigger story (the credential layer Microsoft had spent the year trying to close) was structurally broken in a way no patch could fix. To see why, we have to make the impossibility argument formally.

## Theoretical limits: Why no per-binary hardening could fix the credential layer

A reframe. Every section so far has narrated *evidence*. This section turns that evidence into an argument from architecture: a structural reason the per-binary playbook *could not have* fixed the credential layer, regardless of how good Microsoft's engineering was.

### 8.1 The trusted-computing-base argument

The Windows authentication subsystem must, at some point, hold or broker verifiable proof of identity. As §4.1 established, the single sign-on contract forced LSASS in the pre-Credential-Guard model to hold recoverable secrets or bearer objects in memory [626]. As long as that secret lives in a memory space the OS can read, an attacker who reaches that memory space can read it too.

AppLocker, ASLR, DEP, AppContainer, ELAM, and Secure Boot are all per-binary mitigations [616,42,27]. They prevent the *wrong* code from running. They do not prevent the *right* code (an administrator-launched Mimikatz; a Microsoft-signed but vulnerable third-party kernel driver) from reading LSASS memory through documented Win32 APIs. The per-binary playbook is a code-execution control, not a memory-access control, and the credential-theft attack is not a code-execution attack.

### 8.2 The asymmetry

The defender tries to close enough of the per-binary attack surface that attacker code cannot reliably run. The attacker needs only one useful credential primitive to remain extractable on a high-value path. The two budgets are not comparable. The defender's job is structurally harder, and a single residual gap (one unsigned plug-in, one cached WDigest plaintext, one stolen NT hash on a high-value account) can be enough to reopen lateral movement. This is not a Microsoft engineering failure. It is an architectural inevitability of the in-VTL0 LSASS model.

### 8.3 The VTL0-symmetry argument

In any single-privilege-ring operating system, a protection mechanism implemented *inside* that ring cannot provide strong isolation for a memory region against an attacker who reaches the same ring with kernel authority. This is the formal statement of the limit Microsoft hit in 2014.

RunAsPPL is the strongest 2014-era expression of this bound. As §6.2 documented, a BYOVD-loaded kernel driver can clear the `Protection` byte on the LSASS `EPROCESS` and `OpenProcess(PROCESS_VM_READ)` succeeds [328,436]; the protection is enforced by the same kernel the attacker is compromising; the kernel cannot enforce a protection against itself.

The architectural way to state it: $\text{Protection}_{\text{in-ring}}(M) \lt \text{Adversary}_{\text{in-ring}}(M)$ for any memory region $M$ in the same privilege ring as the adversary. The protection function and the adversary function operate on the same domain, and the adversary always wins by construction. The algebraic notation is intentionally informal; the cited formal lineage is narrower and should not be overstated. Bell-LaPadula gives the classic mandatory-access-control vocabulary for information flow: subjects, objects, labels, and the rule that a reference monitor must mediate reads and writes [658,659]. Lampson's confinement problem gives the complementary warning: if a computation is allowed to handle a secret inside the same authority domain as the observer, the system must account for every channel by which that computation can leak or be inspected [660]. Windows 8.1-era LSASS is not a Bell-LaPadula system, but the lesson transfers cleanly: a reference monitor implemented by the VTL0 kernel cannot make LSASS memory opaque to an adversary who has obtained VTL0 kernel authority, because that adversary can ask the same memory manager to map, copy, patch, or re-label the object. Closing the gap requires moving $M$ to a privilege domain $\text{D}'$ such that the in-ring adversary cannot map $\text{D}'$ at all.

That is exactly what Virtualization-Based Security does in Windows 10 1507 [621]. Hyper-V boots before the Windows kernel and creates two Virtual Trust Levels: VTL0 is the normal Windows kernel attackers compromise; VTL1 is Virtual Secure Mode, an isolated execution domain whose memory the VTL0 kernel cannot read because the hypervisor's Second-Level Address Translation tables deny the mapping. Credential Guard hosts an LSA Isolated trustlet (LSAISO) in VTL1 that holds the high-value credential material; the VTL0 LSASS process holds only obfuscated references that LSAISO can resolve. A Mimikatz invocation in VTL0 can still extract the references, but the references no longer dereference to a credential the VTL0 kernel can read.

> As long as the kernel that protects LSASS executes in the same privilege ring as the kernel an attacker compromises, protections inside that ring provide friction rather than strong isolation. The credential cache must live in a different privilege domain than the kernel that the attacker can compromise.

### 8.4 The way out, foreshadowed

Hardware-rooted isolation of the credential cache is the structural answer Microsoft chose, and in this design space it is the robust answer: move the secret where the VTL0 kernel cannot map it. Virtualization-Based Security, Credential Guard, and the LSAISO trustlet in VTL1 are the architectural answer to the architectural problem this chapter proves cannot be closed inside VTL0 [621]. They are the spine of the chapters that follow, beginning with Credential Guard (Chapter 15). This chapter closes its argument by naming the problem precisely so the Credential Guard chapter can name the solution precisely.

> **Key idea.** Hardware-rooted isolation of the credential cache (the LSAISO trustlet in a VTL1 the VTL0 kernel cannot read) is the structural answer that changes the privilege geometry. The Credential Guard chapter (Chapter 15) ships it; this chapter names *why* it had to.

The architecture was the problem. What did practitioners do with this evidence at the end of 2014?

## Verify it yourself (documented): defensive-state probes

This chapter does not reproduce credential theft. The verification appropriate for a book chapter is the defensive state that explains the historical gap: which credential protections existed, which process was protected, and whether the later VBS answer is present. The following probes are read-only defensive checks; they are meant for an administrator validating their own estate, not for extracting secrets.

> 🔵 **DOCUMENTED**: defensive state checks, not captured on our lab VM. Microsoft documents the registry and WMI surfaces for WDigest, LSA protection, and Credential Guard; expected values below are the states discussed in this chapter.

```powershell
# WDigest plaintext storage disabled by the KB2871997-era default.
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' |
  Select-Object UseLogonCredential
# Expected hardened state: UseLogonCredential = 0 or value absent on modern Windows.

# LSA Protected Process enabled for LSASS.
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' |
  Select-Object RunAsPPL
# Expected hardened state: RunAsPPL = 1 or 2, depending on UEFI-lock configuration.

# Credential Guard / VBS running, the architectural answer beyond this chapter's window.
(Get-CimInstance -ClassName Win32_DeviceGuard `
  -Namespace root\Microsoft\Windows\DeviceGuard).SecurityServicesRunning
# Expected when Credential Guard is running: the array contains 1.
```

The important reading is layered. `UseLogonCredential = 0` removes one plaintext cache. `RunAsPPL` makes LSASS harder to read from VTL0 user mode. `SecurityServicesRunning` containing Credential Guard shows that the high-value long-term secrets have moved to the VBS trustlet model explained in the following chapter. The first two are harm reduction inside the old model; the third is the architectural break from it.

## Open problems at the end of 2014

Picture a Fortune-500 security operations center on a Friday afternoon in early December 2014. The team has applied every Microsoft patch through MS14-066 [656], deployed AppLocker on Enterprise SKUs [616], set `RunAsPPL = 1` after a careful LSA plug-in audit [436], applied KB2871997 and verified WDigest plaintext storage was disabled [446], and read the Mitigating Pass-the-Hash v2 whitepaper cover to cover [620]. They run an internal red-team exercise the following Monday. Mimikatz still works. Why?

The credential layer is still essentially open. WDigest plaintext storage is now disabled by default on Windows 8.1 / Server 2012 R2 and later, and can be disabled on down-level patched systems by explicitly setting `UseLogonCredential = 0`; that closes the single most embarrassing primitive Delpy's 2011 demonstration exposed when administrators actually verify the state [446]. But the cached NT hashes that NTLM authentication needs, the Kerberos Ticket-Granting Tickets the SSO contract holds in the LSA ticket cache, and the krbtgt master signing key on any domain controller whose LSASS the attacker can `OpenProcess` against all remain extractable [261,626]. RunAsPPL stops a Mimikatz invocation from user mode, but it does not stop Mimikatz from invoking its own `mimidrv.sys` driver (or any other vulnerable signed third-party driver) to clear the protection byte from kernel mode and proceed [328,261]. The same `sekurlsa::logonpasswords` family that worked in May 2011 still works in December 2014 wherever the attacker can reach LSASS from user mode or use a vulnerable signed driver to remove PPL: a realistic condition on many estates of the period.

One open problem the security community debated through 2014 deserves a sharper treatment because it surfaces the *structural* limit of any in-LSASS hardening strategy: why does Microsoft not simply relocate or obfuscate the LSA secret structures whose offsets Mimikatz hard-codes? The Mimikatz codebase carries explicit, per-Windows-build signature and offset tables (for example the `lsasrv` `LogonSessionList` table in `mimikatz/modules/sekurlsa/kuhl_m_sekurlsa_utils.c`, with package-specific offsets such as WDigest in `kuhl_m_sekurlsa_wdigest.c`) that map every supported Windows build to the byte offsets and signature byte sequences Mimikatz scans for at run time [651]. The maintenance cost on the offensive side is one row per shipped Windows build per quarter. The proposed defensive response (shuffle the struct layouts each cumulative update, randomise the symbol offsets, swap the byte signatures) fails as a defense for three independent reasons. First, cost asymmetry. Microsoft would commit the test, validation, and Windows Hardware Quality Labs re-certification cost of every layout shuffle across every supported Windows SKU, language pack, and architecture every quarter; Mimikatz's maintainers would commit one pull request and one signature-table row per build. Second, defender-side fragility. The same LSASS structures the offsets index are consumed by Microsoft's own security tooling, by every third-party Endpoint Detection and Response agent, and by Windows Error Reporting; randomising the layout breaks the defender's own dependencies first and the attacker's last. Third, adversary-side robustness. Mimikatz already supports pattern-based signature scanning that finds the target structures even when their absolute offsets move; the offset hard-coding is a performance optimization, not a requirement. The structural defense Microsoft is already building is to lift the credential cache out of the VTL0 user-mode process space entirely and into a Virtualization-Based Security trustlet whose memory the VTL0 kernel cannot read. Alex Ionescu's Black Hat USA 2015 "Battle of SKM and IUM" talk lays out the VTL1 / IUM architecture in operator-facing detail and forward-references the Credential Guard design that ships in Windows 10 1507 [661]. The community of this era could see the answer; the architectural prerequisites simply had not yet shipped.

Microsoft is prototyping Virtualization-Based Security and Credential Guard, but the architectural answer ships outside this chapter's window [621]. Even after it ships, Credential Guard requires Windows 10 Enterprise, UEFI 2.3.1, Secure Boot, a 64-bit CPU with virtualization extensions, and (on most estates) a hardware refresh cycle that costs years and millions. The deployment surface that needs the protection most cannot adopt it until well into 2017.

AppLocker still carries its Windows 7 structural gaps in late 2014: the Application Identity service can be stopped by any process running as LocalSystem, after which enforcement degrades open until reboot, and the dual-DACL bypass class (rules that pass both Publisher and Path checks but reach a different binary at runtime) remains unaddressed [616,627]. Windows Defender Application Control is the kernel-enforced policy successor that closes both gaps, and the subject of the App Control for Business chapter (Chapter 13). It is still a Windows 10 enterprise feature beyond this chapter's window. Secure Boot has its first `dbx` revocation politics in this window: Microsoft's revocation list has to retire compromised UEFI bootloaders without bricking dual-boot Linux installations on the millions of OEM machines that ship with Secure Boot enabled, and the cadence and scope of `dbx` updates becomes a recurring operational point of friction between Microsoft, OEMs, and the Linux distribution community [27,32]. The Pass-the-Hash v2 tiering recommendations are aspirational for the vast majority of 2014 deployments: a complete tier 0 / tier 1 / tier 2 administrative-account program is a multi-year project that requires Active Directory restructuring, change-management governance, and operator retraining at scale, and most estates that read the v2 paper applied KB2871997 and stopped there [620].

Mimikatz's post-2014 modules (Skeleton Key and DCSync) sit in the same codebase, are anchor events beyond this chapter's window, and define the credential-replay horizon this chapter's reader is staring at [647,653].

The defining open question at the end of 2014 is how Microsoft isolates a long-lived user-mode process (LSASS) holding the most valuable secrets in the operating system from an administrator-privileged attacker on the same host, without breaking the hundreds of in-tree dependencies LSASS has accumulated since NT 3.1. The answer (Virtualization-Based Security plus the trustlet model) is the subject of the Credential Guard chapter (Chapter 15). It requires a hypervisor, a hardware-rooted boot chain, a re-architected LSA plug-in protocol that splits sensitive operations into LSAISO trustlet calls, and an operational deployment story that took Microsoft from late 2014 prototypes to general availability in 2015 and broad enterprise adoption only by 2018-2019.

> **The credential layer is still essentially open.** At the end of 2014, WDigest plaintext storage is closed by default on the newer branch and closable by registry on patched down-level systems. NT hashes, Kerberos TGTs, the krbtgt master key, and other secrets LSASS holds in recoverable form remain extractable by an attacker on the same host who can reach LSASS or load a kernel driver. The architectural answer (Credential Guard in Windows 10 1507) ships eight months later [621]. This chapter's window proves the problem is real; the Credential Guard chapter (Chapter 15) ships the answer.
>
> **The deployment gap.** Even at end-of-2014, with every Microsoft control available, many large estates had applied KB2871997 or the WDigest registry change [446] but had not completed the harder controls. Tiering [620] is a multi-year program. RunAsPPL [436] requires an LSA plug-in audit that breaks any custom credential provider not yet re-signed at the PPL signer level. The architectural answer (Credential Guard in 2015 [621]) arrives to a deployment surface still struggling to deploy the 2013 controls. The gap between *the security primitive Microsoft shipped* and *the security primitive a Fortune-500 estate actually had running* was unusually large, and it grew through the Windows 10 1507 General Availability window.

The eight open problems are therefore concrete, not rhetorical:

1. **Credential cache isolation.** LSASS still holds NT hashes, Kerberos tickets, and domain-controller secrets in VTL0-readable memory.
2. **Same-ring enforcement.** RunAsPPL is valuable friction, but a kernel-mode adversary or vulnerable signed driver can alter the protection state it relies on.
3. **Offset-table economics.** Moving LSASS structures raises Microsoft's compatibility and validation cost more than it raises Mimikatz's signature-maintenance cost.
4. **Administrative tiering.** The Pass-the-Hash v2 answer is organizational (tier 0 isolation, PAWs, account separation) and most 2014 estates cannot complete it quickly.
5. **Application-control survivability.** AppLocker reduces commodity launch paths but remains user-mode-service-dependent and is not yet WDAC's kernel-enforced policy model.
6. **Boot-chain politics.** Secure Boot and `dbx` revocation work, but every revocation has OEM, Linux-shim, recovery-key, and help-desk blast radius.
7. **Credential-replay horizon.** The same codebase is about to operationalise Skeleton Key and DCSync just beyond this chapter's window, so the defender cannot treat 2014 as an endpoint.
8. **Deployment lag.** The architectural answer needs VBS-capable hardware, Enterprise licensing, LSA plug-in compatibility, and years of estate churn before it protects the machines that need it most.

None of those admits a complete 2014-era technical solution. So how does a practitioner read the 2009-2014 primitives against a 2026 Windows 11 baseline?

## Practical guide: Reading the 2009-2014 primitives against a 2026 Windows 11 baseline

The previous nine sections built the structural argument. This section answers the operator's question: which of these 2009-2014 primitives are still load-bearing in 2026, and which were superseded?

### 10.1 Which 2009-2014 primitives are still load-bearing in 2026

| Primitive (2009-2014) | Still in use 2026? | Superseded by |
|---|---|---|
| AppLocker (Win 7+) [616] | Yes, on Windows 10/11 Enterprise estates | App Control for Business (WDAC) for new deployments |
| ELAM (Win 8+) [42] | Yes, load-bearing for the boot chain on every supported Windows | Unchanged primitive; Defender's WdBoot.sys is the in-box ELAM driver |
| UEFI Secure Boot (Win 8+) [27] | Yes; mandatory for Windows 11 hardware certification | Strengthened with mandatory dbx revocation enforcement |
| AppContainer (Win 8+) [625] | Yes; substrate for MSIX, Edge renderers, and packaged-app isolation | Generalized across packaged Win32 app models |
| LSA Protected Process (Win 8.1+) [436] | Yes; *on by default* on **new installations** of Windows 11 22H2 and later when requirements are met (upgraded systems and policy-disabled systems require explicit enablement) | Complemented by Credential Guard on enterprise hardware |
| Restricted Admin RDP (Win 8.1+) [446] | Yes; still recommended | Remote Credential Guard (Win 10 1607+) for high-tier environments |
| WDigest plaintext disablement (KB2871997) [446] | Disabled by default on Windows 8.1 / Server 2012 R2 and later; verify `UseLogonCredential = 0` on patched down-level systems | Unchanged primitive; WDigest itself is essentially deprecated |
| Mitigating Pass-the-Hash tiering model [620] | Yes; lives on as Privileged Access Workstations and Enterprise Access Model | *Securing Privileged Access* online documentation |

Two surprises in the table. First, LSA Protected Process is *on by default* on many **new installations** of Windows 11 22H2 and later when hardware and policy requirements are met. Which closes the gap for newly shipped devices, though estates that upgraded from earlier Windows versions or explicitly disabled the feature still require the manual, MDM, or GPO enablement step that defined the 2014-2020 period. Second, AppLocker is still in production on enterprise estates ten-plus years after Windows 7 General Availability; the WDAC successor is the recommendation for new deployments, but the installed AppLocker base did not get replaced.

### 10.2 Mimikatz tradecraft as the floor of red-team capability

On pre-Credential-Guard Windows estates that still expose reusable secrets in VTL0, Mimikatz's 2011-2014 module set defines the floor of red-team capability. `sekurlsa::logonpasswords` reads recoverable LSA-cached credential material the operator's privileges allow [261]. `sekurlsa::tickets /export` extracts Kerberos tickets from the LSA cache that the operator's context can reach. `lsadump::secrets` reads LSA private secrets. `lsadump::sam` reads local SAM hashes. `kerberos::ptt` re-imports tickets for replay. `kerberos::golden` forges Golden Tickets given a stolen krbtgt hash [650]. This chapter's 2009-2014 primitives are the foundation any practitioner reasoning about lateral movement in a Windows-AD estate uses every day, and the conceptual model Sean Metcalf documented on ADSecurity.org remains the canonical operator-grade reference.

### 10.3 Detection

Where to look. Sysmon ProcessAccess events on LSASS (event ID 10) record one process opening another process and are specifically documented as useful for detecting tools that read LSASS memory for credential theft [662]. Granted Access masks such as `0x1010`, `0x1410`, or `0x143A` are common high-signal heuristics for LSASS read/dump behavior rather than canonical requirements; treat them as starting points to combine with source-image allowlists, signer state, PPL state, and MITRE ATT&CK T1003.001 context [663]. `PROCESS_QUERY_LIMITED_INFORMATION` appears in legitimate tooling too (Task Manager, performance tools, and EDR sensors can request it) so these masks need suppression logic rather than a raw alert. Windows Security event 4673 (sensitive privilege use) on `SeDebugPrivilege` fires when a process adjusts its token to enable debug privileges (the prerequisite for `privilege::debug`) which is interesting in itself when the actor is not a known debugger. System Access Control Lists on the krbtgt account, paired with Domain Controller audit subcategories for Kerberos AS-REQ and TGS-REQ, surface the AS-REQ-without-corresponding-logon anomalies that Golden Ticket use produces [650]. Microsoft Defender for Identity raises Suspected Golden Ticket and Suspected Skeleton Key alerts on its analysis of domain-controller telemetry (the Skeleton Key alert points past this chapter's window). The ETW/EDR substrate that carries these signals is the ETW chapter's subject (Chapter 25).

> **Restricted Admin can enable lateral movement.** The same Restricted Admin flag that closes the disclosure-at-server gap [446] can also be paired with Pass-the-Hash from a compromised host so an actor who already holds reusable NTLM material authenticates to the target RDP server without knowing the plaintext password [261]. Restricted Admin is a *disclosure* mitigation, not a *replay* mitigation. Combine it with Remote Credential Guard (Windows 10 1607+) on tier 0 administrative paths.
>
> **Practitioner decision guide for a 2026 Windows estate inheriting a 2014 baseline.**
>
> 1. Apply KB2871997 everywhere it is relevant; on down-level Windows, explicitly set and verify `UseLogonCredential = 0`, and on modern Windows verify that no policy or legacy application has re-enabled WDigest plaintext storage.
> 2. Enable `RunAsPPL = 1` after a one-cycle LSA plug-in audit. Plan a rollback for any custom credential provider not yet re-signed at the PPL signer level [436].
> 3. Adopt the Pass-the-Hash v2 tiering model as planning vocabulary, then operationalise it as Microsoft's *Securing Privileged Access* / Enterprise Access Model documentation. Multi-year program; treat as a roadmap [620].
> 4. Use Restricted Admin for administrative RDP; promote to Remote Credential Guard on tier 0 paths.
> 5. Run AppLocker on every Enterprise SKU you have not yet migrated to WDAC [616]. Ensure the Application Identity service (`AppIDSvc`) is set to start automatically by policy, since AppLocker does not enforce when it is stopped.
> 6. Enable Secure Boot, Measured Boot, and BitLocker (TPM + PIN) on every laptop [27]. Microsoft's default platform validation profile on native UEFI + Secure Boot systems is PCR 7 (Secure Boot State) and PCR 11 (BitLocker access control), which is the *correct* profile to use when Secure Boot is on and the platform's option ROMs are trusted [193]. For hardened estates that want to detect tampering with the UEFI firmware itself, the option-ROM configuration, or the boot-manager binary independent of Secure Boot's signature check, expand the profile to PCRs 0, 2, 4, 7, 11: adding PCR 0 (UEFI firmware code), PCR 2 (option-ROM code), and PCR 4 (boot-manager binary measurements) on top of the default [105]. The hardened profile generates more BitLocker recovery-key prompts after legitimate firmware updates, so the operational cost is real and the choice between the two profiles is the standard balance between detection coverage and help-desk load.
> 7. Enable Credential Guard (Windows 10 1607+, and default-enabled on many Windows 11 22H2+ devices that meet requirements) wherever hardware, SKU, and application compatibility permit [621,664]. This is the architectural answer; everything above is harm reduction.

The 2009-2014 primitives are still here. So is Mimikatz. The Credential Guard chapter (Chapter 15) explains why, and what Microsoft did about it.

## Closing

Skeleton Key. Virtualization-Based Security. Credential Guard. The credential-protection arc opens on January 17, 2015, with the same Mimikatz codebase and a new technique, and the chain's first architectural answer is the next chapter.

> **Bequeaths.** This chapter hands the next links a precisely named, unsolved problem: *on a host where the adversary can reach administrator and load a driver, recoverable reusable credential material LSASS holds in VTL0 is readable, and controls inside that same privilege domain can add friction but not isolation.* The architectural answer (lift the secrets out of VTL0 into a Virtualization-Based Security trustlet) is the Credential Guard chapter (Chapter 15). The protocol-level corollary (that a stealable, replayable NT hash is an indefensible credential and must be retired) is the death-of-NTLM chapter (Chapter 16). What this chapter does **not** bequeath is any fix of its own: it ships no control, only the brief. The downstream replay primitives it names each inherit the same bearer-credential weakness: Kerberos ticket forging and the Golden Ticket (Kerberos, Chapter 17; KRBTGT, Chapter 18), the hash-to-PRT evolution of Pass-the-Hash into the cloud-join era (Pass-the-Hash to Pass-the-PRT, Chapter 19), and the token-impersonation and "Potato" abuse of `SeImpersonatePrivilege` (Windows Access Control, Chapter 22; SeImpersonate, Chapter 24), and carry it into their own domains.
