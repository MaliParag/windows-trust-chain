# Code Integrity

::: trust-ledger

- **Inherits:** VTL1 isolation. A hypervisor-managed secure world whose pages no VTL0 code can map, enforced by second-level address translation (Chapter 6, The Secure Kernel); and that chapter's Secure Kernel (`securekernel.exe`), the VTL1 ring-0 host that Secure Kernel Code Integrity runs under.
- **Promise:** On an HVCI-on machine the decision *which bytes may execute as kernel code* is made inside VTL1 and cannot be revoked from VTL0: no kernel page is ever simultaneously writable and executable, and the `g_CiOptions` policy variable an attacker once patched is held read-only by the Secure Kernel. Serviced boundary: VTL0→VTL1.
- **TCB:** The Hyper-V hypervisor, the Secure Kernel, and Secure Kernel Code Integrity (SKCI) in VTL1, plus the signed policy artifacts (`DriverSiPolicy.p7b`) and the boot/update path that decides which version of each runs. The NT kernel the attacker can own is explicitly outside it.
- **Adversary → Break:** Bring Your Own Vulnerable Driver. A signed, design-vulnerable driver loads cleanly (its Authenticode chain is real and it has no writable-and-executable page) then its IOCTL handler hands the attacker a kernel-write primitive. The Promise covers *who decides* and *code-page immutability*, never the *behavior* of code that is legitimately signed; whether a driver can be coerced into that primitive is undecidable (Rice's theorem).
- **Residual:** What a BYOVD driver *does* after it loads: token theft to SYSTEM → Windows Access Control (Chapter 22) and The SeImpersonate Primitive (Chapter 24); EDR-callback blinding and load-failure telemetry → ETW: The EDR Substrate (Chapter 25); generic application allow-listing and reputation → App Control for Business (Chapter 13); Authenticode and catalog-signing internals → Authenticode and Catalog Files (Chapter 12); the hypervisor and SLAT the policy rests on → Above Ring Zero (Chapter 9).
- **Bequeaths:** Kernel-page immutability (on an HVCI-on box the code that polices executable pages cannot itself be re-coded from VTL0) the floor Credential Guard (Chapter 15) stands on when it assumes the VTL0 kernel cannot be silently rewritten around `LsaIso.exe`. Does NOT provide: any opinion on a signed driver's *behavior*, coverage when HVCI is off, or a block list that names more than what someone has already found.
- **Proof:** 🟢 `deviceguard.txt`. Live lab VM, hash-gated at the point of claim: HVCI listed among the running VBS security services with system code integrity enforced. 🔵 documented for the SKCI, KDP, and block-list internals a VM cannot expose (Microsoft Learn, TrustedSec, Elastic Security Labs).
:::

## The driver that was signed and the page that cannot change

> **The Reasoner's question.** What does Windows Code Integrity prove about kernel code in 2026, and why does a signed vulnerable driver still remain outside that proof?

---

> **Foundations. What you need before this chapter.**
>
> - **Authenticode / catalog signing.** Microsoft's PKCS#7 code-signing format binds a file hash (directly, or via a catalog file covering a driver package) to a certificate chain. It proves publisher identity and file integrity, never program safety. The format itself is the subject of the Authenticode and Catalog Files chapter (Chapter 12); here it is only the input the kernel signature gate checks.
> - **WHQL / HLK.** The Windows Hardware Quality Labs program, now expressed through the Hardware Lab Kit, is a compatibility and distribution program. It can produce a Microsoft signature, but historically it did not make signing a hard load-time boundary.
> - **KMCS.** Kernel-Mode Code Signing is the Vista x64-era policy that refuses to load unsigned kernel-mode drivers. KMCS is a load-time identity gate: it says who signed the driver, not whether the IOCTL handler is safe.
> - **VTL0 / VTL1.** VTL0 is the normal Windows kernel and drivers; VTL1 is the Secure Kernel world VBS creates, whose memory VTL0 cannot map even with ring-0 code execution. Established in the Secure Kernel chapter (Chapter 6); this chapter uses VTL1 to host the code-integrity judge.
> - **HVCI / Memory Integrity.** Hypervisor-Enforced Code Integrity is the VBS consumer that moves the kernel code-integrity decision into VTL1 and asks the hypervisor to enforce the resulting page permissions.
> - **SKCI.** Secure Kernel Code Integrity is the VTL1 component that evaluates executable kernel mappings on HVCI systems. VTL0 can request a mapping; it cannot rewrite the judge.
> - **W^X.** Write xor execute: a page may be writable or executable, but not both. HVCI applies this invariant to kernel code pages, backed by second-level page-table permissions.
> - **KDP.** Kernel Data Protection lets the Secure Kernel protect selected VTL0 kernel data pages, such as the page containing `g_CiOptions`, by making VTL0 writes fault at the SLAT layer.
> - **BYOVD.** Bring Your Own Vulnerable Driver: the adversary brings a signed but design-vulnerable driver and uses its legitimate kernel execution path to get a write primitive, stop EDR, disable a protection, or load later unsigned code. The signature is real; the behavior is unsafe.
> - **DriverSiPolicy.p7b.** The Microsoft-signed App Control policy in `%windir%\System32\CodeIntegrity\` that denies known-vulnerable signed drivers by hash, file name, or signer. It is the point where Windows stops trusting a driver merely because it is signed.

---

> **Chapter thesis.** **Windows ships a list of Microsoft-signed drivers it refuses to load.** That list (`DriverSiPolicy.p7b`) exists because every previous generation of kernel-driver trust assumed a signed driver was a safe driver, and a twenty-year run of Bring-Your-Own-Vulnerable-Driver attacks (Capcom.sys, RTCore64.sys, gdrv.sys) proved that assumption wrong. The 2026 default-on stack (KMCS, the block list, HVCI in VTL1, App Control/Smart App Control policy, and Defender ASR coverage) is five overlapping gates doing what one ideal gate cannot do: name specific weaknesses, enforce page immutability, and narrow unknown risk. The architectural gap that motivates the stack is undecidable for unrestricted program semantics; practical subsets can be analyzed, but no static signing pipeline can be both complete and exact for arbitrary driver safety.

![Figure: Thirty years of kernel-driver trust, 1996–2026. Each generation proves a stronger identity claim, and the next Bring-Your-Own-Vulnerable-Driver incident retires the prior safety assumption: Authenticode advisory signing (Sony BMG's signed XCP rootkit, 2005) → Vista x64 KMCS + PatchGuard (Stuxnet's stolen Realtek/JMicron certs; `Capcom.sys` IOCTL → ring-0 exec) → Microsoft-only attestation / HLK signing (an EV-key compromise re-runs the Stuxnet trick) → HVCI / SKCI in VTL1 → the `DriverSiPolicy.p7b` block list → the signaled 2026 WHCP SBOM requirement. The constant across every generation: identity proven, safety not.](diagrams/06-code-integrity-trust-generations.svg)

## The driver that loaded

In late September 2016, Capcom shipped a kernel driver, `Capcom.sys`, to Street Fighter V's entire installed base as part of an anti-cheat update. Within a day, the researcher @TheWack0lian disclosed that the driver exposed IOCTL `0xAA013044` and used it to execute a user-supplied function pointer in kernel mode, with SMEP disabled along the way. The original blog URL is no longer reachable from its canonical location, so the technical artifacts here are anchored to later public PoCs: the IOCTL and SHA-1 in Tanda's standalone exploit [356], the Metasploit module history [357], and FuzzySecurity's contemporaneous Capcom rootkit walkthrough [358]. Within weeks the technique was operational in Metasploit, and in October 2016 Satoshi Tanda published the canonical standalone exploit on GitHub. Capcom withdrew the SFV driver shortly after, but the bytes were already in the wild.

> **Aside.** The often-told version of this story compresses three distinct events into one. @TheWack0lian's 23 September 2016 Twitter disclosure named the IOCTL number and the function-pointer-execution primitive. OJ Reeves opened the canonical Metasploit pull request, rapid7/metasploit-framework#7363 [357], shortly after; the PR was created on 27 September 2016 and merged the following day [357]. Satoshi Tanda's `tandasat/ExploitCapcom` repository was first published in October 2016 and is the canonical standalone PoC, and the artifact this chapter cites for the IOCTL number and SHA-1 hash.

The driver was properly Authenticode-signed. It chained to a Microsoft-recognized root. On the broad population of default-configured Windows 7, 8.1, and pre-block-list Windows 10 machines that accepted that signing path, it loaded cleanly; later revocation, HVCI, WDAC/App Control policy, S mode, and the vulnerable-driver block list changed that answer on machines where those controls apply.

That is the puzzle this chapter exists to answer. How does an operating system whose entire kernel-loading policy is *was this binary signed?* answer a vulnerability whose only failure mode is *yes, by a real publisher, doing exactly what the signature says it does*?

### A class, not an incident

Capcom.sys was not the first signed kernel driver with a primitive IOCTL, and it would not be the last. The pattern recurs across two decades and is the through-line of this chapter. The catalog includes Micro-Star's `RTCore64.sys` (the kernel component of MSI Afterburner), Gigabyte's `gdrv.sys`, and the `KProcessHacker` driver shipped with Process Hacker; the BYOVD section walks through each one with its primary disclosure record.

The attack class has a name. *Bring Your Own Vulnerable Driver*, or BYOVD. The adversary does not need to find a kernel zero-day. They need to find one signed driver, anywhere, whose interface is unsafe by design, and to ship it.

> **Key idea.**
> Windows in 2026 ships a curated list of Microsoft-signed drivers it refuses to load. Understanding that list is understanding why every previous attempt to make kernel-mode trust mean *safety* instead of just *identity* eventually broke.

The current Windows 11 22H2 client honors `%windir%\system32\CodeIntegrity\DriverSiPolicy.p7b`, a Microsoft-signed deny list enforced as a Code Integrity/App Control policy. On HVCI-on systems, the code-integrity decision is made from a hypervisor-isolated VTL1 context; on supported client builds the vulnerable-driver block list can also be enforced through the Code Integrity/App Control stack without HVCI being the precondition. HVCI adds the separate guarantee that the engine refuses writable-and-executable kernel mappings and that VTL0 cannot rewrite the judge. These behaviors are documented on Microsoft Learn's Memory Integrity page [279] and the Microsoft-recommended driver block rules page [271]. Neither existed in 2006.

To understand why Windows now refuses to load drivers it once asked Microsoft to sign, we need to go back thirty years to the moment Windows first asked a publisher to sign anything at all.

## Advisory trust: 1996 to 2005

For its first decade, the Windows driver signing policy was a polite recommendation.

Microsoft shipped its first user-mode code-signing primitive, Authenticode, in 1996, packaged for developers in the same tool kit that gave us `SignTool`, `MakeCat`, and `Inf2Cat`: the suite Microsoft Learn still documents under "Cryptography tools" [359]. Authenticode wrapped a PKCS#7 signature around the SHA-1 (and later SHA-256) hash of a PE image and let a recipient walk the signer's certificate chain to a trusted root. It was the first answer to the question *who shipped this binary?* It was, deliberately, never an answer to *is this binary safe?*

> **Definition: Authenticode.** Microsoft's PKCS#7-based code-signing format for Windows binaries. Authenticode attests to the publisher's identity by binding the binary's hash to a certificate chain anchored at a trusted root. It does not analyze the program's behavior.

For drivers, the user-mode signing primitive was paired with a separate quality program. The Windows Hardware Quality Labs program, documented today via the Hardware Lab Kit [360], tested third-party drivers against a Microsoft-curated compatibility suite and rewarded passing drivers with a counter-signature, eventually surfaced as the "Designed for Windows" or "Certified for Windows" mark [360]. The badge was operationally meaningful for OEM badging and Windows Update distribution. It was not a load-time gate. An unsigned `.sys` file dropped on disk by a setup script still loaded.

> **Definition: WHQL / HLK (Windows Hardware Quality Labs / Hardware Lab Kit).** Microsoft's compatibility-test program for third-party drivers. A driver that passes the HLK test suite receives a Microsoft counter-signature and is eligible for OEM and Windows Update distribution. The program produces a quality signal, not a load-time enforcement decision.

### The SetupAPI prompt

On 32-bit Windows, the gate the user actually saw was the SetupAPI driver-installation prompt. The administrator could set the system to *Ignore*, *Warn*, or *Block* unsigned drivers; the default was *Warn*. *Warn* meant a click-through dialog at install time. An administrator who clicked *Install this driver anyway* loaded the unsigned driver, no further questions asked. The structural truth is the one Microsoft's modern KMCS policy page [267] acknowledges by contrast: under advisory policy, the prompt is the policy, and a prompt is exactly as strong as the user clicking past it [267].

The Sony BMG XCP incident in October 2005 made the structural weakness concrete. The XCP copy-protection software, shipped on retail audio CDs, autorun-installed an unsigned kernel-mode filter driver. The driver hid any file, registry key, or process whose name began with the string `$sys$`: a textbook rootkit by capability if not by intent. The driver loaded after an administrator clicked through the warning prompt, exactly as advisory policy allowed. The pattern is described well in Wikipedia's code-signing article [361].

> **Aside.** The Sony BMG XCP rootkit triggered class-action lawsuits, FTC settlements, and an industry-wide reconsideration of what "the user clicked OK" actually authorizes. From a kernel-trust perspective, the lesson is narrower: any policy that ends in a dismissible dialog has the same threat model as no policy at all, against an attacker who can show the user a dialog.

The structural takeaway from 1996 through 2005 is the one the next decade tried to repair. When the signing policy is advisory, an attacker who has (or can socially engineer) administrator privilege only needs to dismiss a prompt to load a kernel driver. The signing primitive worked. The policy around the primitive did not.

If the prompt is the only thing between an attacker and ring zero, the kernel itself has to take over. And on a brand-new x64 architecture, Microsoft could break backward compatibility to make that happen.

## KMCS: The Vista x64 revolution (2006-2016)

In November 2006, Vista x64 made a decision that x86 never could: in production/default enforcement mode, it refused to load unsigned kernel drivers.

The mechanism was Kernel-Mode Code Signing, or KMCS. The previous-versions Microsoft Learn page on Vista-era driver signing [362] records the policy [362]. At the point where the kernel loaded a driver image (the `IopLoadDriver` → `MmLoadSystemImage` path), the Code Integrity module (`ci.dll`) intercepted the load, extracted the Authenticode signature embedded in the PE image or attached via a published catalog, walked the certificate chain, and refused to map the image if the chain did not terminate at a Microsoft-trusted root. There was no SetupAPI prompt to dismiss. If the kernel refused, the kernel refused. The decision lived below the user's reach.

> **Definition: KMCS (Kernel-Mode Code Signing).** The Vista-era mandatory load-time signature policy on 64-bit Windows. Before mapping a kernel driver's PE image, the Code Integrity module verifies that the image's Authenticode signature chains to a Microsoft-trusted root. Drivers that fail the check are refused at load time, not at install time.

x86 kept the advisory policy. Microsoft could not break compatibility with two decades of unsigned drivers on the dominant platform. But x64 was a young architecture with a few hundred drivers in the field, and Microsoft used that moment to flip the default. The structural shift was real: kernel-driver trust on x64 became a property of the binary, decided in the kernel, against a fixed set of trusted roots.

### Cross-certificates: opening the gate to the world

A Microsoft-trusted root alone would have meant Microsoft signs every driver, which Microsoft did not want. Instead Microsoft cross-certified a small set of commercial code-signing certificate authorities, including VeriSign, DigiCert, Entrust, GlobalSign, GoDaddy, and several smaller successors enumerated on the historical cross-certificate list (2020 archive) [363], so that a publisher could buy a code-signing certificate from a commercial CA, sign their driver, and have the chain still terminate at a Microsoft-recognized root [363]. The architecture is documented on the cross-certificates for kernel-mode code signing page [364], which now opens with a sentence that did not exist in 2006: "Cross-signing is no longer accepted for driver signing" [364]. We will come back to that.

> **Walkthrough: Vista-era KMCS driver-load decision.**
>
> 1. A service entry or PnP install path asks the I/O manager to create an image section for a kernel driver.
> 2. Code Integrity (`ci.dll`) hashes the PE image exactly as Authenticode defines it, excluding mutable certificate-table bytes, and locates either the embedded signature or a catalog entry whose member hash covers the image.
> 3. The PKCS#7 signature is verified against the publisher's end-entity code-signing certificate; the certificate chain is then walked through the Microsoft kernel-mode cross-certificate to a Microsoft-recognized root.
> 4. If the chain is invalid, missing, revoked, or rooted outside the accepted kernel-mode trust set, the load fails with the familiar invalid-image-hash path before the driver gets code execution.
> 5. If the chain is valid, the section is mapped and the driver enters the normal loader path. No behavior analysis has occurred. The driver has proven identity and integrity, not safety.

### Documented escape hatches

KMCS shipped with three documented bypasses for developers and special cases, all enumerated on the KMCS policy page [267]:

- `bcdedit /set TESTSIGNING ON` enables test-signing mode. The kernel will load drivers signed with self-issued test certificates. The cost is a desktop watermark.
- The F8 advanced-boot option *Disable Driver Signature Enforcement* turns off KMCS for one boot.
- The legacy `nointegritychecks` BCD flag disables enforcement entirely, but is rejected on systems where Secure Boot is on.

Each of these was a development workflow concession. Each of them, with admin privileges and a willingness to reboot, also serves as a kernel-driver loading path for an attacker who has already escalated. The policy holds against unprivileged adversaries. Against an attacker who already runs as administrator, the policy was already, by 2010, defending against a different threat than the one people thought it was defending against.

> **Aside.** Microsoft's servicing criteria make the boundary distinction precise: user-to-kernel is a Windows security boundary, but administrator-to-kernel on the same installation is not treated as a general servicing boundary [301]. Elastic Security Labs applies that distinction to vulnerable-driver mitigations [365]. The historical irony is that Vista x64 KMCS was widely read at the time as a defense against admin-level adversaries; it was actually a defense against unprivileged or pre-admin ones.

### PatchGuard: the parallel runtime defense

KMCS was a load-time check. The runtime parallel arrived in 2005 with Kernel Patch Protection, informally PatchGuard or KPP. Microsoft's 2007 advisory describes KPP on x64 Windows as protecting kernel code and critical structures from modification by unknown code or data [366]; public reverse-engineering summaries add the familiar list of watched objects: the System Service Descriptor Table, IDT, GDT, and selected function prologues [367]. It is the watchdog against runtime modification of the kernel by code that has already loaded; KMCS gates what loads in the first place.

What this fixed: the unsigned-driver-loading path closed on 64-bit Windows in production mode. Kernel rootkits of the early 2000s (FU, Mailbot, Rustock, and their contemporaries, widely documented in the security-research literature of the era) could no longer ship as bare `.sys` files an admin script dropped on disk. The structural class of "unsigned kernel rootkit" effectively died on x64.

But the day Vista x64 shipped, two new attack surfaces opened up. The first one Stuxnet found four years later. The second one nobody had a name for yet.

## Stuxnet, BYOVD, and the two things Vista did not fix

On 17 June 2010, researchers in VirusBlokAda in Belarus identified Stuxnet, a worm targeting supervisory control and data acquisition systems [368] used in industrial-control environments [368]. Two of its drivers carried perfectly valid Authenticode signatures.

The signatures were genuine. The certificates were not. Stuxnet had been signed with private keys stolen from semiconductor vendors whose code-signing certs chained to legitimate cross-certified roots. KMCS verified the chain, found it good, and let the drivers load.

> **Aside.** The cert-holder names are not folklore. Symantec's *W32.Stuxnet Dossier* identifies legitimate certificates belonging to Realtek and JMicron, and Microsoft's 2010 response posts described the signed-driver trust-chain problem while revoking the affected certificates [368] [369]. The Wikipedia Stuxnet and code-signing entries remain useful broad summaries [368] [361], but the technical point rests on the primary incident record: valid code-signing material, stolen from real vendors, caused KMCS to accept malicious drivers until revocation caught up.

The reactive answer was certificate revocation, but revocation propagates through Windows on a schedule, not instantly, and the cached chain on millions of machines remained valid for days.

That was the first failure mode KMCS could not block by design. The signature primitive answers *was this signed by a key that chains to a trusted root?* It cannot answer *was the key still in the publisher's control when it signed this?*

### The Capcom.sys reframe

The second failure mode arrived publicly in 2016. A Capcom driver shipped via a Street Fighter V update exposed an IOCTL, numbered `0xAA013044`, that took a user-supplied function pointer and executed it in kernel mode: with Supervisor Mode Execution Prevention (SMEP) disabled while it did so. The driver was signed and chained correctly. Satoshi Tanda's standalone proof of concept at `tandasat/ExploitCapcom` [356] remains the canonical reference, including the SHA-1 of the binary (`c1d5cf8c43e7679b782630e93f5e6420ca1749a7`) [356].

There was nothing for KMCS to catch. The driver did exactly what the signature said it did: ship bytes from a publisher Microsoft could identify. The signature has no opinion about the IOCTL surface.

> **Pull quote.**
> A signed driver means only that someone Microsoft can identify shipped this binary. It does not mean the driver lacks a function-pointer IOCTL.

That observation is the first of three reframes in this chapter and the easiest to underestimate. Up to 2010 the conventional security reading of a Microsoft-rooted Authenticode signature was that the driver had passed a review. After Stuxnet, the reading narrowed to *the publisher is identifiable*. After Capcom.sys, it narrowed again to *the binary's identity is verifiable*. None of these readings includes *the binary does not have a kernel-write primitive in its IOCTL handler*.

> **Definition: BYOVD (Bring Your Own Vulnerable Driver).** An attack pattern in which an adversary, having obtained or already holding administrator privileges, installs a signed but design-vulnerable third-party kernel driver and uses its exposed primitives (arbitrary memory read/write, port I/O, MSR access, or function-pointer dispatch) to gain ring-zero capability. The signature primitive does not refuse the load because the driver is, on signature alone, legitimate.

### The catalog grows

The BYOVD catalog accumulated through the 2010s.

`RTCore64.sys`, the kernel component of MSI's Afterburner overclocking utility, exposed read/write access to arbitrary kernel memory, I/O ports, and Model-Specific Registers from user mode. The NVD entry for CVE-2019-16098 [370] is unusually direct: "These signed drivers can also be used to bypass the Microsoft driver-signing policy to deploy malicious code." [370] The driver became a workhorse for ransomware crews. Sophos's October 2022 incident analysis of BlackByte's new variant [371] documents the abuse: BlackByte "abus[ed] a known vulnerability in the legitimate vulnerable driver RTCore64.sys" to disable "a whopping list of over 1,000 drivers on which security products rely to provide protection" [371].

`gdrv.sys`, the Gigabyte APP Center driver, exposed a ring-zero memcpy-equivalent that a local attacker could use to overwrite arbitrary kernel addresses. CVE-2018-19320 [372] is on CISA's Known Exploited Vulnerabilities catalog [373]. The RobbinHood ransomware family turned the primitive into the template modern BYOVD crews still copy: install the legitimate signed Gigabyte driver, use it to disable driver-signature enforcement or tamper with security tooling, then load the attacker's own kernel component to blind endpoint defenses before encryption. Sophos's technical coverage of the RobbinHood/gdrv chain and later BlackByte/RTCore64 chain documents the operational pattern rather than merely the CVE label [374] [371].

`KProcessHacker`, the kernel companion to the Process Hacker administration tool, exposed a process-termination primitive that bypassed even the Protected Process Light (PPL) shielding around antivirus and EDR processes: the PPL mechanism the Protected Process Light chapter (Chapter 10) owns in full. CrowdStrike's DoppelPaymer write-up [375] documents the abuse explicitly: "the hijacking technique... leverages ProcessHacker's kernel driver, KProcessHacker, that has been registered under the service name KProcessHacker3... terminate processes, including those protected by Protected Process Light (PPL)." [375]

> **Walkthrough: structural BYOVD attack flow.**
>
> 1. The adversary arrives with administrator rights, drops a signed vulnerable driver such as `Capcom.sys`, `RTCore64.sys`, `gdrv.sys`, or `KProcessHacker`, and creates a kernel-service entry with the Service Control Manager.
> 2. KMCS verifies the Authenticode chain and allows the load because the bytes are signed and the publisher identity is real.
> 3. User-mode malware opens the driver's device object and sends IOCTLs that the driver author intended for diagnostics, overclocking, anti-cheat, or process-management tasks.
> 4. The vulnerable IOCTL handler copies attacker-controlled data to an attacker-chosen kernel address, reads privileged kernel memory back to user mode, disables SMEP for a callback, or terminates PPL-protected security processes.
> 5. The post-load payload uses that primitive for one of three recurring outcomes: patch Code Integrity state and load unsigned code, overwrite an `_EPROCESS` token to become SYSTEM, or clear EDR callback registrations so the ransomware or implant can run quietly.

### The third bypass: patching the policy from kernel mode

There is a third failure mode that closes the loop. Once an attacker has a signed driver with an arbitrary kernel-write primitive, they can write directly into the in-kernel Code Integrity state. The variable of interest is `g_CiOptions`, an integer inside `ci.dll` whose bits gate Driver Signature Enforcement. TrustedSec describes the technique cleanly: "this configuration variable has a number of flags that can be set, but typically for bypassing DSE this value is set to 0, completely disabled DSE and allows the attacker to load unsigned drivers just fine." [376] Set `g_CiOptions` to zero and the subsequent driver loads do not need signatures at all. The signed driver, in effect, is a one-shot key that opens the gate for any unsigned driver behind it. The pattern recurs through the early 2020s; specific malware-family attributions remain research-folklore, but the technique class is well attested in TrustedSec's account.

The structural takeaway: KMCS verifies *who signed*, never *what was signed*. Once an attacker has a signed driver with a write primitive, they have ring zero. Stricter signing closes the front door for new malicious drivers. Many legacy commercial-CA-signed drivers remain loadable on machines matching the documented grandfathering conditions (upgraded installs, Secure Boot off, or pre-cutoff end-entity certificates whose chains still validate) unless revocation, timestamp policy, WDAC/App Control deny rules, S mode, HVCI-associated policy, or the vulnerable-driver block list says otherwise. The policy decision also has to move out of the attacker's reach. And the kernel itself has to stop being the thing that decides.

## Microsoft as the only signer (2016-2024)

In August 2016, Microsoft did something the WHQL program had refused to do for twenty years: it became the only entity that could counter-sign a new Windows kernel driver.

The transition shipped with Windows 10 version 1607. The KMCS policy page [267] records the cut precisely: for end-entity certificates issued after 29 July 2015, the chain had to terminate at one of three Microsoft-owned roots (*Microsoft Root Certificate Authority 2010*, *Microsoft Root Certificate Authority*, or *Microsoft Root Authority*) and the binary had to be counter-signed via the Windows Hardware Dev Center submission portal [267]. The commercial CAs were out. Microsoft was in, as the single point through which any new third-party kernel driver had to pass.

### Two pipelines

Behind the portal sat two submission paths. The HLK/WHQL path required a full Hardware Lab Kit compatibility test pass on the publisher's hardware: the lab kit is the modern incarnation of the WHQL program, documented on Microsoft Learn [360]. A passing run produced a "Certified for Windows" mark and made the driver eligible for OEM badging and Windows Update distribution. The lighter-friction path, called attestation signing [377], did not require an HLK run [377]. The publisher submitted a CAB containing the driver and supporting metadata. Microsoft's backend ran a malware scan and an automated policy check; if both passed, Microsoft applied a counter-signature. Attestation-signed drivers, the page notes, ship only to client SKUs.

> **Definition: Attestation signing.** The lower-friction post-2016 Microsoft signing path for Windows kernel drivers. The publisher uploads a CAB to the Hardware Dev Center; Microsoft runs malware scanning and an automated policy check; on pass, Microsoft applies its counter-signature. The path replaces full HLK testing for client-only drivers.

### EV certificates as the account-binding primitive

Both paths required the publisher to hold an Extended Validation code-signing certificate. The EV cert does not sign the driver image itself; it signs and binds the Hardware Dev Center submission. That gives Microsoft a real-name handle on every kernel-driver publisher. EV certificates ride a strong identity check, cost meaningfully more than commercial OV certs, and live on a hardware token in the publisher's possession. The 2021 Microsoft Security blog announcing the Vulnerable & Malicious Driver Reporting Center spells the requirement out: "Kernel-mode driver publishers must pass the Hardware Lab Kit (HLK) compatibility tests, malware scanning, and prove their identity through extended validation (EV) certificates." [378]

> **Walkthrough: post-1607 Hardware Dev Center signing.**
>
> 1. The publisher obtains an EV code-signing certificate and uses it to authenticate the Hardware Dev Center account and submission package; the EV key is the identity anchor, not the final kernel-load signature.
> 2. The publisher uploads a CAB containing the driver package, INF, catalog, and metadata.
> 3. For the HLK path, Microsoft receives the compatibility-test evidence and verifies that the driver passed the Hardware Lab Kit suite on the declared hardware. For attestation, Microsoft runs the lighter automated policy and malware checks instead.
> 4. If the submission passes the selected path, Microsoft applies the counter-signature that post-1607 Windows requires for new kernel drivers on Secure-Boot-era systems.
> 5. Only after that counter-signature exists can the driver travel through Windows Update or an OEM channel as a normal production kernel driver. The pipeline improves publisher accountability and centralizes revocation; it still cannot prove the IOCTL surface is semantically safe.

### The legacy long tail

The pivot to Microsoft-only signing closed the door for new drivers. It did not close the door for old ones.

> **Aside: The legacy long tail.**
> The KMCS policy page [267] is candid about the carve-outs: "Cross-signed drivers are still permitted if any of the following are true: The PC was upgraded from an earlier release of Windows to Windows 10, version 1607. Secure Boot is off in the BIOS. Drivers was signed with an end-entity certificate issued prior to July 29th 2015 that chains to a supported cross-signed CA." [267]
>
> Operationally, many signed-but-vulnerable drivers from the 2006-2015 era remain loadable on a meaningful population of Windows machines: upgraded installs, devices with Secure Boot disabled in firmware, and drivers with pre-cutoff end-entity certs whose chains are still valid, unless a revocation, timestamp rule, WDAC/App Control deny rule, S mode, HVCI-associated policy, or the vulnerable-driver block list blocks the artifact. `Capcom.sys`, `RTCore64.sys`, `gdrv.sys`, and `KProcessHacker` explain why the carve-outs matter, not why every old binary loads everywhere.

### What attestation signing catches and what it does not

The malware scan inside attestation signing looks for known dangerous behavior. The Microsoft Security blog post on the Vulnerable & Malicious Driver Reporting Center enumerates the categories the backend flags: "Drivers with the ability to read or write arbitrary kernel, physical, or device memory, including Port I/O and central processing unit (CPU) registers from user mode." [378] In other words, the scanner already understands the BYOVD pattern.

What it does not catch are *novel* design flaws. A driver whose IOCTL surface is structurally unsafe in a way the scanner does not have a signature for passes the scan and ships with a Microsoft counter-signature. The Capcom.sys pattern is in the scanner's repertoire today; the pattern in the next driver to ship is, by definition, not.

A second weakness sits on the publisher side. EV-key compromise (whether through the LAPSUS$ supply-chain leaks of 2022 or other vendor incidents) is the Microsoft-only-signing flavor of the Stuxnet problem, but it is not a one-step bypass. Hardware Dev Center account controls, malware scanning, policy checks, and submission review still stand between a stolen publisher credential and a Microsoft-signed driver [378] [379]. The chain is stronger than raw commercial cross-signing, but it still depends on publisher identity and account security.

One bottleneck for signing is an improvement. But the bottleneck still trusts the kernel that asks the question. As long as the policy engine runs in the same memory the attacker can write, the policy engine loses.

## HVCI: Moving the policy out of reach (2015-present)

In July 2015, Microsoft shipped a feature so structurally important that it took six years to become a consumer default, and so misunderstood that it still travels under three different names.

The names are the easiest place to start. *Virtualization-Based Security* (VBS) is the platform: a Hyper-V-rooted virtualization layer that exists on every modern Windows installation that meets the hardware requirements. *Hypervisor-Enforced Code Integrity* (HVCI) is the kernel-code-integrity consumer of VBS. *Memory Integrity* is the label the Windows Security UI uses today. The Microsoft Learn page on Memory Integrity [279] is the canonical primary source [279]. TrustedSec called out the conflation explicitly in their `g_CiOptions in a virtualized world` post [376].

> **Key idea.**
> A security check that shares a trust domain with what it is checking has, by definition, already lost. HVCI moves the check out of the attacker's trust domain. It is the answer to *who decides*. It is not the answer to *what gets decided*.

That sentence is the second of this chapter's three reframes, and the one that makes everything that follows make sense.

### VBS and the Virtual Trust Levels

On a VBS-on Windows machine, Hyper-V is the Type-1 hypervisor: the layer the Above Ring Zero chapter (Chapter 9) dissects. The bootloader brings the hypervisor up first, the hypervisor brings up two execution environments side by side, and the normal Windows kernel runs in one of them while a much smaller Secure Kernel runs in the other.

> **Recap: VTL (Virtual Trust Level).** The Secure Kernel chapter (Chapter 6) established the split: VTL0 is the normal Windows kernel and its drivers; VTL1 is a much smaller Secure Kernel that VTL0 cannot read or write, because Hyper-V's second-level address translation gives VTL0 no mapping for VTL1 pages. The one fact this chapter spends: code-integrity policy lives in VTL1, where a compromised VTL0 cannot reach it.

The Code Integrity engine on an HVCI-on machine (signature verification and policy-file consultation) runs inside VTL1's Secure Kernel as the *Secure Kernel Code Integrity* component, SKCI. The VTL0 kernel cannot read or write VTL1 memory by hardware construction: the hypervisor's second-level address translation tables, programmed before VTL0 ever runs, mark VTL1 pages as unreachable from VTL0. The in-memory `g_CiOptions` state continues to reside in `ci.dll`'s VTL0 data section (it does not relocate into VTL1) but on an HVCI-on machine Kernel Data Protection (KDP), exposed to VTL0 drivers as `MmProtectDriverSection`, asks the Secure Kernel to mark the containing page read-only at the SLAT level. A fully compromised VTL0 kernel (with kernel debugging attached, with all of ring zero's privileges) cannot rewrite `g_CiOptions` to zero, because the SLAT mapping refuses the write.

![Figure: The trust-domain split under HVCI. VTL0, the normal world, holds the NT kernel, its drivers, and `ci.dll` with the `g_CiOptions` policy page; the smaller VTL1, the secure world, holds the Secure Kernel and SKCI, the code-integrity judge that verifies signatures at section-create time and enforces W^X. Beneath both sits the hypervisor's SLAT, which enforces two invariants: VTL1 pages carry no VTL0 mapping, and KDP marks the VTL0 `g_CiOptions` page read-only at the SLAT level. The one legitimate crossing is the mediated section-create secure call.](diagrams/06-code-integrity-hvci-vtl-split.svg)

> **Walkthrough: the VBS/VTL split.**
>
> 1. Firmware, Secure Boot, and the Windows loader establish Hyper-V before the ordinary NT kernel runs. The hypervisor owns the second-level address-translation tables.
> 2. The normal NT kernel, device drivers, and `ci.dll` run in VTL0. The Secure Kernel and Secure Kernel Code Integrity (SKCI) run in VTL1.
> 3. VTL1 pages are not merely hidden by convention; VTL0 translations do not map them with writable access. A compromised VTL0 kernel can ask for service, but it cannot directly patch the Secure Kernel or SKCI policy memory.
> 4. When VTL0 requests an executable kernel section, the hypervisor mediates the transition and SKCI evaluates the signature and Code Integrity policy before executable permission is granted.
> 5. Kernel Data Protection extends the same authority back onto selected VTL0 pages: `g_CiOptions` can remain physically in `ci.dll` while the Secure Kernel marks its containing page read-only through SLAT, so a VTL0 arbitrary write no longer reaches the policy bit it used to patch.

### W^X on kernel memory

There is a second, equally structural property HVCI enforces. When the VTL0 kernel tries to map an executable section (to create a kernel-executable page from a PE image), the hypervisor forces the request through SKCI. SKCI verifies the Authenticode signature *at section creation time*, not only at the driver-load entry point (`IopLoadDriver` / `MmLoadSystemImage`) a load goes through later [279]. And SKCI refuses any page that is simultaneously writable and executable. The classic exploitation technique of allocating a writable kernel buffer, writing shellcode into it, and then jumping to it stops working: the page either is writable, in which case it is not executable, or is executable, in which case it is not writable.

The hardware acceleration matters. The Memory Integrity page [279] is unusually direct about the requirement: "Memory integrity works better with Intel Kabylake and higher processors with Mode-Based Execution Control, and AMD Zen 2 and higher processors with Guest Mode Execute Trap capabilities. Older processors rely on an emulation of these features, called Restricted User Mode, and will have a bigger impact on performance." [279]

> **Aside.** Mode-Based Execute Control (MBEC) is the Intel feature that lets the hypervisor distinguish "executable in supervisor mode" from "executable in user mode" at the page-table-entry level. AMD's Guest Mode Execute Trap (GMET) is the structurally equivalent feature. Older silicon falls back to Restricted User Mode emulation, which works correctly but pays a meaningfully larger performance tax. The hardware cutoff is a major reason HVCI defaulted off on pre-2017 OEM hardware for years.

### What HVCI fixed

The `g_CiOptions` patching family, the third bypass we met in the BYOVD section, closes on HVCI-on systems. TrustedSec's post [376] gives a clean account: `g_CiOptions` still lives in `ci.dll`'s VTL0 data section, but Kernel Data Protection (exposed to VTL0 drivers as `MmProtectDriverSection`) asks the Secure Kernel in VTL1 to mark its containing page read-only at the SLAT level, so a VTL0 ring-zero write to it faults; the VTL0 kernel cannot rewrite the variable; live-kernel debuggers attached to VTL0 cannot rewrite it either [376]. The arbitrary-write-to-disable-DSE pattern that worked on Windows 7 through pre-HVCI Windows 10 is, on an HVCI-on Windows 11, no longer a primitive that exists in the attacker's threat model. The trust domain that decides the policy is not the trust domain the attacker can reach.

### What HVCI did not fix

It is essential to be clear about what HVCI does not catch, because misreading this is how the BYOVD class survives.

HVCI verifies the *signature* and enforces W^X. It does not analyze the driver's *behavior*. Absent a matching vulnerable-driver block-list entry or enterprise WDAC/App Control deny rule, a 2019 `RTCore64.sys` variant can pass HVCI/SKCI section-mapping unchanged: it is signed by MSI through a Microsoft-recognized chain, it has no writable-and-executable pages, and the Authenticode hash on disk matches the binary in memory. After it loads, an attacker in user mode sends an IOCTL; the driver, executing legitimately in ring zero, writes attacker-controlled bytes to an attacker-chosen kernel address; the EDR notify routine table is patched; the BYOVD attack proceeds. Everything that happens inside the IOCTL handler happens with kernel privilege, on properly-signed code paths, inside HVCI's W^X policy. The structural BYOVD class is unaffected.

That is the gap the next two sections close.

> **HVCI is not free, and not universal.**
> The Memory Integrity page [279] is explicit that "some applications and hardware device drivers may be incompatible with memory integrity. This incompatibility can cause devices or software to malfunction and in rare cases may result in a boot failure (blue screen)." [279] For years OEM and gaming-system vendors shipped with HVCI off because legacy ISV drivers, anti-cheat kernel components, or older virtualization tools could not coexist with it. On an HVCI-off system the `g_CiOptions` patching family is back in play, the kernel-CI engine and the kernel it polices are in the same trust domain, and the analysis of the BYOVD section applies unchanged. The 2026 default-on baseline is real, but it is not yet universal.

HVCI hardens the trust domain where the decision is made and enforces W^X. The remaining question is policy content: this specific signed binary is one we do not trust.

## The block list: Naming the weakness (2018-present)

Beginning with Windows 10 1809 (October 2018), Microsoft started shipping something it had spent twenty-five years avoiding: a list of specific drivers it would refuse to load by name.

The artifact lives at `%windir%\system32\CodeIntegrity\DriverSiPolicy.p7b`. The file is a PKCS#7-signed App Control for Business policy ("WDAC" by its former name) whose body consists of deny rules expressed at the granularity of file hash, file name, or publisher. The canonical Microsoft-recommended driver block rules page [271] is the primary source, and is unusually rich for a Microsoft Learn page [271].

> **Definition: App Control for Business (WDAC).** Microsoft's policy-driven application-control engine: the subject of the App Control for Business chapter (Chapter 13). An App Control policy is a signed XML or binary file that lists allow rules, deny rules, and signer-level rules; at load time, the policy engine consults the rules and either allows or refuses the image. What concerns *this* chapter is one specific instance: `DriverSiPolicy.p7b` is itself an App Control policy whose body is all deny rules.

The mechanics matter because `DriverSiPolicy.p7b` is often misdescribed as a certificate revocation list. It is not. A CRL says that a certificate should no longer be trusted; it works at issuer and serial-number granularity. The vulnerable-driver block list is a Code Integrity policy. Microsoft publishes it as source XML on the recommended-block-rules page and ships it to clients as a signed binary policy wrapped in the `.p7b` container [271]. The XML-level concepts are visible even when the exact compiled binary layout is deliberately not a stable public ABI: file rules identify individual artifacts by hash or name; signer rules identify certificate or publisher scopes; policy options define enforcement rather than audit; and the compiler turns those rules into the binary form the kernel Code Integrity engine consumes [380].

For a driver load, that means the decision tree has three independent identities available. First is the content identity: the file hash says "these exact bytes." Second is the package identity: the catalog member hash binds a `.sys` file to the `.cat` file that Authenticode signed. Third is the publisher identity: the certificate chain says who signed the package. `DriverSiPolicy.p7b` can deny at any of those levels. Hash denial is precise and low-compatibility-risk but misses a repacked vulnerable driver. Name denial catches the common commodity case but can overmatch benign files with the same leaf name. Signer denial is broad and powerful but risks collateral damage when a publisher has both vulnerable and non-vulnerable products. The shipped policy is therefore not a simple list of "bad vendors"; it is a compatibility-managed collection of rule types chosen for the narrowest safe blast radius.

The enforcement path is also different from normal application allowlisting. An enterprise WDAC policy often begins with "block everything except these publishers, paths, or hashes." The in-box vulnerable-driver policy is the inverse: normal Windows driver signing remains the allow baseline, and `DriverSiPolicy.p7b` overlays known-bad deny rules on top. Deny rules win because the point is to let the long tail of legitimate drivers keep working while refusing specific artifacts that research, incidents, or Microsoft's reporting center have shown to be unsafe. That is why the published-vs-shipped gap exists: the more general a deny rule is, the more likely it is to break a legitimate fleet.

### Cadence and the published-vs-shipped gap

The block list is refreshed on two cadences. Microsoft publishes the source XML on the block-rules page [271] on a quarterly schedule and pushes the binary `DriverSiPolicy.p7b` to client devices through monthly Windows servicing [271]. Microsoft's Security Baselines team also publishes a running update post [381] cataloging the changes [381].

The candid admission on the block-rules page [271] is the part of the story that is most worth understanding.

> **Pull quote.**
> The blocklist included in this article and in the associated downloadable files usually contains a more complete set of known vulnerable drivers than the version in the OS and delivered by Windows Update. It's often necessary for us to hold back some blocks to avoid breaking existing functionality.: Microsoft Learn, *Microsoft-recommended driver block rules* [271]

The published list is, on purpose, more inclusive than the shipped list. The reason is operational: every entry in the shipped list is a driver that would refuse to load on millions of devices, some of which have legitimate dependencies. Microsoft holds entries back when the compatibility cost is too high, even when the security signal is strong. We will come back to whether that gap is closeable in the undecidability analysis.

### The 22H2 cut and the Server 2016 carve-out

Two dates anchor the deployment story.

The block list was an *optional* feature in Windows 10 1809, enabled by default only on systems that ran Hypervisor-Enforced Code Integrity or Windows in S-mode [382]. With the Windows 11 2022 Update, also known as 22H2 [383], released on 20 September 2022, default-on coverage broadened across client devices rather than only the HVCI-on subset [383]. The 22H2 release is the moment the block list became baseline Windows client behavior, subject to policy state and documented carve-outs, six years after the first BYOVD primitive that motivated it.

The block-rules page [271] notes a single explicit carve-out worth flagging.

> **Aside.** "Except on Windows Server 2016, the vulnerable driver blocklist is also enforced when either memory integrity (also known as hypervisor-protected code integrity or HVCI), Smart App Control, or S mode is active." [271] Windows Server 2016 does not get the default-on block list even when HVCI is on. An enterprise admin managing Server 2016 has to deploy an explicit App Control policy to get the same coverage.

The October 2022 preview cycle saw a documented quirk: KB5020779 [382] explains that a preview release shipped without an actual blocklist refresh, addressed by a subsequent servicing update [382].

> **Aside.** The KB5020779 episode is a useful reminder that the in-box block list ships through the same Windows Update cycle as everything else. Preview releases do not always carry a fresh policy, and the cadence on the block-rules page [271] describes the intended steady state rather than every individual update [271].

### Naming the weakness, not the publisher

For the first time in the story, the question Windows asks at load time is not only *who signed this binary?* but also *is this specific signed binary one we have learned is unsafe?* The block list is a step the previous generations could not have taken with the primitives they had: it requires a deny list that can be authored after the fact, distributed quickly, and enforced inside a trust domain the attacker cannot reach. KMCS supplied the load-time enforcement primitive; HVCI supplied the immune-from-VTL0 enforcement context; with HVCI, that policy decision is made from a VTL1 context that a compromised VTL0 kernel cannot rewrite. Without HVCI, the same vulnerable-driver block list can still be enforced as a Code Integrity/App Control policy on supported clients, but with less isolation of the enforcement context.

> **Walkthrough: block-list enforcement on a 22H2-class machine.**
>
> 1. A driver image is presented for mapping. The ordinary signature gate still runs first: unsigned images and images outside the accepted kernel-mode trust anchors fail before policy allow/deny nuance matters.
> 2. The Code Integrity policy engine then evaluates the active policies, including the in-box `DriverSiPolicy.p7b` vulnerable-driver policy; on HVCI systems this path is mediated through SKCI in VTL1.
> 3. Deny semantics are checked before allow semantics. A hash match blocks the exact artifact; a file-name rule catches known families whose vulnerable payload has stable naming; a signer rule can block a compromised or no-longer-trusted publisher scope.
> 4. If a deny rule matches, the image section is refused and the failure is recorded through Code Integrity telemetry. If no deny rule matches, the load may continue to later allowlist and reputation gates.
> 5. The important subtlety is that this is not revocation of the signing certificate. The driver can remain cryptographically valid and still be refused because Windows has learned that this particular signed artifact is dangerous.

### The vulnerable & malicious driver reporting center

The block list grew faster after Microsoft built a structured channel to feed it. The December 2021 Microsoft Security blog post [378] announced the Vulnerable & Malicious Driver Reporting Center: a portal where researchers and vendors can submit kernel drivers for evaluation, backed by an automated analysis pipeline that looks for the BYOVD primitives. "the ability to read or write arbitrary kernel, physical, or device memory, including Port I/O and central processing unit (CPU) registers from user mode." [378] The post explicitly lists the historical CVE backdrop that motivated the center, naming RobinHood, Uroburos, Derusbi, GrayFish, and Sauron as families that leveraged driver vulnerabilities such as CVE-2008-3431, CVE-2013-3956, CVE-2009-0824, and CVE-2010-1592 [378].

The same post anchors the EV-certificate publisher requirement and the HLK or attestation gating that produces the block list's inputs in the first place. The reporting center is the path by which a flagged driver moves from "spotted in research" to "deny rule in the next quarterly XML push".

### Defender ASR as the HVCI-off coverage path

There is a third surface worth knowing about. Microsoft's Attack Surface Reduction rules [384] include "Block abuse of exploited vulnerable signed drivers" (`56a863a9-875e-4185-98a7-b882c64b5ce5`) as part of the standard ASR protection set [384]. For Microsoft Defender for Endpoint customers on Windows 10 E3 or E5, the rule covers machines where HVCI is not on. Microsoft notes that "the same blocklist is also used by Microsoft Defender Antivirus customers" via the ASR rule [378]. The path is narrower than HVCI-rooted enforcement (Defender has to be running, the rule has to be enabled) but it extends the block list to enterprise environments that have not yet flipped HVCI on.

### LOLDrivers and the dual-use externality

The block list is not the only catalog of vulnerable Windows drivers. The community-maintained LOLDrivers project [385] ("Living Off The Land Drivers") collects vulnerable, malicious, and known-malicious Windows drivers in one place. Every entry carries YAML metadata and where possible YARA, Sigma, ClamAV, and Sysmon rules, plus a pre-compiled App Control deny policy that can be deployed standalone [386] [385]. As of the source verification for this chapter, LOLDrivers carried approximately 2,132 driver entries: considerably more than the Microsoft-shipped list.

Check Point Research called out the dual-use problem in their 2024 piece [387]: a public catalog of vulnerable drivers is also a reading list for attackers. The same researchers ran the methodology in reverse: "we conducted a mass hunt for new drivers that may be vulnerable, uncovering thousands of potentially at-risk drivers." [387] Defenders use the list for hardening; attackers use it for shopping. Both effects are real.

> **Deploy the published list as a WDAC policy.**
> Defenders who can tolerate compatibility risk can compile the source XML from the block-rules page [271] into an App Control policy and deploy it directly, picking up the entries Microsoft holds back from the in-box list. Optionally layer the LOLDrivers App Control policy [386] on top for community-curated coverage. Test in audit mode first. Both lists are more aggressive than the shipped baseline and may flag drivers your environment depends on [271] [386].

### A WDAC rule evaluator, in miniature

The semantics of an App Control policy are simple enough to model in a few lines. Deny rules win; allow rules are consulted next; the default action handles whatever is left.

Naming the weakness is genuinely new. But the list only ever lists what someone has already found. The window between disclosure and enforcement is months, and Microsoft documents that the shipped list is by design weaker than the published one. What gets the rest of the way?

## The 2026 stack: Defense in depth made concrete

On a default-configured Windows 11 22H2-class client as verified for this chapter on 2026-06-09, a kernel driver that tries to load is exposed to five distinct predicates. They are not all a single linear kernel-load hook; they are overlapping enforcement and coverage paths, and each closes a blind spot the previous one cannot reach.

![Figure: The 2026 stack as a defense-in-depth funnel. A kernel driver image encounters overlapping predicates, each catching a blind spot the previous one cannot reach: KMCS signature/chain (misses signed-but-vulnerable) → the `DriverSiPolicy.p7b` Vulnerable Driver Block List (misses unknown-vulnerable) → HVCI / SKCI in VTL1 with W^X (misses behavioral BYOVD) → App Control / Smart App Control policy and app reputation where applicable (misses allow-listed defects) → Defender ASR for HVCI-off coverage (misses non-listed drivers). A driver that survives the applicable gates still maps into ring 0, and the gap no gate closes is the undecidable question of whether a signed driver hides a kernel-write primitive (Rice's theorem).](diagrams/06-code-integrity-five-gates.svg)

The predicates and dependencies are:

1. **Kernel-Mode Code Signing.** The Authenticode chain must terminate at a Microsoft-owned root. The chain check rejects unsigned drivers and drivers chained to non-Microsoft roots, except under the documented grandfathering carve-outs [267].
2. **The Vulnerable Driver Block List.** The Code Integrity policy engine consults `DriverSiPolicy.p7b` for hash, file-name, and signer-level deny rules; on HVCI systems SKCI evaluates that policy from VTL1. The list is default-on for Windows 11 22H2 client devices [383], and is updated quarterly through Microsoft Learn's published source XML and monthly through Windows servicing, subject to compatibility holdbacks [271] [383].
3. **HVCI / SKCI.** The Code Integrity engine runs in VTL1, verifies signatures at section-mapping time rather than only at the driver-load entry point, and enforces W^X on kernel memory. The policy engine is structurally out of reach of a fully compromised VTL0 kernel [279].
4. **App Control / Smart App Control.** Enterprise admins author explicit App Control allowlists. Consumer devices on clean Windows 11 installs can run Smart App Control [388], a Microsoft-authored App Control policy backed by cloud reputation for apps and augmented by the vulnerable-driver block-list behavior Microsoft documents for SAC-enabled systems [388] [380] [271].
5. **Defender ASR.** On Microsoft Defender for Endpoint deployments, the "Block abuse of exploited vulnerable signed drivers" ASR rule extends block-list coverage to HVCI-off environments [384].

> **Definition: Smart App Control (SAC).** The Windows 11 22H2+ consumer-facing front end for App Control for Business (Chapter 13). SAC enforces a Microsoft-authored policy and supplements application decisions with cloud reputation lookups from the Intelligent Security Graph. SAC is only available on clean installs and is shipped in evaluation mode by default; once turned on, Microsoft documents it as one of the states that enforces the vulnerable driver block list [388] [271].

> **Definition: ISG (Intelligent Security Graph).** The cloud-backed reputation service that Smart App Control consults to predict whether a given binary is safe. When confident, ISG approves the binary; when unconfident, SAC falls back to signature checks; absent both, the binary is blocked [388].

### Orthogonality, not redundancy

The five gates look redundant from a distance. They are not. Each closes a class of failure the others cannot reach. The orthogonality is the reason for the stack.

| Gate | Catches | Misses |
|------|---------|--------|
| KMCS | Unsigned and cross-cert-only-signed drivers | Signed-but-vulnerable drivers |
| Block list | Known-vulnerable signed drivers (post-disclosure) | Unknown-vulnerable signed drivers |
| HVCI / SKCI | `g_CiOptions`-patching from VTL0; writable+executable kernel pages | Behavioral BYOVD inside a properly-signed driver |
| WDAC / SAC | Enterprise policy denies or non-allowlisted software; consumer app reputation plus documented SAC block-list state | Allowlisted drivers with unknown defects |
| Defender ASR | Block-list entries on HVCI-off machines (where the rule is enabled) | Drivers not on Microsoft's blocklist |

The matrix is the practical justification for the stack. If `DriverSiPolicy.p7b` had perfect coverage there would be no need for SAC; if SAC had a complete allowlist there would be no need for the block list; if HVCI proved driver safety rather than driver identity there would be no need for either. None of those preconditions hold, and the undecidability analysis explains why they cannot.

### Smart App Control's particulars

SAC merits a few specifics because its behavior differs from the rest of the stack in ways that surprise readers. First, it is consumer-facing and only available on clean Windows 11 installs. An upgrade does not get SAC. Second, SAC ships in *evaluation mode* by default. Windows watches user behavior, and if the user mostly runs cloud-reputable software, SAC quietly flips to *enforce*; if the user runs a lot of niche or self-developed software, SAC quietly flips to *off*. Third, until a 2024 servicing change [388] made SAC re-enableable from Windows Security, turning SAC off used to require a clean install to bring it back [388]. Fourth, on enterprise-managed devices, SAC turns itself off automatically after 48 hours; managed environments are expected to deploy WDAC instead [380].

The cold-start failure mode is worth knowing for the application side of SAC and for driver-adjacent installers, updaters, and control panels. A small independent hardware vendor whose software has never been seen at scale may lack a cloud reputation when SAC asks about it. The fallback is signature, but signed software from an unknown publisher does not always clear SAC's confidence threshold. For kernel drivers themselves, the primary documented SAC linkage is not a per-driver ISG reputation verdict; it is SAC enabling the vulnerable-driver block-list state [271] [388].

> **Walkthrough: the 2026 Windows 11 driver-loading stack.**
>
> 1. KMCS asks the old question first: does the image's Authenticode or catalog signature chain to a Microsoft-accepted kernel-mode trust anchor under the post-1607 rules and documented grandfathering carve-outs?
> 2. The Code Integrity policy engine asks the newer deny-list question: even if the signature is valid, does `DriverSiPolicy.p7b` identify this hash, name, or signer as known vulnerable or malicious? On HVCI systems, SKCI evaluates that question from VTL1.
> 3. HVCI asks the authority question: is the policy decision being made from VTL1, and will the resulting executable mapping respect write-xor-execute?
> 4. Enterprise App Control asks the allowlist question for drivers and applications; SAC asks the Microsoft-authored policy and app-reputation question on consumer devices, while also putting the vulnerable-driver block list into force.
> 5. Defender ASR covers part of the remaining population: HVCI-off enterprise machines can still consume Microsoft's vulnerable-driver intelligence through the "Block abuse of exploited vulnerable signed drivers" rule.
> 6. The order is less important than the orthogonality. Identity, known-bad status, trust-domain isolation, allowlist policy, and endpoint-protection coverage are five different predicates because no one predicate can decide driver safety.

### Verifying what the machine actually does

The state of the stack on any given Windows machine is observable. The Win32_DeviceGuard WMI class exposes a `SecurityServicesRunning` array whose integer codes name the security services currently active. The aside below covers the practitioner-facing details.

> **Aside: How to check what your machine actually does.**
> Two commands answer most of the question. From an elevated PowerShell prompt, `Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard` returns a structure whose `SecurityServicesRunning` array enumerates the services in operation; Microsoft's PowerShell enum documents **1** as **Credential Guard** and **2** as **Hypervisor-Enforced Code Integrity** [389]; newer Windows builds may display additional service names in WMI output, but those labels should be treated as version-specific unless the local OS documentation names them. `bcdedit /enum {default}` shows whether `hypervisorlaunchtype` is set to `Auto`, the prerequisite for VBS being on at all. The block list file itself lives at `%windir%\system32\CodeIntegrity\DriverSiPolicy.p7b`; if it is missing, the in-box list is not deployed on that machine. None of these tell you whether your Defender ASR rule is active without a separate `Get-MpPreference` check.

Five gates is a lot of work to do what one ideal gate could not. The reason for the inflation is uncomfortable: the one ideal gate cannot, in principle, exist.

## Proof on a live machine

The mechanism above is architectural; the live-machine claim is narrower. The following block is the chapter's single captured evidence block. It is copied verbatim from the lab capture and is protected by the build's evidence-fidelity gate.

> 🟢 **CAPTURED**. `explab-win` · Win11 25H2 (build 26200) · 2026-06-07T05:30:49Z
> probe: `Win32_DeviceGuard` (WMI/CIM) · sha256 `c17d18ef37ab…`
> reproduce: `Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard | Format-List *`

<!--evidence file="deviceguard.txt" sha256="c17d18ef37ab6963c272fdbefaf8bd39dd22ebcdc9de606d03beade4428bde98"-->
```text
SecurityServicesRunning           = CredentialGuard, HypervisorEnforcedCodeIntegrity
CodeIntegrityPolicyEnforcementStatus         = 2
UsermodeCodeIntegrityPolicyEnforcementStatus = 1
Scenarios\HVCI\Enabled            = 1
```

`SecurityServicesRunning` listing `HypervisorEnforcedCodeIntegrity` shows that HVCI is actually running, not merely available (a raw `Get-CimInstance` returns this field as the integer enum array `{1, 2}`, surfaced here by the documented names: 1 = Credential Guard, 2 = Hypervisor-Enforced Code Integrity). `Scenarios\HVCI\Enabled = 1` is the policy state that put it there, and `CodeIntegrityPolicyEnforcementStatus = 2` is the enforced system code-integrity-policy state rather than audit-only mode. The same `deviceguard.txt` capture anchors the Secure Kernel chapter (Chapter 6) and the Credential Guard chapter (Chapter 15) as well, because the VBS security services share a single `Win32_DeviceGuard` surface: one probe, three guarantees, each chapter reading only the lines it owns; here, the HVCI-relevant ones.

The next probes are 🔵 **DOCUMENTED**: commands a reader can run and expected output shapes from Microsoft documentation, not additional captures from the lab VM.

> 🔵 **DOCUMENTED**: Microsoft Learn, *Enable virtualization-based protection of code integrity* and `Win32_DeviceGuard`; expected output.
> reproduce: `Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard | Select-Object VirtualizationBasedSecurityStatus,SecurityServicesRunning,CodeIntegrityPolicyEnforcementStatus`

```text
VirtualizationBasedSecurityStatus      : 2
SecurityServicesRunning                : {2}
CodeIntegrityPolicyEnforcementStatus   : 2
```

Read these fields narrowly. `SecurityServicesRunning` is an array of VBS security services; Microsoft documents value `2` as Hypervisor-Enforced Code Integrity / Memory Integrity. `CodeIntegrityPolicyEnforcementStatus = 2` is the documented enforced state for the system code-integrity policy. A fleet query should treat absence of `2` from `SecurityServicesRunning` as "HVCI is not running," even if a policy is configured somewhere else.

> 🔵 **DOCUMENTED**: Microsoft Learn, Code Integrity operational logging for App Control / Code Integrity; event IDs are documented signals, not captured on our lab VM.
> reproduce: `Get-WinEvent -LogName 'Microsoft-Windows-CodeIntegrity/Operational' | Where-Object Id -in 3033,3077 | Select-Object TimeCreated,Id,ProviderName,Message -First 5`

```text
TimeCreated : <timestamp>
Id          : 3033
ProviderName: Microsoft-Windows-CodeIntegrity
Message     : Code Integrity determined that a process attempted to load a file
              that did not meet the signing level requirements.

TimeCreated : <timestamp>
Id          : 3077
ProviderName: Microsoft-Windows-CodeIntegrity
Message     : Code Integrity determined that a file did not meet the code
              integrity policy requirements and was blocked.
```

The exact path and process vary by machine. The provenance of the signal matters more than the placeholder values: the Code Integrity operational log is where Windows records signature- and policy-based load failures, including App Control blocks: the same log an EDR consumes through the telemetry pipeline the ETW chapter (Chapter 25) describes. Use it to corroborate policy behavior; do not infer HVCI state from event presence alone.

> 🔵 **DOCUMENTED**: Microsoft Learn, *Microsoft recommended driver block rules*; expected block-list state, not captured on our lab VM.
> reproduce: `Test-Path "$env:windir\System32\CodeIntegrity\DriverSiPolicy.p7b"; Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config' -Name VulnerableDriverBlocklistEnable -ErrorAction SilentlyContinue`

```text
True

VulnerableDriverBlocklistEnable : 1
```

`DriverSiPolicy.p7b` is the in-box vulnerable-driver block-list policy. Microsoft documents the block list as default-on for Windows 11 22H2 client devices and as enforced when Memory Integrity, Smart App Control, or S mode is active, with a Windows Server 2016 carve-out. The registry value is an administrative state surface; the file's presence confirms the policy artifact is deployed, not that every published Microsoft rule is present in the in-box build.

## The undecidability wall

Why does Windows need five layers to do what one perfect signature ought to do? Because the perfect signature is mathematically impossible.

The third reframe of this chapter is the one that turns engineering frustration into theoretical inevitability. The property of interest ("this signed driver, when exercised through its IOCTL surface, can be coerced into giving an attacker an arbitrary kernel-write primitive") is a non-trivial semantic property of the driver's program text. Rice's theorem says that for any non-trivial semantic property of programs, the predicate is undecidable on the class of all programs. In that unrestricted Turing-machine abstraction, no algorithm exists that, in finite time, answers correctly for every input.

A useful way to state the bound: if $P$ is the set of arbitrary driver programs and $\text{Unsafe}(p) = 1$ iff driver $p$ exposes a kernel-write primitive through its IOCTL handler, then no total computable function $f: P \to \{0, 1\}$ satisfies $f = \text{Unsafe}$ for the unrestricted class. Every approximation either over-blocks ($f(p) = 1$ when $\text{Unsafe}(p) = 0$, false positives, broken drivers) or under-blocks ($f(p) = 0$ when $\text{Unsafe}(p) = 1$, false negatives, BYOVD in the wild). The signing pipeline scans for the obvious cases; sophisticated dynamic analyzers will catch more of the not-obvious cases; restricted driver subsets and specific vulnerability classes can be decidable or model-checkable in principle; but the unrestricted semantic-safety problem has no complete exact solution.

> **Key idea.**
> Whether an arbitrary signed driver can be coerced into giving an attacker a kernel-write primitive is undecidable. No static signing scheme can ever block exactly the unsafe drivers. The Windows answer is therefore not a single perfect gate; it is defense in depth that narrows, but does not close, the gap.

### Microsoft's formal acknowledgment

Microsoft's servicing criteria define the question MSRC asks before issuing a Windows security update: whether a report violates the goal or intent of a Microsoft-defined security boundary or feature, and whether severity meets the servicing bar [301]. The published boundary list includes boundaries such as user/kernel separation, VMs, and VBS enclaves; it does not make administrator-to-kernel escalation on the same Windows installation a general servicing boundary [301]. Elastic Security Labs put the operational consequence in plain English: "the blocklist's deployment model can be slow to adapt to new threats, with updates automatically deployed typically only once or twice a year. Users can manually update their blocklists, but such interventions bring us out of 'secure by default' territory... When determining which vulnerabilities to fix, the Microsoft Security Response Center (MSRC) uses the concept of a security boundary." [365]

> **Pull quote.**
> Administrator-to-kernel is not a general Windows servicing boundary in the MSRC criteria sense; user-to-kernel is. The defense-in-depth mechanisms described here mitigate admin-to-kernel abuse for consumers and enterprises, but they should not be mistaken for a complete servicing-boundary promise.

The MSRC framing is engineering policy and threat-model scoping, not a claim that administrator-to-kernel attacks are harmless. The undecidability result is theoretical inevitability. They land in the same place: an attacker who has administrator privilege, who can pick from the entire history of signed Windows drivers, who is patient, is not stopped by any number of signature checks. The defense-in-depth mechanisms make the attacker work harder; they raise the cost; they shrink the surface of viable signed drivers. They do not close the structural gap.

### Closeable gaps and irreducible gaps

It is worth separating two kinds of gap.

The published-vs-shipped block list gap is a *policy* decision, not an engineering limit. Microsoft documents that "it's often necessary for us to hold back some blocks to avoid breaking existing functionality." [271]

> **Aside.** The published-vs-shipped gap is the closeable part. An administrator who can author or import an App Control policy can deploy the published XML directly and pick up Microsoft's full curation. The irreducible part of the gap sits behind it: even the published list lists only what someone has already disclosed. The undecidability result applies to *finding* unsafe drivers, not to *listing* known-unsafe ones.

 Defenders willing to accept compatibility risk can narrow it on their own machines today by deploying the published Microsoft XML, supplemental policies, or community policies in audit mode before enforcement.

The gap that cannot close is the one between the published list and the universe of vulnerable drivers Microsoft has not yet learned about. That is where the undecidability result bites. No amount of pipeline tightening eliminates the class of design flaws whose recognition requires understanding what the driver's IOCTL handler will do under all possible inputs.

### What static methods *can* achieve

Quantifying what the existing layers achieve is more useful than lamenting what they cannot, but the quantification has to be honest about the public evidence. Microsoft documents the policy schema and the HVCI enforcement properties; it does not publish SKCI's exact in-memory indexes or the compiled `CiPolicy` binary layout as a stable programming contract. So the useful statement is not "Windows implements this exact asymptotic data structure." The useful statement is: every load-time check Windows performs today belongs to one of a few decidable, bounded classes, and none of those classes is equivalent to semantic safety.

Authenticode and catalog verification answer an integrity-and-identity question. The loader has a byte string, a candidate signature, and a set of trusted anchors. The work is finite: hash the PE image under Authenticode's rules; if the file is catalog-signed, find the catalog member hash that covers the image; verify the PKCS#7 signature; build and validate the certificate chain; consult revocation state to the extent policy requires it; then compare the resulting signing level with the kernel-mode threshold. That can be expensive in engineering terms (disk I/O, certificate-chain building, timestamp handling, catalog lookup, cache effects) but it is still a syntactic predicate over bytes and certificates. It never requires executing the driver's IOCTL handlers.

HVCI/SKCI adds a second decidable predicate at section-creation time. The section either has executable permission or it does not; the proposed mapping either attempts writable-and-executable kernel memory or it does not; the policy decision either comes from VTL1 or it does not. MBEC and GMET matter because they let the hypervisor express supervisor/user execute permissions without trapping every transition through a slow emulation path. Microsoft's public Memory Integrity page is careful here: newer Intel Kabylake-and-later and AMD Zen-2-and-later processors do the job with hardware support, while older processors fall back to Restricted User Mode and pay a larger performance cost [279]. That is a performance property, not a proof of behavioral safety.

WDAC and `DriverSiPolicy.p7b` add finite set-membership predicates. A hash rule asks whether the image hash equals one of a finite set of denied hashes. A signer rule asks whether the validated signer chain matches one of a finite set of denied signer descriptions. A file-name rule asks whether the leaf name or package metadata matches a finite string rule. A production implementation can index those structures by hash table, trie, sorted vector, or another internal representation; a naïve implementation could scan linearly. The asymptotic choice affects latency, not expressiveness. Every version still asks membership in a known set.

Static analysis can go further than membership. It can disassemble dispatch tables, identify IOCTL handlers, trace simple dataflow from `Irp->AssociatedIrp.SystemBuffer` to `MmMapIoSpace`, `memcpy`, MSR instructions, port I/O, process-object manipulation, and callback-table writes. Check Point's import-table mass hunt and EURECOM's dynamic Kernelmon work show that these approximations find real vulnerable drivers at scale [387] [390] [391]. But once the question becomes "for all possible inputs and states, can this driver be coerced into a kernel-write primitive?" the problem has crossed from syntactic membership into program semantics. The earlier Rice-theorem argument applies precisely there.

That distinction is the master key. Static methods can prove identity, enforce a mapping invariant, check membership in a curated deny list, and flag many recognizable bug patterns. They cannot be both complete and sound for arbitrary driver safety. If they over-approximate, they block good drivers; if they under-approximate, they let some BYOVD candidates through. The gap between achievable static enforcement and the ideal "block all and only the unsafe drivers" is, in the limit, irreducible.

### Three axes that can be improved

If the gap cannot close, it can be narrowed along three independent axes, and the improvements that matter, look like one of these:

- **Reactiveness.** The disclosure-to-enforcement latency is often measured in servicing cycles. Submission-time analyses could compress it if Microsoft makes them gating.
- **Coverage of unknown-bad signed drivers.** Reputation, allowlists, and dynamic analysis at scale extend coverage beyond what a static deny list lists.
- **Visibility into binary contents.** SBOMs answer "what is inside this driver?": a question the signature alone never asked.

Each axis is the answer to a different blind spot. None substitutes for another. The chapter returns to the SBOM axis specifically because Microsoft has publicly signaled a WHCP SBOM requirement, while detailed enforcement documentation remains thinner than the claim deserves.

Static signing has hit a wall it cannot push through. The only way forward is to widen the question. Two of the answers exist on other operating systems. The third has been publicly signaled for the Windows driver pipeline, but its final submission mechanics still need formal documentation.

## The other two operating systems

Linux solved the signing half and pushed the curated-denylist half down to distribution vendors. macOS solved both by making third-party drivers stop being drivers.

### Linux: signatures without a curated denylist

Linux has supported in-kernel module signing since version 3.7 (December 2012), under the configuration symbol `CONFIG_MODULE_SIG`. The kernel documentation [392] catalogs the supported algorithms: "The built-in facility currently only supports the RSA, NIST P-384 ECDSA and NIST FIPS-204 ML-DSA public key signing standards." [392] The choice of signature scheme is a build-time decision, and the kernel can be told to use a key embedded in the kernel image, a key loaded into the trusted keyring at runtime, or a Machine Owner Key managed by `shim` and the platform's UEFI boot stack.

The structural decision that matters is the enforcement mode. `CONFIG_MODULE_SIG_FORCE` is the toggle. The kernel documentation describes the two settings cleanly: "If this is off (ie. 'permissive'), then modules for which the key is not available and modules that are unsigned are permitted, but the kernel will be marked as being tainted... If this is on (ie. 'restrictive'), only modules that have a valid signature that can be verified by a public key in the kernel's possession will be loaded." [392]

Outside Secure Boot or vendor lockdown profiles, many mainstream Linux installations are permissive: unsigned modules taint the kernel but load. Under Secure Boot on Ubuntu/Fedora/RHEL-class systems, signed-module enforcement and lockdown-style restrictions are commonly part of the default path, and self-built kernels can choose either mode.

> **Aside.** The Linux lockdown LSM is the closest mainline-Linux analog to HVCI's policy-out-of-reach property. The `kernel_lockdown(7)` man page [393] describes lockdown as "designed to prevent both direct and indirect access to a running kernel image" and enumerates the restricted surfaces: `/dev/mem`, `/dev/kmem`, `/dev/kcore`, kprobes, BPF, MSR alteration, ACPI table overrides, and unsigned kexec [393]. It is a partial analog, not equivalent: lockdown still runs in the same trust domain as the kernel it polices, so a sufficient kernel exploit defeats it. HVCI's VTL0/VTL1 split is structurally stronger.

What Linux does not have is the equivalent of `DriverSiPolicy.p7b`. There is no kernel-level curated denylist of "we have learned this module is unsafe; refuse to load it by name". Defenders rely on per-distribution CVE trackers, on `modprobe.blacklist`, and on `udev` rules to keep specific modules out. The G5 generation (naming the *weakness* rather than the publisher) has no mainline Linux equivalent at the kernel-loader level.

### macOS: DriverKit removes the surface

Apple's answer is structurally different. Starting with macOS Catalina 10.15 [394] in 2019, Apple deprecated legacy kernel extensions for third parties and pushed them onto the DriverKit [395] framework instead [394] [395].

> **Definition: DriverKit.** Apple's user-space driver framework, introduced with macOS Catalina 10.15. Third-party drivers ship as `.dext` user-space extensions linked against a curated IOKit subset; they receive IOKit messages from the kernel and respond with the same operations they used to perform in ring zero, but the code itself runs in user mode under sandbox restrictions. The kernel side of the new model exposes a controlled message surface; the third-party side cannot directly execute kernel code.

A `.dext` runs in user space under a sandbox profile. It can claim devices, register for IOKit interrupts, and exchange messages with kernel-side broker code, but it cannot, in any usable sense, execute arbitrary code in the kernel address space. The Capcom.sys class of vulnerability cannot be expressed in DriverKit: there is no IOCTL surface whose handler runs in ring zero, because the handler does not run in ring zero. Apple reinforces the boundary further with System Integrity Protection [396] (since 2015) and, on Apple Silicon, Kernel Integrity Protection (KIP), which makes the kernel page tables read-only after boot [396].

The price was paid by Apple's IHV community. Whole categories of third-party drivers (deep audio, virtualization, certain security tools) spent years migrating, and some categories took multiple macOS releases before a DriverKit equivalent of a particular kext capability existed. Apple Silicon requires explicit reduced-security mode to load *any* legacy kext at all: Apple's Platform Security guide [397] records that "Kexts must be explicitly enabled for a Mac with Apple silicon by holding the power button at startup to enter into One True Recovery (1TR) mode, then downgrading to Reduced Security and checking the box to enable kernel extensions" [397].

### Why Windows cannot copy Apple

The reason Windows cannot make Apple's move in the short term is operational, not architectural. Windows' IHV installed base is orders of magnitude larger and less centrally controlled. Microsoft does not own its hardware vendors the way Apple owns Macs. Breaking compatibility with twenty years of shipped kernel drivers would impose unbounded migration cost on third parties Microsoft cannot direct.

| Dimension | Windows (2026) | Linux (mainline + RHEL-class hardening) | macOS (Catalina+ / Apple Silicon) |
|-----------|-----------------|-----------------------------------------|-----------------------------------|
| Default signature enforcement | Mandatory on x64 since 2006 | Permissive (taints kernel); restrictive on hardened distros | Mandatory; legacy kexts deprecated |
| Curated denylist of signed-but-vulnerable artifacts | `DriverSiPolicy.p7b`, default-on since 22H2 | None at kernel loader; per-distro CVE trackers | Not needed: third-party kexts removed |
| Policy engine isolated from kernel it polices | HVCI in VTL1 | Lockdown LSM (same trust domain) | KIP and SIP on Apple Silicon |
| Third-party drivers in kernel | Yes, still the model | Yes | Default direction is no for modern DriverKit-first paths; legacy kexts remain possible in approved/reduced-security configurations |
| Operational price of the model | Compatibility carve-outs, opt-outs | Permissive default | Multi-year IHV migration |

Windows cannot move drivers to user space at Apple's speed. But it can look at *what is inside* a driver in a way the signature alone never could. And it has been quietly building that capability since 2022.

## What comes next: SBOM, artifact signing, dynamic analysis

If signatures cannot answer "is this driver safe", and the block list can only ever answer "is this driver known-unsafe", the next question Windows has to learn how to ask is "what is inside this driver?"

### SBOM for drivers

A Software Bill of Materials is a structured inventory of the components, dependencies, and versions inside a software artifact. The mainstream community formats are SPDX (now at version 3.0) and CycloneDX; Microsoft contributes to and ships an open-source tool, microsoft/sbom-tool [398], that produces SPDX-compatible SBOMs as part of a build pipeline [398]. The repository description is plain: "The SBOM tool is a highly scalable and enterprise ready tool to create SPDX 2.2 and SPDX 3.0 compatible SBOMs for any variety of artifacts. The tool uses the Component Detection libraries to detect components and the ClearlyDefined API to populate license information for these components." [398]

> **Definition: SBOM (Software Bill of Materials).** A machine-readable inventory of components and dependencies inside a software artifact. For a Windows kernel driver, an SBOM lists the third-party static libraries linked into the PE, the open-source code paths bundled with the driver, and the versions of each, in a format (SPDX, CycloneDX) that automated tools can consume to answer "is any component of this driver subject to a known vulnerability?"

The piece that may affect Windows drivers specifically is the Windows Hardware Compatibility Program SBOM requirement. The strongest public breadcrumb this chapter could verify is still a Microsoft Q&A answer, not a formal WHCP policy PDF: "The WHCP SBOM requirement (Device.DevFund.Security.SoftwareBillofMaterials) has been deferred and will only be enforced starting in H2 2026" [399]. The official WHCP specifications-and-policies page is the place Microsoft publishes downloadable requirements, but the public page itself does not yet provide the detailed SBOM enforcement mechanics [400]. Treat H2 2026 as Microsoft's stated direction as of 2026-06-09, not as a fully documented submission contract.

> **Aside: The compliance angle.**
> The EU Cyber Resilience Act sets phased compliance obligations for products with digital elements sold into the EU market. A Microsoft Q&A answer ties the deferred `Device.DevFund.Security.SoftwareBillofMaterials` WHCP requirement to the same compliance horizon [399]. Until Microsoft publishes the detailed WHCP policy artifact on its specifications-and-policies channel [400], the careful statement is narrower: regulated IHVs should prepare their driver build pipelines for SBOM generation and watch the WHCP documents for the binding submission rule.

There is a structural problem an SBOM does not solve on its own. If the SBOM ships separately from the driver, an attacker who controls the distribution path can substitute a clean-looking SBOM for a contaminated driver. Any submission flow that uses SBOMs for trust should bind the SBOM cryptographically to the artifact it describes so that a recipient can verify the binding. Public WHCP documentation for that binding mechanism remains light beyond the Q&A-level mandate signal [399] and the general WHCP specifications channel [400].

### Dynamic analysis at submission time

The other axis of improvement is reactiveness. Today, the typical disclosure-to-enforcement cycle for a new BYOVD driver looks like this: vendor ships, attacker exploits, researcher discloses, Microsoft adds to the quarterly published list, Windows servicing pushes to clients. The latency is months. Two recent research programs show how dynamic analysis at scale can compress it.

The first is the EURECOM / University of Milan NDSS 2026 paper on the authors' publication page [390]. The team built a DRAKVUF-based instrumentation layer called Kernelmon and traced every kernel function executed by signed drivers under malware-loaded workloads [390]. The numbers are unusually concrete: the paper PDF [391] reports that the team "analyzed 8,779 malware samples that load 773 distinct signed drivers. It flagged suspicious behavior in 48 drivers, and subsequent manual verification led to the responsible disclosure of seven previously unknown vulnerable drivers" [391]. The companion S3 blog post [401] corroborates the 48-flagged / 7-disclosed numbers and notes that one of the seven received CVE-2024-26506 [401]. The technique is dynamic: it runs the driver under a hypervisor, watches what its IOCTL handlers actually do, and flags patterns characteristic of the BYOVD class.

The second is Check Point Research's 2024 work [387], which built a mass-hunt methodology around import-table signatures of risky kernel APIs and ran it across the global driver corpus. "Using the same methodology, we conducted a mass hunt for new drivers that may be vulnerable, uncovering thousands of potentially at-risk drivers." [387] The technique is static: it asks *what does the driver import?* rather than *what does it do under exercise?* Combined, the two approaches cover complementary halves of the surface.

Neither currently gates Hardware Dev Center submissions. Both are candidates for the kind of submission-time check that would compress disclosure-to-enforcement latency from quarters to days.

### Empirical patterns the defenses have to recognize

Cisco Talos's BYOVD work, summarized in their *Exploring vulnerable Windows drivers* post [402], classifies the post-load payloads attackers actually run [402]. Three behavior classes dominate: token-swap escalation that overwrites the access token in the `_EPROCESS` structure to reach SYSTEM; unsigned-code-loading that uses the kernel-write primitive to disable DSE or patch CI state; and EDR-killing that clears the kernel callback registrations endpoint detection products rely on. Each is a target for the dynamic analyses above, each is detectable by import-table heuristics, and each is what defenders see in the wild today.

The historical roots are old. The Microsoft Security blog tracing the Vulnerable & Malicious Driver Reporting Center is direct: "Multiple malware attacks, including RobinHood, Uroburos, Derusbi, GrayFish, and Sauron, have leveraged driver vulnerabilities (for example CVE-2008-3431, CVE-2013-3956, CVE-2009-0824, and CVE-2010-1592)." [378] The payload classes have stayed remarkably stable for fifteen years.

> **Three axes, three answers.**
> The structural gap between *signed* and *safe* cannot close, but it can be narrowed along three independent axes introduced earlier: faster disclosure-to-enforcement loops, broader coverage of unknown-bad signed drivers through policy and reputation, and visibility into binary contents through SBOMs. The EURECOM and Check Point studies show what better analysis can find [390] [387]; the WHCP SBOM signal shows where Microsoft may add metadata to the submission flow [399] [400]. None substitutes for another.

### Threats the stack cannot yet absorb

Three problems remain open and uncovered by the published roadmap. The Smart App Control cold-start window leaves small IHVs whose installers, control panels, and updater binaries have no cloud reputation to fall through to signature, and signature alone is exactly what we already established does not answer the safety question. BYOVD on HVCI-off environments, prevalent in older anti-cheat configurations and on enterprise machines with legacy ISV drivers, still admits the `g_CiOptions`-patching family from VTL0 because there is no VTL1 to keep the policy out of reach. And the shipped-vs-published block list gap, while operationally rational and individually closeable by a willing administrator, is a gap any default-on customer carries.

None of those closes by algorithmic improvement. Each closes only by widening the question.

What started as a yes/no signature check has become a continually expanding set of questions Windows asks before it will hand a driver the keys to ring zero. None of those questions is sufficient. All of them are necessary. The next one (SBOM-backed visibility into driver contents) is signaled for the WHCP submission flow, but should be tracked against the formal policy documents as they land.

## What this means in practice

Three audiences, three things to do.

**Administrators.** Confirm the stack is on. `Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard` returns a `SecurityServicesRunning` array; a `2` in the array confirms HVCI [389]. A `DriverSiPolicy.p7b` in `%windir%\system32\CodeIntegrity\` confirms the in-box block-list artifact is deployed, but not rule parity with Microsoft's published XML; also check `VulnerableDriverBlocklistEnable`, Code Integrity events 3033/3077, policy version, and WDAC/App Control operational logs. If you can tolerate compatibility risk, compile the published block-rules XML [271] into an App Control policy and deploy it: audit first, sign production policies where your process requires it, use supplemental policies for exceptions, keep recovery media or rollback policy ready, and only then enforce. If you run Windows Server 2016, deploy an explicit policy yourself because the in-box default does not apply there [271]. If you ship through the Hardware Dev Center, prepare for the stated H2 2026 WHCP SBOM direction while watching the formal WHCP policy documents [399] [400]. Subscribe to the Vulnerable & Malicious Driver Reporting Center cadence for new disclosures [378].

**Driver authors.** Assume your IOCTL surface will be read by Check Point's import-table mass hunt [387] and exercised by EURECOM's Kernelmon [390]. Any handler that takes a user-supplied address and returns kernel data, maps physical memory, touches MSRs or ports from user mode, or dispatches a user-supplied function pointer is already in the pattern language Microsoft says its reporting pipeline looks for [378].

**Researchers.** The field is wide open. The undecidability result is real, but the practical gap between what current analyses detect and what is, in principle, detectable for any specific vulnerability class is large. The NDSS 2026 paper found seven CVE-worthy drivers in a corpus of 773. The next paper will find more.

### Every layer is somebody's incident report

Every layer in the 2026 stack exists because the previous one lost to a named adversary. Sony BMG XCP retired advisory signing. Stuxnet retired the assumption that a valid chain is a safe chain. Capcom.sys retired the assumption that a safe chain is a safe driver. RTCore64.sys, gdrv.sys, and KProcessHacker retired the assumption that the BYOVD class would burn itself out. Each entry on `DriverSiPolicy.p7b` is somebody's incident report, recorded in the most permanent place Microsoft can put it: the kernel loader's deny list.

> **The block list will keep growing.**
> Windows 11 22H2 ships with a list of drivers Microsoft will not load. The next list will be longer. The story has been adversarial since 1996 and the trajectory does not reverse: every layer was added because the previous one met an attacker. The structural gap is undecidable; the engineering gap, narrowable; the work, unfinished.
