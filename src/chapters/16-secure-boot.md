# Secure Boot

::: trust-ledger

- **Inherits:** Nothing earlier in this book. Secure Boot is the first link in the chain: its root of trust is the silicon and firmware beneath it. On platforms where Intel Boot Guard or AMD Platform Secure Boot is available, enabled, and correctly fused, a lower silicon verifier authenticates firmware before SEC runs; the UEFI Platform Initialization pipeline (SEC → PEI → DXE → BDS) and the authenticated-variable store (PK, KEK, db, dbx) are the platform substrate this book stands on.
- **Promise:** When the machine powers on, only a PE/COFF boot image whose Authenticode hash or signing certificate is in `db` (and absent from `dbx`) is allowed to execute as the operating-system loader; the firmware refuses un-allowlisted code at the `LoadImage()` boundary.
- **TCB:** The platform's pre-SEC firmware-authentication mechanism where one is enforced (Boot Guard / PSB + OTP fuses), the DXE-phase firmware hosting the `LoadImage()` verifier, the authenticated UEFI variable store, and the holders of the PK/KEK private keys (the OEM and Microsoft). The operating system that boots afterward is explicitly *outside* it.
- **Adversary → Break:** An attacker who writes the EFI System Partition with Secure Boot disabled (ESPecter, FinSpy); who chain-loads a legitimately Microsoft-signed but vulnerable older boot manager whose hash is not yet in `dbx` (BlackLotus / Baton Drop); who abuses TPM-only downgrade paths (Bitpixie); or who executes in DXE *below* the verifier (LogoFAIL). The Promise ends at "validly signed," not "actually secure", and the Windows boot-manager failures cluster in the gap between *patched* and *revoked*.
- **Residual:** What loaded is verified but not *recorded* → the Measured Boot chapter (Chapter 4) and the TPM chapter (Chapter 2); proving the boot to a remote party → the Attestation chapter (Chapter 5); code-integrity policy on every kernel-mode image after handoff → the Code Integrity chapter (Chapter 8); isolating the running kernel itself → the Secure Kernel chapter (Chapter 6); the OEM-key-leak and firmware-update-cadence problem → the Pluton chapter (Chapter 3).
- **Bequeaths:** A signature-verified boot path through `bootmgfw.efi`, `winload.efi`, `ntoskrnl.exe`, and ELAM. The trusted starting point the Measured Boot chapter (Chapter 4) and the TPM chapter (Chapter 2) extend into PCRs. Does NOT provide: measurement, a tamper-evident log, or attestation. Secure Boot checks signatures; it does not MEASURE what ran or prove it to anyone.
- **Proof:** 🔵 documented. `Confirm-SecureBootUEFI`, `Get-Tpm`, and `Get-SecureBootUEFI db/dbx` at the point of claim; no hash-verified lab capture exists for machine-specific firmware state.
:::

> **The Reasoner's question.** When a Windows machine powers on, which code gets to become the operating system, and where has that permission check actually failed?

---

> **Foundations. What you need before this chapter.**
>
> - **Verification vs. measurement.** The Foundations chapter (Chapter 0) draws the core distinction: Secure Boot *prevents*, Measured Boot *records*. The load-bearing point here is the division of labor: this chapter owns the firmware verifier, and the TPM chapter (Chapter 2) and Measured Boot chapter (Chapter 4) own the measurement rail.
> - **UEFI, not BIOS.** The modern Windows path assumes UEFI Platform Initialization: SEC, PEI, DXE, and BDS. The Secure Boot verifier lives in DXE, after earlier firmware code has already run.
> - **Authenticated variables.** `PK`, `KEK`, `db`, and `dbx` are signed UEFI variables. They are the policy database that tells firmware which boot images to accept and which to reject.
> - **Microsoft as deployed root.** The UEFI specification does not require Microsoft to be the central gatekeeper, but Windows-certified x86 PCs are operationally built around Microsoft-rooted Secure Boot CAs. That social fact matters as much as the cryptography.
> - **Attacks as gap analysis.** The attacks in this chapter are not recipes. They are a map of where the trust chain's assumptions did not hold: disabled Secure Boot, vulnerable-but-signed boot managers, delayed dbx revocation, DXE parser bugs, and TPM-only BitLocker downgrade paths.

---

## What this link must prove

Windows boots through a chain of verifications and measurements that runs from CPU reset to your desktop. UEFI Secure Boot verifies the boot manager; Trusted Boot extends signature and code-integrity policy checks to kernel-mode components; Measured Boot records the path into TPM PCRs, with DRTM later seeding PCR 17-22 from a CPU-vendor-signed late-launch anchor. After fifteen years of BIOS rootkits, MBR bootkits, and ESP-resident bootkits, the dominant Windows boot-manager failures since 2022 have clustered in one gap: between patching a vulnerable Microsoft-signed binary and revoking it in dbx [1,2,3]. Other breaks sit below the verifier (LogoFAIL) or outside default Secure Boot enforcement (Bootkitty as a self-signed Linux PoC) [4,5]. Pluton is Microsoft's longer-term answer to the firmware-update-cadence side of that problem, not a deployed replacement for DXE Secure Boot today [6,7].

## Eight seconds in 2010, and everything that could already be wrong

Picture a small business owner in December 2010. She unplugs her three-year-old Dell, drives it home, and powers it on. The fan spins. The BIOS chimes. The Windows 7 logo appears. By the time she types her password and the desktop loads, eight seconds have passed.

In those eight seconds, a TDL-4 bootkit that has been on disk for two weeks has already done its work. The infected master boot record patched the operating system loader in memory before the kernel finished initializing. Driver Signature Enforcement, the policy that was supposed to keep unsigned kernel drivers out, was disabled before the kernel checked for it. A ring-0 rootkit is now staged inside `ntoskrnl.exe`. Kaspersky's June 2011 analysis counted 4,524,488 infected machines in the first three months of 2011 alone [8]. The owner notices nothing. By the time she authenticates, the operating system that authenticates her is loading code the operating system never agreed to load.

The structural question raised by that scene is the question this chapter exists to answer: *what would it take for Windows to know, by the time the user types a password, that the machine has not been tampered with since power-on?*

The answer Microsoft began shipping with the Windows 8 generation is a chain [9,10]. UEFI Platform Initialization brings up the firmware. UEFI Secure Boot verifies the boot manager. Trusted Boot extends the signature check through `winload.efi`, the kernel, and every boot-start driver. Early Launch Anti-Malware classifies subsequent drivers. The Secure Kernel comes up in a hardware-isolated execution mode. Through every one of those rungs, a parallel rail (Measured Boot) extends a hash of each component into the TPM's Platform Configuration Registers and records a separate, replayable event log, so that what was loaded can be proven later, even if the verifier itself was bypassed.

That chain is the spine of this chapter, walked rung by rung, with each place it has been broken in the wild. For Windows boot-manager bugs, the recurring operational invariant is the gap between *patched* and *revoked*, not a break in the signature primitive.

![Figure: The end-to-end Windows boot chain. Each rung verifies the next while a parallel measurement is extended into the TPM's PCRs.](diagrams/16-secure-boot-boot-chain.svg)

Secure Boot is easy to describe badly: "the firmware checks a signature." The full Windows chain is more demanding. Firmware may be protected by silicon-rooted mechanisms below it, depending on platform support and OEM provisioning; the firmware has to carry a database of allowed and forbidden signers; the database has to be updated without bricking machines; Windows has to continue the verifier after the firmware hands off; and a parallel TPM measurement rail has to make the result attestable later. The rest of the chapter walks that full depth because the failures only make sense when the whole chain is visible.

Before there was a chain to walk, there was no chain at all.

## Before Secure Boot: sector zero and the fiction of OS-level security

Ask what was actually verified during a 2011 PC boot, and the answer is: one byte pair. The `0x55AA` magic at the end of the 512-byte master boot record. That is a format check, not an authenticity check. The 16-bit BIOS power-on self test loaded sector zero of the boot device into memory at `0000:7C00` and jumped [11]. No signature. No measurement. Whatever was at sector zero, ran.

That architectural fact had been the structural lesson of computer-security history for a quarter century. Stoned, the boot sector virus anonymously attributed to a student in Wellington, New Zealand in 1987, demonstrated it without malicious intent: the virus was a prank that displayed "Your PC is now Stoned!" and propagated by writing itself to the boot sector of every disk a victim machine touched [12]. Brain (Pakistan, 1986) [13] and Michelangelo (1991) [14] were the same lesson at scale. The lesson was not that those particular authors were dangerous. It was that any code reaching sector zero ran with implicit privilege.

**Bootkit.** A class of malware that survives operating-system reinstallation and antivirus scanning by infecting code that runs *before* the operating system loads: traditionally the master boot record or the partition's volume boot record, more recently the EFI System Partition or the firmware itself. A bootkit's defining property is that the operating system it boots is one the bootkit itself chooses to load.

The modern bootkit family arrived in 2005 and ran undefended for the next seven years. Derek Soeder and Ryan Permeh of eEye published *BootRoot* at Black Hat USA 2005 [15], a proof of concept that hooked the BIOS interrupt 13h disk-read service before any operating system loaded and intercepted Windows kernel images on the way to memory. Vbootkit (Vipin and Nitin Kumar) followed in 2007, demonstrating the same primitive on Vista [16]. Mebroot (the malware family Sinowal/Torpig used) brought the technique into actual victim populations in the late-2007 era [17]. By 2011, TDL-3 and TDL-4 had pushed the lineage into the millions of infected hosts [8].

The category took its final structural step on 13 September 2011, when Marco Giuliani at Webroot's threat lab disclosed *Mebromi*, the first BIOS rootkit found in the wild. Mebromi targeted Award BIOS firmware. It used the legitimate Phoenix `CBROM.EXE` utility (the Phoenix-Award firmware-image assembly tool, after Phoenix acquired Award in 1998) to splice malicious code into the firmware ROM image, then used the platform's BIOS flashing routine to write the modified ROM back to the chip. On every subsequent boot, the firmware itself reinstalled the rootkit's MBR before any operating system existed to scan for it [18].

> **Note.**
>
> The Mebromi reuse of the legitimate `CBROM.EXE` firmware-assembly utility is the canonical illustration of the architectural problem. The defender's tools and the attacker's tools were the same tools. The firmware-update path had no signature, no measurement, and no policy gate; CBROM was just an executable that knew the Award ROM image format. The fix was not better antivirus. The fix was a hardware root that the OS itself could not rewrite.

The structural argument that Mebromi made unanswerable: there was no measurement endpoint and no signature verifier *anywhere below* the operating system. Every operating-system-level defense was rhetorical against this layer. Kernel-Mode Code Signing, the policy Windows Vista x64 had introduced in 2006 [19], was enforced by code that the bootkit could rewrite before the kernel started checking. Driver Signature Enforcement was a setting the operating system wrote into a memory location the operating system could not yet defend.

Trust must be rooted in something the operating system cannot rewrite. That means the chain has to start before the operating system exists. The next rung is firmware itself.

## UEFI platform initialization: SEC, PEI, DXE, BDS, and where Secure Boot actually lives

If Secure Boot starts at the operating-system loader, which exact piece of firmware decides whether the operating-system loader is allowed to run, and what verifies *that* piece? The answer is a four-phase pipeline that almost no Windows engineer ever writes about. It is also where every modern firmware attack lands.

**UEFI Platform Initialization (PI).** The Unified Extensible Firmware Interface Platform Initialization specification defines the internal architecture firmware uses to bring a system up. It splits boot into four phases: Security (SEC), Pre-EFI Initialization (PEI), Driver Execution Environment (DXE), and Boot Device Selection (BDS). Standard Windows usage of "UEFI" almost always means the externally-visible behavior exposed by BDS and the EFI runtime services, not the multi-phase internal pipeline the firmware uses to get there.

The four phases, per the TianoCore reference flow [20]:

- **SEC.** The Security phase begins at processor reset. On typical x86 PCs, the reset path enters early firmware in SPI flash, with platform-specific mechanisms such as Boot Guard or PSB authenticating it when they are enabled for enforcement. SEC's job in the PI model is to establish the root of trust in the firmware: before any flexible code path can be taken, the firmware has committed to an instruction stream the operating system cannot influence.
- **PEI.** Pre-EFI Initialization brings up DRAM, configures the memory controller, populates Hand-Off Blocks (HOBs) the later phases consume, and dispatches the small drivers needed to reach a state where general firmware code can run. SEC and PEI together are the part of firmware that fits in the few hundred kilobytes of cache-as-RAM the CPU offers before main memory is up.
- **DXE.** The Driver Execution Environment hosts most of what we think of as firmware: the disk drivers, the network stack, the human-interface drivers, the USB stack, and Secure Boot's image verifier. *This is where `LoadImage()` runs db/dbx checks against incoming PE/COFF binaries.* DXE phase code is several megabytes on a modern x86 platform.
- **BDS.** Boot Device Selection reads the `BootOrder` UEFI variable, picks a boot entry, hands the platform off to the operating system loader, and (in normal operation) never runs again until the next reboot.

![Figure: UEFI Platform Initialization. SEC and PEI establish early firmware state, DXE hosts the Secure Boot verifier, and BDS picks the boot variable; where enabled and provisioned, Boot Guard / AMD PSB verifies firmware one rung below SEC.](diagrams/16-secure-boot-firmware-pipeline.svg)

There can be one enforced rung *below* SEC. Intel Boot Guard verifies the firmware via a CPU-microcode-loaded Authenticated Code Module signed by Intel [21]; AMD Platform Secure Boot performs a similar role from the AMD Platform Security Processor (PSP), an ARM-based co-processor embedded on the SoC [22,23]. When configured for enforcement, both run before SEC can begin; when absent, disabled, fused for measurement-only policy, or misprovisioned, they are not a universal Secure Boot invariant. Intel introduced Boot Guard on platforms based on the Haswell processor family (4th-generation Core, Lynx Point PCH) in 2013 [24,21]; the OEM commits the verification key at provisioning, so Boot Guard support is a chipset-and-OEM property rather than a bare CPU-model property [24,22]. AMD's PSB followed on EPYC server parts and was rolled out to Ryzen Pro platforms over the next several years; the PSP itself has been present on AMD client and server parts since around 2013 [23], but PSB is a distinct firmware-signing flow that uses it [22].

> **Note.**
>
> The Windows Hardware Compatibility Program codified UEFI 2.3.1 as the firmware floor for Windows 10 security features [25]. Anything below 2.3.1 cannot host a Secure Boot configuration that Microsoft will certify.
> Where enforcement is used, the keys that anchor those verifications are burned into one-time-programmable fuses, so the OEM commits to a public key when the part ships and cannot rotate it later [24,22]. ESET's 2018 LoJax disclosure recommended Boot Guard explicitly: "if possible, have a processor with a hardware root of trust as is the case with Intel processors supporting Intel Boot Guard (from the Haswell family of Intel processors onwards)" [24].

> **Note.**
>
> Boot Guard's OTP fuses are the canonical example of why hardware-rooted verification cannot have a software-only escape hatch [24,22]. If the OEM's signing key leaks, the fuses cannot be reprogrammed in the field; an attacker with the leaked key can produce firmware that the silicon will accept. This is the structural argument behind moving more root-of-trust firmware onto a Microsoft-serviced cadence: the long-term Pluton direction, not the way DXE Secure Boot works on deployed PCs today.

The conclusion is the part most engineers skip. By the time `bootmgfw.efi` is verified, several megabytes of DXE-phase code have already executed. Anything that compromises the DXE compromises Secure Boot from below: the verifier itself is now the attacker's code. That is the precondition that LogoFAIL exploits, and it is the reason "Secure Boot starts at the OS loader" is the wrong mental model.

NIST recognized the structural problem early. NIST Special Publication 800-147 *BIOS Protection Guidelines* (April 2011) [26] articulated the BIOS-update-signing baseline two years before Boot Guard shipped a hardware-rooted answer. SP 800-147 said only that firmware updates must be signed; it did not say *who* must verify the signing key. Boot Guard and PSB are platform-specific hardware-rooted answers to that gap when enforcement is enabled, with the OEM holding the verification key in OTP fuses.

Now we have a place to put a verifier. The next question is *what* it verifies, and *who* signed the allowlist.

## Secure Boot itself: PK, KEK, db, dbx, and the Microsoft monoculture

Secure Boot is four UEFI variables, one Authenticode hash per binary, and one centralized root of trust. The technical content of this section is not the hard part. The social and operational content (*who* holds which key, and *what happens when a signed binary becomes vulnerable*) is the rest of the chapter.

The four authenticated UEFI variables, defined in UEFI 2.3.1 (April 2011) and refined through the current 2.11 specification (December 16, 2024) [27]:

- **PK**: the Platform Key. The OEM holds the private half. Whoever holds PK can authorize updates to KEK, db, and dbx; on implementations that permit it, that authority can also clear PK and drop the platform into Setup Mode, disabling normal Secure Boot enforcement.
- **KEK**: the Key Exchange Key. Both the OEM and Microsoft hold KEKs. KEK is the trust anchor for db and dbx updates. A KEK-signed update can add or remove entries in db and dbx without touching PK.
- **db**: the signature database. This is the allowlist: hashes the firmware will accept, plus certificates whose signers it will accept. db typically contains a small handful of entries.
- **dbx**: the forbidden signatures database. The denylist: hashes and certs the firmware must refuse, even if they would otherwise pass db.

**Authenticated UEFI Variables (PK, KEK, db, dbx).** Four EFI variables defined by the UEFI specification that together form Secure Boot's trust hierarchy. Each variable is *authenticated*: any update must be signed by a key one rung up the hierarchy. PK signs updates to itself and KEK; KEK signs updates to db and dbx (a PK holder can replace KEK and thereby control db and dbx indirectly). Microsoft requires the Microsoft Corporation KEK CA to be present in KEK on every Windows-certified PC, so that Microsoft can push db and dbx updates without OEM cooperation per device.

The verification algorithm runs every time UEFI calls `LoadImage()` on a PE/COFF binary, in this order:

1. Hash the PE/COFF image. The Authenticode digest excludes the signature directory and the checksum field, so the hash is computed over the parts of the image that should not change between signing and loading [28].
2. If the hash matches a hash in dbx, reject.
3. Else if the signer's certificate chains to a certificate in dbx, reject.
4. Else if the hash matches an entry in db, accept. Else if the signer chains to a certificate in db, accept.
5. Else, reject.

Microsoft's WHCP requires firmware components to be signed with at least RSA-2048 and SHA-256 [27]. That floor is generous by 2026 standards but has held without serious controversy since the original UEFI 2.3.1 release.

![Figure: The LoadImage() decision tree. The unconditional dbx (denylist) checks run first, so a hash in dbx cannot be rescued by also appearing in db.](diagrams/16-secure-boot-loadimage-decision.svg)

The de facto roots for x86 PCs are *two* Microsoft-rooted certificate authorities, both pre-trusted in db on essentially every certified Windows-class system: the **Microsoft Windows Production PCA 2011**, which signs Microsoft's own Windows boot binaries (`bootmgfw.efi`, `bootmgr.efi`, `winload.efi`), and the **Microsoft Corporation UEFI CA 2011**, which signs third-party UEFI binaries: Linux's `shim`, option ROMs, and third-party firmware drivers [29,27]. The rhboot/shim project documents the arrangement: certified PCs are "typically configured to trust 2 authorities for signing UEFI boot code, the Microsoft UEFI Certificate Authority (CA) and Windows CA" [29]. The fact that *both* are Microsoft-rooted is the reason Secure Boot, as deployed on default Windows-class x86 PCs, and "Microsoft is the gatekeeper of which operating systems may boot" are operationally close to the same thing. The UEFI Forum's specification did not require that monoculture. The economics did. The default Windows PC ecosystem converged on those two Microsoft-rooted authorities because they belong to the operating-system vendor whose installer media OEMs ship.

**Microsoft 2011 CAs / Windows UEFI CA 2023.** The X.509 certificate authorities Microsoft uses for Secure Boot. Two CAs from the 2011 family ship pre-installed in db on essentially every Windows-certified PC: the **Microsoft Windows Production PCA 2011** signs Microsoft's own Windows boot binaries, and expires on 19 October 2026; the **Microsoft Corporation UEFI CA 2011** signs third-party UEFI binaries (Linux's `shim`, option ROMs, third-party firmware drivers), and expires on 27 June 2026 [30]. The **Windows UEFI CA 2023** is the successor for the Windows boot-manager signing path; the third-party UEFI CA / shim path is adjacent, but not the same rollout. KB5025885 is specifically the Windows boot-manager revocation and CA-transition program responding to CVE-2023-24932, and it is still rolling out under phased enrollment via monthly Windows Updates as of 2026 [31].

> **The shim escape hatch.**
>
> Linux's path through Secure Boot runs through `shim.efi`, a small bootloader Matthew Garrett released on November 30, 2012: his last day at Red Hat. The trick is structural: Microsoft signs `shim` itself; `shim` is shipped on the install media of every major Linux distribution; once running, `shim` validates a distribution-signed `grubx64.efi` (or kernel) using a key the distribution embeds, *or* a Machine Owner Key (MOK) the user has enrolled at install time. Garrett credits the MOK design to engineers at SUSE [32]. The arrangement is the open-source community's pressure valve against the Microsoft monoculture: Linux still boots on Secure Boot hardware because Microsoft signs one bootloader that delegates trust to a community-managed key store. It also explains why Linux dual-boot installs can break when older shim builds or their signing paths are revoked.

The dbx variable carries the operational weight of the system. If a signed bootloader is found to be vulnerable, the only blocking remedy is to add its hash to dbx. dbx lives in NV-RAM; on commodity Windows PCs the storage budget is roughly 32 KB total [29].

> **Note.**
>
> The 32 KB figure comes from the rhboot/shim project's SBAT documentation, which notes that the BootHole disclosure of July 2020 (a single GRUB vulnerability requiring revocation of three certificates and roughly 150 image hashes) consumed approximately 10 KB of dbx in one event. That is one third of the available capacity, used up by one CVE.
> Linux distributions and Windows share the same dbx region. A botched update can refuse to validate a bootloader that the platform actually needs, and there is no remote rollback for a brick-on-write to dbx. The attack-catalog section will show what happens when dbx revocation lags behind a CVE.

The Windows boot-manager CA-2023 transition is therefore not a routine certificate rotation. The original 2011 Windows boot-manager certificate (**Microsoft Windows Production PCA 2011**, the CA that signs `bootmgfw.efi`) expires on 19 October 2026; the adjacent third-party **Microsoft Corporation UEFI CA 2011** expires earlier, on 27 June 2026 [30]. Microsoft's industry-wide Windows UEFI CA 2023 rollout started May 2023 with KB5025885, the patch advisory that paired with CVE-2023-24932, and is on track to be, in Microsoft's own framing, one of the largest coordinated security maintenance efforts the Windows install base has ever seen [31]. The phasing, as published: enroll the new CA in db; sign new Windows boot managers with it; enroll new dbx entries to revoke older signed-but-vulnerable Windows boot-manager binaries; finally, revoke the relevant 2011 Windows boot-manager trust. The published cautionary text is unambiguous: once the irreversible mitigation step is enabled on a device, "it cannot be reverted if you continue to use Secure Boot on that device. Even reformatting of the disk will not remove the revocations if they have already been applied" [31].

Verification is a one-shot signature check at firmware boundaries. The chain still has to extend all the way to userland. Microsoft's name for what comes next is *Trusted Boot*. The attack catalog returns to the lifecycle problem this creates: *patched is not revoked*.

## Trusted Boot: bootmgfw.efi, winload.efi, and the Windows-specific chain

Secure Boot can answer "is this `.efi` file in our allowlist?" It cannot answer "does each kernel-mode driver loaded after this `.efi` file satisfy Windows code-integrity policy?" That second question is what Trusted Boot exists to answer.

**Trusted Boot.** Microsoft's term for the post-firmware portion of the verified boot chain. UEFI Secure Boot validates `bootmgfw.efi`. `bootmgfw.efi` validates `winload.efi`. `winload.efi` validates `ntoskrnl.exe`, the Hardware Abstraction Layer, every boot-start driver, and the ELAM driver. `ntoskrnl.exe` validates every driver loaded thereafter against the active code-integrity policy. Trusted Boot is therefore the Microsoft policy enforcement chain layered *on top of* Secure Boot's firmware-side verifier; it is what extends the signature check past the operating-system loader into kernel mode.

The mechanics, after the firmware hands control to `bootmgfw.efi`: the boot manager reads the Boot Configuration Data store, locates `winload.efi` (or `winresume.efi` for resuming from hibernation), and enforces the boot-time integrity policy on every component it loads [10]. The verifier handoff, however, is more interesting than the Microsoft Learn paragraph suggests. It runs in three stages.

**Stage A: `winload`'s in-image `bootlib` verifier.** `winload.efi` does not call kernel-mode `ci.dll` to validate boot images. It carries its own boot-time code-integrity verifier inside the `bootlib` boot library shared with `bootmgr`. Reverse-engineering work on the Elysium bootkit research framework reconstructed the call chain inside `winload.efi`: `OslLoadDrivers` → `OslLoadImage` → `LdrpLoadImage` → `BlImgLoadPEImageEx` → `ImgpLoadPEImage`, with `ImgpValidateImageHash` performing the Authenticode digest check against the trusted boot policy embedded in `winload` itself [33]. Boot-start drivers, `ntoskrnl.exe`, the Hardware Abstraction Layer, and the ELAM driver all flow through this chain before kernel mode is alive to do anything about it.

**Stage B: handoff via `LOADER_PARAMETER_EXTENSION`.** When `winload.efi` is done validating, it has to hand the validated state across the loader-kernel boundary. The mechanism is `LOADER_PARAMETER_EXTENSION` (LPE), the under-documented structure that hangs off the `LOADER_PARAMETER_BLOCK` whose address the loader passes to the kernel.

> **Note.**
>
> The LPE structure has been Microsoft-internal in every shipping Windows release; the public reference Geoff Chappell maintains is the canonical third-party reverse-engineering of its layout across Windows builds. New fields are added at the tail of the structure when shipping features need to communicate state across the loader/kernel boundary. The fact that Smart App Control's CI state needed two new LPE fields is a small but telling indicator of how much policy state Trusted Boot now carries.
> Geoff Chappell's reference describes the LPE as "part of the mechanism through which the kernel and HAL learn the initialization data that was gathered by the loader" [34]. The structure has grown across Windows builds; with Smart App Control on Windows 11 22H2, two new fields (`CodeIntegrityData` and `CodeIntegrityDataSize`) were added so that the loader-validated CI state, including the active SiPolicy and the pre-validated boot-start driver list, would survive the handoff intact [35].

**Stage C: kernel-mode `ci.dll` continuation.** Only after `ntoskrnl.exe` is itself running does the kernel-mode `ci.dll` come into play. It picks up the SiPolicy state from the LPE and continues the same code-integrity policy enforcement on every kernel-mode image loaded after the loader's window closes: principally via the `Se`-prefixed validation routines that the kernel's image-load notification routines call into. From that point, every subsequent driver load goes through the same code-integrity gate. The `bootlib` → LPE → kernel-mode `ci.dll` decomposition is the underlying mechanism Microsoft's high-level documentation collapses into a single sentence:

> The Windows bootloader verifies the digital signature of the Windows kernel before loading it. The Windows kernel, in turn, verifies every other component of the Windows startup process, including boot drivers, startup files, and your anti-malware product's early-launch anti-malware (ELAM) driver.: Microsoft Learn [10]

Trusted Boot is therefore the *Windows-specific* extension of the verifier into kernel mode. UEFI Secure Boot is platform-agnostic; it ships in db on every certified PC. Trusted Boot is the policy engine that reuses the firmware-side trust anchor and walks it forward into `ntoskrnl.exe`. The mechanism for *how* SiPolicy is parsed, how publisher rules are evaluated, and how the kernel's code-integrity state machine handles attempts to load binaries outside policy, lives in the Code Integrity chapter (Chapter 8) and is not redefined here [19].

There is a failure mode you can see coming. If the trusted boot manager itself is signed but vulnerable, the chain still validates, the policy still enforces, and the entire defense is bypassed. The signature is correct; the code path is what is wrong. The attack-catalog section will show what happens when an older `bootmgfw.efi` revision contains a memory-map manipulation flaw that lets attacker-controlled data flow before the SiPolicy enforcement engine is up. That is the BlackLotus failure. For now, hold the framing: Trusted Boot's guarantee is policy-constrained code integrity for the boot path, not that every validly signed binary is secure or Microsoft-authored.

Verification can stop loading bad code. It cannot prove that good code was loaded. For that we need a parallel rail.

## Measured Boot: SRTM, the TPM event log, and PCR 0-7+11 in order

Verification stops bad code from running. *Measurement* makes sure you can prove, after the fact, what code did run. The two rails do not protect against the same thing. This is the chapter's mechanism-densest section, and the place a few key terms have to be exactly right.

**Static Root of Trust for Measurement (SRTM).** A boot-time chain of cryptographic measurements anchored in a Core Root of Trust for Measurement (CRTM): a code segment in the platform's flash that is implicitly trusted because it runs first and is immutable, and that performs the first measurement into the TPM before any flexible code runs. SRTM extends one PCR per component as the chain unfolds, producing a tamper-evident log of exactly which firmware, boot manager, and kernel the platform launched. The measurement does not stop bad code; it records what code ran so a verifier can decide later.

The TPM extend primitive is the cryptographic core. The TPM never overwrites a PCR. When the platform asks the TPM to extend PCR `N` with a measurement `m`, the TPM does:

$$\mathrm{PCR}[N]:= H\bigl(\mathrm{PCR}[N] \,\Vert\, m\bigr)$$

where `H` is the bank's hash algorithm and `||` is byte concatenation [36]. The TPM 2.0 specification was finalized by the Trusted Computing Group on 9 April 2014 [37]. The mechanism guarantees that any later PCR value is a function of every prior measurement in the order it was extended. You cannot rewind, and you cannot reorder. TPM 2.0 PC-client systems expose multiple PCR banks in practice; the Bitpixie analysis uses the SHA-256 bank for the examples in this chapter [36,38]. The full TPM `extend` mechanics are covered in the TPM chapter (Chapter 2); we do not redefine them here [39].

The PCR allocation, per the TCG PC Client Platform Firmware Profile, corroborated against the SySS Bitpixie writeup [36] and Microsoft Learn [9]:

| PCR | Extended by | What it measures |
|-----|-------------|------------------|
| 0 | CRTM, SEC, PEI | SRTM core firmware code (BIOS/UEFI) |
| 1 | PEI / DXE | Host platform configuration (CPU microcode, NVRAM settings) |
| 2 | DXE | UEFI driver and application code (option ROMs) |
| 3 | DXE | UEFI driver and application configuration / data |
| 4 | DXE / BDS | EFI boot applications / boot managers in the boot path; `bootmgfw.efi` lands here |
| 5 | BDS | Boot manager code config and data; GPT; boot attempts |
| 6 | DXE / OEM | Host platform manufacturer specific |
| 7 | DXE | State of Secure Boot: PK, KEK, db, dbx hashes; the `SecureBoot` variable; Secure Boot authority events for UEFI images |
| 11 | `bootmgfw.efi` | BitLocker access control: locked after VMK is obtained |

![Figure: The SRTM extend sequence. Each early-boot stage measures code and policy into the TPM's PCRs, with PCR[4] and PCR[7] accumulating across multiple extends.](diagrams/16-secure-boot-srtm-extend.svg)

PCR[7] deserves a section of its own. On modern Windows, *PCR[7] is the canonical seal target* for BitLocker. A protector sealed to PCR[7] unwraps cleanly across firmware updates, microcode revisions, and option-ROM changes, because PCR[7] reflects Secure Boot policy state: the keys in PK, KEK, db, dbx, the `SecureBoot` variable, and Secure Boot authority events for UEFI images. PCR[0..4] are too volatile for sealing on a real fleet because every BIOS update changes them. PCR[7] changes only when Secure Boot policy itself changes [36,40]. The full BitLocker key hierarchy is documented separately [41]; here we are placing PCR[7] in the chain.

> **Key idea.**
>
> Verification stops bad code. Measurement records what code ran. Neither rail is sufficient alone. Modern Windows boot integrity needs both rails reaching the same place (the kernel and the Secure Kernel) before user-mode runtime defenses take over.

The TCG event log makes the measurement chain useful for more than sealing. Every `extend` is logged through the TCG2 EFI Protocol with the hash, the algorithm, and a description of what was measured. A verifier (BitLocker locally; an attestation service remotely) can replay the log to recover *which binary hashed to which PCR value*, and (if the replay does not match the live PCRs) detect tampering. Microsoft Learn describes exactly that path: "the PC's firmware logs the boot process, and Windows can send it to a trusted server that can objectively assess the PC's health" [9].

There is a second root of measurement that sidesteps the firmware-trust regress entirely. DRTM (Dynamic Root of Trust for Measurement) is late-launched after firmware boot, via Intel TXT's `GETSEC[SENTER]` instruction or AMD's `SKINIT`. It resets PCR[17..22] at locality 4 and re-anchors a measurement chain in a vendor-controlled allowlistable module that does not depend on the DXE phase having been clean [21,40]. Microsoft documents the motivation in plain language:

> There are thousands of PC vendors that produce many models with different UEFI BIOS versions. This creates an incredibly large number of SRTM measurements upon bootup. [40]

The argument: SRTM measurements are platform-specific. An attestation service that wants to know whether a given device booted clean must hold an allowlist of SRTM measurements covering N OEMs *M models* K firmware revisions. The allowlist explodes; the blocklist is asymmetric in the attacker's favor. DRTM collapses the allowlist by defining one small, well-known late-launched measurement chain that the attestation service can recognize across every Secured-core PC.

**Dynamic Root of Trust for Measurement (DRTM).** A late-launched measurement chain that re-anchors trust *after* firmware boot, by using a CPU instruction (`GETSEC[SENTER]` on Intel, `SKINIT` on AMD) to reset a designated set of PCRs and execute a small, vendor-controlled measured launch module. DRTM is Microsoft's answer to the SRTM allowlist explosion. It powers System Guard Secure Launch, which Windows 10 1809 introduced; on supported hardware, the late-launched module brings up the hypervisor and Secure Kernel from a trust anchor that the firmware cannot influence.

The DRTM PCR allocation is parallel to SRTM but lives in a separate range, PCR[17..22], reset only by the late-launch event. Per the TCG PC Client Platform Firmware Profile (corroborated against the Wikipedia Trusted Execution Technology mirror, since TCG returns HTTP 403 to non-browser fetches) and Microsoft's System Guard documentation [21,40]:

| PCR | Reset by | What it measures |
|-----|----------|------------------|
| 17 | `GETSEC[SENTER]` / `SKINIT` at locality 4 | DRTM-event measurement and Launch Control Policy hash extended by the SINIT ACM (Intel TXT) or the Secure Loader block hash (`SKINIT` on AMD) |
| 18 | locality 4 | Trusted-OS start-up code (the Measured Launch Environment itself) |
| 19 | locality 4 | Trusted-OS measurement, e.g., OS configuration |
| 20 | locality 4 | Trusted-OS measurement, e.g., OS kernel and other code |
| 21 | locality 4 | Reserved for and defined by the Trusted OS |
| 22 | locality 4 | Reserved for and defined by the Trusted OS |

The reset semantics are the load-bearing detail. PCR[0..15] are append-only after platform reset; they cannot be cleared without rebooting the box. PCR[16] and PCR[23] are debug PCRs and resettable rather than ordinary boot-history registers. PCR[17..22] are different again: they can be reset *during runtime*, but only by an atomic late-launch event. That asymmetry is what makes DRTM's anchor verifiable [21,36].

The mechanism that enforces it is *TPM locality*. Locality is a side-channel attribute on every TPM command identifying which entity issued the request. Locality 0 is general OS and application traffic. **Locality 4 is assertable only by the CPU itself**, during the atomic `GETSEC[SENTER]` (Intel TXT) or `SKINIT` (AMD) sequence. The TPM accepts a `Reset` of PCR[17..22] only when the request arrives tagged with locality 4. No software running outside the late-launch instruction can forge that tag. That is the structural reason DRTM's late-launch is verifiable rather than forgeable [21].

The asymmetry pays off for an attestation service. If a remote verifier reads PCR[17] and finds it still at its power-on value of all ones (`0xFF...FF`), DRTM did not happen on this boot. If it reads PCR[17] and finds it equal to the iterated extend $\mathrm{PCR}[17]:= H\bigl(0 \,\Vert\, H(\text{SINIT\_ACM\_hash} \,\Vert\, \text{LCP\_hash})\bigr)$ (or, more accurately, the chain of extends the SINIT ACM logged), a CPU-vendor-signed SINIT Authenticated Code Module seeded the chain, and the value is recomputable by the verifier from the published, signed SINIT ACM and the platform's Launch Control Policy [21,40]. The verifier's allowlist for DRTM measurements is bounded by the small set of CPU-vendor-signed measured-launch modules in circulation (SINIT ACMs on Intel TXT; the Secure Loader block measured directly by `SKINIT` on AMD): not by the cross-product of OEMs, models, and firmware revisions.

We now have two rails of trust ready to converge in the kernel. The next thing the kernel has to do is hand control to defenders that can keep the chain alive into runtime.

## ELAM, the kernel, and the Secure Kernel bring-up: where the chain ends

Trusted Boot has enforced boot-time code-integrity policy along the path. Then what? The chain still has to outlive the boot.

**Early Launch Anti-Malware (ELAM).** A specially-signed driver class introduced in Windows 8 (2012) that loads as the *first* boot-start driver (ahead of every other boot-start driver) and classifies each subsequent boot-start driver as *Good*, *Bad*, *Unknown*, or *BadButCritical* for the kernel/code-integrity load path to consult [42,43,44]. ELAM's classification influences whether Windows loads the driver. The ELAM driver itself is a Microsoft-signed binary in the `Early-Launch` service-start group and is itself measured into the SRTM chain; the user-mode anti-malware service that consumes its classification events runs as a Protected Process Light (PPL).

ELAM exists for a specific reason. The boot-start group includes anti-malware, device, and disk drivers that have to load before the rest of the operating system. Before Windows 8, those drivers all loaded in an undefined order, with no anti-malware product running yet. A bootkit that survived the kernel's signature check (or a driver that was signed but malicious) had a window in which nothing was watching. ELAM closed that window by ordering one driver (a Microsoft-signed AM driver) as the first boot-start driver, and giving it the right to classify those drivers as they loaded [42]. ELAM is itself a boot-start driver; the Microsoft documentation specifies the INF requirement plainly: "An ELAM Driver advertises its group as 'Early-Launch'" [43]. The associated user-mode anti-malware service runs as a Protected Process Light (PPL), the mechanism the Protected Process Light chapter (Chapter 10) develops in full, so even SYSTEM-privileged user-mode code cannot inject into it [42,19].

> **Note.**
>
> The classification surface ELAM exposes is the four-element set Good / Bad / Unknown / BadButCritical, enumerated in Microsoft's `BDCB_CLASSIFICATION` reference (ntddk.h) as `BdCbClassificationKnownGoodImage`, `BdCbClassificationKnownBadImage`, `BdCbClassificationUnknownImage`, and `BdCbClassificationKnownBadImageBootCritical` (the ELAM driver requirements page itself only enumerates three classes in prose; the fourth lives in the enum reference) [43,44]. The fourth category exists because some drivers are required for the system to boot; the AM driver's verdict on those is advisory rather than blocking. Defender ships the ELAM driver in Windows; Microsoft's interface allows third-party AM products to ship their own [42].

The kernel itself does the next set of jobs. `ntoskrnl.exe` initializes memory protections and DMA defenses. Kernel DMA Protection enables the IOMMU (Intel VT-d or AMD-Vi) so that PCIe peripherals either DMA only to memory their compatible driver has assigned (DMA-Remapping-compatible drivers, enumerated and started normally) or are blocked from starting and performing DMA entirely until an authorized user signs in or unlocks the screen (DMA-Remapping-incompatible drivers, the user-presence-gated default); both regimes block the drive-by-DMA pattern that targets arbitrary kernel memory and defend against malicious Thunderbolt peripherals [45]. The Driver Block List, enforced at code-integrity load time, refuses to load a recognized set of vulnerable signed drivers (the canonical example is *gdrv2.sys*); details are in the Code Integrity chapter (Chapter 8) [19]. HVCI (Hypervisor-Enforced Code Integrity, also called Memory Integrity) is loaded inside the Secure Kernel and enforces W^X on all kernel-mode memory; details are in the Secure Kernel chapter (Chapter 6) [46].

Then the Secure Kernel comes up. `securekernel.exe` and `skci.dll` initialize in Virtual Trust Level 1: a Hyper-V-managed isolation domain that the normal Windows kernel in VTL0 cannot read or write. The first Trustlet is LSAIso, the isolated process Credential Guard (the Credential Guard chapter, Chapter 15) uses to hold NTLM hashes and Kerberos tickets out of reach of any kernel-mode attacker [46]. Control returns to the normal kernel; the user-mode tail begins.

![Figure: Kernel and Secure Kernel bring-up: ntoskrnl loads ELAM first and launches the Secure Kernel into the isolated VTL1, where LSAIso is the first Trustlet.](diagrams/16-secure-boot-kernel-bringup.svg)

The user-mode tail is not security-cryptographic per se. SMSS (the Session Manager) loads system DLLs and starts the first Win32 subsystem session. `wininit.exe` initializes the LSA, the Service Control Manager, and the Local Session Manager. `winlogon.exe` paints the credential UI, calls into Windows Hello (the Windows Hello chapter, Chapter 20) [47] if applicable, and authenticates the user. `userinit.exe` runs the logon scripts and launches `explorer.exe` [10]. From the boot-integrity perspective, `userinit` is the moment the static-time guarantees of Trusted Boot end and the runtime defenses (Defender, EDR, attestation) take over.

We have walked the chain end to end. The next question is: when did this chain *actually start working*?

## The breakthroughs that made the chain land (2014-2024)

*Secure Boot existed* in 2012. *Secure Boot worked* (in the sense of defending most of what it claims to defend) only after roughly a decade of operational fixes that almost nobody outside Microsoft and a handful of OEMs ever wrote about. Four breakthroughs deserve naming. The matrix below collates them by *layer fixed* and *fix-delivery vehicle* before the prose treatments that follow.

| # | Breakthrough | Year | Layer it fixed | Fix-delivery vehicle |
|---|--------------|------|----------------|----------------------|
| B1 | PCR[7] becomes the canonical BitLocker seal target on modern Windows fleets | Windows 8.1 / Windows 10 era | Sealing brittleness; PCR[0..4] churn vs. firmware-revision cadence | Windows servicing + BitLocker policy default change [36,40] |
| B2 | Windows boot-manager CA rotation away from Microsoft Windows Production PCA 2011 | May 2023 - October 2026 | Revocation gap (BlackLotus / Baton Drop) | KB5025885 / CVE-2023-24932 multi-year, opt-in dbx push and Windows UEFI CA 2023 enrollment [31,30] |
| B3 | Secure Kernel becomes the launch destination | Win10 2015 - Win11 2021 | "Kernel signed" is insufficient (TDL-4 lesson) | OS feature ship and WHCP requirement; HVCI / Driver Block List default-on by 2024 [10,46] |
| B4 | Pluton arrives as a Microsoft-firmware-authored TPM RoT | Nov 2020 announcement; Q1 2022 Ryzen 6000 launch | LPC/SPI bus-sniffing class against discrete TPMs; OEM patch-cadence latency for fTPM/PTT firmware | Windows-Update-delivered Pluton firmware (alongside UEFI capsule), Rust-based on 2024+ AMD/Intel parts [6,48,49] |

The first row is operational, not architectural: PCR[7] becoming the canonical BitLocker seal target on modern Windows fleets [36,40]. Before PCR[7]-centric sealing, BitLocker deployments commonly depended on PCR[0..4]: firmware code, platform configuration, option ROMs, option-ROM configuration, and boot-manager hashes. Many UEFI updates changed PCR[0..4] and forced BitLocker into recovery, which forced an IT staffer to find the recovery key, which was annoying enough to make people turn BitLocker off. PCR[7] sealing decoupled the BitLocker protector from the firmware-revision churn and made Measured Boot durable in practice. This is the operational fix that made Measured Boot actually worth running on a fleet of thousands of laptops with regular UEFI capsule updates.

The second row is the Windows boot-manager CA rotation away from Microsoft Windows Production PCA 2011, which began in May 2023 with KB5025885 and CVE-2023-24932 and is on track to complete in late 2026 [31]. This was the first serious Windows boot-manager dbx housekeeping in a decade. The relevant point: the fix had to be a *program*, not a hotfix, because dbx is too small to handle a one-shot revocation of a CA-rooted set without bricking recovery, PXE, and some dual-boot paths. The Windows UEFI CA 2023 rollout phases the work across four years; third-party UEFI CA and shim maintenance remains adjacent but separate.

The third was VBS and the Secure Kernel becoming the launch target the boot chain was actually defending. Without the Secure Kernel as a destination, Trusted Boot's guarantee ended at "the kernel is signed", which TDL-4 had already shown was insufficient. A signed kernel is of limited use if the SYSTEM-privileged user-mode code that follows can rewrite kernel memory through a vulnerable signed driver. The Secure Kernel arrived in Windows 10 1507 (2015) and matured into its enforced-by-default form in Windows 11 (2021), at which point the chain had a hardware-isolated destination that even a SYSTEM-level attacker could not reach without a hypervisor exploit [46].

The fourth is still landing. Pluton, the cryptoprocessor whose firmware Microsoft (not the OEM) ships and updates, was announced in November 2020 and reached the x86 PC market with AMD Ryzen 6000 in Q1 2022 [48,49]. Pluton is not yet ubiquitous, and its Secure Boot story is pending: as of 2026, Pluton ships as a TPM 2.0 implementation [7], not as a replacement verifier. The Pluton section unpacks why the Microsoft-firmware-on-silicon-Microsoft-doesn't-own model matters more than the part numbers do.

These were the operational fixes. The architectural breaks they were responding to are the next section.

## The boot-chain attacks that actually worked

There has never been a public Secure Boot attack that broke the cryptographic primitive. The Windows boot-manager attacks cluster around one gap (fixing a vulnerability before revoking the signed binaries that carried it) while other failures sit below the verifier, in disabled/custom trust, or in TPM-only downgrade paths. The CVE numbers change. The taxonomy does not.

*Scope note: LoJax (ESET, September 2018) was the first real-world UEFI rootkit deployed in the wild, but it operates at the SPI flash layer (below Secure Boot's signature verification chain) and is therefore outside the scope of this table. The table focuses on attacks on the Secure Boot signature-enforcement chain itself.*

| Attack | Year | Rung broken | Prerequisite | dbx state at disclosure | Fix path |
|--------|------|-------------|--------------|-------------------------|----------|
| ESPecter | 2021 | ESP-resident `bootmgfw.efi` patching | Secure Boot disabled | n/a | Enable Secure Boot |
| FinSpy UEFI | 2021 | bootmgfw.efi replaced on ESP | Secure Boot disabled | n/a | Enable Secure Boot |
| BlackLotus / CVE-2022-21894 (Baton Drop) | 2022-23 | Signed-but-vulnerable older bootmgfw | Patched but unrevoked old binaries | Old binaries not revoked | dbx update via KB5025885 |
| Bitpixie / CVE-2023-21563 | 2022-24 | PXE soft-reboot leaks BitLocker VMK | TPM-only BitLocker; LAN + keyboard | n/a (no signature break) | Pre-boot PIN; KB5025885 (dbx revocation of the downgrade path) |
| LogoFAIL | 2023 | DXE-phase image-parser RCE | UEFI logo customization accepting attacker BMP | n/a | OEM UEFI updates |
| Bootkitty | 2024 | Self-signed PoC; Secure Boot disabled or LogoFAIL | Linux target | n/a | Enable Secure Boot; patch LogoFAIL |
| WinRE / CVE-2024-20666 family | 2024 | Recovery Environment downgrade | TPM-only BitLocker; reachable WinRE | n/a | Servicing stack updates |

ESPecter (ESET, October 2021) [50] is the simplest case. It is an ESP-resident bootkit that bypasses Driver Signature Enforcement to load its own unsigned kernel driver, but only on systems with Secure Boot disabled. ESPecter is in the table to make the category visible: the ESP is a writable FAT partition with no signature on the contents, and any malware that can write to the ESP and persuade the firmware to boot from a different `bootmgfw` path can win on a non-Secure-Boot system. The fix is to turn Secure Boot on.

FinSpy (Kaspersky, September 2021) [51] is the same attack family carrying an actual nation-state-grade payload. Kaspersky's GReAT analysis names the mechanism plainly: "All machines infected with the UEFI bootkit had the Windows Boot Manager (`bootmgfw.efi`) replaced with a malicious one." The malicious `bootmgfw` injected code into `winlogon.exe` for persistence. Again, Secure Boot disabled was the precondition. FinSpy was the proof that the ESP-resident category had real-world tradecraft attached, not just academic interest.

BlackLotus (advertised on hacking forums from at least October 2022 [1]; ESET writeup 1 March 2023) is the case that defines the modern era [1,3]. BlackLotus does not disable Secure Boot. It chain-loads a legitimately-signed but vulnerable older `bootmgfw.efi` revision. The vulnerability is CVE-2022-21894, nicknamed *Baton Drop*: an older boot manager honored a `truncatememory` setting that removed blocks of memory containing serialized data structures from the memory map. The Wack0 PoC repository describes the primitive: "Windows Boot Applications allow the truncatememory setting to remove blocks of memory containing 'persistent' ranges of serialized data from the memory map, leading to Secure Boot bypass" [3]. The chain: boot the legitimately-signed older bootmgfw; trigger Baton Drop; install a malicious SiPolicy that disables further checks; load an unsigned kernel driver; persistently disable HVCI, BitLocker, and Defender from below the trusted-boot horizon. Microsoft's incident-response guide for BlackLotus enumerates six classes of detection artifact: recently-written ESP files, staging directories, registry entries, event-log evidence of policy changes, network indicators, and BCD-log modifications [52]. The NSA published a mitigation guide on 22 June 2023 [53]. ESET's epitaph is the chapter's recurring quote:

> Exploitation is still possible as the affected, validly signed binaries have still not been added to the [UEFI revocation list].: Martin Smolar, ESET, March 2023 [1]

![Figure: The BlackLotus exploit chain. Every enforced step accepts a Microsoft-signed binary; Baton Drop (CVE-2022-21894) then disables HVCI, BitLocker, and Defender from below the trusted-boot horizon.](diagrams/16-secure-boot-blacklotus-chain.svg)

The "disables HVCI / BitLocker / Defender from below the trusted-boot horizon" framing in the caption is verbatim from the ESET disclosure and is reinforced by Microsoft's own incident-response guide [1,52].

Bitpixie / CVE-2023-21563 [2,36] is BlackLotus' twin in BitLocker space. The vulnerability was discovered by `Rairii` in August 2022; Thomas Lambertz of Neodyme published a public PoC at 38C3 in December 2024. The mechanism is a downgrade. The attacker boots the target machine into Windows' PXE network-recovery soft-reboot path, which loads a Microsoft-signed but older `bootmgfw.efi` revision. That older revision does not erase the BitLocker VMK from physical memory before the PXE soft-reboot hands off, leaving the VMK in RAM where the chained payload (a signed Linux PE or downgraded WinPE) can dump it. The combination of TPM-only BitLocker (no pre-boot PIN), a Microsoft-Account-defaulted Windows 11 install (which biases toward TPM-only encryption), and physical access to a network port and keyboard, decrypts the disk in minutes. Lambertz' framing: "All an attacker needs is the ability to plug in a LAN cable and keyboard to decrypt the disk" [2]. Bitpixie does not break Secure Boot. It exploits the same operational invariant (old-but-signed binaries still validate) in a different protection domain.

> **TPM-only BitLocker post-Bitpixie.**
>
> For devices whose threat model includes unattended physical access, TPM-only BitLocker is no longer a defensible default once Bitpixie's PoC is public; the attack reduces to a LAN cable and a keyboard. See the practical guide's `Replace TPM-only BitLocker` bullet for the pre-boot-factor fix list [2,31].

Bootkitty (ESET, 27 November 2024) [4] closes a symmetry. Twelve years after Andrea Allievi's September 2012 PoC (the first UEFI bootkit designed for Windows 8 [54]) Bootkitty is the first UEFI bootkit aimed at Linux. Bootkitty was uploaded as a self-signed PoC, so on systems with Secure Boot enabled, it does not load unless the attacker's certificate has been enrolled in the Machine Owner Key (MOK) list: either by a user via `mokutil` (the ordinary Linux path), by a prior compromise enrolling the cert, or by chaining LogoFAIL (CVE-2023-40238) to inject a rogue MOK certificate from a malicious BMP, as Binarly demonstrated [5]. Bootkitty patches kernel-image-integrity functions and pre-loads ELF binaries via `init`. ESET later updated the attribution: an analysis posted in early December 2024 traced the build to a Korean Best of the Best (BoB) student project. The structural lesson is platform-orthogonal: Secure Boot's gaps live in the firmware and revocation surfaces, not in any one operating system.

> **Bootkitty closes the symmetry.**
>
> The Allievi 2012 ITSEC PoC was *the first UEFI bootkit*, full stop: a research artifact that demonstrated, on Windows 8, the same trick BootRoot had demonstrated on the Windows NT/2000/XP MBR seven years earlier. Twelve years later, Bootkitty is the first UEFI bootkit *for Linux*, also a research artifact. The arc closes a symmetry: UEFI's verifier is platform-agnostic, so its weaknesses are too. A LogoFAIL-style image-parser bug in DXE compromises Secure Boot whether the operating system above it is Windows or Ubuntu. The twelve-year gap is best read as evidence about attacker incentives and deployment targets, not as evidence that the verifier was structurally safer on Linux.

LogoFAIL (Binarly REsearch, Black Hat EU 2023; CVE-2023-39539, CVE-2023-40238, CVE-2023-5058; advisory BRLY-2023-006) is the most architectural of the breaks because it compromises the verifier itself. The DXE phase parses a customizable boot logo image (the OEM splash screen displayed on power-on) and the parser is a piece of firmware code accepting an attacker-controlled input. Binarly demonstrated parser bugs in the BMP, GIF, JPEG, PCX, and TGA decoders shipped in reference code by all three major Independent BIOS Vendors (AMI, Insyde, and Phoenix) across hundreds of consumer and enterprise devices [55]. A successful exploit gives the attacker code execution at the DXE phase, which is *below* Secure Boot's `LoadImage()` verifier. From DXE, the attacker can do whatever they want before the operating-system loader runs. Bootkitty later carried a LogoFAIL exploit (CVE-2023-40238) to inject a rogue MOK certificate from a malicious BMP, demonstrating the chain end to end [5].

Finally, the WinRE downgrade family is the smaller cousin of the bigger story [56,57,58]. The Recovery Environment is a Windows partition with its own boot path; when an older signed boot manager remains reachable, a downgrade can route a BitLocker-protected device into attacker-controlled recovery code. The attack does not break the Secure Boot chain; it routes around the expected Windows path. The point of including it in this catalog: it is another instance of the dbx-revocation-by-hash limit. As long as an older signed binary exists and is reachable, Secure Boot's verifier will validate it.

Across the Windows boot-manager cases, the operational invariant is the same: the gap between *patched* and *revoked* is wide, and dbx is too small to close it. LogoFAIL, disabled Secure Boot, custom trust, and TPM-only downgrades are different failure classes. The next section examines whether anything can shrink the Windows revocation gap.

## Theoretical limits, open problems, and the Pluton pivot

If the dominant Windows boot-manager breaks are operational, why has nobody fixed the operations? Because the operational bounds are themselves theoretical.

Six structural limits.

**The verifier-of-verifiers regress.** Secure Boot's verifier is firmware code that itself must be trusted. Where enabled for enforcement, Boot Guard and AMD PSB push that root one rung deeper, into silicon ROM and OTP fuses [22,21]. Pluton moves the TPM-class root and its firmware update cadence onto Microsoft-serviced silicon today; it does not replace the DXE verifier. There is no software-only bottom turtle. Every architecture in the field has *some* layer that is trusted because there is no further layer to which trust can be deferred. The engineering question is *which party* owns that layer (OEM, Intel, AMD, or Microsoft via Pluton) and *on whose update cadence* the layer can be patched. IOActive's 2024 review of AMD PSB found that "various major vendors fail to" configure PSB correctly [22], which is the kind of operational failure mode no cryptographic primitive can fix.

**Why dbx revocation is hard.** dbx is small, shared with Linux, vendor-implemented, and a brick-risk if mismanaged. The list stayed nearly empty for a decade until BlackLotus forced KB5025885's multi-year program [59]. SBAT (Secure Boot Advanced Targeting), the partial answer in the rhboot/shim project [29], revokes by *generation number* rather than by image hash. SBAT works by embedding a CSV-formatted vendor-and-component-version table in every shim-signed binary; when the `SbatLevel` UEFI variable records "minimum acceptable shim generation is 4", shim refuses every older shim, which still hashes correctly but is too old. SBAT collapses tens of revocation events that would each consume hundreds of bytes of dbx into a single small metadata bump. The UEFI Forum has, since 2024, deferred to the canonical Microsoft-managed `secureboot_objects` GitHub repository [60] as the source of truth for KEK, db, and dbx contents.

**SBAT (Secure Boot Advanced Targeting).** A revocation scheme designed by the rhboot/shim project to address dbx capacity exhaustion. Instead of revoking each vulnerable signed binary by Authenticode hash (which consumes ~32 bytes of dbx per binary), SBAT revokes by *generation number*: each signed component carries a CSV-formatted version table; shim compares it against a minimum generation recorded in the `SbatLevel` UEFI variable and refuses older builds, without consuming dbx capacity (firmware itself still enforces only db and dbx). SBAT is the project's structural answer to the cohort-revocation problem the earlier dbx-capacity note quantifies.

> **Note.**
>
> SBAT and the Windows UEFI CA 2023 rollout answer the same cohort-revocation pressure in different trust domains. KB5025885's Windows boot-manager mitigation strategy combines a small set of dbx hash revocations with a CA rotation, because no single mechanism by itself can revoke a decade's worth of signed bootloaders within the dbx storage budget [31,29].

**The signed-but-vulnerable problem.** As long as Microsoft-signed bootloaders with known flaws remain reachable on production, recovery, or install media, Secure Boot must revoke by hash, by SVN, by SiPolicy, or by certificate: each with collateral damage. Hash revocation does not cover binaries the attacker has not yet seen. SVN revocation forces coordinated rebuilds across the signed-binary population. SiPolicy revocation depends on the SiPolicy update reaching each protected machine. CA rotation can break PXE recovery, recovery USBs, dual-boot Linux, and custom WinPE images.

**Supply chain at the firmware level.** LogoFAIL, BMC-resident attacks against rack servers, leaked or test Platform Keys shipped in production firmware (PKfail, 2024), Boot Guard key leaks (which OTP fuses cannot recover from), and OEM ME/PSP fuse misconfiguration are the categories Secure Boot cannot, by construction, defend against. The verifier sits above these layers; if these layers are compromised, the verifier is running on a base it cannot trust.

**SRTM allowlist explosion.** N OEMs, M models, K firmware revisions; the allowlist of "good SRTM measurements" explodes; the blocklist is asymmetric in the attacker's favor. DRTM late-launch is the only known way to collapse the allowlist. As Microsoft puts it, "DRTM lets the system freely boot into untrusted code initially, but shortly after launches the system into a trusted state" [40].

**Bus interception of discrete TPMs.** A discrete TPM on the LPC or SPI bus can be sniffed by a physical attacker. This is what motivates the move to Pluton: the TPM moves on-die, the bus disappears, and the BitLocker VMK no longer crosses a sniffable wire [39].

> **Key idea.**
>
> For Windows boot-manager failures, the dbx revocation half-life is the chapter's invariant: *patched* is not *revoked*. Pluton helps on the TPM and firmware-update-cadence side. It does not, by itself, close the gap between patched and revoked.

**The Pluton pivot.** Pluton's pitch, for the boot chain, developed in full in the Pluton chapter (Chapter 3), is to improve the measurement endpoint today and potentially move more root-of-trust firmware onto a Microsoft-serviced cadence over time [6,7]. Pluton implements TPM 2.0 on the CPU die, so the existing measurement chain plugs in unchanged. What changes is the *firmware update cadence*. Pluton firmware ships through Windows Update as an additional channel alongside existing UEFI capsule updates; the key difference is that Microsoft authors and controls the Pluton firmware, and the Windows Update path enables Microsoft to deliver those fixes independent of OEM release scheduling. The bus disappears: Pluton's interface is on-die--there is no external LPC or SPI bus crossing a package boundary that can be physically tapped, eliminating bus-sniffing against the TPM link as an attack class. And on 2024+ AMD and Intel parts, the Pluton firmware itself is written in Rust, addressing the memory-safety class of bugs that has historically dominated firmware CVEs [6].

![Figure: Discrete TPM versus Pluton. The LPC/SPI bus crosses the CPU package boundary and is sniffable, while Pluton moves the TPM on-die so there is no external bus to tap.](diagrams/16-secure-boot-tpm-vs-pluton.svg)

> **Why dbx will never simply be larger.**
>
> The first reaction to "dbx is too small" is always: make it bigger. Three constraints stop that. First, dbx is implemented by hundreds of OEM firmware vendors against a UEFI specification floor; raising the floor would invalidate every shipped UEFI implementation. Second, dbx is shared between Windows, Linux, ESXi, and other operating systems, so growing it requires coordination across vendors with different incentives. Third (and the real blocker), the variable lives in NV-RAM with limited write cycles; a runaway revocation update can brick a board if the write fails partway through. The realistic fix is SBAT for image-version bumps and CA rotation for cohort-scale revocation. Both are partial.

> **Apple, Arm, and the design space.**
>
> Pluton's design only makes sense against the contrast with the two endpoints of the design space.
>
> At one endpoint sits Apple. Apple authors the silicon, the Boot ROM, the iBoot bootloader, the kernel, and the Secure Enclave Processor's sepOS firmware. The Apple Boot ROM holds the Apple Root certificate authority public key directly; it verifies iBoot before iBoot loads anything else; on older A-series parts an additional Low-Level Bootloader stage is verified by the Boot ROM and in turn loads and verifies iBoot [61]. The Secure Enclave Processor is "a dedicated secure subsystem integrated into Apple SoC", isolated from the main processor and reachable only over a mailbox interface; sepOS is an L4 microkernel Apple ships and updates [62]. Every stage of secure boot is signed by the same vendor that ships the operating system, and "secure boot begins in silicon and builds a chain of trust through software" [63]. The cadence is the iOS / iPadOS / macOS update cadence (Apple-cadence) because the same release pipeline ships everything from the bootloaders and sepOS up to the user-facing apps (the Boot ROM itself is silicon-resident mask ROM and is never field-updated).
>
> At the other endpoint sits Trusted Firmware-A on Armv7-A and Armv8-A platforms. TF-A is the reference secure-world software stack with a Secure Monitor at Exception Level 3 [64]. The Trusted Board Boot feature implements Arm's TBBR-CLIENT specification (DEN0006D): "The Trusted Board Boot (TBB) feature prevents malicious firmware from running on the platform by authenticating all firmware images up to and including the normal world bootloader" [65]. The chain runs BL1 → BL2 → BL31 / BL32 → BL33, anchored on a ROTPK (Root of Trust Public Key) fused per silicon family. Because TBBR is a specification rather than a single shipping product, the actual signing keys and update cadence are the OEM's choice. The silicon vendor sets the fuse policy; the platform vendor signs the boot images; the operating-system vendor sees a verified BL33 handoff and trusts whatever ROTPK the silicon was fused with. There is no monoculture, and there is no single update cadence. Which is exactly what makes the security guarantees uneven across Arm devices in practice.
>
> Pluton sits between Apple and TF-A. Microsoft authors the Pluton firmware on silicon Microsoft does not own (AMD, Intel, Qualcomm fabricate it) [6]. The contrast is sharpest at the firmware-update cadence. Apple-cadence ships everything as one. OEM-UEFI-capsule-cadence is what discrete TPMs and PCH-isolated fTPM/PTT firmware are stuck with. Which is why a known-bad fTPM firmware can take months to land on every customer device after Microsoft posts a fix. Windows-Update-cadence is what Pluton offers for the TPM-class root it implements today: a Microsoft-authored firmware update riding the same channel that ships kernel patches. The same axis (*who* owns the trust anchor and *on whose schedule* it ships) is the axis on which the chapter's main Pluton argument turns.

There are honest residual limits. Pluton is a TPM, not a verification chain; the rest of Secure Boot still runs in DXE-phase firmware that LogoFAIL can compromise. Adoption is non-universal: as of 2026, Pluton ships on Microsoft Surface, AMD Ryzen 6000-9000/AI series, a subset of Intel Core Ultra (200V / Series 3) parts, and Qualcomm Snapdragon 8cx Gen 3 / X parts powering Copilot+ PCs, with many enterprise PCs still on discrete TPMs [6]. The OEM still owns PK and the firmware update path *outside* Pluton, so the dbx-revocation problem and the OEM-key-leak problem are unaddressed by Pluton alone. Attestation infrastructure (Device Health Attestation, Intune device-health Conditional Access) is still maturing, and the policies that consume attestation outcomes are still hand-rolled per organization.

Pluton closes the cadence gap. It does not close the gap between *patched* and *revoked*. Nothing yet does, and that is the next decade's problem.

## Proof by documentation, not capture

This chapter does not include a hash-verified VM capture. The firmware state that matters for Secure Boot is machine-specific, and the production evidence set for this book has no captured Secure Boot transcript for this chapter. The honest substitute is documented verification: real commands you can run on a Windows system, paired with expected outputs defined by Microsoft documentation rather than by this lab.

> 🔵 **DOCUMENTED**: Secure Boot enforcement probe. Microsoft documents `Confirm-SecureBootUEFI` as returning `True` when Secure Boot is enabled and `False` when disabled; the cmdlet is supported only on UEFI systems.
> reproduce: `Confirm-SecureBootUEFI` (elevated PowerShell)

```text
# UEFI system, Secure Boot enforcing
True

# UEFI system, Secure Boot disabled
False
```

If the platform does not support UEFI Secure Boot, the cmdlet reports that it is not supported on this platform. The interpretation follows Microsoft's Secure Boot and trusted-boot documentation [9,10].

> 🔵 **DOCUMENTED**: TPM readiness and measured-boot endpoint. Microsoft documents the TPM as the endpoint Windows uses for measured boot and BitLocker sealing.
> reproduce: `Get-Tpm | Select-Object TpmPresent,TpmReady,TpmEnabled,TpmActivated` (elevated PowerShell)

```text
TpmPresent TpmReady TpmEnabled TpmActivated
---------- -------- ---------- ------------
      True     True       True         True
```

The exact formatting varies by PowerShell host; the documented claim is not the column width but the state: the TPM is present, ready, enabled, and activated before Windows can use it as the measured-boot and BitLocker seal endpoint [9,10,106].

> 🔵 **DOCUMENTED**: Secure Boot policy database inspection. Microsoft documents `Get-SecureBootUEFI` and the Microsoft-managed Secure Boot object set as the way to inspect UEFI variables such as `db` and `dbx`.
> reproduce: `Get-SecureBootUEFI db | Format-List Name,Bytes` (and `dbx`; elevated PowerShell)

```text
Name  : db
Bytes : {48, 130, ...}

Name  : dbx
Bytes : {48, 130, ...}
```

The bytes are platform policy, not a universal constant. The documented point is that `db` and `dbx` are readable authenticated UEFI variables containing the allowlist and denylist material discussed in this chapter [27,60].

These probes do not prove that a particular boot was clean. They prove the configuration surfaces a Reasoner should inspect before trusting the rest of the Windows chain: Secure Boot enforcing, TPM ready, and the UEFI policy variables present. The measured-boot chapters build the stronger statement by replaying PCRs and event logs.

## Practical guide, and where the chain goes next

This is the part you do today, on whatever Windows machine is in front of you.

**Verify Secure Boot state.** Open an elevated PowerShell prompt and run `Confirm-SecureBootUEFI`. The cmdlet returns `True` only if Secure Boot is currently enforcing. `msinfo32` shows BIOS Mode (UEFI vs Legacy) and Secure Boot State on its System Summary page. `Get-SecureBootPolicy` shows the active Secure Boot policy publisher and related metadata; do not confuse that output with the Microsoft owner GUIDs used for the canonical KEK/db/dbx variable updates in `secureboot_objects` [60]. `Get-Tpm` and `tpmtool getdeviceinformation` confirm that the TPM is present, owned, and ready [10,9].

**Read the TPM event log.** `tpmtool gatherlogs` collects the WBCL files into a working folder you can inspect; `Get-WinEvent -LogName Microsoft-Windows-TPM-WMI` exposes the boot and provisioning events. On a healthy boot, the WBCL and the live PCR state replay to the same digest; mismatch is the attestation signal a remote verifier looks for.

**One-shot health check (PowerShell snippet).**

The following one-liner gathers the basic state in elevated PowerShell:

```powershell
Write-Host "SecureBoot =" (Confirm-SecureBootUEFI)
Write-Host "SBPolicy   =" (Get-SecureBootPolicy).Publisher
Write-Host "TPMReady   =" (Get-Tpm).TpmReady
Write-Host "UEFI/BIOS  =" (Get-CimInstance Win32_BIOS).SMBIOSBIOSVersion
```

If `SecureBoot` is `False`, your boot chain has no firmware-side allowlist. If `TPMReady` is `False`, TPM-based sealing is unavailable; confirm which BitLocker protectors are actually configured (a password, startup key, or PIN may still apply) rather than assuming a TPM protector is in force.

**Verify your Windows UEFI CA 2023 enrollment.** KB5025885 is a phased deployment; each mitigation step is enabled by writing the corresponding value to `HKLM\SYSTEM\CurrentControlSet\Control\Secureboot\AvailableUpdates` (the values are listed in the support article) [31]. The current UEFI db can be inspected with `Get-SecureBootUEFI db` (decode the returned `.Bytes` to enumerate the signature list); note that `Format-SecureBootUEFI` *builds* a signed variable-update payload for `Set-SecureBootUEFI` rather than reading the database. The 2023 CA's certificate has subject CN `Windows UEFI CA 2023`. If you do not see it in db on an online 2025-2026 Windows install, do not assume a single cause: the mitigation may not be enabled, the device or firmware may be blocked or excepted, the install or recovery media may be stale, or the deployment phase may not yet apply to that device. Consult the KB article for the supported next steps.

> **Verify your Windows UEFI CA 2023 enrollment.**
>
> The 2011 Windows boot-manager CA (**Microsoft Windows Production PCA 2011**) expires on 19 October 2026; the adjacent third-party **Microsoft Corporation UEFI CA 2011** expires on 27 June 2026 [30]. Secure Boot firmware does not check certificate expiry at boot, so existing 2011-signed bootloaders keep validating after that date; the real exposure is forward, not backward, because new Windows boot components are signed under the Windows UEFI CA 2023 and require it to be present in `db`. If your install media is older than May 2023 and you have not run a full set of cumulative updates, you may end up with a machine that boots today but cannot boot a future Windows recovery image. The fix is to apply the KB5025885 updates and verify the 2023 CA is enrolled before that deadline [31].

**Enable DRTM / System Guard Secure Launch where the silicon supports it.** The control surfaces are:

- MDM CSP: `DeviceGuard/ConfigureSystemGuardLaunch`.
- Group Policy: *Computer Configuration > Administrative Templates > System > Device Guard > Turn On Virtualization Based Security > Secure Launch Configuration*.
- Registry: `HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\SystemGuard\Enabled = 1`.

Verify via `msinfo32`: under *System Summary* the *Virtualization-based Security Services Configured / Running* line should include *Secure Launch* [40].

**Replace TPM-only BitLocker where physical access is in scope.** After Bitpixie, TPM-only BitLocker is a weak default for laptops or kiosks that an attacker can touch unattended. Add a pre-boot PIN (`manage-bde -protectors -add C: -tpmAndPin`) or a USB startup key where the edition and management model support it [2,36].

## What it means for you

For a Reasoner, Secure Boot changes the first question in an incident or design review. Do not start with "is Windows patched?" Start with "what did the firmware permit before Windows existed?" Then ask whether the machine is UEFI, whether Secure Boot is enforcing, which CAs are in `db`, which hashes and certificates are in `dbx`, whether the Windows UEFI CA 2023 transition has landed, and whether BitLocker is sealed to PCR[7] with a pre-boot factor for machines that face physical access.

The operational lesson is sharper than the architectural one. The cryptography has not been the public failure point. The failure point has been lifecycle: old but validly signed boot managers, small dbx storage, slow OEM firmware updates, recovery media that never got rebuilt, and policies that remained TPM-only after the threat model changed. The fix list is therefore boring and fleet-shaped: keep firmware and Windows current, verify Windows UEFI CA 2023 enrollment for the Windows boot-manager path, keep `shim` current on dual-boot systems, enable DRTM/Secure Launch where hardware supports it, and stop treating TPM-only BitLocker as a physical-access defense.

A minimal verify-it-yourself probe is three commands in elevated PowerShell: `Confirm-SecureBootUEFI`, `Get-Tpm`, and `Get-SecureBootUEFI dbx`. If the first is not `True`, the firmware-side allowlist is not protecting the boot path. If the second is not ready, the measurement and sealing rail has no trustworthy endpoint. If the third cannot be read or never receives revocation updates, you are trusting signatures without a practical way to distrust old signed code.

The chain is longer than it has ever been. It is not yet long enough.

> **Bequeaths.** Secure Boot hands the next links a signature-verified boot path: firmware through `bootmgfw.efi`, and via Trusted Boot on through `winload.efi`, `ntoskrnl.exe`, and ELAM. That verified path is what the TPM chapter (Chapter 2), Measured Boot chapter (Chapter 4), and Attestation chapter (Chapter 5) turn into PCR evidence and remote proof. The non-promise is the whole reason those chapters exist: **Secure Boot checks signatures; it does not MEASURE what ran, and it does not attest.**
>
> The verifier's one structural weakness travels with the chain. The gap this chapter isolates (*patched* is not *revoked*, because an old validly-signed binary keeps validating until its hash reaches `dbx`) is not unique to firmware. It returns in the cloud as the lag between revoking a token and the world still honoring it (the Continuous Access Evaluation chapter, Chapter 27), and at its most expensive as a validly-signed artifact wielded by the wrong hands (the Storm-0558 finale, Chapter 29). Secure Boot ends at the desktop. The runtime chain begins there.
