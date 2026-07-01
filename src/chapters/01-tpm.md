# The TPM

::: trust-ledger

- **Inherits:** A signature-gated boot path. Only validly-signed firmware and boot components execute from reset, and Secure Boot's own policy decision is exposed as a value worth measuring (PCR[7]) (Chapter 1, Secure Boot).
- **Promise:** A key the TPM marks non-exportable never crosses the chip's package boundary in plaintext, and a blob sealed to a PCR policy unseals only when the live boot measurements match the sealed state, so a secret can be bound to "this machine booted *this* way" against an attacker who steals the disk or who tampers before the OS loads.
- **TCB:** The TPM silicon (or the firmware-TPM's host TEE) and its key hierarchy; the CRTM and every stage that measures the next before a secret is sealed; the chip vendor's EK-certificate CA for attestation identity. The host OS that asks for an unseal is explicitly *outside* it.
- **Adversary → Break:** Intercept the key at release. A discrete TPM exposes the unsealed VMK on the LPC/SPI bus (Andzakovic 2019); a firmware TPM relocates that surface into a shared TEE that timing (TPM-Fail 2019) and voltage glitching (faulTPM 2023) defeat. The Promise ends at the instant of *release*. Whoever reads the key as it crosses to the OS wins, regardless of chip strength.
- **Residual:** Once unsealed, the key lives in VTL0 RAM where a runtime-compromised OS reads it → owned by The Secure Kernel (Chapter 6) and Credential Guard (Chapter 15); trust centralized in Pluton's Microsoft-controlled firmware signing/update root → owned by Pluton (Chapter 3); staleness of "what booted" once it is off the box → owned by Attestation (Chapter 5) and Continuous Access Evaluation (Chapter 27).
- **Bequeaths:** Four composable operations (measure, extend, seal, quote) over one set of registers, plus non-exportable key residence: handed to Measured Boot (Chapter 4) to record the boot and to Attestation (Chapter 5) to report it off the box. Does NOT provide: any protection for a key after it is unsealed, nor an *active* root of trust for execution. The TPM is a root of trust for storage and reporting, not for execution.
- **Proof:** 🔵 documented probes: `Get-Tpm`, `tpmtool getdeviceinformation`, `manage-bde` (Microsoft tooling). A VM probe returns a host-provided vTPM (🟡 emulated), not physical-silicon evidence; no physical TPM capture is claimed here.
:::

## The chip that starts the chain

> **The Reasoner's question.** What does the TPM make impossible for software to fake, and where does that guarantee end?

---

> **Foundations. What you need before this chapter.**
>
> - **TPM.** A Trusted Platform Module is a passive cryptoprocessor: it stores keys, performs a small set of cryptographic operations, and records platform measurements. It does not scan RAM, police the kernel, or decide whether Windows is trustworthy.
> - **Non-exportable key.** A key whose private material is generated inside the TPM and cannot be read out by the host OS when its attributes disallow export. The host can ask the TPM to use it; it cannot copy it.
> - **PCR.** A Platform Configuration Register is a TPM register changed by one operation, `extend`: `PCRnew = H(PCRold || measurement)`. Static PCRs cannot be arbitrarily set back to a preferred value; dynamic PCRs can be reset only under defined localities.
> - **Measure / extend.** Measuring hashes the next component or configuration value. Extending folds that hash into a PCR so the register represents an ordered history, not a mutable variable.
> - **Seal / unseal.** Sealing protects a blob under a TPM policy, usually a policy over PCR values. Unseal releases it only when the live policy matches.
> - **Quote.** A TPM-signed report of selected PCRs. It is how a remote service can ask, "what did this device boot?" without trusting the OS's word.
> - **EK / AK.** The Endorsement Key is the TPM's device identity root; the Attestation Key signs quotes. The EK certificate proves TPM provenance; credential activation or a CA/verifier flow binds an AK to that TPM; the AK, not the EK, signs attestation reports.
> - **dTPM / fTPM / Pluton / vTPM.** The same TPM 2.0 command surface can live in a discrete chip, firmware inside Intel CSME or AMD PSP, Microsoft's on-die Pluton block, or a hypervisor-provided virtual TPM. The interface is shared; the attack surface is not.

---

> **Chapter thesis.** The TPM (mainstreamed for Windows by Vista/BitLocker in 2007, 2.0 since 2014) is the hardware root of trust under almost every Windows security feature shipped since Vista. BitLocker, Measured Boot, Credential Guard, Windows Hello, device attestation. Twenty-five years of engineering refined a single primitive (measure, extend, seal, quote) into something one chip could underwrite. Twenty-five years of attacks (Andzakovic 2019, TPM-Fail 2019, faulTPM 2023) have argued empirically about how passive that chip can be. The current state of the art is Microsoft Pluton on the CPU die, with Microsoft-signed Rust firmware delivered via Windows Update on 2024 AMD and Intel platforms. It closes the bus and the TEE attack surfaces, but centralizes firmware trust in a Microsoft-controlled signing and update root. Post-quantum migration is the next frontier.

### The chip nobody asked for

On June 24, 2021, Microsoft announced Windows 11 [66], and told hundreds of millions of working PCs they were no longer eligible to upgrade. Not because they were too slow. Because they did not have a small chip most users had never thought about: a TPM 2.0. The PR backlash was immediate; the technical rationale was almost invisible. *Why was Microsoft willing to take that much heat over a piece of silicon?*

The next morning, Microsoft's security team tried to explain [67]. The argument was four words long: hardware root of trust.

> All certified Windows 11 systems will come with a TPM 2.0 chip to help ensure customers benefit from security backed by a hardware root-of-trust.

That sentence sat awkwardly against the user experience: a green checkmark in the PC Health Check tool, or a red X telling you to buy a new computer. The deeper claim (that a passive cryptoprocessor underwrote the security guarantees of half the operating system) was not something Microsoft had ever asked consumers to think about. For OEMs, the requirement was old news. Since July 28, 2016 [68], every new Windows device model had been contractually required to "implement and enable by default TPM 2.0." The 2021 mandate did not introduce the chip. It made an existing OEM rule into a visible install gate.

> **Trusted Platform Module (TPM).** A small, isolated cryptoprocessor that holds keys, performs cryptographic operations, and records integrity measurements: usually on a separate package or block of silicon that the host operating system cannot read directly. The TPM is "passive": it executes commands sent to it but never reaches into the host's memory.
>
> **Why the Windows 11 mandate was so controversial.** The PC Health Check tool was pulled and re-released. Reddit and Hacker News spent a weekend arguing about whether Microsoft had effectively bricked older hardware to sell new licenses. Microsoft's reply (that TPM-by-default produces measurable population-level security gains even when individual users do not understand it) was correct, but never quite the rebuttal that a consumer audience could engage with. The politics of "Trusted Computing" had returned, twenty years after the original Stallman objection [69].

This chapter is about that piece of silicon: what it does, why Windows needs it more than ever, and why twenty-five years of engineering and twenty-five years of attacks have together produced a chip that quietly defines what modern Windows can defend against, and what it cannot.

The central claim, which the rest of this chapter will earn: a passive cryptoprocessor designed in 1999 became the load-bearing pillar of half of Windows security, and the history of attacks against it has been a sustained empirical argument about exactly how passive that pillar is allowed to be.

## The problem the TPM was built to solve

Picture an engineer at IBM in early 2000. The Windows kernel has just been rooted again. The newly shipped DPAPI master keys (introduced with Windows 2000's general availability on February 17, 2000 [70]) become recoverable once SYSTEM falls. Stolen ThinkPads come back with their fresh EFS volumes already decrypted. Where do you put a secret that the OS cannot read?

Software-only key storage was Generation 0. Windows had DPAPI, EFS, and LSA secrets [71], all deriving their wrapping keys from the user's logon credential or from system-level material. Every derivation had the same structural problem: the unwrapping key, sooner or later, lived in the kernel's address space. An attacker who reached SYSTEM (or who carried the disk away to a separate machine) could replay it. A volume encrypted "at rest" was decryptable as soon as the disk was readable, and a disk you can read is a disk you can read offline. Microsoft now states the constraint plainly: a TPM-resident key, by contrast, "truly can't leave the TPM" [72]. That property cannot be retrofitted onto software-only storage.

> **Key idea.** Software-only key storage cannot defend against an attacker who reaches SYSTEM, and cannot defend against an attacker who carries the disk away. To survive both, the secret must live in silicon that the OS itself cannot read.

In October 1999 [73], five PC-industry incumbents took that observation and turned it into an industrial coalition: Compaq, Hewlett-Packard, IBM, Intel, and Microsoft incorporated the Trusted Computing Platform Alliance. (*Note:* The Wikipedia Trusted Computing Group article gives the day-precision date as October 11, 1999. The original TCPA press release URL has not survived; the founder list and date are consistent across secondary sources.) TCPA's charter was narrow: define a chip that could hold keys an x86 OS could not export, record boot-time integrity measurements, and sign attestations about that boot. The first chip to ship against the resulting TPM Main Specification 1.1b [74] appeared in 2003 [75]. Atmel, Infineon, and STMicroelectronics built it [75].

In parallel, Microsoft Research ran its own bet. Paul England, Butler Lampson, John Manferdelli, Marcus Peinado, and Bryan Willman [76] published "A Trusted Open Platform" in *IEEE Computer*, July 2003. The codename inside Microsoft was Palladium; the public name was the Next-Generation Secure Computing Base, NGSCB. It described a Windows where high-assurance code could run isolated from a possibly-compromised OS kernel, anchored in a hardware secure coprocessor that looked very much like a TPM. The motivating sentence read like a thesis: NGSCB extends personal computers "to offer mechanisms that let high-assurance software protect itself from the operating systems, device drivers, BIOS, and other software running on the same machine."

NGSCB never shipped as advertised. By 2005, reports indicated [77] that Microsoft would ship "only part of the architecture, BitLocker, which can optionally use the Trusted Platform Module to validate the integrity of boot and system files prior to operating system startup." The "Nexus" hypervisor, the user-mode high-assurance "agents," the protected paths for keyboard and display: all dropped against the Vista deadline. (*Note:* The deadline pressure on Vista is legendary. The architecture team chose to ship the smallest piece of NGSCB the existing chip could underwrite (BitLocker) and shelved the rest. That shelved piece eventually returned, fifteen years later, as Virtualization-Based Security and Credential Guard.)

The shelved primitives, however, did not die. *Measured boot* (the firmware measures the boot loader, the boot loader measures the kernel, each measurement extended into a register that cannot be rewound) migrated into Vista BitLocker and, later, into Windows 8 Measured Boot. *Sealed storage* (a key tied to a measured boot state, unreleasable unless the boot state matches) became the defining property of every TPM-bound BitLocker volume. *Remote attestation* (a device signing a quote of its own measurements for a remote verifier) became Device Health Attestation. NGSCB shipped, just not as itself.

> **The Stallman objection, twenty-five years later.** In the early 2000s, Richard Stallman and the Free Software Foundation framed Trusted Computing as "treacherous computing" [69]: hardware secured "for its owner, but also against its owner." That objection has aged unevenly. The DRM concerns the FSF predicted did not dominate. Hollywood never got the protected video paths it wanted on PCs. The trust-centralization concern has aged well: the modern Pluton debate raises a structurally similar question about who controls the firmware-signing trust root on the world's PC fleet, and the answer is now political rather than technical.

TCPA had built a chip that could hold a key the OS couldn't read. Which keys, under whose authority, against which threats? The first answer was almost good enough, and it lasted about a decade.

## Generation 1 and Generation 2: TPM 1.1b to 1.2, and why they failed

If you opened a 2007 ThinkPad and looked at the LPC bus next to the Super-IO chip, you would see a small Infineon SLB chip [78]. That was your TPM 1.2. It did exactly one job, and Vista's BitLocker was the first feature to depend on it.

The architectural skeleton of TPM 1.x [75] was simple. At least sixteen Platform Configuration Registers, with the PC Client TPM Interface Specification mandating 24 per active bank. Hash algorithm: SHA-1. Asymmetric algorithm: RSA-2048. A single root of storage, the Storage Root Key, whose private half never left the chip. An Endorsement Key burned in at manufacture as the chip's permanent identity. An HMAC-SHA1 authorization model over command parameters. A "Take Ownership" ceremony where the platform owner created the SRK and bound it to an owner secret.

> **Platform Configuration Register (PCR).** A TPM-internal register modified only by a one-way "extend" operation: $\text{PCR}_{\text{new}} = H(\text{PCR}_{\text{old}} \,\|\, \text{measurement})$. Static PCRs (0-15) cannot be rolled back without a full platform reset. TPM 2.0 also defines *dynamic* PCRs (16, 17-22, and 23 in the PC Client profile) that can be reset at specific localities via `TPM2_PCR_Reset`. DRTM uses PCRs 17-22 at locality 4 to re-launch a known measurement chain mid-run; PCRs 16 and 23 are resettable at lower localities for debug and application use. Either way, PCRs are the data structure that compresses a chain of measurements into a single attestable digest.
>
> **Endorsement Key (EK).** The TPM's permanent identity key, generated at manufacture and accompanied by an EK certificate from the chip vendor's CA. The EK is non-migratable and is used during attestation to prove that a given key was generated inside a genuine TPM. It is also the privacy-sensitive part of TPM identity: the EK is unique to one chip, so unrestricted use of the EK in attestation reveals which physical machine you are.
>
> **Storage Root Key (SRK).** The root of the TPM's key hierarchy. In TPM 1.x there was exactly one SRK per chip, created during the "Take Ownership" ceremony. Every protected key in the hierarchy was a child of the SRK: if you cleared the SRK, every key tied to it was lost.
>
> **Attestation Identity Key (AIK / AK).** A restricted signing key the TPM uses to sign quotes of PCR values for a remote verifier. Naming changed with the spec: in TPM 1.x it was the Attestation Identity Key (AIK), a separate RSA key whose binding to a real TPM was asserted by a Privacy CA's certificate over the EK. In TPM 2.0 it is the Attestation Key (AK), typically a restricted signing object whose TPM provenance is established through the EK certificate chain and credential activation (or by a CA/verifier policy), not by the EK signing quotes or necessarily by making the AK an EK sibling/primary. Either way, the AIK/AK signs the quote; the EK never directly signs anything.

TPM 1.2 [75], shipped in late 2003 and standardized as ISO/IEC 11889:2009, layered on the practical machinery: locality (a way for code at different privilege levels to extend different PCRs), monotonic counters, NV indices, transport sessions, and the eight-PCR split between firmware (PCR[0..7]) and OS (PCR[8..15]). It was the chip that mass-deployed in essentially every business PC from 2006 to 2014. When Windows Vista [77] reached volume-license RTM in late 2006 and broad availability in early 2007, BitLocker [79] (Enterprise and Ultimate editions only) became the first mainstream Windows feature whose security depended on the chip: BitLocker sealed the Volume Master Key to PCR values describing the boot-loader chain, so that a stolen disk could not be decrypted offline. Secure Boot binding (PCR[7]) would not arrive until UEFI Secure Boot [27] shipped with Windows 8 in 2012.

![Figure: TPM 1.x key hierarchy. A single Storage Root Key roots every child key, while the Attestation Identity Key is an independent RSA signing key whose binding to the chip is certified by a Privacy CA over the EK.](diagrams/01-tpm-1x-hierarchy.svg)

The problem with all of this was not that anyone broke it. The problem was that the architecture hard-coded its cryptographic primitives into its data structures. SHA-1 was not a configurable algorithm; it was the literal width of the PCR register and of every hash field in the spec. RSA-2048 was not a configurable algorithm; it was the literal layout of the EK, the SRK, and every protected key blob. If the world deprecated SHA-1, you did not patch the firmware. You replaced the chip.

NIST SP 800-131A deprecated SHA-1 [80] digital signatures starting in 2011. The 2017 SHAttered collision [81] drove the point home. (*Note:* The 2017 SHAttered SHA-1 collision does not retroactively break Vista BitLocker in practice. To do that, an attacker would have to choose firmware blobs whose hashes collide, not merely demonstrate a collision exists. But it ended any defense of "SHA-1 in PCRs is fine because nobody can collide it.") Algorithm flexibility cannot be retrofitted onto silicon whose data structures hard-code SHA-1. There were other limitations: a single SRK hierarchy meant clearing the chip's storage hierarchy also reset chip identity; the Privacy CA model for attestation never deployed at scale; ECC was missing; and the HMAC-based authorization model made every command exchange a piece of bespoke crypto plumbing.

| Generation | Year | Hash | Asym | Hierarchies | Status |
|---|---|---|---|---|---|
| Software-only (LSA / PStore) | 1996+ [82] | varies | varies | n/a | NT 4.0 baseline; software-wrapped keys exposed with sufficient local or offline access |
| Software-only (DPAPI / EFS) | 2000+ | varies | RSA-1024 (EFS) | n/a | Defeated by offline disk theft and by SYSTEM compromise |
| TPM 1.1b | 2003 | SHA-1 | RSA-2048 | 1 (SRK) | First mass deployment; superseded by 1.2 |
| TPM 1.2 | 2003-2014 | SHA-1 | RSA-2048 | 1 (SRK) | Vista/7/8 BitLocker baseline; algorithm-rigid |
| TPM 2.0 | 2014+ | SHA-1 + SHA-256 banks; extensible algorithm IDs | RSA, ECC | 4 (Platform / Endorsement / Storage / Null) | Current; ISO/IEC 11889:2015; PQC still profile/implementation work |

TCG accepted the constraint in 2014 and started over. The 2.0 design did not add features to 1.2. It answered a different question: how do you let one TPM survive twenty years of cryptographic transitions?

## Generation 3: TPM 2.0: one primitive, many algorithms

On April 9, 2014 [75], the Trusted Computing Group [83] did something rare in standards bodies: they threw away a working specification and started from a different question. The result was the TPM 2.0 Library Specification, Family 2.0, Level 00, Revision 116. A year later it became ISO/IEC 11889-1:2015 Edition 2 [84], which removed the "industry consortium" objection from procurement teams in regulated environments. By July 28, 2016 [68], Microsoft had quietly made TPM 2.0 a contractual must-have for new Windows device models, lines, or series in the OEM manufacturing scope.

Four conceptual changes carry the architecture.

### Algorithm agility

Every cryptographic algorithm in TPM 2.0 carries an integer identifier. PCRs no longer have a single hash; they have *banks*, one per supported algorithm, all extended in parallel by a single command. Microsoft's own documentation [72] describes the contract: when firmware extends PCR[0] with the IBV's CRTM measurement, the TPM extends both the SHA-1 bank and the SHA-256 bank, and on newer parts the SHA-384 bank as well. (*Margin note:* The PC Client Platform TPM Profile mandates SHA-1 + SHA-256 minimum, not SHA-256-only. Backwards compatibility had a cost.) The wire and object formats can name SHA-3 or future post-quantum algorithms by ID; making them practical still requires TPM implementation support, profile updates, certification, and sometimes new silicon.

> **Algorithm agility.** A property of a cryptographic protocol or device whereby the choice of hash, signature, or encryption algorithm is decoupled from the protocol's data structures. Algorithm-agile systems carry algorithm identifiers alongside their cryptographic blobs, so a new algorithm can be specified without re-laying out the wire format, even though implementations and profiles must still support it. TPM 2.0 is algorithm-agile; TPM 1.x was not.

### Four hierarchies, four primary seeds

Where TPM 1.x had a single SRK, TPM 2.0 has four hierarchies (Platform, Endorsement, Storage, Null) each rooted in a per-hierarchy *primary seed*. Primary keys are derived deterministically: call `TPM2_CreatePrimary` with the same template against the same seed, and you get the same key back, byte-for-byte. The Apress textbook by Arthur, Challener, and Goldman [85] (the de-facto developer reference for the spec) describes this as the architectural fix to a real operational problem: the platform owner can clear the storage hierarchy without losing the device's endorsement identity.

![Figure: TPM 2.0's four hierarchies (Platform, Endorsement, Storage, and Null) each rooted in its own primary seed, with primary keys deterministically re-derived via TPM2_CreatePrimary.](diagrams/01-tpm-2x-hierarchies.svg)

### Enhanced authorization

The most interesting change is how TPM 2.0 talks about access control. Every protected object has a `policyDigest`, an algorithm-agile hash of an arbitrarily complex set of conditions. To use the object, the caller starts a policy session (`TPM2_StartAuthSession` with `TPM_SE_POLICY`) and walks predicates (`TPM2_PolicyPCR`, `TPM2_PolicyAuthorize`, `TPM2_PolicySigned`, `TPM2_PolicyCommandCode`, `TPM2_PolicyAuthValue`) each extending the running session digest. At the end, the TPM checks that the session digest matches the object's `policyDigest`, and only then authorizes the operation. BitLocker, in Microsoft's current Learn description [79], can seal the Volume Master Key to a validation profile that commonly includes PCR[7] (Secure Boot policy) and PCR[11] (BitLocker control flags). Tampering with measured Secure Boot configuration (or a non-BitLocker boot path within the configured profile) causes unseal to fail.

> **Enhanced Authorization (policy session).** TPM 2.0's flexible authorization mechanism. Each protected object carries a hash (policyDigest) of the predicates required to use it. A caller builds an equivalent digest by walking a sequence of TPM2_Policy* commands inside a policy session; the TPM only authorizes the operation if the two digests match. This is the mechanism that lets BitLocker bind the VMK to specific PCR values, lets Hello bind a key to a PIN gesture with anti-hammering, and lets attestation servers compose policies they did not design into the chip.

### The unifying primitive: measure, extend, seal, quote

The reason any of this matters for Windows is that the entire feature surface compresses down to four operations on the same set of registers.

- **Measure.** A piece of code computes the hash of the next piece of code (or configuration) about to run.
- **Extend.** That hash is folded into a PCR via `PCR_new = H(PCR_old || hash)`. The operation is one-way: PCRs cannot be rewound.
- **Seal.** A symmetric key (or arbitrary blob) is encrypted under the TPM's Storage hierarchy with a `policyDigest` that names a specific set of PCR values. `TPM2_Unseal` releases the blob if and only if the live PCR state matches.
- **Quote.** The TPM signs a snapshot of selected PCRs with an Attestation Key. A remote verifier can check the signature against a known AKpub and an EK certificate chain.

The boot of a measured Windows machine is exactly this loop. The Core Root of Trust for Measurement (a small piece of immutable firmware) measures the next stage and extends PCR[0]. Common PC-client profiles measure the next stages into PCRs such as PCR[2] for option ROMs, PCR[4] for the Windows Boot Manager, PCR[7] for the Secure Boot policy, and PCR[11] for BitLocker volume control flags, then continue through ELAM and the kernel. Microsoft's Trusted Boot description [9] walks the chain.

![Figure: Measured boot to seal/unseal. Each boot stage extends a PCR as it hands off, and BitLocker's TPM2_Unseal releases the VMK only when the live configured PCR profile matches the sealed policy.](diagrams/01-tpm-measured-boot-seal.svg)

Now compress the Windows feature catalog against those four operations.

- BitLocker [79] seals the VMK to a PCR policy.
- Measured Boot (Chapter 4) and Device Health Attestation (Chapter 5) [86] quote PCRs to a remote verifier.
- Credential Guard (Chapter 15) [87] uses VBS to isolate NTLM/Kerberos secrets; Microsoft recommends TPM support for hardware binding, but the exact sealing policy is configuration- and version-specific.
- Windows Hello for Business (Chapter 20) [88] creates a per-user key protected by a PIN/biometric gesture; when hardware-backed, the TPM protects the private key and enforces anti-hammering.
- Virtual smart cards, DPAPI-NG, and TPM key attestation [89] for ADCS-issued certificates all sit on the same primitives.

> **Aha #1: One primitive, every feature.** BitLocker, Measured Boot, Credential Guard, Windows Hello, virtual smart cards, DPAPI-NG, and TPM key attestation are not seven independent uses of a chip. They are policy expressions over the same TPM contract. The TPM is not a checkbox shared by features; it defines what hardware-rooted security can do in Windows.
>
> **Key idea.** Read the four-operation model above as a single, composable contract: "this key only releases when the boot looks like *this*."

By July 28, 2016, TPM 2.0 was a hidden contractual requirement under the entire Windows OEM channel. By June 24, 2021, Microsoft made the same chip the visible install gate for Windows 11. The architecture had won the building. Then attackers started taking it apart.

## Verify it yourself: documented probes

<!-- The probes below remain documented command shapes unless represented in a hash-verified evidence block. A VM vTPM yields only 🟡 emulated values and cannot meet the silicon-tier 🟢 bar. -->

This chapter is in the silicon tier, but the probes below are 🔵 **DOCUMENTED** command shapes rather than physical-silicon captures: real commands a reader can run, with Microsoft-documented expected fields. If these commands are run inside a virtual machine, the reported TPM may be a hypervisor- or host-provided virtual TPM; under this book's taxonomy that value would be 🟡 emulated, not physical silicon evidence.

> 🔵 **DOCUMENTED**: Windows PowerShell `Get-Tpm`
> reproduce: `Get-Tpm | Format-List *`

```text
TpmPresent                : True
TpmReady                  : True
TpmEnabled                : True
TpmActivated              : True
TpmOwned                  : True
RestartPending            : False
ManufacturerId            : <vendor-specific integer>
ManufacturerIdTxt         : <vendor identifier>
ManufacturerVersion       : <firmware version>
ManagedAuthLevel          : Full
OwnerAuth                 : <not displayed>
OwnerClearDisabled        : True or False
AutoProvisioning          : Enabled
LockedOut                 : False
LockoutHealTime           : <duration>
LockoutCount              : 0
LockoutMax                : <platform value>
```

Read those fields narrowly. `TpmPresent`, `TpmReady`, and `TpmOwned` establish that Windows sees an initialized TPM it can provision. `ManufacturerIdTxt` and `ManufacturerVersion` help you correlate platform advisories and distinguish vendor behavior. They do **not** prove that the TPM is a discrete chip, an on-die block, or physical at all. A VM can return `TpmPresent: True` because the hypervisor exposed a vTPM; that is useful cloud evidence, but it is not physical-silicon evidence.

> 🔵 **DOCUMENTED**, Windows `tpmtool`
> reproduce: `tpmtool getdeviceinformation`

```text
TPM Present: True
TPM Version: 2.0
TPM Manufacturer: <manufacturer>
TPM Manufacturer Version: <firmware version>
TPM Specification Version: 1.38 or later
PPI Version: <platform physical-presence interface version>
Ready For Storage: True
Ready For Attestation: True
Is Capable For Attestation: True
Clear Needed To Recover: False
```

The two readiness lines map directly to this chapter's role for the chip. **Ready For Storage** is the vault: Windows can create and use protected objects. **Ready For Attestation** is the witness stand: Windows can participate in identity and quote workflows. If either is false, higher layers that assume a hardware root are standing on sand.

> 🔵 **DOCUMENTED**: BitLocker administrative surface
> reproduce: `manage-bde -status C:` and `manage-bde -protectors -get C:`

```text
Volume C: [OS]
    Conversion Status:    Fully Encrypted
    Percentage Encrypted: 100.0%
    Protection Status:    Protection On
    Lock Status:          Unlocked
    Key Protectors:
        TPM
        Numerical Password
```

This is the operational join between the TPM and the disk. `Key Protectors: TPM` means the volume has a TPM-bound protector. `Numerical Password` is the recovery protector; before clearing the TPM or changing firmware policy, recovery escrow must be verified. If your threat model includes hands-on attackers against discrete-TPM systems, `TPM` alone should trigger a design discussion. Microsoft's documented mitigation for the bus-sniffing class is preboot authentication (TPM+PIN or a startup key) not wishful thinking about the bus.

> 🔵 **DOCUMENTED**: BitLocker PCR binding surfaces vary by build
> reproduce: inspect `manage-bde -protectors -get C:` and the BitLocker platform-validation profile via `Get-CimInstance -Namespace Root\CIMv2\Security\MicrosoftVolumeEncryption -ClassName Win32_EncryptableVolume`

```text
PCR Validation Profile:
    PCR[7]  : Secure Boot policy
    PCR[11] : BitLocker access control
Protector:
    TPM or TPMAndPIN
```

Different Windows builds expose PCR binding through different administrative surfaces; the key idea is stable. BitLocker binds release to measured state, commonly including Secure Boot policy and BitLocker control measurements. The exact profile is configuration, not folklore. Reasoners should verify it on the systems they defend.

## Where this link breaks: the threat model collapses inward (2019–2024)

On March 13, 2019, a New Zealand security researcher named Denis Andzakovic posted a blog entry [78] that, in retrospect, started the modern era of TPM offense. He demonstrated two LPC-bus sniffing attacks on two different machines. On an HP business laptop running TPM 1.2, he used a DSLogic Plus logic analyzer connected via the laptop's debug header (7 wires: LCLK, LFRAME, LAD[0:3], and ground) to lift the BitLocker Volume Master Key off the LPC bus. On a Surface Pro 3 running TPM 2.0, he spent $40 NZD on a Lattice iCE40 ICEStick FPGA (8 connections: GND, LCLK, LFRAME#, LRESET#, LAD[0:3]) and replicated the attack. With the disk in hand and the motherboard accessible, a thief could decrypt a TPM-only BitLocker volume in the time it took to boot it once. Andzakovic open-sourced the FPGA gateware [90] the same day. (*Note:* Andzakovic credits Hector Martin (`@marcan`) for prototyping LPC sniffing earlier; the 2019 write-up was the first end-to-end public demonstration with reproducible code.)

The structural insight, which has not been backed away from, is that published BitLocker bus-sniffing work shows that Windows does not use TPM 2.0 *parameter encryption* to protect the VMK on the discrete-TPM boot path. The VMK travels in plaintext at the LPC bus's 33 MHz clock across a few millimeters of PCB. (*Note:* Why doesn't Windows turn on parameter encryption for BitLocker? The boot-time pressure is real. Pre-OS code lives in a tight memory budget and parameter encryption requires HMAC-signed sessions. The pragmatic mitigation Microsoft documents is preboot authentication (PIN or startup key), which makes the bus-sniffed VMK insufficient on its own.)

The attack would not stay a one-laptop curio. In late 2020, F-Secure's (later WithSecure) Henri Nurmi released an SPI variant [91] and a public BitLocker-key extraction tool. A year later, Thomas Dewaele and Julien Oberson at SCRT reproduced the LPC attack [92] on a Lenovo ThinkPad L440 with a chip (labeled P24JPVSP, identified by SCRT as probably equivalent to the ST33TPM12LPC) and published a tutorial. By October 2024, SCRT had industrialized the attack [93] across "the three major enterprise-grade laptop manufacturers (i.e. Lenovo, HP, and Dell)" in "a few minutes."

The first reassurance the industry reached for was: ship the TPM inside the chipset. No bus, no sniff. Both Intel (Platform Trust Technology, fTPM-in-CSME [94]) and AMD (fTPM-in-PSP) had already done this for cost reasons. That reassurance lasted eight months.

In November 2019, Daniel Moghimi, Berk Sunar, Thomas Eisenbarth, and Nadia Heninger (soon to be USENIX Security 2020) released TPM-Fail [95]. Their finding: Intel PTT and a STMicro ST33 dTPM both leaked ECDSA private keys through ordinary timing side channels in their scalar multiplication. The numbers were brutal:

> A local adversary can recover the ECDSA key from Intel fTPM in 4-20 minutes depending on the access level. We even show that these attacks can be performed remotely on fast networks, by recovering the authentication key of a virtual private network (VPN) server in 5 hours.: TPM-Fail, tpm.fail [95], 2019

NVD assigned CVE-2019-11090 [96] to Intel PTT and CVE-2019-16863 [97] to STMicroelectronics' ST33TPHF2ESPI. The latter entry is blunt: "STMicroelectronics ST33TPHF2ESPI TPM devices before 2019-09-12 allow attackers to extract the ECDSA private key via a side-channel timing attack because ECDSA scalar multiplication is mishandled, aka TPM-FAIL." Both chips were certified at the moment of disclosure. The STMicro chip held both Common Criteria EAL4+ and FIPS 140-2 Level 2, while the Intel chip held FIPS 140-2 [95]. Certification did not catch the bug. The presentation is preserved in the USENIX Security 2020 proceedings [98].

> **Aha #2: 'No bus to sniff' is not 'no attack surface'.** Removing the bus did not remove the attack surface. It relocated it from the PCB to the trusted execution environment that hosted the firmware TPM. The fTPM closes one channel and opens another, and the certification regime that was supposed to catch both missed the timing leak in chips that had passed their respective certification programs (STMicro: Common Criteria EAL4+ and FIPS 140-2 Level 2; Intel: FIPS 140-2). The "fTPM has no bus to sniff" reassurance was a category error.

The final beat came four years later. In April 2023, Hans Niklas Jacob, Christian Werling, Robert Buhren, and Jean-Pierre Seifert posted faulTPM (arXiv:2304.14717) [99], with reproducible code at github.com/PSPReverse/ftpm_attack [100]. The attack: voltage-glitch the AMD Platform Security Processor and walk out with the entire internal TPM state. The paper's own claim is the sentence that, more than any other, framed the modern TPM threat model.

> this vulnerability exposes the complete internal TPM state of the fTPM. It allows us to extract any cryptographic material stored or sealed by the fTPM regardless of authentication mechanisms such as Platform Configuration Register validation or passphrases with anti-hammering protection.: Jacob, Werling, Buhren, Seifert, faulTPM (2023) [99]

Two to three hours of physical access. Anti-hammering bypassed because anti-hammering is enforced by the TPM, and once the TPM's internal state is on your bench you set the counter to zero. PCR-policy bypassed because the sealed blob's wrapping key is in the extracted state. The structural punch is that this makes BitLocker TPM+PIN on AMD fTPM with a low-entropy PIN *less* secure than a TPM-less passphrase (a corollary the faulTPM paper makes explicit [99]): the TPM concentrates all your trust into a chip whose internal state can be exfiltrated.

![Figure: Three generations of TPM attack, 2019–2024. LPC/SPI bus sniffing, the TPM-Fail timing side channel, and the faulTPM voltage glitch; each generation invalidates the reassurance the previous one reached for.](diagrams/01-tpm-attack-timeline.svg)

| Attack class | TPM form | Cost | Time | Source |
|---|---|---|---|---|
| LPC bus sniffing (BitLocker VMK) | Discrete TPM 1.2 / 2.0 | $0 (logic analyzer): ~$40 NZD (iCE40 FPGA, Surface Pro 3) | Minutes once wired | Andzakovic 2019; SCRT 2021/2024 |
| SPI bus sniffing | Discrete TPM 2.0 | ~$50 (logic analyzer) | Minutes once wired | WithSecure 2020-2024 |
| Timing side channel on ECDSA | Intel PTT, STMicro ST33 | Software-only | 4-20 min local; 5 h remote VPN | TPM-Fail 2019 (USENIX 2020 proceedings) |
| Voltage glitch on PSP | AMD fTPM | ~$200 (glitching rig) | 2-3 h physical | faulTPM 2023 |

If a $40 FPGA defeats discrete TPM, a network packet defeats Intel PTT, and a few hours of physical access defeats AMD fTPM completely. Where does the next generation of TPM live? Microsoft's answer was on the CPU die itself.

## State of the art: five realizations of one specification

All five chips in this section pass the same TCG conformance suite. They expose the same `TPM2_*` command surface to Windows. They fail to completely different attackers. The architecture is identical; the *attack surface* is everything.

> **Discrete TPM (dTPM) and firmware TPM (fTPM).** A *discrete* TPM is a separate chip on the motherboard, talking to the host over LPC, SPI, or I2C. A *firmware* TPM is a TPM 2.0 implementation running inside an existing trusted execution environment on the host: Intel CSME (Platform Trust Technology), AMD PSP (fTPM), or a dedicated Microsoft IP block (Pluton). Both pass the same TCG specification; they differ in physical location, attack surface, and update channel.
>
> **Direct Anonymous Attestation (DAA / ECDAA).** A zero-knowledge protocol that lets a TPM prove "I am a real TPM certified by vendor X" without revealing which chip is talking. Replaces the TPM 1.2 Privacy CA model, which required a third-party CA to mediate every attestation. ECDAA is the elliptic-curve variant standardized in TPM 2.0.

### Discrete TPM

The classical chip. Infineon, STMicroelectronics, Nuvoton. Hangs off the motherboard's LPC, SPI, or I2C bus. Best certifications (Common Criteria EAL4+, FIPS 140-2/3). One bug class: bus sniffing in minutes for $40 against the BitLocker boot path that Windows leaves in plaintext.

### Intel PTT

TPM 2.0 inside the Converged Security and Management Engine: historically on the Platform Controller Hub die, and increasingly on the SoC die in integrated-platform Intel processors since Tiger Lake. Either way, no physical bus to sniff. Defeated by TPM-Fail [95] timing side channel; firmware-patched, but inherits CSME's broader attack surface and CSME's update story (UEFI capsule via OEM, lifecycle entirely under the OEM's control).

### AMD fTPM (PSP)

TPM 2.0 inside the AMD Platform Security Processor [101] (an ARM TrustZone Cortex-A5 core integrated into every modern Ryzen SoC). Ships in essentially all Ryzen-class client SoCs since 2017. No physical bus to sniff. Defeated end-to-end by the faulTPM [99] voltage-glitch attack against the PSP. The structural problem is shared TEE: the same coprocessor is responsible for memory encryption setup, secure-boot enforcement, and TPM service, and a single fault-injection path drops all of those.

### Microsoft Pluton

A Microsoft IP block on the CPU SoC die, with Microsoft-authored Rust firmware (on 2024 AMD and Intel platforms) [6] delivered through Windows Update. According to Microsoft's hardware list, Pluton "is currently available on devices with the following chipsets running on Windows 11: AMD: Ryzen 6000, 7000, 8000, 9000 and Ryzen AI Series... Intel: Core Series Processors: Ultra 200V Series, Ultra Series 3 and Series 3... Qualcomm: Snapdragon 8cx Gen 3 and Snapdragon X Series." The same page notes that "Pluton platforms in 2024 AMD and Intel systems will start to use a Rust-based firmware foundation given the importance of memory safety."

The thesis is laid out in Microsoft's November 17, 2020 announcement post [49], which links explicitly to Andzakovic. The architectural framing is unusually direct.

> The Pluton design removes the potential for that communication channel to be attacked by building security directly into the CPU.: Microsoft Security Blog, November 17, 2020 [49]

Three things change at once. The bus is gone. Pluton is on-die, so dTPM bus-sniffing has no surface to attack. The TEE host is dedicated. Pluton is not the same coprocessor that runs SEV memory encryption or ME runtime services. And the firmware ships through Windows Update, so when a Pluton firmware vulnerability is found (and one will be found), the patch reaches the deployed fleet through Windows Update rather than through OEM UEFI capsule rollouts. (*Note:* The Pluton-as-TPM page makes the trade-off explicit: "Microsoft Pluton can be used as a TPM, or with a TPM. Although Pluton builds security directly into the CPU, device manufacturers might choose to use discrete TPM as the default TPM." [7] Several enterprise security teams have publicly cited the Pluton update model as a reason to keep dTPM as their default for high-assurance fleets even where Pluton silicon is available.)

### vTPM

A software TPM emulation, typically inside a hypervisor. Azure Trusted Launch [102] is Microsoft's flagship implementation: "Trusted Launch is the default state for newly created Azure Gen2 VM and scale sets." The vTPM lives in a host-protected memory region and inherits the trust of the host. For cloud workloads where the threat model already includes "the hypervisor host is honest," this is the right shape; for adversarial physical access, it is not.

### Head-to-head

| Dimension | dTPM | Intel PTT | AMD fTPM | Pluton | vTPM |
|---|---|---|---|---|---|
| Physical location | Separate chip | CSME (PCH die) | PSP (CPU die) | Dedicated IP block on CPU die | Hypervisor memory |
| Bus to host | LPC / SPI / I2C | None (on-die) | None (on-die) | None (on-die) | None (virtual) |
| TEE shared with | none (own die) | CSME | PSP (large) | none (Pluton-only) | hypervisor / host TCB |
| Side-channel exposure | Implementation-dependent | TPM-Fail patched | faulTPM unaddressed structurally | Limited public research | host-dependent |
| Update channel | UEFI capsule | UEFI capsule (CSME) | UEFI capsule (PSP) | Windows Update | hypervisor patch |
| Certifications | EAL4+, FIPS 140-2/3 | EAL4+ | varies | varies | n/a |
| OEM cost | per-chip BOM | bundled | bundled | bundled | n/a |
| Best-known attack | LPC/SPI sniffing in minutes | TPM-Fail timing | faulTPM full state | None public at faulTPM depth | host compromise |
| Algorithm agility | spec-required | spec-required | spec-required | spec-required + Rust firmware updates | spec-required |
| Best fit | Compliance-driven, high-assurance fleets | Existing Intel platforms | Existing AMD platforms | Default for Windows 11 client | Cloud workloads |

![Figure: Five TPM realizations (dTPM, Intel PTT, AMD fTPM, Pluton, vTPM) converging on one TCG2 command surface that underwrites every Windows feature. The command surface is identical; the attack surface is not.](diagrams/01-tpm-realizations-map.svg)

The deep claim of the Pluton design is not that it is a better cryptoprocessor. It is that the previous decade's lesson (TEE memory-safety bugs are systemic, certification did not catch them, and OEM UEFI capsule patching is too slow) argues for moving the firmware signer to Microsoft and the firmware language to Rust. That is a political choice, not just a technical one. The October 2019 Secured-core PCs initiative [103] was the first public step; Pluton is its descendant.

If you can sniff a dTPM, time-attack an Intel PTT, glitch an AMD fTPM, and trust Microsoft to sign your Pluton firmware. Which threat are you actually defending against?

## Theoretical limits: what a passive cryptoprocessor cannot do

A famous joke in the trusted-computing community: the TPM cannot make a compromised OS uncompromised. It can only make sure that nothing else helped.

Three impossibility-style results follow from the architecture itself, regardless of which of the five realizations you pick.

### The TPM is a root of trust for storage and reporting, not execution

The Core Root of Trust for Measurement (the immutable code that bootstraps the measurement chain) lives in firmware, not in the TPM. The TPM cannot detect that the wrong code measured itself; it can only refuse to release sealed material when the PCRs do not match the stored policy. If the CRTM is compromised (or a downstream measurement is forged before extension), the TPM has no way to know.

Stronger guarantees require an *active* root of trust: a Dynamic Root of Trust for Measurement, where the CPU enters a known good state late in the boot and re-measures from there. Intel TXT, AMD SVM-SKINIT, and Microsoft's System Guard Secure Launch [104] on Secured-core PCs all implement this. The TPM is a participant in DRTM; on its own, it is not sufficient.

### TPM-only BitLocker has a structural lower bound

The VMK must enter RAM during Trusted Boot before the user authenticates. This is not a bug; it is the threat-model definition of "TPM-only." Therefore *any* attacker who intercepts the VMK at the moment of release defeats TPM-only BitLocker, regardless of TPM strength. This is what every dTPM bus-sniffing attack actually exploits: not a weakness of the TPM, but the structural condition that the key must traverse the boot path.

Microsoft's countermeasures documentation [105] names the mitigation in plain terms: preboot authentication. Adding TPM+PIN raises the bound to "guess the PIN against intact anti-hammering", but only as long as the TPM's anti-hammering counter cannot be exfiltrated. faulTPM violates that condition for AMD fTPM. On a Pluton or hardened dTPM, anti-hammering still holds, and a sufficiently random PIN raises the bound sharply.

The simple way to think about TPM+PIN is not a one-second sleep after every bad guess. Windows exposes lockout state as `LockoutCount`, `LockoutMax`, and `LockoutHealTime` in `Get-Tpm`; the documented example shows a threshold of 31 and a 10-minute heal interval [106]. Real attack cost is therefore governed by the platform's lockout threshold and heal schedule, not by a constant per-guess delay. The practical conclusion survives the exact arithmetic: a low-entropy PIN is a weak human factor, while a sufficiently random 8+ digit PIN plus intact anti-hammering pushes online guessing out of the unattended-theft threat model.

> **The Bitpixie footnote.** CVE-2023-21563 [107] (the BitLocker Security Feature Bypass that the offensive-security community calls "Bitpixie") is a useful reminder that breaking BitLocker does not require breaking the TPM. The NVD entry reads simply "BitLocker Security Feature Bypass Vulnerability," and the bypass operates against the pre-OS/boot-recovery path that consumes the unsealed VMK, not against the chip that sealed it; operationally, treat it as a physical/boot-control class of failure rather than TPM private-key extraction. (NVD does not use the "Bitpixie" name; it is community-known-as.)

### Once a key is unsealed, it lives in the OS's address space

A runtime-compromised OS reads any key the TPM has unsealed for it. The TPM defends against the *offline* attacker (disk theft, post-shutdown tamper) and the *pre-OS* attacker (boot-time integrity violation that fails the unseal). It does not defend against a privileged runtime attacker. This is a general impossibility, not a TPM weakness; no passive cryptoprocessor can decide whether the OS asking to unseal a key is itself trustworthy at the moment it asks.

This is why VBS, Credential Guard, and DRTM exist as separate disciplines: they answer "what protects the unsealed key once it is in RAM?" by isolating the key inside a VTL1 enclave or by re-measuring the OS after launch. The TPM is a participant; it is not the answer.

> **Key idea.** The TPM defends against the offline attacker and the pre-OS attacker. It does not defend against a runtime-compromised OS. This is by design, and is the most a passive cryptoprocessor can do. Stronger guarantees require an active component (DRTM, VBS, hypervisor isolation), and none of those are the TPM.

What would an *ideal* TPM look like? On-die (no bus), in an isolated TEE shared with nothing else, with the host-firmware-update path replaced by an OS-channel update path, with high-assurance certification depth, with an authenticated wire protocol always on, and with native support for post-quantum primitives. *No shipping TPM today satisfies all six properties.* Pluton plus future PQC firmware updates is the closest existing trajectory; it is on-die, isolated, OS-channel-updated, and Rust-implemented, but it does not yet expose PQC primitives and its certification depth is still evolving.

If the TPM cannot defeat a runtime-compromised OS by design, and the best fTPM can be extracted in three hours, where is the security frontier actually moving?

## Open problems: PQC, supply chain, and trust centralization

On August 13, 2024, NIST finalized FIPS 203 (ML-KEM) [108], FIPS 204 (ML-DSA) [109], and FIPS 205 (SLH-DSA) [110]: the first federal post-quantum cryptography standards. ML-DSA-87's public keys are 2,592 bytes. A typical TPM has 6 to 32 KiB of NV memory total. The math gets uncomfortable quickly.

### Post-quantum migration

The NIST Post-Quantum Cryptography project page [111] describes the timeline: "In August 2024, NIST released its principal PQC standards... Under the transition timeline in NIST IR 8547, NIST will deprecate and ultimately remove quantum-vulnerable algorithms from its standards by 2035, with high-risk systems transitioning much earlier." That is the deadline driving every TPM roadmap, and the August 14, 2024 Federal Register notice [112] made it formal U.S. policy.

Three concrete obstacles. **First**, the TCG algorithm registry has not yet normatively added ML-KEM, ML-DSA, or SLH-DSA; a TCG PQC working group exists, but its output is in flight. The Microsoft TPM 2.0 reference code [113] tracks TCG: the V1.83 release notes describe it as "the first revision in sync with Trusted Computing Group 1.83," and that revision still does not expose PQC algorithm IDs. The Fraunhofer SIT Post-Quantum Cryptography for TPM [114] program has prototyped PQC primitives inside reference TPM stacks, but those changes are research artifacts, not normative TCG output.

**Second**, the TPM's resource budget strains under the larger PQC parameter sets. Ordinary application keys (Windows Hello keys, BitLocker wrapping keys) are not held in on-chip NV at all: they live off-chip as parent-wrapped key blobs and are loaded transiently into volatile context via `TPM2_Load`, so NV pressure falls on *persistent* (evicted) handles and NV indices rather than on every key. Quick arithmetic against ML-DSA-87 (FIPS 204): a 2,592-byte public key plus a 4,896-byte private key plus protocol overhead pushes a single persisted key blob past 7.5 KiB, so a 16-KiB-NV TPM holds only a couple of persisted ML-DSA-87 slots. The larger SLH-DSA-256s signatures (29,792 bytes per FIPS 205 Table 2) [110] routinely exceed the typical 1-4 KiB response-buffer cap (`TPM_PT_MAX_RESPONSE_SIZE` in the PC Client Platform TPM Profile [115]); the related `TPM_PT_NV_BUFFER_MAX` (the maximum NV read/write chunk) is in the same order of magnitude and complicates persistent-storage cases as well. The chip cannot return such a signature in a single command without fragmentation extensions. PQC support on commodity TPMs is not just a software upgrade; it is a transient-buffer and NV-budget renegotiation.

**Third**, hybrid signing schemes (composite RSA + ML-DSA, or ECDSA + ML-DSA) are well-defined for transitional certificates. The IETF LAMPS WG draft on composite ML-DSA signatures [116] specifies "combinations of US NIST Module-Lattice-Based Digital Signature Algorithm (ML-DSA) in hybrid with traditional algorithms RSASSA-PKCS1-v1.5, RSASSA-PSS, ECDSA, Ed25519, and Ed448" for X.509 PKIX. The TLS hybrid key-exchange draft [117] does the same for TLS 1.3 handshakes. Neither defines a hybrid `TPM2_Sign` profile, and as of June 2026 no shipping Windows TPM exposes one.

Microsoft's Quantum Safe Security blog (August 2025) [118] describes the broader effort: "Our PQC effort began in 2014 when we published research on post-quantum algorithms... We participated in four submissions to the original 2017 NIST PQC call and one submission to the current call", but is silent on Pluton-firmware PQC support specifically.

The architectural punchline: Pluton's Windows-Update firmware delivery channel is the only realization that can plausibly add a PQC primitive across the deployed fleet without a hardware refresh. Every other realization will need new silicon to ship native PQC.

### The supply-chain trust of EK certificates

The Microsoft TPM key attestation documentation [89] describes the trust-chain assumption plainly: the requestor proves "to a CA that the RSA key in the certificate request is protected by either 'a' or 'the' TPM that the CA trusts." That trust is anchored on the EK certificate the chip's vendor issued at manufacture. A vendor-CA compromise therefore equals collapse of TPM-bound device identity for an entire OEM cohort.

The 2017 ROCA incident is the canonical event for why this matters. In February 2017, Matúš Nemec, Marek Sýs, Petr Švenda, Dušan Klinec, and Vashek Matyáš at Masaryk University [119] disclosed to Infineon a flaw in its RSA key-generation library that drastically reduced the entropy of generated keys and made factoring tractable. The NVD entry for CVE-2017-15361 [120] is precise about scope: "The Infineon RSA library 1.02.013 in Infineon Trusted Platform Module (TPM) firmware... mishandles RSA key generation, which makes it easier for attackers to defeat various cryptographic protection mechanisms via targeted attacks, aka ROCA. Examples of affected technologies include BitLocker with TPM 1.2, YubiKey 4 (before 4.3.5) PGP key generation, and the Cached User Data encryption feature in Chrome OS." The Wikipedia summary [121] reports the team's own estimate that the bug "affected around one-quarter of all current TPM devices globally."

The Estonian e-ID program (about 750,000 cards issued since 2014 [122], all using the affected Infineon chip) had to be re-enrolled. Microsoft published advisory ADV170012 [123] on the same coordinated disclosure date. There is still no scalable revocation mechanism for individual EK certificates: vendor-level revocation breaks every device whose EKpub was issued by that vendor's CA, and ADCS-template OEM-pinning limits scope but does not solve in-scope CA compromise. Pluton centralizes one part of trust (Microsoft as firmware signer); EK certificate issuance for the silicon is unchanged, and supply-chain integrity remains a per-vendor question.

### Attestation freshness in zero-trust networks

A TPM Quote proves "this device booted clean," not "this device is currently clean." Microsoft Intune's default device-compliance check-in is on the order of hours; Microsoft Entra's Continuous Access Evaluation documentation [124] specifies the upper-bound numerics: "By default, access tokens are valid for one hour... The goal for critical event evaluation is for response to be near real time, but latency of up to 15 minutes might be observed because of event propagation time."

A 15-minute revocation window for critical events is good. But it propagates *signed* policy decisions, not fresh TPM measurements. A device that was clean at boot, was compromised five minutes ago, and just made a request now will pass CAE if its existing access token is valid. Closing that window requires either much shorter token lifetimes, runtime attestation (TCG DICE, Project Cerberus), or a hypervisor-mediated re-measurement, and none of them are the TPM.

DPAPI-NG, the CNG-layer successor to classic DPAPI that Windows uses to encrypt secrets to a set of authorization principals, is a useful test case. The DPAPI-NG documentation [125] describes the API as "secure[ly] shar[ing] secrets (keys, passwords, key material) and messages by protecting them to a set of principals." The protection-descriptor grammar [126] permits five descriptor keywords (`SID`, `SDDL`, `LOCAL`, `WEBCREDENTIALS`, `CERTIFICATE`) across three logical authorization classes (AD-forest groups, web credentials, certificate-store entries). Notably absent: any literal `TPM=true` clause. DPAPI-NG can be backed by a TPM-bound CNG key, but the *authorization* is expressed in principal terms, not in TPM terms. The TPM is a key-residence property, not a policy primitive at this layer: the right architectural choice, but it means TPM-bound DPAPI-NG inherits the freshness limits of whatever principal authorization decides who is currently authorized.

### The Pluton political question

Centralizing firmware under a Microsoft-controlled signing authority and update trust root is a deliberate trade-off, not an oversight. The benefit is the patch path: a Pluton firmware vulnerability becomes a Windows Update release rather than a multi-quarter OEM capsule rollout. The cost is that the chip's firmware trust anchor is now Microsoft-controlled, in a way that even the most conservative dTPM is not. The market response in 2022 was openly mixed.

In March 2022, The Register obtained vendor statements [127] from Dell, Lenovo, and HP. Dell's reply was unusually direct: "Pluton does not align with Dell's approach to hardware security and our most secure commercial PC requirements." Lenovo deployed the chip but disabled it: "[ThinkPads] will not support Microsoft Pluton at launch... But ThinkPads introduced in January with AMD Ryzen 6000 processors will include Pluton as it's present in those AMD chips, though the feature will be disabled by default. AMD has provided an option for users to turn the feature on and off." PCWorld followed up [128] with Lenovo's articulated reasoning: "Pluton is disabled by default on 2022 Lenovo ThinkPad laptops using AMD Ryzen PRO 6000 Series processors because that's what Lenovo customers have asked for, the choice to enable or not."

Matthew Garrett, who later contributed the upstream Linux kernel support for the Pluton TPM CRB interface in Linux 6.3 (merged February 2023, released April 2023) [129], published the closest thing to a public engineering analysis of Pluton's controllability. His April 2022 reverse-engineering write-up [130] of the ASUS ROG Zephyrus G14 BIOS documents two firmware-level disable mechanisms on AMD Ryzen 6000 platforms: an x86-firmware "do not communicate" toggle, and a PSP directory entry 0xB BIT36 soft-fuse that "will NOT put HSP hardware in disable state, to disable HSP hardware, you need setup PSP directory entry 0xB, BIT36 to 1." Garrett's caveat is honest: "My interpretation of this is that it doesn't directly influence Pluton, but disables all mechanisms that would allow the OS to communicate with it." It is not a multi-signer proposal. There is no public peer-reviewed proposal for multi-signer or open-source Pluton firmware.

The unresolved engineering question: whether a multi-signer model is feasible without losing the timely-update property that motivated Pluton in the first place. The answer is genuinely unknown. The political question (whether one Microsoft-controlled firmware-signing trust root on the world's PC fleet is the right cost for the Windows-Update patch latency it enables) is no longer a technical argument. It is a procurement-policy and procurement-jurisdiction argument, and high-assurance fleets are deciding both ways.

The TPM was supposed to be the part of the system you didn't have to trust anyone for. Twenty-five years later, the trust question is back, and the answer is now political.

## What it means for you: A Windows practitioner’s TPM reference

What does this mean for the engineer running `Get-Tpm` on Monday morning? Three concrete things: discovery, choosing a form factor, and avoiding the pitfalls.

### Discovery

Three commands establish ground truth on any Windows 11 device. `Get-Tpm` returns presence, ownership, and command-availability state. `Get-TpmEndorsementKeyInfo` returns the EK public and certificate. `tpm.msc` opens the Microsoft Management Console snap-in. The TCG event log lives at `C:\Windows\Logs\MeasuredBoot\*.log` and contains the per-PCR measurement history for every boot. Microsoft's BitLocker page [79] documents the protector model that pairs with the TPM state.

```powershell
Get-Tpm | Format-List *
tpmtool getdeviceinformation
Get-TpmEndorsementKeyInfo
manage-bde -status C:
manage-bde -protectors -get C:
```

Read these as a decision tree, not as a compliance badge. A ready TPM tells you Windows has a hardware-rooted storage and attestation surface. The protector list tells you whether the OS volume is bound to that surface, whether recovery is escrowed, and whether the policy is TPM-only, TPM+PIN, or TPM+startup key.

### Choosing a TPM form when the OEM gives you a choice

A short decision tree, distilled from the SOTA analysis above:

- **Opportunistic theft, low-skill attacker.** Default TPM-only is acceptable but not ideal. TPM+PIN with at least 8 random digits mitigates unattended dTPM bus-sniffing and the low-PIN-entropy window on AMD fTPM.
- **Determined targeted adversary.** TPM+PIN is necessary but not sufficient. Add a startup-key factor or Network Unlock where appropriate (BitLocker's native OS-volume preboot authentication is TPM, TPM+PIN, and startup key, not FIDO2 or smart card), and prefer Pluton or hardened dTPM over commodity AMD fTPM for the device class.
- **Compliance-driven.** Discrete TPM with EAL4+ / FIPS 140-2 certification is still the easiest procurement story. Verify the OEM has not enabled `Pluton-as-TPM` if the auditor's checklist requires a discrete chip.
- **Cloud workload.** Azure Trusted Launch with vTPM [102] is the default for Gen2 VMs and underwrites Confidential VM offerings.
- **Surface Copilot+, AMD Ryzen 6000+, Intel Core Ultra 200V, Snapdragon X.** Pluton-as-TPM [6] is the OEM default in many SKUs; verify the Pluton firmware is current via Windows Update.

### Five common pitfalls

> **Verify recovery key escrow before clearing the TPM.** Clearing the TPM invalidates every TPM-bound protector, so the next boot falls back to the BitLocker recovery key. Always verify recovery key escrow first: in Microsoft Entra ID for Azure-AD-joined devices, in Active Directory for AD-joined devices, or in a printed/saved location for personal devices. If the recovery key is unescrowed and the TPM is cleared, the volume is unrecoverable.

The other four pitfalls in brief: firmware updates change PCR[0] and PCR[7], so suspend BitLocker before applying them; dual-boot Linux extends PCRs differently than Windows, so PCR-only sealing breaks under it, and the remedy is a PCR profile stable across both Secure-Boot-signed OSes rather than the PIN alone; Windows does not enable parameter encryption on the BitLocker boot path, so the actual mitigation against dTPM bus sniffing is preboot authentication, not "TPM hardening"; and Windows Hello for Business can generate keys in hardware if a TPM is available or in software depending on policy [88], so require hardware-backed keys by policy where that matters and periodically check `Get-Tpm` on enrolled devices. (*Margin note:* "Anti-hammering" is the persistent rate-limit counter the TPM enforces against authValue and policy-PIN failures. It survives reboots and only resets after a long lockout period.)

> **TPM+PIN is the single highest-impact setting.** The Group Policy setting "Require additional authentication at startup" with a minimum PIN length of 8 buys you the most security against published attacks for the least operational cost. It mitigates unattended Andzakovic-style bus sniffing by making the bus-captured VMK insufficient without the user secret; it does not protect a device that an attacker can instrument while observing a legitimate PIN-entered boot. It also forces an attacker on AMD fTPM to either compromise the TPM state out-of-band or guess the PIN against anti-hammering. The exception is a fully-extracted AMD fTPM where faulTPM has already obtained the unsealed material: in that case the PIN is bypassed.

### Suspend BitLocker before a firmware update

From an elevated PowerShell prompt:

```powershell
Suspend-BitLocker -MountPoint "C:" -RebootCount 1
```

The `RebootCount 1` argument auto-resumes after the next reboot, which is what you want when the firmware update reboots the device. After the update completes, run `Get-BitLockerVolume -MountPoint C:` and confirm `ProtectionStatus` is `On` again. If you forget, the next boot will land on the BitLocker recovery prompt because PCR[7] no longer matches the sealed policy.

The TPM does exactly what it was designed to do, no more. Which is exactly enough: if you understand what "exactly" means.

## Closing

Return to June 24, 2021. The PR backlash about a Trusted Platform Module made the chip visible for the first time to a consumer audience that had owned one for a decade. The technical rationale Microsoft gave was four words long; the actual rationale is the rest of this chapter.

A passive cryptoprocessor designed in 1999 quietly became the load-bearing pillar of half of Windows security. Twenty-five years of engineering refined a single primitive (measure, extend, seal, quote) into something one chip could underwrite. Twenty-five years of attacks, from a $40 FPGA on an LPC bus to a voltage glitch against the AMD PSP, argued empirically about how passive that chip can be allowed to be. The current state of the art is on the CPU die, in Rust, signed by Microsoft, patched through Windows Update, and post-quantum migration is the next argument.

The TPM is not a checkbox. It is the point at which Windows decided integrity must be measurable. It is not a panacea (the runtime-compromised OS still wins once the key is unsealed) but it is a primitive, with a clean boundary. Now you know what it can prove, and what it cannot. The chip is the cheapest part of the system. The cost was twenty-five years of getting it right.

> **What this link hands forward.** The TPM gives the rest of Part I four operations on one set of registers, and nothing more. Pluton (Chapter 3) re-homes those operations on the CPU die, closing the bus the discrete chip leaves exposed. Measured Boot (Chapter 4) consumes *measure* and *extend* to turn the path from reset to logon into a PCR transcript a sealed key can be bound to. Attestation (Chapter 5) consumes *quote* and the EK/AK identity to carry that transcript off the box, where a remote verifier can read it without trusting the OS's word. What the TPM explicitly does **not** hand forward is any defense once a key is unsealed: the moment the VMK or a Credential Guard secret lands in VTL0 RAM, a runtime-compromised kernel can read it, and closing that gap belongs to the active roots of trust: DRTM, and the VTL1 isolation that the Secure Kernel chapter (Chapter 6) and the Credential Guard chapter (Chapter 15) build. The TPM proves what booted. It cannot police what runs.
