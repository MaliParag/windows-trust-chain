# Measured Boot

::: trust-ledger

- **Inherits:** the PCR primitive, a register you can only *extend* (`PCR[N]:= H(PCR[N] || measurement)`), plus sealing and `TPM2_Quote` (Chapter 2, The TPM); Secure Boot enforcement, firmware that refuses any boot component unsigned under `db`/`dbx`, whose policy decision is itself measured into PCR[7] (Chapter 1, Secure Boot); and a silicon-rooted anchor for the very first measurement (Chapter 3, Pluton).
- **Promise:** Windows records the boot-time code and configuration inputs that its firmware and loader measure from platform reset to the kernel's ready-to-boot separator as one ordered, tamper-evident hash chain in the TPM's PCRs, so a BitLocker seal or a remote verifier can detect changes to the selected boot profile it was bound to.
- **TCB:** the silicon CRTM (Boot Guard ACM / AMD PSP / Pluton-backed firmware), the TPM's extend-and-hash implementation, and every stage measuring its successor *before* transferring control. The verifier that decides whether the measured state is *good* sits deliberately outside this TCB.
- **Adversary → Break:** an attacker who reproduces a seal-time PCR set with a still-signed but vulnerable binary (bitpixie, CVE-2023-21563) unseals the key the TPM was told to protect; malicious firmware can extend an honest digest yet hand the OS a forged event in the *unsigned* log. The Promise ends at "a faithful record of what ran". Never "what ran was trustworthy."
- **Residual:** whether the measured state is *good* (replaying the unsigned log and judging it) is not decided here → owned by Chapter 5 (Attestation); post-`EV_SEPARATOR` runtime compromise is invisible to PCRs → runtime attestation, layered above measured boot.
- **Bequeaths:** an ordered, replayable, TPM-quotable record of the boot, handed to Chapter 5 (Attestation). Does NOT provide: a verdict, or any enforcement. Measurement reports what ran, it does not refuse a bad boot.
- **Proof:** 🔵 documented: Microsoft Learn (`tpmtool`, `Tbsi_Get_TCG_Log`, BitLocker countermeasures) and the bitpixie disclosures (38C3 / Neodyme / SySS). No 🟢 silicon capture exists in `book/evidence/` for this chapter.
:::

## From reset to a PCR-Bound BitLocker key

> **The Reasoner's question.** How does Windows turn firmware, Secure Boot policy, boot manager, OS loader configuration, boot modules, ELAM, and boot authorities into PCR state, and why does that state decide whether the disk unlocks?

---

> **Foundations: vocabulary for this chapter.**
>
> - **PCR, sealing, and Measured-Boot-vs-Secure-Boot** are recapped in Foundations (Chapter 0) and owned by the TPM chapter (Chapter 2) and the Secure Boot chapter (Chapter 1). In one line: a PCR is a TPM register you can only *extend* (`PCR[N]:= H(PCR[N] || measurement)`); sealing releases a secret only when the PCRs match the state captured at seal time; Secure Boot *enforces*, while Measured Boot *reports*.
> - **SRTM.** The Static Root of Trust for Measurement: the early boot path rooted in the CRTM and platform firmware. SRTM begins at reset and measures firmware, platform configuration, option ROMs, Secure Boot variables, the boot manager, and the Windows boot-time transcript.
> - **CRTM.** The Core Root of Trust for Measurement: the smallest low-level code or silicon-rooted firmware that the platform treats as axiomatic. Modern PCs implement this through mechanisms such as Intel Boot Guard, AMD PSP firmware, or a Pluton-backed security-processor path.
> - **TCG event log / WBCL.** The ordered event list that explains the PCRs. PCR values are the tamper-resistant summary inside the TPM; the event log is the replayable narrative. Windows exposes the Windows Boot Configuration Log (WBCL), “also referred to as a TCG log,” through TPM Base Services.
> - **Correct Windows PCR split.** PCR[11] is the **BitLocker access-control PCR**: the index BitLocker seals to. Windows boot-component code measurements do **not** go there. Boot-application configuration and BCD state go to PCR[12]; boot module details, boot-critical drivers, and ELAM go to PCR[13]; boot authorities go to PCR[14]. The default BitLocker UEFI profile is `0x880`, meaning PCR[7] plus PCR[11].

---

**Measured Boot is the system that lets Windows prove the measured boot-time path from power-on to the kernel's ready-to-boot separator.** A small immutable block called the CRTM measures the next stage, extending a SHA-256 digest into a TPM register (a PCR); each stage measures its successor, building a hash chain whose final value is determined by the ordered sequence of measured boot inputs. BitLocker seals its Volume Master Key to a subset of those PCRs, so an unexpected change in the selected profile (for example Secure Boot policy or BitLocker access-control state on the modern default, and firmware or boot-manager code on stricter profiles) can force a 48-digit recovery prompt. The chain runs event by event from reset to the early OS handoff; reading it is what explains why bitpixie (CVE-2023-21563) was dangerous on TPM-only deployments, and what turns a Monday-morning recovery storm into six predictable commands.

## Two PCs that hash differently

At 06:00 on a Tuesday in March 2024, a senior administrator at a 500-seat law firm finishes patching her fleet of Dell OptiPlex 7090 desktops overnight. At 08:42 she has answered her 173rd help-desk ticket, all variations on the same theme: *Why is my PC asking for a 48-digit BitLocker recovery key?* The answer (the answer the rest of this chapter exists to make obvious) is that a single 32-byte SHA-256 register on every machine in her fleet now holds a different number than it did yesterday, and BitLocker's seal is bound to that number.

The patch she applied to make the fleet safer is the patch that locked it out.

Across town a second firm runs the modern default UEFI BitLocker profile, `0x880` (PCR[7]+PCR[11]). Those machines absorb a firmware-only UEFI delta that moves PCR[0] without a single recovery prompt, because PCR[0] is not in the selected seal profile. If the same maintenance changes Secure Boot policy (`db`, `dbx`, `PK`, or `KEK`) PCR[7] moves and those machines can still recover. Secured-core Secure Launch [179] is a separate attestation benefit: it adds a DRTM evidence plane in PCR[17-22], but default TPM-only BitLocker still keys off PCR[7] and PCR[11].

> **Platform Configuration Register (PCR), recap.** The TPM chapter (Chapter 2) owns this primitive: a register you cannot write, only *extend* (`PCR[N]:= H(PCR[N] || measurement)`, where `H` is a cryptographic hash) that resets to zero only at platform reset. A TPM 2.0 carries 24 PCRs per hash bank, with banks for SHA-1, SHA-256, SHA-384, SHA-512, and SM3-256. What *this* chapter adds is the content: what gets extended, in what order, from reset to the ready-to-boot separator.
>
> **Measured Boot.** A boot mode in which every stage of platform initialization hashes the next stage's code and configuration into one or more PCRs *before* transferring control. Measured Boot is *reporting*, not *enforcement*. It records what ran, but does not refuse to run anything. Secure Boot is the enforcement counterpart that refuses unsigned code; the two cooperate. Microsoft's `Trusted Boot` [9] extends the measurement chain into the Windows kernel.

Every byte that went into that hash can be named, every administrative action's effect on it predicted, and the TCG event log read on your own machine to confirm. Which is what the rest of this chapter does. It is also why the BitLocker seal is, in some configurations, a Faraday cage built on top of a fence the verifier never opened, and why the chip Microsoft calls the *Trusted* Platform Module knows nothing of trust (only of arithmetic over hashes) while the verifier, which knows what good looks like, is always someone other than the chip.

But first, the historical answer: how did a 32-byte register get into the position of deciding whether a PC boots cleanly or asks for a 48-digit key?

## Origins: Arbaugh 1997 and the chain-of-hashes axiom

The first paper to take the boot problem seriously is also one of the calmest. In 1997, three researchers at the University of Pennsylvania Distributed Systems Laboratory, William A. Arbaugh, David J. Farber, and Jonathan M. Smith: presented *A Secure and Reliable Bootstrap Architecture* [180] at the IEEE Symposium on Security and Privacy in Oakland. They opened with a line that ages disconcertingly well: "we find it surprising, given the great attention paid to operating system security that so little attention has been paid to the underpinnings required for secure operation, e.g., a secure bootstrapping phase for these operating systems."

They built a working prototype. A Pentium-class PC. A modified BIOS. A small PROM expansion card with public-key certificates. And, threaded through everything, an inductive structure they called AEGIS.

> **Chain of Trust.** An ordered sequence in which each stage of platform initialization verifies the cryptographic identity of the next stage *before* it executes. If every link verifies its successor, an external observer who trusts the first link transitively trusts the chain, modulo the cryptographic strength of the verification primitive.

AEGIS divided the boot into six levels (0 through 5). **L0** was a small trusted ROM that ran the first POST phase, the signature-verification routines, and recovery code. **L1** was the rest of the BIOS code plus CMOS. **L2** was option-ROM expansion cards (the era's GPUs, network cards, SCSI controllers). **L3** was the operating system boot block(s). **L4** was the OS kernel. **L5** was user programs and any network hosts the kernel reached. Each level verified the next before handing off; on a failed verification, L0 recovered the broken stage from a known-good network image. (The paper also presents a "four levels of abstraction" framing for one of its figures; the article uses the canonical six-level numbering.)

> **Core Root of Trust for Measurement (CRTM).** The smallest, lowest, most immutable code that runs after platform reset. It measures the next stage of firmware and extends that measurement into PCR[0] before transferring control. Modern PCs implement the CRTM in silicon (Intel's Boot Guard Authenticated Code Module, AMD's Platform Security Processor firmware, or Microsoft's Pluton silicon) because anything mutable is not actually a root of trust.

The architectural axiom that survived 28 years of evolution is this: there is always a bottom layer you cannot verify yourself. AEGIS does not eliminate that layer; it reduces trust to *the smallest possible* unverifiable thing. The L0 trusted ROM is the axiom; everything above it is provable from the axiom. Replace "trusted ROM" with "Boot Guard ACM" or "PSP boot ROM" or "Pluton silicon firmware" and the structure does not change.

AEGIS could not, on its own, make the next pivot. It had no hardware-rooted endorsement key. It had no append-only register that could not be lied to. It had no remote-attestation primitive: the L0 ROM trusted itself, but an external auditor was forced to trust the BIOS's own report of the bootstrap. The trick AEGIS could not pull off is the trick the Trusted Computing Platform Alliance was about to attempt: *make the root a chip*. (Arbaugh continued the work at the University of Maryland and later took a senior position at the National Security Agency. The bootstrap problem followed him; in 2005 he co-authored an early TPM-on-Linux survey that anticipates several of the PCR allocation conventions that PFP would formalize.)

The TCPA was founded on October 11, 1999 [73] by Compaq, Hewlett-Packard, IBM, Intel, and Microsoft. Its first specification [73] shipped January 30, 2001. The first hardware-TPM-equipped PC shipped on the IBM ThinkPad T30 in 2002 [73] (with a TPM 1.1-class Infineon SLB chip); the TPM **1.1b** revision deployed in volume the year after. In 2003 the TCPA was reorganised as the Trusted Computing Group, with AMD joining as a founding board member.

The thing AEGIS could not do (turn a chain of in-RAM hash comparisons into a record a remote party can trust) is what the TPM became.

## Early approaches: TPM 1.1b, SHA-1, and the original PCSI

*"The first TPM version that was deployed was 1.1b in 2003"* [181]: Wikipedia, drawing on the TCPA shipment record. A 24-pin chip in a tiny LPC-bus package, soldered to the motherboard of a ThinkPad T30. Sixteen PCRs. One hash bank: SHA-1, 20 bytes wide. A monotonic counter. An endorsement key, fused at manufacture. A storage root key, generated at first ownership. By 2010, hundreds of millions of business PCs shipped with one. By July 28, 2016, Microsoft's Windows 10 hardware logo program required TPM 2.0 on every new OEM Windows 10 PC: desktop, mobile, and server alike [181].

The mechanic that did all the work is one operation: `TPM_Extend`. It takes a PCR index and a 20-byte digest. It produces a new PCR value defined as `PCR[N]:= SHA1(PCR[N] || digest)`.

> **Extend (TPM operation), recap.** Owned by the TPM chapter (Chapter 2): the only writable mutation a TPM permits on a PCR is `PCR[N]:= H(P || M)`. There is no `set`, no `clear` (PCRs reset only at platform reset, and some not even then). The hash chain is the *only* trace, and the next few pages show why that single property is load-bearing for boot.

That two-letter primitive (*extend*) is doing more cryptographic work than its size suggests. A PCR is not a set of measurements; it is a *sequence*. If three boot stages measure three values `a`, `b`, `c` into PCR[0] in that order, the resulting PCR encodes `H(H(H(0 || a) || b) || c)`. Reorder the stages and the final hash differs. Repeat a stage and the final hash differs. *Skip* a stage (the move every rootkit dreams of) and the final hash differs. Under collision-resistance of the underlying hash, producing the same final PCR via a different ordered sequence is computationally infeasible.

> **Why 'extend' and not 'store'.** A naive design might use the PCR as a set: write each measurement into a separate slot, and let the verifier check that the set matches a known-good baseline. That design has two pathologies. First, an attacker who controls one stage can simply *not* report its measurement and let the verifier see a smaller set than ran. Second, order doesn't matter to a set; an attacker can rearrange the stages and slip a measured-but-vulnerable component in early, where its measurement still "matches" the baseline.
> >
> Extend solves both. You cannot omit a stage without changing the final hash. You cannot reorder. You cannot insert. The cost is that *the verifier cannot read the PCR as a list of measurements*. It has to be given the list (the TCG event log) separately and re-derive the final PCR by replaying the extends. This is the trade we will meet again in the limits analysis.

The PC Client Specific Implementation (PCSI) specification carved up the 24 PCRs of TPM 1.2, the chip the TPM chapter (Chapter 2) covers, into eight indices that the world still uses today. PCR[0] holds the CRTM, the system firmware code, and the firmware host platform extensions. PCR[1] holds the host platform configuration (CMOS settings that change platform behavior). PCR[2] holds the option ROM code. PCR[3] holds the option ROM configuration. PCR[4] holds the master boot record code (and on UEFI machines, the boot-loader image). PCR[5] holds the master boot record partition table (and on UEFI machines, the boot configuration). PCR[6] holds state-transition and wake events. PCR[7] holds host platform manufacturer control: a category that, post-PFP, became Secure Boot policy.

> **PCR Bank, recap.** The TPM chapter (Chapter 2) owns banks: TPM 2.0 keeps the same PCR index once per hash algorithm, so a measurement of the same source bytes produces bank-specific digests that are extended into each active bank. That is exactly why the event-log record below must carry a *list* of digests, not one.

TPM 1.2 also defined the first remote-attestation primitive in industry hardware: `TPM_Quote`. The TPM signs a snapshot of selected PCR values plus a verifier-supplied nonce with a private key the chip alone holds (the attestation identity key, certified by a Privacy CA). The verifier checks the signature, checks the nonce, checks the AIK certificate chain, and re-derives the expected PCR set from a TCG event log delivered separately. If the re-derivation matches the signed quote, the platform's boot history is authenticated.

It worked. For a while. Then, on February 23, 2017, the SHAttered team published the first public SHA-1 collision [81]. The team was Marc Stevens (CWI Amsterdam) and Pierre Karpman (Inria), with Elie Bursztein, Ange Albertini, and Yarik Markov (Google Research). Two PDF files with identical SHA-1 hashes. The collision cost about 110 GPU-years of compute [81]. The implication for TPM 1.2 was immediate: a 20-byte SHA-1 PCR can no longer be assumed unique under attacker-controlled input. (The SHA-1 choice in 2003 was state-of-the-art at the time, not negligence. NIST's SHA-256 had been published in 2001 but was not yet broadly trusted; SHA-1 was the IETF-blessed default for X.509 and many TLS deployments. The SHAttered collision required compute that did not exist commercially in 2003. By 2017 it required compute that anyone with a Google Cloud account could buy.)

If the cryptographic floor is broken and you cannot re-floor in place: a TPM 1.2 chip cannot grow a SHA-256 bank [181]. You replace the floor with one that can be moved. That is what TPM 2.0 became.

## Evolution: TPM 2.0, hash agility, and the UEFI PFP

On April 9, 2014, the Trusted Computing Group announced the TPM Library Specification 2.0 [181]. ISO ratified the result the following year as ISO/IEC 11889-1:2015 [84], and confirmed the standard as current in a 2021 review. The change set is large (new algorithm framework, NV index ACLs, sessions, command authorization area, ECC primary keys) but the line that matters for measurement is the simplest one: PCRs now exist in *banks*.

> **Hash Agility, recap.** A TPM-2.0 property the TPM chapter (Chapter 2) owns: a hash function can be swapped without changing interfaces. It is not free. Every bank costs storage and extend time, and the verifier must agree with the prover on which bank to read. For measured boot, that agreement is the difference between a log that replays and one that does not.

A TPM 2.0 chip can run a SHA-1 bank, a SHA-256 bank, and (often) a SHA-384 bank in parallel, plus optional SHA-512 and SM3-256. The same PCR index lives once per bank. A `TPM2_PCR_Extend` call updates each selected bank with a digest already computed for that bank's algorithm; the original measured bytes may be the same, but the digest supplied to the TPM is per-algorithm. `TPM2_PCR_Allocate` reconfigures the bank set at runtime, gated by platform authorization.

The event log structure had to grow with the chip. The pre-2014 log format (`TCG_PCR_EVENT`, single SHA-1 digest) could not carry per-bank digests. The PC Client PFP defined a new structure, `TCG_PCR_EVENT2`, documented in Microsoft's `Tbsi_Get_TCG_Log` reference [182]. Its two load-bearing parts are the event log container and the multi-bank digest list.

> **TCG Event Log.** An in-RAM ordered list of `TCG_PCR_EVENT2` records, populated by firmware and OS components in the exact order they extend digests into PCRs. The log is *unsigned*: only the PCR values are signed when the verifier later requests a quote. A verifier replays the log to re-derive the PCR values and accepts the log if the re-derivation matches the signed quote.
>
> **TPML_DIGEST_VALUES.** The multi-bank digest container inside `TCG_PCR_EVENT2`. It holds a `Count` of `TPMT_HA` records, each carrying a hash-algorithm identifier (`HashAlg`, a TPM_ALG_ID) and the corresponding digest. A modern Windows log on a SHA-256-and-SHA-1 dual-bank TPM emits `Count = 2` per event with both digests of the same source bytes.

The very first event in a TPM-2.0-format log is, deliberately, a TPM-1.2-format record. From Microsoft Learn verbatim [182]: *"The Signature member of the TCG_EfiSpecIdEventStruct structure is set to a null-terminated ASCII string of `\"Spec ID Event03\"`"*. That string is the self-describing handshake: a parser that doesn't know about banks reads the legacy event and either understands it (continuing as a 1.2 parser) or recognizes the Spec ID handshake (and upgrades to the 2.0 parser). The cost of forward compatibility is precisely one event. (The "Event03" suffix is not a typo. The TCG PC Client Platform Firmware Profile defines `TCG_EfiSpecIDEventStruct` with `Signature[16]` containing the ASCII string and a `specVersionMajor`/`specVersionMinor`/`specErrata` triplet. The "03" denotes the third revision of the format. Earlier "Spec ID Event02" structures exist in pre-1.21 PFP firmware; they encode banks differently and are extremely rare in Windows-era machines.)

The bridge between the chip and the firmware is a UEFI protocol. `EFI_TCG2_PROTOCOL` [183] (UEFI 2.5 and later) exposes three calls that matter: `HashLogExtendEvent` (the one-shot "hash this blob, log it, extend the PCR" call), `GetEventLog` (return the in-progress event log to a caller), and `GetCapability` (which banks are active, which algorithms are supported). After `ExitBootServices`, the firmware publishes the final log as a UEFI configuration table; the OS reads it from there.

The Microsoft PFP-era PCR allocation is the table every modern Windows administrator should memorise.

| PCR | TCG PFP definition | Microsoft WBCL convention | Linux IMA / shim convention |
| -: | -: | -: | -: |
| 0 | SRTM, BIOS, host platform extensions, embedded option ROMs | Firmware version (`EV_S_CRTM_VERSION`); platform firmware blob | Same |
| 1 | Host platform configuration | BIOS setup data | Same |
| 2 | UEFI driver and application code (option ROMs) | Pluggable option ROM code | Same |
| 3 | UEFI driver and application configuration | Option ROM data | Same |
| 4 | UEFI boot manager and boot attempts | `EV_EFI_BOOT_SERVICES_APPLICATION` for `bootmgfw.efi` | Same (shim/grub image) |
| 5 | Boot manager configuration and data | Boot partition GPT, EFI variables loaded by boot manager | Same |
| 6 | Host platform manufacturer events | Wake reason, S-state events | Same |
| 7 | Secure Boot policy | `SecureBoot`/`PK`/`KEK`/`db`/`dbx` variable digests | Same |
| 8-9 | OS-loader reserved | Unused on Windows | Linux kernel measurement (some distros) |
| 10 | OS-loader reserved | Unused on Windows | IMA file measurements (canonical) |
| 11 | OS-loader reserved | BitLocker access-control PCR; the index BitLocker seals to | Unused |
| 12 | OS-loader reserved | Boot-application configuration and BCD state | Unused |
| 13 | OS-loader reserved | Boot module details, boot-critical drivers, ELAM policy and verdicts | Unused |
| 14 | OS-loader reserved | Boot authorities and code-signing authorities for boot components | shim MOK certificate enrollment |
| 15 | OS-loader reserved | Reserved | Reserved |
| 16 | Debug | Used during development | Same |
| 17-22 | Dynamic OS (DRTM use only) | Secure Launch, Authenticated Code Module | TrenchBoot, tboot |
| 23 | Application support | Reserved | Reserved |

A small word on the index column: a 24-PCR TPM ranges from PCR[0] to PCR[23]. (The PFP allocates PCR[16] as a debug index that platform firmware may extend during development; the value resets to zero at TPM_Init, which is one of two PCRs (the other is PCR[23]) the platform may explicitly reset.) The allocation itself is normative in the PFP, but it sits inside a wider policy frame: NIST SP 800-155 (BIOS Integrity Measurement Guidelines, December 2011 IPD) [184] defined the federal procurement bar for "BIOS integrity measurement", a draft that, despite never finalizing, became the de-facto procurement template for the SRTM measurement chain U.S. agencies require their suppliers to ship.

> **Why the TCG specifications return 403 in your browser.** If you click the canonical TPM 2.0 Library Specification link [83] or the PC Client PFP link [185], the trustedcomputinggroup.org host returns HTTP 403 to non-browser User-Agents and to some browser fingerprints. The specifications exist and are normative; we cite them by canonical URL. For verbatim struct definitions and the `"Spec ID Event03"` string, Microsoft's `Tbsi_Get_TCG_Log` reference [182] reproduces them word-for-word; Wikipedia's TPM article [181] corroborates the spec metadata.

Measured boot evolves through five overlapping eras and consumer layers: AEGIS in 1997; TCPA and TPM 1.1b/1.2 from 1999 through the PCSI era; TPM 2.0 and ISO/IEC 11889 hash agility beginning in 2014-2015; DRTM from Intel TXT and AMD SKINIT into Microsoft Secure Launch; and the current attestation era in which Azure Attestation, Intune DHA, and the in-flight PFP revision consume the same evidence plane.

We now have a self-describing log, a hash-agile PCR set, and a verbatim ABI. Who actually writes the log? And who reads it?

## The breakthrough: One log, many consumers

Every trust decision a modern Windows machine makes about its own boot ultimately consults the same record. BitLocker's seal release. Windows Defender System Guard runtime attestation [104]. Windows Hello for Business device-bound key attestation. Microsoft Azure Attestation [186] policy evaluation. Microsoft Intune Device Health Attestation. Conditional Access posture checks. All of them ultimately rest on the same measurements: the attestation consumers replay the TCG event log against the quoted PCRs, and BitLocker's seal release binds to the live PCR values those measurements produced. One log; every feature.

This is the structural insight. It is also the reason this specification has survived three generations of attacks: the cost of designing a new attestation feature on Windows is no longer "design a new measurement plane," it is "decide which PCRs your policy cares about."

> **Key idea.** One log, many consumers. Every Windows trust decision about boot integrity: BitLocker unseal, System Guard attestation, Hello for Business key attestation, Azure Attestation, Intune Device Health Attestation, Conditional Access: ultimately consults the same TCG event log and the PCR snapshot it replays into. The cost of adding a new attestation feature is not a new measurement plane; it is a policy decision about which PCRs matter.
>
> One log, every feature.

The cooperative writers populate the log in pipeline order, following the Microsoft `Tbsi_Get_TCG_Log` PCR allocation [182]. Firmware (the silicon root of trust and everything above it through the UEFI driver execution environment) writes PCRs 0 through 7. The Microsoft boot manager image `bootmgfw.efi` is measured into PCR[4] by the preceding UEFI stage (an image is measured before it runs), and `bootmgfw.efi` itself writes Windows boot-application configuration into PCR[12]. PCR[11] remains the BitLocker access-control PCR: it is the index BitLocker seals to, not the bucket for kernel, HAL, or boot-driver code. The Windows OS loader `winload.efi` writes boot module details, boot-critical driver information, and ELAM policy/verdict material into PCR[13], while boot authorities are represented in PCR[14]. UEFI firmware emits an `EV_SEPARATOR` event into PCR[0-7] at the end of the firmware phase, and Windows emits separators into its own OS PCRs once the boot-time measurement phase is complete, freezing the boot-time slice of the log for verifiers.

The unified reader path mirrors the writer fan-in. `EFI_TCG2_PROTOCOL.GetEventLog` exposes the main log to firmware drivers and applications before `ExitBootServices`; events measured after that call are published separately through the `EFI_TCG2_FINAL_EVENTS_TABLE` configuration table. Windows reads both during boot and exposes the merged log (the firmware portion plus the OS-loader extensions) to user mode through `Tbsi_Get_TCG_Log` [182]. Operators read it with the inbox `tpmtool.exe` or cross-platform `tpm2_eventlog` [187]; the practical guide below walks the full tool set.

In prose, the writer fan-in is this: firmware writes the SRTM platform slice into PCR[0] through PCR[7]; the UEFI BDS phase measures the Microsoft boot manager image into PCR[4]; Windows boot components then use Microsoft WBCL events without placing boot-component code in PCR[11]. PCR[11] remains the BitLocker access-control PCR. Boot-application configuration and BCD state belong in PCR[12]; boot module details, boot-critical drivers, and ELAM policy/verdict material belong in PCR[13]; boot authorities belong in PCR[14]. The kernel finishes the boot-time slice by emitting separator events.

A single canonical log eliminates per-feature reinvention. Azure Attestation does not have to parse a different log than BitLocker. Hello for Business does not have to extend its own PCRs. The verifier community (the part that knows what "good" means) builds policies on top of one shared substrate; that community is exactly where the Attestation chapter (Chapter 5) begins. Measured boot manufactures one canonical evidence plane; deciding *good* from *bad* on top of it is the next link's work, not this one's.

We have named the log abstractly. What does an actual event look like, byte by byte, on the wire?

## State of the art: A line-by-line walk through the SRTM chain

We walk the chain in the exact order events are logged on a modern UEFI Windows 11 24H2 machine. Reference: a Dell OptiPlex 7090 with Boot Guard, TPM 2.0 in SHA-256-only mode, Secure Boot enabled, BitLocker with TPM-only protector bound to the PFP-default UEFI profile.

The first *measured* event, after the initial `EV_NO_ACTION` Spec ID record described above, is a `EV_S_CRTM_VERSION` record. PCR index 0. Event type `0x00000008`. One digest per active bank. Event size varies with the encoded firmware-version string. Event data is a little-endian UTF-16 firmware-version string, padded as that implementation emits it. The CRTM extends *its own* version into PCR[0] before measuring anything else. This is the foundation event.

## The CRTM and PCR[0]

The very first instruction the CPU fetches after reset is not in DRAM. On a modern x86, it is in an immutable silicon region whose location and contents differ by silicon vendor.

On AMD Zen-class platforms, the Platform Security Processor (a 32-bit ARM core inside the SOC) boots first, validates the platform firmware against a key fused into silicon, and only then releases the x86 cores from reset. On Intel platforms with Boot Guard, the Authenticated Code Module is loaded from firmware into the cache-as-RAM region, signed by a key whose hash is fused into Intel chipset OTP fuses, and verified by microcode before x86 main core start. On Microsoft Pluton SKUs, the TPM-facing anchor is a distinct Microsoft-designed security-processor IP block integrated into the SoC die (Chapter 3). On AMD Ryzen 6000-series and later parts, Pluton coexists with the existing AMD PSP and PSP-based fTPM; it is not merely a firmware mode running inside the PSP.

In every case, the platform's silicon-rooted CRTM measures the next stage of firmware before transferring control. From Microsoft's hardware-rooted trust documentation [188], verbatim: *"This technique of measuring the static early boot UEFI components is called the Static Root of Trust for Measurement (SRTM)."* The SRTM extends PCR[0] with a chain of three early events: `EV_S_CRTM_VERSION` (firmware version), `EV_S_CRTM_CONTENTS` (the immutable CRTM code hash), and `EV_POST_CODE` (the POST code region hash). Then, if the platform has a separable firmware volume, an `EV_EFI_PLATFORM_FIRMWARE_BLOB` event covers the rest of the SPI flash region per the TCG PFP event-type registry surfaced in Microsoft's `Tbsi_Get_TCG_Log` reference [182]. The PFP closes PCR[0] with an `EV_SEPARATOR` event at the BDS boundary.

Where the firmware-version string differs, the SHA-256 digest of the `EV_S_CRTM_VERSION` event data differs. Where the `EV_S_CRTM_VERSION` digest differs, PCR[0] differs. That is the entire mechanism by which an overnight UEFI patch changes PCR[0]. Dell updated the firmware string from "1.16.0" to "1.17.0"; the bytes hashed; the PCR moved; the seal broke.

## PEI/DXE, option ROMs, and PCR[1-3]

After the CRTM hands off, the Pre-EFI Initialization (PEI) phase runs and the Driver Execution Environment (DXE) phase loads UEFI drivers. PEI does early silicon initialization (memory controller, cache topology, basic chipset config) and DXE does device discovery, including option ROMs for plug-in cards.

Each option ROM that runs is measured into PCR[2]. The option ROM's configuration (card-specific NVRAM state that survives reboot) is measured into PCR[3]. The PFP also reserves PCR[1] for the platform configuration: CMOS settings, the SMBIOS table contents, and any BIOS-setup-visible knob that affects platform behavior per the PCR-allocation mapping surfaced in Microsoft's `Tbsi_Get_TCG_Log` documentation [182]. Disabling a USB controller in firmware changes PCR[1]. (UEFI boot-order changes, by contrast, are recorded as `EV_EFI_VARIABLE_BOOT` events in PCR[5], not PCR[1].) Installing a discrete GPU adds an `EV_EFI_BOOT_SERVICES_DRIVER` event into PCR[2] for the GPU's video BIOS.

## Secure Boot variables and PCR[7]

PCR[7] is the Secure Boot policy PCR. It records the digests of the five values that define Secure Boot identity (Chapter 1): `SecureBoot` (the on/off flag), `PK` (Platform Key), `KEK` (Key Exchange Key), `db` (allowed signers), and `dbx` (revocation list). It also records any signed program execution events the firmware logs to PCR[7] under `EV_EFI_VARIABLE_AUTHORITY` [189].

Each variable contributes one `EV_EFI_VARIABLE_DRIVER_CONFIG` event whose Event field encodes `(VariableName GUID, UnicodeName, VariableDataLength, VariableData)` and whose digest is the SHA-256 of that entire structure. *The digest is not over the variable data alone*; it is over the GUID and name as well. This matters: when the May 2023 Microsoft `dbx` update shipped under KB5025885 [190] added the BlackLotus-vulnerable boot manager hashes to the revocation list, the variable data length grew, the structure changed, and the resulting `EV_EFI_VARIABLE_DRIVER_CONFIG` digest differed. Every Secure-Boot-enabled UEFI Windows machine that consumed that `dbx` update in the relevant bank saw PCR[7] move.

From the Wack0/bitlocker-attacks index [189], reproducing TCG EFI Platform Specification §6.4 verbatim: *"If the platform provides a firmware debugger mode which may be used prior to the UEFI environment or if the platform provides a debugger for the UEFI environment, then the platform SHALL extend an EV_EFI_ACTION event into PCR[7] before allowing use of the debugger"*. The intent is clear: a debugged firmware is a different PCR[7] than a production firmware. The verifier can refuse to release a key to a debugged platform.

## Boot manager (bootmgfw.efi), PCR[4], PCR[11], and PCR[12]

The UEFI Boot Device Selection (BDS) phase locates `EFI/Microsoft/Boot/bootmgfw.efi` on the EFI System Partition, computes its Authenticode digest (Chapter 12), verifies the Authenticode signature against `db` and `dbx`, logs an `EV_EFI_BOOT_SERVICES_APPLICATION` event into PCR[4] [182] with that digest, and transfers control. PCR[4] now binds to the boot manager's image content. A different boot manager binary (a different version, a different language pack) produces a different PCR[4].

> **Authenticode, recap.** The Authenticode and Catalog Files chapter (Chapter 12) owns this PE signature format; the one fact measured boot needs is that the Authenticode digest is computed over the PE image *excluding* fields the loader rewrites (file-offset bytes, the checksum field, the digital-signature pointer), so it is not a raw SHA-256 of the file. Secure Boot and the PCR[4] measurement both use that Authenticode-style PE image hash, not the bytes on disk; Boot Guard is a separate firmware root of trust and does not Authenticode-hash Windows boot applications.

Once `bootmgfw.efi` runs, it begins the Microsoft-specific Windows Boot Configuration Log (WBCL) portion of the transcript. The correction that matters operationally is the PCR split. PCR[11] is the *BitLocker access-control PCR*: the index BitLocker seals to. Boot-application configuration, including BCD state and boot-debug settings, is measured into PCR[12]. Boot module details, boot-critical driver information, and ELAM material are measured into PCR[13]. Boot authorities are represented in PCR[14]. Do not read PCR[11] as the place where kernel, HAL, or boot-driver code measurements accumulate.

> **Windows Boot Configuration Log (WBCL).** The Microsoft-specific extension of the TCG event log carrying boot-manager, loader, and ELAM events. WBCL events use the TCG `EV_EVENT_TAG` event type with Microsoft-private sub-types. They are extended into the Windows boot PCRs with the corrected split: PCR[11] for BitLocker access control, PCR[12] for boot-application configuration, PCR[13] for boot module and ELAM details, and PCR[14] for boot authorities. WBCL is exposed by `Tbsi_Get_TCG_Log`/`Tbsi_Get_TCG_Log_Ex`; `tpmtool gatherlogs` collects the SRTM/DRTM boot logs, while `tpmtool getdeviceinformation` reports basic TPM information [191].

## winload.efi and the ELAM handoff

`bootmgfw.efi` chains to `winload.efi`, the OS loader. `winload` measures the Windows kernel image (`ntoskrnl.exe`), the Hardware Abstraction Layer (`hal.dll`), the OS configuration data, and each boot-critical driver in load order as WBCL boot-module detail. Those boot-component code measurements belong in PCR[12] through PCR[14], with boot-application configuration in PCR[12], boot module details and boot-critical drivers in PCR[13], and boot authorities in PCR[14]. They do **not** belong in PCR[11]. A kernel or boot-driver update changes the boot-module transcript, but PCR[11] remains BitLocker's access-control PCR.

The Early Launch Anti-Malware (ELAM) interface gives a vendor anti-malware driver a chance to run before all other drivers and approve or block subsequent driver load attempts. `winload` measures the ELAM policy file hash into PCR[13]; the ELAM driver, when loaded, extends its own image digest into PCR[13]; the ELAM driver then returns its allow/deny verdict on each subsequent driver, and `winload` logs those verdicts (also into PCR[13] under WBCL `EV_EVENT_TAG`).

## Kernel and the final separator

Once the Windows kernel starts, it exposes the TCG event log through the TPM Base Services driver `Tbs.sys`, which is consumed by Win32 callers through `Tbsi_Get_TCG_Log`. The kernel emits its `EV_SEPARATOR` "ready-to-boot" marker into the Windows OS PCRs (the firmware already closed PCR[0-7] with its own separators at the BDS boundary). After the separator, the Windows boot-time WBCL slice this chapter follows is frozen. A verifier reading that log at this point sees the measured boot history up to the early OS handoff; final-events tables, resume logs, DRTM logs, and runtime measurement systems are separate surfaces.

## Reading the log from user mode

On a Windows 11 24H2 machine, use `tpmtool gatherlogs <dir>` from an elevated prompt to collect `SRTMBoot.dat` and `DRTMBoot.dat`; Microsoft documents `getdeviceinformation` as basic TPM information, not a raw WBCL parser [191]. For API-level access, `Tbsi_Get_TCG_Log` returns the most recent WBCL [182]; for HLK workflows, `MeasuredBootTool.exe -log <path>` reads the raw binary log file written under `C:\Windows\Logs\MeasuredBoot\*.log`.

Cross-platform, `tpm2_eventlog` [187] from the tpm2-tools suite [192] parses any binary log conforming to the PC Client PFP, including Windows-saved logs, because the WBCL extension is structurally compatible. The man page is precise: *"tpm2_eventlog(1): Parse a binary TPM2 event log... The format of this log documented in the 'TCG PC Client Platform Firmware Profile Specification'."* On Linux, the firmware-published log lives at `/sys/kernel/security/tpm0/binary_bios_measurements`.

Two iterative extends of the same measurements in a different order produce two completely different 32-byte PCR values. The PCR encodes *the order*. A verifier comparing your machine's boot-module PCRs (especially PCR[13] for boot module details and boot-critical drivers) against a known-good baseline is implicitly checking that the kernel, the HAL, and the boot-critical drivers all loaded in the expected sequence, not just that they all loaded. Reorder the chain, even with identical inputs, and the PCR moves. This is the property that makes the chain-of-hashes axiom load-bearing.

## The PCR allocation cheat sheet

Pin the PCR-allocation table to your wall. Most operational questions reduce to "which PCR is affected by this change, and is it in my BitLocker profile?" Three quick rules:

1. **Code changes go to even PCRs (0, 2, 4).** Firmware blob, option ROM, boot manager. A firmware update moves PCR[0]; a discrete GPU swap moves PCR[2]; a boot-manager update moves PCR[4].
2. **Configuration changes go to odd PCRs (1, 3, 5).** BIOS setup, option ROM config, EFI variables seen by the boot manager.
3. **Policy and identity go to PCR[7].** Secure Boot keys. Any `dbx` update moves PCR[7]. Disabling Secure Boot moves PCR[7]. Enrolling third-party `db` entries moves PCR[7].

PCR[11] is the BitLocker access-control PCR on Windows. PCR[12] is boot-application configuration and BCD state. PCR[13] is boot module details, boot-critical drivers, and ELAM policy/verdict material. PCR[14] is, by Microsoft convention, boot-loader-authority events; by Linux shim convention, MOK enrollment. Same index; different ontology. Verifiers must pick a side.

## BitLocker seal-binding

![Figure: BitLocker seal vs unseal. At seal time TPM2_PolicyPCR derives the sealed VMK policy from the selected PCRs; every boot rebuilds the policy session and TPM2_Unseal releases the VMK only when the live PCR digest matches the sealed policy, otherwise the 48-digit recovery path. The default UEFI profile 0x880 binds PCR[7] and PCR[11].](diagrams/03-measured-boot-seal-unseal.svg)

BitLocker's Volume Master Key is wrapped by a TPM-resident sealed blob whose policy is `TPM2_PolicyPCR` over a chosen *PCR profile*. The default UEFI profile is the bitmask `0x00000080 | 0x00000800 = 0x880`, that is PCR[7] (bit 7 = `0x80`) plus PCR[11] (bit 11 = `0x800`), as documented in the BitLocker configuration reference [193], which notes verbatim that *"when Secure Boot State (PCR7) support is available, the default platform validation profile secures the encryption key using Secure Boot State (PCR 7) and the BitLocker access control (PCR 11)."* The legacy CSM/BIOS profile is `0x00000015 | 0x00000800 = 0x815`. That is PCR[0], PCR[2], PCR[4], plus PCR[11].

At seal time (when BitLocker enables, or when a user changes the protector configuration), BitLocker builds a `TPM2_PolicyPCR` authorization policy digest from the current values of the selected PCRs. At every subsequent boot, the boot manager rebuilds the session, calls `TPM2_PolicyPCR` with the *current* PCR values, and calls `TPM2_Unseal`. If the current PCRs match the seal-time digest, the TPM releases the VMK and BitLocker unlocks transparently. If they don't match, the TPM refuses and Windows prompts for the 48-digit recovery key.

From Microsoft's BitLocker countermeasures documentation [105]: *"By default, BitLocker provides integrity protection for Secure Boot by using the TPM PCR[7] measurement. An unauthorized EFI firmware, EFI boot application, or bootloader can't run and acquire the BitLocker key"*. The PCR[7]-default choice is deliberate: PCR[7] is the *policy* PCR, not the *code* PCR. Firmware updates don't change a Secure-Boot-policy hash; only key-database updates do.

The boot-time authorization flow is the same profile check in motion: firmware extends the platform PCRs, the boot manager participates in the Windows boot measurements, and BitLocker asks the TPM to unseal only after applying `TPM2_PolicyPCR` to the configured profile.

The on-disk registry path that records the profile choice is `HKLM\SOFTWARE\Policies\Microsoft\FVE\PlatformValidationProfileUEFI` [193]. The value is a 24-bit bitmask where bit `N` selects PCR[N]. A device that sealed under the default `0x880` profile and then has Group Policy changed to `0x815` will *not* automatically re-seal. You must explicitly disable and re-enable the TPM protector with `manage-bde -protectors` [194] to rotate the policy.

Those profile masks cover common defaults and common stricter variants; enterprises can and do set custom validation profiles. If the mask includes PCR[0], every firmware update will trigger a recovery prompt. If it omits PCR[0] but includes PCR[7], only Secure Boot key changes (Microsoft's annual `dbx` updates, third-party Linux enrollments, BIOS-setup Secure Boot toggles) will. The four canonical recovery-prompt causes follow directly:

| Cause | PCR affected | Default `0x880` recovery risk | Mitigation |
| -: | -: | -: | -: |
| UEFI firmware update | PCR[0] | No, unless policy also selects PCR[0] | Suspend BitLocker before firmware update on legacy/stricter profiles |
| Microsoft `dbx` update or Secure Boot key rotation | PCR[7] | Yes | Suspend BitLocker before Secure Boot DB/DBX updates |
| Boot-manager binary swap (KB-driven update) | PCR[4] and, depending on policy/log contents, PCR[12] through PCR[14] | Not merely because PCR[4] changed; yes only if a selected PCR changed | Suspend BitLocker before boot-chain updates that touch selected PCRs |
| Firmware setup change (virtualization toggle, device enable/disable) | PCR[1] | No, unless policy also selects PCR[1] | Suspend BitLocker before deliberate changes on profiles that select PCR[1] |

![Figure: The linear SRTM measurement chain. Each stage measures its successor and extends a PCR before handing off: CRTM→PCR[0], PEI/DXE→PCR[1–3], BDS→PCR[7] (Secure Boot policy) and PCR[4] (bootmgfw.efi), Windows boot→PCR[12–14]. PCR[11] is reserved for the BitLocker seal and carries no boot-code measurement, and the kernel's EV_SEPARATOR freezes the Windows OS PCRs (firmware having already closed PCR[0–7]).](diagrams/03-measured-boot-srtm-chain.svg)

The complete SRTM chain is linear: the CRTM (Boot Guard ACM, AMD PSP, or Pluton-backed firmware) measures firmware version and contents into PCR[0]; PEI/DXE measures platform configuration and option-ROM state into PCR[1] through PCR[3]; BDS measures Secure Boot variables into PCR[7] and the boot manager image into PCR[4]; Windows records boot application configuration in PCR[12], boot module and ELAM details in PCR[13], and boot authorities in PCR[14], while PCR[11] remains the BitLocker access-control PCR; finally the kernel emits `EV_SEPARATOR` records that mark the boot-time transcript complete.

We have walked the chain. What about the chain we cannot trust: the OEM-vendor-firmware-allowlist explosion that overwhelms remote verifiers?

## Competing approaches: DRTM, late launch, and Secure Launch

A quote from Microsoft's hardware-root-of-trust documentation [188] frames the problem precisely: *"As there are thousands of PC vendors that produce many models with different UEFI BIOS versions, there becomes an incredibly large number of SRTM measurements upon bootup. Two techniques exist to establish trust here: either maintain a list of known 'bad' SRTM measurements (also known as a blocklist), or a list of known 'good' SRTM measurements (also known as an allowlist)."*

The allowlist explodes. Every OEM, every model, every firmware revision, every Secure Boot key generation, and every Windows boot transcript produces a fresh PCR[0]/PCR[7]/PCR[12] through PCR[14] context, while BitLocker still keys its default UEFI seal to PCR[7] and PCR[11]. A central verifier that wants to assert "this fleet booted firmware Microsoft has signed off on" has to maintain a database whose cardinality grows with the product of OEMs, models, firmware versions, Secure Boot policy generations, and Windows boot transcript variants. By 2017 the table size made the verifier policy ungovernable for general-purpose Windows fleets.

The fix is structural: introduce a *second* measurement plane that does not depend on the OEM. From the same Microsoft document: *"System Guard Secure Launch, first introduced in Windows 10 version 1809, aims to alleviate these issues by using a technology known as the Dynamic Root of Trust for Measurement (DRTM)."* And: *"Secure Launch simplifies management of SRTM measurements because the launch code is now unrelated to a specific hardware configuration."*

DRTM is a CPU primitive. On Intel, it is [`GETSEC[SENTER]`](https://www.felixcloutier.com/x86/senter), introduced with Trusted Execution Technology in 2007. From the Intel SDM mirror, verbatim: *"GETSEC[SENTER] / Launch a measured environment. EBX holds the SINIT authenticated code module physical base address. ECX holds the SINIT authenticated code module size (bytes)."* On AMD, the equivalent is the `SKINIT` instruction from the AMD-V (SVM) family. Microsoft's Secure Launch implementation [104] issues `SENTER` or `SKINIT` from a small Secure Kernel Loader (SKL) inside `winload.efi`.

What `SENTER` and `SKINIT` do, at machine level, is roughly identical: they suspend all but one CPU, reset PCRs 17 through 22 in the TPM from their power-on all-ones state to all zeroes in each active bank, load the launch module (Intel verifies the signature on its SINIT Authenticated Code Module; AMD measures its Secure Loader Block rather than checking a signature), and atomically transfer control to it with interrupts disabled and the IOMMU active. The ACM/SLB's measurement gets extended into PCR[17]; the Measured Launch Environment (MLE) it loads gets extended into PCR[18]. On Windows, that environment is the Hyper-V hypervisor (the Above Ring Zero chapter, Chapter 9) and the secure kernel (the Secure Kernel chapter, Chapter 6).

> **Measured Launch Environment (MLE).** The code body that the DRTM primitive ($SENTER$/$SKINIT$) measures into PCR[18] after the Authenticated Code Module (Intel) or Secure Loader Block (AMD) has been measured into PCR[17] and verified. On Microsoft Secure Launch, the MLE is the hypervisor plus the secure kernel. On Linux+TrenchBoot, the MLE is the GRUB late-launch component plus the kernel.

The reason `SENTER` and `SKINIT` matter, beyond the resetting of PCRs 17-22, is *what they don't measure*. They do not measure the PEI/DXE firmware. They do not measure option ROMs. They do not measure the entire SRTM trail in PCRs 0-7. A verifier that consumes PCRs 17-22 sees a much smaller, late-launch transcript: ACM/SLB, Secure Kernel Loader/TCB-launch code, launch policy, hypervisor, secure-kernel, TPM bank, and platform launch context still matter, but the PEI/DXE firmware and option-ROM diversity in PCRs 0-7 no longer dominates the allowlist. DRTM reduces OEM-firmware diversity; it does not collapse every capable system to one digest per silicon vendor.

## The Rutkowska / Wojtczuk SMM attack and the DRTM preconditions

Before `SENTER` could be trusted, it had to survive an attack class that Joanna Rutkowska and Rafal Wojtczuk demonstrated at Black Hat DC 2009 [195]. Their paper's abstract is direct: *"We describe a practical attack that is capable of bypassing the TXT's trusted boot process"*. The mechanism: TXT measured the launch environment but did not constrain System Management Mode, so a compromised SMM handler could tamper with the measured launch after an otherwise trusted `SENTER`. Intel's architectural response was the SMI Transfer Monitor (STM), a hypervisor that sandboxes SMM. A separate, standing precondition is the IOMMU: [the SDM mirror's `GETSEC[SENTER]` description](https://www.felixcloutier.com/x86/senter) lists the chipset and TPM preconditions GETSEC[SENTER] checks before opening the measured-launch window, and every modern DRTM design rests on the assumption that VT-d/IOMMU is active at the late-launch instant.

> **Why DRTM and SRTM coexist instead of replacing each other.** DRTM does not replace SRTM; it layers on top. SRTM still measures everything pre-late-launch into PCRs 0-7 and the Windows boot PCRs 11-14, with PCR[11] reserved for BitLocker access control and boot-component code in PCR[12] through PCR[14]. DRTM resets a separate slice (PCRs 17-22) and starts fresh. A verifier that wants the smaller late-launch TCB consumes the DRTM slice and ignores PCRs 0-16. A verifier that wants the full pre-late-launch history consumes the SRTM slice and ignores 17-22. A verifier that wants both (say, "the firmware was on the allowlist *and* the secure kernel started cleanly") consumes both. The cost is one extra `TPM2_Quote` selection mask. The benefit is that you can change attestation policy without changing the measurement plane.

## Microsoft Secure Launch and the Secured-Core PC bar

Microsoft's Secured-core PC program [179] packages Secure Launch with a set of other hardware requirements: SMM Supervisor, kernel DMA protection, Boot Guard or PSP firmware, Pluton or equivalent silicon root of trust, and Memory Integrity (HVCI) enabled by default. The Microsoft framing: *"Microsoft is working closely with OEM partners and silicon vendors to build Secured-core PCs that features deeply integrated hardware, firmware and software to ensure enhanced security for devices, identities and data."* The result is a tier-1 SKU set whose attestation evidence can emphasize the smaller DRTM TCB rather than only the large SRTM history.

Operationally, the Secured-Core flag enables the configuration block at `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios` per Microsoft's Secure Launch configuration guide [104]. When the registry flag is set and the silicon supports late launch, `winload.efi` issues `SENTER`/`SKINIT` after measuring the early kernel, and the hypervisor launches inside the MLE.

## TrenchBoot: Open-source DRTM for Linux

DRTM is not Windows-only. The TrenchBoot project [196] (with contributors from Apertus Solutions, Oracle, and 3mdeb [196]) maintains an open-source DRTM stack for Linux and Xen on GRUB. From the TrenchBoot documentation repo [197]: *"TrenchBoot is a framework that allows individuals and projects to build security engines to perform launch integrity actions for their systems."* The Linux side of the same primitive that Microsoft Secure Launch uses on Windows.

![Figure: Two measurement planes: SRTM fills PCR[0–7, 11–14] from reset as a large, OEM-diverse anchor; at late launch winload's Secure Kernel Loader issues SENTER/SKINIT, the CPU resets PCR[17–22] and re-roots into the ACM/SLB (PCR[17]) and the MLE (PCR[18]), a smaller and less OEM-diverse anchor.](diagrams/03-measured-boot-srtm-vs-drtm.svg)

The DRTM transition is a second measurement plane layered on top of SRTM. The ordinary SRTM chain runs first through firmware, BDS, boot manager, and early loader state. Then the Secure Kernel Loader issues `SENTER` or `SKINIT`; the CPU resets PCR[17] through PCR[22]; the Authenticated Code Module or Secure Loader Block is extended into PCR[17]; the measured launch environment, on Windows the hypervisor plus secure kernel, is extended into PCR[18]; and the secure kernel starts with IOMMU protections active.

The comparison below synthesizes the TCG PFP PCR allocation surfaced in Microsoft's `Tbsi_Get_TCG_Log` reference [182] with the Microsoft hardware-root-of-trust documentation [188] and the BitLocker countermeasures unlock-mode enumeration [105]:

| Property | SRTM (PCR[0-7,11-14]) | DRTM (PCR[17-22]) | TPM-only BitLocker (default seal PCR[7,11]) | TPM+PIN |
| -: | -: | -: | -: | -: |
| Trust-anchor size | OEM CRTM + firmware + option ROMs + drivers (large) | Vendor ACM/SLB + MLE only (small) | Same as SRTM | Same + human PIN secret |
| Hardware required | Any TPM 2.0 platform | Intel TXT-capable or AMD SVM-capable + IOMMU | Same as SRTM | Same |
| Recovery prompts/year | Depends on selected BitLocker profile | Separate attestation plane; not in the default BitLocker profile | Driven by PCR[7]+PCR[11] unless policy is customized | Same PCR profile, plus user factor |
| bitpixie-class attack | Vulnerable | Separate PCR plane; not a default BitLocker mitigation | Vulnerable | Mitigated (PIN required) |
| Verifier policy size | Grows with OEM/model/firmware/boot-policy versions | Smaller, but still varies by ACM/SLB, SKL/TCB-launch, MLE, policy, TPM bank, and platform context | O(profile choices) | O(profile choices + PIN policy) |

DRTM reduces the OEM firmware-diversity problem. It does not solve the problem that the log is unsigned, the measurement is a hash and not a *good* hash, and the CRTM is an axiom. What can measurement never prove?

## Theoretical limits: What measurement can never prove

Restate the axiom from the origins discussion: the first hash in the chain is an axiom; the silicon that computes it is itself unmeasured. CRTM is the *Root of Trust for Measurement*, not the *Root of Trust for Everything*. The trust we can claim is that, *given* the integrity of the silicon and the immutability of the embedded keys, the chain is a faithful record of what ran. The "given" is doing all the work.

Three limits, each architectural and not implementational.

## Trust on first measurement

The CRTM has nothing under it. If you compromise the silicon (through a faulTPM-class SoC voltage glitch against an AMD fTPM, through SPI-bus sniffing of a discrete TPM, through a Pluton supply-chain tamper, through an Intel Boot Guard key extraction), the rest of the chain is, formally, useless. The verifier asks the chip "what ran?"; the chip computes the answer using cryptographic primitives the chip itself implements; if the chip is malicious, every answer is consistent with whatever boot history the attacker wishes. The TPM's `TPM2_Quote` signature is bound to the chip's own AIK; if the chip is the attacker, the signature is honest about a lie.

This is not a flaw of TPM 2.0. It is a feature of mathematics. You cannot bootstrap trust from nothing. AEGIS knew this in 1997; the TCG accepted it in 1999; every silicon root of trust still depends on it in 2026. The only mitigations are (a) make the silicon as small and audited and physically resistant as the budget allows (which is why Pluton ships a separate sub-millimeter microcontroller), and (b) bind the chip's identity to a manufacturer-rooted certificate chain that an out-of-band auditor can verify. Which is why Hello for Business enrollment cross-checks the EK certificate against the OEM root before issuing the device-bound key.

## A PCR value is a hash, not a *good* hash

The TPM has no knowledge of what is good. PCR[0] holding `0xC4F7...` is just a number. To the TPM it is no more or less suspicious than `0xA21E...`. The TPM's job, during `TPM2_PolicyPCR`+`TPM2_Unseal`, is to refuse the key release if the PCRs do not match the seal-time digest: *regardless* of whether the seal-time digest was a benign value or a malicious one.

> A PCR value is a hash, not a *good* hash.

This is why a sealed BitLocker VMK released on a successful `TPM2_PolicyPCR` match is *not* a guarantee that the booted code was actually trustworthy. It is a guarantee that the booted code matched the seal-time digest. If at seal time the platform was running an older, signed, but vulnerable `bootmgfw.efi`, the seal binds to the BitLocker access-control PCR state selected by policy. Years later, when an attacker recreates a boot state that satisfies PCR[7] and PCR[11], the TPM cheerfully releases the key. This is the mechanism that makes bitpixie work; we will meet it again in the open-problems discussion.

The verifier (BitLocker policy, Azure Attestation policy, Intune DHA, your fleet management tool) is the only entity that knows what *good* means. The TPM provides reporting infrastructure; the verifier provides policy infrastructure. *Measurement is reporting infrastructure, not policy infrastructure.*

> **Key idea.** Measurement is reporting infrastructure, not policy infrastructure. The TPM knows what was measured; only the verifier knows what is good. Every BitLocker unseal, every Azure Attestation, every Intune DHA verdict is a *policy* decision made by software outside the TPM, against a number the TPM merely reports.
>
> **Why this matters in practice.** A sealed VMK released on a successful `TPM2_PolicyPCR` match is *not* a guarantee that the booted code was actually trustworthy. It is a guarantee that the booted code matched the seal-time digest. If seal time captured a vulnerable but signed binary, every subsequent boot of that same vulnerable signed binary will unseal cleanly. This is the architectural reason bitpixie works against TPM-only BitLocker even on fully patched 2025 firmware.

## The log is unsigned

`TPM2_Quote` signs only the PCR values plus the verifier's nonce. It does not sign the TCG event log. A malicious firmware can extend an honest digest into the TPM and report a *different* event in the log it hands the OS. The PCR is correct; the log is a fabrication. Detection comes only from the verifier *replaying* the log against the quoted PCRs and flagging a mismatch.

In practice this is not a problem on benign firmware, because the firmware has no incentive to lie about its own events. It becomes a problem precisely in the cases where the firmware is the attacker: BlackLotus-class implants that own the boot manager, faulTPM-class chip compromises that own the TPM. In those cases, a verifier that trusts both the log and the quote without replaying is trusting a forged document.

The mitigation is structural and well-known: verifiers MUST replay. Azure Attestation, Intune DHA, and Microsoft's reference attestation library all replay the log against the quoted PCRs and refuse to issue a token on mismatch. Operators rolling their own attestation pipeline often skip the replay step, especially in early-prototype deployments. *Skip the replay and you have an unauthenticated event list dressed up as evidence.*

## The cuckoo attestation class (Parno 2008)

There is a class of attack that no amount of replay or PCR profile tightening can stop. Bryan Parno's 2008 HotSec paper [198] names the problem the *cuckoo attack* and proposes the first formal model for establishing trust in a platform under that threat. The abstract, paraphrased lightly: any naive approach falls victim to a cuckoo attack; the model, in Parno's own phrasing, *"reveals the cuckoo attack problem"*.

> **Cuckoo Attack.** An attestation-relay attack in which a verifier challenges a compromised device, the compromised device proxies the challenge to a separate, genuine, attested device elsewhere, the genuine device produces a valid signed quote, the compromised device returns that quote as if it were its own, and the verifier accepts. Without out-of-band identification of *this* device's endorsement key, the verifier cannot distinguish "the EK that signed the quote" from "an EK in the world that signed a quote." Named by Bryan Parno in 2008 by analogy with the cuckoo bird's brood parasitism.
>
> **Attestation Identity Key (AK), recap.** The Attestation chapter (Chapter 5) owns the AK and its provisioning: a TPM-resident asymmetric key whose certificate is signed by the platform's Endorsement Key certificate chain, used to sign `TPM2_Quote` responses. The cuckoo-relevant fact is the gap: if that EK chain is not pre-bound to *this* device's serial number (or some other out-of-band identifier), an attacker can relay the challenge to a different TPM and return a valid signature from *that* chip's AK.

The cuckoo class is closeable, but only by binding the AK to *this* device's identity before trust is needed. Microsoft Autopilot [199] and Windows Hello for Business do this transparently during device enrollment: the EK certificate chain is captured at first boot, cross-checked against the OEM root, and the resulting AK is bound to a specific Microsoft Entra ID device object. Ad-hoc attestation deployments that do not capture the EK chain at enrollment are vulnerable.

Bryan Parno is now at Carnegie Mellon [200]. The cuckoo paper remains, on its eighteenth birthday, the canonical reference for the class.

Permanent limits accepted. What are people actively trying to fix that we have not solved yet?

## Open problems: Bitpixie, the dbx-update UX, and what's next

*The fix is the breakage*. The patch that closes the most dangerous BitLocker bypass of the decade is also the patch that drowns help-desks in 48-digit recovery prompts. The structural entanglement of these two facts is the central open problem of measured boot in 2026.

## bitpixie (CVE-2023-21563)

An attacker reaches behind a fully-patched, BitLocker-enabled Windows 11 laptop. They plug in a LAN cable. They plug in a USB keyboard. They press F12 to boot from network. Within five minutes the disk encryption key is on their disk.

That is bitpixie. From the Neodyme write-up [2]: *"Thanks to a bug discovered by Rairii in August 2022, attackers can extract your disk encryption key on Windows' default 'Device Encryption' setup. This exploit, dubbed bitpixie, relies on downgrading the Windows Boot Manager. All an attacker needs is the ability to plug in a LAN cable and keyboard to decrypt the disk."* The CVE is CVE-2023-21563 [107], described as a *"BitLocker Security Feature Bypass Vulnerability"* with the MSRC advisory at CVE-2023-21563 [201].

The mechanism is the limits analysis made operational. From SySS's bitpixie technical write-up [36]: *"The bitpixie vulnerability in Windows Boot Manager is caused by a flaw in the PXE soft reboot feature, whereby the BitLocker key is not erased from memory. To exploit this vulnerability on up-to-date systems, a downgrade attack can be performed by loading an older, unpatched boot manager."*

![Figure: The bitpixie (CVE-2023-21563) VMK-leak flow. A normal unseal leaves the VMK in RAM; the attacker downgrades to an older but still-signed boot manager whose default-profile PCR[7] and PCR[11] still satisfy the seal, triggers a PXE soft reboot that returns control without a platform reset (RAM uncleared, no fresh BitLocker policy challenge), then PXE-boots Linux and scavenges the -FVE-FS- marker from memory.](diagrams/03-measured-boot-bitpixie-leak.svg)

The chain in detail: (1) The attacker boots the target normally. The boot manager unseals the VMK, hands it to `winload.efi`, and loads BitLocker into the boot path. (2) Before `winload.efi` zeroes the VMK from RAM, the attacker triggers a PXE soft reboot (a feature of older boot manager versions) that returns control to the boot manager without a full platform reset. (3) The attacker now PXE-boots a Linux image that scans physical memory for the BitLocker FVE marker `-FVE-FS-` and extracts the VMK. The RAM never cleared, and no fresh platform reset or BitLocker policy challenge forced the secret out of memory. The VMK is just lying there in untouched physical memory.

The downgrade: the older boot manager whose soft-reboot path leaks the VMK is still signed by the Microsoft 2011 production certificate, which is still in `db` on every Secure Boot machine until that certificate's natural 2026 expiry. Secure Boot accepts the downgraded boot manager because it is still validly signed by a trusted authority that has not yet been revoked. PCR[7] records the Secure Boot policy state. It does not measure the boot-manager image, and it does not change merely because an older still-trusted `bootmgfw.efi` was selected. The image digest moves PCR[4], which the modern default `0x880` TPM-only profile does not select; PCR[11], the BitLocker access-control PCR, still satisfies the seal-time policy. The TPM unseals. BitLocker unlocks. The attack proceeds.

This is the architecture-forcing beat: *a BitLocker policy replay with a still-trusted older signed binary*. The TPM is not malfunctioning. The policy is not misconfigured. The seal is doing exactly what it was sealed to do: release the key if the selected PCR profile reproduces the state it was sealed against. The attacker just produced a profile-compatible boot, in 2024, using a signed-but-vulnerable binary the verifier has not revoked.

Public disclosure landed at the 38th Chaos Communication Congress in December 2024 [202]. From the talk abstract verbatim: *"since 2022, when Rairii discovered the bitpixie bug (CVE-2023-21563). While this bug is 'fixed' since Nov. 2022 and publicly known since 2023, we can still use it today with a downgrade attack to decrypt BitLocker."* The full attack chain was demonstrated on stage by Thomas Lambertz of Neodyme. The proof-of-concept code is at github.com/martanne/bitpixie [203]. (The repository handle `martanne` is the GitHub username; the discoverer is Rairii (August 2022); the 38C3 presenter is Thomas Lambertz (Neodyme). Press accounts that refer to "martanne" as a person are confusing the GitHub handle with an author identity.)

## The KB5025885 / Windows UEFI CA 2023 rotation

Microsoft's structural response is documented in the canonical KB article on Boot Manager revocations [190]. The fix is in three stages. Stage 1: enroll the new *Windows UEFI CA 2023* certificate in the Secure Boot `db` variable. Stage 2: replace existing boot manager binaries with copies signed by the 2023 CA instead of the 2011 CA. Stage 3: revoke the 2011 CA in `dbx`. The full rollout is gated on the 2026 natural expiry of the original Microsoft production signing certificate.

Stages 1 and 3 change PCR[7]: Stage 1 adds bytes to `db`, and Stage 3 adds bytes to `dbx`. Stage 2 does not directly touch the Secure Boot variables; it ships a new boot manager binary whose Authenticode digest moves PCR[4] and may alter the Windows boot transcript. On TPM-only BitLocker bound to `0x880 = PCR[7] + PCR[11]`, the PCR[7] stages are recovery-risk planning items; the binary-swap stage matters if the active profile or boot transcript selects PCRs that actually changed.

## BlackLotus (CVE-2022-21894 "Baton Drop")

The bitpixie story does not stand alone. On March 1, 2023, ESET researcher Martin Smolár disclosed BlackLotus [1] (in his own words, *"the first publicly known UEFI bootkit bypassing the essential platform security feature (UEFI Secure Boot) is now a reality."*). BlackLotus exploits CVE-2022-21894 [204] ("Baton Drop"), a Secure Boot bypass in a Microsoft-signed boot manager. From the ESET write-up [1]: *"Although the vulnerability was fixed in Microsoft's January 2022 update, its exploitation is still possible as the affected, validly signed binaries have still not been added to the UEFI revocation list. BlackLotus takes advantage of this, bringing its own copies of legitimate (but vulnerable) binaries to the system in order to exploit the vulnerability."*

The structural fix for BlackLotus is identical to the structural fix for bitpixie: revoke the vulnerable signed binaries in `dbx`. Microsoft shipped the BlackLotus `dbx` revocations in May 2023; that update is the source of most of the "PCR[7] moved overnight" stories from the second half of 2023. The break-fix-break loop is now a recurring operational reality, not an exception.

> the first publicly known UEFI bootkit bypassing the essential platform security feature (UEFI Secure Boot) is now a reality.: Martin Smolár, ESET Research, March 1, 2023

## The break-fix-break loop

> **Key idea.** The fix is the breakage. Every `dbx` update that closes a Secure Boot bypass changes PCR[7] on machines that consume it with Secure Boot enabled. Every PCR[7] change can force a 48-digit recovery prompt on TPM-only BitLocker machines whose active validation profile selects PCR[7]. The patch that closes BlackLotus or bitpixie *is* the operational pain. Pre-boot authentication (TPM+PIN) blocks the downgrade attack from releasing the VMK without the user's PIN, but it does not eliminate PCR[7]-driven recovery: a selected-PCR change still forces suspend/resume or a planned reseal.

![Figure: The break-fix-break loop. A bootkit disclosure forces a Microsoft dbx revocation, which moves PCR[7] on Secure-Boot-enabled UEFI machines that consume it, which can fire fleet-wide 48-digit recovery prompts on TPM-only BitLocker profiles selecting PCR[7], which pushes operators to delay or roll back the patch, so the vulnerable window reopens until the next disclosure. Pre-boot authentication (TPM+PIN) breaks the downgrade path.](diagrams/03-measured-boot-break-fix-loop.svg)

> **Suspend BitLocker before firmware updates.** The safe pattern when applying UEFI firmware, BIOS, Secure Boot DB/DBX, or boot-chain updates expected to move selected BitLocker PCRs is to suspend BitLocker first. Run `Suspend-BitLocker -RebootCount 1` from an elevated PowerShell prompt, apply the patch, and let the suspend auto-resume on the next clean boot. The TPM never sees a PCR mismatch because BitLocker is not asking the TPM for the VMK during the patch reboot.

## Post-quantum agility for the attestation key

Looking ahead, the next structural break is cryptographic: the TPM's signing primitives (RSA-2048, ECC P-256) do not survive Shor's algorithm on a sufficiently large quantum computer. The TCG's PC Client Platform Firmware Profile revision 2 work is expected to target post-quantum agility for attestation keys: ML-DSA (Dilithium) and ML-KEM (Kyber) variants of the signature and key-encapsulation primitives that `TPM2_Quote` and `TPM2_ActivateCredential` depend on.

The constraint that limits the rollout is mechanical. The TPM 2.0 command and response buffer is, by default, 4096 bytes. A Dilithium Level 3 (ML-DSA-65) signature is 3,309 bytes per FIPS 204 [109]. An RSA-2048 signature is 256 bytes. The buffer survives RSA quotes with vast headroom; it has roughly 800 bytes of headroom for an ML-DSA-65 quote. ML-KEM-768 (NIST Category 3) ciphertexts are 1,088 bytes per FIPS 203 [108], with public keys at 1,184 bytes: still tight in a workflow that also requires an ML-DSA-65 signature, which is a distinct TPM operation rather than part of the same command response. A plausible PFP r2 pressure point is negotiating buffer growth across the TPM-firmware-OS path so the post-quantum primitives fit. The TCG specifications site [83] returns HTTP 403 to non-browser User-Agents, so this chapter cites the canonical URL but does not assert a fetch-verified interim buffer-size commitment from TCG or Microsoft.

## DRTM coverage gaps

DRTM is a Secured-core feature; not every fleet runs Secured-core hardware. Raw Intel TXT has shipped on vPro platforms since the Q3 2007 introduction of the Intel DQ35JO board [195], but the deployable surface for Microsoft Secure Launch is narrower because Secured-Core also requires HVCI, kernel DMA protection, and an SMM Supervisor. Microsoft lists System Guard support for Intel vPro Coffee Lake/Whiskey Lake or later, AMD Zen 2 or later, and Qualcomm SD850 or later [188], but actual Secure Launch deployment also depends on firmware and OEM enablement, Windows configuration, VBS/HVCI, DMA protection, SMM protections, and Device Guard policy. Fleets dominated by pre-2018 hardware (and there are many of them, especially in cost-sensitive deployments) cannot use Secure Launch as a SRTM allowlist substitute.

For those fleets, the only deployable mitigation against bitpixie remains pre-boot authentication (TPM+PIN). The cuckoo class remains open against ad-hoc attestation pipelines that do not bind AKs to device serials at provisioning. The OEM allowlist combinatorial explosion remains the unsolved problem that pushed Microsoft to DRTM in the first place.

## PFP r2 in flight

The PC Client Platform Firmware Profile is in active revision. PFP r2 is expected (not yet verified from a fetchable primary source here) to formalize SHA-3 support, revisit default bank guidance, and clarify the PCR[14] semantics that have been a Microsoft-vs-Linux ontology disagreement for the past decade. Because the TCG canonical URL [185] returns the same 403 class to non-browser fetches, this chapter leaves the revision number unspecific; the `tpm2_eventlog` man page [187] tracks the spec by name without a rev number, deliberately so it can absorb a future revision without rebuild.

> **The Brazilian Federal Police DFRWS-Europe 2023 paper.** For practitioners who need a current catalog of hardware-debugger gaps that PCR[7]'s `EV_EFI_ACTION` event was supposed to close, the Wack0/bitlocker-attacks repository [189] maintains a curated index, including a reference to a DFRWS Europe 2023 paper from the Brazilian Federal Police that cataloged debug-mode firmware shipped to retail. The TCG EFI Platform Specification §6.4 quote reproduced there: *"If the platform provides a firmware debugger mode... the platform SHALL extend an EV_EFI_ACTION event into PCR[7]"*. That clause exists precisely because shipped firmware historically did not always do this. The PCR[7] floor is not as solid as the specification suggests.

You have a recovery prompt to clear on Monday morning. What do you do?

## Verify it yourself (documented)

There is no captured silicon-tier evidence for this chapter in `book/evidence/`, so this section deliberately contains **no** 🟢 captured blocks: only documented, reproducible commands. They are evidence of how to inspect the platform, not a claim that this book captured physical silicon values from your machine.

> 🔵 **DOCUMENTED**: Microsoft Learn, `tpmtool` [191] and `Tbsi_Get_TCG_Log` [182]; not captured on our lab VM
> reproduce: `tpmtool getdeviceinformation` from an elevated Windows prompt

```text
tpmtool getdeviceinformation

Expected shape:
  - TPM manufacturer and specification information
  - PCR banks and selected PCR values
  - measured-boot / WBCL-related device information where available
  - enough context to correlate current PCRs with the TCG event log

Interpretation:
  The tool gives you the measured-boot surface. It does not, by itself,
  decide whether the state is good. A verifier still has to replay the
  WBCL / TCG event log and compare it with trusted PCR values or a quote.
```

> 🔵 **DOCUMENTED**: Microsoft Learn, `manage-bde -protectors` [194]; not captured on our lab VM
> reproduce: `manage-bde -protectors -get C:`

```text
manage-bde -protectors -get C:

Expected semantics:
  - displays all key protection methods enabled on the drive
  - shows protector type and identifier for each protector
  - on a TPM-backed OS volume, expect a TPM-family protector such as
    TPM, TPM And PIN, TPM And Startup Key, or TPM And PIN And Startup Key
  - expect a recovery protector such as Numerical Password

Default UEFI BitLocker validation profile when Secure Boot PCR[7]
support is available:
  PCR[7]   Secure Boot State
  PCR[11]  BitLocker access control
  bitmask  0x880
```

The verification pattern is three-part even when only two inbox commands are needed: read the measured-boot surface, read the protector state, and interpret the PCR profile. If the machine is a VM, label any PCR or TPM identity value as **emulated**. If the protector is TPM-only, physical-access risk includes downgrade and pre-boot classes; TPM+PIN changes that calculus.

## Practical guide: A Monday-Morning checklist

Six actions. Each one tied to a verified Microsoft Learn or TCG source. Run them in order; you will know more about your fleet's measured-boot posture in twenty minutes than most operators learn in a year.

## Inspect your log

Run `tpmtool gatherlogs <dir>` from an elevated prompt to collect the SRTM/DRTM boot logs, or call `Tbsi_Get_TCG_Log` for API-level WBCL access [182], [191]. For a clean machine-readable dump, save the binary log via `MeasuredBootTool.exe -log <path>` [182] (Windows HLK), then parse it with `tpm2_eventlog` [187] for a portable text dump. The event stream conforms to the `TCG_PCR_EVENT2` struct documented in the `Tbsi_Get_TCG_Log` reference [182].

## Confirm your BitLocker PCR profile

Run `manage-bde -protectors -get C:` from an elevated prompt and confirm a `Numerical Password` recovery protector exists: without one, you cannot recover from a profile mismatch and you are one PCR drift away from data loss (`manage-bde -status C:` reports overall protection state). Then, if the policy is configured, inspect `HKLM\SOFTWARE\Policies\Microsoft\FVE\PlatformValidationProfileUEFI`; on a Secure Boot UEFI machine a configured value is typically `0x880` (PCR[7] + PCR[11]) per the BitLocker countermeasures documentation [105]: *"By default, BitLocker provides integrity protection for Secure Boot by using the TPM PCR[7] measurement."*

If you see `0x815` (PCR[0,2,4,11]), you are on the non-PCR[7] legacy validation profile (a CSM/legacy boot, or a UEFI system where Secure Boot PCR[7] binding is unavailable) and every firmware update will trigger a recovery prompt. The fix is to verify Secure Boot is on (`Confirm-SecureBootUEFI` from PowerShell), then re-seal by disabling and re-enabling the TPM protector.

## Suspend BitLocker before selected-PCR updates

The safe pattern for firmware, Secure Boot DB/DBX, or boot-chain updates that may move PCRs in your active profile is this:

**The full Suspend-Patch-Resume PowerShell incantation.**

```powershell
# Run as administrator.
# Suspend BitLocker for the next 1 reboot. BitLocker auto-resumes after the
# next clean boot completes, regardless of how many additional boots happen.
Suspend-BitLocker -MountPoint "C:" -RebootCount 1

# Now run the OEM firmware updater or the Windows cumulative update that
# touches Secure Boot. The PCRs will move; BitLocker will not see a mismatch
# because the seal check is bypassed for this boot.

# After the patch reboot, BitLocker automatically re-seals to the new PCR
# values. To verify, run:
manage-bde -status C:
# The output should show "Protection On" and the new PCR profile.
```

## Enable Secure Launch on Secured-Core hardware

If your hardware and firmware meet the Secure Launch requirements Microsoft lists for System Guard-class devices [188], [104], enable Secure Launch. The configuration guide [104] lists the four paths: MDM via Intune, Group Policy, the Windows Security UI, or the registry directly at `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios`. Once enabled, Secure Launch moves verifier attention from the large SRTM firmware transcript to a smaller DRTM transcript. That reduces the OEM allowlist burden, but the allowlist still varies with ACM/SLB, SKL/TCB-launch, MLE, policy, TPM bank, and platform context.

## For high-value devices, switch to TPM+PIN

This is the deployed mitigation this chapter recommends for bitpixie-class physical downgrade risk. From Microsoft's countermeasures documentation [105], four unlock modes exist: TPM-only, TPM+startup-key, TPM+PIN, TPM+startup-key+PIN. Of those, modes that require a human secret are the robust answer to this downgrade path. The attacker may recreate the selected seal-time PCRs by booting an older signed boot manager, but they cannot recreate the PIN.

Enable it with `manage-bde -protectors -add C: -tpmandpin <PIN>`. Users will type the PIN at boot. For Secured-Core fleets where the BIOS exposes USB and TPM+PIN before the OS, this is the best practical security/UX trade. For high-value developer or executive endpoints it is non-negotiable.

> **A class TPM-only BitLocker handles poorly.** bitpixie-style physical downgrade plus memory-retention attacks. TPM-only still has other operational risks (DMA exposure, sleep-state leakage, recovery-key handling, firmware misconfiguration, and revocation timing) but pre-boot authentication is the practical control that blocks this downgrade path before the VMK is released.

## Bind your attestation keys to the device at provisioning

The cuckoo class only closes if the verifier knows the *specific* TPM's endorsement key before trust is needed. Microsoft Autopilot and Hello for Business do this transparently [199] during device enrollment, capturing the EK certificate chain and cross-checking it against the OEM root before issuing the device-bound key. Ad-hoc deployments ("we joined our domain after first boot") usually skip this step and leave the cuckoo path open. If you run an attestation pipeline outside Hello for Business or Azure Attestation, audit your AK provisioning: is the EK chain captured at first boot, and is it bound to a unique device record?

The Monday-morning steps are six items long. The structural questions are not. We close with the questions every reader still has.

> **Bequeaths.** Measured Boot hands the next link a single artifact: an ordered, TPM-backed, replayable record (the PCR snapshot and the TCG event log) of the measured boot-time inputs from platform reset to the kernel's `EV_SEPARATOR`. That record is the evidence plane the Attestation chapter (Chapter 5) signs with `TPM2_Quote`, replays, and judges against policy; it is what lets a verifier in Azure decide whether a machine in the field booted the firmware Microsoft signed off on. But the bequest stops at *reporting*. Measurement records what ran; it does not, by itself, decide whether what ran was *good*, and it does not refuse a bad boot. Enforcement was the Secure Boot chapter's job (Chapter 1), and the *verdict* on the measurements belongs to the Attestation chapter (Chapter 5). A PCR is a hash, not a good hash: this chapter produces the evidence and leaves the judgment to the link above it.
