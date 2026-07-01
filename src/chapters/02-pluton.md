# Pluton

::: trust-ledger

- **Inherits:** The TPM 2.0 primitive from the TPM chapter (Chapter 2): non-exportable keys, PCR measurement, sealing, and a signed quote from a passive cryptoprocessor. Its residual weakness was not the abstraction but the *discrete* form: an external CPU↔TPM bus and an OEM-capsule firmware-patch path. The firmware-first verifier that decides which code is allowed to become the OS from reset (Chapter 1, Secure Boot).
- **Promise:** On a Pluton-as-TPM Windows client the root of trust's TPM services run on a dedicated security processor *on the CPU die* (so there is no off-package bus for a physical-access adversary to interpose on) and its firmware can be serviced through Windows Update, so post-boot Pluton firmware defects have a faster repair channel than OEM-capsule-only paths.
- **TCB:** The Pluton silicon block and its on-die boot ROM; the Microsoft-authored Pluton firmware; the Microsoft signing key and Windows Update channel that authenticate that firmware; and the silicon supply chain (IP licensing → fab → packaging → OEM integration) that produced the die. The host OS the attacker may own is *outside* the TCB for bus resistance, but is back *inside* it the moment an unsealed key reaches OS RAM.
- **Adversary → Break:** The discrete-TPM bus sniffer (Andzakovic) no longer gets an off-package TPM bus on a Pluton-as-TPM die, and the shared-TEE glitcher (faulTPM) no longer reaches Pluton's TPM state through AMD PSP fTPM. But the Promise covers *the bus and the patch path*, not *bug-freeness*: a logic bug in reference-derived TPM firmware can still be relevant to Pluton-derived builds (CVE-2025-2884 is the worked example), and the new single point of failure is the Microsoft-controlled firmware-update authority. Compromise, coerce, or jurisdictionally constrain it and the fleet's firmware-update root is what falls.
- **Residual:** The Volume Master Key in OS RAM after unseal → owned by the Secure Kernel (Chapter 6) and VBS-based key isolation. Detecting that the *wrong code* measured itself (a Root of Trust for Execution, which Pluton is not) → owned by Measured Boot (Chapter 4) and Attestation (Chapter 5). Single-signer revocation, sovereign jurisdiction, pre-ship supply-chain integrity, and component (SPDM) attestation on PC → Pluton-named open problems with no later owner → routed to the back-matter *Unfinished Chain*.
- **Bequeaths:** An on-die root of trust whose storage and reporting survive bus interposition and whose post-boot firmware has an OS-delivered update path. The anchor into which Measured Boot (Chapter 4) extends every boot measurement, and over which Attestation (Chapter 5) signs quotes. Does NOT provide: any measurement of what executed, any proof the *right* code measured itself, protection of the VMK once it reaches OS RAM, or a non-Microsoft trust anchor.
- **Proof:** 🔵 documented throughout: Microsoft's November 17, 2020 announcement [49], the Microsoft Learn Pluton pages [6] [7], Garrett's 2022 BIOS reverse-engineering [130], and CERT/CC VU#282450 [131]; no captured Pluton bytes, because the lab VM exposes a host-provided virtual TPM, not Pluton silicon.
:::

## The root moves on-die, and the update path becomes the trust

> **The Reasoner's question.** What changes when the Windows root of trust becomes CPU-integrated and patchable, and what new trust does that place in Microsoft?

---

> **Foundations. What you need before this chapter.**
>
> - **Root of Trust (RoT).** The Foundations chapter and the TPM chapter (Chapter 2) define the base term; the three names to keep separate are Root of Trust for Storage, Root of Trust for Reporting, and Root of Trust for Measurement. This chapter cares about *where* that root physically lives and *who* can repair it.
> - **dTPM / fTPM / iTPM.** A **discrete TPM** is a separate chip on the board. A **firmware TPM** runs inside an existing firmware environment such as Intel CSME or AMD PSP. An **integrated TPM** is on the SoC die. The TPM chapter (Chapter 2) covers the shared TPM 2.0 command surface; this chapter is about the integrated case. Pluton is an on-die security processor that can present that TPM 2.0 interface to Windows.
> - **CRB.** The TPM 2.0 Command Response Buffer interface. It is the standard host-visible transport Pluton can expose; Linux support for Pluton arrived through the TPM CRB driver.
> - **SHACK.** Secure Hardware Cryptography Key, Microsoft's Pluton claim that some keys are never exposed outside protected hardware, even to Pluton firmware itself.
> - **Renewable security.** The 2017 Microsoft Research phrase for online firmware updates as a security property. Pluton operationalizes it for the Windows client root of trust: a root that can be patched becomes a root whose patch path is part of the security design.
> - **The manufacturer's four-character string.** `Get-Tpm` reports `ManufacturerIdTxt`: `INTC` for Intel PTT, `AMD` for AMD fTPM, vendor strings for discrete chips, and `MSFT` for a Microsoft-backed TPM interface. `MSFT` is necessary evidence for Pluton-as-TPM on physical hardware, but it is also what Microsoft virtual TPMs can report. Cross-check Plug and Play before calling it Pluton.

---

## What this link is responsible for

Pluton's job is not to replace every Windows trust mechanism. It is narrower and more important: anchor the earliest Windows trust decisions in a security processor that is harder to physically interpose on and easier to repair after a firmware defect. BitLocker, Windows Hello, measured boot, System Guard, and conditional-access health claims still consume TPM-like services. Pluton changes where those services live and how their implementation is serviced.

The physical change is the easiest to see. In the discrete-TPM design, the CPU asks an external chip for TPM operations across a board-level bus. That bus is a real object. It can be probed. The TPM chapter's threat model (Chapter 2) included the class of attacks demonstrated by Denis Andzakovic: observe the traffic between CPU and TPM during boot and recover material exposed by the protocol timing and integration, even while the TPM's internal cryptography remains intact [78]. Pluton removes that off-package channel. The CPU and the security processor are integrated into the SoC subsystem, so the attack surface shifts from accessible board traces to silicon-internal integration.

The operational change is less visible but at least as important. A dTPM firmware fix normally flows from TPM vendor to OEM, through UEFI capsule packaging and per-model rollout, then to the endpoint. Pluton firmware can be loaded through operating-system updates during Windows startup, alongside the traditional UEFI mechanism for the SPI-resident early image [6]. That turns patchability from a procurement afterthought into a property of the root of trust itself, while preserving a separate early-boot lifecycle. The security processor is allowed to have bugs; the design bet is that Microsoft can shorten the OS-loaded firmware repair path at Windows-update scale.

Those two changes define the link's responsibility:

1. **Remove the external TPM bus from the client PC threat model.**
2. **Expose TPM 2.0 services from an on-die, dedicated security processor.**
3. **Let Microsoft service the firmware through Windows Update.**
4. **Preserve key non-exportability and attestation semantics for Windows features that already depend on a TPM.**

That list is also the boundary. Pluton does not make the host operating system trustworthy after boot. It does not prevent the volume master key from entering OS memory after BitLocker unseals it. It does not prove that the rest of the supply chain (IP licensing, wafer fabrication, packaging, OEM firmware) was perfect. It gives Windows a stronger silicon anchor and a faster repair path. Everything beyond that must be supplied by other links in the chain.

> **Chapter thesis.** **Microsoft Pluton is Microsoft's architectural answer to TPM threat-model pressure that became public between 2019 and 2024.** It moves TPM services onto the application SoC die, uses a dedicated security subsystem, supports Windows Update firmware loading, and (on 2024+ AMD and Intel systems per Microsoft Learn) starts to use a Rust-based firmware foundation. Those choices narrow the attack surfaces exposed by discrete-TPM bus attacks (Andzakovic 2019), OEM-capsule patch latency (TPM-Fail 2019), and shared-TEE fTPM failures (faulTPM 2023). Each design choice places a new trust in Microsoft: silicon supply chain, firmware compiler and SDLC, signing authority, update channel. The chip is the cheapest part of the system; the cost is a Microsoft-controlled firmware authority for every Pluton-equipped Windows 11 client.

## The question Microsoft answered architecturally before the TPM chapter posed it

*"The TPM was supposed to be the part of the system you didn't have to trust anyone for. Twenty-five years later, the trust question is back, and the answer is now political."* That was the closing line of the TPM chapter (Chapter 2). The counterintuitive fact: by the time that question was asked, Microsoft had already spent years shipping the architectural pattern inside Xbox hardware.

The Xbox One launched in November 2013 with an on-die, Microsoft-signed security processor and a Microsoft-controlled firmware update path. Microsoft's own announcement seven years later named the lineage explicitly: *"the Pluton design was introduced as part of the integrated hardware and OS security capabilities in the Xbox One console released in 2013 by Microsoft in partnership with AMD"* [49]. The November 17, 2020 announcement that Pluton would ship on Windows PCs was not the introduction of a new design. It was a decision to apply a console design pattern to the general-purpose PC, with all the political and supply-chain consequences that come with that decision.

The TPM chapter (Chapter 2) ended with three sets of broken engineering. A NZ\$40 iCE40 FPGA on an LPC bus defeats discrete TPM in the time it takes a laptop to finish Trusted Boot [78]. A network packet defeats Intel PTT through a 5-hour timing side channel against the ECDSA implementation in CSME [95]. A few hours of physical access defeats AMD fTPM via a voltage glitch on the SVI2 power-management bus, walking out with the entire fTPM internal state [99]. All three are derived bit-by-bit in the TPM chapter and will not be re-derived here.

This chapter is what those three results made compelling. Microsoft's reply is structural: move the TPM onto the SoC die so the board-level bus disappears; run it in a dedicated security subsystem so a PSP/CSME-class shared-TEE compromise is not the same failure; use a Rust-based firmware foundation where Microsoft has publicly committed to one (2024+ AMD and Intel systems); and route OS-loaded firmware through Windows Update so part of the patch path no longer depends only on OEM capsules. Each design choice narrows a specific 2014-2024 attack class. Each design choice also names a new trust. *The bus is closed by trusting the silicon supply chain. The TEE is dedicated by trusting Microsoft's chip-level isolation. The 2024+ AMD/Intel firmware foundation is memory-safe by trusting Microsoft's compiler and SDLC. The update path is fast by trusting Microsoft's signing key and Windows Update infrastructure.* That is the chapter in five sentences.

> **Key idea.**
> A single design pattern (on-die security processor, Microsoft-signed firmware, online firmware updates) migrating across product domains from Xbox to Azure Sphere to the general-purpose PC. That migration is the subject of this chapter. Its cost is the subject of its closing.

![Figure: Microsoft security silicon, 2013–2025: a single design pattern crossing product domains.](diagrams/silicon-timeline.svg)

Where did the design pattern come from, and why was it ready for the PC in 2020 and not earlier?

## Origins: Xbox One (2013), Sopris (2015), seven properties (2017), Cerberus (2017), Azure Sphere (2018)

The November 2020 announcement is retroactive. The *design* dates to Xbox One in 2013; the *name* "Pluton" first appears publicly on April 16, 2018, in the "Introducing Microsoft Azure Sphere" launch post [140]. The five-year gap is the architecture maturing from "console-only thing the SoC team built" to "thing Microsoft Research thinks every device should have."

### 2013, Xbox One

A console adversary has full physical access, unlimited time, and an economic incentive measured in hundreds of thousands of pirated units. Microsoft and AMD co-designed the Xbox One SoC with an on-die security subsystem, Microsoft-signed firmware, and a hardware-enforced separation between the Game OS and the System OS. The 2020 Pluton announcement [49] names the lineage explicitly. The architectural shape that the Pluton-on-PC program would later put under TCG TPM 2.0 wire compatibility was already running in production at consumer-console scale by 2014. The motivation matters because it is the clearest public domain where Microsoft had hands-on experience deploying an on-die security processor against an adversary who owned the hardware. (Note: that the design was driven specifically by RGH-class console-modding adversaries is architectural inference, not a Microsoft statement.)

### 2015: Codename 4x4 / Project Sopris

In 2015, a small team in Microsoft AI+Research NExT, led by Galen Hunt, began exploring whether the same architectural shape could secure a \$4 microcontroller [133]. The internal codename was *Codename 4x4*: a reference to the technical requirements that the chip would have at least 4 MB of RAM and 4 MB of Flash [133]. The Microsoft Research blog post is the surviving primary source on Sopris [133].

> **Side note.**
> The "Codename 4x4" name was internal team shorthand. Hunt's MSR Blog post records both the meaning and the constraint: *"This was the origin of the project, internally called 'Codename 4x4', referring to the technical requirements that the chip will have at least 4 MB of RAM and 4 MB of Flash"* [133]. The point was not the storage budget; the point was that a \$4 MCU must afford the same architectural properties as a console SoC.

### March 2017: Seven properties of highly secure devices

Hunt, George Letey, and Edmund Nightingale published *The Seven Properties of Highly Secure Devices* as Microsoft Research Technical Report MSR-TR-2017-16 in March 2017 [134]. The paper makes a single normative claim: *"This paper makes two contributions to the field of device security. First, we identify seven properties we assert are required in all highly secure devices"* [134]. The seven are: hardware-based root of trust, small trusted computing base, defense in depth, compartmentalisation, certificate-based authentication, *renewable security*, and failure reporting. Property #6 is the one the rest of this chapter turns on. *Renewable security via online firmware updates* is precisely the property that distinguishes Pluton-on-PC from a 2014 dTPM. The chip is allowed to be wrong, as long as the chip can be made right again, fast.

> **Definition: Seven Properties of Highly Secure Devices.**
> A 2017 Microsoft Research framework (Hunt, Letey, Nightingale; MSR-TR-2017-16) listing the architectural properties any "highly secure device" must satisfy: hardware-based root of trust, small TCB, defense in depth, compartmentalisation, certificate-based authentication, *renewable security via online updates*, and failure reporting [134]. Renewable security is the property the Pluton-on-PC update path operationalises; it also names the new trust the program places in Microsoft.

### November 8, 2017, Project Cerberus

Microsoft introduced Project Cerberus at DCD>Zettastructure in London on November 8, 2017. Kushagra Vaid, then Microsoft Azure GM, described the architecture as *"a cryptographic microcontroller running secure code which intercepts accesses from the host to flash over the SPI bus (where firmware is stored), so it can continuously measure and attest these accesses to ensure firmware integrity"* [135]. Microsoft contributed a five-PDF specification set to OCP under Project Olympus [136]: Architecture Overview, Challenge Protocol, Firmware Update, Host Processor Firmware Requirements, and Processor Cryptography. The reference implementation lives at `Azure/Project-Cerberus` on GitHub [137]: platform-agnostic core, FreeRTOS and Linux ports, *"designed to be a hardware root of trust (RoT) for server platforms"* [137]. Microsoft Learn describes Cerberus as *"a NIST 800-193 compliant hardware root-of-trust with an identity that cannot be cloned"* [138] [139]. This was Microsoft's first public commitment to publishing a hardware-RoT design and to running it in production at fleet scale.

Cerberus matters here for what it *cannot* do, not what it can. It is a discrete chip. It needs board area, a BOM line, and per-OEM design-in cost. It works on a \$20,000 server motherboard. It does not work on a \$700 ultrabook, and putting it on one would reintroduce the very external-bus surface that Andzakovic 2019 showed to be sniffable [78]. Cerberus solves the server problem definitively. It does not solve the PC problem, and its existence makes the PC-side need explicit.

### April 16, 2018: Azure Sphere preview at RSA 2018

Hunt's announcement of Azure Sphere at the 2018 RSA Conference is the first public, named appearance of "Pluton." The Azure Blog launch post promised *"custom silicon security technology from Microsoft, inspired by 15 years of experience and learnings from Xbox, to secure this new class of MCUs and the devices they power"* [140]. The later (December 20, 2018) *Anatomy of a Secured MCU* post is the first technical description: *"our Pluton Security Subsystem is the heart of our security story"* [132]. Three components, one trust anchor: the MediaTek MT3620 MCU with the Pluton subsystem on die; the Microsoft-managed Linux-based Azure Sphere OS; and the Azure Sphere Security Service (AS3) cloud, which signed firmware updates and consumed device attestations. Microsoft announced Azure Sphere general availability on February 24, 2020 [141]; the Microsoft Security Blog also describes Pluton as *"a Microsoft-designed security subsystem that implements a hardware-based root of trust for Azure Sphere"* [142].

> **Source quotation.**
> Each chip includes custom silicon security technology from Microsoft, inspired by 15 years of experience and learnings from Xbox, to secure this new class of MCUs and the devices they power.: Galen Hunt, Azure Blog, April 16, 2018 [140]

By April 2018, Microsoft had three architectural pieces visible, but not all were yet generally available. Xbox One proved the on-die security processor in production. Project Cerberus proved that Microsoft could publish an open RoT design and operate the back end at hyperscale. Azure Sphere publicly previewed the Pluton block licensed onto a third-party SoC, attested to a Microsoft-operated cloud service, and serviced over the air; Microsoft announced Azure Sphere general availability on February 24, 2020 [141]. *None of those three pieces was on a Windows PC.*

![Figure: Origins of Pluton-on-PC. Three independent product domains converged on the same architectural shape between 2013 and 2018 before any of it shipped on a general-purpose PC.](diagrams/02-pluton-convergence.svg)

Microsoft had a working architecture by 2018. Why did it take until November 17, 2020 to put it on a PC, and what changed between 2018 and 2020 that made the PC mandatory?

## The threat model that made Pluton compelling (2019-2024)

The answer to "what changed between 2018 and 2020" is that, beginning in 2019, public research made the weaknesses of common TPM realisations hard to ignore. Not by intention. By research. By the time Microsoft made the November 17, 2020 announcement, Pluton-on-PC was a compelling architectural option because it could close the board-level TPM bus and give Microsoft a faster firmware-patch path; the later faulTPM result sharpened the dedicated-TEE argument. This is the TPM chapter's threat model (Chapter 2), recast as the story Microsoft was watching unfold while the Pluton design was being prepared for PC.

### March 13, 2019: Andzakovic's \$40 LPC sniffer

Denis Andzakovic, working at Pulse Security, published an end-to-end attack on the Trusted Boot path of an HP business laptop [78]. A NZ\$40 iCE40 FPGA, seven wires (LFRAME, LAD0-LAD3, LCLK, GND) soldered to the LPC bus between the CPU and the discrete TPM, the BitLocker Volume Master Key falling off the wire in plaintext during boot. The TPM chapter (Chapter 2) walks the bit-level details. What matters here is that the November 17, 2020 Pluton announcement names this attack class as motivation: *"attackers have begun to innovate ways to attack [the TPM], particularly in situations where an attacker can... gain physical access to a PC... target[ing] the communication channel between the CPU and TPM"* [49]. Discrete TPM integrations with exposed LPC / SPI traffic are vulnerable against a determined adversary with physical access. The bus is the surface.

### November 12, 2019, TPM-Fail

Daniel Moghimi and colleagues published *TPM-Fail* later in 2019 [95]: timing side channels in the ECDSA implementation in Intel PTT (CVE-2019-11090) and the STMicro ST33 dTPM (CVE-2019-16863). Local key recovery in 4-20 minutes; remote, over the network, in approximately 5 hours. The fixes shipped as firmware patches. The lesson Microsoft took from TPM-Fail is not in the bug, it is in the *deploy mechanism*. PTT lives in CSME; CSME ships through the OEM's UEFI capsule path. ST33 lives behind the TPM vendor's signed flash and ships through the OEM's UEFI capsule path. The OEM UEFI capsule path is measured in quarters to years for high-volume client OEMs. *A fix existed but the deploy mechanism was insufficient.* This is the architectural lesson that the next generation has to internalise: the patch path is part of the security property.

> **Side note.**
> The deploy-mechanism lesson is the one that gets quietly swallowed into Pluton's design. The bug count in firmware-TPM territory is not zero; it is steady. What changes is whether a fix can reach the fleet before its dwell time becomes a procurement problem. TPM-Fail's structural lesson is therefore not "ECDSA timing leaks". It is "the channel that delivers the fix is the security property that matters."

### April 28, 2023, faulTPM

Hans Niklas Jacob, Christian Werling, Robert Buhren, and Jean-Pierre Seifert published *faulTPM: Exposing AMD fTPMs Deepest Secrets* at IEEE EuroS&P 2023 [99]. *"In this paper, we analyze a new class of attacks against fTPMs: Attacking their Trusted Execution Environment can lead to a full TPM state compromise. We experimentally verify this attack by compromising the AMD Secure Processor"* [99]. The mechanism: a voltage glitch on the SVI2 power-management bus, against the AMD PSP (an ARM TrustZone Cortex-A5 inside modern Ryzen SoCs [143]), in 2-3 hours of physical access. The output: the entire fTPM internal state, including the EK and any sealed material.

The structural failure in faulTPM is not the glitch. It is that the PSP is a *shared* TEE. The same coprocessor that runs the fTPM service also runs SEV memory-encryption setup, secure-boot enforcement, and platform initialization. One fault drops everything. *Shared-TEE fTPM is broken because the TEE is shared.* The architectural conclusion that this forces is hard: a fTPM that lives next to memory-encryption services, alongside boot-policy enforcement, in a coprocessor that also handles fuse provisioning, is not separable in failure. To restore TEE isolation, you need a *dedicated* TEE.

### The architecture cascade

Three results in five years made Pluton's trade-off look less like novelty and more like risk reduction.

| Realization | Structural failure | First public proof | What survives the failure |
|---|---|---|---|
| Discrete TPM (LPC / SPI) | External bus is sniffable | Andzakovic 2019 [78] | Hardened dTPM with encrypted bus (TPM 2.0 ENC sessions); not retrofittable to existing fleets |
| Intel PTT in CSME | Slow OEM UEFI capsule patch path | TPM-Fail 2019 [95] | The cryptographic primitive; not the deploy channel |
| AMD fTPM in PSP | Shared TEE: one fault drops everything | faulTPM 2023 [99] | The compatibility surface; not the secrets the chip held |
| **Pluton on the SoC die** | New trust in Microsoft-controlled firmware and update authority | No peer-class public break yet | On-die bus removal; OS-delivered firmware path |

The reasoning chain that lands the design is short. Exposed dTPM buses are sniffable. Shared-TEE fTPM can fail with the TEE. OEM capsule patch paths can leave fixes waiting. Therefore: a dedicated security subsystem on the SoC die, with a deploy channel that is not only the OEM UEFI capsule. That is Pluton-on-PC. *On-die* is not merely a Microsoft engineering preference; it is the shape that answers these three pressures at once.

![Figure: Three attacks closed three architectures between 2019 and 2024. The forced-conclusion node is Pluton-on-PC.](diagrams/02-pluton-forced-conclusion.svg)

> **Why on-die is structural, not stylistic.**
> By 2024, public research had exposed three different failure modes in production TPM realisations: dTPM bus exposure (Andzakovic 2019), Intel PTT / dTPM implementation bugs plus OEM patch latency (TPM-Fail 2019), and AMD fTPM shared-TEE blast radius (faulTPM 2023). On-die is not an aesthetic choice; it is the shape that removes the board-level bus while letting Microsoft own the firmware channel. The "Pluton design" is the trade-off these results make attractive, not a proof that every alternative is dead.

If Microsoft had a working on-die-RoT architecture as early as 2013, and the threat model demanded it on PC by 2020, why did Microsoft go through Cerberus and Azure Sphere first? What did each generation contribute that the previous one could not?

## Five generations of Microsoft security silicon

Microsoft's path to Pluton-on-PC was not linear. The architecture took shape across five generations of Microsoft security silicon: three direct predecessors, the PC deployment itself, and one parallel path. Each generation contributed a piece the next one needed. The shape of Pluton-on-PC was determined by what Xbox One *was*, what Cerberus *could not be on a client*, what Azure Sphere *proved at scale*, and what Caliptra *would later make visible as a choice rather than a technical necessity*.

> **Two 'Generation N' enumerations, different ontologies.**
> This chapter counts Microsoft security-silicon programs (Generations 3-7 = Xbox One, Cerberus, Azure Sphere Pluton, Pluton-on-PC, Caliptra). The TPM chapter (Chapter 2) uses a spec-era/storage taxonomy instead: Generation 0 is software-only storage, and Generations 1-3 are TPM 1.1b, TPM 1.2, and TPM 2.0. The two schemes share an index space but count different things. Project Cerberus appears as Generation 4 here even though it is *discrete* (not on-die), because the count is over Microsoft security-silicon programs, not over TPM realisations.

> **Definition: Hardware Root of Trust (RoT).**
> A hardware element that anchors three separable services: Root of Trust for Storage (the chip can hold private keys that never leave it), Root of Trust for Reporting (the chip can sign attestations of its own state and of code it measured), and Root of Trust for Measurement (the chip records integrity hashes of code as it loads). The TPM 2.0 specification names all three; Pluton, Apple SEP, Caliptra, and OpenTitan implement subsets and combinations of them.

### Generation 3: Xbox One on-die security processor (2013)

Existence proof. Microsoft and AMD co-designed the Xbox One SoC with an on-die security subsystem [49]. Console signing key. Hardware-enforced separation between Game OS and System OS. The Xbox One demonstrated, at consumer-console scale, that Microsoft and a chip vendor could ship an on-die security processor that survived a determined adversary with full physical access. Limitation: console-only. No TCG TPM 2.0 wire surface. Microsoft did not commit publicly that this design would ever leave the Xbox.

### Generation 4, Project Cerberus (November 8, 2017)

Discrete RoT chip on the server BMC. NIST SP 800-193 alignment [138] [139]. Open spec at OCP [136]; reference implementation on GitHub [137]. Architecturally the inverse of Pluton: external chip, separate flash interception, dedicated authority. *That* shape is right for a server motherboard. *That* shape is wrong for a \$700 ultrabook. BOM cost, board area, and per-OEM design-in cost rule it out, and reintroducing an external bus would re-expose the very Andzakovic-class surface the program is trying to close. Cerberus is not a rejected design; it is the *server-side* answer that runs alongside the client-side answer Pluton would later be. The two coexist in the November 17, 2020 announcement, which describes Cerberus as *"providing a secure identity for the CPU that can be attested by Cerberus"* [49]. Server-side RoT and client-side RoT compose; they do not compete.

### Generation 5: Azure Sphere Pluton MCU (April 2018)

The first public, named appearance of "Pluton." MediaTek MT3620 SoC; Linux-based MCU OS; Azure Sphere Security Service in the cloud [140] [132]. *"Our Pluton Security Subsystem is the heart of our security story"* [132]. Three things became public commitments in 2018 and operationally proven by the 2020 GA milestone [141]. First, Microsoft-designed on-die security IP could be licensed to a third-party SoC and taped out under another vendor's process. Second, Microsoft-operated cloud-side firmware servicing was viable at MCU scale. Third, the *Seven Properties* mapped cleanly onto the silicon-plus-firmware-plus-cloud triple. Limitation: MCU-class power and instruction set; not Windows; product retiring in 2027.

> **Side note.**
> The precision matters. The *design pattern* (on-die security processor, Microsoft-signed firmware, cloud or OS-channel updates) dates to Xbox One in 2013. The *name* "Pluton" first appears publicly on April 16, 2018 in the "Introducing Microsoft Azure Sphere" launch post [140]; the December 20, 2018 *Anatomy of a Secured MCU* post [132] is the first technical description. The 2020 PC announcement uses the name retroactively for the 2013 design. When narrating: the design is Xbox-era, the name is Azure-Sphere-era.

### Generation 6: Pluton on Windows-PC SoCs (November 17, 2020)

The subject of the design-choices section below. Brief hand-off here. Microsoft, AMD, Intel, and Qualcomm announced that the Pluton design would ship on Windows-PC SoCs [49]. AMD Ryzen 6000 was the first Pluton silicon to reach market, announced at CES 2022 with OEM systems shipping later that year [144] [145]. Microsoft Learn currently lists AMD Ryzen 6000 / 7000 / 8000 / 9000 / Ryzen AI; Intel Core Ultra 200V Series, Ultra Series 3, and Series 3; and Qualcomm Snapdragon 8cx Gen 3 and Snapdragon X Series [6]. This is the generation the rest of the chapter lives in.

### Generation 7, Caliptra 1.0 (April 2024)

Open-source datacenter Root of Trust. Co-designed by Microsoft, Google, AMD, and NVIDIA. Specification, RTL, ROM, and runtime all public on CHIPS Alliance [146] [147]. *"Caliptra targets datacenter-class SoCs like CPUs, GPUs, DPUs, TPUs. It is the specification, silicon logic, ROM and firmware for implementing a Root of Trust for Measurement (RTM) block inside an SoC"* [146]. Caliptra is not a successor to Pluton. It is a *parallel path*, and that distinction is what makes Caliptra structurally important for this chapter: it makes the single-signer choice in Pluton visible as a choice, not a technical necessity. Caliptra exists. The single-signer property of Pluton-on-PC is therefore not the only design that 2024 hardware can support; it is the one Microsoft chose for the client.

The five generations side by side:

| Generation | Year | On-die? | Discrete? | Open RTL? | Multi-signer? | Trust anchor | Where it ships |
|---|---|---|---|---|---|---|---|
| 3: Xbox One sec proc | 2013 | Yes | No | No | No | Microsoft (Xbox CA) | Xbox One console |
| 4: Project Cerberus | 2017 | No | Yes | No (open spec / firmware RI) | No (per-deployment signer) | Microsoft Azure CA (operator) | Server BMC |
| 5: Azure Sphere Pluton | 2018 | Yes | No | No | No | Microsoft (AS3) | MCU (MediaTek MT3620) |
| 6: Pluton-on-PC | 2020 | Yes | No | No | No | Microsoft (Windows Update) | Windows 11 client SoCs |
| 7: Caliptra 1.0 | 2024 | Yes | No | Yes | Multi-vendor by deployment | Per-chip integrator | Datacenter SoCs |

![Figure: Five generations of Microsoft security silicon: three direct predecessors (Xbox One, Cerberus, Azure Sphere), the PC deployment (Pluton-on-PC), and one parallel path (Caliptra). Edge labels capture the contribution of each generation to the next.](diagrams/02-pluton-generations.svg)

What, exactly, makes Generation 6 different from the four generations that came before it, and what new trust does each of its design choices ask the reader to place in Microsoft?

## The breakthrough: on-die plus dedicated TEE plus Rust plus Windows Update

The November 17, 2020 announcement [49] is shorter than its consequences suggest. It makes four design choices explicit. Each one closes a specific architectural gap that 2014-2024 had opened. Each one also names a new trust that is now placed in Microsoft. This section walks the four choices, the gap each one closes, and the trust each one creates.

### Design choice 1: on-die SoC integration

There is no off-package TPM bus between the CPU and the Pluton block. The November 2020 announcement names this property as the structural answer to the bus-sniffing class: *"attackers have begun to innovate ways to attack [the TPM], particularly in situations where an attacker can... gain physical access to a PC... target[ing] the communication channel between the CPU and TPM"* [49]. With Pluton, that communication channel is silicon, not a board trace. Andzakovic-class bus sniffers therefore lose the off-package TPM bus they need [78].

The new trust: the silicon supply chain. Microsoft licenses the IP block; AMD, Intel, and Qualcomm tape it out on TSMC or another foundry; the OEM integrates the resulting SoC into a finished product. None of those steps is on the public record at the bit level. (See open problem 5 (supply-chain integrity beyond firmware signing) in the open-problems section below.)

### Design choice 2: dedicated TEE, not shared

Public Microsoft documentation describes Pluton as a secure subsystem integrated into the SoC, not as the same coprocessor that runs AMD SEV setup or Intel CSME runtime services [6]. On that public architecture, faulTPM-class attacks on the AMD PSP do not transitively drop Pluton secrets [99], because Pluton-as-TPM is not the PSP fTPM service. The structural failure that defeated AMD fTPM (one fault drops everything because the TEE is shared) does not apply to Pluton-as-Pluton. (AMD-Ryzen-6000-class chips can ship Pluton silicon next to the existing PSP-based fTPM; the OEM picks which the host advertises as the system TPM via the Pluton (HSP) BIOS toggle and PSP-directory 0xB BIT36 soft fuse Garrett 2022 documents [130]. Windows TBS exposes one TPM at a time. On systems the OEM exposes as fTPM, faulTPM-class attacks remain valid; on systems exposed as Pluton-as-TPM they no longer reach Pluton's TPM state.)

The new trust: Microsoft's chip-level isolation engineering. The TEE is dedicated only because Microsoft and the chip vendor agreed to dedicate it. There is no public peer-reviewed audit demonstrating that the Pluton boundary is bit-for-bit non-shared with PSP / CSME on shipping silicon. The independent CHES 2024 study TPMScan [148] [149] sampled 78 TPM 2.0 versions across 6 vendors, and the IACR TCHES record states explicitly that the corpus *"include[s] recent Pluton-based iTPMs"* alongside dTPM, fTPM, and earlier iTPM variants from Microsoft, AMD, Intel, Infineon, ST, and Nuvoton [149]. The paper's per-vendor findings center on RSA / ECDSA nonce-leakage and command-timing observability across the corpus; the paper does not single Pluton out for a per-implementation audit, and it does not characterize Pluton's specific timing surface as worse or better than the iTPM cohort it sits in. The TPMScan study therefore *places* Pluton inside the audited iTPM population without singling it out: a useful baseline, not a Pluton-specific clean bill of health.

### Design choice 3: Rust-based firmware foundation on 2024+ AMD / Intel

Microsoft Learn states the platform scope explicitly: *"Pluton platforms in 2024 AMD and Intel systems will start to use a Rust-based firmware foundation given the importance of memory safety"* [6]. On those 2024+ AMD and Intel platforms, memory-safe firmware is a direct response to the firmware-CVE history: TPM-Fail [95], the long Intel ME / AMD PSP CVE backlog, and reference-code defects such as CVE-2025-2884 (worked example below). The class of bug that a memory-safe runtime structurally rules out is large; it is not the entirety of the bug surface (logic bugs survive Rust), and Microsoft has not made the same public Rust statement for Qualcomm or the 2022 AMD Ryzen 6000-era firmware.

> **What 'Rust-based firmware foundation' actually commits to.**
> Microsoft Learn commits to *"a Rust-based firmware foundation"* on 2024+ AMD and Intel platforms [6]. Secondary technology press has named the runtime as Tock OS, the memory-safe embedded operating system maintained by an open community [150]. Tock is a plausible candidate. It is the most mature publicly reviewed memory-safe embedded RTOS for the kind of constraints Pluton operates under. But Microsoft has not made the Tock attribution publicly. The honest reading is: Rust on the PC firmware path is committed; the specific runtime has not been named by Microsoft as of 2026. The reader who wants to track this should watch the Microsoft Learn Pluton page for an explicit runtime name.
>
> The reason this hedge matters: "Pluton runs Tock" is widely repeated in tech press, and the difference between "memory-safe Rust embedded OS" and "specifically Tock" is the difference between an architectural commitment and a procurement choice. Both are interesting, but they are not the same statement.

> **Side note.**
> Garrett's April 2022 reverse-engineering [130] documented that the Pluton firmware blob on the 2022 AMD Ryzen 6000 BIOS he disassembled was an ARM image containing chunks that appeared to derive from the TCG TPM 2.0 reference code (the *Pluton in 2026* section carries the verbatim quote and the *What Pluton still cannot do* section carries the CVE-2025-2884 connection). That is the 2022 firmware on a 2022-vintage chip; it is not the 2024+ Rust runtime. Both observations are consistent: the 2022 ARM blob is what existed on first silicon, and the 2024+ Rust foundation is what Microsoft Learn now commits to for AMD and Intel systems. CVE-2025-2884 is relevant to that lineage as a reference-code risk, not public proof that every Pluton build carried the vulnerable `CryptHmacSign` revision.

The new trust: Microsoft's compiler and SDLC. The chip ships running code that Microsoft authored. Whatever the compiler optimized away, whatever the test suite did not catch, whatever subtle un-`unsafe`-block reasoning passed code review. That becomes the property of the chip's trust anchor.

### Design choice 4: Windows Update servicing path

Microsoft Learn: *"Pluton platform supports loading new firmware delivered through operating system updates"* [6]. The boot-lifecycle detail matters. The SPI-resident Pluton firmware is loaded during hardware initialization; during Windows startup, the operating system loads the latest valid Pluton firmware if Windows Update has delivered one, otherwise it uses the firmware loaded at hardware initialization; UEFI capsules remain the mechanism that updates the SPI-resident early image [6]. Therefore the architectural fact is narrower than "every boot phase is instantly patched": Windows Update gives Microsoft a dynamic OS-startup firmware-loading path, while pre-OS TPM use on the first boot after an update still depends on the SPI-resident image until the platform's persistence mechanism has advanced. Microsoft has not published a numerical SLA for Pluton firmware delivery; this chapter will not assert one.

The new trust: Microsoft's signing key and Windows Update infrastructure. Whoever can sign valid Pluton firmware for the Windows Update path can, in principle, affect the OS-loaded firmware on every Pluton chip that accepts that channel; the SPI-resident early image remains tied to the UEFI-capsule path Microsoft Learn describes [6]. This is the same trust that already underwrites the rest of Windows; Pluton extends it to the chip itself.

### The trust shift, named explicitly

Pull the four choices together. Each narrows a specific 2014-2024 attack class: bus, shared-TEE, firmware-CVE, OEM-capsule patch latency. Each names a new trust placed in Microsoft: silicon supply chain, chip-level isolation engineering, compiler and SDLC, signing key and Windows Update infrastructure. *On-die alone is not the breakthrough. The breakthrough is the combination.*

The November 2020 announcement also commits to a property beyond TCG TPM 2.0: SHACK. *"Pluton also provides the unique Secure Hardware Cryptography Key (SHACK) technology that helps ensure keys are never exposed outside of the protected hardware, even to the Pluton firmware itself"* [49]. The TCG TPM 2.0 specification requires that keys be non-exportable from the chip; SHACK extends the boundary one ring inward, naming a class of keys that the firmware running on Pluton itself cannot read. This is Microsoft's claim that Pluton offers a *stronger* property than the TCG TPM 2.0 spec requires. Verifying that claim from outside Microsoft requires source access Microsoft has not published.

> **Definition, SHACK (Secure Hardware Cryptography Key).**
> A Pluton property named in the November 17, 2020 announcement [49]; Microsoft's claim that Pluton's non-exportability boundary extends one ring inside the TCG TPM 2.0 boundary, so keys are unreadable even by Pluton firmware. See the design-choices prose above for the verbatim Microsoft quote and the chapter's hedge that no external peer-reviewed validation of SHACK exists as of 2026.

### How the chip boots and how the chip gets patched

The boot-and-attest sequence below is the public shape of how Pluton starts and how new firmware reaches it. The exact ROM-to-FMC-to-runtime chain is generic to on-die RoT designs (Caliptra exposes this shape openly in its source [146]); Pluton's specific protocol details are not all on the public record, so the diagram captures the architectural shape rather than a Microsoft-internal protocol.

![Figure: Pluton boot and update, architectural shape. The shape is generic to on-die RoT designs; specific protocol bytes between Pluton and Windows Update are not on the public record.](diagrams/02-pluton-boot-update.svg)

The detection logic that follows is the structural shape of the `Get-Tpm` PowerShell query that the checklist section will revisit. It is mocked here to make the four-letter `MSFT` check explicit while preserving the caveat: `MSFT` means a Microsoft-backed TPM interface, which can be Pluton on physical hardware or a Microsoft virtual TPM in a VM.

> **Key idea.**
> The Pluton breakthrough is the *combination*, not on-die alone. On-die plus dedicated TEE plus a Rust-based foundation where Microsoft has committed to one plus OS-channel firmware loading: four design choices, each narrowing a different 2014-2024 attack class, each placing a new trust in Microsoft. The chip is the cheapest part of the system. The cost is what those four trusts add up to.

What is actually shipping in 2026? Hardware lists, OEM enablement behavior, vendor pushback that survived from 2022 into 2026: the gap between marketing claim and shipping reality.

## Proof on a live machine

Pluton is physical silicon. The lab VM used for this book exposes a host-provided virtual TPM, not a Microsoft Pluton security processor. This chapter therefore uses only 🔵 **DOCUMENTED** evidence. There are no captured Pluton bytes and no green lab-evidence blocks; only documented-source markers appear.

A reader with Pluton-equipped hardware should verify two separable facts: whether Windows enumerates a Microsoft Pluton security processor under Plug and Play, and whether TPM Base Services is currently backed by a Microsoft TPM manufacturer string. The separation matters because Pluton can be present but not selected as the active TPM, and because virtual TPMs supplied by Microsoft virtualization stacks can also report Microsoft as the TPM manufacturer.

> 🔵 **DOCUMENTED**: Microsoft Learn, *Microsoft Pluton security processor* and *Microsoft Pluton as TPM*; expected shape only · a VM exposes a host vTPM, not the physical Pluton silicon these claims concern
> reproduce: `Get-PnpDevice -Class SecurityDevices | Select-Object FriendlyName, Status`

```text
FriendlyName                         Status
------------                         ------
Microsoft Pluton Security Processor  OK
Trusted Platform Module 2.0          OK
```

The Device Manager form of the same check is: open **Device Manager → Security devices** and look for the Microsoft Pluton security-processor entry. The exact list depends on whether the OEM exposes Pluton as the TPM or alongside another TPM; the point is to distinguish the security processor's presence from the TPM interface Windows is actively using.

> 🔵 **DOCUMENTED**: Microsoft Learn and source-post manufacturer-string logic; expected value only · a VM exposes a host vTPM, not the physical Pluton silicon these claims concern
> reproduce: `Get-Tpm | Select-Object ManufacturerIdTxt, ManufacturerVersion, TpmPresent, TpmReady`

```text
ManufacturerIdTxt ManufacturerVersion TpmPresent TpmReady
----------------- ------------------- ---------- --------
MSFT              "<firmware version>" True       True
```

`ManufacturerIdTxt = MSFT` is a Microsoft TPM signal, but it is not by itself a Pluton proof. On physical hardware, `MSFT` is the value you expect when Pluton is exposed as the TPM. In Azure, Hyper-V, and other Microsoft virtualization contexts, a Microsoft-provided **virtual TPM** can also report `MSFT`. Cross-check `Get-PnpDevice -Class SecurityDevices`, Device Manager, and the OEM firmware setting before concluding that a machine is running on Pluton silicon. In the same fleet query, `INTC` indicates Intel PTT, `AMD` indicates AMD fTPM, and common discrete vendors include Infineon, STMicro, and Nuvoton.

## Pluton in 2026. What is shipping, where, and how to verify

The 2020 announcement is now five and a half years old. The 2022 first-silicon shipment is four. What is the actual fleet shape in 2026?

### The Microsoft-published hardware list

The current Microsoft Learn Pluton page enumerates the supported silicon: AMD Ryzen 6000, 7000, 8000, 9000, and Ryzen AI; Intel Core Ultra 200V Series, Ultra Series 3, and Series 3; and Qualcomm Snapdragon 8cx Gen 3 and Snapdragon X Series [6]. Treat that as the Pluton-capable silicon list. *Present* and *enabled by default* are not the same property, which is the point of the next subsection.

### Default-on versus default-off varies by OEM SKU

The first x86 silicon to ship with Pluton was AMD Ryzen 6000 "Rembrandt", at CES 2022. Phoronix's launch coverage [144] confirms that the CES 2022 keynote disclosed the integration. The vendor responses that followed in March 2022 set the OEM-by-OEM posture that the fleet still reflects in 2026. The Register obtained vendor statements [127]. Lenovo deployed the chip on AMD Ryzen 6000 ThinkPads but disabled it: *"AMD Ryzen 6000 ThinkPads will include Pluton as it's present in those AMD chips, though the feature will be disabled by default"*; Intel-powered ThinkPads *"will not support Microsoft Pluton at launch"*; the Snapdragon 8cx Gen 3 Lenovo X13s did include Pluton [127]. Dell's reply was the most direct: *"Pluton does not align with Dell's approach to hardware security and our most secure commercial PC requirements"* [127] [128]. HP declined to comment.

The 2024 inflection is the Copilot+ PC program. Microsoft Learn lists Snapdragon X Series and current Surface-class silicon as Pluton-capable [6], and Copilot+ made Pluton-visible hardware far easier to buy at retail. But "supported silicon," "enabled in firmware," and "active TPM backing" remain distinct procurement facts; default-on status must still be verified per OEM SKU.

> **Side note.**
> The 2024 Copilot+ inflection is the first time Pluton-capable Windows-PC hardware became a high-volume consumer retail category. Prior to Copilot+, Pluton was often off (Lenovo AMD Ryzen 6000 ThinkPads), absent (Dell), or behind a BIOS toggle the user had to find. Copilot+ narrows the discoverability problem, but procurement still has to verify whether the OEM enabled Pluton and whether Windows is using it as the active TPM.

### Linux 6.3: February 20, 2023

The standard TCG Command Response Buffer (CRB) interface that Pluton exposes is reachable from Linux. Phoronix records the merge: *"Linus Torvalds merged to Linux 6.3 Git the TPM CRB support for Microsoft's controversial Pluton security co-processor"* [129] [151]. The driver author was Matthew Garrett [151]. Pluton-as-TPM is now reachable from non-Windows operating systems via the standard TCG CRB transport. This constrains (although it does not eliminate) the "Microsoft-only black box" narrative. The chip speaks the open TCG wire protocol that any operating system can talk to.

### Garrett's reverse-engineering, April 2022

Matthew Garrett's April 2022 disassembly of the Asus ROG Zephyrus G14 BIOS [130] yielded two facts that matter for the rest of this chapter. First, the user-controllable BIOS Pluton (HSP) toggle on AMD Ryzen 6000 may not be a hardware power-down. The firmware strings Garrett found say: *"NOTE: This option will NOT put HSP hardware in disable state, to disable HSP hardware, you need setup PSP directory entry 0xB, BIT36 to 1"* and then document bit 36 as disabling the HSP core, gating the HSP clock, and allowing no further PSP-to-HSP commands [130]. Garrett's own hedge follows immediately: *"my interpretation of this is that it doesn't directly influence Pluton, but disables all mechanisms that would allow the OS to communicate with it"* [130]. Inventory queries that report "Pluton present" do not always distinguish enabled from soft-disabled. Second, *"there's a blob starting at 0x0069b610 that appears to be firmware for Pluton. It contains chunks that appear to be the reference TPM2 implementation, and it broadly decompiles as valid ARM code"* [130]. The Pluton firmware blob is, on the silicon Garrett looked at, an ARM image with apparent TCG TPM 2.0 reference-code ancestry. That is the observation that makes CVE-2025-2884 (the worked example below) relevant to Pluton firmware as a plausible lineage risk, not proof of a specific vulnerable Microsoft build.

> **Definition: Soft-fuse Pluton disable (PSP directory 0xB BIT36).**
> On AMD Ryzen 6000 / 7000 / 8000 platforms, the OEM can set PSP directory entry 0xB bit 36 in the AMD-firmware part of the BIOS. Garrett's firmware strings say bit 36 disables the HSP core, gates the HSP clock, and stops further PSP-to-HSP commands; Garrett separately hedges that the user-facing BIOS toggle may only disable the mechanisms that let the OS communicate with Pluton [130]. This is a soft fuse / exposure-control path, not evidence that Pluton is merely PSP firmware. The host's TPM advertisement (`Get-Tpm`) does not always distinguish enabled-Pluton from soft-disabled-Pluton; verification requires inspecting the BIOS-level Pluton (HSP) toggle directly, or correlating against the Plug-and-Play device list.

> **Pluton present is not Pluton enabled.**
> Garrett's PSP-directory soft-fuse documentation [130] is the practical pitfall of any 2026 Pluton procurement audit. An OEM can ship AMD Ryzen 6000 / 7000 / 8000 silicon with Pluton soft-disabled at boot. Inventory queries that count "Pluton-present" SKUs without correlating against the BIOS-level Pluton (HSP) toggle will overcount by an unknown margin. The checklist section walks the practical detection path.

The fleet shape, in one comparison table:

| Platform | First shipped | Default state at launch | Vendor posture today | Linux support |
|---|---|---|---|---|
| AMD Ryzen 6000 mobile | January 2022 [144] | Off on Lenovo ThinkPad [127]; Dell declined [128] | Per-OEM; soft-fuse trap on Lenovo | Linux 6.3 CRB driver [129] |
| AMD Ryzen 7000 / 8000 / 9000 / Ryzen AI | 2023-2025 | Per-OEM SKU | Microsoft Learn lists as supported [6] | Same CRB driver |
| Intel Core Ultra 200V / Series 3 | 2024 onward | Per-OEM SKU | Microsoft Learn lists as supported [6] | Same CRB driver |
| Snapdragon 8cx Gen 3 (Lenovo X13s) | 2022 | On at launch [127] | Shipping | Same CRB driver |
| Snapdragon X Series Copilot+ PCs | 2024 | On by default [6] | Microsoft + Qualcomm core program | Same CRB driver |
| Microsoft Surface Copilot+ | 2024 | On by default [6] | First-party Microsoft hardware | Same CRB driver |

![Figure: Pluton fleet shape in 2026: by silicon family, by OEM brand, by default state at retail.](diagrams/02-pluton-fleet-shape.svg)

Pluton is not the only on-die security processor in 2026. Apple has the Secure Enclave Processor. Google has Titan M2. The OCP coalition has Caliptra. How does Pluton compare, and what does the comparison reveal about Microsoft's design choices?

## Competing approaches: Apple SEP, Google Titan M2, OpenTitan, Caliptra, Cerberus

Pluton is not alone. The platforms below are its nearest analogs: the strongest evidence that Microsoft's design choices were *choices*, not technical necessities.

### Apple Secure Enclave processor

Apple's *Apple Platform Security* documentation describes SEP as *"a dedicated secure subsystem integrated into Apple [SoC]... isolated from the main processor to provide an extra layer of security"* [62]. By deployment count it is the most mature single-vendor on-die security processor on the planet: shipping in every iPhone since the iPhone 5s (2013), every iPad since iPad Air, and every Apple-silicon Mac [62] [152]. The architecture has matured generation by generation: a Boot ROM as the hardware root of trust; an Apple-customized L4 microkernel; a Memory Protection Engine that combines AES-XEX with CMAC and an anti-replay tree on A11 / S4 and later; a Boot Monitor on A13 and later that hashes the loaded image and updates the SCIP (System Coprocessor Integrity Protection) settings before transferring control; and on A14 / M1 and later, the Memory Protection Engine *"supports two ephemeral memory protection keys"*: one for SEP-private data and a second one shared with the Secure Neural Engine [62].

The trade-off versus Pluton is not the architecture. It is the *governance model*. Apple owns the silicon, the operating system, the signing key, and the device. The multi-signer political question never arises because there is only one signer for every layer of the stack. The cost: complete lock-in. The Apple T2 line, which shipped in 2017-2020 Intel Macs as a discrete A10-derived security chip running bridgeOS, inherited the A10 Boot ROM [153]. The A10 Boot ROM has the structurally important property that no Boot-ROM-resident bug can be patched without silicon respin: which the *checkm8* / *blackbird* class of jailbreaks demonstrated end-to-end. T2 was discontinued June 5, 2023 [153]. The lesson is direct: *renewable security* (Seven Properties #6) is not optional. Even Apple's vertically integrated stack pays the price when a generation ships without it.

> **Source quotation.**
> A dedicated secure subsystem integrated into Apple [SoC]... isolated from the main processor to provide an extra layer of security.: Apple, *Apple Platform Security* [62]

### Google Titan M / Titan M2 and OpenTitan

Google announced Titan M with the Pixel 3 launch in October 2018 [154]: *"This year, with Pixel 3, we're advancing our investment in secure hardware with Titan M, an enterprise-grade security chip custom built for Pixel 3..."* [154]. Titan M2 followed with Pixel 6 in October 2021 [155]. Both are discrete or in-package security chips on Pixel for Android Verified Boot, StrongBox-grade key storage, anti-rollback, and lock-screen verification. Both are Google-vertical: Google designs the chip, Google operates the cloud back end, Google ships the OS.

OpenTitan is the open-source descendant. Hosted by lowRISC, it is *"the first open source project building a transparent, high-quality reference design and integration guidelines for silicon root of trust (RoT) chips"* [156]. RISC-V Ibex core; hardware AES, HMAC, KMAC, and OTBN big-number engines; full RTL, ROM, and verification stack public; Apache 2.0 license. OpenTitan reached commercial availability on February 13, 2024 [157]: the first open-source silicon project to do so. The press release names the nine coalition members verbatim: *"Google, Winbond, Nuvoton, zeroRISC, Rivos, Western Digital, Seagate, ETH Zurich and Giesecke+Devrient, hosted by the non-profit lowRISC CIC"* [157]. OpenTitan is the closest existing answer to "what would an open-source Pluton look like?", but as of 2026 it is discrete or in-package, not on-die in an application SoC.

> **Side note.**
> The lowRISC press release is precise on a point that secondary press has frequently flubbed. lowRISC is the *host* organization for OpenTitan; it is not a member of the nine. The nine commercially announced coalition members on February 13, 2024 are Google, Winbond, Nuvoton, zeroRISC, Rivos, Western Digital, Seagate, ETH Zurich, and Giesecke+Devrient [157]. The distinction matters because lowRISC's role is governance, not deployment.

### Caliptra

The OCP coalition's open-source datacenter Root of Trust. Specification, RTL, ROM, FMC, and runtime are public on CHIPS Alliance [146] [147]. Founders: Microsoft, Google, AMD, NVIDIA. Google Cloud's Caliptra-1.0 announcement reports: *"the Caliptra specification and open-source hardware and software implementation is complete, reaching the revision 1.0 milestone."* The Google Cloud post adds that the Caliptra IP block is being integrated by member companies into chips expected in the market in 2026. Caliptra targets *"datacenter-class SoCs like CPUs, GPUs, DPUs, TPUs"* [146]. It is not a Pluton substitute on Windows clients: the form factor is different and the threat model assumes server-side operators.

> **Why Caliptra does not replace Pluton on Windows.**
> The instinct, on reading that Caliptra is open-source and multi-vendor, is to ask why Microsoft does not just put Caliptra into the next Surface. Three reasons. First, form factor: Caliptra is a datacenter-SoC IP block; the integration target is a CPU / GPU / DPU / TPU package on a \$20,000 server motherboard, not a \$700 ultrabook. Second, signer model: Caliptra is multi-vendor *by deployment*, but each Caliptra-equipped chip still has *one* signer: the integrating chip vendor (AMD signs AMD's Caliptra firmware; NVIDIA signs NVIDIA's). The choice of signer moved; the count of signers per chip did not. Third, threat model: Caliptra's RTM serves a server attestation flow ending at a fleet operator (Google, Microsoft, NVIDIA, the rack owner), not a client BitLocker flow that has to survive a powered-off laptop on an airport conveyor belt.
>
> Caliptra is the right counter-design to the *governance* of Pluton, not its *form factor*. It is what makes the single-signer-per-chip choice in Pluton-on-PC visible as a choice, not a technical necessity. That visibility is the whole reason this section exists.

### Project Cerberus: still in production

Cerberus has not been retired. Microsoft Learn describes it as *"a NIST 800-193 compliant hardware root-of-trust with an identity that cannot be cloned"* [138] [139] running in Azure datacenters; the GitHub reference implementation [137] is actively maintained. In the November 2020 Pluton announcement, Microsoft framed Cerberus as the *server-side* counterpart to Pluton's client-side root of trust [49]. The two are designed to compose, with Pluton providing the per-CPU identity that an upstream Cerberus chip (or Caliptra-equipped server) can attest. The distinction between Pluton-as-client-RoT and Cerberus-as-server-RoT is operational, not architectural rivalry.

### The cross-design comparison

| Dimension | Pluton-on-PC | Apple SEP | Google Titan M2 | Caliptra | Cerberus |
|---|---|---|---|---|---|
| Physical location | On-die in application SoC | On-die in Apple SoC | Discrete or in-package on Pixel | On-die in datacenter SoC | Discrete on server BMC |
| Trust anchor | Microsoft (chip-firmware signer) | Apple (vertical) | Google (vertical) | Per-chip integrator | Operator (Microsoft on Azure) |
| Update channel | Windows Update [6] | iOS / macOS update | Android / Pixel update | Server-side platform update | OEM / operator update |
| Firmware language | Rust-based foundation on 2024+ AMD/Intel [6] | Apple-customized L4 [62] | Not publicly disclosed | Open-source firmware [146] | C / C++ (open) [137] |
| Open source | Closed | Closed | Closed (driver public) | Open (RTL + firmware) | Open (RI on GitHub) |
| Multi-signer | Single | Single | Single | Multi-vendor by deployment | Per-deployment |
| Standards exposure | TCG TPM 2.0 over CRB | Apple-private | Android Verified Boot, StrongBox | Caliptra spec; SPDM 1.3 in 2.0 | NIST SP 800-193 |
| Best-known structural attack | None peer-reviewed Pluton-specific (TPMScan corpus only [148]) | T2 inherits A10 Boot ROM (checkm8) [153] | None public on Titan M2 | Reviewed open-source RTL | Mature; deployed since 2017 |
| Best suited for | Windows 11 client procurement | Apple devices | Pixel devices | Datacenter SoC integration | Server BMC RoT |
| Form factor | General-purpose PC | Apple devices | Pixel phones | Datacenter SoCs | Server motherboards |

The political question made architectural. Caliptra and OpenTitan answer "what would multi-signer / open-source look like?" in the *datacenter*. Apple SEP demonstrates that the single-vendor / single-signer model is operationally durable at consumer scale, but only when the vendor owns the entire stack. Pluton sits in the awkward middle: single-signer but multi-OEM, closed-firmware but open-Linux-driver, on-die but the chip vendor is not the firmware vendor. That middle position is what makes the procurement debate hard, and it is what makes the open problems in the next section unresolved.

Pluton is the strongest on-die RoT for Windows clients in 2026, with the clearest Microsoft-documented OS-delivered firmware-update path, the broadest hardware list, and the most mature design pedigree. What can it still not do?

## What Pluton still cannot do

Two structural limits inherited from the TPM chapter (Chapter 2), and a third that is specific to single-signer on-die firmware. The first two say what *no* on-die RoT can do. The third says what no *Microsoft-only-signer* RoT can do. The worked example is CVE-2025-2884.

### Limit 1: RTS+RTR, not RTE

A passive cryptoprocessor (including Pluton) cannot detect that the *wrong code* measured itself. It can only refuse to release sealed material when PCRs do not match the stored policy. The TPM chapter (Chapter 2) walks the bit-level reasoning. On-die does not change this. Pluton implements Root of Trust for Storage and Root of Trust for Reporting; it does not implement a Root of Trust for Execution that runs the code outside the chip on the reader's behalf.

### Limit 2: The VMK transits OS RAM at unseal

The Volume Master Key must enter RAM during Trusted Boot, and once unsealed it lives in OS-controlled memory. An attacker who reads OS RAM at the release moment, or any time after, defeats TPM-only BitLocker regardless of TPM strength (developed in the TPM chapter, Chapter 2). Pluton's on-die location eliminates the dTPM *bus* surface; it does not change which side of the unseal boundary the VMK lives on. This is why Virtualization-Based Security, Credential Guard, DRTM, and System Guard Secure Launch exist as *complements*, not substitutes, to the TPM/Pluton primitive.

### Limit 3: Single-signer revocation impossibility

This is the new one. State the result precisely: *if the on-die RoT firmware can only be authenticated by a single signer S, then the chip's trust anchor cannot be retired without bricking the chip's firmware-update path, regardless of whether S is compromised, coerced, or jurisdictionally constrained.* This is not a cryptographic impossibility. It is a key-management impossibility. Revocation requires either (a) a second trust anchor provisioned at chip manufacture and held outside S's control: i.e., multi-signer at the *chip* level, not just at the *deployment* level, or (b) physical replacement of the silicon. Caliptra and Cerberus weaken the failure mode by *moving* the signer to the integrating chip vendor or to the operator, but they do not eliminate it; each chip still has one signing root.

> **Definition: Single-signer revocation impossibility.**
> A key-management (not cryptographic) impossibility: a chip whose firmware-authentication root has one signer in ROM cannot have that signer retired without bricking the firmware-update path or replacing the silicon. Public Pluton documentation exposes a Microsoft-controlled firmware authority and no public multi-signer or alternate-root mechanism. See the prose above and the Callout below for the precise conditional theorem and the operational reasoning (FIDO2 / threshold-signature analogs; the design-choices trust-shift cross-anchor).

> **The objection is operational, not cryptographic.**
> There is no cryptographic objection to multi-signer RoT firmware. The math has been understood since the FIDO2 multi-credential work, and threshold signatures have been a primitive for decades. The objection is operational: replacing public keys after the chip is in the field requires either fab-time multi-signer or hardware replacement. The design-choices section named the choice; this Callout names what makes it hard to undo.

### Worked example, CVE-2025-2884

On June 10, 2025, NVD published CVE-2025-2884 [158]. The CERT/CC coordination ticket is VU#282450 [131]. The vulnerability is an out-of-bounds read in the `CryptHmacSign` function of the TCG TPM 2.0 reference implementation, Level 00, Revision 01.83 (March 2024). The CERT/CC document describes the impact: *"An authenticated local attacker can send malicious commands to a vulnerable TPM interface, resulting in information disclosure or denial of service of the TPM"* [131].

The attribution point is easy to get wrong; the side note below keeps it tied to the primary CERT/CC record.

> **Side note.**
> The Quarkslab attribution that some 2025 tech-press accounts use for CVE-2025-2884 is contradicted by the primary CERT/CC record VU#282450, which says verbatim: *"Thanks to the reporter, who wishes to remain anonymous. This document was written by Vijay Sarvepalli"* [131]. The reporter is anonymous. The document author is Vijay Sarvepalli. This chapter uses that attribution and only that attribution.

Multiple downstream products are affected. Intel published Security Advisory SA-01209 [159]. Siemens published SSA-628843 [160]. The libtpms project assigned CVE-2025-49133 [161] for its own derivative; the upstream fix landed in libtpms commit `04b2d8e9` [162]. The TCG itself coordinated VRT0009 [163] and a TPM 2.0 Library Specification v1.83 errata (cited via NVD as the verifiable mirror: the TCG site returns 403 to non-browser User-Agents).

Why this is the right worked example for Pluton. Garrett's April 2022 reverse-engineering [130] documented that the Pluton firmware blob in the AMD Ryzen 6000 BIOS is *"firmware for Pluton. It contains chunks that appear to be the reference TPM2 implementation, and it broadly decompiles as valid ARM code."* That supports a narrower conclusion than "CVE-2025-2884 was present in Pluton": reference-code defects can plausibly reach Pluton-derived firmware unless Microsoft has already diverged from, removed, or patched the affected code path. No public Microsoft advisory, TCG notice, or vendor bulletin in this chapter proves that the vulnerable `CryptHmacSign` revision was compiled into a shipping Pluton build. *On-die location does not by itself stop a reference-code bug from being relevant.*

What would matter for outcomes is the *dwell time* before vulnerable firmware is replaced. The structural change that distinguishes Pluton from a 2014 dTPM is not only "where the chip is" but "who can patch it, and at which boot phase the new image is loaded." A discrete TPM with the same bug would wait for the dTPM vendor to push a firmware build, the OEM to package a UEFI capsule, the OEM to test it across its product lines, and the user to install it. Microsoft's Pluton path adds Windows Update loading during Windows startup, while SPI-resident early-boot firmware can still be updated through UEFI capsules [6]. Design choice 4 (above) walked the channel-shape change and the no-SLA hedge; this is what makes the channel the security property that matters here.

| Realization | Patch path | Approximate latency | Bottleneck |
|---|---|---|---|
| Discrete TPM | dTPM vendor build → OEM UEFI capsule | Quarters to years | OEM fleet test + per-OEM rollout |
| Intel PTT (CSME) | Intel ME firmware → OEM UEFI capsule | Months to quarters | OEM UEFI capsule path (TPM-Fail lesson) |
| AMD fTPM (PSP) | AMD AGESA → OEM UEFI capsule | Months to quarters | Same OEM UEFI capsule path |
| **Pluton-on-PC** | Microsoft signs → Windows Update OS-load path; UEFI capsule for SPI-resident early image [6] | Faster channel available (no published SLA) | Microsoft signing key + WU infrastructure |

![Figure: CVE-2025-2884 propagation: a single bug in the TCG TPM 2.0 reference code reaches Intel TPM products, Siemens product TPMs, libtpms, and any reference-derived firmware that retained the affected code path. Garrett 2022 makes Pluton a plausible lineage concern, not a proved affected product. The patch paths differ; the underlying defect class is the same.](diagrams/02-pluton-cve-propagation.svg)

> **Key idea.**
> Pluton's structural advantage is the patch path, not the silicon location alone. CVE-2025-2884 demonstrates that on-die location would not, by itself, stop a TCG-reference-code bug from mattering to a reference-derived TPM firmware line. What changes between a 2014 dTPM and Pluton is not only "where the chip is" but "who can patch it, and which firmware phase the patch reaches." On-die is necessary but not sufficient. The breakthrough is the update path. The cost of the update path is the political question this chapter's opening promised.

If single-signer revocation is impossible, what would multi-signer Pluton look like? And what other open problems does this design choice leave unsolved?

## Open problems Pluton has named but not solved

Five concrete open problems sit in front of any 2026 reader of the Pluton design. Each is mapped below to the closest existing partial result. None has a public solution.

### Open problem 1: Multi-signer firmware for on-die client RoTs

No public proposal exists for multi-signer Pluton on a Windows client. Caliptra moves the signer to the integrating chip vendor [146], so the count of signers per *chip* remains one even when the count per *deployment* is many. There is no public proposal for two simultaneous signers on a single client RoT (e.g., Microsoft *and* a sovereign signer; or AMD *and* Microsoft for a Pluton-on-AMD chip). The closest existing analogs live elsewhere (IETF KEYTRANS for transparency-logged keys [164], HSM-cluster split-signing for operational continuity) but none has a hardware-RoT counterpart that has shipped. The unresolved engineering question, named in the TPM chapter (Chapter 2), is whether multi-signer can be added without losing the timely-update property that motivated Pluton in the first place.

> **Side note.**
> The IETF KEYTRANS working group [164] is the closest active venue for the multi-signer thread, although KEYTRANS is concerned with end-user identity-key transparency rather than firmware-signing keys. The transparency-log primitive is the same (a Merkle tree of signed claims, auditable by independent verifiers); the hardware-RoT integration is missing. A reader interested in the multi-signer thread should track KEYTRANS and the OpenTitan / Caliptra governance discussions in parallel.

### Open problem 2: Regulatory jurisdiction of single-signer firmware

Pluton's signing key is, in effect, a US export-controlled artifact. The EU Cyber Resilience Act entered into force on December 10, 2024, with the bulk of its security obligations applying from December 11, 2027 and reporting obligations applying from September 11, 2026 [165]; from the 2027 date it will require demonstrable security properties for products with digital elements, without specifying *who* the signer must be. Sovereign fleets such as the German Federal Office for Information Security (BSI), Singapore, and Switzerland have varying postures on whether a non-domestic RoT is acceptable. Read in 2026, the Dell and Lenovo statements of March 2022 [127] [128] are the first public push-back along this axis. The procurement debate is not technical; it is jurisdictional. There is no current proposal for a Pluton variant that satisfies a non-US sovereign procurement requirement.

> **EU CRA, German BSI, and the sovereign-fleet question.**
> The EU Cyber Resilience Act entered into force on December 10, 2024 [165]. Reporting obligations apply from September 11, 2026; the main security obligations apply from December 11, 2027 [165]. CRA does not name signers; it requires demonstrable security properties, vulnerability handling, and update channels for products sold into the EU. A single-signer foreign-rooted RoT can satisfy CRA. Whether it satisfies *sovereign* procurement requirements is a separate question.
>
> The German BSI's Common Criteria PP-0084 protection profile [166] (used historically for Infineon SLB 9670 / 9672 dTPMs) bakes in expectations of the chip-supplier governance that a US-rooted Pluton does not satisfy without a parallel certification path. Switzerland's federal IT procurement, Singapore's CSA, and a number of EU member-state ministries take comparable positions. None of these is a formal ban on Pluton; all of them are formal preferences that procurement officers must navigate.
>
> The architectural fix (a sovereign signing-root variant of Pluton) has not been publicly proposed by Microsoft. The economic incentives for such a variant are not obviously favorable: every additional signer adds operational cost to the Windows Update path that Pluton's design specifically optimizes. The procurement market is, as of 2026, deciding both ways, and the 2022 Dell statement is the most-cited public datapoint of a vendor declining to take the bet.

### Open problem 3: SPDM 1.3 component attestation on PC

Pluton attests the host SoC. It does not yet attest individual components (NICs, NVMe SSDs, PCIe accelerators) on Windows clients. The DMTF's Security Protocol and Data Model (DSP0274) is the wire protocol for component-to-component attestation: a publication cadence of 1.3.0 in June 2023, 1.3.2 in September 2024, and 1.3.3 in December 2025 [167]. The Caliptra MCU project's Rust SPDM responder design page is the most explicit public reference for what an SPDM 1.3 endpoint looks like inside an on-die RoT: SPDM is *"a protocol designed to ensure secure communication between hardware components by focusing on mutual authentication and the establishment of secure channels over potentially insecure media... using X.509v3 certificates"* [168], with a fixed message inventory (`GetVersion`, `GetCapabilities`, `NegotiateAlgorithms`, `GetDigests`, `GetCertificate`, `Challenge`, `GetMeasurements`, `KeyExchange`, `Finish`) carried over an MCTP transport binding. Caliptra 2.0's RTL design freeze in October 2024 [169] commits SPDM as part of the Caliptra Subsystem reference stack: *"Reference Stack: MCTP PLDM, SPDM"* [169]. That is the server-side commitment.

The PC-client equivalent is not on the public record as of May 2026. Microsoft Learn's Pluton page does not mention SPDM, DSP0274, MCTP, or component attestation [6]. There is no Microsoft-published Windows feature or Pluton-firmware milestone that names "SPDM responder" or "component attestation on PC" as a roadmap deliverable. The architectural question, whether Pluton becomes the platform's SPDM responder, whether each component (NVMe controller, Wi-Fi card) is its own responder and Pluton aggregates the evidence, or whether Windows Defender System Guard owns the Windows-side appraiser, is not answered by any published Microsoft document on the public record as of May 2026. The closest existing reference design lives in `chipsalliance/caliptra-mcu-sw` (Rust SPDM responder, X.509-anchored mutual auth), and the most likely standards venues for a PC-client profile are the DMTF SPDM WG (the wire protocol owner) and the OCP Security WG (the appraisal-framework owner). Until Microsoft publishes a Windows-feature surface that owns the SPDM responder on PC, "Pluton attests the host SoC, period" is this chapter's honest description of the 2026 state.

### Open problem 4, Pluton-Caliptra interoperation

A Pluton-rooted client should, in principle, be able to attest to a Caliptra-rooted server in a single end-to-end protocol with both roots of trust visible in the resulting evidence chain. The wire-protocol candidates exist and are largely standardized. What is missing is the *composite-attestation profile* that wires them into a single client-to-server flow.

The candidate stack as of May 2026 lives across three SDOs and one OCP project. The DMTF owns SPDM 1.3 for component-to-component attestation [167] [168]. The IETF Remote Attestation Procedures (RATS) Working Group owns the architectural primitives for what an evidence-and-results message *contains*: RFC 9711 (April 2025, Standards Track) is the Entity Attestation Token (EAT), a CBOR Web Token (CWT) or JSON Web Token (JWT) form for *"an attested claims set that describes the state and characteristics of an entity"* [170]; `draft-ietf-rats-corim-10` (in WG Last Call as of March 2026) is the Concise Reference Integrity Manifest, the appraisal-time profile for *"Endorsements and Reference Values in CBOR format"* [171]; `draft-ietf-rats-msg-wrap-23` (in the RFC Editor queue since December 2025) is the Conceptual Message Wrapper, a CBOR-tag / JWT / CWT / X.509-extension envelope for *composing* evidence, attestation results, endorsements, and reference values across protocols [172]. The full RATS WG document inventory at `datatracker.ietf.org/wg/rats/documents/` shows additional active drafts on multi-verifier composition, posture-assessment, EAR (an evidence-appraisal-results profile), and PKIX key attestation [173]. The OCP Security WG owns the third-party appraisal framework: OCP S.A.F.E. v2.0 (March 2026) added explicit CoRIM SFR support and is the public mechanism by which a fleet operator certifies that a vendor's firmware-appraisal evidence has been independently audited [174]. Caliptra 2.0's reference stack already wires SPDM, MCTP, and PLDM [169]; the Caliptra MCU Rust responder shows the SPDM endpoint shape [168].

What is *missing* is a single published profile that walks the chain end to end: a Pluton-rooted Windows client emits a `Get-Tpm`-derived attestation (Pluton acting as evidence producer); the network carries CMW-wrapped evidence with a CoRIM endorsement set the verifier consumes; the verifier emits an EAT-formatted attestation result; a Caliptra-rooted server consumes the result and gates fleet membership. Each leg has a draft. No public SDO document binds them into a single Pluton-Caliptra composite-attestation profile with reference implementations on both ends. The natural venue is a joint DMTF SPDM WG and OCP Security WG profile, with IETF RATS as the architectural reference; the natural reference implementation pair is `chipsalliance/caliptra-mcu-sw` on the responder side and a Windows-feature surface (which Microsoft has not named publicly) on the client side. Until that joint profile exists and ships reference implementations, Pluton-Caliptra interoperation in 2026 is two roots-of-trust deployed, with no published end-to-end protocol that visibly carries both signatures into a single evidence chain.

### Open problem 5: Supply-chain integrity beyond firmware signing

The Pluton signing root protects firmware integrity *after* the chip ships. Listing the supply-chain steps in chronological order makes the residual trust gap concrete: (1) the IP-licensing handshake from Microsoft to AMD / Intel / Qualcomm; (2) tape-out and process-design-kit integration at TSMC; (3) wafer fabrication; (4) per-vendor package assembly; (5) OEM motherboard integration; (6) OEM firmware integration (BIOS / UEFI vendor code that surrounds the Pluton block); (7) retail distribution. None of these steps is presently attested by Pluton itself; the on-die signing root is *provisioned* during silicon manufacture (the tape-out and fabrication steps) and *exercised* when signed Pluton firmware is loaded and verified from OEM firmware integration onward, but the licensing, assembly, and board-integration steps around it are out of band of the chip's RoT.

The closest existing partial answer is a layered combination of three primitives. First, DICE (TCG's Device Identifier Composition Engine) gives every component a *Hardware Root of Trust (HRoT) which uniquely identifies the component and attests component firmware* [175], anchored by a per-die Unique Device Secret (UDS) that derives a Compound Device Identifier (CDI) per layer; the Open Profile for DICE v2.6 [176] is the reference profile and explicitly cites the TCG normative parent. DICE answers step 4-5 (per-package and per-board identity) provided the integrator provisions a UDS on the die. Second, SPDM 1.3 [167] [168] is the wire protocol that surfaces those DICE identities to a verifier at runtime: a per-component SPDM responder (carried over MCTP / PLDM in Caliptra 2.0's stack [169]) emits a measurement set tied to its CDI. Third, OCP S.A.F.E. (Security Appraisal Framework and Enablement) v2.0 [174] is the third-party-audit framework that lets a fleet operator certify that a Device Vendor's firmware was assessed by a Security Review Provider; the v2.0 March 2026 revision explicitly added CoRIM SFR support, wiring S.A.F.E. into the IETF RATS appraisal stack [171]. Together, DICE + SPDM + S.A.F.E. answer "is each component what its vendor said it was, and has the firmware been independently appraised?"

What is *not* built is the verifier infrastructure that consumes that evidence end to end. There is no public per-component-EK transparency log analogous to Certificate Transparency for the web PKI; there is no Pluton-rooted client-side appraiser that consumes per-component SPDM evidence and gates Windows boot on it; there is no shipping fleet-side hardware-bill-of-materials (HBOM) audit pipeline that ingests S.A.F.E. reports and Caliptra-rooted server attestations together. The supply-chain trust is *named* by DICE + SPDM + S.A.F.E.; it is not *operationalised* end to end on a 2026 Windows 11 client. The honest framing is: Pluton's signing root closes step 6 and step 7; DICE + SPDM + S.A.F.E. are the public standards that, if implemented in the Windows feature stack, would close steps 4-5; steps 1-3 (IP licensing, tape-out, wafer) remain out of band of any of the public standards above.

### The 10-property scoreboard for an ideal client-PC on-die RoT

Five open problems converge onto a single scoreboard. This chapter's SOTA review enumerates ten properties an ideal client-PC on-die Root of Trust in 2026 would satisfy. It inherits five of the TPM chapter's six ideal-TPM properties (on-die location, isolated TEE, OS-channel firmware updates, native post-quantum primitives, and high-assurance certification depth) while dropping "authenticated wire protocol always on" because an on-die Pluton path has no exposed off-package TPM wire to protect. It adds five Pluton-era properties: memory-protected DRAM with authenticated anti-replay protection, memory-safe firmware language, multi-signer firmware authentication, public RTL / verification flow, and component attestation via SPDM 1.3. The ten rows are therefore: (1) on-die location with no off-package bus; (2) an isolated TEE shared with nothing else; (3) memory-protected DRAM with AES + authenticated + anti-replay protection; (4) OS-channel firmware updates; (5) memory-safe firmware language; (6) multi-signer firmware authentication; (7) public RTL and verification flow; (8) native post-quantum primitives (ML-DSA, ML-KEM); (9) component attestation across PCIe / NVMe / NIC via SPDM 1.3; (10) high-assurance certification depth (Common Criteria EAL4+ and FIPS 140-3). No shipping method satisfies all ten; the matrix below shows where each design sits.

| Property | Pluton-on-PC 2026 | Apple SEP (A14/M1+) | OpenTitan (Earl Gray / Darjeeling) | Caliptra 2.0 (RTL freeze Oct 2024) | Cerberus (current production) |
|---|---|---|---|---|---|
| 1. On-die, no bus | Yes [49] | Yes [62] | Discrete or in-package | Yes [146] | No (discrete on BMC) |
| 2. Isolated TEE | Yes (dedicated) | Yes [62] | Yes (whole chip) | Yes (RTM block) | Yes (whole chip) |
| 3. AES + authenticated + anti-replay DRAM | Not on public record | Yes (A14/M1+) [62] | Limited (chip-internal SRAM) | N/A (no DRAM responder role) | N/A (server BMC) |
| 4. OS-channel firmware updates | Yes (Windows Update) [6] | Yes (iOS / macOS) [62] | Project-managed | Server platform updates | OEM / operator updates |
| 5. Memory-safe firmware | 2024+ AMD/Intel only [6] | Apple-customized L4 [62] | Rust runtime in OpenTitan codebase | Rust [146] [168] | C / C++ [137] |
| 6. Multi-signer | No public alternate root documented | No (Apple only) | No (per-deployment) | Multi-vendor by deployment, single per chip [146] | Per-deployment signer |
| 7. Public RTL and verification | No | No | Yes [156] [157] | Yes [146] | No (firmware reference implementation is public; silicon RTL is not) [137] |
| 8. Native PQC (ML-DSA, ML-KEM) | No public commitment date | No public commitment date | On roadmap [156] | Yes (RTL freeze incl. Dilithium + Kyber) [169] | No |
| 9. Component attestation (SPDM 1.3) | No (open problem 3) | Apple-private equivalents | Not yet | Yes (Reference Stack: MCTP PLDM, SPDM) [169] [168] | NIST SP 800-193 framing [138] |
| 10. EAL4+ and FIPS 140-3 | FIPS 140-3 L2 (Pluton ROM, CMVP #4880); no public EAL4+ [177] | Not pursued for SEP | In assessment | Not pursued | Some certifications via OEM |
| **Properties satisfied (chapter rubric)** | **3-4 (1, 2, 4, plus 5 on 2024+ AMD/Intel)** | **4 (1, 2, 3, 4)** | **2 (5, 7)** | **3 (5, 7, 8): on track for 9** | **0-1 (partial 9; public firmware is not public RTL)** |

The matrix says two things at once. First, under this chapter's rubric, no shipping on-die RoT in 2026 satisfies more than four of the ten properties; the scoreboard is sparse on purpose and is not an assurance metric. Second, the closest *trajectory* to the ten-property ideal is not any single design; it is the union of Pluton's properties (1, 2, 4, and 5 where the 2024+ AMD/Intel Rust foundation applies), Caliptra's open RTL and PQC commitments (7, 8, 9), and OpenTitan's open RTL (7). A hypothetical Pluton variant that adopted Caliptra-style multi-signer governance, OpenTitan-style RTL transparency, and the Caliptra 2.0 SPDM responder reference stack would satisfy 1, 2, 4, 5, 6, 7, 8, 9 (eight of the ten) with high-assurance certification (10) the residual procurement question. That hypothetical Pluton has not been publicly proposed by Microsoft. It is, however, the design the matrix names as the destination if all five open problems above were closed.

### The shape of the unanswered question

| Open problem | Why it matters | Closest existing partial result | Outstanding gap |
|---|---|---|---|
| Multi-signer client RoT | Single-signer revocation impossibility | Caliptra (multi-vendor by deployment, single-signer per chip) [146] | No two-signer-per-chip proposal for client |
| Regulatory jurisdiction | Sovereign procurement, EU CRA (in force Dec 10 2024, reporting from Sep 11 2026, main obligations from Dec 11 2027) [165] | March 2022 Dell / Lenovo posture [127] [128] | No sovereign Pluton variant |
| SPDM 1.3 on PC | Component attestation beyond the SoC | Caliptra 2.0 reference stack with SPDM [169] [168] | No PC-client SPDM responder named on Microsoft Learn |
| Pluton-Caliptra interop | Composite client-to-server attestation | RATS EAT [170] + CoRIM [171] + CMW [172] + S.A.F.E. [174] | No joint DMTF / OCP / RATS profile binding the chain end to end |
| Supply-chain integrity beyond firmware signing | Pre-ship trust (steps 1-5 of the chain) | DICE [175] [176] + SPDM [167] + S.A.F.E. [174] | Verifier infrastructure (per-component-EK transparency, HBOM appraiser) not built |

All five share the same shape. Pluton has *narrowed* but not eliminated structural classes of trust. On-die narrowed but did not eliminate the silicon supply chain trust. Microsoft-rooted firmware servicing narrowed but did not eliminate the firmware-signing trust. Component attestation, when it ships on PC, will narrow but not eliminate the per-component supply-chain trust. Each Pluton design choice trades one trust for another; the residual trusts are the ones this chapter cannot answer technically and must label politically.

On Monday morning, what does the Windows engineer reading this actually do?

## The Pluton checklist for 2026

Five questions. Each has a one-paragraph answer and a verifiable command or check. The reader who skipped the rest of this chapter will still avoid the most expensive mistake: counting "Pluton present" as "Pluton enabled."

### Q1. Is Pluton present on this device?

`Get-Tpm` in PowerShell reports `ManufacturerIdTxt`, Windows's rendering of the TPM 2.0 manufacturer property (`TPM_PT_MANUFACTURER`), a four-byte vendor field in the TCG structures specification [178]. `MSFT` is the Microsoft-backed value: on physical hardware it is the value expected for Pluton-as-TPM; in Microsoft virtualization it can also be a Microsoft vTPM. `INTC` is Intel PTT; `AMD` (with trailing space) is AMD fTPM; `IFX`, `STM`, and `NTC` cover Infineon, STMicro, and Nuvoton discrete TPMs respectively. The TPM chapter (Chapter 2) documents the broader manufacturer-string discovery path. The Pluton-specific check is therefore `MSFT` **plus** Plug-and-Play / Device Manager evidence of a Microsoft Pluton security processor.

**How to detect Pluton with Get-Tpm.**

Open PowerShell as administrator and run:

```powershell
Get-Tpm | Select-Object ManufacturerIdTxt, ManufacturerVersion, TpmPresent, TpmReady
```

A `ManufacturerIdTxt` of `MSFT` indicates a Microsoft-backed TPM interface: Pluton on physical hardware when the Plug-and-Play security-device list also shows the Pluton processor, or a Microsoft vTPM in virtualization. Other vendor strings are as above; for richer detail, run `tpm.msc`: the Microsoft Management Console snap-in shows the full TPM identity.

### Q2. Is Pluton *enabled*, not just *present*?

This is the soft-fuse trap from the *Pluton in 2026* section. On AMD Ryzen 6000 / 7000 / 8000 physical silicon, `Get-Tpm` returning `MSFT` plus Plug-and-Play evidence of the Pluton security processor proves Pluton is *exposed* as the TPM, but does not, on its own, prove Pluton is *enabled* in firmware (the *Soft-fuse Pluton disable* Definition and the *Pluton present is not Pluton enabled* Callout walk the PSP directory 0xB BIT36 mechanism Garrett 2022 documents [130]). The procurement-relevant action is to audit BIOS-level Pluton (HSP) toggles and correlate `Get-Tpm`'s manufacturer string with `Get-PnpDevice` / Device Manager before counting an AMD-Ryzen-6000-class device as Pluton-protected. On Lenovo AMD Ryzen 6000 ThinkPads specifically, the launch posture was Pluton present but disabled by default [127], so a 2022 ThinkPad inventory query that finds Ryzen 6000 silicon will not, on its own, tell the operator whether Pluton is doing any work.

### Q3. Is Pluton firmware current?

Microsoft supports loading new Pluton firmware through Windows Update during Windows startup, alongside UEFI capsules for the SPI-resident early-boot firmware [6]. Microsoft does not publish a per-release notes feed for Pluton firmware, so the operator must rely on the general Windows Update history and the chip vendor's advisory feed (Intel SA-* for Intel-Pluton silicon; AMD's security bulletins for AMD-Pluton silicon). The procurement-relevant property is that the OS-load channel exists; the procurement-relevant *question* is whether the operator's organization is willing to depend on that channel and its boot-phase semantics.

### Q4: When to *prefer* Pluton over dTPM, PTT, or AMD fTPM

Three procurement scenarios where Pluton is the right answer in 2026.

- **Default Windows 11 client procurement.** Pluton on AMD Ryzen 6000 and later, Intel Core Ultra 200V Series and Series 3, and Snapdragon X Series [6]. The Microsoft-supported configuration; the path of least administrative resistance; and, on 2024+ AMD and Intel systems, the realisation for which Microsoft publicly commits to a Rust-based firmware foundation [6].
- **Adversary model includes physical access.** Andzakovic-class bus sniffing [78], faulTPM-class voltage glitching [99]. Pluton (on-die, dedicated TEE) removes the off-package TPM bus and avoids the PSP-fTPM shared-TEE path for Pluton-as-TPM.
- **Need fast firmware updates for security responses to TCG-reference-code bugs.** CVE-2025-2884 is the worked example [158]. Pluton's OS-load servicing path is the clearest realisation here that is not limited to the OEM UEFI capsule path, while the SPI-resident early image still has UEFI-capsule semantics [6].

### Q5: When to *not* prefer it

Three procurement scenarios where Pluton is not the right answer.

- **Regulated fleets requiring a non-US trust anchor.** German BSI PP-0084-class procurement [166], EU sovereign workloads. Hardened dTPM (Infineon SLB 9670 / 9672, STMicro ST33TPHF) has the certified posture [177]; Pluton has no public Common Criteria EAL4+ certification for the whole security processor as of 2026, though its ROM module carries a FIPS 140-3 Level 2 validation (CMVP cert 4880) [177].
- **Air-gapped fleets that cannot accept Windows-Update-delivered firmware.** Offline UEFI capsule servicing remains the only operationally feasible patch path; dTPM is the mechanically right choice for that fleet.
- **Multi-vendor sourcing requirements.** dTPM has multiple silicon vendors (Infineon, STMicro, Nuvoton). Pluton has one signer per chip and only the AMD / Intel / Qualcomm silicon paths Microsoft has licensed. Datacenter operators who need multi-vendor sourcing should look at Caliptra [146]: not a Pluton substitute on Windows clients, but the right answer for datacenter SoC procurement.

| Choose Pluton when... | Choose dTPM (or Caliptra) when... |
|---|---|
| Default Windows 11 client procurement [6] | Sovereign procurement (German BSI, EU sovereign) |
| Adversary model includes physical access | Air-gapped fleet, no Windows Update channel acceptable |
| Need an OS-delivered firmware response path | Need EAL4+ / FIPS 140-3 certification posture today |
| Want Microsoft-committed Rust foundation on 2024+ AMD/Intel | Need multi-vendor silicon sourcing |
| Want on-die dedicated TEE versus shared PSP/CSME | Datacenter SoC integration (Caliptra) |

![Figure: Procurement decision tree: choose Pluton, dTPM, or Caliptra based on fleet shape and regulatory posture.](diagrams/02-pluton-procurement-tree.svg)

We started with the question Microsoft answered architecturally before the TPM chapter (Chapter 2) posed it. Where does that leave the political question that even the architectural answer cannot resolve?

## A closing tied to the TPM chapter

Return to the line that opened this chapter. *"The TPM was supposed to be the part of the system you didn't have to trust anyone for. Twenty-five years later, the trust question is back, and the answer is now political"* [39]. The architectural answer to that question existed inside an Xbox before the question was asked. Twelve years of Microsoft security silicon: Xbox One in 2013, Project Sopris in 2015, the *Seven Properties* paper in 2017, Project Cerberus in 2017, Azure Sphere in 2018, Pluton-on-PC in 2020, AMD Ryzen 6000 silicon in 2022, Linux 6.3 driver in 2023, Caliptra 1.0 in 2024, and the CVE-2025-2884 dwell-time test in 2025, have shaped the on-die security processor on the modern Windows 11 client.

This chapter's own answer is direct. Pluton makes the political question concrete and unavoidable, but it does not resolve it. On-die closes the bus surface. A dedicated Pluton subsystem narrows the shared-TEE blast radius that defeated AMD fTPM. A Rust-based foundation on 2024+ AMD and Intel systems narrows the bug class that has driven the firmware-CVE economy for a decade. Windows Update adds an OS-startup firmware loading path alongside UEFI capsules for the SPI-resident early image. *Each design choice narrows a 2014-2024 attack class. Each design choice places a new trust in Microsoft.* The trust question is now visible at every level of the stack: silicon supply chain, firmware language, signing key, update channel, regulatory jurisdiction. It does not go away because Microsoft engineered the chip well. It goes from being a technical question to being a procurement question.

> **Thesis restatement.**
> Pluton makes the political question concrete and unavoidable, but it does not resolve it.

The closing image is operational. An engineer running `Get-Tpm` on a physical Windows 11 laptop in 2026 reads a four-letter token in the manufacturer string, then cross-checks Plug and Play to rule out the vTPM ambiguity. `MSFT`, when that cross-check shows Pluton, is what twelve years of Microsoft security silicon buys you. It is what closed the bus surface that the TPM chapter's \$40 FPGA exploited (Chapter 2). It is what narrows the shared-TEE surface that faulTPM extracted state from. It is what gives the Windows Update channel firmware to load during Windows startup. It is also what places a Microsoft-controlled firmware authority in the trust path for every Pluton-equipped Windows 11 client. That four-letter token is this chapter's subject, the TPM chapter's epilogue (Chapter 2), and the next decade's procurement question.

> **Bequeaths.** Pluton hands the next link one guarantee, narrow and load-bearing: an on-die root of trust whose stored keys and signed reports survive a physical-access adversary on the bus, and whose post-boot firmware has an OS-delivered update path in addition to OEM capsules for the SPI-resident early image. That anchor is what the Measured Boot chapter (Chapter 4) extends every boot-stage hash into, and what the Attestation chapter (Chapter 5) signs its quotes over. Neither chapter has to re-establish where the measurement registers physically live or trust the bus that reaches them. But the bequest stops at the *anchor*. Pluton measures nothing on its own: the act of measuring the boot chain, and the gap where the *wrong code can measure itself* (a Root of Trust for Execution, which Pluton is not), belong to the Measured Boot chapter (Chapter 4) and the Attestation chapter (Chapter 5). It proves no *liveness* of the right code at runtime: the runtime-environment problem is the Attestation chapter's (Chapter 5). It makes no claim over a secret once that secret is unsealed into OS RAM: the Volume Master Key after release belongs to the Secure Kernel chapter (Chapter 6) and VBS-based key isolation. And it offers no documented *non-Microsoft* firmware authority: single-signer revocation, sovereign jurisdiction, and pre-ship supply-chain integrity are Pluton-named open problems the back-matter *Unfinished Chain* inherits. The chain moves the root onto the die and adds a Windows Update firmware path; it does not yet move the *measurement*, the *liveness proof*, or the *in-RAM secret* out of reach.
