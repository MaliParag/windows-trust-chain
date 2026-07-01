# The Secure Kernel

::: trust-ledger

- **Inherits:** A measured, signed launch path. Secure Boot refused unsigned boot code (Chapter 1, Secure Boot), Measured Boot extended each stage's hash into the TPM's PCRs (Chapter 4, Measured Boot) rooted in the TPM (Chapter 2, The TPM), and Attestation let a remote party believe the record by signing a quote over those PCRs (Chapter 5, Attestation), so the conditions under which Hyper-V and `securekernel.exe` start are themselves verified, not assumed.
- **Promise:** An asset placed in VTL1 cannot be directly read or written through ordinary VTL0 architectural mappings, including by the NT kernel running as `SYSTEM`, because Hyper-V programs second-level address translation (SLAT) so VTL0 holds no mapping for VTL1-owned pages. That promise assumes the hypervisor, Secure Kernel, firmware/DMA posture, update path, and secure-call interface hold; it does not cover oracle use, rollback, or side channels. Serviced boundary: VTL0→VTL1, which Microsoft commits to defending with a security update.
- **TCB:** The Hyper-V hypervisor, the Secure Kernel (`securekernel.exe`), the Isolated User Mode substrate, and the secure-call interface that marshals every VTL0 request. Plus the boot and update policy that decides which version of that code runs. The NT kernel the attacker can own is explicitly outside it.
- **Adversary → Break:** A bug in the secure-call parser turns VTL0 control into VTL1 code execution (Amar and King's Hyperseed fuzzing found ten); rollback runs an old, signed, vulnerable Secure Kernel while the box still reports itself patched (Windows Downdate, CVE-2024-21302); a trustlet can be asked to *use* a secret it will not *surrender* (oracle abuse); and VTL0/VTL1 share microarchitecture, so timing can leak what page permissions hide. The Promise covers *direct architectural reads and writes*, not *use*, *freshness*, or *side channels*.
- **Residual:** Credential *use* and protocol relay → Credential Guard (Chapter 15) and The Death of NTLM (Chapter 16); which binaries enter VTL1 user mode and the third-party enclave model → VBS Trustlets (Chapter 7); kernel code-integrity and vulnerable signed drivers → Code Integrity (Chapter 8); device-health signals consumed by access policy → Zero Trust (Chapter 26) and Continuous Access Evaluation (Chapter 27); protecting a guest from a hostile host, the opposite trust direction → Confidential VMs (Chapter 28).
- **Bequeaths:** A VTL1 floor (a secure world whose owned pages a ring-0 attacker cannot directly map through VTL0 page tables) on which Credential Guard (Chapter 15) isolates the long-term credential and Code Integrity (Chapter 8) makes the kernel's own code pages immutable. Does NOT provide: an honest VTL0, a bug-free secure-call interface, a guarantee that the *current* Secure Kernel version is the one running (rollback), or freedom from shared-hardware leakage.
- **Proof:** 🟢 `deviceguard.txt`. Live lab VM, hash-gated at the point of claim: VBS running with Credential Guard and HVCI as active services. 🔵 documented for the VTL1 internals a VM cannot expose (Ionescu, Wojtczuk, Amar/King, Microsoft Learn).
:::

> **The Reasoner's question.** What does VBS put beyond the reach of a compromised kernel, how is that enforced, and where does the trust chain still break?

---

Part II is easiest to misunderstand if it is read as marketing language. "Virtualization-Based Security" can sound like a feature switch; "Secure Kernel" can sound like a replacement kernel; "Memory Integrity" can sound like a dashboard label. The mechanism is sharper than the labels. Windows takes a machine that historically had one all-powerful kernel and asks the hypervisor to create a second runtime world. The normal kernel remains the operating system. The secure kernel becomes the place where Windows puts the small set of secrets and decisions that must survive when the normal kernel is not fully trusted.

That last clause is the whole chapter. VBS is not a promise that kernel exploitation is impossible. It is not a promise that malware cannot persist, keylog, steal files, tamper with user processes, or abuse tokens in VTL0. It is a narrower but more durable claim: if an asset has been moved into VTL1, and if the hypervisor, secure kernel, boot policy, and secure-call interface hold, then VTL0 compromise alone should not expose that asset directly. The rest of the chapter is the unpacking of each condition in that sentence.

## How to read the boundary

Before walking through the history, hold the architecture as three separate promises. VBS is often discussed as if it were one binary state (on or off, secure or insecure) but the real system is a stack of promises that can fail independently.

The first promise is **placement**: the asset must actually be in VTL1. If a secret remains in a VTL0 process, VBS does not retroactively protect it. If a driver decision is still made entirely by the normal kernel, the Secure Kernel cannot enforce it. If an application keeps its encryption key in ordinary process memory while also using a VBS enclave for some other calculation, the key is still an ordinary VTL0 asset. This placement question is why Credential Guard matters so much: it changes where long-lived authentication material lives. It is also why HVCI matters: it changes who gets the final say over executable kernel pages. A Reasoner should never stop at "VBS is enabled." The first operational question is always: *which asset moved?*

The second promise is **mediation**: VTL0 must not be able to bypass the approved interface. SLAT is the center of that promise. The NT kernel can create and modify its own page tables, but those tables are no longer the final mapping authority. The hypervisor's second-level tables decide whether a guest-physical page is visible to a trust level. That is the new geometry. A VTL0 write primitive can corrupt VTL0. It can patch a driver, alter a token, or lie to a user-mode sensor. It should not, merely by being a kernel write primitive, acquire a mapping for VTL1-owned pages. If the attacker wants VTL1 data, they must either use a legitimate secure-world service as an oracle, exploit a bug in the crossing path, compromise the hypervisor, or attack the boot/update path that decides which trusted code runs.

The third promise is **versioned trust**: the code enforcing the boundary must be the intended code. Secure Boot and measured boot made this question explicit for firmware and boot components; VBS carries it into runtime. `securekernel.exe`, code-integrity components, trustlets, and revocation policies are software. If an attacker can roll them back to vulnerable versions while the machine still reports itself as patched, the boundary may exist in form while losing the fix that made it safe in substance. That is why rollback appears in this chapter as a first-class failure mode rather than as an administrative footnote.

Those promises explain the shape of the chapter. The NT history explains why placement was needed: Ring 0 used to be the last line. PatchGuard and driver signing explain why same-level enforcement was not enough. Secure Boot explains why starting clean did not solve runtime compromise. VTLs and SLAT explain mediation. Credential Guard, HVCI, System Guard, Secured-core PCs, and VBS enclaves explain what Windows chose to place in the secure world. Secure Kernel bugs, Pass-the-Challenge, side channels, and Windows Downdate explain how the promises can break.

This layered reading also prevents two common errors. The first error is overclaiming: "VBS stops kernel compromise." It does not. It lets selected assets survive selected kinds of VTL0 compromise. The second error is underclaiming: "an admin can always win, so VBS does not matter." That misses the operational threat model. Microsoft may not treat administrator-to-kernel as a servicing boundary, but enterprises still care whether a remote intruder who reaches local admin can immediately dump domain credentials, load arbitrary unsigned kernel code, or tamper with measured runtime claims. VBS raises those costs by moving the relevant secret or decision behind a boundary the intruder does not automatically control.

The useful mental model is therefore not a castle wall around the whole machine. It is a vault inside a compromised building. The attacker may own the lobby, cameras, elevators, and many offices. They may coerce clerks into performing authorized actions. They may attack the vault door. They may try to replace the vault firmware with last year's vulnerable build. But if the vault is real, current, and used for the right asset, merely owning the building no longer means holding the contents.

## The Secure Kernel's contract

`securekernel.exe` is not a second Windows that happens to be safer. It is a small kernel with a contract. It initializes the secure world, manages VTL1 memory, hosts the primitives needed by Isolated User Mode, mediates secure service dispatch, and participates in decisions that the normal kernel should not be able to forge. Its value comes as much from what it refuses to do as from what it does. It does not run the desktop. It does not host arbitrary drivers. It does not replace the object manager, the file-system stack, the registry, the network stack, or the scheduler that ordinary applications experience. Those remain VTL0 responsibilities because moving all of Windows into VTL1 would recreate the original problem at a higher level.

The contract is deliberately selective. Credential Guard asks the secure world to hold long-lived credential material and perform cryptographic operations without returning the raw key. HVCI asks it to participate in code-integrity decisions and executable-page permissions. System Guard asks it to help produce runtime claims that VTL0 malware cannot simply edit before a relying service sees them. VBS enclaves ask it to host constrained application code whose private memory is opaque to the host process and the normal kernel. Each service expands the value of VTL1, and each service also expands the interface exposed to VTL0.

This is the central engineering trade. A completely silent secure world would have almost no attack surface, but it would also be useless. A useful secure world must accept inputs, validate buffers, copy data across trust boundaries, maintain handles, return results, and survive hostile callers. The secure-call surface is therefore the new reference monitor problem in miniature. The old SRM asked whether a subject in Windows could access an object in Windows. The VBS boundary asks whether an untrusted normal world can invoke a tightly scoped operation in a trusted secure world without gaining the secure world's memory, code execution, or policy authority.

That is why the Secure Kernel should be judged neither as a magic shield nor as a mere feature flag. It is a new placement of trust. It says: the NT kernel is still trusted to run most of the machine, but no longer trusted with every secret and every final decision. The hypervisor and secure kernel are trusted more, so they must be smaller, more constrained, more carefully serviced, and easier to reason about. The history that follows is the story of Windows moving from one flat trusted kernel toward that more compartmentalized contract.

> **Chapter thesis.** **The Windows Secure Kernel (securekernel.exe) is a minimal kernel running in a hardware-isolated environment (VTL1) above the main NT kernel, enforced by the Hyper-V hypervisor.** It protects selected credentials, code-integrity decisions, and application secrets from direct VTL0 memory access even when an attacker has full control of the standard kernel. Born from the failure of software-only defenses like PatchGuard, it represents the biggest architectural shift in Windows security since the original NT reference monitor. It is not invulnerable (rollback attacks and side-channel vulnerabilities remain open problems) but it fundamentally changed what "kernel compromise" means on Windows.

## When SYSTEM isn't enough

An attacker has achieved the holy grail: SYSTEM-level access on a domain-joined Windows machine. They load Mimikatz, point it at LSASS, and reach for the domain admin's Kerberos ticket. The command runs. The output comes back empty. The credentials are there (the machine uses them every second) but they're locked behind a wall that even full kernel access cannot breach.

For decades, Windows security rested on a single hard boundary: user mode versus kernel mode. If you crossed that line (if you achieved Ring 0 execution), the system was yours. Every credential, every security policy, every secret was accessible. Tools like Benjamin Delpy's Mimikatz turned this architectural reality into a practical catastrophe, making Pass-the-Hash and Pass-the-Ticket attacks trivially easy across enterprise networks [261]; that tool lineage is the subject of the Mimikatz chapter (Chapter 14).

But on a modern Windows 11 machine with Virtualization-Based Security (VBS) enabled, the rules have changed. A new trust boundary exists. One enforced not by the kernel, but by the hypervisor running *above* the kernel. Even SYSTEM-level access in the traditional kernel cannot directly map, read, or write assets that have actually been placed behind this boundary [262].

If kernel mode gives you everything, what could possibly be *above* kernel mode? Answering that means retracing thirty years of Windows kernel security, and every same-level defense that failed before Microsoft moved the boundary.

---

## The all-or-nothing kernel: How Windows NT was built

In 1988, Dave Cutler began designing Windows NT with a security model influenced by military security research: especially the reference monitor concept, distinct from Bell-LaPadula's mandatory-access-control model. State-of-the-art for its era. It also contained a fatal assumption.

> **Definition: Security Reference Monitor (SRM).** The core component of the Windows NT security architecture that mediates all access to securable objects (files, registry keys, processes) by checking Access Control Lists (ACLs) against the caller's security token. The SRM runs in kernel mode and enforces discretionary access control for every system operation.

The NT kernel drew a hard line between Ring 3 (user mode) and Ring 0 (kernel mode) [263]. User-mode processes could not directly access kernel memory. The Security Reference Monitor mediated all access to system objects. For the early 1990s, this was a significant advance over DOS and Windows 9x, where applications and the OS shared the same memory space with no isolation at all.

> **Side note.** Dave Cutler previously designed VMS at Digital Equipment Corporation (DEC). Many NT design principles (including the SRM, the object manager, and the layered architecture) trace directly back to VMS. The letters "WNT" are famously one character ahead of "VMS" in the alphabet.

But the NT model contained a fatal assumption: **all kernel-mode code is equally trusted**. Once a driver or exploit gained Ring 0 access, it shared the same address space and privilege level as the kernel itself. It could read and write any memory, modify the System Service Dispatch Table (SSDT), manipulate the Interrupt Descriptor Table (IDT), or unlink processes from the EPROCESS active process list.

This was the golden age of kernel-mode rootkits. Jamie Butler's FU rootkit (2004) used Direct Kernel Object Manipulation (DKOM) to unlink processes from the active process list, making malicious processes invisible to Task Manager, antivirus tools, and every other system utility [264]. SSDT hooking allowed rootkits to intercept and redirect any system call, providing total control over OS behavior.

Mark Russinovich and Bryce Cogswell built the Sysinternals tools to make these kernel internals visible to defenders [265]. Process Explorer, Filemon, and Regmon became essential diagnostic instruments. But visibility is not protection. Defenders could see the problem; they could not stop it.

> **Key idea.** The NT kernel drew one hard line: user mode versus kernel mode. When attackers crossed that line, there was nothing left to protect. Every security mechanism, every credential, every policy lived in the same flat address space. Microsoft needed to draw a new line.

---

## Software guards for a hardware problem: PatchGuard and friends

What do you do when the prisoners are as powerful as the guards? You send in more guards at the same level. That was Microsoft's first strategy, and its fundamental flaw.

> **Definition: PatchGuard (Kernel Patch Protection / KPP).** A software-only kernel integrity monitor introduced in 2005 for 64-bit Windows. PatchGuard periodically checks critical kernel structures (SSDT, IDT, GDT, processor MSRs) for unauthorized modifications and forces a Blue Screen of Death (CRITICAL_STRUCTURE_CORRUPTION) if tampering is detected.

PatchGuard arrived in Windows XP x64 and Windows Server 2003 SP1 in 2005 [266]. It used obfuscated, randomized integrity checks to detect unauthorized modifications to kernel structures. If it caught tampering, it triggered a BSOD. On the surface, this seemed like a strong defense.

> **Side note.** PatchGuard's internal implementation uses extensive obfuscation: randomized check intervals, encrypted context blocks, and self-protecting code that resists static analysis. Microsoft never published its internal design, treating security through obscurity as a deliberate delaying tactic against attackers.

Mandatory kernel-mode code signing followed with Windows Vista x64 in 2007, requiring all kernel drivers to carry a valid Authenticode signature [267], the code-signing format examined in the Authenticode and Catalog Files chapter (Chapter 12). Data Execution Prevention (DEP) marked memory pages as non-executable [268]. Address Space Layout Randomization (ASLR) randomized the memory layout of loaded modules [269]. Supervisor Mode Execution Prevention (SMEP) blocked kernel code from executing user-mode memory pages [269].

Each mitigation raised the cost of attack. Together, they made kernel exploitation significantly harder. But each one had a fatal weakness.

> **Definition. Bring Your Own Vulnerable Driver (BYOVD).** An attack technique where adversaries install a legitimately signed but vulnerable third-party driver, then exploit the driver's vulnerability to gain arbitrary kernel-mode code execution. Because the driver carries a valid signature, it bypasses kernel-mode code signing enforcement.

**PatchGuard runs at Ring 0: the same privilege level as the attackers it monitors.** In 2019, the InfinityHook project demonstrated how to hook kernel callbacks via the Event Tracing for Windows (ETW) subsystem without patching any kernel structures that PatchGuard checks [270]. PatchGuard never noticed.

**Kernel-mode code signing stops unsigned drivers but not signed-and-vulnerable ones.** The BYOVD technique became a staple of advanced persistent threat (APT) groups: install a legitimately signed driver with a known vulnerability, exploit that vulnerability, and gain arbitrary kernel execution while all code signing checks pass [271].

**DEP is bypassed by Return-Oriented Programming (ROP).** Instead of injecting new code, attackers chain existing executable code snippets ("gadgets") to achieve arbitrary computation [272]. **ASLR has limited entropy** on 32-bit systems and is defeated by information leaks that reveal randomized base addresses [273].

> **The Mimikatz Effect.** Benjamin Delpy's Mimikatz (2011) industrialized extracting credentials from `lsass.exe` memory and, more than any theoretical argument, forced Microsoft to confront the fact that long-lived secrets in a flat kernel address space were indefensible. Credential Guard was the direct response [261]. The tool's full lineage and mechanics belong to the Mimikatz chapter (Chapter 14); what matters here is the architectural verdict it delivered. Same-level secrecy had failed, and the secret had to move below the kernel.
>
> PatchGuard was a guard who could be knocked out by the very prisoners it watched. A defense sharing its privilege level with arbitrary attacker-controlled kernel code cannot provide the same hard isolation guarantee as a lower, hardware-enforced boundary.
>
> **Key idea.** Same-ring software defenses cannot provide the same hard isolation guarantee against arbitrary code execution at their own privilege level. This is not a fixable PatchGuard bug. It is a structural limitation of where the check runs. PatchGuard delays attacks; it cannot be the final boundary. Microsoft needed something that kernel-mode code could not even reach.

---

## Building the foundation: Secure Boot and the Trust Chain

If you cannot trust the kernel at runtime, can you at least trust that it started clean? UEFI Secure Boot bet on that premise.

Windows 8 (October 2012) mandated Secure Boot for certified hardware, establishing a cryptographic chain of trust from firmware through bootloader to OS kernel [27]. Only components signed by trusted authorities could execute during the boot process. Measured Boot extended this by hashing each boot component into TPM Platform Configuration Registers (PCRs), creating a verifiable boot log that remote attestation services could check [10].

This was a real advance. Bootkits like TDL4/Alureon, which operated below the OS and were invisible to all software-based defenses, were effectively blocked [274]. The boot chain was now cryptographically verified.

But Secure Boot had a critical gap: it protected the boot process, not runtime. Once Windows loaded and started executing, a kernel exploit could compromise the system just as before. PatchGuard was still the only runtime defense, and we have already seen its limitations.

> **Warn: BlackLotus: When Secure Boot Itself Falls.** In 2023, ESET researchers confirmed BlackLotus: the first publicly known UEFI bootkit that bypassed Secure Boot on fully updated Windows systems. It exploited CVE-2022-21894, using a legitimately signed but vulnerable Windows boot manager to load malicious code before the OS [1]. The attack demonstrated that even boot-time trust chains can be undermined via BYOVD-style techniques applied to the boot stack itself.

Secure Boot ensured the system started clean but could not keep it clean. Microsoft needed runtime isolation, and the key technology was already sitting on millions of machines, unused for this purpose: the hypervisor.

---

## The breakthrough: Virtual Trust Levels and the Secure Kernel

The insight that changed everything was deceptively simple: if Ring 0 attackers can compromise anything at Ring 0, create a Ring -1. The hypervisor was already there.

Intel VT-x and AMD-V hardware virtualization extensions, shipping since 2005-2006, gave the hypervisor a privilege level above the OS kernel [275]. Microsoft's Hyper-V already used this capability for virtual machines. The breakthrough was recognizing that the same hardware could create a security boundary *within a single OS instance*: not a separate VM, but a hardware-isolated execution context that the kernel could not reach.

> **Definition: Virtual Trust Level (VTL).** A hardware-enforced execution environment created by the Hyper-V hypervisor using Second Level Address Translation (SLAT). VTL0 is the Normal World where the standard NT kernel, drivers, and applications run. VTL1 is the Secure World where securekernel.exe and security-critical trustlets execute. VTL1-owned memory is not directly accessible through VTL0 architectural mappings, including by the NT kernel, assuming Hyper-V, the Secure Kernel, firmware/DMA protections, and the update path hold.
>
> **Definition: Second Level Address Translation (SLAT).** A hardware feature (Intel Extended Page Tables / AMD Nested Page Tables) that provides a second layer of virtual-to-physical address translation managed by the hypervisor. SLAT enables the hypervisor to control which physical memory pages each VTL can access, denying ordinary VTL0 mappings to VTL1-owned pages without relying on NT kernel page-table enforcement.

In May 2015, Brad Anderson announced Virtualization-Based Security, Device Guard, and Credential Guard at Microsoft Ignite [276]. The initial Windows 10 release, version 1507 (July 2015), shipped with VBS, creating two Virtual Trust Levels: VTL0 (Normal World) and VTL1 (Secure World) [262].

![Figure: The VTL stack. The Hyper-V hypervisor owns SLAT at the base, and VTL1 (securekernel.exe plus the IUM trustlets lsaiso.exe and VBS enclaves) sits beside VTL0 (ntoskrnl.exe, lsass.exe, drivers, and any Ring 0 malware); SLAT denies VTL0 any mapping of VTL1 pages, so the only VTL0→VTL1 crossing is the Secure Service Call.](diagrams/05-secure-kernel-vtl-architecture.svg)

Read the VTL architecture as a stack. At the bottom is the Hyper-V hypervisor. It owns the second-level translation tables and therefore decides which guest-physical pages are visible to each trust level. Above it are two worlds. VTL0 is the ordinary Windows world: `ntoskrnl.exe`, the object manager, memory manager, file systems, network stack, display stack, third-party drivers, `lsass.exe`, services, EDR agents, malware, and every normal application. VTL1 is the secure world: `securekernel.exe` in secure kernel mode plus Isolated User Mode trustlets such as `lsaiso.exe` and, on newer systems, VBS enclave code.

A concrete walkthrough makes that topology legible. During boot, firmware and the Windows boot path establish the measured and signed launch conditions. If policy, hardware, and boot configuration allow it, the Hyper-V hypervisor starts before the normal Windows kernel and creates the Virtual Secure Mode environment. The normal kernel then boots in VTL0, but it is no longer the highest authority over all machine memory. `securekernel.exe` initializes in VTL1 and receives ownership of secure-world pages. The hypervisor programs SLAT so that VTL0 translations cannot resolve those pages, even if VTL0 later controls its own page tables perfectly. A malicious VTL0 driver can still corrupt VTL0 memory; it cannot merely add a PTE and map VTL1.

Communication is deliberately asymmetric. VTL0 initiates requests because ordinary Windows owns the user experience and the compatibility surface. VTL1 answers only through defined secure services. A request therefore has to be marshaled: VTL0 supplies handles, lengths, command identifiers, and buffers; the crossing code validates that the buffers are in the expected trust level, copies or maps only what the protocol permits, performs the secure operation, and returns a result rather than raw authority. That validation step is not plumbing. It is the new boundary. Every integer length, pointer, state transition, and object lifetime in that path is security-critical because a compromised VTL0 kernel is allowed to call the doorbell but must not be allowed to choose what lies behind the door.

Here is the lifecycle in operational order:

1. Firmware, Secure Boot, and boot configuration establish whether Hyper-V and Virtual Secure Mode are allowed to launch.
2. The Hyper-V hypervisor initializes first and becomes the owner of SLAT enforcement.
3. VTL0 starts the standard NT kernel, drivers, services, and applications.
4. VTL1 starts `securekernel.exe`, then the IUM substrate needed for trustlets.
5. The hypervisor assigns VTL1-owned pages and denies VTL0 mappings for them.
6. Secure services expose narrow operations: use a credential, validate code, produce an attestation claim, enter an enclave.
7. VTL0 receives outputs, status codes, and authentication responses, but not VTL1 memory or long-lived secrets.

That lifecycle also defines the residual attack surface. If the hypervisor misprograms SLAT, isolation fails. If `securekernel.exe` mishandles a secure call, VTL0 may become VTL1. If boot policy loads a vulnerable old secure kernel, the boundary exists but runs the wrong code. If a trustlet exposes a powerful oracle, the secret may remain hidden while the attacker still obtains useful operations. VBS is therefore not a single magic mode; it is a disciplined reduction in what a VTL0 compromise automatically buys.

> **Definition: Trustlet.** A process running in VTL1 Isolated User Mode (IUM), protected from direct VTL0 memory access by hypervisor-enforced isolation. The canonical example is `LsaIso.exe`, the Credential Guard trustlet that protects reusable NTLM secrets and Kerberos long-term key material in VTL1 where even a fully compromised NT kernel cannot directly read it.

> **Side note.** securekernel.exe is deliberately minimal. While ntoskrnl.exe is a large general-purpose kernel, securekernel.exe is a much smaller, purpose-built VTL1 kernel whose exact size varies by Windows build. A smaller codebase means a smaller attack surface: every line of code in VTL1 is a potential entry point for attackers, so Microsoft keeps it as small as possible.

Alex Ionescu's 2015 Black Hat presentation was the first major public technical teardown of the Secure Kernel Mode (SKM) and Isolated User Mode (IUM) architecture [277]. Rafal Wojtczuk (Bromium) followed in 2016 with the first independent security audit of VBS, mapping the trust boundaries and identifying the secure call interface as the primary attack surface [278].

What can an attacker with full SYSTEM access in VTL0 *not* do?

- Read credentials protected by Credential Guard
- Load unsigned kernel drivers when HVCI is enabled
- Directly map VTL1 memory or modify Secure Kernel data structures through VTL0 page tables
- Disable VBS without rebooting (and with Secure Boot + UEFI lock, not easily even then)

> For the first time, an attacker with full NT kernel compromise could not access secrets protected in VTL1. This fundamentally changed the Windows threat model.

For the first time, full NT kernel compromise was no longer game over. But what, exactly, does this new architecture protect?

---

## The pillars: What the Secure Kernel protects

The Secure Kernel is not a product. It is a platform. Five distinct security features stand on its shoulders, each protecting a different class of asset and exposing a different kind of boundary interface. A masterclass reading starts by separating those three columns: what moves into VTL1, how VTL0 is still allowed to use it, and what failure would look like.

![Figure: The Secure Kernel is the protected VTL1 foundation, not a standalone product. Credential Guard, HVCI / Memory Integrity, VBS Enclaves, System Guard Runtime Attestation, and Secured-core PCs each depend on the same architectural move: hold a secret, verdict, measurement, or platform assurance below the VTL boundary and let VTL0 use only a brokered interface, even after the normal kernel is compromised.](diagrams/05-secure-kernel-pillars.svg)

| Pillar | Asset or decision moved away from VTL0 | Interface VTL0 still gets | Primary failure mode |
|--------|----------------------------------------|----------------------------|----------------------|
| Credential Guard | Long-lived credential material and key-use operations | Authentication requests through `lsass.exe` as broker | Oracle abuse, protocol relay, incompatible domain flows |
| HVCI / Memory Integrity | Final authority over kernel-code trust and executable page state | Driver load and page-permission requests | Vulnerable signed drivers, incompatible drivers, policy not running |
| VBS Enclaves | Application secrets and selected code/data inside VTL1-backed memory | `CallEnclave` and generated EDL stubs | Bad input validation, TOCTOU, malicious or vulnerable enclave code |
| System Guard Runtime Attestation | Runtime measurement and report generation resistant to VTL0 editing | Health claims consumed by MDE/MDM/conditional access | Stale reports, suppressed telemetry, verifier policy gaps |
| Secured-core PCs | Hardware/firmware preconditions needed for the VTL promise | OEM certification and enterprise policy baseline | Misconfigured firmware, missing IOMMU/SMM protection, rollout drift |

That table matters because each pillar has a different shape. Credential Guard protects a secret but must still let Windows authenticate. HVCI protects a decision but must still let legitimate drivers load. VBS Enclaves protect application memory but must still accept untrusted host inputs. System Guard protects the integrity of a report but still depends on a verifier that understands freshness and policy. Secured-core is not a runtime service at all; it is the supply-chain and firmware baseline that makes the other services credible at fleet scale.

## Credential Guard

When Credential Guard is enabled, the important change is not that `lsass.exe` disappears. It does not. `lsass.exe` remains in VTL0 because it is still the compatibility broker for Local Security Authority APIs, Security Support Providers, logon sessions, and the huge ecosystem of Windows authentication callers. The change is that long-lived reusable credential material (especially NTLM password hashes and derived secrets, plus Kerberos TGTs and long-term key material used to obtain or renew them) is isolated in `LsaIso.exe`, a trustlet running in VTL1 Isolated User Mode [87]. `lsass.exe` keeps metadata and brokers requests; `LsaIso.exe` keeps the secrets and performs cryptographic operations. Credential Guard is the canonical instance of the placement question this chapter opened with, and it earns its own treatment in the Credential Guard chapter (Chapter 15); what matters here is *why VTL1 makes that placement possible at all*.

The mechanism is a move from secret *extraction* to secret *use*. When a network protocol needs an NTLM response, VTL0 does not receive the NTLM hash; it asks VTL1 to compute a response to a challenge. When Kerberos needs a ticket operation, VTL0 does not receive raw long-term key material; it asks the isolated component to perform the cryptographic use and return the result. The difference between *secret extraction* and *secret use* is the whole security model. Mimikatz-style dumping fails because the reusable secret is not present in VTL0 memory at all. Kernel reads, handle abuse, token theft, or arbitrary VTL0 driver code can still inspect the broker and ordinary process memory; they cannot directly map `LsaIso.exe` pages or copy the underlying credential. Credential Guard therefore changes the economics of lateral movement: the attacker may still own the workstation, but does not automatically receive domain-reusable material to replay elsewhere [261].

That gain is bounded in two ways the Secure Kernel platform makes inevitable, and both are developed in the Credential Guard chapter (Chapter 15). First, the boundary is a *broker*, not a wall: `lsass.exe` in VTL0 can still ask the trustlet allowed questions, capture a freshly typed password before it becomes protected material, or use the machine's authentication capability as an oracle: the protocol-relay residual that returns later in this chapter as Pass-the-Challenge. Second, the protected asset is *long-term* key material only; service tickets, tokens, delegated credentials, and live sessions remain VTL0 objects, and reducing their usefulness is a domain-policy and protocol problem (NTLM's challenge-response economics are the subject of the Death of NTLM chapter, Chapter 16). Credential Guard composes with, but is stronger than, Protected Process Light (Chapter 10): PPL restricts who may open `lsass.exe` from user mode, but once an attacker reaches kernel mode PPL alone is no longer a boundary, whereas the VTL1 placement still holds.

The honest one-line claim is therefore: Credential Guard protects reusable credential material from VTL0 memory extraction; it does not make a compromised endpoint trustworthy. A keylogged password, a stolen browser token, or a real-time NTLM relay is not a Credential Guard bypass. It is exactly the asset the boundary never promised to cover. The deployment caveats that follow from this belong to that chapter's rollout discussion: the domain-controller exclusion, SKU and firmware preconditions, legacy VPN / smart-card / NLA breakage, and the discipline of verifying `SecurityServicesRunning` rather than trusting a default. Even a Mimikatz-wielding attacker with SYSTEM in VTL0 gets a much poorer prize: broker state, process memory, and live sessions, but not the raw VTL1-held credential. That is the profound change from the flat-kernel era, and it is why Pass-the-Challenge appears later as a protocol-level limitation rather than a memory-isolation failure.

## HVCI / Memory Integrity

HVCI (Hypervisor-Enforced Code Integrity, surfaced to users as "Memory Integrity") is the second major consumer of the VTL1 platform: it moves the authority over *which kernel code may execute* out of the NT kernel and into VTL1 [279]. Before a kernel-mode driver's pages become executable, a VTL1 code-integrity service must accept the image, and the hypervisor enforces W^X (write-xor-execute) on kernel pages through SLAT. A page may be writable or executable, never both. This is the same trick as credential isolation, pointed at a *decision* instead of a *secret*. The attacker may control VTL0's own first-level page tables; the hypervisor controls the second-level permission that makes execution real, so flipping a kernel page to writable-and-executable is denied even with full VTL0 kernel execution. "Kernel code execution" therefore no longer implies "arbitrary kernel code," because the judge of executable memory now lives in a kernel the attacker did not compromise.

The boundary is defined by the failure HVCI does *not* prevent. A legitimately signed but vulnerable driver still grants read/write primitives in VTL0; HVCI narrows what those primitives can become (no admitted unsigned kernel image and no attacker-created executable kernel page) but it does not make the driver bug disappear. It constrains executable-code admission and page permissions; it does not stop data-only corruption, ROP/JOP reuse of already admitted code, logic abuse, or malicious behavior inside a signed driver that policy allows. That residual, the signed-vulnerable-driver problem and the block-list, CodeIntegrity-event, and driver-inventory machinery built around it, is owned by the Code Integrity chapter (Chapter 8), which also covers the MBEC/GMET hardware acceleration and the rollout discipline HVCI demands. Here the load-bearing point is purely architectural: HVCI is the proof that the VTL1 platform protects *decisions*, not only secrets.

## VBS Enclaves

> **Definition: VBS Enclave.** An isolated memory region backed by VTL1 that allows third-party applications to protect selected secrets from direct host and OS memory access. The host application in VTL0 communicates with the enclave via the `CallEnclave` API. Enclave memory is not directly mappable by VTL0 code, including the NT kernel. Microsoft documents support for Windows 11 build 26100.2314 or later and Windows Server 2025 or later [280].

VBS Enclaves are the platform's third-party generalization: the same VTL1 boundary that protects `LsaIso.exe` is opened to ordinary applications on supported Windows builds, with Microsoft-documented requirements that VBS/HVCI be enabled, the enclave DLL be signed with a valid certificate, and production builds avoid debuggable enclave policy [281][280][282]. Unlike Intel SGX they need no specialized enclave hardware beyond a VBS-capable platform [280]; they reuse Hyper-V, SLAT, VTL1, and a constrained user-mode runtime. The build mechanics belong to the VBS Trustlets chapter (Chapter 7), which owns what runs in VTL1 user mode: writing the enclave DLL, declaring the boundary in EDL (the Enclave Definition Language), building with the VBS Enclave Tooling SDK, signing through a trusted path, and entering via `CallEnclave`. What the Secure Kernel chapter must carry is the security consequence of opening that door.

The consequence is that the boundary is almost entirely *in the interface*. The host is untrusted: it controls timing, buffers, pointers, lengths, call order, and cancellation. So enclave code must treat every input as hostile: copy host buffers into enclave-owned memory before trusting them, validate lengths before arithmetic, never reuse a host pointer after a check, and guard against the time-of-check/time-of-use race where a structure is validated in host memory and then mutated before use. The safe pattern is: validate lengths and destination bounds first, copy the untrusted buffer once into enclave-owned memory (which the host has no mapping to mutate), then validate the private copy's contents and operate only on it. This is the secure-call reference-monitor problem exported to third-party code, and it is why the enclave API must stay minimal: every entry point is attack surface, and the only operations that belong inside are the ones that truly require secrecy. Decrypt this blob, sign this challenge, unwrap this token. Persistence, networking, and I/O stay in the VTL0 host, which passes data across the boundary, precisely to keep the VTL1 trusted computing base small.

That minimalism is also a warning, because VTL1 opacity cuts both ways. If an enclave signs whatever the host asks, the key is hidden but still abusable as an oracle; if an old signed enclave carries a vulnerability and policy admits it, the attacker brings their own vulnerable enclave; and because no VTL0 security product can directly inspect VTL1 memory, a malicious enclave is a hiding place as much as a vault. The BYOVE and Mirage research that weaponized exactly this is examined later in this chapter; Microsoft MORSE's hardening guidance restates old lessons in the new boundary: pointer validation, TOCTOU prevention, careful marshalling, reentrancy control, a small API, hostile-caller design [283]. The isolation is a defensive asset only when enclave admission, signing, and interface design are disciplined.

## System Guard runtime attestation

System Guard Runtime Attestation answers a different question from Credential Guard or HVCI. It does not primarily hide a secret or block a driver. It helps a relying party decide whether a device is in a trustworthy state *right now*, or at least recently enough for policy. Microsoft documents System Guard as maintaining platform integrity at startup and validating that integrity through local and remote attestation; Device Health Attestation (DHA) validates TPM/PCR logs and issues a report that MDM systems such as Intune can consume for compliance decisions [188][284][285][286]. Secure Boot and measured boot, and the remote attestation built on them (Chapter 5, Attestation), can tell a verifier what was loaded during boot. Runtime attestation tries to extend that trust into the period after the normal kernel has been running, when VTL0 malware might otherwise edit local status, forge health signals, or hide a kernel compromise [287].

The publicly documented actors are: System Guard measurements protected away from ordinary Windows tampering, TPM-protected boot evidence, the DHA client/CSP and service path, MDM or security tooling that requests or receives the report, and a relying policy engine such as Intune compliance or conditional access [188][284][285][286]. The important design point is that transport can be less trusted than measurement. VTL0 may carry data to the network, but the relying party is supposed to evaluate hardware-attested evidence rather than accept an arbitrary local string saying "healthy."

A concrete report should be understood as an attested claim set, not as a vague "the machine is healthy" bit. Microsoft documents DHA collection of boot logs, TPM audit trails, TPM certificates, report retrieval through the HealthAttestation CSP, and Intune evaluation of settings such as Secure Boot, BitLocker, and code integrity [284][285][286]. The broader verifier model is conceptual but necessary: a relying service should validate device identity, evidence integrity, expected measurements or policy version, and freshness such as a nonce, timestamp, counter, cached-report lifetime, or service-issued challenge. It should reject stale or replayed reports rather than asking only "did Windows say good?"

The workflow is therefore:

1. A management or security service requests health evidence, often as part of device compliance, endpoint-risk evaluation, or conditional access.
2. The device gathers boot/runtime security state through System Guard and DHA surfaces, including TPM-protected measured-boot evidence.
3. The report or cached attestation blob is bounded by freshness policy (for example a nonce, service request, timestamp, counter, or cache lifetime) so that an old healthy result cannot be replayed indefinitely.
4. The report is signed or otherwise tied to hardware-backed identity rooted in the TPM and device provisioning.
5. The remote verifier checks evidence integrity, freshness, device/tenant binding, expected measurements, and policy requirements.
6. Access policy consumes the result: allow, deny, require remediation, reduce trust, or trigger investigation.

Measurement scope is the hard part. System Guard can make claims about the platform features it measures and the Windows security state it knows how to evaluate. It cannot prove every byte of every driver, user process, firmware component, peripheral, browser extension, or cloud token is benign. It also cannot make an untrusted verifier wise. If the relying policy accepts "VBS configured" instead of "VBS running with Credential Guard and HVCI active," the device may satisfy a weak policy while missing the protection the organization intended. Attestation strength is jointly determined by measurement quality and verifier strictness.

A compromised VTL0 attacker still has options. They may suppress the report by blocking the network, killing the management agent, interfering with the MDE sensor, or making the device appear offline. They may attempt denial-of-service rather than forgery. They may feed false context around the signed report, such as misleading hostname, user, or asset metadata from ordinary management channels. They may exploit a verifier misconfiguration that treats missing data as success. They may attack freshness by replaying a captured report if the challenge model is weak. What VTL1-backed attestation is meant to stop is the simplest and most dangerous lie: VTL0 malware directly editing the measured runtime claims and presenting them as if the secure world produced them.

The operational lesson is to treat attestation as a protocol. A useful deployment specifies which claims are mandatory, how fresh a report must be, what happens when reports are absent, what policy version is expected, how devices are enrolled, how TPM identity is validated, and which exceptions are allowed. A report that cannot be produced should not silently become compliant. A report with stale freshness should not unlock sensitive access. A report from a device with VBS merely configured but not running should fail the policy that depends on VBS. Runtime attestation is powerful when the verifier is strict; it becomes theater when the verifier only records whatever the endpoint says. Those same signed device-health claims become an input to the cloud access decisions developed in the Zero Trust chapter (Chapter 26) and the Continuous Access Evaluation chapter (Chapter 27): this is the link by which a VTL1 measurement reaches a token-issuance decision.

## Secured-core PCs

Secured-core PCs are the hardware-and-firmware answer to a deployment problem: VBS is only as credible as the platform beneath it. A machine can have a VBS-capable CPU and still be weak because firmware settings disable virtualization, DMA protection is absent, SMM can tamper with the OS, Secure Boot is misconfigured, or policy can be turned off by a local administrator. Secured-core certification tries to make the baseline composable rather than optional [288].

Map the requirements to threats. SLAT is required because VTL isolation depends on second-level translation. TPM 2.0 is required because measured boot, key protection, and attestation need a hardware root of trust. UEFI Secure Boot is required because the hypervisor and Windows boot path must not be trivially replaced. IOMMU/DMA protection is required because a malicious PCIe/Thunderbolt device with raw DMA should not be able to overwrite memory behind the CPU's back. SMM protection is required because System Management Mode firmware can otherwise become a more privileged attacker than the hypervisor. DRTM support matters because it provides a way to establish a measured late launch even when earlier firmware is too large or complex to trust absolutely. Firmware lock and policy configuration matter because a feature that can be disabled by the attacker before reboot is not a stable enterprise control.

The practical distinction is between *capability* and *assurance*. A non-Secured-core PC may support some or all VBS features. A Secured-core PC is supposed to ship with the right CPU, firmware, TPM, DMA protections, Secure Boot configuration, and VBS/HVCI posture integrated by the OEM. That does not make it invulnerable. It reduces the number of fleet-specific questions an operator has to answer before treating VBS status as meaningful.

Major OEMs (Dell, HP, Lenovo, Microsoft Surface) ship Secured-core PCs for enterprise and government customers. For procurement, the value is not the label alone; it is the threat-to-requirement chain. If your risk model includes malicious peripherals, require IOMMU-backed DMA protection. If it includes evil-maid boot tampering, require Secure Boot, TPM-backed measurements, and firmware configuration controls. If it includes BYOVD and kernel rootkits, require HVCI running, not merely supported. If it includes remote conditional access, require runtime attestation signals that the verifier actually consumes.

VBS also enables additional isolation features beyond these core pillars. Windows Defender Application Guard (WDAG) uses Hyper-V containers to isolate untrusted browser sessions and Office documents, preventing web-based exploits from reaching the host OS. Hyper-V container isolation provides similar protection for containerized workloads. Those features are adjacent rather than identical: they isolate workloads using virtualization, while the Secure Kernel isolates selected assets and decisions inside the host OS itself.

## Decision Guide

| Scenario | Recommended approach | Preconditions | Residual risk / failure mode |
|----------|----------------------|---------------|------------------------------|
| Protect domain credentials from Pass-the-Hash/Ticket | Enable Credential Guard | VBS running, supported Windows edition, domain flows tested, DCs and apps compatible | Does not stop phishing, live token abuse, NTLM relay/oracle use, or secrets outside LSA |
| Prevent unsigned or mutable kernel code | Enable HVCI / Memory Integrity | SLAT, Secure Boot, compatible drivers, code-integrity policy, MBEC/GMET preferred | Signed vulnerable drivers and logic bugs still matter; incompatible drivers may fail |
| Protect application-level secrets from admin attacks | Develop a VBS Enclave | Windows 11 24H2+, VBS-capable hardware, signed enclave, narrow EDL/API, secure marshalling | Bad enclave APIs become oracles; BYOVE/Mirage-style abuse if admission is weak |
| Verify device integrity for zero-trust | Enable System Guard Runtime Attestation | TPM-backed identity, MDE/MDM enrollment, strict verifier policy, freshness checks | VTL0 can suppress telemetry; weak verifier policy can accept stale or incomplete reports |
| Maximum baseline security for new hardware | Require Secured-core PC certification | OEM support, firmware configuration management, enterprise policy enforcement | Certification reduces drift but does not replace runtime verification |

A few negative examples prevent misuse of the guide. Do not deploy Credential Guard to solve browser token theft; the browser token is not an LSA secret. Do not deploy HVCI and assume vulnerable signed drivers no longer matter; the driver may still expose dangerous device-control interfaces even if its code pages are not writable. Do not build a VBS enclave for a secret whose plaintext is immediately copied back into ordinary process memory. Do not rely on attestation unless the relying service rejects stale, missing, or policy-incomplete reports. Do not buy Secured-core hardware and forget to verify that the shipped firmware settings and enterprise policy keep VBS running.

The Secure Kernel now protects credentials, code integrity, application secrets, and device health. It is deployed across many Windows 11 and Windows Server systems, but default enablement depends on hardware eligibility, OEM image, Windows release, upgrade path, SKU, and which VBS-backed service is being discussed. But the protection is conditional: the right asset must move, the interface must be narrow, the platform must satisfy prerequisites, and the operator must verify runtime state. The next sections test those conditions against other platforms and against real attacks.

---

## Proof on a live machine

The Secure Kernel is intentionally hard to see from VTL0. That is the point: if an ordinary administrator, a debugger, or a kernel-mode driver could simply enumerate and map the VTL1 address space, the boundary would be decorative. A live probe can therefore prove only the supported outer shape of the system. It can show that VBS is running rather than merely configured. It can show which VBS-backed security services Windows reports as active. It can show the hardware and firmware properties available to the VBS policy. It cannot, from VTL0, dump `securekernel.exe` memory or inspect a trustlet's secrets.

That limitation is not a weakness in the evidence; it is the evidence. VBS is a boundary whose correct observation from the normal world is mostly negative: the normal world can ask for status, can call documented interfaces, and cannot directly read the secure world. The captured block below is therefore deliberately modest. It is not a claim that our lab VM proves every SKU default, every firmware configuration, or every enterprise policy. It proves the narrow thing a Reasoner should demand before reasoning about VBS on a real system: on this machine, the hypervisor-backed VBS runtime was up, and Credential Guard plus Hypervisor-Enforced Code Integrity were running services.

> 🟢 **CAPTURED**. `explab-win` · Win11 25H2 (build 26200) · 2026-06-07T05:30:49Z
> probe: `Win32_DeviceGuard` (WMI/CIM) · sha256 `c17d18ef37ab…`
> reproduce: `Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard | Format-List *`

<!--evidence file="deviceguard.txt" sha256="c17d18ef37ab6963c272fdbefaf8bd39dd22ebcdc9de606d03beade4428bde98"-->
```text
VirtualizationBasedSecurityStatus = 2  # Running
SecurityServicesConfigured        = CredentialGuard, HypervisorEnforcedCodeIntegrity
SecurityServicesRunning           = CredentialGuard, HypervisorEnforcedCodeIntegrity
AvailableSecurityProperties       = BaseVirtualizationSupport, SecureBoot, UEFICodeReadonly, ModeBasedExecutionControl
RequiredSecurityProperties        = BaseVirtualizationSupport, SecureBoot

```

Read the first field first. `VirtualizationBasedSecurityStatus = 2` is the difference between an aspiration and a runtime fact. A policy key, an Intune profile, or a dashboard setting can say that VBS should be enabled; the WMI status says whether the hypervisor-backed environment is actually running after boot. A value of `0` means the feature is not enabled. A value of `1` means enabled but not running. Only `2` supports the claims this chapter makes.

The service fields are arrays, not a single magic bit. In this capture, the configured and running sets both include Credential Guard and Hypervisor-Enforced Code Integrity (a raw `Get-CimInstance` surfaces these as the integer enum array `{1, 2}`; the capture maps them to their documented names for readability). That pairing matters because it shows two distinct consumers of the same secure-world platform: credential isolation and code-integrity enforcement. If Credential Guard were configured but absent from `SecurityServicesRunning`, an LSASS dump would have to be interpreted differently. If HVCI were configured but not running, a driver policy review would have to ask why the page-permission authority did not come up.

The property fields are the hardware join back to Part I. `BaseVirtualizationSupport` says the CPU virtualization substrate exists. `SecureBoot` says the boot chain precondition is present. `UEFICodeReadonly` and `ModeBasedExecutionControl` describe capabilities that affect the strength and cost of the VBS configuration. The capture does not prove a physical TPM, IOMMU policy, firmware lock, fleet-wide compliance, the absence of a hidden VTL0 mapping bug, the freshness of the exact `securekernel.exe` build, or the integrity of every trustlet/enclave admission policy. It gives one reliable anchor for this chapter's live evidence: a concrete machine reporting that the VTL split and its two major services are active.

The probes below are 🔵 **DOCUMENTED** rather than captured. They are included because they are the operational surfaces Microsoft documents and operators actually use, but they are not presented as lab evidence.

> 🔵 **DOCUMENTED**: Microsoft Learn, `Win32_DeviceGuard` / VBS verification fields [262][279] · not captured on our lab VM
> reproduce: `Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard | Select-Object VirtualizationBasedSecurityStatus,SecurityServicesRunning,SecurityServicesConfigured,AvailableSecurityProperties,RequiredSecurityProperties | Format-List`

```text
VirtualizationBasedSecurityStatus : 2
SecurityServicesRunning           : {1, 2}
SecurityServicesConfigured        : {1, 2}
AvailableSecurityProperties       : {...}
RequiredSecurityProperties        : {...}

Documented interpretation:
VirtualizationBasedSecurityStatus = 0  Not enabled
VirtualizationBasedSecurityStatus = 1  Enabled but not running
VirtualizationBasedSecurityStatus = 2  Running
SecurityServicesRunning includes 1      Credential Guard running
SecurityServicesRunning includes 2      Hypervisor-Enforced Code Integrity running
AvailableSecurityProperties             Hardware/firmware capabilities available to VBS
RequiredSecurityProperties              Properties required by current VBS policy

```

> 🔵 **DOCUMENTED**: Windows boot configuration surface for Hyper-V launch state [262] · not captured on our lab VM
> reproduce: `bcdedit /enum {current} | findstr /i "hypervisorlaunchtype vsmlaunchtype isolatedcontext"`

```text
hypervisorlaunchtype    Auto
vsmlaunchtype           Auto
isolatedcontext         Yes

Documented interpretation:
hypervisorlaunchtype Auto    Hyper-V hypervisor is configured to launch at boot
hypervisorlaunchtype Off     Hypervisor launch is disabled; VBS cannot run
vsmlaunchtype Auto           Virtual Secure Mode is configured to launch when policy and hardware permit
isolatedcontext Yes          Isolated user-mode context support is enabled where applicable

```

> 🔵 **DOCUMENTED**: `msinfo32.exe` System Summary VBS status lines [262][279] · not captured on our lab VM
> reproduce: `msinfo32.exe` → System Summary → search for `Virtualization-based security`

```text
Virtualization-based security                    Running
Virtualization-based security Services Configured Credential Guard, Hypervisor enforced Code Integrity
Virtualization-based security Services Running    Credential Guard, Hypervisor enforced Code Integrity

Documented interpretation:
"Running" means VBS is active, not just supported.
Configured services are policy intent.
Running services are the services currently active in the VBS secure world.

```

A Reasoner should combine these views rather than trusting any one of them alone. CIM is the best inventory surface. Boot configuration explains why VBS can or cannot launch. `msinfo32` is a human-readable local cross-check. A machine is not protected because one of those surfaces sounds encouraging; it is protected only when policy, boot state, hardware capability, and runtime status agree.

---

## How others solve this problem: Competing approaches

Windows is not alone in this challenge. Intel, AMD, ARM, and the Linux ecosystem each built answers to variants of the same problem: how do you keep a more privileged layer from reading or rewriting a less privileged layer's secrets? The important comparison is not "which one is most secure" in the abstract. It is which layer each system distrusts.

There are four broad patterns. **Intra-OS isolation** keeps one operating-system instance but splits trust inside it; Windows VBS is the major production example. **Process enclaves** protect selected application code/data from the OS; Intel SGX was the famous example and VBS Enclaves now provide a Windows-specific variant. **Confidential VMs** protect a guest VM from the cloud hypervisor; AMD SEV-SNP and Intel TDX live here, and the Confidential VMs chapter (Chapter 28) gives them the full treatment. **Firmware/TEE worlds** split the processor into secure and normal execution states; ARM TrustZone dominates mobile and embedded devices. Linux combines MAC, namespaces, containers, confidential VMs, and Android/ChromeOS pKVM work, but mainline desktop/server Linux does not have a direct VTL0/VTL1 equivalent.

## Intel SGX

Intel Software Guard Extensions provided hardware enclaves at the CPU level without requiring a hypervisor [289]. Application code and data inside an SGX enclave lived in the Enclave Page Cache (EPC), a protected memory region whose contents were encrypted and integrity-protected by processor machinery when leaving the package. The OS still scheduled threads and managed ordinary resources, but it was not supposed to read enclave plaintext or forge enclave execution. The developer's trust anchor moved from Windows or Linux to the CPU package and Intel's attestation ecosystem.

The SGX lifecycle illustrates the contrast with VBS. An application creates an enclave, loads measured pages, initializes it, and then enters enclave code through controlled transitions. Remote attestation lets a relying party verify the enclave measurement before provisioning a secret. That is a very different question from Credential Guard. SGX asks: "Can this small measured application component keep a secret from the OS?" VBS asks: "Can Windows keep selected OS secrets and decisions from a compromised normal kernel?" SGX's isolation is finer-grained; VBS's integration with the OS security model is deeper.

SGX also taught the industry a hard lesson about microarchitectural leakage. The enclave boundary stopped architectural reads, but it did not stop all information flow through caches, speculative execution, page faults, branch predictors, or timing. Foreshadow/L1TF in 2018 exploited CPU behavior to extract data from SGX enclaves [290]. Other SGX research showed that a malicious OS could influence scheduling, page faults, and observation channels around the enclave. Intel later deprecated SGX across many client CPUs, including 11th Gen client parts, and continued away from the client-SGX model in later generations [291].

The lesson for VBS is not "SGX failed, VBS wins." The lesson is that every isolation design inherits the side-channel properties of the hardware it shares. VBS uses a different trust anchor and a different product model, but VTL0 and VTL1 still share cores, caches, predictors, and memory controllers. SGX is therefore a warning label for all enclave-like designs: architectural memory isolation is necessary and still incomplete.

## AMD SEV-SNP

AMD Secure Encrypted Virtualization with Secure Nested Paging (SEV-SNP) encrypts VM memory with per-VM keys and enforces page ownership via a Reverse Map Table (RMP): a hardware table that records which VM owns each physical page [292]. Earlier SEV protected confidentiality, SEV-ES encrypted register state on VM exits, and SEV-SNP added stronger integrity and page-ownership protections. The hypervisor can still schedule the VM, deliver virtual interrupts, and provide emulated devices, but it is not supposed to read guest memory plaintext or remap arbitrary host pages into the guest without detection.

The RMP is the conceptual mirror of VBS's SLAT story. In VBS, Hyper-V is trusted to use SLAT to isolate VTL1 from VTL0. In SEV-SNP, the guest uses CPU-enforced metadata to distrust the hypervisor that controls nested page tables. Page-state transitions require explicit ownership changes and validation. Attestation lets a remote relying party verify that the VM is running as a confidential guest on genuine SNP hardware with expected measurements before provisioning secrets.

SEV-SNP is therefore ideal for multi-tenant cloud confidentiality: protect a customer's VM from a malicious or compromised cloud host. It does not solve the Credential Guard problem inside the guest. If Windows inside an SNP-protected VM runs without Credential Guard and an attacker compromises the Windows kernel, SNP will faithfully protect that compromised guest from the cloud provider while the attacker dumps ordinary guest memory from inside. Conversely, VBS does not protect a VM from a malicious hypervisor unless the hypervisor is the trusted Hyper-V layer enforcing VBS. The two technologies answer different attacker positions and can be stacked.

## Intel TDX

Intel Trust Domain Extensions create hardware-isolated Trust Domains for VMs, excluding the host VMM from the guest's trusted computing base [293]. The TDX Module runs in Secure Arbitration Mode (SEAM) and mediates the sensitive operations that would otherwise be controlled entirely by the hypervisor: memory assignment, guest state protection, and transitions between the host VMM and the Trust Domain. Like SEV-SNP, the cloud host can schedule and manage resources but should not be able to inspect TD private memory.

TDX's lifecycle resembles SNP at the security-goal level: build a measured confidential VM, protect its private memory from the host, and use attestation before secrets are released. Its implementation details differ: Intel's TDX module and SEAM architecture play a role analogous to an on-platform security monitor for Trust Domains. The measurement and attestation flow gives a relying party evidence about the TD's initial state and platform security properties.

The VBS contrast is again the trust direction. TDX removes the hypervisor from the VM's TCB as much as possible; VBS adds Hyper-V to the host OS's TCB so it can protect VTL1 from VTL0. TDX is a cloud tenant's answer to "can the host read my VM?" VBS is a Windows endpoint's answer to "can my compromised kernel read this credential or load this code?" A Windows VM can use both: TDX or SEV-SNP to protect the VM from the cloud host, and VBS inside the guest to protect selected Windows assets from the guest's own VTL0 kernel.

## ARM TrustZone

ARM TrustZone partitions the CPU into a Secure World and a Normal World using a hardware security state bit, predating VBS by a decade (2004 vs. 2015) [294]. World transitions happen through a Secure Monitor Call (SMC) instruction, handled by firmware or a trusted OS like OP-TEE. The concept is similar to VBS (two execution worlds with hardware isolation) but the mechanism differs. TrustZone does not put a general-purpose hypervisor in this particular path, but that does not automatically make the deployed TCB small: real systems often include a secure monitor, TEE OS, firmware services, vendor applets, and device-specific drivers. It is less flexible in the VBS sense because it typically supports only two worlds with coarser granularity. TrustZone dominates mobile and embedded devices; Windows on ARM still uses the hypervisor-based VBS model for VTL0/VTL1 separation, the same architecture as VBS on x64.

> **Side note.** ARM TrustZone predates VBS by over a decade. The concept of hardware-enforced dual execution worlds was well established in the mobile/embedded world long before Microsoft applied the idea to desktop Windows. The insight was not the dual-world concept itself, but using the x86 hypervisor to implement it.

## Linux

No production equivalent of Windows VBS exists in mainline Linux in the narrow sense of a general-purpose, hypervisor-enforced, in-host secure kernel that protects selected OS assets from a compromised Linux kernel. Linux has many strong security mechanisms, but most operate either at the same kernel trust level or at VM granularity.

SELinux and AppArmor are Linux Security Module (LSM) systems. They can enforce mandatory access-control policy over files, sockets, capabilities, process transitions, and other kernel-mediated objects. They are extremely valuable, especially when policy is tight. But the LSM hook runs inside the Linux kernel. If the attacker owns arbitrary kernel execution, they can generally tamper with the policy decision path, patch hooks, alter credentials, or disable enforcement unless some lower-level mechanism protects the kernel itself. That is the same-level-enforcement problem that pushed Windows beyond PatchGuard.

Namespaces, cgroups, seccomp, Landlock, and containers isolate processes and reduce the ambient authority available to workloads. They are essential for server hardening and multi-tenant application isolation, but they rely on the host kernel as the reference monitor. A container escape or kernel exploit collapses the boundary because the host kernel is the thing all containers share. Containers are therefore not analogous to VTL1; they are VTL0 compartments enforced by a trusted VTL0 kernel.

Linux does use hardware isolation for confidential computing through KVM guests protected by AMD SEV-SNP or Intel TDX. That protects guest VMs from a potentially hostile host/hypervisor, which is the opposite direction from VBS. It is excellent for cloud tenants but does not create an in-kernel secure world for the host OS's own credentials. Linux also has measured boot, IMA/EVM, TPM-backed sealing, dm-verity, lockdown mode, Secure Boot integration, and eBPF hardening, but those mechanisms either measure, restrict, or harden the kernel rather than making a second trust level that the compromised kernel cannot map.

The closest production relatives are in Android and ChromeOS rather than generic mainline server Linux. Google's protected KVM (pKVM) work uses the hypervisor to isolate protected VMs from the host kernel. That is similar in spirit to using a lower layer to distrust a large OS kernel, but its object of protection is a protected VM, not a Windows-style VTL1 secure kernel hosting OS trustlets inside one host instance. Research systems have explored intra-OS privilege separation, micro-hypervisors, isolated drivers, and compartmentalized kernels, but none has become the default mainline Linux equivalent of Credential Guard plus HVCI plus System Guard.

The philosophical difference is important. Linux tends to layer many mechanisms: MAC policy, least-privilege services, namespaces, seccomp, immutable images, measured boot, confidential VMs, and rapid kernel hardening. Windows VBS is a more centralized architectural split inside the OS. Neither philosophy eliminates the need for the other kind of defense. A VBS-protected Windows machine still needs application sandboxing and policy; a hardened Linux system can still benefit from lower-level isolation when the attacker reaches the kernel.

## Cross-Platform Comparison

![Figure: VBS sits among TEEs as a software-rooted, hypervisor-enforced split inside one Windows instance. SGX protects measured application enclaves from the host OS, SEV-SNP and TDX protect whole guest VMs from the cloud host, TrustZone separates secure and normal worlds, and Linux usually layers MAC, containers, measured boot, and confidential VMs rather than a general VTL0/VTL1 secure-kernel equivalent.](diagrams/05-secure-kernel-tee-comparison.svg)

| Dimension | Windows VBS | Intel SGX | AMD SEV-SNP | Intel TDX | ARM TrustZone |
|-----------|-------------|-----------|-------------|-----------|---------------|
| Isolation granularity | OS-level (VTL split) | Process-level enclaves | VM-level | VM-level | 2 worlds |
| Trusts the hypervisor? | Yes | Tries to distrust OS/VMM for enclave confidentiality; trusts CPU/package and attestation | No | No | N/A; trusts secure monitor/TEE stack |
| Memory encryption | No (isolation only) | Yes | Yes (full VM) | Yes (full VM) | Varies |
| Primary use case | Desktop/server OS | Legacy high-assurance | Cloud confidential VMs | Cloud confidential VMs | Mobile/IoT |
| Status (2025) | Active, expanding | Deprecated on consumer | GA on major clouds | Rolling out | Widely deployed |
| Known weakness | Rollback, side-channels | Foreshadow, deprecated | Physical attacks | Early deployment | Firmware attacks |

Every platform bets on a different trust anchor and TCB. VBS trusts Hyper-V and the Secure Kernel. SEV-SNP and TDX try to remove the cloud hypervisor from the guest-confidentiality TCB while still trusting CPU firmware/microcode and attestation infrastructure. SGX tried to distrust the OS/VMM for enclave plaintext while trusting the CPU package and Intel's attestation ecosystem: until side-channel attacks showed how much shared microarchitecture still mattered. The uncomfortable question follows: what *cannot* VBS protect against?

---

## The limits: What VBS cannot protect against

Every security boundary has an edge. VBS's edge is more nuanced than most defenders realize because the normal Windows world remains powerful by design. VTL0 still controls the user's desktop, network stack, local files, most device drivers, most sensors, most logs, and most applications. VBS protects selected VTL1 assets from direct VTL0 access; it does not make VTL0 honest.

The useful taxonomy is fivefold:

1. **Boundary implementation bugs.** A flaw in Hyper-V, `securekernel.exe`, IUM, or a secure-call parser can turn VTL0 control into VTL1 control. The hypervisor's own architecture and attack surface are the subject of the Above Ring Zero chapter (Chapter 9); here it is simply the layer VBS trusts to enforce the split.
2. **Oracle and protocol abuse.** A secret may stay hidden while the attacker asks the secure component to perform useful operations with it.
3. **Shared-hardware leakage.** VTL0 and VTL1 share physical microarchitectural state, creating potential side channels.
4. **Trust-version attacks.** Rollback can make the machine run an old vulnerable boundary while reporting a misleadingly current state.
5. **Out-of-scope attackers.** Firmware, physical access, malicious peripherals, and weak verifier policies can sit outside the guarantee VBS was designed to provide.

Those limits do not make VBS weak. They make its guarantee precise.

## Attacking the Secure Kernel directly

In August 2020, Saar Amar and Daniel King of Microsoft's own MSRC stood on the Black Hat stage and demonstrated something the community had feared: direct exploitation of securekernel.exe itself [295]. Using a custom fuzzer called Hyperseed, they found the first five vulnerabilities in the secure call interface within two weeks; combined with continued manual auditing, they ultimately disclosed ten vulnerabilities [296]. Memory corruption bugs in pool management and interface validation allowed VTL0 code to achieve code execution inside VTL1: breaking the isolation entirely.

All vulnerabilities were patched before disclosure. Microsoft has since added mitigations: improved KASLR, Control Flow Guard (CFG) in VTL1, and stricter input validation. But the attack proved that VTL1 is not invulnerable. The secure call interface is a real attack surface, and any bug there defeats all VBS guarantees.

## Pass-the-challenge: The protocol-level bypass

Oliver Lyak's "Pass-the-Challenge" research is the canonical instance of limit #2 above: oracle and protocol abuse [297]. Credential Guard prevents credential *extraction* but cannot prevent credential *use*: an attacker with SYSTEM access can relay NTLM authentication challenges through lsaiso.exe, using the machine as an "NTLM oracle." The raw hash never leaves VTL1, but the attacker can still ask the secure world to sign challenges on demand. The Credential Guard chapter (Chapter 15) treats this bypass as one of its central adversaries, and the challenge-response mechanics it abuses belong to the Death of NTLM chapter (Chapter 16); what matters *here* is the architectural shape, not the protocol detail.

> **Insight: The NTLM Oracle Problem.** Credential Guard perfectly isolates secrets in VTL1, but the VTL0 broker (lsass.exe) necessarily provides an interface for using those secrets. Pass-the-Challenge exploits that interface: not to extract secrets, but to relay them. This is a fundamental design tension: the more useful the isolation boundary, the more attack surface the boundary's API exposes.

## Side-Channel Attacks

VBS's architectural boundary is a memory-permission boundary: VTL0 cannot ask the MMU to read VTL1 pages because Hyper-V's second-level permissions deny the mapping. Side channels ask a different question: can VTL0 infer something about VTL1 by measuring shared hardware state that is not modeled as an ordinary memory read?

The VBS-specific leakage model has three ingredients. First, attacker code runs in VTL0, potentially with kernel privileges, so it can schedule carefully, allocate memory, pin threads, read high-resolution timers where available, and create cache or predictor pressure. Second, victim code runs in VTL1, for example `securekernel.exe`, `LsaIso.exe`, an attestation trustlet, or a VBS enclave. Third, both worlds share physical resources: cores, private and shared caches, TLBs, branch predictors, store buffers, memory controllers, and sometimes simultaneous multithreading siblings. Hyper-V can deny architectural access to VTL1 pages, but it cannot magically give the secure world a separate CPU on commodity hardware.

Different channels have different relevance. Cache timing attacks such as Prime+Probe or Flush+Reload-style patterns can reveal access-dependent behavior if the attacker can create a useful shared or congruent cache observation. Branch-predictor and speculative-execution attacks can mistrain or observe predictor state across protection domains unless mitigations partition or flush state. TLB and page-walk effects can leak coarse access patterns. SMT can make sibling threads contend for execution resources. Power, thermal, and memory-bus contention can leak even coarser signals. Meltdown-class attacks exploited transient permission bypasses; Spectre-class attacks mistrained speculative execution so victim code transiently touched data-dependent state [298]. The exact exploitability depends on CPU generation, microcode, Windows configuration, timers, scheduling, and the victim code's data-dependent behavior.

Windows and CPU vendors mitigate rather than abolish these channels. IBRS, STIBP, retpolines, and related microcode/software changes reduce branch-target injection and speculative cross-domain leakage [299]. Kernel VA isolation and Meltdown mitigations reduce transient reads across privilege boundaries. Hypervisors can flush or partition selected state on VM or VTL transitions, restrict high-resolution timers, avoid scheduling mutually distrusting contexts on SMT siblings in high-security configurations, and use constant-time coding patterns for cryptographic code. HVCI and VBS also indirectly help by making it harder for arbitrary unsigned kernel implants to install the most convenient measurement machinery, but a signed vulnerable driver or kernel exploit may still give the attacker strong VTL0 observation capabilities.

The residual risk is not "Spectre breaks VBS" as a blanket claim. It is narrower and more annoying: VBS does not by itself guarantee that no information about VTL1 computation leaks through shared microarchitecture. Turning leakage into a useful attack usually requires attacker code running locally, repeated measurements, a victim operation whose secret affects timing or access patterns, enough scheduling control, and a CPU/mitigation configuration that leaves a channel open. Extracting a whole credential from `LsaIso.exe` is much harder than observing that some secure operation occurred; leaking a bit from a poorly written enclave may be easier than leaking a hardened Windows trustlet.

A masterclass boundary statement is therefore: VBS blocks direct architectural reads and writes from VTL0 to VTL1. It does not create physically separate hardware. Side-channel resistance depends on CPU design, microcode, Hyper-V transition behavior, Windows mitigations, SMT policy, timer availability, and constant-time secure-world code. Complete elimination would require hardware that partitions or duplicates all relevant microarchitectural state across trust levels, or schedules them in a way that removes contention. Commodity systems approximate that ideal; they do not reach it.

## The formal verification gap

> **The Formal Verification Dream.** The seL4 microkernel is formally verified: mathematically proven correct for approximately 8,700 lines of C code [300]. This means its isolation guarantees are not empirical ("we tested it and found no bugs") but mathematical ("we proved it cannot have certain classes of bugs"). Hyper-V is orders of magnitude larger and more complex. Formally verifying it with current techniques is infeasible. The gap between "extensively tested" and "mathematically proven" is significant: Hyper-V's isolation is empirically strong, not provably correct.

For VBS, the proof obligations are concrete. A proof would need to show that SLAT ownership and permission updates never expose VTL1 pages to VTL0; that VTL transitions save, restore, and sanitize state correctly; that secure-call dispatch validates all VTL0-controlled buffers, lengths, handles, and object lifetimes; that interrupts, exceptions, and scheduling cannot confuse the trust level; that DMA is either blocked or mediated by the IOMMU; that device assignment does not create aliases into secure memory; that update and boot policy cannot substitute vulnerable trusted components; and that the implementation matches the model on every supported CPU generation.

Even that list leaves out the hard real-world pieces: microcode behavior, SMM, ACPI/firmware interfaces, power management, nested virtualization, crash dump paths, debugging features, hibernation, live update behavior, and third-party drivers interacting with DMA. seL4's achievement is extraordinary precisely because it narrowed the kernel and the model enough for proof. Hyper-V plus VBS is a living commercial platform with compatibility obligations. The plausible near-term path is therefore partial verification or high-assurance review of the smallest critical mechanisms: page-ownership state machines, VTL transition code, secure-call marshalling libraries, and policy parsing. That would not prove all of Windows secure, but it would shrink the empirical gap around the parts that matter most.

## Microsoft's own boundary

Microsoft explicitly states in its Security Servicing Criteria that an administrator with physical access is *not* a security boundary [301]. VBS defends against remote kernel exploitation and privilege escalation, but not against an administrator who can modify firmware, attach hardware debuggers, or perform DMA or evil-maid-style physical attacks; Microsoft's VBS guidance separately calls out IOMMU-backed DMA protection as a distinct hardware requirement [262].

> **Margin note.** This boundary declaration helps explain Microsoft's servicing posture for CVE-2024-21302 (Windows Downdate), whose documented attack path requires administrator privileges. Microsoft shipped default boot-session protections and a separately deployable `SkuSiPolicy.p7b` revocation policy, but the UEFI-locked rollback mitigation remains an administrator rollout because it carries recovery and boot-compatibility risk [302][301].

VBS is the strongest runtime isolation Windows has ever had. But it is empirically strong, not mathematically proven. And one attack discovered in 2024 threatened to undo it entirely.

---

## The arms race: Rollback attacks and the ongoing Battle

In August 2024, Alon Leviev of SafeBreach Labs stood on the Black Hat stage and demonstrated something terrifying: he could silently roll back a "fully patched" Windows system to a state where all VBS protections were vulnerable: using Windows Update itself.

> I found several vulnerabilities that let me develop Windows Downdate: a tool to take over the Windows Update process to craft fully undetectable downgrades.: Alon Leviev, SafeBreach Labs

The Windows Downdate attack (CVE-2024-21302) works by hijacking the Windows Update mechanism to replace current versions of securekernel.exe, ci.dll, and other VBS components with older, vulnerable versions [303]. The system continues to report itself as "fully patched" while running code with known, exploitable vulnerabilities [304]. The attack requires administrator privileges: which, as we noted, Microsoft does not consider a security boundary.

The rollback attack is best understood as a versioned-trust failure. Step one: an administrator-level attacker in VTL0 gains enough control over the Windows Update path to stage a downgrade instead of an upgrade. Step two: the attacker substitutes older versions of VBS-sensitive components such as `securekernel.exe` and `ci.dll`, along with catalog/policy state that lets the downgrade survive normal servicing checks. Step three: the system reboots. Secure Boot may still verify that the binaries are signed, because the problem is not an unsigned bootkit; the problem is a signed but obsolete component. Step four: inventory and user-facing update status can still look current enough to mislead operators, while the code enforcing the VBS boundary is now a version with known vulnerabilities.

This is the same structural lesson as BYOVD, applied to the trusted computing base itself. A signature proves origin and integrity; it does not prove freshness. VBS depends on the secure world running code that includes the latest boundary fixes. If an attacker can force the machine to run an older trusted binary, the hypervisor and Secure Kernel may faithfully enforce an obsolete policy with obsolete bugs.

> **Side note.** As established above, rollback is the chapter's canonical versioned-trust failure: the dangerous part is not that an unsigned binary loads, but that a signed obsolete boundary component can be made current enough to fool weak checks. KB5042562's stronger UEFI-locked policy is therefore a rollout decision, not a mere patch Tuesday toggle [302].

Microsoft responded with KB5042562, publishing a SkuSiPolicy.p7b revocation policy to block loading of outdated VBS-related binaries [302]. A UEFI variable lock reduces the risk of firmware-level rollback, though Leviev's research demonstrated it can be bypassed through Windows Update manipulation without physical access [305]. But deployment is opt-in and complex: applying it incorrectly can cause boot failures. And the underlying mechanism (admin-level control over the update process) remains exploitable [305].

The weaponization of VBS itself followed shortly. At DEF CON 33 in August 2025, Akamai researchers demonstrated "BYOVE" (Bring Your Own Vulnerable Enclave) and "Mirage": techniques for running malware inside a VBS enclave, hidden from EDR and antimalware tools that cannot inspect VTL1 memory [306]. The very isolation that protects legitimate secrets can also protect malicious code.

> **Warn: VBS Enclave Weaponization.** The same VTL1 isolation that makes VBS enclaves secure for legitimate applications makes their private memory opaque to ordinary VTL0 inspection. An attacker who can load a legitimately signed but vulnerable enclave DLL gains a hiding place that no VTL0 security product can directly inspect. Microsoft is actively hardening the enclave trust boundary [283], but the fundamental tension between isolation and visibility persists.

The pattern is clear: VBS raises the cost of attack, attackers find creative bypasses, Microsoft hardens further. The question is no longer "is VBS breakable?" but "where does the research go next?"

---

## Open questions: Where research is heading

The Secure Kernel is mature but not finished. Five open problems define the next decade of research.

**Complete rollback prevention.** KB5042562 is a start, but complete protection may require hardware-enforced monotonic version counters (similar to ARM's anti-rollback fuse bits) integrated into platform firmware [302]. Without hardware support, the administrator-who-controls-updates problem remains fundamentally unsolved.

**Secure Kernel vulnerability discovery.** Jonathan Jagt's 2025 MSc thesis at Radboud University documented the process of setting up a Secure Kernel debugging environment and analyzed patched security bugs to identify vulnerability patterns [307]. A key finding: the tooling for VTL1 research is scarce. Building a VTL1 debugging environment requires VMware-specific configurations and custom modifications that most researchers do not have access to. Better tooling would accelerate both offensive and defensive research.

**VBS Enclave security model.** The tension between protecting legitimate secrets and preventing malware evasion has no clean solution. Microsoft's hardening guidance addresses developer mistakes (TOCTOU races, pointer validation, reentrancy risks) [283], but the architectural problem (that VTL1 isolation is equally useful to attackers and defenders) requires a new approach to enclave attestation and monitoring.

**Formal verification.** Can we ever prove Hyper-V correct? The seL4 proof covers approximately 8,700 lines of C [300]. Hyper-V is hundreds of thousands of lines. Current verification technology cannot scale to that size. Partial verification of critical subsystems (the SLAT enforcement logic, the secure call dispatcher) might be feasible and would meaningfully reduce the trusted computing base.

**Side-channel elimination.** Requires fundamentally different CPU designs. Current mitigations (microcode patches, partitioned caches, branch prediction barriers) reduce the leakage rate but cannot close the channel entirely while VTL0 and VTL1 share physical hardware [298]. Some academic designs propose physically separate execution units for different trust levels, but these are years from production.

> **Tip: The Ideal Solution (And Why We Don't Have It).** The theoretically perfect system would combine: a formally verified hypervisor, hardware with no shared microarchitectural state between trust levels, a complete binary revocation mechanism preventing all rollback attacks, and zero performance overhead. Each requirement is individually infeasible today. The Secure Kernel is the best available approximation.

The Windows Secure Kernel is the most significant architectural change to Windows security since the NT reference monitor. It does not make Windows invulnerable. No technology does. But it changed what "kernel compromise" means.

The timeline is cumulative: NT began with flat kernel trust in 1993; PatchGuard, driver signing, DEP, ASLR, and SMEP hardened that world from 2005 onward; Secure Boot and measured boot protected the boot path beginning with Windows 8; VBS, Credential Guard, HVCI, System Guard, Secured-core PCs, and VBS enclaves then added hypervisor-enforced runtime isolation from 2015 through Windows 11 24H2.

Modern Windows runs all three generations simultaneously: PatchGuard still watches for kernel tampering, Secure Boot still verifies the boot chain, and VBS adds hardware-enforced isolation on top. Newer defenses supplement rather than replace earlier ones.

---

## What it means for you

Theory is valuable; practice pays the bills. The operator's task is to turn the VBS model into a repeatable control: choose the threat, verify the hardware, enable the right services, confirm they are actually running, watch for compatibility failures, and keep the trusted components from rolling back. Treat VBS as a fleet lifecycle, not a checkbox.

A practical threat-model checklist starts with four questions. Are you trying to prevent credential extraction after endpoint compromise? Prioritize Credential Guard and NTLM reduction. Are you trying to stop kernel code injection and unsigned drivers? Prioritize HVCI and vulnerable-driver blocking. Are you trying to protect application secrets from local administrators? Use VBS Enclaves only after designing a narrow enclave API. Are you trying to make conditional access depend on device health? Pair System Guard attestation with strict verifier policy. The answer may be "all of them," but rollout order and validation differ.

## Hardware Requirements

VBS requires a 64-bit CPU with hardware virtualization (Intel VT-x or AMD-V), Second Level Address Translation (Intel EPT or AMD NPT), TPM 2.0, and UEFI firmware with Secure Boot [262]. Those are baseline requirements, not equal-strength assurances. If virtualization is disabled in firmware, the hypervisor cannot launch. If SLAT is missing, the VTL memory model cannot be enforced. If Secure Boot is off, boot-chain assumptions weaken. If TPM 2.0 is absent or not provisioned, measured boot, key protection, and attestation are less useful. If IOMMU/DMA protection is absent, malicious external devices may sit outside the CPU page-permission model.

Separate launch requirements from assurance requirements:

| Feature or assurance level | Minimum / documented prerequisite | What it proves |
|---|---|---|
| VBS launch | 64-bit virtualization extensions, SLAT, firmware support, Secure Boot configured by policy [262] | Hyper-V can create the VTL split |
| Credential Guard | VBS running, supported Windows edition, compatible domain and application flows [87] | Reusable LSA credential material can move behind `LsaIso.exe` |
| HVCI / Memory Integrity | VBS, compatible drivers, code-integrity policy; MBEC/GMET preferred for performance [279] | Kernel code-integrity decisions and executable-page permissions move into the secure runtime |
| VBS Enclaves | Windows 11 build 26100.2314+ or Windows Server 2025+, VBS/HVCI enabled, signed enclave DLL [280][282] | Application enclave memory can be isolated from the host process and normal OS |
| System Guard / DHA attestation | TPM-backed measured boot evidence, DHA/CSP/MDM integration, strict verifier policy [188][284][285][286] | Remote policy can evaluate hardware-attested security state |
| Secured-core assurance | OEM-integrated TPM, Secure Boot, virtualization, DMA/IOMMU, SMM protections, firmware configuration management [288][188] | Procurement baseline reduces firmware and rollout drift, but still needs runtime verification |

For HVCI performance, CPU generation matters. Intel Mode-Based Execution Control (MBEC, Kaby Lake / 7th Gen+) and AMD Guest Mode Execute Trap (GMET, Zen 2+) provide hardware support that reduces the overhead of execute permission enforcement [279]. Older systems can emulate aspects of the policy through Restricted User Mode, but the performance and compatibility cost is higher. That cost is often acceptable for high-risk endpoints and often invisible in ordinary office workloads, but it can matter for gaming, low-latency workloads, virtualization-heavy developer machines, and old driver stacks.

Verification should be property-by-property. `Win32_DeviceGuard` exposes `AvailableSecurityProperties` and `RequiredSecurityProperties`, which tell you what the platform offers and what policy requires. `msinfo32.exe` gives a human-readable view of VBS status and services. Firmware setup or vendor management tools confirm whether virtualization, Secure Boot, TPM, and DMA protections are enabled. MDM inventory should record both capability and runtime state. A machine that is "VBS capable" but reports `VirtualizationBasedSecurityStatus = 1` is not equivalent to one reporting `2`.

## Enabling VBS

VBS can be enabled through:

- **Group Policy:** Computer Configuration > Administrative Templates > System > Device Guard > Turn On Virtualization Based Security
- **Intune/MDM:** DeviceGuard CSP or endpoint security policies
- **Registry:** `HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\EnableVirtualizationBasedSecurity = 1`
- **Windows Security UI:** Device Security > Core Isolation > Memory Integrity for HVCI on individual machines

In managed fleets, policy precedence matters. MDM and Group Policy can both write Device Guard-related settings; local UI state may not represent the final enforced policy after the next sync. Registry keys show intent, not always effective runtime state. Boot configuration such as `hypervisorlaunchtype` and `vsmlaunchtype` determines whether the hypervisor and Virtual Secure Mode can launch. Most changes require a reboot because the hypervisor, VTL creation, and secure-world services initialize during boot.

UEFI lock changes the administrative semantics. When VBS is configured with a UEFI lock, disabling it is no longer just a registry edit from Windows; firmware variables participate so that turning it off generally requires physical presence or firmware-level action. That is valuable against remote attackers with admin rights, but it raises the operational stakes. A bad policy pushed with lock enabled can strand devices in an undesired state until hands-on remediation. Pilot rings and recovery instructions are mandatory.

HVCI deserves its own rollout track. Before broad enablement, inventory kernel drivers, update OEM firmware and driver packages, enable Microsoft's recommended vulnerable-driver block rules where appropriate, and monitor CodeIntegrity events for blocked images [271]. A blocked driver can mean the control is working, but if that driver is storage, networking, VPN, anticheat, EDR, smart-card, or industrial-control software, the business impact may be immediate. The right sequence is: audit, pilot, remediate drivers, enable, verify running state, then enforce.

Concrete negative examples:

- Setting the registry key but leaving firmware virtualization disabled yields policy intent without a running VTL split.
- Enabling HVCI on a fleet with old unsigned or W+X-assuming drivers can produce boot or device failures.
- Assuming Windows 11 defaults guarantee Credential Guard on every endpoint ignores domain role, SKU, hardware, and upgrade history.
- Treating `SecurityServicesConfigured` as success misses machines where services are configured but not running.
- Deploying rollback protection without reading KB5042562's prerequisites can create recovery problems if old boot components are still needed.

HVCI/Memory Integrity can be enabled separately via Windows Security > Device Security > Core Isolation > Memory Integrity, but enterprise posture should be enforced through policy and verified through telemetry rather than left as a per-user toggle.

## Verifying VBS status

```powershell
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root/Microsoft/Windows/DeviceGuard |
  Select-Object VirtualizationBasedSecurityStatus,
                RequiredSecurityProperties,
                AvailableSecurityProperties,
                SecurityServicesConfigured,
                SecurityServicesRunning |
  Format-List

```

Expected interpretation: `VirtualizationBasedSecurityStatus` is `0` when VBS is not enabled, `1` when enabled but not running, and `2` when running. `SecurityServicesConfigured` and `SecurityServicesRunning` are arrays; common values are `1` for Credential Guard and `2` for HVCI / Memory Integrity.

You can also verify VBS status via:

- **msinfo32.exe:** Look for "Virtualization-based security" in the System Summary
- **Windows Security app:** Device Security > Core Isolation details

> **Troubleshooting common VBS issues.**
> **Driver compatibility:** Some older drivers violate W^X policy and fail to load with HVCI enabled. Check the Windows Event Log (CodeIntegrity events) for blocked drivers. Microsoft's Hardware Lab Kit (HLK) provides HVCI compatibility testing.
>
> **Performance impact:** Public gaming and CPU-bound benchmarks have measured VBS/HVCI overhead in the rough 5-10% range on some configurations [308]. Treat that as an example, not a universal tax: modern CPUs with MBEC/GMET lower the cost, and business workloads often measure differently.
>
> **Credential Guard and NLA:** Because Credential Guard blocks NTLM and the delegation of derived or saved credentials, RDP and Network Level Authentication flows that fall back to NTLM or rely on saved credentials can fail; prefer Kerberos and test interactive-logon and CredSSP-dependent workflows before broad rollout.
>
> **Cannot enable VBS:** Verify that virtualization is enabled in BIOS/UEFI settings, Secure Boot is on, and TPM 2.0 is present and enabled. Some older systems lack SLAT support.
>
> **Tip: Quick Verification Checklist.** 1. Open msinfo32.exe and confirm "Virtualization-based security: Running"
> 2. Check that "Credential Guard" and "Hypervisor enforced Code Integrity" appear under running services
> 3. Run `Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root/Microsoft/Windows/DeviceGuard` in PowerShell for detailed status
> 4. Verify Secure Boot is enabled and TPM 2.0 is present

The Secure Kernel changed the fundamental question of Windows security. From "can we keep attackers out of the kernel?" to "what can we still protect after they get in?" That reframing is the chapter's load-bearing claim: a SYSTEM-level or ring-0 compromise is no longer the end of the story, because the assets that matter most were moved somewhere a compromised kernel cannot directly map.

---

> **Bequeaths.** The Secure Kernel hands the rest of Part II one load-bearing guarantee: a VTL1 whose owned pages a VTL0 attacker should not be able to map, read, or write through architectural memory access (no matter how completely that attacker owns Ring 0) because Hyper-V's second-level page permissions, not the NT kernel, decide the mapping. That floor is what the next chapters spend. The VBS Trustlets chapter (Chapter 7) fills VTL1 with the user-mode trustlets that hold the secrets; the Code Integrity chapter (Chapter 8) uses VTL1's authority to decide which kernel pages may ever execute; the Credential Guard chapter (Chapter 15) puts the domain's long-term secrets behind the wall. But the bequest is deliberately narrow. The Secure Kernel guarantees *isolation of what was placed in VTL1*. It does not promise the boundary's interfaces are free of oracles (Pass-the-Challenge), that shared silicon leaks nothing (the side channels above), that the running boundary is the newest version (Windows Downdate), or that an administrator who controls the update path is outside the threat model: because Microsoft says he is not. The chain moves the secret below the kernel's reach; it does not move the boundary's own attack surface out of reach.
