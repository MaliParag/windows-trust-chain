# VBS Trustlets

::: trust-ledger

- **Inherits:** VTL1 isolation. A hypervisor-managed second world whose pages no VTL0 token can map, enforced per-VTL by SLAT (Chapter 6, The Secure Kernel); and that same chapter's Secure Kernel (`securekernel.exe`), the VTL1 ring-0 scheduler this chapter's user-mode code runs under.
- **Promise:** A user-mode binary runs in VTL1 (Isolated User Mode) only after passing five load-time gates, and once it does, its pages are unreadable from VTL0 (including by a SYSTEM kernel write primitive) because the hypervisor refuses the VTL0→VTL1 translation.
- **TCB:** The hypervisor, the Secure Kernel, and the trustlet's own identity proof: two signing EKUs at Signature Level 12, the `.tpolicy`/`s_IumPolicyMetadata` section, and the runtime Trustlet Instance GUID. The NT kernel the attacker can own is explicitly *outside* it.
- **Adversary → Break:** VTL0 still owns three surfaces the Promise does not cover. The secure-call interface it parses inside VTL1 (`IumInvokeSecureService`), the agent RPC channel that *uses* the secret, and the substrate (Secure Boot, firmware, signing keys) the five gates rest on. The Promise covers *memory isolation*, not *use*, *liveness*, or *substrate*.
- **Residual:** Agent-side credential *use* (Pass-the-Challenge against `lsass.exe`) → Credential Guard (Chapter 15); HVCI policy correctness → Code Integrity (Chapter 8); the hypervisor and SLAT themselves → Above Ring Zero (Chapter 9); substrate trust (Secure Boot, firmware) → Secure Boot (Chapter 1).
- **Bequeaths:** The trustlet execution model (a five-gate VTL1 user-mode process plus its VTL0 agent) that Credential Guard (Chapter 15) and the Hyper-V vTPM trustlets stand on. Does NOT provide: liveness (VTL0 can DOS VTL1 by design), protection for what the agent *does* with the secret, a third-party inbox-trustlet path (use VBS Enclaves), or anything once the substrate falls.
- **Proof:** 🔵 documented: Ionescu's Black Hat 2015 reverse-engineering for the five gates and Trustlet IDs 0–3 [277]; Microsoft Learn for IUM and Credential Guard [310] [311]; Quarkslab for IUM debugging [312]; Amar & King (Black Hat 2020) for the secure-call floor [295]. No fresh 🟢 lab capture in this chapter.
:::

> **The Reasoner's question.** Which binaries get into VTL1 user mode, what gates do they pass, what do they do once they are there, and where does that protection stop?

---

> **Foundations: vocabulary this chapter assumes.**
>
> - **VTL0 / VTL1 and the Secure Kernel (established in Chapter 6).** Virtual Trust Levels are the hypervisor-managed privilege axis beside ordinary ring 0/ring 3; VTL1 is the secure world whose pages VTL0 cannot map, and the Secure Kernel (`securekernel.exe`) is its VTL1 ring-0 scheduler. The Secure Kernel chapter (Chapter 6) owns that boundary; this chapter assumes it and asks what runs *above* it, in VTL1 user mode.
> - **Trustlet / IUM process.** A user-mode process in VTL1. It is not protected merely by ACLs or PPL; VTL0 cannot map its pages because the hypervisor refuses the translation.
> - **Agent.** The ordinary VTL0 process that speaks to a trustlet: `lsass.exe` for `LsaIso.exe`, `vmwp.exe` for `vmsp.exe`, and analogous brokers for other isolated services.
> - **Signing gates.** Inbox trustlets require Microsoft-controlled code-signing properties, including the IUM EKU, because VTL1 user mode is not an arbitrary third-party plugin model. VBS Enclaves are the later third-party cousin, not the same thing.

---

> **Chapter claim.**
>
> **Trustlets are the confirmed user-mode processes Microsoft loads in Virtual Trust Level 1** when a binary passes five gates: a secure-process attribute, Microsoft-controlled signing EKUs at Signature Level 12, a `.tpolicy` PE section containing `s_IumPolicyMetadata`, a Trustlet Instance GUID, and the stripped-down IUM loader path. The public, named trustlets include the 2015 roster: the Secure Kernel Process (ID 0), `LsaIso.exe` (ID 1), `vmsp.exe` (ID 2), and the vTPM provisioning trustlet (ID 3). Newer Windows features such as Enhanced Sign-in Security (documented as VBS-isolated) and Administrator Protection (a documented new security boundary whose VBS/IUM relationship is not public) extend the same isolation philosophy, but their binary names, Trustlet IDs, and exact implementation surfaces are not publicly documented as trustlets. This chapter keeps those epistemic states separate: **confirmed** trustlets where the ID and binary are on record, **documented-not-public** VBS-isolated features where Microsoft documents the boundary but not the implementation object, and **inferred** relationships only where public architecture makes the inference explicit.

## Four locked rooms

It is 3:14 a.m. and a red-team operator on a fully patched Windows 11 25H2 box has, after eight hours of careful work, achieved the prize: a SYSTEM-privilege write primitive in the NT kernel. For two decades, the credential-theft decade the Mimikatz chapter (Chapter 14) documents, that has been the moment when the engagement ends and the report writes itself. SYSTEM in the kernel meant every process, every page, every secret. Game over.

It is not game over.

The operator's target list has four items on it. The NTLM hashes (the Death of NTLM chapter, Chapter 16) and Kerberos Ticket-Granting Tickets that used to sit directly in `lsass.exe`. The user's face template or matcher state in the Windows Hello (Chapter 20) Enhanced Sign-in Security pipeline. The just-in-time admin token that Administrator Protection issued thirty seconds ago. The keys of the four Hyper-V virtual machines running on the box, including the one hosting the user's corporate VPN. Four assets, but not four equally public implementation records. `LsaIso.exe` and `vmsp.exe` are confirmed trustlets with published Trustlet IDs. The vTPM provisioning trustlet is confirmed by the published ID/capability split. ESS is documented as a VBS-isolated boundary; Administrator Protection is a documented new security boundary whose relationship to VBS/IUM is not on the public record. For both, the exact binary names and Trustlet IDs are not public.

The precise claim is therefore narrower and stronger than the casual one. Confirmed trustlets run in a different kernel from the one the operator just compromised, on a different virtual trust level enforced by a hypervisor running underneath both. Some newer features route sensitive decisions through VBS services without Microsoft publishing whether the implementation object is a classic IUM process, a VBS Enclave, or another isolated component. The operator owns the NT kernel; the NT kernel does not automatically own the VTL1 memory that confirmed trustlets use. That sentence is what changed in 2015, and the rest of this chapter is what it actually means.

This is not "Microsoft hid the memory better." It is not obfuscation, not a clever access-control rule, not a kernel mitigation that the next CVE will erase. It is an architectural relocation: for confirmed trustlets, the user-mode process holding the secret no longer lives in the operating system the attacker compromised; for newer VBS-backed features, the documented sensitive boundary is likewise outside ordinary VTL0 memory even when the exact implementation object is unpublished. The hypervisor refuses to map VTL1-only pages into Virtual Trust Level 0 ("VTL0"), and the operator's kernel is in VTL0.

> **Key idea.**
>
> A SYSTEM kernel write primitive no longer implies every Windows security secret is memory-readable. For confirmed trustlets, the boundary is a named VTL1 IUM process. For ESS and Administrator Protection, the public claim is VBS-backed isolation, not a published Trustlet ID.

The aim is concrete: explain trustlets at the level of "what does `LsaIso.exe` actually do, how is it built, how does it talk to the rest of the system, and where does the model end." Not at the level of "VBS isolates them." Where the public record runs out (some trustlet binary names and IDs are not on Microsoft's published list as of mid-2026), this chapter says so, and shows what the actual records look like instead of inventing replacements.

So how does a user-mode process become unreachable from SYSTEM-in-the-NT-kernel? The answer is not new. It begins, like much of operating-system security, at MIT in the early 1970s.

![Figure: The moving privilege ceiling, 1972–2026. Each generation a different answer to where trusted user-mode code lives, from Multics rings through L4 and seL4's proof to Windows 10's VTL1 trustlets.](diagrams/17-vbs-trustlets-privilege-ceiling.svg)

## The user-mode-in-a-higher-privilege problem

In March 1972 Michael Schroeder and Jerome Saltzer published a paper in the *Communications of the ACM* describing an unusual machine. The Multics team at MIT had been wrestling with a question that does not, at first glance, sound like a security question. What should happen when a user program calls a password-checking routine that needs to read the system password file? The user program must not be allowed to read that file directly. The routine must be allowed to read it. The two pieces of code run in the same process. How does the machine know which one is asking?

Schroeder and Saltzer's answer was eight hardware-enforced rings of privilege, with each segment in memory carrying a *ring bracket* in its descriptor word, and with cross-ring calls validated automatically by the hardware [313] [314]. The hardware that shipped this design was the Honeywell 6180 in 1973 [315]. The pattern matters more than the gear. Some user code needed to run with more privilege than its caller and less privilege than the kernel. Multics arranged eight such layers from user code at the outermost ring down to the supervisor at ring 0 [313].

**Trusted Computing Base (TCB).** The set of hardware, firmware, and software whose correct operation is necessary to enforce a security policy. If any component of the TCB can be subverted, the policy can be subverted. The smaller the TCB, the easier it is to audit; the larger it is, the more places an attacker can find a foothold.

A few years later at Carnegie Mellon, William Wulf, Roy Levin, and the Hydra team took a different swing at the same problem. Hydra was a capability-based, object-oriented microkernel that ran on the C.mmp multiprocessor between 1971 and 1975 [316]. Where Multics multiplied rings, Hydra multiplied *vocabulary*: every protected resource was an object addressable only through capability tokens, and security-critical subsystems lived not inside the kernel but as user-mode capability-holders trusted by the kernel to enforce their own policy. Levin et al.'s 1975 SOSP paper "Policy/Mechanism Separation in HYDRA" gave the design its slogan, and that slogan has outlived the system that produced it [317].

> **Sidenote.**
>
> Hydra's "policy versus mechanism" phrasing still appears verbatim in modern object-capability literature, in the design discussion of WebAssembly's component model, and in seL4's published rationale.

For two decades the L4 family answered "but is this fast enough to be practical?" Jochen Liedtke's 1993 prototype, hand-coded in i386 assembly, ran inter-process communication twenty times faster than Carnegie's Mach microkernel [318]. His 1995 SOSP paper "On µ-Kernel Construction" was inducted into the ACM SIGOPS Hall of Fame in 2006 and is the foundational statement of the minimal-kernel, maximal-user-mode-trusted-services design. By 2010, OKL4, a commercial L4 derivative, had shipped in over one billion mobile devices [318].

**Microkernel.** A kernel design that pushes as much functionality as possible out of kernel mode and into user-mode "servers" that communicate via inter-process calls. Filesystem code, networking stacks, even device drivers can run as user-mode processes. The kernel itself shrinks to a few thousand lines of code that schedule processes, route messages, and enforce memory isolation, and nothing else.

In 2009 the lineage reached an end that nobody had reached before. Gerwin Klein, Kevin Elphinstone, Gernot Heiser and the NICTA team published *seL4: Formal Verification of an OS Kernel* at SOSP, reporting a machine-checked proof of functional correctness from a formal specification down to the C implementation [319]. seL4 was open-sourced in July 2014 [320]; the seL4 Foundation's About page states plainly that seL4 stands out because of its thoroughgoing formal verification [321]. A kernel of about 8,700 lines of C, formally verified from specification to C implementation, with sub-microsecond inter-process calls.

Schroeder and Saltzer asked it for hardware rings. Hydra asked it for capabilities. Liedtke asked it for inter-process speed. Klein and Heiser asked it of formal logic. The question stayed the same: how do you let some user-mode code hold a secret that some other code in the same machine is not allowed to read, when both pieces of code are scheduled by the same kernel? The Multics answer was rings. The Hydra answer was capabilities. The L4 answer was a tiny kernel plus IPC. The seL4 answer was a tiny kernel plus IPC, plus a proof.

The Microsoft answer, in July 2015, was a hypervisor.

> **Walkthrough: the lineage as a moving privilege ceiling.**
>
> Read the timeline from left to right as a series of attempts to answer one exact question: where do you put code that is trusted to handle a secret but is too large, too protocol-heavy, or too changeable to live comfortably inside the most privileged kernel? Multics answers by slicing one address space into hardware rings; the password-checking routine can execute inside an inner bracket while its caller stays outside it [313]. Hydra answers by giving user-mode servers unforgeable capabilities and making the kernel a mechanism provider rather than a policy encyclopedia [317]. L4 and seL4 answer by making IPC fast enough, and later verified enough, that a security server outside the kernel can still be part of the TCB [318] [319]. Windows NT originally chooses the simpler two-ring model: user mode and kernel mode. Vista Protected Processes, AppContainer, and PPL then try to recover intermediate trust levels inside that model, but the NT kernel remains the enforcer. VBS changes the ceiling. The trusted user-mode code moves not merely to a higher signer level but to VTL1 user mode, beneath a different kernel and behind hypervisor-owned SLAT entries [322] [312]. VBS Enclaves later expose a similar isolation shape to third-party DLLs, while Administrator Protection appears to reuse the same VBS-era design instinct for transient admin tokens, although Microsoft has not publicly named its implementation surface [280] [323].

If the architectural answer was already in the 1970s academic literature, why did Microsoft wait until 2015 to ship it on Windows? Because three earlier attempts to ship user-mode isolation on Windows (under three different names, in three different decades) each failed in the same way.

## Three tries before trustlets

Before 2015 Microsoft tried three times to ship user-mode isolation on Windows. All three shipped in production. All three failed in the same way. They were useful when the attacker lived *below* the NT kernel's authority: a media process resisting an ordinary debugger, a Store app fenced into a capability set, an administrator process blocked from casually opening LSASS. They stopped being boundaries the moment the attacker controlled the component that evaluated the boundary.

That distinction is the whole reason this history belongs in a trustlet chapter. Vista Protected Processes, AppContainer, and PPL are not embarrassing false starts; each one solves a real problem at the layer it was designed for. The mistake is to ask one of them to solve the stronger problem VBS was built for: keep a secret from a malicious or compromised VTL0 kernel. The three mini-case-studies below therefore have the same structure. First, identify the enforcer. Second, identify the asset. Third, ask whether the attacker is allowed to compromise the enforcer. If yes, the design may still be valuable defense-in-depth, but it is not a trustlet-class boundary.

### 2007: Vista Protected Processes

Windows Vista introduced *Protected Processes* in January 2007. The motivation was not credential security; it was Digital Rights Management. The Protected Media Path required a set of binaries (`audiodg.exe`, `mfpmp.exe`, and a handful of others involved in Blu-ray playback) whose memory non-protected processes could not read, whose threads could not be debugged from outside, and whose DLL imports could not be hijacked at runtime [324]. The kernel enforced these rules by refusing to grant the relevant access masks (`PROCESS_VM_READ`, `PROCESS_VM_WRITE`, `THREAD_ALL_ACCESS`) to handles requested from non-protected processes.

The mechanism was elegant. The threat model was not. Alex Ionescu announced in January 2007 (within weeks of Vista's general availability) that he had developed a bypass method for the Protected Media Path [324]. The same NT kernel that enforced the protection was the kernel an attacker would compromise to bypass it. A signed kernel driver, or any of the long stream of subsequent kernel vulnerabilities, would walk straight through.

### 2012: AppContainer and the LowBox token

Windows 8 introduced AppContainer process isolation in October 2012, originally to support Windows Store apps (later unified as the Universal Windows Platform in Windows 10) [325]. Each AppContainer process ran with a *LowBox* token: a low-integrity primary token plus a SID, plus a set of named capabilities (`internetClient`, `picturesLibrary`, and so on), plus a per-AppContainer named-object subtree under `\Sessions\<N>\AppContainerNamedObjects\<SID>`. The NT kernel checked the SID against object DACLs at every object access, denying access by default and granting it only where the AppContainer's declared capabilities matched the requested operation.

This is a Hydra-style capability lattice bolted onto NT's existing access-control system. It is a useful sandboxing primitive for *untrusted* code, and modern browsers (the Edge renderer, the Chromium sandbox) consume it for exactly that purpose. It is not a defense against an attacker who already has kernel code execution. In August 2018 James Forshaw at Google Project Zero published an exploit for Issue 1550 that turned the AppContainer named-object namespace itself into an arbitrary-directory-creation primitive [326]:

> The AppInfo service... calls the undocumented API CreateAppContainerToken... As the API is called without impersonating the user... the object directories are created with the identity of the service, which is SYSTEM.

A low-integrity caller could direct that SYSTEM-owned creation at any directory it pleased and use the result to elevate. The lattice held; the lattice's *enforcer* did not. AppContainers continue to ship, doing their actual job (sandboxing untrusted code) reasonably well. They were never going to answer the trustlet question (isolating trusted code from a compromised kernel) because they are NT-kernel-enforced.

### 2013: Protected Process Light (PPL) and `RunAsPPL`

Windows 8.1 generalized the Vista mechanism into a *signer-level lattice*. Each protected process now had a two-dimensional protection level: a signer (`PsProtectedSignerWinTcb`, `PsProtectedSignerWindows`, `PsProtectedSignerAntimalware`, `PsProtectedSignerAuthenticode`, others) and a protection type (`PsProtectedTypeProtectedLight` or `PsProtectedTypeProtected`). Higher-signer processes could manipulate lower-signer ones; same-signer processes could not see across the line. The first canonical use case was anti-malware services that registered an Early Launch Anti-Malware (ELAM) driver and then ran their user-mode service as a Protected Process Light [327].

**Protected Process Light (PPL).** A Windows 8.1 process attribute that constrains which other processes can request high-privilege access to it. PPL extends the Vista Protected Process mechanism with a signer-level lattice (WinTcb > Windows > Antimalware > Authenticode > None) and a protection type. The NT kernel enforces the rules. LSASS running as a PPL is the canonical use case, exposed to administrators via the `RunAsPPL` registry value [328]. The Protected Process Light chapter (Chapter 10) owns this mechanism in full; here it is the third and strongest of the three NT-kernel-enforced attempts that motivate trustlets.

Alex Ionescu's 2013 essay "The Evolution of Protected Processes Part 3" documented the resulting Signing Levels table: Signature Level 12 named "Windows," Level 13 "Windows Protected Process Light," Level 14 "Windows TCB" [329] [330]. That table is the load-bearing reference for every later trustlet design: every IUM binary on a 2026 Windows machine must satisfy *at least* Signature Level 12. Microsoft shipped LSASS-as-PPL ("LSA Protection," exposed through the `RunAsPPL` registry value under `HKLM\SYSTEM\CurrentControlSet\Control\Lsa`) as the canonical example: a way to keep the lower-privileged half of an administrator's session from reading credential material out of LSASS memory.

It worked, for some values of "worked." It worked against pass-the-hash tools that ran as an ordinary administrator without a signed kernel driver. It did not work against an attacker willing to load any signed driver, and (as became clear in 2021) it did not work even from userland once the bypass class was identified.

In August 2018 James Forshaw, in the same Project Zero post that exposed the AppContainer issue, also documented a `DefineDosDevice` plus Known-DLL hijack technique. By creating a symbolic link in the NT object manager namespace that aliased a Known DLL section, an administrative caller could induce a target PPL process to load arbitrary code at the next image load [326]. In 2021 the researcher who blogs as itm4n weaponised the same primitive into `PPLdump`, a userland tool that dumped `lsass.exe` memory from an administrator command prompt with no kernel driver involved [328]. itm4n's writeup is honest about what this means:

> Like any other protection though, it is not bulletproof and it is not sufficient on its own, but it is still particularly efficient.

Microsoft closed the `DefineDosDevice` corner of this class in Windows 10 21H2 build 19044.1826, shipped in July 2022 [331]. That is eight years of mainstream PPL deployment during which the LSASS-as-PPL credential boundary was bypassable without ring 0 access at all.

### The pattern

Three primitives. Three different protection mechanisms. One common failure mode.

| Mechanism | Year | Enforcer | Threat model | Defeated by | Status today |
|-----------|------|----------|---------------|--------------|--------------|
| Vista Protected Process | 2007 | NT kernel | Untrusted user code reading DRM-protected media buffers | Signed kernel drivers; Ionescu Jan 2007 [324] | Superseded by PPL for non-DRM use |
| AppContainer / LowBox | 2012 | NT kernel | Untrusted store-app code escaping its capability sandbox | SYSTEM-owned directory creation via service impersonation [326] | Active for sandboxing untrusted code; not a trustlet substitute |
| Protected Process Light (`RunAsPPL`) | 2013 | NT kernel | Userland administrative attacker reading LSASS credential material | `DefineDosDevice` plus Known-DLL hijack; PPLdump 2021 [328] | Active as defense-in-depth; closed in build 19044.1826, July 2022 |
| Isolated User Mode / trustlets | 2015 | Hypervisor + Secure Kernel | VTL0 kernel attacker reading user-mode secrets | Secure-call interface bugs; agent-side RPC residual [295] | Active; the subject of this chapter |

Three rows, one diagnosis. Every NT-kernel-enforced isolation primitive shares the attacker's TCB. Improving the lattice the NT kernel enforces does not move the security ceiling, because the NT kernel itself can be compromised; once it is, any policy decision the NT kernel makes is the attacker's policy decision. Microsoft's own VBS hardware-requirements page admits the diagnosis verbatim:

> **Source note.**
>
> VBS uses hardware virtualization and the Windows hypervisor to create an isolated virtual environment that becomes the root of trust of the OS that assumes the kernel can be compromised.: Microsoft, OEM VBS hardware requirements [262]
>
> **LSA Protection is not a credential-theft countermeasure on its own.**
>
> `RunAsPPL` is useful defense in depth. It is not, and has never been, a substitute for Credential Guard. itm4n's 2021 PPLdump release was the proof for the userland half of that statement; signed-driver loaders are the proof for the ring-zero half. If your threat model includes a determined attacker with administrative rights, Credential Guard is the boundary; PPL is the speed bump in front of it [328].

If every primitive the NT kernel enforces shares the attacker's TCB, the kernel that enforces user-mode isolation has to be a *different* kernel. In July 2015 Microsoft shipped one.

## July 2015: The hypervisor becomes the arbiter

On 29 July 2015 Microsoft shipped Windows 10 build 10240 [332]. Two new ideas shipped with it. The first was Hyper-V's hypervisor running *underneath* the NT kernel even on a laptop, not just on a server hosting virtual machines [333]: the arbiter the Above Ring Zero chapter (Chapter 9) treats in full. The second was a separate kernel running alongside the NT kernel, at a different Virtual Trust Level. Together those two ideas produce a substrate where the long-time equation "SYSTEM kernel write primitive equals every secret in user-mode memory" is no longer true.

**Virtual Trust Level (VTL).** Established in the Secure Kernel chapter (Chapter 6): a hypervisor-managed privilege axis on top of x86's ring 0 / ring 3, where each VTL has its own kernel and user mode, and higher VTLs can read lower-VTL memory but not the reverse. The one detail this chapter needs on top of that recap is the cap: the Hyper-V Top-Level Functional Specification reserves up to 16 VTLs; the current implementation defines `#define HV_NUM_VTLS 2` [322].

The Hyper-V Top-Level Functional Specification states the rule directly: *"VSM achieves and maintains isolation through Virtual Trust Levels (VTLs)... Architecturally, up to 16 levels of VTLs are supported; however a hypervisor may choose to implement fewer than 16 VTL's. Currently, only two VTLs are implemented"* [322]. The NT kernel runs in VTL0 ring 0; user-mode applications run in VTL0 ring 3. The Secure Kernel (Chapter 6) runs in VTL1 ring 0; trustlets run in VTL1 ring 3. Each VTL transition takes the CPU through a VMEXIT and back, with VMCS save and restore on each crossing [334].

> **Sidenote.**
>
> The architectural cap of sixteen VTLs is in the published specification but is not deployed. Stocking the unused slots would require both hypervisor changes and a new design for who manages the additional kernel images. The two-VTL design is the entire shipped product.

Quarkslab's reverse-engineering team put the practical consequence in one sentence in their IUM-debugging writeup: *"VTL0 is the Normal World, where the traditional kernel-mode and user-mode code run in ring 0 and ring 3, respectively. On top of that, a new world appears: VTL1 is the privileged Secure World, where the Secure Kernel runs in ring 0, and a limited number of IUM processes run in ring 3. Code running in VTL0, even in ring 0, cannot access the higher-privileged VTL1"* [312].

That sentence is the architectural fact the whole chapter rests on. The hypervisor configures each guest physical page's permissions on a per-VTL basis using the CPU's Second Level Address Translation tables. A page can be readable from VTL0 and VTL1, readable from VTL1 only, or readable from neither.

> **Margin note.**
>
> On Intel hardware, the per-VTL permissions are implemented with Extended Page Tables (EPT); on AMD they use Nested Page Tables (NPT). The hypervisor keeps the per-VTL EPT/NPT entries in its own memory, not in the guest's.

**Second Level Address Translation (SLAT).** Also established in Chapter 6: the hardware mechanism (Intel EPT, AMD NPT) that lets the hypervisor define page-level permissions per-VTL, independent of the guest's own page tables. The consequence this chapter leans on is sharp: a SYSTEM-privilege VTL0 attacker who edits the NT kernel's page tables cannot change the VTL1-side permissions, because those live in hypervisor-managed structures that VTL0 page-table writes do not touch.

> **Walkthrough: what happens when the VTL0 kernel tries to read a trustlet page.**
>
> Start with an address inside `LsaIso.exe`. In an ordinary Windows process, the NT kernel could translate the process virtual address through that process's page tables, find the guest physical page, map it into a kernel virtual address, and copy the bytes. With VBS, the same first steps are not enough. The NT kernel is executing in VTL0, so the CPU's memory access is checked against the VTL0 view of the hypervisor's second-level translation. The guest page that backs the trustlet is marked VTL1-only in the hypervisor-owned EPT/NPT entry. VTL0 can invent a new PTE, patch `EPROCESS`, disable SMEP, or load a signed driver; none of those writes modifies the hypervisor's per-VTL permission entry. The access dies below the NT kernel. In the other direction, a VTL1 trustlet can read VTL0 request buffers because those pages are intentionally mapped with VTL1-readable permissions. That asymmetry (VTL1 can inspect VTL0, VTL0 cannot inspect VTL1) is the mechanical meaning of the Secure World [322] [312].

The VTL hierarchy is not symmetric. VTL1 code can read VTL0 memory; that is how a trustlet can dispatch the contents of an `lsass.exe` RPC request the moment after VTL0 wrote it. VTL0 code cannot read VTL1 memory under any condition the hypervisor permits. A kernel write primitive in VTL0 lets the attacker corrupt the NT kernel's data structures, modify drivers, and walk every VTL0 process's pages. The attacker can do every one of those things and not be one byte closer to the contents of `LsaIso.exe`.

Microsoft's IUM documentation at Windows 10 RTM named two trustlets explicitly: **Trustlet ID 0 = the Secure Kernel Process** (hosts Device Guard and Hypervisor-protected Code Integrity policy decisions), and **Trustlet ID 1 = `LSAISO.EXE`** (Credential Guard's isolated LSA, holding NTLM hashes and Kerberos Ticket-Granting Tickets out of VTL0 reach). Two more (IDs 2 and 3, covered later in this chapter under the Inbox Roster) also shipped on the RTM image and were enumerated a week later by Ionescu's Black Hat reverse-engineering [310] [277]. Microsoft Learn's IUM page introduces the vocabulary the rest of this chapter will use:

> Trustlets (also known as trusted processes, secure processes, or IUM processes) are programs running as IUM processes in VSM... With VSM enabled, the Local Security Authority (LSASS) environment runs as a trustlet.

A week after Windows 10 shipped, on 5 August 2015, Alex Ionescu walked into a Black Hat USA briefing room in Mandalay Bay and reverse-engineered the entire thing in front of an audience [335]. His talk, "Battle of the SKM and IUM: How Windows 10 Rewrites OS Architecture," is the canonical first public account of the trustlet model and the source from which Microsoft's own later documentation borrows terminology one for one [277]. Almost every concrete fact about the gates that follow (the syscall allow-list, the EKUs, the `.tpolicy` section, the Trustlet Instance GUID) traces back to that single deck.

Now we know what world a trustlet lives in. What architecturally *is* one?

## The five gates

A trustlet is not a special process *class* the way a Protected Process is. It is an ordinary Portable Executable binary that has been loaded under five very specific conditions. Walk through them once and you will be able to recognize a trustlet in a `dumpbin /headers` listing. The status is mechanical, not categorical. Chapter 9 of *Windows Internals, Seventh Edition, Part 2* (Allievi, Russinovich, Ionescu, Solomon) covers the same architecture from the kernel-team side as a reference complement to Ionescu's BH2015 reverse-engineering [336].

**Trustlet.** A Windows user-mode process that runs in Virtual Trust Level 1 user mode (ring 3 of the Secure World), scheduled by the Secure Kernel and isolated from VTL0 by Hyper-V's per-VTL SLAT enforcement. A binary becomes a trustlet only if it satisfies five very specific conditions: a process attribute, two signing EKUs at Signature Level 12, a `.tpolicy` PE section containing `s_IumPolicyMetadata`, a Trustlet Instance GUID bound at runtime, and a stripped-down loader path. Trustlets are sometimes also called "trusted processes," "secure processes," or "IUM processes" [310].

**Isolated User Mode (IUM).** The user-mode environment of Virtual Trust Level 1. IUM is, structurally, ring 3 of VTL1. Its inhabitants are trustlets; its kernel is the Secure Kernel; its system-call surface is approximately one-tenth of NT's. Quarkslab's IUM-debugging writeup describes IUM as the place where *"a limited number of IUM processes run in ring 3"* of VTL1; Microsoft's Win32 documentation describes the same architectural placement with different wording [312] [310].

### Gate 1: the process attribute

VTL0 user-mode code cannot call `CreateProcess` and produce a trustlet. The Win32 API does not expose the necessary primitive. A trustlet is born via a direct `NtCreateUserProcess` syscall that carries a `PsAttributeSecureProcess` attribute with a 64-bit Trustlet ID. Only callers that already live in VTL1, or callers in VTL0 that hold a specific brokering capability, can request that attribute and have the Secure Kernel honor it [277].

This is intentional. The Win32 layering is one of the surfaces an attacker can compromise, so the trustlet boot path bypasses it. There is no "trustlet via shell": not for an administrator, not for SYSTEM, not for the Secure Kernel itself other than through the documented internal path.

Failure mode: if Gate 1 were only a user-mode convention, a VTL0 attacker could start a Microsoft-signed helper under ordinary process creation and then ask later components to treat it as isolated. The attacker would need control over process creation metadata or a broker that could forge `PsAttributeSecureProcess`. The Secure Kernel/NT creation path has to bind the requested Trustlet ID before the image is admitted to IUM; otherwise every later check would be answering the wrong question. What remains exposed is the authorized broker path: a legitimate agent can still request the operations Microsoft designed it to request, and those requests remain part of the VTL0 attack surface.

### Gate 2: Two EKUs at signature level 12

The binary must be signed with a certificate chain that contains two specific Enhanced Key Usage identifiers, and the resulting Signing Level must be 12 or higher. From Ionescu's BH2015 deck (correcting a typo in the slide): *"They must have a Signature Level of 12... This means they must have the Windows System Component Verification EKU (1.3.6.1.4.1.311.10.3.6)... They must have the IUM EKU 1.3.6.1.4.1.311.10.3.37"* [277].

**Enhanced Key Usage (EKU).** An X.509 certificate extension that restricts which purposes a certificate can be used for. An EKU is an object identifier (OID); a code-signing certificate that claims an OID of `1.3.6.1.4.1.311.10.3.6` is asserting it is valid for the "Windows System Component Verification" purpose. The Windows code-integrity subsystem (`ci.dll`), whose internals the Code Integrity chapter (Chapter 8) owns, checks the requested EKU against the actual certificate at image-validation time and refuses to load the image if the EKU is missing or the certificate is not chained to a trusted root [329].

Both EKUs are required. The Windows System Component Verification EKU establishes the binary as a Microsoft-signed Windows component. The IUM EKU asserts the binary's *intent* to load as a trustlet. A PPL EKU may sit on top, layering the PPL signer-level check on the trustlet check, but the two-EKU minimum is what Signing Level 12 enforces.

Failure mode: if Gate 2 accepts an ordinary Microsoft-signed binary, the trustlet boundary becomes a Microsoft-binary allow-list rather than an IUM-intent allow-list. An attacker would not need to forge VTL1 code; they would need only to redirect the loader toward a signed component with a parsing bug, unsafe import pattern, or unexpected command surface. The code-integrity check therefore has two obligations: prove the publisher chain and prove the IUM EKU purpose. The residual exposure is beneath code integrity: Test Signing, a trusted test root, Secure Boot bypass, or signing-key compromise can still turn the gate into a rubber stamp.

> **Sidenote.**
>
> The system-component EKU check is skipped when both Test Signing is enabled and the local machine trusts the Microsoft Test Root. That is the exact attack class Ionescu names verbatim in the BH2015 deck: "compromise the platform via Test Signing" disables the signing gate that defines trustlet identity.

### Gate 3: the `.tpolicy` section and `s_IumPolicyMetadata`

Every trustlet image must contain a PE section named `.tpolicy` marked `IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ`. The section must contain the symbol `s_IumPolicyMetadata`, a structure with three required components: a version byte set to 1, a 64-bit Trustlet ID that must match the one the process attribute requested, and a per-trustlet policy table containing entries for ETW (event tracing), debug permissions, crash-dump key release, and other trustlet-specific runtime knobs [277].

The Secure Kernel parses this section at load time via an internal routine the deck names `SkpspFindPolicy`. A binary with no `.tpolicy` section, or with one whose Trustlet ID disagrees with the process-attribute Trustlet ID, or whose version byte is anything other than 1, fails the gate. The Secure Kernel does not "infer" a trustlet identity; it reads it out of the binary the attacker would have had to sign.

Failure mode: if the requested Trustlet ID and the embedded `.tpolicy` ID can diverge, identity becomes caller-controlled. A malicious or confused broker could request ID 1 semantics for a binary whose policy table was written for another service, gaining the wrong ETW, debug, crash-dump, or secure-storage rules. The Secure Kernel check is a consistency proof: the signed image must carry the policy for the class it is asking to become. Residual exposure remains in policy-table parsing itself, which is why this is not merely metadata; malformed tables are VTL0-influenced input parsed inside the VTL1 load path.

### Gate 4: The trustlet instance GUID

Once gates 1-3 pass, the trustlet calls a secure-service routine the deck names `IumSetTrustletInstance`, identified by secure-call ordinal `0x80000001`. That routine binds the running process to a Trustlet Instance GUID, the runtime identity by which the Secure Kernel discriminates one instance of a trustlet from another. Hyper-V partition GUIDs flow into this identifier for the vTPM trustlets, so that the secrets a partition's vTPM holds are scoped to that partition's Instance GUID.

The same Instance GUID can be shared across distinct Trustlet IDs. That is the architectural primitive Microsoft uses for trustlet-to-trustlet authentication: the host-side Hyper-V vTPM (`vmsp.exe`, Trustlet ID 2) and the vTPM provisioning trustlet (ID 3) cooperate on a single partition's secrets by sharing the partition's Instance GUID. The Secure Kernel's `SkCapabilities` table hardcodes which Trustlet IDs are permitted to invoke which secure-storage operations against an Instance GUID; for the 2015-era IUM surface, the only ID-discriminated rules are `CheckByTrustletId 2` for `SecureStorageGet` and `CheckByTrustletId 3` for `SecureStorageSet` [277].

Failure mode: if Gate 4 binds only a GUID and not the `(Trustlet ID, Instance GUID)` pair, two different trustlet classes become indistinguishable storage principals. An attacker would need either an attacker-controlled trustlet (the malwarelet case), a compromised legitimate trustlet, or a Secure Kernel bug that lets a VTL0 caller set or reuse another component's GUID. The Secure Kernel check is not "does this GUID exist?" but "is this Trustlet ID allowed to perform this operation against this GUID?" Residual exposure is intentional sharing: ID 2 and ID 3 must share enough namespace to provision a vTPM, so the proof obligation shifts to the capability table that separates write authority from read authority.

### Gate 5: the stripped-down loader

A trustlet's image loader is not the standard NT loader. The `ntdll` loader detects the secure-process flag through a check the deck names `LdrpIsSecureProcess`, which skips an unusually long list of features. Application Verifier hooks: skipped. Image File Execution Options registry checks: skipped. SxS / Fusion DLL redirection: skipped. The CSRSS connection ordinary NT processes establish during startup: skipped (the `BASE_STATIC_SERVER_DATA` structure CSRSS would normally hand back is fabricated locally on the trustlet's heap so dependent calls do not crash). Safer, AuthZ, Software Restriction Policies: all skipped. Any DLL load triggered from VTL0: refused.

The result is a loader path with no attack surface against VTL0 environment variables, no susceptibility to NT's normal "load this DLL instead" knobs, and no opportunity for the user's CSRSS process to inject anything into the trustlet's address space. The system-call surface available inside the trustlet is restricted to a version-specific subset: Ionescu's 2015 deck states the count verbatim for that build as *"Only 48 system calls are currently allowed from IUM Trustlets"* [277].

Failure mode: if the ordinary NT loader path runs, VTL0 gets its oldest process-compromise tools back: IFEO debugger redirection, Application Verifier shims, SxS DLL substitution, Known-DLL games, CSRSS-mediated startup state, and policy engines whose inputs live in registry hives or objects VTL0 can edit. The attacker would not need to read VTL1 memory; they would arrange for attacker-chosen code or attacker-chosen loader state to be present before the boundary becomes meaningful. The secure loader's check is negative as much as positive: deny VTL0-triggered DLL loads and skip VTL0-owned customization layers. Residual exposure is the smaller IUM syscall/API surface that remains, not the full Win32 loader ecology.

> **Walkthrough: a trustlet load from image path to running VTL1 process.**
>
> The load begins in a normal-looking place (a request to create a process) but the request contains `PsAttributeSecureProcess`, the first fork from ordinary NT process creation. Code Integrity then evaluates the image as a Windows component and as an IUM-capable component: Signature Level 12 or better, Windows System Component Verification EKU, and IUM EKU. The Secure Kernel does not accept the caller's claimed Trustlet ID on faith; it opens the image's `.tpolicy` section, finds `s_IumPolicyMetadata`, checks the policy version, and verifies that the embedded Trustlet ID matches the requested one. Only after identity is established does the loader take the secure-process path: no IFEO, no Application Verifier, no SxS redirection, no CSRSS-mediated startup state, no VTL0-triggered DLL load. The running process then calls the secure service `IumSetTrustletInstance` to bind an Instance GUID. At that point the identity is three-dimensional: binary signer, Trustlet ID, and runtime Instance GUID. Failure before the GUID means no trustlet; failure after it means a trustlet with no access to its per-instance storage.

![Figure: The five load-time gates that turn a binary into a trustlet (process attribute, signing EKUs at Level 12, `.tpolicy` metadata, Instance GUID, and the stripped-down IUM loader) each shown with its distinct failure outcome.](diagrams/17-vbs-trustlets-five-gates.svg)

| Gate | What it checks | Where it lives | Failure outcome |
|------|----------------|----------------|-----------------|
| 1. Process attribute | `PsAttributeSecureProcess` with 64-bit Trustlet ID, requested via `NtCreateUserProcess` | NT kernel boot path | Normal NT process; no IUM bit ever set [277] |
| 2. EKUs + Signing Level | Windows System Component EKU (`1.3.6.1.4.1.311.10.3.6`) AND IUM EKU (`1.3.6.1.4.1.311.10.3.37`); Signing Level >= 12 | `ci.dll` integrity check, `CipMincryptToSigningLevel` | Load refused; no trustlet [329] [277] |
| 3. `.tpolicy` + `s_IumPolicyMetadata` | PE section with version 1, matching Trustlet ID, and per-trustlet policy entries | Secure Kernel `SkpspFindPolicy` | Load refused; no trustlet [277] |
| 4. Trustlet Instance GUID | `IumSetTrustletInstance` secure-call ordinal `0x80000001`; per-partition scoping for vTPM | Secure Kernel runtime | Process exists but cannot bind to per-instance secret storage |
| 5. Loader strip-down | Skip Application Verifier, IFEO, SxS, CSRSS, Safer, AuthZ, SRP; deny VTL0-triggered DLL loads | NT `LdrpIsSecureProcess` | Normal NT loader runs; image loads but is not isolated |

> **Key idea.**
>
> A trustlet is what passes all five gates. There is no other definition. Status is mechanical, not categorical: it is what the Secure Kernel's load path produces when a properly signed binary with a properly formed `.tpolicy` section calls `NtCreateUserProcess` with a proper secure-process attribute.

All five gates pass. The binary is now a trustlet. It is running in VTL1 user mode. The hypervisor refuses to map its pages into VTL0. Now what does it do? Who does it talk to?

## The inbox roster

Five gates. Pass them all and you become a trustlet. Microsoft passes them on behalf of a small confirmed roster, and Microsoft also ships newer VBS-backed features whose exact implementation object is not publicly named. The word *small* is doing work. VTL1 user mode is not a second copy of Windows where arbitrary services migrate for neatness. It is a scarce compartment for code whose asset is worth the cost of a cross-VTL boundary and whose interface can be narrow enough to audit.

Read the roster with three labels in mind. **Confirmed** means the Trustlet ID and role are on the public record. **Documented-not-public** means Microsoft documents a VBS-isolated security boundary but does not publish the binary name, Trustlet ID, or ALPC endpoint. **Third-party enclave** means the code runs in VTL1-protected enclave memory but is not an inbox trustlet process. Collapsing those categories is how good architecture writing turns into folklore.

Read each row in the roster as four coupled identities, not as a process name. The **Trustlet ID** is the load-time class baked into `.tpolicy`. The **binary** is the Microsoft-signed image that carries the IUM EKU. The **Instance GUID** is the runtime scope for per-instance storage, especially important for Hyper-V partitions. The **agent** is the VTL0 process that still faces the rest of Windows and therefore remains in the attacker's world. A secret is protected only if it stays on the trustlet side of that split; every request, handle, protocol parser, UI prompt, and network packet on the agent side remains ordinary VTL0 attack surface.

![Figure: The canonical agent/trustlet split. The VTL0 agent (lsass.exe) keeps the protocol, session, and network state while the VTL1 trustlet (LsaIso.exe) holds the secret; only the request and response cross the LSA_ISO_RPC_SERVER ALPC channel the Secure Kernel marshals.](diagrams/17-vbs-trustlets-agent-trustlet-split.svg)

### The agent / trustlet pattern

Before the roster, the pattern. Almost every shipping trustlet has a partner: an agent process in VTL0 that does the high-volume work of integrating with the rest of the operating system, and the trustlet itself in VTL1 holding the secret material. The two talk over an Advanced Local Procedure Call port whose server end is hosted by the trustlet.

**Advanced Local Procedure Call (ALPC).** A Windows inter-process communication primitive optimized for fast message exchange between processes on the same machine. The NT kernel hosts ALPC ports as named kernel objects (e.g., `\RPC Control\LSA_ISO_RPC_SERVER`); clients open a port and exchange messages with the server. For trustlets, the ALPC server runs inside the trustlet in VTL1; clients in VTL0 send requests, the Secure Kernel marshals the request across the VTL boundary, and the trustlet returns a result back to VTL0. The hash never leaves VTL1; the request and response do.

> **Walkthrough: an NTLM challenge through the agent/trustlet split.**
>
> A server sends an NTLM challenge to a Windows client. The packet arrives in VTL0 and is parsed by ordinary networking and authentication code; `lsass.exe`, not `LsaIso.exe`, owns that protocol machinery. When LSASS needs the response computed with the user's NTLM material, it sends an ALPC request to `LSA_ISO_RPC_SERVER`. The request crosses into the Secure Kernel, which marshals the call into VTL1 user mode. `LsaIso.exe` reads the challenge, uses the hash it holds in VTL1-only memory, and returns an opaque response blob. The hash never crosses back. The response does. That is both the power and the limit of Credential Guard: memory extraction is blocked, but agent-side use of the credential remains possible because the entire point of authentication is to produce usable responses [311] [337].

The roster below names the agent for each trustlet where Microsoft has published one. Where the agent is not publicly named, the row says so.

### Trustlet ID 0: The Secure Kernel process

The first inhabitant of VTL1 user mode. Hosts Device Guard and Hypervisor-protected Code Integrity policy decisions. Architecturally close to a daemon: it does not service external clients; it provides services the Secure Kernel itself relies on for policy decisions about whether a given image is permitted to load in VTL0 [277].

The important mental model is not "a hidden process that users can call." It is the user-mode policy companion to VTL1's kernel-mode enforcement. Hypervisor-protected Code Integrity has to answer questions that are too policy-rich to be hard-coded as a few SLAT bits: which signing levels are acceptable for a given image, which Device Guard rules are active, whether a Code Integrity policy authorizes a module, and how those decisions are exposed back to VTL0 without letting VTL0 rewrite the rule book. ID 0 is where that policy work lives.

That placement matters because it keeps the code-integrity decision out of the kernel it is judging. If the NT kernel could both request an image-load decision and edit the policy engine's memory, HVCI would collapse into another PPL-like kernel-enforced rule. By locating the policy service in VTL1 user mode, Microsoft gets a familiar user-mode implementation style (parsers, policy tables, ETW choices, crash behavior) while keeping the state VTL0 would most like to corrupt behind the hypervisor boundary. It is "process-like" for engineering reasons and "secure-kernel-adjacent" for threat-model reasons.

Failure-mode walkthrough: suppose a VTL0 kernel attacker can rewrite the policy state ID 0 uses to answer HVCI or Device Guard decisions. The immediate break is not that the attacker reads a secret; it is that the attacker turns the integrity oracle into an approval oracle for code VTL0 wants to run. The attacker would need a way to write VTL1 policy memory, confuse the secure-call parameters that name a policy decision, or compromise the substrate that loaded the Secure Kernel Process in the first place. The Secure Kernel and hypervisor check the memory boundary and the load-time identity; HVCI then consumes decisions from a service VTL0 cannot patch in place. Residual exposure remains at the request boundary: VTL0 still supplies image paths, section objects, and policy-evaluation context, so parser bugs or confused-deputy decisions in the secure-call path are the realistic failure class, not direct memory theft.

### Trustlet ID 1, `LsaIso.exe` (Credential Guard)

The canonical trustlet. Holds NTLM hashes and Kerberos Ticket-Granting Tickets. Its agent in VTL0 is `lsass.exe`, the Local Security Authority Subsystem Service that has held those secrets directly for every version of Windows NT until 2015. The ALPC port name is `LSA_ISO_RPC_SERVER`. The IUM-side API the trustlet exposes is narrow: `EncryptData` and `DecryptData` on opaque blobs, plus a handful of internal management operations [311].

The Microsoft Learn explanation is the verbatim public account:

> With Credential Guard enabled, the LSA process in the operating system talks to a component called the isolated LSA process that stores and protects those secrets, LSAIso.exe. Data stored by the isolated LSA process is protected using VBS and isn't accessible to the rest of the operating system. LSA uses remote procedure calls to communicate with the isolated LSA process [311].

A VTL0 caller (including SYSTEM-in-the-NT-kernel) can ask the trustlet to encrypt a freshly supplied credential or to authenticate a freshly received challenge. It cannot ask the trustlet to expose the underlying NTLM hash in plaintext. The raw hash never leaves VTL1: only encrypted blobs and the authentication outcomes derived from it do. That is the entire point.

Failure-mode walkthrough: if the `LsaIso.exe` boundary is violated, pass-the-hash becomes literal again. The attacker no longer has to relay a challenge or wait for an authentication event; they dump reusable NTLM material and Kerberos tickets out of memory the way older LSASS tooling did. To get there, the attacker needs one of three things: a VTL0-to-VTL1 bug in the secure-call/marshalling path, a substrate failure that lets attacker code load as a trustlet, or a logic bug in `LsaIso.exe` that returns material its contract says should stay opaque. The Secure Kernel checks page ownership and marshals only allowed calls; code integrity checks the image; the ALPC/RPC contract is supposed to return operations, not secrets. The residual exposure is exactly Microsoft and Lyak's documented caveat: VTL0 can still ask for *use* of a credential through `lsass.exe`, so challenge-response relay and protocol abuse remain possible even when memory extraction fails [311] [337].

### Trustlet ID 2, `vmsp.exe` (Hyper-V vTPM, host side)

The Hyper-V Virtual Trusted Platform Module on the host side (the TPM chapter, Chapter 2, owns the underlying primitive). One `vmsp.exe` instance per guest partition; the agent is `vmwp.exe`, the Hyper-V Virtual Machine Worker Process for that partition. The Instance GUID is the partition's GUID, so that the keys a partition's vTPM holds are scoped to that partition and that partition only. Storage primitives include a Mailbox primitive (protected by a per-instance Security Cookie) and a Secure Storage primitive that produces Ingress and Egress blobs encrypted with per-Instance IDK material [277] [338].

Shielded VMs on Windows Server 2016 and later consume `vmsp.exe`. A shielded VM, per Microsoft Learn, *"has a virtual TPM, is encrypted using BitLocker, and can run only on healthy and approved hosts in the fabric"* [338]. The vTPM keys live in the host's `vmsp.exe` trustlet; the BitLocker volume master key in the guest is sealed against that vTPM; and a SYSTEM-privilege NT-kernel write primitive on the host cannot read the partition's vTPM secrets even though the host can otherwise reach the partition's memory.

Failure-mode walkthrough: if the `vmsp.exe` boundary breaks, host compromise becomes key compromise for every protected guest whose vTPM state the broken instance can reach. The attacker wants the vTPM's sealed keys or the ability to make the vTPM sign/decrypt as if the guest were healthy. To exploit that, the attacker would need to cross from `vmwp.exe`/host VTL0 into the VTL1 `vmsp.exe` address space, confuse the partition GUID used as the Instance GUID, or abuse a secure-storage capability that returns another partition's blob. The Secure Kernel's checks are two-dimensional: Trustlet ID 2 is the runtime reader, and the Instance GUID scopes the material to one partition. Residual exposure remains in `vmwp.exe` and the VM management plane: the host can pause, starve, misconfigure, or deny service to the guest, and bugs in TPM command parsing can still be reachable through the legitimate agent channel.

### Trustlet ID 3: vTPM provisioning trustlet

Pushes initial secrets into a partition's Instance GUID at vTPM creation time. The Secure Kernel's `SkCapabilities` array hardcodes `CheckByTrustletId 2` for `SecureStorageGet` and `CheckByTrustletId 3` for `SecureStorageSet`; those are the only Trustlet-ID-checked secure-storage operations in the 2015-era IUM secure-call surface [277]. The pair of trustlets cooperates on the same Instance GUID so the provisioning trustlet writes and `vmsp.exe` reads, with the Secure Kernel enforcing that no other trustlet can do either.

The lifecycle is easiest to understand as a handoff. When Hyper-V creates a protected guest with a virtual TPM, there is a moment before the long-lived `vmsp.exe` instance can serve TPM commands for that partition. Initial vTPM state has to be generated, associated with the partition's GUID, and stored under keys that the VTL0 host cannot read. The provisioning trustlet owns the write side of that first operation. It can set the secure-storage material for the Instance GUID, but it is not the runtime TPM service. After provisioning, `vmsp.exe` owns the read side and services the guest's TPM operations through `vmwp.exe`.

This split is why Trustlet ID and Instance GUID are separate. The Instance GUID says "this partition's vTPM namespace." The Trustlet ID says "which class of trustlet is allowed to perform which operation in that namespace." Sharing the GUID without checking the ID would let any cooperating trustlet become a storage peer; checking only the ID without the GUID would collapse every VM's vTPM state into one global bucket. `SkCapabilities` has to enforce both axes, and for the published 2015 surface the ID-checked operations are exactly the provisioning/runtime pair: ID 3 sets, ID 2 gets [277].

Failure-mode walkthrough: the provisioning trustlet is dangerous precisely because it is allowed to create initial state. If an attacker can run ID 3 operations after provisioning, or can bind ID 3 to a victim partition's Instance GUID, the break is not passive disclosure but active state substitution: seed a vTPM with attacker-known material, overwrite the initial secure-storage blob, or make a later `vmsp.exe` read a blob that was never generated for that guest. The attacker would need a compromised provisioning path, a GUID-binding bug, or a missing `CheckByTrustletId 3`/operation-state check. The Secure Kernel must prove that the caller is ID 3, the operation is `SecureStorageSet`, the GUID is the target partition, and the lifecycle permits setting. Residual exposure is operational: provisioning is a short, high-value window, so logging and host-fabric policy matter even though VTL0 cannot read the resulting keys.

### Enhanced Sign-in Security (ESS) biometric matching component (Windows 11+)

Microsoft Learn documents the architectural placement of Windows Hello's facial-recognition algorithm verbatim:

> When ESS is enabled, the face algorithm is protected using VBS to isolate it from the rest of Windows. The hypervisor is used to specify and protect memory regions, so that they can only be accessed by processes running in VBS. The hypervisor allows the face camera to write to these memory regions providing an isolated pathway... Sensors that support ESS have a certificate embedded during manufacturing [339].

The page also documents the certificate chain that authenticates the camera to the matcher and the match-on-sensor requirement for fingerprint readers under ESS. Microsoft does *not* publicly name the binary that hosts the face algorithm, and it does not publicly assign that binary a Trustlet ID. The public fact is therefore **documented-not-public VBS isolation**, not a confirmed inbox trustlet identity. It may be implemented by an IUM trustlet, by a VBS enclave-like component, or by another Secure Kernel-mediated service; the published docs do not say.

Failure-mode walkthrough: if the ESS boundary is violated, the break is biometric replay or matcher-state compromise, not necessarily password theft. A VTL0 attacker wants to inject camera frames, read or replace face-template/matcher state, downgrade the certificate-authenticated camera path, or trick the matcher into accepting an unauthenticated sensor. The documented Secure Kernel/hypervisor role is to protect the memory regions used by the face algorithm and to permit the ESS-capable camera to write along an isolated path; the documented device role is certificate-backed sensor authentication [339]. Residual exposure remains outside that protected path: the Windows Hello broker, enrollment UX, policy configuration, fallback PIN flows, and any non-ESS sensor mode are still ordinary Windows surfaces. Because Microsoft has not published a Trustlet ID, a reader should not audit ESS by looking for a made-up `EssIso.exe`; they should verify ESS configuration, sensor certification, and the supported Windows Hello state.

### Administrator Protection / Adminless issuer (Windows 11, rolling out 2025-26)

In October 2025 Microsoft shipped a preview of Administrator Protection in KB5067036 [340] and reverted the rollout in the same update note [323]. The Microsoft Learn page describes the security model:

> Once authorized, Windows uses a hidden, system-generated, profile-separated user account to create an isolated admin token. This token is issued to the requesting process and is destroyed once the process ends, ensuring that admin privileges don't persist. Administrator protection introduces a new security boundary with support to fix any reported security bugs [323].

The implementation surface that issues those tokens is not publicly named. The architectural family resemblance to a trustlet is strong, and the "new security boundary with support to fix any reported security bugs" line is the formal servicing commitment Microsoft makes for the boundary. Whether the issuer is a trustlet, a VBS Enclave, or a separately isolated VTL0 process is, as of mid-2026, not on the public record.

The security claim is nevertheless concrete enough to reason about. Classic UAC split tokens leave an administrator's medium-integrity session tied to a high-privilege token that can be requested later. Administrator Protection changes that shape: the everyday session runs as a standard user, a Windows Hello authorization gates elevation, Windows creates a hidden profile-separated admin identity, and the resulting admin token is issued only to the requesting process and destroyed when that process exits [323]. The sensitive operation is therefore not "store my password safely" but "mint a transient administrator authority without leaving reusable standing privilege in the user's logon session."

That is exactly the kind of issuer state VBS isolation is good at protecting: policy inputs arrive from VTL0, a narrow decision is made in an isolated boundary, and a usable outcome returns to VTL0. It is also exactly where this chapter must stay disciplined. There is no published `AdminIso.exe`, no public ALPC endpoint, and no Trustlet ID in the Microsoft documentation. Treat Administrator Protection as a VBS-era security boundary with trustlet-like economics, not as a named inbox trustlet until Microsoft or a reproducible public enumeration says so.

Failure-mode walkthrough: if the Administrator Protection issuer boundary breaks, the failure is unauthorized minting or reuse of administrative authority. The attacker wants a high-privilege token without a fresh Windows Hello authorization, a token that outlives the requesting process, or access to the hidden profile-separated account's standing material. The attacker would need to compromise the broker that asks for elevation, the isolated issuer that decides, the token handoff path back to VTL0, or the policy state that says which operation is being authorized. The documented checks are policy and lifecycle checks: authorize, create a profile-separated admin token, issue it only to the requesting process, destroy it when the process exits [323]. Residual exposure is large because the output is intentionally usable in VTL0: once an elevated process exists, its command line, child processes, handles, and UI are normal Windows attack surface. VBS can protect the issuer; it cannot make every elevated action safe.

### Third-party VBS enclaves (Windows 11 24H2 and later)

For the first time since 2015, a VBS-backed higher-trust user-mode primitive is exposed to third-party developers. It is not an inbox trustlet. A VBS Enclave is a DLL signed with a Trusted Signing certificate and loaded into a VTL1 enclave region of a host process via `CreateEnclave` and `CallEnclave`. The OS support is narrow:

> Windows 11 Build 26100.2314 or later... Windows Server 2025 or later... Visual Studio 2022 version 17.9 or later... The Windows Software Development Kit (SDK) version 10.0.22621.3233 or later, which provides veiid.exe (the VBS Enclave import ID binding utility) and signtool.exe... A Trusted Signing account [280].

Azure SQL's "Always Encrypted with secure enclaves" is the public flagship consumer. The architectural difference from an inbox trustlet is the API surface and the enclave-versus-process model: a VBS Enclave is a region inside an existing process's address space, not a separately scheduled process. The threat model is analogous but not identical: the untrusted host process calls into enclave code, while the enclave region is protected by VBS; there is no inbox Trustlet ID or separate trustlet process to enumerate [281].

Failure-mode walkthrough: if a VBS Enclave boundary breaks, the likely bug is not "dump a trustlet process" but host/enclave confusion. The host controls pointers, lengths, call timing, and shared buffers; the enclave holds keys or plaintext the host should not see. An attacker needs a validation bug (use host pointers after check, trust a length across a time-of-check/time-of-use window, parse a host-owned structure in place) or a signing/measurement failure that loads the wrong enclave image. Microsoft's 2025 MSRC guidance names exactly this proof obligation for enclave authors: validate host parameters, copy before checking, avoid TOCTOU, and assume the host is malicious [283]. Residual exposure is developer discipline. VBS supplies the memory boundary, but application code defines what crosses it.

### Roster table

| Status | Trustlet ID | Binary / component | VTL0 agent | Endpoint / call path | Secret / operation | Source |
|--------|-------------|--------------------|------------|----------------------|---------------------|--------|
| Confirmed trustlet | 0 | Secure Kernel Process | (internal; no external agent) | (internal) | Device Guard / HVCI policy decisions | [277] |
| Confirmed trustlet | 1 | `LsaIso.exe` | `lsass.exe` | `LSA_ISO_RPC_SERVER` | NTLM hashes, Kerberos TGTs; `EncryptData` / `DecryptData` | [311] [277] |
| Confirmed trustlet | 2 | `vmsp.exe` | `vmwp.exe` (per partition) | per-instance, partition GUID scoped | Hyper-V vTPM, host side; secure storage `Get` | [277] [338] |
| Confirmed trustlet | 3 | vTPM provisioning trustlet | (Hyper-V provisioning agent) | per-instance, partition GUID scoped | Initial secret provisioning; secure storage `Set` | [277] |
| Documented-not-public VBS isolation | not publicly documented | ESS face-algorithm component | Hello biometric pipeline; sensor-issued cert auth | not publicly named | Face template matching (fingerprint matching under ESS is match-on-sensor) | [339] |
| Documented-not-public security boundary | not publicly documented | Administrator Protection issuer | UAC / Authorization Manager broker | not publicly named | Just-in-time admin token issuance | [323] |
| Third-party VBS enclave | not a Trustlet ID | VBS Enclave DLL | host process (`CreateEnclave` caller) | direct calls via `CallEnclave` | Application-defined; e.g., Azure SQL Always Encrypted | [280] [281] |

> **Sidenote.**
>
> The published authoritative trustlet list still stops at Trustlet IDs 0-3 from August 2015. Every roster published after that point has been inferred from secondary evidence: kernel symbols, ALPC port enumeration via `NtQuerySystemInformation`, documented architectural placements. Microsoft has not republished an authoritative roster for any later Windows release.
>
> **Where the public record runs out.**
>
> Two rows in the list above are **not confirmed trustlets**. The ESS face-algorithm matcher is documented to live in VBS-isolated memory, with sensor-certificate authentication and template-encryption keys held in VBS, but the binary's name and Trustlet ID are not on the public record [339]. The Administrator Protection token issuer's implementation surface is even less precisely specified: "a hidden, system-generated, profile-separated user account" inside "a new security boundary," but no commitment to whether the issuer is a trustlet, a VBS Enclave, or a separate isolated process [323]. This chapter will not invent names or numbers for either. Empirical enumeration via `NtQuerySystemInformation(SystemIsolatedUserModeInformation)` on a current Windows 11 build is the only way to obtain a current trustlet roster, and that route is outside the scope of this chapter.
>
> **What Credential Guard does not protect.**
>
> Credential Guard prevents the *memory-resident* NTLM hash or Kerberos TGT from being read out of VTL0. It does not protect typed-in credentials, the agent-side relay surface, plaintext-secret protocols (CredSSP / NTLMv1 / MS-CHAPv2 / Digest), or liveness; the full four-item enumeration with citations lives in the Defender guidance later in this chapter. Microsoft documents one corner of the limit verbatim: Credential Guard *"doesn't prevent an attacker with malware on the PC from using the privileges associated with any credential"* [311].

The published confirmed trustlet roster stops at Trustlet IDs 0-3 from 2015. The set of VBS-backed security features on a 2026 box is larger, but Microsoft has not published which of those features are classic IUM trustlets with Trustlet IDs. That is one of the open problems the Open Problems section returns to.

## Documented reproducibility, not captured proof

A Reasoner should be able to separate four questions that get blurred in casual VBS discussions: is the VBS substrate running, is Credential Guard one of the services hosted there, is the isolated LSA trustlet present as a process the normal OS can see, and do ordinary VTL0 process-memory operations fail against that process? The supported verification surface is Windows' Device Guard CIM provider and the normal process table. This section is explicitly **🔵 DOCUMENTED reproducibility**: commands a reader can run and the expected shapes they should see, not a captured, hash-stamped lab artifact from this chapter. There is no captured evidence here, and the chapter should not be read as claiming a hash-stamped lab artifact.

The sequence below is therefore a *reproducibility ladder*. The first rung checks the platform mode. The second checks the security service. The third checks that the canonical agent/trustlet split is visible. The fourth explains the isolation property that a lab would demonstrate with a failed `ReadProcessMemory`, `VirtualAllocEx`, or `CreateRemoteThread` attempt. Without all four rungs, people talk past one another: a box can have VBS configured but not running, Credential Guard configured but not reported in `SecurityServicesRunning`, `LsaIso.exe` present but not understood as VTL1 user mode, or a visible process misread as an ordinary dumpable process.

> 🔵 **DOCUMENTED**: VBS and Credential Guard status via the supported Device Guard CIM provider.

```powershell
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard |
Select-Object VirtualizationBasedSecurityStatus, SecurityServicesRunning
```

Expected shape on a protected Windows 11 system:

```text
VirtualizationBasedSecurityStatus: 2
SecurityServicesRunning: {1, 2}
```

Microsoft documents `VirtualizationBasedSecurityStatus = 2` as VBS running and the security-services array as the place where Credential Guard and Hypervisor-Enforced Code Integrity are reported [311]. The exact integer-to-name rendering depends on the shell and tooling layer; the important distinction is configured versus running.

> 🔵 **DOCUMENTED**: isolated LSA trustlet process presence.

```powershell
Get-Process -Name LsaIso,lsass -ErrorAction Stop |
Select-Object Name, Id, Path
```

Expected shape when Credential Guard is active:

```text
Name Id Path
---- -- ----
LsaIso... C:\Windows\System32\LsaIso.exe
lsass... C:\Windows\System32\lsass.exe
```

The meaning is not that `LsaIso.exe` is secret. It is visible precisely because it is a process. The meaning is that ordinary process-memory APIs do not work against it as they do against `lsass.exe`; Microsoft states that `CreateRemoteThread`, `VirtualAllocEx`, and `Read/WriteProcessMemory` do not work as expected against trustlets [310].

> 🔵 **DOCUMENTED**: candidate trustlet signing and IUM identity check.

```powershell
sigcheck.exe -i C:\Windows\System32\LsaIso.exe
```

Expected shape on a Microsoft-signed isolated LSA binary:

```text
Verified: Signed
Signing date:...
Publisher: Microsoft Windows
Description: Credential Guard & Key Guard
```

The public trustlet gate is stricter than ordinary Microsoft signing: Ionescu's Windows 10 RTM analysis identifies Signature Level 12 plus both the Windows System Component Verification EKU and the IUM EKU as the required code-integrity condition [277]. Sigcheck is a practical first look; the architectural proof is the Secure Kernel load path described in the five gates above.

> 🔵 **DOCUMENTED**: VTL0 process-memory APIs are expected to fail against trustlets.

```powershell
# Do not run invasive memory probes against production credential infrastructure.
# In a lab, a minimal ReadProcessMemory/CreateRemoteThread/VirtualAllocEx probe
# against LsaIso.exe should be treated as a negative test: success would be
# the finding, failure is the documented trustlet behavior.
```

Microsoft documents the negative surface directly: `CreateRemoteThread`, `VirtualAllocEx`, and `Read/WriteProcessMemory` "will also not work as expected when used against Trustlets" [310]. That sentence is stronger evidence for the operational boundary than a screenshot of a failed toy dumper, because the exact error path varies by build, caller privileges, PPL state, EDR hooks, and whether the test process opens a handle before or after the trustlet's secure-process bit is observed. The invariant is not a particular Win32 error code; the invariant is that VTL0 cannot map the VTL1 pages.

These probes do not prove which unpublished trustlets are present on a given servicing build. They prove the part defenders can rely on through supported interfaces: the VBS substrate is running, Credential Guard is reported as a running security service, the canonical trustlet/agent split (`LsaIso.exe` beside `lsass.exe`) exists, and the documented VTL0 memory APIs are outside the supported access model. A current full roster still requires the research path discussed later: `NtQuerySystemInformation(SystemIsolatedUserModeInformation)` under conditions that let you inspect IUM metadata safely [312].

![Figure: The TEE landscape: six answers to protecting user-mode code from a compromised kernel, placed by isolation granularity (process / VM / firmware-core) and trust root (hypervisor / CPU microcode / dedicated core / proof). Windows trustlets occupy the process-granular, hypervisor-rooted corner.](diagrams/17-vbs-trustlets-tee-landscape.svg)

## Competing Approaches

Microsoft is not alone. The same threat model ("protect user-mode code from a compromised OS kernel") has been answered six other ways. None is strictly better than a trustlet. None is strictly worse. The right answer depends on what platform you are on, what threat model you have, and what workload you are trying to protect.

**Trusted Execution Environment (TEE).** A hardware-enforced or hypervisor-enforced execution context whose memory and state are inaccessible to the surrounding host operating system, including its kernel. The Open Mobile Terminal Platform (OMTP) first defined the term, and GlobalPlatform now publishes the standard APIs (TEE Client API for the host, TEE Internal Core API for the trusted code). Windows trustlets, Intel SGX enclaves, ARM TrustZone Trusted Applications, AMD SEV-SNP confidential VMs, Apple's Secure Enclave, and seL4 user-mode security servers are all variants of TEE [341].

### Intel SGX

Software Guard Extensions launched with the sixth-generation Intel Core processors (Skylake) in 2015 [342]. SGX adds two CPU instructions with different privilege requirements: `ENCLS` (ring 0; the OS issues leaves like `ECREATE` on behalf of a user-mode application) and `ENCLU` (ring 3; the application issues leaves like `EENTER` and `EEXIT` to enter and leave its enclave) [343]. The result is a user-mode-controllable enclave whose memory is encrypted on the way out of the CPU's Enclave Page Cache to DRAM. The CPU microcode itself, plus the Quoting Enclave, is the TCB. Neither the OS kernel nor the hypervisor sits in the trust path.

That sounded ideal in 2015. It has not aged well. Foreshadow (USENIX Security 2018, Van Bulck et al.) demonstrated that transient-execution attacks could extract not only enclave memory but the platform's attestation key [344]. The Foreshadow team's site states the consequence:

> **Source note.**
>
> Foreshadow demonstrates how speculative execution can be exploited for reading the contents of SGX-protected memory as well as extracting the machine's private attestation key... due to SGX's privacy features, an attestation report cannot be linked to the identity of its signer. Thus, it only takes a single compromised SGX machine to erode trust in the entire SGX system.: Foreshadow project site [290]

SGAxe (attestation-key extraction) [345], Plundervolt (software-controlled undervolting to fault SGX computations) [346], SgxPectre (branch-target injection across the enclave boundary) [347], and others followed. Intel deprecated SGX on 11th-generation Core and later client CPUs, which incidentally removed Ultra HD Blu-ray playback on officially licensed software including PowerDVD [342]. SGX continues on Xeon for confidential cloud workloads but is no longer a target architects pick on Windows clients.

> **Sidenote.**
>
> The Ultra HD Blu-ray collapse is the closest the SGX deprecation has come to mainstream visibility. PowerDVD's SGX dependency meant that a client SGX deprecation broke a consumer product line, and Cyberlink had to ship updates rerouting around the dropped CPU feature.

### AMD SEV-SNP and Intel TDX

AMD's Secure Encrypted Virtualization with Secure Nested Paging (SEV-SNP), introduced on EPYC 7003 (Milan, launched 15 March 2021) [348], and Intel's Trust Domain Extensions (TDX), introduced on 4th-generation Xeon Scalable (Sapphire Rapids, launched 10 January 2023) [349], provide *whole-VM* confidential computing [292] [293]. AMD's verbatim claim: *"SEV-SNP adds strong memory integrity protection to help prevent malicious hypervisor-based attacks like data replay, memory re-mapping, and more to create an isolated execution environment"* [292]. Intel's verbatim claim about TDX: *"A CPU-measured Intel TDX module enables Intel TDX. This software module runs in a new CPU Secure Arbitration Mode (SEAM) as a peer virtual machine manager (VMM)"* [293]. The AMD SEV-SNP whitepaper "Strengthening VM Isolation with Integrity Protection and More" is the canonical technical reference [350].

The granularity is different from a trustlet. SEV-SNP and TDX isolate an entire virtual machine from its hypervisor and host. They do not isolate a process from its own VM's kernel. For "this user-mode process should be protected from a SYSTEM kernel write primitive on the same OS," a trustlet is the primitive; for "this entire VM should be protected from a compromised cloud provider," a CVM is the primitive. Use the right one.

### ARM TrustZone and OP-TEE

The two-world hardware split that has shipped across Cortex-A-class systems since the mid-2000s is Arm TrustZone: Arm's architecture manual documents the Security Extensions model behind Secure and Non-Secure worlds, with monitor-mediated transitions between them [351]. The CPU enforces a Non-Secure World and a Secure World; switching between the two is mediated by a Secure Monitor Call (`SMC`) instruction. OP-TEE is the canonical open-source secure-world OS for Cortex-A TrustZone, with Trusted Applications running as user-mode binaries in Secure World EL-0 and the OP-TEE OS itself running at EL-1 [352]. The OP-TEE about page describes the design: *"OP-TEE is a Trusted Execution Environment (TEE) designed as companion to a non-secure Linux kernel running on Arm; Cortex-A cores using the TrustZone technology"* [352].

TrustZone is the closest non-Windows analog to a trustlet at the architectural level. The vocabulary maps one for one.

| Concept | Windows VBS / IUM | ARM TrustZone / OP-TEE |
|---------|--------------------|--------------------------|
| Isolation primitive | Hyper-V hypervisor + SLAT | TrustZone Address Space Controller; CPU NS/S bit |
| Secure-side kernel | Secure Kernel (VTL1 ring 0) | OP-TEE OS (Secure World EL-1) |
| Secure-side user mode | IUM (VTL1 ring 3) | Trusted Applications (Secure World EL-0) |
| Agent / supplicant | The trustlet's VTL0 agent (e.g., `lsass.exe`) | `tee-supplicant` and TEE Client API on the Linux side |
| Trust gate | Microsoft EKUs + Signature Level 12 | OP-TEE TA signing key configured at build time |

### Apple Secure Enclave processor (SEP)

Apple's answer is a dedicated on-die security subsystem. SEP is a separate processor core, isolated from the Application Processor on the same SoC, with its own boot ROM, its own AES engine, and its own random number generator. It has been in every iPhone since iPhone 5s (2013), every Apple Silicon Mac, every Apple Watch from Series 1 [62]. Apple's verbatim description:

> The Secure Enclave Processor runs an Apple-customized version of the L4 microkernel. It's designed to operate efficiently at a lower clock speed that helps to protect it against clock and power attacks [62].

SEP is the strongest counter to microarchitectural side channels among the production options, because the cores genuinely do not share microarchitectural state with the Application Processor. The price is that everything is firmware-class: patching a SEP bug means rolling SEP firmware on every Apple device, not pushing an OS update. The cycle is slower and more centralized.

### seL4 plus user-mode security servers

The academic conscience of the lineage. About 8,700 lines of formally verified C, with machine-checked proofs of functional correctness, confidentiality, and integrity [319] [321]. Sub-microsecond IPC. The price is that seL4 is a separation microkernel, not a desktop OS; building a Credential-Guard-equivalent on seL4 means designing the application architecture from the microkernel up, not retrofitting it onto a Windows-compatible stack. seL4 has shipping deployments in defense (the DARPA HACMS program), automotive ECUs, and the security subsystem of Qualcomm SoCs.

The comparison is useful because seL4 and VBS make opposite migration bets. seL4 says: make the kernel small enough to verify, then build the security-sensitive system as explicit user-mode components on top. The verifier's guarantee is extraordinarily strong, but the application must be shaped for the model from the beginning. Windows says: keep the enormous NT compatibility universe in VTL0, introduce a second kernel and a small VTL1 user-mode world beside it, and move only the secrets that cannot survive a VTL0 compromise. The guarantee is narrower (no proof of the Secure Kernel, no proof of the trustlet code, an unverified secure-call parser) but the migration path is viable for hundreds of millions of existing Windows systems.

If you were designing a missile controller, seL4's proof story would dominate. If you are protecting LSASS credentials on laptops that must still run Win32 applications, domain join, EDR, Hyper-V, drivers, and twenty years of enterprise management tooling, a formally verified replacement OS is not an option. Trustlets are the pragmatic middle: not verified minimalism, but a surgically inserted higher-privilege user mode whose TCB is smaller than all of NT and whose deployment cost is small enough to ship by default.

### When to pick which

A decision table of the kind a colleague would actually use.

| You want | Pick |
|----------|------|
| Protect a user-mode Windows process from a SYSTEM kernel write primitive | Trustlet (inbox) or VBS Enclave (third-party) [280] |
| Protect an entire VM from your cloud provider's host | AMD SEV-SNP or Intel TDX [292] [293] |
| Protect a user-mode Linux-on-ARM service from a compromised Linux kernel | TrustZone + OP-TEE Trusted Application [352] |
| Hold an iPhone owner's Touch ID / Face ID template safely from iOS | Apple SEP [62] |
| Build a high-assurance system with a machine-checked proof of kernel correctness | seL4 [319] |
| Run Intel SGX enclaves on Xeon for confidential cloud | SGX (modulo Foreshadow-class side channels) [290] |

Trustlets are the right answer for Windows. They are not the right answer for every platform, every threat model, or every workload. They are also not without limits *on Windows itself*. What are those?

## Where this link breaks: The floor of the threat model

By 2020 the trustlet model had been shipping for five years. Two researchers at the Microsoft Security Response Center, Saar Amar and Daniel King, pointed a fuzzer at the secure-call interface for two weeks and reported back with five VTL0-to-VTL1 bugs [295]. Their Black Hat USA 2020 talk, "Breaking VSM by Attacking Secure Kernel," is the most important public document on what the trustlet model actually guarantees and what it does not [296].

The talk is honest in a way Microsoft is rarely honest about its own products. The slides enumerate the bugs by CVE number, name the specific Secure Kernel routines they exploited, and (unusually) list the hardening changes Microsoft shipped because of what was found. Reading the deck is the closest thing to a Q-and-A with the Secure Kernel team.

### Bug class 1: the secure-call interface is the floor

The Secure Kernel exposes about three dozen "secure services" callable from VTL0 via the `IumInvokeSecureService` dispatcher. Each takes a parameter block from VTL0, parses it inside VTL1, and returns. That dispatcher is, by definition, the largest VTL0-controllable input surface in the model. Amar and King retargeted the Hyperseed hypercall fuzzer, originally written by Daniel King and Shawn Denbow for hypercall fuzzing, at `securekernel!IumInvokeSecureService` [295]. Two weeks of fuzzing produced five bugs.

Two of them shipped with public CVE numbers in 2020. CVE-2020-0917 is an out-of-bounds read in the secure-call surface; CVE-2020-0918 is a design flaw in `SkmmUnmapMdl` where a VTL0 caller could pass a fully attacker-controlled Memory Descriptor List to `SkmiReleaseUnknownPTEs` [353] [354] [295]. The NVD entries describe both with the same boilerplate ("Windows Hyper-V Elevation of Privilege Vulnerability") and classify the CWE as "Insufficient Information"; the technical detail lives in the Amar/King deck.

Microsoft hardened in response. The Amar/King deck enumerates what changed:

- The Secure Kernel pool moved to segment heap in mid-2019, breaking the heap layout the public exploit depended on.
- Four W+X regions in VTL1 were reduced to +X only, eliminating attacker-controlled code-injection targets.
- `SkpgContext`, a HyperGuard-style control-flow integrity check for the Secure Kernel, was introduced [295].

**Malwarelet.** Alex Ionescu's term for an attacker-controlled trustlet, enabled by a substrate compromise rather than a trustlet bug. If Test Signing is on, or if a production Microsoft signing key leaks, or if Secure Boot can be bypassed, an attacker can sign and load their own "trustlet" that passes the five gates described earlier and operates with VTL1 privilege. The trustlet model itself remains intact; the trust roots underneath it are what fail [277].

### Bug class 2: denial of service is not a security boundary

Amar's deck states the rule that excludes liveness from the VBS threat model verbatim:

> **Source note.**
>
> VTL0 can DOS VTL1 by design.: Saar Amar and Daniel King, Black Hat USA 2020 [295]

The hypervisor schedules VTL1; VTL0 is the agent for almost every communication channel into VTL1; VTL0 can stop talking to VTL1 at any time. None of this is, in Microsoft's stated model, a security violation. A VTL0 kernel attacker who can prevent Credential Guard from issuing tickets has not stolen any credential; they have, in the language of the threat model, achieved denial of service, which is out of scope. This matters in practice: a defender cannot reason about a trustlet "always being available." They can only reason about its memory not being readable from VTL0 *when it is available*.

### Bug class 3: the agent RPC surface lives in VTL0

The trustlet's pages are safe even from VTL0 ring 0. The agent process that services the trustlet's ALPC port is *not* safe. The agent is `lsass.exe` for Credential Guard, `vmwp.exe` for the vTPM, presumably the Hello biometric pipeline for ESS. Every byte of every protocol whose state machine the agent implements is reachable from VTL0. The hash never leaves VTL1; the *authentication outcomes* the hash produces can be relayed.

In December 2022 Oliver Lyak published "Pass-the-Challenge: Defeating Windows Defender Credential Guard" [337]. The technique recovers usable NTLM challenge responses from encrypted credential blobs that `LsaIso.exe` returns to `lsass.exe` in VTL0:

> In this blog post, we present new techniques for recovering the NTLM hash from an encrypted credential protected by Windows Defender Credential Guard. While previous techniques for bypassing Credential Guard focus on attackers targeting new victims who log into a compromised server, these new techniques can also be applied to victims logged on before the server was compromised [337].
>
> **Pass-the-Challenge in one paragraph.**
>
> A network authentication protocol that uses NTLM works in challenge-response form: the server sends a challenge, the client encrypts it with its NTLM hash, the server (or a domain controller) verifies the response. With Credential Guard, the client's NTLM hash lives in `LsaIso.exe`; only `LsaIso.exe` can perform the encryption. A VTL0 attacker who can talk to `lsass.exe` can ask `lsass.exe` to ask `LsaIso.exe` to compute an NTLM response for an attacker-supplied challenge. The attacker never sees the hash; they see an authentication response computed with it. Many real-world relay attacks need only the response, not the hash. Lyak's writeup is the worked example; the architectural fact is that the agent RPC channel is a VTL0 surface even though the hash itself is not.

Microsoft documents one corner of the limit verbatim: Credential Guard *"doesn't prevent an attacker with malware on the PC from using the privileges associated with any credential"* [311]. The "use" is the agent-side operation; the trustlet is doing the cryptography, and the cryptography is being used by the attacker.

### Bug class 4: trustlet-to-trustlet via shared Instance GUIDs

Trustlets that share an Instance GUID can participate in the same per-instance storage namespace. The legitimate example is the vTPM pair: Trustlet ID 3 provisions initial state for a partition GUID; Trustlet ID 2 (`vmsp.exe`) later reads and services that partition's vTPM. The mechanism is powerful because the Instance GUID is deliberately not globally unique per Trustlet ID. It names an object instance, while the Trustlet ID names the class of code allowed to perform a particular operation on that object.

The exact proof obligation is therefore: every Secure Kernel operation that touches per-instance trustlet storage must authorize the tuple `(operation, caller Trustlet ID, Instance GUID)`, not merely the GUID. A correct rule says, for example, "ID 3 may call `SecureStorageSet` for this provisioning lifecycle" and "ID 2 may call `SecureStorageGet` for this runtime vTPM lifecycle." An incorrect rule says only "the caller supplied the partition GUID" or only "the caller is an IUM process." The latter two checks create trustlet-to-trustlet confusion: a caller that can bind or guess the same Instance GUID becomes a storage peer even though it is the wrong trustlet class for the operation.

A concrete failure path would require three ingredients. First, the attacker needs execution as a trustlet or trustlet-equivalent caller. That is already outside the ordinary VTL0-kernel-attacker model unless obtained through Test Signing, Secure Boot/signing compromise, a malicious Microsoft-signed IUM binary, or a VTL0-to-VTL1 bug that creates a malwarelet. Second, the attacker needs a victim Instance GUID, such as a Hyper-V partition GUID whose vTPM material is stored under that namespace. Third, `SkCapabilities` or an adjacent secure-storage check must fail to discriminate the caller's Trustlet ID and operation. With those ingredients, the attacker does not need to read raw `vmsp.exe` memory. It can ask the Secure Kernel for storage access under the victim GUID and receive or overwrite blobs the victim trustlet class should have owned.

That is a documented proof obligation, not a claimed public exploit. As of mid-2026, this chapter is not aware of a public CVE whose root cause is "shared Instance GUID allowed trustlet-to-trustlet storage confusion." The public record does show the primitive (shared Instance GUIDs plus `CheckByTrustletId 2`/`CheckByTrustletId 3` rules in the 2015-era surface [277]) and the malwarelet risk from a broken trust root. The honest conclusion is narrow: the design is safe only if the capability table and lifecycle checks are complete; no public exploit proves they are incomplete, and no public audit proves they are complete.

### Bug class 5: substrate compromise (Secure Boot, firmware, signing keys)

If Test Signing is on; if a production signing key leaks; if Secure Boot can be bypassed to boot a kernel that accepts attacker-controlled trustlet roots; if the UEFI firmware itself permits a DMA attack against early-boot memory: the entire trustlet model is moot. Ionescu's BH2015 deck states the diagnosis: *"VBS' key weakness is its reliance on Secure Boot"* [277]. Rafal Wojtczuk's Black Hat USA 2016 attack-surface analysis empirically validated the warning, demonstrating one non-critical VBS-feature bypass and one critical firmware exploit [278]. The firmware below VBS is the substrate trustlets sit on; the trustlet model is no stronger than that substrate.

![Figure: Five ledges below the VTL1 memory wall. The residual surface the trustlet model leaves open even though VTL0 cannot map VTL1 pages: the secure-call parser, designed-out denial of service, the agent RPC channel, trustlet-to-trustlet storage, and the substrate.](diagrams/17-vbs-trustlets-five-ledges.svg)

> **Walkthrough: where an attacker can still stand.**
>
> Draw the system as five ledges rather than one wall. On the first ledge, VTL0 calls into `securekernel!IumInvokeSecureService`; every parameter block parsed there is attacker-controlled input if the NT kernel is compromised, which is why Amar and King found real VTL0-to-VTL1 bugs in two weeks [295]. On the second ledge, VTL0 can starve or stop the agent path; this is denial of service, and Microsoft explicitly excludes it from the confidentiality boundary. On the third ledge, the VTL0 agent remains usable even when the trustlet's memory is not: Pass-the-Challenge asks LSASS to ask `LsaIso.exe` for an authentication result, not for the hash [337]. On the fourth ledge, cooperating trustlets share an Instance GUID, so `SkCapabilities` must keep set/get authority separated by Trustlet ID. On the bottom ledge, Secure Boot, firmware, Test Signing state, and signing keys decide whether the five gates mean anything at all. The wall is real; these ledges are where research and defense still happen.
>
> **Sidenote.**
>
> The Hyperseed fuzzer had a prior life. Daniel King and Shawn Denbow first presented it at OffensiveCon 2019 as a hypercall fuzzer [295]. The retargeting at the secure-call interface is the same tool, pointed at a different parser. The two-weeks-five-bugs result is therefore not "Microsoft wrote bad code" but "a well-built fuzzer aimed at a complex parser will find bugs in ~2 weeks." That is the empirical bar for an unverified TCB.
>
> **Key idea.**
>
> The trustlet model is hypervisor-strong against the VTL0 kernel; it is not stronger than the substrate it sits on. Five attack classes: secure-call interface bugs, designed-out denial-of-service, the agent RPC residual, trustlet-to-trustlet via shared Instance GUIDs, and substrate compromise: bound what the model can guarantee. None of them invalidates trustlets; all of them are reasons to deploy trustlets *alongside* other controls rather than as a sole defense.

The trustlet model has a finite, studied, and hardened attack surface. The surface is not zero. Liveness is not promised. The firmware and Secure Boot underneath everything still matter. What is new on this surface in 2024 to 2026?

## Open Problems

Three things you might expect Microsoft to have published by 2026 are still partial or missing: the current inbox trustlet roster, an architecture diagram of Administrator Protection on par with Credential Guard's, and a public CVE wave around VBS Enclaves. Here is the frontier.

**1. Trustlet enumeration drift.** Ionescu's August 2015 enumeration of Trustlet IDs 0 through 3 remains the only authoritative published list. As of 2026, the ESS biometric matcher has not been named with a Trustlet ID and the Administrator Protection issuer has not been committed to as a trustlet at all. A researcher with a debugger and the Quarkslab IUM-debugging recipe can recover the current roster empirically [312]; Microsoft has not republished it.

**2. VBS Enclave trust-boundary hardening.** Microsoft's Security Response Center published a blog post in June 2025 ("Everything Old Is New Again") explicitly committing to host-to-enclave pointer validation, copy-before-check discipline, and TOCTOU avoidance as the active hardening surface for VBS Enclaves [283]. The post is unambiguous that a CVE wave is foreseeable as researchers turn their attention to the host-enclave seam. As of mid-2026 no public CVE has been issued against a VBS Enclave-using product, but Microsoft's narrowing of supported Windows builds in 2025 (from "Windows 11 24H2 or later" to "Windows 11 Build 26100.2314 or later") is the kind of build-floor adjustment that historically precedes a documented hardening change [280].

**3. Side channels against VTL1.** Transient-execution attacks against VTL1 memory have not been publicly demonstrated end to end. The Foreshadow class of attacks against SGX is the existence proof that a co-resident TEE can leak through microarchitectural side channels, and the threat model explicitly includes them [290]. There is no VBS-specific transient-execution mitigation; platform-wide mitigations (Kernel Virtual Address Shadow, Retpoline, Indirect Branch Restricted Speculation) are the only defense. A demonstration of "Foreshadow-against-LsaIso" would not be surprising; its absence to date is, given the research community's interest, mildly so.

**4. Debugging asymmetry.** Researchers have a working trustlet-debugging recipe; defenders have an explicit "no" from Microsoft. The Quarkslab writeup walks through nested virtualization to attach to a trustlet under controlled conditions [312]; Microsoft's product-facing page states verbatim that *"it is not possible to attach to an IUM process"* and that *"other APIs, such as CreateRemoteThread, VirtualAllocEx, and Read/WriteProcessMemory will also not work as expected when used against Trustlets"* [310]. The asymmetry favors offense: an attacker with the time, hardware, and tooling Quarkslab demonstrates can study trustlet internals in ways a defender on a production box cannot. Live-system trustlet introspection for incident response is the missing capability.

**5. Administrator Protection transparency.** As of 10 May 2026, the Administrator Protection feature has been shipped in preview (KB5067036, 28 October 2025), then reverted in the same update note pending a future re-rollout [340] [323]. There is no architecture diagram on the level of Credential Guard's "how it works" page. There is no published Trustlet ID. There is no public commitment to whether the token issuer is a trustlet, a VBS Enclave, or something else inside the new security boundary. For a feature that materially changes the local-elevation model of Windows, that is unusual reticence.

**6. Cross-architecture portability.** A workload that wants to run as a trustlet on Windows, a Confidential VM on Linux, a Trusted Application on ARM, and a Secure Enclave Application on Apple silicon must, today, be written four times. GlobalPlatform's TEE Client API standardizes one side of TrustZone, the Open Enclave SDK abstracts a subset of SGX and TrustZone, and VBS Enclaves do their own thing. No universal portable TEE API exists. For workloads where portability matters more than peak isolation, this is the open problem with the most direct commercial pressure behind it.

> **Why no current trustlet roster?**
>
> Two answers, both incomplete. The defensive answer: an enumerated trustlet list is an attacker's targeting list, and Microsoft prefers not to publish targeting lists for components whose exact attack surface is still under active study. The historical answer: the 2015 list was a side-effect of Ionescu reverse-engineering Windows 10 RTM. There has been no comparable public reverse-engineering push for any post-2015 Windows release at the same level of completeness, and Microsoft has not chosen to fill the gap with first-party documentation. Empirical enumeration via `NtQuerySystemInformation(SystemIsolatedUserModeInformation)` works on a live system, but doing it on every Windows 11 servicing build is a research program, not a citation.

These are questions a researcher with a year of grant time could move the field on. The practitioner's question is more immediate.

## What it means for you: Practitioner guide

What changes in a real workflow once you know what a trustlet is? Four short answers, each with a different failure mode. Administrators must verify *running state*, not marketing names. Researchers must enumerate and debug without confusing visible process objects for readable memory. Application developers must use VBS Enclaves rather than trying to acquire inbox-trustlet powers they cannot be issued. Defenders must move detections to the places VTL0 can still see: agents, protocol use, configuration drift, and failed assumptions about Credential Guard.

The practical rule is: do not treat "VBS enabled" as a Boolean blessing. Ask which component is isolated, which agent remains in VTL0, which API crosses the boundary, and which residual attack class applies. A mature operational checklist names all four.

### Windows administrator

Verify Credential Guard is actually running before you assume it is. Two ways.

> **Quick verification.**
>
> **GUI:** Run `msinfo32` and check *Virtualization-based security Services Running*. You should see at least "Credential Guard" and ideally "Hypervisor enforced Code Integrity."
> **PowerShell:** `Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard`. The properties `SecurityServicesRunning` and `VirtualizationBasedSecurityStatus` are the load-bearing ones; values of 1 and 2 respectively indicate Credential Guard is running with VBS in full enforcement [311].

Enumerating live trustlets on a 2026 box requires more care than enumerating ordinary processes. Process Explorer's *Image* tab carries an IUM marker for trustlet processes. SysInternals Sigcheck on a candidate binary surfaces the Signing Level. The Microsoft Learn IUM page is explicit that *"other APIs, such as CreateRemoteThread, VirtualAllocEx, and Read/WriteProcessMemory will also not work as expected when used against Trustlets"* [310]: the same APIs many EDR products rely on for behavioral monitoring will silently fail or report sentinel values when targeted at a trustlet. Plan detections accordingly.

### Security researcher

The Quarkslab blog post "Debugging Windows Isolated User Mode (IUM) Processes" is the canonical recipe for attaching to a trustlet under nested virtualization [312]. The empirical enumeration path is `NtQuerySystemInformation` with class `SystemIsolatedUserModeInformation`, an undocumented information class known from reverse engineering rather than a supported Microsoft API; the structure returned includes a count of running trustlets and their identifying metadata.

A serious research workflow has three phases. First, enumerate without perturbing: collect the Device Guard CIM state, the ordinary process list, candidate binaries' signing metadata, and `SystemIsolatedUserModeInformation` output on the exact Windows build under study. Second, map the boundary: identify the VTL0 agent, its ALPC endpoints, the request structures that cross into VTL1, and any documented unsupported APIs that should fail against the trustlet. Third, debug in a sacrificial nested-virtualization lab, not on a production host, because the very act of enabling the required debugging path changes assumptions defenders rely on.

The targets are also different by layer. Fuzzing `IumInvokeSecureService` is secure-kernel research; fuzzing `LSA_ISO_RPC_SERVER` request shapes is agent/trustlet protocol research; auditing `SkCapabilities` is cross-trustlet authorization research; studying Test Signing and Secure Boot bypasses is substrate research. Mixing these layers produces bad claims. A VTL0 ALPC bug may defeat Credential Guard operationally without ever reading `LsaIso.exe` memory. A secure-call bug may pierce VTL1 without touching LSASS. A firmware bypass may make the five gates meaningless by letting the attacker create a malwarelet. Name the layer before you name the vulnerability.

> **Sidenote.**
>
> The driver-side pattern Microsoft documents for "is this process a trustlet?" reads the `IsSecureProcess` flag from `PROCESS_EXTENDED_BASIC_INFORMATION`, queried through `ZwQueryInformationProcess` with `ProcessBasicInformation`; the IUM page presents this as sample code, not a callable `IsSecureProcess` API. Tools that need to behave differently against trustlets (memory scanners, integrity checkers, EDR sensors) should use that documented query rather than parsing process attributes by hand [310].

### Application developer (VBS enclaves)

If you are writing third-party code that needs trustlet-class isolation, the primitive you target is a VBS Enclave, not a trustlet. The toolchain is specific:

- Visual Studio 2022 version 17.9 or later.
- Windows SDK version 10.0.22621.3233 or later (provides `veiid.exe`, the VBS Enclave import ID binding utility, and `signtool.exe`).
- A Trusted Signing account for production signing [280].

The architectural rule is *never trust the host*. The host process's address space is reachable by the enclave; the enclave's address space is not reachable by the host. Range-validate every pointer the host hands the enclave; copy before you check (so the host cannot mutate the data between your check and your use); avoid TOCTOU windows. Microsoft's "Everything Old Is New Again" post is explicit that this is the hardening surface researchers are looking at right now [283].

The development guide includes a sample with a comment that captures the discipline:

> Every DLL loaded in an enclave requires a configuration. This configuration is defined using a global const variable named __enclave_config of type IMAGE_ENCLAVE_CONFIG... // DO NOT SHIP DEBUGGABLE ENCLAVES TO PRODUCTION [282].

The `IMAGE_ENCLAVE_POLICY_DEBUGGABLE` flag is for development only. The `VbsEnclaveTooling` repository on GitHub provides a NuGet package and a code generator that make the cross-VTL marshalling less error-prone, plus reference documentation including `Edl.md`, `HelloWorldWalkthrough.md`, and `CodeGeneration.md` [309].

> **Minimal VBS Enclave development checklist.**
>
> 1. Confirm OS support: Windows 11 Build 26100.2314+ or Windows Server 2025+ [280].
> 2. Install Visual Studio 2022 17.9+ and Windows SDK 10.0.22621.3233+.
> 3. Acquire a Trusted Signing account; configure `signtool.exe` for it.
> 4. Define `__enclave_config` as `IMAGE_ENCLAVE_CONFIG`; set family/image/SVN fields.
> 5. Use `veiid.exe` to bind import IDs.
> 6. Sign the enclave DLL with `signtool.exe` and the Trusted Signing certificate.
> 7. Test with `IMAGE_ENCLAVE_POLICY_DEBUGGABLE` set; remove it before production.
> 8. Range-validate every host-supplied pointer; copy before check.

### Defender

Know what Credential Guard does *not* protect, because that is where most exposure remains.

> **What Credential Guard does NOT protect.**
>
> The trustlet protects memory-resident NTLM hashes and Kerberos TGTs from a VTL0 kernel attacker. It does not protect:
>
> - Supplied credentials at the logon prompt (keyloggers, screen-scrapers, hardware shimming).
> - The agent RPC channel (Pass-the-Challenge-class relay against `lsass.exe` is reachable from VTL0) [337].
> - Protocols that require a usable secret in plaintext: CredSSP, NTLMv1, MS-CHAPv2, Digest. These are unsupported with the trustlet-protected token by design [311].
> - Liveness: a VTL0 kernel attacker can stop talking to VTL1 and prevent the trustlet from being available. Denial of service is out of the VBS threat model [295].
>
> The summary: trustlets shrink the credential-theft attack surface, they do not eliminate it.

The trustlet model is finite, studied, hardened, and useful. Use the lock; do not assume the lock is the only thing on the door.

> **Bequeaths.** Trustlets hand the rest of the chain one load-bearing primitive: a *named, gated, hypervisor-isolated user-mode process*. Five load-time gates, a VTL1 address space VTL0 cannot read, and a VTL0 agent that carries all the messy integration with the rest of Windows. The Credential Guard chapter (Chapter 15) is the first thing that stands on it: `LsaIso.exe` is Trustlet ID 1, and every claim that chapter makes about an unreadable NTLM hash reduces to "the trustlet model holds." The Hyper-V vTPM pair (`vmsp.exe` and its provisioning peer) stands on the same model with a second axis added: the per-partition Instance GUID. But the bequest is deliberately narrow, and naming what it does *not* hand on is the honest half of the gift. It does NOT promise *liveness*: a VTL0 kernel can refuse to schedule or talk to VTL1, and denial of service is out of the threat model by design. It does NOT promise anything about what the agent *does* with the secret: the trustlet computes; the VTL0 agent still relays the result, which is exactly the seam Credential Guard's Pass-the-Challenge residual lives in. It does NOT open VTL1 user mode to third parties. That is what VBS Enclaves are for. And it is no stronger than the Secure Boot and firmware substrate (Chapter 1) the five gates rest on. The chain gains a place to *put* a secret; it does not yet make every *use* of that secret safe.
