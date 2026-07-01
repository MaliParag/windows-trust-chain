# Process Mitigation Policies

::: trust-ledger

- **Inherits:** image-signing enforcement. User-Mode Code Integrity refuses to map any image that does not chain to a Microsoft-trusted root (Chapter 8, Code Integrity); the kernel code-integrity (HVCI / KMCI) that keeps the very kernel installing these policies un-rewritable (Chapter 8, Code Integrity).
- **Promise:** In a process that opts into the full `SetProcessMitigationPolicy` recipe, a surviving memory-corruption bug cannot be turned into code execution by the *classic* primitives. No injected shellcode (DEP), no predictable gadget base (ASLR), no hijacked indirect call (CFG), no hijacked return (CET shadow stack), no runtime-generated code (ACG), and no unsigned image load (CIG). Serviced boundary: this surface is *defense-in-depth*, not a security boundary. By the Microsoft Security Servicing Criteria a CFG or ACG bypass *by itself* is not guaranteed a patch; what it hardens is the process and the kernel syscall edge.
- **TCB:** The MSVC instrumentation (`/guard:cf`, `/CETCOMPAT`), the `ntdll` loader and `LdrpValidateUserCallTarget`, the per-process CFG bitmap, the CPU's CET shadow-stack hardware, UMCI for CIG, and the kernel that installs the policy before the child's first user-mode instruction. Everything below the syscall boundary is explicitly outside it.
- **Adversary → Break:** The bug is still there. CFG is coarse-grained, so COOP reuses prototype-compatible function entries; CIG is a publisher check, not a content check, so signed-but-vulnerable DLLs still load; and Data-Oriented Programming never hijacks control flow at all, so no CFI variant can see it. The Promise ends at the *exploit chain*, not the *bug*.
- **Residual:** Signed-but-vulnerable image load → App Control (Chapter 13, AppLocker vs App Control) and the curated kernel block list in Code Integrity (Chapter 8); what a signature actually proves → Authenticode (Chapter 12, Authenticode and Catalog Files); the kernel surface beneath the syscall: kCFG, kCET, the HVCI-isolated bitmap in VTL1 → Code Integrity (Chapter 8) and VBS Trustlets (Chapter 7); the memory-safety bug itself (the ~70% mitigations only delay) → the long-term language and hardware answer (Rust, MTE, CHERI) collected in the open problems.
- **Bequeaths:** "Only an image that chains to an allowed signing root may execute in this process". The floor the Authenticode chapter (Chapter 12) builds on when it asks what that signature actually proves. Does NOT provide: a fix for the memory-safety bug, defense against data-only attacks, immunity from signed-but-vulnerable code, or any guarantee past the syscall boundary.
- **Proof:** 🔵 documented. `SetProcessMitigationPolicy` / `PROCESS_MITIGATION_POLICY` (Microsoft Learn), Miller's Edge ACG blog, the CET/CFG/XFG primary decks; this chapter carries no live-VM capture, so nothing here is upgraded to a captured (green) block.
:::

> **The Reasoner's question.** When a memory-corruption bug still exists, which exploit primitives do CFG, ACG, CIG, CET, and the rest of the mitigation surface take away, and which primitives survive?

---

> **Foundations. What you need before this chapter.**
>
> - **Process mitigation policy.** A per-process security contract exposed through `SetProcessMitigationPolicy`, `GetProcessMitigationPolicy`, `UpdateProcThreadAttribute`, PowerShell `Get-ProcessMitigation`, and the Defender Exploit Protection policy surface.
> - **Forward edge / backward edge.** The forward edge is an indirect call or jump from one legitimate instruction to another. The backward edge is a return. CFG and XFG constrain the forward edge; CET shadow stack constrains the backward edge.
> - **W^X.** Write XOR execute: a page should be writable or executable, never both. DEP gives Windows the page-level foundation; ACG raises the rule to the lifetime of a process.
> - **Code identity.** CIG does not ask whether code is safe. It asks whether the image being mapped chains to an allowed signing authority. That distinction is why signed-but-vulnerable binaries remain a gap.
> - **Reasoner stance.** Bypasses in this chapter are gap analysis, not instructions. The goal is to know what the link guarantees, what it cannot guarantee, and what evidence you can demand from a live system.

---

Windows ships every modern memory-corruption mitigation as a per-process flag rather than a system-wide setting: because Outlook can't enable CIG, Defender can't enable ACG, and Notepad doesn't need Disable-Win32k. `SetProcessMitigationPolicy` exposes twenty of these knobs (plus a `MaxProcessMitigationPolicy` sentinel that terminates the enum); the canonical six (DEP, ASLR, CFG, CET shadow stack, ACG, CIG) constrain the control-flow primitives, and the other fourteen cover adjacent attack surfaces. Each knob is a tombstone for an exploit primitive that worked in the previous generation. This chapter walks the thirty-year arc that built that surface, then names the residual attacks that survive even a fully-stacked process.

## The bug is still there. Why didn't the exploit work?

A vulnerability researcher has just landed a type-confusion bug in a JavaScript engine inside an Edge content process. The primitive is exactly what they expected: a writable heap address holding a corrupted vtable pointer. From that pointer the renderer will, on its very next virtual-method call, jump into an address the attacker chose.

That is supposed to be game over. It is, in the language of every exploit-development textbook from 1996 onward, a working write-what-where. The CPU loads the corrupted pointer into a register. It dereferences it. It calls.

And the process dies.

There is no shell. There is no remote code execution. There is a Windows Error Reporting dialog showing `STATUS_STACK_BUFFER_OVERRUN` (`0xC0000409`), the NTSTATUS surfaced by the CFG validator's `__fastfail(FAST_FAIL_GUARD_ICALL_CHECK_FAILURE)` subcode, raised from a thunk named `ntdll!LdrpValidateUserCallTarget` the researcher has never seen in their disassembler before [462]. The bug fired exactly as the recipe said. The exploit chain didn't.

What stopped it?

> **The load-bearing claim of this chapter.** Every per-process mitigation in `SetProcessMitigationPolicy` is a tombstone for an exploit primitive that worked in the previous generation. The list of policies is, read top to bottom, an attacker's autobiography [463].

> **Definition: Process Mitigation Policy.** A per-process, opt-in security policy installed via the Win32 `SetProcessMitigationPolicy` API (or, more safely, via `UpdateProcThreadAttribute` before a child process executes its first user-mode instruction). The `PROCESS_MITIGATION_POLICY` enum lists twenty-one values (nineteen attacker-facing mitigation policies, the `ProcessMitigationOptionsMask` discovery value, and the `MaxProcessMitigationPolicy` sentinel that terminates the enum) as of Windows 11 24H2. Each mitigation is a separate axis on which an exploit can fail [464,463].

The fastest way to see this is to compare two PowerShell sessions. Pick a maximally-hardened process, the Edge content process, and run `Get-ProcessMitigation -Name msedge.exe`. Six mitigations show as ON: CFG, CET shadow stack, ACG, CIG, Disable-Win32k, and Disable-Extension-Points. Now do the same for `Notepad.exe`. One or two show as ON. Notepad is a different *kind* of process. It is not parsing attacker-controlled bytes from the public internet, so the mitigation surface it carries is correspondingly small.

> **Margin note.** The mitigation set is not just an enable-everything list. Several of the policies are mutually expensive (CET costs cycles on every call/ret; ACG forbids any in-process JIT; CIG forbids any third-party plugin); turning them all on is only viable for a process whose owner accepts those costs. The PowerShell `Set-ProcessMitigation` and `Get-ProcessMitigation` cmdlets ship in the `ProcessMitigations` module that succeeded EMET in 2018.

Edge carries six mitigations because it has six structurally separate ways the attacker can win. CFG addresses the indirect-call hijack. CET addresses the return-address hijack. ACG addresses the "redirect the JIT to emit my shellcode" hijack. CIG addresses the "plant a Microsoft-signed DLL where the loader picks it up" hijack. Disable-Win32k addresses the renderer-to-kernel escape. Disable-Extension-Points addresses the `AppInit_DLLs`-class injection.

Each one is the closing footnote on a different generation of offensive research. CFG closes indirect-call hijacking. CET closes the shadow-stack-less era. ACG closes JIT spray. CIG closes signed-DLL planting. `Get-ProcessMitigation` lays them out as a flat list of `ON` checkmarks, as if they had always been there: as if they had not each cost a decade of research to design and ship.

So the chain failed. But *which* mitigation caught the indirect-call hijack we started with, and why was that one on? Where do these mitigations come from, and how did Windows arrive at this exact set? To answer that, we have to go back three decades.

## How attackers stopped being able to put bytes on the stack and run them

The story starts in November 1996. *Phrack* magazine, issue forty-nine, file fourteen of sixteen. Aleph One (the handle of Elias Levy, a security columnist who would later moderate the BugTraq mailing list) publishes *Smashing The Stack For Fun And Profit* [465]. The article is a recipe. It walks the reader through process memory layout on Unix, the structure of the call stack on x86, the mechanics of overwriting the saved return address, the construction of `/bin/sh` shellcode, and the use of NOP sleds. Those four programs (`syslog`, `splitvt`, `sendmail 8.7.5`, Linux/FreeBSD `mount`) appear in the introduction as real overflows others had found; the paper's own worked exploit code targets a small sample vulnerable program that, installed setuid root, would have yielded a root shell.

Buffer overflows existed before Aleph One. The 1988 Morris Worm used one in `fingerd`; Mudge's 1995 *How to Write Buffer Overflows* L0pht paper had pieces of the technique. But it was an oral tradition: something you learned at DEFCON or from someone who learned it at DEFCON. Aleph One's contribution was pedagogical: a step-by-step recipe anyone with a debugger and an afternoon could follow. Once that recipe was published, every memory-safety bug in C and C++ (and there were many) became a candidate for shell-as-the-vendor.

The defensive response came fast, and it came with a brutal honesty that has shaped every later mitigation. In August 1997, Alexander Peslyak, writing under the handle Solar Designer and running the Openwall Project, posted to BugTraq [466]. He had two things. The first was a Linux kernel patch (still documented at the Openwall README to this day) that made user-mode stack pages non-executable in software, since AMD's hardware NX bit was six years away [467]. The second was a working return-into-libc exploit against `lpr`, which redirected execution into `system()` in the C library rather than into stack-resident shellcode.

> **Note.** Solar Designer was honest enough to publish the bypass on the same day as the patch. This is a defender-publishes-own-bypass precedent that has governed almost every Microsoft mitigation announcement since: ship the mitigation, name the residual attack class, set the expectation that the mitigation is a speed bump rather than a fix.

> **Definition: W^X.** A memory protection invariant ("write XOR execute") requiring that any page in the process address space be either writable or executable, but never both at the same time. PaX shipped the first complete Linux implementation of non-executable user pages in 2000; the name *W^X* came from OpenBSD's 2003 articulation of the same invariant; AMD's NX bit in 2003 moved it from software emulation to hardware enforcement; the per-process ACG policy in Windows generalizes W^X to apply for the lifetime of an entire process, with no per-thread escape hatch.

The next move was structural. In September 2000 the pseudonymous PaX Team released PAGEEXEC, the Linux non-executable-page implementation that made every writable page non-executable (not just the stack), using clever x86 segment-limit and split-TLB tricks [468]. PaX is also where the term "ASLR" comes from. The July 2001 PaX patch series randomized the executable base, the stack, the heap, the `mmap`'d library region, and (with `RANDEXEC`) even the position of the executable's code segment. The PaX design document for ASLR is unusually rigorous about probability. It derives the expected number of brute-force attempts as a function of entropy bits, decades before anyone framed it that way in the academic literature.

> **Definition: ASLR.** Address Space Layout Randomization. Per-boot or per-load randomization of the locations at which the kernel maps modules, the stack, the heap, and `mmap`'d regions into a process's virtual address space. On x86-32 Windows Vista, modules had one of 256 possible base addresses (about 8 bits of entropy). On x64 with `/HIGHENTROPYVA`, entropy is much higher because the virtual address space is larger. ASLR is the precondition that makes every later forward-edge CFI scheme worth deploying: without it, the attacker just hardcodes the call target.

Hardware finally caught up on September 23, 2003. AMD shipped the no-execute bit ("NX bit," bit 63 of the 64-bit long-mode page-table entry) with the Athlon 64 launch [469]. Intel followed with the marketing-renamed "XD bit" in later Pentium 4 Prescott silicon. From 2003 onward, marking a page non-executable was a single PTE flag away.

Microsoft consumed the hardware almost immediately. Windows XP Service Pack 2, RTM August 6, 2004, shipped Data Execution Prevention as a system-wide feature. DEP defaulted to OptIn on client Windows, while Windows Server 2003 SP1 defaulted to the broader OptOut posture; both supported four system-level modes (OptIn, OptOut, AlwaysOn, AlwaysOff) and exposed a per-binary opt-in via the `/NXCOMPAT` PE-header flag [268]. On hardware without NX, DEP fell back to a software emulation limited to system-supplied binaries.

The Wikipedia ROP article frames this moment exactly: "Microsoft Windows provided no buffer-overrun protections until 2004" [470]. After XP SP2, Windows joined PaX, OpenBSD, and Solar Designer's Openwall on the W^X side of the line.

Three years later, in January 2007, Microsoft shipped Vista. Vista randomized DLL and EXE module bases at boot, with 256 possible load locations per module on x86. Michael Howard's MSDN design blog from May 2006 gives a worked example showing `wsock32.dll` at `0x73ad0000` on one boot and `0x73200000` on the next [471]. Vista paired ASLR with `/GS` stack canaries, `/SafeSEH` validated SEH chains, DEP, and pointer obfuscation: the first Microsoft OS to ship a layered exploit-mitigation stack as policy.

Read the early mitigation timeline as a straight escalation. Aleph One made stack smashing teachable in 1996. Solar Designer answered with a non-executable stack in 1997 and published return-into-libc the same day. PaX expanded the idea to non-executable pages in 2000 and named ASLR in 2001. AMD put NX in hardware in 2003. Microsoft consumed it as DEP in Windows XP SP2 in 2004 and paired it with Vista ASLR in 2007. The first decade moved the fight from “can the attacker run stack bytes?” to “can the attacker predict and reuse existing bytes?”

DEP and ASLR are not per-process mitigations in the modern sense. They are the system-wide foundation that the per-process surface sits on top of. The reason `ProcessDEPPolicy` still exists in the modern enum at all is to give 32-bit processes a way to enforce DEP locally even when the system policy is permissive. On x64, DEP is unconditionally on; the per-process knob is a vestigial 32-bit-only flag. `ProcessASLRPolicy` is more useful (it allows a process to force-on high-entropy bottom-up randomization with `ForceRelocateImages`) but it too is a refinement of a system-wide foundation, not a new defensive primitive [463].

By 2007, the story should have been over. DEP had made shellcode unrunnable. ASLR had made gadget addresses unpredictable. Every attacker primitive Aleph One named in 1996 was, in principle, defended. It was not.

Because the attacker did not need to write new bytes. They could reuse the bytes that were already there.

## ASLR plus DEP made shellcode hard, so attackers stopped writing shellcode

October 2007. Hovav Shacham, then on the UC San Diego computer-science faculty after a postdoctoral fellowship at the Weizmann Institute, presents *The Geometry of Innocent Flesh on the Bone: Return-into-libc without Function Calls (on the x86)* at ACM CCS [472]. The paper's existence claim is simple and devastating: in any sufficiently large C library, the set of short instruction sequences ending in `ret` is Turing-complete. The attacker does not need to inject any new code. They only need to write data (a sequence of return addresses on the stack) and the CPU obediently executes already-mapped, already-executable libc bytes in the attacker's chosen order.

The mechanism is small enough to explain in a paragraph. Shacham named the technique *return-oriented programming*. The attacker arranges for the program to return into a *gadget*: a short sequence of one to four instructions ending in `ret`. The gadget is selected from existing executable memory: libc, ntdll, the program's own code segment. The instructions perform a useful primitive (load a register, do arithmetic, dereference a pointer). The trailing `ret` pops the next stack slot, which the attacker has populated with the address of the next gadget. The stack is now the program counter; the CPU is now a Turing-complete machine for whatever language the gadget catalog implements.

> **Definition: Return-Oriented Programming (ROP).** An exploitation technique in which the attacker chains short, existing instruction sequences ("gadgets") each ending in `ret`. Control transfers happen via the program's own return instructions, executing already-mapped, already-executable code. ROP defeats W^X (DEP, NX) because the attacker injects no new code; it weakens against ASLR but does not break under it because info-leak primitives recover the gadget base address. Coined by Hovav Shacham in 2007 [472].

The follow-up Black Hat USA 2008 talk generalized the result to RISC architectures [473], killing "x86's variable-length instructions are why ROP works" as a defensive direction. ROP works on ARM. ROP works on MIPS. ROP works wherever an attacker can predict the address of executable bytes and control the stack.

> **Quoted source.** Return-oriented programming allows an attacker to execute code in the presence of security defenses such as executable space protection.: Wikipedia, *Return-oriented programming*, lead paragraph [470]

After 2007, the structural agenda of every defensive engineering team on Windows changes. The question is no longer "can we stop the attacker from writing bytes into executable pages?": DEP solved that, and ROP routed around it. The question is now: "which control transfers is the attacker allowed to cause?"

> **Margin note.** Shacham's UCSD lab (later UT Austin) kept exploring the boundary between code-reuse attacks and provable software defenses. The 2007 paper is the field-shaping one; the 2008 BHUSA generalization to RISC was the closing argument.

> **Key idea.** After Shacham 2007, every defensive engineering decision in Windows mitigation has been about which control-flow transfers the attacker is allowed to cause, not about what bytes the attacker can write. This is the chapter's load-bearing axis. CFG, XFG, CET, ACG, CIG, and every smaller mitigation in `PROCESS_MITIGATION_POLICY` follows from this one shift.

Microsoft's first response was behavioral, not structural. In 2009 the company released the *Enhanced Mitigation Experience Toolkit* (EMET), a free shim DLL that injected runtime checks into existing user-mode processes to detect ROP-shaped behavior. EMET checked for stack pivots, for unaligned `ret`-targets, for known-malicious gadget sequences, for unusual SEH chain layouts. It worked, intermittently, for a while. Then attackers adjusted, gadget-replacing around EMET's heuristics, and Microsoft slowly conceded the behavioral-detection direction was a dead end. EMET's final release was 5.52 in November 2016; end of life was July 31, 2018 [474]. Microsoft's stated successors are the `ProcessMitigations` PowerShell module and Windows Defender Exploit Guard: i.e., the formal `SetProcessMitigationPolicy` surface this chapter catalogs [474].

> **A short detour through EMET, 2009-2018.** EMET was an honorable failure. It taught the security industry that you cannot detect a control-flow hijack by looking at its symptoms; you can only prevent it by enforcing an invariant on the control flow itself. That lesson is exactly what Control Flow Guard (CFG) and Control-Flow Enforcement Technology (CET) embody. Every behavioral-ROP-detection product since EMET (Carbon Black's BB exploit protection, Symantec's Heat Shield, vendor-specific EDR ROP checks) has had the same fate against motivated adversaries. You can buy time but you cannot fix the problem in heuristics.

The structural answer arrived two years before the offensive proof that motivated it. In November 2005, at ACM CCS, Martín Abadi, Mihai Budiu, Úlfar Erlingsson, and Jay Ligatti published *Control-Flow Integrity* (also released as Microsoft Research Technical Report MSR-TR-2005-18) [475]. Their formal definition is short: *the execution of a program dynamically follows only paths defined by a static control-flow graph*. They proved CFI is enforceable using compile-time-inserted runtime checks and demonstrated a software rewriting implementation.

> **Definition: Control-Flow Integrity (CFI).** A defensive property formalized by Abadi, Budiu, Erlingsson, and Ligatti in 2005 [475]: the execution of a program must dynamically follow only paths defined by the static control-flow graph (CFG) of the program. CFI partitions into a forward-edge property (the targets of indirect calls and jumps must be valid) and a backward-edge property (the targets of returns must be the call-sites that called them). CFG, XFG, kCFG, and Apple's PAC are forward-edge CFI implementations. CET's shadow stack is a backward-edge CFI implementation.

CFI was a research framework looking for a vendor. It would wait nine years. The reader's belief at this point might be "DEP plus ASLR is enough." The honest belief, after Shacham, is that DEP plus ASLR raises the cost but does not change the game. The attacker still wins if they can choose where the next `ret` lands. The structural answer (constraining the control transfer rather than the write) is what makes Control Flow Guard make sense.

What does *constraining the control transfer* look like in machine code?

## Control Flow Guard (CFG): compile-time, load-time, runtime

Where DEP was enforced by hardware on every page, CFG is enforced by software on every indirect call. The compiler is now a security tool.

CFG's ship history is more complicated than the marketing remembers. The canonical primary on the early dates is Yunhai Zhang's Black Hat USA 2015 deck, *Bypass Control Flow Guard Comprehensively*, which states verbatim: "It was first introduced in Windows 8.1 Preview, but disabled in Windows 8.1 RTM for compatibility reason. Then, it was improved and enabled in Windows 10 Technical Preview and Windows 8.1 Update" [476]. Visual Studio 2015 added the compiler and linker flags. By the time Windows 10 shipped to consumers in July 2015, CFG was a documented Win32 security feature [477].

> **Note.** Stage 1 had this ship date as "Windows 8.1 Update 3 November 2014 vs Windows 10 July 2015". Zhang's deck is the contemporaneous primary that resolves the dispute. CFG was in Windows 8.1 Preview, was *removed* from Windows 8.1 RTM for compatibility, returned in Windows 8.1 Update and Windows 10 Technical Preview, and shipped widely with Windows 10 in 2015.

The mechanism has four phases. Each phase is a separate engineering subsystem, owned by a different team.

**Phase 1: Compile-time** (`/guard:cf`). The MSVC compiler emits, before every indirect call instruction, a call to one of two compiler-supplied thunks: `__guard_check_icall_fptr` for the standard pattern, or `__guard_dispatch_icall_fptr` for the tail-call optimization where the validator itself jumps to the target [478]. The thunk is a single indirection through ntdll. At compile time it is a stub; at load time it is patched to point at the active validator.

**Phase 2: Link-time** (`/GUARD:CF`, which requires `/DYNAMICBASE`). The linker writes the *Guard CF Function Table* (FID table) into the PE image's `IMAGE_LOAD_CONFIG_DIRECTORY` [479]. This table is the static catalog of every CFG-valid call target in this binary: every function whose address is taken, plus every function exported. `dumpbin /headers /loadconfig <binary>` prints the table contents. You can read the actual `Guard CF` flag word and the `FID table present` line.

> **CFG without /DYNAMICBASE is silently a no-op.** The MSVC linker only emits the FID table when `/DYNAMICBASE` is also set [478,479]. A binary compiled with `/guard:cf` but linked without `/DYNAMICBASE` will pass code review, ship, and provide zero protection at runtime. This is the single most common CFG misconfiguration in third-party software. Always confirm with `dumpbin /headers /loadconfig` that the `Guard Flags` word is non-zero and that `FID Table present` is in the output.

**Phase 3: Load-time.** At process startup and on every subsequent `LoadLibrary`, `ntdll!LdrpProtectAndRelocateImage` unions the FID table of the loaded image into a per-process *bitmap*. The bitmap is a sparse data structure with one bit per 8 bytes of virtual address space. On 32-bit Windows, that is about 32 megabytes of address space worth of valid-target bits. On x64, the address space is so large the bitmap is hundreds of megabytes sparse-allocated, but the memory only commits on access, so the resident set stays small.

> **Definition: CFG bitmap.** A sparse, per-process bit vector indexed by virtual address (one bit per 8 bytes). A set bit at index `addr / 8` means that `addr` is a CFG-valid indirect-call target in some loaded image. The kernel commits the bitmap pages on first access and shares them copy-on-write across processes with identical module-load layouts. The bitmap is the runtime data structure that `LdrpValidateUserCallTarget` consults on every indirect call.

**Phase 4: Runtime.** Every indirect call goes through `ntdll!LdrpValidateUserCallTarget`. The validator takes the call target in `rcx` (x64 calling convention), divides by 8, indexes into the bitmap, and tests the bit. If set, return; the call proceeds. If clear, fall through to `__fastfail(FAST_FAIL_GUARD_ICALL_CHECK_FAILURE)`, which raises `STATUS_STACK_BUFFER_OVERRUN`. The process dies.

CFG is best understood as a four-stage pipeline. The compiler instruments indirect-call sites. The linker writes the FID table into the PE load-config directory. The loader unions every loaded image's FID table into a sparse per-process bitmap. At runtime, the ntdll validator checks the target address against that bitmap and fast-fails the process if the bit is clear.

![Figure: Control Flow Guard as a four-phase pipeline, and a debugging checklist. Compile (`/guard:cf`) inserts a guard thunk before every indirect call; link (`/GUARD:CF` + `/DYNAMICBASE`) writes the Guard CF Function Table into the PE load-config directory: without `/DYNAMICBASE` it is a silent no-op; load unions every image's FID table into a sparse per-process bitmap, one bit per 8 bytes of virtual address space; runtime sends every indirect call through `LdrpValidateUserCallTarget`, which tests the target's bit. Bit set: the validator returns and the call proceeds. Bit clear: `__fastfail` raises `STATUS_STACK_BUFFER_OVERRUN` and the process terminates. Each handoff is a separate failure mode.](diagrams/19-mitigations-cfg-pipeline.svg)

That diagram is also the debugging checklist. If the compiler did not instrument a call site, CFG never runs. If the linker did not emit the FID table, the loader has nothing to union. If a JIT page is not deliberately marked with `SetProcessValidCallTargets`, the bitmap bit stays clear. If an attacker redirects a call to a real function entry whose bit is set, CFG has done exactly what it was designed to do, and the coarse-grained limitation has simply become visible.

There is an exception: code that is generated at runtime, like a JavaScript JIT, cannot have its targets pre-baked into a static FID table. For this case, CFG exposes `SetProcessValidCallTargets`, which lets a process programmatically mark an in-process address range as a permitted call target [477]. The companion `PAGE_TARGETS_INVALID` and `PAGE_TARGETS_NO_UPDATE` page-protection flags let the process control which newly-allocated pages start with a clear bitmap. The reason this API exists at all is the structural collision between W^X-via-CFG and runtime code generation: a collision that the ACG section will eventually resolve by moving the JIT out of process.

You can read the load-config flag word directly. The hex value is a bit field of `IMAGE_GUARD_*` constants. The most common bits are `IMAGE_GUARD_CF_INSTRUMENTED` (the binary has CFG indirect-call checks), `IMAGE_GUARD_CFW_INSTRUMENTED` (the binary has CFG indirect-call checks plus write-protection checks), `IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT` (the FID table is in the PE), `IMAGE_GUARD_CF_LONGJUMP_TABLE_PRESENT`, and `IMAGE_GUARD_RETPOLINE_PRESENT`.

CFG is forward-edge only. The `ret` instruction is invisible to it. A ROP chain that uses only return-target gadgets (the original Shacham construction) is not affected by CFG at all, because CFG never asks "where did this `ret` go?" It only asks "where did this indirect call go?" Closing the backward edge is a separate problem (the section on CET shadow stack).

CFG is also *coarse-grained*. The bitmap records "is this address a valid function entry?" but not "is this address a valid function entry *for this particular call site's prototype?*" Any function entry in the entire process is a valid CFG target for every indirect call site. If the attacker finds a legitimate function that takes a controllable argument and does something useful, they can chain it into a working exploit without ever flipping a clear bit to set.

Those two limitations (forward-edge only, coarse-grained) are precisely the open questions the XFG and CET shadow stack sections answer. CFG was the first floor. The next two sections build out the rest.

## eXtended Flow Guard (XFG): type-hash, fine-grained CFI for indirect calls

CFG knows *is this a function entry?* XFG asks the better question: *is this the right kind of function entry?*

The structural reason XFG exists has a name and a paper. May 2015, IEEE Symposium on Security and Privacy. Felix Schuster, Thomas Tendyck, Christopher Liebchen, Lucas Davi, Ahmad-Reza Sadeghi, and Thorsten Holz publish *Counterfeit Object-oriented Programming: On the Difficulty of Preventing Code Reuse Attacks in C++ Applications* [480]. The paper's abstract is constructive and brutal: COOP is "the first code-reuse attack to enable the synthesis of malicious behavior on x86 and ARM platforms" that "fully complies with previously presented coarse-grained CFI defenses."

> **Quoted source.** We propose a new attack technique, called Counterfeit Object-Oriented Programming (COOP), which is the first code-reuse attack to enable the synthesis of malicious behavior on x86 and ARM platforms and which fully complies with previously presented coarse-grained CFI defenses.: Schuster et al., IEEE S&P 2015 [480]

> **Definition: COOP (Counterfeit Object-Oriented Programming).** A code-reuse attack technique that chains legitimate C++ virtual function calls in attacker-chosen order, achieved by corrupting vtable pointers or vtable contents. Each individual callee is a real, address-taken function entry that passes any coarse-grained CFI bitmap. The attacker assembles Turing-complete computation by chaining these legitimate calls. Published by Schuster, Tendyck, Liebchen, Davi, Sadeghi, and Holz at IEEE S&P 2015 [480].

The mechanism is simple to describe but hard to detect. The attacker corrupts a heap-resident C++ object's vtable pointer to point at a fake vtable they have crafted from gadget-like *virtual functions* of real classes in the binary. Each entry in the fake vtable points at the entry of a real virtual method. The program's own virtual dispatch sequence performs the calls. The control transfers all land at legitimate function entries. CFG, which only asks "is this a function entry?", sees nothing wrong.

Microsoft's first public disclosure of the answer came at BlueHat Shanghai in 2019. David Weston (listed on the title slide of the deck as "Microsoft OS Security Group Manager") presented the design of *eXtended Flow Guard* (XFG) [481]. Microsoft never published a written XFG specification; the canonical public deconstruction is Connor McGarr's August 2020 reverse-engineering, which remains the best public account of how the mechanism actually works [482].

The mechanism is elegant. At compile time, MSVC computes a 64-bit type hash for every function: a truncated SHA-256 (first 8 bytes of the 32-byte digest) of the parameter count, parameter types, variadic flag, calling convention, and return type. The compiler stores this hash 8 bytes *before* each CFG-valid function entry [482]. At each indirect call site, the compiler knows the *expected* prototype (from the call's static type), emits the same hash inline, and the dispatch thunk reads the 8 bytes preceding the target and compares.

The XFG decision tree adds one question after the CFG bitmap check. First, is the target a valid function entry? If not, fast-fail. If yes and XFG is not enabled, proceed as ordinary CFG. If XFG is enabled, read the 64-bit prototype hash stored immediately before the target and compare it with the hash expected by this call site. A mismatch fast-fails; a match proceeds.

```text
Indirect call site
  │
  ▼
CFG bitmap check: is target a valid function entry?
  ├─ no  → fast-fail
  └─ yes → continue
          │
          ▼
        Is XFG enabled for this call path?
          ├─ no  → proceed under ordinary CFG
          └─ yes → read 8 bytes at (target - 8)
                    │
                    ▼
                  Compare stored target prototype hash
                  with call-site expected prototype hash
                    ├─ mismatch → fast-fail
                    └─ match    → dispatch to target
```

The extra hash check changes the attacker's job. Under CFG alone, every valid function entry is interchangeable. Under XFG, the attacker needs a function entry that is both valid *and* prototype-compatible with the corrupted call site. That does not make code reuse mathematically impossible (hash collisions, untyped casts, and same-prototype gadgets remain possible) but it removes the broad COOP assumption that any virtual method entry can stand in for any other as long as the bitmap bit is set.

A COOP attacker who replaces a vtable pointer with the address of a different real virtual function passes CFG: the new target is a valid function entry. They fail XFG: the 8 bytes preceding the new target encode a *different* prototype hash than the call site expects. The fix moves the granularity from "every function entry" to "every function entry compatible with this exact prototype": orders of magnitude closer to perfect forward-edge CFI.

XFG shipped in Windows 10 21H1 internals. The `/guard:xfg` MSVC flag was added. The XFG dispatch thunks (`__guard_xfg_dispatch_icall_fptr`) appeared in `ntdll.dll`. Then it didn't enable by default.

> **Note.** Connor McGarr's Black Hat USA 2025 deck, *Out of Control: How KCFG and KCET Redefine Control Flow Integrity in the Windows Kernel*, states verbatim: "XFG was never fully instrumented (UM/KM) and is now deprecated." McGarr is listed on the title slide as Software Engineer, Prelude Security [483].

> **Why a strictly-better CFI scheme can still lose.** Two reasons XFG didn't ship enforcement-by-default. First, compatibility cost: XFG breaks any C-style cast through a different prototype. Windows is full of these, including in third-party drivers and inbox-COM components, and every breakage costs a customer ticket. Second, hardware overtook software. CET shadow stack arrived on Tiger Lake in September 2020 and gave the entire backward edge for free, leaving the forward-edge problem partially un-fine-grained but the *complete* CFI surface achievable by composing CFG (forward, coarse) with CET (backward, perfect). The math worked out: ship CET strictly, and a coarse-grained forward edge is good enough. Because the backward edge, the bigger half of the call graph, is now perfect. XFG remains the most interesting almost-shipped Windows mitigation. The instrumentation is in MSVC. The dispatch thunks are in `ntdll`. Enforcement-by-default never arrived, and the McGarr 2025 deck names it as deprecated. The strategic pivot to hardware is what Microsoft made instead.

What does that hardware look like, and what edge does it protect? Tiger Lake shipped in September 2020. For the first time since Shacham 2007, the kind of ROP that chains `ret`-terminated gadgets could be killed by the CPU itself.

## Hardware-enforced stack protection (Intel CET shadow stack)

The Microsoft Tech Community post that introduced CET shadow stack on Windows (preserved on the Wayback Machine because the live URL is a JavaScript-rendered shell) gives the framing in one sentence:

> **Quoted source.** We shipped Control Flow Guard (CFG) in Windows 10 to enforce integrity on indirect calls (forward-edge CFI). Hardware-enforced Stack Protection will enforce integrity on return addresses on the stack (backward-edge CFI), via Shadow Stacks.: Microsoft Tech Community, *Understanding Hardware-enforced Stack Protection* [484]

> **Definition: Shadow stack.** A second, per-thread stack maintained by the CPU in parallel with the regular call stack. Every `call` instruction pushes the return address to both stacks. Every `ret` pops both and compares. A mismatch raises a `#CP` (Control Protection) fault, which Windows surfaces as `STATUS_CONTROL_PROTECTION_EXCEPTION` (`0xC0000602`). The shadow stack page is hardware-protected: only the write-family instructions `WRSS` and `WRUSS`, plus the call/ret/IRET microcode, can write to it. User-mode stores into a shadow-stack page fault.

The mechanism, drawn from Intel's CET specification and Microsoft's Windows enabling documents [484,408,485]:

- Every `call` instruction now writes the return address twice: once to the regular stack, and once to the per-thread shadow stack at `[SSP]`.
- The shadow-stack page is marked with a new MMU bit that makes it readable but not writable by general store instructions. Only the write-family instructions `WRSS` and `WRUSS`, plus the call/ret/IRET microcode, can store to it.
- Every `ret` pops the regular stack and pops the shadow stack and compares. Equal: proceed. Different: raise `#CP`. On Windows, the shadow-stack `#CP` is surfaced as `STATUS_CONTROL_PROTECTION_EXCEPTION` (`0xC0000602`).
- New instructions exist for legitimate unwinding. `INCSSP imm` advances the SSP across unwound frames: the C++ `longjmp` and the Windows SEH unwinder both use this. `RDSSP` reads the current SSP into a register.
- The `/CETCOMPAT` MSVC linker flag, available from Visual Studio 2019 onward, marks an x64 image as shadow-stack-compatible by setting the `IMAGE_DLLCHARACTERISTICS_EX_CET_COMPAT` bit in the extended DLL characteristics word [485].

Tiger Lake shipped CET first, in September 2020. AMD followed with the same architectural spec in Zen 3 in November 2020 [408]. The two vendors implement the same instructions, the same MMU bit, the same fault. The shadow-stack image format is identical. Windows uses the same code paths on both.

> **Note.** AMD Zen 3 was launched on November 5, 2020, two months after Tiger Lake [408]. Both vendors implement compatible CET shadow-stack behavior, so Microsoft's Windows enabling code is largely single-source.

Shadow-stack enforcement is a hardware double-entry book. On call, the CPU writes the return address to both the regular stack and the shadow stack. If an attacker changes only the regular-stack copy, the later ret pops two different addresses. The CPU raises a control-protection fault, and Windows surfaces the failure through the same fatal status family used by CFG and stack-cookie failures.

```text
call victim()
  CPU pushes return address A to regular stack
  CPU pushes return address A to shadow stack (SSP)

attacker corrupts regular stack slot: A → X
  shadow stack slot remains A because normal stores cannot write SSP pages

ret
  CPU pops X from regular stack
  CPU pops A from shadow stack
  CPU compares X vs A
  ├─ equal    → return proceeds
  └─ mismatch → #CP (Control Protection fault)
                → Windows reports STATUS_CONTROL_PROTECTION_EXCEPTION (0xC0000602)
```

CET also has a second architectural half: Indirect Branch Tracking (IBT). IBT requires valid indirect branch destinations to begin with an `ENDBRANCH` landing instruction; an indirect `call` or `jmp` to a non-landing-pad raises a `#CP` fault. Windows, however, does *not* enforce user-mode IBT: forward-edge validation on Windows is software CFG (and its finer-grained XFG variant), and `ProcessUserShadowStackPolicy` covers the backward edge. The important composition is therefore: CFG checks indirect-call targets before dispatch, and the CET shadow stack checks return targets after the callee finishes. In user-mode Windows a `#CP` fault is a shadow-stack mismatch; IBT `ENDBRANCH` enforcement is part of the CET architecture but is not turned on for user-mode processes.

```text
CET composition
  forward edge: indirect call/jmp → CFG/XFG bitmap (Windows software CFI); IBT ENDBRANCH landing pads exist in the CET architecture but are not enforced in user-mode Windows
  backward edge: ret → regular-stack return address must equal shadow-stack return address
  shadow-stack violation → #CP → process-fatal status on Windows
```

The Windows policy surface for CET is `ProcessUserShadowStackPolicy`, structured exactly like every other policy in the enum: a `DWORD` of bitfields and a "reserved" tail [486]. Ten flags are documented:

- `EnableUserShadowStack`. Turn it on (compatibility mode: only shadow-stack violations in CETCOMPAT-marked modules are fatal)
- `AuditUserShadowStack`: log without enforcing
- `SetContextIpValidation`: block `SetThreadContext` (and the equivalent `NtSetContextThread` from a peer process) from setting an instruction pointer to an unguarded address
- `AuditSetContextIpValidation`, log version
- `EnableUserShadowStackStrictMode`: upgrade from compatibility mode (only CETCOMPAT-module shadow-stack violations are fatal) to strict mode (all shadow-stack violations are fatal, even in non-CETCOMPAT modules)
- `BlockNonCetBinaries`: the loader refuses to map non-`/CETCOMPAT` DLLs into the process; strict policy for the most-hardened sandboxes
- `BlockNonCetBinariesNonEhcont`: like `BlockNonCetBinaries`, but also requires images to carry `/guard:ehcont` exception-handling continuation metadata
- `AuditBlockNonCetBinaries`: log version of `BlockNonCetBinaries`
- `SetContextIpValidationRelaxedMode`: permits some legacy patterns
- `CetDynamicApisOutOfProcOnly`: requires the CET dynamic-enforcement APIs (`SetProcessDynamicEnforcedCetCompatibleRanges`, `SetProcessDynamicEHContinuationTargets`) to be called from a peer process rather than in-process

The `SetContextIpValidation` flag is worth a separate paragraph. The original CET shadow-stack design protected against attackers who corrupted return addresses on the regular stack. A more subtle attack used `SetThreadContext` from a peer process (or, equivalently, the in-process `NtSetContextThread`) to write a register-state structure containing an attacker-chosen `RIP`. The thread, when resumed, would jump to that `RIP`: with no `ret` instruction involved, so the shadow stack saw nothing. `SetContextIpValidation` closes that hole by validating the requested `RIP` against the bitmap before the kernel resumes the thread. Without it, CET shadow stack has a documented bypass [486].

> **Definition: `#CP` (Control Protection fault).** A new CPU exception introduced with Intel CET. Raised when a shadow-stack compare fails on `ret`, or when an `endbranch` instruction is missing at an indirect-branch target (for IBT-style CET, separate from shadow stack). A stray write to a shadow-stack page from an ordinary store instead faults as a page fault (`#PF`) with the shadow-stack bit set in the error code. Windows surfaces a shadow-stack `#CP` as `STATUS_CONTROL_PROTECTION_EXCEPTION` (`0xC0000602`): distinct from the `STATUS_STACK_BUFFER_OVERRUN` (`0xC0000409`) raised by stack-canary violations and CFG fast-fail checks.

Compose CFG with CET shadow stack and you have the result the entire arc since Aleph One has been pointing at:

> **Key idea.** CFG (forward edge) plus CET shadow stack (backward edge) gives Windows a practical forward/backward-edge CFI composition on x86-64: coarse, compiler-checked forward-edge validation plus hardware-enforced return-address validation. It is not fine-grained, whole-program CFI: CFG stays coarse, not every module is instrumented, and the shadow stack does not constrain forward call/jump targets. Even so, two mitigations from two different layers composing into this property took twenty years to assemble.

Full CFI is not the same as full security. CET still does not cover three structural attack classes. *Call-oriented programming* and *jump-oriented programming* chain gadgets ending in `call` or `jmp` rather than `ret`; because no `ret` executes, the shadow stack is never consulted, so CET sees nothing. *COOP* chains entire legitimate virtual functions with matching call/return pairs; CET sees nothing. *Data-oriented* attacks never violate any control-flow invariant at all, because they never hijack control flow in the first place.

We have constrained the control flow. We have not constrained which *code* is in the process. An attacker can still load a malicious-but-signed-looking DLL through the loader, or persuade a JIT to emit attacker-chosen bytes into the JIT heap and then redirect a legitimate call to that JIT-allocated address. That is the *code* layer, not the *control flow* layer. The parallel mitigation path (CIG and ACG) is what closes it.

## Code Integrity Guard (CIG): only signed images can load

Even if the attacker can't generate code and can't redirect control flow, they can still ask the loader to do it for them. Plant a Microsoft-signed DLL somewhere the loader will pick it up; `LoadLibrary` runs the planted DLL's `DllMain`; you have remote code execution through a trusted entry point. The structural answer is to restrict the universe of DLLs the loader will ever map into a hardened process.

That is the function of *Code Integrity Guard*. CIG first appeared in Microsoft Edge in Windows 10 1511 (November 2015) [487]. The canonical primary on its design is Matt Miller's February 2017 Edge blog *Mitigating arbitrary native code execution in Microsoft Edge* [487]. The corresponding policy in `SetProcessMitigationPolicy` is `ProcessSignaturePolicy`, with the bitfield `PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY` [488].

> **Definition: CIG (Code Integrity Guard).** A per-process policy that restricts the set of binaries the loader will map into the process to images signed by an allowed code-signing root. Implemented in Windows via the `ProcessSignaturePolicy` mitigation policy. The most common configuration is `MicrosoftSignedOnly`, which restricts loads to Microsoft-rooted catalog chains. Bypass attempts that load a malicious DLL into the process return `STATUS_INVALID_IMAGE_HASH` from `LoadLibrary` / `LoadLibraryEx` / `NtMapViewOfSection` [487,488].

The policy structure carries three levels:

- `MicrosoftSignedOnly`: only images chaining to a Microsoft root will load
- `StoreSignedOnly`: only Microsoft Store-signed images
- `MitigationOptIn`: the loader accepts any image signed by Microsoft, the Windows Store, *or* the Windows Hardware Quality Labs (WHQL); the broadest of the three signing-level settings

Plus an `AuditMicrosoftSignedOnly` audit-only flag that logs without blocking, for compatibility testing in the run-up to enforcement.

> **Definition: UMCI (User-Mode Code Integrity).** The kernel subsystem that enforces image-signing policy on user-mode binary loads. UMCI is the user-mode counterpart of KMCI (Kernel-Mode Code Integrity, used by Windows Driver Signature Enforcement and HVCI). CIG calls into UMCI on every `NtMapViewOfSection` to verify that the section's backing image is signed by an allowed root before the loader maps it.

The mechanism is small. Every `LoadLibrary`, every `LoadLibraryEx`, and every `NtMapViewOfSection` consults UMCI (User-Mode Code Integrity). If the image is not signed by a Microsoft-rooted catalog chain when `MicrosoftSignedOnly` is in effect, the load returns `STATUS_INVALID_IMAGE_HASH` [487,488]. The process keeps running; the DLL just doesn't load. (Most attack chains aren't structured to handle that gracefully, so in practice the process crashes shortly afterward when it tries to dereference a function pointer the failed DLL was supposed to provide.)

CIG is a publisher check, not a content check. A Microsoft-signed DLL with a controllable side effect: a DLL-search-order hijack against a signed Windows component, or the CVE-2013-3900 Authenticode-padding family that allows a signed binary to carry attacker-controlled trailing data without invalidating the signature: still loads normally. CIG can't tell. *App Control* (formerly Windows Defender Application Control) and the Microsoft Driver Block List are the partial answer: a curated list of banned-but-signed binaries UMCI consults and rejects even when their signatures verify.

> **Margin note.** CVE-2013-3900 was disclosed in December 2013. Microsoft shipped an opt-in registry fix (`EnableCertPaddingCheck`) and left the strict default off for over a decade for compatibility reasons; in July 2024 the company republished the CVE in the Security Update Guide to formally reaffirm that the strict-Authenticode behavior remains available as an opt-in across all currently supported releases of Windows 10 and Windows 11 ("Microsoft does not plan to enforce the stricter verification behavior as a default functionality on supported releases of Microsoft Windows") [489]. The structural-vulnerable-but-signed class has been operationally hard to retire for the same reason every backwards-compatibility constraint is hard to retire.

> **CIG only blocks future loads.** `ProcessSignaturePolicy` is applied to subsequent loader operations after the policy is installed. DLLs that were already mapped into the process before the call to `SetProcessMitigationPolicy` are *not* unloaded retroactively. This is the structural reason serious sandboxed processes (Edge content, Chrome renderer) use `UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY)` at `CreateProcess` time: the kernel installs the policy *before* the child's first user-mode instruction runs, so even the loader's initial sweep of static imports is policed.

> **The signed-but-vulnerable residual risk.** The Microsoft-signed DLL universe is large. Many of those binaries have controllable side effects: search-order hijacks, Authenticode-padding writes, signed-driver privilege primitives, signed-tooling code-injection helpers. CIG does not look at side effects; it only looks at the signature. The residual class that survives `MicrosoftSignedOnly` ("signed but vulnerable") is precisely the class App Control's reactive blocklist tries to keep up with. As of the 2025 Driver Block List there are hundreds of blocked-but-signed binaries; the list grows every quarter. This is one of the unsolved problems the open-problems section names.

CIG and ACG are siblings but not synonyms. CIG prohibits *loading unsigned images*. ACG prohibits *generating new executable code at runtime*. They attack different attack surfaces. The signed-DLL-injection bypass that defeats CIG does not defeat ACG, because the planted DLL is not generating new code. It is using its (signed but vulnerable) existing code. The JIT-spray-as-CFG-bypass that defeats ACG does not defeat CIG, because the JIT was not loading a new DLL. An attacker who solves one still has to solve the other.

What does the *generation* half look like?

## Arbitrary code Guard (ACG): W^X for the entire process

March 2017. Windows 10 Creators Update ships. Microsoft Edge enables a single flag in the new `ProcessDynamicCodePolicy` structure. Every JavaScript JIT engine in the world has to be rearchitected.

> **Definition: ACG (Arbitrary Code Guard).** A per-process policy that prevents the process from generating new executable code or mutating existing code at runtime. With ACG enabled, calls to `VirtualAlloc` with `PAGE_EXECUTE_*` return `STATUS_DYNAMIC_CODE_BLOCKED`. Calls to `VirtualProtect` that attempt to *add* execute permission to an existing page return the same status. `MapViewOfSection` with `SECTION_MAP_EXECUTE` requires the section's backing image to be signed. The net effect: the process cannot allocate new executable memory or add execute rights to existing pages. Every executable page must be backed by a signed image mapped by the loader (which signers are acceptable is governed separately by CIG/the image-signature policy, and images may still be mapped after startup), so the process cannot generate or mutate code on the fly [487,490].

The `PROCESS_MITIGATION_DYNAMIC_CODE_POLICY` structure carries four flags [490]:

- `ProhibitDynamicCode`: the core enforcement flag
- `AllowThreadOptOut`: a thread can call `SetThreadInformation(ThreadDynamicCodePolicy, THREAD_DYNAMIC_CODE_ALLOW)` to escape, which Microsoft's documentation warns against using with `ProhibitDynamicCode` because the two flags together leak the policy's intent
- `AllowRemoteDowngrade`: a higher-privileged peer can disable the policy via `SetProcessMitigationPolicy`
- `AuditProhibitDynamicCode`: log without enforcing

The structural rule, restated mechanically [487,490]:

1. `VirtualAlloc` with `PAGE_EXECUTE`, `PAGE_EXECUTE_READ`, `PAGE_EXECUTE_READWRITE`, or `PAGE_EXECUTE_WRITECOPY`: blocked.
2. `VirtualProtect` that adds any executable permission to an existing page: blocked.
3. `MapViewOfSection` with `SECTION_MAP_EXECUTE` for a section *not* backed by a signed image: blocked.
4. The only way new executable pages enter the process: the loader maps signed PEs at module load time, and (with CIG also on) only Microsoft-signed PEs.

The browser-JIT architectural consequence is the most-cited single change in the entire Windows mitigation literature. Pre-2017, every JavaScript JIT generated native code at runtime into a `RWX`-permission heap inside its own browser process. The pattern was simple: allocate a page, write machine code into it, mark it executable, jump. ACG turned that pattern into a fatal error.

Chakra (then Edge's engine) responded by moving the JIT compilation step out of the renderer process [487]. The architecture became: the renderer ships JavaScript source over an authenticated IPC channel to a *JIT process*; the JIT process compiles to machine code; the JIT process owns the executable section backing the compiled output; the renderer maps that brokered section read-execute via `MapViewOfFile` and dispatches into it. The renderer is locked into ACG. The JIT process is not (it has to write code), but it never parses untrusted content: only pre-validated bytecode from the renderer over a typed IPC schema.

The ACG browser architecture split one process into two trust zones. Before ACG, the renderer contained the JavaScript engine, the JIT compiler, and an RWX or write-then-execute JIT heap. After ACG, the renderer keeps the untrusted parsing surface and runs with dynamic code prohibited; a separate JIT process performs compilation and returns executable output through a controlled shared-section mapping.

![Figure: Arbitrary Code Guard rearchitected the browser into two trust zones. Before ACG, one renderer parses untrusted JavaScript and JITs native bytes into an RWX (write-then-execute) heap it then jumps into: a `W^X` violation living in the same process that touches attacker input. After ACG, the renderer runs with dynamic code prohibited (no `PAGE_EXECUTE_*` allocation, no `VirtualProtect` write→execute transition, signed sections only) and the JIT moves out of process; compiled code returns through a brokered shared section the renderer maps read-execute. ACG denies both halves of the old pattern: allocations that start executable, and permission transitions that later add execute.](diagrams/19-mitigations-acg-split.svg)

The invariant is stronger than "no RWX heap." ACG forbids both common halves of the old pattern: it blocks allocations that start executable, and it blocks permission transitions that turn a writable page into an executable one. That is why an in-process JIT cannot merely switch from `PAGE_EXECUTE_READWRITE` to `PAGE_READWRITE` followed by `PAGE_EXECUTE_READ`: the second step is the step ACG exists to deny.

That rearchitecture is the structural cost ACG imposed. It is not small. Out-of-process JIT adds roughly a millisecond per JIT compilation for the IPC round-trip, which matters for short-lived JavaScript (lots of small functions, one-shot pages). It also creates a new trust boundary (between renderer and JIT process) which is itself an attack surface, and which the next paragraph names.

The bypass tradition starts almost immediately. Reported December 2017, publicly disclosed February 2018, Project Zero issue 1437, by Ivan Fratric. It and the related Project Zero Edge-exploitation work document the *race-the-mitigation-window* class [491,492]. The PoC is small enough to read in one paragraph.

> **The Forshaw-Fratric race: two bytes that disable ACG.** Each Edge content process (`MicrosoftEdgeCP.exe`) called `SetProcessMitigationPolicy(ProcessDynamicCodePolicy,...)` on itself shortly after startup. The advisory documents the verbatim callstack: `MicrosoftEdgeCP!SetProcessDynamicCodePolicy+0xc0`. Forshaw and Fratric discovered that there is a window between `CreateProcess` returning the new content process's handle and that child's first call into `SetProcessDynamicCodePolicy`. During that window, a peer content process in the same AppContainer can `OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION)` the new child and `WriteProcessMemory` two specific bytes: at Edge offsets `0x23090` and `0x23092` on the version Forshaw and Fratric tested, build "up-to-date on Windows 10 version 1709" [491]. The two bytes are global flags that, if set, cause `SetProcessDynamicCodePolicy` to short-circuit and return success without installing the policy. The result: a child renderer that *thinks* ACG is on, that the parent thinks has ACG on, but in which `VirtualAlloc(PAGE_EXECUTE_READWRITE)` succeeds normally. Microsoft's fix was structural: migrate to `UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY)`, so the policy is installed *by the kernel* before the child's first user-mode instruction runs and the race window closes.

The second-generation bypass came faster than anyone expected. May 2018, Ivan Fratric publishes *Bypassing Mitigations by Attacking the JIT Server* on the Project Zero blog [493]. Once ACG forced JIT out of process, the *new* attack surface was the IPC channel and the JIT-server allocation address. Fratric writes: "we believe that any other attempt to implement out-of-process JIT would encounter similar problems." That sentence is the deeper lesson of the entire mitigation tradition: a new trust boundary (between renderer and JIT process, between user and kernel, between content process and broker) is a new attack class. You did not eliminate the attack surface; you moved it.

ACG plus CIG, then, closes "what code can run in this process": no unsigned image loads (CIG), no dynamic code generation (ACG), no executable allocations of any kind that did not originate as a signed PE on disk. That is a closed surface for the *code* dimension. But the attacker has more options than memory and signatures. There is the kernel surface beneath the renderer's syscalls. There is the legacy extension-point loader. There are fonts, image loads, side channels. Those are the smaller, operationally-critical mitigations: the rest of the twenty.

## The smaller, operationally critical mitigations

DEP, ASLR, CFG, CET, CIG, ACG. That is the canonical six. But the `PROCESS_MITIGATION_POLICY` enum lists twenty-one values [464]. The other fourteen actual policies are not afterthoughts. Each one is a tombstone for a specific attack class that did not fit into "don't let the attacker write code" or "don't let the attacker pick the call target."

Read this cluster as the operational half of exploit mitigation. The big six constrain memory permissions, code provenance, and control transfers. The policies below constrain the pivots an attacker tries after the first chain fails: kernel GUI syscalls, ambient DLL injection through legacy extension points, font parsers, unsafe image origins, stale handles, filesystem redirection, side-channel domains, child process creation, legacy ROP heuristics, and the old DEP/ASLR foundation knobs. Each subsection names the enforcement point, the attack class, and the compatibility reason a real product might leave it off.

## `ProcessSystemCallDisablePolicy`: Disable Win32k system calls

Edge content process, 2017 onward. The Win32k.sys driver implements the GUI subsystem and was, for many years, the single largest contributor to Windows kernel CVEs. A renderer process that does not draw windows can refuse Win32k syscalls entirely, eliminating an enormous swath of kernel attack surface for a compromised renderer. The Edge content process is the canonical user. The Edge sandbox blog documents the AC architecture and capability model the renderer runs inside [494]; the policy enum entry itself is in `ms-setprocessmitigationpolicy` [463]. Connor McGarr's 2025 deck addresses the Win32k surface explicitly: "Call targets in Win32k can be corrupted with a valid NT call target". Which is the structural reason the policy exists [483].

Mechanically, the policy denies the lowest-layer `NTUser` and GDI syscall family from the process. User-mode helper DLLs may still be mapped, but the transition into the Win32k kernel subsystem is refused. The failure class it closes is not "arbitrary syscalls" in general; the process can still call the ordinary NT kernel API. It closes the GUI-kernel attack surface: window-manager objects, GDI objects, font and drawing paths, callback-heavy desktop state, and the historical bug density around them. Enable it for renderers, parsers, brokers, services, and AI/AV workers that do not create windows or use GDI. Do not enable it for a real GUI process unless the UI has been intentionally split into a separate broker; otherwise basic window creation, drawing, input, and accessibility paths break.

## `ProcessExtensionPointDisablePolicy`

Disables legacy extension-point classes that have historically been DLL-injection vectors: `AppInit_DLLs` (registry-driven inject-into-everything), IME modules, Layered Service Providers (LSP, the Winsock provider chain), `WinEventHook`/`SetWindowsHookEx` global hooks. Enabling the policy makes the loader refuse to map any DLL through these legacy paths into the process [463,464]. This is one of the lowest-cost mitigations to enable for any process that does not knowingly need legacy IME or LSP integration.

The mechanism is loader-side and policy-side rather than compiler-side. Windows has several compatibility systems whose original contract was "let third-party code inject into or extend arbitrary applications." That was valuable for input methods, networking stacks, accessibility tools, and enterprise shims; it is also exactly the primitive an attacker wants after compromising a lower-integrity or neighboring process. With extension points disabled, those legacy auto-load paths do not get to add their DLLs to the target process merely because a registry key, hook, or provider chain says so.

The failure mode is compatibility, not security incompleteness. Modern explicit plugin systems, COM activation allowed by the application, and ordinary `LoadLibrary` calls are not magically forbidden by this policy; CIG and image-load restrictions are the layers that govern those. You enable extension-point disablement when the process has a closed dependency set and no need for legacy hooks. You avoid it, audit it first, or isolate the extensibility into a broker when the product genuinely depends on IMEs, accessibility hooks, old Winsock providers, or enterprise shims. The policy is "cheap" only when you have already decided that ambient third-party injection is not a supported feature.

## `ProcessFontDisablePolicy`

Refuses non-system fonts. The historical motivation was a 2015 wave of ATMFD.DLL kernel-font-parser CVEs (the Adobe Type Manager font driver). Microsoft moved the font parser out of the kernel into user mode after that wave, and this per-process policy then refuses non-system fonts entirely for browser-class sandboxed processes that do not need them [463].

The enforcement point is the font-loading path: the process can use installed system fonts, but attempts to load fonts supplied by the document, the web page, or a low-trust directory are denied when the policy is active. That matters because fonts are executable-looking data in practice: complex binary parsers, hinting languages, shaping engines, fallback rules, and historically kernel-adjacent code. A compromised document renderer that can feed a font parser attacker-controlled bytes has a second parser surface even after the original PDF, browser, or previewer bug is mitigated.

The limitation is obvious and important: many programs exist to render arbitrary typography. A browser tab, a PDF viewer, a design tool, or Office may need downloadable or embedded fonts for fidelity. In those cases the realistic design is not "enable font disable everywhere"; it is split the font handling into a lower-privilege process, use system-font-only mode for the most sensitive children, and document the fidelity/security tradeoff. Enable this policy for sandboxes that do not need custom fonts (image decoders, script workers, many service processes, broker children) and avoid it for user-facing renderers unless the product can tolerate missing or substituted fonts.

## `ProcessImageLoadPolicy`

Three loader-time flags, all about *where* a DLL can come from:

- `NoRemoteImages`: block DLLs whose path is a UNC `\\server\share\dll`. Eliminates a remote-DLL family that crossed administrative boundaries.
- `NoLowMandatoryLabelImages`: block DLLs whose file was written by a low-integrity-label process. A compromised sandboxed process could write a DLL to disk; this flag stops a peer broker from picking that DLL up.
- `PreferSystem32Images`: search `\Windows\System32\` before the application directory in the DLL search order. Closes the DLL-search-order-hijack class, a very old attack surface.

All three are in [495]. Together they collapse the DLL-loading attack surface to a small, well-controlled set of code paths. The kernel/loader mechanism is path and label validation before mapping an image section: the question is not whether the DLL is malicious in content, but whether the source location is too weak to be trusted for code. The threat class is planted-code loading: remote share preloading, low-integrity write-then-load pivots, and search-order confusion. The main bypass is a signed or legitimate DLL that lives in an allowed location and has a useful side effect; CIG and App Control are the layers for that. Enable all three for hardened children and services with known dependencies. Be careful with applications that intentionally load plugins from application-local directories or network shares; the safer pattern is an explicit plugin broker, not ambient search-order trust.

## `ProcessStrictHandleCheckPolicy`

Causes the process to fault immediately on any use of an invalid handle (use-after-close, double-close, opaque-mismatch) [463]. Handle bugs are an obscure but exploitable class: a freed kernel object's handle can be reissued, and a process that does not detect this can be tricked into operating on an attacker-controlled replacement. Strict handle checking turns a subtle handle-confusion bug into an immediate crash, before the attacker can pivot.

The mechanism is deliberately harsh. Instead of allowing APIs to limp along with `STATUS_INVALID_HANDLE` and letting the program continue in an inconsistent state, Windows terminates the process when it detects invalid-handle use under the strict policy. That converts a possible confused-deputy primitive into a reliability failure. The threat it closes is especially relevant in brokered sandboxes: handles are capabilities. If a renderer can cause a broker to close, duplicate, reuse, or operate on the wrong handle, the broker may perform an action on a more privileged object than intended.

The limits are also clear. Strict handle checking does not prove the handle is semantically the *right* handle; it catches invalid or stale handle values, not every confused-deputy design bug. A live handle to the wrong object can still be dangerous. The compatibility cost is usually low for well-tested code and high for old code that treats invalid-handle errors as recoverable. Enable it almost everywhere in new code, especially brokers and parsers. If it crashes an application during rollout, treat the crash as a bug to fix rather than a reason to permanently disable the mitigation.

## `ProcessRedirectionTrustPolicy`, RedirectionGuard

Mitigates symbolic-link, junction, and mount-point confused-deputy attacks. James Forshaw documented the attack family at Project Zero starting in August 2015 with the Windows 10 symbolic-link mitigations post [496]. Microsoft shipped the per-process mitigation a decade later, in June 2025 [497]. RedirectionGuard refuses to traverse a junction if the junction's target was created by a less-trusted user than the process performing the open: closing the "a low-IL caller plants a junction; a high-IL service follows it" pattern that has been a steady source of local privilege escalation since at least Windows Vista.

> **Note.** RedirectionGuard's June 2025 ship date makes it the freshest entry in the `PROCESS_MITIGATION_POLICY` enum. The MSRC blog states the structural framing in one sentence: "Junctions remain the biggest existing gap. Outside of a sandbox, they can be created by standard users and target any folder on the system" [497].

Its failure mode is policy granularity. Some installers, updaters, backup agents, and developer tools intentionally traverse reparse points. Those programs need either careful allowlists or a less privileged helper that resolves paths before the privileged service touches them. For hardened services and brokers, enable it: filesystem namespace confusion is a classic way to turn "write a file I control" into "overwrite a file the service controls."

## `ProcessSideChannelIsolationPolicy`

The policy exposes five fields [463]:

- `SmtBranchTargetIsolation`: enables `STIBP` (Single Thread Indirect Branch Prediction) so a sibling hyperthread sharing the physical core cannot poison this process's indirect-branch predictor. This is the cross-SMT branch-target-injection control.
- `IsolateSecurityDomain`: places the process in its own security domain and issues an `IBPB` (Indirect Branch Predictor Barrier) when the scheduler switches between domains. This is the per-process Spectre v2 side-channel mitigation. Performance cost is real, in the 2-5% range on indirect-branch-heavy workloads, and is the reason this policy is opt-in rather than default.
- `DisablePageCombine`: prevents the kernel from merging identical physical pages across processes. Page-combining is a memory-saving feature that creates a cross-process side-channel: timing the cost of a write to a shared, copy-on-write page leaks whether the page was previously merged with another process's identical page.
- `SpeculativeStoreBypassDisable`: sets `SSBD` to close the Spectre v4 speculative-store-bypass channel.
- `RestrictCoreSharing`: keeps threads from other security domains off the same physical core, the scheduler-level isolation that backstops the predictor barriers.

This policy does not stop memory corruption. It reduces cross-domain information leakage that would otherwise make exploitation easier: branch predictor state can leak control-flow history; page combining can leak whether another process has an identical page. The bypasses are the general limits of side-channel defense: new microarchitectural channels appear, barriers cost cycles, and not every secret-bearing process can afford the strongest setting. Enable it for high-trust processes that handle secrets or cross-tenant data. Consider audit/performance measurement for CPU-bound workloads, because the security/performance tradeoff is real rather than theoretical.

## `ProcessUserShadowStackPolicy`

The CET-on switch from the CET section [486]. It is not merely an enum placeholder. The policy tells Windows to enable user-mode hardware-enforced stack protection for the process, optionally audit it first, validate `SetThreadContext` instruction-pointer changes, move from compatibility mode to strict mode, and block non-`/CETCOMPAT` binaries from loading.

Mechanically, the kernel creates and manages per-thread shadow stacks, configures the CPU's CET state for user mode, and coordinates loader decisions about CET-compatible modules. The core threat is backward-edge hijack: stack overwrite, use-after-return, or corrupted exception/unwind state that tries to make a `ret` land somewhere other than the call site. `SetContextIpValidation` closes the separate "no ret involved" path where a peer process sets `RIP` directly through a thread-context API.

The policy's failure modes are the same as CET's architectural limits. It does not stop call-oriented programming, jump-oriented programming, COOP chains with balanced calls and returns, or data-only attacks. Compatibility mode may tolerate violations in non-CET modules; strict mode may break old DLLs, handwritten assembly, unusual unwinders, or binaries lacking `/CETCOMPAT` and `/guard:ehcont` metadata. Enable it for new x64 code and hardened sandboxes. Use audit and `BlockNonCetBinaries` only after inventorying every DLL the process must load.

## `ProcessChildProcessPolicy`

Refuses any `CreateProcess` call originating from the process [463]. Edge content processes and Chromium renderers enable this. The structural attack class it closes is "renderer is compromised; renderer spawns `cmd.exe` or `powershell.exe` and the attacker pivots to a non-sandboxed cousin." With `ProcessChildProcessPolicy` on, the renderer cannot spawn anything; the attacker has to either bypass within the sandbox or attack the broker process.

The mechanism is process-creation mediation: the child creation request fails before a new image is launched. It does not prevent IPC to an already-running broker, COM activation that a broker performs on the process's behalf, or abuse of a privileged service that intentionally launches children. That is the point: child creation should be a brokered capability, not an ambient right of the least-trusted process. Enable it for renderers, parsers, and workers. Do not enable it for shells, IDEs, Office-style applications, installers, or any process whose product contract includes launching helpers; instead, move launch authority into a broker with an explicit allowlist.

## `ProcessPayloadRestrictionPolicy`: EAF / IAF / ROP checks

The mitigations that EMET originally bundled, carried forward into Windows Defender Exploit Guard [498]: Export Address Filter (EAF), Import Address Filter (IAF), ROP-Stack-Pivot, ROP-Caller-Check, ROP-Sim-Exec. Five sub-mitigations that detect heuristic exploit patterns. The honest assessment: these are defense-in-depth against legacy 32-bit binaries that cannot be recompiled with CFG, XFG, or CET. On modern x64 binaries built with `/guard:cf /CETCOMPAT`, the payload-restriction checks are largely redundant. They remain useful as a backstop for unrecompilable third-party code that runs in a hardened parent process.

The mechanism is heuristic monitoring of exploit *shapes*: reads of export/import tables that often precede API resolution, stack pivots where `ESP/RSP` moves into an attacker-controlled region, suspicious caller relationships, and simulated-execution patterns associated with ROP chains. The threat class is older payload staging, especially in processes that lack compiler-inserted CFI. The bypass class is any exploit that does not look like those heuristics, or any modern code-reuse chain that stays inside legitimate call/return and import-resolution patterns. Enable it when you are protecting legacy binaries you cannot rebuild; prefer compiler and hardware mitigations for new x64 code.

## `ProcessASLRPolicy` and `ProcessDEPPolicy`

The per-process knobs on top of the system-wide foundations [463]. `ProcessASLRPolicy` exposes `BottomUpRandomization`, `HighEntropy`, `ForceRelocateImages`, and other refinements: useful for forcing a paranoid configuration on processes that load third-party DLLs without `/DYNAMICBASE`. `ProcessDEPPolicy` is a 32-bit-only vestigial knob; on x64 it does nothing because DEP is unconditionally on.

Mechanically, DEP is the page-execute permission rule: data pages are non-executable, and executable pages should not be writable. ASLR is the address-selection rule: image bases, heaps, stacks, and bottom-up allocations move so an attacker cannot rely on constants. DEP closes injected-code execution; ASLR closes fixed-address code reuse and makes information disclosure a prerequisite. Their shared failure mode is composition. DEP alone leads to ROP; ASLR alone is defeated by an info leak; ASLR without `/DYNAMICBASE` leaves non-relocatable images fixed; high-entropy ASLR matters most on x64 where the address space is large enough to spend entropy. Enable ASLR refinements for every process, force relocation for third-party DLL risk, and treat `ProcessDEPPolicy` as relevant only for 32-bit compatibility review.

## The other policies

The remaining enum entries are not narrative afterthoughts; they are the compatibility and deployment edges that make the canonical six usable in real products. They are best read as a failure-analysis checklist rather than as equal-weight peers of CFG, CET, ACG, and CIG [464].

- **`ProcessControlFlowGuardPolicy`.** This is CFG's process-policy surface, complementing the compile/link/load pipeline described earlier. It can enable CFG behavior, export suppression, and strict rejection of images that lack CFG metadata. The threat class is forward-edge hijack through function pointers, vtables, callbacks, and indirect jumps. The failure classes are equally concrete: no compiler instrumentation means no check at the call site; no FID table means no useful bitmap entries; coarse granularity means the wrong valid function can still be called; JITs need deliberate valid-target marking through the supported APIs [477,478,479].

- **`ProcessSignaturePolicy`.** This is CIG's enum entry. The loader consults UMCI during image-section mapping and rejects images outside the selected signing set; failed loads surface as `STATUS_INVALID_IMAGE_HASH` rather than as code inside the process [488]. Its residual class is publisher trust: signed-but-vulnerable DLLs, already-loaded DLLs, and products that intentionally depend on third-party add-ins.

- **`ProcessDynamicCodePolicy`.** This is ACG's enum entry. It blocks executable allocation, W-to-X permission transitions, and executable mappings that are not backed by allowed signed images [490]. It closes shellcode allocation, JIT spray, and write-then-execute staging inside the protected process. Its compatibility failures are all code-generation features: in-process JITs, regex compilers, emulators, and AV signature engines.

- **`ProcessSystemCallFilterPolicy`.** This is the narrow syscall-filter entry [464]. Conceptually, it is stronger than disabling Win32k because it can reduce the reachable kernel ABI to a measured allowlist. Operationally, it is rare because Windows syscalls are not a stable application ABI and ordinary library calls touch surprising kernel paths. Use it only for tightly profiled sandboxes; for most applications, Win32k disablement plus brokered IPC is the maintainable version of the same idea.

- **`ProcessUserPointerAuthPolicy`.** This is the Windows-on-ARM64 pointer-authentication switch [464]. Pointer authentication signs selected pointers with a hardware key so raw pointer substitution fails at use time. The residual risks mirror PAC generally: signing oracles inside the same process, unsigned pointer classes, and non-control-data corruption.

- **`ProcessSEHOPPolicy`.** Structured Exception Handling Overwrite Protection is the 32-bit SEH-overwrite-era ancestor of modern CFI. It validates the exception-handler chain before dispatch, turning overwritten SEH metadata into a crash instead of a branch. On x64, table-based exception handling and CFG/CET make it a legacy backstop, but for 32-bit code it remains the right historical knob.

- **`ProcessActivationContextTrustPolicy`.** Activation contexts and manifests decide side-by-side assembly binding, COM class visibility, and compatibility metadata. The trust policy restricts untrusted activation contexts so manifest-driven redirection cannot become an ambient code-loading or component-confusion primitive. The cost is compatibility for applications with complex SxS and COM dependency graphs.

- **`ProcessMitigationOptionsMask`.** This is not an attacker-facing mitigation; it is ABI discovery. A launcher can ask which mitigation bits exist on the running Windows build, clear unsupported bits, and avoid failing process creation because it composed a policy word using a newer SDK than the target OS supports [464]. Its security value is making the rest of the policy set deployable without version guesswork.

- **`MaxProcessMitigationPolicy`.** This is the sentinel that terminates the enum, not a settable policy. Its existence matters only because the enum is an ABI with a discoverable upper bound.

Twenty policies plus a sentinel. The canonical six handle the control-flow primitives. The other fourteen handle adjacent surfaces. What does it look like when all of these are turned on at once, and which binaries actually do that?

## Verify it yourself (documented)

The source article did not include captured lab evidence, so this chapter does not invent any. This is a 🔵 **DOCUMENTED** verification section: the blocks below are commands a reader can run on a Windows host, plus the expected output shape. They are documented verification paths, not lab-captured transcripts.

> 🔵 **DOCUMENTED**: Microsoft Defender Exploit Protection / ProcessMitigations PowerShell surface

```powershell
Get-ProcessMitigation -Name msedge.exe |
Format-List CFG, CETShadowStack, BinarySignature, DynamicCode,
ExtensionPoint, ImageLoad, StrictHandle, SystemCall,
ChildProcess, FontDisable, PayloadRestriction,
SideChannelIsolation, ASLR, DEP
```

Expected shape: a hardened renderer reports enabled or intentionally audited blocks for CFG, CET shadow stack, dynamic-code policy, binary-signature policy, extension-point disablement, image-load restrictions, strict-handle checking, Win32k system-call disablement, child-process restrictions, and usually font restrictions [498]. Any `OFF` or `NOTSET` cell should have a product-specific reason.

> 🔵 **DOCUMENTED**: MSVC CFG load-config verification

```cmd
dumpbin /headers /loadconfig YourBinary.exe
```

Expected shape: the load-config directory contains non-zero Guard Flags, marks the image as CFG-instrumented, and reports a Guard CF Function Table / FID table. If `/guard:cf` was used without `/DYNAMICBASE`, the useful FID-table evidence is absent and CFG is effectively not protecting indirect calls in that binary [477,478,479].

> 🔵 **DOCUMENTED**: Defender Exploit Protection XML / Group Policy deployment

```powershell
Get-ProcessMitigation -RegistryConfigFilePath .\ProcessMitigations.xml
Set-ProcessMitigation -PolicyFilePath .\ProcessMitigations.xml
```

Expected shape: the XML names per-application mitigation blocks corresponding to the policies in this chapter. For child processes, the strongest deployment path is `CreateProcess` with `PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY` supplied through `UpdateProcThreadAttribute`, so the kernel installs the policy before the first user-mode instruction runs [463,498].

These probes establish narrow, useful facts. They do not prove memory safety, and they do not prove every loaded module was rebuilt with modern flags. They prove whether Windows reports a named mitigation as configured, whether the PE carries the metadata a mitigation needs, and whether the policy was deployed through a supported channel. That is the correct 🔵 DOCUMENTED evidentiary standard for this link in the chain.

## What does a maximally hardened modern Windows process look like?

It is one thing to enumerate policies. It is another to ask: who actually turns them on? Where does Microsoft itself enable each one, and what is the structural reason it cannot be enabled on the others?

The fastest way to answer that question is a single matrix. Each column is a binary; each row is a `PROCESS_MITIGATION_POLICY` value. Each cell is either *enabled*, or the structural reason it cannot be. The matrix below summarizes the typical `Get-ProcessMitigation` output for representative binaries, with structural-can't reasons drawn from public Microsoft documentation, Matt Miller's Edge mitigation blog [487], and the policy-enum reference [464,463].

![Figure: The hardened-process policy matrix as a heatmap: fourteen `PROCESS_MITIGATION_POLICY` values (rows) across six representative binaries (columns). Edge content and Recall light the full canonical recipe, every cell enabled; the other binaries carry documented structural gaps (Outlook's MAPI/COM add-in model blocks CIG and `ChildProcess`, Defender's runtime AV-signature JIT blocks ACG, Chrome's plugin model blocks default CIG) shown as the partial and "structural no" cells. Notepad's attack surface is small, so several policies are simply not applicable. The matrix is a threat-model artifact: every cell that is not enabled has a documentable structural reason.](diagrams/19-mitigations-policy-matrix.svg)

The pattern that emerges from this matrix is the chapter's most important practical observation. The matrix is *a threat-model artifact*.

For any sandboxed-parser design (a renderer, a font rasterizer, a PDF previewer, an image decoder), the structurally-correct policy set is the union of what Edge and Recall enable. Both binaries parse untrusted content from the internet or from local files; both run in isolation; neither needs to load third-party signed DLLs, draw windows, or launch child processes. They can enable the full canonical recipe.

For any extensibility-by-design surface, the policy set is smaller and the threat model has to absorb the gap. Outlook cannot enable CIG because the MAPI plugin model and third-party COM add-ins are an existential product feature. Outlook cannot enable `ChildProcess` because it launches Word to open attachments. Defender cannot enable ACG because the scanner engine generates emulator bytecode, signature-compilation routines, and regex JITs at runtime. It is, by design, a JIT for AV signatures, and that JIT runs in `MsMpEng.exe`. Chromium cannot enable CIG by default because of the third-party plugin model (Widevine, native messaging hosts, accessibility integrations).

> **Key idea.** The canonical 2026 hardened-process recipe is CFG plus CET shadow stack plus ACG plus CIG plus Disable-Win32k plus Disable-Extension-Points plus Image-Load (all three flags) plus StrictHandleCheck plus ChildProcess plus, for parsers, FontDisable, plus RedirectionGuard for filesystem-interacting binaries. Every binary that misses one of these does so for a documentable structural reason. Which is exactly the threat-model artifact the matrix above produces.

> **Note.** This is the recipe the VBS Trustlets chapter (Chapter 7) calls "user-mode hardened." The VBS-isolated Trustlets in the Secure Kernel layer have a separate, complementary surface; that chapter (Chapter 7) carries the kernel-side parallel.

Stacking the recipe is the best a 2026 user-mode process can be. But the attacker is still in the room. What survives even a fully-stacked process? What are the bypasses that work after every mitigation is on? The bypass analysis below answers that. First, a quick comparison: what other operating systems do, and what they do differently.

## What other operating systems do that Windows doesn't

Microsoft is not the only vendor with a per-process mitigation surface. Apple, Linux distributions, Chromium, and ARM-the-vendor are all in the same business, and they have made different structural choices. The honest comparison surfaces where Windows is ahead, where it is behind, and where the gap is not really a gap because the platforms solve slightly different problems.

**Apple: Hardened Runtime, ARM PAC, and JIT entitlement.** Apple shipped Pointer Authentication Codes (PAC) on the A12 (iPhone XS, September 2018) and on every Mac M1 onward. PAC signs a code pointer with a per-process cryptographic key held in privileged hardware registers, storing the signature in the unused upper bits of a 64-bit pointer. The ARM `PACIA`, `AUTIA`, `PACIB`, and `AUTIB` instructions sign and verify [499]; an unsigned or wrongly-signed pointer dereferenced through a `BR`/`BLR` instruction with the AUT variant faults. PAC is *structurally stronger* than CFG/XFG/CET because the key is held in privileged state and is unforgeable from user mode. There is no bitmap to lift the validation through.

Apple's JIT entitlement (`com.apple.security.cs.allow-jit`) is a stronger architectural answer than ACG [500]. Code that wants to JIT must declare it at build time and is granted a specific in-process W^X carve-out *only if* the entitlement is signed into the binary's code signature. The result: JIT capability is an attribute of the *signed binary* rather than a runtime API call, which closes the race-the-mitigation-window class structurally rather than by API migration (`UpdateProcThreadAttribute`).

**Linux: SELinux, landlock, LLVM `-fsanitize=kcfi`, LLVM `-fsanitize=cfi-icall`.** Forward-edge CFI in the Linux kernel first arrived in version 5.13 (June 2021) as an LTO-based jump-table implementation; the second-generation `-fsanitize=kcfi` scheme, which places a 32-bit type hash immediately before each function entry and does not require link-time optimization, replaced it in 6.1 (December 2022) [501]. The kCFI design is conceptually very close to XFG, but cheap enough to deploy on a kernel build because it sheds the LTO requirement. LLVM's user-mode `-fsanitize=cfi-icall` provides per-prototype CFI via jump-table dispatch but still requires LTO [502]. SELinux operates at a different layer of the stack (mandatory access control on filesystem and IPC resources) and is not directly comparable to a control-flow defense. It constrains *what the process can do* rather than *what control flows the process can follow*.

**Chromium / V8 sandbox.** Chrome enables CFG on Windows, leans on ARM PAC on macOS, and is layering the V8 sandbox on top of all of them [503]. The V8 sandbox is a Chrome-side software defense: it confines a compromised renderer to a specific bounded memory range, so a renderer-process compromise cannot synthesize pointers to arbitrary out-of-sandbox memory. The V8 sandbox sits inside the renderer (different from the OOP-JIT trust boundary above it) and aims to make even a fully-compromised JIT-output bug non-fatal at the system level.

**Android: Scudo allocator and ARM Memory Tagging Extension (MTE).** MTE attaches a 4-bit tag to every 16-byte allocation [504]. The CPU enforces the tag on every pointer dereference: tag mismatch raises a synchronous exception. Pixel 8 (October 2023) was the first consumer device with MTE-default-on for the kernel and key system services [504]. MTE catches the *cause* (use-after-free, linear overflow into the next allocation) rather than the *symptom* (control-flow hijack). It is conceptually orthogonal to CFI. The hard part is perf cost on memory-tagged loads, meaningful enough that even Apple has not enabled MTE on iOS as of 2026.

| Platform | Forward-edge | Backward-edge | Dynamic code | Memory safety |
|----------|---|---|---|---|
| Windows (x64) | CFG (coarse), XFG (deprecated) | CET shadow stack | ACG | none structural |
| Apple (ARM64) | PAC (cryptographic, per-process key) | PAC (signs return addresses too) | JIT entitlement (declarative) | none structural |
| Linux kernel | `-fsanitize=kcfi` (Linux 6.1+) | shadow stack on x86 CET; PAC-RA on ARM | not a kernel issue | Rust-in-kernel pilot |
| Android | BTI on supported SoCs | shadow call stack + PAC-RA | sandboxed by selinux + seccomp | MTE on Pixel 8 |
| Chromium | per-platform forward-edge | per-platform backward-edge | V8 sandbox (in-process) | layered |

The honest accounting:

- ARM PAC plus MTE is structurally stronger than CFG plus CET, because the cryptographic key (PAC) and the tag (MTE) are CPU-enforced state that no user-mode primitive can forge.
- Apple's JIT entitlement is a stronger architectural answer than ACG because it is declarative at signing time rather than imperative at process startup.
- SELinux/landlock is at a different layer (data access control) and is not directly comparable. It solves a different problem.
- Windows's mitigation surface is the *most extensively deployed and most frequently extended* per-process surface in industry use, by a wide margin. Twenty actual policies is more than any other vendor exposes to applications, and the API is stable, documented, and ABI-compatible across Windows versions back to Windows 8.

> **Note.** MTE catches what CFI cannot. A use-after-free that produces a controllable write (but never violates the control-flow graph) is invisible to CFG, XFG, CET, and PAC, but raises an MTE tag-mismatch fault on the very first attacker-controlled dereference. This is the structural reason memory-tagging is the emerging frontier and the structural reason a Windows-on-ARM-with-MTE future would close attack classes the current per-process surface cannot reach.

Stronger primitives exist on competing platforms. But Microsoft's per-process surface is the most extensively-deployed and most-frequently-extended in industry use. The *bypasses* are what tell us where the surface still leaks.

## How attackers respond to a fully hardened process

Every generation of Windows mitigation has shipped with a named bypass within a year of its release. Here is the tradition, one named class per defensive generation.

**Signed-DLL injection.** Predates CIG. Find a Microsoft-signed DLL with a controllable side effect: a DLL-search-order hijack against a signed Windows component, an Authenticode-padding write (CVE-2013-3900 family), or a signed driver with a known IOCTL privilege primitive. CIG sees a valid Microsoft signature and lets the DLL load. The mitigation is reactive: Microsoft's App Control / WDAC blocklist and the Driver Block List enumerate hundreds of banned-but-signed binaries; the list grows every quarter; the attacker's job is to find one not yet on it. This is one of the unsolved problems the open-problems section names.

**JIT spray as a CFG bypass (Theori, 2016).** The canonical writeup is Theori's *Chakra JIT CFG Bypass* [505]. The page itself states verbatim that the bypass targeted Microsoft Security Bulletin MS16-119 (October 2016): a Chakra fix that tightened the JIT's emit pattern. The technique: persuade the Chakra JIT to emit attacker-chosen byte sequences inside JIT-allocated code pages, at addresses the attacker has marked as valid CFG targets via the `SetProcessValidCallTargets` carve-out. The MS16-119 patch shrank the set of byte sequences a JavaScript program could induce the JIT to emit, but did not eliminate the technique structurally: the structural fix was ACG: move the JIT out of process.

> **Definition: JIT spray.** An exploitation technique in which an attacker writes JavaScript (or another JIT-targeted language) that causes the runtime JIT compiler to emit a long sequence of executable bytes at predictable addresses, where some of those emitted bytes form a useful gadget chain when reinterpreted at an offset. The classic JIT spray (Dion Blazakis, BHDC 2010) used Adobe Flash's ActionScript JIT. The 2016 Theori work generalized the idea to use the JIT to emit *CFG-valid* function-entry bytes [505].

**COOP: code-reuse without a single CFG-invalid call.** Discussed in the XFG section; recapped here as the *first* bypass class against coarse-grained forward-edge CFI [480]. The structural fix is fine-grained CFI: XFG, which Microsoft did not enforce by default and has since deprecated; LLVM's `-fsanitize=cfi-icall` and `-fsanitize=kcfi`; ARM PAC. The per-prototype hash check that XFG would have provided is exactly the property that closes COOP.

**Race-the-mitigation-window (Forshaw + Fratric, 2017).** Discussed in the ACG section; recapped here. The structural fix is `UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY)`, which installs mitigation policies *by the kernel* at `CreateProcess` time, before any user-mode code in the child runs. The race window between `CreateProcess` return and the child's `SetProcessMitigationPolicy` call is structurally closed. Documented in the Project Zero issue [491] and the Exploit-DB mirror [492].

**The CET-bypass research direction (McGarr, 2025).** Connor McGarr's Black Hat USA 2025 deck *Out of Control* names the live research front: kCFG and kCET in the Windows kernel [483]. The deck enumerates bypass classes that survive both kernel-mode CFG and kernel-mode CET: page-table modification of the kCFG bitmap (requires kernel write primitives the attacker may already have), abuse of unprotected global function-pointer arrays, structural limits of CET when the attacker is operating with kernel privileges in the first place. The user-mode mitigation surface is mature; the kernel-mode surface is where the live work happens. Hypervisor-Protected Code Integrity (HVCI) is what makes kCFG bitmap mutations harder (the bitmap is in VTL1, and a VTL0 kernel write cannot touch it) which is where the VBS Trustlets chapter (Chapter 7) and the Code Integrity chapter (Chapter 8) pick up the kernel-side parallel.

**Cross-context PAC oracles (Apple).** Listed for comparative completeness. PAC's per-process key is forgeable if an attacker can call into a function that signs an attacker-controlled pointer with the per-process key and then read the result. This is a known research class on Apple platforms and has produced several CVEs against Safari and iOS over the past five years.

The mitigation history forms a ladder rather than a finish line. Stack smashing led to DEP/NX. DEP/NX led to ROP. ROP led to CFG. Coarse CFG led to COOP and JIT-spray bypasses. JIT-spray led to ACG. Post-start ACG led to race-the-mitigation-window research and then to kernel-installed process-creation mitigation attributes. CET closes classical ROP on modern CPUs, while kCFG/kCET research marks the current kernel-side frontier.

![Figure: The defender↔attacker bypass ladder, read as gap analysis rather than an exploit recipe. Each rung names the primitive a mitigation removed (green, "closed by") and the residual class that survived to force the next mitigation (oxblood): stack injection → DEP/NX; fixed-address code reuse → ASLR; return-oriented programming → CFG and CET; coarse forward-edge CFI → XFG-style type hashes and PAC; in-process JIT spray → ACG; loader-based code entry → CIG and image-load policy; post-start mitigation races → kernel-installed `UpdateProcThreadAttribute`. CET closes classical ROP on modern CPUs; kCFG and kCET in the kernel remain the live frontier. A mature threat model can say at every rung either "we closed this" or "we accept this residual."](diagrams/19-mitigations-bypass-ladder.svg)

The ladder is defensive gap analysis, not an exploit recipe. Each rung names the primitive the previous mitigation removed and the residual class that forced the next mitigation to exist. A mature threat model should be able to point at every rung and say either "we closed this" or "we accept this residual risk for this documented product reason."

The honest summary is that three classes of bypass survive a fully-stacked user-mode process today:

1. Signed-but-vulnerable DLL hijack: defeats CIG by definition (publisher check, not content check).
2. COOP-style chains where the prototypes match the call site: defeats CFG (coarse-grained) and is not closed by CET because the call/return invariant holds.
3. Data-only attacks: which never violate any control-flow invariant at all, because no control transfer is hijacked.

What is the theoretical limit on what process mitigations can do? That is the next section.

## What process mitigations cannot do

The Abadi paper that founded CFI in 2005 [475] is also the paper that establishes CFI's structural ceiling. CFI is, by construction, a *control-flow* property. That is exactly the property a sophisticated attacker can avoid violating.

The formal claim from Abadi, Budiu, Erlingsson, and Ligatti: enforcement of CFI restricts an attacker to control-flow transfers that respect the static call graph. The paper *does not say* every reachable program behavior is benign. CFI says "the attacker's control flow stays inside the legal CFG." It does not say "the legal CFG is benign." Any attack that operates entirely within the legal CFG is invisible to any CFI variant, including CFG, XFG, CET, PAC, and kCFI.

The lower bound on what an attacker can do *while staying inside the legal CFG* is given by data-oriented programming. The canonical paper is *Data-Oriented Programming: On the Expressiveness of Non-Control Data Attacks* by Hong Hu, Shweta Shinde, Sendroiu Adrian, Zheng Leong Chua, Prateek Saxena, and Zhenkai Liang, all of the National University of Singapore Department of Computer Science [506]. The abstract is constructive and devastating: "such attacks are Turing-complete. We present a systematic technique called data-oriented programming (DOP) to construct expressive non-control data exploits."

> **Definition: Data-Oriented Programming (DOP).** An exploitation technique in which the attacker corrupts non-control data (authentication flags, length fields, function-table indices, loop bounds) and lets the program's own legitimate, unmodified control flow execute the attacker's intended computation. Hu, Shinde, Adrian, Chua, Saxena, and Liang proved DOP is Turing-complete: any computation can be expressed as a chain of data-only corruptions in a sufficiently-large program [506]. No CFI variant (CFG, XFG, CET shadow stack, ARM PAC, kCFI) can detect a DOP attack, because no control flow is hijacked.

The mechanism: the attacker corrupts a `current_user.is_admin` flag rather than redirecting a function pointer. They corrupt a `buffer_len` field to enable a subsequent legitimate write past the allocation's intended end. They corrupt a `next_state` index to drive a state machine through an attacker-chosen path. The program's own logic, executing every instruction the compiler emitted and following every control transfer the static call graph allows, performs the attack. DOP is, in a precise sense, the program working as designed: on data the attacker has chosen.

A second structural limit: process mitigations are *per-process*. The kernel has a parallel mitigation surface (kCFG, kCET, HVCI, Secure Kernel, the VBS/Trustlets stack) the per-process policies do not touch [483]. The user-mode hardening recipe stops at the syscall boundary. Everything beyond is the kernel's job. A renderer that is fully hardened can still be the entry point for a kernel privilege escalation if a syscall takes attacker-controlled input and the kernel-side code path has its own bug.

The third structural limit is the most uncomfortable to state.

> **Key idea.** Process mitigations harden the exploit chain. They do not fix the bug. The C/C++ memory-safety bug is still there; mitigations just constrain what the attacker can do with it.

Matt Miller, then a senior security engineer at the Microsoft Security Response Center, said this in his BlueHat IL 2019 talk. The deck is on GitHub at the Microsoft MSRC Security Research repository, with the load-bearing slide preserved verbatim [507]:

> **Quoted source.** ~70% of the vulnerabilities addressed through a security update each year continue to be memory safety issues.: Matt Miller, BlueHat IL 2019 [507]

ZDNet's contemporaneous coverage extended the claim: "around 70 percent of all the vulnerabilities in Microsoft products addressed through a security update each year are memory safety issues; a Microsoft engineer revealed last week at a security conference; over the last 12 years, around 70 percent of all Microsoft patches were fixes for memory safety bugs" [508].

Seventy percent. For a decade. The mitigations in this chapter (CFG, XFG, CET, ACG, CIG, every smaller policy in the enum) exist precisely because that number was not going down. Each generation raises the cost of weaponizing a memory-safety bug into a working exploit. None of them reduces the rate at which memory-safety bugs are introduced into the codebase in the first place.

> **The kernel has its own parallel surface.** For the kernel-mode side, see the VBS Trustlets chapter (Chapter 7) and the Code Integrity chapter (Chapter 8): kCFG, kCET, HVCI, and the Trustlets that execute in the Virtual Trust Level 1 (VTL1) Secure Kernel layer. The user-mode and kernel-mode mitigation surfaces are designed to compose: a renderer hardened to the canonical recipe in the hardened-process section, syscalling into a kernel hardened with kCFG and kCET, and protected by an HVCI hypervisor, is the layered defense Microsoft's strategic direction since 2014 has been building toward.

The only ceiling-breaker is to replace the *language* (so the bug never exists) or to replace the *memory model* (so the bug cannot be turned into a primitive). The two long-term answers are: memory-safe systems languages, principally Rust (Microsoft has been publicly committing to Rust in Windows since 2019 [509]); and capability-hardware platforms like CHERI and ARM MTE, which catch the bug at the dereference rather than the chain.

Three things have to be true for mitigations to keep buying time:

1. Each new mitigation closes a specific attack class. Which means a specific bypass class becomes the next research front.
2. Each new bypass class must take an attacker longer to develop than it takes Microsoft to ship the next mitigation: otherwise the curve goes the wrong way.
3. The fraction of memory-safety bugs in shipped code has to either stop rising or start falling: otherwise no number of mitigations stacks fast enough.

Mitigations are a delaying action. The long-term answer is somewhere else. The reader's belief at this point is no longer "stack enough mitigations and we win." It is "mitigations have a structural ceiling, and the bug is still there." If process mitigations have a ceiling, what is Microsoft pivoting toward, and what is the open frontier?

## Open problems

Six things are still unsolved, or, more precisely, six things are partially solved in ways that are documented but visibly imperfect.

**1. Forward-edge CFI without recompilation.** Binary-rewriting CFI (BinCFI, Mocfi, Lockdown) is not production-grade on Windows. Microsoft's strategic answer is "recompile first-party code with `/guard:cf` and accept that legacy third-party binaries remain unguarded." That answer is a long-tail problem: the surface of legacy third-party DLLs that load into hardened Windows processes (drivers, COM components, accessibility tools) is large, slow to recompile, and outside Microsoft's direct control.

**2. Backward-edge protection on pre-CET hardware.** Microsoft's pre-CET internal experiment was Return Flow Guard (RFG), a software-implemented per-thread shadow stack maintained by the runtime rather than the CPU. Tencent Xuanwu Lab bypasses came faster than Microsoft could harden RFG [510]; Microsoft pivoted to wait for Intel CET. Pre-Tiger-Lake (pre-September-2020) Intel hardware and pre-Zen-3 (pre-November-2020) AMD hardware remain unprotected on the backward edge. Enterprises that need backward-edge protection on older hardware have to sandbox in VBS-isolated VMs: the kernel-side surface the VBS Trustlets chapter (Chapter 7) owns.

**3. The JIT-engine compatibility tax under ACG.** Out-of-process JIT adds roughly a millisecond per JIT compilation for the IPC round-trip. For short-lived JavaScript (lots of small functions, one-shot pages, ad-network microservices), this is significant. Chrome's V8 sandbox project (active since 2023) confines V8's heap to a bounded memory range inside the renderer's address space (an in-process defense, not an out-of-process JIT boundary), which limits the impact of a JIT-output bug but does not erase the perf cost [503]. Interpreter-only renderers for low-trust contexts (small pages, ad iframes) are the medium-term direction; the cost is the runtime perf gap to fully-jitted JS.

**4. ACG plus AV interoperability.** Defender's `MsMpEng.exe` cannot enable ACG. The scanner engine generates code at runtime: signature compilation routines, emulator bytecode, regex JITs. Migration to interpreted bytecode is partial. This is a permanent compatibility tension between W^X-as-process-invariant and runtime-generated-code-as-a-feature, and it shows up in every AV engine across every vendor (CrowdStrike Falcon, SentinelOne, Symantec), not just Defender.

**5. Signed-but-vulnerable Microsoft DLLs as universal CIG-bypass loaders.** The Microsoft-signed DLL surface is enormous and historically full of side-effect DLLs. The App Control / WDAC blocklist is reactive. The blocklist publishes quarterly. New signed-but-vulnerable DLLs are found every quarter. This is a permanent residual risk against CIG and the structural reason vendors with sensitive workloads sometimes run with `MitigationOptIn` plus a per-process allowlist rather than `MicrosoftSignedOnly` plus an unbounded universe.

**6. XFG default-on tradeoffs.** XFG's instrumentation is in the MSVC binaries; the dispatch thunks are in `ntdll.dll`. Enforcement-by-default never shipped. McGarr's BHUSA 2025 deck names XFG as "deprecated" [483]; Microsoft's strategic direction is hardware-backed CFI (CET shadow stack for the backward edge) plus KCFG / KCET in the kernel. The unsolved question is whether the *forward edge* can ever get fine-grained protection without the compatibility cost that killed XFG. Apple's PAC suggests yes (because the cryptographic key approach has zero compatibility cost on cast); LLVM's `-fsanitize=cfi-icall` suggests yes for code built end-to-end with LTO. Neither has a Windows analog as of 2026.

> **Microsoft's strategic direction in one sentence.** Recompile first-party code with `/guard:cf /CETCOMPAT`. Push the kernel hardening (kCFG, kCET, HVCI) forward, since the user-mode surface is mature. Lean on hardware (Intel CET, AMD shadow stack, eventually MTE-on-Windows-on-ARM) rather than software heuristics. Accept that legacy unrecompiled binaries remain unguarded and quarantine them in lower-trust VBS-isolated contexts. That is the strategy McGarr's 2025 deck implies and that the Defender / Edge / Recall configurations in the hardened-process matrix execute [483].

Six open problems. The first four are engineering. The last two are structural. The structural ones suggest the next-decade answer is not a better mitigation, but a different memory model: Rust, CHERI, MTE.

## Practical guide: ten steps to ship a hardened binary

Ten steps take a new sandboxed-parser binary to the canonical 2026 recipe.

1. Run `dumpbin /headers /loadconfig YourBinary.exe`. Verify the `Guard Flags` word is non-zero, that `FID Table present` is in the output, and that the `Guard CF Function Table` is non-empty [477].
2. Compile and link with: `/guard:cf` `/guard:cfw` `/CETCOMPAT` `/DYNAMICBASE` `/HIGHENTROPYVA` `/NXCOMPAT`. The `/CETCOMPAT` flag requires Visual Studio 2019 or later and x64 only [478,479,485].
3. Call `SetProcessMitigationPolicy` (or, better, `UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY)` for child processes) for: `ProcessDynamicCodePolicy`, `ProcessExtensionPointDisablePolicy`, `ProcessImageLoadPolicy` (with `NoRemoteImages` plus `NoLowMandatoryLabelImages` plus `PreferSystem32Images`), `ProcessStrictHandleCheckPolicy`, `ProcessSystemCallDisablePolicy` (if your process does not draw windows), and `ProcessUserShadowStackPolicy` (with `EnableUserShadowStack` and, for the most-hardened sandboxes, `BlockNonCetBinaries`), but note that `EnableUserShadowStack` must be applied at process creation via `UpdateProcThreadAttribute` or exploit-protection configuration: Microsoft documents that once HSP is disabled it cannot be enabled at runtime through `SetProcessMitigationPolicy` (only strict-mode upgrade and `BlockNonCetBinaries` can be set after start) [463,490,495,486].
4. Use `UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY)` rather than post-`CreateProcess` policy installation for any child process. This is the single most important step on this list.
5. Audit with `Set-ProcessMitigation -PolicyFilePath` (Group Policy / Intune deployable XML). The schema and the cmdlet are documented in the Defender Exploit Protection reference [498].
6. For sandboxed parsers (PDF, image, video, font), enable `ProcessFontDisablePolicy`. Refuse non-system fonts at the per-process layer.
7. For signed-component-only processes, enable `ProcessSignaturePolicy(MicrosoftSignedOnly)`. Accept that some third-party DLLs will not load and document each gap in your threat model [488].
8. For browser-class sandboxed children, prohibit child-process creation with `ProcessChildProcessPolicy`. Closes the renderer-to-`cmd.exe` pivot class.
9. Validate the rendered policy at runtime with `Get-ProcessMitigation -Name <binary>`. Spot-check that every flag you set in code is reflected in the cmdlet output [498].
10. For each policy you *cannot* enable, document the structural reason in your threat model. A binary that misses CIG because it depends on third-party COM add-ins is making a deliberate threat-model choice; that choice must be visible to the security review.

> **Step 4 is the single most important step.** `UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY)` closes the race-the-mitigation-window class structurally (the ACG and bypass-analysis sections). Every other step on this list is a useful addition. Step 4 is the load-bearing step that lets every other step work as designed. Without it, a peer process in the same security context can disable any of the others between `CreateProcess` and the child's first attempt to install its policies.

The composition of the policy bitfield itself is mechanical. Each policy is a small DWORD-sized structure; the `PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY` attribute for `UpdateProcThreadAttribute` carries the enforcement flags as a 64-bit value (extended to a second 64-bit word for the newer Policy Set 2 flags such as CET), while audit-only flags are supplied through a *separate* attribute, `PROC_THREAD_ATTRIBUTE_MITIGATION_AUDIT_POLICY`.

**Show the Get-ProcessMitigation command to verify a running binary**

Run this in an elevated PowerShell session, replacing `msedge.exe` with the basename of your binary:

```text
Get-ProcessMitigation -Name msedge.exe |
  Format-List CFG, CETShadowStack, BinarySignature, DynamicCode,
              ExtensionPoint, ImageLoad, StrictHandle, SystemCall,
              ChildProcess, FontDisable, PayloadRestriction,
              SideChannelIsolation, ASLR, DEP
```

Each block in the output shows `Enable`, `Audit`, and the subordinate flag word with its individual boolean fields. Spot-check that every flag your code sets in `SetProcessMitigationPolicy` is reflected as `ON` in the cmdlet output, and that any `OFF` or `NOTSET` cell has a documented structural reason in your threat model [498].

Stack the recipe. Document the gaps.

> **Bequeaths.** The process-mitigation surface hands the next link one narrow, load-bearing guarantee: inside a process that opts into the full recipe, the *classic* path from a memory-corruption bug to code execution is closed. No injected shellcode, no predictable gadget base, no hijacked indirect call or return, no runtime-generated code, and, the clause the rest of the chain reuses, **no image executes unless it chains to an allowed signing root**. That last clause is Code Integrity Guard, the per-process echo of the loader power the Code Integrity chapter (Chapter 8) built. Which is exactly why it cannot answer the question it raises: *what does that signature actually prove?* The Authenticode chapter (Chapter 12) takes the handoff and dissects the envelope byte by byte, including the CVE-2013-3900 padding gap this chapter could only name; whether "signed" is *enough* (the signed-but-vulnerable residual) is the curated-blocklist problem the App Control chapter (Chapter 13) owns. The bequest is deliberately small, and naming what it does *not* give is the honest half. It does NOT fix the bug: the C/C++ memory-safety defect is still there, still roughly 70% of the year's CVEs, merely harder to weaponize. It does NOT see data-only attacks, because Data-Oriented Programming never leaves the legal control-flow graph. It does NOT reach past the syscall edge: the kernel's own kCFG, kCET, and HVCI surface belongs to the Code Integrity chapter (Chapter 8) and the VBS Trustlets chapter (Chapter 7). The chain has made the exploit expensive; it has not made the bug safe, and the only ceiling-breakers, a memory-safe language or a memory-tagging CPU, live past the end of this surface entirely.
