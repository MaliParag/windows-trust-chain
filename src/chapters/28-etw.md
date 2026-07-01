# ETW: The EDR Substrate

::: trust-ledger

- **Inherits:** Not a guarantee but a vantage point. The events every prior link emits as it runs: process and token creation from Windows Access Control (Chapter 22) and the Integrity-Level Stack (Chapter 23); impersonation from The SeImpersonate Primitive (Chapter 24); script and assembly execution that the credential-theft tradecraft of Mimikatz (Chapter 14) rides; memory-modifying syscalls aimed at Credential Guard isolated secrets (Chapter 15); and driver loads the Code Integrity (Chapter 8) and Authenticode (Chapter 12) chains adjudicate. The consumer gate it leans on is borrowed: Protected Process Light (Chapter 10) for consumer identity and the Early Launch Antimalware step of Secure Boot (Chapter 1) for load order; the one kernel-emitted producer it depends on sits on the VTL0 side of the boundary the hypervisor (Chapter 9) and the Secure Kernel (Chapter 6) enforce.
- **Promise:** A high-rate, mostly-tamper-evident record of what the chain actually did (process, image, script, memory-syscall, and driver events delivered to an authorized consumer) such that an attacker's action against a prior link leaves an observable trace that survives the user-mode patch class. Serviced boundary: the user-to-kernel transition that keeps the EtwTi producer out of reach of in-process patching; the PPL+ELAM consumer-admission gate above it is antimalware infrastructure Microsoft maintains, not a boundary it commits to service against a kernel-level attacker.
- **TCB:** The provider *producers* (where each event is emitted. A user-mode `ntdll` stub versus the kernel syscall path for EtwTi); the per-CPU buffer and session machinery with its `LogFileMode` and keyword configuration; the autologger registry recipe that decides what starts at boot; and the PPL+ELAM signer-and-load-order gate that admits an EtwTi consumer. User-mode SYSTEM or administrator code, the kind that can patch its own `ntdll`, is explicitly *outside* the producer's reach for the EtwTi signal, which is the whole point of emitting it from the kernel. The VTL0 kernel itself stays inside the TCB: an attacker who reaches kernel mode, typically via BYOVD, can still blind or corrupt the signal.
- **Adversary → Break:** An attacker who controls a prior link tries to blind the observer: rewrite the autologger recipe before boot, patch `ntdll!EtwEventWrite` / `NtTraceEvent` to `0xC3` in the emitting process, or bring a vulnerable driver (BYOVD) to tamper with ETW kernel structures. The Promise covers *observation of memory-modifying syscalls from a place the in-process patcher cannot reach*, not completeness: a sub-flush payload, a pre-ETW boot path, or an unenumerated syscall is recorded late or not at all.
- **Residual:** Kernel-mode tampering once a write primitive exists → narrowed by the Vulnerable Driver Blocklist and HVCI, owned by Code Integrity (Chapter 8) and the hypervisor (Chapter 9); pre-ETW early-boot code → Measured Boot (Chapter 4) and the TPM (Chapter 2); telemetry whose producer ought to live above VTL0 (`EtwSi*`) → VBS Trustlets (Chapter 7) and the Secure Kernel (Chapter 6).
- **Bequeaths:** To the defender, *visibility*: a queryable, mostly-tamper-evident account of the chain's behavior. Hands forward to Part IV (Cloud): the risk engines of Zero Trust (Chapter 26) and Continuous Access Evaluation (Chapter 27) consume endpoint detections as one input to an access decision. Does NOT provide: prevention (ETW observes, it does not deny), completeness (it is lossy by design), or forensic soundness (no chain-of-custody guarantee between emission and ingestion).
- **Proof:** 🔵 documented at the point of claim. `logman`, `wevtutil`, `reg query`, and `Win32_DeviceGuard` surfaces (Microsoft Learn); the public EtwTi reverse-engineering record; and Yarden Shafir's live `_ETW_REALTIME_CONSUMER` debugger walk. No lab capture exists for this chapter; its evidence is documented, not captured.
:::

> **The Reasoner's question.** When an EDR says it saw a process, a script block, a memory allocation, or a credential dump, which Windows trust link produced that evidence, and which attacker action can blind it?

The answer turns on one architectural asymmetry. Event Tracing for Windows is a high-rate, kernel-buffered observability bus modern Windows EDRs commonly consume, and a 2007-era decision (letting eight sessions read the same provider concurrently) is what lets multiple vendors coexist on a single host. Microsoft's `Microsoft-Windows-Threat-Intelligence` provider, gated behind Protected Process Light and an ELAM-signed Antimalware certificate in the Windows 10 RS-era (the exact public onboarding date is not pinned by Microsoft), fires from the kernel side of memory-modifying syscalls and survives the user-mode `EtwEventWrite` patch class that defined red-team tradecraft from 2020 to 2022. The remaining attack surface (BYOVD-driven kernel tampering) is structurally narrowed by the Vulnerable Driver Blocklist enabled by default since Windows 11 22H2, leaving the sub-microsecond-payload gap as ETW's irreducible "observation, not enforcement" limit.

## Why the patch did not silence Defender

As a representative 2026 endpoint-detection scene, imagine a red-team operator on a Defender-protected box running the move that worked five years ago. They locate `ntdll!EtwEventWrite` in the calling process, write the byte `0xC3` over the function prologue, and the calling process now silently fails to emit user-mode ETW events. The .NET CLR provider goes dark. `Invoke-Mimikatz` loads from `execute-assembly` without lighting up `Microsoft-Windows-DotNETRuntime`. A Defender alert can still arrive shortly afterward, because the detection pipeline is not limited to that one user-mode provider.

The patch worked. The .NET tracing provider in that process is mute. Attach a debugger and disassemble the function prologue: the first byte is now `0xC3`, the near-return opcode [1072], and any caller falls straight back to its return address before producing a single event. The technique is the one Adam Chester documented in March 2020 [1073], and to a generation of red teamers it has functioned as a near-universal ETW evasion ever since.

So why did Defender still fire?

Because Defender does not have to rely on `Microsoft-Windows-DotNETRuntime` alone to detect credential-theft tradecraft. One load-bearing signal in that class is `Microsoft-Windows-Threat-Intelligence` [1074]: a provider whose GUID is `{f4e1897c-bb5d-5668-f1d8-040f4d8dd344}`, whose events fire from inside the kernel side of memory-modifying syscalls, and whose producer the user-mode patcher cannot reach. Defender and MDE detections are multi-signal and may be cloud-enriched; the architectural point is narrower: the patch operated on a `ntdll` trampoline, while EtwTi is emitted from a different layer entirely.

> **Key idea.** Modern Windows EDR is layered on ETW, and the layers fail under different attacks.

That single asymmetry (one provider goes dark to a one-byte patch, another fires from a place the patcher cannot touch) is the spine of the interlude. Around it sits a 26-year story of one Microsoft team accidentally building the substrate of every modern Windows endpoint security product. The credential dump the operator tried to hide is exactly the tradecraft the Mimikatz chapter (Chapter 14) traces and the secret the Credential Guard chapter (Chapter 15) moves out of reach; this chapter is about the layer that *sees* the attempt.

> **Definition: ETW (Event Tracing for Windows).** A high-rate, kernel-buffered tracing facility built into Windows since 2000. Components called *providers* emit events tagged with a GUID; *controllers* configure trace sessions; *consumers* subscribe to live event streams or read recorded `.etl` files. ETW was designed for low-overhead developer diagnostics; it was retrofitted into a core security-telemetry substrate for modern Windows EDR products.
>
> **Definition: EDR (Endpoint Detection and Response).** A class of endpoint security product that ingests behavioral telemetry (process creation, image load, memory allocation, network connection, registry change), correlates it against detection logic, and produces alerts and response actions. On Windows, the dominant EDRs (Microsoft Defender for Endpoint, CrowdStrike Falcon, SentinelOne, Elastic Defend, Wazuh, Sysmon-plus-SIEM) commonly combine ETW streams, Windows event channels, and/or kernel callbacks, with the exact mix varying by product and evidence class.

To understand why a one-byte patch silences one provider but not another, we have to go back to a Windows 2000 design decision about per-CPU ring buffers.

## ETW in Windows 2000: the performance problem that started it all

Imagine a 1999 network-driver author. A customer's NT4 production server is corrupting packets under load and the only available instrumentation is `DbgPrint`. Each call serializes through a kernel debug port, costs measurable percentage points of CPU on a busy box, and ships data to whoever happens to have the kernel debugger attached. The customer says no. The bug reproduces only at production traffic levels. You cannot ship enough printf-debugging through a debug port to find it.

That is the engineering pain Insung Park and Ricky Buch's team was solving when ETW shipped with Windows 2000. Their design moves (recorded years later in the definitive April 2007 MSDN Magazine article on the Vista upgrade [1075]) still define the architecture two and a half decades later.

The first move was per-CPU ring buffers. A producer on CPU 7 writes to CPU 7's buffer with no lock contention against producers on other CPUs. Hot-path tracing on a 64-core machine does not serialize. The kernel allocates at least two buffers per logical processor [1076] so a producer can keep writing while a writer thread drains the previous buffer.

The second move was an asynchronous writer thread. The producer never blocks on disk I/O. It writes to its CPU's buffer and returns. A separate kernel thread drains buffers to file or hands them to a real-time consumer. ETW pushes the latency tax onto the consumer and the storage path, never onto the producer's hot loop.

The third move was dynamic enable and disable. Park and Buch describe the resulting capability in one sentence:

> ETW gives you the ability to enable and disable logging dynamically, making it easy to perform detailed tracing in production environments without requiring reboots or application restarts.: Park & Buch, *MSDN Magazine*, April 2007 [1075]

That sentence is the entire reason ETW could later become the EDR substrate. A producer compiles its trace points into shipping code at low cost; a controller flips them on at runtime when somebody actually wants the data. Without that property, you cannot build a security product that ships universal kernel tracing on a billion endpoints.

The fourth move was the trichotomy of providers, controllers, and consumers [1077]. Microsoft did not write ETW as an internal-only facility. From the start, third parties could write providers (driver authors instrumenting their own code), controllers (performance tools starting and stopping sessions), and consumers (analyzers reading event streams). The architecture is open by design.

> **Definition: Provider.** A component that emits ETW events, identified by a GUID. A provider is registered with the system at runtime via the `EventRegister` API (or its predecessor `RegisterTraceGuids` for classic providers) and emits events via `EventWrite` (or `TraceEvent`). Providers ship inside Windows itself, inside Microsoft applications, and inside any third-party binary that wants to expose tracing.
>
> **Definition: Controller.** A component that creates, configures, enables, and stops trace sessions. Controllers select which providers a session subscribes to and at which level and keyword bitmask. The Windows Performance Recorder, `logman`, `xperf`, and every EDR's session-management code are controllers.
>
> **Definition: Consumer.** A component that reads events from a session in real time or from an `.etl` file on disk. Consumers register a callback that the system invokes once per delivered event. The Windows Performance Analyzer, the krabsetw library, SilkETW, and every EDR's sensor process are consumers.
>
> **Walkthrough: the Windows 2000 ETW loop.** Start with the controller, not the provider. A tool such as `logman`, Windows Performance Recorder, or an EDR sensor calls `StartTrace` to allocate a trace session: a named kernel object with its own buffer pool, flush timers, logger mode, and optional `.etl` file. The controller then calls the enable API for one or more provider GUIDs. That enable call is the moment a dormant trace point becomes live.
>
> Now follow one event. A provider running on CPU 0 reaches an `EventWrite` or classic `TraceEvent` site. If the provider is disabled for that session's level and keyword mask, the hot path returns quickly. If it is enabled, the event header and payload are copied into CPU 0's ETW buffer, not into a global log protected by a single contended lock. A provider running simultaneously on CPU 7 writes into CPU 7's buffer. When a buffer fills or the flush timer fires, the ETW writer thread drains the completed buffer either into the session's `.etl` file or into the real-time delivery path. A consumer that has called `OpenTrace` and `ProcessTrace` receives the decoded `EVENT_RECORD` later. This is the entire performance bargain: producers pay the cost of a bounded memory copy, while consumers absorb parsing, correlation, and storage latency.

The original Windows 2000 implementation supported 32 trace sessions running simultaneously [1078], a number Microsoft later raised to 64 globally. ETW was framed as a developer-diagnostics facility (the Windows Driver Kit primary still describes it that way [1077]) and the security-telemetry use case did not exist for almost a decade.

But the design choices that made ETW good for low-overhead production diagnostics turn out to be exactly the design choices a security telemetry bus needs. Per-CPU buffers solve the multi-core throughput problem. Asynchronous writes solve the producer-latency problem. Dynamic enable solves the always-shipping-but-mostly-off problem. The trichotomy solves the third-party-extensibility problem. Twenty-six years later, modern Windows EDRs commonly consume telemetry through the same four primitives, alongside product-specific drivers, callbacks, and cloud pipelines.

> **Sidenote.** Windows 2000's 32-session global cap [1078] is preserved verbatim on the modern Microsoft Learn page: "Windows 2000: Supports only 32 event tracing sessions." The cap doubled to 64 in later releases and has stayed there ever since.

The 2000-era design carried one limit, however, that turned out to matter for security: only one trace session could enable a classic provider at a time. The next ten years would be defined by the consequences.

## The MOF era: one session, one steal, one decade of coexistence pain

In 2005, a third-party performance monitor that registered a classic provider could find itself silently disabled the moment Microsoft's `wprui.exe` started its own session against the same provider GUID. The first session got no error. It just stopped receiving events. That second-consumer-steals-first behavior is the architectural fact of the entire 2000-2007 era.

Microsoft Learn still documents the rule in one sentence:

> **The second-consumer-steals semantics.** "Up to eight trace sessions can enable and receive events from the same manifest-based provider. However, only one trace session can enable a classic provider. If more than one trace session tries to enable a classic provider, the first session would stop receiving events when the second session enables the provider.": Microsoft Learn, Configuring and Starting an Event Tracing Session [1079]

That single rule made multi-EDR coexistence on classic providers structurally impossible. If Defender's predecessor and a third-party HIPS both wanted real-time process events from the same classic provider, they had to fight for it. The loser got silence with no notification.

The provider class involved was *MOF-based*, named after the schema language that described its events.

> **Definition: MOF (Managed Object Format).** The schema description language inherited from WBEM (Web-Based Enterprise Management). For ETW, MOF files describe each event a classic provider can emit (field names, types, tasks, opcodes) and are compiled into the WMI repository at install time using `mofcomp`. Consumers decode events by querying the WMI repository for the matching MOF schema.
>
> **Definition: Classic provider.** A synonym for *MOF provider*. The original ETW provider class introduced in Windows 2000. Registered with `RegisterTraceGuids`, emits events via `TraceEvent`, decoded against a MOF schema in the WMI repository. Capped at one trace session per provider.

The MOF model was workable for a single-consumer world. A performance-tuning team running an in-house tool could enable the provider, capture, and disable. As the substrate of a security stack with multiple agents on the same host, it could not work. The mid-2000s had not yet produced a "multiple agents on the same host" world, so the limit did not bite immediately. By 2007 it would.

| Class | Era | Schema location | Sessions/provider | Adoption in 2026 |
|---|---|---|---|---|
| MOF / classic | 2000 | WMI repository | 1 | Niche; mostly NT Kernel Logger |
| WPP | 2002 | `.pdb` (TMF) | implementation-dependent | Pervasive inside Windows internals |
| Manifest-based | 2007 (Vista) | XML manifest | 8 | Dominant for security telemetry |
| TraceLogging | 2015 (Win10) | Inline (TLV) | 8 | Rising for new app/service code |

A handful of classic providers survived the 2007 transition and are still significant. The most important legacy anchor is the NT Kernel Logger [1078], the special-purpose system session that captures high-throughput kernel events such as file I/O, disk I/O, registry operations, and TCP/IP network events; Microsoft documents it as the only session that can accept events from the classic kernel event providers [1080]. On Windows 7 and later, the SystemTraceProvider path widened that model, and on Windows 8 and later it can be multiplexed for up to eight logger sessions [1081]. Diagnostics tools use this kernel-trace family when they need line-rate kernel events; Sysmon, by contrast, is better understood as a callback-then-publish design, as described later.

> **Sidenote.** The NT Kernel Logger is a system reserved logger. There is exactly one of it on a host, and the kernel itself owns the buffers. Tools that want legacy kernel disk, file, registry, or network events at high throughput historically subscribed through this family rather than through ordinary manifest providers. Modern SystemTraceProvider multiplexing relaxes the old single-session picture, but full-fidelity kernel tracing is still governed by system-provider rules, not by the simpler manifest-provider story.

By 2007 Microsoft knew the one-session limit had to go. The fix shipped with Windows Vista in January 2007, and it was the central architectural decision of the entire ETW-as-EDR-substrate story.

## Vista's eight sessions: the architectural decision that made the modern EDR endpoint possible

![Figure: Vista's unified provider model (2007). A single EventWrite fans out to the per-CPU ring buffer (drained by the writer thread to an.etl file or real-time delivery) and to the evtx channel, and up to eight independent real-time sessions read the same manifest provider at once; the classic/MOF model allowed only one, the second consumer silently stealing the first.](diagrams/28-etw-vista-fanout.svg)

Park and Buch open their April 2007 MSDN Magazine article with the line that frames every later development:

> On Windows Vista, ETW has gone through a major upgrade, and one of the most significant changes is the introduction of the unified event provider model and APIs.: Park & Buch, *MSDN Magazine*, April 2007 [1075]

The new model raised the per-provider session cap from one to eight. That single number is why Defender, CrowdStrike Falcon, SentinelOne, Sysmon, and a researcher's SilkETW tap can all read `Microsoft-Windows-Kernel-Process` [1082] from the same host today without one of them stealing events from the others.

The Vista model also unified two things that had been separate. ETW providers wrote to per-CPU ring buffers; the Win32 Event Log was a different facility with its own writer, its own format, and its own consumers. Park and Buch describe the unification verbatim:

> The new unified APIs combine logging traces and writing to the Event Viewer into one consistent, easy-to-use mechanism for event providers.: Park & Buch, *MSDN Magazine*, April 2007 [1075]

After Vista, a manifest-based provider can use the unified eventing APIs to feed ETW trace sessions and Windows Event Log channels from the same provider definition, depending on how the manifest's channel mappings are configured. Event Viewer is therefore a view over Windows Event Log channels backed by that unified provider model, not a real-time ETW consumer equivalent to an EDR sensor.

> **Definition: Manifest-based provider.** The Vista-era ETW provider class. The provider author writes an XML manifest enumerating events, fields, tasks, opcodes, levels, keywords, and channels. The `mc.exe` message compiler turns the manifest into a binary resource embedded in the provider binary; `wevtutil im` registers the manifest with the system at install time. At runtime the provider calls `EventRegister` once per provider GUID and `EventWrite` per event. Capped at eight trace sessions per provider.
>
> **Definition: Channel.** A logical destination for an event, declared in a manifest. The four standard channels are *Admin* (operational events for administrators), *Operational* (verbose events for operators), *Analytic* (high-volume events for diagnostics), and *Debug* (developer-only events). When the provider's `EventWrite` fires, the kernel demultiplexes by channel: events with channels enabled in the `evtx` configuration land in the corresponding channel log, while subscribed real-time consumers receive them through their session.

The deployment pipeline for a manifest-based provider is heavier than for a classic provider. The author writes a manifest, compiles it, embeds the resource, and runs `wevtutil im` at install time. Microsoft Learn calls out the distinction between provider registration and manifest installation [1083] explicitly, and notes that each process can register up to 1,024 providers [1083]. In practice few processes come close.

> **Walkthrough: the Vista manifest pipeline.** A Vista-era provider author begins with XML: provider GUID, event IDs, tasks, opcodes, keyword bits, channel mappings, and typed fields. `mc.exe` compiles that manifest into message resources that ship inside the provider binary; the installer runs `wevtutil im` so the operating system has system-wide decode metadata before the first event fires. At runtime the provider calls `EventRegister` once for its GUID and `EventWrite` for each event instance.
>
> The important change is the fan-out. The same `EventWrite` can feed a real-time ETW session and an Event Log channel. If the event is mapped to an Admin or Operational channel, the Event Log service can persist it as `.evtx`; if an EDR has enabled the provider in a real-time session, the ETW buffer path delivers the same structured payload to that consumer. The installed manifest is the decoder for both worlds. This is why a security engineer can see process creation in Event Viewer or through an EDR pipeline without the provider author maintaining two separate instrumentation systems.

The cap rules now read like this: eight trace sessions can enable a manifest-based provider concurrently [1084]; up to 64 sessions can run on the system at once [1078]; `EnableTraceEx2` returns `ERROR_NO_SYSTEM_RESOURCES` when the per-provider cap binds [1085]. The 8-session number was chosen for ergonomics, not for security planning, but it is the load-bearing number in modern Windows endpoint security.

> **Key idea.** The eight-session cap on manifest-based providers is the single architectural decision that made multi-EDR coexistence on the same Windows host possible. Without it, the second EDR to subscribe to `Microsoft-Windows-Kernel-Process` would silently steal events from the first.

A Windows 7-era driver author shipping the inaugural `Microsoft-Windows-Kernel-Process` provider, GUID `{22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716}`, authored a manifest declaring `ProcessStart` (event ID 1), `ProcessStop` (event ID 2), `ImageLoad` (event ID 5), and so on. Defender's `MsMpEng.exe` could subscribe; the future CrowdStrike Falcon could subscribe; the future Sysmon could subscribe; the future SilkETW researchers could subscribe. None starves another. The Vista unification is the architectural enabler of the modern multi-EDR Windows endpoint.

With multi-consumer concurrency solved, the next problems were authoring overhead and producer integrity. Two parallel paths branched off the Vista manifest model: TraceLogging for the first, the EtwTi PPL/ELAM gate for the second.

## Two more provider classes: WPP for the kernel tree, TraceLogging for the app tier

Vista's manifest-based providers solved coexistence and decoding, but they were heavy to deploy. Microsoft shipped two more provider classes (one older than Vista and one younger) that traded manifest deployment for two different kinds of simplicity.

### WPP: the C-preprocessor approach

WPP (Windows software trace PreProcessor) predates Vista. Community references and the Park & Buch description of ETW being "abstracted into the Windows preprocessor (WPP) software tracing technology" [1075] place its first WDK ship in the Windows XP era; no Microsoft primary pins a specific build. It became the standard tracing facility inside the Windows kernel tree itself for years. The WDK page [1086] frames its purpose:

> "WPP software tracing supplements and enhances WMI event tracing by adding ways to simplify tracing the operation of the trace provider. It is an efficient mechanism for the trace provider to log real-time binary messages."

A WPP provider is authored in C with macros that look like printf calls. The C preprocessor expands `DoTraceMessage(FlagId, "Frobnicating widget %d", widgetId)` into an `EventWrite` call against an auto-generated provider GUID. Format strings are extracted at build time into a *Trace Message Format* file embedded in the binary's `.pdb`. The producer cost is the smallest of any ETW provider class: emitting an event is a function call plus a few stores into a buffer. There is no manifest to deploy, no XML to author.

The corresponding decode cost is the highest. A WPP event arrives at the consumer as a binary payload referencing a TMF identifier. To turn that into a human-readable message the consumer needs the producer's `.pdb` file. If you do not have the symbols for the binary that emitted the event, you do not know what the event means.

That decode cost is why WPP did not become the EDR substrate. Sealighter's README puts the operational consequence verbatim:

> **Definition: WPP (Windows software trace PreProcessor).** A C-preprocessor-based ETW authoring path inherited from the XP-era WDK. Format strings are extracted to a TMF resource that lives in the producer's `.pdb`. Producer cost is minimal; decode cost requires the producer's symbol files. WPP providers are usually treated operationally like classic private tracing: symbol-dependent and poorly suited to multi-consumer security telemetry. The exact session-limit behavior depends on the registration path, so the safe architectural conclusion is about usability, not a universal cap.
>
> "WPP traces compounds the issues, providing almost no easy-to-find data about provider and their events.": Sealighter README [1087]

WPP providers also fail the multi-EDR test for practical reasons even where the underlying ETW session rules vary by implementation: consumers need symbols/TMF data, provider inventories are hard to discover, and the resulting stream is not a stable public security contract. So WPP became the kernel-tree internal tracing facility: ubiquitous inside Microsoft's source tree, marginal for public EDR telemetry.

### TraceLogging: schema in the payload

Eight years after Vista, in Windows 10 (2015), Microsoft shipped a parallel path that solved a different problem. TraceLogging [1088] keeps the eight-session cap of manifest providers but eliminates the manifest deployment burden:

> "TraceLogging is a system for logging events that can be decoded without a manifest.": Microsoft Learn, About TraceLogging [1088]

A TraceLogging event carries its own schema inline. The event payload is a sequence of typed-length-value triples: a one-byte type tag, a length, and the data. A consumer that has never seen the provider before can still decode the event because the names and types of every field are *in the event*. The provider author needs no XML manifest, no `mc.exe`, no `wevtutil im`.

The trade-off is per-event size. Inline schema strings cost bytes per event. For a high-volume provider emitting millions of events per minute, the per-event size matters and a manifest-based provider is correct. For a new component author who wants tracing without an install-time deployment dance, TraceLogging is the right answer.

> **Definition: TraceLogging.** A self-describing ETW provider class shipped in Windows 10. Schema is inline in each event payload as type-length-value triples; consumers decode without a manifest. Available from C/C++ via `TraceLoggingProvider.h`, from .NET via `EventSource` with `EtwSelfDescribingEventFormat`, and from WinRT via `LoggingChannel`. Inherits the eight-session cap from the manifest-based class.

TraceLogging is also the unified path across runtimes. The same self-describing payload format is emitted from native C/C++, from .NET (when an `EventSource` opts into `EtwSelfDescribingEventFormat`), and from kernel-mode drivers [1089]. A consumer using TDH (the Trace Data Helper API) decodes them without distinguishing between the runtime that emitted them.

### Four classes, four trade-offs

| Class | First Shipped | Schema Location | Sessions/Provider | Decode without symbols/manifest? | Best for |
|---|---|---|---|---|---|
| MOF / classic | 2000 | WMI repository (`mofcomp`) | 1 | Needs MOF | Legacy components; NT Kernel Logger |
| WPP | ~2002 | `.pdb` (TMF) | implementation-dependent | No. Needs producer PDB | In-tree Windows kernel dev-time tracing |
| Manifest-based | 2007 (Vista) | XML manifest, system-installed | 8 | Needs installed manifest | Shipping security telemetry |
| TraceLogging | 2015 (Win10) | Inline TLV in payload | 8 | Yes | New apps and services; cross-runtime |

Sources for the table: [1084], [1079], [1088], [1086].

> **Aside. When to use which provider class.** For new shipping Windows components with a known event vocabulary and high volume, choose manifest-based: smallest per-event size, evtx integration, eight-consumer concurrency. For new cross-runtime open-source providers where deployment friction matters, choose TraceLogging: same eight-consumer concurrency, no XML to author, decodable everywhere. For in-source-tree dev-time tracing inside a binary you already have symbols for, WPP is fine. For new security-relevant providers, never choose classic: the one-session cap is structurally incompatible with multi-EDR coexistence.

Four provider classes, four trade-offs. But every one of them shares a structural weakness: the producer fires from inside the calling process, and any code in that process can patch the runtime entry-point and silence the provider for itself. That is the weakness Adam Chester made famous in 2020, and the one EtwTi was built to defeat.

## Sessions, buffers, and the autologger registry: where the telemetry actually lives

Open `regedit` on a Windows host and navigate to `HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger`. You are looking at the persistence surface of every trace session that survives a reboot on this machine, and the persistence surface every modern EDR uses to install itself.

A session is the unit ETW actually exposes to controllers. It owns a per-session pool of buffers, a writer thread, a destination (file or real-time consumer), and a list of providers it has subscribed to. The lifecycle is short. A controller fills out an `EVENT_TRACE_PROPERTIES` structure [1076] with a session name, buffer size, logging mode, and destination, then calls `StartTrace`. The kernel allocates the buffers (at least two per logical processor [1076]) and returns a session handle. The controller then calls `EnableTraceEx2` [1085] for each provider it wants to subscribe to, passing `EVENT_CONTROL_CODE_ENABLE_PROVIDER` along with the provider GUID, level, and keyword bitmask.

If the provider's per-class session cap is already saturated, `EnableTraceEx2` returns `ERROR_NO_SYSTEM_RESOURCES`. If the caller lacks the privilege to enable that provider, it returns `ERROR_ACCESS_DENIED`. We will see both error codes again later, on different paths.

> **Sidenote.** The default buffer size sweet spot is small. The Microsoft Learn primary states it explicitly: "Trace sessions with large buffers (256KB or larger) should be used only for diagnostic investigations or testing, not for production tracing." [1076] Production session buffer sizes typically sit in the 32-64KB range.

There are three logging modes. *File mode* writes events to a sequential `.etl` file on disk; the writer thread drains buffers to disk and the file grows. *Circular mode* writes to a fixed-size file in a circular buffer; old events are overwritten when the file fills. *Real-time mode* delivers events to a real-time consumer process, which receives them through its registered event-record callback. Defender, EDR sensors, and Sysmon all use real-time mode for their hot paths; they may also write to file as a forensic backup.

> **Definition: Real-time consumer.** A process that calls `OpenTrace` with `LogFileMode = EVENT_TRACE_REAL_TIME_MODE` and receives events live via a registered callback rather than from an `.etl` file on disk. Real-time consumers must keep up with producer rate or events are lost.

The autologger registry path is what makes a session survive a reboot. A subkey under `HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\` defines a session that the kernel starts at boot, before most user-mode services are running. Each subkey's values configure the session: `BufferSize`, `MaximumBuffers`, `LogFileMode`, `FileName`, plus a nested `<SessionName>\<ProviderGuid>` subkey for each provider to enable.

> **Definition: Autologger.** A registry-persisted boot-time ETW session. The kernel reads `HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\` at boot, creates the session, enables the configured providers, and begins capture before user-mode services start. Defender's Sense agent, CrowdStrike's Falcon sensor, and Sysmon's driver all install autologgers here.

Defender's `DiagTrack`, `Microsoft-Windows-Diagnosis-PCW`, the SQM kernel logger, the EventLog-Application channel autologger. All live here (observable via `logman query -ets` on a stock Windows install). Third-party EDRs add their own. The Palantir CIRT taxonomy [1090] (about which more in the gap-analysis section) frames this registry surface as the persistent-tampering target: an attacker who can write to this subtree can disable an EDR's boot-time tracing without ever interacting with the running EDR process. The events of interest never get captured because the session never starts.

There is a related concept worth naming: the *Global Logger*. This is a special autologger session whose configuration lives in `HKLM\SYSTEM\CurrentControlSet\Control\WMI\GlobalLogger`. It is the boot-time tracing path that comes online before any user-mode service, including before Sense and the EDR sensor. It exists to capture early-boot kernel events that no later session can record.

> **Walkthrough: autologger boot persistence.** Before any EDR service has a chance to start, the kernel reads `HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\`. Each subkey is a trace session recipe: logger name, `Start` value, `BufferSize`, `MinimumBuffers`, `MaximumBuffers`, `LogFileMode`, optional `FileName`, and nested provider-GUID subkeys with level and keyword masks. If the recipe is enabled, the kernel creates the session during boot and enables the listed providers immediately.
>
> That is powerful and dangerous. It is powerful because a sensor can collect pre-logon activity and early service launches instead of missing the first seconds of the machine's life. It is dangerous because the registry subtree is also the durable tamper surface. Change a provider keyword, redirect a file path, reduce buffers until loss spikes, or disable the autologger, and the next boot starts with a blind spot. The defensive control is not mystical: baseline the autologger tree, monitor writes to it, and treat unexpected changes as telemetry-integrity events rather than as ordinary configuration drift.
>
> **Audit your autologgers.** `logman query -ets` enumerates every live trace session on the host. Cross-reference against the subkeys in `HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\` to find sessions configured to start at boot. Any unauthorised entry (a session you do not recognize, an autologger pointed at a destination outside your EDR's data path, a provider GUID you cannot account for) belongs in your incident response queue.
>
> **Sidenote.** `ERROR_NO_SYSTEM_RESOURCES` from `EnableTraceEx2` is the runtime symptom of the eight-session cap binding [1085]. SOC engineers debugging multi-EDR coexistence problems should look for it in their sensor's diagnostic output. Eight subscribers per manifest provider is enough for the typical Defender + third-party EDR + Sysmon + research tap arrangement, but a host running multiple research-mode tracers can saturate it.

Persistence solved: a session the OS starts at every boot. But who reads it? That requires a consumer process, and consumers are where the architecture forks along the security spectrum.

## Consumer architecture: from `OpenTrace` to KrabsETW to a real-time process watcher

The consumer side of ETW is mechanically simple (three calls to open a trace, register a callback, and process events) but the choice of library tells you almost everything about what kind of EDR you are building.

The native pattern is three Win32 calls. `EnableTraceEx2` subscribes the session to a provider GUID with a level and keyword bitmask. `OpenTrace` returns a handle on the session for consumption. `ProcessTrace` blocks the calling thread, drains events from the kernel's per-CPU buffers, and dispatches each one to a registered callback. Each event arrives as an `EVENT_RECORD` containing a header (provider GUID, event ID, level, keyword, opcode, timestamp, process ID, thread ID) and a payload that the consumer decodes.

For manifest providers the consumer decodes via TDH (the Trace Data Helper API) against the system-installed manifest. For TraceLogging providers the consumer decodes from the inline TLV payload. For classic and WPP providers the consumer needs the MOF schema or the producer's PDB respectively.

> **Definition: TDH (Trace Data Helper).** The Win32 decoder API that turns a raw `EVENT_RECORD` payload into typed fields, using the registered manifest as the schema source. `TdhGetEventInformation` returns a `TRACE_EVENT_INFO` structure with the field names, types, and offsets; `TdhFormatProperty` extracts each field. TDH is what makes manifest events self-describing at the consumer end, even though the schema lives out of band.
>
> **Walkthrough: a real-time EDR consumer.** A user-mode sensor first acts as a controller: `StartTrace` creates or opens a session, then `EnableTraceEx2` subscribes that session to a provider GUID with a level and keyword mask. The provider is notified that somebody is listening, and its trace points begin checking the new enable state. The same sensor then changes roles and becomes a consumer: it calls `OpenTrace` for the live session, supplies an event callback, and calls `ProcessTrace` on a worker thread.
>
> From that point forward the worker thread is a delivery loop. A provider emits an event; the kernel appends it to the session's buffer; the writer path drains the buffer; `ProcessTrace` dispatches an `EVENT_RECORD` into the callback. The callback must be fast, because slow parsing creates backpressure and dropped events. Production EDRs therefore split the path: the ETW callback normalizes the event and enqueues it, while separate threads enrich, correlate, score, and upload. Libraries such as KrabsETW and TraceEvent hide some boilerplate, but they cannot remove the architectural fact that the consumer is asynchronous and must survive bursts without pretending ETW is lossless.

In production almost no one writes the raw three-call pattern. The library universe settled into a small set of widely-used wrappers, and the choice of wrapper maps almost one-to-one onto the kind of EDR the engineering team is building.

**krabsetw** [1091] is a Microsoft-authored C++ library that simplifies session and provider management. Its README explicitly notes the production caller: a C++/CLI wrapper called `Microsoft.O365.Security.Native.ETW`, "used in production by the Office 365 Security team. It's affectionately referred to as Lobsters." If you are building an in-house EDR or a security analytics pipeline in C++ on Windows, krabsetw is the default choice.

**Microsoft.Diagnostics.Tracing.TraceEvent** [1092] is the general-purpose .NET ETW library, distributed as a NuGet package and used heavily inside the .NET diagnostics community. Microsoft's separate `Microsoft.Windows.EventTracing.Processing.All` package is the .NET TraceProcessing API [1093] that the Windows engineering team uses internally to analyze ETW data from the Windows engineering system.

**SilkETW** [1094], originally released by Ruben Boonen at FireEye in March 2019 [1082] (now maintained by Mandiant), wraps `Microsoft.Diagnostics.Tracing.TraceEvent` to expose ETW telemetry to detection-engineering and threat-hunting workflows. SilkETW is the canonical "blue team research" consumer: the tool you reach for when you want to see what events a provider actually emits without writing C++.

**Sealighter** [1087], by `pathtofile`, is a krabsetw-wrapping C++ tool that makes multi-provider subscription and filtering tractable from a JSON config. The README states: "Sealighter leverages the feature-rich Krabs ETW Library to enable detailed filtering and triage of ETW and WPP Providers and Events." Sealighter is the canonical "red/blue team triage" consumer: more flexible than SilkETW, less code to write than raw krabsetw.

The pitfalls are universal across all four libraries. The krabsetw README spells two of them out:

> "The call to 'start' on the trace object is blocking so thread management may be necessary.", [1091]
>
> "Throwing exceptions in the event handler callback... will cause the trace to stop processing events.", [1091]

Both have caused real production outages. An EDR that throws an unhandled exception in its event callback dies silently as an ETW consumer, and the next event the provider emits goes nowhere.

> **Sidenote.** The "throwing in the callback stops the trace" pitfall is the gotcha that bites every team writing their first ETW consumer. The kernel does not catch the exception; the trace simply ends. A production-quality consumer wraps every callback in try/catch (or its language equivalent) and routes failures through a side channel, not through the trace itself.

A real-time `Microsoft-Windows-Kernel-Process` consumer, in production form, is a working EDR sensor's process watcher. Modern Windows EDRs commonly contain a component with this shape: a controller enabling providers, a real-time consumer draining sessions, and a separate pipeline for enrichment and response. Products that also ship drivers add kernel callbacks beside it rather than replacing it.

> **The library choice is the architecture choice.** krabsetw wraps the C++ surface and is the default for production in-house EDRs. TraceEvent wraps .NET and is the default for diagnostics tooling. SilkETW exposes ETW to detection engineers without C++. Sealighter wraps krabsetw with a config file for triage. Pick the library that matches the team that will own the consumer, not the one that looks most powerful.

This is what Sysmon, Wazuh, and Elastic Defend look like under the hood: a SYSTEM-privileged user-mode service consuming public providers. But there is one provider such a consumer cannot subscribe to. Try it and `EnableTraceEx2` returns `ERROR_ACCESS_DENIED`. The following sections are about the GUID that requires a passport.

## Reproducible Windows checks, not captured lab proof

This chapter does not claim a captured lab transcript. The checks below are documented Windows commands whose output is intentionally host-specific: an enterprise Defender endpoint, a CrowdStrike endpoint, a Sysmon lab VM, and a Wazuh collector will not have the same sessions, providers, autologgers, or protection levels. Treat this section as a field checklist for proving the architecture on *your* host, not as universal sample output.

The useful way to run the checklist is in layers. First ask which trace sessions exist. Then ask which providers are registered. Then inspect the special providers and boot-persistent sessions that determine whether an EDR is seeing early activity, memory-modifying syscalls, and tamper attempts. Finally, inspect the platform controls that decide whether kernel-mode ETW tampering is a realistic path.

> 🔵 **DOCUMENTED**. Enumerate live trace sessions · reproducible topology check
>
> Reproduce: `logman query -ets`
>
> Expected shape: a list of running ETW sessions. Windows diagnostic sessions are normal. EDR-owned sessions are normal if they match your sensor baseline. Sysmon-owned sessions are normal if Sysmon is installed. A session that appears here but not in your autologger, EDR, WPR, or diagnostics baseline is an investigation candidate because it means a controller has created a live consumer path.
>
> What to verify: session names, logger IDs, buffer counts, lost-event counters when available, and whether a real-time session is unexpectedly writing to disk. This proves the *session* layer of the provider/session/consumer model: providers do not stream to a consumer directly; they stream into sessions whose buffers and modes are configured by controllers.
>
> 🔵 **DOCUMENTED**: enumerate registered ETW providers · provider catalog check
>
> Reproduce: `logman query providers`
>
> Expected shape: provider names and GUIDs. On a modern Windows host, security-relevant entries include `Microsoft-Windows-Kernel-Process`, `Microsoft-Windows-PowerShell`, `Microsoft-Windows-DotNETRuntime`, `Microsoft-Antimalware-Scan-Interface`, `Microsoft-Windows-Sysmon` when Sysmon is installed, and `Microsoft-Windows-Threat-Intelligence` when the provider is present.
>
> What to verify: the GUID next to the provider name and whether the provider exists on the build you are testing. This proves the *provider* layer. A provider can be registered and still produce nothing for your EDR if no session enabled the provider at the relevant level and keyword mask.
>
> 🔵 **DOCUMENTED**: inspect the Threat Intelligence provider manifest · EtwTi presence and schema check
>
> Reproduce: `wevtutil gp Microsoft-Windows-Threat-Intelligence`
>
> Expected shape: provider metadata for GUID `{f4e1897c-bb5d-5668-f1d8-040f4d8dd344}` and task/keyword definitions for the `KERNEL_THREATINT_TASK_*` family. A non-Antimalware-PPL service should not expect to consume this provider successfully; an `EnableTraceEx2` attempt from the wrong protection level returns access denied.
>
> What to verify: task names for allocation, protection, mapping, queueing, context-setting, read, and write operations; keyword splits for local versus remote and kernel-caller variants; and whether the inventory matches the build-specific references your detection content assumes. This proves why EtwTi is different from `.NET` or PowerShell ETW: the producer is in the kernel syscall path, while the consumer gate is Antimalware-PPL.
>
> 🔵 **DOCUMENTED**: inspect autologger persistence · boot-time session check
>
> Reproduce: `reg query HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger` or inspect the same path in Registry Editor.
>
> Expected shape: one subkey per boot-time ETW session. Each EDR-owned autologger should be known, named, and baselined. Unexpected writes to this subtree are high-signal because persistent ETW tampering happens here.
>
> What to verify: `Start`, buffer sizing, `LogFileMode`, `FileName`, provider-GUID subkeys, levels, and keywords. This proves the persistence layer. If a red team tampers here, the evasion often survives reboot but also leaves a configuration artifact defenders can monitor.
>
> 🔵 **DOCUMENTED**. Verify VBS/HVCI and driver-blocklist state · kernel-tamper narrowing check
>
> Reproduce: `Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard | Select-Object SecurityServicesConfigured,SecurityServicesRunning,VirtualizationBasedSecurityStatus`
>
> Expected shape: `VirtualizationBasedSecurityStatus` indicates whether VBS is running, while `SecurityServicesRunning` indicates services such as HVCI. On Windows 11 22H2 and later, the Vulnerable Driver Blocklist is enabled by default and is reinforced when HVCI, Smart App Control, or S mode is active [271].
>
> What to verify: whether the endpoint has reduced the BYOVD path that kernel-mode ETW tampering depends on. This does not prove ETW events are complete. It proves the platform has made the strongest known evasion family (kernel write primitives against ETW internals or EtwTi producer paths) materially harder to obtain.

## The security provider catalog: what EDRs actually read

![Figure: The security-provider catalog as a layered emission map. User-mode providers (DotNETRuntime, PowerShell, AMSI) funnel through the ntdll!EtwEventWrite stub the 0xC3 patch can reach, kernel-emitted manifest providers sit beyond the user/kernel line, and the kernel-side EtwTi provider is gated by a PPL+ELAM turnstile that admits only an Antimalware-signed consumer.](diagrams/28-etw-catalogue-layers.svg)

There are roughly 1,300 manifest-based providers shipped on a 2026 Windows 11 24H2 install: the community-maintained jdu2600 inventory [1095] tracks the count across builds, and the repnz manifest archive [1096] holds byte-stable copies of the manifests for cross-version diffing. Ten rows below carry the core security telemetry most often discussed in public EDR documentation; grouped by function, they collapse into roughly eight categories. This is the catalog.

### `Microsoft-Windows-Security-Auditing`

GUID `{54849625-5478-4994-A5BA-3E3B0328C30D}`. The audit-policy-driven Security event log producer. Event ID 4624 (logon), 4625 (failed logon), 4634 (logoff), 4688 (process create with command line) [1097] [1098], 4689 (process exit), 4768/4769 (Kerberos TGT and service-ticket requests), and the broader subcategory audit policy events. This is where the interlude watches the authentication links directly: the logon and ticket events are the observable shadow of the protocols the The Death of NTLM chapter (Chapter 16) and the Kerberos chapter (Chapter 17) dissect, and 4769 service-ticket anomalies are the on-host signal of the KRBTGT forgeries the KRBTGT chapter (Chapter 18) describes. This is the closure for the legacy Security event log: when an administrator turns on "audit logon events" in the local security policy, this is the provider that emits the events. EDRs that consume it are reading the same stream the Event Viewer's Security log shows.

### `Microsoft-Windows-Kernel-Process`

GUID `{22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716}`. The canonical real-time process telemetry source for non-PPL EDR. Event ID 1 fires on `ProcessStart` with process ID, parent process ID, create time, session ID, and image name (notably *not* the command line, which is why command-line visibility requires Sysmon Event ID 1 or Security 4688 with command-line auditing enabled); event ID 2 on `ProcessStop`; event ID 3 on thread create; event ID 4 on thread exit; event ID 5 on `ImageLoad` with the loaded module name and base address. SilkETW's launch post enumerates the event record format inline [1082]. This provider is widely cited in EDR community documentation as available since Windows 7, though no Microsoft primary pins the exact build.

### `Microsoft-Windows-kernel-file`, `Microsoft-Windows-kernel-network`, `Microsoft-Windows-kernel-registry`

The per-subsystem siblings of `Kernel-Process`. `Kernel-File` surfaces file open / close / read / write / delete operations with the file path and the operating PID. `Kernel-Network` surfaces TCP and UDP send / receive with the local and remote endpoints. `Kernel-Registry` surfaces registry create / open / set value / delete with the key path and value name. On current builds these names appear in community manifest inventories [1095], [1096], while Microsoft documents the related SystemTraceProvider path and its eight-session multiplexing separately [1081]. Treat them as kernel telemetry surfaces whose exact control path is build-dependent; EDRs that want broad file, network, or registry observation can subscribe to these streams, but products that need enforcement or lower latency still write kernel callbacks.

### `Microsoft-Antimalware-Scan-Interface`

GUID `{2A576B87-09A7-520E-C21A-4942F0271D67}`, documented in the Microsoft Learn AMSI portal [700] and surveyed in the Palantir CIRT taxonomy [1090]. This is the ETW provider that surfaces AMSI scan results: a script block submitted by PowerShell, JScript, VBA, an Office macro engine, or any other AMSI client comes through here *after deobfuscation*. Whatever string the AMSI client actually submits, the registered antimalware engine can inspect in its deobfuscated form; ETW visibility then depends on the provider, keyword mask, channel configuration, and consumer permissions rather than on provider existence alone.

> **Definition: AMSI (Antimalware Scan Interface).** A COM interface exposed by Windows since 2015 that script engines and runtime hosts can call into to submit content for malware scanning. The Microsoft Learn AMSI portal lists PowerShell, JScript and VBScript via Windows Script Host, Office VBA macros, and User Account Control as in-box integrators [700]; the .NET CLR's assembly load path joined the list with .NET Framework 4.8, as documented in Adam Chester's CLR walk-through [1073]. The scanned content is the post-deobfuscation form: the actual code about to execute, not the obfuscated wrapper. AMSI activity can surface via the `Microsoft-Antimalware-Scan-Interface` ETW provider when the relevant events and keywords are enabled by a consumer.
>
> **Sidenote.** The AMSI Operational event log channel typically appears empty by default. The Palantir taxonomy [1090] notes the keyword bitmask configured for the channel does not surface scan-result events. The events fire on the ETW bus and can be consumed in real time, but they do not land in the user-visible evtx log unless the consumer reconfigures the keyword mask.

### `Microsoft-Windows-PowerShell`

GUID `{a0c1853b-5c40-4b15-8766-3cf1c58f985a}`. Event ID 4104 is the script-block-logging event that records each PowerShell script block before execution; event ID 4103 records pipeline execution detail; event ID 4100 records errors. The Microsoft Learn `about_Logging_Windows` reference (Windows PowerShell 5.1) [1099] documents EID 4104 verbatim ("`EventId 4104 / 0x1008`... `Channel Operational`... `Task CommandStart`") and the script-block-logging configuration. PowerShell Core 7+ uses a separate ETW provider (`PowerShellCore`, GUID `{f90714a8-5509-434a-bf6d-b1624c8a19a2}`). Combined with AMSI, PowerShell can expose content through two different mechanisms: AMSI sees what the host submits for scanning, while script-block logging records script blocks when the policy or suspicious-block behavior causes 4104 events to be written [1099]. Detection engineers use both as cross-checks, but neither sentence should be read as a guarantee that every host emits every command twice by default.

### `Microsoft-Windows-DotNETRuntime`

GUID `{e13c0d23-ccbc-4e12-931b-d9cc2eee27e4}`, verbatim in Adam Chester's PoC source [1073]. The .NET CLR provider. Surfaces assembly load events, JIT compilation, AppDomain creation, exception throws. Critical for detecting Cobalt Strike's `execute-assembly` style of in-memory .NET payload loading. This is the provider that goes dark in the opening hook scene after the operator's `EtwEventWrite` patch.

> **Sidenote.** This is the provider Adam Chester targeted in the canonical March 17, 2020 ETW patching post [1073]. The Cobalt Strike `execute-assembly` workflow produces a loud signal here ("assembly X loaded into PID Y from in-memory source Z") so silencing it locally was a valuable evasion. The story comes back in the gap analysis.

### `Microsoft-Windows-Sysmon`

GUID `{5770385F-C22A-43E0-BF4C-06F5698FFBD9}`, surfaced by `wevtutil gp Microsoft-Windows-Sysmon` and inventoried in [1095]; the Microsoft Learn Sysmon page by Russinovich and Garnier [662] documents authorship, the protected-process status, and the `Microsoft-Windows-Sysmon/Operational` channel. This is the *publishing* side of Sysmon. Sysmon's kernel driver `SysmonDrv.sys` collects events through `PsSetCreateProcessNotifyRoutineEx` and friends; the user-mode service then republishes via this ETW provider so any consumer (a SIEM forwarder, a SOC dashboard, a custom analytic) can subscribe without writing its own kernel driver. Events also land in the `Microsoft-Windows-Sysmon/Operational` evtx channel.

### `Microsoft-Windows-Threat-Intelligence` (EtwTi)

GUID `{f4e1897c-bb5d-5668-f1d8-040f4d8dd344}`, verbatim in the fluxsec.red walkthrough [1074]. The only ETW source in the catalog that fires from inside the kernel for memory-modifying syscalls. Ten task IDs, all prefixed `KERNEL_THREATINT_TASK_`:

- `ALLOCVM` (`NtAllocateVirtualMemory`: local and cross-process)
- `PROTECTVM` (`NtProtectVirtualMemory`)
- `MAPVIEW` (section mapping; cross-process and self)
- `QUEUEUSERAPC` (`NtQueueApcThread` cross-process)
- `SETTHREADCONTEXT` (`NtSetContextThread` cross-process)
- `READVM` (`NtReadVirtualMemory`: local and cross-process)
- `WRITEVM` (`NtWriteVirtualMemory`: local and cross-process)
- `SUSPENDRESUME_THREAD`
- `SUSPENDRESUME_PROCESS`
- `DRIVER_DEVICE`

Each task pairs with a 64-bit keyword bitmask that distinguishes `LOCAL` vs `REMOTE` (cross-process) and `KERNEL_CALLER` vs not. The Elastic Security Labs walkthrough [1100] lists the named Win32/Nt syscalls that surface here:

> "The most notable addition to this visibility is the Microsoft-Windows-Threat-Intelligence Event Tracing for Windows (ETW) provider... VirtualAlloc, VirtualProtect, MapViewOfFile, VirtualAllocEx, VirtualProtectEx, MapViewOfFile2, QueueUserAPC, SetThreadContext, WriteProcessMemory, ReadProcessMemory(lsass)": Elastic Security Labs [1100]
>
> **Definition: Microsoft-Windows-Threat-Intelligence (EtwTi).** The kernel-emitted ETW provider for memory-modifying syscalls. GUID `{f4e1897c-bb5d-5668-f1d8-040f4d8dd344}`. Events are emitted from the kernel side of the syscall path (not from a user-mode trampoline), which makes the provider unreachable from a user-mode patcher in the calling process. Consumption is gated behind Protected Process Light at the Antimalware signer level, paired with an Early Launch Antimalware driver. The provider first shipped in the Windows 10 RS-era; the precise build is not stated verbatim in any Microsoft primary located, with community references converging on no later than 1709.

The first-ship-build is hedged: the provider GUID and task inventory are well-documented in third-party reverse-engineering primaries, but no Microsoft primary located in the source verification stage pins the exact build. The community reference range is Windows 10 1607 (RS1) through 1709 (RS3). The dispositive practical evidence is Yarden Shafir's 2023 Trail of Bits walkthrough [1101], which shows live-debugger output of `CSFalconService.exe` (CrowdStrike) holding `EtwConsumer` handles to multiple logger IDs simultaneously. By 2023 third-party EDRs were demonstrably consuming EtwTi at scale.

### The catalog as a single screen

| Provider name | GUID | Surface | Gate | Primary source |
|---|---|---|---|---|
| Microsoft-Windows-Security-Auditing | `{54849625-5478-4994-A5BA-3E3B0328C30D}` | Audit-policy events (4624/4625/4688/...) | Audit policy/SACL configuration | [1098], [1097], [1102] |
| Microsoft-Windows-Kernel-Process | `{22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716}` | Process / thread / image-load events | None (admin) | [1082], [1095] |
| Microsoft-Windows-Kernel-File | (manifest archive) | File I/O syscalls | System-provider/session rules | [1095], [1096], [1081] |
| Microsoft-Windows-Kernel-Network | (manifest archive) | TCP/UDP send/receive | System-provider/session rules | [1095], [1096], [1081] |
| Microsoft-Windows-Kernel-Registry | (manifest archive) | Registry create/open/set/delete | System-provider/session rules | [1095], [1096], [1081] |
| Microsoft-Antimalware-Scan-Interface | `{2A576B87-09A7-520E-C21A-4942F0271D67}` | Post-deobfuscation script content | None (admin) | [700], [1090] |
| Microsoft-Windows-PowerShell | `{a0c1853b-5c40-4b15-8766-3cf1c58f985a}` | Script-block logging (4104), pipeline | Policy/channel configuration | [1099] |
| Microsoft-Windows-DotNETRuntime | `{e13c0d23-ccbc-4e12-931b-d9cc2eee27e4}` | CLR assembly load, JIT, exceptions | None (admin) | [1073] |
| Microsoft-Windows-Sysmon | `{5770385F-C22A-43E0-BF4C-06F5698FFBD9}` | Sysmon driver re-publication | None (admin) | [1095], [662] |
| Microsoft-Windows-Threat-Intelligence | `{f4e1897c-bb5d-5668-f1d8-040f4d8dd344}` | Memory-modifying syscalls (kernel-emitted) | **PPL + ELAM (Antimalware signer level)** | [1074], [1100] |

> **Aside: What this catalog is not.** This is the *security* catalog. The full Windows manifest-based provider list is roughly 1,300 entries on a current Windows 11 build; performance-tuning, diagnostic, and developer-facing providers fill out the rest. The jdu2600 inventory [1095] tracks the full list across Win10 versions; the repnz archive [1096] preserves byte-stable manifest copies for cross-version diffing.

Nine of the ten rows in that table are accessible to any SYSTEM-privileged user-mode service. The tenth (EtwTi) requires a passport. The next section is about who issues the passport.

## The PPL / ELAM gate: why EtwTi is not for everyone

To consume the catalog provider that fires from the kernel for memory-modifying syscalls, your service must be (a) a Protected Process Light, the same kernel-enforced protection level the Protected Process Light chapter (Chapter 10) uses to shield `lsass.exe`, (b) signed at the Antimalware signer level with EKU `1.3.6.1.4.1.311.61.4.1`, and (c) loaded from disk by an Early Launch Antimalware driver registered at boot, on the early-boot path the Secure Boot chapter (Chapter 1) establishes. Two of those three were not possible for third parties until the Windows 10 RS-era.

fluxsec.red [1074] gives the prerequisite list verbatim:

> "In order to start receiving ETW:TI signals, we need: 1. A service running as Protected Process Light, 2. An Early Launch Antimalware driver and certificate, 3. A logging mechanism.", [1074]

Each prerequisite has a story.

### Protected Process Light at the Antimalware signer level

Windows 8.1 introduced the *protected service* concept specifically for antimalware engines. The motivation was simple: a malicious process running as administrator should not be able to inject code into the antimalware service or attach a debugger to it. The Microsoft Learn primary [327] sets out the model:

> "Windows 8.1 introduced a new concept of protected services to protect anti-malware services... In addition to the existing ELAM driver certification requirements, the driver must have an embedded resource section containing the information of the certificates used to sign the user mode service binaries.", [327]

PPL is a process-protection model, not a single ACL bit. The kernel evaluates protection type, signer level, requested access mask, and policy before granting handles such as write, VM, or debug access; as a teaching shorthand, a lower-protection process cannot obtain the sensitive access rights that would let it tamper with a higher-protection target. Antimalware-PPL is a *signer level* in that model. The kernel admits a process to Antimalware-PPL when its image is signed with a certificate whose EKU includes `1.3.6.1.4.1.311.61.4.1` (Windows Antimalware) *and* whose certificate is enrolled in an ELAM driver's allow-list at boot.

> **Definition: PPL (Protected Process Light).** A Windows process-protection model. Each process has a protection type and signer level; sensitive access rights are denied when the requestor lacks sufficient protection for the target and access mask. Originally introduced for DRM, the lattice was extended in Windows 8.1 to host the Antimalware signer level for protecting antimalware services from administrative-rights attackers.
>
> **Definition: Antimalware-PPL.** A specific signer level on the PPL lattice. Reserved in Windows 8.1 for Microsoft Defender; opened to third-party EDR vendors via ELAM onboarding in the Windows 10 RS-era. Consumption of the `Microsoft-Windows-Threat-Intelligence` ETW provider is gated at the Antimalware signer level: an `EnableTraceEx2` call from a non-Antimalware-PPL caller against the EtwTi GUID returns `ERROR_ACCESS_DENIED` (the `EnableTraceEx2` [1085] page documents the error code for callers that lack the documented administrative groups; the per-provider PPL-signer-level check that triggers it for the EtwTi GUID specifically is described in the [1074] prerequisite list).

### Early Launch Antimalware

ELAM is a driver class that loads before any other non-Microsoft boot driver. The Microsoft Learn primary [42] describes it:

> "Because an ELAM service runs as a PPL (Protected Process Light), you need to debug using a kernel debugger... AM drivers are initialized first and allowed to control the initialization of subsequent boot drivers, potentially not initializing unknown boot drivers.", [42]

The boot sequence runs like this. Winload loads the ELAM driver as part of the early-boot path. The ELAM driver registers a callback via `IoRegisterBootDriverCallback` and gets to inspect each subsequent boot driver, returning a verdict (initialize / do not initialize / unknown) based on the certificate inventory it carries in its embedded resource section. The kernel honors that verdict. After boot drivers settle, the SCM launches the paired user-mode antimalware service with the `LaunchProtected = SERVICE_LAUNCH_PROTECTED_ANTIMALWARE_LIGHT` flag, and the kernel admits that service to Antimalware-PPL because its signing certificate matches an entry in the ELAM driver's allow-list.

> **Definition: ELAM (Early Launch Antimalware).** A driver class that loads before any non-Microsoft boot driver. The ELAM driver registers a boot-driver callback to inspect subsequent drivers and an embedded-resource certificate inventory of permitted user-mode antimalware service signatures. Together with PPL, ELAM gates which user-mode antimalware services can pass the Antimalware-PPL admission check.

### The 1709 onboarding

The exact third-party onboarding date is the weakest public link in the chain, so the careful statement is narrower than the folklore version. Microsoft documents the Antimalware protected-service model in Windows 8.1 [327], documents ELAM as the early-boot antimalware admission mechanism [42], and documents `EnableTraceEx2` access-denied behavior for callers that lack required authority [1085]. Microsoft does *not*, in the public ETW pages used for this chapter, publish a sentence that says: "Windows 10 1709 opened EtwTi consumption to third-party Antimalware-PPL EDRs." Therefore this chapter treats 1709 as a widely-cited RS-era boundary, not as a Microsoft-primary-pinned date.

What is proven publicly is the operational end state. The Trail of Bits 2023 walkthrough by Yarden Shafir [1101] uses WinDbg JavaScript to walk `_ETW_REALTIME_CONSUMER` structures on a live machine and prints:

> "Process CSFalconService.exe with ID 0x1e54 has handle 0x760 to Logger ID 3", [1101]

That is not marketing copy. It is debugger evidence that CrowdStrike's user-mode service held a real-time ETW consumer handle to a logger ID associated with protected security telemetry. Paired with the documented Antimalware-PPL/ELAM prerequisites and the EtwTi access gate, it proves that by 2023 at least one third-party EDR had crossed the gate in production. The public evidence does not prove the first build, the first vendor, or every vendor's onboarding path. It proves the architecture and the existence of third-party consumption.

> **Walkthrough: the PPL+ELAM admission path.** The gate begins before user mode. Winload loads the ELAM driver early; the driver registers its boot-driver callback and exposes the embedded certificate inventory that identifies which user-mode antimalware binaries are allowed to run protected. Later, the Service Control Manager starts the EDR service with the Antimalware Light launch-protection flag. The kernel checks the service image signature against the ELAM-provided inventory and admits the process to the Antimalware-PPL signer level.
>
> Only then does the ETW step happen. The EDR service calls `EnableTraceEx2` for the `Microsoft-Windows-Threat-Intelligence` GUID. For a normal administrator or SYSTEM service, the call fails with access denied because the caller lacks the signer level required for this provider. For an admitted Antimalware-PPL service, the same call succeeds and the session begins receiving kernel-emitted EtwTi events. The ordering matters: ELAM establishes trust at boot, PPL carries that trust into the user-mode process object, and ETW uses that process protection state as the consumer-admission check.

### Why this gate matters for the opening hook

The asymmetry that defines the entire generation is one sentence in the fluxsec.red walkthrough [1074]:

> We cannot patch out the Threat Intelligence provider as this is emitted from within the kernel itself. To do so, you'd require kernelmode execution and then to patch out those signals so no ETW signals are emitted. [1074]

That is the answer to the puzzle the opening hook posed. The Adam Chester 2020 patch operates on a user-mode trampoline in the calling process. `ntdll!EtwEventWrite` is a stub that calls down through `NtTraceEvent` into the kernel; rewriting its first byte to `0xC3` short-circuits the user-mode entry path and the calling process emits no events through that stub. But EtwTi does not fire from the user-mode entry path. EtwTi fires from inside the kernel implementation of `NtAllocateVirtualMemory` and friends, after the syscall has crossed the boundary, on a path the user-mode patcher cannot reach without first achieving kernel execution.

> **Key idea.** EtwTi is the only ETW provider in the catalog whose producer fires from the kernel side of the syscall path, and that is exactly why a user-mode patch in the calling process cannot silence it. The PPL+ELAM gate that controls *consumer* admission is paired with a *producer* location that no in-process attacker can reach.

The RS-era PPL+ELAM gate was a structural defense against the patch class that was only fully publicised three years later; 2017/1709 is the commonly cited boundary, not a Microsoft-primary-pinned date. By the time Chester wrote his March 2020 post, the load-bearing security signal was already structurally out of reach of his technique.

This is the interlude's central synthesis, and it is worth stating plainly: EtwTi's producer location is the *observational dual* of Credential Guard's isolation. Both features spend the same hardware boundary: the kernel/user split, and beneath it the VTL0/VTL1 split the hypervisor (Chapter 9) and Secure Kernel (Chapter 6) enforce. The Credential Guard chapter (Chapter 15) puts the long-term secret on the far side of that boundary so a VTL0 attacker cannot *read* it; EtwTi puts the memory-syscall sensor on the far side of the same boundary so an in-process attacker cannot *blind* it. One boundary, two distinct security properties (confidentiality and observability) built from one mechanism. The corollary is sobering: the single capability that defeats one (kernel-mode execution, typically via the BYOVD primitive the Code Integrity chapter (Chapter 8) works to close) defeats both at once. The chain does not have an independent failure for "the secret leaked" and "the sensor went blind"; above kernel mode they are the same event.

> **Aside: Why Microsoft chose this specific gate.** The combination of PPL and ELAM is not an arbitrary defense-in-depth stack. PPL gates *consumer identity* at signer level: only a binary signed with the Antimalware EKU and enrolled in an ELAM allow-list can subscribe. ELAM gates *load order*: the gate is set during early boot, before any code an attacker could load gets a chance to interfere. The signer-level check is hard because forging the signature requires breaking Microsoft's PKI; the load-order check is hard because subverting it requires compromising the boot path, which Secure Boot (Chapter 1) and the Vulnerable Driver Blocklist exist to defend.

That is the gate. Now we walk the consumers that pass through it.

## Six vendors, three spectra: a map of the EDR consumer architecture

Defender, CrowdStrike, SentinelOne, Sysmon, Wazuh, Elastic Defend. They look interchangeable on a vendor comparison sheet. They are not, and the differences are entirely about which substrates each one consumes.

There are three axes that distinguish them.

### Axis 1: kernel callbacks vs ETW

Some EDRs consume process-creation events through ETW (subscribing to `Microsoft-Windows-Kernel-Process` from a SYSTEM-privileged user-mode service). Others register kernel callbacks directly through `PsSetCreateProcessNotifyRoutineEx` [1103] and `PsSetCreateThreadNotifyRoutine` [1104] from a kernel driver they ship.

The trade-off is sharp. Kernel callbacks are synchronous: the kernel calls into the driver before the operation completes, the documented process-create callback runs at PASSIVE_LEVEL in the originating thread context, and the driver can deny the operation by writing a non-success status to `CreationStatus`. ETW is asynchronous: the event is emitted from the producer's hot path, drained from a per-CPU buffer by the writer thread, and delivered to the consumer's callback at some later point. ETW cannot deny anything; it can only observe.

> **Definition: Kernel notify routine.** The `PsSetCreate*NotifyRoutine` family of kernel APIs. A driver calls `PsSetCreateProcessNotifyRoutineEx` (process create/exit), `PsSetCreateThreadNotifyRoutine` (thread create/exit), or `PsSetLoadImageNotifyRoutine` (image load) at boot to register a callback. The kernel invokes the process callback synchronously, in the originating thread context at PASSIVE_LEVEL; APC-delivery constraints are callback-specific rather than a universal promise. The `Ex` variant of the process callback receives a `CreationStatus` field the driver can write to deny the operation.

Public evidence supports a spectrum rather than a uniform product claim. Sysmon documents a driver-backed callback path and ETW publication [662]; Elastic publicly describes driver-backed memory detection and kernel ETW call-stack work [1100]; Defender uses in-box drivers and ETW; CrowdStrike has public debugger evidence of protected ETW consumption [1101]. For SentinelOne and Wazuh, this chapter keeps the claim at architecture class: commercial sensors commonly combine drivers/callbacks with ETW, while Wazuh-style deployments are often downstream of Windows Event Log, Sysmon, and ETW-class sources and cannot deny operations unless an upstream component does.

### Axis 2: PPL adoption

Defender is the clear case: Microsoft's protected-antimalware service model exists for engines like `MsMpEng.exe`, and EtwTi's consumer gate aligns with that Antimalware-PPL signer level [327]. CrowdStrike is the best public third-party case: Shafir's debugger walk shows `CSFalconService.exe` as a real-time ETW consumer in the protected telemetry path [1101]. Sysmon is a different clear case: Microsoft says the service runs as a protected process [662], but the Sysmon page does not say Antimalware-PPL, and Sysmon is not enrolled as an ELAM-backed antimalware service in the same sense as commercial EDR sensors.

The remaining vendor rows should be read as evidence classes, not as equally proven facts. SentinelOne is commonly described operationally as using an Antimalware-PPL service paired with a kernel driver, but the public source set for this chapter does not contain a primary debugger transcript equivalent to the CrowdStrike one. Wazuh's open architecture is primarily user-mode collection and SIEM forwarding around Windows event channels, Sysmon, and ETW-class sources; the source set here does not show an Antimalware-PPL enrollment. Elastic publicly documents kernel ETW call-stack work and its own endpoint driver strategy [1100], but that article is not proof that the user-mode Elastic Defend service is Antimalware-PPL. A masterclass claim must preserve those differences.

### Axis 3: EtwTi consumption

EtwTi consumption is not merely a product-feature checkbox. It is a consequence of three linked facts: the provider emits from the kernel side of memory-modifying syscalls; `EnableTraceEx2` against that provider is gated to Antimalware-PPL consumers; and the consumer must keep a real-time session alive without overrunning buffers. Defender satisfies the gate by design. CrowdStrike has public debugger evidence [1101]. For SentinelOne, the architecture is plausible and widely reported, but not proven by the sources cited here at the same level as CrowdStrike. For Sysmon, Wazuh, and Elastic, this chapter states the conservative version: absent public evidence of Antimalware-PPL EtwTi subscription in the source set, do not assume they consume EtwTi directly. Sysmon and Elastic have kernel-driver paths that cover parts of the same memory-observation problem; Wazuh commonly relies on Sysmon or Windows event sources upstream.

Confidence class key: **High** means Microsoft documentation or a primary debugger transcript in this chapter supports the row; **Medium** means the architecture is widely reported or plausible but lacks an equivalent primary in this source set.

| Vendor | Process surface | PPL / protection evidence in this chapter | EtwTi evidence in this chapter | Confidence class |
|---|---|---|---|---|
| Microsoft Defender | Driver callbacks (`WdFilter.sys`) + ETW (`MsMpEng.exe`) | Microsoft protected-antimalware model [327] | Yes by architecture and in-box role | High |
| CrowdStrike Falcon | Driver callbacks + ETW | Live `_ETW_REALTIME_CONSUMER` debugger evidence for `CSFalconService.exe` [1101] | Yes, public debugger evidence [1101] | High |
| SentinelOne | Driver callbacks + ETW | Commonly reported Antimalware-PPL posture; no equivalent [1101] transcript in this source set | Plausible, not proven here | Medium |
| Sysmon | `SysmonDrv.sys` callbacks; publishes via own ETW provider | Microsoft says protected process, not Antimalware-PPL [662] | No direct EtwTi evidence; uses callback-then-publish design | High for non-EtwTi framing |
| Wazuh | Windows event/Sysmon/ETW-class ingestion | No Antimalware-PPL evidence in this source set | Not assumed; commonly downstream of Sysmon/Event Log | Medium |
| Elastic Defend | Own endpoint driver + ETW/call-stack telemetry | Public Elastic article emphasizes kernel ETW call stacks and driver-backed memory detection [1100], not Antimalware-PPL proof | Not assumed from [1100] alone | Medium |

Sysmon is worth singling out as the canonical *callback-then-publish* reference architecture. Its kernel driver is broadly understood to use `PsSetCreate*NotifyRoutine`-class callbacks; its user-mode service consumes the events the driver delivers; and the service then publishes them via its own `Microsoft-Windows-Sysmon` ETW provider for any downstream consumer (a SIEM forwarder, a SOC dashboard, a custom analytic) to read. The result is that Sysmon's events are universally consumable. Which is why Wazuh and Splunk both ship Sysmon configurations as their default kernel-event source.

> **Aside: Sysmon as the calibration anchor.** Sysmon's design choice is the reference architecture for the callback-then-publish pattern, even though Sysmon is not itself an Antimalware-PPL EDR. By publishing through its own ETW provider rather than writing to a private channel, Sysmon makes its events consumable by any downstream pipeline. Wazuh and the Splunk Universal Forwarder can both ingest Sysmon events without any custom integration work. This is why Sysmon, despite being free, is the de facto kernel-event source for the open-source SIEM world.
>
> **Walkthrough: callbacks and ETW on the same endpoint.** A kernel driver that registers `PsSetCreateProcessNotifyRoutineEx` is in the decision path: the process is not fully created until the callback returns, and the callback can deny by writing a failure status to `CreationStatus`. That buys enforcement and low-latency context, but it couples the vendor's code to the kernel. A malformed content update or parser bug in that path can crash the host, which is the price of synchronous power.
>
> An ETW consumer sits on the other side of the trade. It can subscribe to `Microsoft-Windows-Kernel-Process`, `Microsoft-Windows-PowerShell`, `.NET`, AMSI, Sysmon, and EtwTi without putting its parser in the kernel's synchronous control path. Multiple consumers can share the same manifest provider because Vista raised the per-provider cap to eight. The cost is time and authority: the event arrives after emission, maybe after the operation has already completed, and ETW cannot veto it. Modern EDRs combine the two: callbacks for operations that must be denied, ETW for broad multi-provider observation, and EtwTi for the memory surface where Microsoft intentionally moved high-value observation into a kernel-emitted provider.
>
> **Sidenote.** The CrowdStrike July 2024 channel-file outage was a kernel-driver brittleness story, not an ETW story: a malformed content update triggered an out-of-bounds read in the Falcon sensor path and BSODed roughly 8.5 million Windows hosts [1105][1106]. It is mentioned here only to mark that synchronous kernel power carries higher blast radius when the driver path is buggy; the post-incident discipline that followed belongs in the Authenticode and Catalog Files chapter (Chapter 12).

A note on Defender's cloud schema. The events that surface in Microsoft Defender for Endpoint's hunting tables (`DeviceProcessEvents`, `DeviceFileEvents`, `DeviceNetworkEvents`, `DeviceImageLoadEvents`, `DeviceRegistryEvents`) are the cloud-side abstraction over the kernel and ETW telemetry the Defender sensor collects locally. The full schema mapping from ETW provider to cloud column is out of scope here, but the substrate is the same.

Six vendors, three axes, one substrate. Now we walk the attack tradition that the substrate has to survive.

## Where this link breaks

The detection link breaks in three distinct ways: the session may be prevented from starting, the user-mode producer may be patched before it emits, or the kernel structures underneath ETW may be modified by code that has already won kernel execution. The following sections are gap analysis, not a tutorial. They preserve the public history because a Reasoner needs to know which defensive layer answers which failure mode.

### The attack tradition: five generations of trying to blind ETW

![Figure: Five generations of ETW tradecraft, 2014–2026. Attack generations climb from boot-config (autologger) to user-mode (0xC3 patch) to kernel (BYOVD), while each structural defense answers the attack class at the layer it targets: the Antimalware-PPL+ELAM gate on EtwTi pre-dates the user-mode patch by three years, and the default-on Vulnerable Driver Blocklist closes the BYOVD primitive.](diagrams/28-etw-attack-defense-timeline.svg)

Every generation of ETW has been attacked. Some attacks broke a single provider; some broke every user-mode provider on a host; one would, if it worked at scale, break Defender. The defense story is on the same five-generation timeline.

### Gen 1 (2014-2018): autologger registry tampering

The dispositive taxonomy is Matt Graeber's December 24, 2018 Palantir CIRT post [1090], preserved in the Wayback Machine because the direct Medium URL has since returned HTTP 403 to non-browser fetchers. The opening framing is verbatim:

> "Event Tracing for Windows (ETW) is the mechanism Windows uses to trace and log system events. Attackers often clear event logs to cover their tracks. Though the act of clearing an event log itself generates an event, attackers who know ETW well may take advantage of tampering opportunities to cease the flow of logging temporarily or even permanently, without generating any event log entries in the process.", [1090]

Graeber and Christensen split the technique into two classes. *Persistent tampering* writes to the autologger registry path described earlier, disabling a session before it ever starts at next boot; the events of interest are never captured because the session is never running. *Ephemeral tampering* targets a live session: stopping the session via `ControlTrace`, removing a provider from a session via `EnableTraceEx2(EVENT_CONTROL_CODE_DISABLE_PROVIDER,...)`, or directly clearing the session's buffers.

The defense is direct: monitor the autologger registry surface. Sysmon Event ID 13 [662] surfaces registry value-set events in `HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\`; a SOC playbook that alerts on any unexpected write to that subtree catches the persistent class of attack reliably. Matt Graeber's authorship is cross-confirmed by the palantir/exploitguard repository [1107], which credits him as the lead researcher on the ETW work.

### Gen 2 (2020): user-mode `EtwEventWrite` 0xC3 RET patch

The technique that made ETW patching a household tradecraft term is Adam Chester's "Hiding your .NET - ETW", March 17, 2020 [1073]. The public mechanic is famous because it is small: replace the entry point of a user-mode ETW stub with `0xC3`, the near-return opcode [1072]. A caller into that stub returns before producing an event, so the calling process stops emitting user-mode ETW events for providers that funnel through that stub. Including `Microsoft-Windows-DotNETRuntime`.

The important point for this chapter is not how to perform the patch. It is where the patch sits in the trust chain:

| Property | Gap-analysis reading |
|---|---|
| Target layer | The calling process's user-mode `ntdll` mapping |
| Affected emitters | User-mode providers whose write path reaches the patched stub |
| Affected scope | The patched process, not the whole host |
| Typical casualty | CLR telemetry such as `Microsoft-Windows-DotNETRuntime` |
| Structural limit | It cannot reach kernel-emitted providers such as `Microsoft-Windows-Threat-Intelligence` |

The fluxsec.red Rust port [1108] describes the modern variant in the same architectural terms: user-mode providers eventually reach `ntdll!NtTraceEvent`, and returning from that stub suppresses the local user-mode emission. That observation explains both the power and the boundary of the technique. It is powerful against in-process user-mode telemetry; it is irrelevant to a provider whose producer fires after the syscall has crossed into the kernel.

> **The 0xC3 patch only silences user-mode providers in the patched process.** The patch operates on the calling process's user-mode trampoline. Other processes on the host are unaffected; their ETW emissions continue normally. Kernel-emitted providers like `Microsoft-Windows-Threat-Intelligence` are unaffected even in the patched process; they fire from the kernel side of the syscall path, after control has crossed the user/kernel boundary, on a code path the user-mode patcher cannot reach without first achieving kernel execution.

### Gen 3 (2021-2023): kernel-mode primitives

If a user-mode patch cannot reach EtwTi, can a kernel-mode patch? Yes, but the attacker first needs kernel execution. The most common path is BYOVD: load a signed but vulnerable driver and use its primitive to read or write kernel memory. (BYOVD is the same primitive the Code Integrity chapter (Chapter 8) spends most of its driver-blocklist budget closing.) Once you can write kernel memory you can target ETW's internal data structures directly.

Binarly's Black Hat Europe 2021 talk [1109] documents the surface verbatim:

> Many ways to disable ETW logging are publicly available from passing a TRUE boolean parameter into a `nt!EtwpStopTrace` function to finding an ETW specific structure and dynamically modifying it or patching `ntdll!ETWEventWrite` or `advapi32!EventWrite` to return immediately thus stopping the user-mode loggers. [1109]

The kernel-side primitives Binarly enumerates target the `_ETW_GUID_ENTRY` structure for a provider, the `EtwpRegistration` linked list of registered providers, and the `EtwpEventTracingProhibited` flag the kernel checks before emitting events. Yarden Shafir's 2023 Trail of Bits walkthrough [1101] provides the contemporary kernel-side data structure walk through `_ETW_REALTIME_CONSUMER` and `_ETW_SILODRIVERSTATE`, and notes:

> "Most recently, the Lazarus Group bypassed EDR detection by disabling ETW providers", [1101]

The architectural-level treatment is well-documented; the specific kernel offsets that change between Windows builds are a moving target. We treat the technique class as well-established and the per-build offset details as out of scope.

### Defense Gen 1 (RS-era, commonly cited as 2017): Antimalware-PPL + ELAM gate on EtwTi

The PPL/ELAM gate section covered this in detail. The timeline point is narrower: the Antimalware-PPL/ELAM design was already present in the Windows 10 RS-era before Adam Chester's 2020 user-mode patch became public tradecraft. Microsoft does not publicly pin the third-party EtwTi onboarding date in the sources used here, so treat "2017/1709" as a useful RS-era shorthand, not a primary-sourced release claim. The user-mode patch class is generic against `Microsoft-Windows-DotNETRuntime` and the rest of the user-mode catalog; it is structurally impotent against `Microsoft-Windows-Threat-Intelligence`.

### Defense Gen 2 (2022): Vulnerable driver blocklist on by default

The kernel-mode primitive class needs a kernel write. Without a vulnerability in the EDR's kernel driver, the realistic path is BYOVD: load a third-party signed driver that exposes a memory-write primitive. The structural defense is Microsoft's Vulnerable Driver Blocklist [271]:

> Since the Windows 11 2022 update, the vulnerable driver blocklist is enabled by default for all devices, and can be turned on or off via the Windows Security app... the vulnerable driver blocklist is also enforced when either memory integrity, also known as hypervisor-protected code integrity (HVCI), Smart App Control, or S mode is active... The blocklist is updated quarterly. In addition, blocklist updates are delivered through the monthly Windows updates as part of the standard servicing process. [271]

The blocklist enumerates known-vulnerable signed drivers by hash; the kernel refuses to load anything on the list. On a Windows 11 22H2-or-later host with the default settings, the BYOVD primitive against most known-vulnerable drivers is closed. With HVCI on, the closure is enforced even against attackers who would otherwise try to load drivers via legacy paths. The empirical bound is the LOLDrivers project's catalog of known-vulnerable drivers; the blocklist tracks public discovery with a lag of approximately one quarter, which is the residual window an attacker can exploit before a freshly disclosed driver is added.

> **Definition: BYOVD (Bring Your Own Vulnerable Driver).** The attack pattern of loading a known-vulnerable but signed driver to obtain a kernel-mode primitive (memory read, memory write, or arbitrary code execution). Used in real-world EDR-blinding attacks, including by the Lazarus Group as cited in Trail of Bits' 2023 ETW walk [1101].
>
> **Definition: Vulnerable Driver Blocklist.** The Microsoft-maintained blocklist of known-vulnerable signed drivers, by hash. Enabled by default on Windows 11 22H2 and later. Enforced more strictly when HVCI, Smart App Control, or S mode is active. Updated quarterly per the Microsoft Learn primary [271].
>
> **Sidenote.** The LOLDrivers project [385] is the empirical anchor for the BYOVD lag story. It catalogs known-vulnerable signed drivers as a community resource; the Microsoft blocklist updates quarterly, but blocklist updates are also delivered through monthly Windows servicing, so a freshly-disclosed driver can live in an exploitation window of as short as ~1 month (via Patch Tuesday) or up to a full quarter before its hash is added.
>
> **Walkthrough: the tampering timeline as gap analysis.** The first evasion layer is configuration: change the autologger registry recipe and the next boot starts different telemetry. The defender's answer is configuration integrity: monitor the autologger subtree, baseline provider GUIDs and keyword masks, and alert on drift. The second layer is user mode: patch `EtwEventWrite` or the `NtTraceEvent` path in the emitting process so that process stops producing ordinary user-mode ETW. The defender's answer is architectural separation: high-value memory telemetry moves to EtwTi, whose producer fires after the syscall crosses into the kernel. The third layer is kernel mode: bring a vulnerable signed driver, obtain a write primitive, and tamper with ETW internals or the producer path itself. The defender's answer is to reduce the availability of that primitive through the Vulnerable Driver Blocklist, HVCI, Secure Boot, and driver-load monitoring.
>
> None of those defenses makes ETW magical. They narrow which attacker capabilities are sufficient. Registry tampering requires persistence or administrator-equivalent configuration access. User-mode patching blinds only providers reached through that process's user-mode stubs. Kernel tampering still matters, but it now requires a kernel primitive that survives modern driver policy. The right mental model is not “ETW can be bypassed” or “ETW cannot be bypassed.” It is a layered gap map: identify which layer emits the signal, which layer the attacker controls, and whether the attack reaches the producer, the session, the buffer, or only one consumer's decoder.

### The 2026 picture

User-mode patching cannot reach EtwTi, the kernel-emitted memory-operation signal this chapter has treated as load-bearing. The BYOVD primitive that could reach it is structurally narrowed by default on supported hardware. The remaining gap is the long tail of newly-disclosed vulnerable drivers between disclosure and blocklist update, plus any custom kernel zero-day an attacker discovers in an EDR's own driver. Both are real, both are exploited in the wild, neither is the universally-applicable evasion the 2020-era user-mode patch class was.

That is the operational story. But ETW has structural limits even when no attacker is patching anything.

### Theoretical limits: what ETW cannot see, even with every defense engaged

Even on a well-configured Windows 11 box: HVCI/memory integrity on (VBS-backed protection of kernel-mode code integrity and executable kernel-memory transitions [279]), Vulnerable Driver Blocklist on, Antimalware-PPL Defender consuming EtwTi, third-party EDR ELAM-onboarded where applicable. There are events ETW does not emit. Some are observed too late. Some are not observed at all.

There are three structural ceilings.

### Pre-ETW kernel paths

The Global Logger session is one of the earliest things to come up at boot, but it is not the first. Some early-init driver paths run before any ETW session exists; they cannot be traced via ETW. This is the seam where the interlude hands observation back to the silicon links: Measured Boot (Chapter 4) is the discipline that records this pre-ETW prefix into TPM PCRs (Chapter 2), with attestation (Chapter 5) handled by the platform integrity layer rather than by ETW. The implication for EDR is that any malicious code executing during early boot, before the Global Logger session is up, is invisible to ETW, and visible only to the measured-boot record the first chapters of this book are about.

### Incomplete EtwTi syscall coverage

The 10 `KERNEL_THREATINT_TASK_*` task IDs are the public surface. The underlying syscall set the kernel actually instruments is not exhaustively documented. The fluxsec.red inventory [1074] is the public surface, not the private one. Some syscalls are clearly covered (`NtAllocateVirtualMemory` for cross-process allocation surfaces as `KERNEL_THREATINT_TASK_ALLOCVM`); some have partial coverage (`MAPVIEW_LOCAL` and `MAPVIEW_REMOTE` keywords cover some but not all of the section-mapping primitive set across `NtCreateSection`, `NtMapViewOfSection`, `NtMapViewOfSectionEx`, image-section vs file-section variants); some are not enumerated at all in the public manifest. Process-hollowing primitives that combine `NtUnmapViewOfSection` and `NtMapViewOfSection` may be partially covered depending on which path the attacker takes.

### The async-flush gap

ETW's per-CPU ring buffer is asynchronous. If a process allocates RWX memory, writes shellcode, executes it, and returns within one writer-thread flush interval, the event is *recorded* but the attacker's payload has *already executed*. The synchronous denial primitive on Windows belongs to kernel notify routines, not to ETW. The Microsoft Learn primary on About Event Tracing [1084] is explicit that events can be lost:

> "Events can be lost if any of the following conditions occur... The total event size is greater than 64K... The disk is too slow to keep up with the rate at which events are being generated.... For real-time logging, the real-time consumer is not consuming events fast enough.", [1084]

No ETW-only EDR can prevent a syscall whose payload completes inside one writer flush. EDRs that ship a kernel driver and register synchronous callbacks can have a denial path through fields such as `PsSetCreateProcessNotifyRoutineEx` [1103] `CreationStatus`; Sysmon uses callbacks primarily for collection/publication, while commercial prevention products decide whether to exercise the veto. ETW-only collectors cannot deny through ETW itself. ETW is observation, not enforcement.

> **Key idea.** ETW is observation, not enforcement. The synchronous denial primitive on Windows belongs to kernel notify routines, not to ETW. Sub-microsecond payloads execute before the writer thread flushes; the layered defense stack of 2026 is an empirical bar, not a theoretical guarantee.
>
> **Definition: HVCI (Hypervisor-Protected Code Integrity).** The VBS-backed code-integrity enforcement for kernel-mode code on Windows. With HVCI enabled, kernel-mode code integrity runs in the VBS isolated environment, protecting CI state and restricting kernel memory allocations/transitions that could make unsigned or modified code executable [279]. It closes unsigned-driver and executable-page abuse classes; combined with the Vulnerable Driver Blocklist it narrows much of the realistic BYOVD primitive surface as well.
>
> **Sidenote.** The "events can be lost" enumeration in [1084] is the dispositive Microsoft acknowledgment of ETW's lossy substrate. SOC playbooks should treat ETW telemetry as best-effort, not as a guaranteed audit trail. Forensic claims that depend on completeness need an independent corroborating source.
>
> **Why detection is not prevention.** A detection-only EDR can alert on a malicious operation, but only after the operation has happened. By the time the SOC sees the alert, the syscall has completed, the shellcode has executed, the credentials have been stolen. This is why the kernel-callback path (with its ability to deny via `CreationStatus`) coexists with ETW even though ETW is more flexible: a SOC playbook needs both the speed of denial and the breadth of observation.

The 2026 layered stack (Antimalware-PPL + EtwTi + HVCI + VBL) raises the empirical bar enormously. It does not close the architectural gap. Sub-microsecond payloads still execute before the writer thread flushes. The BYOVD primitive on a non-HVCI box still defeats the kernel-callback layer. There are still problems the substrate cannot solve in principle.

Those are the limits we can describe. The next section is about the limits we cannot yet measure.

### Open problems: keyword drift, secure kernel ETW, and the BYOVD arms race

The 2026 state of the art has five active open problems. Each has a partial workaround; none has a complete solution.

### 1. EtwTi keyword inventory drift across builds

Microsoft has not published a complete, current `Microsoft-Windows-Threat-Intelligence` keyword inventory. The community-maintained references (the jdu2600 cross-build inventory [1095] and the repnz manifest archive [1096]) are partial coverage and lag Microsoft's quarterly servicing cadence. EDR vendors that hard-code keyword bitmasks against an old build can silently miss events on newer builds because the keyword definitions have shifted underneath them. Detection engineers writing rules against `KERNEL_THREATINT_TASK_*` IDs that move between builds can get false negatives.

> **Aside. Why Microsoft has not published a TI keyword inventory.** There are three plausible reasons, and Microsoft has not stated which (or which combination) is operative. *Operational secrecy*: a complete keyword inventory tells attackers exactly which syscall paths are observed and which are not, narrowing the search for evasion paths. *Documentation cost*: the inventory shifts every build, and maintaining a synchronised public reference is engineering work without an obvious internal champion. *Deliberate moving target*: keeping the public surface incomplete forces attackers to reverse-engineer per build, raising the cost of stable evasion. The community references partially defeat all three rationales; the absence remains.

### 2. secure ETW (the `EtwSi*` family)

The secure-kernel ETW story should be treated as a boundary marker, not as a fully documented consumer surface. Windows VBS Trustlets run in VTL1, while ordinary kernel code and ordinary ETW consumers run in VTL0. If a telemetry producer lives in VTL1, then a VTL0 kernel attacker cannot simply patch that producer the way a user-mode attacker patches `ntdll!EtwEventWrite`. That is the strategic significance of the `EtwSi*` family: it points toward telemetry whose producer is above the normal kernel in the trust hierarchy.

The public gap is consumer documentation. The producer-side architecture (what runs in VTL1 and how it is signed and launched) is developed in the VBS Trustlets chapter (Chapter 7), and public conference material has named secure-kernel tracing fragments, but Microsoft has not published a normal Microsoft Learn-style page that says which `EtwSi*` providers exist, which consumers are allowed to subscribe, which events are stable, or which policy gates apply. Therefore no detection rule in this chapter depends on `EtwSi*`. The correct conclusion is narrower: secure-kernel ETW is evidence that Microsoft has already experimented with moving some telemetry above VTL0; it is not yet a public replacement for EtwTi, kernel callbacks, or ordinary manifest providers.

### 3. Forensic soundness of ETW telemetry

ETW is lossy by design (per the [1084] enumeration). Whether ETW-derived telemetry is *forensically sound* (chain-of-custody complete, lossless under load, attestable as untampered between event emission and SIEM ingestion) is an open question. Courts have not ruled. The current best partial result is to treat ETW as supporting evidence and require independent corroboration (file-system snapshots, network captures, OS state captures) for any claim that depends on completeness. Sysmon's Event ID 16 (Sysmon configuration changed) [662] and the autologger registry write events on `HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\` are useful integrity signals: an attacker who silenced ETW typically leaves a footprint here.

### 4. The BYOVD arms race

The Vulnerable Driver Blocklist [271] is hash-based and updated quarterly. The LOLDrivers project [385] documents the public catalog of known-vulnerable signed drivers. The gap between disclosure and blocklist update, as short as ~1 month via Patch Tuesday or up to a full quarter, is the residual exploitation window. The deeper structural issue is that the blocklist is hash-based; an attacker who finds a new vulnerability in a previously-trusted signed driver enjoys a fresh window every quarter. Closing this gap requires either a different trust model (allow-listing of known-good drivers, as Smart App Control does for executables) or behavioral detection of suspicious driver loads. Both are active areas of work.

### 5. Cross-process section-mapping coverage

EtwTi's `KERNEL_THREATINT_TASK_MAPVIEW` covers some but not all section-mapping primitives. The public fluxsec.red [1074] inventory lists `MAPVIEW_LOCAL` and `MAPVIEW_REMOTE` keywords, but the underlying syscall set (`NtMapViewOfSection`, `NtMapViewOfSectionEx`, `NtCreateSection`, image-section vs file-section variants) is not exhaustively documented. Detection engineers who depend on full coverage of cross-process section mapping are working from an incomplete map.

### What would a v2 ETW look like?

A theoretical ideal: synchronous kernel-emitted events on every security-relevant syscall, with the consumer running in VTL1 (Secure Kernel) so even a kernel-mode attacker in VTL0 cannot tamper with the consumer. The `EtwSi*` family is the partial realisation. The full ideal is incompatible with x64 syscall performance: synchronous notification on every syscall would dominate the cost of the syscall itself. The pragmatic answer Microsoft has been building toward is *selective* synchronous notification (the kernel notify routines for high-value control points) layered with *broad* asynchronous observation (ETW for everything else), with the most security-critical of the broad observations promoted to PPL/ELAM-gated kernel-emitted producers (EtwTi). Two decades of layering, no single architectural endpoint.

> **Sidenote.** For the producer side of the Secure Kernel ETW story (`EtwSi*`), the VBS Trustlets chapter (Chapter 7) develops what runs in VTL1. The Trustlet-side architecture is a separate topic large enough to need its own walkthrough.

Open problems frame the limits; the practical checks below are what an engineer can run today.

## What it means for you

The chapter's payoff is practical: ETW is not "logs" in the generic sense. It is the shared observation fabric under Windows endpoint detection. Reasoning about it means asking which provider emits the signal, which session subscribes to it, which consumer owns the callback, which protection level gates the consumer, and which kernel-integrity layer keeps an attacker from changing the substrate underneath you.

### Five things to do Monday morning

Here are five concrete checks an engineer can run on a Windows host to make that fabric visible.

> **1. Inventory your provider catalog.** `logman query providers` enumerates every registered provider on the host. Cross-reference the output against the provider catalog and flag any security-relevant provider your EDR is not consuming. Pay specific attention to `Microsoft-Antimalware-Scan-Interface`, `Microsoft-Windows-PowerShell`, `Microsoft-Windows-DotNETRuntime`, and `Microsoft-Windows-Sysmon` if Sysmon is installed. Missing expected coverage of any of these on a host you are responsible for is a detection-coverage gap, but triage it by state: provider present, channel enabled, policy configured, provider keywords enabled, consumer subscribed, and SIEM ingestion working are separate facts.
>
> **2. Verify EtwTi onboarding.** Run `wevtutil gp Microsoft-Windows-Threat-Intelligence` to confirm the provider is registered and inspect its keyword definitions. Then, if you need proof rather than ordinary health telemetry, use a lab or incident-response kernel-debugging workflow to walk the live `_ETW_REALTIME_CONSUMER` structures as in Yarden Shafir's Trail of Bits post [1101]. That is not a normal enterprise health check; it is an internal-structure inspection. For day-to-day operations, rely on vendor health signals, protected-service state, and expected session/autologger baselines, escalating to debugger enumeration only when those disagree.
>
> **3. Audit the autologger registry.** Enumerate `HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\` for unauthorised session entries. As described earlier, this is the persistent-tampering surface. A baseline audit should produce a known list of expected sessions (Defender, your EDR, Sysmon if installed, the standard Windows diagnostic listeners). Any subkey not on the baseline list is an investigation candidate; Sysmon Event ID 13 (registry value set) [662] on this subtree is a high-signal alert in any SIEM.
>
> **4. Verify HVCI and VBL enablement.** Run `Get-CimInstance Win32_DeviceGuard | Select-Object SecurityServicesConfigured, SecurityServicesRunning, VirtualizationBasedSecurityStatus` to expose whether HVCI and the Vulnerable Driver Blocklist are active. Per the Microsoft Learn primary [271], the BYOVD ceiling is your kernel-tampering risk reducer, not an absolute integrity guarantee. If VBS is `Off` on a managed endpoint, your detection coverage is structurally weaker than it should be on supported hardware. Treat it as a hardening item, not a nice-to-have.
>
> **5. Hunt for unauthorised TI consumers.** Write a hunting query for the pattern: "process X registers as ETW consumer for `Microsoft-Windows-Threat-Intelligence` and X is not on the EDR allow-list." The provider's PPL+ELAM gate makes this a high-signal alert: only an appropriately signed and ELAM-admitted Antimalware-PPL service should pass the gate, so an unexpected process holding an `EtwConsumer` handle to the TI logger ID is either a misconfigured tool, a legitimate research session you forgot about, or an attacker chain that has acquired Antimalware-PPL trust on your fleet. The first two are quick to triage; the third is an incident.

With those five checks, the catalog is no longer an abstraction. You have an inventory of what your host emits, an inventory of who consumes the most security-critical provider, an audit of the persistence surface that defines what gets emitted at all, a confirmation of the integrity layer that closes BYOVD, and a hunt for anyone who has somehow obtained the passport.

> **Bequeaths.** This interlude does not hand the next link a new guarantee. It is not a link in the chain. What it hands the *defender* is visibility: a high-rate, mostly-tamper-evident account of what every prior link actually did, queryable after the fact and, for EtwTi, emitted from a place an in-process attacker cannot reach. That account is what the cloud layer consumes as signal. When the book steps back into the spine for Part IV, the Zero Trust chapter (Chapter 26) and the Continuous Access Evaluation chapter (Chapter 27) treat an endpoint detection as one input to an access decision (device risk feeding a token-issuance or token-revocation choice) not as ground truth. That posture is exactly right, because the honest limit of everything this chapter described is the difference between *seeing* and *proving*. As the limits section argued, sight is not proof: ETW does not supply synchronous denial, losslessness, or chain of custody. The interlude's gift to the chain is visibility: the defender now knows what happened, which is necessary and far from sufficient. The chain that learned to watch itself still has to decide what to do about what it sees, and that decision moves off the box, into the cloud links that follow.
