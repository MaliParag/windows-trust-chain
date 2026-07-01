# Confidential VMs

::: trust-ledger

- **Inherits:** a remote verifier can gate access on proven, hardware-anchored platform state. The EK→AIK→quote attestation shape, here carried into a host-issued vTPM (Chapter 5, Attestation); a hypervisor-enforced isolation boundary that a more-privileged-but-untrusted layer cannot map across. The VTL0/VTL1 split, inverted to protect the *guest* from the *host* (Chapter 6, The Secure Kernel).
- **Promise:** even the cloud operator's hypervisor cannot read a confidential guest's memory or silently remap its pages, and a relying party releases a secret only after a verifier checks hardware-rooted evidence of that guest's identity. Serviced boundary: guest↔host, defended by AMD SEV-SNP or Intel TDX silicon rather than by an on-prem motherboard the customer owns.
- **TCB:** the CPU vendor's silicon and signing root (AMD-SP firmware plus the VCEK chain, or the signed Intel TDX Module plus the SGX/DCAP quoting path and Intel collateral), the in-boundary paravisor (OpenHCL at VMPL0 or the L1 TD seat), and the verifier (Microsoft Azure Attestation). The host hypervisor that schedules the VM is explicitly *outside* the memory-confidentiality boundary, but the provider control plane, signed paravisor deployment, verifier service, and key-release integration remain named trust and availability dependencies.
- **Adversary → Break:** a malicious host that remaps ciphertext (SEVered, defeated by the RMP/PAMT integrity rail) or that abuses the seams *around* the rail: cache-state reset (CacheWarp), injected `#VC` (WeSee), mistimed interrupts (Heckler), or physical voltage-glitching of the AMD-SP (One Glitch). The Promise covers *direct reads and silent remaps*, not *side channels, notification injection, or physical fault*.
- **Residual:** a compromised guest *kernel* reading its own credentials → still the in-guest VTL axis owned by The Secure Kernel (Chapter 6) and Credential Guard (Chapter 15); a relying party that releases a key on a friendly label rather than the evidence → Zero Trust (Chapter 26) and Continuous Access Evaluation (Chapter 27); microarchitectural side channels and physical-fault adversaries → an open residual this chapter names but cannot close.
- **Bequeaths:** a cloud-grade isolation floor (*the operator's hypervisor cannot read or silently alter the guest, and key release is gated on hardware evidence*), the last silicon-to-cloud guarantee the finale tests (Chapter 29, When the Chain Snaps: Storm-0558). Does NOT provide: side-channel resistance, protection against a compromised guest kernel, or safety if the relying party trusts a label instead of the proof.
- **Proof:** 🔵 documented throughout. No private Azure tenant capture, decoded JWT, GPU quote, or customer MAA policy is presented as captured; the command output and JWT/policy blocks are documented expected shapes.
:::

> **The Reasoner's question.** What if the machine you are running on is someone else's machine, and the host itself is outside your trust boundary?

---

> **Foundations. What you need before this chapter.**
>
> - **CVM / TEE.** A Confidential VM is a whole-VM Trusted Execution Environment: memory, register state, launch measurement, and attestation evidence are protected from the host hypervisor and host management code under the architectural threat model.
> - **Host, guest, paravisor.** The host hypervisor schedules the VM but is outside the confidentiality boundary. The customer guest runs Windows or Linux. The paravisor, OpenHCL on Azure, runs inside the boundary and supplies synthetic devices and the vTPM.
> - **SEV-SNP and TDX.** AMD's SEV-SNP adds the Reverse Map Table, VMPL, PVALIDATE, and VCEK-signed SNP_REPORTs. Intel's TDX adds SEAM, the signed TDX Module, Secure EPT/PAMT, MRTD/RTMRs, and TD Quotes.
> - **Attestation.** This is the same primitive the Attestation chapter (Chapter 5) established (a TPM-rooted quote a remote verifier checks against policy) applied to a host-issued vTPM. In RATS vocabulary, the VM is the attester, the SNP_REPORT or TD Quote plus vTPM quote is evidence, Microsoft Azure Attestation is the verifier, and Key Vault or a customer service is the relying party.
> - **VTL versus VMPL.** Windows VBS (the VTL0/VTL1 split owned by the Secure Kernel chapter, Chapter 6, and VBS Trustlets, Chapter 7) still runs inside the guest. SEV-SNP VMPL or TDX partitioning excludes the cloud host; VTL excludes the guest kernel from the Secure Kernel. They protect different boundaries, and a Windows CVM uses both.

---

> **Chapter thesis.**
>
> **Azure Confidential VMs are Windows or Linux guests that the cloud operator's hypervisor cannot read or silently modify.** They are built on two distinct CPU primitives: AMD SEV-SNP (Reverse Map Table + Virtual Machine Privilege Level + SNP_REPORT) and Intel TDX (Secure Arbitration Mode + the signed TDX Module + RTMR0-3), and wrapped on Azure by the open-source Rust paravisor OpenHCL running inside the trust boundary at VMPL0 or the L1 TD seat.
>
> Inside that boundary the paravisor synthesizes a vTPM whose quotes chain to the SEV-SNP or TDX hardware report, and Microsoft Azure Attestation runs a customer-defined policy v1.2 file (with claim rules and JmesPath projection where the grammar permits it) against the evidence to release HSM-backed keys via Secure Key Release.
>
> The Generation-2 integrity rail closes the SEVered and SEVurity ciphertext-remapping class architecturally, but the 2024-era attack set (CacheWarp, WeSee, Heckler, and the broader Ahoi notification-attack family) demonstrates that cache-state and notification-injection seams remain. The core RMP/PAMT rail is mature; the residuals around it, not the rail itself, are where the work now is.

## Even the cloud operator must not see your memory

A Windows Server VM is running a SQL query on Azure right now. It is joining a million-row variant table against a patient-genome reference, building an index in RAM, and serving the answer back to a clinician's web portal. The customer who owns that VM has every reason to want the query to succeed and every reason to make sure that the platform cannot read or silently remap the index through the ordinary host path: not the hypervisor it runs on, not the host management code below it, not the Microsoft engineer holding the on-call pager. That is an architectural claim about direct reads and page substitution, not a promise against every form of physical coercion, side channel, or vendor-root compromise.

As of the 2026-05-20 Azure products page, that is not a thought experiment. It is the contract Azure signs when you provision supported AMD SEV-SNP or Intel TDX confidential VM families [1258]. And the contract has a shape. An architecturally enforced shape rooted in two distinct CPU mechanisms, wrapped in an open-source Rust paravisor [1259], verified by a policy-driven attestation service [186], and dented by the 2024 CacheWarp / WeSee / Heckler attack class that this chapter will name in order.

The Confidential Computing Consortium defines the contract in one sentence: "Confidential Computing protects data in use by performing computation in a hardware-based, attested Trusted Execution Environment" [1260]. That sentence finishes a longer thought. Data at rest gets BitLocker and full-disk encryption. Data in transit gets TLS. Data in use (the gigabytes that sit in DRAM while a process actually computes against them) has historically been the unencrypted leg of a three-legged stool.

> **Definition, Confidential VM.**
>
> A virtual machine whose memory and CPU state are cryptographically protected from the host hypervisor and host management path, and whose configuration is bound to a hardware-rooted attestation report a remote verifier can check. The Confidential Computing Consortium's framing is the canonical one: "These secure and isolated environments prevent unauthorized access or modification of applications and data while in use" [1260].
>
> **Definition: Trusted Execution Environment (TEE).**
>
> A computing environment whose confidentiality, integrity, and attestability are enforced by hardware mechanisms below the level of the operating system. A TEE may be process-scoped (Intel SGX enclaves), VM-scoped (AMD SEV-SNP, Intel TDX), or board-scoped (AWS Nitro Enclaves). The Confidential VM is the VM-scoped specialization.

Three concrete workloads make the contract operationally legible. A regulated clean room running joint analytics over patient genomes between an academic medical center and a pharmaceutical sponsor, where the contract literally forbids the sponsor's staff from reading raw genotypes. A multi-party anti-money-laundering analytic between two competing banks who will share encrypted features but not raw transactions. A sovereign-cloud control plane that must not leak to the hyperscaler's host kernel under any subpoena. In each case the threat model treats the cloud operator as semi-trusted at best and adversarial at worst, and in each case the customer wants the cipher engine to live below the operator's reach.

> **The third leg of the data-protection stool.**
>
> Encryption at rest hides bytes on storage. Encryption in transit hides bytes on the wire. Encryption in use is the missing third leg: the one that asks the cipher engine to live inline with the memory controller, so that a VM's working set is not exposed in plaintext to the host path. That is what AMD SEV-SNP and Intel TDX do at the silicon layer, and what Azure productises with the OpenHCL paravisor and Microsoft Azure Attestation [1260], [1261].

The architecture that makes this contract real takes vocabulary from Internet standards as well as silicon. RFC 9334, published in January 2023, gives us the verifier / evidence / relying party language used throughout [1262]. An *attester* (the guest VM plus the paravisor) generates *evidence* (a hardware attestation report plus a vTPM quote). A *verifier* (Microsoft Azure Attestation in Azure's case) checks the evidence against a policy and emits an *attestation result* (a signed JWT). A *relying party* (Azure Key Vault, or any customer service) consumes the result and decides whether to release a secret. A SEV-SNP or TDX guest, an OpenHCL paravisor, and Microsoft Azure Attestation realise that abstract diagram on commodity silicon. It is the verifier-and-evidence machinery the Attestation chapter (Chapter 5) established, now rooted in a host-issued vTPM rather than a discrete TPM chip on a board the customer owns.

That leads to the obvious question. How can a CPU enforce that even the hypervisor cannot read RAM? And once it can, why does a single mechanism turn out to be insufficient. Why does the architecture need a separate integrity rail on top? The next two sections trace the wrong answers that came first.

## Why enclaves were not enough

In August 2016 David Kaplan stood on the USENIX Security stage in Austin and described "two new x86 ISA features developed by AMD" that he called "the first general-purpose memory encryption features to be integrated into the x86 architecture" [1263]. Kaplan was, in the conference biography's words, the "lead architect for the AMD memory encryption features" [1263]. His argument was deceptively simple. An enclave that lives inside a single process is the wrong unit of confidential computation for a cloud workload. The workloads customers actually run (database engines, analytic services, language runtimes) want gigabytes of working memory, multiple threads, and an unmodified operating system. None of that fits inside a roughly 96-MiB SGX enclave [1264].

Two design ancestors set the shape of the problem before either AMD or Intel solved it.

The first ancestor is the Trusted Platform Module. The TCG TPM specification dates back to 2003, when "the first TPM version that was deployed was 1.1b" [181]. TPM 2.0 was announced on April 9, 2014 [181] and standardized as ISO/IEC 11889. The TPM contributed three concepts that remain load-bearing two decades later: *platform configuration registers* (the extend-only PCR digests that a measured-boot chain builds), *attestation identity keys*, and a *quote* operation that signs PCR state with a key whose origin a remote verifier can trust. The TPM is not a TEE in the modern sense (it does not host computation) but it is the first widely deployed device that lets a remote party gain cryptographic assurance about what a machine is running. Every confidential VM design ships a TPM-shaped attestation surface inside it.

The second ancestor is Intel Software Guard Extensions. Designed at the HASP 2013 workshop and delivered on Skylake in 2015 [1264], SGX introduced the *enclave*: a process-scoped TEE backed by the Enclave Page Cache, a CPU-managed memory region whose contents are decrypted only inside the cache. Programs enter and leave through `ENCLU`-family instructions; cross-domain calls use a partitioned model called `ECALL` / `OCALL`; remote attestation is mediated by Intel through a quoting enclave. SGX worked, in the strict sense that the threat model included even a malicious operating system. But three things kept it from generalizing.

> **Definition: Enclave Page Cache (EPC).**
>
> A CPU-protected DRAM region that holds an SGX enclave's working memory in encrypted, integrity-checked form. On early Skylake / Kaby Lake parts the EPC was capped at approximately 128 MiB physical with between ~93 and 96 MiB usable depending on BIOS reservation after reserved EPCM metadata accounting [1264]. Anything beyond the cap paged through the encrypted-page-eviction path with a substantial performance cliff, which is one of the architectural reasons SGX did not generalize to whole-VM cloud workloads.

The EPC cap was the first. A working set of ~96 MiB is fine for a key-wrapping service or a small ML model, but it is not a cloud-database VM. The second was the partitioned programming model. Real applications had to be split into trusted and untrusted halves with explicit `ECALL` / `OCALL` boundaries, which is a refactoring tax that few existing codebases would pay. The third was the side-channel question: Foreshadow [344], SgxPectre [347], and SGAxe [1265] each demonstrated that a determined attacker with microarchitectural access could extract secrets from SGX, often without ever defeating the cipher itself.

> **Sidenote.**
>
> Microsoft's response was *Haven*, an OSDI 2014 project that put a Windows library OS (Drawbridge) inside an SGX enclave to run unmodified Windows binaries. Haven worked as a proof of concept but was effectively obviated by the EPC cap and by the slow pace of SGX silicon delivery in Xeon-class CPUs. The library-OS-in-an-enclave became one of several dead ends on the road to whole-VM TEEs.

Microsoft staked Azure publicly to "data in use" on September 14, 2017, when Mark Russinovich announced Azure confidential computing on the company blog: "Microsoft Azure is the first cloud to offer new data security capabilities with a collection of features and services called Azure confidential computing" [1266]. The same post named the initial backing TEEs. "Initially we support two TEEs, Virtual Secure Mode and Intel SGX. Virtual Secure Mode (VSM) is a software-based TEE that's implemented by Hyper-V in Windows 10 and Windows Server 2016" [1266]. VSM was already the substrate of Credential Guard and HVCI inside the operating system; pulling it up as a "TEE the cloud customer can target" was the bridge between the in-OS Secure Kernel story and the eventually-needed silicon-rooted CVM.

The industry got organized two years later. Microsoft announced the intent to form the Confidential Computing Consortium on August 21, 2019 [1267], and the Linux Foundation press release on October 17, 2019 supplied the formal founding roster: premiere members "Alibaba, Arm, Google Cloud, Huawei, Intel, Microsoft and Red Hat" and general members "Baidu, ByteDance, decentriq, Fortanix, Kindite, Oasis Labs, Swisscom, Tencent and VMware" [1268].

> **Aside: Why this section names Kaplan but not the Intel TDX architects.**
>
> Across three load-bearing AMD whitepapers (SME/SEV in 2016, SEV-ES in February 2017, and SEV-SNP in January 2020), the PDF cover-page metadata records "David Kaplan" as the named author [1269], [1270], [1271], and the USENIX Security 2016 biography corroborates "lead architect for the AMD memory encryption features" [1263]. Across the parallel Intel artifacts (the September 2020 TDX whitepaper and the Architecture Specification doc 344425-001) PDF metadata names only "Intel Corporation" as the institutional author and does not enumerate individual architects [1272]. We name David Kaplan throughout because the documentary record names him; we deliberately do not name individual Intel architects because the documentary record does not.
>
> **Walkthrough: the three legs of data protection.**
>
> Put the same patient-genome index in three places. On disk, Azure can encrypt the OS and data volumes with platform-managed or customer-managed keys; BitLocker, storage encryption, and Key Vault solve the *at rest* leg. On the wire, TLS 1.3 or IPsec solves the *in transit* leg. The hard case is the in-memory hash table while SQL Server joins variants to reference rows: the CPU must fetch plaintext cache lines to execute the query, yet the host hypervisor and operator must see only ciphertext in DRAM. A confidential VM completes that third leg by moving the cipher boundary below the hypervisor. SEV-SNP or TDX encrypt and integrity-bind memory, OpenHCL supplies the in-boundary devices and vTPM, and MAA turns the resulting evidence into a verifier-signed decision a relying party can use [1260], [1261], [186].

If a TEE has to be smaller than a single page cache, the unit of confidential computation is wrong. What if the unit were a whole VM, and the cipher engine lived inline with the memory controller? The next section is the first time someone tried.

## Generation 1 and SEV-ES: confidentiality without integrity

April 2016. David Kaplan, Jeremy Powell, and Tom Woller publish the AMD whitepaper *AMD Memory Encryption* [1269]. The paper introduces two features in a single document. Secure Memory Encryption (SME) is a chassis-wide bulk cipher: a per-boot AES-128 key, managed by the on-die AMD Secure Processor, encrypts main memory transparently to the operating system. Secure Encrypted Virtualization (SEV) takes the same engine and gives each VM its own AES key tagged into an Address Space Identifier (ASID) in the cache, so two co-resident VMs cannot read each other's memory and neither can the hypervisor. The "C-bit" in the guest page table marks which pages are encrypted [1269]. The first silicon to ship SEV was the first-generation EPYC "Naples" launched June 20, 2017 [1273].

> **Definition, C-bit.**
>
> A high physical-address bit in an AMD SEV guest's page-table entries that signals to the memory controller "this page is encrypted with my VM's key." The C-bit is the per-page opt-in that lets a SEV guest mix encrypted private memory with explicitly shared bounce buffers in the same address space. Its absence means a page is cleartext to the hypervisor; its presence means the AES engine in the memory controller decrypts on every read and encrypts on every write [1269].

The threat model was clear and the architecture was honest about it. The hypervisor sees ciphertext on every encrypted page. What the architecture did *not* do, and what the original whitepaper did *not* claim, was integrity. The hypervisor remained authoritative over the nested page tables. It could remap which host physical page a given guest physical address pointed to, and the cipher engine would happily decrypt whatever blob it found under the same key.

That gap produced the architectural lesson.

## SEVered (Morbitzer et al., EuroSec 2018)

In May 2018, four authors from Fraunhofer AISEC (Mathias Morbitzer, Manuel Huber, Julian Horsch, and Sascha Wessel) published a paper whose abstract is unambiguous: "We present the design and implementation of SEVered, an attack from a malicious hypervisor capable of extracting the full contents of main memory in plaintext from SEV-encrypted virtual machines" [1274]. The attack did not break the cipher. It exploited the fact that a malicious hypervisor could *remap* the guest-physical pages backing a network service's response so that they pointed at the memory holding the secret it wanted. Because SEV transparently decrypts memory for the guest, the service would then read the target page as plaintext and transmit it over its normal output channel. Because there was no architectural binding between a guest physical address and the ciphertext that should sit there, the hypervisor could read the entire VM by chaining such remappings.

> **Primary-source quotation.**
>
> We present the design and implementation of SEVered, an attack from a malicious hypervisor capable of extracting the full contents of main memory in plaintext from SEV-encrypted virtual machines.: Morbitzer, Huber, Horsch, Wessel, EuroSec'18 [1274]

The architectural lesson, stated as bluntly as the paper deserves, is that confidentiality without integrity is not confidentiality.

> **Key idea.**
>
> Confidentiality without integrity is not confidentiality. The hypervisor that can move ciphertext between addresses is the hypervisor that can read it. The integrity of the guest-physical-to-host-physical mapping is as load-bearing as the cipher itself.

## SEV-ES (February 2017): half a fix

AMD's SEV-ES, dated February 17, 2017 in the whitepaper's PDF cover page [1270], actually predates SEVered: it answered original SEV's register-state leakage, not the remapping attack. This is the half-step the section title treats separately from original SEV: guest register state becomes encrypted on VM exits, but the design still lacks the SNP integrity rail that later closes ciphertext remapping. SEV-ES introduced register-state encryption on VMEXIT. Before SEV-ES, every VM exit handed the hypervisor a complete dump of guest CPU registers, including pointers into otherwise-encrypted memory. SEV-ES encrypted the saved register state under the guest key, surfaced a new `#VC` (VMM Communication) exception (vector 29), and required the guest to use a deliberately shared page called the Guest-Hypervisor Communication Block (GHCB) for everything that genuinely needed to cross the boundary: emulated I/O, MMIO, time, the works.

> **Definition, GHCB (Guest-Hypervisor Communication Block).**
>
> A page that a SEV-ES (and later SEV-SNP) guest deliberately shares with the hypervisor for the purposes of communicating about events the hypervisor genuinely needs to handle: emulated I/O, MMIO accesses, certain control-plane operations. The GHCB is the explicit, audited "side channel" through the trust boundary. Everything else stays encrypted [1270].

SEV-ES closed one channel and left the other open. The integrity of the GPA-to-HPA mapping was still the hypervisor's problem to behave on, and the cipher was still XEX-mode AES without any keyed authentication. Two more papers made the architectural pressure unbearable.

## ICUP (Buhren et al., CCS 2019) and SEVurity (Wilke et al., S&P 2020)

In August 2019, Robert Buhren, Christian Werling, and Jean-Pierre Seifert published *Insecure Until Proven Updated* [1275]. The abstract makes the operational point cleanly: "We demonstrate that it is possible to extract critical CPU-specific keys that are fundamental for the security of the remote attestation protocol. This effectively renders the SEV technology on current AMD Epyc CPUs useless when confronted with an untrusted cloud provider" [1275]. The mechanism was a firmware rollback against the AMD-SP that exposed attestation keys.

In May 2020, Wilke, Wichelmann, Morbitzer, and Eisenbarth published *SEVurity: No Security Without Integrity* at IEEE S&P [1276]. Their two new methods, the project-page abstract records verbatim, "allow us to inject arbitrary code into SEV-ES secured virtual machines. Due to the lack of proper integrity protection, it is sufficient to reuse existing ciphertext to build a high-speed encryption oracle" [1276]. The architectural diagnosis was now overdetermined: integrity had to enter the design, not as a side feature, but as a load-bearing rail.

> **Sidenote.**
>
> The same Buhren-led group escalated to physical fault injection in August 2021 with *One Glitch to Rule Them All*, voltage-glitching the AMD Secure Processor on Zen 1 / 2 / 3 to extract custom payloads [1277]. The PSPReverse GitHub artifact contains the supporting tooling [1278]. This is the *physical-fault* lower bound on the AMD-SP: an adversary with the right glitcher can subvert the security processor itself. The SEV-SNP design assumes a logical adversary; physical-access adversaries remain a known residual that Where This Link Breaks will revisit.

## Intel's parallel road: TME and MKTME

Intel's bottom-of-stack cipher engine ran on a parallel track. In December 2017, Intel published *Architecture Memory Encryption Technologies Specification*, document 336907 rev 1.1 [1279], introducing Total Memory Encryption (TME). The multi-key successor, MKTME (later TME-MK), surfaced publicly through a September 7, 2018 Linux-kernel RFC by Alison Schofield archived on LWN: "Multi-Key Total Memory Encryption API (MKTME)... allows multiple encryption domains, each having their own key. While the main use case for the feature is virtual machine isolation" [1280]. TME-MK is the per-keyID memory cipher that the eventual Intel TDX architecture will mount its trust-domain model on top of.

Three papers, two vendors, one architectural verdict: confidentiality without integrity is not confidentiality, and the architecture has to change. What did AMD and Intel actually build in response?

> **Walkthrough: why the AMD line had to grow an integrity rail.**
>
> Read the AMD sequence as a failure-driven state machine, not as a feature list. SME encrypts all DRAM with one platform key, which protects against cold-boot and bus snooping but does not isolate one VM from another. SEV moves to per-VM keys, which blocks a neighboring VM and a curious hypervisor from directly reading another guest's plaintext, but still lets the hypervisor choose the nested-page mapping. SEV-ES encrypts the register save area on VMEXIT and forces legitimate exits through the GHCB, which closes the obvious register-leak path. SEVered, ICUP, and SEVurity then show that neither per-VM encryption nor register encryption binds ciphertext to the guest physical address that owns it. SEV-SNP is the point where the architecture finally says the mapping itself is part of the security property [1269], [1270], [1271], [1274], [1275], [1276].

## Generation 2: the integrity rail

January 9, 2020. AMD publishes the 20-page SEV-SNP whitepaper, sole-authored by David Kaplan, with the title *Strengthening VM Isolation with Integrity Protection and More* [1271]. Eight months later, in September 2020, Intel publishes the first public TDX whitepaper (document 343961-002US, filename `tdx-whitepaper-final9-17.pdf`, PDF creation date Thursday September 17, 2020) and the companion Architecture Specification doc 344425-001 dated September 1, 2020 [1272]. Two vendors, two different architectural answers, one shared diagnosis: the hypervisor must be excluded from the GPA-to-HPA mapping, not just from the ciphertext.

The phrase *integrity rail* is deliberately narrower than "make memory encrypted." A first-generation encrypted-memory design gives the memory controller a key and asks the hypervisor not to lie about where pages live. A generation-2 design makes the page's ownership and expected address part of the hardware-checked translation path. On AMD that check is the RMP entry for the host physical page: ASID, expected GPA, VMPL permissions, immutable state, and validation state must line up before the CPU may consume the plaintext. On Intel it is the combination of Secure EPT, PAMT metadata, the TDX Module, and TME-MK keyIDs: the legacy VMM can propose mappings, but the signed module in SEAM is the authority for private TD state [1271], [293].

That is why SEV-SNP and TDX are not merely "SEV with better encryption" or "TME with a product name." They relocate a power the hypervisor used to have. The host can still schedule vCPUs, back pages with host memory, deliver virtual devices, and force exits. It cannot silently decide that guest physical page X now means host physical page Y if the integrity metadata says otherwise. SEVered becomes a fault, not because AES learned what a database page is, but because the CPU refuses to pass a mismatched translation to the AES engine in the first place [1274], [1271].

> **Sidenote.**
>
> This chapter uses the Intel-authored PDF metadata for the TDX whitepaper and Architecture Specification as the primary date anchor for TDX, rather than tertiary summaries [1272].

## AMD SEV-SNP: four ingredients

SEV-SNP keeps the per-VM AES cipher from SEV and the register-state encryption from SEV-ES, and adds four new architectural ingredients that together close the integrity gap.

The first is the *Reverse Map Table* (RMP). The RMP is a system-wide per-page metadata table consulted on every nested page-table walk. Each entry binds a host physical page to the tuple `(assigned ASID, expected guest physical address, VMPL, immutable bit, validated bit)`. If the hypervisor tries to remap a guest physical address to a different host page, the RMP entry will fail to match and the CPU raises an `#NPF(rmpfault)`. The architecture's own description is verbatim: "SEV-SNP adds strong memory integrity protection to help prevent malicious hypervisor-based attacks like data replay, memory re-mapping, and more to create an isolated execution environment" [292]. This is the integrity rail. It is not a separate keyed MAC over memory; it is a structural binding that turns SEVered-class remappings into faults.

> **Definition: Reverse Map Table (RMP).**
>
> A system-wide AMD SEV-SNP data structure that records, for every host physical page, the guest ASID it belongs to, the guest physical address it is mapped at, the VMPL ACL, an immutable flag, and a validated flag. Every nested page-table walk consults the RMP; mismatches raise `#NPF(rmpfault)`. The RMP is the architectural answer to SEVered: the hypervisor remains in charge of nested page tables, but the RMP says what each host page is allowed to be used for [1271], [292].

The second is the `PVALIDATE` instruction. A SEV-SNP guest must explicitly *validate* a page before it uses it for confidential storage. The hypervisor cannot fake validation; if the page has not been validated by the guest, accesses fault. This pushes the responsibility for tracking "is this page really part of my private memory" into the guest, where the hypervisor cannot lie about it.

The third is the Virtual Machine Privilege Level lattice.

> **Definition: Virtual Machine Privilege Level (VMPL).**
>
> A four-level privilege lattice (VMPL0 highest, VMPL3 lowest) introduced by AMD SEV-SNP. Each RMP entry includes per-VMPL access-control bits, so a single SEV-SNP guest can split itself into multiple ring-shaped partitions where a higher-VMPL component (for example, a paravisor at VMPL0) sees pages that a lower-VMPL component (the customer's kernel at VMPL2) cannot. VMPL appears as a field inside the SNP_REPORT, so a remote verifier can tell which VMPL produced a given quote [1271].

The fourth is the attestation report. The SNP_REPORT is an ECDSA-P384 signed blob produced by the AMD-SP, carrying fields including the launch *measurement*, the guest *policy*, the user-supplied *report_data* nonce, the issuing *vmpl*, the *chip_id* (zeroed when the guest sets the MASK_CHIP_ID policy bit), and the *tcb_version*. The signing key is the Versioned Chip Endorsement Key (VCEK), derived per chip per TCB version from a long-lived endorsement key, and the certificate chain runs `VCEK_cert -> ASK -> AMD root` [292].

> **Definition: Versioned Chip Endorsement Key (VCEK).**
>
> The AMD SEV-SNP attestation signing key. Derived deterministically from each chip's individual endorsement secret and the current TCB version (firmware level), so a single chip exposes one VCEK per TCB version. The certificate chain anchors back to AMD's root via the AMD Signing Key (ASK). The VCEK is what makes SEV-SNP attestation chain to silicon: the verifier checks the SNP_REPORT signature against a VCEK certificate AMD will only issue for genuine AMD-SP firmware [1271], [292].
>
> **Primary-source quotation.**
>
> SEV-SNP adds strong memory integrity protection to help prevent malicious hypervisor-based attacks like data replay, memory re-mapping, and more in order to create an isolated execution environment.: AMD SEV-SNP whitepaper, January 2020 [1271]
>
> **Walkthrough: an RMP check on a single load.**
>
> A guest instruction loads from a guest virtual address. The normal page walk resolves the guest virtual address to a guest physical address, and the nested page walk proposed by the hypervisor resolves that guest physical address to a host physical page. Before the memory controller decrypts anything, SEV-SNP consults the Reverse Map Table entry for that host page. The entry must say, in effect: this host page belongs to this guest ASID, at this expected guest physical address, accessible at this VMPL, and already validated by the guest. If every field matches, the AES engine decrypts the line under the guest key and the CPU retires the load. If a malicious hypervisor performs the SEVered trick (mapping the guest physical address for a known network buffer onto the host page that actually stores a secret), the expected-GPA field fails and the CPU raises `#NPF(rmpfault)`. The cipher did not become authenticated encryption; the mapping became architecturally checked before decryption [1271], [292].

## Intel TDX: a different geometry, the same end-state

Intel reached the same architectural conclusion with a different mechanism. Rather than bake integrity into microcode plus the AMD-SP, Intel introduced a new CPU mode and a separately signed software module that runs in it. The Intel TDX overview is verbatim: "A CPU-measured Intel TDX module enables Intel TDX. This software module runs in a new CPU Secure Arbitration Mode (SEAM) as a peer virtual machine manager (VMM)... hosted in a reserved memory space identified by the SEAM Range Register (SEAMRR)" [293].

The ingredients are seven, not four.

> **Definition: Secure Arbitration Mode (SEAM).**
>
> A new CPU privilege state introduced by Intel TDX. Code running in SEAM is hosted in a physical-memory range identified by the SEAM Range Register (SEAMRR) that the legacy VMM cannot inspect. Only the signed Intel TDX Module runs in SEAM, and it does so as a peer VMM that mediates every interaction between the legacy hypervisor and a Trust Domain [293].

The Intel **TDX Module** is the second ingredient: a CPU-measured firmware binary, loaded by the SEAMLDR at boot, that mediates every entry into and exit from a Trust Domain via `SEAMCALL` and `SEAMRET` instructions. The Intel-signed `intel-tdx-module-1.5-base-spec-348549002.pdf` is the canonical specification for the current generation [1281].

The third is the **Trust Domain**, a VM-shaped container that carries a *Shared Bit* in the guest physical address. A clear shared bit means the page is private; a set shared bit means the page is deliberately shared with the hypervisor for I/O bounce buffers. The fourth is **TME-MK** memory encryption, derived from the December 2017 TME spec [1279] and the September 2018 MKTME Linux-kernel RFC [1280]: AES-128 in XTS mode, with the keyID embedded in the upper physical-address bits, gives one key per Trust Domain.

The fifth ingredient is the structural analog of AMD's RMP, the **Physical-Address-Metadata table** (PAMT). The Intel TDX overview enumerates the architectural elements precisely: "Intel TDX uses architectural elements such as SEAM, a shared bit in Guest Physical Address (GPA), secure Extended Page Table (EPT), physical-address-metadata table, Intel Total Memory Encryption: Multi-Key (Intel TME-MK), and remote attestation" [293].

The sixth ingredient is the measurement registers. The **MRTD** is the build-time measurement of the initial TD image, similar to a TPM PCR fixed at launch. **RTMR0 through RTMR3** are the runtime measurement registers, four PCR-equivalents the TDX Module exposes for runtime measured-boot extensions. These four registers are what a TDX-aware Trusted Boot chain extends.

> **Definition: MRTD and RTMR0-RTMR3.**
>
> The build-time and runtime measurement registers exposed by an Intel TDX Trust Domain. MRTD is hashed by the TDX Module over the initial TD launch image and is the SEAM analog of an immutable launch PCR. RTMR0-3 are four extendable runtime registers, the SEAM analog of the runtime-extension TPM PCRs (the same conceptual role as PCRs 8-15 in the canonical static-OS measurement chain), that hold a measured-boot chain of subsequent components (loaders, kernel, initrd, paravisor pages). The canonical TDX-vTPM event-log convention used by Linux IMA and systemd-stub maps MRTD to PCR[0], RTMR[0] to PCR[1, 7], RTMR[1] to PCR[2-6], and RTMR[2] to PCR[8-15], leaving RTMR[3] reserved. A TD Quote carries all five values; a verifier evaluates them against a customer-defined policy [293], [1272].

The seventh is the **TD Quote**. A TD Quote is produced in two stages. The TD guest first issues `TDCALL[TDG.MR.REPORT]`, which lands in the TDX Module (the VMM-to-Module entry is the separate `SEAMCALL` interface defined in the comparison table below); the TDX Module returns a `TDREPORT`, a MAC-protected report whose report data can carry a nonce or public-key binding. A host-side quote-generation service hosts the Intel SGX TD Quoting Enclave, verifies the TDREPORT was generated on the same host, and converts it into a TD Quote signed through the DCAP / PCK attestation chain. A verifier then checks the quote signature under an Intel-rooted CA chain, the PCK certificate and CRLs, QE identity and TCB, platform TCB info, MRTD/RTMR values, TD-supplied report data, and policy. The Intel Trust Authority (or Microsoft Azure Attestation, or Google's verifier) performs that verification role [293], [1281], [1282].

> **Walkthrough: a TDX transition.**
>
> The legacy VMM still schedules virtual CPUs, injects events, and owns ordinary host policy, but it no longer has unilateral authority over a Trust Domain's private pages. When the VMM needs to perform a TD management operation it enters the signed TDX Module with `SEAMCALL`; the module runs from the SEAMRR-protected range, checks Secure EPT and PAMT metadata, and returns with `SEAMRET`. When the VMM schedules a Trust Domain's vCPU, it enters through the `SEAMCALL` leaf `TDH.VP.ENTER`; a TD exit is an event handled by the module, which returns control to the VMM. Private memory is encrypted with a TME-MK keyID and tracked by PAMT metadata; shared memory is explicitly marked by the GPA shared bit for bounce buffers and device emulation. The important difference from AMD is therefore not the outcome but the mediator: Intel inserts a measured, signed software module in a new CPU mode between the old hypervisor and the private TD state [293], [1281].

## Side by side

The two architectures answer the same question and arrive at the same end-state contract through fundamentally different trust geometries.

| Ingredient | AMD SEV-SNP | Intel TDX |
|---|---|---|
| Memory cipher | AES-128, per-VM key in memory controller | AES-128-XTS, per-TD key by keyID (TME-MK) |
| Integrity binding | Reverse Map Table per host page | Physical-Address-Metadata table + Secure EPT |
| Mediating component | AMD-SP firmware (microcode + on-die security processor) | Signed Intel TDX Module in SEAM mode |
| Privilege lattice | VMPL0-VMPL3 (four levels) | TD Partitioning L1/L2 (TDX Module 1.5) |
| Build-time measurement | Launch measurement in SNP_REPORT | MRTD inside the TDX Module |
| Runtime measurement | None at module level (vTPM provides it) | RTMR0-RTMR3 inside the TDX Module |
| Attestation signing key | VCEK (ECDSA-P384), per chip per TCB version | TD Quote signed through the SGX TD Quoting Enclave / DCAP PCK chain |
| Verification collateral | VCEK certificate plus ASK / AMD root | PCK certificate, Intel CA chain, CRLs, QE identity, and TCB info |
| Page-validation primitive | `PVALIDATE` (guest-driven) | TDX Module-mediated page acceptance |
| Page-class indicator | C-bit (clear = shared, set = private/encrypted) | Shared bit in GPA (set = shared) |
| Hypervisor-to-trust-component call | Mediated VMRUN | `SEAMCALL` / `SEAMRET` |

The page-class row has opposite polarity by design: SEV-SNP marks private/encrypted pages with the C-bit, while TDX marks shared pages with the GPA shared bit.

> **Key idea.**
>
> SEV-SNP and TDX answer the same question differently. AMD bakes integrity into microcode plus the AMD-SP, signs with a per-chip per-TCB VCEK, and exposes a four-level VMPL lattice. Intel puts integrity into a separately loaded, separately signed software module running in a new CPU mode, then routes attestation through the SGX TD Quoting Enclave and DCAP collateral rather than a simple one-hop certificate chain. The trust roots, the breaking surfaces, and the supply chains are different even when the end-state contract is the same.
>
> **Walkthrough: the same contract through two trust geometries.**
>
> On AMD, the trust root is the AMD Secure Processor plus microcode. The AMD-SP provisions the per-VM key, the CPU checks the RMP during address translation, VMPL bits split the guest into paravisor and customer partitions, and the AMD-SP signs an SNP_REPORT with a VCEK whose certificate chains to AMD. On Intel, the trust root is the signed TDX Module running in SEAM plus the SGX/DCAP quoting path. The module owns TD metadata, Secure EPT, PAMT checks, TD entry and exit, MRTD/RTMR measurement, and the TDREPORT that the TD Quoting Enclave converts into a TD Quote; the verifier then validates Intel collateral, QE identity/TCB, platform TCB info, and quote measurements. A relying party should not treat these as interchangeable implementation details: the AMD residual risk concentrates in AMD-SP firmware and VCEK issuance; the Intel residual risk concentrates in the TDX Module, SEAM loader, PAMT/Secure-EPT mediation, Quoting Enclave chain, and freshness of DCAP collateral [292], [293], [1281], [1282].

Generation 2 makes a confidential VM architecturally possible. But a SEV-SNP guest is not yet a Windows Server VM you can lift and shift onto Azure. There is a whole productisation problem still to solve. How does Microsoft put a paravisor inside that trust boundary, and what does it deliver?

## The contract: a cloud-shaped TEE

A confidential VM is two rails, not one. Rail 1 is **confidentiality plus integrity** of memory and CPU state. Rail 2 is **measurement plus attestation**. SEV-SNP and TDX each deliver both rails: a measurement chain anchored in silicon, terminated in a remote verifier, with a signed result that a relying party can act on.

The Confidential Computing Consortium's framing, repeated here as a contract the architectures actually realise: "Confidential Computing protects data in use by performing computation in a hardware-based, attested Trusted Execution Environment" [1260]. *Hardware-based* is rail 1. *Attested* is rail 2. The two words together are why a TPM-only system, however well-measured, is not a CVM, and why a SEV-only system, however well-encrypted, is not a CVM either.

RFC 9334 names the actors. The *attester* is the guest plus the paravisor producing evidence. The *evidence* is the SNP_REPORT or TD Quote, plus optionally a vTPM quote chained to it. The *verifier* is the entity that checks the evidence against a policy and emits an attestation result. The *relying party* is the consumer who acts on the result: typically a key vault releasing a wrapped secret [1262].

> **Definition: RATS roles and topologies.**
>
> The IETF Remote ATtestation procedureS working group's RFC 9334 (January 2023) fixes the vocabulary the rest of the confidential-computing industry uses: an *attester* produces *evidence*; a *verifier* checks it against reference values from an *endorser* and a *reference value provider* and emits an *attestation result*; a *relying party* acts on the result. RFC 9334 §5 names two topologies. In the *Passport* model (§5.1), the attester sends evidence directly to the verifier, collects a signed result, and presents that result to the relying party. In the *Background-Check* model (§5.2), the attester sends evidence to the relying party, which forwards it to the verifier and receives the result on the attester's behalf. Microsoft Azure Attestation, Intel Trust Authority, Google's verifier, and AWS KMS attestation all implement variants of this model [1262].

Microsoft Azure Attestation implements the *Passport* model. The attester (the CVM, through its in-guest agent) sends evidence (an SNP_REPORT or TD Quote, plus a vTPM quote) directly to MAA. MAA validates the evidence against the customer-authored policy and returns a signed JWT. The attester then presents that JWT to the relying party. Azure Key Vault authorizes Secure Key Release against the MAA-issued claim set, not against raw SNP evidence. The relying party never sees the SNP_REPORT and never calls MAA on the attester's behalf, which is the design signature of Passport rather than Background-Check [1262], [186].

> **Walkthrough. From protected bytes to released keys.**
>
> Rail 1 is local and architectural. The CPU decrypts private cache lines only for the guest, rejects illegal RMP or PAMT mappings, encrypts register state on the exit paths that require it, and forces deliberate sharing through C-bit or shared-bit pages. Rail 2 is remote and procedural. The guest asks the hardware for an SNP_REPORT or TD Quote containing a nonce from the relying party; OpenHCL supplies a vTPM quote over Windows boot measurements; MAA verifies the hardware signature, the vTPM chain, the PCR or RTMR values, the TEE type, and the customer policy; MAA signs a JWT; Key Vault releases a wrapped key only if that JWT satisfies the key's release policy. Lose rail 1 and the operator can read memory. Lose rail 2 and the operator may not read memory, but the relying party has no cryptographic reason to release a key to this particular VM [1262], [1261], [186], [1283].
>
> **Key idea.**
>
> A Confidential VM is not a memory-encryption product. It is a contract: confidentiality with integrity, plus an evidence-bearing attestation chain that a relying party can verify before it releases a secret. Anyone who sells you "confidential" infrastructure without rail 2 is selling you half the product.

If this is the contract, how does Azure actually build a usable Windows-guest CVM on top of it? What lives where, and who signs what?

## Azure state of the art: From silicon to MAA

July 20, 2022. Microsoft Azure announces general availability of the DCasv5 and ECasv5 confidential VM SKUs on AMD third-generation EPYC silicon. The Register's coverage captures the framing: "Microsoft is expanding its Azure confidential computing portfolio with virtual machines that use the encryption and memory protection features of AMD's third-gen Epyc processors.... Customers using them can also use the free Microsoft Azure Attestation (MAA) service to remotely verify the operating environment and integrity of the software binaries running on it" [1284]. That is the moment a confidential VM stops being a research paper and starts being a product the customer can pay for by the hour.

The Azure product is a composition, not a single feature toggle. The hardware rail comes from SEV-SNP or TDX. The compatibility rail comes from OpenHCL, because a lift-and-shift Windows Server guest still expects Hyper-V-style synthetic devices, a TPM, disk unlock, network, clock, diagnostics, and interrupt delivery. The measurement rail comes from the vTPM and the underlying hardware quote. The verifier rail comes from MAA policy v1.2. The relying-party rail comes from Key Vault or Managed HSM Secure Key Release. If any rail is missing, the product degrades; see **The contract: a cloud-shaped TEE** above for the full two-rail model [1261], [186], [1283], [1259].

This section walks the Azure stack bottom-up. The walk is a boot-and-release trace: provision a SKU, enter a CPU TEE, run OpenHCL inside the boundary, expose a vTPM, collect SNP or TDX evidence plus PCRs, evaluate a policy, and release a key. That is the concrete path from silicon to MAA.

## The Azure CVM SKU family

As of the 2026-05-20 Microsoft Learn confidential-computing products page, the Azure CVM SKU map has two AMD SEV-SNP generations in view: "DCasv5 and ECasv5 enable rehosting of existing workloads" and "DCasv6 and ECasv6 confidential VMs based on fourth-generation AMD EPYC processors are currently in gated preview" [1258]. The v5 family is the third-generation EPYC Milan line; Lenovo Press corroborates that "SEV-SNP is supported on AMD EPYC processors starting with the AMD EPYC 7003 series processors": i.e., Milan: with the third-generation 7003 series being the first SEV-SNP silicon [1285].

On Intel TDX, the same 2026-05-20 products page names "DCesv6" and "ECesv6" as the current Azure confidential VM families for rehosting workloads on Intel TDX [1258]. The underlying Intel lineage is Sapphire Rapids and later TDX-capable Xeon silicon; SecurityWeek's launch coverage remains useful historical context for the 4th Gen Xeon TDX introduction, but the Azure SKU availability claim should be read from Microsoft Learn [1286], [1258].

GPU CVMs anchor on the same CPU-side TEEs and add a GPU TEE. The Learn page describes the NCCadsH100v5 SKU: "NCCadsH100v5 confidential VMs come with a GPU... use linked CPU and GPU Trusted Execution Environments (TEEs)" [1258]. This is the linked-attestation product for confidential AI: a SEV-SNP host CVM bound by attestation to an NVIDIA H100 in Confidential Compute mode.

> **Sidenote.**
>
> March 30, 2026 brings a pricing change customers should plan for. Microsoft Learn states: "From March 30 2026, encrypted OS disks will incur higher costs" [1261]. Confidential OS-disk encryption remains the recommended configuration where the workload requires it; the change is to the billing line, not to the architecture.

## The paravisor: OpenHCL on OpenVMM

The single most important productisation move Azure made is what Microsoft calls a *paravisor*. The framing from the October 17, 2024 Tech Community announcement is verbatim: "Microsoft developed the first paravisor in the industry, and for years, we have been enhancing the paravisor offered to Azure customers. This effort now culminates in the release of a new, open source paravisor, called OpenHCL" [1259].

> **Definition, Paravisor.**
>
> A thin operating system running inside the trust boundary of a confidential VM, between the host hypervisor and the customer guest. The paravisor exposes the synthetic devices, the vTPM, and the GPA partitioning that a Windows or Linux guest expects from a Hyper-V environment: without trusting any of those services to the host below the trust boundary. The paravisor is itself part of the TCB, but on Azure the paravisor binary is open source [1259], [1287].
>
> **Definition, OpenHCL.**
>
> Microsoft's open-source paravisor, released on October 17, 2024. OpenHCL is built on top of OpenVMM, "a modular, cross-platform Virtual Machine Monitor (VMM), written in Rust" [1287]. On Azure SEV-SNP CVMs OpenHCL runs at VMPL0. On Azure's TDX paravisor path, the comparable design depends on TD Partitioning and an L1 TD role; the exact TDX module prerequisites are platform collateral readers should verify for the SKU generation they deploy [1259], [1288]. It mediates virtual devices, brokers the vTPM, manages GPA partitioning between private and shared pages, and handles diagnostics, all inside the trust boundary.
>
> **Primary-source quotation.**
>
> Microsoft developed the first paravisor in the industry, and for years, we have been enhancing the paravisor offered to Azure customers. This effort now culminates in the release of a new, open source paravisor, called OpenHCL.: Microsoft Tech Community, OpenHCL announcement, October 17, 2024 [1259]

The OpenVMM repository README puts the focus crisply: "OpenVMM is a modular, cross-platform Virtual Machine Monitor (VMM), written in Rust. Although it can function as a traditional VMM, OpenVMM's development is currently focused on its role in the OpenHCL paravisor" [1287]. The OpenVMM Guide lists the virtualization APIs OpenVMM supports, including "MSHV (using VSM / TDX / SEV-SNP)" for paravisor mode, WHP for a Windows host, and KVM for a Linux host [1288]. The use cases listed include Azure Boost, Trusted Launch, and Confidential VMs.

Because OpenHCL is in the TCB, customers do not avoid trusting Microsoft by running it, but they can now *read the source*. That is a categorical change from earlier closed paravisors. The point about a TCB is not its size but its auditability and reviewability.

The canonical Linux-side analog is AMD's **Secure VM Service Module (SVSM)**, which runs at VMPL0 inside an SEV-SNP guest and provides the same kind of in-trust-boundary services (virtual TPM, paravirtualised I/O brokering, attestation surface) that OpenHCL provides on Azure [1289]. SVSM and OpenHCL solve the same problem with different implementations and different signing chains. The Linux community's reference SVSM is the COCONUT-SVSM open-source project [1290]. A reader who needs a confidential-VM paravisor on a non-Azure Linux host should look at SVSM; a reader who needs it on Azure gets OpenHCL.

## The vTPM

Inside the paravisor's protected memory, OpenHCL synthesizes a per-VM virtual TPM. Microsoft Learn is verbatim: "Azure confidential VMs feature a virtual TPM (vTPM) for Azure VMs.... Confidential VMs have their own dedicated vTPM instance, which runs in a secure environment outside the reach of any VM" [1261]. The same Azure Attestation overview says CVM disk-encryption keys are bound to the VM's TPM, that an SNP report with guest-firmware measurements is sent to Azure Attestation on boot, and that the resulting token releases keys used to decrypt vTPM state and unlock the OS disk [186]. Read together, those sources support the operational chain this chapter relies on: `vTPM quote -> EK/AIK identity and boot measurements -> SNP_REPORT or TD Quote -> VCEK or Intel collateral -> MAA token` [1261], [186]. This is the Attestation chapter's EK→AIK→quote shape (Chapter 5) re-rooted: the endorsement identity is no longer burned into a discrete TPM chip but supplied inside the CVM boundary and accepted only through hardware-backed attestation.

The practical consequence is that a Windows Server CVM runs an unmodified Trusted Boot chain inside the guest. PCR-7 still indexes the Secure Boot signer (the measured-boot machinery of Measured Boot, Chapter 4, over the signer database of Secure Boot, Chapter 1). Code Integrity policies still extend their own PCRs (Chapter 8, Code Integrity). BitLocker still seals the Volume Master Key to the TPM (the sealing primitive of The TPM, Chapter 2). None of those operating-system features need to know that the TPM they are talking to is synthesized by OpenHCL inside an SEV-SNP guest, and yet every one of those features is now anchored, transitively, to AMD or Intel silicon rather than to a discrete TPM chip on a motherboard the cloud customer cannot inspect.

## Microsoft Azure Attestation

The verifier in Azure's confidential-computing stack is Microsoft Azure Attestation. The Learn overview describes it: "Microsoft Azure Attestation is a unified solution for remotely verifying the trustworthiness of a platform and integrity of the binaries running inside it. The service supports attestation of the platforms backed by Trusted Platform Modules (TPMs) alongside the ability to attest to the state of Trusted Execution Environments (TEEs) such as Intel Software Guard Extensions (SGX) enclaves, Virtualization-based Security (VBS) enclaves... and Azure confidential VMs" [186].

> **Definition: Microsoft Azure Attestation (MAA).**
>
> Azure's unified verifier service for confidential platforms. MAA accepts evidence (an SNP_REPORT or TD Quote, plus a vTPM quote, plus boot measurements) evaluates it against a customer-defined attestation policy, and returns a signed JWT carrying the issued claims. MAA's role in the RATS architecture is the *verifier*, in *Passport* topology: the attester collects MAA's signed result and presents it to the relying party (Azure Key Vault) [186], [1262].

The SKR loop is documented verbatim. "When a CVM boots up, SNP report containing the guest VM firmware measurements are sent to Azure Attestation. The service validates the measurements and issues an attestation token that is used to release keys from Managed-HSM or Azure Key Vault. These keys are used to decrypt the vTPM state of the guest VM, unlock the OS disk and start the CVM" [186].

> **Definition: Secure Key Release (SKR).**
>
> The Azure Key Vault / Managed HSM operation that releases a wrapped key only after the requesting party presents a valid Microsoft Azure Attestation token that satisfies the key's release policy. SKR is what closes the loop between rail 1 (memory protection) and rail 2 (attestation) at the customer's perimeter: a key never leaves the HSM unless the attesting CVM has been verified [186], [1261].

## MAA policy v1.2

The policy language is the operational surface customers actually interact with. The MAA policy v1.2 grammar has four segments, verbatim from the Microsoft Learn page: "Policy version 1.2 has four segments: version, configurationrules, authorizationrules, issuancerules" [1283]. The critical operational distinction is between the last two. Authorization rules can fail attestation; issuance rules cannot. The docs are explicit: "**authorizationrules**:... These rules can be used to fail attestation. **issuancerules**:... These rules can be used to add to the outgoing claim set and the response token. These rules can't be used to fail attestation" [1283].

> **Authorization rules can fail; issuance rules cannot.**
>
> The most common bug in hand-authored MAA policies is writing a security gate as an issuance rule. If you want a missing SecureBoot value to *reject* the attestation, the predicate must live in `authorizationrules`. Putting it in `issuancerules` only adds a claim to the resulting JWT; the relying party then has to enforce the gate. The verifier will mint the token either way [1283].

The configuration-rule defaults give you sane behavior out of the box: `require_valid_aik_cert` defaults to `true` and `required_pcr_mask` defaults to `0xFFFFFF` (the first twenty-four PCRs must appear in the quote) [1283].

Claim extraction uses JmesPath; the Learn page reproduces a Secure Boot detection rule that flips a `secureBootEnabled` claim from the quote's PCR-7 measurement [1283].

> **Walkthrough: the MAA policy pipeline.**
>
> Evidence enters MAA as a bundle: hardware report, vTPM quote, AIK certificate chain, event log, and any nonce-bound request metadata. `configurationrules` run first and define parser obligations, such as requiring a valid AIK certificate and requiring the expected PCR mask. MAA then constructs a typed claim set. `authorizationrules` are the gate: if the TEE type is wrong, the golden-image measurement is absent, PCR-7 does not match the Secure Boot baseline, the VBS/HVCI claim is false, or the TCB SVN is below the advisory floor, attestation fails and no usable token should reach the relying party. Only after that does `issuancerules` add convenience claims to the outgoing JWT: for example `customer-workload-tier`, `secureBootEnabled`, or a normalized `minimumTcbAccepted` flag. Issuance rules are labels, not locks [1283].

## The two-axis privilege model: VMPL crossed with VTL

A common misconception is that a SEV-SNP CVM makes Virtualization-Based Security inside the guest redundant. The short answer previewed earlier is the full argument here: VMPL (this chapter) and VTL (the Secure Kernel chapter, Chapter 6) are orthogonal axes that exclude different attackers.

The VMPL axis is the *cloud-operator threat model*. VMPL0 (the OpenHCL paravisor) sees pages that the customer's kernel at VMPL2 does not, and the host hypervisor below VMPL0 sees none of the encrypted memory at all. VMPL keeps the operator out.

The VTL axis is the *intra-guest threat model*: the VTL0/VTL1 split owned by the Secure Kernel chapter (Chapter 6). Inside the guest, VTL1 still hosts the Secure Kernel, the Isolated User Mode trustlets such as LSAIso for Credential Guard (Chapter 15), and the HVCI code-integrity verifier (Chapter 8); the trustlet model itself is the subject of VBS Trustlets (Chapter 7). VTL0 hosts the normal Windows kernel and user mode. VTL keeps a kernel-mode attacker out of LSA secrets and credential blobs. Without VTL, the customer's own kernel can read its own LSAIso heap; without VMPL, the hypervisor can read the customer's RAM.

VBS-inside-CVM is therefore not a duplication but a composition: it closes two different attack classes that no single axis covers. This is the chapter's central synthesis: the Secure Kernel chapter (Chapter 6) excluded a hostile *guest kernel*; this chapter excludes a hostile *host*; a hardened Windows CVM needs both axes at once.

> **Walkthrough: two orthogonal isolation failures.**
>
> Imagine two attackers. The first controls the cloud host and tries to read a Windows credential blob from outside the VM. VMPL or TDX partitioning stops that attacker at the trust boundary: host Hyper-V can schedule and deliver virtual devices, but private guest pages are encrypted and integrity-checked, and OpenHCL sits inside the boundary to broker the pieces the guest still needs. The second attacker is already inside the customer guest with kernel code execution in VTL0. SEV-SNP and TDX do not help there, because the customer's own kernel is allowed to read its own ordinary pages. VBS supplies the separate VTL axis: LSAIso, Credential Guard, and HVCI live in VTL1 behind Secure Kernel mediation. A Windows CVM without VBS excludes the operator but not a compromised guest kernel; Windows with VBS but without CVM excludes the guest kernel but not the operator. The product needs both axes [1261], [1259].

## Confidential Containers: three Azure surfaces

Confidential VMs are not the only Azure surface where SEV-SNP attestation can land. There are three more.

**Confidential Containers on Azure Container Instances (ACI), GA.** Microsoft Learn: "Confidential containers on Azure Container Instances are deployed in a container group with a Hyper-V isolated TEE, which includes a memory encryption key generated and managed by an AMD SEV-SNP capable processor" [1291]. ACI Confidential Containers use *confidential computing enforcement* (CCE) policies generated by the `confcom` Azure CLI extension, and they expose SNP attestation reports for the SKR sidecar pattern.

**Confidential Containers on AKS, preview, sunsetting.** As of the 2026-05-22 Learn AKS page, Confidential Containers remain a preview AKS feature, but the older Azure Linux 2.0 / `KataCcIsolation` path has a March 2026 removal timeline and customers should plan migrations to supported Azure Linux and current confidential-container routes [1292].

**Confidential VM AKS worker nodes, GA.** A different model: node-granularity CVM rather than per-pod CVM. Learn: "AKS now supports confidential VM node pools with Azure confidential VMs. These confidential VMs are the generally available DCasv5 and ECasv5 confidential VM-series using 3rd Gen AMD EPYC processors with Secure Encrypted Virtualization-Secure Nested Paging (SEV-SNP) security features" [1293]. This is a lift-and-shift path for existing AKS workloads.

**Confidential Containers on ARO** is the Red Hat OpenShift equivalent, with Kata-isolated per-container SEV-SNP enforcement.

The cross-cloud parallel is the CNCF Confidential Containers project, accepted to CNCF on March 8, 2022 at the Sandbox maturity level [1294]. The project documentation describes it as "an open source project that brings confidential computing to Cloud Native environments, using hardware technology to protect complex workloads" [1295]. Trustee is the canonical attestation broker on the CNCF side. CoCo's substrate is Kata Containers' MicroVM model; the TEE backing is currently Linux-only. The open-source community floor under all of this includes Edgeless's Constellation (historically the canonical confidential-Kubernetes distribution; the upstream repo was archived in 2025-2026 and Edgeless's successor project Contrast [1296] now carries the work forward at the workload-confidential-container layer rather than the whole-cluster layer) [1297], COCONUT-SVSM (the AMD-side reference SVSM running at VMPL0) [1290], and the CoCo Trustee attestation broker.

## NVIDIA H100 CC on NCCadsH100v5

The Azure NCCadsH100v5 SKU pairs an SEV-SNP CVM with an NVIDIA H100 in Confidential Compute mode and links the two attestations together. CPU-side rail 1 is SEV-SNP. GPU-side rail 1 is H100 CC. Rail 2 must compose both: the relying party only releases the workload's key if both attestations check out. Cross-vendor attestation composition is one of the open standards problems the Open Problems section will revisit.

The important operational difference is that the GPU is not automatically covered just because the host CPU is inside SEV-SNP. A confidential AI workload has at least three sensitive objects: the model weights, the prompts or feature tensors, and the intermediate activations in HBM. SEV-SNP protects the CPU VM's DRAM and control plane; H100 CC is the device-side TEE that protects the GPU execution environment and HBM-facing path. A relying party that releases a model key after checking only the CPU quote has proved the VM is a CVM, not that the accelerator consuming the model is in Confidential Compute mode [1258].

A masterclass policy therefore treats CPU and GPU attestation as an AND, not an OR, applying the freshness and evidence rules established in the Attestation chapter (Chapter 5). First, bind a nonce from the relying party into the CPU evidence path so the SNP_REPORT and vTPM quote are fresh. Second, require the MAA result to say the VM is a compliant SEV-SNP CVM, at an accepted measurement and TCB SVN. Third, require the NVIDIA GPU evidence package for the attached H100 to chain to NVIDIA's device-root and report Confidential Compute mode for the GPU that will receive the model. Fourth, bind the two pieces by instance identity, nonce, or a verifier-issued composite token so a good CPU quote from VM A cannot be paired with a good GPU quote from VM B. In current deployments, that usually means carrying NVIDIA GPU evidence from the local verifier or NRAS beside the MAA CVM result and performing the nonce-and-instance binding in relying-party code. Only then should Key Vault or a customer model service release the wrapped model key. This is exactly why RFC 9711's Entity Attestation Token vocabulary matters: the industry needs a standard way to carry multiple attested claim sets into one relying-party decision [170].

> **Walkthrough: the full Azure stack in one boot.**
>
> The silicon layer starts either with AMD-SP firmware enforcing SEV-SNP RMP metadata or with Intel's signed TDX Module enforcing SEAM, Secure EPT, and PAMT. Azure Hyper-V remains the scheduler and host VMM, but it is below the trust boundary for private memory. Inside the boundary, OpenHCL runs at VMPL0 on SEV-SNP or, on Azure TDX hosts that expose the paravisor path, in an L1 TD role enabled by TD Partitioning; it provides synthetic devices, shared-page mediation, diagnostics, and a vTPM. The Windows Server guest runs above it, still split internally into VTL0 and VTL1 for VBS, HVCI, and Credential Guard. During attestation, the guest obtains an SNP_REPORT or TD Quote and a vTPM quote over the measured boot state; MAA evaluates policy v1.2 and returns a signed JWT; Key Vault or Managed HSM uses that JWT for Secure Key Release. A relying-party bug at the final step can still defeat the design: releasing a key on `secureBootEnabled=true` while ignoring `x-ms-attestation-type`, measurement, and TCB SVN is equivalent to trusting a label without checking the hardware evidence behind it [1261], [186], [1283], [1259].

![Figure: The full Azure confidential-VM stack, drawn across the confidentiality boundary. Below the line, AMD-SP / Intel TDX silicon roots the TCB and the Azure Hyper-V host is blind to encrypted RAM; above it, the OpenHCL paravisor and the VTL0/VTL1 Windows Server guest run inside the boundary. The right-hand rail is the attestation evidence flow: an SNP_REPORT or TD Quote plus a vTPM quote to MAA (policy v1.2), a signed JWT, then Key Vault / Managed HSM Secure Key Release. VMPL excludes the host; VTL excludes the guest kernel: the two orthogonal axes.](diagrams/29-confidential-vms-azure-stack.svg)

That is the Azure stack. But Azure is not the only design point: Google and AWS chose different glue, and one of them is on a fundamentally different threat model. How do they compare?

## Competing approaches

Three competitors share the design space with very different choices. Two are near-peers to Azure; one is a fundamentally different model that customers routinely confuse for the same product. Compare them on five axes before comparing prices: the isolation granularity, the operator threat model, the hardware evidence format, the verifier you must trust, and whether the product can run an unmodified Windows or Linux VM. Azure and GCP sit closest together because both expose whole-VM SEV-SNP or TDX and can support lift-and-shift guests. Confidential Containers are a workload-packaging layer over similar silicon, but move the measurement question from "which VM image booted?" to "which container image and policy started?" Nitro Enclaves solve a valuable but different parent-instance isolation problem [1258], [1295], [1298], [1299].

The mistake to avoid is substituting products because they all use the word confidential. A bank trying to hide a signing key from its own web tier can choose Nitro Enclaves. A bank trying to hide a joint AML model from the cloud host needs SEV-SNP or TDX. A platform team trying to keep tenants isolated inside one Kubernetes cluster may need confidential containers. A model owner trying to keep H100 weights secret needs CPU plus GPU linked attestation. The labels converge; the trust boundaries do not.

## Google Cloud Confidential VMs

Google Cloud supports the same two CPU TEEs. The GCP Confidential VM docs are explicit: "AMD Secure Encrypted Virtualization-Secure Nested Paging (SEV-SNP) expands on SEV, adding hardware-based security to help prevent malicious hypervisor-based attacks like data replay and memory remapping. Attestation reports can be requested at any time directly from the AMD Secure Processor" [1299]. And on the Intel side: "Intel Trust Domain Extensions (TDX) creates an isolated trust domain (TD) within a VM, and uses hardware extensions for managing and encrypting memory" [1299].

GCP's machine-type mapping is direct. AMD SEV / SEV-SNP runs on N2D and C3D; Intel TDX runs on C3 Confidential VMs. The Confidential Computing product hub lists "Confidential VMs on the C3 machine series brings hardware-level protection to your AI models and data" and "Confidential VMs on the accelerator-optimized A3 machine series with NVIDIA H100 GPUs" as the parallel GPU-CC product [1300]. There is a Confidential Space product on top for multi-party analytics, plus Confidential GKE Nodes and Confidential Dataflow.

The verifier-of-record is Google's own attestation service, with the guest's vTPM as the default trust root. Intel Trust Authority is supported as a plug-in alternative for TDX evidence.

> **Aside. Why GCP's live migration of confidential VMs is the architectural surprise.**
>
> The GCP Confidential VM docs make a claim Azure does not match, but the boundary is narrower than the surrounding SEV-SNP / TDX discussion: "AMD SEV machines that use the N2D and C3D machine types support live migration" [1299]. Google's supported-configurations page states the same limitation more sharply: live migration is supported only on N2D and C3D machine types running AMD SEV, not on SEV-SNP or TDX instances [1301]. Live migration of a confidential VM is genuinely hard because encrypted state has to move without exposing plaintext to either host. Azure does not currently expose live migration on its confidential VM SKUs. This is the most operationally consequential cross-cloud difference today.

A small correction to a widely repeated framing. It is sometimes said that GCP's confidential offerings are "also SEV-SNP." Per the GCP docs, GCP supports **both** SEV-SNP and TDX [1299]. If you are picking a CVM cloud for a multi-vendor strategy, treat GCP as a near-peer to Azure on the CPU dimension and differentiate on the verifier, the SKU mapping, and the live-migration story instead.

## AWS Nitro Enclaves: a genuinely different model

The most common confusion in this design space is the assumption that AWS Nitro Enclaves is "AWS's confidential VM product." It is not. It is a different model on a different threat boundary.

The Nitro Enclaves user guide is unambiguous about the immediate threat boundary. "AWS Nitro Enclaves is an Amazon EC2 feature that allows you to create isolated execution environments... Enclaves are separate, hardened, and highly-constrained virtual machines. They provide only secure local socket connectivity with their parent instance. They have no persistent storage, interactive access, or external networking" [1298]. The same page continues: "Nitro Enclaves is processor agnostic and it is supported on most Intel, AMD, and AWS Graviton-based Amazon EC2 instance types built on the AWS Nitro System" [1298]. And: "Nitro Enclaves use the same Nitro Hypervisor technology that provides CPU and memory isolation for Amazon EC2 instances" [1298].

Three differences matter.

First, there is no CPU memory cipher. Isolation is enforced by the Nitro hypervisor on a dedicated Nitro System card, not by SEV-SNP or TDX. Memory is in the clear in DRAM, just architecturally walled off by the hypervisor and the hardware root of trust below it.

Second, attestation signs through the Nitro hypervisor and integrates with AWS KMS. There is no VCEK or TDX Quoting Enclave.

Third, the threat model is parent-instance and co-tenant isolation, not cloud-operator hypervisor exclusion. Amazon is in the TCB by design. Azure and GCP CVMs make a narrower but stronger architectural claim (the host hypervisor and host management code should not directly read or silently remap private guest memory) while the provider control plane, verifier service, signed components, availability, and key-release integration remain trust dependencies.

> **AWS Nitro Enclaves is not a whole-VM CVM.**
>
> If your threat model is specifically the parent instance or your own application tier, Nitro Enclaves are a strong fit. If your threat model is the operator's host hypervisor directly reading or remapping guest memory, Nitro Enclaves are the wrong primitive: the Nitro hypervisor enforces the enclave boundary and is software AWS owns and operates. Use Nitro Enclaves for a hardened compartment for key material against your own parent instance and application bugs; use SEV-SNP / TDX on Azure or GCP when you need hardware-backed protection against the operator's host path, while still accounting for provider verifier and control-plane trust [1298].

Nitro Enclaves still has a role: it is excellent at isolating a long-lived signing service from a more loosely audited application instance, and four enclaves per parent EC2 instance is a generous concurrency budget for that pattern.

## Confidential Containers and NVIDIA H100 CC

The Confidential Containers project crosses cloud boundaries. CNCF accepted it in March 2022 [1294]. The project docs describe it as "an open source project that brings confidential computing to Cloud Native environments, using hardware technology to protect complex workloads" [1295]. The Azure surfaces (ACI, AKS, ARO) were covered in Azure State of the Art; the equivalent on AWS is the Kata Containers + Confidential Containers combination on top of bare-metal Nitro hosts, and on GCP it lands on Confidential GKE Nodes.

The NVIDIA H100 CC story is roughly cross-cloud parity. Azure NCCadsH100v5 pairs SEV-SNP with H100 CC; Google's A3 series pairs Intel TDX with H100 CC. Cross-vendor attestation composition is the open standards problem on which the relying party experience still depends. On the silicon side, ARM's Confidential Compute Architecture (CCA, built on the Realm Management Extension, RME) is the ARM-side analog of SEV-SNP/TDX, and Apple's Secure Enclave Processor is a board-scoped TEE with a different form factor; both are adjacent VM-scoped or board-scoped TEE designs but out of scope for the cloud-CVM body of this chapter.

## The head-to-head matrix

| Dimension | Azure CVM | GCP CVM | AWS Nitro Enclaves | Confidential Containers |
|---|---|---|---|---|
| CPU TEE | SEV-SNP, Intel TDX | SEV / SEV-SNP, Intel TDX | None (Nitro hypervisor) | SEV-SNP, TDX (varies by host) |
| Memory cipher | AES (per-VM, per-TD) | AES (per-VM, per-TD) | None (host RAM) | Inherited from host TEE |
| Integrity rail | RMP (AMD), PAMT (Intel) | RMP, PAMT | Nitro hypervisor isolation | Inherited from host TEE |
| Attestation evidence | SNP_REPORT, TD Quote, vTPM quote | SNP_REPORT, TD Quote, vTPM | Nitro attestation document | TEE evidence + container measurement |
| Verifier | Microsoft Azure Attestation | Google attestation, Intel Trust Authority | AWS KMS | Trustee (CNCF) |
| Operator threat model | Host path excluded; provider TCB remains | Host path excluded; provider TCB remains | No (Nitro in TCB) | Host path excluded; provider TCB remains |
| Lift-and-shift Windows | Yes | Yes | No (custom enclave format) | Linux containers only |
| Live migration of CVM | No | Yes (SEV on N2D / C3D) | N/A | No |
| 2024-era CVE exposure | CacheWarp, WeSee, Heckler (SEV-SNP); Heckler (TDX) | Same upstream CVEs | Distinct (Nitro hypervisor) | Inherited from host TEE |
| Granularity | Whole VM, container | Whole VM | Per enclave (up to 4 per host) | Per pod / per container |

> **Walkthrough: choosing by trust-boundary granularity.**
>
> Start with the secret and ask who must be unable to see it. If the threat is a bug in your own monolith and you are willing to keep AWS in the TCB, Nitro Enclaves carve out a small parent-instance-adjacent compartment with no persistent storage or external network. If the threat is the cloud operator or host hypervisor, Azure or GCP CVMs move the whole VM into SEV-SNP or TDX and give you hardware evidence. If the threat is lateral movement between workloads on the same Kubernetes node, confidential containers move the trust boundary down to a pod or MicroVM and require container-image measurement in the evidence. If the secret feeds a GPU model, H100 CC adds a second device TEE and the relying party must require both CPU and GPU evidence before releasing the model key. The products differ most at this granularity line, not in their marketing names [1258], [1295], [1298], [1299], [1300].

If the contract is clear and the products ship, what is still wrong with this picture? Why did the 2024 attack class still extract secrets or break invariants from shipping confidential VMs?

## Where this link breaks: Theoretical limits and the 2024 attack class

May 2, 2024. ETH Zurich's ZISC group publishes the Ahoi family of notification attacks. The lab's announcement is brisk: "Researchers from the SECTRS group have now discovered a new class of attacks, dubbed Ahoi attacks, that exploit vulnerabilities in the notification framework in Intel TDX and AMD SEV-SNP.... the vulnerabilities are tracked under 2 CVEs: CVE-2024-25744, CVE-2024-25743" [1302] (with CVE-2024-25742 covering WeSee). WeSee won the Distinguished Paper Award at IEEE S&P 2024 [1303]. Heckler appeared at USENIX Security 2024 [1304]. CISPA's CacheWarp, also at USENIX Security 2024, is a separate cache-state reset attack [1305].

The 2024-era attack set against shipping confidential VMs has one key observation: none of CacheWarp, WeSee, or Heckler broke the Generation-2 integrity rail itself, and the Ahoi umbrella names the notification-injection family rather than a fourth independent rail break. They exploit seams *around* the rail. That distinction matters because it tells operators what kind of assurance they bought and what kind they did not buy. SEV-SNP and TDX are strong answers to direct host reads and silent page substitution. They are not universal answers to maliciously timed notifications, cache-state rollback, physical fault injection, firmware transparency, or application code that releases secrets on the wrong claim. The break point is therefore not a single fatal flaw; it is the residual attack surface left after the obvious hypervisor read primitive is gone. The Above Ring Zero chapter (Chapter 9) handed this chapter exactly that residual (the host-visibility model and microarchitectural side channels) and the 2024 attack class is where it comes due.

A useful mental model is an onion with named seams. The inner layer is the integrity rail: RMP or PAMT plus encrypted private memory. Around it are the exit and notification mechanisms that let a real VM talk to a real hypervisor: `#VC`, TD exits, interrupts, MMIO, shared pages, GHCB or shared-bit buffers, and paravisor services. Around that are firmware update and attestation roots: AMD-SP, VCEK, TDX Module, Quoting Enclave, OpenHCL, MAA. Around that are relying-party decisions: SKR policies, customer services, and key-release code. The 2024 papers mostly live in the middle rings, not in the RMP/PAMT core.

![Figure: The confidential-VM attack surface as concentric seams around the Generation-2 integrity rail. The RMP / PAMT core holds; each 2024-era attack lands in an outer seam: CacheWarp on the INVD cache-maintenance edge, WeSee on the #VC handler, Heckler on interrupt injection, and One Glitch as a physical fault beneath the AMD-SP, and none crosses into the core.](diagrams/29-confidential-vms-attack-rings.svg)

## Trusted Computing Base accounting

The irreducible silicon-vendor trust root is non-zero by design. On SEV-SNP the customer must trust AMD-SP firmware and the ECDSA-P384 VCEK chain rooted at AMD. On TDX the customer must trust the signed TDX Module binary plus the SGX/DCAP quote-generation and verification path: PCK certificates, Intel CA chain, CRLs, QE identity, and platform TCB collateral [1282]. On Azure the customer additionally trusts Microsoft's signed OpenHCL binary: with the consolation that OpenHCL is open source and reviewable [1259], [1287]. The verifier (MAA, Intel Trust Authority, Google's verifier) is a separate trust component the relying party must extend.

> **Definition, TCB (Trusted Computing Base).**
>
> The set of hardware, firmware, and software components whose correct operation is necessary for a system to enforce its security properties. For an Azure SEV-SNP CVM the TCB is the AMD silicon, the AMD-SP firmware, the OpenHCL paravisor binary, and Microsoft Azure Attestation acting as the verifier. The TCB cannot be empty; the goal is to make it small, auditable, and named [1271], [1259].

The lower bound on TCB is at least one signing root the customer cannot independently rebuild from public artifacts. Reproducible-build transparency over the AMD-SP firmware and the Intel TDX Module is one of the open standards problems on the 2026 frontier. The Google-Intel joint TDX security review from April 2023 is the best public substitute for a reproducible build of the TDX Module today [1306].

## The 2024 attack class, in order of architectural depth

**CacheWarp (USENIX Security 2024; CVE-2023-20592; AMD-SB-3005).** A software fault injection. The mechanism, in NVD's verbatim language: "Improper or unexpected behavior of the INVD instruction in some AMD CPUs may allow an attacker with a malicious hypervisor to affect cache line write-back behavior of the CPU leading to a potential loss of guest virtual machine (VM) memory integrity" [1307]. The project page is plain: "CacheWarp is a new software fault attack on AMD SEV-ES and SEV-SNP. It allows attackers to hijack control flow, break into encrypted VMs, and perform privilege escalation inside the VM" [1308]. The CacheWarp authors demonstrated full RSA key recovery from Intel IPP, passwordless OpenSSH login, and `sudo`-to-`root` escalation [1305]. The team was Ruiyi Zhang, Lukas Gerlach, Daniel Weber, and Lorenz Hetterich (CISPA); Youheng Lü (independent); Andreas Kogler (Graz); and Michael Schwarz (CISPA). SEV-SNP is affected; the fix is the AMD microcode update tracked by AMD-SB-3005 [1309].

**WeSee (IEEE S&P 2024 Distinguished Paper; CVE-2024-25742).** A malicious `#VC` injection. The hypervisor coerces the guest's `#VC` handler into doing the wrong thing by injecting a `#VC` at a moment the guest does not expect one. The arXiv abstract is verbatim: "We present WeSee attack, where the hypervisor injects malicious #VC into a victim VM's CPU to compromise the security guarantees of AMD SEV-SNP.... WeSee can leak sensitive VM information (kTLS keys for NGINX), corrupt kernel data (firewall rules), and inject arbitrary code (launch a root shell from the kernel space)" [1310]. SEV-SNP only.

**Heckler (USENIX Security 2024; CVE-2024-25743, CVE-2024-25744).** A malicious non-timer interrupt injection. The hypervisor injects `int 0x80` or a signal-mapped exception into the guest at a moment that breaks an invariant. The Ahoi Heckler page captures the scope: "All Intel TDX and AMD SEV-SNP processors are vulnerable to Heckler" [1311]. The arXiv extended version demonstrates "Heckler on OpenSSH and sudo to bypass authentication. On AMD SEV-SNP we break execution integrity of C, Java, and Julia applications that perform statistical and text analysis" [1312]. Mitigations are kernel-side interrupt filtering plus AMD's protected interrupt delivery feature.

**Ahoi Attacks (umbrella).** The family page describes scope: "Ahoi Attacks is a family of attacks on Hardware-based Trusted Execution Environments (TEEs) to break AMD SEV-SNP, Intel TDX and Intel SGX" [1313]. The ZISC news framing names the SECTRS group at ETH Zurich (Shweta Shinde's lab) as the locus [1302].

**One Glitch to Rule Them All (CCS 2021).** The physical-fault lower bound established in Generation 1 and 1.5, included here for completeness. Buhren et al. voltage-glitched the AMD-SP on Zen 1 / 2 / 3 to execute custom payloads and to "reverse-engineer the Versioned Chip Endorsement Key (VCEK) mechanism introduced with SEV Secure Nested Paging (SEV-SNP)" [1277]. With supplemental tooling on the PSPReverse GitHub artifact [1278]. With physical access and the right glitcher, the AMD-SP is breakable.

> **Primary-source quotation.**
>
> SEV cannot adequately protect confidential data in cloud environments from insider attackers, such as rogue administrators, on currently available CPUs.: Buhren, Jacob, Krachenfels, Seifert, *One Glitch to Rule Them All*, 2021 [1277]
>
> **Walkthrough: where the 2024 papers sit around the rail.**
>
> Draw the RMP or PAMT check in the center and then place each attack on a different edge. CacheWarp sits below ordinary software semantics at the cache-maintenance edge: the malicious hypervisor abuses `INVD` behavior to reset selected memory state and violate guest execution integrity without asking the RMP to accept a remap [1307]. WeSee sits at the SEV-SNP `#VC` edge: the hypervisor injects a virtualization exception at a point where the guest handler's assumptions are unsafe [1310]. Heckler sits at the non-timer-interrupt edge shared by SEV-SNP and TDX: the notification is architecturally deliverable, but malicious timing breaks higher-level invariants [1312], [1311]. One Glitch sits beneath all of them at the AMD-SP physical-fault edge [1277]. The common lesson is not "the RMP failed." It is that a VM TEE still has exits, exceptions, interrupts, cache instructions, firmware update state, and physical package assumptions, and each seam needs its own mitigation and policy signal.

## Composition limits and operational corollaries

Can the verifier itself be a CVM? Can SKR survive a verifier compromise? These are open standards questions; the Confidential Computing Consortium is iterating on them and there is no settled answer. What there *is* is operational guidance.

The composition problem has three hard requirements. First is freshness: every evidence object in a composite decision must answer the same relying-party challenge, or an attacker can replay yesterday's good GPU quote beside today's good CPU quote. Second is binding: the verifier must know that the CPU VM, vTPM, GPU, container policy, and key-release request describe the same workload instance rather than individually-good components from different machines. Third is failure semantics: if the GPU quote is missing, if PCR-7 is off baseline, or if TCB SVN is below the advisory floor, the decision must fail in `authorizationrules`, not merely omit an issuance claim. This is where RFC 9334's clean actor model becomes messy product engineering: real relying parties consume a graph of evidence, not a single quote [1262], [1283], [170].

Operationally, push every security invariant as far upstream as possible. Do not release a key from application code because a JWT contains a friendly label; bind the HSM release policy to the verifier identity, attestation type, measurement, Secure Boot or RTMR/PCR state, VBS expectation, and TCB SVN: the same relying-party discipline the Zero Trust (Chapter 26) and Continuous Access Evaluation (Chapter 27) chapters apply to access tokens, here applied to key release. Do not let one policy accept both SEV-SNP and TDX evidence by accident; make the TEE branch explicit. Do not treat OpenHCL's openness as the same thing as a reproduced binary; it improves auditability, but the deployed paravisor is still a signed TCB component [186], [1283], [1259].

> **Pin your attestation policy to the latest TCB SVN.**
>
> CacheWarp-class silicon issues are exactly why TCB-SVN floors matter: policies that accept "any TCB SVN at or above the floor of last year's launch" can grandfather CPUs below a vendor advisory floor. Bind your MAA policy to `tcb_version >= latest_advisory` and update the floor when AMD or Intel publishes a relevant security bulletin. For WeSee and Heckler-style notification injection, TCB hygiene is necessary but not sufficient; pair it with guest-kernel and paravisor mitigations, interrupt/exception hardening, and workload-specific fail-closed policy [1309], [1307], [1310], [1312], [1311].

Confidential VMs do not promise side-channel resistance. They promise that the hypervisor cannot *directly read* memory and that an integrity-broken page cannot be silently substituted. The current equilibrium against the 2024 attack class is patch-after-disclosure, guest/paravisor hardening, and attestation-policy hygiene. That equilibrium is itself an architectural statement.

> **Key idea.**
>
> The 2024 attacks do not break the SEV-SNP or TDX integrity rail. They exploit seams *around* the rail: the INVD instruction, the `#VC` handler, the interrupt-injection path, and the physical AMD-SP. The core RMP/PAMT rail is mature. The residuals are the work.

The core integrity rail is mature; the residuals are open. What is the 2026 research frontier actually working on?

## Open Problems

Six open problems shape the 2026 confidential-VM research frontier.

**OP1. Nested CVMs.** Intel TDX Module 1.5 ships TD Partitioning, where an L1 TD can host L2 TDs of its own [1314]. AMD's analog is the VMPL0 / VMPL2 layout that Azure OpenHCL already exploits. The portable cross-vendor formulation (nested-CVM evidence that composes both vendors' attestation reports into a single relying-party-checkable artifact) is not yet standardized. Customers who want a verifier-inside-a-CVM design must build the composition themselves.

**OP2. Cross-vendor attestation composition for CPU+GPU CVMs.** Azure NCCadsH100v5 and GCP A3 already compose AMD or Intel CPU attestation with NVIDIA H100 GPU attestation in production. The relying party today consumes two separate evidence packages and runs two separate policy evaluations. The RATS working group's RFC 9711 (The Entity Attestation Token, EAT) [170] is the canonical wire-format vocabulary (a JWT- or CWT-encoded attested claims set) that a Passport-topology verifier such as Microsoft Azure Attestation produces, and is the path to a single composed evidence package, but the cross-vendor standards work is unsettled.

**OP3. Transparency and reproducible builds of the AMD-SP firmware and the Intel TDX Module.** Both are signed binaries customers trust but do not build. Google's April 2023 joint security review of TDX, authored by Erdem Aktas, Cfir Cohen, Josh Eads (Google Cloud Security), James Forshaw, and Felix Wilhelm (Google Project Zero), enumerated specific vulnerabilities including "Non-Persistent SEAM Loader, Exit Path Interrupt Hijacking, Unsafe Performance Monitoring VMCS Configuration" [1306]. That review is the closest thing to public auditability the TDX Module has today. A reproducible build with binary transparency log (rekor-style) would close the residual auditability gap that even open-source OpenHCL leaves on the table for the silicon vendor's firmware.

**OP4. Post-quantum attestation signatures.** SNP_REPORT signs with ECDSA-P384. TD Quotes are Intel-signed with RSA / ECDSA. The NIST FIPS 204 (ML-DSA) and FIPS 205 (SLH-DSA) standards are final, but vendor-side migration of the CVM signing roots has not been announced for either AMD or Intel. The deployment-feasible path is dual-signing: the SNP_REPORT or TD Quote carries both an ECDSA signature and an ML-DSA signature, the verifier accepts either, and the relying party gates on whichever signing root it trusts most. The transition is non-trivial because the VCEK derivation itself uses a classical KDF chain rooted in classical entropy.

**OP5. Side-channel-resistant CVMs at deployment scale.** The CacheWarp, WeSee, Heckler, and Ahoi family is the *active* frontier. The current operational equilibrium is policy-pinning to the latest relevant TCB SVN, microcode-update discipline, and guest/paravisor notification hardening. There is no production CVM architecture that promises constant-time execution across the integrity rail or that closes the cache-side and notification-injection seams at the silicon layer. The 2026 frontier is what *architectural* mitigations look like, not what microcode patches and kernel workarounds catch up to.

**OP6. Confidential container portability after AKS KataCcIsolation sunset (March 2026).** The Azure CoCo surface fragments into ACI per-pod CVM, ARO per-container CVM, AKS Confidential VM node pools at node granularity, and the upstream CoCo project [1292]. Customers picking a confidential-containers strategy today need to plan for one of those four routes; the CoCo project itself is Linux-only as of 2026-05. Windows confidential containers remain out of scope on every shipping cloud.

> **Aside: What this chapter does not cover.**
>
> This chapter does not deep-cover Intel SGX (its enclave model appears here only as the historical "Why enclaves were not enough" background; SGX has no chapter of its own), ARM Confidential Compute Architecture (CCA) or Apple's Secure Enclave Processor (different threat models and form factors), the full text of the TDX Module Architecture Specification (it is 285 pages [1272]; this chapter cites the load-bearing parts), the regulatory and sovereign-cloud framing of CVMs (a separate topic), or the application-level patterns for designing a customer service to be SKR-aware (a separate operations topic).
>
> **Walkthrough: how the six open problems connect.**
>
> Nested CVMs and CPU+GPU attestation composition are the same problem seen at two layers: a relying party receives more than one evidence object and needs a single policy decision with nonce freshness, identity, measurement, and TCB version preserved across the composition. Firmware transparency and post-quantum signatures are the supply-chain half: even a perfect verifier ultimately trusts AMD or Intel signing roots, so customers need auditable module builds today and signature agility before classical roots become technical debt. Side-channel-resistant CVMs and confidential-container portability are the deployment half: the research frontier must close notification and cache seams while giving operators a portable way to express the same workload policy after AKS `KataCcIsolation` sunsets. The frontier is therefore not one missing feature; it is evidence composition, supply-chain transparency, cryptographic migration, and operational portability moving together [1314], [1292], [1306], [170].

If you are deploying today, what should you do this quarter? The next section is a practical walk-through that ties the architecture to a runnable workflow.

## Verify it yourself (documented): the CVM attestation chain

This chapter presents no private lab captures; it stays 🔵 documented-only. The reproducibility proof is a capture plan a reader can run in their own non-production tenant and then compare to the documented invariants. Save four artifacts: `skus.txt`, `deviceguard.json`, `maa-payload.json`, and `policy.txt`. The proof is complete only when those artifacts agree on the same story: supported CVM SKU, VBS running inside the guest, MAA identifying a compliant SEV-SNP or TDX VM, and a policy that fails in `authorizationrules` when measurement, PCR/RTMR, VBS, or TCB SVN is wrong [1261], [186], [1283].

> 🔵 **DOCUMENTED**: Azure Confidential VM SKU evidence.

```bash
az vm list-skus --location eastus --resource-type virtualMachines \
--query "[?contains(name, 'DCasv5') || contains(name, 'DCesv6')].[name, tier]" \
--output table
```

Expected shape: AMD SEV-SNP SKUs such as `DCasv5` / `ECasv5` and Intel TDX SKUs such as `DCesv6` / `ECesv6` appear where the region supports them [1258].

> 🔵 **DOCUMENTED**: in-guest VBS evidence inside a Windows CVM.

```powershell
Get-CimInstance -Namespace Root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard |
ConvertTo-Json -Depth 4
```

Expected shape:

```json
{
"VirtualizationBasedSecurityStatus": 2,
"SecurityServicesConfigured": [1, 2],
"SecurityServicesRunning": [1, 2]
}
```

The invariant is `VirtualizationBasedSecurityStatus == 2` plus the services your policy enabled. This proves VTL1 is still present inside the outer CVM boundary [1261].

> 🔵 **DOCUMENTED**: MAA JWT claim walk.

After requesting attestation from the regional MAA endpoint, decode the JWT payload locally and inspect at least these fields:

```json
{
"iss": "https://REGION.attest.azure.net/",
"x-ms-attestation-type": "sevsnpvm",
"x-ms-compliance-status": "azure-compliant-cvm",
"x-ms-isolation-tee": { "tee": "sevsnpvm" },
"x-ms-runtime": { "secureBootEnabled": true, "vbsEnabled": true },
"nonce": "RELYING_PARTY_NONCE"
}
```

Then verify the JWT signature against the regional MAA signing certificate. Base64URL decoding is not verification; the relying party must trust the verifier identity, nonce freshness, TEE type, compliance status, runtime claims, and policy hash [186], [1283].

> 🔵 **DOCUMENTED**: MAA policy surface.

```bash
az attestation policy show \
--name PROVIDER_NAME \
--resource-group RESOURCE_GROUP \
--attestation-type SevSnpVm
```

Expected shape:

```text
version: 1.2
configurationrules: require_valid_aik_cert=true; required_pcr_mask=0xFFFFFF
authorizationrules: tee == sevsnpvm-or-tdxvm; measurement in golden set; PCR7/RTMR baseline accepted; VBS/HVCI expected; TCB SVN >= advisory floor
issuancerules: emit customer-workload-tier; emit normalized secureBootEnabled; emit acceptedTcbFloor
```

The gates belong in `authorizationrules`; `issuancerules` only add claims to a token that has already passed [1283].

## What it means for you: VBS-inside-CVM end to end

Six steps move you from a credit-card swipe to a Windows Server CVM that runs an attested workload with HSM-backed key release. Treat the list as a checklist; each step is a place where the architecture from the previous sections becomes operational.

**Step 1. Provision the CVM.** Pick a supported SEV-SNP SKU (for example DCasv5, or DCasv6 where available) or a TDX SKU (DCesv6 / ECesv6 as listed on the 2026-05-20 products page), a supported Windows Server image (2022 or 2025), and turn on Confidential OS-disk encryption with a customer-managed key in Azure Key Vault or Managed HSM. Bind the key to an MAA-aware release policy. The Learn CVM overview describes the SKU family and the OS-image support [1261], [1258]. Plan for the March 30, 2026 encrypted-OS-disk pricing change [1261].

**Step 2. Confirm VBS inside the CVM.** A common misconception is that turning on SEV-SNP makes Virtualization-Based Security redundant. It does not: VMPL and VTL are orthogonal. From an elevated PowerShell session:

> **Verify your guest is still running VBS inside the CVM.**
>
> `Get-CimInstance -Namespace Root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard` should return `VirtualizationBasedSecurityStatus = 2` (running) and a non-empty `SecurityServicesRunning` array that includes Credential Guard and HVCI. This proves that VTL1 / VTL0 separation is intact inside the SEV-SNP trust boundary: the cloud operator is excluded by VMPL, and the customer's own user mode and ring-0 are excluded from the Secure Kernel by VTL.

**Step 3. Capture an attestation token and walk it by hand.** Use the Azure Attestation client (`Microsoft.Azure.Attestation`) to send the guest's SNP_REPORT and vTPM quote to the regional MAA endpoint. Inspect the returned JWT. The decoded claim set will include `x-ms-isolation-tee` describing the TEE (SEV-SNP or TDX), `x-ms-runtime` describing the guest configuration, the boot measurements, and any custom claims your policy mints. Verify the JWT signature against the region's MAA signing certificate: not against an arbitrary trusted root; this is the verifier-identity hygiene that closes the SKR loop.

> **Quick JWT sanity check.**
>
> A valid MAA JWT will contain `x-ms-attestation-type = sevsnpvm` (or `tdxvm`) and a `x-ms-compliance-status = azure-compliant-cvm` claim. If either is missing or has a different value, the policy did not gate on the TEE and the relying party is about to release a key against unattested evidence.

**Step 4. Author the policy.** Write an MAA policy v1.2 file that preserves the configuration-rule defaults (`require_valid_aik_cert=true` and `required_pcr_mask=0xFFFFFF`) unless you have a documented reason to override them [1283]. Add an authorization-rules block that requires (a) `x-ms-attestation-type == "sevsnpvm"`, (b) the SNP_REPORT measurement matches a known reference value for the customer's golden image, (c) the vTPM PCR-7 matches a known Secure Boot signer baseline, (d) the VBS-enabled claim is `true`, and (e) the TCB SVN is at or above the floor for the latest microcode advisory. Add an issuance-rules block that mints a `customer-workload-tier` claim from the accepted TCB band, and set the grammar version to `1.2`. Bind your HSM key's release policy to require the issuance-rule claim plus the authorization-rule pass.

A complete policy review should read like this, even though your exact claim names and numeric TCB floors will follow the schema emitted by your MAA provider and TEE type:

```text
version=1.2;

authorizationrules {
  // SEV-SNP path: every condition must match before MAA can permit.
  [type=="x-ms-attestation-type", value=="sevsnpvm"] &&
  [type=="x-ms-sevsnpvm-launch-measurement", value=="GOLDEN_SNP_MEASUREMENT"] &&
  [type=="secureBootEnabled", value==true] &&
  [type=="vbsEnabled", value==true] &&
  [type=="x-ms-sevsnpvm-tcb-svn", value>=42]
    => permit();

  // TDX path: separate rule because the claim names and measurements differ.
  [type=="x-ms-attestation-type", value=="tdxvm"] &&
  [type=="x-ms-tdx-mrtd", value=="GOLDEN_MRTD"] &&
  [type=="x-ms-tdx-rtmr0", value=="GOLDEN_RTMR0"] &&
  [type=="x-ms-tdx-rtmr1", value=="GOLDEN_RTMR1"] &&
  [type=="secureBootEnabled", value==true] &&
  [type=="vbsEnabled", value==true] &&
  [type=="x-ms-tdx-tcb-svn", value>=42]
    => permit();
};

issuancerules {
  => issue(type="customer-workload-tier", value="prod-cvm-approved");
  => issue(type="minimumTcbAccepted", value="2024-advisory-floor-or-newer");
};
```

The point of the example is placement and semantics: TEE type, measurement, Secure Boot/VBS state, and TCB SVN are authorization gates. Friendly labels such as `customer-workload-tier` are issuance claims. If you reverse those, MAA can mint a token for evidence your relying party meant to reject [1283].

> **Test your MAA policy against synthetic evidence before deploying.**
>
> Use `az attestation policy set` to upload the policy to a non-production attestation provider and replay captured evidence through `attestationProvider` REST endpoints. Focus the replay on the authorization predicates named above; the documented proof section below is only a capture checklist. Pre-production failures here are cheap; failures after SKR binding are expensive [1283].

**Step 5. Repeat on a TDX SKU.** Provision a supported TDX CVM such as DCesv6 / ECesv6 where available. The attestation evidence shape changes: TDX evidence carries `MRTD` plus `RTMR0-3` instead of a single SNP measurement, and the claims JSON shape differs. The claim rules in your policy must branch on the TEE type to handle both TEEs from one policy file, or split into two policy files keyed by attestation provider region and TEE type [293], [1258], [1283].

**Step 6. Plan TCB SVN and guest-mitigation hygiene.** Treat the TCB SVN floor in your policy as a moving target, not a one-time configuration. Subscribe to the AMD security bulletins and the Intel TDX security advisories. When CacheWarp's microcode shipped via AMD-SB-3005 [1309], the appropriate operational response was to raise the policy's TCB SVN floor to the new microcode level, not to leave the floor at the launch baseline. For WeSee / Heckler-style notification injection, also track guest-kernel, paravisor, and workload mitigations; a high TCB SVN alone does not prove the interrupt or `#VC` handling path is safe. This combined patch-and-policy discipline is the single most important operational habit a CVM customer can adopt.

> **Don't pin a CVM SKU to a permissive TCB SVN floor.**
>
> A policy that accepts the launch-baseline TCB SVN forever is a policy that grandfathers in every known CVE the silicon vendor has shipped a microcode patch for. For silicon-fixed issues such as CacheWarp, the 2024 attack class makes this a load-bearing operational discipline, not a footnote; for notification-injection issues, it must be paired with the guest and paravisor mitigations above [1307], [1309], [1310], [1312].

You can build it today.

## Closing

Imagine drawing the architecture from memory. Start at the bottom with AMD silicon plus the AMD-SP firmware, or Intel silicon plus the SEAM Range Register and the signed TDX Module. Above that, the Azure Hyper-V host: below the trust boundary, blind to encrypted RAM. Above that, the OpenHCL paravisor at VMPL0 or the L1 TD seat, mediating synthetic devices and the vTPM. Above that, the Windows Server guest at VMPL2 or the L2 TD, still running VBS, HVCI, and Credential Guard inside. Then evidence flows up: SNP_REPORT or TD Quote plus vTPM quote into Microsoft Azure Attestation, which evaluates policy v1.2 against the evidence and emits a signed JWT, which Azure Key Vault checks before releasing the wrapped OS-disk key. If you can write the MAA policy that says exactly what you mean by "this VM is one of mine," you can build with it.

> **Bequeaths: what the cloud terminus hands the finale.** This chapter closes Part IV and the silicon-to-cloud arc the book has assembled link by link. It hands up one guarantee the earlier links could not: even the party that owns the hardware (the cloud operator's hypervisor) cannot read or silently remap a confidential guest's memory, and a relying party can gate a secret on hardware-rooted evidence of that guest's identity. That is VBS for the cloud, against the host: the Secure Kernel chapter (Chapter 6) excluded a hostile guest *kernel*; this one excludes a hostile *host*. What it does NOT provide is just as load-bearing. It does not promise side-channel resistance (the 2024 attack class lives in the seams), it does not protect a guest whose own kernel is compromised (that is still the in-guest VTL axis owned by Chapter 6 and Credential Guard, Chapter 15), and it does nothing for a relying party that releases a key on a friendly label instead of the evidence. The finale takes it from here. When the Chain Snaps: Storm-0558 (Chapter 29) is the case study in what happens when one trust root *above* all of this (a cloud signing key) breaks, and every guarantee downstream of it inherits the failure. Confidential VMs prove the operator can be excluded from a guest's memory; Storm-0558 proves that excluding the operator from memory is not the same as trusting every key the operator signs.
