# KRBTGT

::: trust-ledger

- **Inherits:** The ticket-granting single-sign-on fabric. The Key Distribution Center hands back a Ticket-Granting Ticket at logon that the client replays for service tickets without resending the password, and every later decision reduces to one signature check (Chapter 17, Kerberos); and the extraction primitive that lands the domain's signing key, DCSync's `DRSGetNCChanges` replication call off a writeable DC (Chapter 14, Mimikatz and the Credential-Theft Decade).
- **Promise:** Within one Active Directory domain, a TGT is valid if and only if it decrypts and its PAC signatures verify under the long-term key of the RID-502 `krbtgt` account. A single shared secret every writeable DC holds. Serviced boundary: the domain KDC and every Kerberos principal that trusts it.
- **TCB:** The secrecy of the krbtgt long-term key in `ntds.dit` and in `kdcsvc.dll` process memory on every writeable DC; the [MS-KILE] / [MS-PAC] encrypt-and-sign construction; and the replication channel that distributes the key. A writeable DC *must* read the key in cleartext to issue tickets, so the DC is inside this TCB by design.
- **Adversary → Break:** An attacker with replication rights (or DC code execution) extracts the krbtgt key, then forges TGTs from scratch (Golden), edits a real TGT's PAC (Diamond), or splices a genuine KDC-issued PAC into a forged TGT (Sapphire). For post-MS14-068 TGT forgery, the Promise ends the instant the key leaks: every signature the KDC computes, the holder can recompute. Historical KDC validation bugs such as MS14-068 are a separate class; this is gap analysis, not a tutorial.
- **Residual:** The parallel trust roots a krbtgt holder usually also took. Service-account keys (Silver Tickets), AD CS CA keys, the KDS root key, inter-domain trust keys, DSRM passwords, AdminSDHolder / SID-History persistence. Survive krbtgt rotation; the credential-extraction lineage is owned by Chapter 14 (Mimikatz), member-host secret isolation by Chapter 15 (Credential Guard), and the cloud generalization of the single-signing-key failure by Chapter 29 (Storm-0558).
- **Bequeaths:** To Pass-the-Hash to Pass-the-PRT (Chapter 19): the lesson that a bearer credential whose verifier is one stored secret is forgeable the moment that secret leaks, and that rotating the secret evicts the forged artifacts but not the compromise that produced them. Does NOT provide: protection for any non-Kerberos bearer artifact (NT hash, certificate key, PRT), nor recovery of the adjacent trust roots; krbtgt rotation is a key event, not an ownership event.
- **Proof:** 🔵 documented: RFC 4120 / [MS-KILE] / [MS-PAC] for the encrypt-and-sign construction, Microsoft AD Forest Recovery for the two-reset procedure, and reproducible `Get-ADUser krbtgt` / `repadmin` administrative checks. No captured (green-tier) domain-controller transcript is asserted: no krbtgt key material is ever dumped for this book.
:::

> **Evidence labels.** 🔵 means documented/reproducible from public sources or local commands; 🟡 means emulated; 🟢 means captured from this book's lab with hash-stamped artifacts.

> **The Reasoner's question.** Once the one account whose key signs every Kerberos ticket is disclosed, what can still be trusted, and what can rotation actually recover?

---

> **Foundations. What you need before this chapter.**
>
> - **Kerberos realm, KDC, TGT (recap).** A Windows domain is a Kerberos realm with Microsoft extensions; its domain controllers run the Key Distribution Center (KDC) that issues Ticket-Granting Tickets (TGTs) at logon and exchanges them for service tickets. The full AS-REQ/TGS-REQ exchange is the Kerberos chapter's subject (Chapter 17), and the shared vocabulary lives in Foundations; this chapter inherits a single fact from them. A TGT is a bearer credential whose validity reduces to a signature under one domain key.
> - **KRBTGT.** The RID-502 account whose long-term key encrypts and signs TGTs in one Active Directory domain. The account is disabled for interactive logon; its key, not its logon ability, is the trust root.
> - **PAC.** The Privilege Attribute Certificate is the Windows authorization structure inside Kerberos tickets. It carries user and group SIDs and signatures that bind those claims to the KDC.
> - **DCSync.** A replication-API primitive that can extract account secrets, including krbtgt key material, from a writeable DC when the caller has replication rights.
> - **Golden, Diamond, and Sapphire tickets.** These are treated here strictly as defensive gap analysis. They name historically documented ways an attacker who already holds the krbtgt key can make forged TGTs look increasingly normal.
> - **Double rotation.** Because the krbtgt account keeps current and previous key material, invalidating a stolen key requires two resets separated by at least the maximum ticket lifetime and completed replication.

---

> **Chapter thesis.** Active Directory's `krbtgt` account is the one secret in any Windows domain whose disclosure forges valid Ticket-Granting Tickets for every principal. Including ones that do not exist. Twelve years of attacks (Golden, Diamond, Sapphire) and Microsoft's responses (the MS14-068 patch, KrbtgtFullPacSignature, the two-reset rotation procedure) converge on one fact: krbtgt rotation invalidates forged TGTs but does not recover the systemic compromise that produced them. Under the systemic-compromise assumptions of modern incident-response playbooks, confirmed krbtgt disclosure is therefore treated as a forest-recovery or rebuild posture, not merely as a key-rotation event.

## Ninety seconds to domain admin

A classic Golden Ticket operation, with the krbtgt account's AES-256 long-term key in hand, can walk the attacker onto resources in the domain as Administrator without first tripping several controls defenders often expect to help. No Domain Admin password need be reset. No Domain Admin account need be created. No SACL need fire until the forged identity touches a monitored object. No LSASS on any host need be dumped for the ticket-minting step. No signature-based IDS rule is guaranteed to trigger. The attacker holds exactly one cryptographic key (the long-term key of the RID-502 service account named `krbtgt`) and the entire Kerberos trust hierarchy of the domain now accepts whatever they sign [787]. The section title's "ninety seconds" is an illustration of how fast the attack is on the wall clock, not a measured demonstration from a published primary.

In the gap-analysis scenario, earlier in the engagement, the attacker used a DCSync-style replication request against the `krbtgt` object from a member-server foothold and obtained the krbtgt long-term key material [261]. Then they used Golden-Ticket tooling to forge a ticket from scratch. The important point for this chapter is not the operator syntax; it is the trust-chain gap: the forged ticket validates because the attacker holds the same domain key the KDC uses. The extraction tooling itself (Mimikatz and its `lsadump::dcsync` module) is owned by the Mimikatz chapter (Chapter 14), whose Residual routed exactly this problem here: Golden Ticket and krbtgt forgery begin where credential theft ends.

Classic Golden-Ticket tooling performs three steps in one local process: it builds a TGT, computes the PAC signatures under the held krbtgt key, and places the resulting bearer ticket into the client Kerberos cache. Sean Metcalf documented that operator workflow in 2015 [650]. This chapter treats the workflow only as gap analysis: the network sees a later TGS request presenting a ticket that decrypts under the domain key, so the KDC accepts the ticket as if it had issued it.

Count the controls that may not fire while the forged ticket is being minted and first presented. No Domain Admin password reset, because the attacker never used a Domain Admin password. No new privileged account, because the attacker impersonated an existing one (RID 500). No SACL on a sensitive object, until the forged identity touches a SACL-covered resource. No LSASS dump on a writeable DC, because DCSync is a replication API call, not a memory scrape [788]. No signature-based IDS hit on a known-malicious payload, if the malicious work stays in attacker process memory and the wire traffic is, structurally, a TGS-REQ. No MFA prompt or Conditional Access decision for the on-prem Kerberos leg itself, because Kerberos pre-authentication is satisfied by holding a valid TGT and the TGT was minted offline. Downstream resource logs can still record access; the gap is that they see an already-authorized identity, not the key disclosure that made it possible.

This chapter's load-bearing thesis: within the Kerberos trust root of a single domain, the krbtgt key is the unique secret whose disclosure yields valid TGTs for every principal. Including ones that do not exist. The technical recovery (two-reset rotation) is well-documented [789] and does cryptographically invalidate forged tickets. But under a confirmed key-disclosure incident, the operational recovery posture often expands to forest recovery or rebuild for reasons that have nothing to do with the krbtgt key itself.

This produces an apparent contradiction. Microsoft documents a clean two-reset rotation procedure with a ten-hour interval [789]; Mandiant- and SpecterOps-style incident-response playbooks often escalate confirmed krbtgt compromise to forest-recovery or rebuild planning under systemic-compromise assumptions [790]. Both postures can be simultaneously true. The job of the next ten thousand words is to explain why: starting with what krbtgt actually is. Not the key. Not the protocol. The account itself: RID 502, disabled, indelible.

## The account: RID 502, disabled, indelible

Open Active Directory Users and Computers on a fresh Windows Server 2022 domain promoted ten seconds ago. In the `Users` container there is an account called `krbtgt`. It has no password visible to the admin. It is disabled. Try to enable it: the checkbox accepts the click, but the next replication cycle puts the account right back into the disabled state. Try to rename it: the operation appears to succeed, but the `objectSID` does not change. Try to delete it. The operation fails outright. You cannot log in as it; the disabled-for-interactive-logon property is enforced inside the Security Accounts Manager. The account exists exactly because the domain exists; the lifetime of the account and the lifetime of the domain are the same lifetime [791].

Why does Active Directory ship with an account that no admin can use, no attacker can authenticate as interactively, and no operator can remove?

> **Definition: KRBTGT account.** The Kerberos Ticket-Granting Ticket service account that exists, exactly once per Active Directory domain, to hold the long-term cryptographic key the domain controllers use to encrypt and sign every TGT issued in the domain. The account name itself is the Kerberos principal name (`krbtgt/DOMAIN@DOMAIN`) inherited from MIT's 1988 Kerberos v4 design.

**Creation.** The account is created automatically when the first writeable domain controller is promoted in a new domain. The Microsoft Learn default-accounts page lists it alongside `Administrator` and `Guest` among the default accounts in the domain's `Users` container, with the verbatim note that "the KRBTGT account can't be enabled in Active Directory" [791]. It is a built-in **domain** account, not a local SAM account in the ordinary workstation sense. The account's lifecycle is bound to the domain's lifecycle; there is no operator-controllable provisioning of a krbtgt account, and no de-provisioning short of demoting the domain.

**RID 502.** The relative identifier at the tail of the account's SID (`S-1-5-21-<domain>-502`) is fixed by the well-known SID specification [792]. Sean Metcalf's operator primer confirms the RID-502 binding directly: "Each Active Directory domain has an associated KRBTGT account... The SID for the KRBTGT account is `S-1-5-<domain>-502`" [793]. (**Note.** RIDs below 1000 are reserved for built-in security principals: 500 is Administrator, 501 is Guest, 502 is krbtgt; the first RID assigned to a user-created principal is 1000.) Renaming the `sAMAccountName` cannot move the RID. The KDC service derives its key lookups from the principal name, which binds to the RID, not from the friendly name shown in ADUC. Renaming krbtgt as a defensive measure is a fallacy that the next section will sharpen further.

> **Sidenote.** Each Read-Only Domain Controller has its own `krbtgt_<rid>` account whose key signs the RODC-issued tickets for principals whose secrets the RODC is allowed to cache under its password-replication policy. The full-domain krbtgt account is read-only from the RODC's perspective: the design property that lets RODCs participate in Kerberos without holding the full-domain trust root [793].

**Container.** `CN=Users,DC=<domain>`. The standard Users container, not a Tier-0 OU or a Protected Users group. The account is privileged by virtue of its RID, not by virtue of its containership. Moving it into a different container does not change its semantic role to the KDC.

**Disabled for interactive logon.** Documented verbatim on the Microsoft Learn default-accounts page: "The KRBTGT account can't be enabled in Active Directory" [791]. The account is reserved for the KDC service. There is no interactive logon surface attached, no LSA logon-rights grant, no Kerberos pre-authentication path that produces a TGT *for* the krbtgt account itself. The account exists to provide a key, not to authenticate.

**Indelible and unrenamable.** Also from the same Microsoft Learn page: "This account can't be deleted, and the account name can't be changed" [791]. ADUC will show a renamed display, but the underlying object identity (the RID, the principal name) is fixed by the directory schema and by `LsaSrv` enforcement on the writeable DCs.

**Password.** System-generated, unknown to operators by design. Microsoft's forest-recovery guidance is precise: ADUC asks the operator to type a new password, but "the password that you specify isn't significant because the system generates a strong password automatically independent of the password that you specify" [789]. The reset is still a real password-write and key-derivation event: it advances the current/previous key slots, updates `pwdLastSet`, and replicates like any other domain secret. What operators do not control is the resulting secret value; rotation is the supported primitive they have over it.

**Password history equals 2.** Documented verbatim on the AD Forest Recovery page: "The password history value for the krbtgt account is 2, meaning it includes the two most recent passwords" [789]. This is the mechanical foundation for the two-reset procedure this chapter later dissects. The KDC keeps both a *current* and a *previous* key in the krbtgt account; in-flight TGT validation tries both during the brief window after a rotation; one reset retires only the older of the two; a second reset, separated by at least the maximum ticket lifetime, evicts the key the attacker held.

**Where the key lives.** The KDC service (`kdcsvc.dll`) on every writeable DC reads the krbtgt long-term key from `ntds.dit` at startup and holds it in process memory for ticket signing and validation. Credential Guard's VBS trustlet, LSAISO (the subject of the Credential Guard chapter, Chapter 15), does not isolate this read on writeable DCs by design: a DC *must* read the key to issue tickets [87] (see also the aside below on why Credential Guard skips the DC). This is the structural asymmetry that makes the krbtgt key reachable to any attacker who can compromise a writeable DC (or invoke its replication API remotely), even on a system where Credential Guard is otherwise enforced everywhere else.

We know what the account is now: a non-interactive, indelible, RID-502 service principal with a system-generated, two-slot password history. But the account is just the container. The rest of this chapter cares about the *long-term cryptographic key* it holds.

## The key: What RFC 4120 and [MS-KILE] specify

Hand a network capture of a Kerberos AS-REP to a Wireshark dissector. The dissector shows the TGT as a sequence of ASN.1 fields. One field is named `enc-part` and its content is opaque. The dissector knows the format of what is *inside* that opaque blob (an `EncTicketPart`) but it cannot show the field values because the blob is encrypted [741]. Encrypted under what? Under one key: the long-term key of the principal named `krbtgt/CONTOSO.LOCAL@CONTOSO.LOCAL`.

The Microsoft specification puts it as plainly as is possible to put it. [MS-KILE] specifies that the KDC encrypts each ticket with the long-term key of the ticket's server principal (RFC 4120 §5.3); for a TGT, that server principal is `krbtgt/CONTOSO.LOCAL@CONTOSO.LOCAL`, so every TGT is encrypted under the krbtgt long-term key [794]. That sentence, more than any other in the Microsoft Open Specifications corpus, is the cryptographic foundation of Active Directory authentication. Every TGT issued by every writeable DC in the domain is encrypted under one key. There is no per-account key, no per-DC key, no rolling subkey. One key, one trust scope.

> **Definition: Ticket-Granting Ticket (TGT).** The credential the Kerberos Key Distribution Center issues at logon, encrypted under the KDC's own service key (in Windows, the krbtgt account's long-term key), that the client subsequently presents to request service tickets without re-authenticating with a password. RFC 4120 §5.3 defines its fields; [MS-KILE] specifies the Windows wire profile [741][794].
>
> **Definition: Key Distribution Center (KDC).** The Kerberos service that issues TGTs (the Authentication Service) and exchanges TGTs for service tickets (the Ticket-Granting Service). In Active Directory the KDC runs as `kdcsvc.dll` on every writeable domain controller; it holds the krbtgt long-term key in process memory for the lifetime of the service [741].

### Inside the encrypted blob

RFC 4120 §5.3 specifies the fields of the `EncTicketPart`: a session key the KDC generates for this TGT, the client's name, the cross-domain transit path, the timestamps (`authtime`, `starttime`, `endtime`, `renew-till`), the optional client-address list, and a final field of `authorization-data` that Windows uses to carry the Privilege Attribute Certificate [741].

> **Definition: Privilege Attribute Certificate (PAC).** The Windows-specific data structure embedded inside the `authorization-data` field of every Kerberos ticket. The PAC carries the user's SID, the SIDs of every group the user belongs to, account restrictions, profile path, logon server, and a small set of cryptographic signatures the KDC computes to bind the structure to the ticket. Defined in [MS-PAC] [743].

The PAC is where the load-bearing security claim of Windows Kerberos lives. RFC 4120 itself does not care about groups; it cares about whether the client can prove identity to a server. The PAC carries the *authorization* layer Windows needs on top of authentication: which security principal the ticket represents, which groups confer which permissions, which restrictions apply [743]. The first thing a Windows file server does when it receives a service ticket is decode the PAC, read the SIDs, and run the access-check algorithm.

### The three signatures inside every PAC

The PAC is integrity-protected by a small set of signatures the KDC computes when it issues the ticket. As of the [MS-PAC] revision 26.0 dated June 10, 2024 [743], a TGT-resident PAC carries three of them:

1. **The PAC server signature.** A keyed HMAC computed under the *service* key. For a TGT the service is `krbtgt/DOMAIN`, so the server signature is computed under the krbtgt long-term key. For a service ticket the server signature is computed under the service account's long-term key (the file server's machine-account key, for example) [743].

2. **The PAC KDC signature.** A keyed HMAC computed under the krbtgt long-term key, signing the bytes of the server signature. This is the pre-2022 anchor of PAC integrity: even if a service holding only its own key could verify the server signature, only the KDC (or anyone holding the krbtgt key) could compute the matching KDC signature. The "pre-2022" framing tracks the deployment of KB5020805's Full PAC Signature, documented in the KrbtgtFullPacSignature discussion [795].

3. **The Full PAC Signature.** Added by Microsoft's response to CVE-2022-37967, deployed via KB5020805 starting November 8, 2022 and enforced by default since July 11, 2023 [795][755]. Computed by the KDC over the *entire* PAC (including the older two signatures) and stored alongside them. Also computed under the krbtgt long-term key.

**PAC-signature walkthrough.** Read the TGT-resident PAC as a three-step integrity chain, not as three independent authorities:

1. The KDC builds the PAC contents: user SID, group SIDs, account restrictions, logon metadata, and policy fields.
2. Because the ticket being issued is a TGT, the "service" named in the ticket is `krbtgt/DOMAIN`. The server-signature key is therefore the krbtgt long-term key, not an application server key.
3. The KDC then computes the KDC signature under the same krbtgt long-term key, binding the server signature to the domain KDC authority.
4. On patched domains, the KDC also computes the Full PAC Signature over the whole PAC buffer, including the older signatures, again under the krbtgt long-term key.
5. The `EncTicketPart` containing that PAC is encrypted under the krbtgt key and sent as the TGT. Later, when any DC receives that TGT in a TGS-REQ, validation is a local cryptographic check: decrypt under krbtgt, verify the PAC signatures, and issue a service ticket if the checks pass.

![Figure: A TGT's three PAC signatures (the PAC server signature, the PAC KDC signature, and the Full PAC Signature added by CVE-2022-37967/KB5020805) all terminate at a single node, the krbtgt long-term key. Adding the third signature enlarged the signed surface but did not relocate the trust anchor: an attacker who holds that key recomputes all three in one step.](diagrams/23-krbtgt-pac-convergence.svg)

The Full PAC Signature adds bytes to the signed surface and closes unsigned-PAC rewriting classes, but the arrows still converge on one secret. A defender who asks "which signature did the attacker fail to compute?" gets a useful question only when the attacker lacks the krbtgt key. Once the attacker has that key, all three checks become reproducible outputs of the same secret.

This is the architectural fact the rest of this chapter will refer back to. The addition of the Full PAC Signature did not relocate the trust to a different key. All three PAC signatures on a TGT terminate at the krbtgt long-term key. An attacker who holds the krbtgt key computes all three correctly in the same step. This is the precise technical observation that motivates the attack cascade and the rotation analysis.

### The enctype matrix

The krbtgt account does not hold a single key; it holds a set of keys, one per Kerberos encryption type advertised in `msDS-SupportedEncryptionTypes` on the account object. The enctype numbers are assigned in RFC 3961/3962/4757 and the IANA Kerberos registry; common Windows values are AES-256-CTS-HMAC-SHA1-96 (enctype 18), AES-128 (enctype 17), and the legacy RC4-HMAC (enctype 23) [741]. AES-256 has been the recommended default for newly-provisioned krbtgt accounts since the Windows Server 2008 R2 / Windows Server 2012 functional levels, though early Windows Server 2008 deployments often required a krbtgt password reset to materialize the AES keys. The post-2016 AES-SHA2 family (enctypes 19 and 20, RFC 8009) is defined by IETF but not documented as deployed in mainline Windows production in the current [MS-KILE] public documentation cited here [794].

> **Definition: Kerberos enctype.** A numeric identifier for the cryptographic algorithm and key length used to encrypt a Kerberos message. RFC 4120 §5.2.9 carries the `etype` field; the numbers themselves are assigned in RFC 3961/3962/4757 and the IANA Kerberos registry. Common Windows values are 17 (AES-128), 18 (AES-256), and 23 (the legacy RC4-HMAC). Each principal's long-term key is derived per enctype, so the krbtgt account stores multiple key derivations side by side [741].

Each derivation is stored in both *current* and *previous* slots; rotating the krbtgt password rederives the entire set for the new password and shifts the previous derivations into the previous slot.

### FAST armoring sits next to, not above, the krbtgt key

RFC 6113 / [MS-KILE] Flexible Authentication Secure Tunneling adds a second key layer for the client-facing pre-authentication exchange, armoring the AS-REQ under a separate channel key derived from a TGT the client already holds. FAST hardens pre-authentication against offline brute-force. It does not change the fact that the TGT's `enc-part` is encrypted under the krbtgt key on its way back to the client [794]. No Kerberos extension shipped through 2026 moves the TGT's trust anchor anywhere other than the krbtgt long-term key.

> Within a Kerberos domain, every TGT reduces to the same key, and that key has a name: krbtgt.

That sentence is the load-bearing claim the rest of this chapter rests on. The next section explains how a 1988 academic design decision became the cryptographic foundation of every Windows domain alive today.

## Origins: 1988 Athena, RFC 4120, [MS-KILE]

Open the bibliography of RFC 4120 and find an entry tagged `[Ste88]`: "Steiner, J., Neuman, C., and J. Schiller, 'Kerberos: An Authentication Service for Open Network Systems,' USENIX Conference Proceedings, February 1988" [741]. The principal name `krbtgt` is in that paper. It has been carried forward unchanged through RFC 1510 (1993) [748], through Active Directory's February 2000 release, through RFC 4120 (2005) [741], through the first [MS-KILE] revision (2007), and into the current [MS-KILE] public documentation cited here [794]. Thirty-eight years.

What did the 1988 design decision look like, and what has changed about its security properties since?

### MIT Project Athena, 1983-1991

Project Athena began at MIT in May 1983 and formally ended on June 30, 1991, after IBM and DEC helped fund and equip a campus-scale distributed-computing environment [796][797]. The authentication problem Athena needed to solve was the one every multi-user network has needed to solve since: how do you let thousands of workstations talk to thousands of services without broadcasting cleartext passwords on every connection? Steiner, Neuman, and Schiller presented their answer at the Winter USENIX conference in Dallas in February 1988. Their design introduced the `krbtgt` principal name and the trust property that one key encrypts every TGT in the Kerberos domain [745].

> **Sidenote.** The principal name `krbtgt` predates Active Directory by twelve years. MIT's 1988 USENIX paper used the name, RFC 1510 standardized it in 1993 [748], and Windows 2000 inherited it unchanged. There is no Microsoft-specific Kerberos principal naming convention; the convention is IETF.

The design property that one key encrypts every TGT was not framed in 1988 as a security risk. It was framed as a *simplification*: by giving the TGS one stable identity that issues every TGT, the protocol does not need to negotiate per-session KDC identities or per-server validation paths. The protocol reduces, mathematically, to two questions: did the KDC issue this TGT, and did the TGT permit the subsequent TGS-REQ for this service? Both reduce to "does this signature validate under the krbtgt key?"

### From RFC 1510 to [MS-KILE]

John Kohl and Clifford Neuman published RFC 1510 in September 1993, standardizing Kerberos version 5 [748]. The `krbtgt/DOMAIN@DOMAIN` principal-name convention carried forward unchanged from Athena. RFC 1510 is the document Microsoft engineers read when they chose Kerberos v5 as the Windows 2000 default authentication protocol; the krbtgt account became part of the AD schema in the Windows 2000 release wave (RTM December 15, 1999; worldwide availability February 17, 2000) [798][70]. The Microsoft Learn default-accounts page binds the two specifications to the same account: "KRBTGT is also the security principal name used by the KDC for a Windows Server domain, as specified by RFC 4120" [791].

RFC 4120, published in July 2005 by Neuman, Yu, Hartman, and Raeburn, obsoleted RFC 1510 [741]. The principal name carried forward unchanged again. RFC 4120 section 5.3 defines the wire format of a ticket; section 6.2 defines the principal-name convention. Microsoft Open Specifications then published the first [MS-KILE] revision in March 2007, documenting the Windows wire profile on top of RFC 4120. The current revision: 47.0, dated April 27, 2026: still says the same thing: the krbtgt long-term key encrypts every TGT [794]. The Microsoft overlay on top of the IETF specification is the AD-account-management surface: RID 502 fixed, password system-generated, password-history-of-2, disabled-for-interactive-logon, automatic provisioning at first-DC promotion [791][789].

Every Active Directory domain has a `krbtgt` principal in it, and conventional Kerberos realms inherit the same Ticket-Granting Service naming pattern from the IETF design. The name has not moved in thirty-eight years. Only the AD-specific overlay is what gives this chapter its Windows-specific subject; the protocol substrate is older than the attack surface by twenty-six years.

The principal name and the trust property are nearly forty years old. The exploit chain that targets them is twelve. The interesting question is what happened in the twelve years that turned an academic design decision into the most consequential single key in enterprise computing. That story has a beginning at Black Hat USA on August 7, 2014.

## The attack cascade, 2014 to 2024

Six generations of attack span ten years, but they do not all belong to the same class. MS14-068 was a historical KDC/PAC-validation bug: an authenticated user could obtain elevated Kerberos authorization without first stealing the krbtgt key. Golden, Diamond, and Sapphire are the post-fix forgery line: absent a KDC validation bug, they require the krbtgt key and get progressively better at hiding the forgery inside genuine-looking wire traffic. By 2022, the forged artifact and the legitimate TGT can be wire-indistinguishable. Here is how that arc unfolded.

![Figure: Six generations of Kerberos-ticket attack on an upper rail (Golden Ticket and MS14-068 in 2014, the Silver Ticket branch to service-account keys in 2015, then Diamond and Sapphire in 2022) over a lower Microsoft-response rail carrying the MS14-068 patch and the staged KB5020805 Full PAC Signature. MS14-068 sits apart as a KDC validation failure; the post-fix Golden/Diamond/Sapphire rail still requires the krbtgt key.](diagrams/23-krbtgt-attack-cascade.svg)

### Academic baseline before November 2014

Two assumptions held for fourteen years between Windows 2000 RTM and Black Hat USA 2014. First, the PAC's two signatures (the Server Signature and the KDC Signature) were treated as adequate; [MS-PAC] specified keyed PAC signatures, while MS14-068 later showed that Windows KDC signature-verification behavior did not enforce the intended authority boundary [743][799][800]. Second, the long-term krbtgt key was held only on writeable DCs and was considered unreachable to remote attackers because no remote primitive existed to extract it. Both assumptions failed within months of each other. The MS14-068 disclosure broke the first; the productionised DCSync primitive in Mimikatz broke the second.

### MS14-068 and CVE-2014-6324

On November 18, 2014, Microsoft published security bulletin MS14-068, "Vulnerability in Kerberos Could Allow Elevation of Privilege (3011780)" [799]. The disclosure: the KDC validated PACs using a checksum algorithm that did not actually depend on the krbtgt key. Any authenticated domain user could obtain a legitimate TGT, then submit a TGS-REQ carrying forged PAC authorization data that asserted Domain Admin group membership, and the vulnerable KDC would accept the forged checksum instead of enforcing the krbtgt-keyed PAC signature. The NVD entry for CVE-2014-6324 records that the bug "allows remote authenticated domain users to obtain domain administrator privileges via a forged signature in a ticket, as exploited in the wild in November 2014, aka 'Kerberos Checksum Vulnerability'" [800]. CVSS 9.0. Critical for every supported Windows Server SKU. Exploited in the wild within hours of the bulletin.

> **Sidenote.** Discovery credit for MS14-068 appears across Metasploit module authorship, AttackerKB, and several practitioner write-ups as Tom Maddock. The MSRC bulletin verbatim says only "privately reported" and does not name the reporter publicly [799]. The Maddock attribution is folk knowledge; the MSRC primary does not confirm it.

Microsoft describes the patch as correcting Kerberos signature-verification behavior [799]. The practical result was to restore PAC integrity to dependence on the keyed construction [MS-PAC] specifies. It also made the defensive dependency explicit: after MS14-068, absent another validation bug, an attacker who wanted arbitrary TGT authority had to hold the krbtgt key itself. From November 18, 2014 onward, an attacker who held that key did not just hold a useful credential; the attacker held the credential the KDC could not check above.

> **Key idea.** MS14-068 was not a Golden Ticket variant; it was a KDC validation bug. The patch was correct because it restored PAC integrity to the keyed authority boundary [799]. After that repair, the post-fix forgery problem narrowed: Golden, Diamond, and Sapphire require the krbtgt key, and the krbtgt key became the single secret worth attacking directly for arbitrary TGT forgery.

### Golden Ticket

Skip Duckwall and Benjamin Delpy presented "Abusing Microsoft Kerberos: Sorry you guys don't get it" at Black Hat USA on August 7, 2014 [801]. The technique they demonstrated is what Sean Metcalf later popularised as the Golden Ticket: with the krbtgt key in hand, an attacker forges a TGT from scratch for any principal SID with any group memberships [650]. The KDC validates the TGT by decrypting `enc-part` with the krbtgt key. There is no upstream authority to check, because krbtgt *is* the authority. MITRE T1558.001 codifies the technique [787]; Benjamin Delpy's Mimikatz tooling operationalised it [261].

**Flow in prose.** In a Golden Ticket gap analysis, the attacker who already holds the krbtgt key constructs the TGT locally, signs and encrypts it under that key, and inserts it into a Kerberos cache. The KDC is not asked to issue the TGT; it sees only a later TGS-REQ whose presented TGT decrypts and verifies under the domain key.

**Golden Ticket sequence, rendered without offensive syntax:**

```text
1. Attacker already holds the domain krbtgt key material.
2. Local process chooses the claimed client SID, group SIDs, timestamps, and PAC contents.
3. Local process computes the PAC server, KDC, and Full PAC signatures under krbtgt.
4. Local process encrypts the TGT EncTicketPart under krbtgt and places the ticket in a cache.
5. Client presents that TGT in a later TGS-REQ.
6. DC decrypts and verifies the TGT with krbtgt, then issues a service ticket.
7. Target service sees a normal service ticket produced by the DC and makes its access decision.
```

The teaching point of the sequence is not how to operate a tool. It is where the trust check occurs: the first domain-controller contact may be the TGS-REQ, not TGT issuance. If the forged TGT is cryptographically consistent with the krbtgt key, the KDC has no issuance log above that key to consult.

The Golden Ticket works because of the single-key trust property the 1988 design chose. There is nothing in the protocol that asks "is this TGT in the KDC's issuance log?" The TGT is self-verifying. If it decrypts and its signatures validate under the key, it is, by definition, a TGT.

Why, then, does Golden Ticket sometimes get caught? Because the default Mimikatz invocation leaves four observable artifacts that Microsoft Defender for Identity ships dedicated alerts for, under the umbrella of the Suspected-Golden-Ticket alert family [802][803]. Mimikatz historically defaulted to RC4-HMAC encryption (enctype 23), which is anomalous on a modern AD where AES is standard. Mimikatz historically defaulted to a ten-year ticket lifetime, against the AD `MaxTicketAge` default of ten hours. The attacker frequently asserts groups the user does not actually hold, which produces a "forged authorization data" anomaly. And the attacker sometimes forges a ticket for an account that does not exist in the directory at all, which produces a "nonexistent account" anomaly. Microsoft's live MDI alerts page enumerates six External IDs in the family: 2009 (encryption downgrade), 2013 (forged authorization data), 2022 (time anomaly), 2027 (nonexistent account), 2032 (ticket anomaly), and 2040 (ticket anomaly using RBCD) [802].

The structural observation: every alert in this family detects *symptoms of forging from scratch*. None of them detects the primitive of *holding the krbtgt key*. That distinction is what makes Diamond and Sapphire interesting.

### Silver Ticket as the parallel path

Silver Tickets deserve more than a footnote because they define the boundary of the krbtgt problem. A Silver Ticket is a forged *service ticket* (TGS), not a forged TGT. The attacker does not need the krbtgt key and does not ask the KDC to issue anything. They need the long-term key of the target service account: a machine-account key for CIFS on a file server, an HTTP service-account key for a web application, an MSSQL service-account key for SQL Server, or any SPN-bearing principal whose key the service will use to decrypt incoming AP-REQs. MITRE catalogs that sibling technique as T1558.002 [804].

The trust root is therefore different. Golden, Diamond, and Sapphire abuse the domain's TGT issuer. Silver abuses one service's local verifier. When a file server accepts a Kerberos AP-REQ, it decrypts the service ticket with its own key. If the attacker forged a ticket that decrypts under that key and carries a PAC whose signatures the service path accepts, the service can grant access without the KDC ever seeing the forged artifact. That is why a Silver Ticket can be quiet on domain-controller telemetry: there may be no TGS-REQ corresponding to the service ticket that later appears at the server.

**Silver Ticket sequence, at the verifier boundary:**

```text
1. Attacker already holds one SPN-bearing account key, not the krbtgt key.
2. Local process builds a service ticket whose sname targets that SPN.
3. The ticket is encrypted under the service account or machine account key.
4. The client presents the ticket directly to the target service in an AP-REQ.
5. The service decrypts with its own key and evaluates the PAC/access token path it normally uses.
6. The KDC may never see the forged ticket, because no TGS-REQ was needed for this artefact.
```

That last line is the detection constraint. A Golden-class forgery usually leaves at least a later DC-side TGS-REQ because the forged TGT must be exchanged for a service ticket. A Silver-class forgery can start at the service boundary. The most reliable analytic is therefore correlation, not a single event: a server accepted a Kerberos logon, but the DCs did not issue a matching service ticket for that client, SPN, time window, and encryption type. That correlation is operationally hard in large domains because DC logs are distributed, service clocks skew, ticket caches are reused, and legitimate constrained-delegation or S4U flows can also decouple the service-side event from a simple client-initiated TGS request.

The blast radius is also different. A stolen krbtgt key mints TGTs that can request service tickets anywhere in the domain. A stolen CIFS service key mints tickets only for that CIFS service identity. If the captured account is a broadly reused service account with SPNs on many hosts, the blast radius can still be large; if it is a single machine account, the blast radius is usually that machine's services. This is the practical reason Silver belongs in the chapter: it prevents a common category error. Rotating krbtgt twice invalidates forged TGTs. It does not rotate every service-account key in the domain, and therefore does not by itself evict Silver Ticket persistence.

The exact constraints are crisp. Silver does **not** let the holder of a random user password mint arbitrary domain TGTs. It does **not** cross to unrelated SPNs unless the same account key backs those SPNs. It does **not** survive reset of the affected service or machine account key. It does **not** prove krbtgt compromise when observed. Conversely, krbtgt double rotation does **not** evict it, because the verifying key is not krbtgt. The incident owner has to ask "which long-term key verified this ticket?" before choosing a rotation plan.

The detection model follows the same boundary. Golden-ticket detections look for impossible or suspicious TGT properties: wrong enctype, implausible lifetime, nonexistent account, group claims that do not match the directory, or later TGS use of a suspect TGT [802][803]. Silver-ticket detection often has to compare service-side logon events with KDC-side issuance events: did the server accept a Kerberos logon for which no matching TGS-REQ was observed? Did the ticket target an SPN whose account password age or delegation settings make key theft plausible? Did the PAC claim groups that the directory does not support for that principal? These are useful but service-local questions, not krbtgt questions.

Recovery is likewise separate. After confirmed krbtgt compromise, double-rotate krbtgt. After confirmed Silver Ticket abuse, reset the affected service account or machine account, purge existing tickets where possible, review SPN placement, and remove unnecessary shared service accounts. In a mature incident response, both workstreams may run at once because an operator with DCSync rights can usually extract both krbtgt and service-account secrets. But the cryptographic guarantees are not interchangeable: krbtgt rotation fixes the TGT issuer; service-key rotation fixes the service verifier. Confusing the two leads to false closure.

### Diamond Ticket

In July 2022, Andrew Schwartz (TrustedSec) and Charlie Clark (Semperis) co-published "A Diamond (Ticket) in the Ruff," cross-posted on the TrustedSec and Semperis blogs, documenting a refinement of Golden Ticket that defeats every PAC-content anomaly detection in one stroke [772][771]. The technique: instead of forging the TGT from scratch, the attacker requests a *real* TGT from the KDC, then decrypts its `enc-part` using the held krbtgt key, modifies the PAC contents, re-signs the PAC under the krbtgt key, re-encrypts the `enc-part`, and walks away with a ticket whose every wire property (`sname`, `cname`, `authtime` skew matching the real KDC's clock, plausible `endtime`, AES-256 envelope) looks like a legitimate KDC-issued artifact.

**Flow in prose.** In a Diamond Ticket gap analysis, the attacker first obtains a real KDC-issued TGT for a low-privilege account, decrypts the TGT with the held krbtgt key, edits the PAC, recomputes the PAC signatures, and re-encrypts the ticket. The resulting ticket keeps the KDC-issued envelope properties while changing the authorization claim inside.

Every MDI Suspected-Golden-Ticket detection disappears, by construction. The encryption type is AES-256 because the KDC issued it that way. The lifetime matches the AD policy because the KDC set it that way. The cname matches a real account because the attacker requested the TGT as a real low-privilege account they own. The only thing the attacker changed is the group SIDs inside the PAC, and the PAC signatures revalidate because the attacker recomputed them under the same krbtgt key the KDC would have used.

> **Sidenote.** TrustedSec verbatim: Diamond "would almost certainly require access to the AES256 key" [772]. The KDC issued the real TGT in AES-256 (the modern default), so the attacker needs the matching krbtgt AES key to decrypt and re-encrypt: not just the RC4 NTLM hash that the classic Golden Ticket can use.

The Diamond Ticket disclosure pointed at an architectural problem: with the krbtgt key in hand, every PAC-content anomaly detection is defeated. Microsoft's structural answer was the Full PAC Signature in November 2022. That response is the KrbtgtFullPacSignature rollout.

### Sapphire Ticket

Charlie Bromberg, who publishes under the handle Shutdown (`@_nwodtuhs`) at Synacktiv and maintains The Hacker Recipes wiki, disclosed Sapphire Ticket in October 2022 [805][806]. Where Diamond modifies the PAC, Sapphire *splices* the PAC. The procedure abuses two Kerberos extensions in combination, Service-for-User-to-Self (S4U2self) and User-to-User (U2U), to coerce the KDC into issuing a service ticket whose embedded PAC describes a target user the attacker wishes to impersonate. The attacker then uses that KDC-issued PAC as source authorization data for a freshly constructed TGT and, because they hold the krbtgt key, produces whatever TGT-resident PAC signatures the final artifact must validate with.

> **Definition: S4U2self (Service-for-User-to-Self).** A Kerberos extension that lets a service request a ticket *to itself*, on behalf of another user, without that user presenting credentials. Originally designed for protocol-transition scenarios (a web service accepting forms-based auth and translating it to Kerberos for downstream calls). Defined in [MS-SFU] (Kerberos Protocol Extensions: Service for User and Constrained Delegation Protocol); referenced from [MS-KILE] [807].
>
> **Definition: U2U (User-to-User).** A Kerberos extension defined in RFC 4120 §3.7 that allows a ticket to be encrypted under the recipient's session key rather than its long-term key, enabling two clients to authenticate to each other without either being a KDC-registered service [741].

**Flow in prose.** In a Sapphire Ticket gap analysis, the attacker combines S4U2self and User-to-User to obtain a service ticket containing KDC-issued authorization data for the target user, then uses that PAC material while constructing a new TGT whose final signatures validate under the held krbtgt key. The detection problem changes because the authorization contents are not synthetic; they originate as real KDC output reused in a forged container.

By construction, there is no simple PAC-content anomaly to detect: the authorization claims began as KDC output for the target user. The important defensive statement is not that every PAC buffer can be transplanted blindly between ticket contexts; [MS-PAC] is precise about ticket, extended-KDC, server, and KDC signatures and about when the KDC recomputes them [743]. The safe claim is narrower: because the attacker holds the krbtgt key, they can produce a final TGT-resident PAC/signature set that validates. Detection must move to traffic-flow analysis (specifically, the anomalous S4U2self plus U2U TGS-REQ sequence on the wire) and in the vendor documents surveyed for this chapter I found no clean canonical default-enabled analytic for that signal as of May 2026 [775][808].

> **Sidenote.** The Sapphire Ticket disclosure is widely misattributed to Charlie Clark (Semperis). The primary tooling artifact (the Impacket PR #1411 conversation thread) addresses the author as `@ShutdownRepo`, who is Charlie Bromberg of Synacktiv [809]. The Hacker Recipes wiki and pgj11.com both confirm Bromberg as the author of record [805][773]. The misattribution conflates Sapphire with Clark's separate "AS Requested Service Tickets" technique.

The empirical artifact is the Impacket pull request #1411, in which Bromberg added the `-impersonate` flag to `ticketer.py` to put the tool into "sapphire ticket mode" [809][806]. Palo Alto Unit 42's "Precious Gemstones" survey is the vendor-side state-of-the-art summary [775].

### KrbtgtFullPacSignature

Microsoft's formal response to the post-2014 attack arc shipped as KB5020805 starting November 8, 2022, addressing CVE-2022-37967 [795][755]. The fix adds a new PAC signature (the Full PAC Signature) computed by the KDC over the *entire* PAC including the older two signatures, validated on incoming tickets, and rolled out across five deployment phases:

| Phase | Date | Mode | `KrbtgtFullPacSignature` value |
|---|---|---|---|
| Initial Deployment | November 8, 2022 | Signatures added, validation disabled | 1 (Compatibility) |
| Second Deployment | December 13, 2022 | Audit mode default | 2 (Audit) |
| Third Deployment | June 13, 2023 | Cannot disable signature addition | (value 0 removed) |
| Default Enforcement | July 11, 2023 | Enforcement default | 3 (Enforcement) |
| Removal of Compatibility | October 10, 2023 | Audit removed, Enforcement permanent | (registry key removed) |

KB5020805 documents the final state verbatim: "Windows updates released on or after October 10, 2023 will do the following: Removes support for the registry subkey KrbtgtFullPacSignature. Removes support for Audit mode. All service tickets without the new PAC signatures will be denied authentication" [795].

> **The most common citation error.** The KB number for KrbtgtFullPacSignature is KB5020805, not KB5021131. KB5021131 is the paired but distinct KB for CVE-2022-37966 (encryption-type enforcement). The PAC-signature-specific KB is KB5020805. Secondary sources routinely confuse the two.

Here is the structural fact. The Full PAC Signature is *also* computed under the krbtgt key. So an attacker who holds the krbtgt key still mints fully-validating tickets, including:

- Sapphire Tickets, where the authorization contents originate as KDC-issued PAC data; the attacker still relies on the held krbtgt key to make the final TGT-resident signature set validate in its new container.
- Recomputed Diamond Tickets, in which the attacker computes the Full PAC Signature alongside the older KDC signature in the same step, because both depend on the same key the attacker holds.

KrbtgtFullPacSignature retired one specific class of attack (Diamond Tickets that did not recompute the Full PAC Signature). It did not retire the underlying primitive (TGT forgery from a known krbtgt key). The PAC signature surface (all three signatures terminating at the same key) is exactly why this is so.

> **Key idea.** The Full PAC Signature was Microsoft's structural response to Diamond Ticket. It expanded the signed surface and retired PAC-modifying variants that did not recompute the new signature. It did not retire the primitive: an attacker who holds the krbtgt key can compute the final validating signature set for Golden, recomputed Diamond, or Sapphire-style artifacts.

### Comparing the three forgery variants

| Dimension | Golden | Diamond | Sapphire |
|---|---|---|---|
| Requires krbtgt key? | Yes | Yes (enctype key, usu. AES-256) | Yes (enctype key, usu. AES-256) |
| Calls the KDC? | No (forges from scratch) | Yes (real AS-REQ) | Yes (AS-REQ + S4U2self+U2U) |
| Modifies the PAC? | Builds it from scratch | Yes (group SIDs) | No (genuine PAC) |
| Defeats MDI encryption downgrade alert? | No (defaults RC4) | Yes (real AES) | Yes (real AES) |
| Defeats MDI time-anomaly alert? | No (defaults 10y) | Yes (KDC lifetime) | Yes (KDC lifetime) |
| Defeats MDI forged-auth-data alert? | No | Yes (still triggers if group mismatch detected via other means) | Yes (PAC is genuine) |
| Defeats Full PAC Signature (post-July 2023)? | Yes (computed under held key) | Yes (recomputed) | Yes (final artifact signed under held key) |
| Known wire-residual? | Encryption type, lifetime, groups | Re-encryption-under-held-key timing | S4U2self+U2U conjunction |

Six generations from MS14-068 to KrbtgtFullPacSignature, and the residual primitive is exactly what the 1988 paper described: hold the key, mint the ticket. So what does the detection topology in 2026 actually catch?

## The detection stack in 2026

Detection of krbtgt-class attacks in 2026 is a four-layer stack. Each layer has a specific class of signal it reads, a specific class of attack it catches, and a specific gap that the next layer is supposed to close. Three of the four layers have a known gap above them. The fourth has nothing above it.

![Figure: The 2026 detection stack as four bands resting on the krbtgt long-term key: posture (BloodHound DCSync edge), behavioral (MDI Suspected-Golden-Ticket), and network/SIEM (RC4-downgrade analytics), each annotated with what it catches and the gap it leaves. The top band, the Sapphire S4U2self+U2U residual, is drawn open: no default-enabled analytic sits above it, so it remains the uncovered frontier.](diagrams/23-krbtgt-detection-stack.svg)

### Posture with the BloodHound DCSync edge

The posture layer asks a question with no per-event component: "Who has rights that *could* extract the krbtgt key, regardless of whether they have used those rights?" In Active Directory terms, the answer is "anyone holding `DS-Replication-Get-Changes` plus `DS-Replication-Get-Changes-All` rights on the domain naming context (exercised by replicating from a writable DC), plus anyone who holds privileges that allow them to grant those rights to themselves." BloodHound encodes the answer as a `DCSync` edge in its graph; the canonical community Cypher query is `MATCH (u)-[:DCSync]->(d:Domain) RETURN u, d`. The current shipping release of BloodHound Community Edition is v9.1.0, dated 2026-05-06 per the release notes [808].

> **Definition: DCSync.** A replication primitive Mimikatz first productionised in August 2015 (the credential-extraction lineage is owned by the Mimikatz chapter, Chapter 14). The attacker invokes the `DRSGetNCChanges` API call against a writeable domain controller, masquerading as a peer DC, and the target DC obligingly streams back the requested account secrets including the krbtgt long-term key. MITRE T1003.006 catalogs the technique [788]. Sean Metcalf's adsecurity.org write-up notes "DCSync was written by Benjamin Delpy and Vincent Le Toux" [653].

What this layer detects: any principal whose existing AD permissions create a path to the krbtgt key. What this layer misses: any attacker who *already* has the key. Posture is preventive, not detective. By the time the attacker is presenting a forged TGT, the posture layer has already missed its window.

### Behavioral detection with Microsoft Defender for Identity

Microsoft Defender for Identity ships an alert family covering classic Golden-Ticket-from-Mimikatz behavior. The live MDI classic alerts page enumerates six Suspected-Golden-Ticket External IDs: 2009 (encryption downgrade), 2013 (forged authorization data), 2022 (time anomaly), 2027 (nonexistent account), 2032 (ticket anomaly), and 2040 (ticket anomaly using RBCD) [802]. The Credential access section adds External ID 2006 for "Suspected DCSync attack" on the extraction side [802].

What this layer detects: the Mimikatz Golden Ticket defaults plus the DCSync extraction primitive that produces the krbtgt key in the first place. What this layer misses: Diamond and Sapphire by construction. Diamond removes the PAC-content anomalies because every artifact except the modified group SIDs comes from the real KDC. Sapphire defeats PAC-content anomaly detection entirely by using a PAC the KDC genuinely issued via S4U2self plus U2U.

The MDI credential-access alerts page is the entry point to the family in the modern Microsoft Defender XDR console layout [803].

### Network and SIEM detection with Sentinel and Splunk

Multi-vendor SIEM content packs ship analytic rules covering Kerberos behaviors flagged under MITRE T1558.001. Splunk's research catalog contains the canonical example: "Kerberos Service Ticket Request Using RC4 Encryption" detects TGS-REQ traffic with encryption-type 0x17 (RC4-HMAC), leveraging Windows Event 4769 from the DCs [810]. Microsoft Sentinel ships parallel rules under the Microsoft Defender XDR content connector. The pattern these analytics share is reliance on encryption-type anomalies, group-membership anomalies, or lifetime anomalies that appear in Windows event logs after the fact.

What this layer detects: signature-style indicators of Golden Ticket behavior on the wire and in the DC event log. What this layer misses: the same encryption-downgrade dependency MDI's alert 2009 has. The Splunk analytic verbatim acknowledges its own limit: "This detection may be bypassed if attackers use the AES key instead of the NTLM hash" [810]. Diamond and Sapphire both use the AES-256 key. Both walk through this layer untouched.

> **Sentinel Kerberoasting rules are not krbtgt detections.** Microsoft Sentinel ships rules called "Kerberoasting" that target MITRE T1558.003 (extracting service-account secrets by requesting SPN-bearing service tickets and brute-forcing the resulting RC4-encrypted blobs offline). Those rules target *service accounts* with SPNs registered against them. They are not a krbtgt detection asset. The krbtgt account does not have an SPN that any client can request a TGS for; the relevant Sentinel content for krbtgt-class attacks is the T1558.001 Golden-Ticket and Kerberos-anomaly analytic family.

### The Sapphire residual

What would catch a Sapphire Ticket? The only wire-observable residual of the technique is the conjunction of (a) a TGS-REQ specifying the S4U2self flag, and (b) the same TGT being used to address a User-to-User request to the KDC. No other layer of the stack reads this signal because no other attack has historically produced it as a precondition.

What ships in the cited public material: nothing canonical and default-enabled. SpecterOps and the BloodHound content team have signaled graph-query work on the U2U TGS issuance pattern in 2026 trend reports [808], but I found no shipped default-enabled analytic in those release notes. Palo Alto Unit 42's "Precious Gemstones" survey describes Cortex XDR detection-attempt heuristics but does not publish the rule [775]. The gap is engineering, not theoretical: the signal exists, but the public vendor material surveyed here does not package a canonical reader for it.

> **The Sapphire residual.** In the public vendor material surveyed for this chapter, I found no canonical default-enabled analytic for the S4U2self plus U2U conjunction as of May 2026. Treat that as a date-stamped research gap, not a permanent product claim.
>
> **Aside: What 'no vendor analytic' means in 2026.** This is the date-stamped survey boundary above, not a claim that no private SOC has written its own rule. The public frontier is packaging and validation: a durable analytic for S4U2self plus U2U that defenders can enable by default without drowning in legitimate delegation noise.

### Defensive method matrix

| Method | Catches Golden? | Catches Diamond? | Catches Sapphire? | Layer |
|---|---|---|---|---|
| BloodHound DCSync edge | preventive only | preventive only | preventive only | 1 |
| MDI Suspected-Golden-Ticket (6 alerts) | yes | no | no | 2 |
| MDI Suspected DCSync (ID 2006) | extraction step only | extraction step only | extraction step only | 2 |
| Sentinel / Splunk T1558.001 RC4 rule | yes (if RC4) | no | no | 3 |
| Sentinel Kerberos-anomaly content pack | partial (lifetime/groups) | no | no | 3 |
| Full PAC Signature (post-July 2023) | n/a (already signed correctly) | retires non-recomputing variants | no | n/a (cryptographic enforcement, not detection) |
| S4U2self+U2U conjunction analytic | n/a | n/a | would catch | 4 (not shipped) |

### Adjacent Kerberos-credential techniques that are not krbtgt detections

| Technique | What it targets | krbtgt detection? |
|---|---|---|
| T1558.002 Silver Ticket | service-account long-term keys | no |
| T1558.003 Kerberoasting | SPN-bearing service accounts via offline RC4 crack | no |
| T1558.004 AS-REP Roasting | accounts with pre-auth disabled | no |
| OverPass-the-Hash (T1550.003) | user NTLM hashes via Kerberos PA-DATA | no |

Detection in 2026 is a four-layer stack, and three of the layers leave gaps the next layer is supposed to close. The fourth gap (the Sapphire residual) has no layer above it. When the gaps close enough to confirm a krbtgt compromise, what does recovery actually look like?

## Documented reproducibility you can run on a Domain Controller

This section is deliberately evidence-bounded. The chapter's claims are protocol and directory-architecture claims, and the evidence below is 🔵 **DOCUMENTED** reproducibility evidence: supported commands, expected output shapes, and the exact inference each output permits. It is not a captured transcript from this book's lab VM, not hash-stamped domain-controller output, and not a claim that the author ran these commands in a controlled lab for this edition. That distinction matters. A captured lab transcript would prove one lab's state; these checks show how to verify the invariant on any real domain without relying on offensive tooling.

Read every block in this section as a *reader-run check*. The command is included because it is an administrative inspection path, the output shape is included so the reader knows what kind of result would support the claim, and the following paragraph states the inference. No captured-evidence label appears in this chapter because no sanitized DC transcript or SHA-256-stamped artifact is being asserted.

> 🔵 **DOCUMENTED**: KRBTGT account identity and disabled state ·

reproduce on a domain controller or management host with the Active Directory PowerShell module:

```powershell
Get-ADUser -Identity krbtgt -Properties objectSID,Enabled,PasswordLastSet,msDS-SupportedEncryptionTypes |
Select-Object SamAccountName,Enabled,SID,PasswordLastSet,msDS-SupportedEncryptionTypes
```

expected output pattern:

```text
SamAccountName: krbtgt
Enabled: False
SID: S-1-5-21-<domain-identifier>-502
PasswordLastSet: <timestamp of the last krbtgt rotation>
msDS-SupportedEncryptionTypes: <bitmask or blank/default depending on domain age>
```

The supported observation proves four chapter claims at once. The account name is conventional, the SID ending is the well-known RID 502 binding, the account is disabled for interactive logon, and the password timestamp is the operational marker of the last rotation. The encryption-type field is the bridge to the earlier enctype discussion: the krbtgt account stores derivations for the encryption types the domain permits, and a rotation rederives the set rather than changing only one algorithm's key.

> 🔵 **DOCUMENTED**. The account is not deletable or normally enabled ·

reproduce as a read-only inspection first:

```powershell
Get-ADUser -Identity krbtgt -Properties CannotChangePassword,PasswordNeverExpires,UserAccountControl |
Select-Object SamAccountName,CannotChangePassword,PasswordNeverExpires,UserAccountControl
```

expected interpretation:

```text
The account exists as a built-in domain object. Its interactive state is disabled,
but its password material remains the KDC's TGT-signing material.
```

Do not "test" the indelible-account claim by trying to delete or enable the account in production. The point is architectural, not destructive: AD creates the object when the first domain controller is promoted, binds it to RID 502, and uses its long-term key for the KDC service. The disabled flag prevents ordinary logon; it does not make the key inert.

> 🔵 **DOCUMENTED**: default ticket lifetime that drives the reset interval ·

reproduce:

```powershell
Get-Content (secedit /export /areas SECURITYPOLICY /cfg kerb.cfg | Out-Null; "kerb.cfg") | Select-String 'Max(Ticket|Service|Renew)Age'
```

expected values in a default domain (`MaxTicketAge` in hours, `MaxServiceAge` in minutes, `MaxRenewAge` in days):

```text
MaxTicketAge = 10
MaxServiceAge = 600
MaxRenewAge = 7
```

Microsoft's forest-recovery guidance ties the wait between krbtgt resets to `MaxTicketAge`: the default is ten hours, and a domain that has changed the policy must wait longer than its configured value before the second reset [789]. The reason is not superstition or vendor conservatism. A single reset moves the pre-reset key into the previous-key slot so in-flight TGTs can finish their normal lifetime. If the second reset happens before those tickets expire, legitimate clients may still be presenting tickets signed by the pre-reset key while some DCs have already evicted it. Waiting out `MaxTicketAge` lets normal TGTs age out before the second reset burns the previous slot.

> 🔵 **DOCUMENTED**: replication health precondition for rotation ·

reproduce before either reset and again after each reset:

```cmd
repadmin /replsummary
repadmin /showrepl * /csv
```

expected output pattern before proceeding:

```text
Source DSA largest delta fails/total %% error
... 0 / <n> 0
Destination DSA largest delta fails/total %% error
... 0 / <n> 0
```

A krbtgt reset that does not replicate cleanly is worse than incomplete; it can create inconsistent KDC validation behavior across domain controllers. Imagine DC-A has current key K2 and previous key K1, while DC-B missed the reset and still has current key K1 and previous key K0. A TGT minted or validated on one DC may fail on another, and the operator can misread the resulting authentication failures as attacker activity. This is why reference automation wraps the password reset with replication checks instead of treating the reset command as a standalone recovery step.

> 🔵 **DOCUMENTED**. DCSync exposure is the preventive proof point ·

reproduce the permission review with directory tooling appropriate to the environment:

```powershell
Get-ACL "AD:\DC=<domain>,DC=<tld>" |
Select-Object -ExpandProperty Access |
Where-Object { $_.ObjectType -match '1131f6aa|1131f6ad|89e95b76' }
```

expected interpretation:

```text
Only Domain Controllers and explicitly justified replication principals should hold
DS-Replication-Get-Changes, DS-Replication-Get-Changes-All, or filtered-set rights.
```

This check connects the defensive posture to the attack path without printing secrets. A krbtgt compromise in modern intrusions often means a principal acquired replication rights and used the domain controller replication protocol to retrieve password material. If unauthorized principals can DCSync, the domain has a krbtgt exposure even before any forged ticket is observed. If no unauthorized principals can DCSync, krbtgt theft is not impossible, but the most common remote extraction path is closed.

The proof discipline is therefore: verify the object, verify the policy interval, verify replication health, and verify replication rights. Those four checks do not prove that no attacker ever held the key. They prove the chapter's mechanical claims and give an operator the minimum safe preflight for rotation.

## Recovery: What the two-reset procedure actually does

The Microsoft AD Forest Recovery page states the procedure verbatim:

> "You should perform this operation twice. You must wait 10 hours between password resets. 10 hours are the default Maximum lifetime for user ticket and Maximum lifetime for service ticket policy settings, hence in a case where the Maximum lifetime period changes, the minimum waiting period between resets should be greater than the configured value." (and) "The password history value for the krbtgt account is 2, meaning it includes the two most recent passwords. By resetting the password twice you effectively clear any old passwords from the history, so there's no way another DC replicates with this DC by using an old password." [789]

What exactly do those two resets buy, and what do they not buy?

### The mechanics of two-slot eviction

The krbtgt account, like every other AD account, stores both *current* and *previous* keys. A TGT issued at time $T = 0$ under key $K_0$ continues to validate after a rotation at $T = T_1$ (when $K_1$ becomes current and $K_0$ moves to the previous slot), because the KDC tries both keys during the in-flight validation window. One rotation fills the previous slot with the now-replaced $K_0$; the second rotation, separated by at least `MaxTicketAge` so that all $K_0$-signed TGTs have expired naturally, fills the previous slot with $K_1$ and evicts $K_0$ entirely. After the second rotation completes and replicates, no key in the krbtgt account matches the attacker's extracted $K_0$; forged TGTs from that key fail validation cleanly [789].

> **Definition: MaxTicketAge.** The Kerberos policy value that bounds the lifetime of a Ticket-Granting Ticket from the moment of issuance. The Active Directory default is 10 hours, configured via the Default Domain Policy. The AD Forest Recovery procedure waits at least `MaxTicketAge` between krbtgt resets to ensure no in-flight TGT outlives the period between the two rotations [789].

**Timeline in prose.** At compromise time, `K_0` is current. After the first reset, `K_1` becomes current and `K_0` remains in the previous slot so in-flight tickets keep working; after at least `MaxTicketAge`, the second reset makes `K_2` current and `K_1` previous, evicting `K_0` entirely once replication completes.

```text
Compromise and recovery state:

T0        KDC slots: current=K_0, previous=K_prior
          Exposure: attacker who stole K_0 can mint TGTs.

T1        Reset 1 completes on the first DC:
          current=K_1, previous=K_0
          Exposure: K_0 is no longer used for new legitimate TGTs,
          but K_0-signed forged or cached TGTs can still validate.

T1..T2    Wait at least MaxTicketAge plus operational skew/replication margin:
          legitimate K_0-signed TGTs age out naturally.
          Risk: DCs must converge before the second reset or clients see
          inconsistent validation depending on which DC they hit.

T2        Reset 2 after the wait:
          current=K_2, previous=K_1
          Exposure: K_0 is evicted from the two accepted slots.

T2+rep    After all writeable DCs converge:
          a TGT signed under stolen K_0 should fail everywhere in the domain.
```

The 10-hour wait between resets is not an arbitrary convenience; it is the `MaxTicketAge` safety interval that prevents legitimate still-live TGTs from being rejected during the second reset. If the second reset lands before all $K_0$-signed TGTs have expired naturally, some of those tickets will hit a DC whose previous slot now holds $K_1$ rather than $K_0$, and the KDC will reject them. This is what KB5020805's PAC-signature deployment phases also had to navigate during the November 2022 to October 2023 rollout: signature additions and validation transitions had to bracket the maximum in-flight ticket lifetime [795].

The operational risk window has two independent clocks. The first is ticket lifetime: existing TGTs cannot be assumed gone until `MaxTicketAge` has elapsed from the first reset, plus any configured skew margin that the estate relies on. The second is replication: a reset that has not reached every writeable DC is not a domain state yet. Good runbooks therefore verify replication before reset one, after reset one, before reset two, and after reset two. A premature second reset is not "faster recovery"; it is forced ticket invalidation while legitimate clients may still be carrying tickets the domain deliberately promised to honor.

### `New-KrbtgtKeys.ps1`

Microsoft's reference automation for the procedure is `New-KrbtgtKeys.ps1`, originally distributed via TechNet Gallery and currently hosted in the `microsoftarchive` GitHub organization. The repository banner reads, verbatim: "This repository was archived by the owner on Mar 8, 2024. It is now read-only" [811]. Archived does not mean conceptually obsolete; it means operators should treat the script as a reference implementation whose controls must be reviewed, tested, and wrapped for the current estate.

The important part of the script is not the password-reset cmdlet. A manual operator can reset an account password in one line. The important part is the choreography around that line: identify the krbtgt object by its domain identity rather than by a possibly renamed friendly label, check that domain-controller replication is healthy, reset once, force or wait for replication, verify that every writeable DC has converged, wait longer than `MaxTicketAge`, repeat the reset, and verify convergence again. The automation exists because the failure mode is distributed-state inconsistency, not because `Set-ADAccountPassword` is hard to type.

Inspection of the archived script shows that its safety model is mode-based, not a blind "run the reset" wrapper. Mode 1 is informational and makes no change. Mode 2 creates a temporary canary contact object and watches that harmless object replicate, explicitly to estimate replication behavior without touching krbtgt. Mode 3 resets pre-created test/bogus krbtgt accounts (`krbtgt_TEST` or RODC-specific test accounts) and compares `pwdLastSet` across DCs. Mode 4 is the real production reset. For the writeable-DC krbtgt, the script uses the RWDC holding the PDC Emulator FSMO as the originating writer and checks reachable RWDCs for matching `pwdLastSet`; RODCs are treated separately through their `krbtgt_<rid>` accounts and `msDS-KrbTgtLink` relationship. That design is exactly the safeguard the source guidance implies: measure replication first, test the reset choreography on non-production keys, then reset the production trust root only when the operator accepts the blast radius [811].

Three safeguards are worth carrying into any 2026 fork or internal runbook:

1. **Preflight replication health.** If `repadmin /replsummary` already shows failures, rotation can strand different DCs on different key slots. Fix replication first. The right emergency exception is rare: if the domain is actively burning and an isolated DC cannot be trusted, the IR decision may be to demote or isolate that DC, not to pretend replication is healthy.
2. **Per-DC convergence checks after each reset.** The first reset is not complete when the local DC accepts the password change. It is complete when every writeable DC that can issue or validate TGTs has the same current/previous key state. The second reset has the same requirement, and it is the second convergence point that delivers cryptographic eviction of the pre-compromise key.
3. **Policy-aware waiting.** The script's familiar ten-hour wait is the default-domain-policy case, not a universal constant. Domains that changed `MaxTicketAge` need an interval longer than their configured maximum TGT lifetime. Shortening the wait converts the previous-key compatibility slot from a safety feature into a split-brain risk.

Those safeguards are also the script's real value. The reset action itself is a password-write operation; the script surrounds that write with questions a human under incident pressure is likely to skip: are all DCs reachable, do replication failures already exist, has the first reset actually converged, has the maximum TGT lifetime elapsed, and is the operator about to perform the second reset against the same domain object rather than a renamed display name? The enforced wait is not merely "ten hours because Microsoft said so"; it is `MaxTicketAge` plus the safety margin required for clock skew and replication convergence. In domains with non-default Kerberos policy, the wait must follow the policy, not the blog-post default.

The wait logic is also inspectable. The script attempts to read `MaxTicketAge` and `MaxClockSkew` from the Default Domain Policy GPO and falls back to the documented defaults of 10 hours and 5 minutes if lookup fails. It calculates the expiration time for "N-1" Kerberos tickets from the previous `pwdLastSet` plus `MaxTicketAge` plus clock-skew margin, then warns that resetting before that time is "MAJOR DOMAIN WIDE IMPACT" and requires explicit operator continuation. In plain English: the script does not make the second reset impossible, but it makes the danger visible. If an operator overrides the warning and resets twice too fast, the result is not a cleaner domain; it is premature invalidation of tickets that services and clients may still be legitimately presenting.

The main failure modes map exactly to those safeguards. Running the script from an underprivileged or poorly connected host can produce partial execution. Running it while replication is unhealthy can create authentication failures that look random because they depend on which DC a client reaches. Running the second reset too early can evict keys that legitimate in-flight TGTs still require. Running only one reset leaves the stolen key in the previous slot. Running the resets correctly but skipping the Domain-of-Thrones work leaves parallel persistence untouched.

Failure mode by failure mode:

| Failure | Immediate symptom | Residual exposure |
|---|---|---|
| Replication unhealthy before reset one | DCs disagree about current/previous key state | forged tickets may fail in one site and validate in another, and legitimate clients may see intermittent auth failures |
| Reset one only | rotation appears to have happened | stolen `K_0` remains in the previous slot and can still validate until reset two evicts it |
| Reset two too fast | sudden service failures and ticket validation errors | recovery causes its own outage while old legitimate TGTs are still inside their promised lifetime |
| Reset two before convergence | site-dependent authentication behavior | a lagging DC can remain a validation island for the old key |
| Correct krbtgt rotation but no adjacent-secret work | TGT forgery primitive is gone | service-account keys, AD CS, trust keys, KDS root keys, DSRM, SID History, and AdminSDHolder persistence can still restore attacker control |

The archive status changes the assurance model, not the mechanics. A read-only Microsoft archive is a useful historical reference and checklist, but it is not a maintained product with ongoing compatibility testing. Production teams should review the code, test it in a representative forest, pin their local copy, and make the runbook owner, not the archived repository, the authority for whether preflight, wait, and convergence checks are satisfied [811].

Treat `New-KrbtgtKeys.ps1` as a checklist encoded in PowerShell: useful, historically canonical, and still aligned with Microsoft guidance, but not magic. The mastery point is to understand each guardrail well enough to reproduce it in a change-controlled runbook and to explain why removing it weakens recovery [789][811].

### What two-reset does

The mechanics and simulation above reduce to one membership test: is the stolen key still in the set of keys a fully replicated writeable DC accepts? One reset moves the compromised key into the previous slot; two resets, separated by `MaxTicketAge` and replication convergence, remove it from the accepted set. The narrow Microsoft guarantee is therefore key eviction for this domain, not whole-forest recovery [789].

```text
Before reset:       accepted keys = {K_0, K_prior}  -> stolen K_0 accepted
After reset one:    accepted keys = {K_1, K_0}      -> stolen K_0 still accepted
After wait:         accepted keys = {K_1, K_0}      -> only compatibility remains
After reset two:    accepted keys = {K_2, K_1}      -> stolen K_0 absent
After replication:  all DCs agree on {K_2, K_1}     -> stolen K_0 absent everywhere
```

Read the table as the compact version of the earlier timeline: reset one is containment, reset two is eviction, and the wait keeps compatibility from becoming an outage. The guarantee is true only after full replication. A branch-office DC that missed the second reset can remain a validation island; a restored DC snapshot can reintroduce old key material; an RODC-specific `krbtgt_<rid>` incident has a different reset object and blast radius [793]; and a multi-domain forest has multiple krbtgt accounts. Within those boundaries, two-reset rotation is strong key eviction, not ticket-by-ticket cleanup and not proof that adjacent persistence is gone.

### What two-reset does not do

An attacker who held the krbtgt key may also have installed parallel persistence, and mature IR assumes that possibility until disproved. SpecterOps's "Domain of Thrones Part II" by Nico Shyne and Josh Prager, published November 6, 2023, names the rotation list verbatim: "Machine accounts... User accounts... Service accounts: Per domain KRBTGT account... Trust keys and objects related to trust of all other domains; Group-managed service accounts; Key distribution service root keys" [790]. The same playbook enumerates the persistence vectors an attacker with krbtgt access typically establishes: AdminSDHolder ACL edits, AD CS template alternates spanning the ESC1 through ESC8 abuse classes (canonically cataloged in Schroeder and Christensen's "Certified Pre-Owned," SpecterOps, June 2021) [812], SID History entries, machine-account secret retention, KDS root key exfiltration, trust-key compromise, and DSRM password exfiltration. Two-reset rotates the krbtgt key only; the rest of the trust-root set is untouched [813][790].

> **Key idea.** Two-reset rotation cryptographically invalidates previously-forged TGTs. It does NOT rotate any of the other secrets an attacker who held the krbtgt key may also have reached: AdminSDHolder edits, ADCS templates, SID History, machine-account secrets, KDS root keys, trust keys, DSRM passwords. Under systemic-compromise assumptions, that is why IR playbooks escalate confirmed krbtgt disclosure from key rotation to forest-recovery or rebuild planning.

Two-reset rotation is the cryptographic finish; the operational finish spans the rest of the Domain-of-Thrones surface, and the rotation alone cannot reach it. The single-sentence punchline lands in the closing section.

> **Aside: Microsoft IR vs. Mandiant IR.** Why does Microsoft's AD Forest Recovery page treat krbtgt rotation as a bounded rotation event while Mandiant-style and SpecterOps-style playbooks may escalate confirmed krbtgt disclosure to forest-recovery or rebuild planning? Both postures can be true at once. Microsoft documents the *cryptographic* recovery, which terminates at the krbtgt key. The IR playbooks document the *operational* recovery, which spans additional secret classes whose compromise the krbtgt holder may also have achieved. The cryptographic recovery is necessary and well-bounded; the operational recovery is necessary and not bounded by the same key.

Recovery has two pieces: a fast cryptographic part (two resets, well-documented) and a slow operational part (seven other secret classes, days to weeks). Both are necessary. Neither is sufficient. Even the combined procedure leaves three structural residuals, which the next section names.

## Where this link breaks

The krbtgt link breaks in four different places, and each break belongs to a different response owner. First, there is a **time-window break**: between the first and second reset, the previous-key slot still accepts tickets signed with the old key. Second, there is a **parallel-root break**: AD CS, KDS root keys, service-account keys, trust keys, and DSRM passwords are not children of krbtgt and do not rotate when krbtgt rotates. Third, there is a **topology break**: a multi-domain forest or external trust can carry compromise across boundaries if trust keys, SID filtering, and Selective Authentication are weak. Fourth, there is a **product-design break**: Windows KDCs must have access to krbtgt key material to issue and validate TGTs; there is no supported HSM-backed or threshold-cryptography mode that makes the key non-exportable to a compromised writeable DC.

Concrete failure paths matter because they determine what "done" can honestly mean:

- **Single-reset false closure.** The operator sees `PasswordLastSet` change and declares victory, but the stolen key remains in the previous slot. Existing forged TGTs can continue to validate until the second reset evicts that key.
- **Replication island.** One branch DC misses reset two or is restored from an unsafe snapshot. Most of the domain rejects the old key, but clients routed to that DC can still receive or validate tickets according to stale key state.
- **Service-key residue.** The same replication rights that exposed krbtgt may also have exposed machine-account and service-account keys. Silver Tickets against those services survive krbtgt rotation because they are verified by service keys, not by krbtgt.
- **Certificate residue.** AD CS misconfiguration or CA-key compromise gives the attacker a PKINIT path to valid Kerberos authentication after krbtgt eviction. The forged TGT primitive is gone; the ability to become a privileged principal may not be.
- **Trust residue.** External or inter-domain trust keys can let an attacker move the problem across a boundary whose krbtgt was never rotated. The failure is not cryptographic validation inside the rotated domain; it is the forest/trust graph around it.
- **Directory-control residue.** AdminSDHolder ACL changes, SID History manipulation, privileged group membership changes, or DSRM password compromise can recreate access after the cryptographic reset. The old tickets die, but the path to mint new authority remains.

That taxonomy prevents two bad conclusions. The optimistic mistake is to say "we rotated krbtgt twice, so the domain is clean." The pessimistic mistake is to say "rotation is useless because the attacker may have other persistence." The correct statement is narrower and stronger: double rotation solves the TGT-forgery primitive for the rotated domain after replication converges; it does not solve the surrounding identity-compromise case. The limits below are the remaining gap analysis.

## Theoretical limits and open problems

Even with the full Domain-of-Thrones rotation surface executed correctly, structural residuals remain. They are "theoretical" only in the sense that no product has completely eliminated them; they are operationally real in incident response. Each one asks a different question. Can defenders shrink the unavoidable pre-second-reset window? Can they discover and recover alternate certificate trust roots? Can they prevent one domain's secret from becoming a forest-wide secret through trust topology? Can the platform ever issue TGTs without leaving exportable krbtgt-equivalent material on a writeable DC?

The word "limits" is doing precise work here. These are not excuses for inaction and not claims that recovery is impossible. They are boundaries between the thing the krbtgt procedure can prove and the things it cannot prove. The two-reset procedure can prove key eviction for one domain after convergence. It cannot prove that every valid-looking TGT before the second reset was legitimate, that every alternate identity issuer was clean, that every trust boundary enforced the intended blast radius, or that future Windows KDCs have a non-exportable root-of-trust design. Treating those residuals as explicit open problems keeps the response evidence-based instead of hope-based.

### The pre-second-reset TGT-lifetime window

Any TGT minted from the compromised krbtgt key between the moment of compromise and the moment the second reset replicates remains valid until naturally expired or until step 3 lands. Historically, Golden-Ticket tooling often used long default lifetimes, which makes pre-minted tickets a years-long risk if a careless DC misses the time-anomaly signal. The MDI Suspected-Golden-Ticket family includes a time-anomaly alert (the External ID 2022 sibling) [802] that reads the difference between plausible and implausible ticket lifetimes. `MaxTicketAge` bounds legitimate ticket lifetime and therefore sets the minimum wait between the two resets; it does **not** bound an attacker-forged TGT, which can name any expiry because the attacker signs it. Microsoft's supported procedure waits at least `MaxTicketAge` (the default 10 hours) before the second reset [789]; an emergency faster double-reset still evicts the old key cryptographically once it replicates, but risks rejecting legitimate in-flight TGTs.

The mitigation is procedural: between detection and the start of the rotation, the IR team treats every TGT in the domain as suspect. In practice that means rejecting cached tickets at high-value services, forcing a TGT renewal cycle, and watching the time-anomaly alert closely. The mitigation is not perfect; an attacker who minted tickets with realistic 10-hour lifetimes inside the typical AD policy survives this residual entirely.

### AD CS alternate persistence and the ESC class

An attacker who held the krbtgt key long enough to also touch AD Certificate Services has often installed an ESC-class alternate-identity persistence: a backdoored client-authentication template that lets a low-privileged enrollee supply its own subject (the `ENROLLEE_SUPPLIES_SUBJECT` class, ESC1), a template whose weak ACLs let an attacker modify it into one (ESC4), an HTTP-bound CA endpoint vulnerable to NTLM relay (ESC8). The ESC class taxonomy is cataloged in Schroeder and Christensen's "Certified Pre-Owned" white paper (SpecterOps, June 2021) [812]. The compromised template or endpoint survives krbtgt rotation entirely. The CA private key is its own trust root, parallel to (not subordinate to) the krbtgt key. Domain-of-Thrones Part II names ADCS as a separate rotation workstream that must be addressed alongside the krbtgt reset [790].

The structural fact: a domain with AD CS deployed has at least two cryptographic trust roots (krbtgt long-term key + CA private key) whose compromises are *both* recoverable only through different mechanisms. PKINIT (developed in the Kerberos chapter, Chapter 17), the Kerberos pre-authentication extension that validates certificate-bearing AS-REQs, accepts identities the CA chain attests to. Compromise of the CA chain yields valid Kerberos authentication as any principal, by a different mechanism than holding the krbtgt key, with the same end result.

### Cross-domain trust-key compromise

Within a multi-domain forest, each domain has its own krbtgt account, but the forest does not behave like a set of sealed boxes. Cross-domain Kerberos depends on trust objects and inter-realm trust keys. When a user in Domain A accesses a service in Domain B, the path can involve referral tickets: Domain A's KDC issues a referral toward Domain B, Domain B validates the trust path, and SID filtering or selective-authentication policy determines which authorization claims survive the boundary. That means krbtgt compromise is domain-scoped at the key level but potentially forest-scoped at the consequence level.

The dangerous cases are usually configuration and history failures. A child domain whose administrators are less protected than the forest root can become a launch point if trust filtering is weak. Old migration-era SID History values can smuggle privileged SIDs across boundaries if filtering is disabled or exceptions are too broad. External trusts created for acquisitions or legacy applications can outlive their original justification. Forest trusts without Selective Authentication can let a compromised source domain request access more broadly than the target domain's owners expect. Domain-of-Thrones Part II captures the recovery implication in one line: "Trust keys and objects related to trust of all other domains" are a separate rotation surface [790].

The mitigation has two phases. Before compromise, design domains as security boundaries only when the trust policy supports that claim: SID Filtering enabled where appropriate, Selective Authentication on inbound trusts that cross administrative boundaries, no unreviewed SID History dependencies, and routine inventory of trust objects. After compromise, assume every direct and transitive trust reachable from the compromised domain needs review. That does not always mean every forest domain must immediately rotate krbtgt, but it does mean every trust key, trust direction, allowed-to-authenticate path, and SID-filtering exception becomes evidence in the blast-radius decision. A krbtgt key is per-domain; an AD forest incident is not automatically per-domain.

### The HSM-bound krbtgt aspiration

A theoretically clean solution exists in the literature: split the krbtgt key material such that no single party (including the DC's own KDC service) could read the full key in cleartext. The construction would be a hardware-security-module-bound krbtgt key (the HSM exposes only sign and verify operations on a key it never releases), or a threshold-cryptography scheme (the key is reconstructed across $n$ DCs, $t$ of which must cooperate per ticket-signing operation). Either construction would close the underlying primitive by making the krbtgt key unreadable in cleartext to anyone with code execution on a DC.

No current [MS-KILE] revision cited by Microsoft documents such a mode [794]. Neither construction is on any published Microsoft roadmap as of May 2026. The closest analogs that have shipped (LSAISO/Credential Guard's VBS trustlet for LSASS secrets on workstations and member servers) explicitly omit the writeable-DC case by design, because a writeable DC must read the krbtgt key to issue tickets. The reason is operational as much as architectural: the user-mode KDC service needs the key for every TGT issuance, and a per-ticket hardware or threshold signing round trip would put login-path latency and availability on the domain's critical path.

Even after two-reset and Domain of Thrones, three residuals remain: a window of time, an alternate trust root, and a topology problem. None of them are theoretical. All three are operational realities documented in 2024-2026 incident-response practice. But they raise a different question: how does the krbtgt key compare to the other secrets in an AD trust-root set?

## Where KRBTGT sits in the AD trust-root set

A correction to a framing that appears in many secondary write-ups: the krbtgt long-term key is *one* of a small set of "AD trust roots," not the only one. The framing matters because the rotation playbook lists seven secret classes for a reason: each is a candidate trust root that survives compromise of any other.

**Map in prose.** The AD trust-root set has several roots with different blast radii: the krbtgt key issues domain TGTs, the AD CS CA private key can create PKINIT-backed identities, the KDS root key derives gMSA passwords, inter-domain trust keys bridge domains, and DSRM passwords unlock DC-local authority. KRBTGT is unique for arbitrary TGT forgery inside one domain, but it is not the only root that must be considered after systemic compromise.

**KRBTGT long-term key.** Issues TGTs for all principals in the domain. Unique property within the Kerberos trust root: holding it forges TGTs for arbitrary principals, including ones that do not exist in the directory. Rotation: the two-reset, ten-hour-interval procedure on the AD Forest Recovery page [789].

**AD CS root CA private key.** Issues certificates that PKINIT trusts for Kerberos pre-authentication. Compromise yields Kerberos auth as any principal via PKINIT: a different mechanism with the same end result. Rotation: CA hierarchy rebuild, significantly more expensive than krbtgt rotation. SpecterOps "Certified Pre-Owned" (Schroeder + Christensen, June 2021) is the canonical primary on the ESC-class abuses of this trust root, cross-referenced in Domain of Thrones Part II [812][790].

**KDS root key.** Group Managed Service Account passwords are derived deterministically from a KDS root key plus a per-account `msDS-ManagedPasswordId`. Compromise of the KDS root key reads every gMSA password in the forest. Different blast radius (service accounts only). Rotation: KDS root key rotation followed by gMSA cycling [790].

**Per-domain inter-domain trust keys.** Bridge Kerberos trust between domains in a forest or across explicit external trusts. Compromise yields cross-domain TGT minting. Rotation: per-trust password rotation, with SID Filtering and Selective Authentication audits as the standard hardening procedure.

**DSRM passwords on writeable DCs.** Directory Services Restore Mode is a local-admin equivalent at the DC level; compromise yields a local logon to the DC, which then enables many other paths including direct read of the krbtgt key from `ntds.dit`. Rotation: per-DC DSRM password rotation [790].

### The precise framing

Within the Kerberos trust root of a single domain, the krbtgt key occupies a *unique* position: it is the issuer of every TGT, and forging a TGT requires exactly this key. At the forest-AD-trust-graph level, the krbtgt key is one of a handful of high-cost-to-rotate trust roots, not the only one. The framing matters because it explains why Domain of Thrones Part II lists seven rotation workstreams: each is a candidate path to the same end result (arbitrary identity in the forest) through a different cryptographic mechanism.

Five trust roots, one (krbtgt) with a unique forge-arbitrary-TGTs property, all five surfacing in the rotation list. With the trust-root topology mapped, this chapter's last technical job is the practical playbook: what does the reader actually do tomorrow morning?

## Practical guide: The rotation and detection playbook

Four lanes. Each lane is a concrete action a reader can execute starting tomorrow morning.

> **The four lanes at a glance.** **Preventive hygiene:** Rotate krbtgt twice a year on a calendar schedule and audit who can DCSync. **Detection deployment:** Ship MDI Suspected-Golden-Ticket alerts plus SIEM T1558.001 content. **Confirmed-compromise response:** two-reset rotation followed by the Domain-of-Thrones surface. **What does NOT work:** four traps to avoid.

### Preventive hygiene

Rotate the krbtgt password twice a year on a calendar schedule, regardless of any specific incident. Use `New-KrbtgtKeys.ps1` (or a fork of it) with pre-reset and post-reset replication-health checks [811]. Verify Active Directory replication health between the two rotations; if replication is lagging on any DC, the second reset can outpace the first in some replicas and break in-flight tickets.

Move every Tier-0 account into the Protected Users group. Enable Credential Guard on every workstation and member server. Credential Guard does NOT protect the DC itself by design (DCs must read the krbtgt key unencrypted) but it kills the worker-station memory-scrape that initially gets an attacker into a position to pivot to the DC.

Audit who can invoke DCSync. The BloodHound query `MATCH (u)-[:DCSync]->(d:Domain)` returns every principal whose existing AD permissions can extract the krbtgt key without a DC compromise [808] [788]. Every match should map to a justified administrative role; any unexpected match is a finding.

> **Aside: Why Credential Guard skips the DC.** LSAISO is a Virtualization-Based Security trustlet that isolates long-term secrets from a SYSTEM-privileged kernel on workstations and member servers. On writeable DCs the design omits LSAISO because the KDC service must read the krbtgt key unencrypted to issue tickets. This is precisely the design property a DCSync-capable attacker exploits.
>
> **Calendar-driven rotation.** Two krbtgt rotations per year as preventive hygiene: not a response to a specific incident. Use `New-KrbtgtKeys.ps1` with replication-health checks before, between, and after. The 10-hour wait between rotations is mandatory; do not shorten it [789].

### Detection deployment

Ship the MDI Suspected-Golden-Ticket alert family plus the DCSync alert (External ID 2006) [802][803]. Confirm the Suspected-Golden-Ticket alert family is active for every domain controller MDI is deployed against:

| External ID | Alert family | What to validate |
|---|---|---|
| 2009 | Suspected Golden Ticket | Encryption-type / ticket-shape anomaly coverage for classic Golden Ticket patterns |
| 2013 | Suspected Golden Ticket | PAC or account-claim anomaly coverage |
| 2022 | Suspected Golden Ticket | Time-anomaly coverage for implausible ticket lifetimes |
| 2027 | Suspected Golden Ticket | Additional KDC-issued-ticket anomaly coverage |
| 2032 | Suspected Golden Ticket | Account/PAC inconsistency coverage |
| 2040 | Suspected Golden Ticket | Newer MDI Golden-Ticket heuristic coverage |

Treat the table as a deployment checklist, not a substitute for Microsoft's live alert catalog [802][803]. Configure Microsoft Sentinel content-pack rules covering T1558.001 Golden Ticket and Kerberos-anomaly patterns (not the T1558.003 Kerberoasting rules, which target service-account SPNs and are not a krbtgt detection asset). Configure Splunk T1558.001 detection [810] and tune the encryption-type baseline against legacy systems that legitimately negotiate RC4 (or, better, retire those systems).

Ingest BloodHound for posture-graph visibility. Configure regular collections (the default is weekly) so the DCSync edge list stays current as ACLs change. Cross-reference the DCSync edge inventory against the actual administrative role assignments quarterly.

### Confirmed-compromise response

When MDI or Sentinel surfaces a confirmed krbtgt compromise (DCSync extraction observed against a writeable DC, or a Suspected-Golden-Ticket alert with concrete supporting evidence), the response runs in two parallel tracks. The cryptographic track executes the two-reset rotation: reset the krbtgt password (replicate, verify), wait at least 10 hours, reset again (replicate, verify) [789]. The operational track executes the Domain-of-Thrones Part II rotation surface [790]:

- AD CS template review covering the ESC1 through ESC8 abuse classes [812]; replace or restrict templates with `EnrolleeSuppliesSubject`, broad `Enroll` permissions, or weak EKU restrictions.
- SID History audit (`Get-ADUser -Filter * -Properties SIDHistory`); investigate every account whose SID History contains a Domain Admins or Enterprise Admins SID.
- AdminSDHolder ACL audit; reset Protected Group inherited ACLs and verify the SDProp runs cleanly.
- Machine-account secret rotation, especially for Tier-0 servers.
- KDS root-key rotation followed by gMSA password cycling.
- Trust-key rotation for every inbound and outbound trust.
- DSRM password rotation on every writeable DC.

After both tracks complete, re-baseline detection: the post-incident DC event-log baseline will differ from the pre-incident baseline, and detection thresholds may need re-tuning to suppress the resulting alerts.

> **Pseudo-code only: the minimum `Set-ADAccountPassword` shape for a krbtgt reset.** The reference automation runs against the krbtgt SID specifically, not the friendly name, to avoid any ambiguity with a renamed object. Conceptually, not as a paste-ready production command: `Set-ADAccountPassword -Identity (Get-ADUser -Filter "objectSID -like '*-502'") -Reset -NewPassword (ConvertTo-SecureString (<cryptographically-random-secret>) -AsPlainText -Force)`. The placeholder is deliberate; `New-RandomPassword` is not a standard Active Directory cmdlet. The Microsoft Learn PowerShell reference for `Set-ADAccountPassword` documents the `-Reset` plus `-NewPassword` parameters used here [814]. The `New-KrbtgtKeys.ps1` script wraps this with replication checks and a confirmation prompt [811]. Production runbooks always include a pre-check that `Get-ADReplicationFailure` returns no failures before any reset is issued.

### What does NOT work

> **Four traps to avoid.** **Renaming krbtgt.** The RID 502 binding is what the KDC derives from, not the `sAMAccountName`. The KDC service does not care about the friendly name. **Disabling krbtgt.** The account is already disabled for interactive logon by design [791]. Toggling the field is semantically meaningless to the KDC service, which reads the long-term key directly from the directory. **Single rotation.** Password-history-of-2 means a single rotation only retires the *older* of the two keys, leaving the attacker-extracted key (which was current at compromise) still in the previous slot [789]. The procedure must run twice. **Treating MDI Suspected-Golden-Ticket alerts as sufficient.** Those alerts do not cover Diamond and Sapphire by construction. Sapphire defeats simple PAC-content anomaly detection because the authorization data began as genuine KDC output. Confirmed-compromise response must assume the worst even when MDI is silent.

## What it means for you

The Reasoner's payoff is simple but uncomfortable: **krbtgt rotation answers a cryptographic question, not an ownership question.** After the second reset has replicated, the old key no longer validates TGTs. That is necessary. It is not sufficient evidence that the forest is clean, because the compromise that reached krbtgt usually reached the adjacent trust roots as well.

A practical verification probe has three parts. First, enumerate the `krbtgt` account and record the RID-502 binding and `PasswordLastSet` timestamp. Second, inventory every principal with DCSync-equivalent rights and explain why it has them. Third, compare the incident-response plan against the broader trust-root list: AD CS, KDS root keys, trust keys, DSRM passwords, AdminSDHolder, SID History, machine-account secrets, and privileged service accounts. If the runbook stops at two krbtgt resets, it is a key-rotation runbook, not a systemic-compromise runbook.

Use the detection stack with the same discipline. MDI and SIEM alerts are valuable for classic Golden Ticket symptoms and extraction primitives. They do not prove the absence of Diamond or Sapphire behavior. The absence of an alert is therefore not a clean bill of health; it is only the absence of the specific anomalies those products read.

The single-shared-signing-key failure mode krbtgt embodies is not unique to Kerberos, and seeing it as a *pattern* is the synthesis this book is built to deliver. The on-prem instance is here: one domain key signs every TGT, so disclosure forges any identity. The cloud instance is the finale: Storm-0558 (Chapter 29) shows the same shape at planetary scale, where a single stolen Microsoft consumer signing key minted tokens across tenant boundaries. The finale traces the documented Golden Ticket → Golden SAML → Storm-0558 lineage end to end. Between them, Pass-the-Hash to Pass-the-PRT (Chapter 19) follows the reusable artifact as it migrates from the NT hash to the Kerberos ticket to the cloud Primary Refresh Token. The lesson generalizes: any authentication fabric that reduces validity to *possession of one secret* inherits krbtgt's recovery problem. Eviction of the secret is necessary, and never sufficient.

> **Bequeaths.** To the next link in the credential arc, Pass-the-Hash to Pass-the-PRT (Chapter 19), this chapter hands a sharpened lesson rather than a fix: a bearer credential whose verifier is one stored secret is forgeable the moment that secret leaks, and rotating the secret evicts the forged artifacts but never the systemic compromise that produced them. krbtgt is the domain-scoped instance; Chapter 19 follows the same reusable-artifact problem as it moves from the NT hash to the Kerberos ticket to the cloud Primary Refresh Token. What this chapter does **not** bequeath is any protection for those other artifacts, nor recovery of the adjacent trust roots a krbtgt holder usually also took: AD CS keys, the KDS root key, inter-domain trust keys, DSRM passwords, and service-account keys whose Silver Tickets survive every krbtgt reset. The finale (Storm-0558, Chapter 29) inherits the warning at cloud scale: when one signing key is the trust root, its disclosure is an ownership event, not a key-rotation event.

## One sentence to take away

> Krbtgt rotation invalidates forged TGTs; it does not, by itself, prove recovery from the systemic compromise that produced them.

That is the precise sentence to keep from ten thousand words. The cryptographic question, "is the ticket valid?", terminates at one key. The operational question, "is the domain still ours?", never does. The 1988 design chose to make ticket validation a property of a single shared secret because that choice made the protocol simple and provably correct. The choice remains correct in 2026. What changed is the meaning of the word *compromise*: in 1988 the threat model was a passive eavesdropper on a campus LAN; in 2026 the threat model is a remote API call that streams the secret across a `DRSGetNCChanges` exchange. The key did not move. The attacker's reach did.
