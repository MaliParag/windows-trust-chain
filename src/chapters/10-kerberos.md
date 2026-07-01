# Kerberos

::: trust-ledger

- **Inherits:** "Long-term secrets are off the box". A signed-in user's NTLM hash and Kerberos *long-term key* are unreadable from any VTL0 process, even SYSTEM with `SeDebugPrivilege` (Chapter 15, Credential Guard); the NTLM-death floor. The challenge-response fallback that survived only because Kerberos could not cover every case is being switched off, leaving Kerberos the single load-bearing authentication path (Chapter 16, The Death of NTLM).
- **Promise:** After NTLM, Kerberos establishes *who you are* through a trusted third party: the KDC issues tickets carrying PAC authorization data; the service decrypts its service ticket locally and can verify the service-keyed PAC checksum without a password-equivalent secret crossing the wire. Full PAC/KDC-signature validation is a Windows policy and protocol-extension matter, not a universal offline property of every ordinary service. Serviced boundary: protocol-level ticket-forgery bugs (Bronze Bit, Certifried, un-covered PAC fields) are CVEs Microsoft patches.
- **TCB:** The `krbtgt` long-term key; every service account's long-term key; the PAC signatures (Server, KDC, and (since CVE-2022-37967) Full PAC); the KDC's S4U2Self / S4U2Proxy and delegation checks; the negotiated enctype (AES vs. RC4); and a synchronized clock (the five-minute skew inherited from Denning, Sacco 1981).
- **Adversary → Break:** Whoever holds a long-term symmetric key *is* the principal. They forge every ticket component that key protects, because the AP exchange is designed for local acceptance and no per-request online revocation. Kerberoasting mines the service-ticket ciphertext from a TGS-REP offline; RBCD / S4U abuse documented delegation; the default `MachineAccountQuota = 10` hands an attacker the bootstrap account. The Promise ends at *key possession*, not at *ticket use*.
- **Residual:** Standing ticket forgery from a stolen long-term key (golden, silver, diamond, sapphire) and `krbtgt` rotation → owned by KRBTGT (Chapter 18); current-session ticket replay that Credential Guard leaves in VTL0 `lsass.exe` → Chapter 15; token / Potato escalation → Windows Access Control (Chapter 22) and The SeImpersonate Primitive (Chapter 24); cloud-token theft and hybrid trust graphs → Pass-the-Hash to Pass-the-PRT (Chapter 19), Zero Trust (Chapter 26), and Continuous Access Evaluation (Chapter 27).
- **Bequeaths:** A `krbtgt`-signed, PAC-carrying ticket and locally decryptable service tickets. The trust fabric the KRBTGT chapter (Chapter 18) examines at its root, the single account that signs every TGT in the domain. Does NOT provide: protection against forgery by anyone holding a long-term key, universal offline verification of every PAC signature by every service, PAC freshness or online revocation, ticket isolation inside `lsass.exe`, or any guarantee off the box.
- **Proof:** 🔵 documented: `klist`, KDC Events 4768 / 4769, and directory-state probes (`msDS-SupportedEncryptionTypes`, delegation attributes, `MachineAccountQuota`) at the point of claim; this chapter records no live-VM 🟢 capture.
:::

> **The Reasoner's question.** When Kerberos becomes the primary trust fabric, what trust does it actually establish, and where can that trust still be abused?

---

> **Foundations. What you need before this chapter.**
>
> - **Kerberos domain / realm.** The administrative boundary, written in uppercase (`CONTOSO.COM`), that scopes principals and a Key Distribution Center. In Active Directory, the domain controller hosts the Kerberos KDC.
> - **Principal.** A user, computer, or service identity. A service instance is named by a **Service Principal Name** such as `HTTP/web01.contoso.com` or `cifs/fs01.contoso.com`; AD maps that SPN to the account whose key decrypts the service ticket.
> - **KDC, AS, and TGS.** The Key Distribution Center contains two logical services. The Authentication Service issues Ticket-Granting Tickets; the Ticket-Granting Service turns a TGT into a ticket for a named service.
> - **TGT.** A Ticket-Granting Ticket is encrypted to the `krbtgt` account and opaque to the client. The client holds adjacent session-key material that lets it ask the TGS for more tickets without sending the password again.
> - **Service ticket / TGS.** A ticket encrypted to the service account that owns the requested SPN. The service validates it locally with its own long-term key.
> - **Long-term key vs. session key.** Passwords, machine secrets, `krbtgt`, gMSA, and service-account secrets are long-term keys. TGT and service exchanges mint short-lived session keys so those long-term keys are not reused on the wire.
> - **PAC.** The Microsoft Privilege Attribute Certificate is the authorization payload in Windows Kerberos: SID, group SIDs, logon metadata, and signatures. Kerberos proves identity; the PAC makes that identity useful for ACL decisions.
> - **Enctype.** A Kerberos encryption type. RC4-HMAC is enctype 23. AES-128-CTS-HMAC-SHA1-96 is enctype 17. AES-256-CTS-HMAC-SHA1-96 is enctype 18. AES-SHA2 lives at enctypes 19 and 20.
> - **Delegation.** The designed exception to "the user presents the user's own ticket." Unconstrained delegation forwards broad authority; constrained delegation and Resource-Based Constrained Delegation scope who may obtain downstream tickets on a user's behalf.
> - **Gap analysis posture.** The abuse paths in this chapter are not instructions. They are the residual seams a defender must model when NTLM exits and Kerberos becomes even more load-bearing.

---

## A chain without NTLM

Imagine a defender who has done every NTLM retrofit Microsoft has shipped. NTLM is disabled by default on the workstations. `RestrictNTLMInDomain` is on at the domain controller. SMB signing is enforced. Extended Protection for Authentication is set on every IIS endpoint. ESC8 has been patched. The defender has applied every control from the Death of NTLM chapter (Chapter 16) and ticked every box.

A low-privileged user on that network opens a PowerShell prompt. They run `Powermad` to create a fresh computer account. The default `MachineAccountQuota` is still `10`, which means any authenticated domain user can create up to ten computer objects in Active Directory by design [691]. They then write a single LDAP attribute, `msDS-AllowedToActOnBehalfOfOtherIdentity`, on a target file server they have any write permission against. They ask the Key Distribution Center for a service ticket via `Rubeus s4u`, present that ticket to the target file server, and walk in as `Administrator`. Total elapsed time: less than this paragraph. Total NTLM in the chain: zero.

> **A chain without NTLM.** The post-NTLM Resource-Based Constrained Delegation chain depends on three properties of Kerberos that are features, not bugs: (a) the default `MachineAccountQuota = 10` setting on every fresh Active Directory forest, (b) in the RBCD case Shamir documents, S4U2Proxy can produce a forwardable TGS even when the input ticket was not forwardable, when the resource-side descriptor and KDC checks permit issuance, and (c) the absence of a traditional "trusted delegator" flag requirement on the requesting principal. All three are documented behaviors of the protocol. None of them is a CVE [691].

The chain has a name and a primary disclosure: Elad Shamir's "Wagging the Dog" post on shenaniganslabs.io, January 28, 2019 [691]. The weaponised tooling is GhostPack's Rubeus, the C# Kerberos toolset that ships ready-made commands for `s4u`, `asktgt`, `kerberoast`, and `diamond` [738]. The single-line elevation wrapper that splices together Powermad, KrbRelay, Rubeus, and an SCM bypass is `KrbRelayUp`, published by Mor Davidovich ("Dec0ne") on April 24, 2022; its README scopes itself as a universal no-fix local privilege escalation in Windows domain environments where LDAP signing is not enforced (and that is the default) [693].

![Figure: The post-NTLM RBCD chain: six steps from a low-privileged user to Administrator-level access on the file server, with zero NTLM messages in the path. Five of the six exchanges touch only the Domain Controller; the trust boundary abused is the msDS-AllowedToActOnBehalfOfOtherIdentity directory attribute, not a password fallback.](diagrams/10-kerberos-rbcd-chain.svg)

**Walkthrough: post-NTLM RBCD chain.** Read the exchange as a ticket-and-directory state machine, not as an exploit recipe. First, the low-privileged user creates `CN=ATTACKER$,CN=Computers,DC=contoso,DC=com`; the directory now stores a fresh machine password and SPNs for that computer because `MachineAccountQuota` permits the create. Second, the user writes the target server's `msDS-AllowedToActOnBehalfOfOtherIdentity` security descriptor so the target resource says, in directory policy, "ATTACKER$ may act for users to me." Third, `ATTACKER$` performs a normal AS exchange and receives a TGT encrypted to `krbtgt`. Fourth, `ATTACKER$` asks S4U2Self for a service ticket whose client name is `Administrator`; the output is a ticket to `ATTACKER$`, not to the file server. Fifth, `ATTACKER$` sends that ticket as the additional ticket in S4U2Proxy and asks for `cifs/fs01.contoso.com`; because the target resource's RBCD descriptor authorizes `ATTACKER$`, the KDC issues a forwardable service ticket to the file server. Sixth, the AP-REQ goes to SMB. The file server decrypts the ticket with its own long-term key, reads a PAC naming Administrator, and has no NTLM decision to make. The trust boundary abused here is not "password fallback"; it is the directory object that defines who may delegate to the resource [691] [693].

Read the chain twice. The first read shows that every step is a documented Kerberos exchange. The second read shows that *removing NTLM did nothing to it*. Restrict-NTLM, EPA, SMB signing, ESC8: the entire NTLM-retrofit catalog has no edge against a Kerberos-only attack path that uses S4U2Self, S4U2Proxy, and the Resource-Based Constrained Delegation attribute exactly as Microsoft documented them in [739].

This is the chapter's load-bearing thesis. *Removing NTLM did not remove the attack surface; it shifted the attack surface onto a protocol with its own long retrofit history and an expanding share of the Windows authentication load.* In October 2023, Matthew Palko, Microsoft's Principal Group Product Manager for Windows authentication, wrote the post that committed Microsoft publicly to deprecating NTLM and named the Kerberos features that would replace it [717]. The Death of NTLM chapter (Chapter 16) walked through the NTLM-side mechanics of that transition. This chapter walks through the Kerberos side.

The question that drives everything that follows is the question the chain above forces: *how did Windows arrive at a state where the most catastrophic post-NTLM Active Directory attack chain depends on Kerberos working exactly as the 1988 designers intended?*

## Origins: Needham, Schroeder, Athena, and 1988

Kerberos is not new engineering. The story of Windows authentication in 2026 starts with a 1978 paper in Communications of the ACM by Roger Needham of the University of Cambridge and Michael Schroeder of Xerox PARC.

In December 1978, Roger M. Needham and Michael D. Schroeder published "Using Encryption for Authentication in Large Networks of Computers" in CACM 21(12), pages 993 to 999 [740]. The paper is paywalled on the ACM Digital Library, but RFC 4120's own Background section names it as the parent protocol [741]. The symmetric-key version of that protocol is five messages long; summarized below, it is the structural blueprint of every "ticket from a trusted third party" design that followed.

$$A \to S:\ A, B, N_A$$
$$S \to A:\ \{N_A, K_{AB}, B, \{K_{AB}, A\}_{K_{BS}}\}_{K_{AS}}$$
$$A \to B:\ \{K_{AB}, A\}_{K_{BS}}$$
$$B \to A:\ \{N_B\}_{K_{AB}}$$
$$A \to B:\ \{N_B - 1\}_{K_{AB}}$$

`A` and `B` are the principals; `S` is the trusted third party; `K_AS` and `K_BS` are pre-shared long-term keys; `K_AB` is the session key that `S` mints for the conversation; `N_A` and `N_B` are nonces. The "ticket" is the part of the third message that `A` cannot decrypt and just forwards to `B`. That structure (a server-issued cryptographic envelope intended for somebody else and opaque to the carrier) is what becomes the Kerberos ticket a decade later.

Three years later, in August 1981, Dorothy Denning and Giovanni Maria Sacco published "Timestamps in Key Distribution Protocols" in CACM 24(8), 533-536. RFC 4120 names Denning and Sacco's modifications as the other parent of Kerberos v5 [741]: the Needham-Schroeder symmetric protocol [742] is vulnerable to replay if an attacker recovers an old session key, and timestamps are the fix. This is the structural reason every Kerberos ticket carries a timestamp and every Kerberos network requires a synchronised time service today.

> **Definition: Kerberos Domain (administrative boundary).** A Kerberos administrative boundary, written in uppercase like `CONTOSO.COM`, that scopes a set of principals (users, services, computers) sharing a single Key Distribution Center. Every Kerberos ticket records realm membership: the client's realm and name appear in `EncTicketPart.crealm` and `EncTicketPart.cname`, while the outer `Ticket.realm` and `Ticket.sname` name the service's realm and principal. Active Directory maps Kerberos realms to AD domains: each domain has domain controllers that host the KDC service for that domain, and a forest can contain child or tree domains with their own realms and trust relationships [739] [743].

Between 1983 and 1991, MIT Project Athena (the joint MIT, DEC, and IBM campus computing effort led by Jerome Saltzer) needed a working authentication service for a distributed workstation network running over a hostile campus LAN. The Athena Technical Plan Section E.2.1, "Kerberos Authentication and Authorization System" [744], is the canonical internal design document. Steve Miller and Clifford Neuman did the protocol work; Jeffrey Schiller ran the network operations.

In February 1988, MIT published two complementary artifacts. Bill Bryant wrote "Designing an Authentication System: a Dialogue in Four Scenes": a pedagogical script in which an engineer named Athena designs her way step by step from "users type their password to every server" to "users obtain time-limited tickets from a trusted third party". Bryant's dialogue is the most cited pre-protocol document about why Kerberos exists in the shape it does [745]. The same month, Jennifer Steiner, Clifford Neuman, and Jeffrey Schiller presented "Kerberos: An Authentication Service for Open Network Systems" at the USENIX Winter Conference in Dallas [746]. The protocol that paper described (later called Kerberos version 4) carried forward to v5 with ASN.1 encoding, extensibility hooks, and pre-authentication, but the AS / TGS / AP message-triple skeleton it specified remains recognizable thirty-eight years later.

On January 24, 1989, MIT shipped the first public release of Kerberos v4 [747]. Five years later, in September 1993, the IETF adopted Kerberos v5 as RFC 1510 [748]. RFC 1510 added ASN.1 encoding, cross-domain trust, and an extensibility hook called PA-DATA that every Kerberos extension since has used. In July 2005, RFC 4120 replaced RFC 1510 as the Kerberos v5 standard [741].

![Figure: The 1988 Kerberos message triple (AS-REQ/REP, TGS-REQ/REP, AP-REQ/REP) structurally unchanged thirty-eight years later. The AS and TGS exchanges are the two logical halves of one KDC; the service validates the final ticket locally with its own long-term key.](diagrams/10-kerberos-message-triple.svg)

**Walkthrough: the Kerberos triple.** The first exchange is AS-REQ / AS-REP. The client names itself, the realm, requested options, requested enctypes, and pre-authentication data; the KDC returns two related objects: a TGT encrypted to the `krbtgt` long-term key, and client-visible key material encrypted to the user's long-term key. The client cannot open the TGT; it can only cache it and use the adjacent TGT session key. The second exchange is TGS-REQ / TGS-REP. The client proves possession of the TGT session key with an authenticator, names an SPN such as `cifs/fs01.contoso.com`, and receives a service ticket encrypted to the service account plus a new client/service session key. The third exchange is AP-REQ / AP-REP. The client sends the opaque service ticket and an authenticator to the service; the service decrypts the ticket with its own key, checks the authenticator freshness, and validates the PAC material it is equipped and required to validate under Windows PAC rules. It may verify the service-keyed PAC signature locally; validation of KDC-keyed PAC signatures is a different trust path. That six-message shape is why a stolen long-term key is so powerful: the service-side AP decision is deliberately local once the ticket arrives [741] [743].

Kerberos in 2026 still exposes the same AS / TGS / AP outline, with decades of extensions layered inside it. The skeleton you draw on a whiteboard for a graduate seminar is recognizably the skeleton a Windows 11 24H2 machine uses with a 2025 domain controller. The interesting question is what those extensions did to the inside of every message. *(Note: The default maximum clock skew between client and KDC in Windows Kerberos is five minutes (300 seconds), set by Group Policy "Maximum tolerance for computer clock synchronization" and documented in [739]. The five-minute window is the residue of Denning and Sacco's 1981 timestamp fix.)*

## The wire in 2026: Six messages and an encryption matrix

Every Kerberos textbook draws the same six-message diagram introduced above. The diagram has been unchanged since 1988. What is different in 2026 is everything inside the messages.

Look first at the AS-REQ. In raw RFC 4120 the AS-REQ carries a `req-body` (client name, target name, requested lifetime, requested enctypes) and an optional `padata` field [741]. That `padata` slot is the load-bearing extensibility hook of the entire protocol. Every Kerberos enhancement since 1993 has been a new PA-DATA type: `PA-ENC-TIMESTAMP` (the encrypted-timestamp pre-auth blob), `PA-PK-AS-REQ` (PKINIT [749]), `PA-FX-FAST-REQUEST` (FAST armoring [750]), `PA-AS-FRESHNESS` (PKINIT freshness [751]). The skeleton survives only because the joints are extensible.

> **Definition: Pre-authentication Data (PA-DATA).** A `SEQUENCE OF { padata-type, padata-value }` field in the Kerberos AS-REQ and AS-REP messages, introduced in RFC 1510 (1993) and carried forward unchanged into RFC 4120 §5.2.7 (2005). PA-DATA is the only protocol-level hook by which a Kerberos client can prove possession of a credential before the KDC issues a Ticket-Granting Ticket, and the only hook by which an enhancement like FAST or PKINIT can attach new behavior to the AS exchange without breaking compatibility with older clients [741].

The AS-REP returns the TGT. The TGT itself is encrypted under the TGS/`krbtgt` long-term key, so the client cannot inspect the TGT's `EncTicketPart`. What the client *can* inspect are the mirrored or adjacent fields in the encrypted AS-REP reply part that is encrypted to the client key, including ticket flags and session-key material. RFC 4120 §2 enumerates the ticket-flag positions, including `forwardable`, `proxiable`, `postdated`, `renewable`, `initial`, `pre-authent`, `hw-authent`, `transited-policy-checked`, and `ok-as-delegate` [741]. (`may-postdate` looks like a sibling but is a `KDCOptions` request bit per RFC 4120 §5.4.1, not a `TicketFlags` bit.) Pay attention to `forwardable`. In 2020, Jake Karnes of NetSPI demonstrated that an attacker who knew a service account's long-term key could decrypt the S4U2Self output ticket, set `forwardable = 1`, re-encrypt, and feed the ticket back to the KDC's S4U2Proxy step. The KDC accepted it. The bypass is CVE-2020-17049 and the attack is called Bronze Bit [752] [753].

Inside the ticket's `AuthorizationData` field is the Microsoft-specific construction that turns Kerberos into a Windows authorization system. The Privilege Attribute Certificate, defined in [MS-PAC] revision 26.0 [743] [754], carries the user's SID, their group SIDs, their logon name, timestamps, and, depending on patch level, up to four cryptographic signatures: a Server signature, a KDC signature, a Ticket Checksum (added for CVE-2020-17049, the Bronze Bit fix, binding the PAC to its ticket), and (since CVE-2022-37967 in November 2022) a Full PAC Signature that covers the entire encoded PAC structure instead of just the existing signatures [755].

> **Definition: Privilege Attribute Certificate (PAC).** A Microsoft-specific authorization data element that the Kerberos KDC normally attaches to tickets it issues for a Windows principal. The PAC carries the user's SID, group SIDs, logon name, and timestamps, and is protected by signatures that include service-keyed and KDC-keyed material. The PAC, not the Kerberos ticket itself, is what gives a Windows file server the access-control information it needs to make a permission decision. Defined in [MS-PAC] [743].
>
> **Precision box. PAC validation is not one offline check.**
>
> | Check | Ordinary service can do locally? | Key / authority | Why it matters |
> |-------|----------------------------------|-----------------|----------------|
> | Service-ticket decryption | Yes | Service long-term key | Proves the ticket was encrypted for this SPN. |
> | Authenticator freshness | Yes | Client/service session key | Rejects replay inside the clock-skew window. |
> | Server PAC signature | Yes, when the service has the service key and PAC validation is required | Service long-term key | Detects PAC tampering visible to the service-keyed checksum. |
> | KDC / Full PAC signature | Not universally; validation can involve KDC/Netlogon semantics and policy exceptions | KDC / `krbtgt` side | Distinguishes local AP acceptance from full Windows PAC validation. |
>
> This is the chapter's corrected ledger entry: Kerberos gives cheap local AP acceptance, not a promise that every service can independently validate every PAC signature offline [743] [756].

> **Aside: Why the November 2022 Kerberos KBs are easy to mix up.** Patch Tuesday paired two Kerberos CVEs: CVE-2022-37967 (Full PAC Signature, KrbtgtFullPacSignature) and CVE-2022-37966 (default session-key encryption type). KB5021131 covers the deployment of the encryption-type bypass side, CVE-2022-37966. A paired KB article, KB5020805, covers the Full PAC Signature side. When citing KB5021131 alongside the Full PAC Signature, both CVE numbers are relevant [756] [755].

Then there is the encryption matrix. Kerberos abstracts ciphers behind the RFC 3961 framework [757], which defines an enctype as a tuple of (encrypt, decrypt, checksum, string-to-key, key-derivation) functions. The history of Windows Kerberos is the history of which enctypes were the default at any given time.

| Enctype | Number | Spec | Status in 2026 |
|---------|--------|------|----------------|
| DES-CBC-CRC | 1 | RFC 3961 [757] | Disabled by default since Server 2008 R2 [758] |
| DES-CBC-MD5 | 3 | RFC 3961 [757] | Disabled by default since Server 2008 R2 [758] |
| RC4-HMAC | 23 | RFC 4757 [759] | Informational, not Standards Track; default-removed in mid-2026 per [760] |
| AES-128-CTS-HMAC-SHA1-96 | 17 | RFC 3962 [761] | Default since Server 2008; cross-version compatible |
| AES-256-CTS-HMAC-SHA1-96 | 18 | RFC 3962 [761] | Default since Server 2008; the mid-2026 destination |
| AES-128-CTS-HMAC-SHA256-128 | 19 | RFC 8009 [762] | Specified in [MS-KILE] bit K [758]; no default-enable timeline |
| AES-256-CTS-HMAC-SHA384-192 | 20 | RFC 8009 [762] | Specified in [MS-KILE] bit L [758]; no default-enable timeline |

Enctype 23 is the row that built every Kerberoasting career. K. Jaganathan, Larry Zhu, and John Brezak of Microsoft published RFC 4757 in December 2006 [759]. The IESG note on the RFC is unusually candid: the document is *Informational*, not Standards Track, because RC4-HMAC "do[es] not provide all the required operations in the Kerberos cryptography framework [RFC 3961]" and because of "security concerns with the use of RC4 and MD4". The choice that made enctype 23 dangerous, however, was upstream of the RFC. To make Windows 2000's Kerberos rollout backward-compatible with the existing SAM password database, Microsoft set the RC4-HMAC long-term Kerberos key equal to the *NT hash of the user's password*: the same hash NTLM was already storing. As Microsoft's own October 2024 Kerberoasting guidance puts it verbatim: "RC4 is more susceptible to the cyberattack because it uses no salt or iterated hash when converting a password to an encryption key" [763].

> **Definition: String-to-Key (s2k).** The function that converts a typed password into a Kerberos long-term symmetric key. For RC4-HMAC (enctype 23), `s2k(password) = MD4(UTF-16-LE(password))`: the NT hash, no salt, no iteration. For AES-CTS-HMAC-SHA1-96 (enctypes 17 and 18), `s2k(password, salt) = PBKDF2-HMAC-SHA1(password, salt, 4096, dklen)` followed by RFC 3962 post-processing into a 128- or 256-bit AES key. The default user-principal salt is conventionally the realm plus principal components, but Active Directory salt behavior varies by principal class and account history; treat the salt as KDC-supplied policy, not a string you can always reconstruct by eye [761] [758].

The cryptography in that definition is short enough to follow end-to-end.

That PBKDF2-HMAC-SHA1 result is only the intermediate; the AES256 long-term key
used by Kerberos is the RFC 3962 `DK(tkey, "kerberos")` result, and Windows stores key material
according to the account's available keys and `msDS-SupportedEncryptionTypes` state. When a
Kerberoasting attacker steals the TGS-REP, what they crack offline is which password produces
that key. The RFC 3962 post-processing (a single round of `DK(key, "kerberos")`) shapes the
output to AES key length but does not slow the dictionary attack down. The dispositive defense
is not in the cryptography; it is in the password, or more precisely in not having one at all.
The move to gMSA and dMSA replaces typed passwords with KDC-generated random secrets [764]
[765]. *(Note: PBKDF2 at 4,096 iterations is well below modern PHC recommendations. The 2023
OWASP guideline for PBKDF2-HMAC-SHA1 is 1.3 million iterations [766], but the 4,096 figure is
wired into RFC 3962 and is the same on every supported Windows version. Service accounts using
gMSA bypass this entirely: the gMSA's "password" is a 240-character random secret rotated every
30 days, derived by the Microsoft Key Distribution Service rather than entered by a human
[764].)*

The wire in 2026 is therefore six messages and a matrix of seven enctypes. The protocol skeleton is forty years old. In 2014 a SANS instructor named Tim Medin gave a forty-five-minute talk that turned every one of those enctypes into a problem.

## The attack cascade: 2014 to 2022

September 26-28, 2014. Louisville, Kentucky. DerbyCon 4. Talk slot T120. Tim Medin (then at Counter Hack Challenges, also a SANS instructor) walks on stage with a forty-five-minute talk titled "Attacking Microsoft Kerberos: Kicking the Guard Dog of Hades" [688]. The talk demonstrates that any authenticated domain user can request a TGS for any Service Principal Name in the directory, and that the service-portion of the returned ticket is encrypted under the SPN account's long-term key: which, under RC4-HMAC enctype 23, is the NT hash of the password. Cracking the ciphertext is reduced to a dictionary attack against whatever password an admin set on the service account.

That talk is the moment Kerberos becomes interesting to attackers. The next eight years play out as a cascade. Five generations, each one named after the canonical primitive that defined it, each one exposing a different structural property of the protocol, each one earning its own engineered Microsoft response years later.

> **Definition: Service Principal Name (SPN).** A unique identifier for a service instance in Active Directory, written in the form `service-class/host:port/service-name` (for example `HTTP/web01.contoso.com`). Kerberos uses the SPN to look up which account holds the long-term key that decrypts the service ticket. Any account that has an SPN (a user account that has had `setspn -A` run against it, every machine account in the directory, every gMSA) is a candidate for Kerberoasting [767].

### Generation 1, 2014: Kerberoasting

Tim Medin's primitive [688]. Will Schroeder's PowerShell weaponisation as `Invoke-Kerberoast` (later rolled into the C# Rubeus) [738]. Sean Metcalf's operational walkthrough on adsecurity.org [767]. MITRE cataloged the technique in 2020 as ATT&CK T1558.003, which preserves the structural definition verbatim: "Portions of these tickets may be encrypted with the RC4 algorithm, meaning the Kerberos 5 TGS-REP etype 23 hash of the service account associated with the SPN is used as the private key and is thus vulnerable to offline Brute Force attacks" [689].

The structural insight is the part that matters. The service ticket inside the TGS-REP is encrypted with the service account's *long-term* password-derived key, so any domain user who can obtain that ticket can mine the service-ticket ciphertext offline against any dictionary they care to assemble. The Kerberos protocol has no mechanism by which the KDC could tell whether the requesting user has any business asking for that SPN, because RFC 4120 has no concept of "this service is for these users". In the ordinary Kerberoasting case, possession of a TGT is enough to request the service ticket.

Microsoft's *dispositive* engineered response did not arrive until ten to twelve years later, even though a partial, not-purpose-built mitigation predated the disclosure. Server 2012 had introduced Group Managed Service Accounts: passwords randomised to 240 characters, derived by the Microsoft Key Distribution Service via `kdssvc.dll`, rotated every 30 days, retrievable from a domain controller by member hosts that are explicitly authorized in `msDS-GroupMSAMembership` [764]. Server 2025 then introduced Delegated Managed Service Accounts (dMSA), which take the next structural step: the dMSA's secret is "derived from the machine account credential" held by the domain controller, and "the secret can't be retrieved or found anywhere other than on the DC" [765]. The October 2024 Microsoft Security Blog formalized the Kerberoasting guidance in a single page that names RC4 as the load-bearing weakness and announces the deprecation [763]. The December 2025 Beyond-RC4 announcement closed the cadence with a calendar date [760].

### Generation 2, 2014-2017: Mimikatz Kerberos and AS-REP Roasting

Benjamin Delpy publishes `mimikatz` 2.0 on April 6, 2014; the v2 banner inside the repository README reads verbatim `mimikatz 2.0 alpha (x86) release "Kiwi en C" (Apr 6 2014 22:02:03)` [261]. The Kerberos module contains two commands that define the era: `kerberos::golden` (forge a TGT from the KRBTGT account's long-term key, granting Domain Admin equivalence indefinitely) and `kerberos::silver` (forge a TGS from any service account's long-term key, granting impersonation of any user against that service).

The structural insight: RFC 4120 has no online ticket validation [741]. Once a ticket carries the right signatures, the service trusts it. Whoever holds a long-term key forges any ticket that key signs. Possession of a key collapses to ticket forgeability.

Around 2017, the same team behind Rubeus publicises AS-REP Roasting [738]: the same offline-cracking primitive as Kerberoasting, but against any account whose `userAccountControl` has `UF_DONT_REQUIRE_PREAUTH` (the `DONT_REQ_PREAUTH` flag) set. With pre-authentication disabled, the KDC will return an AS-REP encrypted under the user's password-derived key to *anyone* who asks for it, no proof of password possession required. The dispositive Microsoft response was already in place: pre-authentication has been required by default for all new Active Directory accounts since Windows 2000, and the flag has to be deliberately cleared by an administrator. The remaining vulnerability is operational hygiene: finding the handful of legacy accounts an organization has left with pre-auth disabled.

### Generation 3, 2018-2020: Delegation abuse

Three primitives in three years.

**SpoolSample / PrinterBug.** Lee Christensen (tifkin_, SpecterOps) published the PoC on GitHub on October 5, 2018 [726]. The MS-RPRN remote-procedure-call interface includes a method, `RpcRemoteFindFirstPrinterChangeNotificationEx`, that any authenticated user can invoke against any host's spooler service to ask the spooler to *please call back* to an attacker-controlled address. The spooler obediently authenticates outbound using the machine account's credentials. Combined with unconstrained Kerberos delegation on the attacker-controlled host, the inbound authentication captures the target machine's TGT.

**Wagging the Dog (RBCD).** Elad Shamir's January 28, 2019 post on shenaniganslabs.io [691]. The TL;DR of the post is the load-bearing structural disclosure: "Resource-based constrained delegation does not require a forwardable TGS when invoking S4U2Proxy. S4U2Self works on any account that has an SPN, regardless of the state of the TrustedToAuthForDelegation attribute. S4U2Proxy always produces a forwardable TGS, even if the provided additional TGS in the request was not forwardable. By default, any domain user can abuse the MachineAccountQuota to create a computer account and set an SPN for it, which makes it even more trivial to abuse resource-based constrained delegation to mimic protocol transition" [691]. Every clause of that TL;DR points at a documented behavior. The chain in this chapter's opening gap analysis is built directly on top.

**Bronze Bit.** Jake Karnes at NetSPI; CVE-2020-17049; disclosed November 10, 2020 [753] [752]. The NVD entry preserves Microsoft's verbatim description: "A security feature bypass vulnerability exists in the way Key Distribution Center (KDC) determines if a service ticket can be used for delegation via Kerberos Constrained Delegation (KCD). To exploit the vulnerability, a compromised service that is configured to use KCD could tamper with a service ticket that is not valid for delegation to force the KDC to accept it" [752]. The bypass: any service in possession of its own long-term key can decrypt the S4U2Self output ticket, flip the `forwardable` bit in `EncTicketPart`, and re-encrypt with the same key. Pre-2020 the KDC's S4U2Proxy validation accepted the resulting ticket because nothing on the ticket independently attested whether the `forwardable` flag had been set by the KDC or by the service itself. Microsoft's November 10, 2020 fix, per the NVD entry verbatim, "addresses this vulnerability by changing how the KDC validates service tickets used with KCD" so that the tampered flag is rejected [752]. The PAC signatures, contra a common framing, were never meant to cover the `EncTicketPart` flag bits in the first place.

Microsoft's engineered responses: the November 2020 Bronze Bit patch [752] tightened the KDC's S4U2Proxy ticket-validation step; KB5008380 (November 2021) [768] shipped alongside the canonical "set `ms-DS-MachineAccountQuota = 0` for non-administrator users" hardening guidance; LDAP signing and channel binding work, ongoing since the NTLM-retirement effort began, became the dispositive control against the relay variant of the chain.

### Generation 4, 2021-2022: Certificate-based ticket forgery and Kerberos relay

**Certifried.** Oliver Lyak (ly4k) at IFCR disclosed CVE-2022-26923 to Microsoft, who patched on May 10, 2022 [769]. The attack exploited a quirk of how Active Directory Certificate Services (ADCS) bound a certificate's identity to an AD account when the certificate was used for PKINIT. Before the strong-mapping fix, AD's account-lookup at PKINIT time matched the certificate's Subject Alternative Name (SAN) to an account: a User Principal Name for user certificates, or the DNS name (populated from `dNSHostName`) for machine certificates. If an attacker controlled a machine account, they could change the machine's `dNSHostName` to match a domain controller's, request a certificate via the (overly-permissive) default `Machine` template, and use the resulting certificate to PKINIT-authenticate to the KDC as that domain controller. Microsoft's response is documented end-to-end in KB5014754 [770]: a new "strong certificate mapping" requirement that pins each issued certificate to a specific account SID via an X.509 extension (OID 1.3.6.1.4.1.311.25.2). The original release moved to Compatibility mode on May 10, 2022; full Enforcement mode took effect on February 11, 2025; Disabled-mode rollback was removed on April 11, 2023; the remaining Compatibility-mode fallback was removed on September 9, 2025 [770].

**KrbRelayUp.** Mor Davidovich (`Dec0ne`), April 24, 2022 [693]. The README's universal-no-fix-LPE framing is preserved in the PullQuote below. The chain wraps `Powermad` (machine account creation), `KrbRelay` (Kerberos relay to LDAP), Rubeus (S4U2Self bypass of Protected Users, RBCD privilege addition), and `SCMUACBypass` (a wrapper that uses the resulting ticket to open the local Service Control Manager and create a service running as `NT AUTHORITY\SYSTEM`). The class of attack is "Kerberos relay": the post-NTLM cousin of NTLM-relay. The dispositive control is not a Kerberos patch; it is domain-wide LDAP signing plus channel binding plus Extended Protection for Authentication on ADCS Web Enrollment.

> A universal no-fix local privilege escalation in windows domain environments where LDAP signing is not enforced (the default settings).: Mor Davidovich, KrbRelayUp README, April 2022 [693]

### Generation 5, 2022: Forged-ticket sophistication

**Diamond Ticket.** Charlie Clark at Semperis co-authored a blog post in 2022 with Andrew Schwartz at TrustedSec disclosing the modern Diamond Ticket technique [771] [772]. The Semperis byline names the antecedent: a 2015 Black Hat EU presentation by Tal Be'ery and Michael Cherny ("Watching the Watchdog") that introduced the "Diamond PAC" idea. Verbatim from the Semperis post: "Golden Ticket attacks take advantage of the ability to forge a ticket granting ticket (TGT) from scratch, Diamond Ticket attacks take advantage of the ability to decrypt and re-encrypt genuine TGTs requested from a domain controller (DC)" [771]. The structural insight is that a Diamond Ticket has a *legitimately issued, KDC-signed* PAC at its base; only the privilege-claim fields inside the PAC are tampered. Before the November 2022 Full PAC Signature fix, no *krbtgt-keyed* signature covered the entire encoded PAC: the Server Signature spanned the whole PAC but used the service's own (recomputable) key, while the KDC Signature covered only the Server Signature's bytes. That left room for a key-holder to modify PAC fields and recompute the coverage they could reach.

**Sapphire Ticket.** Charlie Bromberg, also known online as "Shutdown", at Synacktiv [773]
[774]. The community wiki The Hacker Recipes, which Bromberg maintains, documents the Sapphire
Ticket technique end-to-end at `thehacker.recipes/a-d/movement/kerberos/forged-tickets/sapphire`
[774]. The verifiable third-party attribution lives at pgj11.com, which records verbatim: "One
brand new technique is Sapphire Ticket. Created by Charlie Shutdown (twitter.com/_nwodtuhs) this
approach is more stealthy. You can create a TGT impersonating any user assembling real TGT and
real PAC combining S4U2Self + U2U... He extended Ticketer from Impacket to add this attack"
[773]. The Sapphire Ticket bolts a *legitimately KDC-issued* PAC (obtained by chaining the
S4U2Self and User-to-User Kerberos extensions to request a service ticket *to oneself* with the
PAC of an arbitrary target user) onto a Diamond-style ticket. The result presents PAC signatures
that the KDC itself produced. Unit 42's December 2022 "Next-Gen Kerberos Attacks" writeup is the
secondary that joined Diamond and Sapphire into the same article and named them collectively the
"Precious Gemstones" [775]. *(Note: Some secondary sources attribute Sapphire Ticket to Charlie
Clark of Semperis. The misattribution probably stems from Clark's separate "AS Requested STs"
post on the Semperis blog, which discusses a different technique exploiting unarmored
machine-account AS-REQs and is not the Sapphire Ticket primary [776]. The verified
Sapphire-Ticket originator is Charlie Bromberg (Shutdown, Synacktiv) per [773].)* *(Note: The
adsecurity.org URL `?p=2293` is Sean Metcalf's "Cracking Kerberos TGS Tickets Using Kerberoast:
Exploiting Kerberos to Compromise the Active Directory Domain" (not Metcalf's separate
KRBTGT-account post, which lives at a different URL). The page is the operational walkthrough
that pairs with Tim Medin's 2014 DerbyCon disclosure [767].)*

Microsoft's engineered response to both Diamond and Sapphire was CVE-2022-37967, the KrbtgtFullPacSignature [755] [756]. It is the first PAC-handling protocol change since Windows 2000's introduction of the PAC. After full enforcement, the KDC adds a *Full PAC Signature* that covers the entire encoded PAC, not just the existing sub-signatures. This closes PAC tampering by parties that do *not* hold the krbtgt key, the modification-after-issuance class the sub-signatures left uncovered. It does *not* stop an attacker who already holds the krbtgt key: a Golden or Diamond forger computes a valid Full PAC Signature with that same key. KrbtgtFullPacSignature raises the bar against PAC modification by non-key-holders; it is not a defense against krbtgt compromise itself, for which the only remedy is securing and dual-rotating krbtgt (Chapter 18).

> The accounts most vulnerable to Kerberoasting are those with weak passwords and those that use weaker encryption algorithms, especially RC4. RC4 is more susceptible to the cyberattack because it uses no salt or iterated hash when converting a password to an encryption key, allowing the cyberthreat actor to guess more passwords quickly.: Microsoft Security Blog, October 11, 2024 [763]

### The spine table

| Generation | Year | Primitive | Structural Insight | Microsoft Response |
|------------|------|-----------|--------------------|--------------------|
| 1 | 2014 | Kerberoasting [688] | Service-ticket ciphertext inside the TGS-REP is encrypted with the SPN account's long-term key; offline-crackable | gMSA (2012) [764]; dMSA (2025) [765]; Beyond-RC4 (2025-2026) [760] |
| 2 | 2014-2017 | Golden / Silver Ticket [261]; AS-REP Roasting [738] | RFC 4120 has no online ticket validation [741]; long-term key = forge equivalence | KrbtgtFullPacSignature (2022) [755]; preauth-required default since Windows 2000 |
| 3 | 2018-2020 | SpoolSample [726]; RBCD [691]; Bronze Bit [752] | MS-RPRN coercion; RBCD permits forwardable S4U2Proxy outcomes under Shamir's documented conditions; pre-2020 KDC did not independently validate the EncTicketPart flags | Bronze Bit patch (Nov 2020); KB5008380 + MachineAccountQuota=0 (Nov 2021); LDAP signing |
| 4 | 2022 | Certifried [769]; KrbRelayUp [693] | ADCS template SAN-binding ambiguity; LDAP defaults unsigned | KB5014754 strong-mapping [770]; LDAP signing + EPA on /certsrv/ |
| 5 | 2022 | Diamond [771]; Sapphire [773] [775] | PAC sub-signatures did not cover the encoded PAC structure | KrbtgtFullPacSignature (CVE-2022-37967, Nov 2022) [755] |

![Figure: The 2014–2022 Kerberos attack cascade across five generations: each generation's primitive on the left, Microsoft's response on the right. Every primitive eventually met an engineered response, yet new ones kept appearing until more structural seams were addressed.](diagrams/10-kerberos-attack-cascade.svg)

**Walkthrough timeline: attack cascade.** The public sequence runs from Kerberoasting and Mimikatz Golden/Silver tickets in 2014, through AS-REP roasting, SpoolSample/PrinterBug, RBCD, and Bronze Bit, into the 2022 cluster of KrbRelayUp, Certifried, Diamond, Sapphire, and Microsoft's KrbtgtFullPacSignature response. The security lesson is chronological: each primitive exposed a different ticket, flag, PAC, or delegation seam.

Eight years. Eleven structural primitives. One protocol. By 2022 the public cascade slowed, not because the protocol had become simple, but because the known seams had acquired named mitigations, patches, or operational controls. The 2022 Microsoft response, KrbtgtFullPacSignature, was the first one that targeted the *structural* properties (PAC coverage of its own structure) rather than the per-primitive patches that defined the 2014-2020 era. To see why that was a turning point, it helps to see exactly what the defensive cadence looked like before then.

## The defensive cadence before 2023

Each of the eleven primitives in the attack-cascade section eventually met a patch, mitigation, or operational control. By 2022 every named primitive *had* a response. And yet the cascade kept producing new primitives. Why?

The answer is in the shape of the defensive controls. Walk them in chronological order.

**Protected Users (Server 2012 R2, October 2013) [777].** A new security group that triggers five non-configurable client-side protections and four non-configurable domain-controller-side protections [672]. The client side: CredSSP "doesn't cache the user's plain text credentials"; Windows Digest "doesn't cache the user's plaintext credentials"; "NTLM stops caching the user's plaintext credentials or NT one-way function (NTOWF)"; "Kerberos stops creating Data Encryption Standard (DES) or RC4 keys... or long-term keys after acquiring the initial Ticket Granting Ticket (TGT)"; "The system doesn't create a cached verifier at user sign-in or unlock" [672]. The domain-controller side, also verbatim: members "cannot authenticate with NTLM authentication... use DES or RC4 encryption types in Kerberos preauthentication... delegate with unconstrained or constrained delegation... renew Kerberos TGTs beyond their initial four-hour lifetime" [672]. The limit is the obvious one: Protected Users breaks every workflow that relied on delegation, RC4, or NTLM, and there are many such workflows still in production.

**Authentication Policy Silos (Server 2012 R2).** A scope construct that lets administrators group users, computers, and service accounts under authentication policies that restrict where high-value credentials can be used and tune Kerberos TGT lifetime and access conditions. The standard tier-zero / tier-one / tier-two split fits neatly under three silos [778] [779].

> **Definition: Authentication Policy Silo.** A container of users, computers, and managed service accounts in Active Directory that scopes a single authentication policy. Members can be required to authenticate only from designated hosts, must use AES enctypes, may be excluded from delegation, and (when paired with FAST armoring) sign their AS-REQ inside a machine-account or anonymous-PKINIT armor. Available since Server 2012 R2; the operational granularity that Protected Users does not provide on its own [778].

**Restricted Admin (2014) and Remote Credential Guard (2016) [780].** The RDP-side companions that block credential exposure on the target host. Both work by changing what gets sent on the wire during a remote sign-in: Restricted Admin (Windows 8.1 / Server 2012 R2 era) uses the user's TGT to authenticate via Kerberos network logon, so no credentials reach the target; Remote Credential Guard (Windows 10 1607, August 2016) performs the same trick but for interactive sessions, redirecting CredSSP back to the originating workstation [780].

**Credential Guard (Windows 10 RTM, 2015) [621].** Virtualization-Based-Security-isolated LSASS: secrets that LSASS would otherwise hold in user-mode memory are moved into the LSAISO trustlet running in Virtual Trust Level 1. SYSTEM on the box cannot read VTL1 memory. The Credential Guard chapter (Chapter 15) owns this mechanism in full; the load-bearing distinction for *this* chapter is that it isolates the long-term *key*, not the *tickets* minted from it: current-session TGTs and service tickets still sit in VTL0 `lsass.exe`, which is why ticket abuse remains a Kerberos problem after the long-term secret is off the box.

**FAST armoring (RFC 6113, April 2011).** Sam Hartman and Larry Zhu's "A Generalized Framework for Kerberos Pre-Authentication" defines the FAST (Flexible Authentication Secure Tunneling) channel [750]. The AS-REQ is wrapped in an outer armor envelope, keyed under the machine account's TGT (for a domain-joined client), an anonymous PKINIT TGT (for a non-domain-joined client), or a compound identity. The armor envelope encrypts the PA-ENC-TIMESTAMP blob and authenticates the entire request, closing the offline-cracking path that targets the encrypted-timestamp pre-auth. The limit: FAST is client opt-in, not on by default, and Server 2012 R2 domain functional level is the floor for compound identity. Many production environments still do not require FAST on their tier-zero accounts.

**gMSA (Server 2012).** The dispositive Kerberoasting defense for service accounts [764] [781]. The Microsoft Key Distribution Service (`kdssvc.dll`) computes and rotates the account password material, and member hosts authorized for the gMSA can retrieve current and previous password values from a domain controller. The decisive property that gMSA closes is the human-typed-password assumption: there is no password to remember, write down, or share.

**LDAP signing and channel binding.** The dispositive KrbRelayUp defense. Set `LDAPServerIntegrity = 2` to require signing on every LDAP bind, and `LdapEnforceChannelBinding = 2` to require channel binding on TLS-bound LDAP connections. Both are off by default in older domain functional levels, which is exactly the default the [693] README is targeting when it calls itself "no-fix".

**KrbtgtFullPacSignature (November 2022).** The first PAC-handling protocol change since Windows 2000's introduction of the PAC. After full enforcement, every PAC carries an additional Full PAC Signature covering the entire encoded structure, not just sub-pieces; this closes PAC modification by parties that do not hold the krbtgt key. It does not stop a krbtgt-key holder (Golden or Diamond), nor Sapphire-class variants that obtain a legitimate KDC-issued PAC via S4U2Self [755] [756].

**MachineAccountQuota = 0 guidance (KB5008380, November 2021) [768].** The dispositive RBCD defense as a configuration: setting the directory-wide `ms-DS-MachineAccountQuota` attribute on the domain root to zero prevents non-administrative users from creating computer accounts at all, which kills the first step of the chain in the opening gap analysis.

> **Key idea.** Each defensive control patches a primitive. No control patches the structural property of the protocol. That any long-term symmetric key is forge-equivalent for every ticket type that key signs, and that local AP acceptance without a per-request KDC callback makes online ticket revocation incompatible with the design.

| Defense | Target Primitive | Structural Limit |
|---------|-----------------|------------------|
| Protected Users [672] | Pass-the-Hash, Pass-the-Ticket, RC4 pre-auth | Breaks delegation, RC4, and NTLM; four-hour TGT cap may break legacy apps |
| Authentication Policy Silo [778] | Per-tier scope of Protected-Users behavior | Requires Server 2012 R2 DFL; FAST armoring requires Server 2012 R2 too |
| Credential Guard | LSASS memory theft (Mimikatz `sekurlsa::`) | Does not prevent ticket theft via legitimate Kerberos APIs |
| FAST (RFC 6113) [750] | PA-ENC-TIMESTAMP offline cracking | Client opt-in; not on by default |
| gMSA [764] | Kerberoasting on service accounts | Human-managed service accounts unaffected |
| LDAP signing + channel binding | KrbRelayUp [693] | Off by default in older domains |
| KrbtgtFullPacSignature [755] | Diamond and most Sapphire variants | Does not stop Sapphire-class variants where the abusive PAC is obtained from the KDC legitimately (for example via S4U2Self) rather than forged or modified after issuance |
| MachineAccountQuota = 0 | RBCD chain [691] | Default value is `10`; setting requires admin action |

Read the table the way an attacker reads it. Each row is necessary; no row is sufficient. The "structural limit" column is the next-attack catalog. Protected Users does not stop a Diamond Ticket forged from a stolen KRBTGT key. Credential Guard does not stop the operator who has SYSTEM on a domain controller. FAST does not stop AS-REP Roasting (because AS-REP Roasting only happens on accounts with pre-auth disabled, where FAST is moot). gMSA does not protect a service account someone still manages manually with a Notes-saved password.

The pattern is the answer to the section's opening question. Every control attacks one primitive (a key, a flag, a coercion path, a ticket lifetime) and none of them closes *the* protocol-level structural property that any long-term symmetric key in the domain is forge-equivalent for any ticket type that key signs. By 2022 the known public engineering catalog had matured. The 2023 announcement was the first plan in this sequence that targeted the structure.

What would a structural fix even look like, given that any "online revocation" change would also give up Kerberos's O(1) service-side validation, and given that any "deprecate the long-term key" change has to back-compat to clients that have not been touched since Server 2008? The October 2023 Palko post had answers.

## The breakthrough: Closing the Domainless gap

October 11, 2023. Matthew Palko, Microsoft's Principal Group Product Manager for Windows authentication, publishes "The evolution of Windows authentication" on the Windows IT Pro Blog. The post's raw HTML metadata records a modified time of `2023-11-11T01:30:49.108-08:00`; its description reads "Discover how we're securing authentication and reducing NTLM usage in Windows" [717]. It is the first time Microsoft commits publicly to deprecating NTLM, and the first time Microsoft names the three load-bearing engineering features that move Kerberos from "domain-only" to "load-bearing-for-everything".

The plan has four moving parts. Each one closes a specific reason that NTLM survived for thirty years.

### IAKerb: Kerberos without KDC line-of-sight

The structural reason NTLM lived through Server 2003, Server 2008, Server 2012, and Server 2019 is that Windows had no Kerberos-equivalent path for the case where a client cannot reach a KDC. A laptop on a hotel network, a hybrid Azure-joined workstation that can reach the application server but not the AD DC, a workgroup machine attempting to access a domain file share: all of those flowed back to NTLM by default, because Kerberos required a working AS-REQ to the domain controller before it could mint a TGT.

IAKerb (Initial and Pass Through Authentication Using Kerberos V5 and the GSS-API) closes that gap. The draft IETF specification, draft-ietf-kitten-iakerb, is by Benjamin Kaduk, Jim Schaad, Larry Zhu, and Jeffrey E. Altman [728]. The mechanism is GSS-API encapsulation: the client wraps each AS-REQ, AS-REP, TGS-REQ, and TGS-REP message inside a GSS-API token addressed to the application server, and the application server proxies the token to the KDC the server *can* reach. From the client's perspective, it is talking to the application server; from the KDC's perspective, the AS exchange came from the application server. The protocol's verbatim problem statement reads: "encapsulating the Kerberos messages inside GSS-API tokens. With these extensions a client can obtain Kerberos tickets for services where the KDC is not accessible to the client, but is accessible to the application server" [728].

> **Definition: IAKerb.** Initial and Pass Through Authentication Using Kerberos V5 and the GSS-API. An extension to GSS-API Kerberos (RFC 4121) that encapsulates Kerberos AS / TGS exchanges inside GSS-API tokens between client and application server, so the application server can proxy them to a KDC the server can reach but the client cannot. Documented in the IETF draft `draft-ietf-kitten-iakerb` by Kaduk, Schaad, Zhu, and Altman [728].

> **Definition: Local KDC.** A Kerberos Key Distribution Center for a workgroup or Azure-joined machine's local-account world. Public roadmap material and the FOSDEM localkdc work describe tickets backed by the local account database and reached through the IAKerb/application-protocol path rather than a classic domain-KDC line-of-sight requirement. It closes the "local account auth has no KDC" gap that has kept NTLM alive for workgroups since Windows NT 3.1; exact Windows process placement and key handling remain implementation details unless Microsoft documents them at protocol-spec level [717] [782].

MIT krb5 added IAKERB support nearly sixteen years before Windows' planned broad enablement. The
README for krb5-1.9, released December 22, 2010, says verbatim: "Add support for IAKERB. A
mechanism for tunneling Kerberos KDC transactions over GSS-API, enabling clients to authenticate
to services even when the clients cannot directly reach the KDC that serves the services" [783]
[784]. The capability sat in MIT's mainline Kerberos for over a decade. Windows did not ship the
equivalent because, until NTLM was on a deprecation path, Windows did not need it: NTLM filled
the line-of-sight gap. Once NTLM was on the road to removal, IAKerb stopped being optional.
*(Note: The nearly sixteen-year gap between MIT krb5-1.9 IAKERB (December 22, 2010) and
Microsoft's planned H2 2026 broad enable is the cleanest evidence that Microsoft's NTLM
deprecation is the *forcing function* for the Kerberos refit, not a side effect. The
specification was waiting for the customer demand to catch up.)*

### Local KDC: Kerberos for the workgroup

The second structural reason NTLM survived was that Windows local accounts had no concept of "domain". Without an AD domain, there was no KDC. Without a KDC, there were no Kerberos tickets. Local-account authentication therefore flowed through NT challenge-response (NTLMv2) by default.

Local KDC closes this. The Local KDC, shipping in Windows 11 24H2 and Server 2025 with broad enablement targeted for H2 2026 [717], is a Kerberos KDC built directly on top of the local SAM database. Microsoft's public direction is AES-keyed Kerberos over the local account database rather than NTLM challenge-response; based on the cited roadmap and the FOSDEM localkdc design, the expected access path is IAKerb encapsulation inside application protocols rather than a newly exposed general-purpose KDC service. Treat exact SAM-to-key derivation and in-memory handling as implementation details unless Microsoft documents them at protocol-spec level.

The parallel open-source path was demonstrated by Alexander Bokovoy and Andreas Schneider at FOSDEM 2025, where they presented "localkdc: A General Local Authentication Hub" [782]. The abstract reads verbatim: "A local Kerberos Key Distribution Center (KDC) is not a new invention. It is a useful tool in combination with the Kerberos IAKerb extension but also allows to map SSO from a web authentication to local authentication or in a network environment isolated from the rest of the enterprise environment... how use of NTLM in SMB protocol will be replaced by a localkdc in combination with IAKerb" [782]. Samba 4.21 carries the prototype implementation.

> **Aside: What FOSDEM 2025 confirmed.** The Bokovoy / Schneider talk is the cleanest external evidence that Local KDC is a *protocol-level* architecture, not a Microsoft-proprietary one. Samba, Heimdal, MIT krb5, and Microsoft are converging on the same design: an in-process KDC, GSS-API-tunnelled Kerberos exchanges, AES-keyed local accounts. The IETF draft-ietf-kitten-iakerb specification [728] is the shared standardization layer.

> Add support for IAKERB: a mechanism for tunneling Kerberos KDC transactions over GSS-API, enabling clients to authenticate to services even when the clients cannot directly reach the KDC that serves the services.: MIT krb5-1.9 release notes, December 22, 2010 [783]

### PKINIT and the freshness extension

The third gap NTLM filled was non-password credentials. Windows Hello for Business (developed later in Chapter 20), smart cards, and Federal Information Processing Standard token logon all need to translate "I hold this private key" into "I hold this Kerberos TGT". PKINIT (Public Key Cryptography for Initial Authentication in Kerberos), RFC 4556, by Larry Zhu (Microsoft) and Brian Tung (Aerospace Corporation), is the protocol for that [749]. The AS-REQ carries a `PA-PK-AS-REQ` PA-DATA element wrapping an `AuthPack` CMS structure signed by the client's private key; the AS-REP carries a TGT encrypted to `krbtgt` (opaque to the client) alongside a client-visible reply part protected by a reply key established through RSA key transport or Diffie-Hellman key agreement, and decrypting that reply part yields the TGT session key.

The 2006 RFC 4556 PKINIT had a freshness gap: because the `signedAuthPack` proved possession of the private key only against the client's own timestamp, a party holding a previously- or pre-signed `AuthPack` could authenticate without proving *current* possession of the key. RFC 8070, "PKINIT Freshness Extension," by Michiko Short, Seth Moore, and Peter Miller of Microsoft (February 2017) closed it [751]. The AS-REP issues an opaque `PA-AS-FRESHNESS` blob in a preliminary KDC-error round-trip; the client must echo the blob in its next signed AS-REQ; replays after the freshness window fail. Verbatim from RFC 8070 abstract: "exchange an opaque data blob that a Key Distribution Center (KDC) can validate to ensure that the client is currently in possession of the private key during a PKINIT Authentication Service (AS) exchange" [751].

Together, RFC 4556 plus RFC 8070 anchor every modern non-password Windows credential: Windows Hello for Business, smart-card logon, FIDO2 keys mediated by Windows Hello, and the upcoming Entra-issued cloud TGTs. The 2022 Certifried CVE [769] forced the *strong-mapping* layer on top of all of this: every certificate used for PKINIT must carry an X.509 extension binding it to a specific AD account SID. KB5014754 [770] tracks the rollout, including the Compatibility, Enforcement, and rollback-removal dates.

### FAST armoring as default

The fourth gap was the trust assumption at the start of an AS-REQ: the encrypted-timestamp pre-auth blob, `PA-ENC-TIMESTAMP`, is keyed under the client's password-derived key, which is offline-crackable on observation. FAST (RFC 6113) wraps the AS-REQ inside an armor envelope keyed under a separate key the attacker does not see [750]. In a domain-joined client the armor key is derived from the machine account's TGT; in a non-domain-joined client it is derived from an anonymous PKINIT TGT; in a compound-identity scenario it is the combination of both.

What changes in the 2023 plan is the *default-on* posture: Authentication Policy Silos can require constrained authentication policy for silo members, and FAST is the protocol tool for armoring the exchange. For Local KDC clients, anonymous-PKINIT or equivalent armoring is the expected design pressure because a local password-derived key would otherwise become an offline-cracking target; the exact Windows default should be treated as roadmap behavior until Microsoft documents it in implementation detail.

![Figure: IAKerb encapsulation: a client with no line of sight to the KDC authenticates through the application server, which proxies the AS and TGS exchanges to a KDC it can reach. The server forwards GSS-API tokens only. It never learns the user's password or the client-side reply key.](diagrams/10-kerberos-iakerb.svg)

**Walkthrough. IAKerb encapsulation.** Treat the application server as a relay for KDC traffic, not as a KDC and not as a password verifier. Step 1: the client emits a GSS-API token whose inner payload is an AS-REQ; the application server forwards that byte string to the KDC it can reach. Step 2: the KDC's AS-REP returns to the server, which wraps it back to the client without learning the user's password or the client-side reply key. Step 3: the client uses the TGT session key it received from the AS-REP to build a TGS-REQ, again inside a GSS-API token to the server. Step 4: the server forwards TGS-REQ to the KDC and returns TGS-REP to the client. Step 5: only after the client has a service ticket does the normal AP-REQ happen. The trust boundary is therefore precise: the server is trusted for availability and message forwarding, but the cryptographic binding remains between client, KDC, and service principal. That distinction is what makes replay protection, channel binding, and downgrade detection the operational questions rather than "does the server see the password?" [728].

### The gap-to-closure mapping

| NTLM-fallback gap | Engineered closure | Primary source | Ship target |
|-------------------|--------------------|----------------|-------------|
| Client has no KDC line-of-sight | IAKerb GSS-API encapsulation | [728] | Windows 11 24H2 / Server 2025; broad enable H2 2026 [717] |
| Local accounts have no domain KDC | Local KDC over the local account database, with AES-keyed Kerberos as the direction | [717] [782] | Windows 11 24H2 / Server 2025 |
| Non-password credentials need an AS path | PKINIT (RFC 4556) + Freshness (RFC 8070) + strong mapping (KB5014754) | [749] [751] [770] | Enforcement February 11, 2025; Disabled mode removed April 2023; Compatibility mode removed Sept 9, 2025 |
| AS-REQ pre-auth is offline-crackable | FAST armoring (RFC 6113) where required by policy | [750] [778] | Available since Server 2012 R2; policy-dependent |

After decades of layered extensions, Microsoft's 2026 roadmap makes Kerberos the intended primary authentication path for many scenarios that formerly fell back to NTLM: domain-joined, workgroup, Azure-joined without AD line-of-sight, and local-account to local-account. Legacy interop and staged enablement remain the caveat. The mechanism that closes the last gap (IAKerb) is a nearly sixteen-year-old MIT protocol coming to Windows for the first time. What's left for Kerberos to fix is encryption-type hygiene, and a December 2025 Microsoft post named the calendar dates for that too.

## The Beyond-RC4 cadence

December 3, 2025. The Microsoft Windows Server Blog publishes "Beyond RC4 for Windows authentication" [760]. The post is short and unusually operational. It does not merely say that RC4 is weak. It names a three-phase rollout, names the Windows Server versions whose audit surfaces are being enhanced, and names the mid-2026 enforcement boundary as **CVE-2026-20833** [760]. Verbatim: "By mid-2026, we will be updating the domain controller default assumed supported encryption types. The assumed supported encryption types is applied to service accounts that do not have an explicit configuration defined. Secure Windows authentication does not require RC4; AES-SHA1 can be used across all supported Windows versions since it was introduced in Windows Server 2008" [760].

That sentence is doing three different kinds of work.

First, it says the change is a **KDC default-selection change**, not a client-side preference tweak. The issue is the account that has no explicit `msDS-SupportedEncryptionTypes` value. Before the default flip, a domain controller can assume broad compatibility and issue RC4 if the request and account state allow it. After the flip, that unstated account policy becomes AES-SHA1-only by assumption. The absence of configuration stops being permissive.

Second, it says the migration destination is **AES-SHA1**, meaning RFC 3962 enctypes 17 and 18, not AES-SHA2. That is not because AES-SHA2 is absent from Kerberos. RFC 8009 exists [762], and `[MS-KILE]` already defines supported-encryption-types bits K and L for `AES128-CTS-HMAC-SHA256-128` and `AES256-CTS-HMAC-SHA384-192` [758]. The practical reason is ecosystem coverage: AES-SHA1 has been available across supported Windows versions since Server 2008 [761] [760]. A default flip can survive only if the ordinary Windows estate already knows the destination enctype.

Third, it changes the meaning of "we have not set that attribute". In old estates, many service accounts have blank `msDS-SupportedEncryptionTypes` because the directory object predates AES hygiene, because the account was created by an installer, or because the service owner never had to care. The Beyond-RC4 cadence turns that blank into an operational risk register: every blank service account is either silently compatible with AES or about to become a Phase-3 incident.

The rollout has three phases.

**Phase 1, January 2026, audit only.** Domain controllers gain new fields in Event ID 4768 (TGT issued) and Event ID 4769 (TGS issued): `msDS-SupportedEncryptionTypes`, `Available Keys`, and `Session Encryption Type` [760]. Those are the three fields a defender needs to distinguish policy from reality. `msDS-SupportedEncryptionTypes` answers "what did the directory say this account supports?" `Available Keys` answers "which long-term keys did the KDC actually have material for?" `Session Encryption Type` answers "which enctype did this ticket actually use?" Without all three, teams confuse an account that is configured for AES with a client that still negotiated RC4, or a client that prefers AES with a service account whose key material was never regenerated.

The same phase ships two PowerShell auditing scripts in the `microsoft/Kerberos-Crypto` repository. `List-AccountKeys.ps1` enumerates accounts and configured encryption support. `Get-KerbEncryptionUsage.ps1` parses the 4768 / 4769 stream and reports accounts still requesting or receiving RC4 tickets [760]. This pairing matters. Directory inventory alone over-reports risk because many RC4-capable accounts never receive tickets. Event inventory alone under-reports risk if the lookback window misses a monthly job, a disaster-recovery workflow, or a linked-server path that runs only during close. A masterclass audit needs both views and the join between them.

**Phase 2, April 2026, default flip.** The assumed `msDS-SupportedEncryptionTypes` on accounts with no explicit setting changes from "broad compatibility, including RC4 when negotiated" to "AES-SHA1 only" [760]. On paper this is safe for supported Windows because AES-SHA1 has been present since Server 2008 [761]. In production, the breakage concentrates in places that were never managed as Windows-first Kerberos: old Linux keytabs generated when RC4 was still the practical default, network-attached-storage appliances with embedded Kerberos libraries, Java stacks pinned to old JGSS behavior, SQL Server linked servers using manually managed SPNs, and vendor appliances whose service account password was last reset before AES key material was populated.

The subtle failure mode is key material, not just policy. A service account can advertise AES, but if its password has not been reset since AES keys were expected, the KDC may not have the AES long-term key needed to issue an AES ticket. That is why "reset the service account password" appears in nearly every Kerberoasting hardening roadmap: the password reset is the event that derives and stores fresh key material for the selected enctypes. gMSA and dMSA avoid this human-managed key-material trap by making rotation structural rather than calendar-driven [764] [765].

**Phase 3, mid-2026, enforcement: CVE-2026-20833.** RC4 tickets require explicit per-account opt-in. The enforcement boundary is **CVE-2026-20833**, called out by name in the December 2025 Microsoft post [760]. After that boundary, an account that has not had `msDS-SupportedEncryptionTypes` explicitly written to include `0x4` for RC4 should not receive RC4 tickets merely because the old default was permissive. Domain controllers will reject requests that ask for RC4 against accounts now configured, or assumed, to be AES-only [760].

> **Phase 3: enforcement. CVE-2026-20833.** Treat the CVE name as the operational deadline, not as trivia. It is the point at which "RC4 worked because nobody configured the account" stops being a compatibility feature. If a production service still needs RC4 after that boundary, the dependency must be explicit on the account, documented as an exception, monitored through 4768 / 4769, and attached to a remediation owner [760].

The secure-state table is small enough to memorize.

| Account state | Phase-1 audit meaning | Phase-3 outcome |
|---------------|-----------------------|-----------------|
| `msDS-SupportedEncryptionTypes` blank, no RC4 events | Candidate for safe default flip; still validate key material | Assumed AES-SHA1-only |
| Blank, RC4 observed in 4768 / 4769 | Hidden dependency; investigate client, keytab, appliance, or service password age | Breaks unless fixed or explicitly opted in |
| Explicit `0x18` | AES-128 + AES-256 SHA1; no RC4 | Desired ordinary state |
| Explicit `0x1C` | AES plus RC4 exception | Continues only as a named exception |
| Explicit `0x4` or RC4-only keytab | Legacy dependency | Highest-risk Phase-3 incident |

The security reason is the string-to-key gap from the wire section. RC4-HMAC's long-term key is the NT hash: `MD4(UTF-16-LE(password))`, with no salt and no iteration [759] [763]. AES-SHA1 uses PBKDF2-HMAC-SHA1 with a salt and 4096 iterations under RFC 3962 [761]. AES does not make a weak password safe, but it removes the direct NT-hash equivalence that made Kerberoasting so cheap. Microsoft states the operational point plainly in the October 2024 Kerberoasting guidance: "RC4 is more susceptible to the cyberattack because it uses no salt or iterated hash when converting a password to an encryption key" [763]. The Beyond-RC4 cadence is that sentence turned into a domain-controller default.

The interesting question is why the destination is not AES-SHA2. RFC 8009 has been published since 2016 [762]. MIT krb5 shipped RFC 8009 support in version 1.15 in December 2016 [785]. `[MS-KILE]` has the bit definitions [758]. Cross-implementation interop is not the missing theorem. The missing piece is a Windows rollout cadence with the same three properties RC4 now has: event-log instrumentation that proves which tickets use SHA1-based enctypes, a default flip that can survive the supported-client matrix, and an enforcement boundary that forces old key material and third-party stacks into the light.

> **Key idea.** The cadence Microsoft has demonstrated is **audit, default, enforce**. RC4 to AES-SHA1 has all three: Phase-1 event and script instrumentation, a Phase-2 assumed-default flip, and Phase-3 enforcement via CVE-2026-20833 [760]. AES-SHA1 to AES-SHA2 has specifications and directory bits, but no announced audit/default/enforce ladder. That absence is the next cryptographic roadmap gap, not evidence that Kerberos is stuck on RC4.

![Figure: The Beyond-RC4 three-phase cadence: audit (January 2026), default flip to AES-SHA1 (April 2026), and enforcement gated on CVE-2026-20833 (mid-2026). It is the staged audit, default, and enforce sequence that the still-pending AES-SHA1 to AES-SHA2 migration lacks.](diagrams/10-kerberos-beyond-rc4.svg)

**Walkthrough timeline: Beyond-RC4.** In January 2026 the KDC begins telling you what it is issuing: account policy, available keys, and selected session encryption type. In April 2026 accounts without explicit enctype settings stop inheriting RC4 compatibility and instead inherit AES-SHA1. In mid-2026, at the CVE-2026-20833 enforcement boundary, RC4 survives only where an administrator deliberately writes the RC4 bit back onto the account. The defender's job before the boundary is to make every RC4 dependency visible, choose whether it is a temporary exception or a migration bug, and move every human-managed SPN account to gMSA or dMSA where possible [760] [764] [765].

## Verify it yourself (documented): Evidence plan and documented surfaces

This chapter does not claim a private lab capture. There is no hidden VM transcript, no pasted packet capture, and no invented hash. The evidence below is therefore deliberately tagged 🔵 **DOCUMENTED**: it is a reproducible collection plan tied to Microsoft-documented surfaces and to the cited Kerberos sources. A reader with a Windows domain can run it, save raw outputs, compute hashes, and attach the resulting manifest to their own change record. The standard is masterclass evidence discipline without pretending that this book captured your environment.

A complete capture has four layers.

1. **Local cache evidence** proves what one logon session holds: TGTs, service tickets, flags, lifetimes, and ticket enctypes.
2. **KDC event evidence** proves what the domain controller issued across many principals: 4768 for AS/TGT issuance, 4769 for TGS/service-ticket issuance, and the January-2026 Beyond-RC4 fields [760].
3. **Directory-state evidence** proves what policy and key material the KDC was supposed to use: SPNs, `msDS-SupportedEncryptionTypes`, `userAccountControl`, delegation attributes, machine-account quota, and gMSA/dMSA placement.
4. **Hash-manifest evidence** proves that the exported files did not change after capture.

> 🔵 **DOCUMENTED**: Windows `klist` ticket-cache behavior and Microsoft Kerberos overview [739]

Reproduce on a domain-joined client after accessing a file share and an HTTP service:

```powershell
klist tickets | Tee-Object -FilePath .\evidence-klist-tickets.txt
Get-FileHash .\evidence-klist-tickets.txt -Algorithm SHA256
```

Expected surfaces, not expected literal values:

```text
Current LogonId is ...
Cached Tickets: (...)

#0>     Client: alice @ CONTOSO.COM
        Server: krbtgt/CONTOSO.COM @ CONTOSO.COM
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x...
        Start Time: ...
        End Time: ...
        Renew Time: ...

#1>     Client: alice @ CONTOSO.COM
        Server: cifs/fs01.contoso.com @ CONTOSO.COM
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x...
```

Interpretation: `krbtgt/CONTOSO.COM` is the TGT. `cifs/fs01.contoso.com` is a service ticket. The encryption-type line proves the selected ticket enctype for this cache entry; it does not prove that every service account in the domain is AES-only. The start/end/renew fields prove the ticket lifetime that bounds PAC staleness. The flags are where forwardable and renewable behavior becomes visible for delegation analysis [741] [739].

> 🔵 **DOCUMENTED**: KDC issuance stream, Security Events 4768 and 4769, including Beyond-RC4 audit fields [760]

Reproduce on a domain controller:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4768,4769} -MaxEvents 200 |
Select-Object TimeCreated,Id,ProviderName,Message |
Tee-Object -FilePath .\evidence-kdc-4768-4769.txt
Get-FileHash .\evidence-kdc-4768-4769.txt -Algorithm SHA256
```

Expected surfaces after the January 2026 enhancements include fields for configured encryption support, available keys, and session encryption type [760]. The useful reading is not "do I see AES anywhere?" It is the join: which account requested or received RC4, which account lacked explicit `msDS-SupportedEncryptionTypes`, and whether the session enctype contradicts the policy you thought was deployed.

> 🔵 **DOCUMENTED**: Directory encryption policy for SPN-bearing accounts via `[MS-KILE]` supported-encryption-types bits [758]

Reproduce from a management host with the Active Directory module:

```powershell
Get-ADObject -LDAPFilter '(servicePrincipalName=*)' `
-Properties servicePrincipalName,msDS-SupportedEncryptionTypes | `
Select-Object Name,ObjectClass,servicePrincipalName,msDS-SupportedEncryptionTypes | `
Export-Csv .\evidence-spn-enctypes.csv -NoTypeInformation
Get-FileHash .\evidence-spn-enctypes.csv -Algorithm SHA256
```

Expected policy reading:

```text
0x04  RC4-HMAC
0x08  AES128-CTS-HMAC-SHA1-96
0x10  AES256-CTS-HMAC-SHA1-96
0x18  AES128 + AES256, no RC4
0x1C  AES128 + AES256 + RC4 exception
```

An SPN-bearing user account with a blank value is not automatically vulnerable in the same way in every phase. Before Phase 2, blank may inherit RC4 compatibility. After Phase 2, blank should inherit AES-SHA1-only. During audit, blank plus observed RC4 in 4769 is the evidence combination that matters [760] [758].

> 🔵 **DOCUMENTED**: Kerberoasting exposure inventory: SPNs, manual service accounts, and gMSA/dMSA migration targets [763] [764] [765]

Reproduce:

```powershell
setspn -Q */* | Tee-Object -FilePath .\evidence-setspn-all.txt
Get-ADServiceAccount -Filter * -Properties PrincipalsAllowedToRetrieveManagedPassword |
Export-Csv .\evidence-managed-service-accounts.csv -NoTypeInformation
Get-FileHash .\evidence-setspn-all.txt -Algorithm SHA256
Get-FileHash .\evidence-managed-service-accounts.csv -Algorithm SHA256
```

Interpretation: every SPN maps to an account whose long-term key can receive service tickets. Human-managed user accounts in this list are the Kerberoasting risk class because their password quality is human, their key material may be old, and their `msDS-SupportedEncryptionTypes` may be blank. gMSA and dMSA are the structural migrations because they remove human password choice and rotate secrets through domain-controller machinery [763] [764] [765].

> 🔵 **DOCUMENTED**: Delegation and RBCD exposure inventory [691] [693]

Reproduce:

```powershell
(Get-ADDomain).'ms-DS-MachineAccountQuota' |
Tee-Object -FilePath .\evidence-machine-account-quota.txt
Get-ADObject -LDAPFilter '(|(msDS-AllowedToDelegateTo=*)(msDS-AllowedToActOnBehalfOfOtherIdentity=*))' `
-Properties msDS-AllowedToDelegateTo,msDS-AllowedToActOnBehalfOfOtherIdentity,servicePrincipalName |
Export-Csv .\evidence-delegation-attributes.csv -NoTypeInformation
Get-FileHash .\evidence-machine-account-quota.txt -Algorithm SHA256
Get-FileHash .\evidence-delegation-attributes.csv -Algorithm SHA256
```

Interpretation: a nonzero machine-account quota preserves the first move in many RBCD chains. `msDS-AllowedToActOnBehalfOfOtherIdentity` is the resource-side security descriptor that decides who may obtain S4U2Proxy tickets to the target. `msDS-AllowedToDelegateTo` is the older constrained-delegation list. These attributes are not vulnerabilities by themselves; they are the directory state that explains whether the S4U2Self / S4U2Proxy path is reachable [691].

> 🔵 **DOCUMENTED**: Pre-authentication-disabled accounts for AS-REP roasting exposure [738]

Reproduce:

```powershell
Get-ADUser -LDAPFilter '(userAccountControl:1.2.840.113556.1.4.803:=4194304)' `
-Properties userAccountControl,servicePrincipalName,msDS-SupportedEncryptionTypes |
Select-Object SamAccountName,Enabled,userAccountControl,servicePrincipalName,msDS-SupportedEncryptionTypes |
Export-Csv .\evidence-asrep-preauth-disabled.csv -NoTypeInformation
Get-FileHash .\evidence-asrep-preauth-disabled.csv -Algorithm SHA256
```

Interpretation: this list should be empty unless a legacy exception is documented. FAST does not save an account that has pre-authentication disabled because the vulnerable behavior is the absence of the pre-authentication proof in the first place. The fix is to re-enable pre-authentication or retire the account.

Finally, build a manifest. Use whatever evidence directory your change-management process allows; the point is that the manifest is generated after collection and stored with the ticket.

```powershell
Get-ChildItem .\evidence-* | Get-FileHash -Algorithm SHA256 |
  Sort-Object Path |
  Format-Table Algorithm,Hash,Path -AutoSize |
  Tee-Object -FilePath .\evidence-manifest-sha256.txt
```

A captured masterclass appendix would contain the real hashes and representative redacted outputs from that manifest. This book does not fabricate them. It gives the exact surfaces that prove the chapter's claims: local tickets show TGT/service-ticket/session-key consequences; KDC events show issued enctypes; directory attributes show policy; delegation attributes show S4U reachability; hashes make the capture stable enough to review.

## What removing NTLM cannot buy you

After everything in the IAKerb/Local KDC and Beyond-RC4 sections ships, Kerberos in 2026 is still vulnerable to four classes of attack. None of them are protocol bugs; all of them are protocol *structure*.

**Kerberos has its own relay class.** The KrbRelayUp README explicitly scopes itself to Windows domain environments where LDAP signing is not enforced: the post-NTLM cousin of NTLM-relay [693]. The relay primitive survives the move from NTLM to Kerberos because the attack does not target the authentication protocol. It targets the LDAP protocol's lack of mandatory integrity, and any authenticated bind (Kerberos or NTLM) is fair game once the channel is unsigned. The dispositive control is LDAP signing plus channel binding domain-wide, plus Extended Protection for Authentication on every AD CS Web Enrollment endpoint. It is a configuration, not a protocol fix. The Death of NTLM chapter (Chapter 16) walks through the LDAP-signing and channel-binding work in detail.

**The long-term-key problem is intrinsic to symmetric Kerberos.** Whoever holds the `krbtgt` account's long-term key forges any TGT (the Golden Ticket primitive); the standing compromise of that one account, and the dual-rotation procedure that recovers from it, are owned by the KRBTGT chapter (Chapter 18). Whoever holds an SPN account's long-term key forges any TGS for that service (the Silver Ticket primitive). RFC 4120's local AP-REQ design [741] *requires* that the service make the service-ticket decision without a per-request KDC callback: it decrypts the ticket, checks the authenticator, and validates the PAC material it is equipped and required to validate. Any change that adds an online "is this ticket still valid?" check also gives up Kerberos's O(1) service-side scaling and the local-acceptance property that makes the protocol cheap. Authentication Policy Silos, Protected Users, TPM-backed credentials, and Credential Guard all raise the cost of obtaining the key; they do not close the forge-equivalence property. Mathematically, if you have the key, you are the principal.

**The PAC is a signed vouching token, not a verified live query.** KrbtgtFullPacSignature [755] closes the *modification* side (PAC tampering by parties that do not hold the krbtgt key). It does not close the *staleness* side. A user removed from `Domain Admins` at 09:00 still presents service tickets attesting Domain Admin membership until the ticket expires (default 10 hours user TGT, 7 days renewable; Protected Users members are capped at 4 hours [672]). The PAC vouching window is the residual stale-authorization gap. The defender's option is shorter ticket lifetimes or out-of-band ACL flips at the service tier; the protocol itself has no callback by which a service learns about a group-membership change before the ticket expires.

**Domainless does not mean keyless.** Local KDC moves the local-account path toward AES-keyed Kerberos rather than NTLM challenge-response. The wire form of pass-the-hash is the target for removal: no `LMv2` challenge response should be needed on that path. But do not treat that as keylessness. A `NT AUTHORITY\SYSTEM`-level attacker on the box remains in the local TCB, and unless Microsoft documents stronger isolation for Local KDC key material, defenders should assume local Kerberos keys and the tickets they mint still need the chip-, VBS-, and Credential Guard protections described elsewhere in this book. The chip- and VBS-based countermeasures (TPM-backed credentials, Microsoft Pluton, and the VTL1 isolation the Credential Guard chapter (Chapter 15) owns) remain orthogonal and necessary; none of them is replaced by Local KDC, and none extends to the *tickets* the key then mints.

> **Key idea.** H2 2026 ships Kerberos as the load-bearing single authentication protocol; it does not ship a Kerberos in which (1) the Kerberos-relay class is closed, (2) long-term-key forge-equivalence is closed, (3) PAC staleness is closed, or (4) local-key recovery from a SYSTEM-level attacker on the box is closed. The arc is a transition between tradeoffs, not out of them.

> **Aside: the paired diagnosis.** The Death of NTLM chapter (Chapter 16) and this one are two halves of a single transition: that chapter is the eulogy and the migration story for the protocol being retired; this one is the inheritance and the to-do list for the protocol that absorbs the load. Both end on the same shape: moving from NTLM to Kerberos is a transition *between* tradeoffs, not *out* of them.

## Open problems and the 2026-2027 Edge

Six problems sit on the May-2026 research agenda. None has a shipping Microsoft answer. The important part is not that these are "unknown unknowns"; they are known engineering seams where the source material names a direction but not a complete cadence.

**1. The AES-SHA1 to AES-SHA2 Windows-default timeline.** RFC 8009 [762] is nine years old. `[MS-KILE]` §2.2.7 already includes the AES-SHA2 bits K and L [758]. MIT krb5 shipped RFC 8009 in version 1.15 in December 2016 [785]. The cryptographic destination is therefore not speculative. What is missing is the operational ladder.

The RC4 transition shows what a real ladder looks like: first event fields and scripts that show actual ticket issuance, then a default flip for unset accounts, then enforcement with a named boundary [760]. AES-SHA2 has none of those public Windows milestones. A serious AES-SHA2 plan would need 4768 / 4769 fields that distinguish AES-SHA1 from AES-SHA2 at the same operational granularity as the Beyond-RC4 fields; a directory inventory that shows which principals have key material for enctypes 19 and 20; a client-compatibility matrix for older Java, NAS, MIT, Heimdal, appliance, and cross-forest stacks; and a password-reset or managed-account migration plan to ensure the KDC actually has AES-SHA2 keys to issue. The hard part is not the RFC. It is proving that every SPN-bearing account, every trust path, and every non-Windows client can survive the default.

**2. Post-quantum PKINIT migration mechanics.** Kerberos's symmetric core is not the first quantum failure point. AES-128 and AES-256 under Grover's algorithm retain an effective security margin of roughly 64 and 128 bits respectively; AES-256 remains a durable symmetric choice for the horizon relevant to enterprise migrations [111]. PKINIT is different. RFC 4556 authenticates the client with CMS structures in `PA-PK-AS-REQ`, including RSA or Diffie-Hellman profiles and certificate chains whose ordinary signatures are RSA or ECDSA [749]. Shor's algorithm breaks the public-key assumptions behind those chains.

That creates three migration problems, not one. The first is the **certificate-chain problem**: domain controllers validate an X.509 chain for smart cards, Windows Hello for Business, and certificate-based logon. A post-quantum PKINIT path needs a certificate ecosystem, not merely a new Kerberos enctype. The second is the **AuthPack signature problem**: the client's proof of private-key possession has to move from RSA/ECDSA to a post-quantum or hybrid signature without breaking old KDCs. The third is the **FAST armor problem**: anonymous PKINIT is one way to obtain armor for non-domain-joined clients, including Local KDC scenarios. If the anonymous PKINIT chain is quantum-fragile, then the protection around the first AS-REQ inherits that fragility.

The practical migration is likely to be hybrid before it is pure post-quantum: classical PKINIT plus a post-quantum signature or key-establishment component, policy bits that say which KDCs require the hybrid, and audit events that identify clients still presenting classical-only credentials. Microsoft has not announced such a PKINIT-specific roadmap in the cited material. The honest status is therefore: Kerberos tickets can remain AES-256; PKINIT's certificate and CMS layer needs a separate post-quantum cadence [749] [111].

**3. IAKerb and Local KDC trust boundaries.** The IAKerb draft closes KDC line-of-sight by letting the application server proxy AS and TGS traffic [728]. That is elegant, but it moves an operational trust boundary into every protocol that carries the GSS-API tokens. The application server should not learn the user's long-term key, should not be able to modify the inner Kerberos messages without detection, and should not be able to silently downgrade the client from Kerberos to NTLM or from armored to unarmored pre-auth. Those properties are not magic; they depend on strict mechanism negotiation, replay handling, channel binding to the outer application session, and clear failure behavior when the KDC path is unavailable.

The failure modes are worth naming. If the server can choose between ordinary Kerberos, IAKerb, NTLM, and local-account paths, then the negotiation transcript matters: a downgrade that says "KDC unreachable, try NTLM" is exactly the kind of fallback the NTLM deprecation is meant to end. If the server proxies KDC traffic over an application channel that lacks binding to the final AP exchange, then a relay-shaped confusion bug becomes plausible even though the inner Kerberos cryptography is sound. If Local KDC material is available to LSASS without stronger isolation, then SYSTEM-level compromise of the host remains key compromise even though the wire no longer carries NTLM challenge-response. If the client cannot distinguish "KDC said no" from "server did not forward the token," troubleshooting becomes a security problem: operators will be tempted to re-enable fallback to make the outage disappear.

The masterclass defensive posture is therefore to log IAKerb as its own authentication path, not as generic Kerberos; bind the inner exchange to the outer channel wherever the application protocol supports channel binding; treat Local KDC keys as high-value local secrets that still require Credential Guard, TPM-backed protections, and OS hardening; and make downgrade failures loud. The source tells us IAKerb and Local KDC are the closure for line-of-sight and workgroup gaps [717] [782]. The open problem is proving those closures do not recreate silent fallback under a different name.

**4. dMSA field-deployment maturity.** Server 2025 introduced Delegated Managed Service Accounts as the successor to gMSA [765]. The protocol-level direction is strong: authentication is linked to device identity, and the randomized secret is held by the domain controller rather than recoverable as a shared human-managed password [765]. That directly targets the Kerberoasting class because the best roasted ticket is useless if the underlying service secret has machine-grade entropy and rotates under KDS control.

The field question is migration, not theory. Existing services have SPNs, ACLs, SQL logins, constrained-delegation settings, certificate bindings, and monitoring identities attached to old user accounts. A dMSA migration has to preserve those dependencies while changing the secret source and, in some workflows, the account identity. The source notes startup and migration windows in which both the legacy account and dMSA behaviors may coexist [765]. That overlap is the dangerous period: logs must show which account actually received the TGS; service owners must know which identity owns downstream ACLs; and defenders must avoid interpreting the presence of dMSA as proof that the old account no longer receives tickets. Until dMSA becomes the default creation path for new services and the migration tooling is boring, gMSA remains the known-good floor and dMSA the direction of travel.

**5. Cross-cloud Kerberos trust graphs.** Kerberos Cloud Trust for Windows Hello for Business lets an Entra-joined laptop obtain domain-usable Kerberos outcomes without the laptop behaving like a classic line-of-sight domain client [717]. Local KDC gives workgroup or Azure-joined machines a way to issue local tickets over the local account database [717] [782]. IAKerb lets a server proxy KDC exchanges when the client cannot reach the KDC [728]. Each component is understandable alone. The open problem is the graph when all three coexist with on-premises AD.

Draw three issuers: an on-premises KDC, Entra ID acting through Cloud Trust, and a Local KDC inside the endpoint. Draw three relying parties: a domain file server, a cloud-managed application, and a local SMB or RDP service. Then ask four questions for every edge. Who minted the ticket or token? Which long-term key or certificate chain anchors it? Which directory owns the authorization attributes? Which log stream is authoritative when the edge fails or is abused? In a classic AD-only Kerberos path, the answers are mostly "the domain controller" and "the PAC." In a hybrid path, the answers can split: Entra may authenticate the user, AD may authorize access to an on-premises resource, Local KDC may handle local accounts, and IAKerb may carry the messages through an application server.

That split creates new governance work. Incident responders need to correlate Entra sign-in logs, domain-controller 4768 / 4769 events, endpoint Local KDC telemetry, and service AP-REQ acceptance. Access reviewers need to know whether group membership came from AD, cloud, or a synchronized projection. Architects need explicit rules for which issuer is allowed to speak for which resource class. The source material says the architecture is planned and shipping in stages [717]. It does not yet provide the full trust-graph operating model. That is the cross-cloud Kerberos problem: not "can a ticket be minted?" but "can the enterprise explain every issuer-to-resource edge under failure and compromise?"

**6. Open-source IAKerb and Local KDC convergence.** Samba's `localkdc` work, demonstrated by Alexander Bokovoy and Andreas Schneider at FOSDEM 2025, is the clearest public mirror of Microsoft's Local KDC direction [782]. MIT krb5 has had IAKERB support since krb5-1.9 in December 2010 [783] [784]. Heimdal has partial coverage. The conceptual pattern (a Kerberos KDC backed by a local identity store and reachable through GSS-API encapsulation) is not Microsoft-only. That is good for protocol confidence and hard for interoperability testing.

The convergence test is whether a Windows client, Samba server, MIT or Heimdal library, and Windows domain controller all make the same decisions about mechanism negotiation, channel binding, enctype selection, PAC-like authorization data, and failure fallback. If they do, Local KDC becomes a real ecosystem pattern. If they do not, the industry recreates the old NTLM problem in a new form: a theoretically better protocol with enough implementation-specific exception paths that the weakest fallback dominates. The FOSDEM evidence says the ecosystem is moving in the same direction [782]. The open problem is the conformance suite.

Each problem is a residual. None invalidates the Phase-3 shipping commitment. H2 2026 is not the end state; it is the point where Windows authentication moves from "Kerberos except when NTLM is easier" to "Kerberos everywhere, with the remaining tradeoffs exposed." The next decade's work is making those tradeoffs auditable: AES-SHA2 defaults, post-quantum PKINIT, IAKerb downgrade safety, dMSA migration, hybrid trust graphs, and cross-implementation conformance.

## What it means for you

The practical payoff is not a new trick; it is a trust map. You are looking for accounts with SPNs, accounts with weak or legacy enctypes, accounts with pre-authentication disabled, writable delegation attributes, nonzero machine-account creation quota, and KDC events that show RC4 still being issued. Run the following as an inventory probe, not as an exploit:

```powershell
Import-Module ActiveDirectory

# 1. Accounts with SPNs and their encryption policy.
Get-ADObject -LDAPFilter '(servicePrincipalName=*)' `
  -Properties servicePrincipalName,msDS-SupportedEncryptionTypes | `
  Select-Object Name,ObjectClass,servicePrincipalName,msDS-SupportedEncryptionTypes

# 2. Accounts still allowed to receive AS-REP material without pre-auth.
Get-ADUser -LDAPFilter '(userAccountControl:1.2.840.113556.1.4.803:=4194304)' `
  -Properties userAccountControl | Select-Object SamAccountName,Enabled

# 3. Domain machine-account creation default that enables many RBCD chains.
(Get-ADDomain).'ms-DS-MachineAccountQuota'

# 4. Recent Kerberos ticket issuance events; inspect encryption/session fields.
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4768,4769} -MaxEvents 50 |
  Select-Object TimeCreated,Id,ProviderName,Message

# 5. Local ticket cache for the current logon session.
klist tickets
```

Read the results as a trust map. SPN-bearing user accounts with RC4 allowed are roasting candidates. Pre-auth-disabled users are AS-REP roasting candidates. A nonzero machine-account quota is delegation attack surface. Events 4768 and 4769 tell you what the KDC actually issued, not what the policy spreadsheet says it should issue.

Seven controls follow. Each is tied to one primary Microsoft Learn or MSRC source, and each closes one of the primitives from the attack-cascade section; the Death of NTLM chapter (Chapter 16) carries the parallel NTLM-side checklist.

> **1. Audit RC4 use today.** Run the two PowerShell scripts in `microsoft/Kerberos-Crypto`: `List-AccountKeys.ps1` enumerates every account's configured enctypes; `Get-KerbEncryptionUsage.ps1` parses your Event 4768 / 4769 stream and lists accounts still requesting or being issued RC4 tickets. The audit window closes in April 2026 when Phase 2 flips the default [760]. Every account on the list above is a Phase-3 production incident if you do nothing.

> **2. Set msDS-SupportedEncryptionTypes explicitly on every service account.** Do not rely on the mid-2026 default flip. Explicitly write `msDS-SupportedEncryptionTypes` with the value `0x18` (AES-128 + AES-256, no RC4) on every service account that does not have a documented RC4 dependency. For service accounts that do, write `0x1C` (AES-128 + AES-256 + RC4) and put a calendar reminder against the RC4 dependency so it gets remediated before Phase 3 [760].

> **3. Move every service account to gMSA or dMSA.** Manually-managed service-account passwords are the Kerberoasting attack surface per [763]. gMSA gives you KDS-managed password material rotated by Windows rather than by a human [764] [781]. dMSA on Server 2025 binds the account secret to the device identity and stores it only on the domain controller, where it can be further protected by Credential Guard [765]. For ordinary Windows service-account workflows, gMSA or dMSA should be the default target; products, cross-platform stacks, and vendor appliances can still impose support constraints, so the migration is usually operational but not always trivial.

> **4. Set ms-DS-MachineAccountQuota = 0 unless documented otherwise.** Setting `ms-DS-MachineAccountQuota` on the domain root to zero kills the first step of the opening RBCD chain [691] and the KrbRelayUp chain [693]. The default value of 10 has been the de facto attack-surface enabler since Windows 2000. The control is one PowerShell line: `Set-ADDomain -Identity (Get-ADDomain) -Replace @{'ms-DS-MachineAccountQuota'=0}`. The breakage surface is small: only legitimate computer-account bootstrap workflows that today rely on user-driven `djoin.exe`.

> **5. Add Tier-0 and Tier-1 accounts to Protected Users + Authentication Policy Silo with FAST.** Protected Users gives every member the five non-configurable client protections plus the 4-hour TGT cap [672]. Wrap an Authentication Policy Silo around the same population to add per-silo logon-from constraints and pair the silo with FAST armoring where the domain functional level and clients support it [750] [778]. Both controls have been available since Server 2012 R2; the operational reason most environments still have not adopted them is the breakage in legacy delegation workflows. Audit and remediate those workflows; do not skip Protected Users.

> **6. Enforce LDAP signing and channel binding.** Set `LDAPServerIntegrity = 2` (require signing) and `LdapEnforceChannelBinding = 2` (require channel binding on TLS-bound connections) via Group Policy. This is the dispositive KrbRelayUp defense [693] and the dispositive defense against any Kerberos-relay-class attack that targets the LDAP control plane. Pair with Extended Protection for Authentication on every AD CS Web Enrollment endpoint to close the AD CS HTTP-enrollment relay (ESC8) variant [770].

> **7. Plan the mid-2026 RC4 enforcement transition now.** Flight the `RC4DefaultDisablementPhase` Group Policy setting in your Insider channel; pilot non-production AES-only configurations on a representative subset of service accounts; identify legacy NAS appliances, Linux MIT krb5 clients with keytabs older than 2017, and SQL Server linked-server SPNs before Phase 2 closes the audit window [760]. Phase 3 ships with Microsoft's mid-2026 enforcement boundary; production environments that have not run the audit will discover the dependency list the day enforcement lands.

By mid-2026, every default in this list will have changed. Do the work in the audit window or do it in the post-flip ticket queue. The cost of an audit-window migration is a quarter of engineering time; the cost of a post-flip remediation is a sixty-minute outage on every undocumented RC4 dependency the directory holds. The TPM chapter (Chapter 2), the Pluton chapter (Chapter 3), and the Credential Guard chapter (Chapter 15) cover the hardware-backing layer that protects the long-term keys these controls assume.

## How to audit a domain for accounts still using RC4 (PowerShell)

The commands below assume Server 2019 or later with the `microsoft/Kerberos-Crypto` repo cloned locally. Run on a domain controller; output names every account whose configured `msDS-SupportedEncryptionTypes` allows RC4 or has no explicit setting (in which case it inherits the pre-Phase-2 default of "anything goes"). Cross-reference with the 4768 / 4769 audit stream from `Get-KerbEncryptionUsage.ps1` to identify which of those accounts is actually being issued RC4 tickets in practice.

```powershell
# Enumerate accounts and configured enctypes
Import-Module ActiveDirectory
.\List-AccountKeys.ps1 -OutputCsv accounts.csv

# Parse 4768 / 4769 events for issued ticket enctypes
.\Get-KerbEncryptionUsage.ps1 -LookbackDays 30 -OutputCsv tickets.csv

# Join the two on account name -- the accounts that
# both have RC4-allowed AND were issued RC4 tickets
# are your Phase 3 incident list.
```

> **Bequeaths.** Kerberos hands the next link a precise, load-bearing guarantee: a `krbtgt`-signed ticket plus locally decryptable service tickets whose AP exchange can be accepted without a per-request callback to the KDC, while full PAC/KDC-signature validation remains governed by Windows PAC validation rules. That local-acceptance property is exactly what makes the protocol cheap to operate, and exactly what the KRBTGT chapter (Chapter 18) interrogates at its root, because the one account whose key signs every TGT in the domain is the single point at which "whoever holds the key is the principal" becomes "whoever holds *this* key is *every* principal." The bequest stops where forgery begins: Kerberos does not protect against an adversary who already holds a long-term key (golden, silver, diamond, and sapphire tickets all live in Chapter 18); it does not make a PAC fresh or revocable mid-ticket; it does not isolate the current-session tickets that still sit in VTL0 `lsass.exe` (the Credential Guard chapter, Chapter 15, owns that residual); and it makes no claim once the identity leaves the box for the cloud (Pass-the-Hash to Pass-the-PRT, Chapter 19; Zero Trust, Chapter 26; Continuous Access Evaluation, Chapter 27). The chain has made authentication single-protocol; it has not made the long-term key un-stealable, and the account that owns the most dangerous key of all is the next link.
