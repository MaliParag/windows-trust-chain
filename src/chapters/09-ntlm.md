# The Death of NTLM

::: trust-ledger

- **Inherits:** "Long-term secrets are off the box". On a Credential-Guard box the signed-in NTOWF and the Kerberos long-term keys can no longer be read from any VTL0 process, regardless of SYSTEM or `SeDebugPrivilege` (Chapter 15, Credential Guard). That fixed *storage*; it left intact the *protocol* that made the secret worth stealing.
- **Promise:** Once the four reasons `Negotiate` fell back to NTLM are closed (no domain-controller line-of-sight, local accounts, missing SPN, and hard-coded `Ntlm` calls) Windows can disable network NTLM by default, so that possessing, relaying, or coercing a live NTLM exchange stops being a path to Active Directory compromise. Serviced boundary: the SSPI `Negotiate` authentication decision.
- **TCB:** The `Negotiate` negotiator preferring Kerberos; its IAKerb, Local KDC, and IP-SPN replacements; the NEGOEX carrier; the absence of callers that still name `Ntlm` directly; and the Group Policy that keeps NTLM default-off. Every legacy NTLM-speaking server, and any code that hard-codes `Ntlm`, sits *outside* it.
- **Adversary → Break:** NTLM is the storage-equivalence break: the stored NT hash is password-equivalent on the wire (Pass-the-Hash), and the three unbound messages are relayable and coercible (SMBRelay → PrinterBug → PetitPotam → ESC8). The Promise ends at "disabled, not removed": policy can re-enable NTLM, and the relay *class* survives intact on Kerberos.
- **Residual:** Kerberos relay and delegation abuse (KrbRelay, KrbRelayUp, RBCD, S4U) → Kerberos (Chapter 17) and KRBTGT (Chapter 18); the full Pass-the-Hash-to-Pass-the-PRT arc → Chapter 19; offline SAM-hash extraction on a SYSTEM-owned box → Mimikatz (Chapter 14) (a boundary Credential Guard, Chapter 15, explicitly does not cover); coerced-SYSTEM confused deputies → The SeImpersonate Primitive (Chapter 24).
- **Bequeaths:** Kerberos becomes the sole default interactive domain authentication protocol: every former NTLM fallback now routes through `Negotiate` → Kerberos (Chapter 17). Does NOT provide: removal of the relay class, isolation of the tickets Kerberos mints, or protection of the local SAM on a box an attacker already owns as SYSTEM.
- **Proof:** 🔵 documented: `[MS-NLMP]` wire algorithm; KB 5064479 NTLM Operational channel and the `Lsa` policy registry surfaces. No hash-gated VM capture exists for this chapter; see the Evidence note.
:::

> **The Reasoner's question.** What does Windows have to build before it can finally turn NTLM off by default, and what risks survive after it does?

---

> **Foundations. What you need before this chapter.**
>
> - **NT hash / NTOWF.** The NT hash is `MD4(UTF-16LE(password))`: sixteen bytes that function as the long-term secret for NTLM. NTLMv2 derives `NTOWFv2 = HMAC_MD5(NT-hash, UNICODE(Upper(user) || domain))`, but the root remains the NT hash.
> - **Password-equivalence.** If a protocol lets the hash produce every valid response without the plaintext password, possession of the hash is possession of the credential. That is the technical core of Pass-the-Hash.
> - **Challenge-response.** NTLM does not send the password. The server sends a challenge; the client proves it can compute the correct response from the long-term secret. That sounds safe until you notice that the long-term secret itself is reusable authority.
> - **Relay.** A relay does not steal the hash. It forwards a live `NEGOTIATE` / `CHALLENGE` / `AUTHENTICATE` exchange to a different target that accepts it as the victim.
> - **AV_PAIRS, MIC, and CBT.** NTLMv2 retrofits target names, message integrity, and TLS channel binding into the old exchange. These fields help only when both sides generate and enforce them.
> - **SPNEGO / Negotiate.** Windows applications should ask SSPI for `Negotiate`; Windows then prefers Kerberos and falls back to NTLM when Kerberos cannot run. The fallback path is the surface this chapter is about.
> - **IAKerb, Local KDC, IP-SPN, and NEGOEX.** These are the new plumbing pieces Microsoft is using to remove the historical reasons `Negotiate` fell back to NTLM: no domain-controller line-of-sight, local accounts, missing SPNs, and richer mechanism negotiation under the existing API.

---

## What NTLM is responsible for in the trust chain

NTLM is the credentials link's inherited liability. It was born before Active Directory, before Kerberos became Windows' domain default, and before defenders thought in terms of channel binding, service principal names, or relay-resistant authentication. Its original job was pragmatic: authenticate a Windows client to a Windows server without requiring a live domain controller, a registered service principal name, or even a domain at all. Those properties made it deployable. They also made it durable.

This is why the death of NTLM belongs immediately after Credential Guard in the chain. The Credential Guard chapter (Chapter 15) asks whether a compromised endpoint can still read the long-term credential. This chapter asks why a credential protocol continued letting live authentication be coerced and relayed long after the storage problem had a VBS answer.

**NTLM is the 30-year-old fallback authentication protocol that Active Directory still rests on whenever Kerberos cannot do the job, and the consequential NTLM-centered AD attack chains (pass-the-hash, NTLM relay, PetitPotam, ESC8) live in or begin from that fallback path.** Microsoft's exit plan (IAKerb, Local KDC, IP-SPN policy, and the Negotiate-everywhere refactor, carried under Negotiate/NEGOEX where needed) closes the four reasons NTLM survived, and the January 2026 roadmap names "disabled by default in the next major Windows release" as Phase 3. This chapter tells the whole arc as one story: how NTLM works on the wire, the attack classes that depend on it, exactly what is being removed, and what is not.

## The relay chain in one paragraph

![Figure: The ESC8 + PetitPotam chain as a vertical attack flow. An unauthenticated Coercer call (EfsRpcOpenFileRaw over LSARPC) makes the DC machine account NTLM-authenticate outbound as SYSTEM; ntlmrelayx forwards the live exchange to AD CS Web Enrollment, which issues a machine certificate; the certificate drives PKINIT to a DC-machine TGT, and the TGT DCSyncs the domain. Including krbtgt. The side rail shows where each retrofit sits and why it is silent: SMB signing is not in the chain (this rides LSARPC, not SMB), EPA on /certsrv/ is under-enforced, and Credential Guard has no hash to guard. The chain exploits the existence of the fallback path, not any one primitive.](diagrams/09-ntlm-esc8-relay-chain.svg)

A defender has done every retrofit Microsoft has shipped over twenty years. SMB signing enforced on every member server. EPA broadly enabled but not yet verified as required on every AD CS Web Enrollment endpoint. Credential Guard on. Restrict NTLM in audit mode. KB 5005413 applied to AD CS. An attacker with no domain credentials reaches a vulnerable coercion path on a domain controller, relays the DC machine account to `/certsrv/`, and a handful of seconds later holds a Kerberos TGT for that DC machine account: enough to DCSync the domain's secrets, including `krbtgt` [708,709,710]. Total elapsed time: less than the time it took you to read this paragraph. Total prerequisite for the chain: that NTLM still exists as a relayable fallback path on Windows.

The chain has a name. ESC8, from Will Schroeder and Lee Christensen's "Certified Pre-Owned" whitepaper, published June 17, 2021 [709,711]. Its best-known coercion primitive has another name. PetitPotam, from Gilles Lionel, published the next month [710]. Together they can take a retrofitted-but-not-bound Active Directory environment to domain compromise in four steps.

> **The chain in four steps.**
>
> 1. **Coerce.** In the historically decisive PetitPotam case, call `EfsRpcOpenFileRaw` against a domain controller over LSARPC; on vulnerable builds the service, running as SYSTEM, NTLM-authenticates back to an attacker-controlled UNC path with no domain credentials required. In the broader coercion family, the exact RPC method, server role, and authentication requirement vary by patch level and configuration [708,710].
> 2. **Relay.** `ntlmrelayx.py` from Impacket sits on the listening side and forwards the live NTLM exchange to the AD CS Web Enrollment endpoint at `/certsrv/certfnsh.asp` [712].
> 3. **Enroll.** The relayed authentication enrolls the DC's machine account for a client certificate against the `Machine` template (or any default-enabled template that allows enrollment) [711].
> 4. **Escalate.** The attacker uses the certificate to perform PKINIT against the KDC, obtains a TGT for the DC's machine account, and uses that authority to DCSync the domain's hashes (including the `krbtgt` hash) achieving full domain compromise quickly once the relay path succeeds [709].

Pause on what is and is not true here. SMB signing did not fail; SMB signing was not in the chain. EPA failed because it was deployed on IIS authentication endpoints generally but the `/certsrv/` deployment lagged [713]. Credential Guard did not fail; Credential Guard protects the NT-hash, and the attacker never touched a hash. Restrict NTLM in audit mode worked exactly as labeled: it audited.

The retrofits are not wrong. They patch the named primitives. The chain exploits the *existence* of the fallback path, not a primitive. Every protective control is honest about what it does and silent about what it does not.

> **Walkthrough: ESC8 + PetitPotam without hand-waving.**
>
> 1. The attacker sends an EFSRPC call such as `EfsRpcOpenFileRaw` to a vulnerable domain controller and supplies a UNC path that resolves to the attacker's relay host. The interesting fact is not the API name; it is that a privileged Windows service accepts a remote path and tries to reach it as the machine account. Patched systems may close that exact unauthenticated LSARPC route; Coercer exists because the confused-deputy pattern spans many RPC interfaces [708,710].
> 2. The domain controller initiates NTLM authentication to the relay host. The attacker still has no password, no NT hash, and no Kerberos ticket. The attacker only controls the TCP endpoint that receives `NEGOTIATE` and the UNC path that caused the authentication.
> 3. The relay opens a separate HTTP session to the AD CS Web Enrollment endpoint (`/certsrv/certfnsh.asp`) and forwards the NTLM messages. The CA sees a valid authentication from the DC machine account because the HMAC was computed by the DC and the endpoint did not bind the authentication to the original channel.
> 4. The relayed identity requests a machine certificate. If Web Enrollment accepts NTLM and EPA is absent or not enforced, the CA returns a client-authentication certificate for the DC machine account.
> 5. The attacker uses that certificate in PKINIT. Kerberos is now on the back side of the attack: the KDC issues a TGT to the identity proven by the certificate.
> 6. With a DC machine-account TGT, the attacker can use the DC account's replication authority to DCSync secrets. The compromise moved from coerced NTLM to certificate authentication to Kerberos without ever stealing the original NT hash [709,711,713].

This is the question that drives the rest of the chapter: *how did Windows arrive at a state where the most catastrophic modern Active Directory attack chain depends on a thirty-year-old fallback nobody wants?*

## Origins: Why NTLM existed at all

Rewind to 1987. IBM and Microsoft ship LAN Manager 1.0 for OS/2. PCs are still mostly file-and-print islands on Token Ring or 10BASE-2 coax; networking exists, but "domain" is a word for what a single server controls. LAN Manager needs an authentication scheme that can run on hardware with 640 KB of RAM, no DES export license, and roughly zero institutional knowledge about cryptography. What it produces, the LM hash, is a near-perfect snapshot of every constraint and assumption of its moment [714].

The construction is short enough to write out. Take the password. Uppercase it. Pad or truncate to exactly fourteen ASCII characters. Split into two seven-byte halves. Convert each half into a 56-bit DES key (the eighth bit of each byte is a parity bit). Use each key to DES-encrypt the eight-byte constant `KGS!@#$%`. Concatenate the two eight-byte ciphertexts. That is the LM hash [715,714,716].

> **Definition: LM hash.** The LAN Manager password hash from 1987. Constructed by uppercasing the password, truncating or padding to 14 characters, splitting into two 7-byte halves, and DES-encrypting the constant `KGS!@#$%` with each half as a key. The two halves are independent, the password is case-insensitive, and there is no salt. Those LM-specific weaknesses do not all survive NTLMv2; the property that does survive is password-equivalence: a reusable long-term hash can answer future challenges until the password changes [715,714].

> **Aside.** The eight-byte constant `KGS!@#$%` is what you get when somebody types "KGS" and then mashes shift-1, shift-2, shift-3, shift-4, shift-5 on a 1980s American IBM keyboard. The constant is in the protocol because the protocol predates the cryptographic-engineering norm that constants should look random. It would not survive a 2026 design review; in 1987 nobody asked.

Every choice tells a story about 1987. Uppercase, because some clients normalized case anyway and the developers wanted authentication to "just work" across mixed locale settings. Fourteen characters, because that was the field width DOS dictated. Two halves, because a 56-bit DES key already maxed out the practical computation; nobody was going to chain two DES operations through a feedback function with that much per-keystroke latency. No salt, because the deployment model was one server, one user database, and identical-password collisions were a feature for the help desk, not a leak.

The result is password-equivalent: anyone who possesses the LM hash *is* the user, forever, regardless of how the wire protocol presents the credential.

Six years later, July 27, 1993, Windows NT 3.1 ships. NTLM(v1) arrives with it [715,716]. The NT-hash is what you would design if you started over with mid-1990s assumptions but were not yet willing to abandon DES at the response layer. It is simpler than the LM hash and stronger in exactly one place: `NT-hash = MD4(UTF-16LE(password))` [716]. No truncation. No case folding. Sixteen bytes of output. The hash is still password-equivalent; what changes is that the *input* to the hash is now whatever Unicode string the user typed, in full.

The wire protocol around the NT-hash is the famous three-message handshake. NEGOTIATE from the client. CHALLENGE from the server (an eight-byte random nonce). AUTHENTICATE from the client, carrying a DES-based response computed from the NT-hash and the server challenge. The whole exchange is self-contained: nothing in the three messages binds the authentication to a particular transport, a particular client, a particular server, or a particular service [715]. That property (the absence of *binding*) is the property NTLM relay will eat for the next twenty-five years.

> **Definition, NT-hash.** `MD4(UTF-16LE(password))`. Sixteen bytes. The single long-term secret that every NTLM authentication ever performed for a given user derives from. Possession of the NT-hash is mathematically equivalent to possession of the password for every authentication purpose. NTLMv2 changes the response computation but not the hash [716].

> **Walkthrough: the thirty-year dependency chain.**
>
> 1. LAN Manager (1987) solved file-and-print authentication with the LM hash: weak by modern standards, but deployable on machines that could not assume a domain controller or modern crypto.
> 2. Windows NT 3.1 (1993) replaced the LM hash's input processing with the NT hash, but the protocol still treated possession of the long-term hash as enough to answer challenges.
> 3. NTLMv2 (NT 4.0 SP4, 1998) added HMAC-MD5, a client challenge, timestamps, target-info AV_PAIRS, and later MIC/CBT fields. It improved the response. It did not change password-equivalence.
> 4. Windows 2000 made Kerberos the domain default and demoted NTLM to compatibility fallback. The fallback survived because real networks kept hitting no-DC, local-account, no-SPN, and hard-coded-NTLM cases.
> 5. MS08-068 (2008), Credential Guard (2015), Drop-the-MIC patches (2019), KB 5005413 (2021), and Server 2025 hardening each closed a known primitive. None removed the fallback.
> 6. The exit plan begins only after Microsoft can name replacements for every fallback: IAKerb for no DC line-of-sight, Local KDC for local accounts, IP-SPN for missing SPNs, and a Negotiate-first refactor for hard-coded call sites [717,718,719].
> 7. The 2024-2026 distinction matters: the NTLMv1 server feature is removed in Windows 11 24H2 and Windows Server 2025; NTLMv2 is deprecated, still present, and scheduled to be disabled by default only at Phase 3 [605].

The third revision arrives with NT 4.0 Service Pack 4, October 1998. NTLMv2 throws away DES at the response layer and replaces it with HMAC-MD5. It introduces a *client* challenge (so the response is no longer purely a function of the server's choice). It introduces AV_PAIRS, a small TLV structure carrying the target name, a timestamp, and (in much later retrofits) the channel binding hash and message integrity field [715,716]. NTLMv2 defeats pre-computation attacks against the response. It does not change the long-term secret. The NT-hash is still the NT-hash; possession is still authority.

> **Aside.** An intermediate variant, NTLM2 Session Security, shipped in NT 4.0 SP4 alongside NTLMv2 and is the dead end most often confused for v2. It added an 8-byte client challenge to the NTLMv1 DES envelope without touching the long-term hash, hoping to defeat pre-computation while preserving wire compatibility. It survived only as a transitional `LMCompatibilityLevel` setting; nothing in the modern attack catalog treats NTLM2 SS as a distinct target [715].

| Property | LM hash (1987) | NTLMv1 (1993) | NTLMv2 (1998) |
|---|---|---|---|
| Hash function for the long-term secret | DES of constant with password halves | MD4(UTF-16LE(password)) | MD4(UTF-16LE(password)) |
| Case-sensitive | No (uppercase only) | Yes | Yes |
| Max input length | 14 characters (truncated) | Unlimited Unicode | Unlimited Unicode |
| Salted | No | No | No (per-exchange challenge + timestamp added to the response, not a hash salt) |
| Response keyed MAC | DES (3 keys, 56-bit each) | DES (3 keys, 56-bit each) | HMAC-MD5 |
| Binds to target server name | No | No | AV_PAIR `MsvAvTargetName` (retrofit) |
| Binds to TLS endpoint | No | No | AV_PAIR `MsvAvChannelBindings` (retrofit) |
| Possession of hash = authority | Yes | Yes | Yes |

> **Definition: NTLMv1 / NTLMv2.** The two production response constructions on top of the same NT-hash. NTLMv1 chains three 56-bit DES operations across `K1 = NT-hash[0:7]`, `K2 = NT-hash[7:14]`, `K3 = NT-hash[14:16] || \x00\x00\x00\x00\x00`, encrypting the eight-byte server challenge under each. The third sub-key has only 16 bits of variable input (two hash bytes plus five zero bytes); DES parity expansion does not reduce or add to that entropy. NTLMv2 replaces all three DES operations with one HMAC-MD5 over `server_challenge || client_challenge || timestamp || av_pairs`, keyed by `NTOWFv2 = HMAC_MD5(NT-hash, UNICODE(Upper(user) || domain))` [715,716].

Then comes Windows 2000, and Kerberos. Microsoft's plan was simple: in a domain, Kerberos handles everything; NTLM stays around as a compatibility blanket for the cases Kerberos cannot cover yet [720]. The trouble was that "the cases Kerberos cannot cover yet" turned out to be a permanent set, not a transitional one. Twenty-three years later, the same four cases would be the table-of-contents of Microsoft's NTLM-removal plan [717]:

1. **No domain-controller line-of-sight.** A laptop on a hotel Wi-Fi authenticating to a corporate file share through a VPN tunnel terminator has no Kerberos KDC to talk to. NTLM does not need one.
2. **Local accounts.** A user signing into a workgroup machine or a domain-joined machine's local SAM has no domain at all; Kerberos has nothing to authenticate against.
3. **No service principal name.** Kerberos requires a known SPN for the target service. Connect to a server by raw IP, by an alias DNS name not yet in the SPN database, or by a CNAME the operator forgot to register. There is no SPN, so Kerberos cannot run.
4. **Hard-coded NTLM.** Application code that calls `AcquireCredentialsHandleW(..., "Ntlm",...)` or RPC code that asks for `RPC_C_AUTHN_WINNT` directly bypasses the negotiator and forces NTLM regardless of what is available.

> **Definition: SPNEGO / Negotiate.** The Simple and Protected GSS-API Negotiation Mechanism. When two parties want to authenticate but do not know which security mechanism they share, SPNEGO offers a list and picks the best one both support. On Windows the SSPI provider is called `Negotiate`, and it has historically chosen Kerberos when possible and NTLM otherwise [720]. The "otherwise" path is where every modern NTLM attack lives.

Each fallback case is one shutter through which NTLM continues to leak into a Kerberos-by-default world. *The demotion was supposed to be terminal. Why did the four fallback cases turn out to cover most of the real-world authentication surface, and what does that look like on the wire?*

## The wire: Three messages and one hash

Most defenders have never read an NTLM authentication off the wire. The cryptography is short enough to fit on one screen, and the structural property that drives the next 28 years of attacks is visible inside those three messages. What follows makes that property impossible to miss.

### NEGOTIATE, CHALLENGE, AUTHENTICATE

![Figure: The three-message NTLMv2 handshake on the wire. The client opens with NEGOTIATE (capability flags, no identity); the server replies with CHALLENGE (a 64-bit nonce plus TargetInfo AV_PAIRS); the client derives NTOWFv2 and NTProofStr from the NT-hash and returns AUTHENTICATE, carrying the proof plus an optional MIC and optional MsvAvChannelBindings CBT. The server holds no plaintext, so it pass-throughs the response to the domain controller via Netlogon to verify. The structural point is the oxblood callout: nothing in the three messages binds the exchange to a transport, a server, or a service: the property NTLM relay eats for twenty-five years.](diagrams/09-ntlm-handshake.svg)

The client opens with `NEGOTIATE`, advertising its capability flags: which signing modes it supports, whether it is willing to do session security, whether it is asking for extended session keys, and so on. The server replies with `CHALLENGE`. The body of `CHALLENGE` contains a single 64-bit nonce (the server challenge) and a TLV blob called `TargetInfo`: a list of attribute-value pairs the server wants to bind into the authentication [715].

The client computes its response and sends `AUTHENTICATE`. That message contains the user name, the workstation name, the response itself, the AV_PAIRS the client wants to echo back, a Message Integrity Code field (HMAC-MD5 of the concatenation of all three NTLM messages), and (in EPA-enforced deployments) a hash of the TLS endpoint certificate placed in the `MsvAvChannelBindings` AV_PAIR [715,721].

> **Walkthrough: the NTLMv2 exchange as the verifier sees it.**
>
> 1. The client sends `NEGOTIATE`: a list of flags, not proof of identity.
> 2. The server sends `CHALLENGE`: an eight-byte nonce plus `TargetInfo` AV_PAIRS such as target name, timestamp requirements, and optional channel-binding requirements.
> 3. The client derives `NTOWFv2 = HMAC_MD5(NT-hash, UNICODE(Upper(user) || domain))`. The plaintext password is already gone; the NT hash is the root secret.
> 4. The client builds `temp = version || zeros || timestamp || client_challenge || zeros || ServerName(AV_PAIRS) || zeros`. Most of `temp` either came from the server or is sent back in cleartext.
> 5. The client computes `NTProofStr = HMAC_MD5(NTOWFv2, ServerChallenge || temp)` and sends `NTProofStr || temp` in `AUTHENTICATE`, alongside the username, workstation, optional MIC, and optional CBT AV_PAIR.
> 6. For a local SAM account, the accepting machine can repeat the same derivation from its local copy of the user's NT hash. For a domain account on a member server, the usual path is pass-through validation: the server forwards the challenge/response over Netlogon to a domain controller, and the DC verifies it against the domain copy of the secret. In both cases, matching MACs make the stolen NT hash (not the plaintext password) sufficient authority [715].

### The NTLMv2 response, verbatim

`[MS-NLMP]` §3.3.2 gives the response algorithm in three lines of pseudocode [715]:

`NTOWFv2 = HMAC-MD5(NT-hash, UNICODE(Upper(user) || domain))`

`temp = ResponseVersion || HiResponseVersion || Z(6) || Time || ClientChallenge || Z(4) || ServerName || Z(4)`

`NTProofStr = HMAC-MD5(NTOWFv2, ServerChallenge || temp)`

The `temp` byte string carries two version bytes, six zero bytes, the 8-byte FILETIME, the 8-byte client challenge, four zero bytes, the AV_PAIR list the spec calls `ServerName`, and a final four zero bytes. The client sends `NTProofStr || temp` as the response. A local-account verifier can recompute directly from the local SAM; a member server validating a domain account normally forwards the material to a domain controller for pass-through verification. That is the entire response protocol.

Notice what `NTOWFv2` is. It is a function of two inputs: the NT-hash, and a normalized user/domain string. Both inputs are static once the user logs in. *Knowing the NT-hash is sufficient to compute every NTLMv2 response forever, against every server, for every challenge, until the password changes* [666].

> **Aside.** Why is HMAC-MD5 considered fine for the response side but considered weak for the *key* side? The response side is being asked: given a known key, can a verifier check a freshly computed tag? HMAC-MD5 still answers that without a known break. The key side is being asked: given a stolen 16-byte value, how hard is it to mount a precomputation attack on candidate passwords? MD4 of UTF-16LE is so cheap on modern GPUs that an 8-character password is in the minutes-to-hours range. Hashcat lists NetNTLMv2 (mode 5600) as the practical attack format and benchmarks NTLM cracking accordingly.

### AV_PAIRS, MIC, and channel binding: retrofits all the way down

AV_PAIRS is a TLV structure. The server places target NetBIOS, target DNS, a timestamp, and various flags into the `TargetInfo` of `CHALLENGE`. The client echoes the structure into `AUTHENTICATE` and adds two retrofit fields when both ends agree to use them [715]:

- **`MsvAvFlags`** is a bit field signaling that the client has computed a MIC and is therefore willing to bind all three NTLM messages together.
- **`MsvAvChannelBindings`** holds the 16-byte MD5 hash of the GSS channel-bindings structure; for TLS EPA, that structure carries the RFC 5929 `tls-server-end-point` certificate hash, binding the authentication to the HTTPS channel the client can see. This is the Extended Protection for Authentication (EPA) channel-binding-token mechanism [721].

The MIC field itself is added to `AUTHENTICATE`. It is `HMAC_MD5(ExportedSessionKey, NEGOTIATE || CHALLENGE || AUTHENTICATE)`, computed with the MIC field zeroed inside the `AUTHENTICATE` bytes being hashed so the receiver can recompute and compare. `ExportedSessionKey` coincides with `SessionBaseKey` in the common case; when `NTLMSSP_NEGOTIATE_KEY_EXCH` is set, the client generates a random session key, encrypts it under `KeyExchangeKey`, and `ExportedSessionKey` is the random key. The MIC always uses `ExportedSessionKey`, and it is intended to make tampering with any of the three messages detectable [715].

> **Definition: AV_PAIRS.** A length-prefixed TLV list carried inside the `TargetInfo` byte string of NTLM `CHALLENGE` and the AV-list byte string of `AUTHENTICATE`. AV_PAIRS hold the target server names, a timestamp, the `MsvAvFlags`, the `MsvAvChannelBindings` (EPA), and the optional `MsvAvTargetName` (SPN). NTLMv2 reserved AV_PAIRS in 1998 but most of the fields are 2009-2019-era retrofits onto the original wire format [715].

> **Definition: Message Integrity Code (MIC).** A 16-byte HMAC-MD5, keyed by `ExportedSessionKey`, computed over the concatenation of the NTLM `NEGOTIATE`, `CHALLENGE`, and `AUTHENTICATE` messages and embedded in `AUTHENTICATE`. (`ExportedSessionKey` equals `SessionBaseKey` unless `NTLMSSP_NEGOTIATE_KEY_EXCH` is negotiated; the MIC always uses the exported key.) Introduced as a retrofit so that a man-in-the-middle relay could not silently strip the signing-required flags from the negotiate phase. Drop-the-MIC (CVE-2019-1040) demonstrated that the *presence* of the MIC was itself a negotiated property and could be stripped [715,722].

> **Definition: Channel Binding Token (CBT).** An MD5 hash of the GSS channel-bindings structure (which carries the server's `tls-server-end-point` certificate hash) placed in `MsvAvChannelBindings` so the authentication is bound to the specific TLS channel the client believed it was talking over. When both ends enforce CBT, an attacker who terminates one TLS channel and opens a different TLS channel to the real server cannot reuse the captured NTLM response. Microsoft documents enforcement as off, when-supported, and required (WCF `Never` / `WhenSupported` / `Always`) [721].

### Mechanism check: why the hash is enough

> **Key idea.** The NT-hash is not a credential; it *is* the credential. Knowing the hash IS authentication. Every pass-the-hash tool ever written, from Paul Ashton's modified Samba in 1997 to the present, is a different packaging of the same realisation: an authentication that is a deterministic function of a static secret turns possession of that secret into permanent authority [666].

If possession of the hash is the protocol, the last 28 years of attacks are not surprises. They are obvious next steps. What are those steps?

## The three-decade attack cascade

![Figure: Five generations of NTLM attacks, 1997–2021, as a dated timeline. Each generation pairs the named attack with the Microsoft response and the class that response left alive: Pass-the-Hash (operational guidance; the hash stays password-equivalent), SMBRelay (MS08-068 patches self-relay only; cross-server relay survives), LSASS extraction (Credential Guard isolates the hash; credential use survives), forced-auth coercion (KB 5005413, EPA, and MIC per primitive; the class survives), and ESC8 (remove NTLM; the relay class moves intact to Kerberos). The cadence is the argument. Every fix closed a primitive, never the fallback, until ESC8 ended the retrofit strategy.](diagrams/09-ntlm-attack-cascade.svg)

Five generations of attacks. Each one is named, each one is dated, each one took Microsoft years to respond to, and each Microsoft response always closed the *primitive* and left the *class* alive. They are not five surprises; they are five logical consequences of the wire protocol you just read.

### Generation 1 -- 1997: Pass-the-Hash (Paul Ashton)

The first published exploit of password-equivalence comes from Paul Ashton, posted to the Bugtraq mailing list in 1997. Ashton ships a patch against the Samba SMB client that takes a 16-byte NT-hash directly on the command line, *instead* of asking for a cleartext password [666]. The patch is a one-paragraph change against an open-source codebase, and that fact (the brevity of the change) is the lesson.

The NTLM response function has no input that depends on knowing the plaintext password. Replacing the plaintext-password input with a literal NT-hash input does not change the bytes that go on the wire. The server cannot tell the difference.

Microsoft's response, for more than a decade, is *do not lose your hashes*. There is no protocol fix because there is no protocol bug to fix; the design is doing exactly what it was designed to do. The response is operational guidance: tier your admins, scrub LSASS, do not run privileged sessions on workstations.

### Generation 2 -- 2001: NTLM relay (Sir Dystic / SMBRelay)

If you do not have to *steal* the hash to use the credential, you also do not have to *steal* the live exchange. You can simply *relay* it. On March 31, 2001, at the.con conference, Sir Dystic of the Cult of the Dead Cow (Josh Buchbinder) releases SMBRelay: a small program that accepts an SMB connection on port 139, opens a second SMB connection back to *another* server, and shuttles the NEGOTIATE / CHALLENGE / AUTHENTICATE messages between the two sides [723].

The attack works because the three NTLM messages are not bound to a particular client, server, or service. Whoever sits between them can replay the credential against whatever destination the attacker chooses, as that user, for the duration of the exchange.

> **Aside.** The colorful provenance matters. The Cult of the Dead Cow released SMBRelay alongside Back Orifice 2000; "Sir Dystic" is the same Josh Buchbinder who later wrote the SMBProxy authentication-relay framework. The point is not the chrome. It is that the relay class was disclosed publicly *at a conference* in 2001, with working code on the cDc website, and Microsoft did not ship a fix for the trivial case (self-relay) until November 2008 [723].

Microsoft's response is incomplete and slow. SMB signing exists from Windows 2000 onward, but it is off by default on member servers for more than a decade [724]. MS08-068, in November 2008, finally patches the *self-relay* case (CVE-2008-4037): the SMB server now refuses to accept an authentication that the client itself just generated against the same server [725]. Seven years to fix the simplest variant; the *cross-server* relay class is still wide open.

### Generation 3 -- 2008-2014: Credential theft as a service

By 2008, the operational guidance "do not lose your hashes" stops being defensible. On February 29, 2008, Hernan Ochoa releases the Pass-the-Hash Toolkit v1.3, two native Windows binaries called `iam.exe` and `whosthere.exe` that read the NT-hash out of LSASS memory and inject it into a new logon session. PtH stops being a Linux-and-Samba trick and becomes a Windows-everywhere reality.

Three years later, Benjamin Delpy publishes Mimikatz. The first version is closed-source, released in May 2011 [617]. By April 6, 2014, the GitHub repository goes public with the version string "mimikatz 2.0 alpha (x86) release 'Kiwi en C' (Apr 6 2014 22:02:03)" [261]. The repo description is a near-perfect summary of what LSASS is to an attacker: "extract plaintexts passwords, hash, PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash, pass-the-ticket or build Golden tickets" [261]. LSASS becomes the universal credential oracle.

> **Aside.** Delpy did not intend Mimikatz to be a weapon. Wired's Andy Greenberg records that he "released it publicly in May 2011, but as a closed source program." He went open-source only after the tool surfaced in nation-state intrusions and a pair of in-person confrontations. That biography (the DigiNotar breach, the Moscow hotel room, the man in the dark suit who wanted a copy on a USB drive) belongs to the Mimikatz chapter (Chapter 14). What matters for NTLM is the consequence: by 2014, extracting the password-equivalent NT hash from LSASS was a commodity, and "do not lose your hashes" had stopped being a defense [617].

Microsoft's response is structural and specific. Credential Guard ships in Windows 10 RTM (Enterprise and Education editions), July 29, 2015 [87]: it moves the long-term secret into a VBS trustlet the NT kernel cannot read, so a SYSTEM-level memory dump of `lsass.exe` returns an empty hash. The mechanism (`LsaIso.exe` in VTL1, plus the Protected Users, Restricted Admin, and LSASS-as-PPL hardening around it) is the subject of the Credential Guard chapter (Chapter 15) [87].

Credential Guard works: against the credential-*theft* class. It does nothing against credential-*use*. An attacker who never extracts a hash, because they never need to, sails right past it. Relay does not need the hash. Coercion does not need the hash. ESC8 does not need the hash. That is the next generation.

### Generation 4 -- 2018-2021: Forced-authentication coercion

In 2018 at DerbyCon 8, Lee Christensen releases SpoolSample, known publicly as "PrinterBug." The GitHub description is exact: "PoC tool to coerce Windows hosts authenticate to other machines via the MS-RPRN RPC interface" [726]. The trick is that the Print Spooler service runs as SYSTEM, accepts a remote RPC call (`RpcRemoteFindFirstPrinterChangeNotificationEx`) that takes a UNC path, and dutifully NTLM-authenticates back to whatever path the caller named: on behalf of the machine account. Any Windows service running as SYSTEM that accepts a UNC path is a confused deputy that will authenticate on demand.

> **Why 'PrinterBug' was 'by design' for three years.** Microsoft's initial classification of SpoolSample was *authenticated-only / by design*: a caller needed valid domain credentials to reach the spooler endpoint, and authenticated callers triggering machine-account authentications was deemed within spec. The classification held through 2018, 2019, and most of 2020. PetitPotam broke it, because its original MS-EFSRPC-over-LSARPC path accepted *unauthenticated* binds on vulnerable domain controllers. With that authentication requirement gone in the high-value DC case, "by design" stopped being a coherent defense. Microsoft started shipping fixes.

Marina Simakov and Yaron Zinar of Preempt (now CrowdStrike) publish "Drop the MIC" on June 11, 2019. The vulnerability is CVE-2019-1040: a tampering bug where "a man-in-the-middle attacker is able to successfully bypass the NTLM MIC (Message Integrity Check) protection" [727,722]. The bypass works by stripping the `NTLMSSP_NEGOTIATE_SIGN` and `NTLMSSP_NEGOTIATE_ALWAYS_SIGN` flags from the initial `NEGOTIATE`, removing the MIC field from `AUTHENTICATE`, and removing the `Version` field that drives MIC detection.

Servers that should have required a MIC silently accept the modified message. The MIC (the retrofit integrity layer that was supposed to make tampering detectable) turns out to be itself untethered to the negotiation [727].

Gilles Lionel (topotam77) publishes PetitPotam in July 2021. The GitHub repository description reads: "PoC tool to coerce Windows hosts to authenticate to other machines via MS-EFSRPC EfsRpcOpenFileRaw or other functions" [710]. The decisive new property compared to SpoolSample was the original domain-controller path: PetitPotam needed *no credentials* against a vulnerable DC because LSARPC accepted unauthenticated binds. After patches and mitigations, treat that as the historical high-water mark, not a universal claim about every Windows server or every coercion method.

In 2022, Remi Gascou (p0dalirius) publishes Coercer, a Python script that consolidates the coercion class across MS-RPRN, MS-EFSR, MS-DFSNM, MS-FSRVP, and many more RPC interfaces. The README describes it succinctly: "A python script to automatically coerce a Windows server to authenticate on an arbitrary machine through many methods" [708].

### Generation 5 -- 2021: ADCS web-enrollment relay (ESC8)

On June 17, 2021, Will Schroeder and Lee Christensen of SpecterOps publish "Certified Pre-Owned," a whitepaper and matching blog post that maps eight new attack classes against Active Directory Certificate Services [709,711]. ESC1 through ESC7 are template and configuration weaknesses. ESC8 is the keystone of this chapter.

ESC8 says: AD CS Web Enrollment endpoints (`/certsrv/`) accept NTLM authentication. Coerce a server's machine account to authenticate to your relay listener; relay the authentication to `/certsrv/`; enroll the relayed identity for a machine-template certificate; use that certificate to perform PKINIT against the KDC and request a TGT [709]. The NTLM-vs-Kerberos boundary stops being a meaningful one. NTLM is the protocol on the front side of the attack; Kerberos is the trust token on the back side; the certificate is the conduit between them.

The point of ESC8 is not just that it works. The point is that it works against a perfectly retrofitted environment. SMB signing did not enter the chain. LDAP signing did not enter the chain. EPA was supposed to enter the chain on the `/certsrv/` side but was unevenly deployed. Credential Guard never had a hash to protect.

> **Walkthrough: why each generation survived the previous fix.**
>
> 1. Pass-the-Hash taught defenders that the NT hash itself was authority. The obvious response was operational: protect hashes and rotate passwords after compromise.
> 2. SMBRelay showed that even a protected hash could be used indirectly. The attacker did not need the secret; a live victim computed the response and the attacker forwarded it. MS08-068 closed the most obvious reflection case, not arbitrary cross-server relay [725,723].
> 3. LSASS-extraction tooling industrialized credential theft. Credential Guard answered that theft path by isolating secrets in VTL1. It did not stop a coerced service from using its credential legitimately.
> 4. Forced-authentication techniques moved the attack trigger into RPC and service behavior. PrinterBug, Drop-the-MIC, PetitPotam, and Coercer are different handles on the same idea: make a privileged service authenticate outward, then relay that authentication where binding is weak [726,708,727].
> 5. ESC8 crossed the protocol boundary. NTLM was only the front half; the back half was certificate enrollment and Kerberos PKINIT. At that point the correct response stopped being another primitive patch and became removal of the fallback itself [709,711,713].

> **Walkthrough: the coercion-and-relay flow.**
>
> 1. The attacker calls an RPC method that accepts a UNC path: printer notification, EFSRPC file access, DFS namespace management, or another endpoint in Coercer's catalog.
> 2. The victim service, running as SYSTEM or as a machine account, tries to reach that path. Windows treats the outbound connection as normal integrated authentication and starts NTLM.
> 3. The attacker's relay listener does not answer the challenge itself. It opens a second connection to the real target and asks the target for a challenge.
> 4. The relay sends that target challenge back to the victim service. The victim computes `AUTHENTICATE` with its own machine credential.
> 5. The relay forwards `AUTHENTICATE` to the target. If the target does not require signing, channel binding, or endpoint-specific protection, it accepts the attacker's socket as the victim's authenticated session.
> 6. The confused deputy is the service that authenticated; the confused verifier is the target that accepted a response not bound to the channel where it was created [726,708].

| Generation | Primitive | Public date | Microsoft response | What survived |
|---|---|---|---|---|
| 1. Pass-the-Hash | Use the hash directly | 1997, Paul Ashton, Bugtraq [666] | Operational guidance | Hash is still password-equivalent on the wire |
| 2. NTLM relay (SMB) | Forward live exchange | March 31, 2001, Sir Dystic, the.con [723] | MS08-068 (Nov 2008): self-relay only [725] | Cross-server, cross-protocol relay |
| 3. LSASS extraction | Steal hashes from memory | Feb 2008 (Ochoa); May 2011 closed / Apr 2014 open (Delpy) [261,617] | Credential Guard (Jul 29, 2015) [87] | Hash *use* outside LSASS path; SYSTEM-level Mimikatz on the SAM |
| 4. Coercion | Make SYSTEM authenticate on demand | 2018 SpoolSample [726]; 2019 Drop-the-MIC [727,722]; 2021 PetitPotam [710]; 2022 Coercer [708] | Per-interface patches; KB 5005413 EPA recipe [713] | The pattern of "SYSTEM holds an unanchored credential" |
| 5. ESC8 ADCS Web Enrollment relay | NTLM coerce → /certsrv/ → TGT via PKINIT | June 17, 2021, Schroeder/Christensen, "Certified Pre-Owned" [709,711] | KB 5005413; AD CS hardening; eventually Phase 3 of NTLM removal | Kerberos relay class on the other side (KrbRelay/KrbRelayUp) [693] |

> KrbRelayUp: a universal no-fix local privilege escalation in windows domain environments where LDAP signing is not enforced (the default settings).: Dec0ne, KrbRelayUp README [693]

A reader who comes to the retrofit catalog believing "if I patch each named NTLM attack, the protocol is safe" leaves it believing something else. Every retrofit patches a *primitive*; none addresses the *existence* of the fallback path. The next attack is always one cross-protocol step away. The retrofit strategy is structurally incapable of closing the class.

By the end of 2021, NTLM-the-protocol cannot be removed because four use cases require it, and NTLM-the-fallback cannot be kept because ESC8 turned it into a domain-takeover oracle. Something has to change. What?

## The retrofit strategy and its funeral

Before naming the answer, name the strategy that failed. Microsoft's defensive cadence between 2001 and 2021 splits into three families, each effective against a named primitive, each defeated by an unanchored cousin of that primitive.

### Family A: Per-protocol message authentication

SMB signing. LDAP signing and sealing. The idea is to anchor the *content* of each authenticated request inside a per-session signature derived from the authentication. SMB signing introduces an HMAC over every SMB message keyed by a per-session `SigningKey`; LDAP signing and sealing do the equivalent for LDAP operations [724].

Family A works when the *target* protocol enforces it. SMB-to-SMB relay against an SMB server with required signing fails; LDAP-to-LDAP relay against an LDAP server with required signing fails. The strategy assumes the attacker stays in the same protocol family. Cross-protocol relay (SMB authentication relayed to LDAP, or SMB authentication relayed to `/certsrv/`) defeats it. The MS-EFSR coercion can produce an authentication that originates "as if from SMB" and gets accepted by an unrelated HTTPS service that ignores the SMB signing flag entirely [722,709].

### Family B: Per-channel binding tokens and the MIC

EPA (channel binding) and the NTLMv2 MIC are the response to cross-protocol relay. Both try to tie the authentication to *the specific channel* the client believes it is using. EPA places a channel-bindings hash (covering the server's TLS endpoint certificate) into the `MsvAvChannelBindings` AV_PAIR; an HTTPS server with EPA required compares it to its own certificate's hash and rejects the authentication if they do not match [721]. The MIC binds all three NTLM messages together so a relay cannot strip the signing-required flags from `NEGOTIATE` after the client sets them [715].

Family B works when both ends agree to enforce. Drop-the-MIC (CVE-2019-1040) demonstrated that the *presence* of the MIC was negotiated and could be stripped, so a server that supported MIC-less clients silently accepted MIC-less messages from a relay [727,722]. EPA suffers from the same enforcement-asymmetry: when an AD CS web endpoint runs with EPA disabled or merely opportunistic (WCF `policyEnforcement="Never"` or `"WhenSupported"`), the binding is not enforced. KB 5005413 published the explicit `<extendedProtectionPolicy policyEnforcement="Always" />` recipe for `/certsrv/` because field deployments had been running with weaker settings [713].

### Family C, credential isolation

Credential Guard. LSASS-as-PPL. Protected Users. Restricted Admin. These attack the *theft* surface: Credential Guard moves the NT-hash into a VTL1 trustlet the kernel cannot read (Chapter 15). Microsoft documents default enablement starting in Windows 11 22H2 and Windows Server 2025 for domain-joined, non-DC systems that meet license, hardware, and software requirements and have not been explicitly configured to keep Credential Guard disabled [87].

Family C is honest about what it covers. It does nothing about coercion flows that never touch the NT-hash. PetitPotam and ESC8 do not need a hash; the relay session uses the live NTLM exchange and is never persisted. Credential Guard cannot help.

| Family | What it closes | What it does not close | Defeating attack |
|---|---|---|---|
| A. Per-protocol message auth (SMB/LDAP signing) | Same-protocol relay against the target | Cross-protocol relay; targets that do not enforce | LDAP relay from SMB coercion [722]; ESC8 relay to /certsrv/ |
| B. Channel binding (EPA) + MIC | Same-channel relay through TLS termination | MIC stripping in negotiation; EPA at None/Partial; non-TLS targets | Drop-the-MIC [722]; under-enforced EPA [713] |
| C. Credential isolation (Credential Guard, LSASS-PPL) | Hash theft from running LSASS | Hash *use* in live relay; SAM extraction from disk; coercion | ESC8 + PetitPotam [709]; SAM hive offline [87] |

> **Key idea.** Every retrofit Microsoft has shipped against NTLM attacks one *primitive* of NTLM. None address the *existence* of NTLM as a fallback path. ESC8 was the funeral of the retrofit strategy because ESC8 turned a fully retrofitted environment into a domain takeover without defeating any retrofit.

> **The funeral of the retrofit strategy.**
>
> "Certified Pre-Owned" did not break a Microsoft fix; it composed the existing infrastructure. The chain assumes SMB signing is on, EPA is on (somewhere), and Credential Guard is on. It still works, because none of those controls cover the path that goes Coercer → NTLM relay → AD CS Web Enrollment → PKINIT. After 2021, the question stopped being "what's the next retrofit?" and became "what does it take to remove the fallback?" [709,713].

To remove ESC8 without rebuilding AD CS, Microsoft has to remove NTLM. To remove NTLM, Microsoft has to remove the four reasons NTLM existed as a fallback in the first place. What does that look like in shippable form?

## The breakthrough: Closing the fallback

![Figure: The removal architecture for NTLM's fallback. Each of the four reasons Negotiate fell back to NTLM (amber, left) is closed by an engineered mechanism (green): no DC line-of-sight by IAKerb, no domain by a Local KDC over the SAM, a missing SPN by IP-SPN policy, and hard-coded `Ntlm` call sites by the Negotiate refactor. All four ride NEGOEX inside the existing Negotiate/SSPI envelope, so the unchanged API now prefers Kerberos with no application change.](diagrams/09-ntlm-fallback-closure.svg)

October 11, 2023. Matthew Palko, Windows IT Pro Blog. "The evolution of Windows authentication." For the first time in twenty-three years, Microsoft publicly commits to *removing* NTLM, not restricting it, and names the three load-bearing features that make removal possible [717].

The plan starts where every honest plan starts: by stating the problem in its own words. There are four fallback reasons NTLM persisted: no DC line-of-sight, no domain at all (local accounts), no SPN for the target, and hard-coded NTLM in application code [717]. Each gets an engineered answer. The four-to-three correspondence (three protocols plus one refactor) is the new architecture.

> Our end goal is eliminating the need to use NTLM at all to help improve the security bar of authentication for all Windows users.: Matthew Palko, Microsoft Windows IT Pro Blog, October 11, 2023 [717]

### IAKerb: closing "no DC line-of-sight"

IAKerb stands for *Initial and Pass Through Authentication Using Kerberos V5 and the GSS-API*. The IETF draft has a four-author list: Benjamin Kaduk, Jim Schaad, Larry Zhu, and Jeffrey E. Altman, and a quiet history [728].

The premise is simple. A client wants to authenticate to an application server with Kerberos but cannot reach a KDC: maybe the client is behind a firewall, maybe the KDC is only reachable from the server's side of a VPN. IAKerb wraps the Kerberos `AS-REQ` and `TGS-REQ` messages inside GSS-API tokens and asks the application server to proxy them to a KDC that the server *can* reach. The client never opens a direct TCP/UDP connection to a KDC; the application server acts as the carrier.

> **Why the IETF marked IAKerb dead in 2019.** The honesty duty: IAKerb's IETF draft (`draft-ietf-kitten-iakerb`) was marked "Dead WG Document" on August 29, 2019, by Robbie Harwood [728]. Harwood's note read, roughly, that IAKerb was historical at that point and the working group had no interest left. The last revision (`-03`) is from March 30, 2017, by Benjamin Kaduk. Microsoft is now reviving the protocol in its Windows 11 / Windows Server 2025-era NTLM-removal work, with broader pre-release deployment called out for Phase 2 in H2 2026: without acknowledging the dead-WG status in its own blog posts. This is the gap between an IETF standards-track document and what a vendor ships; this chapter reports both [728,717].

> **Definition: IAKerb.** Initial and Pass Through Authentication Using Kerberos V5 and the GSS-API. A GSS-API-wrapped Kerberos exchange in which the client cannot reach a KDC directly and the application server proxies `AS-REQ` / `TGS-REQ` on the client's behalf. Defined by `draft-ietf-kitten-iakerb` (IETF kitten WG, currently a Dead WG Document). MIT Kerberos has shipped IAKerb since 1.9 (released December 2010); Apple ships `GSS_IAKERB_MECHANISM` since macOS 10.14. Microsoft documents IAKerb as part of its Windows 11 / Server 2025-era authentication work, with Phase 2 pre-release flighting before Phase 3 GA [728,717,718,719]; it is developed as a Kerberos mechanism in the Kerberos chapter (Chapter 17).

### Local KDC: closing "no domain at all"

Local accounts in the machine SAM have never had a KDC. Workgroup machines have no domain at all. Both cases force NTLM today. The fix is conceptually trivial: run a tiny Kerberos KDC against the local SAM, exposed only through IAKerb-wrapped exchanges so the wire protocol is the same as the trust-traversing case [717,719].

This is the late-adopter move that surprises Linux-side practitioners. MIT Kerberos has had IAKerb since 1.9 (released December 2010). Samba has been working on a `localkdc` for years. At FOSDEM 2025 (February 2, 2025), Alexander Bokovoy and Andreas Schneider gave a talk explicitly framed as "localkdc: a general local authentication hub" [729]. Schneider's follow-up post the next week summarized the work: a parallel local-authentication hub for Linux that interoperates with the IAKerb wire format Windows is now adopting [729].

> **Definition: Local KDC.** A small Kerberos Key Distribution Center process that runs against a machine's local user database (the SAM on Windows; a file or sssd on Linux) and is exposed only through IAKerb. It lets local-account authentications use Kerberos under the same Negotiate / NEGOEX wire envelope used by domain authentications: removing one of the four reasons NTLM persisted. Documented in Microsoft's Windows 11 / Server 2025-era NTLM-removal work and slated for Phase 2 pre-release flighting before Phase 3 GA [717,718,719]; parallel Linux/Samba work coordinated under the FOSDEM 2025 `localkdc` umbrella [729].

### IP-SPN policy: closing the literal-address gap

The third historical fallback was the no-SPN case: a client reaches a server by IP address, cannot construct the conventional service principal name, and falls back. Dan Cuomo's 2024 Server 2025 summary names IP SPN as one of the new Kerberos features for minimizing NTLM use [719]. NEGOEX can carry richer mechanism negotiation, but the IP-SPN behavior itself is part of the Windows Server 2025 Negotiate/Kerberos roadmap rather than a property defined by `[MS-NEGOEX]`.

### NEGOEX: carrying IAKerb under the existing `Negotiate` API

You do not want to teach every application a new SSPI provider. Existing code calls `AcquireCredentialsHandle("Negotiate",...)`; that should keep working, and IAKerb should be one of the mechanisms `Negotiate` is willing to pick. The piece of plumbing that makes this possible is NEGOEX: SPNEGO Extended Negotiation [730,731].

NEGOEX adds a pair of meta-data messages on top of the standard SPNEGO `NegTokenInit` / `NegTokenResp` exchange, so that mechanisms (like IAKerb) that need a richer negotiation can ride inside the `Negotiate` envelope. The Microsoft Open Specification `[MS-NEGOEX]` is currently at revision 4.0 (April 23, 2024), with the original revision dated July 9, 2020 [730]. The expired Microsoft IETF draft `draft-zhu-negoex` from January 2011 is the historical anchor; four Microsoft authors (Michiko Short, Larry Zhu, Kevin Damour, and Dave McPherson) are listed verbatim in the draft metadata [731].

A correction is owed here. Scope notes inherited from earlier in this project cited "RFC 8143" as the NEGOEX standard. RFC 8143 is actually titled "Using Transport Layer Security (TLS) with Network News Transfer Protocol (NNTP)" and updates RFC 4642; it has nothing to do with NEGOEX [732]. The correct primary references for NEGOEX are `[MS-NEGOEX]` and `draft-zhu-negoex`, both used consistently throughout this chapter [730,731].

> **Definition: NEGOEX.** The SPNEGO Extended Negotiation security mechanism. Adds a meta-data exchange inside the SPNEGO envelope so that richer mechanisms (like IAKerb) can be negotiated without changing the SSPI surface. Primary sources: Microsoft Open Specification `[MS-NEGOEX]` revision 4.0 (April 2024); expired IETF draft `draft-zhu-negoex` (January 2011). Despite a common scope-doc error, RFC 8143 is *not* NEGOEX; RFC 8143 is "Using TLS with NNTP" [730,731,732].

### Negotiate-everywhere refactor: closing "hard-coded NTLM"

The last fallback case is the most prosaic: application code that calls `AcquireCredentialsHandleW(..., "Ntlm",...)` or RPC code that asks for `RPC_C_AUTHN_WINNT`. Both bypass `Negotiate` and force NTLM no matter what is on the wire. The fix is editorial (audit Windows internals, replace each hard-coded `Ntlm` call with `Negotiate`) and very large in surface area. Dan Cuomo's "Active Directory improvements in Windows Server 2025" post summarizes the Windows Server Summit 2024 session in one sentence: "we have created completely new Kerberos features to minimize use of NTLM in your environments. This session explains and demonstrates IAKerb, Local KDC, IP SPN, and the roadmap to the end of NTLM" [719].

| Fallback reason | Closure mechanism | Primary source | Ship target |
|---|---|---|---|
| No DC line-of-sight | IAKerb (GSS-wrapped Kerberos through the app server) | `draft-ietf-kitten-iakerb` (Dead WG, revived by Microsoft) [728] | Server 2025-era work; Phase 2 pre-release before Phase 3 GA [717,718,719] |
| No domain at all (local accounts) | Local KDC over IAKerb | Palko 2023; Samba `localkdc` parallel [717] | Phase 2 pre-release before Phase 3 GA [718,719] |
| No SPN | IP-SPN policy under Negotiate | Cuomo 2024 session [719] | Server 2025-era work plus flighting [718,719] |
| Hard-coded NTLM | Audit + replace hard-coded `Ntlm` calls with `Negotiate` | Palko 2023 [717] | Editorial, ongoing through Phase 2 |

> **Walkthrough: the four fallback closures.**
>
> 1. If the client cannot reach a domain controller, IAKerb lets the application server carry AS-REQ and TGS-REQ messages to the KDC. The client gets Kerberos without direct KDC line-of-sight [728,717].
> 2. If there is no domain because the identity is local, the Local KDC gives the local SAM a Kerberos-speaking front end. Local authentication can use Kerberos semantics instead of NTLM semantics [717,719].
> 3. If the target was reached by IP address and therefore lacks a conventional SPN, IP-SPN policy gives Negotiate a Kerberos name to try rather than falling back immediately [719].
> 4. If application code explicitly asks for `Ntlm`, no protocol invention can save it. The code must ask for `Negotiate`, and Phase 1 auditing must identify the process names and reason codes that still force NTLM [717,733].
> 5. NEGOEX is the carrier that lets these new choices ride under the existing SPNEGO/Negotiate surface, so the architectural goal is not a new application API; it is making the old preferred API finally stop choosing NTLM [730,731].

> **Walkthrough: IAKerb as a Kerberos courier.**
>
> 1. The client calls `Negotiate` as usual. Inside SPNEGO/NEGOEX, it advertises mechanisms that include Kerberos and IAKerb.
> 2. The server selects IAKerb because it can reach the KDC and the client cannot. The server is not trusted with the client's password; it is a transport for Kerberos messages.
> 3. The client constructs an AS-REQ and wraps it in an IAKerb token. The application server forwards the request to the KDC and returns the AS-REP to the client. The client now has a TGT exactly as if it had reached the KDC directly.
> 4. The client constructs a TGS-REQ for the application service and again sends it through IAKerb. The server forwards it to the KDC and returns the TGS-REP.
> 5. Once the client has the service ticket, authentication becomes ordinary Kerberos AP-REQ/AP-REP to the service. NTLM was never needed on the wire, and the application did not have to learn a new non-Negotiate API [728,717].

> **Aside.** What does this mean for Linux and macOS clients in a Windows domain? IAKerb is a GSS-API mechanism, and MIT's `krb5` library shipped IAKerb in 1.9 (released December 2010): well before Microsoft. Apple's Heimdal-derived GSS framework has shipped `GSS_IAKERB_MECHANISM` since macOS 10.14 (Mojave, 2018). The cross-platform interoperability story is therefore *better* in 2026 than it has been in years: a Linux client using MIT 1.9+ or an Apple client using macOS 10.14+ can already speak IAKerb to a Windows Server 2025 Local KDC. The parallel Samba `localkdc` effort closes the symmetric case: a Linux machine acting as the IAKerb server [729].

A reader who comes to the removal plan believing "NTLM is too entrenched to remove" leaves it believing something else. The entrenchment is *exactly four* named cases, and *each one* has been given an engineered answer. Removal is now a sequencing problem, not an architecture problem.

The engineering existed by October 2023. The shipping commitment came in January 2026. What is Microsoft actually shipping, and on what schedule?

## The three-phase roadmap

![Figure: The three-phase NTLM disablement roadmap drawn as a dependency chain. Each phase produces the input the next consumes. Phase 1 (NOW) is audit: KB 5064479 enhanced logging plus NTLMv1 removal in 24H2/WS2025, whose telemetry names the callers Phase 2 must refactor. Phase 2 (H2 2026) ships the closures in pre-release (IAKerb, Local KDC, IP-SPN policy, and the Negotiate-first refactor) all of which must reach GA before Phase 3 (next major release) flips network NTLM off by default. The amber caveat records the honest limit: disabled is not removed. NTLM stays in the OS and policy can re-enable it.](diagrams/09-ntlm-disablement-roadmap.svg)

January 29, 2026. The Windows IT Pro Blog publishes "Advancing Windows security: Disabling NTLM by default" under the byline `mariam_gewida` [718]. The post documents Microsoft's published roadmap and opens with a caveat that the rest of this chapter works hard not to forget.

> **The honest caveat from the January 2026 post.**
>
> "Disabling NTLM by default does not mean completely removing NTLM from Windows yet... during phase 3, NTLM will remain present in the OS and can be explicitly re-enabled via policy if you still need it.": mariam_gewida, "Advancing Windows security: Disabling NTLM by default," Microsoft Windows IT Pro Blog, January 29, 2026 [718]

The plan has three phases. They are sequenced; each phase produces the inputs the next phase needs.

### Phase 1 (now), Audit

Phase 1 is auditing. The deliverable is enhanced NTLM logging in Windows 11 24H2 and Windows Server 2025, documented in KB 5064479 (published July 11, 2025) [733]. The new logging surface is `Applications and Services Logs > Microsoft > Windows > NTLM > Operational`, gated by two GPOs called "NTLM Enhanced Logging" and "Log Enhanced Domain-wide NTLM Logs." For each NTLM authentication, the event tells the administrator three things: *who* called (the process), *why* (the negotiated SSPI provider chose NTLM), and *where* (the target service). The KB also names per-event warning classes for NTLMv1, MIC-less, and EPA-not-supported authentications [733].

Phase 1 also closes the oldest residual: NTLMv1. Microsoft's deprecation page added an NTLM entry in June 2024 with verbatim language: "All versions of NTLM, including LANMAN, NTLMv1, and NTLMv2, are no longer under active feature development and are deprecated. Use of NTLM will continue to work in the next release of Windows Server and the next annual release of Windows. Calls to NTLM should be replaced by calls to Negotiate" [605].

The same row adds: "the NTLMv1 server feature is removed starting in Windows 11, version 24H2 and Windows Server 2025": the November 2024 update note [605]. The KB 4090105 pre-24H2 NTLMv1 auditing surface (Event ID 4624 with `Package Name (NTLM only): NTLM V1`) remains valid for legacy environments [734].

### Phase 2 (H2 2026): IAKerb + Local KDC + Negotiate-first refactor in pre-release

Phase 2 puts those four engineered closures into pre-release. IAKerb and Local KDC ship for Windows Insiders and Server preview channels. The Negotiate-first refactor lands. Microsoft's own subsystems audit their `AcquireCredentialsHandleW("Ntlm",...)` and `RPC_C_AUTHN_WINNT` call sites and replace them with `Negotiate` calls. Per-machine policy controls for NTLM scope make finer-grained restriction possible. IP-SPN policy lands so the "no SPN" case can be closed without naming every server by FQDN [718,719].

The Microsoft outreach mechanism for Phase 2 is the `ntlm@microsoft.com` mailbox; the January 2026 post names it explicitly as the channel for surfacing cross-forest, federated, and ISV-edge cases that need engineering help before Phase 3 [718].

### Phase 3 (next major Windows / Windows Server release): Disabled by default

Phase 3 is the default-off flip. Network NTLM authentication is disabled by default in the next major Windows and Windows Server release. The disablement is a configuration, not a binary removal: NTLM remains in the OS, callable through `Negotiate` only when a policy explicitly re-enables it for a named scope [718]. The Hacker News' summary of the roadmap published February 2026 documents the same three-phase structure for industry-press consumption [735].

> **Walkthrough: the disablement roadmap as a dependency chain.**
>
> 1. Phase 1 turns on visibility before enforcement. KB 5064479 gives administrators process, target, and reason data for NTLM use; Windows 11 24H2 and Windows Server 2025 also remove the NTLMv1 server feature. NTLMv2 remains present but deprecated [605,733].
> 2. Phase 2 uses that telemetry to make the fallback unnecessary. IAKerb and Local KDC enter pre-release, IP-SPN covers the missing-SPN case, and Microsoft's own code moves from explicit NTLM calls to `Negotiate` [718,719].
> 3. Phase 3 changes the default. Network NTLM is disabled by default in the next major Windows and Windows Server release; the caveat is the same as above: policy can still re-enable legacy scope, so this is compatibility disablement, not binary deletion [718].

| Phase | Deliverable | Date / target | Prerequisite | Primary |
|---|---|---|---|---|
| Phase 1 | Enhanced NTLM auditing | KB 5064479, July 11, 2025 | Windows 11 24H2 / Server 2025 | [733] |
| Phase 1 | NTLMv1 removal | Windows 11 24H2 / Server 2025, November 2024 | NTLM family deprecation (June 2024) | [605] |
| Phase 2 | IAKerb + Local KDC pre-release | H2 2026, Windows Insider channel | Phase 1 audit data identifies callers | [718,719] |
| Phase 2 | Negotiate-first refactor of Windows subsystems | H2 2026 | Phase 1 audit data | [717,718] |
| Phase 2 | IP-SPN policy for "no SPN" case | Windows Server 2025 + flighting | NEGOEX in Negotiate | [719] |
| Phase 3 | Network NTLM disabled by default | Next major Windows / Server release | All Phase 2 features GA | [718] |

Phase 3 is the first default configuration in 30 years that does not include NTLM. It is *not* the first configuration in 30 years without authentication-relay attacks. Why not?

## Proof surface: documented Windows probes, not captured lab output

This section is not a live-machine proof. The production record for this chapter does not contain a hash-verified VM capture, and the chapter will not pretend otherwise. What it can do, usefully, is show the exact Windows surfaces a reader should query when validating NTLM retirement in their own environment. Think of this as a reproducible probe map: commands, expected fields, and the reason each field matters.

The three probes correspond to the three questions an engineer has to answer before Phase 3. First, where is NTLM still happening? Second, which policy state is the machine enforcing or auditing? Third, is any legacy NTLMv1 path still visible on older systems? The distinction matters because Windows 11 version 24H2 and Windows Server 2025 removed the NTLMv1 server feature, while NTLMv2 remains deprecated rather than deleted [605].

> 🔵 **DOCUMENTED**: Microsoft Support, KB 5064479 enhanced NTLM auditing; documented probe, not captured lab evidence
> reproduce: `Get-WinEvent -LogName 'Microsoft-Windows-NTLM/Operational' -FilterXPath '*[System[(EventID >= 4020 and EventID <= 4033)]]' -MaxEvents 5 | Select-Object TimeCreated,Id,ProviderName,Message`

```text
Expected shape when enhanced NTLM/domain-wide auditing is enabled and NTLM occurs:
TimeCreated  : <event time>
Id           : 4020
ProviderName : Microsoft-Windows-NTLM
Message      : NTLM authentication audit data including the account/client,
               target/server, calling process, and reason NTLM was used.

This is documented behavior of the NTLM Operational channel and KB 5064479
logging enhancements. It is not output captured from this book's lab VM.
```

Use the enhanced NTLM events as the corrected migration work order: client events 4020/4021, server events 4022/4023, and domain-controller events 4030-4033 carry the Who/Why/Where fields KB 5064479 adds [733]. The `Message` field gives the operational detail. When this documented probe is converted to captured lab evidence, split the filter across those KB 5064479 IDs rather than copying a single legacy 4020 query. A process name tells you which binary needs owner assignment. A target tells you whether the failure is a service-principal-name problem, a local-account path, or a legacy endpoint. A reason code tells you which Phase 2 closure is relevant: a missing, unresolved, IP-address, or duplicate target name maps to SPN registration or IP-SPN policy; no domain-controller reachability maps to IAKerb; local-account traffic maps to Local KDC; direct NTLM calls map to code that bypassed `Negotiate`. The event is not merely an audit artifact. It is the join key between the old fallback and the new replacement.

> 🔵 **DOCUMENTED**: Microsoft Learn, NTLM policy and compatibility registry surfaces; documented probe, not captured lab evidence
> reproduce: `Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa','HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' | Select-Object PSPath,LmCompatibilityLevel,RestrictSendingNTLMTraffic,RestrictReceivingNTLMTraffic,AuditSendingNTLMTraffic,AuditReceivingNTLMTraffic`

```text
Expected shape when values are configured by local policy or Group Policy:
PSPath                       : ...\Control\Lsa
LmCompatibilityLevel         : <for example, 5 = send NTLMv2 response only;
                               refuse LM and NTLM>

PSPath                       : ...\Control\Lsa\MSV1_0
RestrictSendingNTLMTraffic   : <policy-controlled NTLM outgoing restriction>
RestrictReceivingNTLMTraffic : <policy-controlled NTLM incoming restriction>
AuditSendingNTLMTraffic      : <policy-controlled outgoing audit mode>
AuditReceivingNTLMTraffic    : <policy-controlled incoming audit mode>

The presence and meaning of these policy surfaces are documented. This block is
not a claim that these values were present on the book lab VM.
```

The registry probe is the control-plane half of the same story. `LmCompatibilityLevel` answers which response versions the machine is willing to send or accept. The Restrict NTLM values answer whether the machine is auditing, denying, or allowing sending and receiving paths. In a real migration, you do not read these values once. You read them next to enhanced NTLM event volume, per-server exemptions, and the outage blast radius of every caller that still names `Ntlm` explicitly.

> 🔵 **DOCUMENTED**: Microsoft Learn KB 4090105 legacy NTLMv1 audit surface; documented probe, not captured lab evidence
> reproduce: `Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} | Where-Object { $_.Message -match 'Package Name \(NTLM only\):\s+NTLM V1' } | Select-Object -First 5 TimeCreated,Id,Message`

```text
Expected shape on legacy systems where NTLMv1 auditing is enabled and an NTLMv1
logon occurs:
Id      : 4624
Message : ... Authentication Package: NTLM ...
          Package Name (NTLM only): NTLM V1 ...

On Windows 11 version 24H2 and Windows Server 2025, the NTLMv1 server feature is
removed; NTLMv2 remains deprecated, not deleted.
```

This legacy probe is included because mixed estates live longer than product roadmaps. A domain with Server 2025 domain controllers can still contain old member servers, appliances, or trust edges where NTLMv1 audit logic is the fastest way to find the last unsafe callers. The correct conclusion is narrow: NTLMv1 server support is removed on the named new platforms; NTLMv2 is the still-present fallback that Phase 3 disables by default.

Read these surfaces as architecture, not merely administration. The enhanced operational-channel events answer the Phase-1 question: where is NTLM still being used, by whom, by which process, and for what target? The registry and GPO-backed values answer the control question: is the machine merely compatible with NTLM, auditing NTLM, restricting it, or refusing older forms? The legacy Security-log probe answers whether older systems still emit NTLMv1. Before Phase 3, those three questions are the difference between migration and outage.

## Where this link breaks: what disabling NTLM cannot buy you

A blunt section. Phase 3 is real progress. It is not the end of authentication attacks on Windows. Three structural ceilings survive the transition; this chapter will not pretend otherwise.

### Disabled is not removed

Phase 3 still ships NTLM in the OS. The default is off; the policy lockout is exactly as strong as the domain's tier-0 administrative segregation, not stronger. An attacker who reaches a domain controller with Group Policy edit rights can flip the policy and re-enable NTLM for the scope they want. The wording in the January 2026 post is precise: "during phase 3, NTLM will remain present in the OS and can be explicitly re-enabled via policy if you still need it" [718].

This is the design choice Microsoft has to make, because removing NTLM binaries entirely would brick every third-party application that hard-codes `Ntlm` and every legacy device that has not been firmware-updated since 2018. "Disabled by default with policy override" is the only configuration that has any chance of getting deployed.

### Kerberos has its own relay class

The relay *class* does not depend on NTLM. KrbRelay, KrbRelayUp, resource-based constrained delegation (RBCD) abuse, unconstrained-delegation abuse, and S4U2Self / S4U2Proxy chains all survive the move to Kerberos with different named primitives: the territory of the Kerberos chapter (Chapter 17), the KRBTGT chapter (Chapter 18), and the Pass-the-Hash-to-Pass-the-PRT chapter (Chapter 19). Dec0ne's KrbRelayUp README calls the class a universal no-fix local privilege escalation in Windows domain environments where LDAP signing is not enforced, and the tool's default path is a useful representative flow rather than just a name in a taxonomy [693].

Walk the KrbRelayUp-style chain slowly. The attacker starts as a low-privilege local user on a domain-joined machine. They trigger the local machine account to authenticate to an attacker-controlled listener using Kerberos rather than NTLM. The relay forwards the Kerberos authentication to LDAP on a domain controller. If LDAP signing and channel binding are not enforced, the DC accepts the relayed authenticated LDAP session as the machine account. The attacker then writes an RBCD attribute that says a computer account they control is allowed to act on behalf of the victim machine. With that delegation edge in place, the attacker uses S4U2Self to obtain a service ticket to themselves for a target user and S4U2Proxy to turn that into a service ticket to the victim service. The final effect is local privilege escalation or service impersonation, depending on the exact target and delegation edge [693].

That chain is not NTLM relay with a different logo. Kerberos has tickets, authenticators, service names, and delegation extensions; the failure mode is not the NTLMv2 `AUTHENTICATE` message. The failure mode is still familiar: a verifier accepts a relayed authentication on a channel that is not cryptographically tied to the client that created it, then allows the resulting authenticated LDAP session to modify delegation state. LDAP signing and LDAP channel binding are therefore post-NTLM controls, not historical NTLM controls. Removing NTLM deletes the most abused relay substrate; it does not delete the need to require message integrity and channel binding on Kerberos-authenticated administrative protocols.

The defensive lesson is exact. If an administrator reads Phase 3 as permission to relax LDAP signing, EPA, or channel binding, they have misunderstood the roadmap. Phase 3 removes one fallback protocol. It does not make unsigned LDAP safe, and it does not make delegation attributes harmless. The named primitives change; the invariant remains: every authenticated administrative protocol has to bind identity to the channel and to the intended service.

### Local SAM hashes remain password-equivalent

The Local KDC reads the SAM. An attacker with SYSTEM-level access to the same machine reads the SAM too. Once they have the hash in hand, they can either feed it to a Local KDC running on a machine they control, or they can attempt offline cracking. IAKerb does not change either of those facts; what it changes is whether the *wire* exposes the password-equivalent secret. Defense in depth remains necessary [87]: TPM-backed key wrapping (Chapter 2), Credential Guard's VBS isolation of process credentials (Chapter 15), and BitLocker for the cold-boot scenario.

> **Key idea.** Phase 3 is a transition between tradeoffs, not a transition out of them. The exit from NTLM-the-protocol is not the exit from the authentication-relay class, or from the chip-layer credential class. The arc closes one specific 30-year-old attack surface and opens different conversations about the next.

If the structural classes survive, what practical problems remain that an administrator should worry about between today and Phase 3?

## Open problems at the 2026-2027 edge

Five named problems sit between Phase 1 (now) and Phase 3 GA. None is a reason to keep NTLM. Each is a reason not to treat default-off as magic. The best operators will spend 2026 converting the Phase 1 event stream into ownership, patches, exceptions, and removal work before the default changes underneath them.

1. **ESC8 field deployment of EPA on `/certsrv/` is uneven.** Microsoft published KB 5005413 on July 23, 2021 with the dispositive recipe: `<extendedProtectionPolicy policyEnforcement="Always" />` on every `/certsrv/` virtual directory, plus disabling plain HTTP [713]. That recipe is narrow and concrete because the vulnerability class is narrow and concrete: NTLM authentication to AD CS Web Enrollment must be bound to the TLS channel, or a relayed machine account can enroll for a certificate. Server 2025 hardening pushes EPA to required-by-default in many AD CS templates, but many production CAs are older, inherited, or deliberately configured for compatibility. Microsoft's KB frames PetitPotam as a classic NTLM relay attack against AD CS, and the later LSA-spoofing variants showed the same lesson after initial PetitPotam mitigations: named CVEs are snapshots of a broader coercion-and-relay class. The operational lesson is not that any one CVE is the only danger. The lesson is that coercion primitives keep finding new front doors while `/certsrv/` remains the high-value back door [713].

2. **Third-party and legacy-app hard-coded NTLM.** Microsoft's Negotiate-everywhere refactor covers Microsoft's own code. It does not rewrite a backup agent, a line-of-business thick client, a NAS appliance, an old Java bridge to SSPI, or a vendor service that calls `AcquireCredentialsHandleW` with `"Ntlm"` because the original developer copied sample code in 2006. Phase 1's enhanced auditing surface (KB 5064479) is the practical instrument for identifying those callers: every NTLM authentication can carry the calling process name, target, and reason code [733]. The hard part is organizational rather than cryptographic. Someone has to own the binary, find the code path, change it to `Negotiate`, test Kerberos with SPNs and channel binding, and decide whether a temporary per-server exception is acceptable. Phase 3 will make any skipped ownership visible as outage.

3. **Cross-forest and federated IAKerb edges.** Single-forest IAKerb is conceptually clean: the application server can reach the KDC that the client cannot, so it ferries AS and TGS traffic. Multi-forest, partner-trust, and federation scenarios are messier. The proxying server may not be in the same forest as the KDC. SPN construction may cross aliasing, CNAME, or IP-SPN policy. A trust path may allow Kerberos for one service but not for the local-account or offline path the application historically covered with NTLM. NEGOEX has to carry the mechanism negotiation under the same `Negotiate` call while preserving enough metadata for both sides to pick the right Kerberos path [730,731,728]. Microsoft's `ntlm@microsoft.com` outreach mailbox exists precisely because those edges need field reports before Phase 3, not after [718].

4. **Linux and macOS parallel.** The open-source world is not starting from zero. MIT Kerberos has had IAKerb since 1.9, released in December 2010. Apple's GSS framework has exposed `GSS_IAKERB_MECHANISM` since macOS 10.14. The Samba and `localkdc` work described by Bokovoy and Schneider at FOSDEM 2025 is the parallel path for local authentication without NTLM: a Linux machine that can act as the IAKerb application server for a Windows client, or vice versa, under the same `Negotiate` envelope [729]. The open problem is not whether non-Windows systems can understand the concepts. It is whether heterogeneous estates will test the exact library versions, Samba roles, SPNs, and local-account semantics they actually deploy.

5. **Policy pressure and exception debt.** EU NIS2 requires covered entities in critical sectors to adopt cybersecurity risk-management measures and reporting processes; the Cyber Resilience Act adds lifecycle cybersecurity requirements for products with digital elements [736,165]. This chapter is not a regulatory analysis, and those texts do not mention NTLM; the authentication implication is narrower: a published vendor deprecation plus a named audit surface turns "legacy authentication" into evidence. An organization can show KB 5064479 data, count remaining NTLM callers, assign owners, document exceptions, and demonstrate retirement progress [605,733]. The inverse is also true. A domain that re-enables NTLM broadly after Phase 3 will need to explain why a deprecated, default-off authentication path stayed in production.

> **Aside.** The EU regulatory framing is intentionally light because the primary texts are extensive regulatory documents this chapter does not quote verbatim beyond official summaries. The relevant connection is operational: deprecation pages and audit logs give compliance teams an artifact for "we are retiring this class of credential under a published deprecation," which is the kind of evidence auditors and regulators can evaluate.

All five problems converge to one question for the AD engineer reading this chapter: *what should I do this quarter?*

## What it means for you

Six numbered actions, ordered by impact. No filler, no compliance boilerplate.

> **Defensive priority 1: Audit NTLM with the Windows 11 24H2 / Server 2025 enhanced auditing surface.**
>
> This is the prerequisite. Without Who/Why/Where data, Phase 3 surfaces breakage as outage. Enable the "NTLM Enhanced Logging" and "Log Enhanced Domain-wide NTLM Logs" GPOs on every domain controller and member server you operate. Subscribe to the `Applications and Services Logs > Microsoft > Windows > NTLM > Operational` channel. Identify every process that initiates NTLM, the reason `Negotiate` declined Kerberos, and the target service. Triage by call volume and criticality [733].

> **Defensive priority 2: Enforce LDAP signing AND channel binding on every DC.**
>
> Set `LDAPServerIntegrity = 2` and `LdapEnforceChannelBinding = 2` on every domain controller. This is the server-side LDAP signing setting, distinct from client-side `LDAPClientIntegrity`; Microsoft documents the DC policy path as **Domain controller: LDAP server signing requirements** [737]. The control closes SMB-to-LDAP relay regardless of whether the originating authentication was NTLM or Kerberos. KrbRelayUp's existence makes it *more* urgent post-NTLM, not less: the relay class on Kerberos uses the same un-anchored LDAP target [693].

> **Defensive priority 3: Require EPA first on AD CS Web Enrollment, then stage it across other IIS-hosted Windows-authentication endpoints.**
>
> The KB 5005413 recipe is verbatim for AD CS: add `<extendedProtectionPolicy policyEnforcement="Always" />` where applicable and disable plain HTTP. `/certsrv/` is the dispositive ESC8 target. Certificate Enrollment Web Service and policy/proxy endpoints are the second tier. For other IIS-hosted Windows-authentication applications, stage EPA with owner testing: inventory compatibility first, then move from audit/partial modes to required channel binding where the application can support it [713].

> **Defensive priority 4: Disable Spooler on DCs and any server you do not print from.**
>
> The Print Spooler service is the single highest-impact MS-RPRN coercion surface. Disabling Spooler on every server that does not actually print closes the entire `RpcRemoteFindFirstPrinterChangeNotificationEx` coercion class on those hosts. Microsoft's hardening guidance and the PrintNightmare disclosures (2021) made this an explicit recommendation [726].

> **Defensive priority 5: Audit RPC interfaces for the MS-EFSR / MS-DFSNM / MS-FSRVP / MS-RPRN coercion surface.**
>
> Coercer's scan mode is a practical defensive auditing tool: it inventories which RPC coercion methods a given server still answers. Run it against every server you operate, in scan mode and with change-control approval. The output is a list of unauthenticated and authenticated coercion endpoints to either patch, disable, or compensate around. Treat unauthenticated endpoints (LSARPC, `\PIPE\lsarpc`) as P0 [708,710].

> **Defensive priority 6: Plan the Phase-3 transition now.**
>
> Microsoft's preferred sequence: Windows Insider flighting → pilot non-production NTLM-off configurations → identify hard-coded `Ntlm` SSPI calls in your in-house code → stage Phase-3 rollout against your audit data. If you wait, the cut-over surfaces breakage as outage. If you audit, the cut-over is uneventful [718].

The Phase 1 audit is the load-bearing piece. Priority 1 produces the data that makes priorities 2-6 prioritise correctly. The triage an administrator applies after parsing the KB 5064479 events is small: classify each blocked authentication by reason. Reason names such as `ExplicitNtlm`, `NoSPN`, `NoDcReach`, or `LocalAccount` are illustrative labels, not literal Microsoft event strings; the published events carry numeric Usage IDs and descriptions [733].

> **Common pitfalls (field-deploy mistakes).**
>
> - **`LMCompatibilityLevel = 5` without audit.** Forcing NTLMv2-only on every DC is correct as an endpoint, but flipping it without first running KB 5064479 audit will outage legacy applications that still attempt NTLMv1 [733].
> - **`RestrictNTLM:Deny` without exceptions.** The Restrict NTLM family of GPOs supports per-server exemptions. Going straight to `Deny` without an exemption list is the classic outage path.
> - **EPA on HTTPS-only while leaving plain HTTP enabled.** KB 5005413 explicitly requires *both* `policyEnforcement="Always"` and disabling plain HTTP on `/certsrv/`. Leaving HTTP up makes the EPA enforcement moot [713].
> - **Trusting Credential Guard against coercion.** Credential Guard protects against credential *theft*. It does not protect against ESC8, PetitPotam, or any other relay-of-live-authentication chain [87].

> **Phase 2 pilot caution.** On a non-production Windows 11 Insider machine, the per-machine NTLM scope policy lives under `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0`. Microsoft's pre-release documentation will name the value used to gate the Phase 2 IAKerb / Local KDC behaviors; consult the Windows Insider release notes that ship with the Phase 2 flight rather than hard-coding a value here. The keys are subject to change up to GA. Use the `ntlm@microsoft.com` outreach channel for any environment-specific question [718].

This is the work. The Phase 3 deadline is the next major Windows release; the Phase 1 audit window is right now. If you wait, the cut-over surfaces breakage as outage. If you audit, the cut-over is uneventful.

## Closing

NTLM was the answer to a 1987 problem and a 1993 problem. It survived because removing it required engineering four orthogonal capabilities that did not exist. They exist now. The next major Windows release ships without it on by default. The attacks that follow it (KrbRelayUp, RBCD chains, S4U2Self abuse, certificate-template misconfiguration) target a different protocol with a different vocabulary. The relay *class* persists. The protocol it targets is no longer NTLM.

NTLM removal is one strand of a larger weave. The Windows Access Control chapter (Chapter 22) covers the authorization model (`SeAccessCheck` and its inputs); the chip-and-credential chapters (the TPM in Chapter 2, Pluton in Chapter 3, and Credential Guard in Chapter 15) cover where keys are sealed and isolated; and the application-identity chapters, Authenticode and Catalog Files (Chapter 12) and AppLocker vs App Control for Business (Chapter 13), cover which code is allowed to run at all. NTLM removal advances the same move every one of those links makes: from "trust the perimeter" to "tie every credential to a token, a chip, or a Kerberos ticket whose lifetime you can name." Each strand by itself is incomplete; together they are how the next decade of Windows authentication looks.

> **Bequeaths.** This chapter hands the next link one guarantee: once Phase 3 ships, NTLM is no longer a default network fallback, so Kerberos becomes the sole interactive domain authentication protocol Windows reaches for: every case that historically dropped to NTLM (no DC line-of-sight, local accounts, missing SPN, hard-coded `Ntlm`) now routes through `Negotiate` to Kerberos or to its IAKerb, Local KDC, and IP-SPN replacements. The Kerberos chapter (Chapter 17) takes the handoff from here. But the bequest is deliberately narrow. It does NOT remove the relay *class*: KrbRelay, KrbRelayUp, RBCD, and S4U abuse all survive on Kerberos and belong to the Kerberos chapter (Chapter 17), the KRBTGT chapter (Chapter 18), and the Pass-the-Hash-to-Pass-the-PRT chapter (Chapter 19). It does NOT isolate the tickets Kerberos mints from the long-term keys Credential Guard already protects (Chapter 15). And it does NOT protect the local SAM: a box owned as SYSTEM still yields password-equivalent hashes to the tradecraft of the Mimikatz chapter (Chapter 14). The chain retires the protocol; it does not retire the relay.
