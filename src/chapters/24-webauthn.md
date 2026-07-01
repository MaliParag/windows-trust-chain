# WebAuthn and Passkeys

::: trust-ledger

- **Inherits:** The hardware-bound asymmetric credential and local user-verification gesture. A private key the verifier never receives, usable only after a PIN, face, or fingerprint unlocks it (Chapter 12, Windows Hello); and the TPM-sealed, non-exportable key whose private half the operating system can use but never read (Chapter 2, The TPM).
- **Promise:** When a user signs in with a platform-bound Windows passkey, the relying party receives only a public key and an origin-bound signature; the long-term private key never leaves the TPM and signs only after a Windows Hello gesture, so a relying-party impersonator (adversary-in-the-middle) cannot induce a usable credential and a verifier-database leak yields no authenticator. Serviced boundary: the browser/app ↔ relying-party network channel, bound by `clientDataJSON.origin` and `rpIdHash`.
- **TCB:** `webauthn.dll` (the OS dispatcher), the TPM-backed platform authenticator and CNG/NCrypt key provider, Windows Hello as the user-verification gate, the browser's correct origin determination, and the relying party's server-side verification of origin, `rpIdHash`, challenge, and signature. For a synced or vault-backed passkey the sync fabric or third-party vault joins the TCB.
- **Adversary → Break:** The adversary stops attacking the ceremony and attacks the *lifecycle*. Origin binding defeats AitM phishing and the public-key model defeats verifier compromise, but the system's assurance is the *minimum* of the sign-in ceremony and the recovery flow, and the major consumer and enterprise recovery flows surveyed here bottom out at weaker primitives (SMS-OTP, a retained recovery key, audited helpdesk discretion, or sync-fabric account recovery). Synced and vault-backed passkeys additionally remove the single-TPM non-exportability premise; NIST treats their assurance ceiling as AAL2 because of the syncable-authenticator and recovery model, even when key material is end-to-end encrypted at rest. Coerced consent and same-device kernel malware are outside the protocol entirely.
- **Residual:** Recovery-flow strength is diagnosed here, but the session a strong sign-in mints is governed downstream: bearer-token issuance and revocation → Zero Trust (Chapter 26) and Continuous Access Evaluation (Chapter 27); the enterprise transport carrying the resulting assertion → Kerberos (Chapter 17), and the legacy protocol it displaces → The Death of NTLM (Chapter 16); same-device kernel-mode malware and the secure-world gesture path → The Secure Kernel (Chapter 6) and Credential Guard (Chapter 15); the TPM AIK/EK attestation chain and the biometric-template internals behind the UV gesture → The TPM (Chapter 2), Attestation (Chapter 5), and Windows Hello (Chapter 20); plug-in-registration telemetry → ETW: The EDR Substrate (Chapter 25). Post-quantum forgeability of the COSE/TPM signature algorithms is out of scope for this book's chain.
- **Bequeaths:** Origin-bound, non-replayable front-door authentication (in its strongest form a platform-bound Windows Hello passkey that reaches AAL3 at the moment of sign-in), the floor the cloud-session chapters Zero Trust (Chapter 26) and Continuous Access Evaluation (Chapter 27) stand on when they govern the session that sign-in mints. Does NOT provide: recovery-flow strength (the system's AAL is the minimum of ceremony and recovery), AAL3 for synced or vault-backed passkeys, defense against a coerced user, or protection from kernel-mode malware already on the device.
- **Proof:** 🔵 documented + reproducible. W3C WebAuthn Level 3, FIDO CTAP 2.x, NIST SP 800-63-4, and Microsoft Learn / the `microsoft/webauthn` header; the PowerShell probes below are the local capture recipe. No 🟢 capture: WebAuthn signing needs a Windows host with a TPM, which this Linux build host is not.
:::

> **The Reasoner's question.** When a user signs in with a passkey on Windows, what is bound to the relying party, what stays inside the authenticator, and where does the trust chain fall back to weaker recovery machinery?

---

> **Foundations. What you need before this chapter.**
>
> - **Windows Hello (Chapter 20).** The local user-verification gesture (PIN, fingerprint, or face) that unlocks key use without becoming the remote secret. In this chapter Hello is the `UV` provider: it proves the local user is present and verified before a WebAuthn credential signs. The gesture and biometric-template internals belong to that chapter.
> - **TPM 2.0 (Chapter 2).** A Windows platform passkey is normally backed by the TPM and exposed through `webauthn.dll`; the private key is never exported to the browser or relying party, only used after Hello unlocks it. The sealing and attestation internals belong to the TPM chapter.
> - **Relying party and origin.** The relying party is the service that owns the account. The origin is the scheme, host, and port the browser is actually on. WebAuthn's security comes from binding signatures to the relying party identifier derived from that origin.
> - **CTAP.** The Client-to-Authenticator Protocol is the wire format between the client and authenticator: USB, NFC, BLE, platform APIs, or hybrid transport. WebAuthn is the browser/API layer; CTAP is the authenticator layer.
> - **Passkey.** A user-facing name for a discoverable WebAuthn credential. The credential can be device-bound in a hardware authenticator or synced through an end-to-end-encrypted platform or password-manager fabric. That lifecycle distinction matters as much as the cryptography.
> - **Reasoner stance.** Count factors only after asking what an attacker must defeat: phishing resistance, verifier-compromise resistance, replay/relay resistance, step-up, and recovery. The old know/have/are taxonomy is not strong enough for this chapter.

---

> **Chapter thesis.** **Password plus push-notification MFA is no longer a strong authenticator.** 2024-2026 adversary-in-the-middle phishing kits walk straight through it. WebAuthn and passkeys are strong, but only if you score them against the right axes (phishing resistance, verifier-compromise resistance, replay/relay resistance, step-up, recovery), not the inherited know/have/are taxonomy. This chapter walks the five-axis criteria framework, the WebAuthn Level 3 plus CTAP 2.x protocol layer, and the Windows-specific stack: `webauthn.dll`, Windows Hello as the user-verification gesture, the Windows 11 24H2 third-party passkey provider plug-in model, hybrid transport from a phone, and the seven attestation statement formats. The thesis the chapter lands on: a passkey deployment is exactly as strong as the weakest path back into the account; in the major consumer platforms surveyed here, that recovery path is weaker than the authentication ceremony itself, while managed enterprises can improve the floor only by engineering recovery with the same care as sign-in.

## Two factors, no security

A junior engineer at a mid-size firm types her Microsoft 365 credentials into what looks exactly like the real `login.microsoftonline` page, approves the push notification on her phone, and an hour later the security team is reading her inbox: because the attacker was, too. The kit is Tycoon 2FA, the technique is reverse-proxy adversary-in-the-middle, and the marketing claim that "password plus MFA is two factors" just lost to a commodity off-the-shelf service. The same class of phishing-as-a-service kit (Evilginx, Caffeine, EvilProxy, Tycoon 2FA) is the dominant phishing toolset in 2024-2026; the kit sits between the user and the real Microsoft login page, captures the credentials and the post-MFA session cookie in flight, and hands a live session to the attacker [888].

Replay the exact same attack against a colleague whose only authenticator is a WebAuthn passkey. The kit serves the look-alike page; the page hands the browser a WebAuthn `PublicKeyCredentialRequestOptions` blob with a fresh challenge. The browser builds `clientDataJSON` with `type: "webauthn.get"`, the actual origin the user is on (the look-alike domain `login-microsoft0nline.example`, protocol scheme included), and the challenge. The browser will not let the look-alike page claim Microsoft's real `rpId` (the `rpId` must be a registrable suffix of the actual origin), so the authenticator is queried for a credential scoped to the look-alike domain and finds nothing. It never registered a passkey for that domain. There is no signature to relay. The kit gets bytes that the real Microsoft server will reject on the first verification step. Microsoft's own documentation puts it bluntly: passkeys "use origin-bound public key cryptography, ensuring credentials can't be replayed or shared with malicious actors" [879].

The know/have/are taxonomy ranks these two ceremonies as the same. Password plus push is "something you know" plus "something you have," and so is password plus a passkey on a YubiKey. The taxonomy predicts that both ceremonies are roughly twice as strong as one factor alone. The phishing kit demolishes one and bounces off the other. *The taxonomy is wrong.*

The right question is not "how many factors did the user produce?" It is "what does the attacker have to defeat?" The know/have/are buckets group authenticators by what the user *feels* they are producing. The criteria framework groups them by *what an attacker has to defeat*. Only the second taxonomy predicts the outcome of a real-world attack. The phishing kit walks through password plus push because nothing in that ceremony binds the user's secret to a specific origin. It bounces off the passkey because the passkey signs over the origin the browser is actually on, and no amount of reverse proxying changes that string.

If the taxonomy is wrong, what is the right one? That is the question the criteria framework answers.

## The criteria framework: five axes that actually predict outcomes

The replacement for know/have/are is a five-row table. The rows are *what an attacker has to defeat*, not *what the user thinks they are producing*. NIST SP 800-63-4 does not enumerate exactly these five axes; this is the chapter's synthesis of NIST's normative criteria with FIDO and IETF literature. The spine of the table is taken from NIST SP 800-63-4 (final, July 2025) [889], NIST SP 800-63B-4 [890], the FIDO Alliance Authenticator Certification Levels [891], and the IETF channel-binding lineage that runs from RFC 5056 (Williams, November 2007) [892] through RFC 9266 (Whited, July 2022) [893].

> **Definition, Phishing-resistant authenticator.**
> An authenticator whose protocol prevents a relying party impersonator (an adversary-in-the-middle) from inducing the authenticator to release a usable credential value. NIST SP 800-63B-4 formalizes the requirement as *verifier-impersonation resistance*. The practitioner formulation, courtesy of Yubico, is verbatim: an authenticator is phishing-resistant if it binds its output to a communication channel or a verifier name [894].

**Axis 1: phishing resistance**

The criterion: can a look-alike domain induce the user (or the user's authenticator) to release a credential value that the look-alike then replays to the real verifier? Password plus any unbound second factor (SMS-OTP, TOTP, push) fails the criterion: the kit just forwards every value the user produces. WebAuthn passes it by construction: the authenticator signs over `clientDataJSON`, which the *browser* fills in with the actual origin the user is on, and the signature is computed jointly over a hash of the RP identifier derived from that origin. The RP refuses any signature whose RP-ID hash does not match the registered `rpId`.

> **Definition, Origin binding.**
> The mechanism by which WebAuthn enforces phishing resistance: the browser writes the user's actual origin into `clientDataJSON.origin`, the authenticator signs over the SHA-256 hash of the canonical RP identifier (`rpIdHash` in `authenticatorData`), and the relying party validates that `rpIdHash` matches the RP identifier under which the credential was registered. The cryptography is trivial. The value is in the binding.

Microsoft's Entra documentation states the criterion verbatim: passkeys "provide verifier impersonation resistance, which ensures an authenticator only releases secrets to the Relying Party (RP) the passkey was registered with and not an attacker pretending to be that RP" [879].

**Axis 2: verifier-compromise resistance**

The criterion: if the relying party's authentication database is exfiltrated, can the attacker use the stolen material to log in? Passwords fail this criterion in the worst possible way: a salted hash is replayable after offline cracking, and a billion-row password dump is the standard primary input to credential stuffing. The public-key model passes the criterion definitionally. The relying party stores only the credential's public key; no signature is ever made by the relying party. Even a complete database leak gives the attacker zero authenticators.

This criterion is older than WebAuthn by half a century. Morris and Thompson's 1979 password paper made the verifier-compromise case for hashing passwords on a multi-user UNIX system [895]; the WebAuthn move is the realisation that even bcrypt'd password databases lose this criterion eventually, because the work factor that protects them today is one Moore's-law decade away from being trivial.

**Axis 3: replay and relay resistance**

The criterion: can an attacker who observes one successful authentication replay it later, or relay it to a different verifier? OTP-based ceremonies (HOTP [896], TOTP [897]) provide partial replay resistance via a per-instance counter or timestamp, but they offer almost no relay resistance: the AitM kit forwards the OTP through its proxy within the OTP's validity window.

WebAuthn passes the criterion with three layered mechanisms. The first is a fresh challenge issued by the RP for every ceremony, which the authenticator signs over. The second is a signature counter in `authenticatorData` that, when an authenticator maintains one, increases on each use; a regression is a clone signal the relying party can reject, though zero or non-monotonic counters (common for synced passkeys) are allowed. The third is channel binding: the structurally correct answer to relay attacks, which sits at the TLS layer rather than the application layer. (The IETF Token Binding stack (RFC 8471, RFC 8473, both October 2018) [898] [899] was the most ambitious attempt at the channel-binding criterion at the application layer. Both RFCs remain Proposed Standard at the IETF (the datatracker history pages record no Historic reclassification event for either [900] [901]) but Chromium disabled the feature path around the RFC publication window and removed Token Binding support in Chrome 72 in January 2019; no major browser has implemented it since [902] [903]. The `clientDataJSON.tokenBinding` field is therefore a no-op in 2026 production. WebAuthn solves the criterion above the channel by signing the origin into the assertion itself.)

The cleaner channel-binding answer is RFC 9266 `tls-exporter` for TLS 1.3 (Whited, July 2022) [893], which extends RFC 5056's channel-binding framework into the TLS 1.3 world, but no major browser wires `tls-exporter` into WebAuthn out of the box as of January 2026. The current WebAuthn deployment treats the origin string in `clientDataJSON` as the primary channel binding, with HTTPS itself providing the underlying TLS guarantee.

**Axis 4: step-up and session continuity**

The criterion: can the relying party demand a *fresh* authentication for a high-value action (transfer money, change password, invite a user), and can it tell the difference between a session that was authenticated with strong factors and one that was authenticated with weak factors? WebAuthn answers this with two flag bits in `authenticatorData`. `UP` (user present) is set when the authenticator detected a presence test: a touch, a click, an NFC tap. `UV` (user verified) is set when the authenticator additionally verified the user via PIN, biometric, or other gesture. A relying party that demands `userVerification: "required"` can force `UV=1` on the assertion; an RP that issues a fresh challenge for a high-value action gets a fresh signature tied to that challenge.

Generic transactional confirmation ("sign a description of *this specific transaction*") was attempted in WebAuthn's earliest drafts via the `txAuthSimple` and `txAuthGeneric` extensions [904]. Neither extension was ever implemented by browsers, and both are absent from the Level 3 specification surface as of January 2026 [905]. Secure Payment Confirmation, a sibling W3C specification (Web Payments Working Group) that builds on WebAuthn via the `payment` extension [865], is the productised replacement for payment transactions; general transactional authorization remains an open problem.

**Axis 5: recovery and lifecycle**

The heretical thesis: this is the only axis that matters in production, and it is the axis on which every modern platform still bottoms out at a single-factor primitive. We will foreshadow it here and land on it in the recovery section. A passkey ceremony that scores AAL3 phishing-resistant at the authentication moment can be a single-factor SMS-OTP at the recovery moment, and the *system's* AAL is the recovery flow's AAL, not the authentication ceremony's. Microsoft's Entra documentation already flags account recovery as a load-bearing deployment cost: FIDO2 keys "can increase costs for equipment, training, and helpdesk support. Especially when users lose their physical keys and need account recovery" [879].

> **Note. Recovery is the factor.**
> The single most predictive question about an authentication system is not "what factor does the user produce at sign-in?" but "what factor produces the credential when the user has lost the original one?" We come back to this in the recovery section.

**The criteria table as a spine**

The five axes give the chapter its spine. Every later section fills in a row of the same five-column table. The columns are the strongest authenticators we have shipped: password, password plus SMS-OTP, password plus TOTP, password plus push with number matching, device-bound FIDO2 hardware key, synced passkey, and a hypothetical "recovery-flow-aware" composite. The criteria-aware ranking later in this chapter re-orders that table in a way the know/have/are taxonomy cannot.

> **Key idea.**
> The know/have/are taxonomy groups authenticators by what the user feels they are producing. The criteria framework groups them by what an attacker has to defeat. Only the second taxonomy predicts the outcome of a real-world attack.

If these are the right axes, when did we figure that out?

## Where the taxonomy came from

The know/have/are taxonomy did not appear all at once. The 1970s and 1980s operating-systems literature already grouped authentication factors into "something the user knows," "something the user has," and "something the user is". It was a way of talking about the design space, not a regulatory criterion. The taxonomy entered U.S. federal procurement via the Department of Defense's *Trusted Computer System Evaluation Criteria* in December 1985: the Orange Book, DOD 5200.28-STD [906], which required identification and authentication at every assurance class above D and made passwords the canonical *something you know* in federal IT. The Orange Book did not invent the taxonomy; it codified it.

Two decades later, in June 2004, NIST canonised the same taxonomy as the U.S. federal regulatory framework. NIST SP 800-63 *Electronic Authentication Guideline*: by William Burr, Donna Dodson, and W. Timothy Polk: defined four assurance levels and tied each to a combination of authenticator categories that the levels could accept [907] [908]. Burr's framework absorbed two decades of accumulated practice with hardware OTP tokens. The canonical commercial OTP product, RSA SecurID, had shipped in 1986 (a key fob that produced a fresh code each minute using a built-in clock and a factory-encoded seed [909]) and SP 800-63 explicitly accepted SecurID-class authenticators at the higher assurance levels. The four-level structure (later AAL1 through AAL3 in the post-2017 redesign) lasted through SP 800-63-1 (2011), -2 (2013), -3 (2017), and -4 (2025); every revision is recognizably the same shape [910]. (The CSRC bibliographic page for the 2004 first edition renders the leading author as a blank entry preceded by a stray comma for reasons unrelated to authorship. The actual cover-page authorship is Burr, Dodson, and Polk: the citation in the references list above uses the correct three-name form.)

In parallel, the cryptographic protocol literature was building the *criteria* taxonomy that would eventually displace know/have/are. Bellcore's Neil Haller published RFC 1760 in February 1995: the S/KEY one-time password system, a Lamport hash chain that produced a fresh login secret each time and that an eavesdropper could not replay [911]. Haller's text already says the technique was first suggested by Leslie Lamport, which makes 1995 the first IETF standardization of replay-resistance as a design criterion. RFC 4226 (HOTP, December 2005) [896] and RFC 6238 (TOTP, May 2011) [897] generalized the same idea into the synchronised counter and time-based variants the world now calls "authenticator app" codes.

The verifier-impersonation criterion got its first IETF expression in November 2007. Nico Williams' RFC 5056 *On the Use of Channel Bindings to Secure Channels* defined the concept that "the two end-points of a secure channel at one network layer are the same as at a higher layer," and bound authentication at the higher layer to the channel at the lower layer [892]. RFC 5056 was the protocol-literature acknowledgment that authentication needed to be tied to *something the network attacker could not change*: the channel itself, not just the user's typing.

Kim Cameron's *The Laws of Identity*, published on identityblog.com in May 2005, captured the same idea from a higher-level perspective. The seven Laws are a framework for federated identity on the open Internet; Laws 2 ("minimal disclosure for a constrained use") and 4 ("directed identity") are the conceptual ancestors of WebAuthn's *origin binding* and *per-RP key pair* design [912]. Cameron was Microsoft's Chief Architect of Identity through this period, and the Laws shaped a generation of Microsoft thinking on identity. The Laws preceded the consortium that would actually ship the protocol by eight years.

> **Aside: Why the taxonomy stuck.**
> The criteria framework was *available* in the literature by 2007: replay resistance from S/KEY (1995), channel binding from RFC 5056 (2007), origin binding from Cameron's Laws of Identity (2005). It did not displace know/have/are in regulatory documents until NIST SP 800-63-3 in 2017 (which introduced the "phishing-resistant authenticator" term) and SP 800-63-4 in 2025 (which made verifier-impersonation resistance a first-class criterion). Why the gap? The know/have/are taxonomy is *legible to procurement*. It produces neat checkboxes. The criteria taxonomy is *cryptographically meaningful* but produces fewer neat checkboxes. Regulation prefers checkboxes until breach data forces a change.

![Figure: Forty years of authentication standards on four converging tracks: Regulatory (Orange Book → NIST SP 800-63 → SP 800-63-3 → SP 800-63-4), Protocol (S/KEY → HOTP/TOTP → RFC 5056 → Token Binding), FIDO (U2F → WebAuthn+CTAP2 → passkeys → CTAP 2.2), and Windows (webauthn.dll → ECC+Conditional UI → third-party providers): all feeding the five-axis criteria framework: phishing resistance, verifier-compromise resistance, replay/relay resistance, step-up, and recovery.](diagrams/24-webauthn-standards-timeline.svg)

By 2007 the criteria framework was on paper. By 2013 there was a consortium for it: the FIDO Alliance launched on 12 February 2013, with six founding members [861]. Earlier identity-layer attempts (Mozilla Persona / BrowserID, launched July 2011, with decommissioning announced January 2016 and the service shut down on 30 November 2016 [913]) had tried to build a browser-mediated identity layer at the HTTP level and failed to achieve traction. The FIDO consortium took a different bet: solve the authentication ceremony first, leave the identity-layer above it to OIDC and SAML. What happened first in a browser?

## U2F: the first browser ceremony designed against phishing

December 2014. Yubico, Google, and NXP Semiconductors publish FIDO 1.0 / Universal 2nd Factor (U2F) [914]; U2F 1.0 reached Proposed Standard status on 9 October 2014, with the broader FIDO 1.0 announcement window running through December [914]. The FIDO overview catalogs the design tradeoffs explicitly: a U2F device mints origin-specific keys, checks the origin hash before signing, and refuses to sign if the relayed key handle does not match the request origin [914]. This was the first time a browser ceremony was designed against the phishing-resistance criterion as a *primary* goal rather than as an afterthought.

The U2F ceremony has five field-level moving parts. An *AppID* string identifies the relying party, derived from the page's origin so a phisher's domain cannot produce a U2F signature for the real bank. A *challenge* is a per-ceremony nonce the relying party generates. A *key handle* is an opaque blob the authenticator returns at registration and supplies on every later assertion; the relying party uses it to address the right credential on the next challenge. A *signature counter* increments monotonically on every assertion, letting the relying party detect simple cloning. And the *signature* itself is an ECDSA P-256 signature over the AppID hash, the challenge, the counter, and a presence flag.

The AppID rule is the load-bearing piece. The browser computes the AppID from the actual origin the user is on; the authenticator signs over its hash; the relying party compares it to the AppID under which the credential was registered. A look-alike domain produces a different AppID, which produces a different signature, which the real verifier rejects. This is the same trick WebAuthn will later generalize as `rpId` binding, and it is the trick that makes a U2F signature for the real RP structurally unusable to an AitM kit operating from a different origin. Password capture, fallback paths, and stolen sessions remain deployment risks; the U2F signature itself is the part the kit cannot replay.

The canonical deployment paper is *Security Keys: Practical Cryptographic Second Factors for the Modern Web*, by Juan Lang, Alexei Czeskis, Dirk Balfanz, Marius Schilder, and Sampath Srinivas, in the Financial Cryptography 2016 preproceedings [915]. The paper documents Google's internal rollout: a hardware second factor for every employee, replacing the company's previous OTP-based MFA. The empirical scoreboard for the criteria framework gets its first data point here: after the rollout, Google reported zero phishing-related account takeovers on employee accounts during the deployment period. This is not a controlled study; it is the largest natural experiment in deployed phishing resistance the industry had seen.

> **Note. What U2F got right.**
> U2F is the moment the authentication community made a structural design choice: phishing resistance is a property of the *protocol*, not of *user training*. No amount of "look for the lock icon" advice closes the phishing gap; a protocol that signs over the origin closes it by construction.

U2F's limitation is that it is, by design, a *second* factor. The password under it remains the load-bearing weak link: a credential-stuffer can reuse the password against a service that does not require U2F, and a phisher can still capture the password even if they cannot capture the U2F signature. The AppID idea was correct; what was missing was the willingness to make the strong factor *the* factor, not a layer on top of a weak one. The bridge from U2F to FIDO2 is exactly that move.

The other piece U2F got right and FIDO2 inherited is the principle that the credential is *device-bound* by default. The FIDO U2F overview describes origin-specific public/private key pairs created on the device and usable only for that origin [914]. This is the same property that makes synced passkeys, when they arrive in May 2022, a *productization* rather than a *cryptographic* move. The bytes are the same. The lifecycle is different.

If the second factor is doing all the work, why not make it *the* factor?

## FIDO2 + CTAP 2.0 + WebAuthn Level 1: the spec lands

March 4, 2019. The World Wide Web Consortium and the FIDO Alliance announced that the Web Authentication specification was an official W3C Recommendation [916]; the dated Recommendation slug is `REC-webauthn-1-20190304` [250]. Same launch window, with January 30, 2019 as the underlying CTAP 2.0 Proposed Standard date [917]. The pair is what the industry markets as *FIDO2*.

The reframe was decisive. A *platform authenticator* (Windows Hello on Windows, Touch ID on macOS, the Android Keystore on Android) was now a first-class FIDO authenticator. The user's laptop or phone could be the authenticator. The browser did not need a separate USB device; it could call into the OS instead. This is the move that made FIDO2 a consumer technology, not just a security-team technology.

> **Definition: WebAuthn relying party (RP) and rpId.**
> The *relying party* is the web service that owns the user's account. The *rpId* is a string identifying that party for credential scoping; it must be a registrable suffix of the page's origin (so `login.bank.com` may use `bank.com` as its `rpId`, but `evil.com` may not). All WebAuthn signatures cover the SHA-256 hash of the `rpId` (`rpIdHash`), which the authenticator places in `authenticatorData`; the browser separately records the actual origin in `clientDataJSON` and enforces that the `rpId` is a registrable suffix of that origin. The relying party validates the signature against the public key registered for that `rpId`. Phishing resistance is `rpId` binding, full stop [865].

The Web IDL surface that WebAuthn Level 1 standardized is small. `navigator.credentials.create({publicKey:...})` registers a new credential; `navigator.credentials.get({publicKey:...})` produces an assertion. Both return `PublicKeyCredential` objects. The complexity is not in the API; it is in the byte-level structures the API exchanges.

A registration ceremony looks like this. The relying party generates a `PublicKeyCredentialCreationOptions` blob containing a fresh challenge, the `rpId`, the user's account identifier, the list of algorithms the RP supports, the desired user verification, and an optional list of credentials the user already has. The browser passes this to the authenticator and gets back `clientDataJSON` plus an `attestationObject`. The `clientDataJSON` is a UTF-8 JSON blob containing `type: "webauthn.create"`, the origin the browser was actually on, and the challenge. The `attestationObject` is a CBOR structure whose `authData` field is a binary blob containing the `rpIdHash` (SHA-256 of the canonical `rpId`), the flags byte (with `UP`, `UV`, `AT`, `ED` bits), the signature counter (initially zero, sometimes non-zero), the AAGUID identifying the authenticator model, the new credential's identifier, and the credential's public key in COSE_Key format, alongside an optional *attestation statement* that binds those bytes to a hardware root of trust.

> **Definition, AAGUID (Authenticator Attestation GUID).**
> A 16-byte identifier the authenticator includes in `authenticatorData` to identify its make and model. Some authenticators emit an all-zeros AAGUID for privacy. Microsoft's Entra ID hardware-vendor matrix lists dozens of FIDO2 keys with their AAGUIDs and supported transports [918]; the FIDO Metadata Service is the authoritative directory.
>
> **Walkthrough: WebAuthn registration at the field level.** Step 1: the relying party creates `PublicKeyCredentialCreationOptions` with a fresh challenge, an `rp.id`, a stable user handle, `pubKeyCredParams` such as ES256, and an attestation preference. Step 2: the browser writes `clientDataJSON` with `type: "webauthn.create"`, the base64url challenge, and the actual web origin; this is the anti-phishing handoff because script cannot choose a different origin. Step 3: the client hashes `clientDataJSON` and sends the request to the authenticator through CTAP2 or the platform API. Step 4: after `UP` and optionally `UV`, the authenticator generates a per-RP key pair, stores the private key or credential secret, and returns `authenticatorData` containing `SHA256(rpId)`, flags, counter, AAGUID, credential ID, and COSE public key. Step 5: the RP verifies the challenge, origin, `rpIdHash`, attestation statement if requested, and then stores only the credential ID and public key.

An authentication ceremony is the same shape with one structural change: the RP supplies `PublicKeyCredentialRequestOptions` with a fresh challenge, the authenticator finds the credential matching the `rpId`, prompts the user for a gesture (if `userVerification` is requested), and produces an *assertion*: a signature over `authenticatorData || SHA-256(clientDataJSON)` with the credential's private key. The relying party verifies the signature against the stored public key.

The Windows-side surface debuts in the same window. Microsoft Learn states verbatim that Microsoft "introduced the W3C/Fast IDentity Online 2 (FIDO2) Win32 WebAuthn platform APIs in Windows 10 (version 1903)" [919]. May 2019. `webauthn.dll` ships. From that moment on, every browser on Windows (Edge, Chrome, Firefox, Brave) talks WebAuthn through one Win32 surface. The Microsoft Learn passkey overview makes the underlying architecture explicit: "When these APIs are in use, Windows 10 browsers or applications don't have direct access to the FIDO2 transports for FIDO-related messaging" [919]. The OS is the dispatcher.

The W3C/FIDO press release named the launch implementations: Windows 10, Android, Chrome, Firefox, Edge, and Safari (in preview) [916]. Microsoft, Google, Mozilla, and Apple all shipped within the same year. WebAuthn became the most-implemented strong-authentication standard on the consumer web inside eighteen months.

The credential's public key is encoded as a COSE_Key map: a CBOR object whose algorithm identifier is one of the entries in the IANA COSE Algorithms registry [920]. As of the registry's 2026-03-04 update, no post-quantum algorithm is in WebAuthn-recommended status; ECDSA P-256 and EdDSA Ed25519 remain the workhorses. The post-quantum algorithm migration is a separate subject this book does not cover; for WebAuthn the load-bearing fact is the still-empty PQC row in the registry.

Level 1 settled the field-level shape. What did the next two years sharpen?

## CTAP 2.1: the wire protocol every security key is speaking

15 June 2021. The FIDO Alliance published CTAP 2.1 as a Proposed Standard [921]. CTAP 2.1 is the CBOR-on-the-wire version most security keys in 2024-2026 are running; CTAP 2.2 (Proposed Standard, 14 July 2025) [922] refines a few corners, and CTAP 2.3 followed as a Proposed Standard on 26 February 2026 [923]. Each version adds capability without breaking the previous one's commands.

> **Definition, CTAP 2.x.**
> The Client-to-Authenticator Protocol: the wire format the browser speaks to a roaming authenticator over USB-HID, NFC, or BLE. CTAP1 (the original U2F messages) carries APDU-style binary structures; CTAP2 carries CBOR-encoded commands. A *CTAP2 authenticator* (also called a FIDO2 or WebAuthn authenticator) implements the CTAP2 command set; modern keys also implement CTAP1 for backwards compatibility [917].

The CTAP2 command-byte table is the surface a browser actually dispatches to. Each command is a single byte followed by a CBOR-encoded request map. The table below names the commands in order and the criterion-table cell each one strengthens.

| Command byte | Command name | What it does | Criterion strengthened |
|---|---|---|---|
| 0x01 | `authenticatorMakeCredential` | Registration: generate a fresh keypair bound to `(rpId, user.id)` | Phishing resistance (origin binding) |
| 0x02 | `authenticatorGetAssertion` | Authentication: sign the challenge with the credential's private key | Phishing + replay + verifier-compromise |
| 0x04 | `authenticatorGetInfo` | Capability discovery: list supported algorithms, extensions, transports, `UV` modes | Step-up (lets RP know what's available) |
| 0x06 | `authenticatorClientPIN` | Manage the PIN, issue `pinUvAuthToken` with permissions bitmap and `rpId` scoping | Step-up + replay |
| 0x07 | `authenticatorReset` | Wipe all resident credentials on the device | Lifecycle |
| 0x08 | `authenticatorGetNextAssertion` | Continue a multi-credential assertion enumeration after `authenticatorGetAssertion` | Discoverable-credential UX / lifecycle |
| 0x09 | `authenticatorBioEnrollment` | On-token fingerprint enrollment (CTAP 2.1) | Step-up (`UV=1`) |
| 0x0A | `authenticatorCredentialManagement` | List, enumerate, and delete resident credentials per RP | Lifecycle / recovery |
| 0x0B | `authenticatorSelection` | "Pick this device" prompt when multiple authenticators are present | UX (no criterion change) |
| 0x0C | `authenticatorLargeBlobs` | Per-credential blob store under the credential | Step-up (extension data) |
| 0x0D | `authenticatorConfig` | Enable enterprise attestation, toggle `alwaysUv`, set minimum PIN length | Authenticator provenance + lifecycle |

Three pieces of CTAP 2.1 are worth pulling out because they meaningfully change the criteria-table cells.

**`pinUvAuthToken` and permissions.** CTAP 2.0's PIN protocol let the browser obtain a `pinToken` and spend it broadly across PIN-authenticated operations. CTAP 2.1 introduced `pinUvAuthToken`, with a *permissions bitmap* and *rpId scoping*, so that a token issued for *one* relying party's ceremony cannot be replayed against a different relying party's ceremony on the same authenticator [921]. This closes a class of host-side mischief: an attacker who got the PIN out of one ceremony could not previously be stopped from spending it on a different `rpId`.

**`credProtect`.** A CTAP 2.1 extension that lets the RP request one of three credential-protection policies: `userVerificationOptional` (0x01), `userVerificationOptionalWithCredentialIDList` (0x02), or `userVerificationRequired` (0x03). The strongest level is the one this chapter cares about operationally: the authenticator should refuse to list the discoverable credential without a `UV=1` gesture. The first generation of WebAuthn discoverable credentials were more easily enumerable by any host that could speak CTAP2 to the connected key; `credProtect` lets the RP say "don't show this credential's existence to anything that doesn't pass user verification first."

**Enterprise attestation.** CTAP 2.1 added an explicit *enterprise attestation* mode in which the authenticator binds its attestation statement to a list of relying parties the device's enrolling organization has pre-approved. This is the bridge that makes vendor attestation useful in managed enterprises without leaking the user's specific device identity to every relying party. (The largeBlob extension (CTAP 2.1, command 0x0C) gives each credential a small per-credential blob store. RPs use it for things like cached short-lived tokens or per-user policy. The 2024 release notes for the Windows `webauthn.dll` API surface flagged largeBlob support as one of the additions in Windows 11 22H2 [919]; a March 2023 Review Draft [924] foreshadowed the 2.2 refinements that landed in July 2025.)

All of this is for experts. When did this stop being a security-team conversation and start being a consumer product? What changed in May 2022?

## Passkeys: the productization moment

5 May 2022. Apple, Google, and Microsoft jointly committed at the FIDO Alliance to a common passwordless sign-in standard [925]. The press release is short on protocol detail and long on user-facing language. The headline commitment, verbatim: "Allow users to automatically access their FIDO sign-in credentials (referred to by some as a 'passkey') on many of their devices, even new ones, without having to reenroll every account" [925]. *Passkey* entered the public lexicon. Andrew Shikiar, the FIDO Alliance's executive director and Chief Marketing Officer at the time, named it in the press call.

> Allow users to automatically access their FIDO sign-in credentials (referred to by some as a 'passkey') on many of their devices, even new ones, without having to reenroll every account.: Apple, Google, and Microsoft, joint FIDO Alliance announcement, 5 May 2022 [925]

The *cryptographic* move in May 2022 was small. The protocol bytes are the same FIDO2 / WebAuthn / CTAP2 bytes that shipped in March 2019. What changed was twofold: (a) the three platform vendors aligned their sync fabrics so that a passkey created on a user's phone would appear on the user's laptop, and (b) the user-facing terminology consolidated from a confusing menagerie ("discoverable credential," "resident key," "client-side discoverable credential") onto a single product term, *passkey*.

> **Definition: Discoverable credential (resident key, passkey).**
> A WebAuthn credential whose `user.id` and account metadata are stored *on the authenticator*, so the authenticator can produce an assertion without the relying party first supplying a credential identifier. The CTAP 2.0 spec calls these *resident keys* [917]; the WebAuthn Level 2 spec calls them *client-side discoverable credentials* [212]; the May 2022 vendor commitment rebranded them as *passkeys* [925]. All three terms refer to the same on-the-wire object.

Discoverable credentials unlock *usernameless* sign-in. The relying party does not need to tell the authenticator which credential to use; the authenticator looks up its own resident credentials for the supplied `rpId`, shows the user the matching account, and asks for the user-verification gesture. This is the UX primitive every consumer-passkey flow leans on.

WebAuthn Level 3 (W3C Candidate Recommendation, latest snapshot dated 13 January 2026 [865] [905]) is the spec generation that productises passkeys. Level 3 standardizes:

- The **hybrid transport** (formerly known as caBLE), exposed as the `hybrid` value of WebAuthn's `AuthenticatorTransport` enumeration (L3 §5.8.4) with the handshake protocol specified in FIDO CTAP 2.2, which lets a phone act as a roaming authenticator for a nearby laptop via QR code plus ephemeral ECDH plus BLE proximity. We cover hybrid below.
- **JSON-serialization helpers** (`PublicKeyCredentialCreationOptionsJSON` and `PublicKeyCredentialRequestOptionsJSON`) that make WebAuthn easier to drive from a server SDK without manual base64url juggling.
- **`getClientCapabilities()`** so the relying party can probe what the client supports before issuing the ceremony.
- The **`credProps`**, **`prf`**, and **`largeBlob`** client extensions (plus the CTAP-level **`credProtect`**), and the sibling **Secure Payment Confirmation** specification, each of which sharpens one cell of the criteria table.

The mid-2025 cadence picked up: CTAP 2.2 Proposed Standard on 14 July 2025 [922] refined hybrid-transport semantics and tightened `credProtect`.

The synced-vs-bound distinction is the structural new thing about passkeys. Before May 2022 a FIDO2 credential lived in one secure element; lose the YubiKey, lose the credential. Synced passkeys put the private key into a sync fabric: Apple iCloud Keychain (introduced with OS X Mavericks in 2013) [926], Google Password Manager (Chrome password sync, late 2000s onward), Microsoft Authenticator (originally 2015) [927], and Microsoft Account passkey support (announced for consumer accounts on 2 May 2024, with rollout staged through the consumer services) [928], and let it appear on every device the user signs into. The mechanism is end-to-end encryption against a sync-fabric key that the platform vendor cannot read; Apple's Advanced Data Protection model is the strongest current public realisation [929].

The price: the long-term private key is intentionally recoverable outside the original authenticator, even though sync fabrics encrypt it at rest. NIST is unambiguous about the assurance consequence. The April 2024 supplement *Incorporating Syncable Authenticators into NIST SP 800-63B* [930] (since absorbed into NIST SP 800-63B-4 final, July 2025 [890]) classifies synced passkeys at AAL2, not AAL3, because the syncable-authenticator and recovery model no longer proves single-device hardware binding. Yubico, a vendor with an incentive in the device-bound distinction, captures the operational dichotomy clearly, while NIST remains the normative source: "FIDO passkeys that are not synced (device-bound passkeys like YubiKeys) and are properly stored in dedicated hardware have an AAL3 rating" [894].

The WebAuthn spec made the distinction *observable*. Two new flag bits in `authenticatorData`, `BE` (Backup Eligible) and `BS` (Backup State), tell the relying party whether the credential is in principle syncable (`BE=1`) and whether it is currently backed up (`BS=1`) [865]. The RP can decide policy from those flags: a banking RP can require `BE=0` (device-bound) credentials for AAL3 transactions, while accepting `BS=1` (synced) credentials for AAL2 sign-in.

Microsoft's own numbers tell the productization story in raw counts. The May 2024 Microsoft Security blog announcing passkey support for consumer accounts notes that Microsoft was "detecting around 115 password attacks per second" when Windows Hello first shipped in 2015; "less than a decade later, that number has surged 3,378% to more than 4,000 password attacks per second" [928]. The 1 May 2025 World Passkey Day post escalates again: "we observed a staggering 7,000 password attacks per second (more than double the rate from 2023). [...] now we see nearly a million passkeys registered every day." It also reports that "passkey sign-ins are eight times faster than a password and multifactor authentication" (Microsoft's published metric, methodology unspecified) and that "more than 99% of people who sign into their Windows devices with their Microsoft account do so using Windows Hello," a denominator limited to Microsoft-account sign-ins on Windows devices rather than enterprise domain-joined usage [884].

> **Key idea.**
> Passkeys are not a new cryptographic primitive. They are a productization moment in which discoverable credentials became consumer-grade UX. The protocol moves were two years earlier; the product move is what changed the criteria-table scoreboard.

Passkeys are a *productization* moment. On Windows specifically, what does the platform actually do between `navigator.credentials.create` and the TPM?

## The Windows platform authenticator: `webauthn.dll` end-to-end

May 2019. Windows 10 version 1903. The Win32 platform WebAuthn API shipped, and from that moment on every browser and every native application on Windows that wants to do WebAuthn calls `webauthn.dll`. The header file `webauthn.h` is in the Windows SDK and is also published on GitHub at `github.com/microsoft/webauthn` [931]. The reference page on Microsoft Learn enumerates every function the API surfaces [932]. The 1903 ship date and the subsequent feature additions are documented verbatim by Microsoft Learn: "Microsoft has long been a proponent of passwordless authentication, and has introduced the W3C/Fast IDentity Online 2 (FIDO2) Win32 WebAuthn platform APIs in Windows 10 (version 1903). Starting in **Windows 11, version 22H2**, WebAuthn APIs support ECC algorithms and starting in **Windows 11 version 24H2** WebAuthn APIs support plugin passkey managers" [919].

> When these APIs are in use, Windows 10 browsers or applications don't have direct access to the FIDO2 transports for FIDO-related messaging.: Microsoft Learn, *WebAuthn APIs for password-less authentication on Windows* [919]

That sentence is the entire architectural premise. The OS dispatches FIDO2 ceremonies. The browser does not own the CTAP2 stack, the USB-HID transport, the NFC reader, the BLE pairing, or the Hello UV gesture. It hands `webauthn.dll` a request and gets back an assertion.

The API surface is a small set of functions. The ceremony surface is two functions, the management surface is the remainder.

- **`WebAuthNAuthenticatorMakeCredential`**: the registration entry point. Caller supplies origin / `rpId` / user / algorithms / attestation preference / authenticator-selection criteria. Returns an attestation object.
- **`WebAuthNAuthenticatorGetAssertion`**: the authentication entry point. Caller supplies origin / `rpId` / allowed credential IDs (or empty for usernameless) / user-verification preference / mediation (Conditional UI, covered below). Returns an assertion.
- **`WebAuthNGetApiVersionNumber`**: a monotonically increasing integer that lets callers feature-detect the local `webauthn.dll` instead of guessing from a Windows marketing release. Microsoft documents the public release milestones (initial Win32 APIs in Windows 10 1903, ECC algorithm support starting in Windows 11 22H2, plug-in passkey managers starting in Windows 11 24H2) but production code should compare the returned number with the SDK header constants it was compiled against [919] [932].
- **`WebAuthNGetCancellationId`** / **`WebAuthNCancelCurrentOperation`**: cooperative cancellation; the browser asks `webauthn.dll` to drop the active ceremony.
- **`WebAuthNGetPlatformCredentialList`** / **`WebAuthNDeletePlatformCredential`**: resident-credential management for synced passkeys held by the OS provider.
- **`WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable`**: the `isUVPAA` capability probe; the RP uses this to decide whether to offer a passkey enrollment flow at all.
- **`WebAuthNFreeAssertion`** / **`WebAuthNFreeCredentialAttestation`** / **`WebAuthNFreePlatformCredentialList`**: caller-side memory release; the OS allocates on the heap and the caller is responsible for `Free`.
- **`WebAuthNGetErrorName`** / **`WebAuthNGetW3CExceptionDOMError`**. Translate the Win32 `HRESULT` into a WebAuthn-spec error string.

![Figure: A platform-bound WebAuthn registration on Windows. The browser calls MakeCredential() across the OS dispatch boundary into webauthn.dll; Windows Hello collects the user-verification gesture, CNG/NCrypt provisions the key, and the TPM 2.0 generates a non-exportable keypair and certifies the attestation. The caller hands off a request and receives only bytes (clientDataJSON, authenticatorData, attestationObject) and never holds the TPM private key or speaks raw CTAP transport.](diagrams/24-webauthn-windows-registration.svg)

The criteria-framework consequence of that call graph is strong, but only for the platform-bound case. Microsoft Learn states the Windows Hello property verbatim: "The private keys can only be used after they're unlocked by the user using the Windows Hello unlock factor (biometrics or PIN)" [933]. That sentence should not be generalized to every object marketed as a passkey. There are three materially different storage cases:

| Storage case | Where the long-term key lives | What "private key never leaves hardware" means | Phishing resistance | NIST AAL implication |
|---|---|---|---|---|
| **Platform-bound Windows Hello credential** | TPM-backed Windows platform authenticator, unlocked by Hello PIN/biometric | Applies. The raw private key is non-exportable and hardware-bound; malware can ask for a signature only through the OS/TPM policy boundary and user-verification gate. | Applies, because WebAuthn still signs `clientDataJSON.origin` and `rpIdHash`. | This is the case closest to the AAL3 claim when paired with appropriate recovery controls and attestation policy. |
| **Synced Microsoft passkey** | Microsoft Account / Windows passkey sync fabric, protected by end-to-end encryption and a recovery key or account recovery path | Does **not** apply. The credential is intentionally recoverable on another signed-in device; the long-term key material is no longer pinned to one TPM. | Still applies at the ceremony layer: the synced key signs only for the registered RP. | AAL3 does **not** hold. NIST caps syncable authenticators at AAL2 because the key can be restored across devices [930] [890]. |
| **Third-party password-manager or vault-backed passkey** | Vendor vault such as 1Password, Bitwarden, or Dashlane, dispatched through the Windows 11 24H2 plug-in model | Does **not** apply unless that vendor explicitly binds a credential to local hardware. The key is governed by vault storage, sync, export, and recovery policy. | Still applies if the provider returns a normal WebAuthn assertion: the RP verifies the same origin-bound bytes. | AAL3 should not be assumed. Treat it as vault-backed AAL2-or-lower until the provider supplies device-binding, non-exportability, attestation, and recovery evidence. |

Only the first row earns the literal reading of "the private key never leaves hardware," and it earns it only because two earlier links in this book hold at the same time: the TPM's non-exportable seal from the TPM chapter (Chapter 2) and the user-verification gate from the Windows Hello chapter (Chapter 20). Remove either one (export the key into a sync fabric, or let any caller sign without a gesture) and the platform-bound row collapses into the AAL2 cases beneath it. The Windows picker that lists all three side by side is precisely where that distinction goes missing.

The API version sentinel tells a clean feature-evolution story, but production code should not hard-code a marketing-release map. Microsoft exposes a numeric `WebAuthNGetApiVersionNumber()` precisely so callers can probe the local DLL and then gate feature use against the header they compiled with [932]. Because this chapter does not carry a hash-stamped Windows lab capture of `WEBAUTHN_API_VERSION_*` values across builds, the table below deliberately avoids pretending to map API versions 1-7 to exact Windows builds. Read it as a documented capability progression and a verification checklist, not as a substitute for the probe.

| Documented milestone | Local thing to verify | Notable surface to look for |
|---|---|---|
| Windows 10 1903: first public Win32 WebAuthn APIs [919] | `WebAuthNGetApiVersionNumber()` returns a non-zero value; `webauthn.dll` exports make-credential, get-assertion, and isUVPAA functions | Initial OS-dispatched FIDO2/WebAuthn surface |
| Windows 11 22H2: ECC algorithm support [919] | Header and local behavior support the ECC algorithms your RP offers, especially ES256 paths | ECC-backed Windows Hello platform credentials |
| Windows 11 24H2: plug-in passkey managers [919] | Header/sample expose `WebAuthNPlugin*`; Settings exposes passkey provider choices when a provider is installed | Third-party provider registration, provider picker, OS-mediated plug-in dispatch |
| Current SDK / `microsoft/webauthn` header [931] | Compare the returned API number with the `WEBAUTHN_API_VERSION_*` constants and structures in the SDK you compile against | Feature-gate structure fields, extensions, credential-management calls, and plug-in calls from headers rather than release names |
| Insider builds after KB5072046 [931] | GitHub header exposes `EXPERIMENTAL_*2` functions | `EXPERIMENTAL_WebAuthNPluginAddAuthenticator2`, `EXPERIMENTAL_WebAuthNPluginPerformUserVerification2`, `EXPERIMENTAL_WebAuthNPluginUpdateAuthenticatorDetails2`; the prefix is the warning label |

The important tightening is methodological: cite the Microsoft Learn and `microsoft/webauthn` header surface for the function names, capture the local DLL's returned API number for the machine you are testing, and never publish an exact-looking build/API map unless you captured or sourced that map directly. The three `EXPERIMENTAL_*2` APIs are Insider-only; the `EXPERIMENTAL_` prefix is the SDK signal that the shape may change before it becomes load-bearing public API.

> **Note. Use the platform API.**
> On Windows, do not roll your own CTAP2 stack. `webauthn.dll` handles USB-HID, NFC, BLE, hybrid transport, Conditional UI, plug-in dispatch, and Windows Hello user verification in a single call. The Win32 reference at `learn.microsoft.com/en-us/windows/win32/api/webauthn/` is the source of truth, the header file is at `github.com/microsoft/webauthn`, and the YubiKey 5 series [934] plus the Entra-listed FIDO2 vendors [918] are the supported keys.

The criterion-table consequence of dispatching FIDO2 through one OS surface is narrower than "the browser disappears." Edge, Chrome, Firefox, and Brave can delegate CTAP transport, provider selection, platform-authenticator mediation, and Windows Hello UV to the same `webauthn.dll`; they still own origin determination, WebAuthn API behavior, `clientDataJSON`, permissions and mediation UX, and the handoff to the relying party. The OS routes the registration to the TPM (for platform-bound passkeys), to USB-HID (for roaming security keys), or to a plug-in (for Windows 11 24H2 third-party providers, covered below).

The `webauthn.dll` surface answers one half of the question. The other half is: what does the user actually *see*?

## Conditional UI: passkey autofill that looks like password autofill

The bridge between users' password-trained mental model and the new asymmetric-crypto reality is a UX primitive called Conditional Mediation (the spec name) or *Conditional UI* in informal use. The relying party renders a normal-looking username field. The browser sees that the page has called `navigator.credentials.get({mediation: "conditional", publicKey: {...}})` and quietly offers the user's passkey as one of the autofill suggestions, alongside whatever the user has typed and whatever the password manager remembers. The user clicks the passkey suggestion, completes a Windows Hello gesture, and they are signed in. No popup. No modal. No "do you want to use a passkey?" dialog.

> **Definition: Conditional UI / Conditional Mediation.**
> A WebAuthn invocation mode in which the browser offers the user's discoverable credentials *inside* the same autofill UI it uses for saved passwords, rather than via a modal credential picker. The relying party calls `navigator.credentials.get({mediation: "conditional", publicKey: {...}})`; the browser silently consults the platform authenticator (and, on Windows 11 24H2, the plug-in passkey providers) for credentials matching the `rpId`. The capability is probed via `PublicKeyCredential.isConditionalMediationAvailable()` [865].

The canonical engineer-perspective walkthrough is Adam Langley's *Passkeys* post on imperialviolet.org, dated 22 September 2022 [935]. Langley walks the flag-page invocation needed on early Chrome Canary builds (`chrome://flags#webauthn-conditional-ui`) and the capability surface: `isUserVerifyingPlatformAuthenticatorAvailable()` to decide whether to offer enrollment, `isConditionalMediationAvailable()` to decide whether to render the autofill hint at all. The post is the first time most working engineers saw what passkeys would actually look like at the page level.

On Windows the browser calls `WebAuthNAuthenticatorGetAssertion` with the Conditional mediation flag set; `webauthn.dll` consults its resident credential store, finds passkeys matching the `rpId`, and surfaces a small in-line affordance for each. The full-screen Windows Hello modal becomes a small in-place gesture acquisition. From the user's perspective the password-manager metaphor is unchanged; from the cryptography's perspective the work product is a public-key signature over an origin-bound challenge.

The four mediation modes (`silent` no user interaction, `optional` browser decides, `conditional` autofill, and `required` modal) come from Credential Management Level 1's `CredentialMediationRequirement` enumeration; WebAuthn L3 §5.1.4 specifies how `conditional` is processed in the assertion flow [865]. Conditional is the one that makes passkeys feel like passwords, and that is precisely why it took the consumer-passkey rollout off the security-team conversation and into product reviews.

The Microsoft Learn passkey overview ties the UX to the Windows ship vehicle: "Starting in Windows 11, version 22H2 with KB5030310, Windows provides a native experience for passkey management" [933]. The Settings → Accounts → Passkeys page is the management UI; Conditional Mediation surfaces those passkeys at sign-in time. The passkeys.dev developer directory [936] is the FIDO Alliance's collected resource for relying parties implementing the flow.

The UX implication is the one Adam Langley underlined in the September 2022 post: the password-autofill metaphor is the load-bearing UX primitive that makes passkeys consumer-ready. The cryptography was solved in 2014. The UX took eight more years.

But what if the user's passkey lives in 1Password or Bitwarden, not in Windows itself?

## The Windows 11 24H2 third-party passkey provider model

8 October 2024. Microsoft published the Windows Developer Blog post *Passkeys on Windows: authenticate seamlessly with passkey providers* [937] as a pre-conference announcement ahead of the FIDO Alliance's Authenticate 2024 conference (14-16 October 2024 in Carlsbad, California). The post announced three deliverables: "1. A plug-in model for third-party passkey providers. 2. Enhanced native UX for passkeys. 3. A Microsoft synced passkey provider." 1Password and Bitwarden were the named launch partners; Dashlane joined the roster shortly thereafter. The post says verbatim: "Microsoft is partnering closely with 1Password, Bitwarden and others on integrating this capability" [937].

The plug-in model brings an OS-level third-party passkey-provider API to Windows, matching the passkey-provider models Apple shipped in macOS Sonoma / iOS 17 (`ASCredentialIdentityStore` plus `ASCredentialProviderExtension`) [938] and Android 14 added through Credential Manager [939]. The mechanism is a COM interface called `IPluginAuthenticator`, declared in `pluginauthenticator.idl` [931]. A passkey-manager vendor ships a packaged Windows app that registers a COM object implementing the interface, supplies an AAGUID and a friendly name, and lets the OS dispatch ceremonies to it.

The Plugin API surface is six functions on the OS side and one COM interface on the vendor side. From `webauthnplugin.h` and the Microsoft Learn reference [919]:

- **`WebAuthNPluginAddAuthenticator`**: register the plug-in with the OS. The vendor app calls this on first run.
- **`WebAuthNPluginAuthenticatorAddCredentials`**: supply the OS with the credentials the plug-in currently has, so the OS can render them in pickers.
- **`WebAuthNPluginAuthenticatorRemoveCredentials`**: the inverse; remove credentials the plug-in no longer holds.
- **`WebAuthNPluginPerformUserVerification`**: request Windows Hello UV on behalf of the plug-in. The plug-in does *not* take the UV gesture itself; Windows Hello does, so the gesture-to-credential trust path is OS-mediated.
- **`WebAuthNPluginRemoveAuthenticator`**: the vendor's uninstall path.
- **`WebAuthNPluginGetAuthenticatorState`**: query the Enabled/Disabled state of a registered plug-in authenticator by its COM CLSID.

Three additional `EXPERIMENTAL_*2` functions ship in Insider build KB5072046 and refine the registration, UV, and update flows. The list, verbatim from the `github.com/microsoft/webauthn` README: `EXPERIMENTAL_WebAuthNPluginAddAuthenticator2`, `EXPERIMENTAL_WebAuthNPluginPerformUserVerification2`, `EXPERIMENTAL_WebAuthNPluginUpdateAuthenticatorDetails2` [931].

The Microsoft-authored reference implementation is the Contoso Passkey Manager sample in `microsoft/Windows-classic-samples` [940]. The sample's build manifest is explicit: "Windows SDK version 10.0.26100.7175 or higher. Operating system requirements: Windows 11 version 25H2. Build Major Version = 26200 and Minor Version >= 6725. Windows 11 version 24H2. Build Major Version = 26100 and Minor Version >= 6725" [940]. The Microsoft Learn tutorial *Third-party passkey providers on Windows* walks the same sample step by step [941]. Treat the 25H2 line as a sample-manifest / SDK requirement, not a general-availability claim about a released Windows version.

> **Note: Contoso Passkey Manager is not for production.**
> The Microsoft Learn third-party tutorial carries an explicit disclaimer: "Contoso Passkey Manager is designed for passkey creation and usage testing only. Don't use the app for production passkeys" [941]. The sample illustrates the COM contract; it does not replace a vetted vendor's credential vault.
>
> **Walkthrough: Windows 11 24H2 provider dispatch.** The caller still invokes `WebAuthNAuthenticatorMakeCredential` or `WebAuthNAuthenticatorGetAssertion`. Windows then enumerates registered authenticators: the built-in Hello/TPM provider, roaming FIDO2 transports over USB-HID/NFC/BLE, hybrid phone transport, and any enabled COM plug-in provider. If the user picks a vault-backed provider, the provider receives the ceremony through the `WebAuthNPlugin*` contract rather than by scraping browser state. If it needs user verification, it asks Windows to perform the gesture with `WebAuthNPluginPerformUserVerification`, so the vault does not invent its own fake Hello prompt. The provider returns a normal WebAuthn attestation or assertion. The RP sees ordinary W3C bytes; only the storage and recovery floor changed.

The user-facing flow follows the same logic as the macOS / iOS / Android equivalents. The user installs 1Password or Bitwarden from the Microsoft Store. The vendor app calls `WebAuthNPluginAddAuthenticator` on first launch. The user enables the provider in Settings → Accounts → Passkeys → Advanced options [937]. From that point on, when any browser or native app on Windows starts a WebAuthn ceremony, `webauthn.dll` presents the user with a picker ("use a passkey from Windows Hello, from 1Password, from Bitwarden, from a hardware security key, or from your phone") and routes the ceremony to the selected provider. The plug-in itself returns an attestation object and an assertion; Windows Hello handles user verification on the plug-in's behalf via `WebAuthNPluginPerformUserVerification`. The Windows trust boundary still owns the gesture acquisition.

> **Aside: What the plug-in model is NOT.**
> The plug-in model adds credential-store choice; it does not change the lock-screen credential. The plug-in cannot replace Windows Hello at the lock screen; lock-screen sign-in remains the platform authenticator. The plug-in cannot proxy domain credentials: Kerberos and NTLM are unaffected. The plug-in is *not* a replacement for the legacy `CredMan` (Credential Manager) generic-credential surface; that surface is still where Windows applications stash Basic-Auth-style credentials. The plug-in model is, specifically, a WebAuthn credential store. Everything else stays where it was.

The criterion-table consequence is mixed. The plug-in model strengthens *user choice* and sometimes *availability*, because a user with an existing 1Password / Bitwarden vault can reuse the recovery primitives they already know. It weakens *hardware-bound non-exportability* relative to a pure platform-bound passkey, because the long-term key now lives under the vendor vault's storage, sync, export, and recovery policy rather than under the local TPM. It does not change RP-side verifier-compromise resistance, phishing resistance, replay resistance, or step-up, because the relying party still stores a public key and verifies a WebAuthn-shaped assertion. It does change the assurance ceiling: unless the provider proves device binding and non-exportability, the AAL3 claim does not travel with the Windows picker.

What 1Password, Bitwarden, and Dashlane each ship in their plug-in implementations follows the same template: registration requests get either a `packed` attestation statement (for vendor-signed batch attestation keys) or a `none` attestation (most consumer flows), and authentication assertions come back the same shape as any other WebAuthn assertion. The plug-in itself decides whether the credential is `BE=1, BS=1` (synced in the vendor's cloud) or `BE=0, BS=0` (device-bound to the local install).

A plug-in supplies the credential. But the *attestation statement* on registration tells the relying party *what kind of credential it is*. That's a separate API surface. What shapes does it come in?

## Documented reproducibility checklist for a Windows machine

This section is not a lab capture from this Linux build host. It is a documented reproducibility path: a reader with Windows 10 1903+ can run the base WebAuthn probes, and a reader with Windows 11 24H2 can additionally verify third-party provider dispatch. The commands below are expected shapes to capture locally: not hash-stamped output from this chapter. That is the correct proof boundary because the decisive evidence is the signed WebAuthn byte string, not a screenshot of a Settings page.

> 🔵 **DOCUMENTED + REPRODUCIBLE**: Windows WebAuthn platform surface, documented by Microsoft; commands below are the capture recipe for a local Windows host.

**Probe 1: prove the platform API exists and returns a feature number.** Run this in Windows PowerShell. It loads `webauthn.dll`, calls the documented sentinel, and prints the integer your code should feature-gate on.

```powershell
$src = @"
using System;
using System.Runtime.InteropServices;
public static class WebAuthnNative {
  [DllImport("webauthn.dll", ExactSpelling=true)]
  public static extern UInt32 WebAuthNGetApiVersionNumber();
}
"@
Add-Type $src
"webauthn.dll present: " + (Test-Path "$env:WINDIR\System32\webauthn.dll")
"WebAuthN API version: " + [WebAuthnNative]::WebAuthNGetApiVersionNumber()
```

A supported host prints `webauthn.dll present: True` and a non-zero API version. Do not copy a version number from this book into production code; capture it on the host under test and compare it with the `WEBAUTHN_API_VERSION_*` constants in the SDK header [932].

**Probe 2: prove Windows has a user-verifying platform authenticator.** The next call checks whether Hello can satisfy `UV` for platform credentials. A clean `HRESULT` and `True` answer mean the RP can offer a Windows Hello passkey enrollment flow.

```powershell
$src = @"
using System;
using System.Runtime.InteropServices;
public static class WebAuthnUv {
  [DllImport("webauthn.dll", ExactSpelling=true)]
  public static extern Int32 WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable(out bool available);
}
"@
Add-Type $src
[bool]$available = $false
$hr = [WebAuthnUv]::WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable([ref]$available)
"HRESULT: 0x{0:X8}" -f $hr
"UV platform authenticator available: $available"
```

**Probe 3: verify the signed fields, not the UX.** Capture one registration response from a test RP and decode the attestation object. The RP must verify five things: `clientDataJSON.type == "webauthn.create"`; the challenge equals the server nonce; `clientDataJSON.origin` is the exact HTTPS origin; `authenticatorData[0..31] == SHA256(rpId)`; and, when the attestation format is not `none` and policy requires attestation, the format-specific attestation statement over `authenticatorData || SHA256(clientDataJSON)`. For assertion, the RP verifies `type == "webauthn.get"`, the same origin and `rpIdHash`, `UP=1`, `UV=1` when required, a fresh challenge, and the signature with the stored credential public key. This is also the phishing-resistance proof: an adversary-in-the-middle can relay a password or OTP, but it cannot make a browser on `login-microsoft0nline.example` produce `clientDataJSON.origin == "https://login.microsoftonline.com"` or an `rpIdHash` for the real RP.

**Probe 4: distinguish storage models.** On a platform-bound Windows passkey, the private key is TPM/Hello-gated; on a Windows 11 24H2 third-party provider, the same Win32 ceremony may dispatch to a vault provider. The WebAuthn assertion format is the same, but the recovery floor is not. Therefore the capture should record three facts next to the bytes: the API version returned by `WebAuthNGetApiVersionNumber()`, whether `isUVPAA` returned true, and which provider fulfilled the ceremony (Hello/TPM, roaming key, hybrid phone, or registered plug-in). That tuple is the evidence a security reviewer needs.

## The seven attestation statement formats

The IANA WebAuthn registry lists seven format identifiers for the *attestation statement* a registration ceremony can produce [942]. These are not the WebAuthn attestation-conveyance preferences (`none`, `indirect`, `direct`, `enterprise`); they are the CBOR statement formats that appear inside the attestation object. The registry is reachable via RFC 8809 (Hodges, Mandyam, M.B. Jones, August 2020) [943] and the canonical normative definitions are in WebAuthn Level 2 §§8.2-8.8 [212], whose dated Recommendation is at `REC-webauthn-2-20210408` [944]. The seven, in registry order: `packed`, `tpm`, `android-key`, `android-safetynet`, `fido-u2f`, `apple`, and `none`. (WebAuthn Level 3 adds an eighth, `compound` (§8.9), not yet reflected in the IANA snapshot.) Each is one option a relying party can require, accept, or ignore.

> **Definition, Attestation conveyance.**
> The mechanism by which a WebAuthn registration ceremony optionally produces a signature over the new credential's public key (and `authenticatorData` containing the `rpIdHash`), chained to a vendor or platform root. The relying party validates the chain to establish that the new credential's private key is held by a specific authenticator model or certification level. Attestation is distinct from authentication; attestation runs once at registration, authentication runs every sign-in. The WebAuthn `attestation` parameter on registration controls whether the RP asks for an attestation statement at all (values: `none`, `indirect`, `direct`, `enterprise`).

The table below summarizes what each format teaches the relying party. The public-key credential model is what provides verifier-compromise resistance; attestation adds provenance, device-class, certification, and anti-fraud evidence at registration time.

| Format | What the RP verifies | Trust anchor required | Assurance signal | Current adoption |
|---|---|---|---|---|
| `packed` | Signature over `authenticatorData \|\| clientDataHash` by batch attestation key or self-attestation key | Vendor X.509 cert chain or none (self) | Authenticator provenance, optional anti-fraud | Default for most CTAP2 keys; dominant in production |
| `tpm` | TPM 2.0 `TPM2_Certify`-style certification over the new credential public key | AIK / EK chain to TPM vendor root | Authenticator provenance + device-bound storage evidence | Windows platform-bound passkeys |
| `android-key` | Android Keystore attestation chain | Google-rooted hardware-attestation CA | Authenticator provenance + StrongBox / TEE residency | Android platform passkeys |
| `android-safetynet` | SafetyNet API-derived attestation token | Google SafetyNet CA | Legacy; declining | Legacy Android; SafetyNet deprecation announced June 2022; migration deadline end of January 2024; complete shutdown end of January 2025 |
| `fido-u2f` | ECDSA P-256 signature with vendor X.509 cert | Vendor U2F-era cert | Authenticator provenance (legacy) | Legacy U2F-era hardware keys; declining |
| `apple` | Anonymous Apple-issued attestation chain | Apple anonymous-attestation CA | Authenticator provenance without device de-anonymisation | Apple platform passkeys |
| `none` | No attestation; credential public key plus AAGUID only | None | None | The default for synced-passkey consumer flows |

A few of these deserve a paragraph each.

**`packed`** is the spec default and the most widely deployed. The authenticator emits one signature over the concatenation of `authenticatorData` and a hash of `clientDataJSON`, using one of three keys: (a) a per-authenticator-model *batch attestation key* whose X.509 chain anchors to the vendor's attestation root (the privacy-vs-anti-fraud trade-off. The cert reveals the device model, but not which specific user owns which device); (b) an *Anonymisation CA* or Enterprise Attestation key, which lets a managed enterprise distinguish its own devices without leaking that information to consumer relying parties; or (c) a *self-attestation* key derived from the credential itself, which proves only that the private key signs and makes no identity claim.

**`tpm`** is the format the Windows platform authenticator emits when the user has a TPM 2.0. The signing object is a TPM `TPM2_Certify`-style structure with the TPM's Attestation Identity Key (AIK), chained back to the TPM vendor's Endorsement Key (EK) root certificate. This is the most cryptographically opinionated attestation in the registry: it proves the credential is held by a specific TPM vendor's part. The TPM chapter (Chapter 2) walks the AIK / EK chain end to end.

**`apple`** is Apple's anonymous-attestation design. The X.509 chain ends in an Apple anonymous-attestation CA; cryptographically the relying party can verify the cert chain back to Apple's root, but the cert itself is engineered to not reveal the user's specific device. This is the privacy-vs-anti-fraud trade-off resolved in favor of privacy: a relying party gets "this came from a real Apple device" without learning *which* Apple device.

**`android-safetynet`** is the legacy format that lots of installed-base Android passkeys still use. Google announced the SafetyNet Attestation API's deprecation in June 2022 in favor of Play Integrity; the migration deadline was extended to end of January 2024, with complete shutdown landing end of January 2025 [945]. Any new Android passkey registered in 2025 or later uses `android-key` or `none` instead. Relying parties with old `android-safetynet` credentials in their database must accept both formats during the transition window; new credentials use the new path.

**`fido-u2f`** is the U2F-era legacy format, descended directly from the December 2014 U2F design [914]. ECDSA P-256 signing key plus a vendor X.509 cert. Modern keys still emit it for U2F-mode CTAP1 ceremonies, but every modern CTAP2 ceremony uses `packed` instead.

**`none`** is the most-deployed format in *consumer* flows, and the recommended default for any relying party that does not have a specific anti-fraud requirement. The RP asks for `attestation: "none"`; the authenticator returns just the credential public key and the AAGUID, with no signature chain. The privacy benefit is real: attestation deanonymises the user's device by model, and a relying party that does not need that information should not collect it. The 2024-2026 best practice is `attestation: "none"` for consumer passkey flows. NIST SP 800-63B-4 (final) inherits this caution [890].

> **Note: Pick attestation deliberately.**
> Use `attestation: "none"` for consumer flows; the privacy cost of `direct` outweighs the anti-fraud benefit for low-value accounts. Use `attestation: "direct"` only when (a) you have a documented anti-fraud requirement, (b) you can verify the chain against the FIDO Metadata Service, and (c) you accept that the cert reveals the authenticator model. Use `attestation: "enterprise"` only inside a managed enterprise where the user's device is corporately enrolled.

The discussion so far assumed the authenticator is *on the same device* as the browser (the attestation formats themselves are transport-independent: platform, roaming USB/NFC/BLE, and hybrid phone authenticators can all return these objects). What happens when the authenticator is a phone across the room?

## Hybrid transport: a phone authenticator for a laptop browser

A user on a borrowed Windows laptop with no Windows passkey signs in to their bank by scanning a QR code with their iPhone. The phone is the authenticator. The laptop is the WebAuthn client. The protocol that ties them together is *hybrid transport*, formerly known as caBLE (Cloud-Assisted Bluetooth Low Energy), exposed as the `hybrid` value of WebAuthn's `AuthenticatorTransport` enumeration (L3 §5.8.4) with the transport protocol itself specified in FIDO CTAP 2.2 [865].

> **Definition: Hybrid transport (caBLE).**
> A WebAuthn transport in which a roaming authenticator (typically a mobile phone) cooperates with a WebAuthn client on a nearby device (typically a laptop) via three concurrent channels: an out-of-band channel (QR code) for one-time setup, BLE for proximity, and HTTPS to a discoverable cloud tunnel relay for the actual ceremony bytes. The cryptographic trust anchor is the QR-code-seeded ephemeral ECDH exchange; BLE supplies proximity and routing material rather than identity; the tunnel relay carries the encrypted ceremony [905].

The ceremony, simplified: the laptop's browser asks the user to use a phone, generates an ephemeral ECDH keypair, and renders a QR code containing the Tunnel Service URL the phone should connect to, the laptop's ephemeral public key, and a derived HMAC key. The phone's camera scans the QR code and derives a shared secret with the laptop via ECDH. The phone then advertises its presence over BLE, the laptop listens for the BLE beacon to confirm physical proximity, and both endpoints connect to the Tunnel Service URL over HTTPS. From that point on, the laptop and the phone exchange CTAP2 ceremony messages, encrypted under the ECDH-derived key, through the tunnel relay. The phone produces a WebAuthn assertion locally using whatever authenticator is on the phone (the Secure Enclave on iPhone, the Android Keystore on Android), encrypts it for the laptop, and the laptop forwards it to the relying party.

![Figure: Hybrid transport (caBLE). A phone authenticates a sign-in on a laptop that holds no credential. Three channels do three jobs: the QR code is the cryptographic binding (ephemeral ECDH), BLE supplies a physical-proximity signal (not identity), and the cloud Tunnel Service is an encrypted CTAP2 relay, not a trust anchor. The phone performs local user verification and signs over the laptop’s clientDataJSON.origin and rpIdHash, so origin binding (and phishing resistance) holds end to end.](diagrams/24-webauthn-hybrid-transport.svg)

The criterion-table consequence is precise. Phishing resistance is preserved because the *origin* in `clientDataJSON` is the laptop's actual browser origin, which the phone signs over the same way it would for its own browser. The QR code is the cryptographic trust anchor, not the BLE advertisement; the BLE advertisement is a proximity/routing signal keyed to that handshake, not an identity proof. In the FIDO hybrid design, BLE also carries encrypted advertisement bytes used to route the tunnel session; it is not a raw unauthenticated broadcast. The Tunnel Service is a *relay*, not a trust anchor; even if the tunnel were compromised, the encrypted ceremony bytes would be unreadable without the ECDH-derived key.

The original caBLE design and its later WebAuthn/CTAP productization were led by Google's Chrome security and Android Identity teams. The WebAuthn Level 3 editor masthead lists Tim Cappalli, Akshay Kumar, Emil Lundberg, Matthew Miller, John Bradley, and Nina Satragno as current editors, with Jeff Hodges, J.C. Jones, Michael B. Jones, and Dirk Balfanz among the former editors [865].

Hybrid transport is the only competitor to the Windows platform authenticator that involves no Windows-side credential storage. The Windows laptop holds nothing: no key, no recovery state, no cached credential. Every ceremony round-trips to the phone. This is the use case the bank-on-a-borrowed-laptop story illustrates: you can sign in to your accounts on a machine you do not own without leaving a credential behind.

How do other authentication approaches score on the criteria framework?

## Competing approaches scored against the criteria

The criteria-framework table makes the competitive field legible. Five rows, six competing columns: password alone, password plus SMS-OTP, password plus TOTP, password plus push with number matching, smart card / PIV, and device-bound or synced passkey. The NIST SP 800-63B-4 AAL grading [890] and the NIST syncable-authenticator supplement [930] anchor the right edge of the table; Yubico's commentary corroborates the dichotomy between device-bound (AAL3) and synced (AAL2) passkeys [894].

| Criterion | Password | Password + SMS-OTP | Password + TOTP | Password + Push (number match) | Smart Card / PIV | Device-bound passkey | Synced passkey |
|---|---|---|---|---|---|---|---|
| Phishing resistance | None | None (AitM relays the OTP) | None (AitM relays the TOTP) | Partial (number match defeats most kits) | Strong (channel-bound via mutual TLS) | **Strong** (`rpId` binding) | **Strong** |
| Verifier-compromise resistance | None | None (SMS infra leaks) | Partial (TOTP seed on server) | Partial | Strong (public-key only) | **Strong** | **Strong** |
| Replay / relay resistance | None | Weak (OTP relay in 30-60 s) | Weak (TOTP relay in 30 s) | Strong (number match per challenge) | Strong (per-handshake nonce) | **Strong** (challenge + counter) | **Strong** |
| Step-up / continuity | None | None | None | Partial | Strong (PIN re-prompt) | **Strong** (`UV=1`) | **Strong** |
| Recovery floor | Reset via SMS | SMS-OTP all the way down | TOTP seed reset via SMS | SMS / password | Admin re-issue | RP-dependent backup key | Sync-fabric recovery (Recovery Key + Recovery Contact) |
| NIST AAL ceiling | AAL1 | AAL2 nominal (SMS-OTP RESTRICTED in 800-63-3 [910]; remains RESTRICTED with added obligations in 800-63B-4 [889]) | AAL2 | AAL2 | **AAL3** | **AAL3** | **AAL2** |

Push MFA needs a paragraph of nuance. Vanilla push ("tap to approve") is phishable by default because the attacker can simply trigger the push at the moment they have the password, and a fatigued user taps. Number matching (the user types a code shown on the laptop into the phone, or vice versa) defeats most kits because it ties the push to a specific session. *Location binding* (the push is rejected unless the phone is geographically near the laptop) adds another layer. The net is "partial" phishing resistance: much better than vanilla push, not as strong as origin binding.

Smart cards and PIV deserve their own paragraph because they are not historically associated with WebAuthn but score well on the criteria. A PIV card with a PIN provides strong phishing resistance via TLS client authentication (channel-bound at the TLS layer), strong verifier-compromise resistance via the public-key model, and strong replay resistance via per-handshake nonces. The weakness is *recovery*: a lost card requires an administrative reissue, which scales poorly for consumer flows. The full Windows smart-card stack is outside this book's chain; on the five axes a PIV card is a strong ceremony bounded by a weak recovery story.

OATH-TOTP is interesting in the criteria table because it is phishing-vulnerable by construction. The TOTP code is the same on the legitimate origin and the look-alike; the AitM kit forwards the code through. Google Authenticator's cloud-sync feature additionally broke the verifier-compromise property in a subtle way: if the user's Google account is compromised, the synced TOTP seeds give the attacker a complete second-factor toolkit [946].

SAML and OIDC federation are not competitors to WebAuthn in the criteria table. They are *transport layers above* WebAuthn. A SAML or OIDC identity provider does the WebAuthn ceremony for the user; the IdP then issues a SAML assertion or an OIDC ID token to the relying party. WebAuthn underneath is the strong primitive; SAML and OIDC are the enterprise transport for the resulting assertions.

WebAuthn wins decisively on four of five rows. What's left in row five? The recovery row.

## Where this link breaks

Even with the U2F, FIDO2, passkey, Windows, attestation, and hybrid-transport machinery in place, WebAuthn has corners it cannot defend. The relevant impossibility results are well-known in the protocol literature; they are worth naming because they tell a practitioner where defense-in-depth has to come from.

**Coerced consent.** WebAuthn cannot distinguish a willing user from a coerced one. The protocol's only signal is "the user performed the gesture": a fingerprint, a PIN, a face match. No protocol whose only observable is gesture completion can tell whether the user was free at the moment of the gesture. NIST SP 800-63B-4 does not classify physical coercion among the attacks it defends against [890]; this is a general impossibility, not a WebAuthn-specific weakness.

> **Note. Coerced consent is undefined.**
> A user under duress can be made to present a gesture. WebAuthn cannot detect this. The compensating control is *transactional*: step-up authentication with a fresh challenge for high-value actions, and out-of-band confirmation for transactions above a risk threshold. The protocol cannot solve coercion; the application layer must.

**Kernel-level malware on the client.** Malware with kernel privilege on the user's device can race the legitimate user. If the malware can call into `webauthn.dll` and trigger a Hello UV prompt the user blindly approves, it can extract assertions. The mitigation is TPM-bound keys plus the Hello ESS trustlet (covered in the Windows Hello chapter (Chapter 20) and the Credential Guard chapter (Chapter 15)), not WebAuthn itself. WebAuthn protects against *network* attackers; defending against a kernel-mode attacker on the same device requires the OS's secure-kernel architecture.

**Sync-fabric compromise.** Compromise of Apple iCloud, Google account recovery, or Microsoft's recovery-key service effectively compromises every passkey held there. Apple's Advanced Data Protection model [929] is the strongest currently-shipped consumer realisation of the end-to-end-encrypted sync invariant, and even it depends on the user retaining their Recovery Contact or Recovery Key in some form. The NIST April 2024 supplement classifies synced passkeys at AAL2 for exactly this reason: the private key leaves the original authenticator [930]. Yubico's commentary makes the practitioner consequence explicit: device-bound is AAL3, synced is AAL2 [894].

**Username enumeration and discoverable-credential privacy.** Discoverable credentials let an authenticator answer "do you have a credential for this `rpId`?" without further information. A relying party that asks the question maliciously can enumerate which of its users have set up a passkey. The `credProtect` extension introduced in CTAP 2.1 [921] requires `UV=1` to even list the credential, which closes most of the leak; it is not universally deployed.

**Counter-regression false positives on synced passkeys.** The per-credential signature counter is per-authenticator. A passkey synced across two devices will see the counter desynchronise between them. WebAuthn L3 §6.1.1 explicitly permits a *zero-counter* for synced passkeys; relying parties that treat any counter regression as evidence of cloning will produce false positives. Treat counter regression as evidence of cloning *only* for `BS=0` (device-bound) credentials. This is a deployment foot-gun, not a protocol flaw.

> **Walkthrough: Mapping features to the criteria table.** For phishing resistance, inspect `clientDataJSON.origin` and `authenticatorData.rpIdHash`; a look-alike domain cannot make those bytes equal the real RP. For verifier compromise, inspect storage: the RP keeps a public key and credential ID, not a reusable shared secret. For replay and relay, inspect the fresh challenge, counter, and transport: captured assertions die with the challenge, while `BS=0` device-bound keys cannot be replayed from a sync copy. For step-up, inspect `UP`, `UV`, and any transaction-specific challenge the RP binds to the operation. For availability and recovery, inspect `BE` and `BS`, then leave the protocol and audit the platform's recovery primitive: TPM-only device binding can satisfy AAL3; synced passkeys inherit the sync fabric and remain AAL2.

These are the *protocol* limits. The biggest practical limit is one the protocol cannot fix at all, recovery. The protocol can specify what factor produces the credential at sign-in; it cannot specify what factor produces the credential when the original one is lost. That is the application-layer question every relying party answers differently, and it is the question the recovery section lands on.

## Open problems: what's still moving in late 2025 / early 2026

Standardization is not done. Several major surfaces are still in active draft.

**WebAuthn Level 3** is currently a W3C Candidate Recommendation [865]; the dated CR snapshot is 13 January 2026 [905]. As of January 2026, Candidate Recommendation means implementation feedback can still change details before Proposed Recommendation and Recommendation; treat the CR as the normative draft to track, not as a promise of dates. The active editor masthead is in the W3C draft itself [865].

**CTAP 2.2** is a FIDO Proposed Standard as of 14 July 2025 [922]; **CTAP 2.3** followed as a Proposed Standard on 26 February 2026 [923]. The 2.2 and 2.3 revisions refine hybrid transport, `credProtect`, and PIN-protocol handling without breaking 2.1's command-byte table.

**Cross-vendor passkey portability.** The FIDO Alliance *Credential Exchange Protocol* (CXP) and *Credential Exchange Format* (CXF) Working Drafts, dated 3 October 2024 [947], are the standards effort. The draft text identifies the problem: "the transfer of credentials between two different providers has traditionally been an infrequent occurrence... As it becomes more common for users to have multiple credential providers that they use to create [and] manage credentials, it becomes important to address some of the security concerns with regard to migration" [947]. Apple has signaled CXP-based import for iOS; Bitwarden has signaled support. The plausible 2026 trajectory is CXP moving toward Proposed Standard and the major OS passkey surfaces experimenting with import-export UX, but that is forecast rather than normative status.

**Transactional authorization.** The earliest WebAuthn drafts included `txAuthSimple` and `txAuthGeneric` extensions [904]; neither was ever implemented by browsers, and both are absent from L3. The productised path is Secure Payment Confirmation (a sibling spec to WebAuthn), but it covers only payment transactions. General "sign a description of *this transaction*" remains an open problem. Conjecture: payment-confirmation becomes the template that gets generalized in WebAuthn Level 4.

**Quantum-safe attestation.** The IANA COSE algorithm registry (last updated 2026-03-04) currently has no PQC algorithm in WebAuthn-recommended status [920]. ECDSA P-256, EdDSA Ed25519, RSA-PKCS1.5, and RSA-PSS are the registered options, all quantum-breakable in principle. A long-lived TPM AIK signed today is forgeable to a quantum-capable adversary at any future date. Post-quantum migration on Windows is a separate subject this book does not cover; the WebAuthn deployment side of it is open. One plausible trajectory is ML-DSA (FIPS 204) eventually entering the WebAuthn COSE registry and new TPM attestation chains gaining a parallel post-quantum enrollment path; neither is a registered WebAuthn status claim as of the IANA snapshot cited here.

Standards are still moving. What should a practitioner do *today*?

## What it means for you

Six pieces of operational advice, each tied to a primary source.

**1. Windows developers: use `webauthn.dll`, do not roll your own.** The Win32 reference at `learn.microsoft.com/en-us/windows/win32/api/webauthn/` [932] is the only surface you should be calling. The OS handles USB-HID, NFC, BLE, hybrid transport, Conditional Mediation, plug-in dispatch, and Windows Hello UV in one call. The header is at `github.com/microsoft/webauthn` [931]; the Microsoft Learn overview is at `learn.microsoft.com/.../hello-for-business/webauthn-apis` [919].

**2. Relying parties: default to `attestation: "none"`, `userVerification: "required"`, `residentKey: "preferred"`.** This is the 2024-2026 consumer-flow baseline. `attestation: "none"` preserves user privacy and interoperates with every authenticator type. `userVerification: "required"` forces `UV=1` and the gesture acquisition. `residentKey: "preferred"` enables usernameless sign-in on platforms that support it without burning a credential slot on older authenticators that don't. The Microsoft Entra passwordless documentation [879] and the WebAuthn Level 3 spec [865] are the references.

**3. Enterprise IT: device-bound FIDO2 keys for AAL3 (admin, finance, tier 0); synced passkeys for AAL2 workforce.** NIST SP 800-63B-4 [890] formalizes the dichotomy via the syncable-authenticator supplement [930]. Yubico's enterprise commentary makes the operational point: device-bound passkeys on dedicated hardware are AAL3; synced passkeys are AAL2 [894]. For admin accounts use FIDO Alliance L3-certified hardware [891]: YubiKey Bio, Feitian BioPass, the Entra-listed vendors at `learn.microsoft.com/.../concept-fido2-hardware-vendor` [918].

**4. Windows 11 24H2 end users: enable third-party passkey providers in Settings.** Settings → Accounts → Passkeys → Advanced options. Toggle the provider on for any vendor you trust (1Password, Bitwarden, Dashlane) [937]. The Microsoft Learn third-party tutorial walks the flow [941]. If you do not use a third-party vault, the Microsoft synced passkey provider is enabled by default on 24H2 systems signed in with a Microsoft Account.

**5. Security architects: write down your recovery flow first.** Score it against the five-axis criteria table from the criteria framework before you design the authentication factors. The recovery row's strength is the system's ceiling, not the floor; the authentication ceremony cannot raise it. Microsoft Entra's own guidance flags account recovery as a deployment risk: FIDO2 keys "can increase costs for equipment, training, and helpdesk support. Especially when users lose their physical keys and need account recovery" [879]. The recovery section lands this argument.

**6. Incident responders: collect ETW events from the WebAuthn provider.** Plug-in authenticator registration events on managed devices are a high-signal indicator. A newly enrolled `IPluginAuthenticator` on a privileged user's machine should be treated as a credential-store change requiring review. The ETW chapter (Chapter 25) walks the WebAuthn provider events end to end.

> **A one-line PowerShell to enumerate Windows passkeys.** Open PowerShell as the signed-in user (no admin needed for your own credentials) and call into the `webauthn.dll` `WebAuthNGetPlatformCredentialList` API via a managed wrapper, or use the Settings → Accounts → Passkeys page directly. There is no first-class `Get-WebAuthnCredential` cmdlet as of Windows 11 25H2; the Settings page is the supported management surface. The Microsoft Learn passkey overview is the canonical management reference; this is an absence claim, so verify it against Microsoft's current PowerShell and Windows passkey documentation before turning it into an operational dependency [933].

Most of this is engineering. One row of the table has resisted engineering for fifty years. That's where the chapter lands.

## Recovery: your weakest factor is always your recovery flow

The thesis surfaced in the criteria framework and deferred through the mechanism sections is the one the chapter lands on. The argument is direct, almost embarrassingly so: every authentication system that admits any external recovery primitive is, in the formal sense, at most as strong as that primitive. Strong authentication ceremonies coexist with weaker recovery ceremonies across the major consumer platforms surveyed here, and the *system's* assurance level is the minimum of the two, not the maximum.

> *Your weakest factor is always your recovery flow.*

To make the claim concrete, score representative major-platform recovery flows against the same five-axis criteria table.

**Apple iCloud Keychain (with Advanced Data Protection).** Apple's published model has three recovery primitives [929]: (a) a *trusted device* the user previously signed into; (b) an *iCloud Recovery Contact*, another Apple ID owner the user has nominated to attest their identity; and (c) an *iCloud Recovery Key*, a 28-character string the user must retain [948]. Apple's published architecture is the strongest current consumer realisation of the end-to-end-encrypted invariant: the recovery primitives unlock an HSM-backed escrow cluster that holds the user's iCloud Keychain encryption material, but Apple itself does not hold the keys in plaintext. The fundamental dependency is the Apple ID password plus, originally, SMS-OTP at device-trust establishment.

**Google Password Manager (with Google Account end-to-end encrypted passkey sync).** Trusted-device fallback, security-key fallback, recovery code, recovery phone, recovery email. The recovery floor reduces, in the worst case, to SMS-OTP via the recovery phone. Google's architecture is end-to-end encrypted in the steady state but the trust establishment depends on Google account recovery, which depends on out-of-band verification primitives the user enrolled at account creation.

**Microsoft Account.** The October 2024 Windows Developer Blog states the recovery primitive verbatim: "you will be prompted to save a recovery key that will be used to verify your identity and protect your passkeys through end-to-end encryption" [937]. The recovery key is a high-entropy string the user retains; if they lose it, the recovery flow falls back to the secondary factors the user enrolled (alternate email or SMS-OTP via the recovery phone). As with Google, the worst-case recovery floor is the weakest of the secondary factors the user enrolled.

**Microsoft Entra ID (enterprise).** Entra's Temporary Access Pass (TAP) is a stronger enterprise recovery primitive than consumer self-service recovery when it is time-bound, audited, and issued by an administrator under separation-of-duties policy: the user redeems it to bootstrap a new authenticator. TAP can raise the floor because the admin's identity is on the issuance, but it is still weaker than the authentication ceremony if helpdesk identity proofing is socially engineerable or unaudited. Microsoft documents the TAP issuance and redemption flow in detail [949].

**1Password, Bitwarden, Dashlane under the 24H2 plug-in model.** Each vendor's master password and secondary recovery primitive becomes the *de facto* floor of the entire passkey ceremony when the plug-in is the credential store. 1Password's master password plus Secret Key, Bitwarden's master password plus 2FA recovery code, and Dashlane's device trust plus master password. Each is the recovery floor for every passkey the vault holds. The Microsoft Learn third-party tutorial reinforces the warning, in context: "Contoso Passkey Manager is designed for passkey creation and usage testing only. Don't use the app for production passkeys" [941].

![Figure: The surveyed passkey platforms start from the same origin-bound ceremony, but expose different ladders of account-recovery primitives, and the common weak floors are out-of-band recovery primitives such as SMS-OTP, email, a retained secret, or an admin Temporary Access Pass. Per-leaf AAL tags show the drop; the system’s assurance is the minimum: System AAL = min(ceremony, recovery).](diagrams/24-webauthn-recovery-floor.svg)

The diagram looks busy because it is. Across the surveyed platforms, the recovery flow is a different combination of trusted-device fallback, recovery code or key, recovery contact, and an out-of-band primitive (SMS-OTP, email, or admin attestation). Every one of those out-of-band primitives is weaker than origin-bound public-key cryptography. The cryptographic ceremony scores AAL3 phishing-resistant at the authentication moment; the recovery primitive scores AAL1 or AAL2 at the recovery moment. *The system's AAL is the minimum.*

> **Aside, Compliance reading.**
> NIST SP 800-63B-4's AAL2 / AAL3 split makes the recovery story explicit. Section 5.1 of SP 800-63B-4 enumerates permitted recovery primitives; every one is at most as strong as its underlying factor. The April 2024 supplement [930] caps synced passkeys at AAL2 because the recovery/sync model can recreate the credential outside the original authenticator: the same logic that caps the recovery row applies to the sync fabric. Auditors who care about AAL3 for tier-zero accounts will require *both* a device-bound authenticator and a documented recovery flow whose own strength is at AAL3. The current best-practice composition is two device-bound hardware authenticators in different physical locations, each registered as primary for the other's recovery.
>
> **Key idea.**
> For the surveyed consumer and vault-backed passkey platforms, the recovery floor (trusted-device fallback, recovery code or key, recovery contact, email, SMS-OTP, or administrator-issued bootstrap token) is the AAL ceiling for the whole account unless the organization deliberately engineers a stronger, audited re-enrollment path.

The protocol literature has been clear about this for fifty years and the regulatory literature has been catching up since 2017. NIST SP 800-63-3 introduced "phishing-resistant authenticator" as a first-class term; SP 800-63-4 (2025) [889] makes verifier-impersonation resistance a normative criterion. Neither standard solves recovery; both standards explicitly enumerate what counts as a recovery primitive without specifying how to *compose* them into an AAL-graded flow. There is no IETF or FIDO Alliance standard that says "here is a recovery flow whose strength is AAL3." There may never be. Recovery is application-specific, and the only general protocol is "social attestation" (multiple human witnesses), which does not scale.

As shown in the criteria framework, the same WebAuthn ceremony that scores AAL3 phishing-resistant at the authentication moment can collapse to a single-factor recovery moment if re-enrollment falls back to SMS, email, or unaudited discretion. That is the design review line: write down and score recovery *before* designing the authentication factors.

## Study artifact: reasoning traps to carry forward

Use this as a review checklist, not as a vocabulary dump. Each row names the byte, boundary, or policy decision that should change what you accept in a design review.

| Trap | Correct reading | Why it matters operationally |
|---|---|---|
| "Two factors" predicts strength | Count attacker defeats instead: verifier-impersonation resistance, verifier-compromise resistance, replay/relay resistance, step-up, and recovery. | Password plus push and passkey sign-in can both look like two factors, but AitM phishing kits walk through the first and fail on the origin binding in the second. |
| "The private key never leaves" describes all passkeys | It describes platform-bound Windows Hello / TPM credentials and hardware keys. It does not describe synced Microsoft passkeys or third-party vault-backed passkeys unless the provider supplies independent hardware-binding evidence. | This is the difference between an AAL3 argument and an AAL2 syncable-authenticator argument. Do not let the Windows picker UI erase the storage model. |
| "Phishing-resistant" means "unrecoverable" | Phishing resistance is a ceremony property: the assertion is bound to `clientDataJSON.origin` and `authenticatorData.rpIdHash`. Recovery is a lifecycle property: who can recreate, unlock, or re-enroll the credential after device loss. | A synced passkey can be phishing-resistant during sign-in and still capped below AAL3 because its recovery or sync fabric can recreate the key on another device. |
| "Attestation proves the user" | Attestation proves something about the authenticator or platform at registration. Authentication proves possession of the credential private key during sign-in. User identity is still the relying party's account-binding decision. | Requiring `direct` attestation in a consumer flow can create privacy risk without solving account takeover; use it only when model identity changes fraud decisions. |
| "Hybrid transport trusts Bluetooth" | The QR code carries tunnel material; ephemeral ECDH establishes the encrypted channel; BLE mainly contributes proximity. | Treat BLE failure as an availability/debugging issue, not as the cryptographic trust anchor. The signed WebAuthn assertion is still the thing the RP verifies. |
| "Counter regression always means cloned key" | For `BS=0` device-bound credentials, a regressing sign counter is strong clone evidence. For synced passkeys, L3 permits zero or non-monotonic counters across devices. | Incident-response rules must branch on `BE`/`BS`; otherwise synced passkeys generate false positives. |
| "AAL3 is an authentication-only label" | AAL3 requires the authenticator and the recovery / re-enrollment path to preserve equivalent strength. | Tier-zero accounts need two or more device-bound authenticators and a recovery process that does not fall back to SMS, email, or unaudited helpdesk discretion. |

The compact term sheet follows from those traps:

| Term | Working definition |
|---|---|
| Phishing-resistant authenticator | An authenticator whose protocol prevents a relying-party impersonator from inducing release of a reusable credential; NIST calls this verifier-impersonation resistance. |
| Origin binding | The browser writes the origin into `clientDataJSON`; the authenticator signs over the `rpIdHash`; the RP rejects any mismatch. |
| `rpId` | The relying-party identifier scoped to a registrable domain suffix; WebAuthn signatures bind to `SHA256(rpId)`. |
| CTAP 2.x | The CBOR wire protocol between client and roaming authenticator over USB-HID, NFC, BLE, or hybrid transport. |
| Discoverable credential / passkey | A credential whose account metadata is available to the authenticator, enabling usernameless sign-in; CTAP called this a resident key. The term does not by itself say whether the key is TPM-bound, synced, or vault-backed. |
| Attestation conveyance | Optional registration evidence that chains the new credential public key to an authenticator or platform root. It is a registration-time device/platform claim, not proof of account identity. |
| Hybrid transport | Phone-as-authenticator flow: QR transfers tunnel material, BLE supplies proximity, encrypted CTAP2 crosses an HTTPS tunnel. |
| AAGUID | Sixteen-byte authenticator model identifier; privacy-preserving authenticators may emit all zeros. |
| Conditional UI | Browser mediation mode where passkeys appear in autofill; the RP calls `navigator.credentials.get()` with conditional mediation. |
| `BE` / `BS` flags | Backup Eligible and Backup State bits; `BE=1` means sync is possible, `BS=1` means currently backed up. Use them to distinguish AAL2 syncable behavior from device-bound behavior. |
| AAL2 / AAL3 | NIST assurance levels: synced passkeys can satisfy AAL2; hardware-bound, non-syncable authenticators can satisfy AAL3 only when recovery and re-enrollment preserve equivalent strength. |

> **Bequeaths.** WebAuthn hands the next link one guarantee: a front-door sign-in an adversary-in-the-middle cannot replay, bound to `clientDataJSON.origin` and the `rpIdHash`, and (in its platform-bound Windows Hello form) backed by a TPM key that never reaches the wire. That is the floor the cloud-session chapters stand on: the Zero Trust chapter (Chapter 26) and the Continuous Access Evaluation chapter (Chapter 27) assume the human who authenticated did so with something phishing-resistant, then govern the session that sign-in mints. But the bequest stops at the ceremony. It does not raise the *recovery* floor: the system's assurance is the minimum of sign-in and recovery, and recovery still bottoms out at weaker primitives across the consumer platforms surveyed here. It does not carry AAL3 to synced or vault-backed passkeys, whose assurance is governed by the sync and recovery model rather than by one TPM-bound key. And it makes no claim against a coerced user or kernel-mode malware already on the device. That defense belongs to The Secure Kernel chapter (Chapter 6) and the Credential Guard chapter (Chapter 15). The chain proves who is at the keyboard; it does not prove they will come back the same way they left.
