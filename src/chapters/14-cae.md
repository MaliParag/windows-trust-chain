# Continuous Access Evaluation

::: trust-ledger

- **Inherits:** The sign-in authorization decision and the self-contained bearer access token it issues. Validated locally by a resource provider (signature, issuer, audience, expiry) with no call back to the identity provider (Chapter 26, Zero Trust); and the cloud bearer-token residual the credential chain kept routing forward: Credential Guard (Chapter 15) isolated the *storage* of the long-term secret but conceded the *token* minted downstream, and Pass-the-Hash to Pass-the-PRT (Chapter 19) traced the Primary Refresh Token that silently mints those tokens and named CAE its dwell-time control.
- **Promise:** An access token that was correct at issuance but is invalidated mid-session (the user disabled, the password reset, MFA enabled, refresh tokens revoked, or risk elevated) stops being honored by a cooperating Microsoft 365 resource provider in near-real-time (up to 15 minutes for critical events; instant for IP-location changes where CAE Conditional Access location enforcement is supported), without returning to a per-request authorization round-trip. Serviced boundary: the Entra identity provider → resource-provider push channel.
- **TCB:** Microsoft Entra as the transmitter of critical events; the CAE-aware resource provider (Exchange Online, SharePoint Online, Teams, Microsoft Graph for Conditional Access policy) as a trustworthy receiver that honors them; Microsoft's first-party push channel between them; and the client app (using MSAL) detecting the 401 and acting on the claims challenge. A compromised resource provider is explicitly *outside* it.
- **Adversary → Break:** The fired employee (or a token thief) who keeps presenting a still-valid token. CAE closes the *stale-authorization* gap on the *next* request, never the request already in flight, never a token the IdP never issued (a forgery), and, at Microsoft 365 scale, not instantaneously: critical-event revocation lands within a fan-out window of up to 15 minutes. The Promise covers *revocation of a legitimately-issued token*, not its *possession* or its *authenticity*.
- **Residual:** Theft and replay of a legitimately-issued bearer token → sender-constrained tokens (DPoP, mTLS), the same proof-of-possession principle Windows Hello (Chapter 20) and WebAuthn and Passkeys (Chapter 21) build into the front door; PRT-layer theft that mints fresh CAE-aware tokens → Pass-the-Hash to Pass-the-PRT (Chapter 19); a *forged* token signed by a key outside Entra's control → When the Chain Snaps: Storm-0558 (Chapter 29); a compromised resource provider that drops revocation events → out of scope.
- **Bequeaths:** Near-real-time revocation of a still-valid, *legitimately-issued* token. The premise the finale (Chapter 29, When the Chain Snaps: Storm-0558) stress-tests when it asks what happens if the token was *forged* and no revocation event ever fires. Does NOT provide: revocation of a token the IdP never issued, defense against token *theft* (→ sender-constrained tokens), or PRT-layer revocation (→ Chapter 19). The parallel cloud link, Confidential VMs (Chapter 28), secures the *workload's* memory, not the *session's* tokens.
- **Proof:** 🔵 documented throughout: Microsoft Learn (the five critical events, the 15-minute SLA, instant IP-location enforcement, `cp1`/`xms_cc`, the up-to-28-hour lifetime), the OpenID SSF/CAEP/RISC Final Specifications, and IETF RFCs 6749/7009/7662/8417/8935/8936/9449/8705. No live-VM capture: CAE is a tenant-and-cloud behavior the book's offline lab cannot exercise.
:::

> **The Reasoner's question.** How can Microsoft Entra and a resource provider revoke or re-evaluate a still-valid access token mid-session without returning to a per-request authorization bottleneck?

---

> **Foundations. What you need before this chapter.**
>
> - **OAuth 2.0 access token.** A credential the client presents to a protected
> resource. In the cloud pattern this chapter discusses, the token is usually a
> signed, self-contained bearer token that the resource provider can validate
> locally: signature, issuer, audience, expiry, and selected claims. Local
> validation is why OAuth scales; local validation is also why mid-life
> revocation is hard. [1227]
> - **Bearer token.** "Bearer" means possession is enough. Unless the access
> token is sender-constrained by another mechanism, a party that holds the token
> can present it. CAE changes when a resource provider should honor the token;
> it does not by itself prove that the presenter is the original client. That
> distinction is why DPoP and mTLS reappear later in the chapter. [848]
> - **Conditional Access.** Microsoft Entra's policy decision layer for user,
> device, application, location, risk, and session controls: owned by Zero Trust
> (Chapter 26), which covers the sign-in decision. This chapter covers the period
> after that decision, when the access token is already in a client's cache.
> - **Resource provider.** In generic OAuth language this is a resource server. In
> Microsoft CAE language it is narrower: Exchange Online, SharePoint Online,
> Teams, or Microsoft Graph for Conditional Access policy evaluation, a
> workload that participates in Entra's CAE contract and can enforce a claims
> challenge on subsequent token-bearing requests. [124]
> - **Claims challenge.** A `401 Unauthorized` response whose
> `WWW-Authenticate` header carries `error="insufficient_claims"` and a
> base64url-encoded `claims` parameter. It tells a CAE-capable client to bypass
> the token-cache happy path and ask Entra for a fresh token reflecting current
> state. [1228]
> - **`cp1` / `xms_cc`.** The client-capability declaration that advertises CAE
> readiness. The client SDK/application advertises capability `cp1` to Entra
> through `xms_cc` client-capabilities request metadata or the equivalent SDK
> configuration; Entra then issues CAE-aware tokens whose lifetime can extend up
> to 28 hours. Without that declaration, Entra falls back to ordinary one-hour
> access-token behavior. [1228]
> - **Security Event Token, SSF, CAEP, RISC.** The standards-track version of the
> same idea uses RFC 8417 Security Event Tokens as signed event envelopes, SSF
> as the stream/subscription framework, CAEP for continuous-access session
> events, and RISC for account-risk and incident events. Microsoft CAE is the
> first-party Microsoft channel; OpenID Shared Signals is the vendor-neutral
> direction of travel. [1229]

---

> **The bargain in one paragraph.** **Microsoft Entra Continuous Access Evaluation (CAE) lets access tokens safely live up to 28 hours; "up to" is an upper bound, and actual lifetimes can be shorter.** It works by maintaining a push-subscription channel between Entra and Microsoft 365 resource providers, so that when a user is disabled, has their password reset, or has MFA enabled, the resource provider rejects the next request with a `401` and a claims challenge: typically within 15 minutes for critical events, and instantly for IP-location changes where CAE Conditional Access location enforcement is supported [124]. The same pattern was standardized by the OpenID Foundation on September 2, 2025 as SSF 1.0, CAEP 1.0, and RISC 1.0 Final Specifications [1229], opening the door to vendor-neutral cross-SaaS revocation. CAE does **not** solve token theft (for that, use a sender-constrained token; on Entra / Microsoft 365 today that mechanism is Token Protection, not standard RFC 9449 DPoP) and does **not** cover Microsoft Defender for Endpoint or Intune as resource providers (they are signal sources into Conditional Access, not CAE consumers). It also does not extend to the Azure management plane (ARM, the Azure portal and CLI) or to SAML-federated sessions; tokens for those remain valid until their natural expiry even after a revocation event.

## Your fired employee is still reading email

09:00 Tuesday. The administrator disables the account at 09:01. In the pre-CAE model, or against a non-CAE-aware path, the ex-employee's open Outlook for the Web tab refreshes at 09:23, and pulls down new mail. This is not a bug. This is RFC 6749 working exactly as designed. Before Microsoft Entra shipped a production answer after a decade of standards and Zero Trust pressure, the access token that user held at 09:00 stayed cryptographically valid until 10:00 at the latest, and there was nothing Conditional Access could do about it [1227].

The window has a name now. It did not, for most of cloud identity's history. Microsoft's own documentation calls it "the lag between when conditions change for a user, and when policy changes are enforced" [124]. Between sign-in (Conditional Access territory) and the next token refresh (refresh-token territory) sits a stretch of time in which Conditional Access decisions have no enforcement surface. That stretch ranged from 60 minutes to 24 hours, depending on tenant configuration. For every OAuth 2.0 deployment from 2012 onward, this was the security debt the industry carried.

> **Note.** "Microsoft Entra ID" is the rebranded name for what most engineers learned as "Azure Active Directory" or "Azure AD." Microsoft announced the rename in July 2023 [1230]; the underlying service, tenants, app registrations, and APIs are unchanged. Throughout this chapter, "Entra" and the older "Azure AD" refer to the same identity platform.

This chapter explains the engineering pattern that lets a Microsoft 365 tenant do two things that look contradictory at the same time: extend access-token lifetime from 1 hour to up to 28 hours, *and* revoke a disabled user's session in under 15 minutes [124]. The reconciling idea is a near-real-time push channel between the identity provider (Entra) and a small set of cooperating resource providers. When you can revoke a token in minutes rather than waiting for it to expire, expiry stops doing the security work, and the token can live as long as the user actually needs it.

> **Definition: Continuous Access Evaluation (CAE).** Microsoft Entra's push-subscription channel between the identity provider and cooperating resource providers (Exchange Online, SharePoint Online, Teams, and Microsoft Graph). CAE lets a resource provider revoke an already-issued access token in near-real-time (up to 15 minutes for critical events, and instantly for supported IP-location changes) without waiting for the token to expire [124].

The trade has a price. The 15-minute critical-event service-level objective is plausibly the price the channel pays for fanning out events across hyperscale Microsoft 365 infrastructure. Sub-second revocation is possible in smaller deployments, but at Exchange-Online volume Microsoft documents the operating point rather than the full cost model behind it.

For now: the OAuth 2.0 designers knew about this gap when they wrote RFC 6749 in 2012. They chose it on purpose. To see why, and to see why the obvious patches all failed, we have to walk back to the moment the trade was made.

## The static-expiry compromise

In October 2012, Dick Hardt of Microsoft published RFC 6749: *The OAuth 2.0 Authorization Framework*: as the editor of record for an IETF working group that had spent about three and a half years arguing about it [1227]. Section 1.4 defines access tokens as carrying "specific scopes and durations of access," but the specification never characterizes them as short-lived. That an access token should be short enough to limit exposure was always convention, not a normative requirement: the closest the RFC comes is Section 1.5's aside that an access token "may have a shorter lifetime and fewer permissions" than the refresh token that renews it. Nothing in the protocol enforces a short lifetime. Nothing in the protocol provides revocation. Nothing in the protocol stops a server from issuing 24-hour bearer tokens that, once minted, stay cryptographically valid until they expire on their own.

This was a deliberate trade. To see why it was rational, remember what came before.

### Web Access Management: the model OAuth replaced

> **Definition: Web Access Management (WAM).** The pre-2012 enterprise-identity pattern in which every protected HTTP request synchronously queried a central policy decision point. Strength: instant revocation, because every request consulted authoritative state. Weakness: a chatty bottleneck that did not scale to cloud volumes and could not federate trust across organizations.

Web Access Management dominated enterprise identity from the late 1990s into the early 2010s. Every protected HTTP request to a WAM-fronted application made a synchronous round-trip to a Policy Decision Point. The PDP held authoritative session and policy state. Revoke a user? The next request failed, immediately, because the PDP said no. No token-lifetime window. No gap between policy change and enforcement.

WAM was correct. WAM was also unworkable for the web that was coming. It did not scale: every request was a network hop. It did not federate: cross-organization SaaS meant the PDP could not live inside any one company's network. And it required every protected resource to participate in a single trust domain. By the time enterprises were running cross-organization SaaS at scale, the WAM model had run out of road.

The OAuth 2.0 authors made the opposite trade. Replace the chatty PDP round-trip with a self-contained signed bearer token: a JWT the resource server validates locally. Validation becomes O(1) cryptographic verification with no round-trip. Throughput scales horizontally. Federation works, because the JWT carries its own attestation of the issuer. Revocation becomes...approximated. By expiry. The token is valid until it isn't, and you trust that the lifetime is short enough.

For a 2012 web of forum logins and consumer mashups, "short enough" was a defensible answer. For a 2020 enterprise running compliance-bound SaaS across thousands of employees, it was not.

### The Zero Trust pressure

The intellectual pressure that turned that gap into a procurement problem belongs to Zero Trust (Chapter 26): BeyondCorp's December 2014 argument that a session is a *time-varying* authorization rather than a one-shot decision at sign-in [1231], codified in August 2020 as NIST Special Publication 800-207, *Zero Trust Architecture* [1116]. One sentence in SP 800-207 made the engineering investment commercially rational: *"Authentication and authorization (both subject and device) are discrete functions performed before a session to an enterprise resource is established."* A federal mandate for continuous re-evaluation pushed every cloud vendor with U.S. government contracts to find an implementation. CAE is the part of that story that lives *after* the token is issued; the philosophy and its thirteen-month standardization belong to Chapter 26.

### A name for the problem

The third moment named the gap. On February 21, 2019, Atul Tulshibagwale, then an engineer at Google, published *Re-thinking federated identity with the Continuous Access Evaluation Protocol* on the Google Cloud blog [1232]. The post introduced a term (CAEP) and a framing: publish-and-subscribe between identity providers and resource providers, as a third option between WAM's per-request chattiness and OAuth's fire-and-forget expiry. We return to Tulshibagwale's actual proposal below. For now what matters: 2019 was the year the industry got a vocabulary for a problem it had been carrying for seven years.

> **Aside.** The OpenID Foundation working group that grew out of Tulshibagwale's proposal was originally chartered as the *Shared Signals & Events* (SSE) working group. It was renamed *Shared Signals* in subsequent years, but older industry write-ups from 2020-2022 still use the SSE abbreviation [1233].

The timeline is the important point, not the diagram. OAuth 2.0 standardized the static-expiry bargain in October 2012. OAuth token revocation followed in August 2013, introspection in October 2015, the Security Event Token envelope in July 2018, and SET push/poll delivery in November 2020. In parallel, BeyondCorp appeared in December 2014 and NIST SP 800-207 made Zero Trust federal guidance in August 2020. Atul Tulshibagwale named the Continuous Access Evaluation Protocol idea in February 2019; the OpenID Shared Signals working group formed that year; and SSF 1.0, CAEP 1.0, and RISC 1.0 reached Final Specification status in September 2025. Microsoft Entra CAE sits inside that arc: limited preview in April 2020, expanded public preview in October 2020, and general availability in January 2022.

![Figure: The thirteen-year arc from RFC 6749's static-expiry bargain (October 2012) to the OpenID Shared Signals Final Specifications (September 2025), shown as two rails: the IETF and OpenID standards track, and Zero Trust thinking alongside Microsoft Entra's CAE rollout. The oxblood bracket is the fired-employee window: for roughly a decade, 2012–2022, a revoked user's token stayed cryptographically valid until expiry, and Entra CAE's general availability is what finally closed it.](diagrams/14-cae-timeline.svg)

The OAuth 2.0 designers traded revocation latency for throughput on purpose [1227]. Once that gap proved unacceptable, three obvious patches were tried. None of them worked. To see *why* none of them worked is to understand the negative space CAE was designed to fill.

## Three patches, three failures

Between 2013 and the late 2010s, the OAuth community published three patches for RFC 6749's revocation gap. Each was rationally adopted; each was rationally abandoned at hyperscale. This section is the genealogy of those failures, because what each one got wrong defines the shape of the design that finally worked.

### Patch 1: RFC 7009: the `/revoke` endpoint (August 2013)

In August 2013, Torsten Lodderstedt of Deutsche Telekom, Stefanie Dronia, and Marius Scurtescu of Google published RFC 7009, *OAuth 2.0 Token Revocation* [1234]. The contribution was a standardized HTTP endpoint, `/revoke`, that a client could POST a token to in order to invalidate it. The mental model is the logout button: when a user signs out, the client tells the authorization server "I'm done with this token, please retire it."

The failure mode is in the threat model. RFC 7009 is *client-initiated*. The token holder asks for revocation. But the scenario that motivates CAE is precisely the one where the token holder is uncooperative. A fired employee will not POST their access token to `/revoke` on the way out the door. An attacker who has stolen a token will certainly not. The administrator on the other side cannot use the endpoint either, because they do not possess the bearer token.

Worse, RFC 7009's Implementation Note (Section 3) is candid about self-contained tokens: the only standardized recourse is "some (currently non-standardized) backend interaction between the authorization server and the resource server" when immediate revocation is desired [1234]. Read that carefully. The spec admits there is no spec. The JWT in flight at the resource server is *cryptographically valid until it expires*. The authorization server can mark it revoked in a local database, but the resource server never asks. It validates the signature locally. The revocation event never crosses the wire.

RFC 7009 works for opaque tokens with a token-introspection back-channel. It does not, by itself, solve revocation for self-contained JWT bearers: which by the mid-2010s were the dominant pattern in the cloud.

### Patch 2: RFC 7662: the `/introspect` endpoint (October 2015)

Two years later, in October 2015, Justin Richer published RFC 7662, *OAuth 2.0 Token Introspection* [1235]. The mechanism: on every request, the resource server calls a `/introspect` endpoint on the authorization server with the bearer token. The AS replies with the token's current state. If the token has been revoked, `/introspect` returns `active: false`, and the resource server denies the request.

This is correct. It also reintroduces the WAM bottleneck that OAuth was designed to escape.

For an AS serving billions of requests per day (Microsoft Entra ID as one example, Google's IdP as another) making `/introspect` the per-request critical path turns the authorization server into a synchronous dependency on every API call against every resource server in the estate. Latency adds up. Availability becomes shared. If the AS has a bad five minutes, every resource server has a bad five minutes simultaneously. The architecture OAuth bought with self-contained tokens (resource server scales independently of AS) gets traded back for exactly the WAM property that motivated OAuth's existence.

> **A parallel-path note on RFC 7662.** RFC 7662 introspection is alive and well. It remains the right choice for opaque-token systems and on-premises IdPs where the resource server count is small, the per-request latency budget is generous, and the AS is well within capacity. The criticism here is structural and only applies at hyperscale public-cloud volumes. RFC 7662 was not killed by RFC 7009 or by CAE; it is a parallel path that continues to serve a substantial fraction of the deployed OAuth surface.

### Patch 3: Make the token life so short revocation does not matter

The third patch was the obvious one. If you cannot revoke a token mid-life, make its life short. Issue access tokens with a minutes-long lifetime, the way early Microsoft experiments did. The revocation window collapses. Problem solved.

Microsoft tried it. The retrospective is unusually candid. On April 21, 2020, Alex Weinert, then Director of Identity Security at Microsoft, published *Moving toward real time policy and security enforcement* on the Azure Active Directory Identity Blog [1236]. (The original lives at post ID 1276933 on Microsoft's tech community; the full body is preserved in Microsoft's Japanese translation on the jpazureid GitHub mirror [1237].) The post names the failure mode in one sentence:

> **Documented source.** "We have experimented with the "blunt object" approach of reduced token lifetimes but found they can degrade user experiences and reliability without eliminating risks.": Alex Weinert, Microsoft, April 21, 2020 [1236]

Two things break. First, *user experience and reliability*. Every short-lifetime boundary forces every active client to round-trip the IdP for a fresh token. For Outlook, Teams, Word Online, OneDrive, and every other client an enterprise user has open at once, that is a wave of token requests per user per cycle. Multiplied by Microsoft 365 active users, the load profile creates real outages. Network blips that would otherwise be invisible surface as failed refreshes, with user-visible re-authentication prompts. Second, *it does not eliminate the risk*. A minutes-long window is still a window. A fired employee can read or exfiltrate a great deal of email in that window. You have paid the full user-experience cost and still left a non-trivial breach surface.

This was the third failure. The negative space across the three patches defines the shape any real solution has to take: it must be *server-initiated* (not RFC 7009), it must be *push-based* rather than per-request poll (not RFC 7662), and it must *separate revocation from expiry* so the IdP does not pay for every revocation with a refresh-load spike (not the short-lifetime patch). The three failures exhaust the surface of the obvious fix.

> **Aha moment: the patches do not just fail, they fail for distinct reasons.** Each of the three patches fails for a different reason; together they rule out everything except server-initiated push subscription that decouples revocation from expiry.

If the patches all fail, the next move has to be architectural. The first published statement of that architecture was Atul Tulshibagwale's February 2019 Google blog post, and the move he proposed is the one Microsoft would ship three years later.

## Four generations of session enforcement

Walk forward through the genealogy of session enforcement and the subscription/claims-challenge breakthrough stops looking like a stroke of genius and starts looking like the path that survived the scale and federation constraints. Four generations, each killed by a documented limit of the previous one.

### Generation 0: WAM (pre-2012)

Per-request synchronous round-trip to a Policy Decision Point. Instant revocation; chatty bottleneck; no federation. Killed by cloud-scale request rates and the rise of cross-organization SaaS, where the protected resource and the policy authority no longer lived in the same trust domain. WAM remains valuable in single-tenant enterprise contexts, but for the public-cloud API mesh it cannot scale.

### Generation 1: Static-expiry JWT (2012-2020)

Self-contained signed bearer tokens validated locally at the resource server. Revocation approximated by expiry per RFC 6749 [1227]. Throughput scales; federation works; revocation is acceptable when the lifetime is short and the threat model is benign. Killed by (a) the fired-employee window, (b) the three failed patches above, and (c) the philosophical pressure from Zero Trust to treat sessions as continuously re-evaluated.

### Generation 2: Microsoft CAE (limited preview April 2020, GA January 10, 2022)

The first production solution. Limited preview launched in April 2020 with Alex Weinert's *Moving toward real time policy and security enforcement* announcement [1236]. Expanded public preview October 2020 [1238]. General Availability January 10, 2022, announced by Alex Simons, Corporate VP for Program Management in the Microsoft Identity Division [1239].

The architecture is a private push-subscription channel between Entra and a small set of Microsoft 365 resource providers, with a wire-level handshake (the `claims` challenge) for telling the client to re-acquire a token reflecting new state. Access-token lifetime extends from the default 1 hour to up to 28 hours specifically for CAE-aware sessions [124]. We will unpack the mechanism next.

The Gen-2 limitation that motivated Gen 3: the wire format is *Microsoft-internal*. A SaaS vendor that wants the same revocation properties for its own resource provider cannot use Microsoft's CAE channel. The protocol does not federate.

### Generation 3: OpenID SSF 1.0 + CAEP 1.0 + RISC 1.0 (final specifications, September 2, 2025)

The OpenID Foundation generalized the Microsoft pattern into a vendor-neutral specification. On September 2, 2025, three Final Specifications were approved: the Shared Signals Framework 1.0 (SSF), the Continuous Access Evaluation Profile 1.0 (CAEP), and the Risk and Incident Sharing and Coordination 1.0 (RISC) [1229].

The wire envelope is IETF RFC 8417's Security Event Token (SET), published in July 2018 by Phil Hunt (Oracle), Michael Jones (Microsoft), William Denniss (Google), and Morteza Ansari (Cisco) [1240]. A SET is a signed JWT carrying a single security event. The transport layer is RFC 8935 push (POST over TLS from transmitter to receiver) and RFC 8936 poll (recipient-initiated retrieval), both published November 2020 by Annabelle Backman and collaborators [1241]. SSF defines the subscription model: streams, subjects, transmitter and receiver metadata endpoints. CAEP and RISC define the *vocabulary* of events that can ride that envelope.

> **Aside.** RFC 8417 was a cross-vendor IETF effort that pre-dated the OpenID Shared Signals working group by a year. Phil Hunt was at Oracle; Michael Jones at Microsoft; William Denniss at Google; Morteza Ansari at Cisco. The envelope-only design (leaving event vocabularies to higher-layer profiles) is what allowed the OpenID profiles to reuse a neutral event container while Microsoft's first-party CAE documentation could keep its internal Entra-to-Microsoft-365 channel private [1240].

Public documentation draws a bright line:

| Publicly documented surface | Not publicly specified |
|---|---|
| CAE critical events, supported workloads, 15-minute critical-event target, supported instant IP-location paths, 401 claims challenges, `cp1` client capability, and up-to-28-hour CAE token lifetime [124] | The exact Entra-to-Microsoft-365 event envelope, queueing topology, subscription state model, cache layout, and fan-out mechanics |
| OpenID SSF streams, CAEP/RISC event vocabularies, RFC 8417 SET envelopes, and RFC 8935/8936 delivery for vendor-neutral implementations [1229] | Whether any given Microsoft first-party CAE internal message is a literal SET on the wire |

Read the OpenID stack from the bottom up. Layer 1 is RFC 8417, the signed Security Event Token envelope. Layer 2 is transport: RFC 8935 for HTTP push and RFC 8936 for polling. Layer 3 is SSF 1.0, which defines streams, subjects, transmitters, receivers, metadata, verification events, and stream-control endpoints. Layer 4 is vocabulary: CAEP 1.0 for session-level continuous access events and RISC 1.0 for account-risk and incident-sharing events.

The generation chain has a documented engineering reason for each transition. The comparison matrix below pulls the essentials together.

| Approach | Year | Revocation latency | Strengths | Weaknesses |
|---|---|---|---|---|
| WAM (Gen 0) | pre-2012 | Instant | Authoritative state, instant enforcement | No federation, per-request bottleneck |
| Static-expiry JWT (Gen 1) | 2012-2020 | Up to token lifetime (1h-24h) | O(1) RP validation, federation works | No revocation; fired-employee window |
| Short-lifetime patch | mid-2010s | Minutes | Conceptually simple | Load amplification, window remains, UX degradation |
| RFC 7662 introspection | 2015 onward | Instant | Standardized, works for opaque tokens | AS becomes per-request critical path |
| Microsoft CAE (Gen 2) | 2020-2022 | Up to 15 min critical; instant IP | Push, decoupled from request rate, long tokens safe | Microsoft-internal protocol; tiny RP set |
| OpenID SSF/CAEP (Gen 3) | 2025 onward | Vendor-dependent | Vendor-neutral standard, cross-SaaS | Receiver adoption still early |

The generation chain is simple in prose: WAM gave instant per-request authorization but failed at cloud scale and federation. Static-expiry JWTs gave local validation and federation but created the fired-employee window. Microsoft CAE preserved local validation while adding push revocation and claims challenges, but only inside Microsoft's first-party estate. OpenID SSF and CAEP generalize the same pattern into a vendor-neutral signal framework.

Knowing the lineage is not knowing the trick. What is the actual mechanism CAE deploys: the thing that turns this standards-history arc into a feature that ships and makes 28-hour tokens defensible? It has three parts, and once you see them together, you understand why long tokens are safe.

## Subscription, claims challenge, extended lifetime

Three innovations, none new in isolation, all unprecedented in combination.

Atul Tulshibagwale's 2019 framing names the move: "Our vision for continuous access evaluation is based on a publish-and-subscribe ('pub-sub') approach... It's complementary to federated or cert-based authentication... It's not as chatty as WAM... It doesn't impact latency for user access" [1232]. Pub-sub is the third option between WAM's per-request chattiness and RFC 6749's fire-and-forget. Subscription is the channel; claims challenge is the wire-level handshake; extended lifetime is the user-experience prize.

### Part 1: Subscription

Microsoft's CAE concept page describes the architecture in one sentence that rewards close reading:

> **Documented source.** Timely response to policy violations or security issues really requires a 'conversation' between the token issuer Microsoft Entra, and the relying party (enlightened app).: Microsoft Learn, *Continuous access evaluation in Microsoft Entra* [124]

The word *conversation* is the architecture. The relying party (a CAE-aware Microsoft 365 workload such as Exchange Online) subscribes to a finite, documented set of *critical events* for the subjects it cares about. Entra pushes events to the RP as state changes. State is cached at the RP. On the hot path (the per-request data plane), the RP does an O(1) JWT signature verification plus an O(1) hash-table lookup of cached revocation state. No back-channel round-trip on the hot path. The 28-hour token costs no more to validate than the 1-hour token it replaced [124].

This is the move that defeats RFC 7662. The state lives at the RP, not at the AS. The control-plane cost scales with the rate of *events*, not the rate of *requests*. Push, not poll.

### Part 2: The claims challenge

When state at the RP changes (because a push event has arrived saying "this user's password has been reset"), the RP cannot reach into a request that has already been accepted and is being served. CAE is in-band with the *next* request, not the current one. The next time the client presents the stale token, the RP rejects it with `HTTP 401` and a specific header:

```text
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer error="insufficient_claims",
                  claims="eyJhY2Nlc3NfdG9rZW4iOnsiYWNyc..."
```

The `claims` parameter is a base64url-encoded JSON object that tells the client what to re-acquire from the IdP. The Microsoft Authentication Library (MSAL) on the client decodes the challenge transparently and requests a new access token from Entra with the indicated claims. Entra either issues a fresh CAE-aware token (if authorization still holds) or rejects, forcing interactive re-authentication. The client retries the original API call with the new token [1228].

> **Definition: Claims Challenge.** The HTTP-level mechanism by which a CAE-aware resource provider signals to a client that the presented token must be re-acquired with fresh state. The challenge is conveyed as a `WWW-Authenticate: Bearer error="insufficient_claims"` header with a base64url-encoded `claims` parameter; current Microsoft Authentication Library (MSAL) releases decode and handle it automatically when the client/application configuration advertises the `cp1` capability through `xms_cc` client-capabilities metadata or the SDK's equivalent setting [1228].

This is the move that defeats RFC 7009. Revocation is initiated by the *resource provider's view of the IdP's state*, not by the token holder. A fired employee's client cannot opt out of the claims challenge; the RP will not serve any further request until a fresh token arrives that reflects the post-revocation state.

The `nbf` (not-before) claim challenge is the most common shape: the RP is telling the client "give me a token issued after this moment." The client requests one. Entra checks current state. Did the user get disabled? did the password get reset? did the risk score elevate?, and either issues or denies. The wire format is simple enough to inspect in a browser tab, which is part of why the architecture has been able to standardize: there is no magic to reverse-engineer.

### Part 3: Extended lifetime, the prize

The first two parts buy you the third. Once revocation is push-based and the claims challenge gives the RP a way to evict stale tokens on the next applicable request after it has received and applied a control-plane event, the expiry timer stops carrying the security weight. Tokens can live longer because the expiry is no longer the only revocation mechanism.

Microsoft documents the upper bound as "up to 28 hours" for CAE-aware sessions [124]. The default for non-CAE-capable clients remains 1 hour. This is the move that defeats the short-lifetime patch: the IdP load profile collapses because tokens refresh once a day, not on a per-minute cycle, and the revocation window is dramatically smaller. Not because expiry shrank, but because the channel now does the revocation work expiry used to do.

> **Key idea.** Long-lived access tokens are safe only when paired with a near-real-time revocation channel. CAE is the channel. Subscription provides the push, the claims challenge is the in-band handshake the push enables, and the 28-hour lifetime is what the channel buys: not what the channel costs.

### The full round trip

The three parts interlock. The complete flow, from a state change at Entra to a re-validated request, runs end-to-end through every layer this chapter has named.

![Figure: The end-to-end CAE claims-challenge round trip. A control-plane state change at Entra (steps 1–3) propagates by push to the resource provider, which caches the new revocation state; the next stale-token request is rejected on the data-plane hot path (steps 4–5) with a 401 claims challenge; MSAL then re-acquires and Entra refuses because the account is disabled, so the session terminates (step 6). The hot path is an O(1) signature verification plus an O(1) cached-state lookup, with no authorization-server round-trip.](diagrams/14-cae-roundtrip.svg)

The end-to-end flow is a six-step conversation. First, an administrator disables a user account in Microsoft Entra. Second, Entra pushes a critical-event notification to a participating resource provider such as Exchange Online. Third, the resource provider updates cached revocation state for the subject and tenant. Fourth, the client presents the old bearer token on the next request; the resource provider validates the JWT signature, then checks cached CAE state and sees that the token is stale. Fifth, the resource provider returns `401 Unauthorized` with `WWW-Authenticate: Bearer error="insufficient_claims"` and a `claims` parameter. Sixth, MSAL requests a fresh token from Entra with those claims; because the account is disabled, Entra rejects the request and the session terminates rather than silently continuing.

Three moves, one design. Remove any one and the system collapses. Subscription without a claims challenge gives you push events the RP cannot act on at the wire. Claims challenge without subscription gives you a 401 mechanism with no information to decide when to fire it. Extended lifetime without either gives you Generation 1's fired-employee window. The 28-hour token is not the *cost* of CAE; it is what CAE *purchases*.

This is the design. What does it actually do in production today, and where does it stop?

## CAE as deployed in Microsoft Entra (2026)

Concrete answers to concrete questions. Which events trigger CAE? Who participates? What is the actual SLA? How long do tokens actually live? No marketing language; only what Microsoft Learn currently documents.

### Critical event evaluation events

Microsoft Learn lists exactly five events that drive *critical event evaluation* at the IdP-to-RP boundary [124]:

1. A user account is deleted or disabled.
2. A password for a user is changed or reset.
3. Multi-factor authentication is enabled for the user.
4. An administrator explicitly revokes all refresh tokens for a user.
5. High user risk is detected by Microsoft Entra ID Protection.

These five events propagate from Entra to the participating CAE-aware resource providers via the push channel. Microsoft's published service-level objective is "up to 15 minutes" for critical-event propagation [124]. That is not the same as "instant." The phrase to avoid is "CAE delivers instant revocation"; the accurate phrase is "CAE delivers near-real-time revocation, typically within 15 minutes for critical events."

A separate scenario (*Conditional Access policy evaluation*) covers network and IP-location changes. Here the SLA is different: IP-location enforcement is **instant** per Microsoft's published documentation [124]. The difference is mechanical. IP location is a property the RP sees directly on every request (the source IP of the incoming HTTP connection); the RP can compare it against the location constraints attached to the session and reject locally with no propagation delay. Critical events have to travel from Entra to the RP through the event channel, and that travel has a 15-minute budget at Microsoft 365 scale.

| Event | Source | Propagation | Notes |
|---|---|---|---|
| Account deleted or disabled | Entra ID directory | Up to 15 min | Honored by Exchange Online, SharePoint Online, Teams, Graph (CA) |
| Password changed or reset | Entra ID directory | Up to 15 min | Same RP set |
| MFA enabled for user | Entra ID directory | Up to 15 min | Same RP set |
| All refresh tokens revoked (admin) | Entra ID admin action | Up to 15 min | Same RP set |
| High user risk detected | Entra ID Protection | Up to 15 min | **SharePoint Online does not honor user-risk events** [124] |
| IP location changed (CA policy) | Resource-provider observation | Instant | Conditional Access policy evaluation path; strict location enforcement [1242] |

> **Common misconception: MDE and Intune are not CAE resource providers.** Microsoft Defender for Endpoint and Microsoft Intune (MDM) are *signal sources* into Conditional Access. They contribute to the risk score and device-compliance state that drive CA policy decisions, but they are **not** CAE-consuming resource providers. They do not subscribe to Entra critical-event notifications and they do not enforce the claims-challenge handshake on token-bearing requests. The CAE-aware RP set is exactly: Exchange Online, SharePoint Online, Microsoft Teams, and Microsoft Graph (the last only for Conditional Access policy evaluation) [124]. If you read older deck slides or vendor blog posts that list MDE or Intune as CAE participants, they are conflating the signal-source role with the resource-provider role.
>
> **Aside.** The SharePoint Online user-risk caveat is a concrete example of why "CAE-aware" is not a binary property at the workload level. SharePoint Online is fully CAE-aware for the first four critical events on the list; it just does not subscribe to user-risk events specifically. The lesson is that you must read the per-workload documentation carefully when designing controls that depend on a specific event's enforcement [124].

### Workloads that participate

The CAE-aware resource-provider set, per Microsoft Learn [124]:

- **Exchange Online**: full CAE consumer (initial implementation, October 2020).
- **SharePoint Online**: full CAE consumer, with the user-risk caveat noted above.
- **Microsoft Teams**: full CAE consumer in the current Microsoft Learn workload list, with the client-surface caveats in the compatibility table [124].
- **Microsoft Graph**: consumes Conditional Access policy evaluation events (the IP-location instant path); narrower scope than the M365 productivity workloads.

Client-side support is also explicit. Microsoft's compatibility tables in the CAE concept page enumerate which client and server combinations are *Supported*, *Partially supported*, or *Not Supported* on every major operating system and form factor [124]. Office web apps against SharePoint Online and Exchange Online are documented as *Not Supported* on several combinations; every Teams client surface shows as *Partially supported*. The point is not that CAE is broken on these surfaces. It is that Microsoft documents the rough edges in primary source, and tenant administrators who care about specific scenarios must read the table.

### Tokens and clients

The default access-token lifetime for CAE-aware sessions is up to 28 hours; the default for non-CAE-capable clients remains 1 hour [124]. Client support requires a current Microsoft Authentication Library (MSAL) release on the target platform. Microsoft Learn's *Use Continuous Access Evaluation enabled APIs* page enumerates the per-SDK knobs: `.WithClientCapabilities(new[] {"cp1"})` for MSAL.NET, `clientCapabilities: ["CP1"]` for MSAL.js, `client_capabilities=["cp1"]` for MSAL Python, `client_capabilities: "CP1"` in MSAL Android JSON configuration, `clientApplicationCapabilities = ["CP1"]` for MSAL ObjC/iOS/macOS, and `WithClientCapabilities([]string{"cp1"})` for MSAL Go [1228]. The important rule is not "edit one universal app-registration field"; it is that the client/application configuration must advertise CP1 and the code must handle the resulting claims challenge.

> **Definition: xms_cc (Client Capabilities).** The request-side client-capability metadata by which an application advertises support for CAE-aware token issuance. The capability value is `cp1` (Microsoft's SDK examples use both `"cp1"` and `"CP1"` in configuration). It signals that the client's MSAL implementation can decode and act on a `WWW-Authenticate: Bearer error="insufficient_claims"` response by parsing the `claims` parameter and re-acquiring a token. When Entra accepts that declaration, it can return CAE-aware tokens whose lifetime extends up to 28 hours; without it, Entra issues the default 1-hour token and the resource provider falls back to standard expiry [1228].
>
> **Definition: Resource Provider (RP) in the CAE sense.** A Microsoft 365 workload (Exchange Online, SharePoint Online, Teams, or Microsoft Graph for Conditional Access policy) that consumes Entra's critical-event notifications and enforces them on subsequent token-bearing requests via the claims-challenge handshake. This is a narrower meaning than the generic OAuth 2.0 sense of "resource server"; in CAE, "resource provider" specifically means a workload that has implemented the CAE participation contract with Entra [124].
>
> **What 'up to 28 hours' actually means.** Microsoft documents an *upper bound* on token lifetime. The actual lifetime issued for any given session is variable and can be shorter. CAE-aware sessions can also be refreshed silently as long as the channel signals nothing has changed. Practically, this means most users with CAE-aware clients on M365 productivity workloads almost never see an interactive re-authentication prompt during normal working hours [124].

### A migration note for older tenants

Tenant administrators with Conditional Access policies that pre-date GA may carry legacy "strict location enforcement" preview settings. Microsoft has since migrated the feature into GA, and the current Microsoft Learn page *Strictly enforce location policies using continuous access evaluation* documents the post-migration configuration model [1242]. Administrators should verify their policies after each major Conditional Access feature wave to ensure preview-to-GA migrations have been picked up.

CAE is one approach among several. Where does it sit relative to introspection-per-request, identity-aware proxies, DPoP, and the cross-vendor OpenID standard? The design space is small enough to map cleanly.

## Proof surfaces on a live tenant

This chapter contains no lab capture. The evidence posture is therefore strictly documented: the probes below are reproducible tenant surfaces, and the expected shapes come from Microsoft Learn and the source analysis. They are not presented as captured output from this book's lab VM.

> 🔵 **DOCUMENTED**: Microsoft Learn, *Continuous access evaluation in Microsoft Entra* and tenant observability guidance; not captured on our lab VM.
> Reproduce: inspect sign-in and audit logs with Microsoft Graph PowerShell in a non-production Microsoft Entra tenant.

```powershell
# Sign-in log surface: inspect recent sign-ins for event type, Conditional Access
# status, and CAE-related telemetry shape. Exact filtering depends on tenant
# volume and Graph permissions.
Get-MgAuditLogSignIn -Top 20 |
  Select-Object CreatedDateTime, UserPrincipalName, AppDisplayName,
    SignInEventTypes, ConditionalAccessStatus

# Audit-log surface: correlate administrative revocation or password-reset events
# with later resource-provider 401 claims challenges.
Get-MgAuditLogDirectoryAudit -Top 20 |
  Select-Object ActivityDateTime, ActivityDisplayName, Result, InitiatedBy
```

Expected documented signals, not captured: sign-in logs expose sign-in event typing and Conditional Access status; directory audit logs contain administrator actions such as password reset and revocation of sign-in sessions; Microsoft documents the revocation flow in which Entra sends a revocation event to a resource provider, the resource provider denies the next stale-token request, and the client receives a `401` plus claims challenge. [124]

> 🔵 **DOCUMENTED**: Microsoft Learn, *How to use Continuous Access Evaluation enabled APIs in your applications*; not captured on our lab VM.
> Reproduce: trigger a CAE event in a test tenant and inspect the HTTP response from a CAE-enabled resource API.

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer authorization_uri="https://login.windows.net/common/oauth2/authorize",
  error="insufficient_claims",
  claims="eyJhY2Nlc3NfdG9rZW4iOnsibmJmIjp7ImVzc2VudGlhbCI6dHJ1ZSwgInZhbHVlIjoiMTYwNDEwNjY1MSJ9fX0="
```

Expected documented meaning, not captured: the resource API rejected a token that may still be cryptographically unexpired; `error="insufficient_claims"` tells the client this is not an ordinary authentication failure; the `claims` value is passed to MSAL, which requests a new access token so Entra can re-evaluate current user, policy, risk, and location state. [1228]

> 🔵 **DOCUMENTED**: Microsoft Learn token lifetime behavior; not captured on our lab VM.
> Reproduce: compare token cache metadata for a CAE-capable client/API pair and a non-CAE-capable pair.

Expected documented lifetime behavior, not captured: CAE-aware sessions can receive long-lived access tokens up to 28 hours; non-CAE-capable clients keep the default one-hour access-token lifetime; client readiness is advertised with the `cp1` client capability, and applications that declare readiness must handle CAE claim challenges for CAE-enabled resource APIs. [124]

The proof is operational rather than theatrical. A Reasoner should be able to show four things in a tenant: the administrative or risk event that changed state, the sign-in or token-issuance shape that indicates CAE participation, the resource-provider `401` claims challenge, and the one-hour-versus-up-to-28-hour lifetime split. If any one of those surfaces is missing, the tenant has not proven the link end to end.

## Competing approaches and their relation to CAE

Five named methods occupy adjacent positions in the design space. Some compete; some compose. The map matters because deployments that confuse the two get wrong answers.

### CAE versus OpenID SSF and CAEP 1.0

Same architecture, different implementations. Microsoft CAE solves the Microsoft estate via a Microsoft-internal protocol; OpenID SSF and CAEP solve the cross-vendor SaaS long tail via a public standard atop RFC 8417 [1229][1243][1244]. The two are convergent rather than rivalrous: OpenID interop events show vendors building SSF transmitters and receivers around the same publish/subscribe model, while Microsoft continues to document its first-party CAE contract through Microsoft Learn rather than exposing the internal Entra-to-Microsoft-365 channel.

The Authenticate 2025 interop event in October 2025 was the first whose tested text was the Final-Specification version of SSF [1245]. Multi-vendor SSF and CAEP interoperability has been demonstrated at successive Gartner IAM Summit interop events as well. At the March 2024 London summit, SGNL's CAEP Hub interoperated as both transmitter and receiver with Cisco Duo, Okta, SailPoint, and Helisoft on the `session-revoked` CAEP event [1246]. Okta's own blog characterizes the March 2025 London summit as "a significant industry shift toward interconnected, real-time security" with "interoperable implementations from pioneers like Okta, Google, IBM, Omnissa, SailPoint, and Thales" [1247].

> **Aside.** Tim Cappalli, who joined Okta after his time at Microsoft, co-chairs the OpenID Shared Signals Working Group alongside Atul Tulshibagwale (SGNL, formerly Google) [1248][1249]. The cross-vendor co-chair arrangement is part of why the Final Specifications passed without significant vendor pushback: the people doing the standardization had visibility into both Microsoft's and Google's prior implementations.

### CAE versus RFC 7662 introspection

Parallel paths, not competitors. RFC 7662 introspection [1235] continues to be the right answer for opaque-token systems and on-premises IdPs where the AS-to-RP per-request round-trip is acceptable. CAE wins at hyperscale public-cloud volumes specifically because it inverts the per-request dependency: state pushes to the RP once and lives in cache; the data plane does not consult the AS on every request. If you are building a B2B integration with a small RP count and a few hundred requests per second, RFC 7662 is fine. If you are building Exchange Online, it is not.

### CAE versus DPoP and mTLS-bound tokens

Complementary, not competitive. The threat model for CAE is *stale authorization*: the authorization decision at sign-in is no longer accurate, because the user has been disabled, their password has been reset, their risk score has changed, or their network location has shifted. The threat model for proof-of-possession is *stolen tokens*: an attacker holding a bearer token that was legitimately issued to a different party.

RFC 9449, *OAuth 2.0 Demonstrating Proof of Possession (DPoP)*, published September 2023 by Daniel Fett and collaborators [848], binds an access token to a client-held key pair: a DPoP-bound token can only be replayed by an attacker who also stole the private key. RFC 8705, *OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Access Tokens*, published February 2020 by Brian Campbell and collaborators [1250], does the same thing using mTLS certificates. Both are sender-constrained-token mechanisms; both close the bearer-token-replay attack surface. They are the cloud-token expression of the same proof-of-possession principle the front-door chapters already rely on: the device-bound key behind Windows Hello (Chapter 20) and the origin-bound credential behind WebAuthn and Passkeys (Chapter 21): bind the credential to a key the holder cannot exfiltrate, and possession alone stops being enough.

The consequence follows directly: combine CAE with DPoP or mTLS-binding where the application threat model includes both stale authorization and bearer-token replay. CAE supplies the revocation channel; sender-constraint supplies proof that the presenter still holds the bound key. On Microsoft Entra ID specifically, standard RFC 9449 DPoP is not yet available for Microsoft 365 workloads (Exchange Online, SharePoint, Graph); the shipping sender-constraint there is **Token Protection**, a Conditional Access session control that binds the issued token to a TPM-backed device key.

### CAE versus BeyondCorp-style identity-aware proxies

Different architectural layer. Identity-aware proxies (Google IAP, Cloudflare Access, AWS Verified Access) sit *in front of* the resource server and enforce policy at the proxy. They have full visibility into per-request state and can do instant revocation by terminating the connection at the proxy when policy changes. This is correct for proxy-fronted workloads but does not scale to the long tail of API surfaces that cannot or will not sit behind a proxy. CAE pushes the enforcement into the resource server itself, which is what lets it work for native cloud APIs and federated SaaS where the proxy model would not.

### A note on PRT theft

CAE does not address attacks at the Primary Refresh Token (PRT) layer: the subject of Pass-the-Hash to Pass-the-PRT (Chapter 19). The PRT is a long-lived refresh credential Windows uses to mint access tokens silently from a logged-in session. A stolen PRT can mint CAE-aware access tokens that are, from Entra's perspective, legitimately issued. The attacker holds a credential the IdP still recognizes. CAE will only catch this if the user is revoked, the password is reset, or one of the other critical events fires *after* the PRT theft. The Pass-the-PRT attack class therefore bypasses CAE entirely; Chapter 19 makes the boundary precise by labeling CAE a *dwell-time* control over PRT theft (it shortens the window between extraction and detection-driven revocation) rather than an *extraction* control that could prevent the theft in the first place.

### Mapping the design space

The table is the cleanest way to see who competes with whom and who composes with whom.

![Figure: The CAE design space on two axes: what a mechanism solves (stale authorization versus token possession) and how it learns of change (per-request poll versus push and cached state). CAE and OpenID SSF/CAEP cluster as push-based, stale-authorization controls; DPoP and mTLS-bound tokens sit on the possession axis and compose with CAE; RFC 7662 introspection is the per-request-poll alternative; short access-token lifetime is the degenerate fallback; and an identity-aware proxy enforces at a different architectural layer.](diagrams/14-cae-design-space.svg)

| Approach | Solves | Composes with CAE | Competes with CAE |
|---|---|---|---|
| OpenID SSF/CAEP 1.0 | Cross-vendor revocation | Yes (CAE is a Microsoft implementation of the same pattern) | No |
| RFC 7662 introspection | Opaque-token revocation at modest scale | Parallel path | At hyperscale only |
| DPoP (RFC 9449) | Sender-constrained tokens | Yes (compose for full coverage) | No |
| mTLS-bound tokens (RFC 8705) | Sender-constrained tokens | Yes (compose for full coverage) | No |
| Identity-aware proxy | Per-request policy at the proxy edge | Composes for proxy-fronted workloads | Different layer |
| Short access-token lifetime | Reduces revocation window mechanically | Falls back when CAE not available | Yes, and loses on the trade |

The reader who came to this chapter expecting a binary contest. "which one wins?". Has the wrong frame. The actual answer is that CAE is one move in a layered defense, and most production deployments will end up composing it with DPoP or mTLS for token binding, falling back to short lifetimes for non-CAE clients, and continuing to use introspection for opaque-token internal APIs.

That handles deployment. Every architecture also has a floor, and CAE's is sharp enough to enumerate.

## Where this link breaks: What CAE cannot do

Every architecture has a floor. This is where the limits show up: not as vendor laziness, but as physics, scale, and trust topology.

### Limit 1: cannot revoke a token already in flight

Once a request has been accepted and is being served by the resource provider, CAE cannot reach into the RP's execution thread and abort it. The revocation applies to the *next* request. A long-running operation (a bulk Outlook export, a large SharePoint upload) that began at 10:23:00 may complete normally even if the user is disabled at 10:23:01. The revocation takes effect the next time the client presents the token [124]. For most use cases the in-flight window is sub-second and the consequence is negligible; for long-running data egress, it matters.

### Limit 2: cannot beat the 15-minute critical-event SLA for most events

Microsoft's published SLA is "up to 15 minutes" for critical-event propagation [124]. Only supported IP-location enforcement is instant. The 15-minute number is not a fundamental limit; it is best treated as Microsoft's published operating point for hyperscale fan-out. Fanning out an event to every CAE-aware RP for every potentially affected subject across Microsoft 365's global infrastructure plausibly produces that budget. Smaller-scale deployments are documented by vendors as achieving much better numbers: TigerIdentity self-reports sub-second end-to-end revocation in a tuned CAEP receiver configuration [1251]. The architecture appears to allow sub-second operation in narrower deployments; Microsoft's particular deployment documents the 15-minute bound without publicly proving the full cost model behind it.

The strict physical floor sits below even the tuned implementations. An RP cannot enforce a revocation it has not yet learned about. The one-way network latency $L$ between IdP and RP sets the absolute minimum: with a transcontinental L ≈ 70 ms, no push protocol can revoke faster than that, and pull protocols are necessarily worse. In practice, queuing, scheduling, and event-fanout dominate $L$ at scale, but the floor remains.

> **Key idea.** The 15-minute SLA is not a fundamental limit; it is Microsoft's published operating point at hyperscale. Sub-second is feasible at smaller fan-outs, but the strict physical floor is the network latency between IdP and RP; no cooperative protocol can do better than that.

### Limit 3: cannot cover non-CAE-aware clients or resource providers

CAE is a cooperative protocol. Both the client (via the `xms_cc=cp1` capability declaration) and the resource provider (via implementing the participation contract) must be CAE-aware [1228]. A non-CAE client receives a default 1-hour token and never sees a claims challenge; it relies on standard expiry. A non-CAE RP silently falls back to standard token expiry as well; the IdP's events have no consumer. The CAE-aware portion of the estate enjoys the new contract; the rest carries the old security debt unchanged.

This is why audit posture matters. A tenant administrator who wants to argue that revocation latency for their workforce is "under 15 minutes" must be able to demonstrate that the client and RP combinations the workforce actually uses are CAE-aware. Microsoft's compatibility tables [124] document several Office-web-app and OneDrive-Win32-versus-SharePoint combinations as *Not Supported* or *Partially supported*; those gaps are part of the tenant's effective revocation profile, not someone else's problem.

### Limit 4: cannot help if the resource provider itself is compromised

Revocation state lives at the RP. A compromised RP can simply ignore revocation events: keep serving requests against tokens Entra has signaled are invalid; misreport its own subscription state; drop events on the floor. CAE is a *cooperative* protocol between trustworthy parties. It is not a defense against an RP that has been pwned. The OpenID SSF specification addresses this implicitly by defining receiver requirements (verification events, stream-control endpoints, signature verification on SETs), but no receiver requirement can compel a compromised receiver to obey the protocol.

The threat model implication: an attacker who has compromised an RP does not need to bypass CAE. They simply do not implement it from the inside, and the protocol's design has no remedy. RP integrity is a prerequisite, not a guarantee.

### Limit 5: cannot revoke a stolen PRT before it mints a new access token

As noted in the comparison with adjacent controls, the Primary Refresh Token (Chapter 19) sits outside CAE's scope. A stolen PRT mints new CAE-aware access tokens that Entra treats as legitimately issued, because from Entra's perspective they *are* legitimately issued. The attacker is presenting a credential the IdP recognizes. CAE catches PRT theft only when one of the five critical events fires after the theft. If the attacker exfiltrates a PRT, refreshes a token, and immediately uses it, the access token is valid and the revocation channel has nothing to revoke.

> **Aside.** The SharePoint Online user-risk-event caveat is a useful concrete example of the per-feature limit pattern. Even within the four CAE-consuming RPs, feature support is not uniform; you cannot reason about CAE as a single boolean property at the workload level. Every event you care about must be checked against the specific RP that will enforce it [124].

### The bounded design space

Put together, the five limits draw the perimeter of what CAE can do. It cannot stop in-flight requests. It cannot beat network latency at the strict floor or 15 minutes at Microsoft's chosen operating point. It cannot help non-participating clients or RPs. It cannot fix a compromised RP. It cannot revoke PRT-layer credentials before they mint new tokens. The honest summary is that the design space is *bounded*: the reader who internalizes the five limits has a calibrated sense of what is fundamentally possible, and can stop expecting CAE to be a single fix for revocation in all situations.

The limits also map the open frontier. If those are the structural constraints, what are the OpenID Foundation and the SaaS long tail working on in 2026?

## Open Problems (2026)

Final Specifications are necessary but not sufficient. CAEP 1.0, SSF 1.0, and RISC 1.0 were approved on September 2, 2025 [1229]. The question for 2026 is what *adoption* and *extension* look like. Five live problems.

### Third-party SaaS receiver-adoption depth

The Final Specifications give every SaaS vendor a clean target to build against. The question is whether they will. As of the current Google Workspace SSF API page retrieved for this June 2026 review, Google Workspace describes its SSF receiver as Closed Beta and says the initial release supports the `session-revoked` CAEP event [1252]. That is one event out of CAEP 1.0's eight. For the SaaS long tail (Workday, ServiceNow, GitHub Enterprise, Atlassian, Salesforce) public receiver coverage is still sparse enough that a tenant cannot assume cross-SaaS revocation simply because SSF 1.0 is final.

For the "fired employee with N SaaS apps" scenario to be fully solved, every SaaS app in the user's bundle has to be a CAEP receiver subscribed to events from the enterprise IdP. The architecture is in place; the integration work is per-vendor and per-customer. This is the largest single determinant of CAE's real-world value over the next several years.

> **Why third-party adoption is the 2026 story.** The Microsoft 365 estate enjoys near-complete CAE coverage because Microsoft built both the IdP and the resource providers. The cross-vendor story is fundamentally a coordination problem: every receiver has to be built, deployed, and configured to subscribe to events from every transmitter the enterprise uses. SSF 1.0 makes the integration tractable; it does not make the work disappear. Watch receiver coverage in 2026-2028 as the leading indicator of CAE's industry-wide impact.

### CAE for non-human and agent identities

CAEP subject identifiers assume user-shaped or device-shaped subjects [1244]. Workload identities, service principals, and emerging AI-agent identities sit outside the model as currently profiled. An agent acting on behalf of a user, with its own identity and its own session, is not yet covered by a Final-Specification profile. Microsoft Entra *Conditional Access for Agent Identities* is a documented Microsoft Learn surface as of 2026 [1253], but Microsoft's page describes token issuance and Conditional Access evaluation for agents, not a CAEP profile for non-human subjects. As of mid-2026, the cross-vendor standardization gap is open.

### Cross-IdP federation of SSF streams

When tenant A federates to tenant B, the event-flow path crosses a trust boundary the current Final Specifications do not explicitly profile. If a user is disabled in tenant A's IdP, how does the revocation event reach the resource providers downstream in tenant B? The pieces (transmitter, receiver, SET envelope, signed events) are all in place; what is missing is the canonical profile for cross-IdP federation of SSF streams. Treat this as an adoption and profiling frontier, not as something the September 2025 Final Specifications already settle.

### Bidirectional signal sharing

Today's CAE and CAEP deployments are largely IdP-as-transmitter, RP-as-receiver. The full vision is bidirectional: an RP that detects anomalous behavior (unusual access patterns, suspected automation, post-authentication risk signals) should be able to transmit those signals back to the IdP, which can then incorporate them into the next authorization decision. SGNL and similar vendors are building toward this model. The Final Specifications support bidirectional flow at the protocol level; the policy and operational pieces (who trusts whom, what events flow which way, how an IdP weighs signals from an RP) are still being worked out.

### Reason-code convergence between CAEP and RISC

CAEP 1.0 and RISC 1.0 cover overlapping ground around credential mutation. CAEP defines a `credential-change` event; RISC defines `account-credential-change-required` [1244][1249]. Implementers must choose, and vendor extensions proliferate where the spec leaves room. Reason-code convergence between the two profiles is incomplete; some receivers will subscribe to both streams to be safe, others will pick one and hope upstream transmitters agree. Over time the WG will likely consolidate; for 2026, the practical guidance is to support both event vocabularies in receiver code.

> **The Authenticate 2025 interop event.** The first interoperability event whose tested text was the Final-Specification version of SSF took place at Authenticate 2025 in Carlsbad, California, October 13-15, 2025, hosted by the FIDO Alliance and coordinated by the OpenID Foundation Shared Signals Working Group [1245]. The event required that all participants with an SSF Transmitter pass the OpenID Foundation's free, open-source conformance tests. This was the fourth in a series of Gartner-IAM and Authenticate interops since March 2024, and the first conducted after SSF 1.0 was approved Final on September 2, 2025. The list of vendor participants has grown at each event; cross-vendor receiver coverage is the metric to watch.

Given all this (the architecture, the limits, the open frontier) what should you actually do this week in your tenant and your code?

## Turning CAE on in your tenant and your code

Three audiences, three checklists. Each section is what an engineer in that role needs to confirm or change to make CAE work in their environment.

### For the tenant administrator

CAE is auto-enabled for new Microsoft Entra tenants in the current Microsoft Learn migration table [124]. Tenants that configured the older preview experience may need to verify enablement in **Conditional Access → Session controls → Customize continuous access evaluation**. The relevant signals to check:

1. **CAE enablement state.** Confirm that the tenant-wide CAE policy is set to *Enabled* rather than *Disabled* or *Strict location*.
2. **Per-policy disable flags.** Some legacy CA policies carry per-policy CAE overrides. Audit any that explicitly disable CAE; the right default is to honor it.
3. **Strict location enforcement migration.** Tenants with pre-GA "strict location enforcement" preview settings should verify that the policy has migrated to the current GA configuration model documented in Microsoft Learn [1242].
4. **Audit log baselines.** Sign-in logs surface `signInEventTypes` with CAE-related entries; refresh-token issuance events and revocation events appear in the Entra ID audit log. Build a baseline before changing policies so you can detect drift.

### For the MSAL client developer

The client side has three things to confirm and one thing to test:

1. **MSAL version.** Use a current MSAL release on your client platform: 4.x for MSAL.NET and MSAL.js; the appropriate current line for MSAL Python, MSAL Java, MSAL Android, and MSAL for iOS/macOS, per each SDK's own release stream. Microsoft Learn's *Use Continuous Access Evaluation enabled APIs* page enumerates the per-SDK guidance [1228]. Earlier major-version lines do not handle the claims challenge transparently.
2. **Capability declaration.** Configure the MSAL client/application to advertise CP1: `.WithClientCapabilities(new[] {"cp1"})` in MSAL.NET, `clientCapabilities: ["CP1"]` in MSAL.js, `client_capabilities=["cp1"]` in MSAL Python, `client_capabilities: "CP1"` in MSAL Android JSON, `clientApplicationCapabilities = ["CP1"]` in MSAL ObjC/iOS/macOS, or `WithClientCapabilities([]string{"cp1"})` in MSAL Go [1228]. This is the signal to Entra that the client can handle a CAE-aware token and the claims challenge that comes with it.
3. **Claims-challenge handling.** MSAL helpers do this transparently in current SDK versions, but custom HTTP pipelines that bypass MSAL must implement the `WWW-Authenticate: Bearer error="insufficient_claims"` response handler manually. Decode the `claims` parameter (base64url), pass it to `AcquireTokenInteractive` or the equivalent, retry the original request with the new token.
4. **End-to-end test.** Trigger an admin password reset against a test user in a non-production tenant and verify that the next API call from a signed-in MSAL session surfaces the claims challenge and recovers cleanly. This is the single most useful confidence test; it exercises every layer of the protocol in one round trip.

### For the custom-API author

This is the hardest path. To make a custom protected API a CAE-aware resource provider today, the first-party Microsoft pathway is not publicly available: the CAE participation contract for the M365 productivity workloads is internal to Microsoft. The community-canonical implementation pattern is Damien Bowden's `damienbod/AspNetCoreMeIDCAE` reference repository on GitHub [1254], with an accompanying blog post walkthrough [1255]. That pattern demonstrates CP1-aware client/API behavior and claims-challenge handling; it does not give the API access to Microsoft's internal Entra-to-Microsoft-365 critical-event stream. The repository (initial version April 3, 2022; updated through .NET 10 in late 2025) demonstrates:

- The CP1 capability declaration on the participating client/API application configuration.
- The Microsoft.Identity.Web claims-challenge handling on the API side.
- The Razor Page client flow that catches a `401` with the challenge header and re-acquires the token.

For a fully standards-track pathway, the same custom API can be built as an OpenID SSF receiver consuming CAEP events from any SSF-compliant transmitter, using the RFC 8417 SET envelope over the RFC 8935 push transport [1240][1241]. Production-grade SSF receiver code is now available in commercial CAEP Hub products (SGNL, TigerIdentity) and a growing set of open-source libraries.

> **Licensing and tenant prerequisites.** CAE itself does not require add-on licensing for the basic critical-event evaluation across Microsoft 365. It is part of the Entra ID baseline for new tenants. The Microsoft Entra ID Protection feed that drives *high user risk detected* events, however, requires Microsoft Entra ID P2 (or an equivalent SKU that includes Identity Protection). Confirm current licensing terms in the Microsoft licensing documentation before making procurement decisions; the lower SKUs cover four of the five critical events but not the risk-based one [124].

### Observability

Sign-in logs and audit logs are where CAE behavior shows up. Look for:

- **Sign-in logs**: filter by `signInEventTypes` containing CAE-related entries. CAE-aware sign-ins have a different telemetry shape than non-CAE sign-ins.
- **Token-issuance events**: refresh-token issuance against CAE-aware app registrations should show the extended lifetime.
- **Audit log revocation entries**: administrator revocation actions and Identity-Protection-driven revocations appear here; cross-correlate with the resource-provider-side telemetry to validate end-to-end propagation.

> **How to confirm a tenant is CAE-active end to end.** Use Microsoft Graph PowerShell to enumerate the tenant's CAE configuration and then trigger a synthetic test: 1) read `Get-MgIdentityConditionalAccessPolicy` to verify the relevant CA policies have CAE enabled in their `SessionControls.ContinuousAccessEvaluation` block; 2) create a test user, sign them in via Outlook on the Web; 3) reset their password via `Update-MgUser`; 4) observe in the audit log that the password reset propagates to a CAE event, and verify in Outlook on the Web that the next refresh surfaces a re-authentication prompt within the 15-minute SLA. This is the simplest end-to-end confidence test that does not require modifying any production resource.

### Defaults are good

The most common engineering recommendation here is to leave the defaults alone: CAE on, default tenant settings, current MSAL clients, and CP1 advertised in every new client/application configuration that can actually handle claims challenges. The configuration surface area is small precisely because the design is right: there are not many knobs to turn. The work is in confirming that the client and RP combinations your users actually exercise are CAE-aware, and in monitoring the audit logs to catch drift.

That is what to do. The last section is what to remember: the misconceptions every team carries into a CAE conversation, and the answers that close them.

## Coda: The bargain

The OAuth 2.0 designers in 2012 took a deliberate trade: short-lived self-contained tokens were the price they paid to escape the WAM bottleneck. The trade was correct for the web they were designing for. It became wrong the moment enterprises ran compliance-bound SaaS at scale on top of those tokens. Three obvious patches were tried (the `/revoke` endpoint, the `/introspect` endpoint, the short-lifetime experiment) and each failed for a distinct reason: the wrong party initiates revocation; the AS becomes a per-request critical path; expiry as a blunt instrument creates load and reliability problems while still leaving a window.

What replaced them was an architecture that took two facts seriously. First, revocation has to be push from the IdP to the RP: not pull from RP to AS, not client-initiated POST to `/revoke`. Second, expiry and revocation can be separated: once the channel handles revocation, expiry can be measured in days rather than minutes. The 15-minute critical-event SLA and the up-to-28-hour token lifetime are two halves of the same bargain. Microsoft Entra ships them together because they only work together; the OpenID Foundation has standardized the same pattern across vendors because the long tail of SaaS faces the same problem.

The architecture is settled; the adoption is in progress. The CAEP, SSF, and RISC Final Specifications give every SaaS vendor a tractable target. The Microsoft 365 estate is already covered. Cross-vendor receiver coverage is the metric that will decide how much of the 2026 enterprise identity surface actually inherits the bargain, and that, more than any further protocol work, is the story to watch over the next several years.

> **Bequeaths.** Continuous Access Evaluation hands the next link one guarantee, and it is narrower than it first sounds: a token that was *legitimately issued* by Entra and later invalidated mid-session stops being honored by a cooperating Microsoft 365 resource provider within minutes, not at the hour-or-more expiry boundary. That is the floor the finale, When the Chain Snaps: Storm-0558 (Chapter 29), stands on when it asks the one question CAE cannot answer: *what if the token was never Entra's to revoke?* A forged token, signed by a key outside the identity provider's control, fires no critical event, because the IdP holds no record that the session exists; the revocation channel has nothing to revoke. CAE also does not stop token *theft*: for that the chain composes sender-constrained tokens, the proof-of-possession idea Windows Hello (Chapter 20) and WebAuthn and Passkeys (Chapter 21) already build into the front door, and it cannot reach the Primary Refresh Token that mints fresh tokens beneath it, which remains Pass-the-Hash to Pass-the-PRT (Chapter 19)'s problem. The parallel cloud link, Confidential VMs (Chapter 28), secures a different boundary entirely: the *workload's* memory against its own host, not the *session's* tokens against a stale decision. The chain has learned to revoke a true token quickly; it has not yet learned to disbelieve a false one.
