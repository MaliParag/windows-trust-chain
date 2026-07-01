# The SeImpersonate Primitive

::: trust-ledger

- **Inherits:** the access-token and privilege model (Chapter 22, Windows Access Control); the integrity labels that decide who may write upward (Chapter 23, The Integrity-Level Stack).
- **Promise:** a hardened, lower-privileged service identity (LOCAL SERVICE / NETWORK SERVICE) can impersonate a client to serve it, without thereby becoming more privileged than the service itself.
- **TCB:** the kernel's token and impersonation-level enforcement, and the `SeImpersonatePrivilege` check that gates the high-value impersonation and token-substitution APIs.
- **Adversary → Break:** a compromised service holding `SeImpersonatePrivilege` coerces a SYSTEM caller over RPC/COM/named pipes and impersonates the returned token. The Promise ends where "impersonate the client" meets "the client we coerced is SYSTEM."
- **Residual:** the privilege cannot be removed without breaking the service model, so it is owned here as documented policy; behavioral detection of the coercion is the interlude's job (Chapter 25, ETW).
- **Bequeaths:** the lesson that a service account is not a security boundary against its own host, which the cloud chapters spend when they stop trusting the box at all. Does NOT provide protection once an attacker already holds the privilege.
- **Proof:** 🔵 documented (`whoami /priv` shape; Microsoft default-assignment pages).
:::

> **The Reasoner's question.** Why does a privilege introduced as a service-hardening mitigation become the durable primitive behind nearly every Potato-family service-to-SYSTEM escalation?

---

> **Foundations. What you need before this chapter.**
>
> - **Access token.** The kernel object that carries a process or thread's user SID, group SIDs, privileges, and integrity level. Primary tokens attach to processes; impersonation tokens attach to threads and additionally carry an impersonation level.
> - **Privilege.** A named user right such as `SeImpersonatePrivilege` or `SeAssignPrimaryTokenPrivilege`. The privilege can be present but disabled, or present and enabled. The enabled bit matters because Windows checks it during sensitive token operations.
> - **Impersonation.** The service pattern in which a server temporarily acts as a connected client so access checks happen under the client's identity rather than the service's identity.
> - **LOCAL SERVICE / NETWORK SERVICE.** Lower-privileged built-in service identities introduced so network-exposed services did not all need to run as `NT AUTHORITY\SYSTEM`. Both receive `SeImpersonatePrivilege` by default.
> - **Potato family.** The named exploit lineage (HotPotato, RottenPotato, JuicyPotato, PrintSpoofer, GodPotato, LocalPotato, SilverPotato, FakePotato) that repeatedly finds new token sources while relying on the same underlying impersonation gate.
> - **Gap analysis, not a how-to.** The discussion below explains the mechanism and the compatibility reasons Microsoft cannot simply remove it. It intentionally frames Potato-chain material as boundary analysis rather than an operational recipe.

---

## What this link is responsible for

This link in the Windows trust chain is responsible for the boundary between a hardened service account and the more privileged identity that service is allowed to serve. Windows needs servers to impersonate clients: IIS needs to evaluate a user's file access, SQL Server needs to enforce Windows-authenticated login semantics, Exchange needs to perform mailbox operations for the connected user, and named-pipe or RPC servers need per-client authorization. The same mechanism that makes those legitimate behaviors work is the mechanism a compromised service process can abuse after it receives a more privileged token.

The chapter's thesis is therefore narrower and stronger than "Potato attacks exist." The thesis is that `SeImpersonatePrivilege` is not an accidental footgun. It is the compatibility valve Microsoft installed when it moved services away from universal `SYSTEM` execution. Once that valve exists, mitigations that preserve legacy service impersonation tend to narrow the current token source rather than remove the primitive. Removing the primitive wholesale would break the service model that justified the privilege in the first place.

## Documented reproducibility, not a captured transcript

> 🔵 **DOCUMENTED**: reproducible service-account privilege inventory shape, not captured lab output. This chapter contains no hash-stamped Windows VM transcript and no unpublished capture. The section below gives commands a reader can run and the expected *shape* of their output; the claim itself is anchored in the Microsoft default-assignment pages for `SeImpersonatePrivilege`, LOCAL SERVICE, and NETWORK SERVICE [1033], [1034], [1035].

A reader-side reproduction has two observations, not one. First, identify the subject token. Run `whoami /user` from the shell whose token you are evaluating. In an IIS worker, SQL Server job step, Exchange worker, custom Windows service, or scheduled service process, the point is to verify that the process is not already `NT AUTHORITY\SYSTEM`; it should be a service identity such as `NT AUTHORITY\NETWORK SERVICE`, `NT AUTHORITY\LOCAL SERVICE`, `NT SERVICE\<name>`, or an application-pool virtual account derived from the service logon model. If this first probe returns `SYSTEM`, the experiment is malformed for this chapter's purpose: it proves only that the shell is already high-privileged, not that a hardened service identity carries the impersonation gate.

Second, print the token's privilege set with `whoami /priv`. The load-bearing row has this expected shape:

```text
Privilege Name                Description                                State
============================= ========================================== =======
SeImpersonatePrivilege        Impersonate a client after authentication  Enabled
```

Interpret the output field by field. The name binds the row to the privilege constant `SE_IMPERSONATE_NAME` [1036]. The description binds it to the policy right Microsoft names "Impersonate a client after authentication" [1033]. The state binds it to the kernel check: enabled, not merely present. A disabled privilege can be listed in a token but ignored until the process successfully enables it with `AdjustTokenPrivileges`. An enabled privilege is already in the effective privilege mask the security subsystem consults when APIs ask whether the caller may impersonate or create a process under a supplied token. The surrounding rows vary by account, product, service configuration, and domain policy; that variation is expected and is why the proof focuses on the one row's three fields.

The sanity check is to compare the row against the account documentation rather than against folklore. Microsoft lists `SE_IMPERSONATE_NAME` in the default LOCAL SERVICE privilege set with the `(enabled)` marker [1034]. It lists the same marker for NETWORK SERVICE [1035]. The dedicated policy page says the default assignments include Administrators, LOCAL SERVICE, NETWORK SERVICE, and Service [1033]. The proof therefore triangulates from three independent views of the same state: local token output, account-default documentation, and policy-default documentation. If all three agree, the row is not an exploit artifact. It is a platform invariant for the service model.

A negative result is still useful, but it has to be read carefully. If the row is absent, one of four things is usually true: you are not actually inside a service-account token; local or domain policy has intentionally removed the right; the service is running under a custom account whose required-privileges list has been narrowed; or the shell is constrained by a container, job, sandbox, or product wrapper that does not expose the normal service token. If the row is present but disabled, the host has diverged from the default LOCAL SERVICE / NETWORK SERVICE state and the process would need a successful privilege-enablement path before using APIs that check the enabled bit. If `whoami /priv` cannot be run, use policy inventory instead: `secedit /export /cfg secpol.cfg` shows which SIDs the local policy grants `SeImpersonatePrivilege`, and Sysinternals AccessChk can enumerate effective holders [609]. Those alternatives prove assignment policy; `whoami /priv` proves the effective token in the specific process.

What this reproducibility check does *not* show is a complete Potato exploit. That omission is intentional. The chapter is proving the architectural precondition: a non-SYSTEM service process can start life holding an enabled right that allows token substitution once a suitable token source exists. The Potato lineage supplies the historical record for the token-source half. The documented row supplies the reason every generation can end the same way.

> **Chapter thesis.** On default or common service-account tokens: IIS application pools, SQL or Exchange workers, and LOCAL SERVICE / NETWORK SERVICE-derived services that have not been narrowed by policy, required-privileges configuration, custom accounts, containers, or product wrappers: one enabled privilege, `SeImpersonatePrivilege`, is often sufficient, given a usable privileged token-source primitive and process-creation path, to become `NT AUTHORITY\SYSTEM`. The privilege was introduced in Windows Server 2003 as a *mitigation*, so that lower-privileged service accounts could keep impersonating their RPC clients after Microsoft moved services off `SYSTEM`. Eighteen years of named-exploit lineage (Token Kidnapping in 2008, HotPotato in 2016, then RottenPotato, JuicyPotato, PrintSpoofer, GodPotato, LocalPotato, and SilverPotato) all ride on the same system shape: an enabled impersonation privilege, a privileged authentication/coercion source, impersonation and token-conversion APIs, and Microsoft's public servicing criteria for what counts as a security boundary. This chapter explains why the closure paths Microsoft has shipped narrow token sources without removing the service-impersonation primitive.

## The One Line in `whoami /priv`

On default LOCAL SERVICE / NETWORK SERVICE-derived service tokens, the Microsoft account documentation and the reader-side `whoami /priv` check in the previous section converge on one expected row:

```text
SeImpersonatePrivilege  Impersonate a client after authentication  Enabled
```

That single line can be sufficient, given a usable privileged token source, a usable impersonation level, and a process-creation path, to cross from a service identity to `NT AUTHORITY\SYSTEM`. Microsoft has known this on the record since April 2009 [1037]. The privilege has not moved.

> **Definition, SeImpersonatePrivilege.**
> A Windows user right that lets a process call high-value token-substitution APIs on a token it has received from another principal. The right is enumerated as the constant `SE_IMPERSONATE_NAME` [1036]. Microsoft assigns it by default to `LOCAL SERVICE`, `NETWORK SERVICE`, the local Administrators group, and the SERVICE well-known SID [1033]; concrete service tokens can still be narrowed by local or domain policy, `RequiredPrivileges`, custom identities, containers, or product-specific wrappers.

> **Definition: LOCAL SERVICE and NETWORK SERVICE.**
> Two well-known Windows accounts introduced in Windows Server 2003 / XP SP2 as a hardening alternative to running services under `NT AUTHORITY\SYSTEM`. The Microsoft Learn account documentation lists each account's default privilege set; in both cases `SE_IMPERSONATE_NAME` appears with the marker `(enabled)` [1034], [1035].

The Microsoft Learn pages list this assignment as a default. "Enabled" is a token-state distinction with operational weight. Most privileges in a service-account token are *present but disabled*: the process can call `AdjustTokenPrivileges` to turn them on, but until that happens the kernel treats the privilege as absent during access checks. `SeImpersonatePrivilege` on a NETWORK SERVICE token is shipped *enabled*. The process can call `CreateProcessWithTokenW` immediately, on first instruction.

> **The privilege is enabled, not just present.**
> There is a real semantic difference between a privilege that is present-but-disabled and a privilege that is enabled. The kernel checks the *enabled* bit during access decisions. A NETWORK SERVICE process does not need to elevate the privilege before using it; the token already has it in the active state. Services started by the Service Control Manager also receive the built-in Service group, which the default "Impersonate a client after authentication" assignment covers unless local or domain policy narrows it. This is why an already-compromised service worker with a suitable token source crosses the boundary without a separate privilege-enablement step.

Andrea Pierini, one of the most prolific researchers on this primitive, put the operational fact in ten words: "if you have SeAssignPrimaryToken or SeImpersonate privilege, you are SYSTEM" [699]. Clement Labro, quoting him, added the qualifier: "a deliberately provocative shortcut obviously, but it's not far from the truth." The aphorism gets repeated in every PrintSpoofer-era writeup for a reason.

Here is the chapter's load-bearing claim, stated up front and re-argued through every section that follows:

> Microsoft gave default NETWORK SERVICE-style service tokens a privilege that, in the wrong hands and with a usable token source, can be equivalent to SYSTEM. They knew. They have not removed it from the default service model, because doing so would break the impersonation contract that model depends on. Roughly eighteen years after Cerrudo first put that fact on the record (and ten years after HotPotato made it pushbutton), the default remains recognizable.

> **Note.**
> The figure "roughly eighteen years" anchors to Cesar Cerrudo's April 2008 disclosure at Hack In The Box Dubai [1038]. The privilege itself shipped earlier, in Server 2003 / XP SP2 (2003-2004), and the operational-pushbutton anchor is Stephen Breen's HotPotato (January 16, 2016) [1039]. Three different dates, three different anchors for "how long has this been true." The article uses the Cerrudo date because that is when the fact entered the offensive-research public record.

From here, this chapter traces the privilege from a 2003 backward-compatibility concession to a 2024 Troopers articulation by Pierini and Cocomazzi, and explains why the closure paths Microsoft has shipped narrow token sources without removing the service-impersonation primitive.

The privilege inventory can be read as a token-state table. The important row is:

```text
SeImpersonatePrivilege        Enabled   # the gate
```

If one line in `whoami /priv` can be sufficient to become SYSTEM once a privileged token source exists, why does Microsoft still ship that line in common service tokens: IIS application pools, SQL Server service steps, Exchange worker processes, and other LOCAL SERVICE / NETWORK SERVICE-derived workloads unless policy narrows them? The answer is not a mistake. It is a decision, and to understand it we need to go back to a Tymshare FORTRAN compiler in the late 1970s, around 1977 by Hardy's own "about eleven years ago" dating from his 1988 paper.

## Hardy's deputy and the 2003 service-hardening pivot

In the late 1970s, around 1977, a Tymshare engineer named Norm Hardy watched a FORTRAN compiler with "home files license" overwrite the system billing file `(SYSX)BILL` because some user had passed that path as the compiler's debug-output target. The compiler had two authorities, its own (to read system libraries) and the caller's (to write the caller's files), and no way to keep them separate when serving a request. The compiler was, in Hardy's later phrasing, *confused* about which authority to use [1040].

> **Definition, Confused Deputy.**
> A program that holds authority on behalf of two or more principals at once and has no architectural way to keep those authorities separate when acting on a request. Hardy's 1988 paper [1040] argues that any identity-and-ACL system in which a server holds more authority than its clients and acts on client requests has a confused-deputy attack surface by construction. The only complete defense, Hardy argues, is capability-based access control.

Hardy's argument generalizes: as long as authority flows ambiently with identity rather than being passed explicitly with each request, a server cannot reliably tell whose authority a given request should run under. This is not a bug class. It is a structural property of the access-matrix model Lampson formalized in 1971 [1041]. Windows is an instance of that model. A NETWORK SERVICE process holding `SeImpersonatePrivilege` is *Hardy's deputy*: it carries two authorities at once (its own modest service identity and whatever caller just connected to its named pipe), and Windows has no in-architecture way to keep them apart.

> **Aside. Why Windows is not a capability system.**
> Capability systems (EROS, Coyotos, seL4) bind authority to operations rather than to running identities. A capability is an unforgeable token that names both an object and the rights you have on it; you cannot exercise authority you were not handed. In a capability system, Hardy's compiler would have been handed a capability only for the file the caller actually wanted opened, and the bill-overwrite would have been mechanically prevented. Windows shipped the alternative design in 1993 (identity-and-ACL with kernel tokens carrying ambient authority) and the rest of this chapter is, in a precise sense, the story of what that design costs thirty-three years on. The Hardy Ceiling section returns to this thread.

### The kernel object Cutler's team shipped in 1993

Dave Cutler's NT 3.1 team chose the identity-and-ACL model and built a kernel object to carry it. The *access token* is what an NT thread or process holds; it enumerates the user SID, the group SIDs, and the privileges currently associated with the running code. Every access check the kernel performs reduces to "does this token, evaluated against this object's ACL, grant the requested rights?" The standard reference is *Windows Internals*, Part 1, chapter on security [625].

> **Definition, Access Token.**
> A kernel object the Windows security subsystem creates at logon (and clones on demand), carrying the user SID, group SIDs, privileges, and integrity level for a running thread or process. Access tokens are defined in full in the Windows Access Control chapter (Chapter 22); this chapter needs only the *primary*-versus-*impersonation* distinction developed below.

NT 3.1 also shipped two structural distinctions that the rest of this chapter depends on. First, *primary* versus *impersonation* tokens: a primary token is what a process is born with; an impersonation token is what a thread can wear temporarily to act on behalf of someone else. Second, the four *impersonation levels* (Anonymous, Identification, Impersonation, Delegation), each granting progressively more authority to act under the borrowed identity. Both distinctions exist because servers need to act on client requests under the client's authority, and both distinctions are the surface every Potato variant operates on.

> **Note.**
> The Tymshare anecdote that Hardy uses in the 1988 paper (the FORTRAN compiler that overwrote `(SYSX)BILL`) is worth recounting in full because it is structurally identical to the Windows scenario. A user invoked the compiler with the billing information file as the debug-output target. The compiler had write access to system files (it was a "home files license" service). The compiler dutifully opened the user-supplied path under its own authority and wrote debug output to it, destroying the bill. The compiler was not malicious; it had no way to ask the OS to scope its write to "only files the caller could write." Hardy's own dating in the paper is "about eleven years ago" from 1988, so the events sit in the late 1970s, not the early ones.

### Why the privilege exists: the 2003 service-hardening pivot

Through the 1990s, Windows services almost universally ran under `NT AUTHORITY\SYSTEM`. The convenience was operational: SYSTEM is the local-machine principal and holds every right the kernel knows about, so a service running as SYSTEM never needed an explicit privilege grant. The cost became visible in 2001-2003 as the first generation of service-borne worms hit production: Code Red and Nimda (2001) walked IIS; SQL Slammer and MSBlast (2003) walked SQL Server and the DCOM RPC endpoint [1042], [1043]. Every successful remote code execution against a service became a SYSTEM compromise of the host, because the service *was* SYSTEM.

Microsoft's response was a structural retreat. Two new well-known accounts shipped in Windows Server 2003 (and reached desktop with XP SP2 in 2004): `NT AUTHORITY\LOCAL SERVICE` (no network credentials) and `NT AUTHORITY\NETWORK SERVICE` (machine-account credentials when authenticating off-box). The two account documentation pages enumerate the default privileges the SCM assigns when a service is configured to run under either account [1034], [1035]. Most of the SYSTEM-only privileges (`SeTcbPrivilege`, `SeLoadDriverPrivilege`, `SeRestorePrivilege`) are absent from the enumerated default sets [1034], [1035]. The intent was clear: a worm-popped IIS worker should land as a low-privileged process, not as SYSTEM.

But the new accounts could not lose *every* SYSTEM authority. Pre-2003 services routinely impersonated their clients to make access checks against per-user resources: IIS reading a user's home directory under the user's identity, SQL Server enforcing per-login row security, the SMB server returning per-user file lists. That entire pattern depended on the service being able to call `ImpersonateNamedPipeClient` (or `RpcImpersonateClient`, or one of the LSA-side APIs) and then act under the caller's token. If LOCAL SERVICE and NETWORK SERVICE could not impersonate, the entire RPC server population would break.

So Microsoft introduced `SeImpersonatePrivilege` (a new named user right gating the impersonation APIs) and assigned it by default to the local Administrators group, LOCAL SERVICE, NETWORK SERVICE, and the SERVICE well-known group; because the SCM adds the SERVICE group SID to every service token, SCM-started services inherit the right through that assignment [1033]. The policy-setting page is explicit about the intent: "If this user right is required for this type of impersonation, an unauthorized user cannot cause a client to connect (for example, by remote procedure call (RPC) or named pipes) to a service that they have created to impersonate that client" [1033].

The privilege, in other words, was created *as a mitigation*. Its purpose was to keep impersonation working for legitimate service-account RPC servers while denying it to ordinary user processes. That decision (to gate impersonation on an explicit named right rather than to forbid impersonation outright) is the architectural pivot the rest of this chapter re-examines from every angle.

**Walkthrough: Hardy's deputy on Windows.** Start with a service-account process, not with malware. It has Authority 1: its own modest service identity, usually LOCAL SERVICE, NETWORK SERVICE, or a virtual service SID. That authority is intentionally smaller than SYSTEM because the 2003 pivot was supposed to make service compromise less catastrophic. Now add Authority 2: the authority of any authenticated client that connects to the service endpoint and permits impersonation. In the benign case, a user connects to a named-pipe or RPC service and the server thread temporarily wears that user's token so the file system, registry, or application authorization layer can ask, "may this user do this?" In the failure case, a privileged component authenticates to an endpoint the service-account process controls. The server thread calls the same impersonation mechanism, receives a SYSTEM-level impersonation token, duplicates it into a primary-token-shaped object, and asks the process-creation API to launch work under that borrowed identity. The confused deputy is not confused because the service is malicious. It is confused because the operating system gave one server process two authorities and made the distinction a runtime convention rather than a mechanically enforced capability boundary.

Microsoft did not introduce `SeImpersonatePrivilege` to enable an exploit. They introduced it as a backward-compatibility concession. So why did the privilege become the dominant lineage of service-to-SYSTEM elevation for nearly two decades? The answer starts with the API surface.

## The token API surface

There is no single "impersonate" API on Windows. There are substitution APIs that put a token on a thread or a new process, and there are coercion or authentication paths that supply the token in the first place. The Potato family lives at that intersection.

### Primary versus impersonation tokens

The kernel distinguishes `TOKEN_PRIMARY` from `TOKEN_IMPERSONATION`. A primary token is what a process is created with; an impersonation token can be attached only to a thread. The distinction matters operationally because only an impersonation token at level `SecurityImpersonation` or `SecurityDelegation` lets you take real action under the borrowed identity. An `Identification`-level token can be checked against ACLs but cannot be used to open kernel objects under the new identity, and an `Anonymous`-level token is useless for almost everything [625], [1044].

> **Definition: Primary Token vs Impersonation Token.**
> A *primary token* is created at logon and attached to a process for its lifetime; the kernel uses it for every access check the process makes by default. An *impersonation token* is attached to an individual thread by `SetThreadToken` (or by an impersonation API that calls it internally) and overrides the primary token for that thread only. The kernel reserves the right to demote impersonation tokens to `Identification` level in cross-machine RPC scenarios where delegation has not been explicitly negotiated.

> **Definition, Impersonation Level.**
> A four-value enum (`SecurityAnonymous`, `SecurityIdentification`, `SecurityImpersonation`, `SecurityDelegation`) carried on every impersonation token. It limits what the impersonating thread can do under the borrowed identity. `SecurityImpersonation` is the level a service can act under for local access checks; `SecurityDelegation` extends that to off-box authentication and is the level cross-host variants such as SilverPotato occasionally need.

The Potato lineage navigates these four levels with care. `Identification` is harmless because it cannot spawn a process under the borrowed identity; `Impersonation` is the level a service can act under for any local kernel object; `Delegation` is what cross-host variants such as SilverPotato sometimes need.

> **Note.**
> The `SecurityIdentification` versus `SecurityImpersonation` distinction is the gate that makes many naive coercion attempts fail. If the attacker controls only an RPC interface that performs an `ImpersonateClient` call without the right SQOS (Security Quality of Service) negotiation, the resulting token may land at `SecurityIdentification`: usable for `AccessCheck`, useless for `CreateProcessWithTokenW`. Each Potato variant must choose a coercion primitive that arrives at `SecurityImpersonation` or higher; `DuplicateTokenEx` can reshape an already-obtained token, but it cannot promote an identification-level token into a usable impersonation-level token.

### The substitution primitives

Four APIs move tokens around the system. None of them produces a token from nothing; all of them assume the caller already has a handle to one.

- `SetThreadToken`: attach an impersonation token to a thread [1045]. The thread now runs under the borrowed identity for every subsequent access check.
- `ImpersonateLoggedOnUser`: the thread-level convenience wrapper [1044]. Same effect as `SetThreadToken`, with simpler arguments.
- `DuplicateTokenEx`: create a new token from an existing one, with adjustable type (primary vs impersonation) and level (the four-value enum above) [1046]. The Potato lineage uses this to convert an impersonation token into a primary one before launching a process.
- `CreateProcessWithTokenW`: spawn a new process under an arbitrary primary token [1047]. The Microsoft Learn documentation is explicit about the gate: "The process that calls **CreateProcessWithTokenW** must have the `SE_IMPERSONATE_NAME` privilege."

That last sentence is the keystone. `SeImpersonatePrivilege` is not just "the right to impersonate." It is the right to convert an impersonated identity into a fresh process that owns the desktop, the registry, the file system, and every other kernel object the borrowed identity has authority over. Without the privilege, the attacker has at most a thread temporarily wearing SYSTEM's hat; with it, the borrowed identity can become a durable process context with SYSTEM authority.

### The coercion primitive

The substitution primitives are inert without a token to substitute. In classic local Potato chains, the named-pipe handoff API `ImpersonateNamedPipeClient`, shipped since Windows XP / Server 2003 [1048], is the usual way the controlled server endpoint turns a connected client's authentication into a thread token. Any process that owns a named pipe can call this API after a client connects; whether the result is useful depends on the caller's SQOS-negotiated impersonation level and on the privilege or same-identity/explicit-credential conditions Microsoft documents.

> **Definition, ImpersonateNamedPipeClient.**
> A Win32 API that copies the connected client's access token onto the calling thread, after which the thread acts under the client's identity until `RevertToSelf` is called. The API has shipped since Windows XP / Server 2003 [1048]. In named-pipe Potato variants it is the token-handoff surface; other variants use related RPC, COM, or LSA impersonation paths to arrive at the same token-substitution problem. Microsoft documents that higher impersonation levels require `SeImpersonatePrivilege`, an explicit-credential token created in the caller's logon session, or the same authenticated identity [1048], [1044].

For gap-analysis purposes, Forshaw's 2021 Project Zero retrospective lets us describe the shared chain at the level defenders need: a service-account process controls an endpoint; a privileged Windows component authenticates to that endpoint; the service process receives an impersonation token; and Windows token-substitution APIs can convert that borrowed identity into a durable process context [1049]. The mechanics matter because they reveal where the boundary fails, not because this chapter is a reproduction guide.

**Walkthrough: the shared Potato shape.** Every member of the family has the same abstract geometry, even when the concrete handoff is not literally a named-pipe API call. First, a service-account process creates or controls an endpoint. In the classic local form this is a named pipe, because named pipes carry authenticated client identity into `ImpersonateNamedPipeClient`. Second, some Windows component running in a more privileged context authenticates to that endpoint. The generations differ here: Cerrudo used leaked token handles, HotPotato used local NTLM reflection, Rotten and Juicy used DCOM activation and OXID resolution, PrintSpoofer used printer/RPC coercion, and GodPotato moved the interesting edge into RPCSS OXID handling. Third, the service process calls the impersonation API while the privileged client is connected, placing the client's impersonation token on the server thread. Fourth, the process turns that borrowed identity into a durable execution context by duplicating the token into primary form and using the process-creation API gated by `SeImpersonatePrivilege`. The named exploit changes when Microsoft patches step two. The privilege gate remains step four.

A non-operational pseudocode view makes the separation precise:

```text
endpoint = service_process.controls_authenticated_endpoint()
privileged_component.authenticates_to(endpoint)      # the token-source question
thread_token = impersonate_connected_client(endpoint)
primary = duplicate_impersonation_token(thread_token)
create_process_with_token(primary)                  # the SeImpersonatePrivilege gate
```

The model is useful because it shows what a patch actually patches. If a bulletin prevents one privileged component from authenticating to one class of endpoints, the second line changes. If Windows leaves the fourth line intact for service accounts, the family is not closed; it is waiting for another token source.

**Proof obligations for the shared shape.** To reason about a Potato claim without turning it into a copy-paste exploit recipe, ask for five independent facts. First, prove the starting subject: the process is a service-account process, not already SYSTEM. Second, prove the gate: the process token contains `SeImpersonatePrivilege` in the enabled state. Third, prove the source: some higher-privileged component authenticated to an endpoint the service process controlled. Fourth, prove the token quality: the resulting impersonation token is at `SecurityImpersonation` or `SecurityDelegation`, not merely `SecurityIdentification`. Fifth, prove the conversion: the borrowed identity was duplicated into primary-token form and handed to a process-creation API whose documented privilege check the caller satisfies. A report that skips any one of those facts is either describing a different bug class or has not yet shown service-account-to-SYSTEM.

Step three depends on step two. Impersonating the client depends on first receiving the privileged authentication, and that authentication, the question of where the token comes from, is the one every generation of Potato has answered differently, and that Microsoft has patched, one token source at a time, for nearly two decades.

In gap-analysis terms, the chain decomposes into four abstract operations: create an endpoint, receive a privileged authentication, impersonate the connected client, and convert the resulting token into a process context. Those steps are useful for reasoning about the boundary; they are not a remediation procedure and not a recommended reproduction path.

### The privilege next to it

`CreateProcessWithTokenW` is gated on `SeImpersonatePrivilege`. Its sibling `CreateProcessAsUser` is gated on a *different* pair of privileges: `SeAssignPrimaryTokenPrivilege` (constant name `SE_ASSIGNPRIMARYTOKEN_NAME`) when the supplied token is not assignable by the caller, plus `SeIncreaseQuotaPrivilege` (`SE_INCREASE_QUOTA_NAME`) in all cases. Both are enumerated separately in the privilege-constants table [1036]. On a NETWORK SERVICE or LOCAL SERVICE token, `SE_ASSIGNPRIMARYTOKEN_NAME` and `SE_INCREASE_QUOTA_NAME` are both *present but disabled* [1034], [1035]: `CreateProcessAsUser` depends on the caller possessing those rights and may enable them for the duration of the call if they are present [1050], whereas `SeImpersonatePrivilege` is shipped *enabled* and `CreateProcessWithTokenW` works on the first instruction. Pierini's aphorism quoted near the opening names both privileges because either one independently makes the same chain runnable, but on a vanilla NETWORK SERVICE token, only `SeImpersonatePrivilege` is enabled, and the rest of this chapter treats it as the privilege that matters in practice.

| API | Privilege required | Input | Output |
|---|---|---|---|
| `ImpersonateNamedPipeClient` | none for `SecurityIdentification` or `SecurityAnonymous`; for higher levels, either `SeImpersonatePrivilege`, or the token was created with explicit credentials via `LogonUser`/`LsaLogonUser` from within the caller's logon session, or the authenticated identity is the same as the caller (see [1048]) | connected pipe handle | impersonation token on thread |
| `ImpersonateLoggedOnUser` | allowed when the caller has `SeImpersonatePrivilege`, the token came from explicit credentials in the caller's logon session, or the authenticated identity is the caller; token must be `SecurityImpersonation` or higher [1044] | token handle | impersonation token on thread |
| `SetThreadToken` | token access/level dependent; not a token source | token handle | impersonation token on thread |
| `DuplicateTokenEx` | none | source token | new token, type/level adjustable |
| `CreateProcessWithTokenW` | **`SeImpersonatePrivilege`** | primary token + command line | new process |
| `CreateProcessAsUser` | **`SeIncreaseQuotaPrivilege`** and, when the token is not assignable, **`SeAssignPrimaryTokenPrivilege`** [1050] | primary token + command line | new process |

**Walkthrough: where the gate sits.** Picture the token surface as three slots. Slot one is the process primary token: the identity the process normally runs as. Slot two is the optional thread impersonation token: the identity a single thread can wear while serving a client. Slot three is the primary token supplied to a new process. `ImpersonateNamedPipeClient` moves a connected client's identity into slot two. `DuplicateTokenEx` can reshape that impersonation token into a primary token suitable for slot three. `CreateProcessWithTokenW` then asks the decisive policy question: does the caller hold `SeImpersonatePrivilege`? On a default NETWORK SERVICE token the answer is yes and the privilege is enabled [1035]. That is why the privilege, not the pipe name, is the architectural gate.

**Structured ladder: SeImpersonate to a full token context.** Read the surface as a ladder, not as one magic API call:

1. **Service primary token.** The process begins with a normal service-account primary token. The key inspectable fact is the enabled `SeImpersonatePrivilege` row, not the account's marketing name.
2. **Client impersonation token.** A connected client supplies an authenticated identity to a server thread. Benign services use this to perform the client's requested operation under the client's access rights.
3. **Impersonation level check.** The token must permit action, not just identification. `SecurityIdentification` proves identity but cannot be used as the operating authority for the interesting local actions; `SecurityImpersonation` or `SecurityDelegation` is the meaningful threshold.
4. **Token duplication.** `DuplicateTokenEx` reshapes the thread-bound impersonation token into a primary-token-shaped object. This is a type conversion of an already-obtained token, not the moment where SYSTEM authority is created.
5. **Process creation gate.** `CreateProcessWithTokenW` consumes the primary token and checks the caller's `SE_IMPERSONATE_NAME` privilege [1047]. If the caller's service token has the privilege enabled, the borrowed identity becomes a durable process context. If the privilege is missing or disabled, the ladder stops here even if the earlier impersonation succeeded.

This ladder preserves the diagram's pedagogy while keeping the chapter in defender/reasoner mode: each rung is a fact to verify, a telemetry point to monitor, or a mitigation point to evaluate.

> **The privilege is the gate. The pipe is the source.**
> The surface decomposes cleanly into two halves. `SeImpersonatePrivilege` is the kernel-side *gate* that decides whether a process can substitute a borrowed token into high-value impersonation or process-creation paths. `ImpersonateNamedPipeClient` is a classic user-mode *handoff* that provides the token after a client connects; other Potato variants find different privileged authentication sources. Removing either the gate or all usable sources would close the chain. Microsoft has instead narrowed sources while preserving service impersonation.

So how do you get a SYSTEM-context Windows process to authenticate to a pipe you control? Cesar Cerrudo asked that question in 2008, and his answer was just the first of five.

## Five generations of token sources, one constant privilege

Cesar Cerrudo had the privilege figured out in April 2008. So why did it take until January 2016 for HotPotato to make the chain pushbutton, until August 2018 for JuicyPotato to industrialize it, and until December 2022 for GodPotato to bypass the most aggressive DCOM hardening Microsoft has shipped? Because every generation answered the same question, *where do the tokens come from?*, differently, and Microsoft patched each token source one at a time.

![Figure: Five generations of SeImpersonate token-source attacks mutate from leaked handles to NTLM reflection, DCOM activation, non-DCOM coercion APIs, and RPCSS itself, but every generation still reaches the same constant gate: an enabled `SeImpersonatePrivilege` that turns a service-account compromise into SYSTEM.](diagrams/27-seimpersonate-five-generations.svg)

This section is *generation-level*. Variants appear here only as evidence for claims about the primitive, not as an exhaustive variant-by-variant chronology of every named Potato.

### Generation 1, direct token theft (2008-2010)

Cerrudo's HITB Dubai 2008 paper, *Token Kidnapping*, named the privilege and named the technique [1038]. The chain ran inside an MSSQL or IIS process and looked like this at a mechanism level: enumerate processes the service account could open; find a thread that was already impersonating a higher-privileged token, typically leaked by some service-startup path; duplicate that token; and create a new process under the borrowed identity. Two years later, at DEF CON 18, Cerrudo presented *Token Kidnapping's Revenge* with fresh examples and a community-canonical title for the technique [1051].

Microsoft's response was MS09-012 in April 2009 (community-known as the *Chimichurri* fix, after Cesar Cerrudo's PoC of the same name shipped by Argeniss alongside the disclosure [1052], [1053]). The MSRC blog post announcing the bulletin is unusually clear about what it closed and what it deliberately did not:

> **Quoted anchor.**
> An attacker can escalate their privileges on a system if they can control the SeImpersonatePrivilege token. An attacker would need to be executing code in the context of a Windows service to use this exploit.: MSRC blog, April 14, 2009 [1037]

The MSRC text continues: "the first update addresses service isolation, while the second addresses processes running as service accounts" [1037]. *Service isolation*, not the privilege itself. The bulletin closed the specific handle-leak surface Cerrudo had used. It did not revoke `SeImpersonatePrivilege` from NETWORK SERVICE, did not modify `CreateProcessWithTokenW`, did not modify `ImpersonateNamedPipeClient`. The MSRC acknowledged on the record that the privilege was sufficient for the escalation and elected to fix the *symptom* (the leak surface), not the *gate*.

This is the supersession pattern that every subsequent generation follows: Microsoft patches the current token source; the next generation finds a new one within months.

> **Note.**
> *Chimichurri* (sometimes `Chimichurri.exe`) is not a Microsoft codename. It is the name Cesar Cerrudo gave to the PoC exploit Argeniss released alongside the MS09-012 bulletin, hosted at the time at `argeniss.com/research/Chimichurri_CesarCerrudo.zip` and preserved in the Internet Archive [1052]. Microsoft's own naming for the bulletin is simply MS09-012 / KB959454. Offensive-research convention has used "Chimichurri" as shorthand for the Cerrudo PoC ever since: never for a Microsoft internal codename. Forshaw's January 2020 service-hardening retrospective references the same Cerrudo / Argeniss lineage [1053].

> **Note.**
> Cerrudo presented the 2008 paper under his Argeniss affiliation and the 2010 DEF CON talk under IOActive [1038], [1051]. The affiliation change occasionally trips up archival cross-referencing. The work is the same lineage.

### Generation 2, local NTLM cross-protocol reflection (2014-2016)

In December 2014, James Forshaw filed Project Zero Issue 222: a WebDAV-to-SMB local NTLM reflection that turned the Windows authentication redirector into a self-service token source. Stephen Breen's *HotPotato* (January 16, 2016) used a related local-NTLM-relay primitive to deliver the first end-to-end service-account-to-SYSTEM chain that did not depend on finding a leaked token handle [1039]. Breen credits the genealogy openly: "If this sounds vaguely familiar, it's because a similar technique was disclosed by the guys at Google Project Zero... In fact, some of our code was shamelessly borrowed from their PoC and expanded upon" [1039].

The conceptual leap is the one every subsequent generation depends on. Cerrudo's G1 had to *find* a high-privileged token leaked into the local process tree; Breen's G2 *makes the system hand you one* by coercing it to authenticate. The system itself becomes the token source. Forshaw articulated this generalization explicitly in the 2021 Project Zero retrospective on the entire lineage [1049].

Microsoft's response was MS16-075 (the SMB-side fix) and a handful of WPAD-hardening rollups. The chain became fragile and stopped being pushbutton, but, again, none of these changes touched `SeImpersonatePrivilege` or `ImpersonateNamedPipeClient`.

### Generation 3, local DCOM activation (2016-2018)

Within months of HotPotato, the community converged on a more reliable coercion primitive: a forged DCOM `OBJREF` marshalled with an attacker-chosen OXID resolver. The trick induces a SYSTEM-context COM server to authenticate to a named pipe the attacker controls. Forshaw had reported the underlying primitive at Project Zero in 2015 as Issue 325, fixed as CVE-2015-2370 [1054], but as his 2021 retrospective notes:

> "The technique to locally relay authentication for DCOM was something I originally reported back in 2015 (issue 325). This issue was fixed as CVE-2015-2370, however the underlying authentication relay using DCOM remained. This was repurposed and expanded upon by various others for local and remote privilege escalation in the RottenPotato series of exploits, the latest in that line being RemotePotato which is currently unpatched as of October 2021." [1049]

> **Definition, OXID Resolver.**
> The DCOM service that maps an OXID (Object Exporter Identifier) to the RPC binding string a client uses to call methods on a marshalled COM object. The "Rotten" and "Juicy" Potato families forge `OBJREF` marshalled blobs in which the OXID resolver field points back at an attacker-controlled endpoint, causing the SYSTEM-context RPCSS to authenticate to the attacker's pipe when it tries to resolve the OXID.

RottenPotato (September 26, 2016) demonstrated the chain [697]; JuicyPotato (August 2018) industrialized it with a configurable CLSID table and reliable handling. The canonical mirror for the JuicyPotato repository is the `ohpe/juicy-potato` GitHub project [698]. Crucially, the gate was still `SeImpersonatePrivilege`: Rotten and Juicy capture the SYSTEM token through a local NTLM relay over a loopback socket, completing the server side of the exchange with SSPI's `AcceptSecurityContext` and extracting the token with `QuerySecurityContextToken`; the DCOM and OXID-resolution trick is just the *vehicle* that delivers a SYSTEM-context authentication to that local endpoint. `ImpersonateNamedPipeClient` becomes the literal handoff only in the later named-pipe variants such as PrintSpoofer and RoguePotato.

### Generation 4, coercion APIs beyond DCOM (2020-2024)

Clement Labro (itm4n) shipped PrintSpoofer on May 1, 2020 [699], [989]. The coercion primitive was MS-RPRN's `RpcRemoteFindFirstPrinterChangeNotificationEx`: an RPC method on the Print Spooler that takes an attacker-supplied UNC-like notification target and authenticates to it under the Spooler's SYSTEM identity. PrintSpoofer needed neither DCOM nor any leaked handle; the coercion primitive lived inside an always-running Windows service.

PrintSpoofer generalized. Researchers quickly mapped a family of Windows RPC interfaces with the same shape: an RPC method that takes an attacker-supplied path and resolves it server-side under a privileged identity. MS-EFSR (the Encrypting File System remote protocol) gave EfsPotato and SharpEfsPotato: the canonical fork is `bugch3ck/SharpEfsPotato` [994], not the `ly4k` mirror. MS-FSRVP, MS-DFSNM, and a long tail followed. CoercedPotato's `--interface {ms-rprn, ms-efsr}` switch operationalises the enumeration in a single tool [1055]; the project's MS-EFSR catalog alone lists fourteen entry points (indices 0-13, with two marked NOT WORKING).

The pattern is clear at this point: the privilege is the constant; the coercion primitive is interchangeable. Microsoft has shipped per-CVE patches for individual coercion APIs (targeted MS-EFSR fixes, for instance), but no commitment to enumerate or class-close the surface. The PrintNightmare cluster (CVE-2021-34527 [996]) is instructive precisely because it does *not* belong on that list: it patched a point-and-print driver-install RCE (`RpcAddPrinterDriverEx`), and pointedly left the MS-RPRN coercion primitive PrintSpoofer abuses (`RpcRemoteFindFirstPrinterChangeNotificationEx`) untouched, which Microsoft still treats as by-design.

### Generation 5, into RPCSS itself (2022-2024)

In December 2022, the researcher who goes by BeichenDream published GodPotato, with a README that names the structural defect plainly:

> "Based on the history of Potato privilege escalation for 6 years, from the beginning of RottenPotato to the end of JuicyPotatoNG, I discovered a new technology by researching DCOM, which enables privilege escalation in Windows 2012 - Windows 2022, now as long as you have `ImpersonatePrivilege` permission. Then you are `NT AUTHORITY\SYSTEM`... There are some defects in rpcss when dealing with oxid, and rpcss is a service that must be opened by the system." [1056]

GodPotato is presented by its README as surviving the CVE-2021-26414 three-phase DCOM hardening (rolled out 2021-06-08, 2022-06-14, 2023-03-14) [1057] because the defect is in RPCSS's OXID *handling*, not ordinary DCOM *activation*. The other structural half of the defect is documented by Forshaw in April 2020: "When LSASS creates a Token for a new Logon session it stores that Token for later retrieval... in this case it does matter as it means that the negotiated Token on the server, which is the same machine, will actually be the session's Token, not the caller's Token" [967]. Together those two structural properties explain the README's tested matrix (Server 2012 through Server 2022, Windows 8 through Windows 11) but that is a public-research claim, not a guarantee for every patched build, configuration, or future release [1056]. As of the date of this writing, this chapter found no public Microsoft CVE or security update naming GodPotato's underlying RPCSS path; readers should re-check the MSRC Update Guide for `GodPotato`, `RPCSS`, and related OXID terms before relying on that negative claim.

LocalPotato (February 2023) is the parallel branch: Antonio Cocomazzi and Andrea Pierini discovered that the NTLM Type-2 "Reserved" field could be used to swap context handles during local authentication, escalating from an *unprivileged* user, and the first variant in the lineage that does not require `SeImpersonatePrivilege` to start [1058]. Microsoft fixed it as CVE-2023-21746 [1059], but the conceptual proof remains: the local NTLM stack itself is an attacker-controllable token source.

SilverPotato (April 24, 2024) extended the family across hosts [1060]. Members of the Distributed COM Users or Performance Log Users groups trigger remote activation of the `sppui` DCOM application (CLSID `{F87B28F1-DA9A-4F35-8EC0-800EFCF26B83}`) on a target server. The coerced Domain Admin authentication is then chained through SMB relay to the ADCS host, SAM dump, Pass-the-Hash, CA private key extraction, and ForgeCert to mint a Domain Admin certificate. Microsoft fixed SilverPotato as CVE-2024-38061 in the July 2024 Patch Tuesday [1061]; the original researcher's credit was subsequently removed after a second-reporter overlap and an MSRC severity re-grading from *moderate* to *important* [1060]. The structural primitive the chain exploits (DCOM cross-session activation gated on Distributed COM Users / Performance Log Users group membership chained into a cross-host NTLM relay) remains a per-CVE rather than a class-level close.

FakePotato (CVE-2024-38100, July 2024 KB5040434) closed the ShellWindows DCOM activation path that Pierini disclosed; the patch shipped about a month *before* the public disclosure [1062], [1063].

> **Aside: The Forshaw body of work.**
> James Forshaw's writing is, by some margin, the single most-cited body on the impersonation primitive in the offensive-research community. Four single-author primaries underpin most of this chapter: *The Art of Becoming TrustedInstaller* (2017-08) on Service-SID derivation [970]; *Empirically Assessing Windows Service Hardening* (2020-01), the canonical empirical assessment of what the WSH stack actually closes and what it does not [1053]; *Sharing a Logon Session a Little Too Much* (2020-04), which documents the LSASS cached-token defect that GodPotato later weaponised [967]; and *Windows Exploitation Tricks: Relaying DCOM Authentication* (2021-10), the Project Zero retrospective that names the genealogy from Issue 325 to RemotePotato [1049]. Forshaw's 2020-01 opening sentence is the line every defender quotes back: "In the past few years there's been numerous exploits for service to system privilege escalation. Primarily they revolve around the fact that system services typically have impersonation privilege" [1053].

**Walkthrough: five generations, one constant.** Read the lineage as a gap-analysis table rather than as a museum of tools. Generation 1 proved that if a service-account process could obtain or steal an impersonation token handle, the enabled privilege made SYSTEM reachable; MS09-012 narrowed that handle-leak source [1037]. Generation 2 asked a different question: can the machine be made to authenticate to itself through NTLM and WPAD so the service process receives a usable token? HotPotato answered yes, and MS16-075/WPAD hardening narrowed that route [1039]. Generation 3 shifted to DCOM: if a forged OBJREF can influence OXID resolution and local activation, Rotten and Juicy can turn COM authentication into the same SYSTEM token through a local SSPI relay; CVE-2021-26414 eventually narrowed that class [1057]. Generation 4 generalized beyond DCOM into coercion APIs such as MS-RPRN and MS-EFSR, showing that the problem was not one COM interface but a supply of privileged callers willing to authenticate to attacker-chosen local endpoints [699], [989]. Generation 5 moved inward, into RPCSS and NTLM-loopback defects: GodPotato, LocalPotato, SilverPotato, and FakePotato showed that even after DCOM hardening, OXID handling and cached-token behavior could still supply the missing token [1056], [1058], [1060], [1063]. In every row, Microsoft narrows the source. In no row does Microsoft remove the enabled service privilege or the thread-impersonation model.

| Generation | Years | Token source | Microsoft response | Public status in 2026 |
|---|---|---|---|---|
| G1 Direct Token Theft (Cerrudo) | 2008-2010 | Leaked impersonation handles | MS09-012 (Cerrudo *Chimichurri* PoC) | No (handle leaks closed) |
| G2 Local NTLM Reflection (HotPotato) | 2014-2016 | WPAD + HTTP-to-SMB reflection | MS16-075 + WPAD hardening | No (chain too fragile) |
| G3 DCOM Activation (Rotten/Juicy) | 2016-2018 | Coerced DCOM auth to attacker pipe | Win10 1809 OXID + CVE-2021-26414 | Partial (some LTSC pins) |
| G4 Non-DCOM RPC Coercion (PrintSpoofer/Coerced) | 2020-2024 | MS-RPRN / MS-EFSR / MS-FSRVP coercion | Per-CVE patches | Yes (long tail) |
| G5 RPCSS OXID + NTLM-Loopback (GodPotato/Local/Silver) | 2022-2024 | RPCSS handling defect + cross-host NTLM relay | No public CVE/security update named for GodPotato; CVE-2023-21746 for LocalPotato; CVE-2024-38061 for SilverPotato (July 2024) | Public GodPotato README still claims Server 2012-2022 / Windows 8-11 coverage |

> **Definition: Windows Service Hardening (WSH).**
> Microsoft's umbrella term for the post-2003 stack of mitigations around the service-account population: Service SIDs, restricted tokens, write-restricted tokens, integrity levels for services, the SCM's per-service required-privileges list, and the LPAC variants for select Windows components. The hardening is real, but as the MSRC servicing-criteria discussion establishes, Microsoft has elected not to treat WSH as a *security* boundary.

> **Key idea.**
> Eighteen years. Five generations. One privilege. The variable is the token source; the constant is the gate.

Each generation tells a story of an MSRC bulletin that closed a specific token source and a researcher who found a new one within months. But every generation also leaves the same three components in place: the privilege, the named-pipe coercion API, and Microsoft's choice not to close the family at its root. What if those three components, taken together, form a closed system?

## Where this link breaks

The link breaks at the seam between two assumptions that are each reasonable in isolation. The first assumption is the service-design assumption: a server must be allowed to act as a client after authentication, because otherwise Windows cannot implement per-user file access, printer access, mailbox access, database access, or RPC authorization inside long-running services. The second assumption is the hardening assumption: LOCAL SERVICE and NETWORK SERVICE are low-privileged enough that moving services away from SYSTEM materially reduces worm blast radius. `SeImpersonatePrivilege` is the compatibility object that lets both assumptions coexist.

The Potato family is the gap analysis for that coexistence. It asks a single question over and over: if a low-privileged service process is allowed to impersonate authenticated clients, how many ways can a privileged client be made to authenticate to an endpoint the service process controls? Cerrudo's answer was leaked handles. HotPotato's answer was local NTLM reflection (the relayable-NTLM property established in Chapter 16). Rotten/Juicy's answer was DCOM activation and OXID resolution. PrintSpoofer's answer was coercion through non-DCOM RPC surfaces. GodPotato's answer was RPCSS itself. LocalPotato, SilverPotato, and FakePotato then showed that token-swapping and loopback-authentication defects still matter even after the obvious DCOM path is narrowed [1038], [1049], [1039], [699], [1056], [1058], [1060], [1063].

That is why the important question is not which binary works this month. The important question is which architectural pieces remain unchanged after each patch. If the service process still starts with enabled `SeImpersonatePrivilege`, if a named-pipe/RPC server can still receive an impersonation token from an authenticated client, and if MSRC still treats Windows Service Hardening as a safety boundary rather than a serviced security boundary, the link is not closed. It is reduced to the current token-source search problem.

## The three-piece theorem

The Potato lineage is not a collection of bugs. It is the consequence of a single architectural identity:

> **Key idea.**
> Enabled service-account `SeImpersonatePrivilege` + a usable privileged authentication/coercion source + impersonation/token-conversion APIs + the MSRC servicing-criteria carve-out = service-account-to-SYSTEM.

Each summand is individually documented or visible in shipped Windows behavior. Each is justified by a real engineering or product requirement. *Together they form a system that point fixes only narrow: removing the privilege or the impersonation API surface breaks documented Windows behaviors, while fixing one token source leaves the search for another source open.*

This is the chapter's main contribution: re-frame the eighteen-year named-exploit lineage as the consequence of a documented three-piece architectural decision rather than as a series of bugs.

![Figure: The three-piece theorem is an AND composition, not a menu: default service-account impersonation privilege, a coercion path that makes SYSTEM authenticate to the attacker-controlled endpoint, and the MSRC servicing carve-out must all remain in place before the chain becomes service account to SYSTEM. Removing any one piece breaks the chain, but Microsoft has not serviced the class by removing any of them.](diagrams/27-seimpersonate-three-piece.svg)

### Component 1: the privilege

`SeImpersonatePrivilege` is enumerated in the privilege-constants table as `SE_IMPERSONATE_NAME` [1036] and is the subject of a dedicated security-policy page that lists default assignments [1033]. The LOCAL SERVICE and NETWORK SERVICE account documentation each enumerate it as `(enabled)` in the default privilege set [1034], [1035].

*Cost of removal:* many RPC servers that impersonate clients break; the MSRC servicing-criteria section walks through the production-Windows surface this affects in detail.

### Component 2: the token-handoff and coercion surface

`ImpersonateNamedPipeClient` has shipped since Windows XP / Server 2003 [1048]. It is a standard mechanism by which a named-pipe server picks up the identity of a connecting client to make per-user access checks, and RPC/COM/LSA impersonation surfaces compose into the same broader token-substitution model. Deprecating one API would not remove the need for services to receive and act under client identity; it would force a migration of long-standing Win32/RPC patterns.

*Cost of removal:* the named-pipe server population that pre-dates the modern impersonation APIs breaks; the deprecation discussion details server-side SMB, Print-Spooler, EFS-RPC, and broader Win32 ABI migration cost.

### Component 3: the carve-out

> **Definition: MSRC Servicing Criteria.**
> Microsoft's public policy document defining what counts as a security boundary, a security feature, and a defense-in-depth feature for servicing purposes. The two-question test is direct: "Does the vulnerability violate the goal or intent of a security boundary or a security feature? Does the severity of the vulnerability meet the bar for servicing?" If either answer is no, "the vulnerability will be considered for the next version or release of Windows but will not be addressed through a security update or guidance" [301].

The MSRC Windows Security Servicing Criteria document [301] is the policy-level anchor. The operational articulation came at Troopers 24 from Pierini and Cocomazzi, who reported the WSH-as-safety-not-security distinction [1064]. The MSRC servicing-criteria section opens with the full quote and walks through its implications; for the theorem here, what matters is the combination of Microsoft's published boundary criteria and researcher-reported MSRC handling, not an inference from exploit folklore alone.

*Cost of removal:* Microsoft would have to turn the per-CVE cadence into a structural-close cadence: servicing every coercion API in the long tail, every NTLM-loopback edge case, every cross-session token confusion, on the same SLAs as security-boundary violations. The public criteria [301] do not make that commitment, and the researcher-reported cases below show MSRC handling the class more narrowly.

> **Quoted anchor.**
> "if you have SeAssignPrimaryToken or SeImpersonate privilege, you are SYSTEM" (Andrea Pierini; "a deliberately provocative shortcut obviously, but it's not far from the truth") Clement Labro's gloss on the same line [699]

**Walkthrough: the three-piece theorem.** The first piece is the privilege: Microsoft default-assigns `SE_IMPERSONATE_NAME` to the service accounts that run much of the Windows server estate, and the account pages mark it enabled [1033], [1034], [1035]. The second piece is the token-handoff API: `ImpersonateNamedPipeClient` and the related RPC impersonation surfaces let a server thread wear a connected client's identity because otherwise ordinary Windows services cannot authorize per-client work [1048]. The third piece is doctrine: the MSRC criteria and the Troopers 24 articulation treat the Windows Service Hardening boundary as a safety boundary rather than a security boundary, so variants are serviced as point defects or not serviced at all rather than as violations of a root boundary [301], [1064]. Put those three pieces in the same host and the theorem is mechanical. A low-privileged service compromise is not yet SYSTEM. A low-privileged service compromise plus a usable privileged authentication event plus an enabled impersonation gate is SYSTEM. Every named Potato is a different proof of the middle term.

> **Note.**
If the primitive is a closed three-piece system, what has Microsoft actually shipped in the eighteen years since Cerrudo? Five containment mitigations: each of which narrows the surface around the primitive without closing it.

## Five mitigations and the surface none of them closes

Microsoft has not been idle. Over nineteen years of service hardening they have shipped Service SIDs, restricted tokens, the Less-Privileged AppContainer model, group Managed Service Accounts, and the three-phase DCOM hardening of CVE-2021-26414. Each closes a real surface. None of them closes the primitive. The pattern is too consistent to be accidental.

### Service SID isolation (Vista, 2007)

Vista shipped per-service SIDs of the form `NT SERVICE\<name>`: a SID generated on the fly from the service's name and attached to the service-process token. Forshaw's *The Art of Becoming TrustedInstaller* is the canonical reference for the derivation: "The SID itself is generated on the fly as the SHA1 hash of the uppercase version of the service name" [970]. Service SIDs are also documented as part of the SCM service-security model [1065].

> **Definition, Service SID.**
> A SID of the form `NT SERVICE\<service-name>` derived as the SHA1 hash of the uppercased service name. Service SIDs let an ACL grant access to a specific service without granting access to every service running under the same account. When `SERVICE_SID_TYPE_UNRESTRICTED` is configured, the Service SID is added to the service-process token as a regular group SID.

*Closes:* lateral movement between services sharing an account. A process for service A cannot, by Service SID alone, open files ACL'd to service B's Service SID (`NT SERVICE\B`), even though both run as NETWORK SERVICE.

*Does NOT close:* vertical movement to SYSTEM via NETWORK SERVICE. Forshaw's April 2020 *Sharing a Logon Session a Little Too Much* documents the LSASS cached-token defect that underpins GodPotato: even with Service SIDs in place, the local logon session that LSASS retrieves for a same-machine authentication is the *session's* token, not the *caller's* token, which is exactly the structural property GodPotato weaponises [967].

### Restricted and write-restricted service tokens (Vista 2007, backport via MS09-012)

`SERVICE_SID_TYPE_RESTRICTED` is the SCM service-SID setting that wraps the service-process token in a write-restricted restricting-SID set (adding the write-restricted SID `S-1-5-33`); for restricted operations the kernel performs the access check twice (once against the regular group SIDs, once against the restricting set) and grants only the intersection. Forshaw's January 2020 empirical assessment is the canonical study of what these settings actually accomplish: "In the past few years there's been numerous exploits for service to system privilege escalation. Primarily they revolve around the fact that system services typically have impersonation privilege" [1053].

> **Definition, Restricted Token.**
> A token marked with a *restricting SID* set in addition to its regular group SIDs. The kernel grants access only when both sets satisfy the ACL. Configured per-service via `SERVICE_SID_TYPE_RESTRICTED`; the resulting token is write-restricted (marked with the write-restricted SID `S-1-5-33`), so the restricting set gates write access. The intent is to prevent a compromised service from touching arbitrary objects outside an explicit allow-list of restricting SIDs.

*Closes:* the compromised service's ability to write to (or read, depending on configuration) arbitrary objects outside its restricting-SID set.

*Does NOT close:* `SeImpersonatePrivilege` is not revoked. A restricted token can still call `ImpersonateNamedPipeClient` and `CreateProcessWithTokenW`. The privilege gate is orthogonal to the restricting-SID gate.

### LPAC (Less-Privileged AppContainer) for select services (Windows 10+)

Some Microsoft components opt into the AppContainer model with the Less-Privileged variant: the Edge browser broker, certain Defender child processes, parts of the DNS Client and Web Account Manager stacks. Inside an LPAC, the process runs with a deny-all token capabilities profile and must declare every Win32 capability it intends to use. The AppContainer and LowBox token model is developed where Windows access tokens and capabilities are covered (Chapter 22, Windows Access Control).

*Closes:* the attack surface of a few specific Microsoft-shipped contained services.

*Does NOT close:* the LOCAL SERVICE and NETWORK SERVICE population this chapter is about is **not** LPAC-contained by default. Declaring an LPAC service requires rewriting the service to operate inside an AppContainer, which most product teams do not undertake.

> **Aside: Why LPAC adoption is essentially nil for third-party services.**
> Building an LPAC service is not a configuration flag; it is an architectural commitment. The service must declare every Win32 capability it uses, must be packaged through the modern app installer pipeline, and must accept the deny-by-default file-system view that the LPAC sandbox enforces. The cost is real for legacy code: file paths and registry keys the service has historically reached without scrutiny become inaccessible, and IPC patterns that assumed a normal token need to be re-engineered through capability-mediated brokers. Even Microsoft uses LPAC narrowly. Third-party adoption among independent software vendors that ship NETWORK SERVICE workloads is essentially nil. The mitigation that *would* containerise the impersonation surface is technically available; in practice almost nobody uses it.

### group Managed Service Accounts (gMSA, Server 2012+)

gMSA is Microsoft's solution to the credential-hygiene problem for service accounts: a domain-managed identity whose 240-byte password is rotated automatically by the KDS Root Key, retrieved by authorized hosts via Group Policy, and never typed by a human [764].

*Closes:* domain-credential exposure for service accounts. A service no longer has a memorable password an admin will reuse; the credential lives in AD and is rotated on a schedule.

*Does NOT close:* anything to do with `SeImpersonatePrivilege` on the local box. gMSA is a credential-hygiene mitigation, not a privilege-escape mitigation. A service running under a gMSA still holds the same default service-account privileges, and the SilverPotato-class cross-host coerce-and-relay flow [1060], [1061] directly exploits a chain that gMSA does not protect against (per-variant patches like CVE-2024-38061 close instances, not the class).

### CVE-2021-26414 three-phase DCOM hardening

CVE-2021-26414 raised the minimum DCOM client authentication level to `RPC_C_AUTHN_LEVEL_PKT_INTEGRITY`. The rollout was deliberately gradual: phase 1 (2021-06-08) opt-in via registry, phase 2 (2022-06-14) opt-out via registry, phase 3 (2023-03-14) enforced with no opt-out [1057].

*Closes:* the original RottenPotato and JuicyPotato OBJREF-with-attacker-OXID chain on phase-3-enforced builds. The DCOM activation surface those variants depended on is meaningfully harder after phase 3.

*Does NOT close:* anything that does not depend on DCOM activation. **GodPotato** (RPCSS OXID handling, not DCOM activation) remains functional [1056]; **PrintSpoofer / CoercedPotato** (non-DCOM RPC coercion) remain functional [699], [1055]; **JuicyPotatoNG** (September 2022) found a bypass on the DCOM side via the PrintNotify CLSID `{854A20FB-2D44-457D-992F-EF13785D2B51}` [1066]; **SilverPotato** used a different CLSID and a cross-host relay until Microsoft fixed it as CVE-2024-38061 in July 2024 [1060], [1061]: a per-variant fix that illustrates exactly why CVE-2021-26414 does not address the cross-host coerce-and-relay class as a whole.

### The mitigation that does not exist: "RBAC for services"

Windows has shipped no unified RBAC architecture for local services. The SCM provides per-service SDDL controls, the file system and registry provide per-resource ACLs everywhere, and Service SIDs let ACLs name a specific service identity, but "RBAC for services" as a single named mechanism is non-standard Windows terminology. Azure RBAC and Microsoft Entra RBAC are cloud-side authorization systems and do not gate the local `SeImpersonatePrivilege` at all.

**Walkthrough: mitigations around, not through, the primitive.** Service SIDs answer the question, "can one service sharing an account casually write another service's resources?" Restricted and write-restricted tokens answer, "can this service token write objects that were not explicitly ACLed for its restricting SID?" LPAC answers, for a small set of Microsoft-selected services, "can this process run in an AppContainer-like low-privilege compartment?" gMSA answers, "can we avoid static domain service-account passwords and reduce credential-management exposure?" CVE-2021-26414 answers, "can we harden the classic DCOM activation route Rotten/Juicy used?" These are valuable answers. None asks the root question: should a default service identity hold an enabled privilege that can turn any sufficiently privileged client authentication into a primary-token process? The table below is therefore not a list of failed mitigations. It is a list of correct mitigations that operate on adjacent surfaces.

| Mitigation | What it closes | What it does NOT close | Primary |
|---|---|---|---|
| Service SID Isolation (Vista 2007) | Lateral movement between services sharing an account | Vertical SYSTEM via NETWORK SERVICE LSASS-cached-token defect | [970], [967] |
| Restricted / Write-Restricted Tokens | Write access to non-restricting-SID objects | `SeImpersonatePrivilege` still present; `CreateProcessWithTokenW` still works | [1053] |
| LPAC (Windows 10+) | Select-services blast radius | NETWORK / LOCAL SERVICE population not LPAC-contained by default | Chapter 22 (Windows Access Control) |
| gMSA (Server 2012+) | Domain-credential exposure | Local `SeImpersonate`; SilverPotato-class cross-host relay | [764] |
| CVE-2021-26414 phase 3 (2023-03-14) | DCOM activation chain (Rotten/Juicy) | GodPotato (RPCSS), PrintSpoofer (non-DCOM), JuicyPotatoNG (Sept 2022) | [1057] |

> **The mitigations are real. The gap is structural.**
> None of this section is an indictment of the mitigations. Each one closes a meaningful surface, and a NETWORK SERVICE host with all five active is materially harder to attack than a host without them. But the surface they collectively leave open (the `SeImpersonatePrivilege` plus `ImpersonateNamedPipeClient` plus coercion-API combination) is the surface the named Potato lineage keeps returning to. The gap is not a missing patch. The gap is the design.

Microsoft has shipped five mitigations in nineteen years. Every one narrows the surface around the primitive. None of them closes it. The pattern is too consistent to be accidental. So what is the policy that produces this pattern?

## The MSRC servicing-criteria carve-out

> **Quoted anchor.**
> Most of these exploits allow an attacker to break the WSH (Windows Service Hardening) boundary, enabling privilege escalation from a limited service to SYSTEM: a common scenario when dealing with web services like IIS or MSSQL. Interestingly, Microsoft does not consider WSH a security boundary but rather a safety boundary; for this reason, many Potato exploits work (and have been working) on fully updated Windows systems.: Andrea Pierini and Antonio Cocomazzi, Troopers 24 [1064]

This is the Microsoft-position-as-stated-to-researchers anchor for the entire article. The MSRC Windows Security Servicing Criteria page [301] is the policy-document anchor with the same content: the two-question test "Does the vulnerability violate the goal or intent of a security boundary or a security feature? Does the severity of the vulnerability meet the bar for servicing?" If either answer is no, the vulnerability is considered for the next version of Windows but is not addressed through a security update.

Service-to-SYSTEM escalation across the Windows Service Hardening boundary is treated, in the Troopers account, as a violation of a *safety boundary* rather than a *security boundary* [1064]. That distinction matches the public criteria's emphasis on defined security boundaries [301]. Microsoft does fix specific token-source primitives (LocalPotato got CVE-2023-21746, FakePotato got CVE-2024-38100) but the public record does not show Microsoft committing to service the WSH class as a root security-boundary violation [1059], [1062].

Why? Walk through each of the three closure paths Microsoft could in principle take, and the cost of each.

### Revoke `SeImpersonatePrivilege` from NETWORK SERVICE and LOCAL SERVICE

The cleanest fix in the model: drop the privilege from the default-assignment list documented on the LOCAL SERVICE and NETWORK SERVICE account pages [1034], [1035]. Every Potato variant that ends in `CreateProcessWithTokenW` fails immediately.

*Cost.* Every RPC server, web server, database server, and Office service that needs to act on a client's behalf breaks. The privilege exists *because* services need it. IIS application pools cannot impersonate authenticated users; SQL Server cannot enforce per-login row security; Exchange cannot operate on mailboxes under the connected user's identity; the print spooler cannot enforce per-user printer ACLs; the file server cannot enforce per-user file ACLs. The 2003 service-hardening pivot would be reversed. Services would have to run as SYSTEM again to do the work they need to do, which is precisely the worm-target population Microsoft spent the early 2000s migrating away from.

### Declare local DCOM activation a security boundary and service it

This was the partial path Microsoft did take with CVE-2021-26414 [1057]: tighten the DCOM activation surface and ship the change in three phases over twenty-one months. But declaring *all* local DCOM activation a security boundary requires a serviceable-CVE pipeline for every cross-session COM activation, every cross-integrity-level activation, every weakly-authenticated marshalled OBJREF.

*Cost.* The on-the-record case is RemotePotato0 [998], which researchers reported as classified "Won't Fix" by MSRC and which Forshaw's 2021 retrospective described as still unpatched at the time of writing [1049]. RemotePotato0 is empirical evidence for a narrow servicing posture: Microsoft addressed major DCOM hardening in CVE-2021-26414, but did not publicly commit to treating every local or cross-session DCOM relay as a structural boundary violation.

### Deprecate `ImpersonateNamedPipeClient`

Remove the named-pipe-server impersonation API from the Win32 surface. Mark it deprecated. Stop callers from using it. Provide a replacement that requires explicit per-request token plumbing.

*Cost.* Many Win32 RPC servers stop being able to impersonate their callers. Server-side SMB components, the Print Spooler, the EFS RPC server, and a long tail of named-pipe RPC servers depend on this impersonation model; their alternatives all compose into the same kernel-side call. The replacement (a per-request capability handle threading through every RPC binding) would be a multi-year ABI change with no clean migration path for legacy binaries.

**Walkthrough: three closure paths and their costs.** The first true closure path is privilege removal. It is clean in the model and brutal in production: the service accounts that were created to avoid universal SYSTEM execution would lose the one right that lets them continue serving authenticated clients. The second path is boundary reclassification. If local service-to-SYSTEM transitions through WSH become security-boundary violations, MSRC inherits a servicing obligation for every new coercion API, COM activation edge, NTLM-loopback defect, and token-cache confusion in the long tail. The third path is API replacement. Deprecating `ImpersonateNamedPipeClient` requires a capability-like replacement that passes explicit per-request authority through old Win32/RPC ABIs, and legacy binaries cannot be recompiled into that model by policy fiat. All three closures are technically imaginable. None is a small patch. That is the compatibility fact that explains why the OS feature cannot simply be removed.

> **Note.**
> RemotePotato0 [998] holds a particular place in the lineage because it is the first variant for which MSRC's "Won't Fix" classification became public on the record. Forshaw's 2021 Project Zero retrospective notes the variant as "currently unpatched as of October 2021" [1049], and Microsoft did not subsequently issue a CVE for it. Variant-by-variant detail is beyond this chapter's generation-level scope; in this chapter RemotePotato0 functions as the empirical proof that the carve-out is not a hypothetical preference but a shipped policy choice.

> **Key idea.**
> Nineteen years. Five mitigations. Three closure paths with no public Microsoft commitment to structural adoption. The primitive is not merely an unpatched bug. It sits outside Microsoft's published security-boundary framing unless a specific token source independently meets the servicing bar.

Microsoft has chosen, on the record, to treat this boundary as a safety boundary rather than a security boundary. Is that an architectural failure, or is it a rational policy choice under a deeper structural constraint? Hardy 1988 has an answer.

## The Hardy ceiling

Norm Hardy named the class in 1988. Forty years later, Windows is still demonstrating it. The confused-deputy attack surface is not a Microsoft mistake; it is the predictable behavior of any identity-and-ACL system in which a server holds more authority than its clients and acts on client requests [1040].

The argument generalizes beyond Windows. Any system that lets a process inherit ambient authority from its identity, and then lets that process act on requests from less-authorized principals, has a confused-deputy surface by construction. The only complete defense is capability discipline: bind authority to operations rather than to running identities, and never let a process exercise authority it was not explicitly handed [1040]. Lampson's 1971 access-matrix paper is the formal substrate the argument depends on [1041].

Windows is not a capability system. It is an identity-and-ACL system, as Cutler's NT 3.1 team chose in 1993 [625]. As long as that remains true, *some* version of "service-account to higher-privileged identity" is reachable, and the only question is which specific token-source primitive is currently in play. Microsoft's eighteen-year per-CVE response cadence is consistent with that ceiling. Each individual token source is fixable; the class is not.

> **Aside: A note on capability systems.**
> The capability-systems lineage (KeyKOS, EROS, Coyotos, seL4) spent four decades demonstrating that the confused-deputy class is closeable in principle. In a capability system, when Hardy's user passed the FORTRAN compiler the path to the billing file as a debug-output target, the OS would have handed the compiler a write capability only for the file the *user* could write: not for `(SYSX)BILL`. The compiler could not have damaged the bill even if it tried. seL4 has a machine-checked proof of this property. But none of those systems is the Windows service-compatibility envelope, and porting Windows to a capability substrate is not on any public roadmap. The road exists; Microsoft has not taken it.

The closest in-architecture approximations Windows has shipped are narrow: AppContainer and LowBox tokens (Chapter 22, Windows Access Control) bind a subset of authority to declared capabilities for select Microsoft components; the Adminless / Administrator Protection feature (Chapter 22) binds elevation authority to per-action prompts for interactive admins. Both are partial applications of the capability principle within an otherwise identity-and-ACL system. Neither extends to the service-account population this chapter is about.

> **Key idea.**
> Windows is an identity-and-ACL system. As long as it remains one, the confused-deputy class is structurally present, and the Potato lineage is its Windows-specific instantiation.

If the ceiling is structural and Microsoft has chosen the doctrine to match, what is the offensive-research community working on next? And what should defenders be doing in the meantime?

## Open Problems

The closure of LocalPotato in 2023, SilverPotato (CVE-2024-38061) in July 2024, and FakePotato (CVE-2024-38100) in July 2024 did not end the lineage. GodPotato's public README still claims broad tested coverage. The supply of coercion APIs is structurally large. Microsoft has shipped no public policy change reclassifying WSH as a security boundary. The four open questions below define what the lineage looks like through the rest of the decade.

### The coercion-API treadmill

Generation 4 demonstrated that any Windows RPC interface accepting an attacker-supplied path or endpoint and resolving it server-side under a privileged identity is a viable token source. CoercedPotato's MS-EFSR catalog alone lists fourteen entry points (two marked NOT WORKING) [1055], with additional protocols (MS-RPRN, MS-FSRVP, MS-DFSNM) in the same family. Microsoft patches per CVE (targeted MS-EFSR fixes, individual spooler servicing) but the supply is not exhausted, and there is no public Microsoft commitment to exhaustive enumeration or class-level closure.

### GodPotato's RPCSS OXID path

Three years after the three-phase CVE-2021-26414 DCOM hardening completed [1057], the public GodPotato README still claims coverage across its tested Windows matrix (Server 2012-2022 / Windows 8-11) [1056]. Treat that as public-research status, not as a universal statement about every patch level. As of the date of this writing, this chapter found no public Microsoft CVE or security update naming the underlying GodPotato RPCSS path; readers should re-check the MSRC Update Guide for `GodPotato`, `RPCSS`, and related OXID terms before relying on that negative claim. The architectural question (is RPCSS itself the right place to harden, or is the LSASS cached-token defect Forshaw documented in April 2020 [967] the right place) remains open.

### Credential Guard does not stop this

Credential Guard protects the *NTLM hash and Kerberos TGT* in the LSASS Isolated User Mode trustlet. It does **not** protect against runtime impersonation of an already-issued token. The boundary between credential-theft mitigations and impersonation mitigations is frequently confused.

> **Note.**
> Credential Guard's actual scope is narrower than its name suggests. The mitigation moves long-term authenticators (the NT hash, the Kerberos TGT, and certain ticket-granting material) into an isolated user-mode trustlet whose memory the regular kernel cannot read. None of that touches the runtime token plumbing the Potato lineage exercises. The token you receive from `ImpersonateNamedPipeClient` is not a credential and is not held in LSASS-isolated memory; Credential Guard cannot see it.

> **Credential Guard is not a Potato mitigation.**
> Practitioners frequently treat Credential Guard and Virtualization-Based Security as a generic answer to "Windows privilege-escalation risk." For the Potato family they are not. A Credential-Guard-enabled host that runs IIS as NETWORK SERVICE is not protected from PrintSpoofer / CoercedPotato / GodPotato-style chains where their token-source preconditions hold. The category error matters operationally: a security team that buys Credential Guard expecting it to mitigate this primitive is misallocating defensive budget.

### The "service boundary" re-definition Microsoft has quietly avoided

Adminless / Administrator Protection: the 2024-2025 feature that re-frames local admin identity as a per-action consent surface [323] (covered in Chapter 22, Windows Access Control): explicitly excludes services from its new boundary.

> **Note.**
> The Adminless documentation scopes the feature to interactive administrator accounts on a device [323]; services, MSAs, gMSAs, and virtual accounts are out of scope by construction because none of them is an interactive admin account. The new boundary applies to elevation-prompt consent for interactive admins, not to service-account workloads. The open question is whether Microsoft will ever extend the Adminless boundary to include service accounts. As of mid-2026, the answer is *not on the public roadmap*.

### Generation-6 candidates

Three candidate paths for the next generation of the lineage, none with a pushbutton PoC on the scale of HotPotato / JuicyPotato / PrintSpoofer / GodPotato as of mid-2026:

- *Kerberos-only loopback coercion.* The existing NTLM-reflection mitigations target NTLM specifically; a coercion primitive that lands as a Kerberos AP-REQ to the same loopback endpoint would sidestep them.
- *Virtual-account / gMSA token-state defects.* Forshaw's April 2020 analysis [967] established that the LSASS cached-token logic has surprising behaviors under same-machine authentication; the gMSA-account variant of those edge cases has not been publicly explored.
- *Cross-host extensions beyond ADCS.* SilverPotato's coerce-and-relay chain into ADCS infrastructure [1060] (patched as CVE-2024-38061 in July 2024 [1061] but exemplifying an open class) is the strongest current exemplar for the "Generation 6" archetype: cross-host coerce-and-relay attacks that combine the existing local impersonation primitive with off-box authentication targets. LDAP, WinRM, and MSSQL-with-cert-auth are obvious next targets for the same class; what matters for taxonomy is the cross-host shape, not the patched-or-unpatched status of any specific variant.

If the lineage is not closing, what should a defender actually do today?

## What it means for you

For defenders, the practical takeaway is not "panic-remove the privilege." That breaks real services, and the breakage is not incidental: it is the same IIS, SQL Server, Exchange, SMB, spooler, and RPC impersonation surface that caused Microsoft to create the privilege in the first place. Treat `SeImpersonatePrivilege` the way you would treat a production routing table or a domain controller delegation setting: dangerous when mis-scoped, but often load-bearing.

The operational model has three layers. First, inventory effective holders, not just policy text. A GPO may grant the right, a service SID may inherit it through the SERVICE well-known SID, and a product installer may depend on it without making that dependency obvious. Second, classify hosts by service role. A hardened jump box, build worker, or single-purpose management host may not need LOCAL SERVICE or NETWORK SERVICE to impersonate clients; a web server, print server, database server, or Exchange server probably does. Third, detect the primitive rather than the latest binary. A renamed Potato executable is uninteresting if your telemetry sees the sequence of rogue named-pipe creation, privileged service authentication, token duplication, and unexpected process creation from a service account. Conversely, a host can pass every named-tool IOC and still be exposed at the primitive level.

The defender's win condition is therefore not universal removal. It is making the primitive rare, visible, and justified. Remove the right only where service dependency mapping says it is safe. Alert when a service account creates unusual impersonation endpoints or spawns a process under an identity inconsistent with its role. Use named-tool rules as low-noise enrichment, not as your primary control. The feature exists because Windows cannot remove it wholesale without breaking the service model; your job is to make the small number of places that truly need it explicit.

## Defending, detecting, and (carefully) removing the privilege

Three operational questions: which accounts hold the privilege on your box, can you remove it, and how do you detect when someone is actually using it?

### Auditing which accounts hold `SeImpersonatePrivilege`

The first defensive action is enumeration, not removal. Concrete commands, in increasing order of detail:

- `whoami /priv`: per-process self-check from any shell. Reports the token's privileges in the form the chapter opens with.
- `secedit /export /cfg secpol.cfg`: full local-policy export. Grep the output for `SeImpersonatePrivilege` to see every SID the local policy grants it to.
- `accesschk.exe -a SeImpersonatePrivilege`: the Sysinternals AccessChk tool [609] enumerates the effective holders directly from the LSA policy database.
- `Get-NtTokenPrivilege` from James Forshaw's NtObjectManager PowerShell module [988]: the same data, scriptable, with the broader NtObjectManager surface available for follow-up (named-pipe enumeration, token-handle leak search, kernel-object introspection).
- `Invoke-PrivescCheck` from Clement Labro's PrivescCheck module [1067]: the canonical local-privesc check-list. The output includes `SeImpersonatePrivilege` presence as one of approximately forty enumerated checks.

| Tool | Author | What it reports |
|---|---|---|
| AccessChk (Sysinternals) | Mark Russinovich | Effective permissions, account-privilege enumeration via `-a` [609] |
| NtObjectManager | James Forshaw | `Get-NtTokenPrivilege`, named-pipe enumeration, token-handle leak search [988] |
| PrivescCheck | Clement Labro | Canonical local-privesc check-list incl. `SeImpersonatePrivilege` presence [1067] |

A typical local-policy export expresses the assignment as SIDs. On a server-style default, the holders commonly include `S-1-5-19` (LOCAL SERVICE), `S-1-5-20` (NETWORK SERVICE), `S-1-5-32-544` (Administrators), and `S-1-5-6` (SERVICE). Treat that list as inventory input, not as an instruction to remove anything blindly.

### Removing the privilege where you can

The policy path is documented: `Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment -> Impersonate a client after authentication` [1033]. The temptation, especially after reading an article like this one, is to remove `SeImpersonatePrivilege` from NETWORK SERVICE wholesale.

Do not do that. It will break IIS, Exchange, SQL Server, and most other Windows server products. The same set the 2003 service-hardening pivot was designed to support. The realistic defensive approach is narrower: *audit first*, *understand the dependency surface*, then *narrow the assignment to the specific service accounts that need it* on the specific hosts where they run. On hosts that do not run an RPC-impersonating workload (jump boxes, build agents, certain hardened-management hosts), the privilege can sometimes be removed safely from the unused well-known accounts.

> **Do not blanket-remove SeImpersonatePrivilege from NETWORK SERVICE.**
> The single most common mistake after reading any Potato writeup is to remove the privilege from NETWORK SERVICE on a production host. Doing so breaks IIS (per-user authentication fails), Exchange (mailbox impersonation fails), SQL Server (per-login row security fails), server-side SMB components (file-server impersonation fails), the Print Spooler (per-user printer ACLs fail), and most third-party Win32 service products. The privilege exists because services need it. Audit before you remove. Remove only after you have positively identified which production services on this host depend on the privilege and confirmed none of them does.

> **Operational caution: Concrete Group Policy click-through to AUDIT (not remove) the privilege.**
> *Hidden behind a spoiler intentionally, so a skimming reader does not accidentally remove the privilege from production NETWORK SERVICE.* Open `gpedit.msc` (or the Group Policy Management Console for a domain-joined host). Navigate Computer Configuration → Windows Settings → Security Settings → Local Policies → User Rights Assignment → Impersonate a client after authentication. The right-hand pane lists the SIDs holding the privilege. Note the current list. Do not change it. Compare it against the audit output from the inventory subsection. If the local list and the AccessChk output disagree, you have a domain-pushed policy override worth tracing. If they agree and you have a documented business reason to remove a specific account, change the policy for that specific account only, and confirm on a non-production host that the dependent services still function.

### Detection signatures

Detection in this space breaks into two abstractions: *primitive-level* rules that match the named-pipe pattern many Potato variants generate, and *named-tool* rules that match a specific binary's fingerprint.

The primitive-level open-source reference is the Elastic detection rule `Privilege Escalation via Rogue Named Pipe Impersonation` [1068] (commit `66f03fba0a6f8645b8b2a53f72ebe40b9a04c2b8`, checked June 2026), rule_id `76ddb638-abf7-42d5-be22-4a70b0bf7241`. The EQL queries Sysmon Event ID 17 (pipe-creation events) and matches paths in which a `\pipe\` token appears after another path segment: the canonical PrintSpoofer-style relay endpoint fingerprint. Because the rule looks for a primitive-level pattern rather than a binary name (a service-account process creating a suspicious named pipe whose path embeds a coercion-API hint), it survives binary rename, source-recompile, and most CLI variation.

The named-tool reference is the SigmaHQ LocalPotato rule [1069] (commit `36957d791d00bda02d332f44b684d5f65c187c56`, checked June 2026), rule `id 6bd75993-9888-4f91-9404-e1e4e4e34b77`. Three OR-joined selectors: image path ending in `\LocalPotato.exe`; CLI fingerprint `-i C:\` paired with `-o Windows\`; specific IMPHASH selectors `E1742EE971D6549E8D4D81115F88F1FC` and `DD82066EFBA94D7556EF582F247C8BB5`. Useful as a low-noise IOC tripwire; trivially evaded by binary rename or recompilation.

> **Aside: Why named-tool detection is brittle by construction.**
> The Sigma LocalPotato rule is a perfectly competent detection rule for *the LocalPotato binary distributed at a specific commit*. It is essentially useless against the *technique*. An attacker recompiling LocalPotato from source breaks the IMPHASH selectors; renaming the output binary breaks the image-path selector; rewriting the CLI argument parsing breaks the third selector. The rule is brittle by construction, and the brittleness is structural to named-tool detection. The same point this chapter makes about Microsoft's per-CVE patches applies one level down: closing this binary does not close the technique; closing this technique does not close the primitive.

> **Primitive-level detection beats named-tool detection.**
> Invest detection budget in the Elastic primitive-level rule (or equivalent) and accept the higher false-positive rate that comes with it. The named-tool rules are a useful low-noise tripwire but should not be the primary signal. The same logic that makes the privilege durable against per-CVE patches makes the named-tool rules ephemeral against re-tooling.

We have walked the eighteen-year history, named the three-piece system, surveyed the mitigations, articulated the Microsoft policy, hit the Hardy ceiling, scanned the open problems, and listed the operational tools. One thing remains: the eight misconceptions practitioners hold about this primitive that this chapter must explicitly correct.

## The line, re-read

Return to where this chapter started: one line in `whoami /priv`.

```text
SeImpersonatePrivilege  Impersonate a client after authentication  Enabled
```

Now you know what it means. The line ships in the default token of common IIS application pool workers, SQL Server service steps, Exchange worker processes, and other LOCAL SERVICE / NETWORK SERVICE-derived accounts unless local policy, service `RequiredPrivileges`, a custom identity, a container, or a product wrapper narrows it. The line gates `CreateProcessWithTokenW`. The kernel-level token-substitution surface sits behind that gate. Named-pipe impersonation and related RPC/COM handoff surfaces on the other side of the gate have shipped since Windows XP / Server 2003 and remain a dominant token-source family on the platform. Microsoft has shipped five containment mitigations in nineteen years. Each closes a real surface; none closes this primitive. The doctrinal articulation came at Troopers 24: Windows Service Hardening is a *safety* boundary, not a *security* boundary [1064]. The 1988 ceiling that explains why is older than the operating system.

> **Quoted anchor.**
> Microsoft gave default NETWORK SERVICE-style service tokens a privilege that, in the wrong hands and with a usable token source, can be equivalent to SYSTEM. They knew: the MSRC said as much in April 2009 [1037]. They have not removed it from the service model, because every true closure path carries compatibility cost that Microsoft's published criteria do not take on as a root security-boundary obligation [301]. Pierini and Cocomazzi made the doctrine quotable at Troopers 24 [1064]: WSH is a safety boundary, not a security boundary. Roughly eighteen years after Cerrudo first put that fact on the record [1038], ten years after HotPotato made it pushbutton [1039], and three years after GodPotato publicly claimed survival across DCOM hardening [1056], [1057], the primitive is still in place. It is not merely unpatched; it is preserved by the service-compatibility contract unless a specific token source independently meets the servicing bar.

For the variant-by-variant chronology this chapter deliberately deferred: HotPotato, RottenPotato, JuicyPotato, JuicyPotatoNG, PrintSpoofer, EfsPotato, CoercedPotato, RoguePotato, RemotePotato0, GodPotato, LocalPotato, SilverPotato, FakePotato: consult the per-variant references cataloged at the end of this chapter; each names the tool's CLSID, coercion primitive, and patch state. This chapter, which owns the Potato lineage for the book, is about why the family exists at all.

The one line in `whoami /priv` is not a bug. It is the decision.

**Bequeaths.** This chapter hands forward a hard truth the cloud part will build on: on a Windows host, a lower-privileged service account is a *safety* boundary, not a *security* boundary, so privilege held on the box is never the last word on what an attacker can become. It does not hand forward any containment of an attacker who already holds the privilege. That is precisely why the trust story has to continue off the box, where Part IV stops trusting the machine's own verdict (Chapter 26, Zero Trust).
