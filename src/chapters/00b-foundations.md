# Chapter 0 · Foundations

## A shared vocabulary

The trust chain spans four worlds (silicon, kernel, credentials, cloud) and almost
no one is fluent in all four. A firmware engineer who can recite the PCR allocation
may not know what a service ticket's session key is for; an identity architect who
lives in Conditional Access may never have heard the term *trustlet*. This chapter
levels that ground. It is not a textbook on any of the four domains; it is the
minimum shared vocabulary the rest of the book leans on, with one line on *why each
term matters to trust*. Read what you need and skip what you know: each later
chapter also carries a short Foundations sidebar for its own terms.

## 0.1 Trust, the TCB, and boundaries

**Trusted Computing Base (TCB).** The set of components that *must* be correct for
a security guarantee to hold. The art of the trust chain is making the TCB for
each guarantee as small as possible: Credential Guard's whole point, for example,
is to remove the enormous NT kernel from the TCB for your password hash and
replace it with a tiny trustlet. When you read "moves X out of the TCB," read
"shrinks the set of things that can betray X."

**Root of trust.** The one component whose trustworthiness is *assumed* rather
than verified, because there is nothing beneath it to verify it. On a Windows
machine the root is in silicon: a key fixed at manufacture. Everything else is
verified by something below it; the root is where the regress stops.

**Security boundary.** A wall the platform commits to defending: crossing it
without authorization is a serviceable vulnerability. Microsoft enumerates which
boundaries it will fix with a security update (the kernel/user boundary, the
hypervisor/guest boundary, the VTL0/VTL1 boundary) and which it will not (one
administrator reading another's data on the same box). "Is this a security
boundary?" is the first question to ask of any defense, because it tells you
whether a bypass is a bug Microsoft will patch or a documented limitation you must
design around.

## 0.2 The silicon tier

**TPM (Trusted Platform Module).** A small, tamper-resistant chip (or firmware
enclave) that holds keys, performs a few fixed cryptographic operations, and
crucially *measures* the boot. Keys generated in a TPM can be made non-exportable:
they are *used* inside the chip and never leave it. This is what lets a machine
prove "this key is on this specific device" rather than merely "someone holds this
key."

**PCR (Platform Configuration Register).** A TPM register you cannot write, only
*extend*: a new value is hashed together with the old one, so a PCR ends up a
one-way summary of everything measured into it, in order. Tamper with any step and
the final PCR no longer matches. PCRs are how a machine binds a secret to "the
exact software state I booted."

**Measured boot vs. Secure Boot.** Two different jobs, often confused. *Secure
Boot* refuses to run firmware/bootloaders that are not validly signed. It
*prevents*. *Measured boot* records what ran into the PCRs whether or not it was
allowed. It *remembers*. Prevention stops the known-bad; measurement lets you
detect the unknown-bad after the fact and bind secrets to a known-good state.

**Sealing.** Encrypting a secret under a TPM policy so it can be decrypted
("unsealed") only when the PCRs match a specified state. BitLocker seals its key
to measured boot so that booting a tampered OS (or moving the disk to another
machine) leaves the key locked.

**Attestation.** The TPM signing a statement about the machine's measured state
with a key only it holds, so a *remote* party (your identity provider, a
management service) can believe the boot was healthy without trusting the machine
to self-report. Attestation is how the silicon root's promise travels off the box.

**Pluton.** A security processor Microsoft places *on the CPU die* and updates
through Windows Update: a root of trust that, unlike a discrete TPM on a bus, has
no exposed wires to sniff and can be patched after a flaw is found.

## 0.3 The kernel tier

**Rings, user mode, kernel mode.** The CPU enforces privilege levels. Your
applications run in *user mode* (ring 3), mediated; the *NT kernel* and drivers
run in *kernel mode* (ring 0), with full control of the machine. Historically,
anything in kernel mode could read anything. Which is why so much of this book is
about putting things *out of reach of ring 0*.

**Driver.** Kernel-mode code, often third-party. A signed-but-vulnerable driver is
the master key of modern Windows attacks ("bring your own vulnerable driver"),
because loading one legitimately grants ring-0 power that defeats user-mode
defenses.

**Hypervisor / VBS / VTL0 / VTL1.** Windows runs its own hypervisor beneath the
kernel and uses it to split the machine into two *Virtual Trust Levels*. **VTL0**
is the normal world: the NT kernel, drivers, your code, and any malware. **VTL1**
is a second, smaller secure world the hypervisor isolates from VTL0 using the
CPU's second-level address translation (**SLAT**), so VTL0 cannot map VTL1's
memory *no matter what privilege it holds.* This whole arrangement is
**Virtualization-Based Security (VBS)**. It is the structural trick the credential
and code-integrity chapters depend on: a boundary the all-powerful ring-0 attacker
cannot cross.

**Secure Kernel.** The kernel that runs *in* VTL1, much smaller than the NT
kernel and therefore a far smaller TCB. It hosts the trustlets.

**Trustlet.** A small, Microsoft-signed user-mode process that runs in VTL1 behind
the boundary. `LsaIso.exe` (Credential Guard) is Trustlet ID 1. A trustlet's
identity is gated by two specific Microsoft signing EKUs the Secure Kernel checks
at load (detailed in Chapter 7, VBS Trustlets), so VTL0 cannot impersonate
one.

**HVCI (Hypervisor-Enforced Code Integrity).** Uses the hypervisor to guarantee
that any executable page in the kernel is signed and immutable, and any writable
kernel page is non-executable. It closes the unsigned-code-in-the-kernel door even
against ring 0.

## 0.4 The credential tier

**Authentication vs. authorization.** *Authentication* establishes who you are;
*authorization* decides what that identity may do. This tier is mostly about
protecting the secrets that prove *who you are*.

**LSASS (`lsass.exe`).** The Local Security Authority Subsystem Service: the process that
performs authentication and, historically, held the secrets it needed. Dumping
LSASS memory was the canonical way to steal credentials for two decades.

**SSP (Security Support Provider).** A pluggable protocol module loaded into
LSASS: NTLM (`msv1_0`), Kerberos, `cloudap` for Entra, Schannel for TLS. The SSP
speaks the wire protocol; the question this book keeps asking is *where the key it
uses lives.*

**NTLM hash / NTOWF.** The "NT One-Way Function" is the MD4 of the user's
password. Windows authenticates by proving possession of this hash, which means
the hash is *password-equivalent*: steal it and you can authenticate as the user
without ever cracking the password. That equivalence (**Pass-the-Hash**) is the
original sin this entire tier exists to contain.

**Kerberos: KDC, TGT, service ticket, session key.** In a domain, a Key
Distribution Center (the domain controller) issues a **Ticket-Granting Ticket
(TGT)** after you prove your *long-term key* (derived from your password). You then
exchange the TGT for **service tickets**, each carrying a fresh **session key**,
to reach individual services. Two distinctions matter throughout the book: the
*long-term key* (durable, the thing worth isolating) versus the *session
keys/tickets* (per-session, but still in LSASS memory while in use), and the TGT
(your domain-wide proof) versus a single service ticket.

**DPAPI (Data Protection API).** Windows' standard way to encrypt per-user secrets
at rest (saved passwords, certificates, the Credential Manager vault), keyed
ultimately off the user's credentials. When Credential Guard isolates those credentials, the secret DPAPI's chain ultimately depends on sits behind the VTL1 boundary, even though the DPAPI master-key hierarchy itself stays in the normal OS.

**Token, privilege, impersonation.** After authentication, a process carries an
*access token* describing its identity and *privileges*. Some privileges
(`SeImpersonatePrivilege`, `SeDebugPrivilege`) are powerful enough to be
escalation primitives in their own right, and tokens, unlike credentials, are not
what Credential Guard protects.

**PPL (Protected Process Light).** An NT-kernel mechanism that wraps a process
(such as LSASS, via `RunAsPPL`) so only equally-or-higher-signed code may tamper
with it. (Its `RunAsPPL` value follows the scheme `1` = enabled with a UEFI lock,
`2` = enabled without: the same "without UEFI lock" convention you meet again at
`LsaCfgFlags` in Chapter 15.) Useful, but enforced by the same kernel an attacker is
trying to subvert. Which is exactly why it is *complementary to*, not a replacement
for, the VTL1 isolation of Credential Guard.

## 0.5 The access-control tier

**Security principal and SID.** Every user, group, computer, and service is a
*principal* identified by a Security Identifier (SID). Authorization is decided by
comparing the SIDs in a caller's token against the SIDs in an object's permissions.

**Access token.** After authentication, every process carries a token listing its
user and group SIDs, its *privileges*, and its *integrity level*. The token is the
runtime answer to "who is this code, and what may it do."

**ACL / DACL / SACL / ACE.** A securable object carries a Discretionary Access
Control List (who may do what) and a System Access Control List (what to audit),
each a list of Access Control Entries (ACEs). The check walks the DACL against the
token.

**Privilege.** A named right held in a token that is *not* tied to a specific
object: `SeDebugPrivilege` (open any process), `SeImpersonatePrivilege` (act as a
token you obtained), `SeBackupPrivilege` (read anything). Some privileges are
escalation primitives in their own right.

**Integrity level (MIC) and UIPI.** Mandatory Integrity Control tags every process
and object with an integrity level (Low, Medium, High, System). A lower-integrity
process cannot write to a higher-integrity object, and User Interface Privilege
Isolation blocks it from sending window messages upward: the mechanism behind
browser and AppContainer sandboxes.

**UAC and elevation.** User Account Control splits an administrator's logon into a
filtered (Medium-integrity) token and a full (High-integrity) one; elevation
swaps to the full token. Whether that boundary is a *security* boundary is a theme
of the Integrity-Level Stack chapter.

## 0.6 Code, application control, and detection

**Authenticode.** Microsoft's code-signing scheme: a PE file carries (or a catalog
vouches for) a signature the OS verifies before trusting the code. The crypto
foundation under driver signing, WDAC, and SmartScreen.

**Catalog file.** A detached signature listing the hashes of many files, so
unsigned-but-cataloged binaries (most of Windows) can still be verified.

**WDAC / App Control / AppLocker.** Application-control engines that allow or deny
code by signer, hash, or path: the difference between "anything signed may run"
and "only what I listed may run."

**ETW.** Event Tracing for Windows: a high-throughput, in-kernel event pipeline
originally built for performance tracing that became the telemetry substrate EDR
sensors consume. The interlude returns to ETW as the book's observation layer.

**EDR.** Endpoint Detection and Response: the sensor-plus-analytics layer that
watches process, file, registry, and network events (largely via ETW and kernel
callbacks) to detect attacker behavior the preventive controls did not stop.

**Sysmon.** A Microsoft Sysinternals driver that turns selected ETW and kernel
events into a richer, durable event log: a common bridge from raw telemetry to a
SIEM.

## 0.7 The cloud tier

**Microsoft Entra ID.** Microsoft's cloud identity provider (formerly Azure AD).
On modern Windows, the credential chain does not end at the domain controller; it
extends to Entra, and the device itself becomes an identity.

**Primary Refresh Token (PRT).** The cloud analog of the long-term credential: a
token, issued to a joined device, that mints the access tokens applications use.
On capable devices it is bound to a TPM key, so the PRT is useful only on the
device that earned it: the cloud version of "non-exportable."

**Access token / refresh token.** Short-lived *access tokens* authorize individual
API calls; longer-lived *refresh tokens* (like the PRT) obtain new ones. Stealing
a token is the cloud-era equivalent of stealing a hash. Which is why binding
tokens to devices, and re-checking them continuously, became necessary.

**Conditional Access / Continuous Access Evaluation (CAE).** Policy that decides
whether a token should be honored *right now*, based on device health, location,
and risk, and, with CAE, can revoke a still-valid token mid-session when
conditions change. This is the cloud's answer to "the token was fine when issued
but the world changed."

**Device join state.** Whether a machine is domain-joined, Entra-joined, or hybrid
determines which credentials and tokens it holds and how they are protected; the
diagnostic `dsregcmd /status` reports it.

## 0.8 Reading the evidence

Finally, the vocabulary for the book's own claims. Every block of machine evidence
carries one of three tags, and the tag tells you exactly how much to trust it:

- 🟢 **CAPTURED**: verbatim output from a live Windows machine, recorded with a
  SHA-256 at capture time and re-checked by a build gate. Reproducible with the
  command shown.
- 🟡 **EMULATED**: a real value whose root is provided by the virtualization host
  rather than physical silicon (a virtual TPM's PCRs on a cloud VM, for example).
- 🔵 **DOCUMENTED**: a mechanism in physical silicon a virtual machine cannot
  expose, or a value not captured on the lab machine; explained from the
  authoritative source, with the reproduce command, but not a measurement the book
  is itself making.

Those tiers are not a list but a chain: each link trusts the one beneath it, and the whole book climbs that spine from the silicon upward.

![Figure: The trust chain as one spine: a map of this book. Each part inherits its security from the part below it: Silicon roots the chain at the foundation; the Kernel and its code sit above it; Credentials and Access spend the trust those layers protect; and Cloud rides near the top, where the machine boundary becomes one signal among many. The Interlude observes every link from the side, and the Finale is what happens when a link inherits more authority than the link below it meant to grant. The argument of the entire book is the direction of the arrows: trust is inherited, never asserted.](diagrams/trust-chain-map.svg)

With the vocabulary in hand, we can start where trust has to start: in the
silicon.
