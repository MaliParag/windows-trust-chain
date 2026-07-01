# How to Read This Book

This book is one argument in four numbered parts, a watching interlude, and a
finale. It rewards being read in order, but it is built so you can also drop
into any link you own.

## The numbered parts follow the chain

- **Part I · Silicon.** The hardware root of trust: Secure Boot, the TPM, Pluton,
  measured boot, and remote attestation. Where the chain's first promise is made.
- **Part II · Kernel & Code.** The isolated core and the code it admits:
  Virtualization-Based Security, the Secure Kernel, VBS trustlets, code integrity,
  the hypervisor as a security boundary, Protected Process Light, process
  mitigations, Authenticode, and App Control.
- **Part III · Credentials & Access.** The secrets and who may spend them:
  Mimikatz and the credential-theft decade, Credential Guard, the death of NTLM,
  Kerberos and KRBTGT, the long arc from pass-the-hash to pass-the-PRT, Windows
  Hello, WebAuthn, access control, the integrity-level stack, and SeImpersonate.
- **Interlude · Watching the Chain**: ETW and the telemetry substrate that lets
  defenders observe what the chain did.
- **Part IV · Cloud.** Trust off the box: Zero Trust, Continuous Access
  Evaluation, and Confidential VMs.
- **Finale · When the Chain Snaps**: Storm-0558, the case study for a cloud
  signing key inheriting more authority than the lower links meant to grant.

Before Part I, a short **Foundations** chapter establishes the shared vocabulary
the chain spans. If you live in one domain and are visiting another, read it
first; if a later chapter assumes a term you don't have, its inline **Foundations** section will catch you up just in time.

## Most chapters use the same six beats

1. **The Reasoner's question**: the one question the chapter exists to answer, after a trust-chain ledger places the link in the chain.
2. **Foundations**: the vocabulary this chapter assumes, in brief.
3. **How Windows implements it**: the architecture, bottomed out on mechanism.
4. **Proof on a live machine**: captured evidence where the lab can produce it,
   or documented command surfaces where it cannot.
5. **Where this link breaks**: the honest gap analysis.
6. **What it means for you**: a residual-risk table and a probe you can run.

## The evidence is tagged: read the mark and the color

Every block of machine evidence carries a provenance tag. The tag tells you
*exactly* how much to trust it:

- 🟢 **CAPTURED**: verbatim output from a live Windows 11 machine, recorded with
  a SHA-256 at capture time and re-verified by a build gate. The strongest claim
  the book makes. You can reproduce it with the command shown.
- 🟡 **EMULATED**: a real value whose root is provided by the virtualization host
  rather than physical silicon (for example, a virtual TPM's PCRs on a cloud VM).
  Real, but rooted in emulation, and labeled so.
- 🔵 **DOCUMENTED**: a mechanism that lives in physical silicon a virtual machine
  cannot expose (Boot Guard, Pluton, the firmware fuses), or a value not captured
  on the lab machine. Explained from the authoritative source and the reproduce
  command given, but *not* a measurement the book is making.

When the chapter shows you a 🔵 block, it is telling you the truth about its own
limits. That is deliberate. A book that cannot show you the silicon should say so,
not pretend.

## Run the probes

The "what it means for you" beat in each chapter ends with a **verify-it-yourself**
probe (usually one line of PowerShell) that you can run on your own machine. Where
the chapter shows 🟢 evidence, that probe is the same one that produced it. The
fastest way to internalize the trust chain is to watch it answer on a box you
control.

A note on builds: Windows security changes fast, and the live evidence here was
captured against a specific build, stamped on each capture. Treat the *mechanism*
as durable and the *exact value* as a snapshot, and re-run the probe to see
today's.
