# Prologue

## What "trust" means here

Pull the memory out of a modern Windows machine while a user is signed in, walk to
the place the password hash has lived since 1993. You will find nothing.
Not an empty file. An *encrypted* nothing: a blob whose key sits one privilege
boundary away, in a second operating system your administrator account cannot
touch. That absence is not an accident or an oversight. It is the visible end of a
chain of decisions that begins before the operating system exists, in a key fused
into silicon that Windows itself never gets to see.

This book is about that chain.

A modern Windows machine is not secured by a feature. It is secured by a sequence
of *promises*, each one made by a lower, smaller, more trusted component to the
larger one above it. The CPU promises it executed only firmware a manufacturer
signed. The firmware promises it measured everything it loaded into a tamper-
evident log. The hypervisor promises it walled off a second world the normal
kernel cannot enter. That second world promises it will hold your credentials and
hand back only answers, never keys. And the cloud, finally, promises it will
honor a token only while the device that earned it still looks trustworthy. Break
any one promise and the promises above it are worth exactly nothing. This is
why the order matters, and why this book follows it.

### Trust is inherited, never asserted

The reason the chain runs in that direction (silicon first, cloud last) is the
single idea the whole book turns on: **trust cannot be asserted by the thing that
wants to be trusted.** A program that says "I am safe to run" tells you nothing; a
kernel that says "I have not been tampered with" is exactly what a tampered kernel
would say. Trust has to be *inherited* from something lower that the asserting
component cannot influence. Follow that requirement down far enough and you arrive
at the only place a Windows machine can put its root: a secret in hardware, fixed
at manufacture, that no software (not a driver, not the kernel, not the
hypervisor) can read or forge. Everything above it is a structure for extending
that one unforgeable fact upward, one verifiable step at a time.

That is what a *chain of trust* is. Each link does two things: it verifies the
link below it before extending trust, and it makes a promise the link above can
rely on. The book is organized as the chain is built:

- **Part I: Silicon.** The root: Secure Boot, the TPM and Pluton, measured boot,
  and the attestation that lets a remote party believe any of it. Where the first,
  unforgeable promise is made.
- **Part II: Kernel & Code.** The isolated core and the code it admits:
  Virtualization-Based Security, the Secure Kernel, code integrity, the hypervisor
  as a boundary the ordinary kernel cannot cross, and the process-level controls
  (Protected Process Light, mitigation policies, Authenticode, App Control) that
  decide what is allowed to run.
- **Part III: Credentials & Access.** The secrets and who may spend them: Mimikatz
  and the theft decade, Credential Guard, the retirement of NTLM, Kerberos and
  KRBTGT, the long war over credential replay, Windows Hello's bet that the safest
  secret is the one that never existed, WebAuthn, and the access-control machinery
  (tokens, integrity levels, SeImpersonate) the whole fight is waged over.
- **Interlude: Watching the Chain.** ETW, the telemetry substrate that lets
  defenders observe what every link actually did.
- **Part IV: Cloud.** Trust carried off the box: Zero Trust, Continuous Access
  Evaluation, and Confidential VMs.
- **Finale.** A forensic account of what happens when a single stolen key snaps
  the chain near the top.

### A promise you can hold someone to

It is easy to talk about "promises" and "boundaries" as metaphors. Microsoft does
not have that luxury. Microsoft publishes a document, the Microsoft Security
Servicing Criteria, that draws a hard line between the boundaries
Microsoft commits to *defending with a security update* and the ones it merely
tries to make hard to cross. A bug that lets ordinary code read the Credential
Guard trustlet's memory is a serviced boundary violation; a bug that lets an
administrator read another administrator's data on the same machine, by the same
document, is not. Where that line falls decides which "weaknesses" become urgent
patches and which become documentation.

This book takes that document seriously, because it is the difference between a
defense and a decoration. When a chapter says a link "protects" something, it
means there is a boundary Microsoft has committed to keep. And when a chapter
says a link "does not cover" something, it usually means the line was deliberately
drawn to leave that case outside. The most useful thing a security architect can
know about any Windows defense is not how it works but *where its promise ends*.
So every chapter walks to that edge on purpose.

### The honest part

Every link in this chain has a documented way around it. The TPM's low-pin-count bus can be sniffed for secrets in transit; the hypervisor has had escapes; Credential
Guard hands derived material to anyone who compromises the agent that calls it; a
cloud signing key, stolen once, forged tokens that unlocked mailboxes across
approximately twenty-five organizations.
A book that walked the chain link by link and pronounced each one "secure" would
be lying by omission. So each chapter ends at the same place: the honest gap
analysis, the boundary of what the link was ever going to cover, so you can decide
what compensating control has to live somewhere else.

That is also why this book shows its work. Wherever a claim could be checked
against a live Windows machine, you will find the evidence inline: the exact
command, the verbatim output, and a cryptographic hash that proves the output was
not edited to fit the argument. Where the claim lives in physical silicon a
virtual machine cannot expose, the book says so plainly rather than dressing a
documented fact up as a measured one. *How to Read This Book* explains the three
tags that make that distinction visible. Use them. The trust chain is only worth
anything if you can verify it, and so is a book about it.

The chain starts where trust has to start: below the operating system, in the
silicon. Turn the page.
