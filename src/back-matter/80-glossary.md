# Glossary

Cross-tier quick reference. Fuller treatment of most terms is in Chapter 0.

**ALPC (Advanced Local Procedure Call).** The Windows IPC primitive; in Credential
Guard the agent reaches the trustlet over a single ALPC channel mediated by the
Secure Kernel.

**Attestation.** The TPM signing a statement about the machine's measured boot
state so a remote party can believe it without trusting the machine to
self-report.

**BYOVD (Bring Your Own Vulnerable Driver).** Loading a legitimately signed but
vulnerable kernel driver to obtain ring-0 execution; the residual that HVCI's
unsigned-code enforcement does not close.

**CAE (Continuous Access Evaluation).** Cloud mechanism that re-evaluates or
revokes a still-valid access token mid-session in near-real-time.

**Conditional Access.** Entra policy deciding whether to honor an authentication
based on user, device, location, and risk.

**Credential Guard.** Uses VBS to hold long-lived credentials in a VTL1 trustlet
(`LsaIso.exe`) so a compromised VTL0 cannot read them.

**DPAPI (Data Protection API).** Windows' standard per-user secret encryption at
rest, keyed off the user's credentials.

**EKU (Extended Key Usage).** An OID in an Authenticode signature constraining
what the signed binary may do; trustlets require two specific Microsoft EKUs.

**Entra ID.** Microsoft's cloud identity provider (formerly Azure AD).

**HVCI (Hypervisor-Enforced Code Integrity).** Uses the hypervisor to guarantee
kernel code pages are signed and immutable and writable pages non-executable.

**Hypervisor.** The layer beneath the NT kernel that creates the VTLs; the bottom
of the on-box TCB once VBS is on.

**Kerberoasting.** Requesting a service ticket for any SPN and cracking its
encrypted portion offline to recover a weak service-account password (ATT&CK
T1558.003).

**KDC (Key Distribution Center).** The domain controller service that issues
Kerberos TGTs and service tickets.

**LSASS (`lsass.exe`).** The Local Security Authority Subsystem; performs
authentication and historically held the secrets it used.

**Measured boot.** Recording each boot stage into the TPM's PCRs (remembering),
as distinct from Secure Boot (preventing).

**NTOWF / NTLM hash.** The MD4 of the user's password; password-equivalent, hence
Pass-the-Hash.

**Pass-the-Hash / Pass-the-Ticket / Pass-the-PRT.** Authenticating by replaying a
stolen credential artifact (the NT hash, a Kerberos ticket, or a cloud Primary
Refresh Token) without the password.

**PCR (Platform Configuration Register).** A TPM register you can only extend
(hash-chain), forming a tamper-evident summary of the boot.

**Pluton.** A Microsoft security processor integrated on the CPU die and updatable
through Windows Update.

**PPL (Protected Process Light).** NT-kernel process protection (e.g. `RunAsPPL`
for LSASS); complementary to, not a substitute for, Credential Guard.

**PRT (Primary Refresh Token).** The cloud analog of the long-term credential,
issued to a joined device and (on capable hardware) bound to a TPM key.

**RBCD (Resource-Based Constrained Delegation).** A Kerberos delegation feature
abusable to mint service tickets as any user when an attacker can write the target
computer object's delegation attribute.

**Root of trust.** The one component whose trustworthiness is assumed because
nothing beneath it can verify it; on Windows, in silicon.

**Secure Boot.** Firmware refusing to run improperly signed bootloaders/firmware.

**Secure Kernel.** The small kernel running in VTL1; hosts the trustlets.

**Sealing.** Encrypting a secret under a TPM policy so it unseals only when the
PCRs match a specified state (e.g. BitLocker).

**SLAT (Second-Level Address Translation).** The CPU feature the hypervisor uses
to make VTL1 memory unmappable from VTL0.

**SSP (Security Support Provider).** A pluggable authentication-protocol module in
LSASS (NTLM, Kerberos, `cloudap`, Schannel).

**TCB (Trusted Computing Base).** The set of components that must be correct for a
security guarantee to hold; the chain works to shrink it.

**TGT (Ticket-Granting Ticket).** The Kerberos credential, obtained from the KDC,
exchanged for per-service tickets.

**TPM (Trusted Platform Module).** A tamper-resistant chip/enclave holding keys,
performing fixed crypto, and measuring the boot.

**Trustlet.** A Microsoft-signed user-mode process running in VTL1 (e.g.
`LsaIso.exe`); `LsaIso` is Trustlet ID 1.

**VBS (Virtualization-Based Security).** Using the hypervisor to create the
isolated VTL1 secure world.

**VTL0 / VTL1.** Virtual Trust Levels: the normal world (kernel, drivers, your
code) and the secure world the hypervisor isolates from it.

**VSM master key.** A VTL1-only key, TPM-sealed under PCR policy, that wraps any
persistent trustlet state.
