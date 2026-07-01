# References

1. Martin Smolar (2023). *BlackLotus UEFI bootkit: Myth confirmed*. <https://www.welivesecurity.com/2023/03/01/blacklotus-uefi-bootkit-myth-confirmed/> Accessed 2026-05-09. March 1, 2023 ESET writeup; signed-but-unrevoked epitaph; HVCI/BitLocker/Defender disablement.
2. Thomas Lambertz (2024). *BitLocker: Screwed without a screwdriver*. <https://neodyme.io/en/blog/bitlocker_screwed_without_a_screwdriver/> Accessed 2026-05-09. 38C3 (December 2024) Bitpixie writeup; Rairii August 2022 discovery.
3. Wack0. *CVE-2022-21894 (Baton Drop)*. [https://github.com/Wack0/CVE-2022-21894](https://github.com/Wack0/CVE-2022-21894) Accessed 2026-05-09. Truncatememory abuse; Baton Drop technical primitive.
4. Martin Smolar, Peter Strycek (2024). *Bootkitty: Analyzing the first UEFI bootkit for Linux*. <https://www.welivesecurity.com/en/eset-research/bootkitty-analyzing-first-uefi-bootkit-linux/> Accessed 2026-05-09. November 27, 2024 ESET research; the BoB attribution update of December 2, 2024; Allievi 2012 anchor.
5. Binarly REsearch (2024). *LogoFAIL Exploited to Deploy Bootkitty*. <https://www.binarly.io/blog/logofail-exploited-to-deploy-bootkitty-the-first-uefi-bootkit-for-linux> Accessed 2026-05-09. Bootkitty exploits CVE-2023-40238 to inject MOK certs from a malicious BMP.
6. Microsoft. *Microsoft Pluton security processor*. <https://learn.microsoft.com/en-us/windows/security/hardware-security/pluton/microsoft-pluton-security-processor> Accessed 2026-05-09. Pluton silicon list and Windows Update firmware path; Rust-based foundation on 2024+ AMD/Intel parts.
7. Microsoft. *Pluton as TPM*. <https://learn.microsoft.com/en-us/windows/security/hardware-security/pluton/pluton-as-tpm> Accessed 2026-05-09. Pluton implements TPM 2.0 functionality and is the silicon root of trust.
8. Sergey Golovanov, Igor Soumenkov (2011). *TDL4: Top Bot*. <https://securelist.com/tdl4-top-bot/36152/> Accessed 2026-05-09. Canonical Kaspersky SecureList post on TDL-4; reports 4,524,488 infections in the first three months of 2011 (post-ID 36152, distinct from the 2005 slug-collision at /36060/).
9. Microsoft. *Secure the Windows boot process*. <https://learn.microsoft.com/en-us/windows/security/operating-system-security/system-security/secure-the-windows-10-boot-process> Accessed 2026-05-09. Microsoft Learn overview of the Trusted Boot quartet and the SRTM event log.
10. Microsoft. *Trusted Boot*. <https://learn.microsoft.com/en-us/windows/security/operating-system-security/system-security/trusted-boot> Accessed 2026-05-09. Canonical Microsoft definition: bootloader verifies the kernel; the kernel verifies every other boot component.
11. IBM. *IBM Personal Computer Technical Reference*. <https://dn790002.ca.archive.org/0/items/bitsavers_ibmpcpc602renceAug81_17295874/6025008_PC_Technical_Reference_Aug81.pdf> Accessed 2026-05-09. Original IBM PC BIOS technical reference; bootstrap loader checks AA55h, loads the boot sector at 0000:7C00, and passes control to it.
12. Wikipedia. *Stoned (computer virus)*. <https://en.wikipedia.org/wiki/Stoned_(computer_virus)> Accessed 2026-05-09. 1987 boot sector virus, Wellington student attribution.
13. F-Secure. *Brain*. <https://www.f-secure.com/v-descs/brain> Accessed 2026-05-09. 1986 Brain boot-sector virus text identifies Brain Computer Services in Lahore, Pakistan; infection hooks INT 13h and hides infected boot sectors.
14. ESET. *Malware of the 90s: Remembering the Michelangelo and Melissa viruses*. <https://www.welivesecurity.com/2018/11/12/malware-90s-michelangelo-melissa-viruses/> Accessed 2026-05-09. Michelangelo discovered in 1991; infects hard-disk MBRs and floppy boot sectors; Stoned variant with a March 6 destructive payload.
15. Derek Soeder, Ryan Permeh (2005). *eEye BootRoot*. <https://www.blackhat.com/presentations/bh-usa-05/bh-us-05-soeder.pdf> Accessed 2026-05-09. Black Hat USA 2005 BootRoot slides.
16. Vipin Kumar, Nitin Kumar. *Vbootkit 2.0 (April 2007 release page, archived)*. [https://web.archive.org/web/20211027223059/https://nvlabs.in/vkumar/vbootkit](https://web.archive.org/web/20211027223059/https://nvlabs.in/vkumar/vbootkit) Accessed 2026-05-09. Wayback Machine snapshot of the original NVlabs Vbootkit project page; dates the release to April 2007 and identifies Vipin and Nitin Kumar as authors.
17. Brett Stone-Gross et al. *Your Botnet is My Botnet: Analysis of a Botnet Takeover*. <https://web.stanford.edu/class/cs114/readings/JO-Stone-Gross.pdf> Accessed 2026-05-09. Torpig/Sinowal botnet analysis; Mebroot replaces the system MBR and executes before the operating system.
18. Marco Giuliani / Webroot (2011). *Mebromi: the first BIOS rootkit in the wild*. [https://web.archive.org/web/20110924155423/http://blog.webroot.com/2011/09/13/mebromi-the-first-bios-rootkit-in-the-wild/](https://web.archive.org/web/20110924155423/http://blog.webroot.com/2011/09/13/mebromi-the-first-bios-rootkit-in-the-wild/) Accessed 2026-06-09. Webroot analysis of Mebromi's Award BIOS, CBROM, SMI-port flashing, and MBR reinfection mechanics.
19. *"Who Is This Code?" — The Quiet 33-Year Reinvention of App Identity in Windows*. 2026. <https://paragmali.com/blog/windows-app-identity-33-year-reinvention/>. Accessed 2026-05-10. Sibling article on Authenticode, AppContainer, Package SID derivation, and the layered code-identity stack.
20. TianoCore. *PI Boot Flow*. [https://github.com/tianocore/tianocore.github.io/wiki/PI-Boot-Flow](https://github.com/tianocore/tianocore.github.io/wiki/PI-Boot-Flow) Accessed 2026-05-09. Canonical SEC → PEI → DXE → BDS phase descriptions.
21. Intel. *Intel Trusted Execution Technology Software Development Guide*. <https://cdrdv2-public.intel.com/315168/315168_TXT_MLE_DG_rev_017_7.pdf> Accessed 2026-05-09. Intel TXT GETSEC[SENTER] and TPM locality 4/PCR measured-launch mechanics.
22. IOActive. *Exploring AMD Platform Secure Boot*. <https://www.ioactive.com/exploring-amd-platform-secure-boot/> Accessed 2026-05-09. AMD PSB chain of trust; vendor-misconfiguration finding.
23. AMD. *AMD Strengthens Security Solutions Through Technology Partnership With ARM*. <https://ir.amd.com/news-events/press-releases/detail/385/amd-strengthens-security-solutions-through-technology-partnership-with-arm> Accessed 2026-05-09. AMD announcement of ARM TrustZone integration and a platform security processor using an ARM Cortex-A5 CPU, with 2013 development platforms.
24. ESET Research (2018). *LoJax: First UEFI rootkit found in the wild*. <https://www.welivesecurity.com/2018/09/27/lojax-first-uefi-rootkit-found-wild-courtesy-sednit-group/> Accessed 2026-05-09. September 27, 2018 first in-the-wild UEFI rootkit; Sednit/Fancy Bear; Boot Guard remediation guidance.
25. Microsoft. *OEM UEFI*. <https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/oem-uefi> Accessed 2026-05-09. UEFI 2.3.1 as the WHCP firmware floor for Windows 10 security features.
26. NIST (2011). *NIST SP 800-147: BIOS Protection Guidelines*. <https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-147.pdf> Accessed 2026-05-09. April 2011 BIOS-update signing baseline.
27. Microsoft. *OEM Secure Boot*. <https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/oem-secure-boot> Accessed 2026-05-09. WHCP firmware-signing floor (RSA-2048 + SHA-256) and the PK/KEK/db/dbx hierarchy.
28. Microsoft. *PE Format (Portable Executable and Common Object File Format Specification)*. <https://learn.microsoft.com/en-us/windows/win32/debug/pe-format> Accessed 2026-05-09. Canonical Microsoft PE/COFF specification; describes the Attribute Certificate Table and notes that the Authenticode image digest must exclude the Checksum and Certificate Table entry in Optional Header Data Directories.
29. rhboot/shim contributors. *SBAT: Secure Boot Advanced Targeting*. [https://github.com/rhboot/shim/blob/main/SBAT.md](https://github.com/rhboot/shim/blob/main/SBAT.md) Accessed 2026-05-09. BootHole event consumed ~10 kB of ~32 kB dbx; generation-number revocation design.
30. Microsoft (2025). *Windows Secure Boot certificate expiration and CA updates (KB5062710)*. <https://support.microsoft.com/en-us/topic/windows-secure-boot-certificate-expiration-and-ca-updates-7ff40d33-95dc-4c3c-8725-a9b95457578e> Accessed 2026-06-10. Certificate table: Microsoft Windows Production PCA 2011 expires 19 October 2026; Microsoft UEFI CA 2011 expires 27 June 2026.
31. Microsoft (2023). *KB5025885: How to manage the Windows Boot Manager revocations for Secure Boot changes associated with CVE-2023-24932*. <https://support.microsoft.com/help/5025885> Accessed 2026-05-09. May 9, 2023 published; July 2024 mitigations; July 2025 enforcement; opt-in irreversibility caution.
32. Matthew Garrett (2012). *shim release note*. <https://mjg59.dreamwidth.org/20303.html> Accessed 2026-06-09. November 30, 2012 shim release; documents MOK enrolment and credits SUSE engineers with the MOK concept and implementation work.
33. z3bra. *Elysium bootkit -- writing a Windows bootkit*. <https://z3bra.cat/posts/elysium-bootkit/> Accessed 2026-05-09. Reverse-engineered call chain: OslLoadDrivers → OslLoadImage → LdrpLoadImage → BlImgLoadPEImageEx → ImgpLoadPEImage → ImgpValidateImageHash inside winload.efi bootlib.
34. Geoff Chappell. *LOADER_PARAMETER_EXTENSION*. <https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/arc/loader_parameter_extension/index.htm> Accessed 2026-05-09. The under-documented loader-to-kernel handoff structure that carries validated SiPolicy across the boundary.
35. n4r1b. *Smart App Control Internals -- Part 1*. <https://n4r1b.com/posts/2022/08/smart-app-control-internals-part-1/> Accessed 2026-05-09. CodeIntegrityData / CodeIntegrityDataSize fields added to LOADER_PARAMETER_EXTENSION in Windows 11 22H2 to carry serialised CI state across the loader/kernel boundary.
36. SySS Research (2024). *Bitpixie: Defeating BitLocker through unverified PXE boot*. <https://blog.syss.com/posts/bitpixie/> Accessed 2026-05-09. PCR allocation table; SHA-256 extend formula; downgrade attack flow.
37. Trusted Computing Group. *Trusted Computing Group Releases TPM 2.0 Specification for Improved Platform and Device Security*. [https://web.archive.org/web/20170823111717/https://trustedcomputinggroup.org/trusted-computing-group-releases-tpm-2-0-specification-improved-platform-device-security/](https://web.archive.org/web/20170823111717/https://trustedcomputinggroup.org/trusted-computing-group-releases-tpm-2-0-specification-improved-platform-device-security/) Accessed 2026-05-09. Archived TCG announcement for TPM 2.0 specification availability on April 9, 2014.
38. Microsoft. *Trusted Platform Module Technology Overview*. <https://learn.microsoft.com/en-us/windows/security/hardware-security/tpm/trusted-platform-module-overview> Accessed 2026-06-09. Microsoft overview of TPM integrity measurements and TPM-bound keys.
39. *The TPM in Windows: One Primitive, Twenty-Five Years, and the Chip Microsoft Bet On Twice* (2026). <https://paragmali.com/blog/the-tpm-in-windows-one-primitive-twenty-five-years-and-the-c/> Note: The prior article in this series; its conclusions on dTPM, Intel PTT, and AMD fTPM are required reading here.
40. Microsoft. *How hardware-based root of trust helps protect Windows*. <https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-system-guard/how-hardware-based-root-of-trust-helps-protect-windows> Accessed 2026-05-09. SRTM allowlist explosion; DRTM late-launch via Secure Launch in Windows 10 1809+.
41. *BitLocker on Windows: Architecture, Attacks, and the Limits of Full-Disk Encryption*. <https://paragmali.com/blog/bitlocker-on-windows-architecture-attacks-and-the-limits-of-/> Accessed 2026-05-09. Sibling article; VMK/FVEK key hierarchy; TPM-only protector mechanics.
42. Microsoft. *Early Launch Antimalware*. <https://learn.microsoft.com/en-us/windows-hardware/drivers/install/early-launch-antimalware> Accessed 2026-05-09. ELAM ordering, PPL execution, classification surface for boot-start drivers.
43. Microsoft. *ELAM driver requirements*. <https://learn.microsoft.com/en-us/windows-hardware/drivers/install/elam-driver-requirements> Accessed 2026-05-09. INF requirements for an ELAM driver; verbatim three-class prose ("known good binary, known bad binary, or an unknown binary") plus the Early-Launch service-group requirement.
44. Microsoft. *_BDCB_CLASSIFICATION enumeration (ntddk.h)*. <https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/ne-ntddk-_bdcb_classification> Accessed 2026-06-09. Microsoft WDK enum reference listing ELAM boot-start image classifications, including `BdCbClassificationKnownBadImageBootCritical`.
45. Microsoft. *Kernel DMA Protection (Thunderbolt / USB4 / CFexpress)*. <https://learn.microsoft.com/en-us/windows/security/hardware-security/kernel-dma-protection-for-thunderbolt> Accessed 2026-05-09. Kernel DMA Protection blocks DMA from PCIe hot-plug peripherals using the system IOMMU until an authorized user signs in or unlocks the screen.
46. *When SYSTEM Isn't Enough: The Windows Secure Kernel and the End of Total Kernel Trust*. 2026. <https://paragmali.com/blog/the-windows-secure-kernel/>. Accessed 2026-05-10. Sibling article on VBS / IUM / VTL0-VTL1, Trustlet API, Credential Guard, HVCI.
47. *No Secrets to Steal: How Windows Hello Eliminated the Shared Secret*. <https://paragmali.com/blog/your-face-is-not-your-password-inside-windows-hellos-hardwar/> Accessed 2026-05-09. Sibling article; Windows Hello, TPM-backed biometrics, FIDO2 / passkeys mechanism.
48. AMD (2022). *AMD Unveils New Ryzen Mobile Processors Uniting "Zen 3+" core with AMD RDNA 2 Graphics in Powerhouse Design*. <https://ir.amd.com/news-events/press-releases/detail/1039/amdunveils-new-ryzen-mobile-processors-uniting-zen-3-core-with-amd-rdna-2-graphics-in-powerhousedesign> Accessed 2026-06-09. January 4, 2022 Ryzen 6000 launch; states Ryzen 6000 processors integrated the Microsoft Pluton security processor.
49. David Weston — *Meet the Microsoft Pluton processor — The security chip designed for the future of Windows PCs* (2020). <https://www.microsoft.com/en-us/security/blog/2020/11/17/meet-the-microsoft-pluton-processor-the-security-chip-designed-for-the-future-of-windows-pcs/> Note: November 17, 2020 announcement; AMD, Intel, Qualcomm partnership; SHACK; Cerberus complementarity.
50. Martin Smolar, Anton Cherepanov (2021). *UEFI threats moving to the ESP: Introducing ESPecter bootkit*. <https://www.welivesecurity.com/2021/10/05/uefi-threats-moving-esp-introducing-especter-bootkit/> Accessed 2026-05-09. October 5, 2021 ESET disclosure of ESPecter; ESP-resident bootkit category.
51. Kaspersky GReAT (2021). *FinSpy: unseen findings*. <https://securelist.com/finspy-unseen-findings/104322/> Accessed 2026-05-09. September 2021 first public analysis of a real-world UEFI bootkit replacing bootmgfw.efi.
52. Microsoft DART/MSTIC (2023). *Guidance for investigating attacks using CVE-2022-21894: the BlackLotus campaign*. <https://www.microsoft.com/en-us/security/blog/2023/04/11/guidance-for-investigating-attacks-using-cve-2022-21894-the-blacklotus-campaign/> Accessed 2026-05-09. April 11, 2023 incident-response guide; six BlackLotus forensic artefact classes.
53. NSA, CISA (2023). *BlackLotus Mitigation Guide*. <https://media.defense.gov/2023/Jun/22/2003245723/-1/-1/0/CSI_BlackLotus_Mitigation_Guide.PDF> Accessed 2026-05-09. June 22, 2023 joint US government cybersecurity information sheet.
54. The Register (2012). *Researcher creates proof-of-concept Win 8 UEFI rootkit*. <https://www.theregister.com/2012/09/19/win8_rootkit/> Accessed 2026-05-09. September 19, 2012 reporting of the Allievi/ITSEC PoC.
55. Binarly REsearch (2023). *The Far-Reaching Consequences of LogoFAIL*. <https://www.binarly.io/blog/far-reaching-consequences-of-logofail> Accessed 2026-06-09. Original LogoFAIL disclosure describing image-parser vulnerabilities across AMI, Insyde, and Phoenix firmware and BMP/GIF/JPEG/PCX/TGA parser exposure.
56. NIST NVD. *CVE-2024-20666: BitLocker Security Feature Bypass Vulnerability*. <https://nvd.nist.gov/vuln/detail/CVE-2024-20666> Accessed 2026-05-09. NVD entry establishing the CVE and BitLocker security-feature-bypass classification.
57. Heise (2025). *Attack bypasses BitLocker using Windows Recovery Environment*. <https://www.heise.de/en/news/Attack-bypasses-BitLocker-using-Windows-Recovery-Environment-11292729.html> Accessed 2026-06-09. Technical reporting on WinRE/BitLocker downgrade attacks using older signed `bootmgfw.efi` and the PCA-2011 to CA-2023 migration.
58. Microsoft (2024). *KB5034957: Updating the WinRE partition on deployed devices to address security vulnerabilities in CVE-2024-20666*. <https://support.microsoft.com/en-us/topic/kb5034957-updating-the-winre-partition-on-deployed-devices-to-address-security-vulnerabilities-in-cve-2024-20666-0190331b-1ca3-42d8-8a55-7fc406910c10> Accessed 2026-06-09. Microsoft guidance tying CVE-2024-20666 mitigation to WinRE partition updates.
59. NVD (2023). *CVE-2023-24932 -- Secure Boot Security Feature Bypass Vulnerability*. <https://nvd.nist.gov/vuln/detail/CVE-2023-24932> Accessed 2026-05-09. NVD entry for the KB5025885 paired CVE.
60. Microsoft. *microsoft/secureboot_objects*. [https://github.com/microsoft/secureboot_objects](https://github.com/microsoft/secureboot_objects) Accessed 2026-05-09. Canonical KEK/db/dbx distribution since 2024.
61. Apple. *Boot process for an Apple device*. <https://support.apple.com/guide/security/boot-process-secb3000f149/web> Accessed 2026-05-09. Apple application-processor boot chain: Boot ROM → LLB (legacy) → iBoot → kernel; Apple Root CA public key in Boot ROM.
62. Apple. *Secure Enclave*. <https://support.apple.com/guide/security/secure-enclave-sec59b0b31ff/web> Accessed 2026-05-09. Secure Enclave Processor as a dedicated subsystem integrated into Apple SoC; sepOS L4 microkernel; mailbox interface.
63. Apple. *System security overview*. <https://support.apple.com/guide/security/system-security-overview-sec114e4db04/web> Accessed 2026-05-09. Apple secure-boot continuity model: silicon-rooted chain of trust through software, including Secure Enclave secure boot.
64. Trusted Firmware-A project. *Trusted Firmware-A*. <https://trustedfirmware-a.readthedocs.io/en/latest/> Accessed 2026-05-09. Reference secure-world software for Armv7-A and Armv8-A platforms; Secure Monitor at EL3; PSCI / TBBR / SMC Calling Convention.
65. Trusted Firmware-A. *Trusted Board Boot*. <https://trustedfirmware-a.readthedocs.io/en/latest/design/trusted-board-boot.html> Accessed 2026-05-09. Trusted Board Boot Requirements (TBBR, Arm DEN0006D) and the BL1 → BL2 → BL31/BL32 → BL33 chain anchored on the ROTPK fused per silicon family.
66. Microsoft — *Introducing Windows 11* (2021). <https://blogs.windows.com/windowsexperience/2021/06/24/introducing-windows-11/>
67. David Weston — *Windows 11 enables security by design from the chip to the cloud*. <https://www.microsoft.com/en-us/security/blog/2021/06/25/windows-11-enables-security-by-design-from-the-chip-to-the-cloud/>
68. Microsoft — *TPM 2.0 -- OEM mandate*. <https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/oem-tpm>
69. Richard Stallman — *Can You Trust Your Computer?*. <https://www.gnu.org/philosophy/can-you-trust.html>
70. Gates Ushers in Next Generation of PC Computing With Launch of Windows 2000 — Microsoft News Center; 2000. <https://news.microsoft.com/source/2000/02/17/gates-ushers-in-next-generation-of-pc-computing-with-launch-of-windows-2000/>
71. Microsoft — *Cryptography portal (Win32)*. <https://learn.microsoft.com/en-us/windows/win32/seccrypto/cryptography-portal>
72. Microsoft — *How Windows uses the TPM*. <https://learn.microsoft.com/en-us/windows/security/hardware-security/tpm/how-windows-uses-the-tpm>
73. Wikipedia contributors — *Trusted Computing Group*. <https://en.wikipedia.org/wiki/Trusted_Computing_Group>
74. Trusted Computing Group — *TPM Main Specification (Version 1.2)*. <https://trustedcomputinggroup.org/resource/tpm-main-specification/>
75. Johns Hopkins APL Technical Digest — *Trusted Platform Module Evolution*. <https://secwww.jhuapl.edu/techdigest/Content/techdigest/pdf/V32-N02/32-02-Osborn.pdf>
76. Paul England, Butler Lampson, John Manferdelli, Marcus Peinado, Bryan Willman — *A Trusted Open Platform*. <https://www.microsoft.com/en-us/research/publication/trusted-open-platform/>
77. Microsoft — *Secure Startup-Full Volume Encryption: Technical Overview*. <https://download.microsoft.com/download/5/D/6/5D6EAF2B-7DDF-476B-93DC-7CF0072878E6/secure-start_tech.doc>
78. Denis Andzakovic — *Extracting BitLocker keys from a TPM*. <https://pulsesecurity.co.nz/articles/TPM-sniffing>
79. Microsoft — *BitLocker overview*. <https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/>
80. Elaine Barker, Allen Roginsky — *NIST SP 800-131A Rev. 2 -- Transitioning the Use of Cryptographic Algorithms and Key Lengths*. <https://csrc.nist.gov/pubs/sp/800/131/a/r2/final>
81. Marc Stevens, Elie Bursztein, Pierre Karpman, Ange Albertini, and Yarik Markov. *Announcing the first SHA1 collision*. <https://security.googleblog.com/2017/02/announcing-first-sha1-collision.html>
82. Microsoft — *Microsoft Announces the Release of Windows NT Workstation 4.0*. <https://news.microsoft.com/source/1996/07/31/microsoft-announces-the-release-of-windows-nt-workstation-4-0/>
83. Trusted Computing Group — *TPM 2.0 Library Specification*. <https://trustedcomputinggroup.org/resource/tpm-library-specification/>
84. ISO/IEC — *ISO/IEC 11889-1:2015 -- Information technology -- Trusted platform module library -- Part 1: Architecture*. <https://www.iso.org/standard/66510.html>
85. Will Arthur, David Challener, Kenneth Goldman — *A Practical Guide to TPM 2.0*. <https://link.springer.com/book/10.1007/978-1-4302-6584-9>
86. Microsoft — *Measured boot and host attestation*. <https://learn.microsoft.com/en-us/azure/security/fundamentals/measured-boot-host-attestation>
87. Configure Credential Guard / Virtualization-based security (overview). <https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/>
88. Microsoft — *How Windows Hello for Business works*. <https://learn.microsoft.com/en-us/windows/security/identity-protection/hello-for-business/how-it-works>
89. Microsoft — *TPM key attestation*. <https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/tpm-key-attestation>
90. Denis Andzakovic — *lpc_sniffer_tpm*. [https://github.com/denandz/lpc_sniffer_tpm](https://github.com/denandz/lpc_sniffer_tpm)
91. Henri Nurmi — *Sniff There, Leaks My BitLocker Key* (2022). <https://labs.withsecure.com/publications/sniff-there-leaks-my-bitlocker-key>
92. Thomas Dewaele, Julien Oberson — *TPM sniffing*. <https://blog.scrt.ch/2021/11/15/tpm-sniffing/>
93. SCRT — *Privilege escalation through TPM sniffing when BitLocker PIN is enabled*. <https://blog.scrt.ch/2024/10/28/privilege-escalation-through-tpm-sniffing-when-bitlocker-pin-is-enabled/>
94. Intel — *Intel NUC 13 Extreme Technical Product Specification*. <https://www.intel.com/content/dam/support/us/en/documents/intel-nuc/NUC13SB-RN_TechProdSpec.pdf>
95. Daniel Moghimi, Berk Sunar, Thomas Eisenbarth, Nadia Heninger — *TPM-Fail*. <https://tpm.fail/>
96. NIST NVD — *CVE-2019-11090 -- Intel PTT timing leak (TPM-Fail)*. <https://nvd.nist.gov/vuln/detail/CVE-2019-11090>
97. NIST NVD — *CVE-2019-16863 -- STMicroelectronics ST33 TPM-FAIL*. <https://nvd.nist.gov/vuln/detail/CVE-2019-16863>
98. Daniel Moghimi, Berk Sunar, Thomas Eisenbarth, Nadia Heninger — *TPM-FAIL: TPM meets Timing and Lattice Attacks*. <https://www.usenix.org/conference/usenixsecurity20/presentation/moghimi>
99. Hans Niklas Jacob, Christian Werling, Robert Buhren, Jean-Pierre Seifert — *faulTPM: Exposing AMD fTPMs Deepest Secrets* (2023). <https://arxiv.org/abs/2304.14717>
100. PSPReverse — *ftpm_attack -- proof-of-concept code for faulTPM*. [https://github.com/PSPReverse/ftpm_attack](https://github.com/PSPReverse/ftpm_attack)
101. AMD — *TPM Attestation Failure on AMD Platforms with ASP fTPM*. <https://www.amd.com/en/resources/support-articles/faqs/pa-420.html>
102. Microsoft — *Trusted launch for Azure VMs*. <https://learn.microsoft.com/en-us/azure/virtual-machines/trusted-launch>
103. Microsoft Security — *Microsoft and partners design new device security requirements to protect against targeted firmware attacks*. <https://www.microsoft.com/en-us/security/blog/2019/10/21/microsoft-and-partners-design-new-device-security-requirements-to-protect-against-targeted-firmware-attacks/>
104. *System Guard Secure Launch and SMM protection* (2026-05-10). Microsoft Learn. <https://learn.microsoft.com/en-us/windows/security/hardware-security/system-guard-secure-launch-and-smm-protection>
105. *BitLocker Countermeasures (Microsoft Learn)*, 2024. <https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/countermeasures>
106. Microsoft Learn — *Get-Tpm*. <https://learn.microsoft.com/en-us/powershell/module/trustedplatformmodule/get-tpm>
107. NIST NVD — *CVE-2023-21563 -- BitLocker Security Feature Bypass*. <https://nvd.nist.gov/vuln/detail/CVE-2023-21563>
108. NIST — *FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard (ML-KEM)*. <https://csrc.nist.gov/pubs/fips/203/final>
109. NIST — *FIPS 204: Module-Lattice-Based Digital Signature Standard (ML-DSA)*. <https://csrc.nist.gov/pubs/fips/204/final>
110. NIST — *FIPS 205: Stateless Hash-Based Digital Signature Standard (SLH-DSA)*. <https://csrc.nist.gov/pubs/fips/205/final>
111. NIST — *Post-Quantum Cryptography project*. <https://csrc.nist.gov/projects/post-quantum-cryptography>
112. U.S. Federal Register — *Announcing Issuance of Federal Information Processing Standards (FIPS) -- FIPS 203, 204, and 205*. <https://www.federalregister.gov/documents/2024/08/14/2024-17956/announcing-issuance-of-federal-information-processing-standards-fips-fips-203-module-lattice-based>
113. Microsoft — *ms-tpm-20-ref releases*. [https://github.com/microsoft/ms-tpm-20-ref/releases](https://github.com/microsoft/ms-tpm-20-ref/releases)
114. Fraunhofer SIT — *Post-Quantum Cryptography for TPM*. <https://www.sit.fraunhofer.de/en/pqcryptography/post-quantum-cryptography-for-tpm/>
115. Trusted Computing Group — *PC Client Platform TPM Profile (PTP) Specification*. <https://trustedcomputinggroup.org/resource/pc-client-platform-tpm-profile-ptp-specification/>
116. Mike Ounsworth, John Gray, Massimiliano Pala, Jan Klaussner, Scott Fluhrer — *Composite ML-DSA for X.509 (IETF LAMPS WG draft)*. <https://datatracker.ietf.org/doc/draft-ietf-lamps-pq-composite-sigs/>
117. Douglas Stebila, Scott Fluhrer, Shay Gueron — *Hybrid key exchange in TLS 1.3 (IETF TLS WG draft)*. <https://datatracker.ietf.org/doc/draft-ietf-tls-hybrid-design/>
118. Microsoft Security — *Quantum-safe security: Progress towards next-generation cryptography*. <https://www.microsoft.com/en-us/security/blog/2025/08/20/quantum-safe-security-progress-towards-next-generation-cryptography/>
119. CRoCS Masaryk University — *ROCA detection tool*. [https://github.com/crocs-muni/roca](https://github.com/crocs-muni/roca)
120. NIST NVD — *CVE-2017-15361 -- Infineon ROCA*. <https://nvd.nist.gov/vuln/detail/CVE-2017-15361>
121. Wikipedia contributors — *ROCA vulnerability*. <https://en.wikipedia.org/wiki/ROCA_vulnerability>
122. Dan Goodin — *Crypto failure cripples millions of high-security keys, 750k Estonian IDs*. <https://arstechnica.com/information-technology/2017/10/crypto-failure-cripples-millions-of-high-security-keys-750k-estonian-ids/>
123. Microsoft Security Response Center — *MSRC Advisory ADV170012 -- Vulnerability in TPM Could Allow Security Feature Bypass*. <https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/ADV170012>
124. Microsoft — *Continuous access evaluation in Microsoft Entra ID* (2025). <https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-continuous-access-evaluation>
125. Microsoft — *CNG DPAPI (DPAPI-NG)*. <https://learn.microsoft.com/en-us/windows/win32/seccng/cng-dpapi>
126. Microsoft — *DPAPI-NG protection descriptors*. <https://learn.microsoft.com/en-us/windows/win32/seccng/protection-descriptors>
127. Brandon Vigliarolo — *Dell, Lenovo and HP responses to Microsoft Pluton*. <https://www.theregister.com/2022/03/09/dell_pluton_microsoft/>
128. Mark Hachman — *Why the biggest laptop vendors are ignoring Microsoft Pluton security tech* (2022). <https://www.pcworld.com/article/621767/why-the-biggest-laptop-vendors-are-ignoring-microsofts-pluton-security-tech.html>
129. Michael Larabel — *Pluton TPM CRB driver merged for Linux 6.3* (2023). <https://www.phoronix.com/news/Pluton-TPM-CRB-Merged-Linux-6.3>
130. Matthew Garrett — *Bringing Pluton support to Linux* (2022). <https://mjg59.dreamwidth.org/58879.html> Note: AMD Ryzen 6000 / Asus G14 BIOS reverse-engineering; PSP soft-fuse 0xB BIT36; observed Pluton firmware blob appeared to contain chunks of TPM 2.0 reference code and decompiled as ARM.
131. Vijay Sarvepalli — *CERT/CC VU#282450 — TPM 2.0 reference implementation OOB read in CryptHmacSign* (2025). <https://www.kb.cert.org/vuls/id/282450> Note: Anonymous reporter; document author Vijay Sarvepalli; Date Public 2025-06-10.
132. *Anatomy of a secured MCU* (2018). <https://azure.microsoft.com/en-us/blog/anatomy-of-a-secured-mcu/> Note: First publicly verifiable use of the "Pluton" name (April 2018).
133. *From research idea to research-powered product: Behind the scenes with Azure Sphere*. <https://www.microsoft.com/en-us/research/blog/from-research-idea-to-research-powered-product-behind-the-scenes-with-azure-sphere> Note: Codename 4x4 = 4 MB RAM + 4 MB Flash; AI+Research NExT origin (2015).
134. Galen Hunt, George Letey, Edmund Nightingale — *The Seven Properties of Highly Secure Devices* (2017). <https://www.microsoft.com/en-us/research/publication/seven-properties-highly-secure-devices/> Note: MSR-TR-2017-16 (March 2017); the architectural manifesto behind Azure Sphere and Pluton.
135. *Microsoft open-sources effort to build a hardware chip that protects firmware* (2017). <https://siliconangle.com/2017/11/09/microsoft-open-sources-effort-build-hardware-chip-protects-firmware-hackers/>
136. *Project Cerberus — Open Compute Project / Project Olympus*. [https://github.com/opencomputeproject/Project_Olympus/tree/master/Project_Cerberus](https://github.com/opencomputeproject/Project_Olympus/tree/master/Project_Cerberus) Note: Architecture, Challenge Protocol, Firmware Update, HPFR, Processor Cryptography PDFs.
137. *Project Cerberus reference implementation*. [https://github.com/Azure/Project-Cerberus](https://github.com/Azure/Project-Cerberus) Note: Microsoft-maintained Cerberus reference implementation; FreeRTOS and Linux ports.
138. *Project Cerberus (Microsoft Learn)*. <https://learn.microsoft.com/en-us/azure/security/fundamentals/project-cerberus> Note: NIST 800-193 alignment; Platform Firmware Manifest; Azure Host Attestation Service.
139. *NIST SP 800-193: Platform Firmware Resiliency Guidelines* (2018). <https://csrc.nist.gov/pubs/sp/800/193/final>
140. Galen Hunt — *Introducing Microsoft Azure Sphere: Secure and power the intelligent edge* (2018). <https://azure.microsoft.com/en-us/blog/introducing-microsoft-azure-sphere-secure-and-power-the-intelligent-edge/> Note: Azure Sphere preview at RSA 2018 (April 16, 2018); custom silicon "inspired by 15 years of experience and learnings from Xbox".
141. Microsoft Azure Blog — *A secure foundation for IoT, Azure Sphere now generally available* (2020). <https://azure.microsoft.com/en-us/blog/a-secure-foundation-for-iot-azure-sphere-now-generally-available/> Note: February 24, 2020 Azure Sphere general-availability announcement.
142. *Azure Sphere—Microsoft's answer to escalating IoT threats—reaches general availability* (Microsoft Security Blog, 2020). <https://www.microsoft.com/en-us/security/blog/2020/02/24/azure-sphere-microsoft-answer-iot-threats-reaches-general-availability/>
143. *AMD Platform Security Processor (Wikipedia)*. <https://en.wikipedia.org/wiki/AMD_Platform_Security_Processor>
144. Michael Larabel — *AMD Ryzen 6000 to ship with Microsoft Pluton* (2022). <https://www.phoronix.com/news/AMD-Ryzen-6000-Pluton>
145. AMD — *AMD Unveils New Ryzen Mobile Processors Uniting "Zen 3+" core with AMD RDNA 2 Graphics* (2022). <https://www.amd.com/en/newsroom/press-releases/2022-1-4-amd-unveils-new-ryzen-mobile-processors-uniting-z.html> Note: AMD's January 4, 2022 announcement; states Ryzen 6000 Series integrated the Microsoft Pluton security processor.
146. *Caliptra: open-source datacenter Root of Trust*. [https://github.com/chipsalliance/Caliptra](https://github.com/chipsalliance/Caliptra) Note: Datacenter-class on-die RTM IP; CHIPS Alliance source stewardship.
147. *Caliptra specification (CHIPS Alliance Pages)*. <https://chipsalliance.github.io/Caliptra/>
148. *TPMScan: a wide-scale study of security-relevant properties of TPM 2.0 chips* (2024). <https://crocs.fi.muni.cz/_media/publications/pdf/2024-ches-tpmscan.pdf> Note: CHES 2024.
149. Petr Svenda, Antonin Dufka, Milan Broz, Roman Lacko, Tomas Jaros, Daniel Zatovic, Josef Pospisil — *TPMScan: A wide-scale study of security-relevant properties of TPM 2.0 chips* (2024). <https://tches.iacr.org/index.php/TCHES/article/view/11444> Note: IACR TCHES vol. 2024 issue 2 pp. 714-734; DOI 10.46586/tches.v2024.i2.714-734; iTPM corpus includes Pluton-based iTPMs.
150. *Tock embedded operating system*. [https://github.com/tock/tock](https://github.com/tock/tock)
151. *Linux 6.3 Pluton TPM CRB merge commit*. <https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=219ac97a486c1ad9c110cb96ebdad7ba068236fb>
152. *The Secure Enclave (Apple Platform Security)*. <https://support.apple.com/guide/security/the-secure-enclave-sec59b0b31ff/web> Note: Cross-confirmation source for Apple SEP universal-deployment scope across iPhone 5s+, iPad Air+, and Apple-silicon Mac generations.
153. *Apple T2 (Wikipedia)*. <https://en.wikipedia.org/wiki/Apple_T2>
154. *Titan M makes Pixel 3 our most secure phone yet* (2018). <https://blog.google/products-and-platforms/devices/pixel/titan-m-makes-pixel-3-our-most-secure-phone-yet/>
155. *Pixel 6: Setting a new standard for mobile security* (2021). <https://security.googleblog.com/2021/10/pixel-6-setting-new-standard-for-mobile.html> Note: Google Online Security Blog post on Titan M2 / Pixel 6 (October 2021); in-house RISC-V security chip with AVA_VAN.5 target.
156. *OpenTitan*. <https://opentitan.org/>
157. *OpenTitan reaches commercial availability (lowRISC)* (2024). <https://lowrisc.org/news/opentitan-commercial-availability/> Note: February 13, 2024; nine coalition members; lowRISC = host.
158. *NVD CVE-2025-2884* (2025). <https://nvd.nist.gov/vuln/detail/CVE-2025-2884> Note: CryptHmacSign OOB read in TCG TPM 2.0 reference (Level 00, Revision 01.83).
159. *Intel Security Advisory SA-01209*. <https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-01209.html>
160. *Siemens SSA-628843*. <https://cert-portal.siemens.com/productcert/html/ssa-628843.html>
161. *CVE-2025-49133 (libtpms)*. <https://www.cve.org/CVERecord?id=CVE-2025-49133>
162. *libtpms commit 04b2d8e9 (CVE-2025-49133)*. [https://github.com/stefanberger/libtpms/commit/04b2d8e9afc0a9b6bffe562a23e58c0de11532d1](https://github.com/stefanberger/libtpms/commit/04b2d8e9afc0a9b6bffe562a23e58c0de11532d1)
163. *TCG VRT0009 Advisory*. <https://trustedcomputinggroup.org/wp-content/uploads/VRT0009-Advisory-FINAL.pdf>
164. *IETF Key Transparency (KEYTRANS) Working Group*. <https://datatracker.ietf.org/wg/keytrans/about/> Note: Active IETF working group on transparency-logged identity keys; the closest active venue for the multi-signer transparency thread, although KEYTRANS scope is end-user identity keys, not firmware-signing keys.
165. *Cyber Resilience Act*. <https://digital-strategy.ec.europa.eu/en/policies/cyber-resilience-act> Note: European Commission policy page; verbatim "The CRA entered into force on 10 December 2024. The main obligations introduced by the Act will apply from 11 December 2027, with reporting obligations to apply as of 11 September 2026."
166. *BSI-CC-PP-0084 — Security IC Platform Protection Profile*. <https://www.bsi.bund.de/SharedDocs/Zertifikate_CC/PP/aktuell/PP_0084.html> Note: German BSI Common Criteria PP-0084 (current version PP-0084-V2-2026; 2014 historical version); EAL4 / AVA_VAN.5 baseline used historically for Infineon SLB 9670 / 9672 dTPMs.
167. *DMTF DSP0274 — Security Protocol and Data Model (SPDM)*. <https://www.dmtf.org/dsp/DSP0274> Note: Canonical SPDM 1.3 reference; publication cadence 1.3.0 (Jun 2023) → 1.3.2 (Sep 2024) → 1.3.3 (Dec 2025); content mirror via caliptra-mcu-spdm.
168. *Caliptra MCU SPDM Responder*. <https://chipsalliance.github.io/caliptra-mcu-sw/spdm.html> Note: Rust SPDM 1.3 responder design; X.509v3-anchored mutual auth; canonical mirror of DSP0274 v1.3.2 content.
169. *Caliptra at OCP Global Summit 2024 — 2.0 RTL Design Freeze* (2024). <https://www.chipsalliance.org/news/caliptra-ocp-global-summit-2024/> Note: Caliptra 2.0 RTL freeze October 2024; Dilithium / Kyber commitment; Reference Stack: MCTP PLDM, SPDM.
170. L. Lundblade, G. Mandyam, J. O'Donoghue, C. Wallace — *RFC 9711 — The Entity Attestation Token (EAT)* (2025). <https://datatracker.ietf.org/doc/rfc9711/> Note: Standards Track, April 2025; CWT/JWT evidence/result token format.
171. H. Birkholz, T. Fossati, Y. Deshpande, N. Smith, W. Pan — *draft-ietf-rats-corim-10 — Concise Reference Integrity Manifest*. <https://datatracker.ietf.org/doc/draft-ietf-rats-corim/> Note: In WG Last Call as of March 2026; appraisal-time profile for endorsements + reference values.
172. H. Birkholz, N. Smith, T. Fossati, H. Tschofenig, D. Glaze — *draft-ietf-rats-msg-wrap-23 — Conceptual Message Wrapper*. <https://datatracker.ietf.org/doc/draft-ietf-rats-msg-wrap/> Note: In RFC Editor queue since December 2025; CBOR tag + JWT/CWT claims + X.509 extension envelope.
173. *IETF RATS WG Documents*. <https://datatracker.ietf.org/wg/rats/documents/> Note: Active Internet-Draft inventory: corim-10, msg-wrap-23, multi-verifier-00, posture-assessment-04, EAR-03, epoch-markers-03, pkix-key-attestation-05.
174. *OCP S.A.F.E. — Security Appraisal Framework and Enablement*. [https://github.com/opencomputeproject/OCP-Security-SAFE/blob/main/Documentation/framework.md](https://github.com/opencomputeproject/OCP-Security-SAFE/blob/main/Documentation/framework.md) Note: v2.0 March 2026 added CoRIM SFR support; third-party-audit framework for firmware appraisal.
175. *TCG DICE Architecture Landing Page*. <https://trustedcomputinggroup.github.io/DICE/> Note: Hardware Root of Trust as a component-level identity primitive; UDS / CDI canonical reference.
176. *Open Profile for DICE — Specification v2.6*. <https://pigweed.googlesource.com/open-dice/+/refs/heads/main/docs/specification.md> Note: Reference profile citing TCG DICE; defines UDS / CDI primitives.
177. *BSI-DSZ-CC-1021-V2-2017 — Infineon SLB 9670 EAL4+*. <https://www.bsi.bund.de/SharedDocs/Zertifikate_CC/CC/SmartCards_IC_Cryptolib/1021_1021V2.html> Note: BSI Common Criteria certificate for Infineon SLB 9670 family; EAL4+ ALC_FLR.1 AVA_VAN.4 against TCG TPM PC Client PP; the most recent public CC certification of the Infineon SLB 9670 / 9672 family at that posture.
178. Trusted Computing Group — *TPM 2.0 Library Specification, Part 2: Structures*. <https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-01.38.pdf> Note: Defines the TPM 2.0 structures and permanent properties, including `TPM_PT_MANUFACTURER`, the four-byte manufacturer identifier surfaced by Windows as `ManufacturerIdTxt`.
179. Secured-core PCs (OEM highly secure 11). <https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/oem-highly-secure-11>
180. A Secure and Reliable Bootstrap Architecture. <https://www.cs.umd.edu/~waa/pubs/oakland97.pdf>
181. *Wikipedia: Trusted Platform Module*. <https://en.wikipedia.org/wiki/Trusted_Platform_Module>
182. Tbsi_Get_TCG_Log function (tbs.h). <https://learn.microsoft.com/en-us/windows/win32/api/tbs/nf-tbs-tbsi_get_tcg_log>
183. UEFI Forum specifications index. <https://uefi.org/specifications>
184. NIST SP 800-155 IPD (December 2011 draft PDF). <https://csrc.nist.gov/files/pubs/sp/800/155/ipd/docs/draft-SP800-155_Dec2011.pdf>
185. PC Client Platform Firmware Profile Specification (TCG). <https://trustedcomputinggroup.org/resource/pc-client-specific-platform-firmware-profile-specification/>
186. *Microsoft Learn: Microsoft Azure Attestation overview*. <https://learn.microsoft.com/en-us/azure/attestation/overview>
187. tpm2_eventlog man page. [https://github.com/tpm2-software/tpm2-tools/blob/master/man/tpm2_eventlog.1.md](https://github.com/tpm2-software/tpm2-tools/blob/master/man/tpm2_eventlog.1.md)
188. *How a hardware-based root of trust helps protect Windows* (2026-05-10). Microsoft Learn. <https://learn.microsoft.com/en-us/windows/security/hardware-security/how-hardware-based-root-of-trust-helps-protect-windows>
189. Wack0/bitlocker-attacks index (GitHub). [https://github.com/Wack0/bitlocker-attacks](https://github.com/Wack0/bitlocker-attacks)
190. How to manage the Windows Boot Manager revocations for Secure Boot changes associated with CVE-2023-24932. <https://support.microsoft.com/en-us/topic/how-to-manage-the-windows-boot-manager-revocations-for-secure-boot-changes-associated-with-cve-2023-24932-41a975df-beb2-40c1-99a3-b3ff139f832d>
191. tpmtool. <https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/tpmtool>
192. tpm2-software/tpm2-tools. [https://github.com/tpm2-software/tpm2-tools](https://github.com/tpm2-software/tpm2-tools)
193. *Configure BitLocker (TPM platform validation profile for native UEFI; Microsoft Learn)*, 2024. <https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/configure?tabs=os>
194. manage-bde protectors. <https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/manage-bde-protectors>
195. Attacking Intel Trusted Execution Technology. <https://invisiblethingslab.com/resources/bh09dc/Attacking%20Intel%20TXT%20-%20paper.pdf>
196. TrenchBoot project home. <https://trenchboot.org/>
197. TrenchBoot documentation (GitHub). [https://github.com/TrenchBoot/documentation](https://github.com/TrenchBoot/documentation)
198. Bootstrapping Trust in a "Trusted" Platform. <https://www.usenix.org/legacy/event/hotsec08/tech/full_papers/parno/parno.pdf>
199. *Microsoft Azure Attestation — TPM attestation concepts*. <https://learn.microsoft.com/en-us/azure/attestation/tpm-attestation-concepts>
200. Bryan Parno — faculty page (CMU). <https://www.andrew.cmu.edu/user/bparno/>
201. MSRC advisory for CVE-2023-21563 (bitpixie). <https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-21563>
202. Windows BitLocker: Screwed without a Screwdriver (38C3). <https://events.ccc.de/congress/2024/hub/en/event/windows-bitlocker-screwed-without-a-screwdriver/>
203. martanne/bitpixie proof-of-concept (GitHub). [https://github.com/martanne/bitpixie](https://github.com/martanne/bitpixie)
204. CVE-2022-21894: Secure Boot Security Feature Bypass Vulnerability (Baton Drop). <https://nvd.nist.gov/vuln/detail/CVE-2022-21894>
205. *x86 virtualization* (2026-05-10). Wikipedia. <https://en.wikipedia.org/wiki/X86_virtualization>
206. BitLocker Group Policy settings. <https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/bitlocker-group-policy-settings>
207. *Microsoft Graph — deviceHealthAttestationState resource type*. <https://learn.microsoft.com/en-us/graph/api/resources/intune-devices-devicehealthattestationstate?view=graph-rest-1.0>
208. Ernie Brickell, Jan Camenisch, Liqun Chen — *Direct Anonymous Attestation*. <https://research.ibm.com/publications/direct-anonymous-attestation>
209. *AWS Nitro Enclaves — Set up attestation*. <https://docs.aws.amazon.com/enclaves/latest/user/set-up-attestation.html>
210. *Establishing your app integrity (App Attest)*. <https://developer.apple.com/documentation/devicecheck/establishing-your-app-s-integrity>
211. *Play Integrity API overview*. <https://developer.android.com/google/play/integrity/overview>
212. Web Authentication: An API for accessing Public Key Credentials -- Level 2 (latest). W3C. <https://www.w3.org/TR/webauthn-2/>
213. Trusted Computing Group — *About the Trusted Computing Group*. [https://web.archive.org/web/20030415224302/http://www.trustedcomputinggroup.org/about](https://web.archive.org/web/20030415224302/http://www.trustedcomputinggroup.org/about)
214. Rolf Lindemann — *FIDO ECDAA Algorithm v2.0*. <https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-ecdaa-algorithm-v2.0-id-20180227.html>
215. Ross Anderson — *Trusted Computing Frequently Asked Questions — TC / TCG / LaGrande / NGSCB / Longhorn / Palladium / TCPA Version 1.1*. <https://www.cl.cam.ac.uk/~rja14/tcpa-faq.html>
216. Ross Anderson — *Cryptography and Competition Policy — Issues with Trusted Computing*. <https://www.cl.cam.ac.uk/~rja14/Papers/tcpa.pdf>
217. Seth Schoen — *Trusted Computing: Promise and Risk*. <https://www.eff.org/wp/trusted-computing-promise-and-risk>
218. David Chaum, Eugène van Heyst — *Group Signatures*. <https://doi.org/10.1007/3-540-46416-6_22>
219. Jan Camenisch, Markus Stadler — *Efficient group signature schemes for large groups*. <https://doi.org/10.1007/BFb0052252>
220. Giuseppe Ateniese, Jan Camenisch, Marc Joye, Gene Tsudik — *A Practical and Provably Secure Coalition-Resistant Group Signature Scheme*. <https://doi.org/10.1007/3-540-44598-6_16>
221. Jan Camenisch, Markus Michels — *A Group Signature Scheme with Improved Efficiency*. <https://doi.org/10.1007/3-540-49649-1_14>
222. Jan Camenisch, Anna Lysyanskaya — *An Efficient System for Non-transferable Anonymous Credentials with Optional Anonymity Revocation*. <https://doi.org/10.1007/3-540-44987-6_7>
223. Jan Camenisch, Anna Lysyanskaya — *Signature Schemes and Anonymous Credentials from Bilinear Maps*. <https://doi.org/10.1007/978-3-540-28628-8_4>
224. Dan Boneh, Xavier Boyen, Hovav Shacham — *Short Group Signatures*. <https://doi.org/10.1007/978-3-540-28628-8_3>
225. Ernie Brickell, Jan Camenisch, Liqun Chen — *Direct Anonymous Attestation*. <https://eprint.iacr.org/2004/205>
226. David Bernhard, Georg Fuchsbauer, Essam Ghadafi, Nigel Smart, Bogdan Warinschi — *Anonymous attestation with user-controlled linkability*. <https://link.springer.com/article/10.1007/s10207-013-0191-z>
227. Ben Smyth, Mark Ryan, Liqun Chen — *Formal analysis of privacy in Direct Anonymous Attestation schemes*. <https://doi.org/10.1016/j.scico.2015.04.004>
228. Ernie Brickell, Liqun Chen, Jiangtao Li — *Simplified security notions of Direct Anonymous Attestation and a concrete scheme from pairings*. <https://doi.org/10.1007/s10207-009-0076-3>
229. Ernie Brickell, Jiangtao Li — *Enhanced Privacy ID: A Direct Anonymous Attestation Scheme with Enhanced Revocation Capabilities*. <https://doi.org/10.1145/1314333.1314337>
230. Ernie Brickell, Jiangtao Li — *Enhanced Privacy ID: A Direct Anonymous Attestation Scheme with Enhanced Revocation Capabilities*. <https://doi.org/10.1109/TDSC.2011.63>
231. Intel — *Intel® Enhanced Privacy ID (EPID): Foundation for IoT Security*. <https://www.intel.com/content/dam/www/public/us/en/documents/white-papers/intel-epid-white-paper.pdf>
232. *Intel EPID SDK (archived)*. [https://github.com/Intel-EPID-SDK/epid-sdk](https://github.com/Intel-EPID-SDK/epid-sdk)
233. Ernie Brickell, Liqun Chen, Jiangtao Li — *A New Direct Anonymous Attestation Scheme from Bilinear Maps*. <https://link.springer.com/chapter/10.1007/978-3-540-68979-9_13>
234. Liqun Chen, Dan Page, Nigel Smart — *On the Design and Implementation of an Efficient DAA Scheme*. <https://link.springer.com/chapter/10.1007/978-3-642-12510-2_16>
235. Liqun Chen, Paul Morrissey, Nigel Smart — *Pairings in Trusted Computing*. <https://link.springer.com/chapter/10.1007/978-3-540-85538-5_1>
236. Liqun Chen, Paul Morrissey, Nigel Smart — *On Proofs of Security for DAA Schemes*. <https://link.springer.com/chapter/10.1007/978-3-540-88733-1_11>
237. Liqun Chen, Jiangtao Li — *A note on the Chen-Morrissey-Smart Direct Anonymous Attestation scheme*. <https://doi.org/10.1016/j.ipl.2010.04.017>
238. *Smart Card Research and Advanced Applications (CARDIS 2010)*. <https://link.springer.com/book/10.1007/978-3-642-12510-2>
239. Liqun Chen, Dan Page, Nigel Smart — *On the Design and Implementation of an Efficient DAA Scheme*. <https://eprint.iacr.org/2009/598>
240. Paulo S. L. M. Barreto, Michael Naehrig — *Pairing-Friendly Elliptic Curves of Prime Order*. <https://doi.org/10.1007/11693383_22>
241. Taechan Kim, Razvan Barbulescu — *Extended Tower Number Field Sieve: A New Complexity for the Medium Prime Case*. <https://doi.org/10.1007/978-3-662-53018-4_20>
242. David Bernhard, Georg Fuchsbauer, Essam Ghadafi, Nigel Smart, Bogdan Warinschi — *Anonymous attestation with user-controlled linkability*. <https://eprint.iacr.org/2011/658>
243. Jan Camenisch, Manu Drijvers, Anja Lehmann — *Anonymous Attestation Using the Strong Diffie Hellman Assumption Revisited*. <https://link.springer.com/chapter/10.1007/978-3-319-45572-3_1>
244. Jan Camenisch, Manu Drijvers, Anja Lehmann — *Anonymous Attestation Using the Strong Diffie Hellman Assumption Revisited*. <https://eprint.iacr.org/2016/663>
245. Jan Camenisch, Liqun Chen, Manu Drijvers, Anja Lehmann, David Novick, Rainer Urian — *One TPM to Bind Them All: Fixing TPM 2.0 for Provably Secure Anonymous Attestation*. <https://eprint.iacr.org/2017/639>
246. *ISO/IEC 20008-1:2013 - Information technology - Security techniques - Anonymous digital signatures - Part 1: General*. <https://www.iso.org/standard/57018.html>
247. *ISO/IEC 20008-2:2013 - Information technology - Security techniques - Anonymous digital signatures - Part 2: Mechanisms using a group public key*. <https://www.iso.org/standard/56916.html>
248. *ISO/IEC 20009-2:2013 - Information technology - Security techniques - Anonymous entity authentication - Part 2: Mechanisms based on signatures using a group public key*. <https://www.iso.org/standard/56913.html>
249. *FIDO Alliance Authenticator Certification Levels*. [https://web.archive.org/web/2024/https://fidoalliance.org/certification/authenticator-certification-levels](https://web.archive.org/web/2024/https://fidoalliance.org/certification/authenticator-certification-levels)
250. Web Authentication: An API for accessing Public Key Credentials -- Level 1 (W3C Recommendation, 4 March 2019). W3C; 2019. <https://www.w3.org/TR/2019/REC-webauthn-1-20190304/>
251. *Migrating from java-webauthn-server v1 (Yubico)*. [https://github.com/Yubico/java-webauthn-server/blob/main/doc/Migrating_from_v1.adoc](https://github.com/Yubico/java-webauthn-server/blob/main/doc/Migrating_from_v1.adoc)
252. *U2F / FIDO2 Attestation and Metadata (Yubico Developer)*. <https://developers.yubico.com/U2F/Attestation_and_Metadata/>
253. Microsoft Learn — *Windows Hello for Business overview*. <https://learn.microsoft.com/en-us/windows/security/identity-protection/hello-for-business/>
254. *Meet the Microsoft Pluton processor — The security chip designed for the future of Windows PCs*. [https://web.archive.org/web/2024/https://www.microsoft.com/en-us/security/blog/2020/11/17/meet-the-microsoft-pluton-processor-the-security-chip-designed-for-the-future-of-windows-pcs](https://web.archive.org/web/2024/https://www.microsoft.com/en-us/security/blog/2020/11/17/meet-the-microsoft-pluton-processor-the-security-chip-designed-for-the-future-of-windows-pcs)
255. Microsoft Learn — *Windows 11 requirements*. <https://learn.microsoft.com/en-us/windows/whats-new/windows-11-requirements>
256. *Microsoft Learn — Get-TpmEndorsementKeyInfo*. <https://learn.microsoft.com/en-us/powershell/module/trustedplatformmodule/get-tpmendorsementkeyinfo?view=windowsserver2025-ps>
257. Dan Boneh, Saba Eskandarian, Ben Fisch — *Post-quantum EPID Signatures from Symmetric Primitives*. <https://doi.org/10.1007/978-3-030-12612-4_13>
258. Rachid El Bansarkhani, Ali El Kaafarani — *Direct Anonymous Attestation from Lattices*. <https://eprint.iacr.org/2017/1022>
259. Liqun Chen, Patrick Hough, Nada El Kassem — *Collaborative, Segregated NIZK (CoSNIZK) and More Efficient Lattice-Based Direct Anonymous Attestation*. <https://eprint.iacr.org/2024/864>
260. Liqun Chen, Changyu Dong, Nada El Kassem, Christopher Newton, Yalan Wang — *Hash-Based Direct Anonymous Attestation*. <https://link.springer.com/chapter/10.1007/978-3-031-40003-2_21>
261. Benjamin Delpy. *gentilkiwi/mimikatz*. [https://github.com/gentilkiwi/mimikatz](https://github.com/gentilkiwi/mimikatz). Accessed 2026-05-10. Mimikatz repository; privilege::debug, token::elevate, sekurlsa::logonpasswords, lsadump::sam command surface.
262. "Enable virtualization-based protection of code integrity (OEM VBS requirements)". <https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/oem-vbs>. accessed 2026-05-10.
263. Helen Custer, “Inside Windows NT.” Microsoft Press, 1992, ISBN 978-1-55615-481-2
264. Greg Hoglund, Jamie Butler, “Rootkits: Subverting the Windows Kernel.” Addison-Wesley, 2005, ISBN 0-321-29431-9
265. Microsoft, “Microsoft Acquires Winternals Software.” <https://news.microsoft.com/source/2006/07/18/microsoft-acquires-winternals-software/>
266. Microsoft, “Patching Policy for x64-Based Systems.” [https://web.archive.org/web/20080411065859/http://www.microsoft.com/whdc/driver/kernel/64bitpatching.mspx](https://web.archive.org/web/20080411065859/http://www.microsoft.com/whdc/driver/kernel/64bitpatching.mspx)
267. Kernel-mode code signing policy (Windows Vista and later). <https://learn.microsoft.com/en-us/windows-hardware/drivers/install/kernel-mode-code-signing-policy--windows-vista-and-later>
268. Microsoft, “Data Execution Prevention.” <https://learn.microsoft.com/en-us/windows/win32/memory/data-execution-prevention>
269. Microsoft, “Overview of Threat Mitigations in Windows 10.” <https://learn.microsoft.com/en-us/windows/security/threat-protection/overview-of-threat-mitigations-in-windows-10>
270. “InfinityHook.” [https://github.com/everdox/InfinityHook](https://github.com/everdox/InfinityHook)
271. Microsoft. *Microsoft Recommended Driver Block Rules*. <https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules>. Accessed 2026-05-10. Vulnerable-driver blocklist enabled by default since the Windows 11 2022 update; covers BYOVD attack class.
272. Hovav Shacham, “The Geometry of Innocent Flesh on the Bone: Return-into-libc without Function Calls (on the x86).” <https://hovav.net/ucsd/papers/s07.html>
273. Hovav Shacham, Matthew Page, Ben Pfaff, Eu-Jin Goh, Nagendra Modadugu, Dan Boneh, “On the Effectiveness of Address Space Randomization.” <https://crypto.stanford.edu/~eujin/papers/asrandom/index.html>
274. Microsoft, “Virus:Win32/Alureon.A.” <https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=Virus%3AWin32%2FAlureon.A>
275. Microsoft, “System Requirements for Hyper-V on Windows and Windows Server.” <https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/host-hardware-requirements>
276. Brad Anderson, Microsoft Ignite 2015 keynote (May 4, 2015). <https://news.microsoft.com/speeches/brad-anderson-ignite-2015/>
277. Alex Ionescu, "Battle of the SKM and IUM: How Windows 10 Rewrites OS Architecture". 2015. [https://github.com/tpn/pdfs/blob/master/Battle%20of%20SKM%20and%20IUM%20-%20How%20Windows%2010%20Rewrites%20OS%20Architecture%20-%20Alex%20Ionescu%20-%202015%20(blackhat2015)](https://github.com/tpn/pdfs/blob/master/Battle%20of%20SKM%20and%20IUM%20-%20How%20Windows%2010%20Rewrites%20OS%20Architecture%20-%20Alex%20Ionescu%20-%202015%20(blackhat2015)).pdf. accessed 2026-05-10. Black Hat USA 2015 PDF mirror.
278. Rafal Wojtczuk, "Analysis of the Attack Surface of Windows 10 Virtualization-Based Security". 2016. <https://infocondb.org/con/black-hat/black-hat-usa-2016/analysis-of-the-attack-surface-of-windows-10-virtualization-based-security>. accessed 2026-05-10.
279. *Enable virtualization-based protection of code integrity* (2026-05-10). Microsoft Learn. <https://learn.microsoft.com/en-us/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity>
280. "VBS Enclaves". <https://learn.microsoft.com/en-us/windows/win32/trusted-execution/vbs-enclaves>. accessed 2026-05-10.
281. Hari Pulapaka, "Securely design your applications and protect your sensitive data with VBS enclaves". 2024. <https://techcommunity.microsoft.com/blog/windowsosplatform/securely-design-your-applications-and-protect-your-sensitive-data-with-vbs-encla/4179543>. accessed 2026-05-10.
282. "VBS Enclaves Development Guide". <https://learn.microsoft.com/en-us/windows/win32/trusted-execution/vbs-enclaves-dev-guide>. accessed 2026-05-10.
283. "Everything Old Is New Again: Hardening the Trust Boundary of VBS Enclaves". 2025. <https://techcommunity.microsoft.com/blog/microsoft-security-blog/everything-old-is-new-again-hardening-the-trust-boundary-of-vbs-enclaves/4386961>. accessed 2026-05-10. Microsoft Security Blog (MORSE), June 24 2025.
284. Microsoft, “Device Health Attestation.” <https://learn.microsoft.com/en-us/windows-server/security/device-health-attestation>
285. Microsoft, “HealthAttestation CSP.” <https://learn.microsoft.com/en-us/windows/client-management/mdm/healthattestation-csp>
286. Microsoft, “Windows compliance settings in Microsoft Intune.” <https://learn.microsoft.com/en-us/intune/device-security/compliance/ref-windows-settings>
287. Microsoft, “Introducing Windows Defender System Guard runtime attestation.” <https://www.microsoft.com/en-us/security/blog/2018/04/19/introducing-windows-defender-system-guard-runtime-attestation/>
288. Microsoft, “Secured-core Windows 11 PCs.” <https://www.microsoft.com/en-us/windows/business/windows-11-secured-core-computers>
289. Intel, “Intel Software Guard Extensions.” <https://www.intel.com/content/www/us/en/developer/tools/software-guard-extensions/overview.html>
290. “Foreshadow: Breaking the Virtual Memory Abstraction with Transient Out-of-Order Execution.” <https://foreshadowattack.eu/>
291. Intel, “Intel® Core™ i7-1165G7 Processor Specifications.” <https://www.intel.com/content/www/us/en/products/sku/208921/intel-core-i71165g7-processor-12m-cache-up-to-4-70-ghz-with-ipu/specifications.html>
292. AMD, “AMD SEV-SNP: Strengthening VM Isolation with Integrity Protection and More.” <https://www.amd.com/en/developer/sev.html>
293. "Intel Trust Domain Extensions (Intel TDX)". <https://www.intel.com/content/www/us/en/developer/tools/trust-domain-extensions/overview.html>. accessed 2026-05-10.
294. ARM, “ARM TrustZone Technology.” <https://developer.arm.com/documentation/102418/latest/>
295. Saar Amar, Daniel King, "Breaking VSM by Attacking Secure Kernel: Hardening Secure Kernel through Offensive Research". 2020. [https://github.com/microsoft/MSRC-Security-Research/blob/master/presentations/2020_08_BlackHatUSA/Breaking_VSM_by_Attacking_SecureKernel.pdf](https://github.com/microsoft/MSRC-Security-Research/blob/master/presentations/2020_08_BlackHatUSA/Breaking_VSM_by_Attacking_SecureKernel.pdf). accessed 2026-05-10. Black Hat USA 2020, MSRC Security Research repository.
296. Saar Amar, "Publications". <https://saaramar.github.io/Publications/>. accessed 2026-05-10.
297. Oliver Lyak, “PassTheChallenge.” <https://raw.githubusercontent.com/ly4k/PassTheChallenge/main/README.md>
298. Paul Kocher, Jann Horn, Anders Fogh, Daniel Genkin, Daniel Gruss, Werner Haas, Mike Hamburg, Moritz Lipp, Stefan Mangard, Thomas Prescher, Michael Schwarz, Yuval Yarom, “Spectre Attacks: Exploiting Speculative Execution.” <https://spectreattack.com/spectre.pdf>
299. Microsoft, “Understanding the Performance Impact of Spectre and Meltdown Mitigations on Windows Systems.” <https://www.microsoft.com/en-us/security/blog/2018/01/09/understanding-the-performance-impact-of-spectre-and-meltdown-mitigations-on-windows-systems/>
300. Gerwin Klein, Kevin Elphinstone, Gernot Heiser, June Andronick, David Cock, Philip Derrin, Dhammika Elkaduwe, Kai Engelhardt, Rafal Kolanski, Michael Norrish, Thomas Sewell, Harvey Tuch, Simon Winwood, “seL4: Formal Verification of an OS Kernel.” <https://trustworthy.systems/publications/nicta_full_text/1971.pdf>
301. Microsoft Security Response Center. *Microsoft Security Servicing Criteria for Windows*. <https://www.microsoft.com/en-us/msrc/windows-security-servicing-criteria>. Accessed 2026-05-10. The security-boundary definition; the kernel-mode / user-mode separation as a classic boundary; UAC and admin-to-kernel are not in the enumerated list.
302. Microsoft, “KB5042562: Guidance for blocking rollback of VBS security updates.” <https://support.microsoft.com/en-us/topic/guidance-for-blocking-rollback-of-virtualization-based-security-vbs-related-security-updates-b2e7ebf4-f64d-4884-a390-38d63171b8d3>
303. Alon Leviev, “Downgrade Attacks Using Windows Updates.” <https://www.safebreach.com/blog/downgrade-attacks-using-windows-updates/>
304. *CVE-2024-21302 (Windows Secure Kernel Mode EoP / Windows Downdate)* (2026-05-10). NIST National Vulnerability Database. <https://nvd.nist.gov/vuln/detail/CVE-2024-21302>
305. Alon Leviev, “Update on Windows Downdate Downgrade Attacks.” <https://www.safebreach.com/blog/update-on-windows-downdate-downgrade-attacks/>
306. Ori David, “Virtualized (In)Security: How Attackers Can Weaponize VBS Enclaves.” <https://www.akamai.com/blog/security-research/virtualized-insecurity-attackers-weaponize-vbs-enclaves>
307. Jonathan Jagt, “Analysis of Windows Secure Kernel Security Bugs.” <https://www.cs.ru.nl/masters-theses/2025/J_Jagt___Analysis_of_Windows_Secure_Kernel_security_bugs.pdf>
308. Tom's Hardware, “Tested: Default Windows VBS Setting Slows Games Up to 10%, Even on RTX 4090.” <https://www.tomshardware.com/news/windows-vbs-harms-performance-rtx-4090>
309. "VbsEnclaveTooling (GitHub repository)". [https://github.com/microsoft/VbsEnclaveTooling](https://github.com/microsoft/VbsEnclaveTooling). accessed 2026-05-10.
310. "Isolated User Mode (IUM) Processes". <https://learn.microsoft.com/en-us/windows/win32/procthread/isolated-user-mode--ium--processes>. accessed 2026-05-10. Microsoft Win32 SDK documentation.
311. "How Credential Guard works". <https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/how-it-works>. accessed 2026-05-10.
312. "Debugging Windows Isolated User Mode (IUM) Processes". <https://blog.quarkslab.com/debugging-windows-isolated-user-mode-ium-processes.html>. accessed 2026-05-10.
313. Michael D. Schroeder, Jerome H. Saltzer, "A Hardware Architecture for Implementing Protection Rings". 1972. <https://multicians.org/protection.html>. accessed 2026-05-10. Multicians.org full-text mirror of the CACM 15(3) paper.
314. "Multics bibliography". <https://multicians.org/papers.html>. accessed 2026-05-10.
315. "Multics History". <https://multicians.org/history.html>. accessed 2026-05-10.
316. William A. Wulf, Roy Levin, Samuel P. Harbison, "HYDRA/C.mmp: An Experimental Computer System". 1981. <http://bitsavers.informatik.uni-stuttgart.de/pdf/cmu/hydra_c.mmp/Wulf_HYDRA_Cmmp_An_Experimental_Computer_System_1981.pdf>. accessed 2026-05-10.
317. Henry M. Levy, "Capability-Based Computer Systems, Chapter 6: Hydra". Digital Press. 1984. <https://homes.cs.washington.edu/~levy/capabook/Chapter6.pdf>. accessed 2026-05-10.
318. Kevin Elphinstone, Gernot Heiser, "L4 Microkernels: The Lessons from 20 Years of Research and Deployment". 2013. <https://rcs.uwaterloo.ca/~ali/cs350-f19/papers/l4.pdf>. accessed 2026-05-10.
319. Gerwin Klein, Kevin Elphinstone, Gernot Heiser, June Andronick, David Cock, Philip Derrin, Dhammika Elkaduwe, Kai Engelhardt, Rafal Kolanski, Michael Norrish, Thomas Sewell, Harvey Tuch, Simon Winwood, "seL4: Formal Verification of an OS Kernel". 2009. <https://trustworthy.systems/publications/nicta_full_text/1852.pdf>. accessed 2026-05-10. SOSP 2009 canonical paper PDF.
320. "GitHub REST API: seL4/seL4 repository metadata". <https://api.github.com/repos/seL4/seL4>. accessed 2026-05-10.
321. "seL4 Foundation: About seL4". <https://sel4.systems/About/>. accessed 2026-05-10.
322. *Virtual Secure Mode -- Hyper-V Top Level Functional Specification* (2026-05-10). Microsoft Learn. <https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/vsm>
323. Microsoft. *Administrator Protection (Adminless)*. <https://learn.microsoft.com/en-us/windows/security/application-security/application-control/administrator-protection/>. Accessed 2026-05-10. Adminless / Administrator Protection on Windows 11; just-in-time elevation via Windows Hello plus a hidden, profile-separated user account that issues an isolated admin token.
324. "Protected Media Path". <https://learn.microsoft.com/en-us/windows/win32/medfound/protected-media-path>. accessed 2026-05-10.
325. Microsoft Learn — *AppContainer Isolation* — 2024. <https://learn.microsoft.com/en-us/windows/win32/secauthz/appcontainer-isolation>
326. James Forshaw, "Windows Exploitation Tricks: Exploiting Arbitrary Object Directory Creation for Local Elevation of Privilege". 2018. <https://googleprojectzero.blogspot.com/2018/08/windows-exploitation-tricks-exploiting.html>. accessed 2026-05-10. Google Project Zero, August 2018.
327. Microsoft Learn — *Protecting Anti-Malware Services* (2024). <https://learn.microsoft.com/en-us/windows/win32/services/protecting-anti-malware-services>
328. itm4n (Clement Labro) — *Do You Really Know About LSA Protection (RunAsPPL)?*, 2021. <https://itm4n.github.io/lsass-runasppl/>
329. Alex Ionescu, "The Evolution of Protected Processes Part 3: Windows PKI Internals (Signing Levels, Scenarios, Signers, Root Keys, EKUs & Runtime Signers)". [https://web.archive.org/web/2023/http://www.alex-ionescu.com/?p=146.](https://web.archive.org/web/2023/http://www.alex-ionescu.com/?p=146.) accessed 2026-05-10. Wayback Machine snapshot; original alex-ionescu.com offline.
330. Alex Ionescu, "The Evolution of Protected Processes Part 1: Pass-the-Hash Mitigations in Windows 8.1". [https://web.archive.org/web/2023/http://www.alex-ionescu.com/?p=97.](https://web.archive.org/web/2023/http://www.alex-ionescu.com/?p=97.) accessed 2026-05-10. Wayback Machine snapshot; original alex-ionescu.com offline.
331. itm4n, "The End of PPLdump". <https://itm4n.github.io/the-end-of-ppldump/>. accessed 2026-05-10. Companion post documenting the build 19044.1826 (July 2022) NTDLL patch that prevents PPLs from loading Known DLLs; the github.com/itm4n/PPLdump README carries the same verbatim build/date statement at [https://github.com/itm4n/PPLdump](https://github.com/itm4n/PPLdump).
332. "Windows 10 - release information". <https://learn.microsoft.com/en-us/windows/release-health/release-information>. accessed 2026-05-10. Microsoft release table for Windows 10 release history, including version 1507 build 10240 availability.
333. "Hyper-V Architecture". <https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/architecture>. accessed 2026-05-10.
334. "A Virtual Journey: From Hardware Virtualization to Hyper-V's Virtual Trust Levels". <https://blog.quarkslab.com/a-virtual-journey-from-hardware-virtualization-to-hyper-vs-virtual-trust-levels.html>. accessed 2026-05-10.
335. "Black Hat USA 2015 conference archive". <https://infocondb.org/con/black-hat/black-hat-usa-2015/>. accessed 2026-05-10.
336. Andrea Allievi, Mark E. Russinovich, Alex Ionescu, David A. Solomon, "Windows Internals, Seventh Edition, Part 2". Microsoft Press. 2021. Chapter 9: Management mechanisms, trustlet architecture reference. ISBN 978-0135462409.
337. Oliver Lyak, "Pass-the-Challenge: Defeating Windows Defender Credential Guard". 2022. [https://web.archive.org/web/20231217204121/https://research.ifcr.dk/pass-the-challenge-defeating-windows-defender-credential-guard-31a892eee22.](https://web.archive.org/web/20231217204121/https://research.ifcr.dk/pass-the-challenge-defeating-windows-defender-credential-guard-31a892eee22.) accessed 2026-05-10. Wayback Machine snapshot; original returns 403 to non-browser agents.
338. "Guarded Fabric and Shielded VMs Overview". <https://learn.microsoft.com/en-us/windows-server/security/guarded-fabric-shielded-vm/guarded-fabric-and-shielded-vms>. accessed 2026-05-10.
339. "Windows Hello Enhanced Sign-in Security". <https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/windows-hello-enhanced-sign-in-security>. accessed 2026-05-10.
340. "October 28, 2025: KB5067036 (OS Builds 26200.7019 and 26100.7019) Preview". <https://support.microsoft.com/en-us/topic/october-28-2025-kb5067036-os-builds-26200-7019-and-26100-7019-preview-ec3da7dc-63ba-4b1d-ac41-cf2494d2123a>. accessed 2026-05-10.
341. "TEE Client API Specification v1.0". <https://globalplatform.org/wp-content/uploads/2010/07/TEE_Client_API_Specification-V1.0.pdf>. accessed 2026-05-10.
342. "Software Guard Extensions". <https://en.wikipedia.org/wiki/Software_Guard_Extensions>. accessed 2026-05-10.
343. "Intel x86 SGX instructions: ENCLS (ring 0 supervisor) and ENCLU (ring 3 user) -- Intel SDM Volume 3D, Chapters 36-38". <https://www.felixcloutier.com/x86/encls>. accessed 2026-05-10. Felix Cloutier's machine-checkable mirror of the Intel 64 and IA-32 Architectures Software Developer's Manual. ENCLS reference (<https://www.felixcloutier.com/x86/encls>) states verbatim 'any attempt to execute the instruction when CPL > 0 results in #UD'; ENCLU reference (<https://www.felixcloutier.com/x86/enclu>) states verbatim 'any attempt to execute this instruction when CPL < 3 results in #UD'. Both pages enumerate the SGX leaf functions (ECREATE, EADD, EINIT, EREMOVE on ENCLS; EENTER, EEXIT, EGETKEY, EREPORT on ENCLU).
344. Jo Van Bulck, Marina Minkin, Ofir Weisse, Daniel Genkin, Baris Kasikci, Frank Piessens, Mark Silberstein, Thomas F. Wenisch, Yuval Yarom, Raoul Strackx, "Foreshadow: Extracting the Keys to the Intel SGX Kingdom with Transient Out-of-Order Execution". 2018. <https://www.usenix.org/conference/usenixsecurity18/presentation/bulck>. accessed 2026-05-10. USENIX Security 2018.
345. "SGAxe: How SGX Fails in Practice". <https://sgaxe.com/>. accessed 2026-05-10. Canonical project page by the CacheOut / SGAxe authors; SGAxe extracts SGX private attestation keys.
346. "Plundervolt: Software-based Fault Injection Attacks against Intel SGX". <https://plundervolt.com/>. accessed 2026-05-10. Canonical project page; first reported June 7, 2019 by Murdock, Oswald, Garcia, Van Bulck, Piessens, Gruss.
347. Guoxing Chen, Sanchuan Chen, Yuan Xiao, Yinqian Zhang, Zhiqiang Lin, Ten H. Lai, "SgxPectre Attacks: Stealing Intel Secrets from SGX Enclaves via Speculative Execution". 2019. <https://arxiv.org/abs/1802.09085>. accessed 2026-05-10. IEEE EuroS&P 2019; arXiv preprint 1802.09085.
348. "AMD EPYC 7003 Series CPUs Set New Standard as Highest Performance Server Processor". <https://www.amd.com/en/newsroom/press-releases/2021-3-15-amd-epyc-7003-series-cpus-set-new-standard-as-hig.html>. accessed 2026-05-10. AMD press release announcing EPYC 7003 on March 15, 2021 and SEV-SNP support.
349. "Intel Launches 4th Gen Xeon Scalable Processors, Max Series CPUs and GPUs". <https://download.intel.com/newsroom/archive/2025/en-us-2023-01-10-intel-launches-4th-gen-xeon-scalable-processors-max-series-cpus.pdf>. accessed 2026-05-10. Intel Newsroom PDF for the January 10, 2023 4th Gen Xeon Scalable launch.
350. "AMD SEV-SNP: Strengthening VM Isolation with Integrity Protection and More". <https://docs.amd.com/api/khub/documents/~uAtQszeypAVVEk_B91Ojg/content>. accessed 2026-05-10.
351. "Arm Architecture Reference Manual Armv7-A and Armv7-R edition". <https://developer.arm.com/documentation/ddi0406/latest/>. accessed 2026-05-10. Arm architecture manual documenting the Security Extensions/TrustZone architecture, Secure and Non-secure worlds, and Secure Monitor Call model.
352. "About OP-TEE". <https://optee.readthedocs.io/en/latest/general/about.html>. accessed 2026-05-10.
353. "NVD - CVE-2020-0917". <https://nvd.nist.gov/vuln/detail/CVE-2020-0917>. accessed 2026-05-10.
354. "NVD - CVE-2020-0918". <https://nvd.nist.gov/vuln/detail/CVE-2020-0918>. accessed 2026-05-10.
355. "Trusted Platform Module Technology Overview". <https://learn.microsoft.com/en-us/windows/security/information-protection/tpm/trusted-platform-module-overview>. accessed 2026-05-10.
356. tandasat/ExploitCapcom. [https://github.com/tandasat/ExploitCapcom](https://github.com/tandasat/ExploitCapcom)
357. rapid7/metasploit-framework#7363 -- Add LPE exploit module for the capcom driver flaw. [https://github.com/rapid7/metasploit-framework/pull/7363](https://github.com/rapid7/metasploit-framework/pull/7363)
358. FuzzySecurity Capcom Rootkit POC. <https://fuzzysecurity.com/tutorials/28.html>
359. Cryptography tools. <https://learn.microsoft.com/en-us/windows/win32/seccrypto/cryptography-tools>
360. Windows Hardware Lab Kit. <https://learn.microsoft.com/en-us/windows-hardware/test/hlk/>
361. Sony, Rootkits and Digital Rights Management Gone Too Far. [https://web.archive.org/web/20051102053346/http://www.sysinternals.com/blog/2005/10/sony-rootkits-and-digital-rights.html](https://web.archive.org/web/20051102053346/http://www.sysinternals.com/blog/2005/10/sony-rootkits-and-digital-rights.html)
362. Kernel-mode code signing requirements (Windows previous-versions). <https://learn.microsoft.com/en-us/previous-versions/windows/hardware/design/dn653567(v=vs.85)>
363. Cross-Certificates for Kernel Mode Code Signing (2020 archive of the historical CA list). [https://web.archive.org/web/2020/https://docs.microsoft.com/en-us/windows-hardware/drivers/install/cross-certificates-for-kernel-mode-code-signing](https://web.archive.org/web/2020/https://docs.microsoft.com/en-us/windows-hardware/drivers/install/cross-certificates-for-kernel-mode-code-signing)
364. Cross-certificates for kernel-mode code signing. <https://learn.microsoft.com/en-us/windows-hardware/drivers/install/cross-certificates-for-kernel-mode-code-signing>
365. Gabriel Landau — *Forget Vulnerable Drivers — Admin Is All You Need* (2024). <https://www.elastic.co/security-labs/forget-vulnerable-drivers-admin-is-all-you-need>
366. Microsoft Security Advisory 932596: Update to Improve Kernel Patch Protection. <https://learn.microsoft.com/en-us/security-updates/securityadvisories/2007/932596>
367. skape, Skywing. *Bypassing PatchGuard on Windows x64*. Uninformed. <http://www.uninformed.org/?v=3&a=3&t=pdf>
368. W32.Stuxnet Dossier. <https://docs.broadcom.com/doc/security-response-w32-stuxnet-dossier-11-en>
369. Stuxnet signed binary: signed malware, certs and trust chains. <https://www.microsoft.com/en-us/security/blog/2010/07/16/stuxnet-signed-binary-signed-malware-cert-auth-trust-chains/>
370. NIST National Vulnerability Database. *CVE-2019-16098 (RTCore64.sys)*. 2019. <https://nvd.nist.gov/vuln/detail/CVE-2019-16098>. Accessed 2026-05-10. Micro-Star MSI Afterburner driver allows arbitrary memory read/write; signed driver used by BlackByte ransomware to disable EDR.
371. Sophos News. *BlackByte ransomware returns*. 2022. <https://news.sophos.com/en-us/2022/10/04/blackbyte-ransomware-returns/>. Accessed 2026-05-10. October 2022 BlackByte BYOVD via RTCore64.sys (CVE-2019-16098); disables ~1000 security drivers; references mhyprot2.sys / aswArPot.sys precedents.
372. NIST National Vulnerability Database. *CVE-2018-19320 (GIGABYTE gdrv.sys)*. 2018. <https://nvd.nist.gov/vuln/detail/CVE-2018-19320>. Accessed 2026-05-10. gdrv.sys exposes ring0 memcpy-like functionality; CISA Known Exploited Vulnerabilities Catalog listing 2022-10-24, due date 2022-11-14.
373. Cybersecurity and Infrastructure Security Agency. Known Exploited Vulnerabilities Catalog (CSV). <https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv>
374. Sophos gdrv.sys / RobbinHood technical coverage. <https://www.sophos.com/en-us/blog/tag/gdrv-sys>
375. How DoppelPaymer hunts and kills Windows processes. <https://www.crowdstrike.com/en-us/blog/how-doppelpaymer-hunts-and-kills-windows-processes/>
376. g_CiOptions in a virtualized world. <https://www.trustedsec.com/blog/g_cioptions-in-a-virtualized-world>
377. Code signing attestation. <https://learn.microsoft.com/en-us/windows-hardware/drivers/dashboard/code-signing-attestation>
378. Improve Kernel Security with the New Microsoft Vulnerable and Malicious Driver Reporting Center. 2021. <https://www.microsoft.com/en-us/security/blog/2021/12/08/improve-kernel-security-with-the-new-microsoft-vulnerable-and-malicious-driver-reporting-center/>
379. Driver Code Signing Requirements. <https://learn.microsoft.com/en-us/windows-hardware/drivers/dashboard/code-signing-reqs>
380. App Control for Business. <https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/appcontrol>
381. Microsoft vulnerable driver blocklist: getting better and better. <https://techcommunity.microsoft.com/blog/microsoft-security-baselines/microsoft-vulnerable-driver-blocklist-getting-better-and-better/4172168>
382. Microsoft — *KB5020779: The vulnerable driver blocklist after the October 2022 preview release* (2022). <https://support.microsoft.com/en-us/topic/kb5020779-the-vulnerable-driver-blocklist-after-the-october-2022-preview-release-3fcbe13a-6013-4118-b584-fcfbc6a09936>
383. *Available today: the Windows 11 2022 Update*, 2022. <https://blogs.windows.com/windowsexperience/2022/09/20/available-today-the-windows-11-2022-update/>
384. *Attack surface reduction rules reference*, 2026. <https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference>
385. *Living Off The Land Drivers*, Michael Haag, Magicsword.io. <https://www.loldrivers.io/>
386. magicsword-io/LOLDrivers. [https://github.com/magicsword-io/LOLDrivers](https://github.com/magicsword-io/LOLDrivers)
387. Breaking boundaries: investigating vulnerable drivers and mitigating risks. <https://research.checkpoint.com/2024/breaking-boundaries-investigating-vulnerable-drivers-and-mitigating-risks/>
388. Smart App Control frequently asked questions. <https://support.microsoft.com/topic/what-is-smart-app-control-285ea03d-fa88-4d56-882e-6698afdb7003>
389. DeviceGuardSoftwareSecure Enum. <https://learn.microsoft.com/en-us/dotnet/api/microsoft.powershell.commands.deviceguardsoftwaresecure?view=powershellsdk-1.1.0>
390. Unveiling BYOVD threats: kernel-driver dynamic analysis at scale. <https://www.eurecom.fr/publication/8384>
391. Unveiling BYOVD threats: kernel-driver dynamic analysis at scale (NDSS 2026 paper PDF). <https://www.s3.eurecom.fr/docs/ndss26_monzani.pdf>
392. Linux kernel module signing. <https://docs.kernel.org/admin-guide/module-signing.html>
393. kernel_lockdown(7) -- Linux manual page. <https://man7.org/linux/man-pages/man7/kernel_lockdown.7.html>
394. Legacy system extensions in macOS. <https://support.apple.com/en-us/HT210999>
395. DriverKit (Apple Developer Documentation). <https://developer.apple.com/documentation/driverkit>
396. System Integrity Protection (Apple Platform Security). <https://support.apple.com/guide/security/system-integrity-protection-secb7ea06b49/web>
397. Securely extending the kernel in macOS (Apple Platform Security). <https://support.apple.com/guide/security/securely-extending-the-kernel-sec8e454101b/web>
398. Microsoft — *microsoft/sbom-tool* (2024). [https://github.com/microsoft/sbom-tool](https://github.com/microsoft/sbom-tool)
399. Would Hardware Dev Center for CRA compliance change?. <https://learn.microsoft.com/en-us/answers/questions/5732099/would-hardware-dev-center-for-cra-compliance-chang>
400. Windows Hardware Compatibility Program Specifications and Policies. <https://learn.microsoft.com/en-us/windows-hardware/design/compatibility/whcp-specifications-policies>
401. Unveiling BYOVD threats: malware use and abuse of kernel drivers. <https://www.s3.eurecom.fr/post/2025/10/13/unveiling-byovd-threats-malwares-use-and-abuse-of-kernel-drivers/>
402. Exploring vulnerable Windows drivers. <https://blog.talosintelligence.com/exploring-vulnerable-windows-drivers/>
403. Driver compatibility with Hypervisor-Protected Code Integrity (HVCI). <https://learn.microsoft.com/en-us/windows-hardware/test/hlk/testref/driver-compatibility-with-device-guard>
404. Riot Games Vanguard restriction guidance. <https://support.riotgames.com/en-us/riot/penalties/error-van-restriction-5>
405. Symantec W32.Stuxnet Dossier. <https://docs.broadcom.com/doc/security-response-w32-stuxnet-dossier>
406. *Hyper-V Architecture* (2026-05-10). Microsoft Learn. <https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/reference/hyper-v-architecture>
407. *Hypervisor Top-Level Functional Specification v6.0b* (2026-05-10). Microsoft. [https://github.com/MicrosoftDocs/Virtualization-Documentation/raw/live/tlfs/Hypervisor%20Top%20Level%20Functional%20Specification%20v6.0b.pdf](https://github.com/MicrosoftDocs/Virtualization-Documentation/raw/live/tlfs/Hypervisor%20Top%20Level%20Functional%20Specification%20v6.0b.pdf)
408. Intel. *Intel 64 and IA-32 Architectures Software Developer's Manual*. <https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html>
409. AMD. *AMD64 Architecture Programmer's Manual Volume 2: System Programming*. <https://www.amd.com/system/files/TechDocs/24593.pdf>
410. David A. Hepkin, Arun U. Kishan. *US Patent 9,430,642 B2: Providing virtual secure mode with different virtual trust levels* (2016). Microsoft Technology Licensing, LLC. <https://patents.google.com/patent/US9430642B2/en>
411. John S. Robin, Cynthia E. Irvine. *Analysis of the Intel Pentium's Ability to Support a Secure Virtual Machine Monitor*. USENIX Security 2000. <https://www.usenix.org/legacy/events/sec00/full_papers/robin/robin.pdf>
412. Microsoft. *Hyper-V hits RTM*. Microsoft Community Hub. <https://techcommunity.microsoft.com/blog/coreinfrastructureandsecurityblog/hyper-v-hits-rtm/333167>
413. Samuel T. King, Peter M. Chen, Yi-Min Wang, Chad Verbowski, Helen J. Wang, Jacob R. Lorch. *SubVirt: Implementing malware with virtual machines* (2006). IEEE Symposium on Security and Privacy. <https://web.eecs.umich.edu/~pmchen/papers/king06.pdf>
414. *Blue Pill (software)* (2026-05-10). Wikipedia. <https://en.wikipedia.org/wiki/Blue_Pill_(software)>
415. *CVE-2009-1244 (CLOUDBURST: VMware SVGA display function)* (2026-05-10). NIST National Vulnerability Database. <https://nvd.nist.gov/vuln/detail/CVE-2009-1244>
416. Joanna Rutkowska. *Introducing Qubes OS* (2010). Invisible Things Lab. <https://blog.invisiblethings.org/2010/04/07/introducing-qubes-os.html>
417. Microsoft. *Your free upgrade is here: Windows 10 launches with worldwide celebrations with fans, #UpgradeYourWorld and more*. <https://blogs.microsoft.com/blog/2015/07/28/your-free-upgrade-is-here-windows-10-launches-with-worldwide-celebrations-with-fans-upgradeyourworld-and-more/>
418. *CVE-2024-21407 (Windows Hyper-V Remote Code Execution / UAF)* (2026-05-10). NIST National Vulnerability Database. <https://nvd.nist.gov/vuln/detail/CVE-2024-21407>
419. *Microsoft Hyper-V Bounty Program* (2026-05-10). Microsoft Security Response Center. <https://www.microsoft.com/en-us/msrc/bounty-hyper-v>
420. *Pwn2Own Berlin 2025: Day Three Results* (2025). Zero Day Initiative. <https://www.zerodayinitiative.com/blog/2025/5/17/pwn2own-berlin-2025-day-three-results>
421. *seL4 White Paper* (2026-05-10). seL4 Project. <https://sel4.systems/About/seL4-whitepaper.pdf>
422. *CVE-2021-28476 (Windows Hyper-V Remote Code Execution)* (2026-05-10). NIST National Vulnerability Database. <https://nvd.nist.gov/vuln/detail/CVE-2021-28476>
423. *CVE-2025-21333 (Windows Hyper-V NT Kernel Integration VSP EoP)* (2026-05-10). NIST National Vulnerability Database. <https://nvd.nist.gov/vuln/detail/CVE-2025-21333>
424. *CVE-2024-30092 (Windows Hyper-V Remote Code Execution)* (2026-05-10). NIST National Vulnerability Database. <https://nvd.nist.gov/vuln/detail/CVE-2024-30092>
425. *CVE-2024-49117 (Windows Hyper-V Remote Code Execution)* (2026-05-10). NIST National Vulnerability Database. <https://nvd.nist.gov/vuln/detail/CVE-2024-49117>
426. Bjorn Ruytenberg. *Thunderspy* (2020). <https://thunderspy.io/>
427. *Hyper-V* (2026-05-10). Wikipedia. <https://en.wikipedia.org/wiki/Hyper-V>
428. *Windows 10* (2026-05-10). Wikipedia. <https://en.wikipedia.org/wiki/Windows_10>
429. *Hypervisor* (2026-05-10). Wikipedia. <https://en.wikipedia.org/wiki/Hypervisor>
430. *Kernel Patch Protection* (2026-05-10). Wikipedia. <https://en.wikipedia.org/wiki/Kernel_Patch_Protection>
431. Alex Ionescu — *The Evolution of Protected Processes — Part 1: Pass-the-Hash Mitigations in Windows 8.1* (2013). <https://www.alex-ionescu.com/?p=97>
432. Alex Ionescu — *The Evolution of Protected Processes — Part 2: Exploit/Jailbreak Mitigations* (2013). <https://www.alex-ionescu.com/?p=116>
433. Alex Ionescu — *The Evolution of Protected Processes — Part 3* (2014). <https://www.alex-ionescu.com/?p=146>
434. itm4n — *Bypassing LSA Protection in Userland* (2021). <https://blog.scrt.ch/2021/04/22/bypassing-lsa-protection-in-userland/>
435. itm4n — *Ghost in the PPL Part 1: BYOVDLL* (2024). <https://itm4n.github.io/ghost-in-the-ppl-part-1/>
436. Microsoft Learn — *Configuring Additional LSA Protection* (2024). <https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection>
437. Microsoft Learn — *Microsoft Virus Initiative Criteria* (2024). <https://learn.microsoft.com/en-us/microsoft-365/security/intelligence/virus-initiative-criteria>
438. Benjamin Delpy — *mimikatz/modules/sekurlsa/kuhl_m_sekurlsa.c at commit fe4e98405589e96ed6de5e05ce3c872f8108c0a0* (2018). [https://github.com/gentilkiwi/mimikatz/blob/fe4e98405589e96ed6de5e05ce3c872f8108c0a0/mimikatz/modules/sekurlsa/kuhl_m_sekurlsa.c](https://github.com/gentilkiwi/mimikatz/blob/fe4e98405589e96ed6de5e05ce3c872f8108c0a0/mimikatz/modules/sekurlsa/kuhl_m_sekurlsa.c)
439. Microsoft Corporation — *Protected Processes in Windows Vista* (2006). <https://download.microsoft.com/download/a/f/7/af7777e5-7dcd-4800-8a0a-b18336565f5b/process_vista.doc>
440. James Forshaw — *Injecting Code into Windows Protected Processes Using COM — Part 1* (2018). <https://googleprojectzero.blogspot.com/2018/10/injecting-code-into-windows-protected.html>
441. Alex Ionescu — *Why Protected Processes Are A Bad Idea* (2007). <https://www.alex-ionescu.com/?p=34>
442. Mateusz "j00ru" Jurczyk — *CSRSS Win32k Reserved System Call List* (2012). <https://j00ru.vexillium.org/?p=1393>
443. IANA — *Private Enterprise Numbers (PEN) — entry 311 (Microsoft)* (2024). <https://www.iana.org/assignments/enterprise-numbers/?q=311>
444. oid-base.com (OID Repository) — *OID 1.3.6.1.4.1.311.10.3 — Microsoft Enhanced Key Usage (purpose)* (2024). <https://oid-base.com/get/1.3.6.1.4.1.311.10.3>
445. Microsoft Corporation — *Early Launch Anti-Malware Driver sample (Windows-driver-samples/security/elam)* (2024). [https://github.com/microsoft/Windows-driver-samples/tree/main/security/elam](https://github.com/microsoft/Windows-driver-samples/tree/main/security/elam)
446. Microsoft Support — *Microsoft Security Advisory: Update to improve credentials protection and management — May 13, 2014 (KB2871997)* (2014). <https://support.microsoft.com/en-US/security/microsoft-security-advisory-update-to-improve-credentials-protection-and-management-may-13-2014>
447. Alex Ionescu, James Forshaw — *Unknown Known DLLs and other Code Integrity Trust Violations* (2018). <https://recon.cx/2018/montreal/>
448. James Forshaw — *Bypassing VirtualBox Process Hardening on Windows* (2017). <https://googleprojectzero.blogspot.com/2017/08/bypassing-virtualbox-process-hardening.html>
449. itm4n — *PPLdump (GitHub repository)* (2021). [https://github.com/itm4n/PPLdump](https://github.com/itm4n/PPLdump)
450. Forrest Orr — *Malicious Memory Artifacts: Part I — DLL Hollowing* (2020). <https://www.forrest-orr.net/post/malicious-memory-artifacts-part-i-dll-hollowing>
451. Gabriel Landau — *PPLdump Is Dead. Long Live PPLdump!* (2023). <https://i.blackhat.com/Asia-23/AS-23-Landau-PPLdump-Is-Dead-Long-Live-PPLdump.pdf>
452. Gabriel Landau — *Inside Microsoft's Plan to Kill PPLFault* (2023). <https://www.elastic.co/security-labs/inside-microsofts-plan-to-kill-pplfault>
453. Gabriel Landau — *PPLFault (GitHub repository)* (2023). [https://github.com/gabriellandau/PPLFault](https://github.com/gabriellandau/PPLFault)
454. k0shl — *Isolate Me from Sandbox — Explore Elevation of Privilege of CNG Key Isolation* (2023). <https://whereisk0shl.top/post/isolate-me-from-sandbox-explore-elevation-of-privilege-of-cng-key-isolation>
455. NIST — *CVE-2023-28229 — Windows CNG Key Isolation Service Elevation of Privilege* (2023). <https://nvd.nist.gov/vuln/detail/CVE-2023-28229>
456. NIST — *CVE-2023-36906 — Windows Cryptographic Information Disclosure* (2023). <https://nvd.nist.gov/vuln/detail/CVE-2023-36906>
457. Y3A — *CVE-2023-28229 PoC (GitHub repository)* (2023). [https://github.com/Y3A/CVE-2023-28229](https://github.com/Y3A/CVE-2023-28229)
458. Microsoft Security Response Center — *Windows Security Servicing Criteria (Wayback archive)* (2023). [https://web.archive.org/web/20230506125554/https://www.microsoft.com/en-us/msrc/windows-security-servicing-criteria](https://web.archive.org/web/20230506125554/https://www.microsoft.com/en-us/msrc/windows-security-servicing-criteria)
459. Mark Russinovich — *Process Explorer (Sysinternals)* (2026). <https://learn.microsoft.com/en-us/sysinternals/downloads/process-explorer>
460. Microsoft Learn — *NtQueryInformationProcess function (winternl.h)* (2024). <https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess>
461. Wikipedia contributors. *Mimikatz*. <https://en.wikipedia.org/wiki/Mimikatz>. Accessed 2026-05-10. Mimikatz first-release date (May 2011); Benjamin Delpy attribution.
462. *__fastfail*. <https://learn.microsoft.com/en-us/cpp/intrinsics/fastfail?view=msvc-170>
463. *SetProcessMitigationPolicy function*. <https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-setprocessmitigationpolicy>
464. *PROCESS_MITIGATION_POLICY enum*. <https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-process_mitigation_policy>
465. Aleph One (Elias Levy) — *Smashing The Stack For Fun And Profit* (1996). <http://phrack.org/issues/49/14.html>
466. Alexander Peslyak (Solar Designer) — *Return-into-libc overflow exploit + non-exec stack patch* (1997). <https://seclists.org/bugtraq/1997/Aug/63>
467. Openwall Project — *Openwall Linux kernel patch README*. <https://www.openwall.com/linux/README>
468. *PaX PAGEEXEC design*. <https://pax.grsecurity.net/docs/pageexec.txt>
469. *AMD64 Architecture Programmer’s Manual Volume 2: System Programming*. <https://docs.amd.com/v/u/en-US/24593_3.44_APM_Vol2>
470. *Return-oriented programming*. <https://en.wikipedia.org/wiki/Return-oriented_programming>
471. Michael Howard — *Address Space Layout Randomization in Windows Vista* (2006). <https://learn.microsoft.com/en-us/archive/blogs/michael_howard/address-space-layout-randomization-in-windows-vista>
472. Hovav Shacham — *The Geometry of Innocent Flesh on the Bone (PDF)* (2007). <https://hovav.net/ucsd/dist/geometry.pdf>
473. Hovav Shacham — *Return-Oriented Programming: Systems, Languages, and Applications* (2008). <https://hovav.net/ucsd/talks/blackhat08.html>
474. *Enhanced Mitigation Experience Toolkit*. <https://en.wikipedia.org/wiki/Enhanced_Mitigation_Experience_Toolkit>
475. Martín Abadi, Mihai Budiu, Úlfar Erlingsson, Jay Ligatti — *Control-Flow Integrity* (2005). <https://www.microsoft.com/en-us/research/publication/control-flow-integrity/>
476. Yunhai Zhang — *Bypass Control Flow Guard Comprehensively* (2015). [https://github.com/tpn/pdfs/raw/master/Bypass%20Control%20Flow%20Guard%20Comprehensively%20-%20Slides%20(2015)](https://github.com/tpn/pdfs/raw/master/Bypass%20Control%20Flow%20Guard%20Comprehensively%20-%20Slides%20(2015)).pdf
477. *Control Flow Guard*. <https://learn.microsoft.com/en-us/windows/win32/secbp/control-flow-guard>
478. */guard (Enable Control Flow Guard)*. <https://learn.microsoft.com/en-us/cpp/build/reference/guard-enable-control-flow-guard?view=msvc-170>
479. */GUARD (Enable Guard Checks)*. <https://learn.microsoft.com/en-us/cpp/build/reference/guard-enable-guard-checks?view=msvc-170>
480. Felix Schuster, Thomas Tendyck, Christopher Liebchen, Lucas Davi, Ahmad-Reza Sadeghi, Thorsten Holz — *Counterfeit Object-oriented Programming* (2015). <https://www.ieee-security.org/TC/SP2015/papers-archived/6949a745.pdf>
481. David Weston — *Advancing Windows Security* (2019). [https://github.com/dwizzzle/Presentations/raw/master/Bluehat%20Shanghai%20-%20Advancing%20Windows%20Security.pdf](https://github.com/dwizzzle/Presentations/raw/master/Bluehat%20Shanghai%20-%20Advancing%20Windows%20Security.pdf)
482. Connor McGarr — *Examining Xtended Flow Guard (XFG)* (2020). <https://connormcgarr.github.io/examining-xfg/>
483. Connor McGarr — *Out Of Control: How KCFG and KCET Redefine Control Flow Integrity in the Windows Kernel* (2025). <https://i.blackhat.com/BH-USA-25/Presentations/USA-25-McGarr-Out-Of-Control-KCFG-And-KCET.pdf>
484. *Understanding Hardware-enforced Stack Protection (Wayback)* (2020). [https://web.archive.org/web/20241119023959/https://techcommunity.microsoft.com/blog/windowsosplatform/understanding-hardware-enforced-stack-protection/1247815](https://web.archive.org/web/20241119023959/https://techcommunity.microsoft.com/blog/windowsosplatform/understanding-hardware-enforced-stack-protection/1247815)
485. */CETCOMPAT linker option*. <https://learn.microsoft.com/en-us/cpp/build/reference/cetcompat?view=msvc-170>
486. *PROCESS_MITIGATION_USER_SHADOW_STACK_POLICY*. <https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-process_mitigation_user_shadow_stack_policy>
487. Matt Miller — *Mitigating arbitrary native code execution in Microsoft Edge* (2017). <https://blogs.windows.com/msedgedev/2017/02/23/mitigating-arbitrary-native-code-execution/>
488. *PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY*. <https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-process_mitigation_binary_signature_policy>
489. *CVE-2013-3900 -- WinVerifyTrust Signature Validation Vulnerability* (2013). <https://nvd.nist.gov/vuln/detail/CVE-2013-3900>
490. *PROCESS_MITIGATION_DYNAMIC_CODE_POLICY*. <https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-process_mitigation_dynamic_code_policy>
491. James Forshaw, Ivan Fratric — *Project Zero issue 42450607: Edge ACG OpenProcess race* (2018). <https://project-zero.issues.chromium.org/issues/42450607>
492. *Microsoft Edge Chakra - ACG OpenProcess Bypass (EDB 44467)* (2018). <https://www.exploit-db.com/exploits/44467>
493. Ivan Fratric — *Bypassing Mitigations by Attacking JIT Server in Microsoft Edge* (2018). <https://projectzero.google/2018/05/bypassing-mitigations-by-attacking-jit.html>
494. Crispin Cowan — *Strengthening the Microsoft Edge Sandbox* (2017). <https://blogs.windows.com/msedgedev/2017/03/23/strengthening-microsoft-edge-sandbox/>
495. *PROCESS_MITIGATION_IMAGE_LOAD_POLICY*. <https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-process_mitigation_image_load_policy>
496. James Forshaw — *Windows 10 Symbolic Link Mitigations* (2015). <https://projectzero.google/2015/08/windows-10hh-symbolic-link-mitigations.html>
497. *RedirectionGuard: Mitigating unsafe junction traversal in Windows* (2025). <https://www.microsoft.com/en-us/msrc/blog/2025/06/redirectionguard-mitigating-unsafe-junction-traversal-in-windows/>
498. *Exploit protection reference (Microsoft Defender)*. <https://learn.microsoft.com/en-us/defender-endpoint/exploit-protection-reference>
499. *PACIA, PACIA1716, PACIASP, PACIAZ, PACIZA — Pointer Authentication Code for Instruction address, using key A*. <https://developer.arm.com/documentation/ddi0602/2025-12/Base-Instructions/PACIA--PACIA1716--PACIASP--PACIAZ--PACIZA--Pointer-Authentication-Code-for-Instruction-address--using-key-A-?lang=en>
500. Apple Inc. — *Hardened Runtime*. <https://developer.apple.com/documentation/security/hardened_runtime>
501. Jonathan Corbet — *Forward-edge control-flow integrity for the kernel* (2022). <https://lwn.net/Articles/898040/>
502. *Control Flow Integrity (Clang)*. <https://clang.llvm.org/docs/ControlFlowIntegrity.html>
503. Samuel Gross — *The V8 Sandbox* (2024). <https://v8.dev/blog/sandbox>
504. Arm Ltd. — *Memory safety: Arm Memory Tagging Extension*. <https://newsroom.arm.com/blog/memory-safety-arm-memory-tagging-extension>
505. *Chakra JIT CFG Bypass* (2016). <https://theori.io/blog/chakra-jit-cfg-bypass>
506. Hong Hu, Shweta Shinde, Sendroiu Adrian, Zheng Leong Chua, Prateek Saxena, Zhenkai Liang — *Data-Oriented Programming: On the Expressiveness of Non-Control Data Attacks* (2016). <https://huhong789.github.io/papers/hu:dop.pdf>
507. Matt Miller — *Trends, challenges, and shifts in software vulnerability mitigation* (2019). [https://github.com/microsoft/MSRC-Security-Research/raw/master/presentations/2019_02_BlueHatIL/2019_01%20-%20BlueHatIL%20-%20Trends%2C%20challenge%2C%20and%20shifts%20in%20software%20vulnerability%20mitigation.pdf](https://github.com/microsoft/MSRC-Security-Research/raw/master/presentations/2019_02_BlueHatIL/2019_01%20-%20BlueHatIL%20-%20Trends%2C%20challenge%2C%20and%20shifts%20in%20software%20vulnerability%20mitigation.pdf)
508. Catalin Cimpanu — *Microsoft: 70 percent of all security bugs are memory safety issues* (2019). <https://www.zdnet.com/article/microsoft-70-percent-of-all-security-bugs-are-memory-safety-issues/>
509. Adam Burch — *Using Rust in Windows* (2019). <https://msrc.microsoft.com/blog/2019/11/using-rust-in-windows/>
510. *Return Flow Guard*. <https://xlab.tencent.com/en/2016/11/02/return-flow-guard/>
511. Nicolas Falliere, Liam O Murchu, Eric Chien. W32.Stuxnet Dossier (Version 1.4). 2011. <https://archive.org/download/w32_stuxnet_dossier/w32_stuxnet_dossier.pdf>
512. Nicolas Falliere, Liam O Murchu, Eric Chien — *W32.Stuxnet Dossier, Version 1.4*, 2011. <https://archive.org/details/w32_stuxnet_dossier>
513. Microsoft Learn — *Authenticode Digital Signatures* (2024). <https://learn.microsoft.com/en-us/windows-hardware/drivers/install/authenticode>
514. App Control for Business. <https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/>
515. Microsoft Defender SmartScreen overview. <https://learn.microsoft.com/en-us/windows/security/operating-system-security/virus-and-threat-protection/microsoft-defender-smartscreen/>
516. Microsoft Edge support for Microsoft Defender SmartScreen. <https://learn.microsoft.com/en-us/deployedge/microsoft-edge-security-smartscreen>
517. Select Types of Rules to Create. <https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/select-types-of-rules-to-create>
518. Windows Authenticode Portable Executable Signature Format. 2008. <https://download.microsoft.com/download/9/c/5/9c5b2167-8017-4bae-9fde-d599bac8184a/Authenticode_PE.docx>
519. Microsoft and VeriSign Provide First Technology for Secure Downloading of Software Over the Internet. 1996. <https://news.microsoft.com/source/1996/08/07/microsoft-and-verisign-provide-first-technology-for-secure-downloading-of-software-over-the-internet/>
520. Burt Kaliski. PKCS #7: Cryptographic Message Syntax Version 1.5 (RFC 2315). 1998. <https://datatracker.ietf.org/doc/html/rfc2315>
521. Russell Housley. Cryptographic Message Syntax (CMS) (RFC 5652). 2009. <https://datatracker.ietf.org/doc/html/rfc5652>
522. Ron Rivest, Adi Shamir, Leonard Adleman. A Method for Obtaining Digital Signatures and Public-Key Cryptosystems. 1978. <https://people.csail.mit.edu/rivest/Rsapaper.pdf>
523. Whitfield Diffie, Martin Hellman. New Directions in Cryptography. 1976. <https://ee.stanford.edu/~hellman/publications/24.pdf>
524. Microsoft Security Bulletin MS13-098. 2013. <https://docs.microsoft.com/en-us/security-updates/securitybulletins/2013/ms13-098>
525. Catalog Files and Digital Signatures. <https://learn.microsoft.com/en-us/windows-hardware/drivers/install/catalog-files>
526. Driver Signing. <https://learn.microsoft.com/en-us/windows-hardware/drivers/install/digital-signatures>
527. Microsoft Security Advisory 2718704. 2012. <https://docs.microsoft.com/en-us/security-updates/securityadvisories/2012/2718704>
528. Marc Stevens. Counter-Cryptanalysis. 2013. <https://link.springer.com/chapter/10.1007/978-3-642-40041-4_8>
529. Alexander Sotirov, Marc Stevens, Jacob Appelbaum, Arjen Lenstra, David Molnar, Dag Arne Osvik, Benne de Weger. MD5 considered harmful today: Creating a rogue CA certificate. 2008. <https://www.win.tue.nl/hashclash/rogue-ca/>
530. Program Requirements -- Microsoft Trusted Root Program. <https://learn.microsoft.com/en-us/security/trusted-root/program-requirements>
531. Minimum Requirements for the Issuance and Management of Publicly-Trusted Code Signing Certificates. 2016. <https://pkic.org/uploads/2016/09/Minimum-requirements-for-the-Issuance-and-Management-of-code-signing.pdf>
532. CA/Browser Forum Code Signing Documents. <https://cabforum.org/working-groups/code-signing/documents/>
533. CA/Browser Forum Code Signing Certificate Working Group. <https://cabforum.org/working-groups/code-signing/>
534. Attestation Signing a Kernel Driver for Public Release. <https://learn.microsoft.com/en-us/windows-hardware/drivers/dashboard/attestation-signing-a-kernel-driver-for-public-release>
535. Driver Signing Offerings. <https://learn.microsoft.com/en-us/windows-hardware/drivers/dashboard/driver-signing-offerings>
536. Deprecation of Software Publisher Certificates and Commercial Release Certificates. <https://learn.microsoft.com/en-us/windows-hardware/drivers/install/deprecation-of-software-publisher-certificates-and-commercial-release-certificates>
537. *App Control for Business and AppLocker Overview*, 2026. <https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/appcontrol-and-applocker-overview>
538. Operation ShadowHammer. 2019. <https://securelist.com/operation-shadowhammer/89992/>
539. Bitwarden Statement on the Checkmarx Supply Chain Incident. 2026. <https://community.bitwarden.com/t/bitwarden-statement-on-checkmarx-supply-chain-incident/96127>
540. Bitwarden CLI Compromised in Ongoing npm Supply-Chain Campaign. 2026. <https://thehackernews.com/2026/04/bitwarden-cli-compromised-in-ongoing.html>
541. Bitwarden CLI Hijacked on npm: Bun-Staged Credential Stealer. 2026. <https://www.stepsecurity.io/blog/bitwarden-cli-hijacked-on-npm-bun-staged-credential-stealer-targets-developers-github-actions-and-ai-tools>
542. CryptCATAdminCalcHashFromFileHandle function. <https://learn.microsoft.com/en-us/windows/win32/api/mscat/nf-mscat-cryptcatadmincalchashfromfilehandle>
543. Deploy Catalog Files to Support App Control for Business. <https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/deployment/deploy-catalog-files-to-support-appcontrol>
544. Carlisle Adams, Pat Cain, Denis Pinkas, Robert Zuccherato. Internet X.509 Public Key Infrastructure Time-Stamp Protocol (TSP) (RFC 3161). 2001. <https://datatracker.ietf.org/doc/html/rfc3161>
545. WinVerifyTrust function. <https://learn.microsoft.com/en-us/windows/win32/api/wintrust/nf-wintrust-winverifytrust>
546. App Control for Business Event ID Explanations. <https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/operations/event-id-explanations>
547. Use Code Signing for Better Control and Protection. <https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/deployment/use-code-signing-for-better-control-and-protection>
548. Protecting Against Malware in macOS. <https://support.apple.com/guide/security/protecting-against-malware-sec469d47bd8/web>
549. Linux Integrity Subsystem. <https://sourceforge.net/p/linux-ima/wiki/Home/>
550. APK Signature Scheme v3. <https://source.android.com/docs/security/features/apksigning/v3>
551. Sigstore Overview. <https://docs.sigstore.dev/about/overview/>
552. Signing Blobs with Cosign. <https://docs.sigstore.dev/cosign/signing/signing_with_blobs/>
553. sigstore/rekor (GitHub). [https://github.com/sigstore/rekor](https://github.com/sigstore/rekor)
554. Doowon Kim, Bum Jun Kwon, Tudor Dumitraș. Certified Malware: Measuring Breaches of Trust in the Windows Code-Signing PKI. 2017. <https://users.umiacs.umd.edu/~tdumitra/papers/CCS-2017.pdf>
555. David McGrew, Michael Curcio, Scott Fluhrer. Leighton-Micali Hash-Based Signatures (RFC 8554). 2019. <https://datatracker.ietf.org/doc/html/rfc8554>
556. Russ Housley. Use of Edwards-Curve Digital Signature Algorithm (EdDSA) Signatures in the Cryptographic Message Syntax (CMS) (RFC 8419). 2018. <https://datatracker.ietf.org/doc/html/rfc8419>
557. Internet Explorer 3. <https://en.wikipedia.org/wiki/Internet_Explorer_3>
558. Code signing. <https://en.wikipedia.org/wiki/Code_signing>
559. Stuxnet. <https://en.wikipedia.org/wiki/Stuxnet>
560. Flame (malware). <https://en.wikipedia.org/wiki/Flame_(malware)>
561. Wikipedia contributors. *Windows Vista*. <https://en.wikipedia.org/wiki/Windows_Vista>. Accessed 2026-05-10. Vista released to manufacturing November 8, 2006; general availability January 30, 2007; first release with UAC, MIC, and IE Protected Mode.
562. *AppLocker Architecture and Components*, 2026. <https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/applocker-architecture-and-components>
563. *Applications that can bypass App Control and how to block them*, 2026. <https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/applications-that-can-bypass-appcontrol>
564. Oddvar Moe — *UltimateAppLockerByPassList*, 2024. [https://github.com/api0cradle/UltimateAppLockerByPassList](https://github.com/api0cradle/UltimateAppLockerByPassList)
565. Jimmy Bayne — *UltimateWDACBypassList*, 2024. [https://github.com/bohops/UltimateWDACBypassList](https://github.com/bohops/UltimateWDACBypassList)
566. Microsoft Security Team — *Introducing Windows Defender Application Control*, 2017. <https://www.microsoft.com/en-us/security/blog/2017/10/23/introducing-windows-defender-application-control/>
567. *CERT Advisory CA-2000-04 Love Letter Worm*, 2000. [https://web.archive.org/web/20140109062734/http://www.cert.org:80/advisories/CA-2000-04.html](https://web.archive.org/web/20140109062734/http://www.cert.org:80/advisories/CA-2000-04.html)
568. *CERT Advisory CA-2001-19 "Code Red" Worm Exploiting Buffer Overflow In IIS Indexing Service DLL*, 2001. [https://web.archive.org/web/20131209034953/http://www.cert.org/advisories/CA-2001-19.html](https://web.archive.org/web/20131209034953/http://www.cert.org/advisories/CA-2001-19.html)
569. *CERT Advisory CA-2001-26 Nimda Worm*, 2001. [https://web.archive.org/web/20131105111012/http://www.cert.org/advisories/CA-2001-26.html](https://web.archive.org/web/20131105111012/http://www.cert.org/advisories/CA-2001-26.html)
570. John Lambert — *Software Restriction Policies in Windows XP*, 2002. <https://www.virusbulletin.com/uploads/pdf/conference/vb2002/johnlambert_vb2002.pdf>
571. *What Is AppLocker? (archived TechNet)*, 2024. <https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/ee424367(v=ws.11)>
572. *Windows 7 Lifecycle*, 2026. <https://learn.microsoft.com/en-us/lifecycle/products/windows-7>
573. *Windows Server 2008 R2 Lifecycle*, 2026. <https://learn.microsoft.com/en-us/lifecycle/products/windows-server-2008-r2>
574. *Working with AppLocker Rules*, 2026. <https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/working-with-applocker-rules>
575. *App Control feature availability*, 2026. <https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/feature-availability>
576. Aaron Margosis — *AaronLocker GitHub repository*, 2024. [https://github.com/microsoft/AaronLocker](https://github.com/microsoft/AaronLocker)
577. Oddvar Moe — *AppLocker Case Study: How insecure is it really? Part 1*, 2017. <https://oddvar.moe/2017/12/13/applocker-case-study-how-insecure-is-it-really-part-1/>
578. Oddvar Moe — *AppLocker — Case study: How insecure is it really? -- Part 2*, 2017. <https://oddvar.moe/2017/12/21/applocker-case-study-how-insecure-is-it-really-part-2/>
579. *Device protection in Windows Security*, 2026. <https://support.microsoft.com/windows/device-protection-in-windows-security-afa11526-de57-b1c5-599f-3a4c6a61c5e2>
580. *Windows 11 Enterprise and Education Lifecycle*, 2026. <https://learn.microsoft.com/en-us/lifecycle/products/windows-11-enterprise-and-education>
581. *Windows Server 2025 Lifecycle*, 2026. <https://learn.microsoft.com/en-us/lifecycle/products/windows-server-2025>
582. *Issue 411: Naming change to App Control for Business*, 2024. [https://github.com/MicrosoftDocs/WDAC-Toolkit/issues/411](https://github.com/MicrosoftDocs/WDAC-Toolkit/issues/411)
583. *PsSetLoadImageNotifyRoutine kernel API*, 2026. <https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetloadimagenotifyroutine>
584. *PsLookupProcessByProcessId kernel API*, 2026. <https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-pslookupprocessbyprocessid>
585. Aaron Margosis — *AaronLocker Create-Policies.ps1*, 2024. <https://raw.githubusercontent.com/microsoft/AaronLocker/main/AaronLocker/Create-Policies.ps1>
586. *Configure authorized apps deployed with a managed installer*, 2026. <https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/configure-authorized-apps-deployed-with-a-managed-installer>
587. *Use App Control with the Intelligent Security Graph*, 2026. <https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/use-appcontrol-with-intelligent-security-graph>
588. *App Control for Business policy wizard*, 2026. <https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/appcontrol-wizard>
589. *April 9 2024 KB5036893 (OS Builds 22621.3447 and 22631.3447)*, 2024. <https://support.microsoft.com/en-us/topic/april-9-2024-kb5036893-os-builds-22621-3447-and-22631-3447-a674a67b-85f5-4a40-8d74-5f8af8ead5bb>
590. *April 9 2024 KB5036892 (OS Builds 19044.4291 and 19045.4291)*, 2024. <https://support.microsoft.com/en-us/topic/april-9-2024-kb5036892-os-builds-19044-4291-and-19045-4291-expired-cb5d2d42-6b10-48f7-829a-be7d416a811b>
591. *Deploy multiple App Control policies*, 2026. <https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/deploy-multiple-appcontrol-policies>
592. *LOLBAS Project*, 2026. <https://lolbas-project.github.io/>
593. Matt Graeber — *WinDbg / CDB shellcode runner (Wayback preservation)*, 2016. [https://web.archive.org/web/2019/http://www.exploit-monday.com/2016/08/windbg-cdb-shellcode-runner.html](https://web.archive.org/web/2019/http://www.exploit-monday.com/2016/08/windbg-cdb-shellcode-runner.html)
594. Casey Smith — *Application Whitelisting Bypass: csi.exe (Wayback)*, 2016. [https://web.archive.org/web/20161008143428/http://subt0x10.blogspot.com/2016/09/application-whitelisting-bypass-csiexe.html](https://web.archive.org/web/20161008143428/http://subt0x10.blogspot.com/2016/09/application-whitelisting-bypass-csiexe.html)
595. Matt Nelson — *Bypassing Application Whitelisting by using dnx.exe*, 2016. <https://enigma0x3.net/2016/11/17/bypassing-application-whitelisting-by-using-dnx-exe/>
596. James Forshaw — *DG on Windows 10 S: Executing Arbitrary Code*, 2017. <https://www.tiraniddo.dev/2017/07/dg-on-windows-10-s-executing-arbitrary.html>
597. Jimmy Bayne — *DotNet Core: A Vector For AWL Bypass and Defense Evasion*, 2019. <https://bohops.com/2019/08/19/dotnet-core-a-vector-for-awl-bypass-defense-evasion/>
598. Peter Upfold — *Word hangs on saving: App Control for Business and webclnt.dll*, 2024. <https://peter.upfold.org.uk/blog/2024/07/28/word-hangs-on-saving-app-control-for-business-and-webclnt-dll/>
599. *Smart App Control overview*, 2026. <https://learn.microsoft.com/en-us/windows/apps/develop/smart-app-control/overview>
600. *Smart App Control: Frequently Asked Questions*, 2026. <https://support.microsoft.com/en-us/windows/smart-app-control-frequently-asked-questions-285ea03d-fa88-4d56-882e-6698afdb7003>
601. *App Control script enforcement*, 2026. <https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/script-enforcement>
602. *ApplicationControl CSP*, 2026. <https://learn.microsoft.com/en-us/windows/client-management/mdm/applicationcontrol-csp>
603. *App Control for Business policy in Intune*, 2026. <https://learn.microsoft.com/en-us/intune/intune-service/protect/endpoint-security-app-control-policy>
604. *Announcing App Control for Business (aka WDAC) with OSConfig*, 2024. <https://techcommunity.microsoft.com/discussions/windowsserverinsiders/announcing-app-control-for-business-aka-wdac-with-osconfig/4268618>
605. Microsoft Learn — *Deprecated features for Windows client (NTLM row).* <https://learn.microsoft.com/en-us/windows/whats-new/deprecated-features>
606. *October 8 2024 KB5044288 (OS Build 25398.1189)*, 2024. <https://support.microsoft.com/en-us/topic/october-8-2024-kb5044288-os-build-25398-1189-07468931-d90b-4566-9865-f435fe4c3ea8>
607. *Implementing application control (ACSC)*, 2026. <https://www.cyber.gov.au/business-government/protecting-devices-systems/hardening-systems-applications/system-hardening/implementing-application-control>
608. Souppaya, Scarfone — *NIST SP 800-167: Guide to Application Whitelisting*, 2015. <https://csrc.nist.gov/publications/detail/sp/800-167/final>
609. Mark Russinovich — *AccessChk Sysinternals*, 2022. <https://learn.microsoft.com/en-us/sysinternals/downloads/accesschk>
610. *Policy Configuration Agent in Microsoft Intune*, 2026. <https://learn.microsoft.com/en-us/intune/copilot/agents/policy-configuration-agent>
611. *Manage the Policy Configuration Agent in Microsoft Intune*, 2026. <https://learn.microsoft.com/en-us/intune/copilot/agents/manage-policy-configuration-agent>
612. *Security Copilot in Intune features overview*, 2026. <https://learn.microsoft.com/en-us/intune/copilot/>
613. *MicrosoftDocs WDAC-Toolkit*, 2024. [https://github.com/MicrosoftDocs/WDAC-Toolkit](https://github.com/MicrosoftDocs/WDAC-Toolkit)
614. *PCI Security Standards Document Library*, 2026. <https://www.pcisecuritystandards.org/document_library>
615. *Deploy Code Integrity Policies (Wayback 2017)*, 2017. [https://web.archive.org/web/20170101000000/https://docs.microsoft.com/en-us/windows/device-security/device-guard/deploy-code-integrity-policies-steps](https://web.archive.org/web/20170101000000/https://docs.microsoft.com/en-us/windows/device-security/device-guard/deploy-code-integrity-policies-steps)
616. *What Is AppLocker (Microsoft Learn)*, 2024. <https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/what-is-applocker>
617. Andy Greenberg — *He Perfected a Password-Hacking Tool, then the Russians Came Calling* (2017). <https://www.wired.com/story/how-mimikatz-became-go-to-hacker-tool/>
618. Benjamin Delpy — *mimikatz 1.0 vient de sortir en version alpha! (Wayback snapshot)*, 2011. [https://web.archive.org/web/20110910081729/http://blog.gentilkiwi.com/mimikatz](https://web.archive.org/web/20110910081729/http://blog.gentilkiwi.com/mimikatz)
619. Microsoft — *Mitigating Pass-the-Hash (PtH) Attacks and Other Credential Theft* (versions 1 and 2). <https://www.microsoft.com/en-us/download/details.aspx?id=36036>
620. Microsoft Trustworthy Computing Group — *Mitigating Pass-the-Hash and Other Credential Theft, Version 2*, 2014. <https://download.microsoft.com/download/7/7/A/77ABC5BD-8320-41AF-863C-6ECFB10CB4B9/Mitigating-Pass-the-Hash-Attacks-and-Other-Credential-Theft-Version-2.pdf>
621. *Credential Guard overview (Microsoft Learn)*, 2024. <https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard>
622. Kim Zetter — *Countdown to Zero Day: Stuxnet and the Launch of the World's First Digital Weapon*, 2014. ISBN 978-0770436179
623. *Microsoft Security Bulletin MS10-046 — Critical (Windows Shell LNK RCE)*, 2010. <https://learn.microsoft.com/en-us/security-updates/SecurityBulletins/2010/ms10-046>
624. Benjamin Delpy — *mimikatz/sekurlsa (Wayback snapshot)*, 2011. [https://web.archive.org/web/20110711232613/http://blog.gentilkiwi.com/mimikatz/sekurlsa](https://web.archive.org/web/20110711232613/http://blog.gentilkiwi.com/mimikatz/sekurlsa)
625. Pavel Yosifovich, Alex Ionescu, Mark Russinovich, David Solomon — *Windows Internals, Part 1 (7th edition)* (2017). <https://learn.microsoft.com/en-us/sysinternals/resources/windows-internals>
626. *Credentials Processes in Windows Authentication (Microsoft Learn)*, 2025. <https://learn.microsoft.com/en-us/windows-server/security/windows-authentication/credentials-processes-in-windows-authentication>
627. *Understand AppLocker policy design decisions (Microsoft Learn)*, 2024. <https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/understand-applocker-policy-design-decisions>
628. Joanna Rutkowska, Alex Tereshkin — *Evil Maid Goes After TrueCrypt! (Invisible Things Lab, October 16, 2009; Wayback snapshot)*, 2009. [https://web.archive.org/web/20110114043427/http://theinvisiblethings.blogspot.com/2009/10/evil-maid-goes-after-truecrypt.html](https://web.archive.org/web/20110114043427/http://theinvisiblethings.blogspot.com/2009/10/evil-maid-goes-after-truecrypt.html)
629. *DirectAccess Design Guide for Windows 7 / Server 2008 R2 (Microsoft Learn archive)*, 2012. <https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/ee649191(v=ws.10)>
630. Ralph Langner — *To Kill a Centrifuge: A Technical Analysis of What Stuxnet's Creators Tried to Achieve*, 2013. <https://archive.org/details/to-kill-a-centrifuge>
631. Bruce Dang, Peter Ferrie — *Adventures in Analyzing Stuxnet (27C3)*, 2010. <https://media.ccc.de/v/27c3-4245-en-adventures_in_analyzing_stuxnet>
632. *Microsoft Security Bulletin MS10-061 — Critical (Print Spooler RCE)*, 2010. <https://learn.microsoft.com/en-us/security-updates/SecurityBulletins/2010/ms10-061>
633. *Microsoft Security Bulletin MS10-073 — Important (Windows Kernel-Mode Drivers LPE)*, 2010. <https://learn.microsoft.com/en-us/security-updates/SecurityBulletins/2010/ms10-073>
634. *Microsoft Security Bulletin MS10-092 — Important (Task Scheduler LPE)*, 2010. <https://learn.microsoft.com/en-us/security-updates/SecurityBulletins/2010/ms10-092>
635. *Microsoft Security Bulletin MS08-067 — Critical (Server Service RCE)*, 2008. <https://learn.microsoft.com/en-us/security-updates/SecurityBulletins/2008/ms08-067>
636. Brian Krebs — *Adobe, Microsoft, WordPress Issue Security Fixes (February 2011 autorun re-release)*, 2011. <https://krebsonsecurity.com/2011/02/adobe-microsoft-wordpress-issue-security-fixes/>
637. David Drummond — *A New Approach to China (Operation Aurora disclosure)*, 2010. <https://googleblog.blogspot.com/2010/01/new-approach-to-china.html>
638. David Drummond — *A New Approach to China (Operation Aurora disclosure — Wayback snapshot 2010-01-13)*, 2010. [https://web.archive.org/web/20100113172117/http://googleblog.blogspot.com/2010/01/new-approach-to-china.html](https://web.archive.org/web/20100113172117/http://googleblog.blogspot.com/2010/01/new-approach-to-china.html)
639. *NVD CVE-2010-0249 (Operation Aurora IE use-after-free)*, 2010. <https://nvd.nist.gov/vuln/detail/CVE-2010-0249>
640. *Adobe Investigates Corporate Network Security Issue*, 2010. <https://blogs.adobe.com/conversations/2010/01/adobe_investigates_corporate_n.html>
641. *Operation Aurora (Wikipedia)*, 2024. <https://en.wikipedia.org/wiki/Operation_Aurora>
642. Ariana Eunjung Cha, Ellen Nakashima — *Google China cyberattack part of vast espionage campaign, experts say*, 2010. <https://www.washingtonpost.com/wp-dyn/content/article/2010/01/13/AR2010011300359.html>
643. Dmitri Alperovitch — *More Details on Operation 'Aurora' (McAfee Labs)*, 2010. <https://www.mcafee.com/blogs/other-blogs/mcafee-labs/more-details-on-operation-aurora/>
644. *Microsoft Security Bulletin MS10-002 — Critical (Cumulative Security Update for Internet Explorer)*, 2010. <https://learn.microsoft.com/en-us/security-updates/SecurityBulletins/2010/ms10-002>
645. Skip Duckwall, Chris Campbell — *Pass-the-Hash 2: The Admin's Revenge (Black Hat USA 2013)*, 2013. <https://media.blackhat.com/us-13/US-13-Duckwall-Pass-the-Hash-2-The-Admins-Revenge-Slides.pdf>
646. *MS-NLMP Section 3.3.2: NTLM v2 Authentication (Microsoft Open Specifications)*, 2024. <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/5e550938-91d4-459f-b67d-75d70009e3f3>
647. Dell SecureWorks Counter Threat Unit — *Skeleton Key Malware Analysis*, 2015. <https://www.secureworks.com/research/skeleton-key-malware-analysis>
648. Andy Robbins, Will Schroeder, Rohan Vazarkar — *Six Degrees of Domain Admin — Using Graph Theory to Accelerate Red Team Operations (DEF CON 24)*, 2016. <https://media.defcon.org/DEF%20CON%2024/DEF%20CON%2024%20presentations/DEF%20CON%2024%20-%20Robbins-Vazarkar-Schroeder-Six-Degrees-of-Domain-Admin.pdf>
649. Benjamin Delpy, Skip Duckwall — *Abusing Microsoft Kerberos: Sorry You Guys Don't Get It (Black Hat USA 2014)*, 2014. <https://www.blackhat.com/us-14/archives.html>
650. Sean Metcalf — *Kerberos Golden Ticket (ADSecurity.org)*, 2015. <https://adsecurity.org/?p=1640>
651. Benjamin Delpy — *mimikatz/modules/sekurlsa/kuhl_m_sekurlsa_utils.c (per-Windows-build signature table)*, 2024. <https://raw.githubusercontent.com/gentilkiwi/mimikatz/master/mimikatz/modules/sekurlsa/kuhl_m_sekurlsa_utils.c>
652. Benjamin Delpy — *gentilkiwi/mimikatz August 2014 commit listing (GitHub API)*, 2014. <https://api.github.com/repos/gentilkiwi/mimikatz/commits?since=2014-08-01T00:00:00Z&until=2014-08-31T23:59:59Z&per_page=100>
653. Sean Metcalf — *Mimikatz DCSync Usage, Exploitation, and Detection (ADSecurity.org)*, 2015. <https://adsecurity.org/?p=1729>
654. Brian Krebs — *Microsoft Releases Emergency Security Update (Schannel)*, 2014. <https://krebsonsecurity.com/2014/11/microsoft-releases-emergency-security-update/>
655. *NVD CVE-2014-6321 (Schannel WinShock)*, 2014. <https://nvd.nist.gov/vuln/detail/CVE-2014-6321>
656. *Microsoft Security Bulletin MS14-066 — Critical (Schannel RCE)*, 2014. <https://learn.microsoft.com/en-us/security-updates/SecurityBulletins/2014/ms14-066>
657. *Microsoft 365 network connectivity principles (Microsoft Learn)*, 2026. <https://learn.microsoft.com/en-us/microsoft-365/enterprise/microsoft-365-network-connectivity-principles>
658. D. E. Bell, L. J. LaPadula — *Secure Computer System: Unified Exposition and Multics Interpretation*, 1976. <https://csrc.nist.gov/files/pubs/conference/1998/10/08/proceedings-of-the-21st-nissc-1998/final/docs/early-cs-papers/bell76.pdf>
659. D. E. Bell, L. J. LaPadula — *Secure Computer Systems: Mathematical Foundations*, MITRE Technical Report 2547, Volume I, 1973. <https://apps.dtic.mil/sti/citations/AD0770768>
660. Butler W. Lampson — *A Note on the Confinement Problem*, Communications of the ACM 16(10), 1973. <https://dl.acm.org/doi/10.1145/362375.362389>
661. Alex Ionescu — *Battle of SKM and IUM: How Windows 10 Rewrites the OS Architecture (Black Hat USA 2015)*, 2015. <http://publications.alex-ionescu.com/BlackHat/BlackHat%202015%20-%20Battle%20of%20SKM%20and%20IUM.pdf>
662. Mark Russinovich, Thomas Garnier — *Sysmon — Sysinternals (Microsoft Learn)*, 2026. <https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon>
663. *OS Credential Dumping: LSASS Memory (MITRE ATT&CK T1003.001)*, 2024. <https://attack.mitre.org/techniques/T1003/001/>
664. *Configure Credential Guard (Microsoft Learn)*, 2026. <https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/configure>
665. Hernan Ochoa — *Pass-The-Hash Toolkit (Core Security Corelabs; iam.exe / whosthere.exe, 2008; Wayback snapshot)*, 2008. [https://web.archive.org/web/20150910081824/http://www.coresecurity.com/corelabs-research/open-source-tools/pass-hash-toolkit](https://web.archive.org/web/20150910081824/http://www.coresecurity.com/corelabs-research/open-source-tools/pass-hash-toolkit)
666. Paul Ashton / Exploit-DB — *Microsoft Windows NT 4.0 SP5 / Terminal Server 4.0 - 'Pass the Hash' with Modified SMB Client.* <https://www.exploit-db.com/raw/19197>
667. ly4k/PassTheChallenge. [https://github.com/ly4k/PassTheChallenge](https://github.com/ly4k/PassTheChallenge)
668. LSA Authentication. <https://learn.microsoft.com/en-us/windows/win32/secauthn/lsa-authentication>
669. Hernan Ochoa. *Pass-The-Hash Toolkit*. <https://web.archive.org/web/20080817055631/http://oss.coresecurity.com/projects/pshtoolkit.htm>
670. Microsoft Security Advisory: Update to improve credentials protection and management (May 13, 2014). <https://support.microsoft.com/en-us/topic/microsoft-security-advisory-update-to-improve-credentials-protection-and-management-may-13-2014-93434251-04ac-b7f3-52aa-9f951c14b649>
671. Battle of SKM and IUM: How Windows 10 Rewrites OS Architecture. [https://github.com/tpn/pdfs/blob/master/Battle%20of%20SKM%20and%20IUM%20-%20How%20Windows%2010%20Rewrites%20OS%20Architecture%20-%20Alex%20Ionescu%20-%202015%20%28blackhat2015%29.pdf](https://github.com/tpn/pdfs/blob/master/Battle%20of%20SKM%20and%20IUM%20-%20How%20Windows%2010%20Rewrites%20OS%20Architecture%20-%20Alex%20Ionescu%20-%202015%20%28blackhat2015%29.pdf)
672. Microsoft — *Protected Users security group* (2025). <https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group>
673. Brandon LeBlanc. *Windows 8.1 now available!*. <https://blogs.windows.com/windowsexperience/2013/10/17/windows-8-1-now-available/>
674. Jeff Meisner. *Save the date: Windows Server 2012 R2, Windows System Center 2012 R2 and Windows Intune update coming Oct. 18*. <https://blogs.microsoft.com/blog/2013/08/14/save-the-date-windows-server-2012-r2-windows-system-center-2012-r2-and-windows-intune-update-coming-oct-18/>
675. Microsoft Ignite: The day-one wrap-up (Wayback Machine snapshot, February 2025). <https://web.archive.org/web/2025/https://www.itprotoday.com/unified-communications/microsoft-ignite-the-day-one-wrap-up>
676. What's new in Windows Server 2016. <https://learn.microsoft.com/en-us/windows-server/get-started/whats-new-in-windows-server-2016>
677. Pass-the-Challenge: Defeating Credential Guard (Wayback). <https://web.archive.org/web/20240203005631/https://research.ifcr.dk/pass-the-challenge-defeating-credential-guard-31a892eee22>
678. Microsoft Learn. *Windows Server release information*. <https://learn.microsoft.com/en-us/windows/release-health/windows-server-release-info>
679. SSP Packages Provided by Microsoft. <https://learn.microsoft.com/en-us/windows/win32/secauthn/ssp-packages-provided-by-microsoft>
680. `Win32_DeviceGuard` schema. <https://learn.microsoft.com/en-us/windows/security/threat-protection/device-guard/enable-virtualization-based-protection-of-code-integrity>
681. Credential Guard considerations and known issues. <https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/considerations-known-issues>
682. Microsoft Defender for Identity overview. <https://learn.microsoft.com/en-us/defender-for-identity/>
683. Microsoft — *Microsoft Entra: What is a Primary Refresh Token* (2025). <https://learn.microsoft.com/en-us/entra/identity/devices/concept-primary-refresh-token>
684. sssd-kcm(8) -- SSSD Kerberos Cache Manager. <https://man.archlinux.org/man/sssd-kcm.8.en>
685. Protecting Cached User Data (ChromiumOS design doc). <https://www.chromium.org/chromium-os/chromiumos-design-docs/protecting-cached-user-data/>
686. ly4k/Pypykatz (LSA Isolated Data fork). [https://github.com/ly4k/Pypykatz](https://github.com/ly4k/Pypykatz)
687. Microsoft Support. *Upcoming changes to NTLMv1 in Windows 11, version 24H2 and Windows Server 2025*. <https://support.microsoft.com/en-us/topic/upcoming-changes-to-ntlmv1-in-windows-11-version-24h2-and-windows-server-2025-c0554217-cdbc-420f-b47c-e02b2db49b2e>
688. Attacking Microsoft Kerberos: Kicking the Guard Dog of Hades (Tim Medin, DerbyCon 4). <https://www.irongeek.com/i.php?page=videos/derbycon4/t120-attacking-microsoft-kerberos-kicking-the-guard-dog-of-hades-tim-medin>
689. MITRE ATT&CK T1558.003 -- Kerberoasting. <https://attack.mitre.org/techniques/T1558/003/>
690. MITRE ATT&CK T1558.004 -- AS-REP Roasting. <https://attack.mitre.org/techniques/T1558/004/>
691. Wagging the Dog: Abusing Resource-Based Constrained Delegation to Attack Active Directory (2019). <https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html>
692. Exploiting RBCD using a normal user. <https://www.tiraniddo.dev/2022/05/exploiting-rbcd-using-normal-user.html>
693. Dec0ne — *KrbRelayUp.* [https://github.com/Dec0ne/KrbRelayUp](https://github.com/Dec0ne/KrbRelayUp)
694. Microsoft Learn. *Kerberos Constrained Delegation Overview in Windows Server*. <https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview#resource-based-constrained-delegation-across-domains>
695. Microsoft Learn. *ms-DS-Allowed-To-Act-On-Behalf-Of-Other-Identity attribute*. <https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-allowedtoactonbehalfofotheridentity>
696. Stephen Breen. *Hot Potato*. 2016. <https://foxglovesecurity.com/2016/01/16/hot-potato/>. Accessed 2026-05-10. Hot Potato disclosure (January 16, 2016); references Project Zero issue 222 as prior art seed.
697. Stephen Breen, Chris Mallz. *Rotten Potato — Privilege Escalation from Service Accounts to SYSTEM*. 2016. <https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/>. Accessed 2026-05-10. Rotten Potato three-step attack flow; explicit attribution to James Forshaw Project Zero issue 325 and BlackHat talk.
698. Andrea Pierini, Giuseppe Trotta. *ohpe/juicy-potato*. 2018. [https://github.com/ohpe/juicy-potato](https://github.com/ohpe/juicy-potato). Accessed 2026-05-10. Juicy Potato (2018); CLSID enumeration; configurable RPC port.
699. Clément Labro (itm4n). *PrintSpoofer — Abusing Impersonation Privileges on Windows 10 and Server 2019*. 2020. <https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/>. Accessed 2026-05-10. PrintSpoofer technique blog; named-pipe path-validation bypass; the canonical decoder_it quote.
700. *Antimalware Scan Interface Portal*, Microsoft Learn. <https://learn.microsoft.com/en-us/windows/win32/amsi/antimalware-scan-interface-portal>
701. Parag Mali — *VBS Trustlets: What Actually Runs in the Secure Kernel*, paragmali.com, 2026. <https://paragmali.com/blog/vbs-trustlets-what-actually-runs-in-the-secure-kernel/>
702. NTLMless: The Death of NTLM in Windows. <https://paragmali.com/blog/ntlmless-the-death-of-ntlm-in-windows>
703. protocol-defined string-to-key function. <https://en.wikipedia.org/wiki/Kerberos_(protocol)>
704. SMBRelay (Cult of the Dead Cow). <https://www.cultdeadcow.com/tools/smbrelay.html>
705. DigiNotar (Wikipedia). <https://en.wikipedia.org/wiki/DigiNotar>
706. hypervisor. <https://paragmali.com/blog/above-ring-zero-how-the-windows-hypervisor-became-a-security/>
707. Potato family. <https://paragmali.com/blog/windows-access-control-25-years-of-attacks/>
708. Remi Gascou — *Coercer.* [https://github.com/p0dalirius/Coercer](https://github.com/p0dalirius/Coercer)
709. SpecterOps — *Certified Pre-Owned: Abusing Active Directory Certificate Services.* <https://posts.specterops.io/certified-pre-owned-d95910965cd2>
710. Gilles Lionel (topotam77). *topotam/PetitPotam*. 2021. [https://github.com/topotam/PetitPotam](https://github.com/topotam/PetitPotam). Accessed 2026-05-10. PetitPotam coercion via MS-EFSRPC EfsRpcOpenFileRaw and other LSARPC-bound functions.
711. SpecterOps — *Certified Pre-Owned: Abusing Active Directory Certificate Services (whitepaper).* <https://specterops.io/assets/resources/Certified_Pre-Owned.pdf>
712. Fortra — *Impacket.* [https://github.com/fortra/impacket](https://github.com/fortra/impacket)
713. Microsoft Support — *KB5005413: Mitigating NTLM Relay Attacks on Active Directory Certificate Services (AD CS).* <https://support.microsoft.com/en-us/topic/kb5005413-mitigating-ntlm-relay-attacks-on-active-directory-certificate-services-ad-cs-3612b773-4043-4aa9-b23d-b87910cd3429>
714. Microsoft Open Specifications — *[MS-NLMP]: LMOWFv1().* <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/a724e8df-2b0a-4a36-aef4-2d2b56fd3db7>
715. Microsoft Open Specifications — *[MS-NLMP]: NT LAN Manager (NTLM) Authentication Protocol.* <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/b38c36ed-2804-4868-a9ff-8dd3182128e4>
716. Microsoft Open Specifications — *[MS-NLMP]: NTLM v1 Authentication.* <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/464551a8-9fc4-428e-b3d3-bc5bfb2e73a5>
717. Microsoft Tech Community. *The Evolution of Windows Authentication*. 2023. <https://techcommunity.microsoft.com/blog/windows-itpro-blog/the-evolution-of-windows-authentication/3926848>. Accessed 2026-05-10. NTLM future-disablement announcement; local KDC / IAKerb for both local and domain accounts; future disablement of NTLM in Windows 11.
718. mariam_gewida, Microsoft Windows IT Pro Blog — *Advancing Windows security: Disabling NTLM by default.* <https://techcommunity.microsoft.com/blog/windows-itpro-blog/advancing-windows-security-disabling-ntlm-by-default/4489526>
719. Dan Cuomo, Microsoft Windows OS Platform Blog — *Active Directory improvements in Windows Server 2025.* <https://techcommunity.microsoft.com/blog/windowsosplatform/active-directory-improvements-in-windows-server-2025/4202383>
720. Microsoft Learn — *NTLM Overview.* <https://learn.microsoft.com/en-us/windows-server/security/kerberos/ntlm-overview>
721. Microsoft Learn — *Extended Protection for Authentication Overview.* <https://learn.microsoft.com/en-us/dotnet/framework/wcf/feature-details/extended-protection-for-authentication-overview>
722. NIST NVD — *CVE-2019-1040 — NTLM MIC bypass (Drop the MIC).* <https://nvd.nist.gov/vuln/detail/CVE-2019-1040>
723. Cult of the Dead Cow — *The SMB Man-In-the-Middle Attack / SMBRelay.* <https://cultdeadcow.com/tools/smbrelay.html>
724. Microsoft Learn — *Overview of Server Message Block signing.* <https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/overview-server-message-block-signing>
725. NIST NVD — *CVE-2008-4037 — SMB Credential Reflection Vulnerability (MS08-068).* <https://nvd.nist.gov/vuln/detail/CVE-2008-4037>
726. Lee Christensen — *SpoolSample (PrinterBug).* [https://github.com/leechristensen/SpoolSample](https://github.com/leechristensen/SpoolSample)
727. CrowdStrike — *From the Archives: Drop the MIC — CVE-2019-1040.* <https://www.crowdstrike.com/en-us/blog/from-the-archives-drop-the-mic-cve-2019-1040/>
728. IETF kitten WG — *Initial and Pass Through Authentication Using Kerberos V5 and the GSS-API (IAKERB).* <https://datatracker.ietf.org/doc/draft-ietf-kitten-iakerb/>
729. Andreas Schneider — *Local authentication hub.* <https://blog.cryptomilk.org/2025/02/09/local-authentication-hub/>
730. Microsoft Open Specifications — *[MS-NEGOEX]: SPNEGO Extended Negotiation (NEGOEX) Security Mechanism.* <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-negoex/0ad7a003-ab56-4839-a204-b555ca6759a2>
731. IETF — *SPNEGO Extended Negotiation (NEGOEX) Security Mechanism (Internet-Draft).* <https://datatracker.ietf.org/doc/html/draft-zhu-negoex>
732. IETF — *RFC 8143: Using Transport Layer Security (TLS) with NNTP.* <https://datatracker.ietf.org/doc/rfc8143/>
733. Microsoft Support. *Overview of NTLM auditing enhancements in Windows 11 24H2 and Windows Server 2025*. 2025. <https://support.microsoft.com/en-us/topic/overview-of-ntlm-auditing-enhancements-in-windows-11-version-24h2-and-windows-server-2025-b7ead732-6fc5-46a3-a943-27a4571d9e7b>. Accessed 2026-05-10. Original publish date July 11, 2025; KB5064479; new audit logs in Microsoft\Windows\NTLM\Operational; client / server / domain-controller NTLMv1 audit channels.
734. Microsoft Learn — *Audit use of NTLMv1 on a Windows Server-based domain controller (KB 4090105).* <https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/audit-domain-controller-ntlmv1>
735. The Hacker News — *Microsoft Begins NTLM Phase-Out With Three-Stage Plan to Move Windows to Kerberos.* <https://thehackernews.com/2026/02/microsoft-begins-ntlm-phase-out-with.html>
736. European Commission — *NIS2 Directive: new rules on cybersecurity of network and information systems.* <https://digital-strategy.ec.europa.eu/en/policies/nis2-directive>
737. Microsoft Learn — *How to enable LDAP signing - Windows Server.* <https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/enable-ldap-signing-in-windows-server>
738. Rubeus. [https://github.com/GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
739. Microsoft Learn — *Kerberos authentication overview*. <https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-authentication-overview>
740. Using Encryption for Authentication in Large Networks of Computers (1978). <https://dl.acm.org/doi/10.1145/359657.359659>
741. C. Neuman, T. Yu, S. Hartman, K. Raeburn — *RFC 4120 -- The Kerberos Network Authentication Service (V5)* (2005). <https://datatracker.ietf.org/doc/html/rfc4120>
742. Needham-Schroeder protocol. <https://en.wikipedia.org/wiki/Needham%E2%80%93Schroeder_protocol>
743. [MS-PAC]: Privilege Attribute Certificate Data Structure — 2024. <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/>
744. Project Athena Technical Plan, Section E.2.1: Kerberos Authentication and Authorization System (1989). <https://web.mit.edu/Saltzer/www/publications/athenaplan/e.2.1.pdf>
745. Designing an Authentication System: a Dialogue in Four Scenes (1988). <https://web.mit.edu/kerberos/dialogue.html>
746. Kerberos: An Authentication Service for Open Network Systems (1988). <https://www.cerias.purdue.edu/apps/reports_and_papers/view/1760>
747. Bill Bryant, Jennifer Steiner, John Kohl. *Kerberos Installation Notes*. <https://raw.githubusercontent.com/jameshilliard/acs-GPL-3.3.0/5d2be5d30f3ccef7153906123c90405833b1bf13/tarbal/krb5-1.4/doc/old-V4-docs/installation.mss>
748. RFC 1510: The Kerberos Network Authentication Service (V5) — J. Kohl, C. Neuman; 1993. <https://datatracker.ietf.org/doc/html/rfc1510>
749. L. Zhu, B. Tung — *RFC 4556 -- Public Key Cryptography for Initial Authentication in Kerberos (PKINIT)* (2006). <https://datatracker.ietf.org/doc/html/rfc4556>
750. A Generalized Framework for Kerberos Pre-Authentication (2011). <https://datatracker.ietf.org/doc/html/rfc6113>
751. PKINIT Freshness Extension (2017). <https://datatracker.ietf.org/doc/html/rfc8070>
752. CVE-2020-17049: Kerberos KDC Security Feature Bypass (Bronze Bit) (2020). <https://nvd.nist.gov/vuln/detail/CVE-2020-17049>
753. CVE-2020-17049: Kerberos Bronze Bit Attack -- Theory (2020). <https://www.netspi.com/blog/technical-blog/network-pentesting/cve-2020-17049-kerberos-bronze-bit-attack-theory/>
754. [MS-PAC] Introduction. <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/166d8064-c863-41e1-9c23-edaaa5f36962>
755. CVE-2022-37967: Windows Kerberos Elevation of Privilege Vulnerability (KrbtgtFullPacSignature) (2022). <https://nvd.nist.gov/vuln/detail/CVE-2022-37967>
756. Microsoft — *KB5021131: Manage the Kerberos protocol changes related to CVE-2022-37966* (2022). <https://support.microsoft.com/en-us/topic/kb5021131-how-to-manage-the-kerberos-protocol-changes-related-to-cve-2022-37966-fd837ac3-cdec-4e76-a6ec-86e67501407d>
757. Encryption and Checksum Specifications for Kerberos 5 (2005). <https://datatracker.ietf.org/doc/html/rfc3961>
758. [MS-KILE] §2.2.7 -- Supported Encryption Types Bit Flags. <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/6cfc7b50-11ed-4b4d-846d-6f08f0812919>
759. K. Jaganathan, L. Zhu, J. Brezak — *RFC 4757 -- The RC4-HMAC Kerberos Encryption Types Used by Microsoft Windows* (2006). <https://datatracker.ietf.org/doc/html/rfc4757>
760. Beyond RC4 for Windows authentication (2025). <https://www.microsoft.com/en-us/windows-server/blog/2025/12/03/beyond-rc4-for-windows-authentication/>
761. Advanced Encryption Standard (AES) Encryption for Kerberos 5 (2005). <https://datatracker.ietf.org/doc/html/rfc3962>
762. AES Encryption with HMAC-SHA2 for Kerberos 5 (2016). <https://datatracker.ietf.org/doc/html/rfc8009>
763. Microsoft's guidance to help mitigate Kerberoasting (2024). <https://www.microsoft.com/en-us/security/blog/2024/10/11/microsofts-guidance-to-help-mitigate-kerberoasting/>
764. *Group Managed Service Accounts Overview*. <https://learn.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/group-managed-service-accounts-overview>
765. Delegated Managed Service Accounts Overview. <https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/delegated-managed-service-accounts/delegated-managed-service-accounts-overview>
766. OWASP Password Storage Cheat Sheet (Wayback snapshot, June 2023). [https://web.archive.org/web/20230621142207/https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html](https://web.archive.org/web/20230621142207/https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
767. Cracking Kerberos TGS Tickets Using Kerberoast -- Exploiting Kerberos to Compromise the Active Directory Domain. <https://adsecurity.org/?p=2293>
768. KB5008380 - Authentication updates (CVE-2021-42287). <https://support.microsoft.com/en-us/topic/kb5008380-authentication-updates-cve-2021-42287-9dafac11-e0d0-4cb8-959a-143bd0201041>
769. NVD — *CVE-2022-26923 -- Active Directory Domain Services Elevation of Privilege Vulnerability* (2022). <https://nvd.nist.gov/vuln/detail/CVE-2022-26923>
770. Microsoft — *KB5014754: Certificate-based authentication changes on Windows domain controllers* (2025). <https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16>
771. A Diamond Ticket in the Ruff — Charlie Clark, Andrew Schwartz; 2022. <https://www.semperis.com/blog/a-diamond-ticket-in-the-ruff/>
772. A Diamond (Ticket) in the Ruff — Andrew Schwartz, Charlie Clark; 2022. <https://www.trustedsec.com/blog/a-diamond-in-the-ruff>
773. Diamond and Sapphire Tickets. <https://pgj11.com/posts/Diamond-And-Sapphire-Tickets/>
774. Sapphire Ticket -- The Hacker Recipes. <https://www.thehacker.recipes/a-d/movement/kerberos/forged-tickets/sapphire>
775. Next-Gen Kerberos Attacks: Sapphire and Diamond Tickets (2022). <https://unit42.paloaltonetworks.com/next-gen-kerberos-attacks/>
776. New Attack Paths? AS Requested STs (2022). <https://www.semperis.com/blog/new-attack-paths-as-requested-sts/>
777. Microsoft. *Protected Users Security Group*. <https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/dn466518(v=ws.11)>
778. Microsoft. *Authentication Policies and Authentication Policy Silos*. <https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/authentication-policies-and-authentication-policy-silos>
779. Privileged access: Enterprise access model. <https://learn.microsoft.com/en-us/security/privileged-access-workstations/privileged-access-access-model>
780. Remote Credential Guard. <https://learn.microsoft.com/en-us/windows/security/identity-protection/remote-credential-guard>
781. Microsoft. *Group Managed Service Accounts overview*. <https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/group-managed-service-accounts/group-managed-service-accounts/group-managed-service-accounts-overview>
782. localkdc -- A General Local Authentication Hub (2025). <https://fosdem.org/2025/schedule/event/fosdem-2025-5618-localkdc-a-general-local-authentication-hub/>
783. MIT krb5-1.9 README -- Major changes in 1.9 (2010). <https://web.mit.edu/kerberos/krb5-1.9/README-1.9.txt>
784. MIT krb5 Release 1.9 (2010). <https://web.mit.edu/kerberos/krb5-1.9/>
785. MIT krb5 Release 1.15. <https://web.mit.edu/kerberos/krb5-1.15/>
786. Microsoft. *Microsoft Entra Kerberos FAQ*. <https://learn.microsoft.com/en-us/entra/identity/authentication/kerberos-faq>
787. MITRE — *Steal or Forge Kerberos Tickets: Golden Ticket (T1558.001)* (2024). <https://attack.mitre.org/techniques/T1558/001/>
788. MITRE ATT&CK T1003.006 — OS Credential Dumping: DCSync. <https://attack.mitre.org/techniques/T1003/006/>
789. Microsoft — *AD Forest Recovery - Resetting the krbtgt password* (2024). <https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/ad-forest-recovery-resetting-the-krbtgt-password>
790. Domain of Thrones: Part II — Nico Shyne, Josh Prager; 2023. <https://specterops.io/blog/2023/11/06/domain-of-thrones-part-ii/>
791. Understand default user accounts in Active Directory. <https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-default-user-accounts>
792. Security identifiers in Active Directory. <https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers>
793. KRBTGT Account Password Reset Scripts now available for customers — Sean Metcalf. <https://adsecurity.org/?p=483>
794. [MS-KILE]: Kerberos Protocol Extensions — 2026. <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/>
795. KB5020805: How to manage Kerberos protocol changes related to CVE-2022-37967 — 2023. <https://support.microsoft.com/en-us/topic/kb5020805-how-to-manage-kerberos-protocol-changes-related-to-cve-2022-37967-997e9acc-67c5-48e1-8d0d-190269bf4efb>
796. Looking back at Project Athena — MIT News; 2018. <https://news.mit.edu/2018/mit-looking-back-project-athena-distributed-computing-for-students-1111>
797. Athena history (1983-present) from A to Z — MIT Academic Computing Services. <https://web.mit.edu/acs/athena.html>
798. Microsoft Releases Windows 2000 to Manufacturing — Microsoft News Center; 1999. <https://news.microsoft.com/source/1999/12/15/microsoft-releases-windows-2000-to-manufacturing/>
799. Microsoft Security Bulletin MS14-068: Vulnerability in Kerberos Could Allow Elevation of Privilege (3011780) — 2014. <https://learn.microsoft.com/en-us/security-updates/securitybulletins/2014/ms14-068>
800. NVD: CVE-2014-6324 — Kerberos Checksum Vulnerability — 2014. <https://nvd.nist.gov/vuln/detail/CVE-2014-6324>
801. Alva Duckwall, Benjamin Delpy — *Abusing Microsoft Kerberos: Sorry You Guys Don't Get It (Black Hat USA 2014)* (2014). <https://infocondb.org/con/black-hat/black-hat-usa-2014/abusing-microsoft-kerberos-sorry-you-guys-dont-get-it>
802. Microsoft Defender for Identity — Classic alerts catalogue. <https://learn.microsoft.com/en-us/defender-for-identity/alerts-mdi-classic>
803. Microsoft Learn — *Microsoft Defender for Identity credential access alerts* (2024). <https://learn.microsoft.com/en-us/defender-for-identity/credential-access-alerts>
804. MITRE ATT&CK T1558.002 — Silver Ticket. <https://attack.mitre.org/techniques/T1558/002/>
805. The Hacker Recipes — Sapphire ticket — Charlie Bromberg. <https://www.thehacker.recipes/ad/movement/kerberos/forged-tickets/sapphire>
806. ShutdownRepo/impacket — sapphire-tickets branch — Charlie Bromberg. [https://github.com/ShutdownRepo/impacket/tree/sapphire-tickets](https://github.com/ShutdownRepo/impacket/tree/sapphire-tickets)
807. [MS-SFU]: Kerberos Protocol Extensions: Service for User and Constrained Delegation Protocol — 2026. <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/>
808. BloodHound Release Notes. <https://bloodhound.specterops.io/resources/release-notes/>
809. Impacket PR #1411: Sapphire ticket support in ticketer.py. [https://github.com/fortra/impacket/pull/1411](https://github.com/fortra/impacket/pull/1411)
810. Kerberos Service Ticket Request Using RC4 Encryption. <https://research.splunk.com/endpoint/7d90f334-a482-11ec-908c-acde48001122/>
811. microsoftarchive/New-KrbtgtKeys.ps1. [https://github.com/microsoftarchive/New-KrbtgtKeys.ps1](https://github.com/microsoftarchive/New-KrbtgtKeys.ps1)
812. Certified Pre-Owned: Abusing Active Directory Certificate Services — Will Schroeder, Lee Christensen; 2021. <https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf>
813. Domain of Thrones: Part I — Nico Shyne, Josh Prager; 2023. <https://specterops.io/blog/2023/10/24/domain-of-thrones-part-i/>
814. Set-ADAccountPassword (ActiveDirectory PowerShell module). <https://learn.microsoft.com/en-us/powershell/module/activedirectory/set-adaccountpassword>
815. Microsoft Learn — *Windows Hello for Business cloud Kerberos trust deployment guide*. <https://learn.microsoft.com/en-us/windows/security/identity-protection/hello-for-business/deploy/hybrid-cloud-kerberos-trust>
816. Project Athena (encyclopedia entry citing the MIT/IBM/DEC partnership and 1983—1991 timeline). <https://en.wikipedia.org/wiki/Project_Athena>
817. Windows 2000 (encyclopedia entry citing the December 15, 1999 RTM and February 17, 2000 general-availability dates). <https://en.wikipedia.org/wiki/Windows_2000>
818. Paul Ashton — *NT pass-the-hash exploit code originally posted to NTBugtraq (April 1997); archived as Microsoft Windows NT 4.0 SP5 / Terminal Server 4.0 - Pass the Hash exploit* (1997). <https://www.exploit-db.com/exploits/19197>
819. Dirk-jan Mollema — *Digging further into the Primary Refresh Token* (2020). <https://dirkjanm.io/digging-further-into-the-primary-refresh-token/>
820. Dirk-jan Mollema — *Abusing Azure AD SSO with the Primary Refresh Token* (2020). <https://dirkjanm.io/abusing-azure-ad-sso-with-the-primary-refresh-token/>
821. Dirk-jan Mollema — *ROADtools and roadtx* (2025). [https://github.com/dirkjanm/ROADtools](https://github.com/dirkjanm/ROADtools)
822. Wikipedia contributors — *Pass the hash*. <https://en.wikipedia.org/wiki/Pass_the_hash>
823. Alva Duckwall, Christopher Campbell — *Still Passing the Hash 15 Years Later* (2012). <https://media.blackhat.com/bh-us-12/Briefings/Duckwall/BH_US_12_Duckwall_Campbell_Still_Passing_WP.pdf>
824. Hernan Ochoa — *Pass-the-Hash Toolkit (CoreLabs project page, Wayback)* (2008). <https://web.archive.org/web/20121025075348/http://oss.coresecurity.com/projects/pshtoolkit.htm>
825. Microsoft — *LsaCallAuthenticationPackage function (ntsecapi.h)* (2025). <https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-lsacallauthenticationpackage>
826. Alva Duckwall, Benjamin Delpy — *Abusing Microsoft Kerberos: Sorry You Guys Don't Get It (whitepaper)* (2014). <https://www.blackhat.com/docs/us-14/materials/us-14-Duckwall-Abusing-Microsoft-Kerberos-Sorry-You-Guys-Don't-Get-It-wp.pdf>
827. Sean Metcalf — *Mimikatz and Active Directory Kerberos Attacks* (2014). <https://adsecurity.org/?p=556>
828. Sean Metcalf — *Red vs. Blue: Modern Active Directory Attacks, Detection, and Protection* (2015). <https://www.blackhat.com/docs/us-15/materials/us-15-Metcalf-Red-Vs-Blue-Modern-Active-Directory-Attacks-Detection-And-Protection-wp.pdf>
829. VASCO Data Security International, Inc. — *Quarterly Report on Form 10-Q for the Quarter Ended September 30, 2011* (2011). <https://www.sec.gov/Archives/edgar/data/1044777/000119312511297526/d246524d10q.htm>
830. Fox-IT — *Black Tulip: Report of the investigation into the DigiNotar Certificate Authority breach* (2012). [https://github.com/juliocesarfort/public-pentesting-reports/blob/master/Fox-IT/Fox-IT_-_DigiNotar.pdf](https://github.com/juliocesarfort/public-pentesting-reports/blob/master/Fox-IT/Fox-IT_-_DigiNotar.pdf)
831. Microsoft — *KB2871997: Microsoft Security Advisory -- Update to improve credentials protection and management (May 13, 2014)* (2014). <https://support.microsoft.com/help/2871997>
832. SpecterOps — *BloodHound CE/Enterprise: CanRDP edge* (2025). <https://bloodhound.specterops.io/resources/edges/can-rdp>
833. Microsoft — *Windows 10 Enterprise and Education -- Modern Lifecycle Policy* (2025). <https://learn.microsoft.com/en-us/lifecycle/products/windows-10-enterprise-and-education>
834. Will Schroeder, Lee Christensen — *Certified Pre-Owned: Abusing Active Directory Certificate Services* (2021). <https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf>
835. Yannick Méheut — *AlmondOffSec/PassTheCert* (2022). [https://github.com/AlmondOffSec/PassTheCert](https://github.com/AlmondOffSec/PassTheCert)
836. Yannick Méheut — *Authenticating with certificates when PKINIT is not supported* (2022). <https://offsec.almond.consulting/authenticating-with-certificates-when-pkinit-is-not-supported.html>
837. Oliver Lyak — *Certipy Wiki: Privilege Escalation (ESC1-ESC16)* (2025). [https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation)
838. Semperis — *AD Vulnerability CVE-2022-26923* (2022). <https://www.semperis.com/blog/ad-vulnerability-cve-2022-26923/>
839. Will Schroeder, Lee Christensen — *Certificates and Pwnage and Patches, Oh My!* (2022). <https://posts.specterops.io/certificates-and-pwnage-and-patches-oh-my-8ae0f4304c1d>
840. Microsoft — *Defender for Identity -- Certificates posture assessments* (2025). <https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates>
841. SpecterOps — *Certify Wiki: Escalation Techniques (ESC1-ESC16)* (2025). <https://docs.specterops.io/ghostpack-docs/Certify.wik-mdx/4-escalation-techniques>
842. Microsoft — *Conditional Access: Token Protection* (2025). <https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-token-protection>
843. Microsoft — *Plan your Microsoft Entra hybrid join deployment* (2025). <https://learn.microsoft.com/en-us/entra/identity/devices/hybrid-join-plan>
844. SpecterOps — *BloodHound CE/Enterprise: Edges reference* (2025). <https://bloodhound.specterops.io/resources/edges/>
845. Dirk-jan Mollema — *Phishing for Microsoft Entra Primary Refresh Tokens* (2023). <https://dirkjanm.io/phishing-for-microsoft-entra-primary-refresh-tokens/>
846. Dirk-jan Mollema — *Obtaining Global Admin in every Entra ID tenant with Actor tokens* (2025). <https://dirkjanm.io/obtaining-global-admin-in-every-entra-id-tenant-with-actor-tokens/>
847. Dirk-jan Mollema — *Persisting on Entra ID applications and User Managed Identities with Federated Credentials* (2024). <https://dirkjanm.io/persisting-with-federated-credentials-entra-apps-managed-identities/>
848. D. Fett, B. Campbell, J. Bradley, T. Lodderstedt, M. Jones, D. Waite — *RFC 9449 -- OAuth 2.0 Demonstrating Proof of Possession (DPoP)* (2023). <https://datatracker.ietf.org/doc/html/rfc9449>
849. FIDO Alliance — *How FIDO Works*. <https://fidoalliance.org/how-fido-works/>
850. Wikipedia — *Password: History*. <https://en.wikipedia.org/wiki/Password#History>
851. Multicians — *Corby Memorial*. <https://www.multicians.org/corby-memorial.html>
852. Tom Van Vleck — *Multics Security*. <https://www.multicians.org/security.html>
853. Wikipedia — *crypt (C)*. <https://en.wikipedia.org/wiki/Crypt_(C)>
854. Electronic Frontier Foundation — *DES Challenge III Broken in Record 22 Hours*. <https://w2.eff.org/Privacy/Crypto/Crypto_misc/DESCracker/HTML/19990119_deschallenge3.html>
855. Microsoft Learn — *Passwords technical overview*. <https://learn.microsoft.com/en-us/windows-server/security/kerberos/passwords-technical-overview>
856. MITRE — *Use Alternate Authentication Material: Pass the Hash (T1550.002)* (2024). <https://attack.mitre.org/techniques/T1550/002/>
857. The Register — *Gummi Bears Defeat Fingerprint Sensors*. <https://www.theregister.com/2002/05/16/gummi_bears_defeat_fingerprint_sensors/>
858. Microsoft Learn — *Windows Biometric Framework API*. <https://learn.microsoft.com/en-us/windows/win32/secbiomet/biometric-service-api-portal>
859. PR Newswire — Motorola Mobility and AT&T ATRIX 4G announcement. <https://www.prnewswire.com/news-releases/motorola-mobility-and-att-announce-atrix-4g-the-future-of-mobile-computing-112974014.html>
860. Apple — *Apple Announces iPhone 5s*. <https://www.apple.com/newsroom/2013/09/10Apple-Announces-iPhone-5s-The-Most-Forward-Thinking-Smartphone-in-the-World/>
861. FIDO Alliance Launch Announcement (PDF), 12 February 2013. FIDO Alliance; 2013. <https://fidoalliance.org/assets/downloads/FIDO_Alliance_launch__FINAL__02_12_13docx.pdf>
862. FIDO Alliance — specifications collection. <https://fidoalliance.org/specifications/>
863. FIDO Alliance — *FIDO UAF Protocol Specification*. <https://fidoalliance.org/specs/fido-uaf-v1.2-ps-20201020/fido-uaf-protocol-v1.2-ps-20201020.html>
864. FIDO Alliance — *Universal 2nd Factor (U2F) Overview*. <https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-overview-v1.2-ps-20170411.html>
865. Web Authentication: An API for accessing Public Key Credentials -- Level 3 (W3C Candidate Recommendation). W3C. <https://www.w3.org/TR/webauthn-3/>
866. Microsoft Learn — *Windows Hello biometric requirements*. <https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/windows-hello-biometric-requirements>
867. Apple Platform Security — *Optic ID, Face ID, Touch ID, passcodes, and passwords*. <https://support.apple.com/en-ca/guide/security/sec9479035f1/web>
868. Microsoft Tech Community — *Windows Hello for Business Hybrid Cloud Kerberos Trust is now available!*. <https://techcommunity.microsoft.com/blog/windows-itpro-blog/windows-hello-for-business-hybrid-cloud-kerberos-trust-is-now-available/3651049>
869. Microsoft Learn — *Plan a Windows Hello for Business Deployment*. <https://learn.microsoft.com/en-us/windows/security/identity-protection/hello-for-business/deploy/>
870. FIDO Alliance — *Android Now FIDO2 Certified*. <https://fidoalliance.org/android-now-fido2-certified-accelerating-global-migration-beyond-passwords/>
871. FIDO Alliance — *Microsoft Achieves FIDO2 Certification for Windows Hello*. <https://fidoalliance.org/microsoft-achieves-fido2-certification-for-windows-hello/>
872. NIST SP 800-63B — *Authentication Assurance Levels*. <https://pages.nist.gov/800-63-4/sp800-63b/aal/>
873. NIST SP 800-63B — *Authenticator and Verifier Requirements*. <https://pages.nist.gov/800-63-4/sp800-63b/authenticators/>
874. Omer Tsarfati / CyberArk — *Bypassing Windows Hello Without Masks or Plastic Surgery*. <https://www.cyberark.com/resources/threat-research-blog/bypassing-windows-hello-without-masks-or-plastic-surgery>
875. Bowen Hu, Kuo Wang, and Chip Hong Chang — near-infrared facial presentation-attack research page. <https://www.usenix.org/conference/usenixsecurity25/presentation/hu-bowen>
876. Hu, Wang, and Chang — PDF describing a near-infrared facial presentation attack. <https://www.usenix.org/system/files/usenixsecurity25-hu-bowen.pdf>
877. ERNW / Insinuator — *Faceplant: Planting Biometric Templates*. <https://insinuator.net/2025/08/windows-hello-for-buiness-faceplant-planting-biometric-templates/>
878. Black Hat USA 2025 — *Windows Hell No for Business* official conference video. <https://www.youtube.com/watch?v=SkWZ5KcelD4>
879. Passwordless authentication options for Microsoft Entra ID. Microsoft Learn. <https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-passwordless>
880. Apple Newsroom — *Apple, Google, and Microsoft Commit to Expanded Support for FIDO Standard*. <https://www.apple.com/newsroom/2022/05/apple-google-and-microsoft-commit-to-expanded-support-for-fido-standard/>
881. Google Identity — *Passkeys*. <https://developers.google.com/identity/passkeys>
882. Apple Platform Security — *Passkeys*. <https://support.apple.com/guide/security/passkeys-sec50554cb94/web>
883. FIDO Alliance — credential exchange specifications announcement. <https://fidoalliance.org/fido-alliance-publishes-new-specifications-to-promote-user-choice-and-enhanced-ux-for-passkeys/>
884. Pushing passkeys forward: Microsoft's latest updates for simpler, safer sign-ins. Microsoft Security Blog; 2025. <https://www.microsoft.com/en-us/security/blog/2025/05/01/pushing-passkeys-forward-microsofts-latest-updates-for-simpler-safer-sign-ins/>
885. Anil K. Jain, Arun Ross, and Salil Prabhakar — *An Introduction to Biometric Recognition*. <https://ieeexplore.ieee.org/document/1262027>
886. NVD — *CVE-2025-26644*. <https://nvd.nist.gov/vuln/detail/CVE-2025-26644>
887. Wiz Vulnerability Database — *CVE-2025-26644*. <https://www.wiz.io/vulnerability-database/cve/cve-2025-26644>
888. Tycoon 2FA: an in-depth analysis of the latest version of the AiTM phishing kit. Sekoia.io; 2024. <https://blog.sekoia.io/tycoon-2fa-an-in-depth-analysis-of-the-latest-version-of-the-aitm-phishing-kit/>
889. NIST SP 800-63-4: Digital Identity Guidelines (final, July 2025). Proud-Madruga, Choong, Galluzzo, Gupta, LaSalle, Lefkovitz, Regenscheid; NIST; 2025. <https://pages.nist.gov/800-63-4/>
890. NIST SP 800-63B-4: Authentication and Authenticator Management (HTML). NIST; 2025. <https://pages.nist.gov/800-63-4/sp800-63b.html>
891. FIDO Authenticator Certification Levels (L1, L1+, L2, L3, L3+). FIDO Alliance. <https://fidoalliance.org/certification/authenticator-certification-levels/>
892. RFC 5056: On the Use of Channel Bindings to Secure Channels. Nicolas Williams; IETF; 2007. <https://auth.ietf.org/doc/html/rfc5056>
893. RFC 9266: Channel Bindings for TLS 1.3. Sam Whited; IETF; 2022. <https://auth.ietf.org/doc/html/rfc9266>
894. New NIST Guidance on Passkeys: Key Takeaways for Enterprises. Yubico. <https://www.yubico.com/blog/new-nist-guidance-on-passkeys-key-takeaways-for-enterprises/>
895. Password Security: A Case History. Robert Morris, Ken Thompson; Communications of the ACM 22(11), 594-597; 1979. <https://doi.org/10.1145/359168.359172>
896. RFC 4226: HOTP -- An HMAC-Based One-Time Password Algorithm. M'Raihi, Bellare, Hoornaert, Naccache, Ranen; IETF; 2005. <https://auth.ietf.org/doc/html/rfc4226>
897. RFC 6238: TOTP -- Time-Based One-Time Password Algorithm. M'Raihi, Machani, Pei, Rydell; IETF; 2011. <https://auth.ietf.org/doc/html/rfc6238>
898. RFC 8471: The Token Binding Protocol Version 1.0. Popov, Nystroem, Balfanz, Hodges; IETF; 2018. <https://auth.ietf.org/doc/html/rfc8471>
899. RFC 8473: Token Binding over HTTP. Popov, Nystroem, Balfanz, Harper, Hodges; IETF; 2018. <https://auth.ietf.org/doc/html/rfc8473>
900. RFC 8471 datatracker history page. IETF. <https://datatracker.ietf.org/doc/rfc8471/history/>
901. RFC 8473 datatracker history page. IETF. <https://datatracker.ietf.org/doc/rfc8473/history/>
902. Chrome Platform Status: Token Binding. Chromium. <https://chromestatus.com/api/v0/features/5097603234529280>
903. Chrome Platform Status: Remove Token Binding. Chromium. <https://chromestatus.com/feature/5044401232918528>
904. Web Authentication: An API for accessing Scoped Credentials (W3C First Public Working Draft, 31 May 2016). W3C; 2016. <https://www.w3.org/TR/2016/WD-webauthn-20160531/>
905. Web Authentication Level 3 (Candidate Recommendation dated snapshot, 13 January 2026). W3C; 2026. <https://www.w3.org/TR/2026/CR-webauthn-3-20260113/>
906. DoD 5200.28-STD: Department of Defense Trusted Computer System Evaluation Criteria. Department of Defense; 1985. <https://irp.fas.org/nsa/rainbow/std001.htm>
907. NIST Special Publication 800-63 (first edition): Electronic Authentication Guideline. William E. Burr, Donna Dodson, W. Timothy Polk; NIST CSRC; 2004. <https://csrc.nist.gov/pubs/sp/800/63/final>
908. NIST SP 800-63 version 1.0.2 (PDF). NIST; 2004. <https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-63ver1.0.2.pdf>
909. RSA SecurID (Wikipedia). Wikipedia. <https://en.wikipedia.org/wiki/RSA_SecurID>
910. NIST SP 800-63-3: Digital Identity Guidelines. NIST CSRC; 2017. <https://csrc.nist.gov/pubs/sp/800/63/3/upd2/final>
911. RFC 1760: The S/KEY One-Time Password System. Neil Haller; IETF; 1995. <https://auth.ietf.org/doc/html/rfc1760>
912. The Laws of Identity. Kim Cameron; identityblog.com; 2005. <https://www.identityblog.com/?p=352>
913. Persona Shutdown Guidelines for Reliers. Mozilla Wiki; 2016. <https://wiki.mozilla.org/Identity/Persona_Shutdown_Guidelines_for_Reliers>
914. FIDO U2F Overview (specs archive). FIDO Alliance. <https://fidoalliance.org/specs/u2f-specs-master/fido-u2f-overview.html>
915. Security Keys: Practical Cryptographic Second Factors for the Modern Web. Juan Lang, Alexei Czeskis, Dirk Balfanz, Marius Schilder, Sampath Srinivas; Financial Cryptography 2016; 2016. <https://fc16.ifca.ai/preproceedings/25_Lang.pdf>
916. W3C and FIDO Alliance Finalize Web Standard for Secure, Passwordless Logins. W3C; 2019. <https://www.w3.org/press-releases/2019/webauthn/>
917. FIDO Client to Authenticator Protocol (CTAP) 2.0 Proposed Standard, 30 January 2019. FIDO Alliance; 2019. <https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html>
918. FIDO2 security key hardware vendors for Microsoft Entra ID. Microsoft Learn. <https://learn.microsoft.com/en-us/entra/identity/authentication/concept-fido2-hardware-vendor>
919. WebAuthn APIs for password-less authentication on Windows. Microsoft Learn. <https://learn.microsoft.com/en-us/windows/security/identity-protection/hello-for-business/webauthn-apis>
920. CBOR Object Signing and Encryption (COSE) Algorithms (IANA registry). IANA. <https://www.iana.org/assignments/cose/cose.xhtml>
921. FIDO Client to Authenticator Protocol (CTAP) 2.1 Proposed Standard, 15 June 2021. FIDO Alliance; 2021. <https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html>
922. FIDO CTAP 2.2 Proposed Standard, 14 July 2025. FIDO Alliance; 2025. <https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html>
923. FIDO Alliance Specifications Download Page. FIDO Alliance. <https://fidoalliance.org/specifications/download/>
924. FIDO CTAP 2.2 Review Draft, 21 March 2023. FIDO Alliance; 2023. <https://fidoalliance.org/specs/fido-v2.2-rd-20230321/fido-client-to-authenticator-protocol-v2.2-rd-20230321.html>
925. Apple, Google and Microsoft Commit to Expanded Support for FIDO Standard to Accelerate Availability of Passwordless Sign-Ins. FIDO Alliance; 2022. <https://fidoalliance.org/apple-google-and-microsoft-commit-to-expanded-support-for-fido-standard-to-accelerate-availability-of-passwordless-sign-ins/>
926. OS X Mavericks Available Today Free from the Mac App Store. Apple Newsroom; 2013. <https://www.apple.com/ci/newsroom/2013/10/23OS-X-Mavericks-Available-Today-Free-from-the-Mac-App-Store/>
927. Microsoft Authenticator (Wikipedia). Wikipedia. <https://en.wikipedia.org/wiki/Microsoft_Authenticator>
928. Microsoft Introduces Passkeys for Consumer Accounts. Microsoft Security Blog; 2024. <https://www.microsoft.com/en-us/security/blog/2024/05/02/microsoft-introduces-passkeys-for-consumer-accounts/>
929. iCloud data security overview (Standard and Advanced Data Protection). Apple Support. <https://support.apple.com/en-us/HT202303>
930. NIST SP 800-63B Supplement 1: Incorporating Syncable Authenticators. Temoshok, LaSalle, Regenscheid; NIST CSRC; 2024. <https://csrc.nist.gov/pubs/sp/800/63/b/sup/final>
931. microsoft/webauthn: Win32 APIs and plugin header files. GitHub. [https://github.com/microsoft/webauthn](https://github.com/microsoft/webauthn)
932. webauthn.h Win32 API reference. Microsoft Learn. <https://learn.microsoft.com/en-us/windows/win32/api/webauthn/>
933. Passkeys (Windows identity protection). Microsoft Learn. <https://learn.microsoft.com/en-us/windows/security/identity-protection/passkeys/>
934. YubiKey 5 Series Overview. Yubico. <https://www.yubico.com/products/yubikey-5-overview/>
935. Passkeys. Adam Langley; imperialviolet.org; 2022. <https://www.imperialviolet.org/2022/09/22/passkeys.html>
936. passkeys.dev (FIDO Alliance / WebKit / Chrome team passkey resource). FIDO Alliance. <https://passkeys.dev/>
937. Passkeys on Windows: authenticate seamlessly with passkey providers. Windows Developer Blog; 2024. <https://blogs.windows.com/windowsdeveloper/2024/10/08/passkeys-on-windows-authenticate-seamlessly-with-passkey-providers/>
938. ASCredentialIdentityStore -- AuthenticationServices. Apple Developer. <https://developer.apple.com/documentation/authenticationservices/ascredentialidentitystore>
939. Credential Manager (Android Developers). Android Developers. <https://developer.android.com/identity/credential-manager>
940. Contoso Passkey Manager (Windows-classic-samples). GitHub. [https://github.com/microsoft/Windows-classic-samples/tree/main/Samples/PasskeyManager](https://github.com/microsoft/Windows-classic-samples/tree/main/Samples/PasskeyManager)
941. Third-party passkey providers on Windows. Microsoft Learn. <https://learn.microsoft.com/en-us/windows/apps/develop/security/third-party>
942. WebAuthn Attestation Statement Format Identifiers (IANA registry). IANA. <https://www.iana.org/assignments/webauthn/webauthn.xhtml>
943. RFC 8809: Registries for Web Authentication (WebAuthn). Hodges, Mandyam, M.B. Jones; IETF; 2020. <https://auth.ietf.org/doc/html/rfc8809>
944. Web Authentication: An API for accessing Public Key Credentials -- Level 2 (W3C Recommendation, 8 April 2021). W3C; 2021. <https://www.w3.org/TR/2021/REC-webauthn-2-20210408/>
945. SafetyNet Attestation API deprecation timeline. Android Developers; 2024. <https://developer.android.com/privacy-and-security/safetynet/attestation>
946. Google vows to fix a glaring omission in Authenticator's cloud backup feature. Android Police; 2023. <https://www.androidpolice.com/google-to-add-e2ee-to-authenticator/>
947. FIDO Credential Exchange Protocol (CXP) v1.0 Working Draft, 3 October 2024. FIDO Alliance; 2024. <https://fidoalliance.org/specs/cx/cxp-v1.0-wd-20241003.html>
948. Use a recovery key for your Apple Account. Apple Support. <https://support.apple.com/en-us/109345>
949. Configure Temporary Access Pass to register passwordless authentication methods. Microsoft Learn. <https://learn.microsoft.com/en-us/entra/identity/authentication/howto-authentication-temporary-access-pass>
950. Universal 2nd Factor (Wikipedia). Wikipedia. <https://en.wikipedia.org/wiki/Universal_2nd_Factor>
951. iCloud Keychain (Wikipedia). Wikipedia. <https://en.wikipedia.org/wiki/ICloud_Keychain>
952. Microsoft. *Access Control*. <https://learn.microsoft.com/en-us/windows/win32/secauthz/access-control>. Accessed 2026-05-10. Index page for the Windows Win32 access-control surface; lists the C2-level, Access Control Model, SDDL, Privileges, Audit Generation, Securable Objects, and Low-level Access Control sub-pages.
953. Microsoft News Center. *The engineer's engineer: Computer industry luminaries salute Dave Cutler's five-decade-long quest for quality*. <https://news.microsoft.com/features/the-engineers-engineer-computer-industry-luminaries-salute-dave-cutlers-five-decade-long-quest-for-quality/>. Accessed 2026-05-10. Cutler started at Microsoft on October 31, 1988; led VMS, VAXeln, Mica / Prism at DEC; Microsoft Senior Technical Fellow.
954. hFireF0x. *hfiref0x/UACME*. [https://github.com/hfiref0x/UACME](https://github.com/hfiref0x/UACME). Accessed 2026-05-10. Institutional catalogue of UAC AutoElevate-whitelist redirect bypasses; 70+ methods with structured metadata.
955. Microsoft. *How DACLs Control Access to an Object*. <https://learn.microsoft.com/en-us/windows/win32/secauthz/how-dacls-control-access-to-an-object>. Accessed 2026-05-10. Canonical SeAccessCheck DACL evaluation algorithm, deny-first sequencing, NULL DACL vs empty DACL distinction.
956. NIST National Vulnerability Database. *CVE-2021-36934 (HiveNightmare / SeriousSAM)*. 2021. <https://nvd.nist.gov/vuln/detail/CVE-2021-36934>. Accessed 2026-05-10. Overly permissive ACLs on the SAM database; KB5005357 plus manual shadow-copy deletion.
957. NIST Computer Security Resource Center. *DoD Rainbow Series*. 1985. <https://csrc.nist.gov/pubs/other/1985/12/26/dod-rainbow-series/final>. Accessed 2026-05-10. Listing of DoD 5200.28-STD (Orange Book, December 26, 1985) and Rainbow Series companion volumes.
958. Norm Hardy. *The Confused Deputy (Wayback mirror of cap-lore.com)*. 1988. [https://web.archive.org/web/2024/https://www.cap-lore.com/CapTheory/ConfusedDeputy.html](https://web.archive.org/web/2024/https://www.cap-lore.com/CapTheory/ConfusedDeputy.html). Accessed 2026-05-10. Verbatim text of the 1988 paper, mirrored on the Internet Archive Wayback Machine.
959. Norm Hardy. *The Confused Deputy (or why capabilities might have been invented)*. [https://web.archive.org/web/20250105182012/http://www.cap-lore.com/CapTheory/ConfusedDeputy.html](https://web.archive.org/web/20250105182012/http://www.cap-lore.com/CapTheory/ConfusedDeputy.html). Accessed 2026-05-10. Hardy 1988 framing; the ACL-vs-capability comparison and capability-system remedy.
960. National Computer Security Center. *Final Evaluation Report: Digital Equipment Corporation VAX/VMS Version 4.3*. <https://dn760002.eu.archive.org/0/items/DTIC_ADA208004/DTIC_ADA208004_djvu.txt>. Accessed 2026-05-10. VAX/VMS Version 4.3 formal evaluation at TCSEC Class C2; UIC protection, ACLs, auditing, and kernel-mode security architecture.
961. G. Pascal Zachary. *Showstopper!: The Breakneck Race to Create Windows NT*. 1994. Cited for cultural / narrative context on Cutler and the NT team.
962. National Computer Security Center. *Final Evaluation Report: Microsoft, Inc. Windows NT Workstation and Server Version 3.5 with U.S. Service Pack 3*. <https://dn710806.ca.archive.org/0/items/NCSCFER95003/NCSC-FER-95-003_djvu.txt>. Accessed 2026-05-10. Windows NT Workstation and Server Version 3.5 with U.S. Service Pack 3 formal evaluation against TCSEC C2 criteria.
963. Microsoft. *Access Tokens*. <https://learn.microsoft.com/en-us/windows/win32/secauthz/access-tokens>. Accessed 2026-05-10. Token contents; primary-vs-impersonation distinction; OpenProcessToken / DuplicateTokenEx / AdjustTokenPrivileges API surface.
964. Microsoft. *Mandatory Integrity Control*. <https://learn.microsoft.com/en-us/windows/win32/secauthz/mandatory-integrity-control>. Accessed 2026-05-10. MIC four-level lattice, SYSTEM_MANDATORY_LABEL_ACE in SACL, AppContainer Low-IL exception.
965. Microsoft. *ACE Strings*. <https://learn.microsoft.com/en-us/windows/win32/secauthz/ace-strings>. Accessed 2026-05-10. SDDL ACE type strings (XA, XD, XU, ZA conditional callbacks; ML mandatory label).
966. Microsoft. *Order of ACEs in a DACL*. <https://learn.microsoft.com/en-us/windows/win32/secauthz/order-of-aces-in-a-dacl>. Accessed 2026-05-10. The four-step preferred ACE order; caller responsibility note.
967. James Forshaw. *Sharing a Logon Session a Little Too Much*. 2020. <https://www.tiraniddo.dev/2020/04/sharing-logon-session-little-too-much.html>. Accessed 2026-05-10. LSASS token-cache primitive; "S-1-1-0 is NOT A SECURITY BOUNDARY" framing.
968. Microsoft. *Security Identifiers*. <https://learn.microsoft.com/en-us/windows/win32/secauthz/security-identifiers>. Accessed 2026-05-10. SID structure and uniqueness; SID API surface; well-known-SIDs cross-link.
969. Microsoft. *Well-known SIDs*. <https://learn.microsoft.com/en-us/windows/win32/secauthz/well-known-sids>. Accessed 2026-05-10. Mandatory integrity RID values (Low 0x1000, Medium 0x2000, High 0x3000, System 0x4000) used with the S-1-16 mandatory label authority.
970. James Forshaw. *The Art of Becoming TrustedInstaller*. 2017. <https://www.tiraniddo.dev/2017/08/the-art-of-becoming-trustedinstaller.html>. Accessed 2026-05-10. Service SIDs are the SHA-1 of the uppercased service name; RtlCreateServiceSid.
971. Microsoft. *Restricted Tokens*. <https://learn.microsoft.com/en-us/windows/win32/secauthz/restricted-tokens>. Accessed 2026-05-10. Two-pass access check; deny-only / restricting SIDs / privilege removal; desktop-isolation requirement.
972. Microsoft. *Privileges*. <https://learn.microsoft.com/en-us/windows/win32/secauthz/privileges>. Accessed 2026-05-10. Privilege-vs-right distinction; default-disabled rule; AdjustTokenPrivileges to enable.
973. SentinelLabs. *Vulnerabilities in Avast and AVG Put Millions at Risk*. 2022. <https://www.sentinelone.com/labs/vulnerabilities-in-avast-and-avg-put-millions-at-risk/>. Accessed 2026-05-10. CVE-2022-26522 + CVE-2022-26523 in aswArPot.sys; reported December 2021; security-product driver as BYOVD precedent.
974. Microsoft. *SYSTEM_MANDATORY_LABEL_ACE structure*. <https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-system_mandatory_label_ace>. Accessed 2026-05-10. Mandatory-label ACE in the SACL; mask values SYSTEM_MANDATORY_LABEL_NO_WRITE_UP (0x1), NO_READ_UP (0x2), NO_EXECUTE_UP (0x4).
975. Microsoft. *ACCESS_MASK*. <https://learn.microsoft.com/en-us/windows/win32/secauthz/access-mask>. Accessed 2026-05-10. 32-bit ACCESS_MASK layout: specific bits 0-15, standard bits 16-23 (WRITE_DAC bit 18, WRITE_OWNER bit 19), ACCESS_SYSTEM_SECURITY bit 24, generic bits 28-31.
976. Microsoft. *File Access Rights Constants*. <https://learn.microsoft.com/en-us/windows/win32/fileio/file-access-rights-constants>. Accessed 2026-05-10. FILE_READ_DATA = 1, FILE_WRITE_DATA = 2, FILE_APPEND_DATA = 4 and the rest of the file-specific access mask constants.
977. Skywing (Ken Johnson). *Getting Out of Jail: Escaping Internet Explorer Protected Mode*. 2007. [https://web.archive.org/web/20080926082628/http://uninformed.org/index.cgi?v=8&a=6](https://web.archive.org/web/20080926082628/http://uninformed.org/index.cgi?v=8&a=6). Accessed 2026-05-10. Uninformed Volume 8 Article 6; first public reverse-engineering of MIC and the IE Protected Mode broker pattern.
978. Dean Hachamovitch, Microsoft Internet Explorer Team. *Internet Explorer 7 for Windows XP Available Now*. <https://learn.microsoft.com/en-us/archive/blogs/ie/internet-explorer-7-for-windows-xp-available-now>. Accessed 2026-05-10. IE7 for Windows XP final release on October 18, 2006; Vista release still pending.
979. Microsoft. *How User Account Control Works*. <https://learn.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works>. Accessed 2026-05-10. UAC split-token model; filtered Medium-IL token vs full High-IL token; explorer.exe as parent of all user processes.
980. Microsoft. *The COM Elevation Moniker*. <https://learn.microsoft.com/en-us/windows/win32/com/the-com-elevation-moniker>. Accessed 2026-05-10. COM elevation moniker syntax (Elevation:Administrator!new:{guid}, Elevation:Highest!new:{guid}); supported run levels Administrator and Highest; produces a High-IL admin caller, not SYSTEM.
981. Leo Davidson. *Windows 7 UAC Whitelist: Code-Injection Issue, Anti-Competitive API, Security Theatre*. 2009. <https://www.pretentiousname.com/misc/win7_uac_whitelist2.html>. Accessed 2026-05-10. The original 2009 sysprep / IFileOperation / cryptbase.dll UAC bypass writeup.
982. Matt Nelson (enigma0x3). *Fileless UAC Bypass Using eventvwr.exe and Registry Hijacking*. 2016. <https://enigma0x3.net/2016/08/15/fileless-uac-bypass-using-eventvwr-exe-and-registry-hijacking/>. Accessed 2026-05-10. August 15, 2016; the canonical fileless-UAC-bypass template; mscfile HKCU registry redirect.
983. Mark Russinovich. *Inside Windows Vista User Account Control*. 2007. [https://web.archive.org/web/20070715040322/http://technet.microsoft.com/en-us/magazine/cc138019.aspx](https://web.archive.org/web/20070715040322/http://technet.microsoft.com/en-us/magazine/cc138019.aspx). Accessed 2026-05-10. Mark Russinovich TechNet Magazine cover story (June 2007); canonical practitioner walkthrough of the split-token model.
984. itm4n (Clément Labro). *CVE-2020-0668 — A Trivial Privilege Escalation Bug in Windows Service Tracing*. 2020. <https://itm4n.github.io/cve-2020-0668-windows-service-tracing-eop/>. Accessed 2026-05-10. Original disclosure of CVE-2020-0668; exploitation via mountpoint to \RPC Control plus two object-manager symbolic links.
985. James Forshaw / Google Project Zero. *googleprojectzero/symboliclink-testing-tools*. [https://github.com/googleprojectzero/symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools). Accessed 2026-05-10. Forshaw symbolic-link / hardlink / mount-point / object-directory testing tools (CreateSymlink, CreateHardlink, CreateMountPoint, BaitAndSwitch).
986. James Forshaw. *Between a Rock and a Hard Link*. 2015. <https://googleprojectzero.blogspot.com/2015/12/between-rock-and-hard-link.html>. Accessed 2026-05-10. Forshaw December 2015 post on the NTFS hard-link primitive for sandbox escape and LPE; CVE-2015-4481 Mozilla Maintenance Service hard-link to update-log file; MS15-115 sandboxed-context mitigation aftermath.
987. seL4 Foundation. *Frequently Asked Questions*. <https://sel4.systems/About/FAQ.html>. Accessed 2026-05-10. seL4 formal-verification overview; capabilities as unforgeable, delegatable access-right tokens.
988. James Forshaw, Google Project Zero. *googleprojectzero/sandbox-attacksurface-analysis-tools*. [https://github.com/googleprojectzero/sandbox-attacksurface-analysis-tools](https://github.com/googleprojectzero/sandbox-attacksurface-analysis-tools). Accessed 2026-05-10. NtObjectManager PowerShell module; the modern empirical-enumeration platform for the Windows access-control surface.
989. Clément Labro (itm4n). *itm4n/PrintSpoofer*. 2020. [https://github.com/itm4n/PrintSpoofer](https://github.com/itm4n/PrintSpoofer). Accessed 2026-05-10. PrintSpoofer source; LOCAL/NETWORK SERVICE to SYSTEM via SeImpersonatePrivilege.
990. Microsoft. *Dynamic Access Control: Scenario Overview*. <https://learn.microsoft.com/en-us/windows-server/identity/solution-guides/dynamic-access-control-overview>. Accessed 2026-05-10. DAC architecture; user / device / resource claims; Central Access Rules and Policies; AD/Kerberos compound-ID dependency.
991. Microsoft. *Dynamic Access Control: Scenario Overview*. <https://learn.microsoft.com/en-us/windows-server/identity/solution-guides/dynamic-access-control--scenario-overview>. Accessed 2026-05-10. DAC scenarios: classification, central access policies, audit policies; Kerberos compound-ID claims dependency.
992. Microsoft Tech Community. *Administrator Protection on Windows 11*. 2024. <https://techcommunity.microsoft.com/blog/windows-itpro-blog/administrator-protection-on-windows-11/4303482>. Accessed 2026-05-10. Modified November 19, 2024; the Administrator Protection feature announcement; just-in-time admin privileges via Windows Hello.
993. *Pluton: A TPM On Silicon Microsoft Can Patch*. 2026. <https://paragmali.com/blog/pluton-a-tpm-on-silicon-microsoft-can-patch/>. Accessed 2026-05-10. Sibling article on Pluton-rooted attestation; the in-die security processor.
994. bugch3ck. *bugch3ck/SharpEfsPotato*. 2021. [https://github.com/bugch3ck/SharpEfsPotato](https://github.com/bugch3ck/SharpEfsPotato). Accessed 2026-05-10. SharpEfsPotato; built atop SweetPotato (EthicalChaos) and SharpEfsTrigger (cube0x0). Replaces the original scope file pointer to ly4k/SharpEfsPotato (HTTP 404).
995. NIST National Vulnerability Database. *CVE-2021-36942 (PetitPotam)*. 2021. <https://nvd.nist.gov/vuln/detail/CVE-2021-36942>. Accessed 2026-05-10. PetitPotam advisory; KB5005413; CISA KEV.
996. NIST National Vulnerability Database. *CVE-2021-34527 (PrintNightmare)*. 2021. <https://nvd.nist.gov/vuln/detail/CVE-2021-34527>. Accessed 2026-05-10. Print Spooler RCE adjacent to PrintSpoofer; CISA KEV; KB5005010.
997. Andrea Pierini (decoder_it). *No more JuicyPotato? Old story, welcome RoguePotato*. 2020. <https://decoder.cloud/2020/05/11/no-more-juicypotato-old-story-welcome-roguepotato/>. Accessed 2026-05-10. Rogue Potato disclosure narrative; identification of the Windows 10 1809 / Server 2019 loopback-OXID mitigation.
998. Antonio Cocomazzi, Andrea Pierini. *antonioCoco/RemotePotato0*. 2021. [https://github.com/antonioCoco/RemotePotato0](https://github.com/antonioCoco/RemotePotato0). Accessed 2026-05-10. RemotePotato0 (2021); cross-session DCOM activation; cross-protocol RPC-to-LDAP relay; partial fix October 2022.
999. Microsoft Learn — *How User Account Control works* — 2026. <https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/how-it-works>
1000. Mark Russinovich — *Security: Inside Windows Vista User Account Control* — 2007. <https://learn.microsoft.com/en-us/previous-versions/technet-magazine/cc138019(v=msdn.10)>
1001. Mark Russinovich — *PsExec, User Account Control and Security Boundaries* — 2007. [https://web.archive.org/web/20110518125531/http://blogs.technet.com/b/markrussinovich/archive/2007/02/12/638372.aspx](https://web.archive.org/web/20110518125531/http://blogs.technet.com/b/markrussinovich/archive/2007/02/12/638372.aspx)
1002. Aaron Margosis — *Aaron Margosis's Non-Admin and App-Compat WebLog (Archive)* — 2026. <https://learn.microsoft.com/en-us/archive/blogs/aaron_margosis/>
1003. Chris Paget — *Exploiting design flaws in the Win32 API for privilege escalation (Shatter Attacks)* — 2002. <https://www.helpnetsecurity.com/2002/08/08/exploiting-design-flaws-in-the-win32-api-for-privilege-escalation-shatter-attacks-how-to-break-windows/>
1004. Microsoft News Center — *Microsoft Launches Windows Vista and Microsoft Office 2007 to Consumers Worldwide* — 2007. <https://news.microsoft.com/source/2007/01/29/microsoft-launches-windows-vista-and-microsoft-office-2007-to-consumers-worldwide/>
1005. Pavel Yosifovich, Alex Ionescu, Mark E. Russinovich, David A. Solomon — *Windows Internals, 7th Edition, Part 1* — 2017
1006. D. Elliott Bell and Leonard J. LaPadula — *Secure Computer Systems: Mathematical Foundations* — 1973. <https://archive.org/details/DTIC_AD0770768>
1007. Kenneth J. Biba — *Integrity Considerations for Secure Computer Systems* — 1977. <https://archive.org/details/DTIC_ADA039324>
1008. Microsoft Learn — *CreateRestrictedToken function* — 2024. <https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-createrestrictedtoken>
1009. Microsoft Learn — *Software Restriction Policies (Windows Server 2003)* — 2003. <https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc779607(v=ws.10)>
1010. Microsoft Learn — *Winsafer.h header reference* — 2024. <https://learn.microsoft.com/en-us/windows/win32/api/winsafer/>
1011. James Forshaw — *Reading Your Way Around UAC (Part 1)* — 2017. <https://tyranidslair.blogspot.com/2017/05/reading-your-way-around-uac-part-1.html>
1012. Microsoft Learn — *SendMessage function (winuser.h)* — 2024. <https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-sendmessage>
1013. Microsoft Learn — *PostMessageA function (winuser.h)* — 2025. <https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-postmessagea>
1014. Microsoft Learn — *SendInput function (winuser.h)* — 2025. <https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-sendinput>
1015. Microsoft Learn — *GetWindowTextA function (winuser.h)* — 2025. <https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getwindowtexta>
1016. Microsoft Learn — *ChangeWindowMessageFilterEx function* — 2024. <https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-changewindowmessagefilterex>
1017. Microsoft Learn — *Security Considerations for Assistive Technologies* — 2026. <https://learn.microsoft.com/en-us/windows/win32/winauto/uiauto-securityoverview>
1018. James Forshaw — *Bypassing Administrator Protection by Abusing UI Access* — 2026. <https://projectzero.google/2026/02/windows-administrator-protection.html>
1019. Microsoft Learn — *TOKEN_ELEVATION_TYPE enumeration* — 2024. <https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-token_elevation_type>
1020. Microsoft Learn — *ShellExecuteExA function* — 2024. <https://learn.microsoft.com/en-us/windows/win32/api/shellapi/nf-shellapi-shellexecuteexa>
1021. Leo Davidson — *Windows 7 UAC whitelist: Code injection issue (and more)* — 2009. <https://pretentiousname.com/misc/win7_uac_whitelist2.html>
1022. Microsoft Learn — *IFileOperation interface* — 2024. <https://learn.microsoft.com/en-us/windows/win32/api/shobjidl_core/nn-shobjidl_core-ifileoperation>
1023. Microsoft Learn — *Application Manifests* — 2025. <https://learn.microsoft.com/en-us/windows/win32/sbscs/application-manifests>
1024. MITRE ATT&CK — *Abuse Elevation Control Mechanism: Bypass User Account Control (T1548.002)* — 2026. <https://attack.mitre.org/techniques/T1548/002/>
1025. Matt Nelson — *Bypassing UAC Using App Paths* — 2017. <https://enigma0x3.net/2017/03/14/bypassing-uac-using-app-paths/>
1026. Matt Nelson — *Fileless' UAC Bypass Using sdclt.exe* — 2017. <https://enigma0x3.net/2017/03/17/fileless-uac-bypass-using-sdclt-exe/>
1027. The Register — *Windows 7 UAC flaw silently elevates malware access* — 2009. <https://www.theregister.com/software/2009/02/04/windows-7-uac-flaw-silently-elevates-malware-access/790560>
1028. Dorothy E. Denning — *A lattice model of secure information flow* — 1976. <https://doi.org/10.1145/360051.360056>
1029. Chromium Project — *Sandbox - Chromium Design Documents* — 2025. <https://chromium.googlesource.com/chromium/src/+/main/docs/design/sandbox.md>
1030. Michael A. Harrison, Walter L. Ruzzo, Jeffrey D. Ullman — *Protection in Operating Systems* — 1976. <https://doi.org/10.1145/360303.360333>
1031. Microsoft Windows Developer Blog — *Enhance your application security with Administrator protection* — 2025. <https://blogs.windows.com/windowsdeveloper/2025/05/19/enhance-your-application-security-with-administrator-protection/>
1032. The Register — *Google researcher sits on UAC bypass for ages, only for it to become valid with new security feature* — 2026. <https://www.theregister.com/security/2026/01/28/old-windows-quirks-help-punch-through-new-admin-defenses/4440743>
1033. *Impersonate a client after authentication - Windows security policy setting*. <https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/impersonate-a-client-after-authentication>
1034. *LocalService Account*. <https://learn.microsoft.com/en-us/windows/win32/services/localservice-account>
1035. *NetworkService Account*. <https://learn.microsoft.com/en-us/windows/win32/services/networkservice-account>
1036. *Privilege Constants (Win32 SecAuthZ)*. <https://learn.microsoft.com/en-us/windows/win32/secauthz/privilege-constants>
1037. *Token Kidnapping (MSRC blog, April 14, 2009)* (2009). <https://www.microsoft.com/en-us/msrc/blog/2009/04/token-kidnapping/>
1038. Cesar Cerrudo — *Token Kidnapping* (2008). <https://dl.packetstormsecurity.net/papers/presentations/TokenKidnapping.pdf> — HITB Dubai 2008 disclosure of service-account-to-SYSTEM via SeImpersonatePrivilege + leaked handles.
1039. Stephen Breen — *Hot Potato* (2016). <https://www.foxglovesecurity.com/2016/01/16/hot-potato/>
1040. Norm Hardy — *The Confused Deputy (or why capabilities might have been invented)* (1988). <http://cap-lore.com/CapTheory/ConfusedDeputy.html> — Tymshare FORTRAN compiler / (SYSX)BILL anecdote; structural argument for capabilities.
1041. Butler Lampson — *Protection* (1971). <http://bwlampson.site/08-Protection/WebPage.html> — Access-matrix model; the formal substrate Windows tokens instantiate.
1042. *Timeline of computer viruses and worms*. <https://en.wikipedia.org/wiki/Timeline_of_computer_viruses_and_worms>
1043. Microsoft. *Microsoft Security Bulletin MS03-026 - Critical*. <https://learn.microsoft.com/en-us/security-updates/securitybulletins/2003/ms03-026>
1044. *ImpersonateLoggedOnUser function (securitybaseapi.h)*. <https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-impersonateloggedonuser>
1045. *SetThreadToken function (processthreadsapi.h)*. <https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-setthreadtoken>
1046. *DuplicateTokenEx function (securitybaseapi.h)*. <https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-duplicatetokenex>
1047. *CreateProcessWithTokenW function (winbase.h)*. <https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw>
1048. *ImpersonateNamedPipeClient function (namedpipeapi.h)*. <https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient>
1049. James Forshaw — *Windows Exploitation Tricks: Relaying DCOM Authentication* (2021). <https://googleprojectzero.blogspot.com/2021/10/windows-exploitation-tricks-relaying.html>
1050. Microsoft. *CreateProcessAsUserW function (processthreadsapi.h)*. <https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasuserw>
1051. Cesar Cerrudo — *Token Kidnapping's Revenge* (2010). <https://defcon.org/images/defcon-18/dc-18-presentations/Cerrudo/DEFCON-18-Cerrudo-Token-Kidnapping-Revenge.pdf>
1052. Cesar Cerrudo — *Chimichurri.zip (Argeniss PoC for MS09-012; Wayback Machine snapshot)* (2009). [https://web.archive.org/web/20120108215145/http://www.argeniss.com/research/Chimichurri.zip](https://web.archive.org/web/20120108215145/http://www.argeniss.com/research/Chimichurri.zip)
1053. James Forshaw — *Empirically Assessing Windows Service Hardening* (2020). <https://www.tiraniddo.dev/2020/01/empirically-assessing-windows-service.html>
1054. *CVE-2015-2370 (DCOM activation; Forshaw Issue 325)*. <https://nvd.nist.gov/vuln/detail/CVE-2015-2370>
1055. *CoercedPotato*. [https://github.com/Prepouce/CoercedPotato](https://github.com/Prepouce/CoercedPotato)
1056. BeichenDream — *GodPotato* (2022). [https://github.com/BeichenDream/GodPotato](https://github.com/BeichenDream/GodPotato)
1057. *CVE-2021-26414 (DCOM three-phase hardening)*. <https://nvd.nist.gov/vuln/detail/CVE-2021-26414>
1058. Antonio Cocomazzi, Andrea Pierini — *LocalPotato: When Swapping the Context Leads You to SYSTEM* (2023). <https://decoder.cloud/2023/02/13/localpotato-when-swapping-the-context-leads-you-to-system/>
1059. *CVE-2023-21746 (LocalPotato fix)*. <https://nvd.nist.gov/vuln/detail/CVE-2023-21746>
1060. Andrea Pierini — *Hello, I'm your Domain Admin and I want to authenticate against you (SilverPotato)* (2024). <https://decoder.cloud/2024/04/24/hello-im-your-domain-admin-and-i-want-to-authenticate-against-you/>
1061. *CVE-2024-38061 (SilverPotato / DCOM permissions, July 2024 Patch Tuesday)*. <https://nvd.nist.gov/vuln/detail/CVE-2024-38061>
1062. *CVE-2024-38100 (FakePotato / ShellWindows AppID activation)*. <https://nvd.nist.gov/vuln/detail/CVE-2024-38100>
1063. Andrea Pierini — *The Fake Potato* (2024). <https://decoder.cloud/2024/08/02/the-fake-potato/>
1064. Andrea Pierini, Antonio Cocomazzi — *10 Years of Windows Privilege Escalation with Potatoes* (2024). <https://www.troopers.de/troopers24/talks/cyzbj3/>
1065. *Service Security and Access Rights*. <https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights>
1066. Antonio Cocomazzi — *JuicyPotatoNG*. [https://github.com/antonioCoco/JuicyPotatoNG](https://github.com/antonioCoco/JuicyPotatoNG)
1067. Clement Labro — *PrivescCheck*. [https://github.com/itm4n/PrivescCheck](https://github.com/itm4n/PrivescCheck)
1068. Elastic. *Privilege Escalation via Rogue Named Pipe Impersonation detection rule (commit 66f03fba0a6f8645b8b2a53f72ebe40b9a04c2b8)*. <https://raw.githubusercontent.com/elastic/detection-rules/66f03fba0a6f8645b8b2a53f72ebe40b9a04c2b8/rules/windows/privilege_escalation_via_rogue_named_pipe.toml>
1069. SigmaHQ. *HackTool - LocalPotato Execution detection rule (commit 36957d791d00bda02d332f44b684d5f65c187c56)*. <https://raw.githubusercontent.com/SigmaHQ/sigma/36957d791d00bda02d332f44b684d5f65c187c56/rules/windows/process_creation/proc_creation_win_hktl_localpotato.yml>
1070. *SigmaHQ LocalPotato detection rule*. <https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/process_creation/proc_creation_win_hktl_localpotato.yml>
1071. *Elastic detection rule: Privilege Escalation via Rogue Named Pipe*. <https://raw.githubusercontent.com/elastic/detection-rules/main/rules/windows/privilege_escalation_via_rogue_named_pipe.toml>
1072. *RET - Intel x86/x64 Instruction Reference*. <https://www.felixcloutier.com/x86/ret>
1073. Adam Chester — *Hiding your.NET - ETW*, 2020. <https://blog.xpnsec.com/hiding-your-dotnet-etw/>
1074. *Event Tracing for Windows: Threat Intelligence Rust Consumer*, fluxsec.red. <https://fluxsec.red/event-tracing-for-windows-threat-intelligence-rust-consumer>
1075. Insung Park, Ricky Buch — *Event Tracing: Improve Debugging And Performance Tuning With ETW*, MSDN Magazine, 2007. <https://learn.microsoft.com/en-us/archive/msdn-magazine/2007/april/event-tracing-improve-debugging-and-performance-tuning-with-etw>
1076. *EVENT_TRACE_PROPERTIES structure*, Microsoft Learn. <https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_properties>
1077. *Event Tracing for Windows (ETW)*, Microsoft Learn (Windows Driver Kit). <https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/event-tracing-for-windows--etw>
1078. *Event Tracing Sessions*, Microsoft Learn. <https://learn.microsoft.com/en-us/windows/win32/etw/event-tracing-sessions>
1079. *Configuring and Starting an Event Tracing Session*, Microsoft Learn. <https://learn.microsoft.com/en-us/windows/win32/etw/configuring-and-starting-an-event-tracing-session>
1080. *NT Kernel Logger Constants*, Microsoft Learn. <https://learn.microsoft.com/en-us/windows/win32/etw/nt-kernel-logger-constants>
1081. *Configuring and Starting a SystemTraceProvider Session*, Microsoft Learn. <https://learn.microsoft.com/en-us/windows/win32/etw/configuring-and-starting-a-systemtraceprovider-session>
1082. Ruben Boonen — *SilkETW: Because Free Telemetry is # FreeTelemetry*, 2019. <https://www.fireeye.com/blog/threat-research/2019/03/silketw-because-free-telemetry-is-free.html>
1083. *EventRegister function*, Microsoft Learn. <https://learn.microsoft.com/en-us/windows/win32/api/evntprov/nf-evntprov-eventregister>
1084. *About Event Tracing*, Microsoft Learn. <https://learn.microsoft.com/en-us/windows/win32/etw/about-event-tracing>
1085. *EnableTraceEx2 function*, Microsoft Learn. <https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-enabletraceex2>
1086. *WPP Software Tracing*, Microsoft Learn. <https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/wpp-software-tracing>
1087. pathtofile — *Sealighter: ETW and WPP-based Threat Hunting Tool*, GitHub. [https://github.com/pathtofile/Sealighter](https://github.com/pathtofile/Sealighter)
1088. *About TraceLogging*, Microsoft Learn. <https://learn.microsoft.com/en-us/windows/win32/tracelogging/trace-logging-about>
1089. *TraceLogging*, Microsoft Learn. <https://learn.microsoft.com/en-us/windows/win32/tracelogging/trace-logging-portal>
1090. Matt Graeber — *Tampering with Windows Event Tracing: Background, Offense, and Defense*, 2018. [https://web.archive.org/web/2023/https://blog.palantir.com/tampering-with-windows-event-tracing-background-offense-and-defense-4be7ac62ac63](https://web.archive.org/web/2023/https://blog.palantir.com/tampering-with-windows-event-tracing-background-offense-and-defense-4be7ac62ac63)
1091. *krabsetw - Microsoft*, GitHub. [https://github.com/microsoft/krabsetw](https://github.com/microsoft/krabsetw)
1092. *PerfView TraceEvent source (Microsoft.Diagnostics.Tracing.TraceEvent)*, GitHub / microsoft/perfview. [https://github.com/microsoft/perfview/tree/main/src/TraceEvent](https://github.com/microsoft/perfview/tree/main/src/TraceEvent)
1093. *Event Tracing*, Microsoft Learn. <https://learn.microsoft.com/en-us/windows/win32/etw/event-tracing-portal>
1094. Ruben Boonen (FuzzySec) — *SilkETW & SilkService - Mandiant*, GitHub. [https://github.com/mandiant/SilkETW](https://github.com/mandiant/SilkETW)
1095. *Windows 10 ETW Events*, GitHub. [https://github.com/jdu2600/Windows10EtwEvents](https://github.com/jdu2600/Windows10EtwEvents)
1096. *ETW Providers Documentation*, GitHub. [https://github.com/repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
1097. Microsoft — *4688 (process create with command line)*, 2026. <https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4688>
1098. *4624(S): An account was successfully logged on*, Microsoft Learn. <https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624>
1099. *about_Logging_Windows (Windows PowerShell 5.1)*, Microsoft Learn. <https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows?view=powershell-5.1>
1100. *Doubling Down: Detecting In-Memory Threats with Kernel ETW Call Stacks*, Elastic Security Labs. <https://www.elastic.co/security-labs/doubling-down-etw-callstacks>
1101. Yarden Shafir — *ETW internals for security research and forensics*, 2023. <https://blog.trailofbits.com/2023/11/22/etw-internals-for-security-research-and-forensics/>
1102. *Advanced security audit policy settings*, Microsoft Learn. <https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/advanced-security-audit-policy-settings>
1103. *PsSetCreateProcessNotifyRoutineEx*, Microsoft Learn. <https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreateprocessnotifyroutineex>
1104. *PsSetCreateThreadNotifyRoutine*, Microsoft Learn. <https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreatethreadnotifyroutine>
1105. David Weston — *Helping our customers through the CrowdStrike outage*, Microsoft Blog, 2024. <https://blogs.microsoft.com/blog/2024/07/20/helping-our-customers-through-the-crowdstrike-outage/>
1106. *Falcon Update for Windows Hosts -- Technical Details*, CrowdStrike Blog, 2024. <https://www.crowdstrike.com/blog/falcon-update-for-windows-hosts-technical-details/>
1107. Matt Graeber — *Palantir ExploitGuard*, GitHub. [https://github.com/palantir/exploitguard](https://github.com/palantir/exploitguard)
1108. *ETW Patching in Rust*, fluxsec.red. <https://fluxsec.red/etw-patching-rust>
1109. *Design issues of modern EDRs: bypassing ETW-based solutions*, Binarly, 2021. <https://www.binarly.io/posts/Design_issues_of_modern_EDRs_bypassing_ETW-based_solutions/index.html>
1110. *Defender*, 2026. <https://paragmali.com/blog/the-defenders-dilemma-microsoft-antivirus/>
1111. *credential dump*, 2026. <https://paragmali.com/blog/the-empty-hash-credential-guard-the-lsaiso-trustlet-and-the-/>
1112. *Early Launch Antimalware*, 2026. <https://paragmali.com/blog/secure-boot-in-windows-the-chain-from-sector-zero-to-userini/>
1113. *BYOVD*, 2026. <https://paragmali.com/blog/wdac--hvci-code-integrity-at-every-layer-in-windows/>
1114. John Kindervag — *No More Chewy Centers: Introducing the Zero Trust Model of Information Security* (2010). <https://media.paloaltonetworks.com/documents/Forrester-No-More-Chewy-Centers.pdf>
1115. Rory Ward, Betsy Beyer — *BeyondCorp: A New Approach to Enterprise Security* (2014). <https://www.usenix.org/publications/login/dec14/ward>
1116. Scott Rose, Oliver Borchert, Stu Mitchell, Sean Connelly — *NIST Special Publication 800-207: Zero Trust Architecture* (2020). <https://csrc.nist.gov/pubs/sp/800/207/final>
1117. Microsoft Learn — *Zero Trust security model overview* (2024). <https://learn.microsoft.com/en-us/security/zero-trust/zero-trust-overview>
1118. Microsoft Learn — *What is Conditional Access in Microsoft Entra ID?* (2024). <https://learn.microsoft.com/en-us/entra/identity/conditional-access/overview>
1119. Microsoft Learn — *Troubleshoot devices by using the dsregcmd command* (2024). <https://learn.microsoft.com/en-us/entra/identity/devices/troubleshoot-device-dsregcmd>
1120. Microsoft Graph — *deviceDetail resource type* (2024). <https://learn.microsoft.com/en-us/graph/api/resources/devicedetail?view=graph-rest-1.0>
1121. Mandiant Threat Intelligence — *Highly Evasive Attacker Leverages SolarWinds Supply Chain to Compromise Multiple Global Victims With SUNBURST Backdoor* (2020). <https://www.mandiant.com/resources/blog/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor>
1122. SolarWinds Corp. — *Form 8-K Filings* (2020). <https://www.sec.gov/cgi-bin/browse-edgar?action=getcompany&CIK=0001739942&type=8-K>
1123. U.S. Senate Select Committee on Intelligence — *Open Hearing on the Hack of U.S. Networks by a Foreign Adversary* (2021). <https://www.intelligence.senate.gov/hearings/open-hearing-hearing-hack-us-networks-foreign-adversary>
1124. Ken Thompson — *Reflections on Trusting Trust* (1984). <https://dl.acm.org/doi/10.1145/358198.358210>
1125. Ken Thompson — *Reflections on Trusting Trust (reading copy)* (1984). <https://nakamotoinstitute.org/library/reflections-on-trusting-trust/>
1126. Microsoft Learn — *Manage Credential Guard* (2024). <https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage>
1127. SpecterOps — *BloodHound Documentation* (2024). <https://bloodhound.specterops.io/>
1128. Microsoft Threat Intelligence — *Microsoft Digital Defense Report 2021* (2021). <https://www.microsoft.com/en-us/security/security-insider/threat-landscape/microsoft-digital-defense-report-2021>
1129. Kim Lewandowski, Mark Lodder — *Introducing SLSA, an End-to-End Framework for Supply Chain Integrity* (2021). <https://security.googleblog.com/2021/06/introducing-slsa-end-to-end-framework.html>
1130. *SLSA Specification v1.0: Levels* (2023). <https://slsa.dev/spec/v1.0/levels>
1131. *CycloneDX Bill of Materials Standard* (2024). <https://cyclonedx.org/>
1132. *SPDX (System Package Data Exchange)* (2024). <https://spdx.dev/>
1133. *in-toto: Software Supply Chain Integrity Framework* (2024). <https://in-toto.io/>
1134. The White House — *Executive Order 14028 on Improving the Nation's Cybersecurity* (2021). <https://bidenwhitehouse.archives.gov/briefing-room/presidential-actions/2021/05/12/executive-order-on-improving-the-nations-cybersecurity/>
1135. CISA, FBI — *Guidance for MSPs and their Customers Affected by the Kaseya VSA Supply-Chain Ransomware Attack* (2021). <https://www.ic3.gov/CSA/2021/210706.pdf>
1136. CISA, FBI, NSA, USSS — *Conti Ransomware (Joint Cybersecurity Advisory AA21-265A, archived snapshot)* (2022). [https://web.archive.org/web/2022/https://www.cisa.gov/uscert/ncas/alerts/aa21-265a](https://web.archive.org/web/2022/https://www.cisa.gov/uscert/ncas/alerts/aa21-265a)
1137. CISA — *FBI Releases IOCs Associated with BlackCat/ALPHV Ransomware* (2022). <https://www.cisa.gov/news-events/alerts/2022/04/22/fbi-releases-iocs-associated-blackcatalphv-ransomware>
1138. CISA, FBI, NSA, ACSC, NCSC-UK — *2021 Trends Show Increased Globalized Threat of Ransomware (Joint Cybersecurity Advisory AA22-040A)* (2022). <https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-040a>
1139. Microsoft — *Microsoft Digital Defense Report 2022* (2022). <https://www.microsoft.com/en-us/security/business/microsoft-digital-defense-report-2022>
1140. Kevin Mandia — *Unauthorized Access of FireEye Red Team Tools* (2020). <https://www.mandiant.com/resources/blog/unauthorized-access-of-fireeye-red-team-tools>
1141. CISA — *Emergency Directive 21-01: Mitigate SolarWinds Orion Code Compromise* (2020). <https://www.cisa.gov/news-events/directives/ed-21-01-mitigate-solarwinds-orion-code-compromise>
1142. Sudhakar Ramakrishna — *New Findings from Our Investigation of SUNBURST* (2021). <https://orangematter.solarwinds.com/2021/01/11/new-findings-from-our-investigation-of-sunburst>
1143. Symantec Threat Hunter Team, Broadcom — *Raindrop: New Malware Discovered in SolarWinds Investigation* (2021). <https://www.security.com/threat-intelligence/solarwinds-raindrop-malware>
1144. CrowdStrike Intelligence Team — *SUNSPOT: An Implant in the Build Process* (2021). <https://www.crowdstrike.com/blog/sunspot-malware-technical-analysis/>
1145. Shaked Reiner — *Golden SAML: Newly Discovered Attack Technique Forges Authentication to Cloud Apps* (2017). <https://www.cyberark.com/resources/threat-research-blog/golden-saml-newly-discovered-attack-technique-forges-authentication-to-cloud-apps>
1146. CyberArk — *shimit -- Golden SAML proof-of-concept tool* (2017). [https://github.com/cyberark/shimit](https://github.com/cyberark/shimit)
1147. The White House — *Fact Sheet: Imposing Costs for Harmful Foreign Activities by the Russian Government* (2021). <https://bidenwhitehouse.archives.gov/briefing-room/statements-releases/2021/04/15/fact-sheet-imposing-costs-for-harmful-foreign-activities-by-the-russian-government/>
1148. Mandiant — *UNC2452 Merged into APT29* (2022). <https://cloud.google.com/blog/topics/threat-intelligence/unc2452-merged-into-apt29>
1149. John Lambert, Microsoft Threat Intelligence — *Microsoft shifts to a new threat actor naming taxonomy* (2023). <https://www.microsoft.com/en-us/security/blog/2023/04/18/microsoft-shifts-to-a-new-threat-actor-naming-taxonomy/>
1150. *FireEye Mandiant SunBurst Countermeasures* (2020). [https://github.com/mandiant/sunburst_countermeasures](https://github.com/mandiant/sunburst_countermeasures)
1151. CISA — *AA21-008A: Detecting Post-Compromise Threat Activity in Microsoft Cloud Environments* (2021). <https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-008a>
1152. Steven Adair, Thomas Lancaster, Josh Grunzweig, Matthew Meltzer, Sean Koessel — *Operation Exchange Marauder: Active Exploitation of Multiple Zero-Day Microsoft Exchange Vulnerabilities* (2021). <https://www.volexity.com/blog/2021/03/02/active-exploitation-of-microsoft-exchange-zero-day-vulnerabilities/>
1153. Cheng-Da Tsai — *ProxyLogon: A New Attack Surface on MS Exchange - Part 1* (2021). <https://blog.orange.tw/posts/2021-08-proxylogon-a-new-attack-surface-on-ms-exchange-part-1/>
1154. Microsoft Threat Intelligence Center — *HAFNIUM targeting Exchange Servers with 0-day exploits* (2021). <https://www.microsoft.com/en-us/security/blog/2021/03/02/hafnium-targeting-exchange-servers/>
1155. *NVD - CVE-2021-26855* (2021). <https://nvd.nist.gov/vuln/detail/CVE-2021-26855>
1156. Tenable Research — *CVE-2021-26855, CVE-2021-26857, CVE-2021-26858, CVE-2021-27065: Four Microsoft Exchange Server Zero-Day Vulnerabilities* (2021). <https://www.tenable.com/blog/cve-2021-26855-cve-2021-26857-cve-2021-26858-cve-2021-27065-four-microsoft-exchange-server-zero-day-vulnerabilities>
1157. Brian Krebs — *At Least 30,000 U.S. Organizations Newly Hacked Via Holes in Microsoft's Email Software* (2021). <https://krebsonsecurity.com/2021/03/at-least-30000-u-s-organizations-newly-hacked-via-holes-in-microsofts-email-software/>
1158. William Turton, Kartikay Mehrotra — *Hackers Breach Thousands of Microsoft Customers Around the World* (2021). [https://web.archive.org/web/20210307165519/https://www.bloomberg.com/news/articles/2021-03-07/hackers-breach-thousands-of-microsoft-customers-around-the-world](https://web.archive.org/web/20210307165519/https://www.bloomberg.com/news/articles/2021-03-07/hackers-breach-thousands-of-microsoft-customers-around-the-world)
1159. Matthieu Faou, Mathieu Tartare, Thomas Dupuy — *Exchange servers under siege from at least 10 APT groups* (2021). <https://www.welivesecurity.com/2021/03/10/exchange-servers-under-siege-10-apt-groups/>
1160. U.S. Department of Justice — *Justice Department Announces Court-Authorized Effort to Disrupt Exploitation of Microsoft Exchange Server Vulnerabilities* (2021). <https://www.justice.gov/opa/pr/justice-department-announces-court-authorized-effort-disrupt-exploitation-microsoft-exchange>
1161. Hunton Andrews Kurth — *Court Authorizes FBI to Remove Web Shells from Compromised Microsoft Exchange Servers* (2021). <https://www.hunton.com/privacy-and-cybersecurity-law-blog/court-authorizes-fbi-to-remove-web-shells-from-compromised-microsoft-exchange-servers>
1162. Microsoft Security Response Center — *CVE-2021-1675 Update Guide* (2021). <https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-1675>
1163. *cube0x0/CVE-2021-1675 (PrintNightmare PoC)* (2021). [https://github.com/cube0x0/CVE-2021-1675](https://github.com/cube0x0/CVE-2021-1675)
1164. Will Dormann — *VU#383432: Microsoft Windows Print Spooler allows for RCE via AddPrinterDriverEx()* (2021). <https://kb.cert.org/vuls/id/383432>
1165. Microsoft Security Response Center — *CVE-2021-34527 Update Guide* (2021). <https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527>
1166. CISA — *Emergency Directive 21-04: Mitigate Windows Print Spooler Service Vulnerability* (2021). <https://www.cisa.gov/news-events/directives/ed-21-04-mitigate-windows-print-spooler-service-vulnerability>
1167. Microsoft — *KB5005010: Restricting installation of new printer drivers after applying the July 6, 2021 updates* (2021). <https://support.microsoft.com/topic/kb5005010-restricting-installation-of-new-printer-drivers-after-applying-the-july-6-2021-updates-31b91c02-05bc-4ada-a7ea-183b129578a7>
1168. GitHub — *About forks* (2024). <https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/working-with-forks/about-forks>
1169. Alex Ionescu, Yarden Shafir — *PrintDemon: Print Spooler Privilege Escalation, Persistence & Stealth (CVE-2020-1048)* (2020). <https://windows-internals.com/printdemon-cve-2020-1048/>
1170. Sean Lyngaas — *Old vulnerabilities die hard: researchers uncover 20-year-old code in Windows print spooler* (2020). <https://cyberscoop.com/windows-print-spooler-safebreach-black-hat/>
1171. Apache Software Foundation — *Apache Log4j Security Vulnerabilities* (2021). <https://logging.apache.org/log4j/2.x/security.html>
1172. Free Wortley, Chris Thompson, Forrest Allison — *Log4Shell: RCE 0-day exploit found in log4j* (2021). [https://github.com/lunasec-io/lunasec/blob/master/docs/blog/2021-12-09-log4j-zero-day.mdx](https://github.com/lunasec-io/lunasec/blob/master/docs/blog/2021-12-09-log4j-zero-day.mdx)
1173. *NVD - CVE-2021-44228* (2021). <https://nvd.nist.gov/vuln/detail/CVE-2021-44228>
1174. Jen Easterly — *Statement from CISA Director Easterly on Log4j Vulnerability* (2021). <https://www.cisa.gov/news-events/news/statement-cisa-director-easterly-log4j-vulnerability>
1175. Tim Starks — *CISA chief: Log4j among the most serious flaws in her career* (2021). <https://cyberscoop.com/log4j-cisa-easterly-most-serious/>
1176. Microsoft Threat Intelligence — *Guidance for preventing, detecting, and hunting for CVE-2021-44228 Log4j 2 exploitation* (2021). <https://www.microsoft.com/en-us/security/blog/2021/12/11/guidance-for-preventing-detecting-and-hunting-for-cve-2021-44228-log4j-2-exploitation/>
1177. CISA — *AA21-356A: Mitigating Log4Shell and Other Log4j-Related Vulnerabilities* (2021). <https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-356a>
1178. Barclay Osborn, Justin McWilliams, Betsy Beyer, Max Saltonstall — *BeyondCorp: Design to Deployment at Google* (2016). <https://www.usenix.org/publications/login/spring2016/osborn>
1179. Luca Cittadini, Batz Spear, Betsy Beyer, Max Saltonstall — *BeyondCorp Part III: The Access Proxy* (2016). <https://www.usenix.org/publications/login/winter2016/cittadini>
1180. Jeff Peck, Betsy Beyer, Colin Beske, Max Saltonstall — *Migrating to BeyondCorp: Maintaining Productivity While Improving Security* (2017). <https://www.usenix.org/publications/login/summer2017/peck>
1181. Victor Escobedo, Betsy Beyer, Max Saltonstall, Filip Żyźniewski — *BeyondCorp: The User Experience* (2017). <https://www.usenix.org/publications/login/fall2017/escobedo>
1182. Microsoft — *Update release cycle for Windows clients* (2024). <https://learn.microsoft.com/en-us/windows/deployment/update/release-cycle>
1183. ISC2 — *15 Years of Zero Trust* (2025). <https://www.isc2.org/Insights/2025/10/15-Years-of-Zero-Trust>
1184. John Kindervag — *No More Chewy Centers: Reflecting on 15 Years of Zero Trust* (2025). <https://hub.illumio.com/briefs/no-more-chewy-centers-reflecting-on-15-years-of-zero-trust>
1185. Office of Management and Budget — *M-22-09: Moving the U.S. Government Toward Zero Trust Cybersecurity Principles* (2022). <https://www.whitehouse.gov/wp-content/uploads/2022/01/M-22-09.pdf>
1186. Lenovo — *ThinkPad Z Series Ushers in a New Look and Recycled Materials for the Iconic Brand* (2022). [https://web.archive.org/web/2022/https://news.lenovo.com/pressroom/press-releases/thinkpad-z-series-new-look-recycled-materials](https://web.archive.org/web/2022/https://news.lenovo.com/pressroom/press-releases/thinkpad-z-series-new-look-recycled-materials)
1187. David Weston — *CES 2022: Chip to cloud security: Pluton-powered Windows 11 PCs are coming* (2022). <https://blogs.windows.com/windowsexperience/2022/01/04/ces-2022-chip-to-cloud-security-pluton-powered-windows-11-pcs-are-coming/>
1188. Microsoft — *Windows 11 specifications* (2021). <https://www.microsoft.com/en-us/windows/windows-11-specifications>
1189. OpenID Foundation — *OpenID Continuous Access Evaluation Profile (CAEP)* (2024). <https://openid.net/specs/openid-caep-specification-1_0-01.html>
1190. Vasu Jakkal — *Secure access for a connected world--meet Microsoft Entra* (2022). <https://www.microsoft.com/en-us/security/blog/2022/05/31/secure-access-for-a-connected-worldmeet-microsoft-entra/>
1191. Microsoft — *Azure AD is Becoming Microsoft Entra ID* (2023). <https://techcommunity.microsoft.com/blog/microsoft-entra-blog/azure-ad-is-becoming-microsoft-entra-id/2520436>
1192. Microsoft Learn — *Microsoft Entra ID Protection risk detections* (2024). <https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks>
1193. Microsoft Graph — *signIn resource type* (2024). <https://learn.microsoft.com/en-us/graph/api/resources/signin?view=graph-rest-1.0>
1194. Microsoft Graph — *appliedConditionalAccessPolicy resource type* (2024). <https://learn.microsoft.com/en-us/graph/api/resources/appliedconditionalaccesspolicy?view=graph-rest-1.0>
1195. Microsoft Learn — *Windows 11 Security Book -- Advanced credential protection (LSA Protection)* (2024). <https://learn.microsoft.com/en-us/windows/security/book/identity-protection-advanced-credential-protection>
1196. Microsoft Learn — *Microsoft recommended driver block rules* (2024). <https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules>
1197. Microsoft Learn — *Get behavioral analytics and anomaly detection in Defender for Cloud Apps* (2024). <https://learn.microsoft.com/en-us/defender-cloud-apps/anomaly-detection-policy>
1198. Microsoft 365 Defender Team — *Web shell attacks continue to rise* (2021). <https://www.microsoft.com/en-us/security/blog/2021/02/11/web-shell-attacks-continue-to-rise/>
1199. Microsoft Learn — *Zero Trust deployment guide* (2024). <https://learn.microsoft.com/en-us/security/zero-trust/>
1200. Microsoft Inside Track — *Implementing a Zero Trust security model at Microsoft* (2024). <https://www.microsoft.com/insidetrack/blog/implementing-a-zero-trust-security-model-at-microsoft/>
1201. Okta — *Okta Customer Stories* (2024). <https://www.okta.com/customers/>
1202. CISA — *Zero Trust Maturity Model Version 2.0* (2023). <https://www.cisa.gov/sites/default/files/2023-04/CISA_Zero_Trust_Maturity_Model_Version_2_508c.pdf>
1203. U.S. Department of Homeland Security — *CISA Zero Trust Architecture Implementation* (2025). <https://www.dhs.gov/sites/default/files/2025-04/2025_0129_cisa_zero_trust_architecture_implementation.pdf>
1204. U.S. Government Accountability Office — *Cybersecurity: Implementation of Executive Order Requirements Is Essential to Address Key Actions* (2024). <https://www.gao.gov/products/gao-24-106343>
1205. U.S. Securities and Exchange Commission Office of Inspector General — *Final Management Letter: Readiness Review -- The SEC's Progress Toward Implementing Zero Trust Cybersecurity Principles* (2023). <https://www.sec.gov/files/fnl-mgmt-ltr-readiness-rvw-secs-prog-twd-implmntng-zero-trust-cyber-prncpls.pdf>
1206. Microsoft Security Response Center — *Microsoft Internal Solorigate Investigation - Final Update* (2021). <https://www.microsoft.com/en-us/msrc/blog/2021/02/microsoft-internal-solorigate-investigation-final-update/>
1207. Fred Cohen — *Computer Viruses: Theory and Experiments* (1984). <https://all.net/books/virus/index.html>
1208. Microsoft Security Response Center — *Results of Major Technical Investigations for Storm-0558 Key Acquisition* (2023). <https://msrc.microsoft.com/blog/2023/09/results-of-major-technical-investigations-for-storm-0558-key-acquisition/>
1209. Mandiant Consulting — *3CX Software Supply Chain Compromise Initiated by a Prior Software Supply Chain Compromise* (2023). <https://www.mandiant.com/resources/blog/3cx-software-supply-chain-compromise>
1210. CISA, FBI — *#StopRansomware: CL0P Ransomware Gang Exploits CVE-2023-34362 MOVEit Vulnerability* (2023). <https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-158a>
1211. UnitedHealth Group — *Form 8-K: Material Cybersecurity Incident (Change Healthcare)* (2024). <https://www.sec.gov/Archives/edgar/data/731766/000073176624000045/unh-20240221.htm>
1212. Christian Vasquez, CyberScoop — *U.S. car dealers are feeling the pain of CDK cyberattack* (2024). <https://www.cyberscoop.com/cdk-ransomware-car-dealers/>
1213. OpenSSF SLSA Project — *SLSA v1.0 Specification: Producing Artifacts Requirements* (2023). <https://slsa.dev/spec/v1.0/requirements>
1214. GitHub — *About security hardening with OpenID Connect* (2024). <https://docs.github.com/en/actions/security-for-github-actions/security-hardening-your-deployments/about-security-hardening-with-openid-connect>
1215. Zachary Newman, John Speed Meyers, Santiago Torres-Arias — *Sigstore: Software Signing for Everybody* (2022). <https://dl.acm.org/doi/10.1145/3548606.3560596>
1216. Sigstore Project — *Cosign: Signing Overview* (2024). <https://docs.sigstore.dev/cosign/signing/overview/>
1217. Sigstore Project — *Rekor: Logging Overview* (2024). <https://docs.sigstore.dev/logging/overview/>
1218. OpenSSF SLSA Project — *slsa-framework/slsa-github-generator* (2024). [https://github.com/slsa-framework/slsa-github-generator](https://github.com/slsa-framework/slsa-github-generator)
1219. Anchore — *anchore/syft* (2024). [https://github.com/anchore/syft](https://github.com/anchore/syft)
1220. Aqua Security — *aquasecurity/trivy* (2024). [https://github.com/aquasecurity/trivy](https://github.com/aquasecurity/trivy)
1221. Merill Fernando, Thomas Naunheim — *maester365/maester* (2024). [https://github.com/maester365/maester](https://github.com/maester365/maester)
1222. Maester Project — *Maester: Test Automation for Microsoft 365 Security* (2024). <https://maester.dev/>
1223. Maester Project — *Conditional Access What-If Tests* (2024). <https://maester.dev/docs/ca-what-if/>
1224. Joosua Santasalo — *jsa2/caOptics: Azure AD Conditional Access Gap Analyzer* (2024). [https://github.com/jsa2/caOptics](https://github.com/jsa2/caOptics)
1225. SpecterOps — *SpecterOps/AzureHound: BloodHound data collector for Microsoft Azure* (2024). [https://github.com/SpecterOps/AzureHound](https://github.com/SpecterOps/AzureHound)
1226. SpecterOps — *BloodHound CE: AzureHound CE Collection Documentation* (2024). <https://bloodhound.specterops.io/collect-data/ce-collection/azurehound>
1227. RFC 6749: The OAuth 2.0 Authorization Framework. <https://datatracker.ietf.org/doc/html/rfc6749>
1228. How to use Continuous Access Evaluation enabled APIs in your applications. <https://learn.microsoft.com/en-us/entra/identity-platform/app-resilience-continuous-access-evaluation>
1229. Three Shared Signals Final Specifications Approved. <https://openid.net/three-shared-signals-final-specifications-approved/>
1230. Microsoft Entra expands into security service edge and Azure AD becomes Microsoft Entra ID. <https://www.microsoft.com/en-us/security/blog/2023/07/11/microsoft-entra-expands-into-security-service-edge-and-azure-ad-becomes-microsoft-entra-id/>
1231. BeyondCorp: A New Approach to Enterprise Security. <https://www.usenix.org/system/files/login/articles/login_dec14_02_ward.pdf>
1232. Re-thinking federated identity with the Continuous Access Evaluation Protocol. <https://cloud.google.com/blog/products/identity-security/re-thinking-federated-identity-with-the-continuous-access-evaluation-protocol>
1233. Securing Cloud Access with Continuous Access Evaluation Protocol. <https://www.idsalliance.org/blog/securing-cloud-access-with-continuous-access-evaluation-protocol/>
1234. RFC 7009: OAuth 2.0 Token Revocation. <https://datatracker.ietf.org/doc/html/rfc7009>
1235. RFC 7662: OAuth 2.0 Token Introspection. <https://datatracker.ietf.org/doc/html/rfc7662>
1236. Moving towards real time policy and security enforcement. <https://techcommunity.microsoft.com/blog/microsoft-entra-blog/moving-towards-real-time-policy-and-security-enforcement/1276933>
1237. Moving towards real time policy and security enforcement (Japanese translation). [https://github.com/jpazureid/blog-1/blob/main/articles/azure-active-directory/moving-towards-real-time-policy-and-security-enforcement.md](https://github.com/jpazureid/blog-1/blob/main/articles/azure-active-directory/moving-towards-real-time-policy-and-security-enforcement.md)
1238. Continuous Access Evaluation in Azure AD is now in public preview. <https://techcommunity.microsoft.com/blog/microsoft-entra-blog/continuous-access-evaluation-in-azure-ad-is-now-in-public-preview/1751704>
1239. Continuous Access Evaluation in Azure AD is now generally available. <https://thewindowsupdate.com/2022/01/10/continuous-access-evaluation-in-azure-ad-is-now-generally-available/>
1240. RFC 8417: Security Event Token (SET). <https://datatracker.ietf.org/doc/html/rfc8417>
1241. RFC 8935: Push-Based Security Event Token (SET) Delivery Using HTTP. <https://datatracker.ietf.org/doc/html/rfc8935>
1242. Strictly enforce location policies using continuous access evaluation. <https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-continuous-access-evaluation-strict-enforcement>
1243. OpenID Shared Signals Framework 1.0 (Final). <https://openid.net/specs/openid-sharedsignals-framework-1_0-final.html>
1244. OpenID Continuous Access Evaluation Profile 1.0. <https://openid.net/specs/openid-caep-1_0-final.html>
1245. Shared Signals Interop Event at Authenticate 2025 - Call for Participation. <https://openid.net/shared-signals-interop-event-at-authenticate-2025-call-for-participation/>
1246. SGNL Demonstrates Standards-Based Interoperability with Okta, Cisco, SailPoint, and Helisoft. <https://sgnl.ai/2024/04/sgnl-demonstrates-standards-based-interoperability-with-okta-cisco-sailpoint-and-helisoft/>
1247. Okta Leads the Way Driving Real-Time Security with Shared Signals. <https://www.okta.com/blog/product-innovation/okta-leads-the-way-driving-real-time-security-with-shared-signals/>
1248. CAEP and SSF: Your Questions Answered. <https://sgnl.ai/2023/08/caep-and-ssf-your-questions-answered/>
1249. OpenID Shared Signals Working Group. <https://openid.net/wg/sharedsignals/>
1250. RFC 8705: OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Access Tokens. <https://datatracker.ietf.org/doc/html/rfc8705>
1251. CAEP and Shared Signals Explained. <https://www.tigeridentity.com/blog/caep-shared-signals-explained/>
1252. Google Workspace Shared Signals Framework API. <https://developers.google.com/workspace/shared-signals/api/ssf-api>
1253. Conditional Access for Agent Identities in Microsoft Entra. <https://learn.microsoft.com/en-us/entra/identity/conditional-access/agent-id>
1254. AspNetCoreMeIDCAE reference implementation. [https://github.com/damienbod/AspNetCoreMeIDCAE](https://github.com/damienbod/AspNetCoreMeIDCAE)
1255. Implement Microsoft Entra ID Continuous Access in an ASP.NET Core Razor Page app using a Web API. <https://damienbod.com/2022/04/20/implement-azure-ad-continuous-access-evaluation-in-an-asp-net-core-razor-page-app-using-a-web-api/>
1256. RFC 8936: Poll-Based Security Event Token (SET) Delivery Using HTTP. <https://datatracker.ietf.org/doc/html/rfc8936>
1257. Azure AD Continuous Access Evaluation (CAE) - A First Look. <https://www.vansurksum.com/2020/10/10/azure-ad-continuous-access-evaluation-cae-a-first-look/>
1258. Microsoft — *Azure Confidential Computing: products overview* (2024). <https://learn.microsoft.com/en-us/azure/confidential-computing/overview-azure-products>
1259. *OpenHCL: the new, open source paravisor (Microsoft Tech Community)*, 2024. <https://techcommunity.microsoft.com/blog/windowsosplatform/openhcl-the-new-open-source-paravisor/4273172>
1260. *Confidential Computing Consortium — About*. <https://confidentialcomputing.io/about/>
1261. *Microsoft Learn: Azure confidential VM overview*. <https://learn.microsoft.com/en-us/azure/confidential-computing/confidential-vm-overview>
1262. H. Birkholz, D. Thaler, M. Richardson, N. Smith, W. Pan, *RFC 9334: Remote ATtestation procedureS (RATS) Architecture*, 2023. <https://datatracker.ietf.org/doc/rfc9334/>
1263. David Kaplan, *AMD x86 Memory Encryption Technologies*, 2016. <https://www.usenix.org/conference/usenixsecurity16/technical-sessions/presentation/kaplan>
1264. Victor Costan, Srinivas Devadas, *Intel SGX Explained*, 2016. <https://eprint.iacr.org/2016/086>
1265. Stephan van Schaik, Andrew Kwong, Daniel Genkin, Yuval Yarom, *SGAxe: How SGX Fails in Practice*, 2020. <https://cacheoutattack.com/files/SGAxe.pdf>
1266. Mark Russinovich, *Introducing Azure confidential computing*, 2017. <https://azure.microsoft.com/en-us/blog/introducing-azure-confidential-computing/>
1267. Mark Russinovich, *Microsoft partners with the Linux Foundation to announce the Confidential Computing Consortium*, 2019. <https://opensource.microsoft.com/blog/2019/08/21/microsoft-partners-linux-foundation-announce-confidential-computing-consortium/>
1268. *Linux Foundation press release: CCC formation (Oct 17 2019)*. <https://www.linuxfoundation.org/press/press-release/confidential-computing-consortium-establishes-formation-with-founding-members-and-open-governance-structure-2>
1269. David Kaplan, Jeremy Powell, Tom Woller, *AMD Memory Encryption*, 2016. <https://kib.kiev.ua/x86docs/AMD/SEV/memory-encryption-white-paper-Oct-2021.pdf>
1270. David Kaplan, *Protecting VM Register State with SEV-ES*, 2017. <https://www.amd.com/content/dam/amd/en/documents/epyc-business-docs/white-papers/Protecting-VM-Register-State-with-SEV-ES.pdf>
1271. David Kaplan, *AMD SEV-SNP: Strengthening VM Isolation with Integrity Protection and More*, 2020. <https://www.amd.com/content/dam/amd/en/documents/epyc-business-docs/white-papers/SEV-SNP-strengthening-vm-isolation-with-integrity-protection-and-more.pdf>
1272. Intel Corporation, *Architecture Specification: Intel Trust Domain Extensions Module (doc 344425-001)*, 2020. <https://kib.kiev.ua/x86docs/Intel/TDX/344425-001.pdf>
1273. *AMD EPYC Datacenter Processor Launches with Record-Setting Performance, Optimized Platforms, and Global Server Ecosystem Support*. <https://ir.amd.com/news-events/press-releases/detail/773/amd-epyc-datacenter-processor-launches-with-record-setting-performance-optimized-platforms-and-global-server-ecosystem-support>
1274. Mathias Morbitzer, Manuel Huber, Julian Horsch, Sascha Wessel, *SEVered: Subverting AMD's Virtual Machine Encryption*, 2018. <https://arxiv.org/abs/1805.09604>
1275. Robert Buhren, Christian Werling, Jean-Pierre Seifert, *Insecure Until Proven Updated: Analyzing AMD SEV's Remote Attestation*, 2019. <https://arxiv.org/abs/1908.11680>
1276. Luca Wilke, Jan Wichelmann, Mathias Morbitzer, Thomas Eisenbarth, *SEVurity: No Security Without Integrity (project page)*, 2020. <https://uzl-its.github.io/SEVurity/>
1277. Robert Buhren, Hans Niklas Jacob, Thilo Krachenfels, Jean-Pierre Seifert, *One Glitch to Rule Them All: Fault Injection Attacks Against AMD's Secure Encrypted Virtualization*, 2021. <https://arxiv.org/abs/2108.04575>
1278. *PSPReverse / amd-sp-glitch (One Glitch artefact)*. [https://github.com/PSPReverse/amd-sp-glitch](https://github.com/PSPReverse/amd-sp-glitch)
1279. Intel Corporation, *Intel Architecture Memory Encryption Technologies Specification (doc 336907)*, 2017. <https://kib.kiev.ua/x86docs/Intel/MemEncryption/336907-001.pdf>
1280. *LWN-archived RFC: Multi-Key Total Memory Encryption API (MKTME)*, 2018. <https://lwn.net/Articles/764480/>
1281. Intel Corporation, *Intel TDX Module 1.5 Base Architecture Specification (doc 348549, rev 002)*, 2024. <https://cdrdv2-public.intel.com/733575/intel-tdx-module-1.5-base-spec-348549002.pdf>
1282. Intel Corporation, *Intel TDX Enabling Guide: Infrastructure Setup — Intel TDX Remote Attestation*. <https://cc-enabling.trustedservices.intel.com/intel-tdx-enabling-guide/02/infrastructure_setup/>
1283. *Microsoft Learn: Azure Attestation policy version 1.2*. <https://learn.microsoft.com/en-us/azure/attestation/policy-version-1-2>
1284. *Microsoft Azure expands confidential VM offerings (The Register)*, 2022. <https://www.theregister.com/2022/07/20/microsoft_confidential_vms/>
1285. *Lenovo Press: Enabling AMD SEV-SNP on ThinkSystem servers (LP1893)*. <https://lenovopress.lenovo.com/lp1893-enabling-amd-sev-snp-on-thinksystem-servers>
1286. *Intel Adds TDX to Confidential Computing Portfolio with 4th Gen Xeon launch (SecurityWeek)*, 2023. <https://www.securityweek.com/intel-adds-tdx-confidential-computing-portfolio-launch-4th-gen-xeon-processors/>
1287. *microsoft/openvmm (GitHub)*. [https://github.com/microsoft/openvmm](https://github.com/microsoft/openvmm)
1288. *OpenVMM Guide*. <https://openvmm.dev/guide/>
1289. *AMD-SEV linux-svsm reference Secure VM Service Module*. [https://github.com/AMDESE/linux-svsm](https://github.com/AMDESE/linux-svsm)
1290. *COCONUT-SVSM: an open-source Secure VM Service Module*. [https://github.com/coconut-svsm/svsm](https://github.com/coconut-svsm/svsm)
1291. *Microsoft Learn: Confidential containers on Azure Container Instances*. <https://learn.microsoft.com/en-us/azure/container-instances/container-instances-confidential-overview>
1292. *Microsoft Learn: Confidential containers on AKS (preview / sunset notice)*. <https://learn.microsoft.com/en-us/azure/aks/confidential-containers-overview>
1293. *Microsoft Learn: AKS confidential VM node pools*. <https://learn.microsoft.com/en-us/azure/confidential-computing/confidential-node-pool-aks>
1294. *CNCF Confidential Containers project page*. <https://www.cncf.io/projects/confidential-containers/>
1295. *Confidential Containers documentation*. <https://confidentialcontainers.org/docs/>
1296. *Edgeless Contrast: workload-level confidential containers (Constellation successor)*. [https://github.com/edgelesssys/contrast](https://github.com/edgelesssys/contrast)
1297. *Edgeless Constellation: confidential Kubernetes distribution (archived; succeeded by Contrast)*. [https://github.com/edgelesssys/constellation](https://github.com/edgelesssys/constellation)
1298. *AWS Nitro Enclaves user guide*. <https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave.html>
1299. *Google Cloud: Confidential VM overview*. <https://cloud.google.com/confidential-computing/confidential-vm/docs/about-cvm>
1300. *Google Cloud: Confidential Computing product hub*. <https://cloud.google.com/confidential-computing>
1301. *Google Cloud: Confidential VM supported configurations*. <https://docs.cloud.google.com/confidential-computing/confidential-vm/docs/supported-configurations?hl=en>
1302. *ETH Zurich ZISC news: Ahoi attacks disrupting TEEs with malicious notifications*, 2024. <https://zisc.ethz.ch/2024/05/02/ahoi-attacks-disrupting-tees-with-malicious-notifications/>
1303. *Ahoi Attacks: WeSee project page*. <https://ahoi-attacks.github.io/wesee/>
1304. Benedict Schlueter, Supraja Sridhara, Mark Kuhne, Andrin Bertschi, Shweta Shinde, *Heckler — USENIX Security 2024*, 2024. <https://www.usenix.org/conference/usenixsecurity24/presentation/schl%C3%BCter>
1305. Ruiyi Zhang, Lukas Gerlach, Daniel Weber, Lorenz Hetterich, Youheng Lü, Andreas Kogler, Michael Schwarz, *CacheWarp: Software-based Fault Injection using Selective State Reset*, 2024. <https://www.usenix.org/conference/usenixsecurity24/presentation/zhang-ruiyi>
1306. Erdem Aktas, Cfir Cohen, Josh Eads, James Forshaw, Felix Wilhelm, *Intel Trust Domain Extensions (TDX) Security Review*, 2023. <https://services.google.com/fh/files/misc/intel_tdx_-_full_report_041423.pdf>
1307. *NVD record for CVE-2023-20592 (CacheWarp / INVD)*. <https://nvd.nist.gov/vuln/detail/CVE-2023-20592>
1308. *CacheWarp project page*. <https://cachewarpattack.com/>
1309. *AMD Security Bulletin AMD-SB-3005 (CacheWarp / CVE-2023-20592)*. <https://www.amd.com/en/resources/product-security/bulletin/amd-sb-3005.html>
1310. Benedict Schlueter, Supraja Sridhara, Andrin Bertschi, Shweta Shinde, *WeSee: Using Malicious #VC Interrupts to Break AMD SEV-SNP*, 2024. <https://arxiv.org/abs/2404.03526>
1311. *Ahoi Attacks: Heckler project page*. <https://ahoi-attacks.github.io/heckler/>
1312. Benedict Schlueter, Supraja Sridhara, Mark Kuhne, Andrin Bertschi, Shweta Shinde, *Heckler: Breaking Confidential VMs with Malicious Interrupts*, 2024. <https://arxiv.org/abs/2404.03387>
1313. *Ahoi Attacks family page*. <https://ahoi-attacks.github.io/>
1314. Intel Corporation, *Intel TDX Module 1.5 TD Partitioning Architecture Specification (doc 354807, rev 003)*, 2024. <https://cdrdv2-public.intel.com/817876/intel-tdx-module-1.5-td-partitioning-spec-354807003.pdf>
1315. *Wikipedia: Trust Domain Extensions*. <https://en.wikipedia.org/wiki/Trust_Domain_Extensions>
1316. Cyber Safety Review Board — *Review of the Summer 2023 Microsoft Exchange Online Intrusion* (2024). <https://www.cisa.gov/sites/default/files/2025-03/CSRBReviewOfTheSummer2023MEOIntrusion508.pdf>
1317. Microsoft Security Response Center — *Microsoft mitigates China-based threat actor Storm-0558 targeting of customer email* (2023). <https://msrc.microsoft.com/blog/2023/07/microsoft-mitigates-china-based-threat-actor-storm-0558-targeting-of-customer-email/>
1318. Microsoft Threat Intelligence — *Analysis of Storm-0558 techniques for unauthorized email access* (2023). <https://www.microsoft.com/en-us/security/blog/2023/07/14/analysis-of-storm-0558-techniques-for-unauthorized-email-access/>
1319. Microsoft — *Microsoft threat actor naming* (2024). <https://learn.microsoft.com/en-us/unified-secops/microsoft-threat-actor-naming>
1320. Microsoft Security Response Center — *Microsoft Internal Solorigate Investigation -- Final Update* (2021). <https://msrc.microsoft.com/blog/2021/02/microsoft-internal-solorigate-investigation-final-update/>
1321. CISA — *Advanced Persistent Threat Compromise of Government Agencies, Critical Infrastructure, and Private Sector Organizations (AA20-352A)* (2020). <https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-352a>
1322. Wiz Research — *Storm-0558: Compromised Microsoft Key Enables Authentication of Countless Microsoft Applications* (2023). <https://www.wiz.io/blog/storm-0558-compromised-microsoft-key-enables-authentication-of-countless-micr>
1323. Microsoft — *Microsoft identity platform OpenID Connect v2.0 discovery document (consumers tenant)* (2026). <https://login.microsoftonline.com/consumers/v2.0/.well-known/openid-configuration>
1324. Y. Sheffer, D. Hardt, M. Jones — *RFC 8725: JSON Web Token Best Current Practices* (2020). <https://datatracker.ietf.org/doc/html/rfc8725>
1325. CISA, FBI — *Enhanced Monitoring to Detect APT Activity Targeting Outlook Online (AA23-193A)* (2023). <https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-193a>
1326. Microsoft — *Expanding cloud logging to give customers deeper security visibility* (2023). <https://www.microsoft.com/en-us/security/blog/2023/07/19/expanding-cloud-logging-to-give-customers-deeper-security-visibility/>
1327. CISA — *CISA and Microsoft Partnership Expands Access to Logging Capabilities Broadly* (2023). <https://www.cisa.gov/news-events/news/cisa-and-microsoft-partnership-expands-access-logging-capabilities-broadly>
1328. Office of Senator Ron Wyden — *Wyden Requests Federal Agencies Investigate Lax Cybersecurity Practices by Microsoft that Reportedly Enabled Chinese Espionage* (2023). <https://www.wyden.senate.gov/news/press-releases/wyden-requests-federal-agencies-investigate-lax-cybersecurity-practices-by-microsoft-that-reportedly-enabled-chinese-espionage>
1329. Office of Senator Ron Wyden — *Wyden Statement on Cyber Safety Review Board Investigation of Recent Microsoft Exchange Online Intrusion* (2023). <https://www.wyden.senate.gov/news/press-releases/wyden-statement-on-cyber-safety-review-board-investigation-of-recent-microsoft-exchange-online-intrusion>
1330. The White House — *Executive Order 14028: Improving the Nation's Cybersecurity* (2021). <https://www.gsa.gov/technology/government-it-initiatives/cybersecurity/executive-order-14028>
1331. CISA — *Cyber Safety Review Board (CSRB)* (2024). <https://www.cisa.gov/resources-tools/groups/cyber-safety-review-board-csrb>
1332. U.S. Department of Homeland Security — *Department of Homeland Security's Cyber Safety Review Board to Conduct Review on Cloud Security (archive)* (2023). <https://www.dhs.gov/archive/news/2023/08/11/department-homeland-securitys-cyber-safety-review-board-conduct-review-cloud>
1333. U.S. Department of Homeland Security — *Cyber Safety Review Board Releases Report on Microsoft Online Exchange Incident from Summer 2023* (2024). <https://www.dhs.gov/news/2024/04/02/cyber-safety-review-board-releases-report-microsoft-online-exchange-incident-summer>
1334. Brad Smith — *Microsoft's work to strengthen cybersecurity protection* (2024). <https://blogs.microsoft.com/on-the-issues/2024/06/13/microsofts-work-to-strengthen-cybersecurity-protection/>
1335. U.S. House Committee on Homeland Security — *A Cascade of Security Failures: Assessing Microsoft Corporation's Cybersecurity Shortfalls and the Implications for Homeland Security* (2024). <https://homeland.house.gov/hearing/a-cascade-of-security-failures-assessing-microsoft-corporations-cybersecurity-shortfalls-and-the-implications-for-homeland-security/>
1336. Microsoft Security Response Center — *Microsoft Actions Following Attack by Nation State Actor Midnight Blizzard (archive)* (2024). [https://web.archive.org/web/2024/https://msrc.microsoft.com/blog/2024/01/microsoft-actions-following-attack-by-nation-state-actor-midnight-blizzard](https://web.archive.org/web/2024/https://msrc.microsoft.com/blog/2024/01/microsoft-actions-following-attack-by-nation-state-actor-midnight-blizzard)
1337. Microsoft Security Response Center — *Update on Microsoft Actions Following Attack by Nation State Actor Midnight Blizzard (archive)* (2024). [https://web.archive.org/web/2024/https://msrc.microsoft.com/blog/2024/03/update-on-microsoft-actions-following-attack-by-nation-state-actor-midnight-blizzard](https://web.archive.org/web/2024/https://msrc.microsoft.com/blog/2024/03/update-on-microsoft-actions-following-attack-by-nation-state-actor-midnight-blizzard)
1338. Brad Smith — *A new world of security: Microsoft's Secure Future Initiative* (2023). <https://blogs.microsoft.com/on-the-issues/2023/11/02/secure-future-initiative-sfi-cybersecurity-cyberattacks/>
1339. Charlie Bell — *Security above all else -- expanding Microsoft's Secure Future Initiative* (2024). <https://www.microsoft.com/en-us/security/blog/2024/05/03/security-above-all-else-expanding-microsofts-secure-future-initiative/>
1340. Microsoft — *Securing our future: September 2024 progress update on Microsoft's Secure Future Initiative* (2024). <https://www.microsoft.com/en-us/security/blog/2024/09/23/securing-our-future-september-2024-progress-update-on-microsofts-secure-future-initiative-sfi/>
1341. Microsoft — *Azure Key Vault Managed HSM Overview* (2024). <https://learn.microsoft.com/en-us/azure/key-vault/managed-hsm/overview>
1342. Microsoft — *Azure Integrated HSM Overview* (2024). <https://learn.microsoft.com/en-us/azure/security/fundamentals/azure-integrated-hardware-security-module-overview>
1343. Microsoft — *Securing our future: April 2025 progress report on Microsoft's Secure Future Initiative* (2025). <https://www.microsoft.com/en-us/security/blog/2025/04/21/securing-our-future-april-2025-progress-report-on-microsofts-secure-future-initiative/>
1344. The Hacker News — *Microsoft Secures MSA Signing with Azure Confidential VMs After Storm-0558 Breach* (2025). <https://thehackernews.com/2025/04/microsoft-secures-msa-signing-with.html>
1345. Google Cloud — *Cloud HSM* (2024). <https://cloud.google.com/kms/docs/hsm>
1346. Amazon Web Services — *Rotating AWS KMS keys* (2024). <https://docs.aws.amazon.com/kms/latest/developerguide/rotate-keys.html>
1347. Google Workspace — *Maintain SAML certificates* (2024). <https://knowledge.workspace.google.com/admin/apps/maintain-saml-certificates>
1348. Google — *Tink cryptographic library* (2024). <https://developers.google.com/tink>
1349. Amazon Web Services — *AWS Security Bulletins* (2024). <https://aws.amazon.com/security/security-bulletins/>
1350. Google Cloud — *Google Cloud Security Bulletins* (2024). <https://cloud.google.com/support/bulletins>
1351. Cloudflare — *How Cloudflare mitigated yet another Okta compromise* (2023). <https://blog.cloudflare.com/how-cloudflare-mitigated-yet-another-okta-compromise/>
1352. Shafi Goldwasser, Silvio Micali, Ronald L. Rivest — *A Digital Signature Scheme Secure Against Adaptive Chosen-Message Attacks* (1988). DOI: 10.1137/0217017. <https://people.csail.mit.edu/silvio/Selected%20Scientific%20Papers/Digital%20Signatures/A_Digital_Signature_Scheme_Secure_Against_Adaptive_Chosen-Message_Attack.pdf>
1353. Dan Boneh, Victor Shoup — *A Graduate Course in Applied Cryptography (Chapter 13: Digital Signatures, EUF-CMA security definition)* (2023). <https://toc.cryptobook.us/>
1354. Chelsea Komlo, Ian Goldberg — *FROST: Flexible Round-Optimized Schnorr Threshold Signatures (Selected Areas in Cryptography, SAC 2020, LNCS 12804)* (2021). <https://link.springer.com/chapter/10.1007/978-3-030-81652-0_2>
1355. D. Connolly, C. Komlo, I. Goldberg, C. A. Wood — *RFC 9591: The Flexible Round-Optimized Schnorr Threshold (FROST) Protocol for Two-Round Schnorr Signatures* (2024). <https://datatracker.ietf.org/doc/rfc9591/>
1356. Yehuda Lindell, Ariel Nof — *Fast Secure Multiparty ECDSA with Practical Distributed Key Generation and Applications to Cryptocurrency Custody (ACM CCS 2018)* (2018). <https://cris.technion.ac.il/en/publications/fast-secure-multiparty-ecdsa-with-practical-distributed-key-gener/>
1357. Jack Doerner, Yashvanth Kondi, Eysa Lee, abhi shelat — *DKLs: Threshold ECDSA Signing Schemes (project landing page, including DKLs23 Threshold ECDSA in Three Rounds)* (2023). <https://dkls.info/>
1358. B. Laurie, A. Langley, E. Kasper — *RFC 6962: Certificate Transparency* (2013). <https://www.rfc-editor.org/rfc/rfc6962.html>
1359. Nat Sakimura, John Bradley, Michael B. Jones, Edmund Jay — *OpenID Connect Discovery 1.0 (final, errata set 2)* (2023). <https://openid.net/specs/openid-connect-discovery-1_0.html>
1360. MITRE — *Forge Web Credentials (T1606)* (2024). <https://attack.mitre.org/techniques/T1606/>
1361. MITRE — *Forge Web Credentials: SAML Tokens (T1606.002)* (2024). <https://attack.mitre.org/techniques/T1606/002/>
1362. Benjamin Delpy — *mimikatz: Kerberos module wiki* (2014). [https://github.com/gentilkiwi/mimikatz/wiki/module-~-kerberos](https://github.com/gentilkiwi/mimikatz/wiki/module-~-kerberos)
1363. CrowdStrike — *Golden Ticket Attack* (2024). <https://www.crowdstrike.com/en-us/cybersecurity-101/cyberattacks/golden-ticket-attack/>
1364. CyberArk — *Golden SAML Revisited: The Solorigate Connection* (2020). <https://www.cyberark.com/resources/threat-research-blog/golden-saml-revisited-the-solorigate-connection>
1365. Microsoft Security Response Center — *Results of Major Technical Investigations for Storm-0558 Key Acquisition (archived)* (2024). [https://web.archive.org/web/2024/https://msrc.microsoft.com/blog/2023/09/results-of-major-technical-investigations-for-storm-0558-key-acquisition](https://web.archive.org/web/2024/https://msrc.microsoft.com/blog/2023/09/results-of-major-technical-investigations-for-storm-0558-key-acquisition)
1366. Y. Sheffer, D. Hardt, M. Jones — *RFC 8725: JSON Web Token Best Current Practices (canonical HTML rendering)* (2020). <https://www.rfc-editor.org/rfc/rfc8725.html>
1367. CISA, FBI — *AA23-193A Joint Cybersecurity Advisory (PDF)* (2023). <https://www.cisa.gov/sites/default/files/2023-07/aa23-193a_joint_csa_enhanced_monitoring_to_detect_apt_activity_targeting_outlook_online_2.pdf>
1368. Ron Wyden — *Wyden letter to CISA, DOJ, FTC re: 2023 Microsoft Breach (PDF)* (2023). <https://www.wyden.senate.gov/imo/media/doc/wyden_letter_to_cisa_doj_ftc_re_2023_microsoft_breach.pdf>
1369. Brad Smith — *Written Testimony of Brad Smith, House Committee on Homeland Security (PDF)* (2024). <https://homeland.house.gov/wp-content/uploads/2024/06/2024-06-13-HRG-Testimony-Smith.pdf>
1370. NIST — *FIPS 140-3: Security Requirements for Cryptographic Modules* (2019). <https://csrc.nist.gov/pubs/fips/140-3/final>
1371. Amazon Web Services — *AWS CloudHSM* (2024). <https://aws.amazon.com/cloudhsm/>
1372. Amazon Web Services — *Security in AWS IAM Identity Center* (2024). <https://docs.aws.amazon.com/singlesignon/latest/userguide/security.html>
1373. Amazon Web Services — *AWS Nitro Enclaves: concepts* (2024). <https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave-concepts.html>
1374. Amazon Web Services — *The Security Design of the AWS Nitro System* (2024). <https://docs.aws.amazon.com/whitepapers/latest/security-design-of-aws-nitro-system/security-design-of-aws-nitro-system.html>
1375. Amazon Web Services — *aws-jwt-verify (Node library)* (2024). [https://github.com/awslabs/aws-jwt-verify](https://github.com/awslabs/aws-jwt-verify)
1376. Amazon Web Services — *Verifying a JSON Web Token (Amazon Cognito)* (2024). <https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-tokens-verifying-a-jwt.html>
1377. Okta Security — *Unauthorized Access to Okta's Support Case Management System: Root Cause and Remediation* (2023). <https://sec.okta.com/articles/2023/11/unauthorized-access-oktas-support-case-management-system-root-cause>
1378. Okta Security — *October Security Incident: Recommended Actions* (2023). <https://sec.okta.com/october-security-incident-recommended-actions>
1379. Cloud Security Alliance — *Cloud Controls Matrix and CAIQ* (2024). <https://cloudsecurityalliance.org/research/cloud-controls-matrix/>
1380. FedRAMP — *FedRAMP Marketplace* (2024). <https://www.fedramp.gov/>
