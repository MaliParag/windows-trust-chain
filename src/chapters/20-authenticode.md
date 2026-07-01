# Authenticode and Catalog Files

::: trust-ledger

- **Inherits:** A signature-verified chain to a trusted root. Secure Boot already refused any boot image whose Authenticode hash or signing certificate was not in `db` (Chapter 1, Secure Boot); the TPM supplied the non-exportable, hardware-held asymmetric keys and the RSA/SHA primitives that key-custody model rests on (Chapter 2, The TPM); and Attestation made X.509 chain-to-a-trusted-root validation a load-bearing operation (Chapter 5, Attestation). Authenticode is that same CMS/PKCS#7 signature scheme, generalized from the firmware gate to *every* PE the operating system is asked to run.
- **Promise:** When Windows reports a binary as signed, catalog-covered, WHQL-approved, or allowed by App Control, it has cryptographically proven that a private key chaining to a currently-trusted root produced (or, through a catalog, vouched for) the PE's Authenticode digest under Microsoft's hashing rules, or the matching catalog member hash, at a timestamped moment. Serviced boundary: kernel-mode driver loading (KMCS), which Microsoft commits to defending with a security update; the user-mode "Verified publisher" string and SmartScreen verdicts are advisory, not serviced boundaries.
- **TCB:** The CMS/ASN.1 parser and Authenticode-hash recomputation in `wintrust.dll!WinVerifyTrust` and `ci.dll`; the PE hash algorithm's exclusions, section ordering, and certificate-table omission; the certificate-chain builder plus the trusted-root set (legacy KMCS chains include the `Microsoft Code Verification Root`; Windows 10 1607+ Secure Boot driver loads use the Microsoft Root Authority anchors named in the verifier section; user-mode loads use the system Trusted Root store); the `CatRoot` catalog store and the `CryptSvc` member-hash index; the RFC 3161 TSA chain and the `genTime` comparison, and, outside Microsoft's control, the private-key custody of every CA and signer in the trusted set.
- **Adversary → Break:** Signatures prove *who*, never *what*. A stolen leaf key signs a malicious driver (Stuxnet/Realtek, 2010); a sub-CA forged through an MD5 chosen-prefix collision is treated as Microsoft-origin (Flame, 2012); a compromised legitimate signer ships a trojaned update (ShadowHammer, 2019; the Bitwarden CLI npm hijack, 2026); a parser ambiguity lets appended bytes ride inside the certificate table (CVE-2013-3900); a disconnected endpoint trusts a stale `CatRoot`/blocklist; a compromised TSA antedates a token. The Promise ends at "a key-holder touched this hash at this claimed time."
- **Residual:** Runtime enforcement of these verdicts (the driver-load gate and HVCI page-hash checking at fault time) → owned by Code Integrity (Chapter 8, Code Integrity); the administrator-authored allow/deny policy language that consumes these primitives → owned by App Control (Chapter 13, AppLocker vs App Control for Business); protecting the signing and verifying processes from tampering → Protected Process Light (Chapter 10) and Process Mitigation Policies (Chapter 11); signing-key custody and stolen-key blast radius → The TPM (Chapter 2) and Credential Guard (Chapter 15); the whole-chain "provenance ≠ safety" failure → the Storm-0558 finale (Chapter 29).
- **Bequeaths:** A verified provenance-and-integrity verdict (signer identity, built chain, Authenticode hash, and signing time) handed to the next link, App Control for Business (Chapter 13), which evaluates it against administrator-authored allow and deny rules, and consumed at runtime by Code Integrity (Chapter 8), which enforces it at driver load and HVCI page-fault time. Does NOT provide: any guarantee the signed code is *safe*, fresh revocation on a disconnected endpoint, or immunity to a stolen key or a forged sub-CA.
- **Proof:** 🔵 documented. `signtool verify /v /pa /all`, `Get-AuthenticodeSignature`, `certutil -CatDB`, and `New-CIPolicyRule` reproduce the field-by-field walk at the point of claim; no hash-verified lab capture exists (the traces below are reference format and vary by servicing level).
:::

> **Evidence labels.** 🔵 means documented/reproducible from public sources or local commands; 🟡 means emulated; 🟢 means captured from this book's lab with hash-stamped artifacts.

> **The Reasoner's question.** When Windows says a binary is signed, catalog-covered, WHQL-approved, or allowed by App Control, what cryptographic fact has actually been proven, and what remains unproven?

---

> **Foundations. What you need before this chapter.**
>
> - **PE / COFF image.** The executable file format Windows loads for `.exe`, `.dll`, and `.sys` files. Authenticode stores embedded signatures in a PE data directory, but those bytes are not mapped as executable image pages. The certificate-table layout is dissected in full below; this chapter owns it.
> - **CMS / PKCS#7 `SignedData`.** The ASN.1 envelope that carries signer information, certificates, signed attributes, unsigned attributes, and signature bytes. Authenticode is a Microsoft profile of this envelope, not a wholly separate cryptosystem.
> - **X.509 chain.** A leaf code-signing certificate chains through one or more intermediate certificates to a trusted root. Different Windows consumers accept different roots and different enhanced key usages; the Attestation chapter (Chapter 5) owns chain-to-a-trusted-root validation as a primitive.
> - **Signed-code vocabulary.** The one-line definitions of *Authenticode*, *catalog file*, and *WDAC / App Control* live in the Foundations chapter; this chapter supplies the byte-level mechanism beneath them.

---

## The Reasoner’s question

Many Windows code-identity decisions (UAC's publisher display, App Control for Business, and kernel-mode driver loading) bottom out on the same PKCS#7 / CMS `SignedData` envelope that Microsoft shipped with Internet Explorer 3 in August 1996. SmartScreen also consults signature and certificate reputation, but it is a broader reputation service rather than a pure Authenticode verifier. This chapter dissects the envelope byte by byte: the `WIN_CERTIFICATE` record inside the PE certificate table, the `SpcIndirectDataContent` attribute that signs a hash rather than a file (which is what makes catalog signing and per-page hashing possible), the RFC 3161 timestamp tokens that keep 2010 signatures verifying in 2026, and the `Microsoft Code Verification Root` kernel chain. We follow the named incidents that drove every post-2010 retrenchment (Stuxnet, Flame, CVE-2013-3900, ShadowHammer, the 2022 Vulnerable Driver Blocklist, the 2026 Bitwarden CLI npm hijack) and finish at the App Control rule levels (`Publisher`, `FilePublisher`, `WHQL`) that finally surface those primitives to administrators as policy.

## The verified-publisher question

On 17 June 2010, Sergey Ulasen and his colleagues at VirusBlokAda in Minsk began circulating a sample of a worm that would, a month later, be named Stuxnet [511]. Two of its kernel-mode components, `mrxcls.sys` and `mrxnet.sys`, were signed properly, by an Authenticode-conformant certificate issued to Realtek Semiconductor Corp.; weeks later a further Stuxnet driver surfaced under a JMicron Technology Corp. certificate [511][512]. The Windows kernel loaded them because the certificate chains validated. The chains validated because, cryptographically, nothing was wrong.

That sentence is the lens for everything in this chapter. Microsoft's code-identity system did its job exactly as designed, and a piece of state-grade sabotage walked through it. What follows reconstructs what the kernel checks before loading a driver, why those checks could not have caught Stuxnet, and what Microsoft layered on top during the next fourteen years so that the next stolen Realtek private key has less reach.

## Where Authenticode shows up

Most Windows users meet Authenticode without realising it. The User Account Control dialog that says "Verified publisher: Microsoft Windows" instead of "Publisher: Unknown" is the user-visible end of a long cryptographic chain that bottoms out in a PKCS#7 / CMS `SignedData` envelope wrapped inside a `WIN_CERTIFICATE` record at the end of the PE file [513][28]. The same signature facts are consumed directly by App Control for Business (the 2024 rename of Windows Defender Application Control) [514], by `ci.dll` at kernel-driver load [267], and by Windows Update during servicing; SmartScreen uses them as one reputation input among URL, download, telemetry, and known-good/known-bad signals [515][516]. The Authenticode bytes are shared; the verdicts differ in which fields each consumer consults and which policy it overlays.

**Walkthrough: one signature, four consumers.** Start with one PE file on disk. The optional header's security directory points to one `WIN_CERTIFICATE`; that record wraps one CMS `SignedData`; the `SignedData` identifies one signer, one chain, one Authenticode hash, and usually one RFC 3161 timestamp. UAC asks only a display question: can the chain be built well enough to print a verified publisher instead of `Unknown`? SmartScreen asks a reputation question: has this downloaded file, URL, app, or signing certificate accumulated enough benign history to avoid a warning [515]? App Control asks an administrator-policy question: does this signer, file name, version, hash, WHQL EKU, or catalog signer match an allow rule and avoid all deny rules [517]? `ci.dll` asks a kernel-integrity question: may this image be loaded into ring 0, and under HVCI can its pages be checked again at fault time [267][518]? The bytes are shared; the questions are not.

> **Key idea.** Windows code-identity consumers repeatedly query the same small set of structures inside the PE certificate table. Once you can read those structures, you can predict the cryptographic facts that UAC, App Control, and kernel-mode Code Integrity will receive: while remembering that SmartScreen adds a separate reputation layer.

Stuxnet's kernel components loaded because the chain validated. The chain validated because, cryptographically, nothing was wrong. To understand why that sentence is true (and what Microsoft has done in the fourteen years since to keep the next stolen Realtek certificate from getting as far), we have to start in August 1996.

## 1996: PKCS#7, ActiveX, and the original sin of downloadable code

Counterintuitively, Authenticode was not invented to sign Windows binaries. It was invented to sign downloadable web payloads.

On 7 August 1996, Microsoft and VeriSign jointly announced what their press release called "the first technology for secure downloading of software over the Internet" [519]. The release introduces Authenticode as a feature of Internet Explorer 3 beta 2, names Hank Vigil ("general manager of the electronic commerce group at Microsoft") and Stratton Sclavos ("president and CEO" of VeriSign), and explicitly anchors the design in *open* standards: "Authenticode and VeriSign's Digital ID service support Internet standards, including the X.509 certificate format and PKCS #7 signature blocks" [519].

The original motivating problem was ActiveX. An ActiveX control was a downloadable COM binary that the browser would load in-process; without a signature, the browser had no idea who built it. The April 1996 W3C submission that preceded Authenticode is described in the press release as a "code-signing proposal supported by more than 40 companies" [519] (The 40+ company W3C signatory list is the institutional fact that made third-party CA participation possible from day one and seeded the modern multi-vendor code-signing economy. None of the architectural decisions that followed (catalog signing, RFC 3161 timestamping, EV certificates) would have been viable inside a single-vendor PKI.). Anchoring the design in X.509 and PKCS#7 instead of inventing a Microsoft-only signature format is the choice that made everything afterwards possible.

## PKCS#7 was already there

By 1996, the *envelope* part of the design was solved. RSA Laboratories had published PKCS #7 v1.5 in November 1993 as part of the Public-Key Cryptography Standards series [520]; in March 1998 the IETF republished it verbatim as RFC 2315, "Cryptographic Message Syntax Version 1.5," authored by Burt Kaliski [520]. The same envelope evolved further: the IETF rebranded it as Cryptographic Message Syntax (CMS) and shipped progressively richer versions through RFCs 2630 (1999), 3369 (2002), 3852 (2004), and 5652 (2009) [521]. Modern Authenticode parsers consume the CMS dialect, but the on-disk envelope structure has barely moved in thirty years.

> **PKCS#7 SignedData.** The ASN.1 envelope: originally PKCS#7 v1.5 (Kaliski, 1993; republished as RFC 2315 in 1998), now generalized as CMS in RFC 5652. That carries the signature, signed and unsigned attributes, and the chain of X.509 certificates inside the Authenticode certificate-table entry [521].

Authenticode is, in one sentence, *"PKCS#7 SignedData carrying a Microsoft-defined content type that hashes the PE file in a specific repeatable way"* [518]. The asymmetric signature inside that envelope is typically RSA, the public-key system Rivest, Shamir, and Adleman published in 1978 [522], built on the Diffie-Hellman digital-signature concept introduced in 1976 [523]. None of that primitive cryptography has changed since. Everything that has changed sits *around* the envelope: the algorithms it carries, the catalog store that lets Microsoft sign tens of thousands of files at once, the timestamp tokens that pin a signing moment in time.

**Walkthrough: the lineage from primitive to PE bytes.** The stack is not a Microsoft-only invention that begins in 1996. Diffie and Hellman supply the public-key-signature idea in 1976 [523]. RSA supplies the practical signature primitive in 1978 [522]. PKCS#7 supplies the signed envelope in 1993, later standardized as CMS [520][521]. Authenticode then adds only the Windows-specific layer: a Microsoft OID for `SpcIndirectDataContent`, a PE-image data object OID, the PE-specific image-hash algorithm, and the rule that the DER envelope is stored as `bCertificate[]` inside a `WIN_CERTIFICATE`. When a verifier succeeds, it is not saying that Authenticode invented a new cryptosystem; it is saying that this old CMS envelope contains Microsoft's PE-specific digest in exactly the place Windows expects it.

## From one click to four trust decisions

The original UX of Authenticode in IE 3 was a *modal trust prompt*. The user saw a dialog ("Do you want to install and run [name] signed and distributed by [publisher]?") and clicked Yes or No. The signature was checked once, and that was the entire trust decision. By 2026, the same `SignedData` envelope feeds at least four entirely different trust subsystems (UAC, SmartScreen, App Control for Business, kernel-mode code integrity) and most of the time the user clicks nothing at all.

That layering is what the rest of this chapter is about. Thirty years on, the on-disk bytes have barely changed. The certificate table at the end of every signed Windows binary still carries a PKCS#7 SignedData envelope, and at the head of that envelope is the same content type (`SpcIndirectDataContent`) Microsoft defined in 1996. What *has* changed is everything around it: the algorithms inside the envelope, the catalog store, the timestamp tokens, the WDAC policy layer on top. Let's open the envelope and look.

## Anatomy on disk: WIN_CERTIFICATE, PKCS#7 SignedData, SpcIndirectDataContent

Where does the signature actually live in a signed `.exe`? Most engineers can guess "the end of the file." Fewer can name the data directory entry, fewer still the wrapper structure, and almost nobody volunteers the exact ASN.1 content type. Four nesting levels matter. Walk them in order and the whole rest of the architecture starts making sense.

## Level 1: the PE certificate table

The PE optional header carries a `DataDirectory[16]` array. Entry index 4, `IMAGE_DIRECTORY_ENTRY_SECURITY`, points at the *certificate table*: an offset and size into the file [28]. Unlike every other data directory entry, the certificate table is the only one whose offset is a *file* offset, not a relative virtual address; the certificate table is never mapped into memory at load time.

Inside that offset+size region is a sequence of `WIN_CERTIFICATE` records.

For Authenticode-signed Windows binaries, `wCertificateType == WIN_CERT_TYPE_PKCS_SIGNED_DATA` (constant value `0x0002`), and `bCertificate[]` is a DER-encoded CMS / PKCS#7 SignedData blob [518]. Multiple `WIN_CERTIFICATE` records in the certificate table are legal but uncommon. The usual way a single binary carries both a SHA-1 (legacy) and a SHA-256 (modern) signature is the distinct *nested-signature* mechanism: one `WIN_CERTIFICATE` whose primary CMS `SignedData` holds the secondary signature inside its `unsignedAttrs` (`szOID_NESTED_SIGNATURE`, via `signtool /as`).

> **WIN_CERTIFICATE.** The PE certificate-table record (`dwLength`, `wRevision`, `wCertificateType`, `bCertificate[]`) that wraps a single attribute certificate inside a PE. For Authenticode signatures, `wCertificateType` is `WIN_CERT_TYPE_PKCS_SIGNED_DATA` and `bCertificate` holds a DER-encoded CMS / PKCS#7 SignedData blob [518][28].

## Level 2: The CMS SignedData envelope

Decoding `bCertificate` produces an ASN.1 SEQUENCE describing a CMS `ContentInfo` whose content type is `signedData` (OID `1.2.840.113549.1.7.2`). Inside that is the `SignedData` structure proper [521]:

- `version`: an integer, typically 1 or 3.
- `digestAlgorithms`. The set of hash algorithms used by any signer (commonly `sha256`).
- `encapContentInfo`: the content the signers are signing over. *This is the field that matters.*
- `certificates`: the X.509 chain certificates needed to validate the signers.
- `crls`: optional, almost never populated inline.
- `signerInfos`: one or more `SignerInfo` structures, each with the actual signature bytes plus signed and unsigned attributes.

Each `SignerInfo` carries the signing certificate identifier, a set of `signedAttrs` (whose digest is what gets signed), an `encryptedDigest` (the actual signature bytes), and a set of `unsignedAttrs`. The single most important unsigned attribute, in practice, is the RFC 3161 `TimeStampToken`: the counter-signature that pegs the signing event to a moment in time. We will come back to that when we discuss RFC 3161 timestamping.

## Level 3: SpcIndirectDataContent

The `encapContentInfo.eContentType` for Authenticode is `1.3.6.1.4.1.311.2.1.4`: the OID Microsoft registered for `SpcIndirectDataContent`. Inside, the `eContent` is a Microsoft-specific ASN.1 structure [518]:

```asn1
SpcIndirectDataContent ::= SEQUENCE {
    data        SpcAttributeTypeAndOptionalValue,
    messageDigest DigestInfo
}

SpcAttributeTypeAndOptionalValue ::= SEQUENCE {
    type   OBJECT IDENTIFIER,   -- 1.3.6.1.4.1.311.2.1.15 for PE images
    value  [0] EXPLICIT ANY DEFINED BY type OPTIONAL
}

DigestInfo ::= SEQUENCE {
    digestAlgorithm AlgorithmIdentifier,
    digest          OCTET STRING
}
```

For a PE binary, `data.type` is `1.3.6.1.4.1.311.2.1.15` (`SPC_PE_IMAGE_DATAOBJ`) and `data.value` carries a `SpcPeImageData` structure (signing flags plus an optional `SpcLink`); the PE's architecture and type come from the PE headers, not this ASN.1 value. The `messageDigest.digest` is the **Authenticode hash** of the PE file [518]. That hash is *not* SHA-256 over the file bytes.

> **SpcIndirectDataContent.** Microsoft's `eContentType` registered under OID `1.3.6.1.4.1.311.2.1.4`. Its `messageDigest` field holds the Authenticode hash of the signed artifact, and its `data` field describes what kind of artifact it is (PE image, MSI, script). The fact that this structure signs *a hash* rather than a file is what makes catalog signing possible [518].

## Level 4: the Authenticode hash and its PE-specific omissions

The Authenticode hash is not a raw file hash and not a blanket "hash everything except padding" rule. Microsoft's PE Authenticode algorithm skips two fields in the optional header, hashes sections in file-offset order using each section's `SizeOfRawData`, omits the Attribute Certificate Table itself, and then hashes qualifying remaining file data outside that certificate table [518]. The practical rules are:

| Hash rule | Why it exists | Spec reference |
|---|---|---|
| Skip `OptionalHeader.CheckSum` (4 bytes). | The OS and signing tools may recompute the checksum; signing over it would make the act of servicing mutate the signed digest. | `Authenticode_PE.docx` "Calculating the PE Image Hash" steps 3-4 [518] |
| Skip `DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY]` (8 bytes). | The certificate-table pointer and size change when a signature is appended; signing over them would be a chicken-and-egg loop. | `Authenticode_PE.docx` steps 5-7 [518] |
| Hash non-empty sections sorted by `PointerToRawData`, using `SizeOfRawData`. | The digest follows the on-disk section layout, not RVA order. Raw section padding inside `SizeOfRawData` is included; zero-raw-data sections are not. | `Authenticode_PE.docx` steps 8-13 [518] |
| Omit the Attribute Certificate Table bytes, then hash remaining file data outside that table. | The signature cannot sign itself, but ordinary overlay or gap data is not automatically ignored merely because it is outside a section. | `Authenticode_PE.docx` steps 14-15 [518] |

> **Authenticode hash.** The PE digest computed by Microsoft's Authenticode image-hash algorithm: skip the optional-header `CheckSum`, skip the `IMAGE_DIRECTORY_ENTRY_SECURITY` entry, hash sections in raw-file order by `SizeOfRawData`, omit the Attribute Certificate Table itself, and hash qualifying remaining data outside that table. Because the certificate-table area is omitted, the same digest remains valid after the signature is appended [518].

The exclusion of the certificate-table bytes is the design move that makes the whole architecture work. The Authenticode hash is computed *first*, signed, and then the signature is appended into the very region the hash excluded. After appending, the hash is still valid; verifying recomputes the digest with the same PE-specific algorithm and compares. (ASN.1 DER's tag-length-value shape means that, given enough patience, you can decode every level of the certificate table with nothing but a hex dump. This accessibility is also why parser bugs are particularly damaging: a verifier that accepts unauthenticated bytes inside the certificate-table region can be tricked into trusting an object whose executable image hash still verifies while downstream tooling or installers consume attacker-controlled appended data: the structural failure mode at the bottom of CVE-2013-3900 [489].)

## A separate, smaller hash per 4 KiB page

Authenticode supports an optional signed attribute, `SpcPeImagePageHashes2`, with OID `1.3.6.1.4.1.311.2.3.2` (SHA-256). It carries a sequence of `(RVA, hash)` pairs, one hash per 4 KiB page of the PE image [518]. The older `1.3.6.1.4.1.311.2.3.1` SHA-1 variant is effectively deprecated. Under Hypervisor-Protected Code Integrity (HVCI), the page hashes are validated at demand-fault time: when the OS faults in a page from disk, HVCI hashes the page and compares it to the signed page-hash entry before mapping the page as executable. Whole-file integrity checking at load is *not* the same as runtime integrity checking at fault; page hashes are what closes that gap. This chapter owns the *signed attribute* that carries those hashes; the runtime *check* (how `ci.dll` and the secure kernel re-hash a page at fault time and refuse to map a mismatch as executable) is owned by the Code Integrity chapter (Chapter 8). (ARM64 Windows configurations have used 4 KiB native pages on the systems that ship Authenticode page-hash enforcement to date. The page-hash attribute encodes RVAs into the on-disk image, so any future move to 16 KiB or 64 KiB page granularity would require a corresponding spec revision.)

> **Page hash (SpcPeImagePageHashes2).** An optional signed attribute (OID `1.3.6.1.4.1.311.2.3.2` for SHA-256) carrying a sequence of `(RVA, SHA-256)` pairs, one per 4 KiB page of the PE image. The hashes are checked at demand-fault time by HVCI / Code Integrity, not just at load time [518].

## The whole nest, in one picture

![Figure: The four nesting levels of an Authenticode signature on disk. The optional header points by file offset (not an RVA) at a WIN_CERTIFICATE, which wraps a CMS SignedData, whose SpcIndirectDataContent carries the one signed value, the Authenticode hash. the optional page-hash signed attribute and the RFC 3161 timestamp hang off the SignerInfo, and the three PE regions excluded from the hash are shaded.](diagrams/20-authenticode-signature-nest.svg)

**Walkthrough: opening the nest by hand.** If you open a signed PE in a hex viewer, do not start at the last byte; start at the optional header. Read `DataDirectory[4]`, remembering that this one directory is a file offset, not an RVA [28]. Jump there and parse `dwLength`, `wRevision`, and `wCertificateType`. If the type is `0x0002`, treat the following bytes as DER and decode a CMS `ContentInfo` whose type is `signedData` [521]. Inside `SignedData`, find `encapContentInfo` and require Microsoft's `SpcIndirectDataContent` OID. Inside that content, find `messageDigest`: this is the Authenticode hash after the three PE exclusions, not the ordinary file hash. Then move sideways to the `SignerInfo`: the signed attributes are what the asymmetric signature covers, the optional page-hash attribute supplies HVCI's per-page checks, and the unsigned attributes carry the RFC 3161 timestamp. Every later Windows trust decision is a different walk over this same nest.

## Try it yourself

**Decode a PE certificate table.**

```python
# Decode the four nesting levels of an Authenticode signature.
# Requires: pip install pefile asn1crypto
import pefile
from asn1crypto import cms

PE_PATH = r"C:\\Windows\\System32\\notepad.exe"  # any signed PE

pe = pefile.PE(PE_PATH, fast_load=True)
pe.parse_data_directories(
    directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']])

cert_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]
if cert_dir.VirtualAddress == 0:
    print("No certificate table -- file is unsigned (or catalog-signed elsewhere).")
else:
    raw = pe.__data__[cert_dir.VirtualAddress: cert_dir.VirtualAddress + cert_dir.Size]
    # WIN_CERTIFICATE header: dwLength(4) wRevision(2) wCertificateType(2)
    import struct
    dw_length, w_revision, w_cert_type = struct.unpack("<IHH", raw[:8])
    pkcs7_blob = raw[8: dw_length]
    print(f"WIN_CERTIFICATE: dwLength={dw_length} wRevision=0x{w_revision:04x} wCertificateType=0x{w_cert_type:04x}")

    info = cms.ContentInfo.load(pkcs7_blob)
    signed_data = info["content"]
    encap = signed_data["encap_content_info"]
    print(f"eContentType: {encap['content_type'].native}")  # expect SpcIndirectDataContent OID 1.3.6.1.4.1.311.2.1.4

    # Authenticode SpcIndirectDataContent is not a standard CMS payload, so
    # asn1crypto returns it as raw bytes -- decode the messageDigest by hand.
    inner = encap["content"].parsed if encap["content"].native else encap["content"].contents
    print(f"Inner bytes (first 32 hex): {bytes(inner)[:32].hex()}")
```

We can now describe, byte for byte, what a signed PE looks like. The on-disk shape is precise enough that a parser flaw in `WinVerifyTrust` (the one that became CVE-2013-3900 in December 2013 [489][524]) could let an attacker append bytes inside the certificate-table region without invalidating the signature, because the verifier happily skipped over them. To understand why such a flaw exists, why Microsoft still has not made the fix default-on twelve years later, and why no fewer than four named incidents drove the kernel-mode signing regime toward its current shape, we have to walk the evolution generation by generation.

## Six generations of Windows code signing

![Figure: Six generations of Windows code signing as accreting strata, not a replacement sequence. The 1996 embedded signature is the foundation at the bottom; each later generation (catalogs, the KMCS kernel anchor, hash agility and the strict parser, portal counter-signing, and App Control plus the Vulnerable Driver Blocklist) adds a layer and removes nothing, so a 2026 driver load traverses all six. Stuxnet, Flame, and CVE-2013-3900 are pinned to the generation they provoked; every break carried a cryptographically valid signature.](diagrams/20-authenticode-generations.svg)

Each generation solved a real problem in the previous one. None of them is dead. Catalog signing, introduced as Gen 2, is still load-bearing on every modern Windows install for driver packages and inbox files; embedded Authenticode, the Gen 1 idea, is still how every commercial ISV ships a binary. The generations are *layers*, not replacements.

**Walkthrough: six layers, not six replacements.** The timeline is cumulative. Gen 1 gives ISVs embedded signatures: one file, one `WIN_CERTIFICATE`. Gen 2 adds catalogs: one signed `.cat`, many member hashes, endpoint storage in `CatRoot`, and `CryptSvc` lookup. Gen 3 narrows kernel-mode loading on x64 by requiring a chain to a Microsoft-trusted kernel anchor. Gen 4 responds to Stuxnet, Flame, and CVE-2013-3900 with hash agility and an opt-in strict parser. Gen 5 moves new kernel-driver signing through Hardware Developer Center, where Microsoft counter-signs attestation or WHQL submissions. Gen 6 adds administrator-authored App Control rules, HVCI page hashes, and the Vulnerable Driver Blocklist. A 2026 driver load can traverse all six layers: embedded signature if present, catalog fallback if not, kernel chain, timestamp, strict-parser option, page hashes, WDAC, and VDB.

## Gen 1 (1996-1999): per-file embedded Authenticode

The original design. Each ISV holds its own private key, signs each binary as it ships, the signature lives inside the PE certificate table. The IE 3 trust prompt is the only consumer. It works. It does not scale to operating-system inbox files. Microsoft cannot hold every IHV's private key (the IHV would have to mail its source binary to Redmond to be signed) and an IHV cannot sign Microsoft's own binaries (Microsoft will not surrender its private key). Worse, the spec property "single-byte change invalidates the signature" [525] means that even a corrected misspelling in an INF file would break the signature on the driver package the INF is paired with. Embedded Authenticode is the right answer for an ISV that ships a single product; it is the wrong answer for an OS that ships tens of thousands of files.

## Gen 2 (1999-2005): catalog files and the CatRoot store

The conceptual breakthrough is to sign a *list of hashes*, not a file: the verbatim Microsoft Learn definition of a catalog file is quoted below [525][526]. The OS installs the `.cat` to `%SystemRoot%\System32\CatRoot\{GUID}\` [525], indexes the member hashes via the `CryptSvc` service, and when `WinVerifyTrust` is asked to validate a PE without an embedded signature it computes the Authenticode hash and asks the catalog database whether any installed catalog covers that hash [513]. Starting with Windows 2000, INF files use a single `CatalogFile` directive that lets the same package install identically on every Windows version it supports [525].

Catalogs fix scale: Microsoft signs one `.cat`, that catalog covers thousands of driver-package files, and any one-byte INF correction rebuilds the catalog without touching the per-file signatures. They do not yet fix kernel-mode trust on 32-bit Windows, where unsigned drivers still load.

## Gen 3 (2005-2010): Kernel-mode code signing on x64

PatchGuard (Kernel Patch Protection) shipped first on x64 Windows Server 2003 SP1 to prevent runtime patching of kernel structures. With x64 Windows Vista, Microsoft made kernel-mode driver loading conditional on a valid Authenticode signature chaining to the `Microsoft Code Verification Root`: the first Windows client release to enforce KMCS at load. The Microsoft Learn KMCS policy page is explicit that the regime applies to Windows Vista and later [267]. Cross-signing (a third-party CA's intermediate cross-signed by a Microsoft anchor) let independent driver vendors continue shipping without Microsoft holding their keys [267]. KMCS works exactly as intended on x64. Then someone steals a private key.

On 17 June 2010, the first Stuxnet samples, carrying `mrxcls.sys` and `mrxnet.sys` signed by a legitimately issued Realtek Semiconductor Corp. certificate, are uncovered [511]; weeks later a further Stuxnet driver surfaced signed by a JMicron Technology Corp. certificate. VeriSign revokes the Realtek certificate on 16 July 2010 per the Symantec dossier [511]. Two years later, Flame is publicly disclosed; Microsoft Security Advisory 2718704 follows on 3 June 2012 and describes the unauthorized Microsoft certificates used by the malware [527]. The Flame authors forged a Microsoft-issued sub-CA, the `Microsoft Enforced Licensing Intermediate PCA`, by mounting an MD5 chosen-prefix collision [528][527]. Microsoft's advisory revoked the two intermediate certificates and the matching SHA-1 RA certificate within days of disclosure [527]. The cryptanalytic precedent for the Flame work was the December 2008 rogue-CA result by Alexander Sotirov, Marc Stevens, Jacob Appelbaum, Arjen Lenstra, David Molnar, Dag Arne Osvik, and Benne de Weger: presented as "MD5 considered harmful today: Creating a rogue CA certificate" at 25C3 in Berlin [529], later published as the Crypto 2009 best paper "Short Chosen-Prefix Collisions for MD5 and the Creation of a Rogue CA Certificate." (The rogue-CA cryptanalysis is sometimes mis-cited as Eurocrypt 2009. The correct venue is Crypto 2009 (Santa Barbara), where the paper won the best-paper award. The original disclosure was the December 2008 25C3 talk. Stevens later used the same forensic technique to identify the Flame collision in his Crypto 2013 paper *Counter-Cryptanalysis* [528].)

The composite lesson of Gen 3 is uncomfortable: validating the chain does not protect against a stolen private key, and it does not protect against a forged sub-CA certificate either. The signature was, in both cases, cryptographically valid.

## Gen 4 (2010-2015): hash agility and CVE-2013-3900

Microsoft moved Authenticode away from collision-broken hashes such as MD5 and toward SHA-2-family digests for code-signing and time-stamping use [530]. On 10 December 2013, MS13-098 patched CVE-2013-3900, a parser flaw in `WinVerifyTrust` that let an attacker append additional bytes inside the certificate-table region without invalidating the signature [524]. The patch added a *stricter* parser that rejected the appended-data form. Microsoft did *not* enable the stricter parser by default.

> **Quoted source.** Microsoft does not plan to enforce the stricter verification behavior as a default functionality on supported releases of Microsoft Windows.: NVD, CVE-2013-3900 [489]

The reasoning, as preserved verbatim in the NVD republication, is application compatibility: legitimate installers shipped binaries that had small amounts of extra data appended inside the certificate-table area, and breaking those installers en masse would have been a customer-visible regression. The opt-in registry setting (`HKLM\Software\Microsoft\Cryptography\Wintrust\Config\EnableCertPaddingCheck=1`, with a matching `Wow6432Node` sibling) has been available on every supported Windows release since December 2013. CISA added CVE-2013-3900 to the Known Exploited Vulnerabilities catalog on 10 January 2022 with a federal due date of 10 July 2022 [489]. As of this writing, the strict-parser behavior is still opt-in.

> **EnableCertPaddingCheck.** Hardened Windows environments should set both the native and `Wow6432Node` `Wintrust\Config` registry values to `1` (REG_DWORD); the exact commands appear in the practical guide below. The CISA KEV entry for CVE-2013-3900 [489] makes this a federal-government remediation requirement. The application-compatibility risk that kept Microsoft from making it default-on is real, but hardened baselines usually choose the stricter parser.
>
> **Aside: Why Microsoft never made the CVE-2013-3900 fix default-on.** The patch ships in supported Windows builds [489], but the strict-parser code path remains opt-in. The reason is application compatibility: some legitimate installers historically carried legacy bytes in the certificate-table region, and turning strict parsing on globally would refuse to verify them. CISA's KEV listing (with the 10 July 2022 federal due date) is the strongest public push to flip the setting; hardened environments should treat the registry key as effectively mandatory.

EV (Extended Validation) code signing requirements emerged during the Gen 4-Gen 5 transition. The CA/Browser Forum approved the initial *Minimum Requirements for the Issuance and Management of Publicly-Trusted Code Signing Certificates* on 22 September 2016, with effective force from 1 February 2017 [531]. (The CSBR is commonly cited with a 2017 publication date. The correct framing is that the v1.0 baseline was approved on 22 September 2016 and became effective on 1 February 2017; the v1.1 update in the PKI Consortium mirror dates from the same approval cycle. The current CSBR is v3.8, dated 5 August 2024 [532], with the EV code-signing requirements imported from the older EV Guidelines [532][533].) Historically, EV was the first widely deployed public code-signing tier where the signing key had to live in hardware rather than on a developer's disk; today that hardware boundary can be a local token, an HSM, or a managed/cloud signing service that keeps the private key non-exportable. Microsoft has also changed the operational meaning of EV in its Trusted Root Program: starting February 2024 it says it no longer accepts or recognizes EV Code Signing Certificates and treats code-signing certificates equally [530]. The durable lesson is key custody, not the EV label itself: hardware-backed, non-exportable keys move the Stuxnet-style "stolen private key" problem out of the ordinary filesystem and into a smaller custody surface: the same model the TPM chapter (Chapter 2) established for platform keys.

## Gen 5 (2015-2021): Hardware Developer Center portal signing

On **29 July 2015**, Microsoft closed cross-signing for new kernel-mode end-entity certificates. The KMCS policy page is verbatim: *"Cross-signed drivers are still permitted if any of the following are true:... Drivers was signed with an end-entity certificate issued prior to July 29th 2015 that chains to a supported cross-signed CA"* [267]. Practically, new kernel drivers now have to go through the Hardware Developer Center: either attestation signing (an EV-cert-signed driver that Microsoft counter-signs, valid for in-house and OEM-channel distribution [534]) or full Windows Hardware Quality Labs (WHQL) signing (HLK-tested, publishable on Windows Update, valid on Vista and later [535]). Attestation-signed drivers cannot be published to Windows Update for retail audiences [535]. That lever is reserved for WHQL.

By July 2021, most cross-certificates had expired, and the deprecation page is exact: *"Most cross-certificates expired in July 2021. You can't use code-signing certificates that chain with expired cross-certificates to create new kernel mode digital signatures for any version of Windows"* [536]. Cross-signing for new signatures is fully closed.

## Gen 6 (2017-present): App Control for Business, page hashes, the VDB

In 2017 Microsoft introduced the Windows Defender Application Control name for the configurable code integrity feature it had first shipped with Windows 10 in 2015 (originally under Device Guard) [537], renamed again to App Control for Business in 2024 [514]. The policy language defines rule levels over hashes, publishers, file names, versions, certificates, and WHQL status [517]; we look at the full catalog in the App Control policy section. The Vulnerable Driver Blocklist (VDB), seeded in 2019 and shipped as a default-on supplemental deny policy from the Windows 11 2022 Update onward, denies a curated set of known-vulnerable signed kernel drivers [271]. The VDB is automatically enforced whenever memory integrity (HVCI), Smart App Control, or S Mode is active (except on Windows Server 2016) [271]; the blocklist is updated quarterly. Microsoft launched the Vulnerable and Malicious Driver Reporting Center in December 2021 to formalize the intake side of the VDB pipeline [378].

Gen 6 does not invent a new envelope. It treats the existing Authenticode primitives as inputs to a policy engine. The "trust" decision is no longer a single yes/no derived from the certificate chain; it is a composite of cryptographic verdicts and administrator-authored rules. Even so, every named incident continues to fit the same pattern. Operation ShadowHammer (publicly disclosed 25 March 2019) compromised the ASUS Live Update mechanism, distributing trojanised updaters signed with legitimate ASUSTeK certificates: "over 57,000 Kaspersky users" downloaded them, hosted on `liveupdate01s.asus[.]com` and `liveupdate01.asus[.]com` [538]. The signature was valid; the binary was malicious. Seven years later, on 22 April 2026, a malicious version of `@bitwarden/cli@2026.4.0` was briefly distributed through npm between 5:57 PM and 7:30 PM Eastern Time as part of the broader Checkmarx supply-chain campaign [539][540][541]. StepSecurity's analysis calls this *"the first confirmed supply chain attack where npm's OIDC Trusted Publishing was used to publish a compromised package"* [541]. The signature path is different from a PE Authenticode signature (npm uses its own OIDC-based attestation) but the lower bound is identical to Stuxnet, fourteen years earlier. *Provenance does not imply safety.*

| Approach | Year | Idea | Status |
|---|---|---|---|
| Per-binary embedded Authenticode | 1996 | One signature per file, in the certificate table | Active (every commercial ISV) |
| Catalog (.cat) signing | 1999-2000 | Sign a list of hashes; OS-managed `CatRoot` store | Active (every modern Windows for driver packages and inbox files) |
| KMCS + cross-signing | 2006-2007 | Mandatory chain to `Microsoft Code Verification Root` on x64 (Vista RTM Nov 2006, GA Jan 2007) | Cross-signing closed for new certs (29 Jul 2015); KMCS still active |
| RFC 3161 timestamping | 2001 | Counter-signature pinning signing time | Optional but strongly recommended; applied with SignTool `/tr` (RFC 3161) or `/t` (legacy) |
| Hash agility (MD5 → SHA-256) | 2012-2015 | Replace collision-broken hash algorithm | Active; SHA-256 universal |
| EnableCertPaddingCheck (CVE-2013-3900 strict parser) | 2013 | Reject appended bytes in certificate-table region | Opt-in; CISA KEV-listed since 10 Jan 2022 |
| Hardware Developer Center portal signing | 2015 | Microsoft counter-signs every new kernel driver | Active; cross-signing fully retired by July 2021 |
| WHQL / HLK signing | 2007-present | Driver passes HLK, publishable on Windows Update | Active (recommended retail path) |
| Attestation signing | 2015-present | EV-cert + Microsoft counter-signature; not publishable on WU retail | Active (in-house, OEM channel) |
| Vulnerable Driver Blocklist | 2019-present (default-on 2022) | Deny known-vulnerable signed drivers | Default-on with HVCI / Smart App Control / S Mode; quarterly cadence |
| App Control for Business (WDAC) | 2015-present | Engine shipped as configurable code integrity / Device Guard (2015); renamed Windows Defender Application Control (2017); rebranded App Control for Business (2024). Administrator-authored allow/deny rules over Authenticode primitives. | Active; current production policy language |

Six generations is a lot of layering for what is, at the bottom, the same PKCS#7 SignedData envelope from 1996. The one moment in this lineage that genuinely *changed* something is small enough to fit in one sentence: the realisation that `SpcIndirectDataContent` signs a hash, not a file. That single observation produced catalog signing (and, via counter-signing the signature itself, RFC 3161 timestamping). Both of them are why Windows code identity scaled and survived to 2026.

## The two decoupling insights: catalog signing and RFC 3161 timestamping

Both insights are instances of the same move: *the signature is not where you think it is.* Once you internalise that, the rest of the architecture stops being a sequence of incremental crypto choices and starts being a sequence of policy choices on top of a small set of primitives.

## Insight A: catalog signing decouples the hash from the file

Recall from the on-disk anatomy that `SpcIndirectDataContent` carries a `messageDigest` (a hash) and a small descriptor of what was hashed. *Nothing in that envelope says the hash must come from one specific file.* Catalog signing exploits exactly that. Operationally, a `.cat` is a signed catalog whose member entries bind hashes to attributes: Microsoft Learn describes the catalog as a collection of file thumbprints [525], and the WinTrust catalog API exposes the corresponding "calculate the hash for a file" operation through `CryptCATAdminCalcHashFromFileHandle` [542]. The implementation details are catalog-format-specific; the invariant this chapter relies on is narrower and documented: the catalog signer vouches for a member hash, not for an embedded PE certificate table.

Microsoft Learn's verbatim definition is again exact:

> **Quoted source.** A digitally signed catalog file (.cat) can be used as a digital signature for an arbitrary collection of files. A catalog file contains a collection of cryptographic hashes, or thumbprints. Each thumbprint corresponds to a file that is included in the collection.: Microsoft Learn, *Catalog Files and Digital Signatures* [525]

When a catalog is installed on disk, the OS drops it into `%SystemRoot%\System32\CatRoot\{GUID}\` (with staging in `CatRoot2`) [525]. The `CryptSvc` service maintains the catalog database (effectively an index from `memberHash -> catalogFile`) and answers lookups from `WinVerifyTrust`. When a PE without an embedded signature reaches the verifier, the verifier computes the file's Authenticode hash and asks `CryptSvc` whether any installed catalog contains that hash. If yes, the catalog signer becomes the effective signer for the file [513].

> **Catalog file (.cat).** A signed catalog containing file thumbprints/member hashes plus attributes; a single catalog signature covers the list. Catalog files act as detached signatures for an arbitrary set of binaries: any file whose catalog hash appears in the list is treated as if it carried the catalog signer's embedded signature [525][513][542].
>
> **CatRoot / CryptSvc.** The on-endpoint catalog store at `%SystemRoot%\System32\CatRoot\{GUID}\` (with staging in `CatRoot2`) and the Windows service that indexes installed catalog member hashes so `WinVerifyTrust` can answer "is this Authenticode hash covered by any installed catalog?" [525].

Catalog signing makes three workflows possible that embedded signing alone cannot:

1. **WHQL signing at OS scale.** Microsoft signs a single `.cat` covering every Windows inbox file in a build; updates to those files arrive as new catalogs without re-signing each binary.
2. **Trust refresh through Windows Update.** Adding new trust without touching any binary. Microsoft just ships another catalog, and the on-endpoint `CryptSvc` extends its index.
3. **Catalog-signing unsigned line-of-business apps.** Enterprises with internally built apps that lack their own code-signing infrastructure can use the Package Inspector workflow (*"you can create catalog files for existing apps without requiring access to the original source code or needing any expensive repackaging"* [543]) to wrap a `.cat` around the installed binary set and pass App Control rule evaluation without modifying the executable itself.

**Walkthrough: detached signing as an operating-system workflow.** A driver vendor builds a package containing `.sys`, `.inf`, and support files. The package produces a catalog: a signed object whose payload is a set of member hashes and attributes, not a PE image [525][526][542]. The vendor submits the package through Hardware Developer Center; Microsoft validates the submission and, for attestation or WHQL, counter-signs the catalog [534][535]. Delivery can then happen through Windows Update, an OEM channel, or the vendor's own installer. At install time, Windows copies the `.cat` into a GUID-named `CatRoot` database and `CryptSvc` indexes the member hashes. Later, when `ci.dll` sees an unsigned-on-disk driver, it computes the driver's Authenticode or catalog hash, asks the catalog database for that hash, and treats the catalog's signer as the effective signer if a trusted catalog contains it. The file did not need to mutate; the trust statement moved into a signed inventory.

## Insight B: RFC 3161 timestamping decouples the signature lifetime from the certificate's validity

Every X.509 end-entity code-signing certificate has a finite validity window: usually one to three years. Without something extra, a signature would stop verifying the moment the signing certificate expired. That is operationally unacceptable: Microsoft has been shipping Windows binaries since 1996 and cannot reissue every certificate every time something old gets re-installed. RFC 3161 [544] is the answer.

The relevant paragraph from the RFC, verbatim:

> **Quoted source.** The TSA's role is to time-stamp a datum to establish evidence indicating that a datum existed before a particular time. This can then be used, for example, to verify that a digital signature was applied to a message before the corresponding certificate was revoked thus allowing a revoked public key certificate to be used for verifying signatures created prior to the time of revocation.: RFC 3161 §1 [544]

Operationally: the signer hashes the original `SignerInfo.encryptedDigest`, sends that hash to a Trusted Time-Stamping Authority (TSA), and the TSA returns a `TimeStampToken` (itself a CMS `SignedData`) whose signed content (`TSTInfo`) binds the hash of the original signature to a trusted `genTime`. The signer attaches the token as an *unsigned* attribute on the original `SignerInfo` under Microsoft's `szOID_RFC3161_counterSign` (OID `1.3.6.1.4.1.311.3.3.1`). Later verifiers can recover `genTime` from the token, confirm the TSA's signature chains to a trusted root, and decide: was the signing certificate valid *at* `genTime`? Expiry is the easy case: a timestamp inside the certificate's validity window lets the signature survive ordinary certificate expiry. Revocation is policy-dependent: callers differ on whether they check revocation, whether they can reach CRL/OCSP material, whether they honor signatures made before the revocation time, and whether the revocation reason is treated as retroactive compromise rather than ordinary retirement.

> **Trusted Time-Stamping Authority (TSA).** An RFC 3161 service that, given a hash of a signature, returns a CMS-wrapped `TimeStampToken` countersigning the hash with a trusted signing time (`genTime`). The token is attached as an unsigned attribute on the original `SignerInfo`. The TSA's role is to make the signing event verifiable in time even after the signing certificate expires [544].

**Walkthrough: timestamping as a second signature over the first signature.** The signer first computes the Authenticode hash and produces the normal `SignerInfo` signature. Then the signing tool hashes the signature value and sends that imprint to a Time-Stamping Authority under RFC 3161 [544]. The TSA returns a CMS `TimeStampToken` whose signed attributes include the imprint and `genTime`. Authenticode stores that token in `unsignedAttrs` because it is not part of the original signer's signed attribute set; it is a countersignature made by a different key. Years later, the verifier validates two chains: the code-signing chain for the original signer and the TSA chain for the token. The decisive question is temporal: was the code-signing leaf certificate valid at `genTime`? If yes, the signature can remain valid after the leaf expires. If no token exists, the verifier has no durable proof that the signature was made before expiry.

## The unifying observation

Both moves untie something that was previously tied:

- Catalog signing unties the *signature* from a specific file's bytes.
- RFC 3161 unties the *signing event* from the issuing certificate's validity window.

After these two decouplings, signing at scale and signing for longevity both become tractable, and everything later in the Windows code-signing stack is a policy layer operating on top.

> **Key idea.** Two decouplings, catalog signing untying the signature from a specific file, and RFC 3161 timestamping untying the signature from the end-entity certificate's validity window, are what made Windows code identity scale to OS-sized binaries and survive across decades. Every later layer (KMCS, WDAC, the Vulnerable Driver Blocklist, HVCI) presumes these two primitives are already in place.

Once you can sign a hash instead of a file, and once you can pin a signing event to a moment in time that outlives the certificate, the rest of the architecture stops being a sequence of crypto choices and starts being a sequence of *policy* choices: which roots do we trust for ring 0, which file-publisher tuples does this enterprise authorize, which drivers does Microsoft deny by hash? To see those policy choices in operation, watch a single `WinVerifyTrust` call end to end.

## A modern WinVerifyTrust call, end to end

![Figure: A conceptual union of modern WinVerifyTrust / ci.dll checks in ten gates. The cryptographic checks read the certificate table, decode SignedData, confirm SpcIndirectDataContent, recompute the Authenticode hash, preserve page hashes for HVCI, build the chain to a trusted root, fall back to a catalog when appropriate, and validate the RFC 3161 timestamp. Policy checks then apply App Control plus the Vulnerable Driver Blocklist, while the opt-in EnableCertPaddingCheck strict parser affects certificate-table parsing. Real callers may change order, flags, and revocation behavior.](diagrams/20-authenticode-verify-pipeline.svg)

A user double-clicks a Microsoft-signed `.exe` on Windows 11 24H2. HVCI is on, Smart App Control is on, an enterprise App Control policy is loaded. The shell calls `ShellExecute`. Before the OS hands control to the new process, user-mode `WinVerifyTrust`, catalog APIs, SmartScreen, App Control, and the kernel's code-integrity stack (`ci.dll`) may all consume overlapping signature facts. The following ten stages are a conceptual union of those consumers, not a literal call stack: caller flags, kernel-versus-user mode, revocation settings, catalog availability, and active WDAC/UMCI policy can change the exact order and scope.

## Stage 1: read the certificate table

`ci.dll` reads the optional header, finds `DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY]`, walks the certificate-table region, and enumerates the `WIN_CERTIFICATE` records. Dual signing is carried as a nested signature (`szOID_NESTED_SIGNATURE`) inside the primary signature's `unsignedAttrs` rather than as separate top-level records (for example a SHA-256 primary with a SHA-1 nested signature for older Windows 7 verifiers); the verifier selects the strongest signature its policy allows [518][28].

## Stage 2: decode the SignedData

For each candidate record with `wCertificateType == WIN_CERT_TYPE_PKCS_SIGNED_DATA`, the verifier DER-decodes `bCertificate` into a CMS `ContentInfo`, then into a `SignedData` structure [521]. The verifier reads `signerInfos`, picks the signer (usually one), and extracts the signed and unsigned attributes.

## Stage 3: verify the content type

The verifier confirms `encapContentInfo.eContentType == 1.3.6.1.4.1.311.2.1.4` (`SpcIndirectDataContent`), then decodes the inner structure and confirms `data.type == 1.3.6.1.4.1.311.2.1.15` (`SPC_PE_IMAGE_DATAOBJ`) [518]. The inner `messageDigest` is the Authenticode hash this signature claims to cover; the `digestAlgorithm` says how it was computed.

## Stage 4: recompute the Authenticode hash

The verifier re-reads the PE file bytes, applies the Authenticode image-hash algorithm (skip `CheckSum`, skip the SECURITY data-directory entry, hash raw sections in file-offset order, omit the Attribute Certificate Table, and hash qualifying remaining data), and compares the result to `SpcIndirectDataContent.messageDigest` [518]. If they differ, the signature is rejected.

## Stage 5: validate page hashes under HVCI

If `SpcPeImagePageHashes2` is attached and the running policy includes HVCI, the page-hash table is preserved across the verification call and consulted later by the secure kernel at demand-fault time [518]. The full-file Authenticode hash check is *necessary* but not *sufficient* for runtime integrity; pages on disk can be tampered after load by a kernel-level attacker who bypasses file-system protections. Page hashes are what closes that gap by re-checking each page at the moment it is mapped executable.

## Stage 6: build the chain

The verifier collects the `certificates` SET from the `SignedData`, plus any AIA-fetched certificates needed to complete the chain, and tries to terminate the path at a trusted root. For kernel-mode loads, the legacy anchor is the `Microsoft Code Verification Root`; for portal-signed drivers, the chain may instead terminate at one of the Microsoft Root Authority anchors. The KMCS policy page describes the Windows 10 1607+ kernel-mode anchors verbatim: *"Microsoft Root Authority 2010, Microsoft Root Certificate Authority, Microsoft Root Authority"* with Secure Boot on [267]. For user-mode loads, the chain may terminate at any root in the system Trusted Root store; the enterprise's App Control policy narrows the trust further by referencing specific anchors at the RootCertificate / PcaCertificate rule level [517].

> **WinVerifyTrust.** The CryptoAPI function (`wintrust.dll!WinVerifyTrust`) that performs a trust verification action on a specified object and dispatches to the appropriate trust provider [545]. In the Authenticode case, callers commonly use it around certificate-table parsing, SignedData decode, content-type checks, Authenticode-hash recomputation, chain building, catalog fallback, and timestamp validation. It returns a success or specific error code; the caller interprets the result against its own policy.
>
> **Code Integrity / ci.dll.** The Windows kernel-mode component that enforces the Kernel-Mode Code Signing policy on driver loads (Vista x64 and later [267]) and, under HVCI, evaluates page hashes at fault time. `ci.dll` is the kernel-side caller of `WinVerifyTrust` semantics for driver loads.
>
> **Microsoft Code Verification Root.** The historical kernel-mode trust anchor whose name appears in Microsoft's KMCS documentation and whose intermediates cross-signed third-party code-signing CAs for pre-July-2015 drivers [267]. Microsoft Learn does not publish a single canonical page with the root's SHA-1 / SHA-256 thumbprint, validity dates, or issuance year; in practice the thumbprint is read by running `certutil -store` on a recent Windows system.

 (The Microsoft Code Verification Root metadata absence is real: although the root is named in the KMCS policy document [267], no Microsoft Learn URL publishes its thumbprint or validity dates on a stable page. Practitioners should reference the root by name in policy and treat the actual thumbprint as something to be enumerated via `certutil -store` on the running system rather than copy-pasted from a published document.)

## Stage 7: catalog fallback for unsigned PEs

If the PE has no embedded signature, the verifier computes the Authenticode hash and queries `CryptSvc`: is this hash a member of any installed catalog under `%SystemRoot%\System32\CatRoot\`? If yes, the verifier uses the catalog's signer as the effective signer for the PE [525][513]. Cross-system files installed by Windows Update (most drivers, most inbox executables) take this path.

## Stage 8: validate the RFC 3161 timestamp

If the unsigned attributes carry an RFC 3161 token (`szOID_RFC3161_counterSign`, OID `1.3.6.1.4.1.311.3.3.1`), the verifier decodes it, validates the TSA's chain, extracts `genTime`, and confirms the signing certificate was valid at `genTime` [544]. This is how a 2010 signature still verifies in 2026: not because the 2010 certificate is still valid, but because a TSA attested at signing time that the signature existed when the certificate was valid.

## Stage 9: App Control policy evaluation

With cryptographic verdicts in hand, the App Control policy engine evaluates the file against the active policy: does any allow rule match, does any deny rule match, including the default-on Vulnerable Driver Blocklist supplemental deny [271]? The matching rule (by Hash, FileName, Publisher, FilePublisher, WHQL, WHQLPublisher, WHQLFilePublisher, LeafCertificate, PcaCertificate, or RootCertificate level [517]) decides the final outcome. Audit-mode hits produce event ID 3076; enforcement-mode blocks produce event ID 3077 [546].

## Stage 10: legacy parser hardening, if opted in

A hardened environment will also have `EnableCertPaddingCheck=1` set [489], enabling the strict parser that rejects the CVE-2013-3900 appended-data form. This is not truly "last" in an implementation; it changes how the certificate table is parsed near the beginning of verification. It is listed here because it is an opt-in hardening switch over the same Authenticode parse. CISA added the CVE to its Known Exploited Vulnerabilities catalog on 10 January 2022 with a federal due date of 10 July 2022 [489]; environments subject to federal compliance regimes treat this as mandatory. The exact two registry writes appear in the practical guide below.

**Walkthrough: the WinVerifyTrust decision tree.** The conceptual flow begins with bytes, not policy. First parse the PE certificate table; if a `WIN_CERTIFICATE` exists, decode its CMS `SignedData`; if none exists, compute the catalog hash so catalog lookup has a key. For embedded signatures, require `SpcIndirectDataContent`, recompute the Authenticode hash with the PE-specific hashing algorithm, and reject on mismatch. Build the signer chain against the trust store appropriate to the caller: broad user-mode roots for a shell prompt, narrower Microsoft kernel anchors for driver load, or whatever an App Control rule later references. If the file was unsigned on disk, query `CryptSvc` for a catalog member hash and transfer the catalog signer to the file. Decode any RFC 3161 token and evaluate signing time, preserve page hashes for HVCI, apply `EnableCertPaddingCheck` during parsing if the registry opts in, and then hand the cryptographic facts to App Control or SmartScreen. The cryptographic pipeline can succeed while policy still denies, and policy can allow only because the cryptographic pipeline succeeded.

> **Every consumer reads the same SignedData.** There is no separate certificate table per trust subsystem. UAC, SmartScreen, `ci.dll`, App Control, and the catalog-fallback path all read the *same* bytes inside the same `WIN_CERTIFICATE` record. What differs is which fields each consumer cares about and what policy each consumer overlays on top. Once you read the on-disk structures, every later trust decision is predictable.
>
> **Aside. What WinVerifyTrust does *not* check.** `WinVerifyTrust` does not execute the binary. It does not appraise behavior or reputation. That is SmartScreen's job, downstream. It does not verify runtime page integrity. HVCI does, in the secure kernel, at demand-fault time. It does not enforce the App Control policy: the policy engine does, downstream. It does not check OCSP unless the caller opts in; chain-revocation behavior is governed by `WinVerifyTrust` flags supplied by the caller. The function answers only the narrow cryptographic question: does the SignedData blob parse, does the recomputed hash match, does the chain build, and (if a token is attached) did the signing event happen inside the signing certificate's validity window?

When this pipeline finishes, the answer to "is this binary trusted?" is no longer a yes-or-no statement about cryptography. It is a *composite* of cryptographic verdicts (signature integrity, hash match, chain build, timestamp validity, page hashes) and *policy* verdicts (allowed by App Control, not on the blocklist). Authenticode supplies the inputs to a policy; App Control writes the policy. Let us look at the policy language.

## Verify it yourself (documented)

A strict proof beat has to do more than say "run SignTool." It has to pin each command to the invariant it proves, record concrete fields, and show the handoff from embedded signature to catalog signature to policy. The following is the reference trace format for a Windows 11 24H2 host with the Windows SDK installed. The exact hash values and package catalog names vary by servicing level; the relationships between fields do not.

<!--EVIDENCE-NEEDED: 🟢 hash-gated capture of `signtool verify /v /pa /all` on a live Windows 11 24H2 host would upgrade this 🔵 reference trace by pinning the chain, the Authenticode hash, and the RFC 3161 genTime to a real servicing level.-->

> 🔵 **REPRODUCIBLE TRACE**: Embedded Authenticode verification with Microsoft SignTool. Reproduce on a Windows host with: `signtool verify /v /pa /all "C:\Windows\System32\notepad.exe"` [359].

```text
Verifying: C:\Windows\System32\notepad.exe

Signature Index: 0 (Primary Signature)
Hash of file (sha256): 6B9B7E39B5E7B0F888A4C2F1B3C0E2D99F67A9282C61121A8F91654F2F45A81D

Signing Certificate Chain:
    Issued to: Microsoft Root Certificate Authority 2010
    Issued by: Microsoft Root Certificate Authority 2010
        Expires: 06/23/2035

    Issued to: Microsoft Windows Production PCA 2011
    Issued by: Microsoft Root Certificate Authority 2010
        Expires: 10/19/2026

    Issued to: Microsoft Windows
    Issued by: Microsoft Windows Production PCA 2011
        Expires: 09/18/2025

The signature is timestamped: Thu Jan 11 02:14:37 2024
Timestamp Verified by:
    Issued to: Microsoft Time-Stamp PCA 2010
    Issued to: Microsoft Time-Stamp Service

Successfully verified: C:\Windows\System32\notepad.exe
```

Read the transcript as a byte walk. `Hash of file (sha256)` is SignTool's label for the Authenticode hash, not the ordinary SHA-256 over all file bytes. It is the digest stored inside `SpcIndirectDataContent.messageDigest`; it excludes `CheckSum`, the security-directory pointer, and the certificate-table bytes [518]. The three signing-chain lines come from the CMS `certificates` SET plus any chain-completion material CryptoAPI obtains. The timestamp block is not signed by the Microsoft Windows leaf; it is the RFC 3161 token in `unsignedAttrs`, signed by the time-stamping service [544]. `/pa` selects the default Authenticode policy, and `/all` prevents a dual-signed file from hiding a weaker nested or legacy signature behind the strongest one.

The negative control is just as important. Run a normal file hash next to the Authenticode hash:

```text
certutil -hashfile C:\Windows\System32\notepad.exe SHA256
SHA256 hash of C:\Windows\System32\notepad.exe:
2F 3A 58 6E 0B 27 14 9C 22 6A D4 E7 2B A7 44 68 85 90 F0 9F 7B 9C C2 2B 85 24 91 19 47 54 10 91
CertUtil: -hashfile command completed successfully.
```

The `certutil -hashfile` value will differ from the SignTool Authenticode hash whenever an embedded signature is present, because `certutil -hashfile` includes the certificate table and Authenticode excludes it. That mismatch is the fastest live-machine proof that Authenticode signs a PE-specific digest, not the literal file blob.

> 🔵 **REPRODUCIBLE TRACE**: PowerShell exposes the same trust result and distinguishes embedded from catalog provenance. Reproduce: `Get-AuthenticodeSignature C:\Windows\System32\notepad.exe | Format-List Status,StatusMessage,SignatureType,SignerCertificate,TimeStamperCertificate,Path`.

```text
Status                  : Valid
StatusMessage           : Signature verified.
SignatureType           : Authenticode
Path                    : C:\Windows\System32\notepad.exe
SignerCertificate       : [Subject] CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US
TimeStamperCertificate  : [Subject] CN=Microsoft Time-Stamp Service, OU=Thales TSS ESN:3B34-4B55-19A1, O=Microsoft Corporation, C=US
```

`SignatureType: Authenticode` is the embedded path: the PE itself contains the `WIN_CERTIFICATE`. Now choose an inbox driver or protected system component that is catalog-signed on your servicing level and run the same command:

```text
Get-AuthenticodeSignature C:\Windows\System32\drivers\disk.sys | Format-List Status,SignatureType,SignerCertificate,Path

Status            : Valid
SignatureType     : Catalog
Path              : C:\Windows\System32\drivers\disk.sys
SignerCertificate : [Subject] CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US
```

The file may have no embedded `WIN_CERTIFICATE` at all. Windows computed the Authenticode hash, asked the catalog database for that member hash, and lifted the signer from the covering `.cat` file. The live invariant is: `SignatureType` changes from `Authenticode` to `Catalog`, but the policy engine still receives a signer identity, a chain, and a hash.

> 🔵 **REPRODUCIBLE TRACE**. Catalog-store lookup shows the detached signature. Reproduce by taking the Authenticode/catalog hash from SignTool or a catalog API such as `CryptCATAdminCalcHashFromFileHandle` (not the ordinary `certutil -hashfile` file digest) and searching the catalog database by name (not by CatRoot folder path): `certutil -CatDB -v -search 6B9B7E39B5E7B0F888A4C2F1B3C0E2D99F67A9282C61121A8F91654F2F45A81D` [525][359][542].

```text
Catalog:
  C:\Windows\System32\CatRoot\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}\
  Package_for_RollupFix~31bf3856ad364e35~amd64~~10.0.22621.3880.cat
Member tag: 6B9B7E39B5E7B0F888A4C2F1B3C0E2D99F67A9282C61121A8F91654F2F45A81D
Subject: CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, C=US
Hash: 6B9B7E39B5E7B0F888A4C2F1B3C0E2D99F67A9282C61121A8F91654F2F45A81D
```

That line is the detached-signature proof. The catalog is the signed object; the driver or component is a catalog member. A one-byte change to the member file changes the Authenticode hash, the catalog search misses, and `SignatureType` falls to `None` or `Status` becomes invalid depending on the caller.

> 🔵 **REPRODUCIBLE TRACE**: App Control rule generation proves that WDAC consumes Authenticode facts rather than creating new cryptography. Reproduce: `New-CIPolicyRule -FilePath "C:\Windows\System32\notepad.exe" -Level FilePublisher | Format-List *` [517].

```xml
<FileRule FriendlyName="Microsoft Windows notepad.exe" FileName="notepad.exe" MinimumFileVersion="10.0.22621.3880">
  <SignerRef RuleID="ID_SIGNER_MICROSOFT_WINDOWS" />
</FileRule>
<Signer Name="Microsoft Windows">
  <CertRoot Type="TBS" Value="3082010A0282010100C7A1B2C3D4E5F60718293A4B5C6D7E8F" />
  <CertPublisher Value="Microsoft Windows" />
</Signer>
```

The XML contains no signature bytes. It references the publisher and version metadata the previous steps proved: issuing chain, leaf publisher, `OriginalFileName`, and minimum version. In audit mode, a would-be deny appears as event ID 3076 in `Microsoft-Windows-CodeIntegrity/Operational`; in enforcement mode the corresponding block is event ID 3077 [546]. That is the final handoff: Authenticode proves identity and integrity, catalog lookup may supply the identity for unsigned-on-disk files, and WDAC decides whether the proved identity is authorized.

## App Control rule levels: Authenticode as policy input, not policy itself

App Control for Business is where the Authenticode primitives finally surface to administrators as policy. The `SignerInfo`, the subject CN of the leaf certificate, the file's `OriginalFileName` and `ProductVersion` from the version resource, the page-hash table, even the choice of catalog signer: all of them become inputs to a small rule language. The full AppLocker-versus-App-Control treatment (deployment models, the Microsoft Recommended Block Rules, signed policy plus HVCI, and the decision tree for choosing a level) is owned by the App Control for Business chapter (Chapter 13); here we look only at how each rule level reads an Authenticode field.

## Rule levels: what Authenticode field each level consults

The verbatim rule-level catalog from Microsoft Learn is [517]:

| Rule level | Authenticode field(s) consulted | Example use case |
|---|---|---|
| `Hash` | Authenticode hash of the file | Pinning a single binary by exact Authenticode digest; brittle across patches. |
| `FileName` | `OriginalFileName` from the PE version resource | Convenience for inbox files; not cryptographic. |
| `FilePath` | Filesystem path | UNC or absolute path; not cryptographic. Use sparingly. |
| `SignedVersion` | Publisher + `OriginalFileName` + version range | Allow a publisher's binary at a given version or higher. |
| `Publisher` | Issuing CA + leaf-cert subject CN | Allow anything signed by a given vendor under a given CA. |
| `FilePublisher` | Publisher + `OriginalFileName` + minimum `FileVersion` | Allow a specific binary from a specific vendor at min version. |
| `WHQL` | The Windows Hardware Quality Labs EKU | Allow any WHQL-signed driver. |
| `WHQLPublisher` | WHQL EKU + leaf-cert subject CN | Allow WHQL drivers from a specific OEM. |
| `WHQLFilePublisher` | WHQL EKU + `OriginalFileName` + min `FileVersion` | The strictest driver rule. |
| `LeafCertificate` | Leaf cert subject + issuer | Pin to a specific signing cert. |
| `PcaCertificate` | The PCA (intermediate) cert | Useful for "anything Microsoft-signed" without enumerating leaves. |
| `RootCertificate` | The root anchor | Broadest; usually too coarse. |

## Policy options

App Control policies are XML documents with a `<Rules>` section that toggles broad behavioral options [517]:

- **`0 Enabled:UMCI`**: *"App Control policies restrict both kernel-mode and user-mode binaries. By default, only kernel-mode binaries are restricted. Enabling this rule option validates user mode executables and scripts"* [517].
- **`2 Required:WHQL`**: *"By default, kernel drivers that aren't Windows Hardware Quality Labs (WHQL) signed are allowed to run. Enabling this rule requires that every driver is WHQL signed and removes legacy driver support"* [517].
- **`8 Required:EV Signers`**: documented but, per the same Microsoft Learn page, *"This option isn't currently supported."* (The Required:EV Signers option is in every published rule-options table but never makes it past parsing today. The EV requirement is enforced contractually via the Hardware Developer Center submission gate, not via the rule option. Treat it as documentation of intent rather than runtime enforcement.)

The Vulnerable Driver Blocklist is shipped as a *supplemental* deny policy that overlays the user's primary policy. From Windows 11 22H2 onward it is default-on and automatically enforced under HVCI, Smart App Control, or S Mode [271]. Updates arrive quarterly. The blocklist is deliberately conservative: Microsoft's own documentation acknowledges *"It's often necessary for us to hold back some blocks to avoid breaking existing functionality while we work with our partners who are engaging their users to update to patched versions"* [271].

> **App Control for Business (WDAC).** The post-2024 rename of Windows Defender Application Control [514]; a code-integrity policy language that consumes Authenticode primitives (chain, leaf-cert subject, `OriginalFileName`, version, WHQL EKU, page-hash table, embedded-vs-catalog provenance) as inputs to administrator-authored allow and deny rules.
>
> **FilePublisher rule.** An App Control rule level that allows or denies a binary if it is signed by a given Publisher (issuing CA + leaf-cert subject CN) **and** the PE's `OriginalFileName` matches **and** the PE's `FileVersion` is at or above a minimum. The tightest commonly used rule level; brittle across self-updating applications whose binaries change without warning [517][547].

## A worked example

Generating a FilePublisher rule for a Microsoft-signed binary on PowerShell:

```powershell
New-CIPolicyRule -FilePath "C:\Path\To\App.exe" -Level FilePublisher
```

produces a `<FileRule>` whose XML carries the issuing CA, the leaf-cert subject CN, the `OriginalFileName` from the version resource, and a `MinimumFileVersion` attribute. Every one of those fields is a direct read of the Authenticode `SignerInfo` and the PE version resource; nothing in the rule generation step talks to Microsoft. The administrator owns the rule.

> **Publisher vs FilePublisher.** Microsoft's own guidance is verbatim: *"Be aware of self-updating apps, as their app binaries may change without your knowledge"* [547]. FilePublisher rules pin a minimum version; if a self-updating app rolls out a build with a different `OriginalFileName` casing, or with `ProductVersion` changes that some packagers reuse as `FileVersion`, the rule silently stops matching. For self-updating apps, prefer `Publisher` (CA + subject CN only) and accept the looser blast radius.

 (Operational tip: audit-mode hits write event ID 3076 to the *Microsoft-Windows-CodeIntegrity/Operational* channel, enforcement-mode blocks write event ID 3077 [546]. Stage every policy in audit mode for at least one full patch cycle before flipping to enforcement; the 3076 stream is your inventory of what the rules would have denied.)

WDAC's vocabulary makes one structural choice explicit that the chapter has been implicit about until now: trust is *administrator-authored*, not *vendor-authored*. The cryptographic identity is supplied by the same Authenticode primitives we just dissected; the policy is whatever the organization writes. Before we look at the limits of what this stack can prove, one quick detour into how other operating systems have approached the same problem.

## Catalog-vs-embedded across operating systems

Windows is unusual in two specific ways: it stores detached catalogs on the endpoint, and it refreshes those catalogs through the operating-system servicing channel. That combination is not the only way to bind code to identity, and the comparison is easy to overstate. The table below compares only the *signature carrier* and freshness model, not the whole application-identity stack.

| System | Signature carrier | Detached catalog analog? | Freshness / transparency caveat | Longevity mechanism |
|---|---|---|---|---|
| Windows (Authenticode) | PKCS#7 / CMS `SignedData` inside `WIN_CERTIFICATE`, or a signed `.cat` whose member hashes cover files [525][513] | Yes. `.cat` files live in `CatRoot`; `CryptSvc` indexes member Authenticode hashes. | Offline endpoints see only the catalogs and VDB supplemental policies already delivered by Windows Update. No public transparency log records every issued catalog. | RFC 3161 token in `unsignedAttrs` proves signing time [544]. |
| macOS | Apple code signature embedded in the Mach-O bundle plus notarization ticket stapled to the app or fetched online [548] | Not in the Windows sense. A notarization ticket attests Apple's automated service accepted a submitted artifact, but it is not an endpoint database of arbitrary member hashes. | Gatekeeper can use a stapled ticket offline, but the trust model is Apple-service-centric: Developer ID, notarization, revocation, and XProtect/MRT are policy layers outside the signature bytes. | The notarization ticket gives Apple-service evidence; it is not a third-party RFC 3161 TSA model. |
| Linux IMA / EVM | Per-file extended-attribute signatures such as `security.ima` and metadata protection through EVM [549] | No central OS catalog. Appraisal is local-policy-driven against keys in kernel keyrings. | Coverage depends on distribution configuration, filesystem xattr preservation, measured/appraise mode, and which paths policy covers. Many Linux systems do not enforce IMA appraisal for arbitrary user applications. | Out of scope for a universal claim; policy and keyring state decide. |
| Android | APK Signature Scheme blocks inside the APK; v3 adds proof-of-rotation metadata [550] | No. The signed unit is the APK package, not an endpoint catalog covering unrelated files. | Freshness and revocation are mediated by platform policy, package manager state, and Play Protect for Google-distributed devices; sideloading changes the risk model. | v3 proof-of-rotation lets a publisher rotate signing keys without treating every update as a new identity. |
| sigstore / OCI | Detached signature and certificate material associated with an artifact in a registry; Fulcio issues short-lived certificates [551][552] | Closest analog structurally: detached signatures can cover blobs or images, but storage is registry/log based rather than CatRoot based. | Rekor supplies transparency [553], but offline verifiers need cached log inclusion material or must defer freshness. Registry availability becomes part of the operational model. | Short-lived certs plus log entries replace the long-lived code-signing-certificate + TSA pattern. |

The important difference is not "embedded" versus "detached" in the abstract. It is *who operates the freshness channel*. Windows makes the endpoint carry a local catalog database. That is excellent for offline driver installation and Windows servicing, but it creates the stale-CatRoot problem: a laptop that has missed three months of updates cannot know that a newer catalog or driver-block supplemental policy exists [271]. macOS moves more of the decision into Apple-operated services: Developer ID identifies the signer, notarization records Apple's automated acceptance, and Gatekeeper can consult or use a stapled ticket [548]. That reduces the need for a local list-of-hashes catalog but increases dependence on Apple's service and policy choices. Linux IMA/EVM is not a consumer-app reputation system at all; it is an integrity-appraisal framework that distributions and administrators may enable for selected paths. Android treats the APK as the signed unit and gives package identity continuity through key rotation rather than catalog membership. Sigstore externalises the detached signature into registry and transparency-log infrastructure: stronger public auditability than Authenticode timestamps, weaker offline autonomy unless inclusion proofs and signatures have already been cached [551][553][552].

So the shallow statement "Windows uses catalogs; everyone else embeds" is wrong. The better statement is: Windows is the mainstream desktop OS whose detached-signature database is local, service-refreshed, and directly consumed by the code-integrity path. Other systems split the same work among notarization services, package managers, kernel appraisal policies, registry signatures, and transparency logs. The cryptographic lower bound remains identical across all of them: the signature carrier proves provenance and integrity for bytes or hashes; it does not prove that the program is safe.

## What signatures cannot prove

Stuxnet did not break Authenticode. It walked through it. The same is true of Flame, of ShadowHammer, and of the Bitwarden CLI npm hijack. Every named incident on the modern Windows code-signing timeline is an instance of the same structural lower bound: signatures prove *who*, not *what*. The Windows code-identity stack has spent fourteen years adding layers that narrow the consequences of that bound. None of them eliminate it.

Four limits are worth naming explicitly.

## L1. Provenance is not safety

By Rice's theorem corollary, no decision procedure can determine arbitrary non-trivial semantic properties of a program. A signing system can therefore certify only "this binary came from a key-holder," never "this binary is benign." Stuxnet 2010 [511], Flame 2012 [528][527], Operation ShadowHammer 2019 [538], and the Bitwarden CLI npm hijack of 22 April 2026 [539][541][540] are four independent instances of the same gap, across four entirely different attack surfaces (stolen kernel-driver key; forged sub-CA via MD5 collision; compromised ASUS Live Update certificate; compromised npm OIDC trusted-publishing). The empirical scale is concrete: Kim, Kwon, and Dumitraș identified 325 signed malware samples, 189 of them carrying valid signatures produced by 111 compromised code-signing certificates, in their CCS 2017 paper [554].

The mathematics of Rice's theorem is succinct. Let $P$ be any non-trivial semantic property of programs (e.g. *is malicious*). For any algorithm $A$ that on input program $p$ outputs $A(p) \in \{\text{yes}, \text{no}\}$ claiming whether $p$ has property $P$, there exists a program $q$ where $A(q)$ is wrong. A signature scheme is not such an algorithm $A$ in the first place: it computes $\text{Sig}_{\text{sk}}(\text{hash}(p))$. The signature output has no semantic content about $p$'s behavior; it asserts only that the holder of $\text{sk}$ touched $\text{hash}(p)$.

## L2. CA cardinality and the weakest-link property

The trust graph for kernel-mode loads is narrow: a small number of Microsoft roots [267]. The trust graph for user-mode loads is the union of every root in the system Trusted Root store: a much larger set. *Any one* root, if compromised, degrades the entire user-mode code-identity trust graph; *any one* sub-CA, if forged, opens the kernel-mode path for the lifetime of the certificate. The Sotirov / Stevens / Appelbaum / Lenstra / Molnar / Osvik / de Weger rogue-CA work from December 2008 [529] demonstrated this dynamic for the web PKI; the same family of attack was then mounted in Flame in 2012 against the Microsoft Enforced Licensing Intermediate PCA [527]. The CSBR's EV-on-hardware requirements [532] reduce stolen-key risk at the leaf level, but a forged sub-CA bypasses the leaf entirely.

## L3. Catalog-store freshness on disconnected endpoints

A disconnected endpoint cannot freshness-check its `CatRoot`. The catalog database is whatever Windows Update last delivered. Which means freshly issued catalogs covering newly shipped inbox files cannot be trusted on machines that have been offline. The Vulnerable Driver Blocklist faces the same problem in reverse: a freshly blocked driver does not become *un*-trusted on a disconnected endpoint until the supplemental policy lands. Microsoft acknowledges this in the VDB documentation: *"It's often necessary for us to hold back some blocks to avoid breaking existing functionality"* [271]. The publication lag is deliberate, not accidental, and there is no in-band way for an endpoint to ask "is my VDB current?"

## L4. TSA centralization and antedating

RFC 3161 has no transparency log. A compromised TSA can issue countersignatures with arbitrary `genTime` undetectably, until and unless the TSA's root is revoked. Sigstore Rekor [553] is the canonical answer to this problem in the OSS world; nothing equivalent ships in the Authenticode stack. The consequence is asymmetric: a compromised TSA can antedate a signature backwards, making a freshly signed but recently malicious binary appear to have been signed before the malicious campaign began. Which on most verifiers means it will *still* verify even after the actual signing certificate is revoked.

**Walkthrough: reducing every bypass to the same floor.** Take any successful bypass and write down the exact fact the verifier accepted. Stuxnet accepted: Realtek's key signed these driver hashes before revocation [511]. Flame accepted: a Microsoft licensing intermediate, forged through an MD5 chosen-prefix collision, issued a chain Windows treated as Microsoft-origin [527][528]. ShadowHammer accepted: ASUS's update signer signed an updater that later delivered malicious behavior [538]. A stale offline endpoint accepts: this catalog or VDB is the newest policy it has ever received, not necessarily the newest one Microsoft has published [271]. A compromised TSA accepts: this timestamp token says the signature existed at `genTime`, with no public log proving the TSA did not antedate it [544][553]. The common floor is always narrower than users want: a key-holder, or someone who compromised the key hierarchy, touched a particular hash at a particular claimed time. Everything above that floor is policy and incident response.

> **Quoted source.** A valid signature proves only who signed the binary, never what the binary does.
>
> **Key idea.** Authenticode is the floor of Windows trust, not the ceiling. Every later layer (Kernel-Mode Code Signing, App Control for Business, the Vulnerable Driver Blocklist, HVCI page-hash enforcement) exists because the floor cannot, by construction, do more.
>
> **Aside: Aha moment: Stuxnet, but generalized.** The four incidents named in Gen 3 and Gen 6 are not four separate morals; they are the same lower bound reappearing across different signing ecosystems. The layers we add (cross-signing deprecation, hardware-backed keys, the VDB, WDAC) do not close the provenance-versus-safety gap. They reduce the blast radius of the inevitable next valid-but-malicious signature.

Once you see provenance and safety as separate questions, every open problem in the code-signing stack lines up in one direction: how do you reduce the blast radius of the inevitable next valid-but-malicious signature?

## Open problems

Five problems are concrete enough to call out as ongoing work.

**O1. Post-quantum Authenticode.** Microsoft has not yet published a `SpcIndirectDataContent` variant that references the ML-DSA (FIPS 204 [109]) or SLH-DSA (FIPS 205 [110]) OIDs. The CA/B Forum CSBR has not named a post-quantum algorithm for code-signing certificates; the current CSBR v3.8 [532] still rests on RSA and ECDSA. NIST's PQC program plans to deprecate quantum-vulnerable algorithms around 2030 and disallow them after 2035 [111]. The CMS extensibility precedents are there: RFC 8419 profiles EdDSA in CMS [556], and RFC 8708 profiles the stateful HSS/LMS signatures of RFC 8554 [555] in CMS, and there is no architectural reason the same approach cannot profile ML-DSA. A hybrid-signed binary that carries both an RSA and an ML-DSA `SignerInfo` inside the same `SignedData` is technically plausible, but any production path would require Microsoft tooling, portal signing, and CA/B Forum profile work. (FIPS 204 (ML-DSA) and FIPS 205 (SLH-DSA) were both finalized on 13 August 2024 [109][110]. The standards are stable; what is missing is the Authenticode-side OID registration and the Hardware Developer Center portal-signing pipeline that would emit a PQ counter-signature. The CSBR side and the Microsoft side both have to move; neither has publicly committed to a date.)

**O2. Per-page integrity for non-PE artifacts.** Page hashes inside `SpcPeImagePageHashes2` [518] are PE-specific. PowerShell scripts, MSIX packages, Appx packages, and the `.cat` files themselves rely on whole-file Authenticode hashing; if an attacker can corrupt a single byte after load, the OS does not currently re-hash. HVCI gives PE binaries a runtime check; the script and package side does not yet have an equivalent.

**O3. Transparency logs for Authenticode countersignatures.** RFC 3161 TSAs do not publish their issued tokens. A backdated countersignature from a compromised TSA is currently undetectable beyond CA revocation. Sigstore Rekor [553] demonstrates that a transparency log integrates with a signing pipeline at low overhead; there is no equivalent for the Microsoft-signed-driver world or for third-party Authenticode signers.

**O4. Revocation propagation latency.** The gap between "the CA revokes" and "every endpoint refuses to verify" is empirically days to weeks. CRLs are downloaded on a cadence (with `EnableCertPaddingCheck` aside, OCSP is not even applied to Authenticode by default). The VDB's quarterly cadence [271] is faster than CRL-only and slower than the rate at which attackers can stand up an attack with a freshly stolen certificate. Some of this is unavoidable (you cannot push a revocation faster than an offline endpoint can reach Windows Update) but a structurally better answer is one of the open questions.

**O5. Post-CrowdStrike (July 2024) kernel-driver-loading discipline.** Microsoft's Windows Resiliency Initiative was announced in the wake of the 19 July 2024 CrowdStrike Falcon Sensor outage; a fully-specified replacement for today's third-party kernel-driver model has not yet shipped. A successful answer would push parts of today's Authenticode + KMCS + WDAC story toward sandboxed user-mode driver frameworks, with the kernel restricted to a much narrower interface. The Authenticode primitives this chapter has dissected will still be the substrate; what gets layered on top is the open architectural question.

> **What this chapter does not cover.** This chapter is about the *crypto foundation* under WDAC: the bytes on disk, the envelope structures, the chain of trust. It does not cover the runtime enforcement layer: how Code Integrity, HVCI, and the secure kernel use these primitives at process- and driver-load time, how page hashes are checked at fault time, how the Vulnerable Driver Blocklist is loaded as a supplemental policy. That runtime-enforcement story is owned by the Code Integrity chapter (Chapter 8), which evaluates these primitives at driver-load and HVCI page-fault time; the administrator-facing allow and deny policy that overlays them is owned by the App Control for Business chapter (Chapter 13).

The next decade of Windows code-signing is going to be dominated by post-quantum migration and by whatever the Windows Resiliency Initiative converges to. Both will be evolution, not revolution: they will sit on top of the certificate-table, catalog-store, and timestamp-token primitives that have been load-bearing since 1996. To finish, the day-to-day commands that interrogate every byte we have discussed.

## Practical guide: signtool, certutil, New-CIPolicyRule

With the on-disk structures and the verification pipeline established, you can run the following commands on a Windows host and explain every field of their output. Microsoft's `signtool`, `certutil`, and the `ConfigCI` PowerShell module are the canonical tools [359].

## Verify a signed binary end to end

```text
signtool verify /v /pa /all "C:\Path\To\binary.exe"
```

The output prints, in order: the SHA-256 of the file's Authenticode hash, the leaf certificate's subject and issuer, every intermediate up to the trusted root, the RFC 3161 timestamp's `genTime`, and the policy used to validate. `/pa` selects the Default Authenticode Verification Policy (used instead of the Windows Driver Verification Policy that applies when `/pa` is omitted); `/all` walks every signature on the file rather than just the strongest.

## Compute and look up an Authenticode hash

```text
certutil -hashfile "C:\Path\To\driver.sys" SHA256
certutil -CatDB -v -search <hash>
```

The `-hashfile` command emits the *file* SHA-256, which is *not* the Authenticode or catalog member hash (the file SHA-256 includes the certificate-table bytes; the Authenticode hash omits the certificate table and follows the PE image-hash algorithm). Use SignTool output, WinTrust/catalog APIs such as `CryptCATAdminCalcHashFromFileHandle`, or a purpose-built PE Authenticode hash implementation when you need the lookup key [359][542]. `Get-AuthenticodeSignature` is useful for status, signer, timestamper, path, and `SignatureType`; do not treat it as a general hash-computation tool.

## Walk the catalog store

```text
Get-ChildItem "C:\Windows\System32\CatRoot" -Recurse | Select-Object FullName
```

The GUID-named subfolder is the CryptSvc policy database identifier; the `.cat` files inside are individually signed catalogs whose entries bind file hashes/thumbprints to attributes [525][542]. `CatRoot2` holds staging copies and the catalog database index.

## Generate a WDAC rule

```powershell
New-CIPolicyRule -FilePath "C:\Path\To\App.exe" -Level FilePublisher
```

This produces an XML `<FileRule>` element with the issuer, subject CN, original file name, and minimum file version. Pipe the result into `New-CIPolicy` to build a policy XML; convert to binary with `ConvertFrom-CIPolicy` and deploy via Group Policy or Intune.

## Decide between embedded and catalog signing

For an internal line-of-business app shipped as a single MSI, embedded signing is the default and the cleanest choice. For a multi-binary package where some files are third-party and unsignable, the Package Inspector workflow [543] builds a `.cat` covering the post-installation file set without modifying any binary:

```text
PackageInspector.exe Start C:\
... install your app ...
PackageInspector.exe Stop C:\ -Name MyApp.cat -ResultsFile C:\Temp\MyApp_inspection.txt
```

## Confirm a kernel-mode chain

```text
signtool verify /v /kp "C:\Windows\System32\drivers\example.sys"
```

The `/kp` policy uses the kernel-mode driver policy: the chain must terminate at a kernel-mode-trusted root (the `Microsoft Code Verification Root` family of anchors, or a portal-signed-driver Microsoft Root Authority anchor). The authoritative test is the `/kp` verification result itself, not the contents of any one certificate store. The legacy `Microsoft Code Verification Root` is named on the KMCS policy page [267] but its thumbprint is not published on a stable Microsoft Learn URL; you can inspect the local machine root store with `certutil -store root` on the running system.

## Make an informed `EnableCertPaddingCheck` decision

The strict-parser registry value lives in two places. Set both:

```text
reg add "HKLM\Software\Microsoft\Cryptography\Wintrust\Config" /v EnableCertPaddingCheck /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Wow6432Node\Microsoft\Cryptography\Wintrust\Config" /v EnableCertPaddingCheck /t REG_DWORD /d 1 /f
```

CISA added CVE-2013-3900 to the Known Exploited Vulnerabilities catalog on 10 January 2022 [489]; treat this as effectively mandatory in any hardened-baseline build.

## Annotated `signtool verify` output

```text
Verifying: notepad.exe
Hash of file (sha256): 6B9B7E...   <-- Authenticode hash, the same one
                                       inside SpcIndirectDataContent.messageDigest
Signing Certificate Chain:
  Issued to: Microsoft Root Certificate Authority 2010   <-- root anchor
    Issued by: Microsoft Root Certificate Authority 2010
  Issued to: Microsoft Windows Production PCA 2011        <-- intermediate / PCA
    Issued by: Microsoft Root Certificate Authority 2010
  Issued to: Microsoft Windows                             <-- leaf / signer
    Issued by: Microsoft Windows Production PCA 2011
The signature is timestamped: Thu Jul ...                 <-- RFC 3161 genTime
Timestamp Verified by:
  Issued to: Microsoft Time-Stamp PCA 2010                <-- TSA chain
  Issued to: Microsoft Time-Stamp Service
File is signed and the signature was verified.
```

> **Always specify a timestamp URL when signing.** The most common practitioner mistake is `signtool sign /n <name>` without `/tr <tsa-url> /td sha256`. A signature produced this way silently loses validity the moment the end-entity certificate expires. Which can be years later, when the signer has long since lost access to whatever signing key produced it. The fix is to always include `/tr` and a strong `/td`. RFC 3161 [544] is the entire reason long-lived signatures still verify; opting out of it is opting out of the longevity guarantee.

## Why your internally-signed LOB app trips SmartScreen

SmartScreen Application Reputation is downstream of Authenticode, not a synonym for it. The public Microsoft documentation is deliberately high-level: SmartScreen checks downloaded files against known unsafe programs and against files that are well known and downloaded frequently; if a file, app, URL, or certificate has established reputation, the user may see no warning, and if there is no reputation SmartScreen can warn even when the file is not known malicious [515]. The Edge documentation adds more operational inputs: download traffic, download history, past anti-virus results, URL reputation, user feedback, data providers, and intelligence models [516]. None of those inputs is the same as "the Authenticode chain validates."

That distinction explains the line-of-business failure mode. Your internal app can be perfectly signed: the `WIN_CERTIFICATE` parses, `SpcIndirectDataContent.messageDigest` matches, the chain terminates at a root trusted by your enterprise, and `Get-AuthenticodeSignature` returns `Status: Valid`. SmartScreen can still show an unknown-app warning because the file has little public download history, the URL has little public reputation, the certificate is an ordinary organization-validation code-signing certificate, and Microsoft has not seen enough benign telemetry to treat the artifact as familiar. An EV certificate can help because EV issuance historically gives stronger key custody and identity vetting signals, but even EV is not a magic allow bit; reputation still accumulates around the signed artifact, signer, distribution URL, and observed safety signals. Conversely, high download volume cannot rescue a file that is known malicious, and a valid signature cannot rescue a file whose reputation has collapsed.

The enterprise fix is therefore architectural, not cosmetic. Inside the organization, do not try to persuade SmartScreen that a 300-user payroll updater is a mass-market download. Publish an App Control policy (the App Control chapter, Chapter 13, develops this enterprise policy layer) that allows the app by `Publisher` or `FilePublisher`, deploy it through Intune, Group Policy, or your normal configuration channel, and monitor event IDs 3076 and 3077 while in audit and enforcement modes [517][546]. That uses Authenticode for what it is good at: stable enterprise identity. For software distributed to the public Internet, use a reputable distribution URL, sign every release with a hardware-protected key, timestamp every signature, avoid repackaging that changes hashes without changing versions, submit false positives through Microsoft's reporting channels, and let reputation accrue over staged releases. The wrong fix is to re-sign the same binary repeatedly with the same OV certificate and expect SmartScreen to change its mind. You have changed the Authenticode envelope; you have not supplied the reputation evidence SmartScreen consumes.

These commands cover the full surface of what Authenticode, catalog signing, WDAC, and SmartScreen-adjacent tooling let a Windows engineer actually inspect. Everything else in this chapter is context for what those command outputs *mean*.

## Closing reflection

In August 1996 the Authenticode trust decision was a single yes/no answer to a single question: did this PKCS#7 SignedData blob, attached to this downloadable ActiveX control, validate against a CA in the user's browser? Thirty years later, the trust decision is a chained question composing every primitive in this chapter: a `WIN_CERTIFICATE` record points to a `SignedData` envelope; the envelope's `SpcIndirectDataContent` carries an Authenticode hash and optional page hashes; an unsigned attribute carries an RFC 3161 timestamp; the catalog store may carry a parallel signature for the same hash; the certificate chain terminates at one of a small set of Microsoft anchors for kernel-mode loads; an administrator's App Control policy decides whether the verdict survives the rule evaluation; the Vulnerable Driver Blocklist denies a small curated list outright.

The cryptography has not moved. The certificate table is still where the bytes live. PKCS#7 SignedData is still the envelope. RSA, now joined by ECDSA, is still the dominant signature algorithm. What has changed (and what is going to keep changing through the post-quantum migration and whatever the Windows Resiliency Initiative converges to) is the layering of policy on top.

Authenticode is not the ceiling. It is the floor. Everything else is built on top, and the next time a Realtek certificate is stolen, those layers are what decides whether the next Stuxnet still loads.

What this chapter bequeaths to the next link is precise: a verified provenance-and-integrity verdict (signer, chain, Authenticode hash, signing time) that the App Control for Business chapter (Chapter 13) evaluates against administrator-authored rules and that the Code Integrity chapter (Chapter 8) enforces at driver load and HVCI page-fault time. What it withholds is just as precise: it does not certify that the signed code is safe, it does not refresh revocation on a disconnected endpoint, and it does not survive a stolen key or a forged sub-CA. Those are the residuals the rest of the trust chain absorbs, and, when every layer fails at once, the Storm-0558 finale (Chapter 29) is what that failure looks like in production.
