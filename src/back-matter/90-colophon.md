# Colophon

This book was made the way it argues you should reason about a Windows machine:
by refusing to take any claim on faith.

**The pipeline.** The text was produced by a multi-agent academic writing pipeline
the author designed and operates. Each chapter passes through staged research,
drafting, and a battery of automated gates (source verification before writing, a
technical-accuracy review, a depth check, a citation audit, an academic-critic
gate, and a final fact-check) before it is allowed near a reader. More than half
of the pipeline's stages exist only to try to prove the draft wrong.

**The evidence.** Where a claim is presented as 🟢 **CAPTURED**, the chapter shows
the probe, the verbatim output, and a SHA-256 of that output recorded at capture
time. A build gate (`evidence-fidelity-gate`) re-hashes every quoted capture
against its manifest and against the bytes on disk, and refuses to build the
chapter if a single character differs. Evidence that could not be captured on the
lab machine (the parts of the chain rooted in physical silicon a virtual machine
cannot expose, or cloud control-plane behavior outside the lab) is labeled 🔵
**DOCUMENTED** rather than dressed up as a measurement. The three-color
provenance taxonomy (🟢 captured · 🟡 emulated · 🔵 documented) is explained in *How
to Read This Book*.

**The tools.** Authored once in Markdown; rendered to web, EPUB, and print from a
single source. Typesetting by **Typst**; multi-format conversion by **Pandoc**.
Body text is set in **Source Serif 4**; headings and navigation in **Source Sans
3**; code in **JetBrains Mono**. The cover was drawn in Typst. No proprietary
toolchain was used, and the entire build (gate, render, and all) runs from one
script.

**Provenance of the live evidence.** Captured on a Microsoft Azure Trusted-Launch
virtual machine (Windows 11, 25H2) with a virtual TPM, Secure Boot, and
Virtualization-Based Security enabled. Because the TPM and the platform root are
host-provided on a virtual machine, silicon-level mechanisms are presented as
🔵 documented or 🟡 emulated, never as captured silicon.

**License.** © 2026 Parag Mali. All rights reserved. See the copyright page.

*If you find an error, the author wants to know, and will record the correction
where the claim was made.*
