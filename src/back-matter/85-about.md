# About This Book

## The author

Parag Mali writes about Windows security, operating-system internals, and
supply-chain attacks at **paragmali.com**. He designed and operates the
multi-agent writing pipeline that researches, drafts, fact-checks, and
citation-audits the work published there: choosing the topics, setting the
editorial bar, auditing the output, and owning the failures. This book is drawn
from and built on that body of work.

## The method

Every chapter in this book began as a long-form, primary-source-driven essay that
passed a battery of automated quality gates: source verification before writing,
a technical-accuracy review, a depth check, a citation audit, an academic-critic
gate, and a final fact-check. To become a *book*, each essay was reshaped to a
single audience and a single argument (the trust chain) and re-checked.

The book's distinguishing discipline is its treatment of evidence. When a claim is
presented as captured evidence, the raw output is recorded with a cryptographic
hash and re-verified by a build gate that refuses to publish a chapter whose
quoted evidence does not match the capture byte-for-byte. Claims that could not be
captured (the parts of the trust chain rooted in physical silicon a virtual
machine cannot expose, or cloud control-plane behavior outside the lab) are
labeled as documented rather than measured. The three-color provenance taxonomy
that makes this distinction visible is explained in *How to Read This Book*, and
the mechanics are in the Colophon.

This is deliberate. A security book asks for the reader's trust; this one tries to
earn it the way the systems it describes earn theirs: by inheriting it from
something you can verify, not by asserting it.

## Errata and reproduction

The live evidence in this book was captured against a specific Windows build,
stamped on each capture. Mechanisms are durable; exact values are snapshots.
Readers are encouraged to run the verify-it-yourself probe at the end of each
chapter on a machine they control. Corrections are recorded where the original
claim was made; the author welcomes them through the contact channels at
**paragmali.com**.
