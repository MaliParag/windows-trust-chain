# Contributing

Thank you for helping improve *The Windows Trust Chain*. This book aims to be
accurate, reproducible, and honest about where each security link breaks.
Corrections and clarifications are very welcome.

## Ways to help

- **Fix an error.** Technical inaccuracies, broken reproductions, dead links,
  typos, or unclear passages.
- **Strengthen the evidence.** If a mechanism is marked 🔵 DOCUMENTED and you can
  reproduce it on a live machine, propose the captured output.
- **Improve the site.** mdBook configuration, styling, accessibility, or build.

## Ground rules for content

1. **Never fabricate evidence.** A 🟢 CAPTURED block must be verbatim output that
   actually exists. When in doubt, use 🔵 DOCUMENTED with a real command and a
   clearly labeled expected value from an authoritative source.
2. **Keep verbatim quotes verbatim.** Quotes from vendors, researchers, and
   standards must not be paraphrased inside quotation marks.
3. **No exploit tutorials.** Attacker material appears only as gap analysis:
   what a technique is, and why a given link does not cover it.
4. **Cite sources.** Carry real citations; do not invent URLs.

## House style (please do not "fix" these)

- The prose is deliberately **free of em-dashes** (U+2014). Use commas,
  semicolons, or parentheses instead.
- The `.:` quote-attribution punctuation (quote text ending with `.: Author,
  Source`) is intentional.

## Making a change

1. Edit the relevant file under `src/`.
2. Preview locally with `mdbook serve --open`.
3. If you added, removed, or reordered chapters, run
   `node tools/gen-summary.mjs` to regenerate `src/SUMMARY.md`.
4. Open a pull request describing the change and, for technical edits, how you
   verified it.

By contributing, you agree that your contributions are licensed under the
project's [CC BY-NC-SA 4.0](LICENSE) terms. In addition, you grant Parag Mali a
perpetual, worldwide, non-exclusive, royalty-free, irrevocable license to use,
reproduce, adapt, publish, and distribute your contribution for any purpose,
including commercial editions of this book. This keeps a future commercial
edition unencumbered while the public edition stays open.
