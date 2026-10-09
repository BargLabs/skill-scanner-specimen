# Cisco skill-scanner on a constructed known-answer corpus: the public record

Copies of the experiment records from the Barg Labs alfred repository at commit `041109a7989725ff28578250134d3225a829a7db` (the merge of the result, alfred #2415), mirrored 2026-10-09T13:54:20Z. The preregistration was signed at alfred `7f15c835`; the erratum is in commit `738344e3`.

Read the result's "Limits, first" section before any number. This is one scanner version (`cisco-ai-skill-scanner` 2.1.0) with its default analyzers only, on single explicit insertions we constructed. It is not an estimate of recall on real malicious packages. The erratum records three reading notes on the unedited result; it changes no figure.

Layout:
- the preregistration and erratum at the root;
- `result/` holds the unedited result, as markdown and aggregate JSON;
- `harness/skill-scanner-specimen/` holds the corpus generator, inertness check, runner, scorer, statistics and the hash-pinned install lockfile; `harness/__tests__/` holds its test and the three synthetic fixture skills it was tried on before freeze;
- `harness/DEPENDENCIES.md` reproduces the three helpers it imports from elsewhere in the alfred tree.

The harness here is at `041109a7989725ff28578250134d3225a829a7db`. The runs used `15ee0adf`; the only harness difference between the two is `cli.ts`, which gained the read-only `frozen-digest` and `rebuild-digest` commands after the run (alfred #2417). `rebuild-digest` rebuilds the corpus from the pinned public commit and prints its digest, so anyone can check it against the result's `corpusDigest`.

Not published: the built corpus (it is rebuilt byte for byte from the generator, the base list at its pinned commit and the digest), the raw scanner output, and run logs. The corpus was never submitted to any registry, marketplace or scanner service.
