# Contributing to the Deployer AI Risk Register dataset

Thanks for helping improve DARR. This repository is the **open dataset** behind
[airiskdeployer.org](https://www.airiskdeployer.org). You do not need to be a
developer: a well-sourced issue about a wrong or missing mapping is a real
contribution.

## Ways to contribute

- **Review a crosswalk mapping.** Check the mappings between a register risk and
  a framework (ISO/IEC 42001, ISO/IEC 23894, the EU AI Act, MITRE ATLAS, NIST,
  OWASP, IBM, Cisco) and flag anything wrong, missing, or over-reaching.
- **Add a framework.** Propose crosswalking the register to a standard it does
  not cover yet (for example the CSA AI Controls Matrix).
- **Propose a new risk or fix a description**, always from the deployer's
  perspective.
- **Close a known gap.** The register has no quantitative scoring and no
  deployment-pattern-specific breakdowns (RAG, agentic, copilots) yet. These are
  the highest-impact areas.
- **Docs and fixes.** Typos, broken links, clearer explanations.

## The dataset

`data/` is the published register. The files most contributions touch:

- `risks.json` - the 82 canonical risks
- `subrisks.json` - the 61 MITRE ATLAS-anchored sub-risks
- `crosswalks/*_reverse_crosswalk.csv` - per-framework mappings (one CSV each)
- `crosswalk.json` / `crosswalk.csv` - the forward crosswalk
- `reverse_crosswalks.json`, `reverse_crosswalks_all.csv`, `atlas_to_register_map.csv`
- `darr-deployer-ai-risk-register.csv` / `.json` - the combined register

Field definitions for every column are on the
[download page](https://www.airiskdeployer.org/download/).

## How to propose a change

- **Open an issue** (preferred for anything substantive) using one of the
  templates - mapping correction, new framework, or risk/taxonomy feedback -
  and cite your source.
- Or **open a pull request** editing the relevant file(s) in `data/` as a
  concrete proposal, again citing your source.

Maintainers review contributions, reconcile them into the register, and publish
the updated dataset and site (the website is generated from this data).
Accepted changes are credited in the release notes. For anything structural (a
new framework, a new risk, or a taxonomy change), please open an issue first so
we can agree the approach before you invest time.

## Ground rules

- **Cite your source.** A mapping change should point to a specific clause,
  article, control, or technique (for example "ISO/IEC 42001 clause 6.1.2",
  "EU AI Act Art. 9", "MITRE ATLAS AML.T0051").
- **Keep the deployer frame.** The register describes risks for the organization
  that *deploys* AI, not the one that builds the model.
- **Naming:** always write "MITRE ATLAS", never bare "ATLAS".
- **No reproduced licensed text.** Reference standards by number or identifier;
  do not paste ISO, EU AI Act, or other licensed text.
- Be respectful and constructive. Assume good faith.

## Licensing

By contributing, you agree that your contributions are licensed under the
project's terms: **CC BY 4.0** (see `LICENSE`). Only submit material you have the
right to contribute.

## Questions

Open an issue, or see the roadmap on the
[Contribute page](https://www.airiskdeployer.org/contribute/).
