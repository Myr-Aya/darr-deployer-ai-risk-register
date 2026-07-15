# Deployer AI Risk Register (DARR): the open dataset

[![DOI](https://img.shields.io/badge/DOI-10.5281%2Fzenodo.21223593-007ec6)](https://doi.org/10.5281/zenodo.21223593)
[![Data license: CC BY 4.0](https://img.shields.io/badge/data-CC%20BY%204.0-1F3935)](https://creativecommons.org/licenses/by/4.0/)
[![Live site](https://img.shields.io/badge/site-airiskdeployer.org-22B891)](https://www.airiskdeployer.org)
[![Cite this repository](https://img.shields.io/badge/cite-CITATION.cff-6C75C0)](CITATION.cff)

The open, citable **dataset** behind the
[Deployer AI Risk Register](https://www.airiskdeployer.org): a canonical set of
AI risks for organizations that **deploy** AI systems, published by
[MindXO](https://www.mind-xo.com). This repository holds the published data and
is where corrections and contributions are proposed. The register is browsable
at **[www.airiskdeployer.org](https://www.airiskdeployer.org)**.

- **82 canonical risks** (`MR-001` to `MR-082`)
- **61 MITRE ATLAS-anchored sub-risks** beneath 12 of them (`MR-0xx.N`)
- **143 register rows** across the two tiers
- Crosswalked to **ISO/IEC 23894 & 42001, the EU AI Act, and MITRE ATLAS**, and
  cross-checked against IBM, Cisco, NIST, and OWASP
- Consolidated from **1,835 MIT AI Risk Repository entries** (V4, December 2025)

This is an **independent derivative** of the
[MIT AI Risk Repository](https://airisk.mit.edu/) (V4, December 2025), used under
CC BY 4.0. It is **not endorsed by or affiliated with MIT**.

## The seven families

| Family | Risks | Sub-risks | Enterprise risk domain |
|---|---:|---:|---|
| Model & system behaviour | 29 | 5 | Operational & technology risk |
| Governance & process | 13 | 0 | Governance & oversight risk |
| Regulatory compliance | 12 | 0 | Compliance & legal risk |
| Human & usage | 10 | 0 | Users risks |
| Security & adversarial | 7 | 43 | Cyber & information security risk |
| Data, privacy & content liability | 6 | 5 | Privacy, data & legal risk |
| Third party & supply chain | 5 | 8 | Third-party & supply-chain risk |
| **Total** | **82** | **61** | |

## What's in this repository

```
data/
  risks.json            82 canonical risks (published fields)
  subrisks.json         61 MITRE ATLAS-anchored sub-risks
  stats.json            verified counts
  methodology.md        the methodology report (as published)
  darr-deployer-ai-risk-register.csv    flat register, 143 rows
  darr-deployer-ai-risk-register.json   nested risks + sub-risks + metadata
  crosswalk.{json,csv}                  forward crosswalk (risk -> framework items)
  reverse_crosswalks.json               reverse crosswalk (framework item -> risk)
  reverse_crosswalks_all.csv            reverse crosswalk, flat
  crosswalks/*_reverse_crosswalk.csv    per-framework reverse crosswalks
  atlas_to_register_map.csv             MITRE ATLAS technique -> register map
```

Full field definitions for every column are on the
[download page](https://www.airiskdeployer.org/download/).

## Using the dataset

The data is CC BY 4.0: free to use, adapt, and build on, including commercially,
with attribution (see [`LICENSE`](LICENSE)). The stable identifiers (`MR-001`...)
are a shared vocabulary you can reference in risk registers, vendor and model
assessments, scanners, evaluations, and GRC tooling.

## Citation

```
Deployer AI Risk Register: an open-source canonical AI risk register for
organizations that deploy AI systems. Developed by MindXO. Version 1.0,
3 July 2026. https://www.airiskdeployer.org/ DOI: 10.5281/zenodo.21223593
```

GitHub's "Cite this repository" (from [`CITATION.cff`](CITATION.cff)) provides
APA and BibTeX forms.

## Contributing

Corrections and new mappings are very welcome, and you do not need to be a
developer. See [`CONTRIBUTING.md`](CONTRIBUTING.md), browse
[good first issues](../../labels/good%20first%20issue), or open an
[issue](../../issues).

## License and attribution

Dataset and register content: **CC BY 4.0** (see [`LICENSE`](LICENSE)); attribute
as described there. Referenced standards (ISO/IEC, the EU AI Act, MITRE ATLAS,
NIST, OWASP, IBM, Cisco) retain their own licenses and are cited by identifier
only. MITRE ATLAS is a trademark of The MITRE Corporation; its use does not imply
endorsement.
