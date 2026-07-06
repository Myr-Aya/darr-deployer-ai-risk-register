# Methodology Report: Building a GPAI Deployer Risk Register from the MIT AI Risk Repository, ISO/IEC 23894 + 42001, MITRE ATLAS, the EU AI Act, the IBM AI Risk Atlas, and the Cisco AI Security Framework

This report documents seven parts of work. Part One filters and consolidates the MIT AI Risk Repository into 61 canonical deployer risks. Part Two checks those 61 against ISO/IEC 23894:2023 and ISO/IEC 42001:2023, identifies risks the MIT set does not cover, and produces a combined register of 70 risks. Part Three maps MITRE ATLAS against the register and, rather than treating MITRE ATLAS as flat metadata, decomposes the security and misuse risks into a second tier of technique-level sub-risks, adding one new agentic risk (the seventy-first) and producing a complete MITRE ATLAS-to-register crosswalk. Part Four reads the EU AI Act and the GPAI Code of Practice obligations backward into deployer risks, adding eleven compliance and provider-dependency risks to reach a register of 82 canonical risks with 61 MITRE ATLAS sub-risks beneath them. Parts Five, Six, and Seven are coverage checks rather than construction passes: Part Five maps the IBM AI Risk Atlas against the register, confirming completeness and harvesting IBM's cross-taxonomy mappings and pipeline-position tags (which become additional register columns); Part Six maps the Cisco Integrated AI Security and Safety Framework, confirming agentic and supply-chain coverage in particular; Part Seven runs four further direct coverage checks against NIST AI 100-2 (adversarial ML), the OWASP Top 10 for LLM and for Agentic Applications, and the NIST Generative AI Profile, each confirming completeness with no new canonical risk required. Each part records its methods, decisions, validation, and limitations.

# Part One: Filtering the MIT AI Risk Repository

## 1. Objective

The goal was to convert the MIT AI Risk Repository (AI Risk Database v4, dated 03 December 2025) into a canonical risk register for organizations that deploy AI systems, as opposed to those that develop foundation models. Three sequential filters were applied to every risk entry (deployer relevance, operational measurability, and deduplication), and each surviving risk was tagged for AI-type applicability, scope, and the organizational impact domains where harm lands. This report documents how that was done and the decisions behind it.

## 2. Source data and unit of analysis

The source workbook contains 2,574 rows in the `AI Risk Database v4` sheet, drawn from 74 published frameworks. The rows are not homogeneous. They sit at four levels, identified by the `Category level` column:

| Category level | Rows | Treatment |
|---|---:|---|
| Paper | 74 | Framework header. Not a risk. Not processed. |
| Risk Category | 570 | Top-level risk statement. Processed. |
| Risk Sub-Category | 1,265 | Granular risk statement. Processed. |
| Additional evidence | 665 | Supporting quote attached to a parent risk. Not a standalone risk. Not processed. |

The unit of analysis is therefore the **1,835 discrete risk entries** at the `Risk Category` and `Risk Sub-Category` levels. The `Additional evidence` rows carry no independent description (they are quotations supporting an existing risk), and the `Paper` rows are bibliographic headers, so neither constitutes a discrete risk. This figure aligns with the repository's own framing of roughly 1,700 to 1,800 extracted risks.

Each entry was reduced to a normalized record: its framework citation key (`QuickRef`), the MIT mid-level domain and sub-domain, the causal metadata (entity, intent, timing), and a combined searchable text built from the risk category label, sub-category label, and description.

## 3. Filter design

The brief specified three filters applied in order, with an explicit instruction to keep a risk when its status is uncertain. That keep-bias shaped every threshold below.

**Filter 1, deployer relevance.** Retain a risk if it can materialize for an organization that procures, configures, deploys, operates, monitors, or retires an AI system, including risks that originate at the developer stage but surface for the deployer (for example, training-data bias that manifests as unfair outputs). Exclude risks that are exclusively about model architecture and pre-training decisions, fundamental alignment or interpretability research programs, existential or superintelligence or AI-consciousness scenarios, and nation-state military or geopolitical arms-race dynamics.

**Filter 2, operational measurability.** Retain a risk if a deploying organization could plausibly measure or monitor it through system evaluation, production monitoring, organizational records, or operational telemetry. Exclude risks that are purely speculative, that describe macro-societal dynamics no single organization can measure, or that concern long-term effects with no observable proxy.

**Filter 3, deduplication.** Consolidate entries that describe the same underlying risk under different terminology into one canonical risk, retaining every source reference. Consolidation was kept conservative: entries were only merged when they shared an underlying hazard, and were left separate when their measurement or mitigation differs (for example, disparate performance was kept distinct from discriminatory decisions because the former is measured by per-group accuracy and the latter by outcome fairness).

## 4. Canonical taxonomy construction

Before any automated classification, all 1,835 entries were read in full, grouped by MIT sub-domain, so that the canonical taxonomy was grounded in the actual content rather than imposed from outside. This produced **61 canonical deployer risks** organized along the seven MIT domains plus an organizational-governance cluster. The granularity sits deliberately between the MIT sub-domain level (around 24 themes, too coarse for a working register) and the raw entry level (1,219 distinct free-text labels, too fine and inconsistent). Examples of the consolidation logic:

- The MIT sub-domain "AI system security vulnerabilities and attacks" was split into eight canonical risks (prompt injection and jailbreaking, data and model poisoning, model theft, adversarial evasion, insecure code generation, supply-chain vulnerabilities, insecure tool integration, and a general security residual), because each has a distinct threat model and control set.
- Conversely, hallucination, confabulation, fabricated content, and unfaithful generation were merged into a single canonical risk, as the brief illustrated.
- Cross-cutting risks that appear under several MIT domains (copyright, defamation, deepfakes, CBRN uplift, privacy leakage) were consolidated across those domains into one canonical risk each.

## 5. Classification architecture

Because the brief required that the same type of risk always receive the same treatment, the three filters and the canonical mapping were encoded as a single deterministic, rule-based classifier rather than applied ad hoc. Determinism guarantees consistency and makes every decision auditable and reproducible. The classifier resolves each entry as follows.

1. **Exclusion screen.** A set of high-precision regular expressions tests for the Filter 1 and Filter 2 exclusion themes (existential and superintelligence framing, nation-state military and geopolitical framing, alignment-research framing, and macro-societal framing). These patterns are intentionally narrow so they fire only on unmistakable cases.

2. **Keyword routing, domain-aware.** A priority-ordered list of content patterns (specific risks before general ones) proposes a canonical risk. The key design decision is that a proposed route is accepted only when it is **in-domain** (the canonical risk sits in the same MIT domain that MIT's coders assigned to the entry) or when the canonical risk is on a short **cross-precise** list of risks whose vocabulary is distinctive enough to trust across domains (for example CBRN, copyright, deepfakes, prompt injection). Generic terms such as "bias" or "manipulation" are not on that list, so they only route an entry within its own MIT domain. The rationale is that the MIT sub-domain is an expert-coded signal and is more reliable than a single generic keyword; the classifier defers to it and uses keywords mainly to add within-domain granularity and to capture genuinely cross-cutting risks.

3. **Arbitration.** When both an exclusion and an accepted route match, the entry is excluded unless the route is one of a small set of unambiguously operational and measurable risks (for example cyberattacks, CBRN uplift, surveillance, environmental footprint), which are retained even when macro or existential language co-occurs. This operationalizes the keep-bias without letting it readmit clearly out-of-scope content.

4. **Fallbacks.** Entries with no accepted route fall through to: a paper-specific default for the dedicated multi-agent-risks framework; removal of non-substantive taxonomy scaffolding and umbrella headers; removal of residual macro or non-risk framings; and finally the MIT sub-domain default, which assigns the entry to that sub-domain's representative canonical risk (a keep) or marks the sub-domain as out of scope (an exclude). This step is where MIT's expert coding does most of the work for entries that keyword routing did not resolve.

This ordering means the backbone of the classification is MIT's own expert taxonomy, with keyword logic layered on top for splitting and for cross-domain consolidation.

## 6. Tagging

Tagging was applied per canonical risk (61 decisions) rather than per entry, which made genuine case-by-case judgment feasible.

- **AI-type applicability** (GPAI, Agentic, Classical_ML, multi-select). All 61 risks apply to GPAI systems, consistent with the register's GPAI-deployer focus. Agentic was added where autonomy, tool use, or multi-step planning materially changes the risk (35 risks); Classical_ML was added where the risk predates and applies to narrow models such as classifiers and regressors (31 risks).
- **Scope class** (System, Organization, Both). Output, safety, and security risks that attach to a specific deployment were marked System; organization-level risks that exist regardless of any single deployment (governance gaps, competence gaps, vendor concentration, workforce impact) were marked Organization; risks that genuinely manifest at both levels were marked Both.
- **Impact-domain routing** (D1 through D9, multi-select). Domains were assigned by where harm lands as an organizational consequence, not by what causes the risk, per the brief. For example, a hallucination is caused by the model but lands as operational disruption (D1), customer and conduct harm (D4), and reputation erosion (D8).
- **MIT metadata.** For each canonical risk, `mit_domain`, `mit_subdomain`, `mit_entity`, `mit_intent`, and `mit_timing` are reported as the modal value across that risk's consolidated entries. A canonical risk may span more than one MIT domain; the modal value is the single best representation, and the full provenance remains in the source columns.

## 7. Validation

The classifier was iterated against three checks until stable.

- **Cross-domain leakage.** A diagnostic flagged every entry assigned to a canonical risk outside its MIT domain that was not on the cross-precise list. The count was driven from an initial 214 down to **zero**. Each resolution either tightened a pattern (for example, restricting "manipulate" to human targets so it no longer matched "manipulate parameters") or moved the relevant canonical onto the cross-precise list with a precise pattern.
- **Exclusion audit.** Excluded entries were sampled by filter and rationale. This surfaced several false exclusions that were corrected: "non-existential" matching the substring "existential", "information warfare" matching a military pattern, "law enforcement" matching a regulatory pattern, and a market-monopoly pattern catching "ideological monopolization" inside a fairness entry. False inclusions were corrected the same way (for example, the child-safety pattern "minor" was matching "minorities").
- **Reconciliation.** Kept entries (1,583) plus excluded entries (252) equal the 1,835 processed entries exactly, with no unresolved records.

The top-cited canonical risks provide an external sanity check: disinformation, personal-data leakage, bias, and hallucination are the most widely attested across frameworks, which matches expectation for a deployer-facing register.

## 8. Results

| Stage | Count |
|---|---:|
| Discrete risk entries processed | 1,835 |
| Passing Filter 1 (deployer relevance) | 1,638 |
| Passing Filter 2 (operational measurability) | 1,583 |
| Canonical risks after Filter 3 (deduplication) | 61 |

Of the 252 exclusions, 197 fell at Filter 1 (108 non-substantive taxonomy or umbrella headers, plus 89 substantive out-of-scope risks covering existential, military or geopolitical, alignment-research, and non-risk framings) and 55 fell at Filter 2 (macro-societal and unmeasurable framings). The 1,583 surviving entries consolidated into 61 canonical risks, a consolidation ratio of roughly 26 to 1.

## 9. Limitations

- **Residual consolidation noise.** Automated keyword routing leaves an estimated 2 to 3 percent of source entries in an adjacent canonical risk when they mention a cross-cutting term only in passing. Because every original entry text and framework reference is preserved during consolidation, any grouping can be inspected and corrected.
- **Modal MIT metadata.** Reporting a single modal MIT domain per canonical risk loses the spread for risks that span domains. The spread remains recoverable from the source entries.
- **Filter boundaries are judgments.** The line between an operational safety failure that is kept (for example, specification gaming, observable in deployment) and an existential framing that is excluded (for example, superintelligent takeover) reflects a defensible reading of the brief, not a settled standard. The keep-bias means borderline cases were retained.
- **Structural exclusions.** Non-substantive umbrella and dimension headers were logged under Filter 1 for transparency, although they are structural rather than out-of-scope on relevance grounds. They are reported separately in the summary so they do not inflate the substantive relevance count.

## 10. Reproducibility

The pipeline is fully scripted and re-runnable. `prep.py` builds the normalized entry set; `taxonomy.py` holds the 61-risk canonical taxonomy, the routing rules, the exclusion rules, and the classifier; `tags.py` holds the per-risk tags; `diag.py` runs the cross-domain leakage diagnostic; and `gen.py` and `gen_summary.py` produce the three deliverables. Re-running the scripts regenerates the register, the exclusion log, and the summary deterministically. Adjusting any rule (for example, splitting a large canonical risk or moving a filter boundary) and re-running propagates the change end to end.

# Part Two: Extending coverage with ISO/IEC 23894 and 42001

## 11. Objective and rationale

Part One drew on the MIT repository, which catalogues AI harms and failure modes. That lens systematically under-represents the management-system and life-cycle process risks that a deploying organization is actually governed and audited against. Part Two corrects for that by reading the 61 canonical risks against two complementary standards: ISO/IEC 23894:2023 (AI risk management guidance) and ISO/IEC 42001:2023 (the auditable AI management system standard). The aim was twofold: identify risks not covered by the 61 (gaps), and attach structural ISO metadata to those that are covered (enrichment). The 42001 Annex A controls were treated as the priority input because they are normative and are what deployers are certified against.

## 12. Source handling and the licensing constraint

Both standards are licensed documents, so a firm rule governed all outputs: paraphrase everything, reference by clause, annex, and control number only, and never reproduce standard text. Full text was extracted to local working files for analysis, but no deliverable contains verbatim wording, including section and control titles, which were reworded into the author's own labels. Compliance was enforced mechanically by an n-gram scan described in section 15.

The following structures were extracted and paraphrased. From 23894: the ten organizational risk source areas (clause 6.4.2.3), the eleven AI-related objectives (Annex A, A.2 to A.12), the seven mechanism-level risk-source families (Annex B, B.2 to B.8), the consequence types (clause 6.4.2.6), and the risk-criteria factors (clause 6.3.4 and its Table 4). From 42001: all 38 controls across the nine Annex A families (A.2 to A.10), and Annex C. One edition note: in this printing of 23894, consequence-identification guidance sits in clause 6.4.2.6, not 6.4.2.5 as the brief assumed (6.4.2.5 is the controls clause here); the source areas and objectives matched the brief exactly.

## 13. Gap-analysis method

The method is the deliberate inverse of Part One. There, 1,835 free-text entries forced a deterministic classifier. Here the ISO item set is small and bounded (roughly 66 items: 10 source areas, 11 objectives, 7 mechanism families, and 38 controls), so each item was judged by hand against the 61, which is both feasible and more accurate than automation at this scale.

Three rules governed the judgments:

- **Coverage bar.** An ISO item counts as covered only when a MIT risk addresses the same underlying hazard. Partial overlap is recorded as a gap with the nearest MIT risk named, following the brief's instruction to err toward identifying gaps.
- **Backward-read of controls.** Each normative 42001 Annex A control exists to mitigate some risk. For every control the implied risk was inferred and then checked against the 61. A control whose implied risk has no home in the register is a gap signal.
- **Cross-reference of the mirrored annexes.** 42001 Annex C was compared against 23894 Annex A and B. It proved to be a condensed mirror that defers to 23894 for detail, so it contributed no net-new objectives or risk sources.

## 14. Results

Nine gap risks were identified (ISO-001 to ISO-009) and renumbered MR-062 to MR-070 on integration. All five pre-registered hypotheses (shadow AI, inventory blind spots, embedded AI through procurement, vendor model version churn, and change without revalidation) were confirmed as genuine, ISO-derivable gaps that the 61 do not contain. The backward-read surfaced four further gaps the hypotheses did not name: no impact-assessment process, inadequate incident response and communication, inadequate logging and traceability, and unmanaged decommissioning. Of the 38 controls, 25 mapped to an existing MIT risk and 13 surfaced a gap, concentrated in impact assessment (A.5), life-cycle operations including logging and change control (A.6), incident and adverse-impact reporting (A.8), responsible use (A.9), and supplier management (A.10). All 61 MIT risks received crosswalk metadata linking them to 23894 source areas, objectives, and mechanisms and to 42001 controls.

The headline finding is structural rather than incidental. No net-new deployer risk was found that is absent from both the MIT set and ISO. Every gap is ISO-derivable, and seven of the nine are organization-scope governance and life-cycle risks, which is exactly the band the harm-centric MIT repository thins out and the management-system standard fills. The practical implication, recorded in the summary, is that further work beyond this combined set sits above the risk layer, not in further net-new risks.

## 15. Validation

Three checks were run. Completeness: all 61 MIT risks appear in the crosswalk, and every ISO item is either mapped to a MIT risk or recorded as a gap. Reference integrity: every clause, annex, objective, and control number cited in the outputs was asserted against the extracted inventory, so no reference is invented. Licensing: a sliding n-gram scan compared all outputs against the extracted full text of both standards. Author-written content (gap names, descriptions, rationales, and crosswalk notes) returned zero verbatim runs of six words or more, and the labels were reworded until that held at five words. The only residual overlaps sit in the inherited MIT quote column, where MIT entries and ISO happen to share generic phrasing drawn from common source standards; that text is MIT-licensed (CC BY 4.0) and reproducing it was a requirement of Part One, so it is benign for the ISO constraint. One mapping correction came out of validation: eight misuse risks had been routed to source area 10 (reliance on external parties), which actually denotes suppliers a deployer depends on rather than external adversaries, and were remapped to source area 7 (system configuration and safeguards).

## 16. Integration into the register: the ISO gaps

The nine gaps were merged into the 61 to produce a single 70-risk register. The new rows carry the same tag schema as the originals: AI-type applicability, scope class, and freshly assigned impact domains. Three provenance columns were added across the whole register: `source_standard` (distinguishing MIT-derived from ISO-derived rows), `iso_source` (the clause and control references, prefixed with the ISO identifier so the row links back to the gap analysis), and `nearest_mit_risk`. The MIT-taxonomy columns are marked not applicable for the ISO rows, since those risks do not originate from the MIT taxonomy. The MIT-only set was preserved, and the combined register written as a new stage.

## 17. Limitations

- **Judgment, not computation.** Part Two's coverage calls are reasoned judgments against 61 short risk statements. They are defensible and documented, but a different reader could merge or split a small number of them.
- **One risk per control.** The backward-read infers a single principal risk per control, although some controls imply several; secondary implications are captured through the crosswalk rather than as separate gaps.
- **Paraphrase distance.** Gap descriptions express the author's reading of the risk a clause or control implies, not the standard's own wording, so they should be read alongside the cited references rather than as substitutes for the standards.
- **Interpretive metadata.** The nearest-MIT-risk notes and the impact-domain assignments for the nine gaps are interpretive, on the same basis as the Part One tags.

## 18. Reproducibility

Part Two is scripted on top of Part One's outputs. `iso_map.py` holds the paraphrased ISO inventories, the 38-control backward-read with its coverage mapping, the nine gap definitions, and the 61-row crosswalk; `gen_iso.py` produces the five gap-analysis deliverables and runs the completeness and reference-integrity assertions; and `gen_register_v2.py` merges the nine gaps into the 70-risk register. The licensing n-gram scan is a standalone check re-run against the outputs. As in Part One, editing the data module and re-running propagates changes through every deliverable.

# Part Three: Decomposing MITRE ATLAS into technique-level sub-risks

## 19. Objective and rationale

MITRE ATLAS is an adversarial taxonomy: its entries are attacker techniques, not deployer risks. Parts One and Two produced risks at the level a board or risk committee reasons about. MITRE ATLAS sits one level lower, at the level a security or red team reasons about. Rather than hang MITRE ATLAS technique identifiers on the register as flat metadata, Part Three treats each deployer-relevant technique as a sub-risk beneath a parent canonical risk. This gives the register a genuine second tier: canonical risk, then MITRE ATLAS-anchored sub-risk, then the technique, its mitigations, and its real-world case studies. The value of MITRE ATLAS here is technique-level granularity, countermeasures, and documented incidents, not the discovery of risks the earlier sources missed.

## 20. Source and structure

The analysis used the consolidated distribution file from a local clone of the MITRE ATLAS data repository, MITRE ATLAS Matrix version 5.6.0: 16 tactics, 170 techniques (101 top-level and 69 sub-techniques), 35 mitigations, and 57 case studies. Mitigations carry their technique links, and each case study carries a procedure listing the techniques it demonstrated, which made the mitigation-to-technique and incident-to-technique joins exact. MITRE ATLAS is openly published, so technique, mitigation, and case-study identifiers are cited directly with attribution to MITRE; descriptive prose was paraphrased, and case-study summaries were synthesised from structured fields rather than copied.

## 21. The sub-risk model

The core design decision is that a sub-risk corresponds one-to-one to an MITRE ATLAS technique entry. Sub-risks are defined at the top-level technique by default, with that technique's sub-techniques carried as variants on the same sub-risk, since they usually share a mitigation and control story. A sub-technique is promoted to its own sub-risk only when it is a materially distinct deployer risk. Each sub-risk receives a deployer-perspective name and one-line description (the MITRE ATLAS label is attacker-phrased; the sub-risk is phrased as what can go wrong for the deployer), an identifier of the form parent-risk-id point sequence (for example MR-010.1), and its own AI-type and scope tags, plus the anchoring technique identifier, tactics, variant sub-technique identifiers, mitigation identifiers, and case-study identifiers.

## 22. Classification method

Every one of the 101 top-level techniques was placed into one of three classes by reading its name, description, and tactic:

- **Sub-risk.** A deployer-relevant technique that decomposes a parent canonical risk. The parent was assigned by tactic and content, with the register's security and misuse risks as the targets (prompt injection, adversarial evasion, poisoning, model theft, data leakage, confidential disclosure, supply chain, cyberattack, general security and availability, deepfakes and fraud).
- **Attack-chain context.** A reconnaissance, resource-development, or discovery step, or a generic cyber stage borrowed from ATT&CK, that is adversary activity rather than a deployer risk in itself. These were recorded with a reason and not added to the register, in line with the brief.
- **Gap.** A deployer risk with no adequate home in the register.

Sub-techniques inherit the classification of their parent technique.

## 23. Results

The 101 top-level techniques resolved to 61 sub-risks and 40 attack-chain context techniques, and one gap. The 61 sub-risks attach to twelve parents: eleven existing security and misuse risks plus one new top-level risk. The single gap is the agentic cluster that MITRE ATLAS version 5.6 has expanded substantially (agent tool-invocation abuse, context poisoning, agent-driven exfiltration and data destruction, agent configuration tampering, and agent command-and-control). These do not sit cleanly under the existing insecure-tool-integration or loss-of-oversight risks, so they became a new risk, "Autonomous agent hijacking and excessive-agency abuse," parent to thirteen agentic sub-risks. One further technique, AI supply-chain rug pull, mapped onto the ISO-derived vendor-churn risk and reinforced it. As expected for an adversarial taxonomy mapped against a broad register, the non-security risks (fairness, content, governance, environmental, workforce) carry no MITRE ATLAS sub-risks.

All 57 case studies were extracted, paraphrased, and linked; 55 connect to at least one canonical risk through their techniques. A complete MITRE ATLAS-to-register crosswalk was then produced covering all 170 entries: 61 mapped as sub-risks, 41 sub-techniques mapped as variants, and 68 classified as attack-chain context, so every MITRE ATLAS entry is accounted for and the "why is this technique not in our register" question is answerable for each one.

## 24. Integration into the register: the MITRE ATLAS sub-risks

The new agentic risk was added to the register as MR-071, following the same provenance convention used for the ISO gaps (MR-062 to MR-070). The 61 sub-risks were folded in as indented, collapsible child rows beneath their parents using spreadsheet outline grouping, so each parent risk can be expanded to reveal its technique-level decomposition. The schema is unified across both tiers: parent rows retain all MIT and ISO metadata (impact domains, source-row anchors, ISO references, taxonomy fields), and child rows carry the MITRE ATLAS metadata (technique identifier and name, tactics, variant sub-techniques, mitigations, case studies, AI type, and scope). A `row_type` field distinguishes the two tiers for filtering.

## 25. Limitations

- **Granularity is a judgment.** Defining sub-risks at the technique level, with sub-techniques as variants, is a deliberate choice; a finer or coarser cut is defensible, and the standalone sub-risk register and full crosswalk preserve the technique-level detail either way.
- **Context is a boundary call.** Marking 68 entries as attack-chain context reflects the brief's instruction not to treat adversary staging steps as deployer risks. Some generic cyber stages do create exposure for the surrounding system; they are noted rather than added so the register stays AI-specific.
- **Version-bound.** MITRE ATLAS is updated frequently, and its agentic coverage in particular is moving quickly. The mapping is pinned to version 5.6.0 and should be refreshed when MITRE ATLAS releases.
- **Synthesised case-study summaries.** Case-study summaries are composed from structured fields and the technique mapping, so they are accurate but terser than the source narratives; the case-study identifiers link back to the originals.

## 26. Reproducibility

`atlas_extract` reads the MITRE ATLAS distribution file into a normalised JSON of techniques, mitigations, and case studies; `atlas_map.py` holds the per-technique classification, the parent assignments, and the authored sub-risk text; `gen_atlas.py` produces the sub-risk register, the parent rollup, the case studies, the gap risk, and the summary; `gen_register_v4.py` folds the sub-risks into the register as child rows; and `gen_atlas_full_map.py` produces the complete MITRE ATLAS-to-register crosswalk with its reconciliation checks. Re-running regenerates every MITRE ATLAS deliverable deterministically, and a refresh to a newer MITRE ATLAS version is a re-extract followed by a review of any newly added techniques.

# Part Four: Reading EU AI Act and GPAI Code of Practice obligations backward into risks

## 27. Objective and rationale

The first three sources describe what can go wrong technically and organizationally. The EU AI Act and its GPAI Code of Practice describe what a deployer is legally required to do. Every legal obligation implies a risk, namely the risk of failing to meet it, with regulatory enforcement and a downstream harm attached. Part Four extracts the deployer-facing obligations from the Act and the Code, translates each into the risk of non-compliance, and checks that risk against the register. This obligation-read-backward method is standard in compliance risk management but has not been applied systematically to the Act's deployer obligations to build a risk register.

## 28. Sources and citation stance

The analysis used Regulation (EU) 2024/1689 and the three GPAI Code of Practice chapters (Transparency, Copyright, Safety and Security), with the Commission's GPAI Guidelines for scope. The Act is public legislation, but the same discipline was kept as for the licensed standards: no Act or Code text is reproduced, obligations are paraphrased, and sources are cited by article number or by Code chapter and commitment. One correction was recorded: the deployer transparency duties sit in Article 50, not Article 29 as the brief assumed, and article numbers were verified against the Regulation.

## 29. Method and the coverage rule

The deployer-facing articles were read in full: Article 4 (AI literacy), Article 5 (prohibited practices), Articles 9, 10, 12, 13, 14 and 15 (the high-risk requirements a deployer must keep intact in use under Article 26), Article 26 (the twelve deployer obligations), Article 27 (the fundamental-rights impact assessment), Article 49 (registration), and Article 50 (transparency). Twenty-one distinct obligations were extracted; obligations addressing the same risk were consolidated rather than split per sub-clause.

Two rules governed the gap-versus-enrichment decision. First, per the brief, the generic compliance risk (MR-040) was treated as insufficient: an obligation whose only home would be that umbrella, or which had no home, became a granular, article-specific gap, because a duty such as "retain logs for the required period" is more actionable and auditable than a generic compliance heading. Second, where an obligation matched a specific existing risk, including the ISO-derived governance risks, it was recorded as enrichment rather than duplicated. Every derived risk carries an `eu_obligation_type` (deployer duty, provider duty with deployer dependency, or prohibited practice) and an `eu_high_risk_scope` (high-risk only, broad, or mixed), the latter feeding the deployment profiles.

The Code of Practice was read from the deployer's side. Each chapter binds GPAI providers, so for each chapter one consolidated provider-dependency risk was derived: what the deployer is exposed to when the provider does not comply. This supply-chain-of-compliance exposure is the unique contribution of this source.

## 30. Results

Of the twenty-one obligations, eleven became gap risks (EU-001 to EU-011) and the remainder enriched twenty-five existing canonical risks. The eleven gaps comprise seven deployer duties, one prohibited-practice risk, and three provider-dependency risks; five bind only high-risk systems and six apply broadly. The high-risk-only set is the fundamental-rights impact assessment, worker information before workplace deployment, registration, informing affected individuals, and operational monitoring with incident reporting and suspension. The broad set is prohibited-practice exposure, the Article 50 disclosure duties, the AI literacy obligation, and the three Code-of-Practice provider-dependency risks.

The most useful finding is that the Act's process duties land squarely on the ISO-derived governance risks from Part Two, which gives those risks statutory force: the fundamental-rights assessment sits next to the impact-assessment risk, logging on the logging risk, incident reporting next to the incident-response risk, registration next to the inventory risk, AI literacy next to the competence risk, and human oversight on the oversight risk. The genuinely new compliance content is the worker-information duty, the registration duty, prohibited-practice exposure, the Article 50 disclosure duties, and the three provider-dependency risks, which also reinforce the ISO vendor risk.

## 31. Integration into the register: the EU gaps

The eleven gaps were added as MR-072 to MR-082, following the convention used for the ISO gaps (MR-062 to MR-070) and the MITRE ATLAS gap (MR-071). The twenty-five enrichment mappings were folded onto their existing canonical risks in the same pass, so the register itself, not only the standalone crosswalk, records every EU touchpoint. EU coverage is exposed as a dedicated column family rather than a single composite cell, so a reader can filter which provision touches a risk and how: `eu_coverage` (gap or enrichment), `eu_ai_act_articles`, `eu_cop_references`, `eu_obligation_type`, `eu_high_risk_scope`, `eu_mapping_note`, and `eu_source` (the EU-### provenance identifier carried on the gap rows). Thirty-six risks are EU-relevant, the eleven gaps plus twenty-five enriched, of which thirty cite a specific AI Act article and the remainder rest on Code-of-Practice commitments. Each EU risk received impact-domain tags on the same basis as the rest of the register. The register holds 82 canonical risks with the 61 MITRE ATLAS sub-risks beneath their parents, in the same indented, collapsible layout.

## 32. Limitations

- **Gap versus enrichment is a judgment.** The rule of thumb (specific match enriches, generic-only becomes a gap) is defensible but leaves borderline calls, notably AI literacy, which sits close to the existing competence risk and was made a gap because it is a standing legal duty for all deployers.
- **High-risk classification is system-level.** The `eu_high_risk_scope` field records whether an obligation binds high-risk systems, applies broadly, or is mixed, not whether any particular deployment is high-risk; that classification is made per system against Annex III when the register is applied.
- **Living instruments.** The Act's obligations phase in over time and the Code of Practice is recent; the references are pinned to the current texts and should be refreshed as guidance and delegated acts arrive.
- **Provider-dependency is consolidated.** Each Code chapter is reduced to one deployer risk; the underlying commitments are cited but not enumerated as separate risks, by design.

## 33. Reproducibility

`eu_map.py` holds the paraphrased obligation inventory, the eleven gap definitions with their flags, and the enrichment crosswalk; `gen_eu.py` produces the five EU deliverables and asserts that every referenced canonical risk exists; and `gen_register_v5.py` folds the eleven gaps into the register as MR-072 to MR-082 and adds the two columns. A paraphrase n-gram scan against the Act and Code text confirms no verbatim reproduction. Re-running regenerates the EU deliverables and the register deterministically.

---

# Part Five: The IBM AI Risk Atlas as a coverage check

## 34. Purpose and source

By this point the register held 82 canonical risks and 61 MITRE ATLAS sub-risks built from four sources. The IBM AI Risk Atlas was brought in not to add risks but to test completeness from an independent direction and to harvest the cross-taxonomy mappings IBM had already performed. The source is the open IBM AI Atlas Nexus knowledge graph (Apache 2.0), cloned locally, with IBM text reproduced verbatim under that licence. The Atlas is IBM's own taxonomy of 99 risks across sixteen dimensions and five pipeline positions (training data, inference, output, non-technical, agentic), developed independently of MIT and crosswalked by IBM to the MIT Repository, NIST, OWASP and others. This independence is the point: a second taxonomy that agrees the register is complete is stronger evidence than extending the same source.

## 35. Method

Every one of the 99 IBM risks was mapped to a canonical risk, or to a specific MITRE ATLAS sub-risk where that was finer, with a confidence of Clear, Partial or Weak and a one-sentence rationale. The semantic mapping was cross-checked deterministically. IBM publishes its own IBM-to-MIT-subdomain mapping, and because the register is itself built from MIT subdomains, that mapping bridges an IBM risk to candidate canonical risks independently of the human judgment; agreement between the two was then measured. IBM's finer splits, for example several hallucination variants, were collapsed onto one canonical risk, following the instruction not to manufacture granularity.

## 36. Results and the cross-taxonomy harvest

All 99 IBM risks mapped (79 Clear, 20 Partial, 0 No-match), so no IBM risk fell outside the register and no new canonical risk was added. The MIT-subdomain cross-check agreed with the semantic mapping in 54 of 61 checkable cases (89 percent). The seven disagreements were instructive rather than errors: some were precision wins, where membership and attribute inference belong on the privacy-inference risk rather than IBM's coarser security subdomain, and the rest were cases whose correct home is an ISO or EU governance risk that the MIT-subdomain index cannot see. IBM's contribution was twofold. First, the cross-taxonomy harvest: IBM had already mapped its Atlas to the MIT Repository, the NIST GenAI Profile, OWASP for LLM and Agentic applications, AILuminate and Credo, all extracted into `outputs/ibm_mappings` with the canonical id attached to each row, giving several independent cross-checks at once. Second, the pipeline-position tag, recording where each risk originates in the AI pipeline, a dimension no other source in the stack provides.

## 37. Integration and limitations

The pipeline-position tag folded into the register as the `ibm_pipeline_position` and `ibm_dimension` columns, populating the 45 canonical risks IBM exercises. Two areas are covered but thin, non-malicious computational inefficiency and agentic lifecycle maintenance, and were recorded rather than turned into risks. One limitation: the per-entry external cross-references in the cloned repository capture only the matched pairs, and a fuller both-sided version that also lists the no-match rows is staged in the scripts but was not regenerated. `ibm_extract.py`, `ibm_map.py` and `gen_ibm.py` reproduce the analysis and assert that every referenced canonical id exists.

---

# Part Six: The Cisco Integrated AI Security and Safety Framework as a coverage check

## 38. Purpose and source

The Cisco framework (December 2025) is the most detailed public catalogue of AI attacker techniques, and in particular of the agentic and Model Context Protocol threats that are newest and least settled. It served as a final coverage check, with specific attention to whether the single agentic risk (MR-071) and its MITRE ATLAS sub-risks adequately cover Cisco's agentic and MCP threats, and whether the supply-chain risks are complete. The source is the arXiv report (2512.12921) for the narrative and the group structures, and the Apache-2.0 canonical taxonomy published in Cisco's open `cisco-ai-defense` repositories for the machine-readable codes; both are reproduced verbatim under that licence.

## 39. Method

The hierarchy was loaded from the canonical taxonomy: 19 objectives, 40 techniques and 112 sub-techniques. Each sub-technique was mapped to a canonical risk or MITRE ATLAS sub-risk with a confidence and rationale, defaulting at the technique level and overriding where a sub-technique diverges, most notably the 25 harmful-content categories which split across the content-harm risks. Cisco's per-threat cross-references to MITRE ATLAS, NIST AI 100-2 and OWASP were sought but are not present in any static artifact: the open taxonomy ships its framework-mappings empty and the interactive portal is a JavaScript application that is not machine-readable. The cross-reference harvest was therefore taken at the framework level, from the report's coverage-comparison table.

## 40. Results: coverage, the agentic verdict, and supply chain

All 112 sub-techniques mapped (83 Clear, 27 Partial, 2 Weak, 0 No-match), exercising 27 canonical risks, and no new canonical risk was warranted. On the central question, MR-071 and its thirteen MITRE ATLAS technique sub-risks anchor Cisco's agentic threats (rogue-agent introduction, protocol manipulation, memory and profile persistence, delegated-authority abuse, trusted-agent spoofing), tool and MCP integration is carried by the insecure-integration risk (MR-020), and multi-agent injection by the prompt-injection risk (MR-010). The multi-agent-interaction risk (MR-057) proved complementary rather than duplicated: Cisco's entries are adversarial hijack and integration attacks, whereas MR-057 covers emergent coordination failure, a different risk. The verdict is that MR-071 is sufficient and needs no split, since the MCP protocol detail is attack-technique granularity rather than new deployer risk. Cisco's 22 supply-chain threat types distribute cleanly across MR-018 and its MITRE ATLAS sub-risks, the poisoning risk (MR-014), the insecure-code risk (MR-019) and the ISO procurement and version risks (MR-064, MR-065, MR-047).

## 41. Limitations and reproducibility

The two weakly-covered items are content-harm categories the register does not name distinctly, animal-abuse and environmental-harm content, which map to the general harmful-content risk and were left as is. The cross-reference harvest is framework-level only, for the reason above. `cisco_extract.py` builds the catalogue from the cloned taxonomy, `cisco_map.py` holds the authored mapping, and `gen_cisco.py` produces the six deliverables and asserts that every referenced canonical and MITRE ATLAS id exists. Because the Cisco pass confirmed coverage, it left the register unchanged.

---

# Part Seven: Four direct coverage checks (NIST AML, OWASP LLM, OWASP Agentic, NIST GenAI Profile)

## 42. Purpose and sources

This part runs four widely used external taxonomies through the same coverage-check lens as IBM and Cisco, mapping each entry one to one to the register and confirming whether anything is missing. The four are the NIST adversarial machine learning taxonomy (AI 100-2e2025, five attacker-goal categories and 23 leaf attacks across predictive and generative AI), the OWASP Top 10 for LLM Applications (2025, ten risks), the OWASP Top 10 for Agentic Applications (2026, ten risks) and the NIST Generative AI Profile (AI 600-1, twelve risks). They were chosen to stress three dimensions the earlier sources touch only partly: formal attack-level adversarial ML, the application-security view of LLM and agentic deployments, and the generative-AI harm catalogue. The exercise is deliberately risk-only. The mitigations and suggested actions that NIST AI 100-2 and the GenAI Profile also contain were not folded in, because this register is deliberately risk-only; the controls layer is out of scope.

## 43. Method

Each taxonomy was extracted from the source PDF the user supplied in `coverage-check`, including the NIST AML taxonomy index with its NISTAML identifiers and the two NIST and OWASP definition sets. Every entry was mapped to one or more canonical risks, and to a finer MITRE ATLAS sub-risk wherever the register goes deeper, with a confidence of Clear or Partial and a one-sentence rationale. Definitions are reproduced verbatim, since NIST documents are public-domain U.S. Government works and the OWASP documents are licensed CC BY-SA 4.0, with typographic normalisation only. A generator validates that every canonical and MITRE ATLAS identifier referenced exists in the register before it writes, then emits one matrix per framework, a register-anchored crosswalk across all eighty-two parents and an MITRE ATLAS sub-risk crosswalk.

## 44. Results

All sixty entries map to existing risks: fifty-seven Clear, three Partial, none unmatched, so no new canonical risk is warranted and the register is unchanged. Two register risks are anchored by all four frameworks, the general security and availability risk (MR-015) and the supply-chain risk (MR-018), and five more by three frameworks each, namely data leakage (MR-009), prompt injection (MR-010), insecure tool and API integration (MR-020), overreliance (MR-034) and autonomous-agent excessive agency (MR-071). That convergence on the technical and agentic core is strong external validation of the scoping. Two confirmations stand out. The OWASP agentic risk of cascading failures gives the multi-agent-interaction risk (MR-057) its first direct external anchor, settling the question left open by the Cisco check, where MR-057 was judged complementary to the MITRE ATLAS agent sub-risks. And the NIST adversarial ML taxonomy gives the register's security cluster rigorous attack-level backing, with evasion, poisoning and backdoors, model extraction, privacy-inference and prompt injection each receiving a home for every named attack. The four frameworks touch thirty-six of the eighty-two parents; the forty-six they do not touch are the governance, societal, labour, environmental and EU-compliance risks that sit outside an adversarial-ML or LLM-security remit, which is the expected shape for a register that is deliberately wider than any single external source.

## 45. Limitations and reproducibility

The three partial mappings are distributed coverage, not gaps. Training-data reconstruction (NISTAML.032) is carried by the data-leakage and privacy-inference risks; improper output handling (OWASP LLM05) is mapped to the insecure-integration risk as an integration-boundary failure; and vector and embedding weaknesses (OWASP LLM08) spread across the RAG-poisoning sub-risks and data leakage. In each case the register represents the underlying harm without a dedicated row, by design. `coverage_map.py` holds the four taxonomies, their verbatim definitions and the authored mapping, and `gen_coverage.py` produces the deliverables in `outputs/coverage_check` and asserts that every referenced identifier exists. Because all four checks confirmed coverage, they left the register unchanged.

## 46. The published crosswalks

The mapping work above is published in both directions. The forward crosswalk runs from each canonical risk outward to the framework items that touch it, and appears on every risk page and in the coverage matrix. The reverse crosswalk runs the other way, from each source framework's own entries back into the register, and is published as one table per framework covering all 531 entries across the ten frameworks. Publishing the reverse direction makes the register auditable from a reader's existing framework: a team that already works to ISO/IEC 42001, the EU AI Act, or MITRE ATLAS can start from a clause, article, or technique they know and see the canonical risk it corresponds to, rather than having to read the whole register to locate the overlap.

Each reverse-crosswalk row carries three fields beyond the entry itself. **Disposition** is either mapped, meaning the entry corresponds to one or more canonical risks, or out of scope, meaning the entry is accounted for but sits outside a deployer risk register. Out-of-scope entries are almost entirely MITRE ATLAS techniques: of the 170 MITRE ATLAS entries, 68 are attack-chain context such as reconnaissance and staging steps that describe how an adversary operates rather than a risk the deployer owns, and each records the reason in its note. **Confidence** is the mapping pass's own grade of how cleanly the entry matches, recorded as clear, partial, or weak where the pass graded it; for MITRE ATLAS the sub-risk and sub-risk-variant labels mark the two-tier technique decomposition rather than a strength grade. **Note** gives the basis for the mapping, or the reason an entry falls out of scope. These grades are the analysis's own assessment, published for transparency and to make each mapping contestable; they are not a claim that the source framework endorses the alignment. The same rows are offered as per-framework and combined CSV downloads, alongside an extended MITRE ATLAS map that adds each technique's tactics, mitigations, and case-study identifiers.
