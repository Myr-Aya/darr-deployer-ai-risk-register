"""Validator for the public Deployer AI Risk Register dataset.

Independent of the private build pipeline: checks only what this repository
holds, so anyone can run it and CI re-verifies every pull request from anyone.
Exits 1 on any failure.

    python validate.py

Checks: register structure and identity, CSV/JSON equivalence, crosswalk
integrity (forward and reverse agree), release-identity consistency across
CITATION.cff / release.json / README / dataset / .zenodo.json, publication
hygiene (no leaked paths or working files), and - in CI on pull requests -
that only approved public files are touched.
"""
import csv
import io
import json
import os
import re
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DATA = ROOT / "data"

FAMILIES = {
    "Model & system behaviour",
    "Data, privacy & content liability",
    "Security & adversarial",
    "Third party & supply chain",
    "Human & usage",
    "Governance & process",
    "Regulatory compliance",
}

CSV_HEADER = [
    "canonical_risk_id", "row_type", "name", "description", "risk_family",
    "mit_domain", "mit_subdomain", "ai_type", "scope_class", "source_standard",
    "source_frameworks", "source_count", "iso_references", "eu_ai_act_articles",
    "eu_cop_references", "nearest_mit_risk", "related_frameworks",
    "parent_risk_id", "atlas_technique_id", "atlas_technique_name",
]

RCW_COLS = ["framework", "framework_name", "entry_id", "entry_name",
            "entry_description", "disposition", "register_ids",
            "register_names", "confidence", "note"]

results = {"pass": 0, "fail": [], "warn": []}


def check(cond, name, detail=""):
    if cond:
        results["pass"] += 1
    else:
        results["fail"].append(name + (f" :: {detail}" if detail else ""))


def warn(cond, name, detail=""):
    if cond:
        results["pass"] += 1
    else:
        results["warn"].append(name + (f" :: {detail}" if detail else ""))


def jload(name):
    return json.loads((DATA / name).read_text("utf-8"))


def read_csv(path):
    return list(csv.DictReader(io.StringIO(path.read_text("utf-8-sig"))))


def join_list(v):
    return " | ".join(v)


def main():
    risks = jload("risks.json")
    subs = jload("subrisks.json")
    stats = jload("stats.json")
    cw = jload("crosswalk.json")
    rcw = jload("reverse_crosswalks.json")
    nested = jload("darr-deployer-ai-risk-register.json")
    rows = read_csv(DATA / "darr-deployer-ai-risk-register.csv")

    rby = {r["id"]: r for r in risks}
    sby = {s["id"]: s for s in subs}
    risk_ids, sub_ids = set(rby), set(sby)

    # ---- A. register structure ------------------------------------------------
    check(len(risks) == 82, "A1 risks.json holds 82 risks", f"got {len(risks)}")
    check([r["id"] for r in risks] == [f"MR-{i:03d}" for i in range(1, 83)],
          "A2 canonical IDs are MR-001..MR-082, unique and sequential")
    for f in ("name", "description", "family", "ai_type", "scope_class", "source_standard"):
        missing = [r["id"] for r in risks if not str(r.get(f, "")).strip()]
        check(not missing, f"A3 required field '{f}' present on every risk", str(missing[:5]))
    check(not ({r["family"] for r in risks} - FAMILIES),
          "A4 families restricted to the seven known values")
    check(len(subs) == 61, "A5 subrisks.json holds 61 sub-risks", f"got {len(subs)}")
    badpar = [s["id"] for s in subs if s["parent_id"] not in risk_ids]
    check(not badpar, "A6 every sub-risk parent exists", str(badpar[:5]))
    badform = [s["id"] for s in subs
               if not re.fullmatch(re.escape(s["parent_id"]) + r"\.\d+", s["id"])]
    check(not badform, "A7 sub-risk IDs are <parent>.<n>", str(badform[:5]))
    bypar = defaultdict(list)
    for s in subs:
        bypar[s["parent_id"]].append(int(s["id"].rsplit(".", 1)[1]))
    gaps = {p: sorted(v) for p, v in bypar.items() if sorted(v) != list(range(1, len(v) + 1))}
    check(not gaps, "A8 sub-risk numbering is gapless 1..k per parent", str(gaps))
    for r in risks:
        declared = r.get("subrisk_ids") or []
        actual = sorted((s["id"] for s in subs if s["parent_id"] == r["id"]),
                        key=lambda x: int(x.rsplit(".", 1)[1]))
        check(declared == actual, f"A9 {r['id']} subrisk_ids match actual children")
    missing_atlas = [s["id"] for s in subs
                     if not s["atlas_technique_id"].strip() or not s["atlas_technique_name"].strip()]
    check(not missing_atlas, "A10 every sub-risk carries a MITRE ATLAS technique id and name",
          str(missing_atlas[:5]))

    # ---- B. CSV / JSON equivalence ---------------------------------------------
    check(list(rows[0].keys()) == CSV_HEADER, "B1 flat CSV header exact")
    crisk = [r for r in rows if r["row_type"] == "Risk"]
    csub = [r for r in rows if r["row_type"] == "Sub-risk"]
    check(len(rows) == 143 and len(crisk) == 82 and len(csub) == 61,
          "B2 flat CSV is 143 rows: 82 Risk + 61 Sub-risk",
          f"rows={len(rows)} risk={len(crisk)} sub={len(csub)}")
    fieldmap = [
        ("name", "name"), ("description", "description"), ("family", "risk_family"),
        ("mit_domain", "mit_domain"), ("mit_subdomain", "mit_subdomain"),
        ("ai_type", "ai_type"), ("scope_class", "scope_class"),
        ("source_standard", "source_standard"), ("iso_references", "iso_references"),
        ("nearest_mit_risk", "nearest_mit_risk"),
    ]
    listmap = [("source_frameworks", "source_frameworks"), ("frameworks", "related_frameworks"),
               ("eu_ai_act_articles", "eu_ai_act_articles"), ("eu_cop_references", "eu_cop_references")]
    mism = []
    for c in crisk:
        r = rby.get(c["canonical_risk_id"])
        if r is None:
            mism.append(f"{c['canonical_risk_id']} not in risks.json")
            continue
        for jf, cf in fieldmap:
            if (str(r.get(jf) or "")) != (c[cf] or ""):
                mism.append(f"{r['id']}.{cf}")
        for jf, cf in listmap:
            if join_list(r.get(jf) or []) != (c[cf] or ""):
                mism.append(f"{r['id']}.{cf}")
        if str(r.get("source_count", "")) != (c["source_count"] or ""):
            mism.append(f"{r['id']}.source_count")
    check(not mism, "B3 CSV risk rows are field-equivalent to risks.json", str(mism[:5]))
    mism = []
    for c in csub:
        s = sby.get(c["canonical_risk_id"])
        if s is None:
            mism.append(f"{c['canonical_risk_id']} not in subrisks.json")
            continue
        for jf, cf in [("name", "name"), ("description", "description"),
                       ("parent_id", "parent_risk_id"),
                       ("atlas_technique_id", "atlas_technique_id"),
                       ("atlas_technique_name", "atlas_technique_name")]:
            if (s.get(jf) or "") != (c[cf] or ""):
                mism.append(f"{s['id']}.{cf}")
    check(not mism, "B4 CSV sub-risk rows are field-equivalent to subrisks.json", str(mism[:5]))
    nrisks = nested["risks"]
    check(len(nrisks) == 82, "B5 nested register holds 82 risks")
    mism = [nr["id"] for nr in nrisks
            if {k: v for k, v in nr.items() if k != "subrisks"} != rby.get(nr["id"])
            or (nr.get("subrisks") or []) != [sby[i] for i in (nr.get("subrisk_ids") or [])]]
    check(not mism, "B6 nested risks equal risks.json/subrisks.json", str(mism[:5]))
    check(nested["counts"] == {"risks": 82, "subrisks": 61, "register_rows": 143},
          "B7 nested counts block correct")
    src = defaultdict(int)
    for r in risks:
        ss = r["source_standard"]
        key = ("atlas" if ss.startswith("MITRE ATLAS") else
               "mit" if ss.startswith("MIT") else
               "iso" if ss.startswith("ISO") else
               "eu" if ss.startswith(("EU", "GPAI")) else "other")
        src[key] += 1
    check(stats["risks"] == 82 and stats["subrisks"] == 61 and stats["register_rows"] == 143
          and stats["risks_mit"] == src["mit"] and stats["risks_iso"] == src["iso"]
          and stats["risks_atlas"] == src["atlas"] and stats["risks_eu"] == src["eu"]
          and src["other"] == 0,
          "B8 stats.json equals recomputed counts", f"stats={stats} recomputed={dict(src)}")

    # ---- C. crosswalk integrity -------------------------------------------------
    fw_ids = {f["id"] for f in cw["frameworks"]}
    item_ids = {fid: {it["id"] for it in lst} for fid, lst in cw["items"].items()}
    check(set(cw["items"]) == fw_ids, "C1 crosswalk items keyed by known frameworks")
    badmap = []
    for rid, lst in cw["map"].items():
        if rid not in risk_ids:
            badmap.append(f"unknown risk {rid}")
        for m in lst:
            if m["fw"] not in fw_ids or m["item"] not in item_ids.get(m["fw"], ()):
                badmap.append(f"{rid}:{m['fw']}/{m['item']}")
            if m["m"] not in ("clear", "partial", "sub"):
                badmap.append(f"{rid}: strength {m['m']}")
    check(not badmap, "C2 forward map references valid risks, frameworks, items, strengths",
          str(badmap[:5]))
    for f in cw["frameworks"]:
        check(f["item_count"] == len(cw["items"][f["id"]]), f"C3 {f['id']} item_count honest")
        mapped = {rid for rid, lst in cw["map"].items() if any(m["fw"] == f["id"] for m in lst)}
        check(f["mapped_risk_count"] == len(mapped), f"C4 {f['id']} mapped_risk_count honest")
    fwd_n = sum(len(v) for v in cw["map"].values())
    cw_rows = read_csv(DATA / "crosswalk.csv")
    check(len(cw_rows) == fwd_n == 674, "C5 crosswalk.csv rows equal forward mappings (674)",
          f"csv={len(cw_rows)} json={fwd_n}")
    total, disp_bad, id_bad = 0, [], []
    for fid, blk in rcw.items():
        total += len(blk["rows"])
        check(blk["count"] == len(blk["rows"]), f"C6 {fid} reverse count honest")
        for row in blk["rows"]:
            if row["disposition"] not in ("Mapped", "Out of scope"):
                disp_bad.append(f"{fid}/{row['entry_id']}")
            toks = [t.strip() for t in row["register_ids"].split("|") if t.strip()]
            if row["disposition"] == "Mapped" and not toks:
                id_bad.append(f"{fid}/{row['entry_id']}: no ids")
            for t in toks:
                if t not in risk_ids and t not in sub_ids:
                    id_bad.append(f"{fid}/{row['entry_id']}: {t}")
    check(not disp_bad, "C7 reverse dispositions restricted to Mapped / Out of scope",
          str(disp_bad[:5]))
    check(not id_bad, "C8 reverse register_ids resolve to risks or sub-risks", str(id_bad[:5]))
    check(total == 531, "C9 reverse crosswalk covers 531 framework entries", f"got {total}")
    all_rows = read_csv(DATA / "reverse_crosswalks_all.csv")
    check(list(all_rows[0].keys()) == RCW_COLS and len(all_rows) == 531,
          "C10 reverse_crosswalks_all.csv matches the JSON (531 rows, exact columns)")
    per = 0
    for fid, blk in rcw.items():
        p = DATA / "crosswalks" / f"{fid}_reverse_crosswalk.csv"
        if not p.exists():
            check(False, f"C11 per-framework CSV present for {fid}")
            continue
        per += len(read_csv(p))
    check(per == 531, "C11 per-framework CSVs sum to 531 rows", f"got {per}")
    sub2par = {s["id"]: s["parent_id"] for s in subs}
    fwd = {(m["fw"], m["item"], rid) for rid, lst in cw["map"].items() for m in lst}
    revn = {(fid, row["entry_id"], sub2par.get(t, t))
            for fid, blk in rcw.items() for row in blk["rows"]
            for t in [t.strip() for t in row["register_ids"].split("|") if t.strip()]}
    check(fwd == revn, "C12 forward and reverse mappings agree (sub-risks to parents)",
          f"fwd-only {len(fwd - revn)}, rev-only {len(revn - fwd)}")

    # ---- D. release identity ------------------------------------------------------
    rel = json.loads((ROOT / "release.json").read_text("utf-8")) if (ROOT / "release.json").exists() else None
    check(rel is not None, "D1 release.json present")
    if rel:
        y, m, d = rel["release_date"].split("-")
        months = ("January", "February", "March", "April", "May", "June", "July",
                  "August", "September", "October", "November", "December")
        hdate = f"{int(d)} {months[int(m) - 1]} {y}"
        cff = (ROOT / "CITATION.cff").read_text("utf-8")
        cffm = dict(re.findall(r'^(version|doi|date-released):\s*"?([^"\n]+?)"?\s*$', cff, re.M))
        check(cffm.get("version") == rel["version"] and cffm.get("doi") == rel["doi"]
              and cffm.get("date-released") == rel["release_date"],
              "D2 CITATION.cff identity equals release.json", str(cffm))
        check(nested.get("version") == rel["version"] and nested.get("doi") == rel["doi"]
              and nested.get("date") == hdate,
              "D3 dataset register identity equals release.json")
        readme_flat = " ".join((ROOT / "README.md").read_text("utf-8").split())
        check(rel["doi"] in readme_flat
              and f"Version {rel['version']}, {hdate}" in readme_flat,
              "D4 README citation carries the release version, date, and DOI")
        zp = ROOT / ".zenodo.json"
        check(zp.exists(), "D5 .zenodo.json present")
        if zp.exists():
            zen = json.loads(zp.read_text("utf-8"))
            check(zen.get("version") == rel["version"]
                  and zen.get("publication_date") == rel["release_date"]
                  and zen.get("upload_type") == "dataset"
                  and zen.get("license") == rel["license_spdx"].lower(),
                  "D6 .zenodo.json identity equals release.json (dataset typing)")

    # ---- E. publication hygiene ------------------------------------------------
    tracked = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True,
                             text=True).stdout.split()
    ok_ext = {".md", ".csv", ".json", ".cff", ".yml", ".yaml", ".py", ".gitattributes"}
    bad = [t for t in tracked
           if Path(t).suffix not in ok_ext and Path(t).name not in ("LICENSE", ".gitattributes")]
    bad += [t for t in tracked if Path(t).suffix == ".py" and t != "validate.py"]
    check(not bad, "E1 only approved file types tracked (no working or source files)",
          str(bad[:5]))
    leak_pat = [
        (re.compile(r"[A-Za-z]:[\\/]Users[\\/]", re.I), "local path"),
        (re.compile(r"AppData[\\/]", re.I), "profile path"),
        (re.compile(r"ghp_[A-Za-z0-9]{36}"), "GitHub token"),
        (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS key"),
        (re.compile(r"sk-[A-Za-z0-9]{32,}"), "secret key"),
    ]
    hits = []
    for t in tracked:
        if Path(t).suffix in {".md", ".csv", ".json", ".cff", ".yml", ".yaml", ".py"}:
            text = (ROOT / t).read_text("utf-8", errors="replace")
            for pat, label in leak_pat:
                if pat.search(text) and t != "validate.py":
                    hits.append(f"{t}: {label}")
    check(not hits, "E2 no local paths or credential-like strings", str(hits[:5]))
    meth = (DATA / "methodology.md").read_text("utf-8")
    check("mit_entries" not in meth,
          "E3 public methodology carries the public variant (no mit_entries reference)")
    bare = []
    for t in tracked:
        if t.startswith("data/") and Path(t).suffix in {".csv", ".json", ".md"}:
            if re.search(r"(?<!MITRE )ATLAS-derived",
                         (ROOT / t).read_text("utf-8", errors="replace")):
                bare.append(t)
    check(not bare, "E4 'ATLAS-derived' always reads 'MITRE ATLAS-derived'", str(bare[:5]))
    readme = (ROOT / "README.md").read_text("utf-8")
    # ../ links are GitHub-web navigation (issues, labels), not repo files.
    misslink = [m for m in re.findall(r"\]\(((?!https?://|#|\.\./)[^)]+)\)", readme)
                if not (ROOT / m.split("#")[0]).exists()]
    check(not misslink, "E5 README relative links resolve to files in this repo",
          str(misslink[:5]))

    # ---- F. pull-request scope (CI only) -----------------------------------------
    base = os.environ.get("GITHUB_BASE_REF")
    if base:
        r = subprocess.run(["git", "diff", "--name-only", f"origin/{base}...HEAD"],
                           cwd=ROOT, capture_output=True, text=True)
        changed = [c for c in r.stdout.split() if c]
        known = set(subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True,
                                   text=True).stdout.split())
        new = [c for c in changed if c not in known and not c.startswith(".github/")]
        check(not new, "F1 pull request introduces no unapproved new files",
              str(new[:5]))

    # ---- report -------------------------------------------------------------------
    print(f"PASS  {results['pass']} checks")
    for w in results["warn"]:
        print(f"WARN  {w}")
    for f in results["fail"]:
        print(f"FAIL  {f}")
    if results["fail"]:
        print(f"\nvalidate: {len(results['fail'])} failure(s).")
        sys.exit(1)
    print("validate: all checks passed.")


if __name__ == "__main__":
    main()
