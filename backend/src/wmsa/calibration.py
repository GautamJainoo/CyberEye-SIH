"""
Calibration Engine for WMSA.
Evaluates scanner precision and recall strictly against labelled calibration fixtures
without contaminating or conflating with live target findings.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from wmsa.adapters.base import CandidateFinding


class CalibrationEvaluator:
    """Computes precision and recall against labelled planted issues."""

    def __init__(self, ground_truth_file: Optional[Path] = None):
        self.ground_truth_file = ground_truth_file

    def load_ground_truth(self, path: Optional[Path] = None) -> Dict[str, Any]:
        target = path or self.ground_truth_file
        if not target or not target.exists():
            raise FileNotFoundError(f"Calibration ground truth file not found: {target}")
        with open(target, "r", encoding="utf-8") as fp:
            return json.load(fp)

    def evaluate(
        self,
        detected_findings: List[CandidateFinding],
        ground_truth: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        gt = ground_truth or self.load_ground_truth()
        planted_issues = gt.get("planted_issues", [])
        clean_controls = gt.get("planted_clean_controls", [])

        tp = []
        fn = []
        fp = []

        matched_planted_ids = set()

        for cand in detected_findings:
            matched_issue = None
            for p in planted_issues:
                # Match by category and file or package
                cat_match = cand.category == p.get("category")
                file_match = cand.file and p.get("file") and p.get("file") in cand.file
                pkg_match = cand.package and p.get("package") and cand.package == p.get("package")
                cwe_match = any(c in p.get("rule_or_cwe", "") for c in cand.cwe) or (cand.rule_id and p.get("rule_or_cwe") in cand.rule_id)
                cve_match = any(c in p.get("rule_or_cwe", "") for c in cand.cve)

                if cat_match and (file_match or pkg_match or cwe_match or cve_match):
                    matched_issue = p
                    break

            if matched_issue:
                matched_planted_ids.add(matched_issue["id"])
                tp.append({
                    "planted_id": matched_issue["id"],
                    "category": cand.category,
                    "title": cand.title,
                    "tool": cand.tool,
                    "file": cand.file,
                })
            else:
                fp.append({
                    "category": cand.category,
                    "title": cand.title,
                    "tool": cand.tool,
                    "file": cand.file,
                })

        for p in planted_issues:
            if p["id"] not in matched_planted_ids:
                fn.append(p)

        tp_count = len(tp)
        fp_count = len(fp)
        fn_count = len(fn)
        tn_count = len(clean_controls)

        precision_den = tp_count + fp_count
        precision_pct = (tp_count / precision_den * 100.0) if precision_den > 0 else 100.0

        recall_den = tp_count + fn_count
        recall_pct = (tp_count / recall_den * 100.0) if recall_den > 0 else 100.0

        return {
            "fixture": "calibration-fixture-v1",
            "total_planted_issues": len(planted_issues),
            "true_positives": {
                "count": tp_count,
                "items": tp,
            },
            "false_positives": {
                "count": fp_count,
                "items": fp,
            },
            "false_negatives": {
                "count": fn_count,
                "items": fn,
            },
            "true_negatives": {
                "count": tn_count,
                "controls": clean_controls,
            },
            "metrics": {
                "precision": {
                    "numerator": tp_count,
                    "denominator": precision_den,
                    "fraction": f"{tp_count}/{precision_den}",
                    "percentage": round(precision_pct, 2),
                },
                "recall": {
                    "numerator": tp_count,
                    "denominator": recall_den,
                    "fraction": f"{tp_count}/{recall_den}",
                    "percentage": round(recall_pct, 2),
                },
            },
        }
