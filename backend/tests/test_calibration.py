from pathlib import Path
import pytest

from wmsa.adapters.base import CandidateFinding
from wmsa.calibration import CalibrationEvaluator


@pytest.fixture
def calibration_fixture_dir():
    return Path(__file__).parent / "fixtures" / "calibration"


@pytest.fixture
def evaluator(calibration_fixture_dir):
    gt_file = calibration_fixture_dir / "ground_truth.json"
    return CalibrationEvaluator(ground_truth_file=gt_file)


def test_calibration_perfect_detection(evaluator):
    # Simulate perfect detection of all 4 planted issues
    findings = [
        CandidateFinding(
            title="DOM XSS via innerHTML",
            category="sast",
            status="CANDIDATE",
            severity="HIGH",
            repo="calibration-repo",
            commit_sha="00000000",
            build_id="calib-b1",
            scope_id="calib-s1",
            tool="semgrep",
            tool_version="1.176.0",
            rule_id="generic.xss.dom",
            file="src/app.js",
            line_start=8,
            line_end=8,
            cwe=["CWE-79"],
            description="Planted DOM XSS",
        ),
        CandidateFinding(
            title="GitHub Personal Access Token",
            category="secret",
            status="CANDIDATE",
            severity="CRITICAL",
            repo="calibration-repo",
            commit_sha="00000000",
            build_id="calib-b1",
            scope_id="calib-s1",
            tool="gitleaks",
            tool_version="8.30.1",
            rule_id="github-pat",
            file="config/secrets.env",
            line_start=5,
            line_end=5,
            description="Planted GitHub PAT",
        ),
        CandidateFinding(
            title="Command Injection in lodash",
            category="sca",
            status="CANDIDATE",
            severity="HIGH",
            repo="calibration-repo",
            commit_sha="00000000",
            build_id="calib-b1",
            scope_id="calib-s1",
            tool="osv-scanner",
            tool_version="2.6.0",
            rule_id="GHSA-35jh-r3h4-6jhm",
            package="lodash",
            package_version="4.17.15",
            file="package-lock.json",
            cve=["CVE-2021-23337"],
            description="Known vulnerable lodash version",
        ),
        CandidateFinding(
            title="RSS Proxy SSRF",
            category="dast_io",
            status="CANDIDATE",
            severity="HIGH",
            repo="calibration-repo",
            commit_sha="00000000",
            build_id="calib-b1",
            scope_id="calib-s1",
            tool="worldmonitor-probes",
            tool_version="1.0.0",
            rule_id="wm-probe-ssrf-01",
            file="api/rss-proxy.js",
            cwe=["CWE-918"],
            description="Planted SSRF probe finding",
        ),
    ]

    report = evaluator.evaluate(findings)

    assert report["true_positives"]["count"] == 4
    assert report["false_positives"]["count"] == 0
    assert report["false_negatives"]["count"] == 0
    assert report["true_negatives"]["count"] == 2

    # Precision: 4/4 (100%)
    prec = report["metrics"]["precision"]
    assert prec["numerator"] == 4
    assert prec["denominator"] == 4
    assert prec["fraction"] == "4/4"
    assert prec["percentage"] == 100.0

    # Recall: 4/4 (100%)
    rec = report["metrics"]["recall"]
    assert rec["numerator"] == 4
    assert rec["denominator"] == 4
    assert rec["fraction"] == "4/4"
    assert rec["percentage"] == 100.0


def test_calibration_with_miss_and_false_positive(evaluator):
    # Simulate missing SCA (FN=1) and having an extra false alarm (FP=1)
    findings = [
        CandidateFinding(
            title="DOM XSS via innerHTML",
            category="sast",
            status="CANDIDATE",
            severity="HIGH",
            repo="calibration-repo",
            commit_sha="00000000",
            build_id="calib-b1",
            scope_id="calib-s1",
            tool="semgrep",
            tool_version="1.176.0",
            rule_id="generic.xss.dom",
            file="src/app.js",
            line_start=8,
            line_end=8,
            cwe=["CWE-79"],
            description="Planted DOM XSS",
        ),
        CandidateFinding(
            title="Spurious alert on clean file",
            category="sast",
            status="CANDIDATE",
            severity="LOW",
            repo="calibration-repo",
            commit_sha="00000000",
            build_id="calib-b1",
            scope_id="calib-s1",
            tool="semgrep",
            tool_version="1.176.0",
            rule_id="spurious-rule",
            file="src/other.js",
            description="False positive",
        ),
    ]

    report = evaluator.evaluate(findings)

    # 1 TP (XSS), 1 FP (other.js), 3 FN (secret, sca, probe)
    assert report["true_positives"]["count"] == 1
    assert report["false_positives"]["count"] == 1
    assert report["false_negatives"]["count"] == 3

    # Precision: 1 / (1 + 1) = 50.0%
    prec = report["metrics"]["precision"]
    assert prec["fraction"] == "1/2"
    assert prec["percentage"] == 50.0

    # Recall: 1 / (1 + 3) = 25.0%
    rec = report["metrics"]["recall"]
    assert rec["fraction"] == "1/4"
    assert rec["percentage"] == 25.0
