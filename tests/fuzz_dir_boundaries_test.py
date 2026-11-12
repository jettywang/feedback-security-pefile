"""Regression tests for the directory-boundary fuzzing harness.

The heavy lifting lives in fuzz_dir_boundaries.py; these tests make the
corpus a regression suite: the intact pefile must parse the whole corpus
without failures, and deliberately broken bounds checks must be caught.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import fuzz_dir_boundaries as fdb


def test_intact_pefile_parses_corpus_without_failures(tmp_path):
    results = fdb.run_corpus(
        fdb.pefile, fdb.enumerated_cases(), artifacts_dir=tmp_path
    )
    summary = fdb.summarize_results(results)
    assert summary["unstable"] == []
    assert summary["failures"] == []
    # every case must reach all three directory parsers
    for case, _data, _layout, result in results:
        assert {"export", "import", "reloc"} <= set(result.reached), case.case_id


def test_seeded_random_cases_are_stable(tmp_path):
    cases = fdb.random_cases(seed=20261112, count=25)
    results = fdb.run_corpus(fdb.pefile, cases, artifacts_dir=tmp_path)
    summary = fdb.summarize_results(results)
    assert summary["unstable"] == []
    assert summary["failures"] == []


def test_deliberately_broken_bounds_checks_are_caught(tmp_path):
    outcome = fdb.selftest(artifacts_dir=tmp_path)
    assert outcome["intact_failures"] == []
    for name, info in outcome["breaks"].items():
        assert info["caught"], f"broken bounds check '{name}' was not caught"
        # caught failures must come with a readable layout artifact
        for case_id in info["caught_by"][:1]:
            layout = tmp_path / f"broken-{name}" / f"case-{case_id}" / "layout.txt"
            assert layout.exists()
            text = layout.read_text()
            assert "== Data directories" in text
            assert "== Directory layout" in text
