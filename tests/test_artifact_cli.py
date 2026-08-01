from __future__ import annotations

import csv
import os
from pathlib import Path
import re
import subprocess
import sys
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "bin/lbo-artifact"
VERIFIERS = ROOT / "scripts/verifiers"
if str(VERIFIERS) not in sys.path:
    sys.path.insert(0, str(VERIFIERS))

from t3_del1 import boolean_field


def run_cli(*args: str, columns: int | None = None):
    environment = os.environ.copy()
    if columns is not None:
        environment["COLUMNS"] = str(columns)
    return subprocess.run(
        [str(CLI), *args],
        cwd=ROOT,
        capture_output=True,
        text=True,
        env=environment,
        check=False,
        timeout=300,
    )


class ArtifactCliTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cells = yaml.safe_load(
            (ROOT / "manifest/cells.yaml").read_text(encoding="utf-8")
        )["cells"]
        cls.evidence = yaml.safe_load(
            (ROOT / "manifest/evidence.yaml").read_text(encoding="utf-8")
        )["cases"]
        cls.by_id = {cell["id"]: cell for cell in cls.cells}

    def test_tshark_boolean_field_compatibility(self):
        for value in ("True", "true", "1", "Set", "yes"):
            self.assertTrue(boolean_field(value))
        for value in ("False", "false", "0", "Not Set", "no", ""):
            self.assertFalse(boolean_field(value))

    def test_current_twenty_cell_model(self):
        expected = {
            f"T{surface}-{mutation}"
            for surface in range(1, 5)
            for mutation in ("MOD", "INS", "DEL", "DUP", "SEQ")
        }
        self.assertEqual(set(self.by_id), expected)
        self.assertEqual(len(self.cells), 20)
        self.assertEqual(sum(c["native_scenario_count"] for c in self.cells), 232)
        self.assertEqual(sum(c["status"] == "E2E" for c in self.cells), 19)
        self.assertEqual(self.by_id["T1-INS"]["status"], "N/A")
        representatives = {
            c["representative_id"] for c in self.cells if c["status"] == "E2E"
        }
        self.assertEqual(len(representatives), 19)
        self.assertTrue(all(
            re.fullmatch(r"T[1-4]-(MOD|INS|DEL|DUP|SEQ)1", value)
            for value in representatives
        ))

    def test_current_evidence_and_attack_layout(self):
        representatives = {
            c["representative_id"] for c in self.cells if c["status"] == "E2E"
        }
        self.assertEqual(set(self.evidence), set(self.by_id) - {"T1-INS"})
        self.assertEqual(
            {path.name for path in (ROOT / "evidence").iterdir() if path.is_dir()},
            representatives,
        )
        self.assertEqual(
            {path.name for path in (ROOT / "attacks").iterdir() if path.is_dir()},
            representatives,
        )
        for config in self.evidence.values():
            directory = ROOT / config["path"]
            self.assertTrue((directory / "SHA256SUMS").is_file())
            self.assertTrue((directory / config["result"]).is_file())

    def test_only_reviewer_commands_are_public(self):
        result = run_cli("--help")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("{demo,verify,doctor}", result.stdout)
        for removed in ("overview", "list", "trace", "defense", "explain"):
            self.assertNotIn(removed, result.stdout)

    def test_doctor_reports_paper_counts_and_tshark(self):
        result = run_cli("doctor")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("TShark >= 3.6", result.stdout)
        self.assertRegex(result.stdout, r"cells\s+PASS\s+20")
        self.assertRegex(result.stdout, r"runnable cells\s+PASS\s+19")
        self.assertRegex(result.stdout, r"native scenarios\s+PASS\s+232")
        self.assertRegex(
            result.stdout,
            r"all-field dataset\s+PASS\s+2280 rows; English-only=yes",
        )
        self.assertRegex(
            result.stdout,
            r"scenario dataset\s+PASS\s+232 rows; English-only=yes",
        )

    def test_public_analysis_tables_are_complete_and_english_only(self):
        expected = {
            "all_field_positions_2280.csv": 2280,
            "charging_relevant_fields_2050.csv": 2050,
            "consistency_constraints_81.csv": 81,
            "threat_scenarios_232.csv": 232,
            "derivation_crosswalk.csv": 2050,
        }
        loaded = {}
        for filename, expected_rows in expected.items():
            with self.subTest(filename=filename):
                with (ROOT / "analysis" / filename).open(
                    encoding="utf-8", newline=""
                ) as stream:
                    rows = list(csv.DictReader(stream))
                self.assertEqual(len(rows), expected_rows)
                self.assertFalse(any(
                    re.search(r"[\uac00-\ud7a3]", value or "")
                    for row in rows
                    for value in row.values()
                ))
                loaded[filename] = rows

        all_ids = {
            row["field_position_id"]
            for row in loaded["all_field_positions_2280.csv"]
        }
        relevant_ids = {
            row["field_position_id"]
            for row in loaded["charging_relevant_fields_2050.csv"]
        }
        crosswalk_ids = {
            row["field_position_id"]
            for row in loaded["derivation_crosswalk.csv"]
        }
        self.assertTrue(relevant_ids < all_ids)
        self.assertEqual(crosswalk_ids, relevant_ids)

    def test_readme_uses_current_anonymous_repository_and_video(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("https://github.com/5g-lbo-tee/charging-artifact.git", readme)
        self.assertIn("https://youtu.be/n1MCp5k2rZ8", readme)
        self.assertNotIn("assets/artifact-overview-t3-mod1.png", readme)
        self.assertFalse((ROOT / "assets/artifact-overview-t3-mod1.png").exists())
        self.assertIn("assets/t3-mod1-attack-demo.gif", readme)
        self.assertGreater(
            (ROOT / "assets/t3-mod1-attack-demo.gif").stat().st_size,
            100_000,
        )
        self.assertIn("## Live demo video", readme)
        self.assertIn("doubles the reported usage", readme)
        self.assertIn("TEE-based defense", readme)
        self.assertNotIn("anonymoussubmission3197", readme)

    def test_public_authored_text_contains_no_hangul(self):
        text_suffixes = {".csv", ".json", ".md", ".patch", ".py", ".txt", ".yaml"}
        for path in ROOT.rglob("*"):
            if (
                not path.is_file()
                or ".git" in path.parts
                or path.suffix.lower() not in text_suffixes
            ):
                continue
            with self.subTest(path=path.relative_to(ROOT)):
                content = path.read_text(encoding="utf-8")
                self.assertIsNone(re.search(r"[\uac00-\ud7a3]", content))

    def test_four_step_demo_remains_reviewer_readable(self):
        for representative in ("T2-MOD1", "T3-MOD1", "T4-MOD1", "T4-SEQ1"):
            with self.subTest(representative=representative):
                result = run_cli(
                    "demo", representative, "--non-interactive", columns=140
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn(f"SELECTED ATTACK {representative}", result.stdout)
                for step in range(1, 5):
                    self.assertIn(f"STEP {step}/4", result.stdout)
                self.assertIn("BENIGN", result.stdout)
                self.assertIn("ATTACK", result.stdout)
                self.assertIn(
                    f"wireshark pcaps/{representative}_pfcp.pcap",
                    result.stdout,
                )
                self.assertIn(
                    f"wireshark pcaps/{representative}_gy.pcap",
                    result.stdout,
                )
                self.assertNotIn("GUIDED DEMO COMPLETE", result.stdout)
                self.assertNotIn("trace case", result.stdout)

    def test_updated_t1_and_t4_results_are_presented_consistently(self):
        t1 = run_cli("demo", "T1-MOD1", "--non-interactive", columns=140)
        self.assertEqual(t1.returncode, 0, t1.stderr)
        self.assertIn("22 -> 220 cents", t1.stdout)
        self.assertIn("16,049,952-byte PFCP usage", t1.stdout)
        self.assertNotIn("7 -> 70 cents", t1.stdout)

        t4 = run_cli("demo", "T4-MOD1", "--non-interactive", columns=140)
        self.assertEqual(t4.returncode, 0, t4.stderr)
        self.assertIn("63,149,076 B charged / UL x5", t4.stdout)
        self.assertIn("27 -> 69 cents", t4.stdout)
        self.assertIn("21.05 to 63.15 MB", t4.stdout)
        self.assertNotIn("27 -> 58 cents", t4.stdout)

    def test_verify_all_passes_nineteen_and_marks_na(self):
        result = run_cli("verify", "--all")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(
            "Summary: 19/19 runnable PASS; T1-INS N/A (0 scenarios)",
            result.stdout,
        )

    def test_root_readme_is_the_only_readme(self):
        readmes = [
            path for path in ROOT.rglob("README*") if ".git" not in path.parts
        ]
        self.assertEqual(readmes, [ROOT / "README.md"])
        self.assertEqual(
            {path.name for path in (ROOT / "manifest").iterdir()},
            {"cells.yaml", "evidence.yaml", "message_scope.yaml"},
        )


if __name__ == "__main__":
    unittest.main()
