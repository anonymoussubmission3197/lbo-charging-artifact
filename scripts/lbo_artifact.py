#!/usr/bin/env python3
"""Reviewer-facing browser and offline verifier for the LBO artifact."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import textwrap
from typing import Any

import yaml

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "manifest"
ANALYSIS = ROOT / "analysis"
VERIFIER_DIR = SCRIPT_DIR / "verifiers"
if str(VERIFIER_DIR) not in sys.path:
    sys.path.insert(0, str(VERIFIER_DIR))

from t3_mod1 import (
    PairError,
    accepted_cca_updates,
    accepted_pfcp_responses,
    charge as live_charge,
    gy_usage as live_gy_usage,
    packet_count as live_packet_count,
    pfcp_usage as live_pfcp_usage,
    trace_usage as live_trace_usage,
)
from t4_mod1 import (
    clean_release as t4_clean_release,
    gy_session as t4_gy_session,
    gy_usage as t4_live_gy_usage,
    pfcp_usage as t4_live_pfcp_usage,
    terminal_pfcp_usage as t4_terminal_pfcp_usage,
    trace_usage as t4_live_trace_usage,
)
from t4_dup1 import (
    cca_result_groups as t4_2_cca_result_groups,
    gy_usage_groups as t4_2_gy_usage_groups,
)
from t4_seq1 import (
    aggregate as t4_3_aggregate,
    ccr_updates as t4_3_ccr_updates,
    replay_pairs as t4_3_replay_pairs,
)
from t1_mod1 import (
    application_flow as t1_application_flow,
    experiment_values as t1_experiment_values,
    gy_file_identity as t1_gy_file_identity,
    icmp_noise as t1_icmp_noise,
    n7_frame_5qi as t1_n7_frame_5qi,
    pfcp_file_usage as t1_pfcp_file_usage,
    workload as t1_workload,
)
from t2_ins1 import (
    aggregate_streams as t2_aggregate_streams,
    established_urrs as t2_established_urrs,
    gy_update_aggregate as t2_gy_update_aggregate,
    pfcp_usage_by_urr as t2_pfcp_usage_by_urr,
    successful_cca as t2_successful_cca,
    trace_urrs as t2_trace_urrs,
)
from t3_dup1 import (
    accepted as t3_2_accepted,
    charge as t3_2_charge,
    gy as t3_2_gy,
    icmp_counts as t3_2_icmp_counts,
    pfcp as t3_2_pfcp,
)
from t3_seq1 import pfcp_sequences as t3_3_pfcp_sequences
from t3_del1 import suppressed_pfcp as t3_4_suppressed_pfcp


# Reviewer-facing identifiers are the twenty paper cells.  Each runnable cell
# maps to the representative standard scenario reported by the paper.
CELL_SCENARIOS = {
    "T1-MOD": ["T1-A25"], "T1-INS": [], "T1-DEL": ["T1-A04"],
    "T1-DUP": ["T1-A05"], "T1-SEQ": ["T1-A32"],
    "T2-MOD": ["T2-A17"], "T2-INS": ["T2-A22"],
    "T2-DEL": ["T2-A50"], "T2-DUP": ["T2-A64"],
    "T2-SEQ": ["T2-A02"], "T3-MOD": ["T3-A17"],
    "T3-INS": ["T3-A09"], "T3-DEL": ["T3-A20"],
    "T3-DUP": ["T3-A08"], "T3-SEQ": ["T3-A02"],
    "T4-MOD": ["T4G-A17"], "T4-INS": ["T4N-A25"],
    "T4-DEL": ["T4N-A16"], "T4-DUP": ["T4G-A12"],
    "T4-SEQ": ["T4G-A03"],
}


class ArtifactError(Exception):
    pass


def load_yaml(path: Path) -> Any:
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as error:
        raise ArtifactError(f"cannot load {path.relative_to(ROOT)}: {error}") from error


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ArtifactError(f"cannot load {path.relative_to(ROOT)}: {error}") from error


def manifests() -> tuple[list[dict], dict[str, dict]]:
    messages = load_yaml(MANIFEST / "message_scope.yaml")["messages"]
    cells = load_yaml(MANIFEST / "cells.yaml")["cells"]
    evidence = load_yaml(MANIFEST / "evidence.yaml")["cases"]
    for cell in cells:
        cell.update({
            "scenario_ids": CELL_SCENARIOS[cell["id"]],
            "validation": cell["status"],
        })
        cell["evidence"] = evidence.get(cell["id"])
    return messages, {cell["id"]: cell for cell in cells}


def _format_count(value: int) -> str:
    return f"{value:,}"


def _display_id(case: dict) -> str:
    return case.get("representative_id") or case["id"]


def _resolve_case_id(cases: dict[str, dict], identifier: str) -> str:
    normalized = identifier.upper()
    if normalized in cases:
        return normalized
    for case in cases.values():
        if case.get("representative_id") == normalized:
            return case["id"]
    raise ValueError(f"unknown case or representative ID: {identifier}")


def _demo_entries(cases: dict[str, dict]) -> list[tuple[str, str, str]]:
    entries = []
    for case in cases.values():
        status = (
            "N/A: disabled — no retained scenario"
            if case["status"] == "N/A"
            else (
                f"READY: {case['baseline_charge_cents']} -> "
                f"{case['attack_charge_cents']} cents"
            )
        )
        entries.append((_display_id(case), case["title"], status))
    entries.append(("EXIT", "Exit", "Return to the shell"))
    return entries


def _select_demo_case_with_curses(cases: dict[str, dict]) -> str | None:
    import curses

    entries = _demo_entries(cases)
    display_items: list[tuple[str, int | None]] = []
    for index in range(len(entries)):
        if index in (5, 10, 15):
            display_items.append(("separator", None))
        display_items.append(("entry", index))

    def selector(screen) -> str | None:
        try:
            curses.curs_set(0)
        except curses.error:
            pass
        curses.mousemask(curses.ALL_MOUSE_EVENTS)
        selected = 0
        first_row = 7
        scroll = 0

        def put(row: int, column: int, text: str, attribute: int = 0) -> None:
            height, width = screen.getmaxyx()
            if row < 0 or row >= height or column >= width:
                return
            available = max(0, width - column - 1)
            try:
                screen.addnstr(row, column, text, available, attribute)
            except curses.error:
                pass

        while True:
            screen.erase()
            put(1, 2, "LBO CHARGING ATTACK ARTIFACT", curses.A_BOLD)
            put(3, 2, "Choose a paper cell to open its guided PoC.")
            put(4, 2, "Mouse: click an item")
            put(5, 2, "Keyboard: Up/Down + Enter | Q: quit")

            rows: dict[int, int] = {}
            height, _width = screen.getmaxyx()
            visible = max(3, height - first_row - 2)
            selected_display = next(
                position
                for position, item in enumerate(display_items)
                if item == ("entry", selected)
            )
            if selected_display < scroll:
                scroll = selected_display
            if selected_display >= scroll + visible:
                scroll = selected_display - visible + 1
            for display_position in range(
                scroll,
                min(len(display_items), scroll + visible),
            ):
                kind, entry_index = display_items[display_position]
                row = first_row + display_position - scroll
                if kind == "separator":
                    put(row, 3, "─" * 76, curses.A_DIM)
                    continue
                assert entry_index is not None
                case_id, title, status = entries[entry_index]
                rows[row] = entry_index
                attribute = curses.A_REVERSE if entry_index == selected else 0
                put(
                    row,
                    3,
                    f" {case_id:<8} {title:<33} {status}",
                    attribute,
                )

            put(
                height - 1,
                2,
                f"20 cells: 19 runnable + T1-INS N/A | item {selected + 1}/{len(entries)}",
            )
            screen.refresh()
            key = screen.getch()
            if key in (curses.KEY_UP, ord("k")):
                selected = (selected - 1) % len(entries)
            elif key in (curses.KEY_DOWN, ord("j")):
                selected = (selected + 1) % len(entries)
            elif key in (10, 13, curses.KEY_ENTER):
                if entries[selected][0] == "EXIT":
                    return None
                selected_id = _resolve_case_id(cases, entries[selected][0])
                if cases[selected_id]["status"] == "N/A":
                    curses.flash()
                    continue
                return selected_id
            elif key in (ord("q"), ord("Q"), 27):
                return None
            elif key == curses.KEY_MOUSE:
                try:
                    _, mouse_x, mouse_y, _, button_state = curses.getmouse()
                except curses.error:
                    continue
                if not button_state & (
                    curses.BUTTON1_CLICKED
                    | curses.BUTTON1_RELEASED
                    | curses.BUTTON1_PRESSED
                ):
                    continue
                for row, index in rows.items():
                    if mouse_y == row and mouse_x >= 2:
                        if entries[index][0] == "EXIT":
                            return None
                        selected_id = _resolve_case_id(cases, entries[index][0])
                        if cases[selected_id]["status"] == "N/A":
                            curses.flash()
                            continue
                        return selected_id
        return None

    return curses.wrapper(selector)


def _select_demo_case_fallback(cases: dict[str, dict]) -> str | None:
    print("LBO Charging Attack Artifact")
    print()
    entries = list(cases.values())
    for index, case in enumerate(entries, start=1):
        if index in (6, 11, 16):
            print("  " + "-" * 76)
        status = (
            "N/A / disabled"
            if case["status"] == "N/A"
            else (
                f"{case['baseline_charge_cents']} -> "
                f"{case['attack_charge_cents']} cents"
            )
        )
        print(f"  [{index:>2}] {_display_id(case):<9} {case['title']:<34} {status}")
    print("  [q] Exit")
    while True:
        try:
            selection = input("\nSelect a paper cell [T3-MOD]: ").strip().upper()
        except EOFError:
            return "T3-MOD"
        if not selection:
            return "T3-MOD"
        if selection in ("Q", "QUIT", "EXIT"):
            return None
        if selection.isdigit() and 1 <= int(selection) <= len(entries):
            selected_id = entries[int(selection) - 1]["id"]
        else:
            selected_id = _resolve_case_id(cases, selection)
        if cases[selected_id]["status"] == "N/A":
            print("T1-INS is N/A and has no guided PoC. Choose a runnable item.")
            continue
        return selected_id


def select_demo_case(cases: dict[str, dict]) -> str | None:
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        return "T3-MOD"
    try:
        return _select_demo_case_with_curses(cases)
    except Exception:
        # Minimal terminals may not support curses or mouse events. A numbered
        # prompt still lets the reviewer continue without another dependency.
        return _select_demo_case_fallback(cases)


_DEMO_SCREEN_ACTIVE = False
_DEMO_THEME = "\033[48;2;20;22;35m\033[38;2;238;238;238m"


def _enter_demo_screen() -> None:
    global _DEMO_SCREEN_ACTIVE
    _DEMO_SCREEN_ACTIVE = True
    sys.stdout.write("\033[?1049h" + _DEMO_THEME + "\033[2J\033[H")
    sys.stdout.flush()


def _clear_demo_screen() -> None:
    if not _DEMO_SCREEN_ACTIVE:
        return
    sys.stdout.write(_DEMO_THEME + "\033[2J\033[H")
    sys.stdout.flush()


def _leave_demo_screen() -> None:
    global _DEMO_SCREEN_ACTIVE
    if not _DEMO_SCREEN_ACTIVE:
        return
    sys.stdout.write("\033[0m\033[?1049l")
    sys.stdout.flush()
    _DEMO_SCREEN_ACTIVE = False


def _demo_pause(interactive: bool, next_title: str) -> bool:
    if not interactive:
        return True
    try:
        answer = input(
            f"\nPress Enter for {next_title}, or type q to quit: "
        ).strip().lower()
    except EOFError:
        return False
    if answer in ("q", "quit", "exit"):
        return False
    _clear_demo_screen()
    return True


def _paint(text: str, code: str, enabled: bool) -> str:
    if not enabled:
        return text
    reset = "\033[0m" + (_DEMO_THEME if _DEMO_SCREEN_ACTIVE else "")
    return f"\033[{code}m{text}{reset}"


def _paint_spans(
    text: str,
    spans: list[tuple[int, int]],
    enabled: bool,
) -> str:
    if not enabled or not spans:
        return text
    output = []
    position = 0
    for start, end in sorted(spans):
        if start < position or end <= start:
            continue
        output.append(text[position:start])
        output.append(_paint(text[start:end], "1;31", True))
        position = end
    output.append(text[position:])
    return "".join(output)


def _paint_base_with_accents(
    text: str,
    spans: list[tuple[int, int]],
    enabled: bool,
    *,
    base_code: str = "1;36",
    accent_code: str = "1;31",
) -> str:
    if not enabled:
        return text
    output = []
    position = 0
    for start, end in sorted(spans):
        if start < position or end <= start:
            continue
        output.append(_paint(text[position:start], base_code, True))
        output.append(_paint(text[start:end], accent_code, True))
        position = end
    output.append(_paint(text[position:], base_code, True))
    return "".join(output)


def _framed_title(title: str, content_width: int) -> str:
    label = f" {title} "
    return "┌" + label + "─" * max(0, content_width - len(label)) + "┐"


def _print_framed_rows(
    title: str,
    rows: list[tuple[str, list[tuple[int, int]]]],
    *,
    content_width: int,
    color: bool,
    accent_code: str = "1;31",
) -> None:
    print(_paint(_framed_title(title, content_width), "1;36", color))
    for text, spans in rows:
        padded = text[:content_width].ljust(content_width)
        if color:
            print(
                _paint("│", "1;36", True)
                + _paint_base_with_accents(
                    padded,
                    spans,
                    True,
                    accent_code=accent_code,
                )
                + _paint("│", "1;36", True)
            )
        else:
            print(f"│{padded}│")
    print(_paint("└" + "─" * content_width + "┘", "1;36", color))


def _positioned_line(*placements: tuple[int, str], width: int = 100) -> str:
    characters = [" "] * width
    for column, text in placements:
        for offset, character in enumerate(text):
            index = column + offset
            if 0 <= index < width:
                characters[index] = character
    return "".join(characters).rstrip()


def _paint_fragments(text: str, fragments: list[str], enabled: bool) -> str:
    if not enabled:
        return text
    for fragment in fragments:
        text = text.replace(
            fragment,
            _paint(fragment, "1;31", True),
            1,
        )
    return text


def _visual_panel(title: str, lines: list[str], inner_width: int = 48) -> list[str]:
    label = f" {title} "
    remaining = max(0, inner_width - len(label))
    output = ["┌" + label + "─" * remaining + "┐"]
    output.extend(f"│ {line:<{inner_width - 2}} │" for line in lines)
    output.append("└" + "─" * inner_width + "┘")
    return output


def _print_visual_pair(
    left_title: str,
    left_lines: list[str],
    right_title: str,
    right_lines: list[str],
    *,
    color: bool,
    left_code: str = "1;36",
    right_code: str = "1;31",
) -> None:
    width = shutil.get_terminal_size(fallback=(100, 24)).columns
    inner_width = 48
    left = _visual_panel(left_title, left_lines, inner_width)
    right = _visual_panel(right_title, right_lines, inner_width)
    row_count = max(len(left), len(right))
    left.extend(" " * (inner_width + 2) for _ in range(row_count - len(left)))
    right.extend(" " * (inner_width + 2) for _ in range(row_count - len(right)))
    if width >= 106:
        for left_row, right_row in zip(left, right):
            print(
                f"{_paint(left_row, left_code, color)}  "
                f"{_paint(right_row, right_code, color)}"
            )
        return
    for row in left:
        print(_paint(row, left_code, color))
    print()
    for row in right:
        print(_paint(row, right_code, color))


def _print_analysis_pipeline(counts: dict, color: bool) -> None:
    items = [
        (str(counts["messages"]), "SELECTED MESSAGES"),
        (f"{counts['native_fields']:,}", "ALL FIELD POSITIONS"),
        (f"{counts['native_relevant_fields']:,}", "CHARGING-RELEVANT"),
        (str(counts["native_constraints"]), "CONSISTENCY CONSTRAINTS"),
        (str(counts["manipulation_primitives"]), "MOD INS DEL DUP SEQ"),
        (str(counts["native_scenarios"]), "THREAT SCENARIOS"),
        ("19", "REPRESENTATIVE PoCs"),
    ]
    width = shutil.get_terminal_size(fallback=(100, 24)).columns
    if width >= 120:
        box_top = "┌───────────────────────┐"
        box_bottom = "└───────────────────────┘"
        top = "   ".join(box_top for _ in items[:4])
        top_numbers = "──▶".join(
            f"│{number:^23}│" for number, _ in items[:4]
        )
        top_labels = "   ".join(
            f"│{label:^23}│" for _, label in items[:4]
        )
        top_bottom = "   ".join(box_bottom for _ in items[:4])

        # The second row runs right-to-left so the five primitives remain
        # directly below the 81 constraints that produce them.
        lower = [items[6], items[5], items[4]]
        prefix = " " * 28
        lower_top = prefix + "   ".join(box_top for _ in lower)
        lower_numbers = prefix + "◀──".join(
            f"│{number:^23}│" for number, _ in lower
        )
        lower_labels = prefix + "   ".join(
            f"│{label:^23}│" for _, label in lower
        )
        lower_bottom = prefix + "   ".join(box_bottom for _ in lower)

        # Keep the inner boxes away from the outer frame.  Four columns match
        # the visual breathing room between the individual analysis boxes.
        margin = " " * 4
        framed_width = 117
        rows = [
            ("", []),
            (margin + top, []),
            (margin + top_numbers, []),
            (margin + top_labels, []),
            (margin + top_bottom, []),
            (_positioned_line((100, "│"), width=framed_width), []),
            (_positioned_line((100, "▼"), width=framed_width), []),
            (margin + lower_top, []),
            (margin + lower_numbers, []),
            (margin + lower_labels, []),
            (margin + lower_bottom, []),
            ("", []),
        ]
        _print_framed_rows(
            "STANDARD-MESSAGE ANALYSIS AND THREAT DERIVATION",
            rows,
            content_width=framed_width,
            color=color,
        )
        return
    rows = [("", [])]
    for index, (number, label) in enumerate(items):
        rows.extend([
            ("  ┌────────────────────────────┐", []),
            (f"  │{number:^28}│", []),
            (f"  │{label:^28}│", []),
            ("  └────────────────────────────┘", []),
        ])
        if index != len(items) - 1:
            rows.extend([("                 │", []), ("                 ▼", [])])
    rows.append(("", []))
    _print_framed_rows(
        "STANDARD-MESSAGE ANALYSIS AND THREAT DERIVATION",
        rows,
        content_width=34,
        color=color,
    )


def _print_demo_foundation(color: bool, case_id: str) -> None:
    summary = load_json(ANALYSIS / "coverage_summary.json")
    counts = dict(summary["counts"])
    public_cells = {
        cell["id"]: cell
        for cell in load_yaml(MANIFEST / "cells.yaml")["cells"]
    }
    selected = public_cells[case_id]
    print("=" * 72)
    print("STEP 1/4 | STANDARD-DRIVEN FOUNDATION")
    print("=" * 72)
    print("This PoC is not an isolated scenario invented for the demo.")
    print("This representative was selected for implementation from the analysis below:")
    print()
    _print_analysis_pipeline(counts, color)
    print()
    print("  3GPP scope  -> field positions -> constraints -> threat derivation")
    print("                         experimentally validated PoCs")
    print("  Outcome: 20 surface-primitive cells; 19 representative attacks")
    print()
    representative = selected.get("representative_id")
    selection = (
        f"CATEGORY {case_id} | REPRESENTATIVE {representative}"
        if representative
        else f"CATEGORY {case_id} | REPRESENTATIVE N/A"
    )
    if case_id == "T3-MOD":
        print(_paint(f"SELECTED: {selection}  VOLUME INFLATION", "1;31", color))
        print("Question: Can a dishonest UPF inflate a valid usage report and cause")
        print("          the charging backend to produce a higher result?")
    elif case_id == "T4-MOD":
        print(_paint(
            f"SELECTED: {selection}  CHARGING-REQUEST INFLATION",
            "1;31",
            color,
        ))
        print("Question: Can a dishonest SMF preserve the accepted PFCP report but")
        print("          inflate the outgoing charging request and its result?")
    else:
        print(_paint(
            f"SELECTED: {selection}  {selected['title'].upper()}",
            "1;31",
            color,
        ))
        print(f"Question: {selected['summary']}")


def _labelled_left_arrow(label: str, width: int) -> str:
    label = f" {label} "
    fill = max(0, width - 1 - len(label))
    left = fill // 2
    return "◀" + "─" * left + label + "─" * (fill - left)


def _right_arrow(width: int) -> str:
    return "─" * max(0, width - 1) + "▶"


def _load_case_result(case: dict) -> dict:
    config = case.get("evidence") or {}
    return load_json(ROOT / config["path"] / config["result"])


def _generic_demo_facts(case: dict, result: dict) -> dict[str, str]:
    """Return only values that are explicitly present in public PoC data."""
    case_id = case["id"]
    facts: dict[str, dict[str, str]] = {
        "T1-MOD": {
            "workload": "4 PFCP reports / 16.05 MB",
            "source": "V-PCF / POLICY",
            "baseline": "5QI 9 / Rating Group 9",
            "attack": "5QI 6 / Rating Group 6",
            "consumer": "V-SMF / ACCEPTED",
            "baseline_effect": "baseline policy accepted",
            "attack_effect": "mutated policy accepted",
        },
        "T1-DEL": {
            "workload": "same controlled workload",
            "source": "V-PCF / POLICY",
            "baseline": "refChgData present",
            "attack": "refChgData deleted",
            "consumer": "V-SMF / STATE",
            "baseline_effect": "forwarding + charging",
            "attack_effect": "forwarding; no charging ref",
        },
        "T1-DUP": {
            "workload": "same controlled workload",
            "source": "V-PCF / POLICY",
            "baseline": "1 ChargingData attribution",
            "attack": "2 valid attributions",
            "consumer": "V-SMF / ACCOUNTING",
            "baseline_effect": "Gy 1,048,844 B",
            "attack_effect": "Gy 2,097,688 B",
        },
        "T1-SEQ": {
            "workload": "same controlled workload",
            "source": "V-PCF / POLICY",
            "baseline": "newer decision retained",
            "attack": "stale decision replayed",
            "consumer": "V-SMF / ACCOUNTING",
            "baseline_effect": "Gy 1,048,844 B",
            "attack_effect": "Gy 2,097,688 B",
        },
        "T2-MOD": {
            "workload": "same 1 MiB workload",
            "source": "V-SMF / PFCP RULE",
            "baseline": "PDR precedence 100000",
            "attack": "PDR precedence 1000",
            "consumer": "V-UPF / RULE STATE",
            "baseline_effect": "uncharged fallback selected",
            "attack_effect": "charged PDR selected",
        },
        "T2-INS": {
            "workload": "4,096 packets / 4 MiB",
            "source": "V-SMF / PFCP RULE",
            "baseline": "1 URR reference",
            "attack": "2 URR references",
            "consumer": "V-UPF / ATTRIBUTION",
            "baseline_effect": "1 metering attribution",
            "attack_effect": "2 metering attributions",
        },
        "T2-DEL": {
            "workload": "same controlled workload",
            "source": "V-SMF / PFCP RULE",
            "baseline": "charged PDR installed",
            "attack": "charged PDR removed",
            "consumer": "V-UPF / RULE STATE",
            "baseline_effect": "charged forwarding",
            "attack_effect": "unmetered fallback",
        },
        "T2-DUP": {
            "workload": "same controlled workload",
            "source": "V-SMF / PFCP RULE",
            "baseline": "1 Create PDR / 1 URR",
            "attack": "repeated PDR / 0 URR",
            "consumer": "V-UPF / RULE STATE",
            "baseline_effect": "1 retained URR",
            "attack_effect": "0 retained URRs",
        },
        "T2-SEQ": {
            "workload": "same controlled workload",
            "source": "V-SMF / PFCP RULE",
            "baseline": "fresh state / 0 URR",
            "attack": "stale rule replay / 1 URR",
            "consumer": "V-UPF / RULE STATE",
            "baseline_effect": "uncharged current state",
            "attack_effect": "charged state restored",
        },
        "T3-INS": {
            "workload": "same controlled workload",
            "source": "V-UPF / USAGE REPORT",
            "baseline": "1 Usage Report IE",
            "attack": "+ near-duplicate / 4,096 B",
            "consumer": "V-SMF / Gy USAGE",
            "baseline_effect": "1,048,844 B",
            "attack_effect": "2,101,784 B",
        },
        "T3-MOD": {
            "workload": "30,399 packets",
            "source": "V-UPF / USAGE REPORT",
            "baseline": "11,049,660 B measured",
            "attack": "55,248,300 B reported / x5",
            "consumer": "V-SMF / Gy USAGE",
            "baseline_effect": "11,049,660 B accepted",
            "attack_effect": "55,248,300 B accepted",
        },
        "T3-DEL": {
            "workload": "30,400 packets",
            "source": "V-UPF / USAGE REPORT",
            "baseline": "UL + DL = 21.05 MB",
            "attack": "one direction deleted",
            "consumer": "V-SMF / Gy USAGE",
            "baseline_effect": "21.05 MB accepted",
            "attack_effect": "10.53 MB accepted",
        },
        "T3-DUP": {
            "workload": "30,399 packets",
            "source": "V-UPF / USAGE REPORT",
            "baseline": "1 report IE / request",
            "attack": "2 identical report IEs",
            "consumer": "V-SMF / Gy USAGE",
            "baseline_effect": "11,049,660 B",
            "attack_effect": "22,099,320 B",
        },
        "T3-SEQ": {
            "workload": "30,399 packets",
            "source": "V-UPF / USAGE REPORT",
            "baseline": "3 semantic reports",
            "attack": "3 reports + 3 replays",
            "consumer": "V-SMF / Gy USAGE",
            "baseline_effect": "11,049,660 B",
            "attack_effect": "22,099,320 B",
        },
        "T4-INS": {
            "workload": "same PFCP producer usage",
            "source": "V-UPF / PFCP SOURCE",
            "baseline": "1,048,844 B produced",
            "attack": "1,048,844 B unchanged",
            "consumer": "V-SMF / Gy REQUEST",
            "baseline_effect": "Rating Group 9 MSCC",
            "attack_effect": "RG 9 + RG 6 MSCC",
        },
        "T4-MOD": {
            "workload": "30,400 packets / same PFCP",
            "source": "V-UPF / PFCP SOURCE",
            "baseline": "21,050,244 B produced",
            "attack": "21,050,244 B unchanged",
            "consumer": "V-SMF / Gy REQUEST",
            "baseline_effect": "21,050,244 B charged",
            "attack_effect": "63,149,076 B charged / UL x5",
        },
        "T4-DEL": {
            "workload": "same PFCP producer usage",
            "source": "V-UPF / PFCP SOURCE",
            "baseline": "1,048,844 B produced",
            "attack": "1,048,844 B unchanged",
            "consumer": "V-SMF / Gy REQUEST",
            "baseline_effect": "Rating Group 6",
            "attack_effect": "RG 6 deleted; RG 9 fallback",
        },
        "T4-DUP": {
            "workload": "30,400 packets / same PFCP",
            "source": "V-UPF / PFCP SOURCE",
            "baseline": "21,050,244 B produced",
            "attack": "21,050,244 B unchanged",
            "consumer": "V-SMF / Gy REQUEST",
            "baseline_effect": "1 MSCC / 21,050,244 B",
            "attack_effect": "2 MSCCs / 42,100,488 B",
        },
        "T4-SEQ": {
            "workload": "30,400 packets / same PFCP",
            "source": "V-UPF / PFCP SOURCE",
            "baseline": "5 reports / 21,050,244 B",
            "attack": "same 5 reports unchanged",
            "consumer": "V-SMF / Gy REQUEST",
            "baseline_effect": "5 CCR-U / 21,050,244 B",
            "attack_effect": "10 CCR-U / 42,100,488 B",
        },
    }[case_id]
    facts = dict(facts)
    facts["baseline_charge"] = str(case["baseline_charge_cents"])
    facts["attack_charge"] = str(case["attack_charge_cents"])
    facts["delta"] = f"{case['attack_charge_cents'] - case['baseline_charge_cents']:+d}"
    facts["passed"] = "yes" if result.get("passed", True) else "no"
    facts["mutation_stage"] = "consumer" if case["surface"] == "T4" else "source"
    return facts


def _print_topology_frame(surface: str, color: bool) -> None:
    """Print the shared Figure-2 topology used by all runnable PoCs."""
    width = shutil.get_terminal_size(fallback=(100, 24)).columns
    if width >= 84:
        content_width = 84
        rows: list[tuple[str, dict[str, list[tuple[int, int]]]]] = [
            (
                _positioned_line(
                    (1, "┌──────────┐"),
                    (40, "┌──────────┐"),
                    (71, "┌──────────┐"),
                    width=content_width,
                ),
                {},
            ),
            (
                _positioned_line(
                    (1, "│ OCS*/CHF │"),
                    (14, _labelled_left_arrow("T4", 25)),
                    (40, "│  V-SMF   │"),
                    (53, _labelled_left_arrow("T1/N7", 17)),
                    (71, "│  V-PCF   │"),
                    width=content_width,
                ),
                {"T4": [(14, 39)], "T1": [(53, 70)]},
            ),
            (
                _positioned_line(
                    (1, "└──────────┘"),
                    (40, "└──────────┘"),
                    (71, "└──────────┘"),
                    width=content_width,
                ),
                {},
            ),
            ("", {}),
            (
                _positioned_line((45, "▲"), (48, "│"), width=content_width),
                {"T3": [(45, 46)], "T2": [(48, 49)]},
            ),
            (
                _positioned_line(
                    (32, "T3/N4"),
                    (45, "│"),
                    (48, "│"),
                    (53, "T2/N4"),
                    width=content_width,
                ),
                {
                    "T3": [(32, 37), (45, 46)],
                    "T2": [(48, 49), (53, 58)],
                },
            ),
            (
                _positioned_line(
                    (27, "UPF -> SMF"),
                    (45, "│"),
                    (48, "│"),
                    (53, "SMF -> UPF"),
                    width=content_width,
                ),
                {
                    "T3": [(27, 37), (45, 46)],
                    "T2": [(48, 49), (53, 63)],
                },
            ),
            (
                _positioned_line((45, "│"), (48, "▼"), width=content_width),
                {"T3": [(45, 46)], "T2": [(48, 49)]},
            ),
            ("", {}),
            (
                _positioned_line(
                    (1, "┌──────┐"),
                    (18, "┌──────────┐"),
                    (40, "┌──────────┐"),
                    (60, "┌──────────┐"),
                    width=content_width,
                ),
                {},
            ),
            (
                _positioned_line(
                    (1, "│  UE  │"),
                    (9, _right_arrow(8)),
                    (18, "│ gNB/RAN  │"),
                    (31, _right_arrow(8)),
                    (40, "│  V-UPF   │"),
                    (53, _right_arrow(6)),
                    (60, "│ Internet │"),
                    width=content_width,
                ),
                {},
            ),
            (
                _positioned_line(
                    (1, "└──────┘"),
                    (18, "└──────────┘"),
                    (40, "└──────────┘"),
                    (60, "└──────────┘"),
                    width=content_width,
                ),
                {},
            ),
        ]
    else:
        content_width = 48
        rows = [
            (_positioned_line((0, "┌───────┐"), (19, "┌───────┐"), (39, "┌───────┐"), width=48), {}),
            (
                _positioned_line(
                    (0, "│ OCS*  │"), (9, _labelled_left_arrow("T4", 10)),
                    (19, "│ V-SMF │"), (28, _labelled_left_arrow("T1", 11)),
                    (39, "│ V-PCF │"), width=48,
                ),
                {"T4": [(9, 19)], "T1": [(28, 39)]},
            ),
            (_positioned_line((0, "└───────┘"), (19, "└───────┘"), (39, "└───────┘"), width=48), {}),
            (_positioned_line((23, "▲"), (26, "│"), width=48), {"T3": [(23, 24)], "T2": [(26, 27)]}),
            (_positioned_line((8, "T3 UPF->SMF"), (23, "│"), (26, "│"), (29, "T2 SMF->UPF"), width=48), {"T3": [(8, 24)], "T2": [(26, 42)]}),
            (_positioned_line((23, "│"), (26, "▼"), width=48), {"T3": [(23, 24)], "T2": [(26, 27)]}),
            ("", {}),
            (_positioned_line((0, "┌────┐"), (9, "┌───────┐"), (21, "┌────────┐"), (34, "┌────────────┐"), width=48), {}),
            (_positioned_line((0, "│ UE │"), (6, "──▶"), (9, "│ gNB   │"), (18, "──▶"), (21, "│ V-UPF  │"), (31, "──▶"), (34, "│ Internet   │"), width=48), {}),
            (_positioned_line((0, "└────┘"), (9, "└───────┘"), (21, "└────────┘"), (34, "└────────────┘"), width=48), {}),
        ]
    _print_framed_rows(
        "FIG. 2-ALIGNED LBO WORKFLOW",
        [
            (line, spans.get(surface, []))
            for line, spans in rows
        ],
        content_width=content_width,
        color=color,
    )


def _print_generic_propagation(
    case: dict,
    facts: dict[str, str],
    color: bool,
) -> None:
    print()
    print(_paint(f"{_display_id(case)} ATTACK PROPAGATION", "1;31", color))
    print()
    source_mutated = facts["mutation_stage"] == "source"
    panels = (
        # T4 replay/duplication labels include "30,400 packets / same PFCP".
        # Keep the full measured description inside the right border.
        (_visual_panel("UE / WORKLOAD", [facts["workload"], "[SAME]"], 30), "1;36"),
        (
            _visual_panel(
                facts["source"],
                [facts["attack"], "[MUTATED]" if source_mutated else "[UNCHANGED]"],
                31,
            ),
            "1;31" if source_mutated else "1;36",
        ),
        (
            _visual_panel(
                facts["consumer"],
                [
                    facts["attack_effect"],
                    "[ACCEPTED]" if source_mutated else "[MUTATED / ACCEPTED]",
                ],
                31,
            ),
            "1;33" if source_mutated else "1;31",
        ),
        (
            _visual_panel(
                "OCS / RESULT",
                [f"{facts['attack_charge']} cents", f"[{facts['delta']} cents]"],
                18,
            ),
            "1;32",
        ),
    )
    width = shutil.get_terminal_size(fallback=(100, 24)).columns
    if width >= 136:
        for row_index, rows in enumerate(zip(*(panel for panel, _ in panels))):
            connector = " ──▶ " if row_index == 2 else "     "
            for panel_index, row in enumerate(rows):
                print(_paint(row, panels[panel_index][1], color), end="")
                if panel_index != len(rows) - 1:
                    print(_paint(connector, "1;37", color), end="")
            print()
    else:
        for index, (panel, panel_code) in enumerate(panels):
            for row in panel:
                print(_paint(row, panel_code, color))
            if index != len(panels) - 1:
                print("            │")
                print("            ▼")
    print()
    print(_paint(f"MUTATION: {case['paper_mutation']}", "1;31", color))


def _print_generic_topology(
    case: dict,
    facts: dict[str, str],
    color: bool,
) -> None:
    surface = case["surface"]
    print("=" * 72)
    print("STEP 2/4 | WHOLE SYSTEM AND ATTACK LOCATION")
    print("=" * 72)
    _print_topology_frame(surface, color)
    print()
    edge = {
        "T1": "V-PCF -> V-SMF policy decision",
        "T2": "V-SMF -> V-UPF PFCP rule operation",
        "T3": "V-UPF -> V-SMF PFCP Usage Report",
        "T4": "V-SMF -> OCS*/CHF charging request",
    }[surface]
    print(_paint(
        f"SELECTED ATTACK {_display_id(case)} (category {case['id']}): {edge}",
        "1;31",
        color,
    ))
    print(f"Mutation: {case['summary']}")
    print("* OCS* denotes the measured Gy prototype; CHF denotes the native design.")
    print()
    print("Only the selected surface is highlighted; the other links provide context.")
    _print_generic_propagation(case, facts, color)


def _print_generic_poc(
    case: dict,
    facts: dict[str, str],
    color: bool,
) -> None:
    baseline = case["baseline_charge_cents"]
    attack = case["attack_charge_cents"]
    delta = attack - baseline
    repetitions = case["repetitions"]
    print("=" * 72)
    print("STEP 3/4 | MEASURED UNPROTECTED BENIGN-VERSUS-ATTACK PoC")
    print("=" * 72)
    _print_visual_pair(
        "UNPROTECTED BENIGN RUN",
        [
            f"[UE] {facts['workload']}",
            "  │",
            "  ▼",
            f"[{facts['source'].split(' / ')[0]}] {facts['baseline']}",
            "  │",
            "  ▼",
            f"[{facts['consumer'].split(' / ')[0]}] {facts['baseline_effect']}",
            "  │",
            "  ▼",
            f"[OCS] balance debit {baseline} cents",
        ],
        f"UNPROTECTED ATTACK / {_display_id(case)}",
        [
            f"[UE] {facts['workload']}  [SAME]",
            "  │",
            "  ▼",
            f"[{facts['source'].split(' / ')[0]}] {facts['attack']}  "
            f"[{'CHANGED' if facts['mutation_stage'] == 'source' else 'SAME'}]",
            "  │",
            "  ▼",
            f"[{facts['consumer'].split(' / ')[0]}] {facts['attack_effect']}  "
            f"[{'ACCEPTED' if facts['mutation_stage'] == 'source' else 'CHANGED'}]",
            "  │",
            "  ▼",
            f"[OCS] balance debit {attack} cents ({delta:+d})",
        ],
        color=color,
    )
    print()
    print(_paint("CAUSE → PROPAGATION → OUTCOME", "1;31", color))
    print(
        f"  {facts['attack']}  ──▶  {facts['attack_effect']}  ──▶  "
        f"OCS {attack} cents"
    )
    print()
    print(_paint("TABLE II REPRESENTATIVE", "1;31", color))
    print(f"  Category / ID : {case['id']} / {_display_id(case)}")
    mutation_lines = textwrap.wrap(case["paper_mutation"], width=66)
    effect_lines = textwrap.wrap(case["measured_effect"], width=66)
    for index, line in enumerate(mutation_lines):
        print(f"  Mutation      : {line}" if index == 0 else f"                  {line}")
    for index, line in enumerate(effect_lines):
        print(f"  Effect        : {line}" if index == 0 else f"                  {line}")
    print()
    print(_paint("PoC VALIDATION CHECKS", "1;31", color))
    print("  ✓ V1: mutated protocol object accepted")
    print("  ✓ V2: downstream semantic state changed")
    print("  ✓ V3: persistent OCS balance effect observed")
    print(
        f"  ✓ Repetition: {repetitions}/{repetitions} baseline and "
        f"{repetitions}/{repetitions} attack runs agree"
    )
    print(
        f"  ✓ Observed OCS balance debit: {baseline} -> {attack} cents"
    )
    if case["id"] == "T1-MOD":
        print("  ! Tariff: rounded-up 1,000,000-byte units; 5QI 9 = 1 cent,")
        print("            5QI 6 = 10 cents; results include reserved quota.")
    else:
        print("  ! Pricing: observed in the documented paired OCS testbed profile.")
    print(f"  ! Claim boundary: {case['claim_boundary']}")


def _print_generic_defense(
    case: dict,
    facts: dict[str, str],
    color: bool,
) -> None:
    predicate, transition = {
        "T1": ("P1", "E0 -> E1"),
        "T2": ("P2", "E1 -> E2"),
        "T3": ("P3", "E2 -> E3"),
        "T4": ("P4", "E3 -> E4"),
    }[case["surface"]]
    print("=" * 72)
    print("STEP 4/4 | PAPER DEFENSE MECHANISM MAPPING")
    print("=" * 72)
    print(_paint(
        "PAPER-EVALUATED MECHANISM — NOT REPRODUCED IN THIS PACKAGE  ⚠",
        "1;33",
        color,
    ))
    print()
    print(f"Decision predicate: {predicate}: {transition}")
    print()
    if facts["mutation_stage"] == "consumer":
        expected = facts["baseline_effect"]
        received = facts["attack_effect"]
    else:
        expected = facts["baseline"]
        received = facts["attack"]
    _print_visual_pair(
        f"BENIGN {predicate} CHECK / {transition}",
        [
            f"EXPECTED   {expected}",
            "       │",
            "       ▼",
            f"CONSUMER   {facts['baseline_effect']}",
            "",
            "predecessor evidence and state agree",
            "",
            "                    ✓ ACCEPT",
        ],
        f"{_display_id(case)} {predicate} CHECK / {transition}",
        [
            f"EXPECTED   {expected}",
            f"RECEIVED   {received}",
            "       │",
            "       ▼",
            f"CONSUMER   {facts['attack_effect']}",
            "semantic mismatch detected",
            "",
            f"                    ✗ {predicate} REJECTS",
        ],
        color=color,
        left_code="1;32",
        right_code="1;33",
    )
    print()
    invariant = {
        "T1": "Bind the accepted policy and tariff state to predecessor evidence.",
        "T2": "Bind installed PFCP rules and URR relations to the accepted policy.",
        "T3": "Bind reported usage, direction, identity, and sequence to trusted metering.",
        "T4": "Bind accepted PFCP usage to the outgoing charging request.",
    }[case["surface"]]
    print(f"Trusted invariant: {invariant}")
    print()
    print("The paper reports the Charging-TCB evaluation. This public package")
    print("reproduces the attacks and explains the predicate, but does not include")
    print("the defense implementation or its raw evaluation data.")


def _print_pcap_commands(case: dict, color: bool) -> None:
    representative = _display_id(case)
    captures = {
        "PFCP": f"pcaps/{representative}_pfcp.pcap",
        "Gy": f"pcaps/{representative}_gy.pcap",
    }
    for relative in captures.values():
        if not (ROOT / relative).is_file():
            raise ArtifactError(f"missing reviewer capture: {relative}")
    print()
    print(_paint("OPEN THE SELECTED ATTACK CAPTURES IN WIRESHARK", "1;36", color))
    print(f"  PFCP : wireshark {captures['PFCP']} &")
    print(f"  Gy   : wireshark {captures['Gy']} &")


def run_generic_demo(case: dict, interactive: bool) -> None:
    if not verify_case(case, show_output=False):
        raise ArtifactError(f"{case['id']} PoC data did not pass verification")
    result = _load_case_result(case)
    facts = _generic_demo_facts(case, result)
    _print_demo_foundation(interactive, case["id"])
    if not _demo_pause(interactive, "the whole-system attack map"):
        return
    print()
    _print_generic_topology(case, facts, interactive)
    if not _demo_pause(interactive, "the baseline-versus-attack PoC"):
        return
    print()
    _print_generic_poc(case, facts, interactive)
    if not _demo_pause(interactive, "the paper defense mechanism mapping"):
        return
    print()
    _print_generic_defense(case, facts, interactive)
    _print_pcap_commands(case, interactive)


def run_na_demo(case: dict) -> None:
    print("=" * 72)
    print(f"{case['id']} | NOT APPLICABLE")
    print("=" * 72)
    print("Native scenarios : 0")
    print(f"Reason           : {case['summary']}")
    print("Runnable attack  : none")
    print()
    print("This is an intentional empty cell, not a missing implementation or failure.")


def _run_selected_demo(
    cases: dict[str, dict],
    selected: str,
    interactive: bool,
) -> None:
    if selected not in cases:
        raise ValueError(f"unknown case ID: {selected}")
    case = cases[selected]
    if case["status"] == "N/A":
        run_na_demo(case)
    else:
        run_generic_demo(case, interactive)


def _finish_interactive_demo(
    case: dict,
    return_to_menu: bool,
) -> bool:
    destination = "return to the attack menu" if return_to_menu else "close the demo"
    try:
        answer = input(
            f"\nPress Enter to {destination}, or type q to exit: "
        ).strip().lower()
    except EOFError:
        return False
    return answer not in ("q", "quit", "exit")


def run_demo(
    cases: dict[str, dict],
    identifier: str | None,
    non_interactive: bool,
) -> None:
    interactive = (
        not non_interactive and sys.stdin.isatty() and sys.stdout.isatty()
    )
    if not interactive:
        selected = _resolve_case_id(cases, identifier) if identifier else "T3-MOD"
        _run_selected_demo(cases, selected, False)
        return

    # An explicitly named case is a single full-screen demo.  The bare
    # reviewer command is a persistent browser: finishing one PoC returns to
    # the twenty-cell menu without requiring another shell command.
    if identifier:
        selected = _resolve_case_id(cases, identifier)
        _enter_demo_screen()
        try:
            _run_selected_demo(cases, selected, True)
            _finish_interactive_demo(cases[selected], False)
        finally:
            _leave_demo_screen()
        return

    while True:
        selected = select_demo_case(cases)
        if selected is None:
            return
        _enter_demo_screen()
        try:
            _run_selected_demo(cases, selected, True)
            return_to_menu = _finish_interactive_demo(
                cases[selected], True
            )
        finally:
            _leave_demo_screen()
        if not return_to_menu:
            return


def sha256(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(block)
    return hasher.hexdigest()


def verify_checksums(directory: Path) -> int:
    checksum_file = directory / "SHA256SUMS"
    if not checksum_file.is_file():
        raise ArtifactError(f"missing checksum file: {checksum_file}")
    count = 0
    for line in checksum_file.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        expected, relative = line.split(None, 1)
        path = directory / relative.strip()
        if not path.is_file():
            raise ArtifactError(f"missing evidence: {path}")
        observed = sha256(path)
        if observed != expected:
            raise ArtifactError(f"checksum mismatch: {path}")
        count += 1
    return count


def compare_expected(observed: dict, expected: dict, prefix: str = "") -> list[str]:
    failures = []
    for key, value in expected.items():
        label = f"{prefix}.{key}" if prefix else key
        if isinstance(value, dict):
            child = observed.get(key)
            if not isinstance(child, dict):
                failures.append(f"{label}: expected object, observed {child!r}")
            else:
                failures.extend(compare_expected(child, value, label))
        elif observed.get(key) != value:
            failures.append(f"{label}: expected {value!r}, observed {observed.get(key)!r}")
    return failures


def ensure_pcaps_parse(directory: Path) -> int:
    tshark = shutil.which("tshark")
    if not tshark:
        raise ArtifactError("tshark is required to parse the selected packet evidence")
    pcaps = sorted(directory.rglob("*.pcap"))
    for path in pcaps:
        result = subprocess.run(
            [tshark, "-r", str(path), "-c", "1"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            raise ArtifactError(f"tshark cannot parse {path}: {result.stderr.strip()}")
    return len(pcaps)


def verify_t3_mod1(case: dict, config: dict) -> tuple[bool, list[str]]:
    directory = ROOT / config["path"]
    checksum_count = verify_checksums(directory)
    pcap_count = ensure_pcaps_parse(directory)
    result = load_json(directory / config["result"])
    baseline = directory / "baseline"
    attack = directory / "attack"
    failures = compare_expected(result, config["expected"])
    try:
        baseline_pfcp = live_pfcp_usage(baseline)
        baseline_gy = live_gy_usage(baseline)
        attack_pfcp = live_pfcp_usage(attack)
        attack_gy = live_gy_usage(attack)
        trace_actual, trace_reported = live_trace_usage(attack)
        baseline_charge = live_charge(baseline)
        attack_charge = live_charge(attack)
        baseline_packets = live_packet_count(baseline / "gtpu.pcap")
        attack_packets = live_packet_count(attack / "gtpu.pcap")
    except PairError as error:
        raise ArtifactError(str(error)) from error

    relations = {
        "identical_gtpu_packet_count": baseline_packets == attack_packets
        and baseline_packets > 0,
        "baseline_pfcp_equals_gy": baseline_pfcp == baseline_gy,
        "baseline_equals_attack_actual": baseline_pfcp == trace_actual,
        "attack_trace_exact_x5": trace_reported
        == [tuple(value * 5 for value in item) for item in trace_actual],
        "attack_trace_equals_pfcp": trace_reported == attack_pfcp,
        "attack_pfcp_equals_gy": attack_pfcp == attack_gy,
        "pfcp_reports_accepted": accepted_pfcp_responses(attack) == len(attack_pfcp),
        "cca_updates_accepted": accepted_cca_updates(attack) == len(attack_gy),
        "backend_charge_increased": attack_charge["charged_cents"]
        > baseline_charge["charged_cents"],
    }
    for label, passed in relations.items():
        if not passed:
            failures.append(f"semantic relation failed: {label}")

    observed = {
        "gtpu_packet_count_each": baseline_packets,
        "report_count": len(attack_pfcp),
        "baseline_usage_sum": sum(item[0] for item in baseline_pfcp),
        "attack_reported_usage_sum": sum(item[0] for item in attack_pfcp),
        "baseline_charge_cents": baseline_charge["charged_cents"],
        "attack_charge_cents": attack_charge["charged_cents"],
        "charge_delta_cents": attack_charge["charged_cents"]
        - baseline_charge["charged_cents"],
        "semantic_relations": relations,
    }
    failures.extend(compare_expected(observed, {
        key: result[key]
        for key in observed
    }))
    observations = [
        f"checksums={checksum_count}",
        f"parseable_pcaps={pcap_count}",
        f"claim={case['validation']}",
        (
            "semantic[identical-workload]=PASS "
            f"(gtpu_packets_each={baseline_packets})"
        ),
        (
            "semantic[exact-x5-pair]=PASS "
            f"(baseline={observed['baseline_usage_sum']}, "
            f"attack={observed['attack_reported_usage_sum']})"
        ),
        "semantic[pfcp-to-gy-directional]=PASS (baseline and attack)",
        (
            "semantic[paired-backend-charge]=PASS "
            f"({observed['baseline_charge_cents']} -> "
            f"{observed['attack_charge_cents']} cents)"
        ),
        "semantic[claim-boundary]=CCR-U/CCA-U pair; CCR-I/T not claimed",
    ]
    observations.extend(f"FAIL {failure}" for failure in failures)
    return not failures, observations


def verify_t3_dup1(case: dict, config: dict) -> tuple[bool, list[str]]:
    directory = ROOT / config["path"]
    checksum_count = verify_checksums(directory)
    pcap_count = ensure_pcaps_parse(directory)
    result = load_json(directory / config["result"])
    baseline, attack = directory / "baseline", directory / "attack"
    failures = compare_expected(result, config["expected"])
    try:
        baseline_pfcp = t3_2_pfcp(baseline)
        attack_pfcp = t3_2_pfcp(attack)
        baseline_gy = t3_2_gy(baseline)
        attack_gy = t3_2_gy(attack)
        baseline_charge = t3_2_charge(baseline)
        attack_charge = t3_2_charge(attack)
        baseline_icmp = t3_2_icmp_counts(baseline)
        attack_icmp = t3_2_icmp_counts(attack)
    except PairError as error:
        raise ArtifactError(str(error)) from error

    originals = [report[0] for report in baseline_pfcp if len(report) == 1]
    doubled = [tuple(value * 2 for value in item) for item in originals]
    relations = {
        "three_reports": len(baseline_pfcp) == len(attack_pfcp) == 3,
        "one_baseline_ie": len(originals) == len(baseline_pfcp),
        "two_identical_attack_ies": all(
            len(report) == 2 and report[0] == report[1]
            for report in attack_pfcp
        ),
        "identical_producer_usage": originals
        == [report[0] for report in attack_pfcp],
        "baseline_pfcp_equals_gy": originals == baseline_gy,
        "attack_gy_exact_x2": attack_gy == doubled,
        "pfcp_responses_accepted": t3_2_accepted(attack, "pfcp") == 3,
        "cca_updates_accepted": t3_2_accepted(attack, "gy") == 3,
        "intended_requests_equal": baseline_icmp["echo_request"]
        == attack_icmp["echo_request"] == 15200,
        "reply_capture_noise_bounded": abs(
            baseline_icmp["echo_reply"] - attack_icmp["echo_reply"]
        ) <= 1,
        "backend_charge_increased": attack_charge["charged_cents"]
        > baseline_charge["charged_cents"],
    }
    failures.extend(
        f"semantic relation failed: {name}"
        for name, passed in relations.items()
        if not passed
    )
    observations = [
        f"checksums={checksum_count}",
        f"parseable_pcaps={pcap_count}",
        f"claim={case['validation']}",
        "semantic[PFCP-intra-message-duplication]=PASS (3 requests, 2 identical IEs each)",
        (
            "semantic[PFCP-to-Gy-exact-x2]=PASS "
            f"({sum(item[0] for item in originals)} -> "
            f"{sum(item[0] for item in attack_gy)} bytes)"
        ),
        (
            "semantic[paired-backend-charge]=PASS "
            f"({baseline_charge['charged_cents']} -> "
            f"{attack_charge['charged_cents']} cents)"
        ),
        (
            "semantic[capture-noise-separated]=PASS "
            f"(requests 15200/15200, replies "
            f"{baseline_icmp['echo_reply']}/{attack_icmp['echo_reply']})"
        ),
        "semantic[claim-boundary]=observed CCR-U/CCA-U; CCR-I/T not claimed",
    ]
    observations.extend(f"FAIL {failure}" for failure in failures)
    return not failures, observations


def verify_t3_seq1(case: dict, config: dict) -> tuple[bool, list[str]]:
    directory = ROOT / config["path"]
    checksum_count = verify_checksums(directory)
    pcap_count = ensure_pcaps_parse(directory)
    result = load_json(directory / config["result"])
    baseline, attack = directory / "baseline", directory / "attack"
    failures = compare_expected(result, config["expected"])
    try:
        baseline_pfcp = t3_2_pfcp(baseline)
        attack_pfcp = t3_2_pfcp(attack)
        sequences = t3_3_pfcp_sequences(attack)
        baseline_gy = t3_2_gy(baseline)
        attack_gy = t3_2_gy(attack)
        baseline_charge = t3_2_charge(baseline)
        attack_charge = t3_2_charge(attack)
    except PairError as error:
        raise ArtifactError(str(error)) from error
    originals = [report[0] for report in baseline_pfcp if len(report) == 1]
    replayed = [report[0] for report in attack_pfcp if len(report) == 1]
    pairs = [replayed[index:index + 2] for index in range(0, len(replayed), 2)]
    sequence_pairs = [sequences[index:index + 2] for index in range(0, len(sequences), 2)]
    relations = {
        "three_to_six_reports": len(originals) == 3 and len(replayed) == 6,
        "semantic_pairs_identical": len(pairs) == 3
        and all(len(pair) == 2 and pair[0] == pair[1] for pair in pairs),
        "fresh_pfcp_transactions": len(sequence_pairs) == 3
        and all(len(pair) == 2 and pair[0] != pair[1] for pair in sequence_pairs),
        "baseline_matches_pair_originals": originals == [pair[0] for pair in pairs],
        "pfcp_equals_gy": baseline_gy == originals and attack_gy == replayed,
        "all_pfcp_accepted": t3_2_accepted(attack, "pfcp") == 6,
        "all_cca_accepted": t3_2_accepted(attack, "gy") == 6,
        "backend_charge_increased": attack_charge["charged_cents"]
        > baseline_charge["charged_cents"],
    }
    failures.extend(
        f"semantic relation failed: {name}"
        for name, passed in relations.items()
        if not passed
    )
    observations = [
        f"checksums={checksum_count}",
        f"parseable_pcaps={pcap_count}",
        f"claim={case['validation']}",
        (
            "semantic[fresh-transaction-semantic-replay]=PASS "
            f"(PFCP sequence pairs={sequence_pairs})"
        ),
        "semantic[PFCP-to-Gy-replay]=PASS (3 original -> 6 accepted updates)",
        (
            "semantic[paired-backend-charge]=PASS "
            f"({baseline_charge['charged_cents']} -> "
            f"{attack_charge['charged_cents']} cents)"
        ),
        "semantic[claim-boundary]=semantic PFCP replay; transport retransmission not claimed",
    ]
    observations.extend(f"FAIL {failure}" for failure in failures)
    return not failures, observations


def verify_t3_del1(case: dict, config: dict) -> tuple[bool, list[str]]:
    directory = ROOT / config["path"]
    checksum_count = verify_checksums(directory)
    pcap_count = ensure_pcaps_parse(directory)
    result = load_json(directory / config["result"])
    baseline, attack = directory / "baseline", directory / "attack"
    failures = compare_expected(result, config["expected"])
    try:
        baseline_pfcp = live_pfcp_usage(baseline)
        reports = t3_4_suppressed_pfcp(attack)
        baseline_gy = t3_2_gy(baseline)
        attack_gy = t3_2_gy(attack)
        baseline_charge = t3_2_charge(baseline)
        attack_charge = t3_2_charge(attack)
        baseline_packets = live_packet_count(baseline / "gtpu.pcap")
        attack_packets = live_packet_count(attack / "gtpu.pcap")
    except PairError as error:
        raise ArtifactError(str(error)) from error
    inferred = [
        (item["total"], item["inferred_omitted_uplink"], item["downlink"])
        for item in reports
    ]
    expected_attack_gy = [
        (item["downlink"], 0, item["downlink"]) for item in reports
    ]
    relations = {
        "identical_workload": baseline_packets == attack_packets == 30400,
        "five_reports": len(reports) == len(baseline_pfcp) == 5,
        "flags_and_length": all(
            item["tovol"] and not item["ulvol"] and item["dlvol"]
            and not item["uplink_present"] and item["ie_length"] == 41
            for item in reports
        ),
        "inferred_actual_equals_baseline": inferred == baseline_pfcp,
        "baseline_pfcp_equals_gy": baseline_pfcp == baseline_gy,
        "attack_gy_suppresses_only_ul": attack_gy == expected_attack_gy,
        "all_pfcp_accepted": t3_2_accepted(attack, "pfcp") == 5,
        "all_cca_accepted": t3_2_accepted(attack, "gy") == 5,
        "backend_charge_decreased": attack_charge["charged_cents"]
        < baseline_charge["charged_cents"],
    }
    failures.extend(
        f"semantic relation failed: {name}"
        for name, passed in relations.items()
        if not passed
    )
    omitted = sum(item["inferred_omitted_uplink"] for item in reports)
    observations = [
        f"checksums={checksum_count}",
        f"parseable_pcaps={pcap_count}",
        f"claim={case['validation']}",
        (
            "semantic[TOVOL=1,ULVOL=0,DLVOL=1]="
            f"{'PASS' if relations['flags_and_length'] else 'FAIL'} "
            "(Type 66 length=41)"
        ),
        (
            "semantic[directional-omission]="
            f"{'PASS' if relations['inferred_actual_equals_baseline'] else 'FAIL'} "
            f"(omitted_ul={omitted} bytes)"
        ),
        (
            "semantic[PFCP-to-Gy]="
            f"{'PASS' if relations['baseline_pfcp_equals_gy'] and relations['attack_gy_suppresses_only_ul'] else 'FAIL'} "
            "(CC-Input-Octets=0; output preserved)"
        ),
        (
            "semantic[paired-backend-charge]="
            f"{'PASS' if relations['backend_charge_decreased'] else 'FAIL'} "
            f"({baseline_charge['charged_cents']} -> "
            f"{attack_charge['charged_cents']} cents)"
        ),
        "semantic[claim-boundary]=observed CCR-U/CCA-U; CCR-I/T not claimed",
    ]
    observations.extend(f"FAIL {failure}" for failure in failures)
    return not failures, observations


def verify_t2_ins1(case: dict, config: dict) -> tuple[bool, list[str]]:
    directory = ROOT / config["path"]
    checksum_count = verify_checksums(directory)
    pcap_count = ensure_pcaps_parse(directory)
    result = load_json(directory / config["result"])
    baseline = directory / "baseline"
    attack = directory / "attack"
    failures = compare_expected(result, config["expected"])
    try:
        baseline_established = t2_established_urrs(baseline)
        attack_established = t2_established_urrs(attack)
        baseline_pfcp = t2_pfcp_usage_by_urr(baseline)
        attack_pfcp = t2_pfcp_usage_by_urr(attack)
        baseline_updates = t2_pfcp_usage_by_urr(
            baseline,
            "pfcp.msg_type == 56 && pfcp.volume_measurement.tovol",
        )
        attack_updates = t2_pfcp_usage_by_urr(
            attack,
            "pfcp.msg_type == 56 && pfcp.volume_measurement.tovol",
        )
        baseline_pfcp_aggregate = t2_aggregate_streams(baseline_pfcp)
        attack_pfcp_aggregate = t2_aggregate_streams(attack_pfcp)
        baseline_update_aggregate = t2_aggregate_streams(baseline_updates)
        attack_update_aggregate = t2_aggregate_streams(attack_updates)
        baseline_gy_aggregate, baseline_gy_count = t2_gy_update_aggregate(
            baseline
        )
        attack_gy_aggregate, attack_gy_count = t2_gy_update_aggregate(attack)
        primary_urr, duplicate_urr, trace_count = t2_trace_urrs(attack)
        baseline_charge = live_charge(baseline)
        attack_charge = live_charge(attack)
        baseline_requests, baseline_successful = t2_successful_cca(baseline)
        attack_requests, attack_successful = t2_successful_cca(attack)
        baseline_packets = live_packet_count(baseline / "gtpu.pcap")
        attack_packets = live_packet_count(attack / "gtpu.pcap")
        baseline_app_packets, baseline_app_bytes = t1_application_flow(baseline)
        attack_app_packets, attack_app_bytes = t1_application_flow(attack)
        baseline_icmp_count, baseline_icmp_bytes = t1_icmp_noise(baseline)
        attack_icmp_count, attack_icmp_bytes = t1_icmp_noise(attack)
        baseline_workload = t1_workload(baseline)
        attack_workload = t1_workload(attack)
    except PairError as error:
        raise ArtifactError(str(error)) from error

    expected_workload = {
        "workload_id": "W3_EXACT_1MIB_UL_3MIB_DL",
        "ul_application_bytes": 1_048_576,
        "dl_application_bytes": 3_145_728,
        "total_application_bytes": 4_194_304,
        "datagram_payload_bytes": 1024,
    }
    attack_streams = list(attack_pfcp.values())
    relations = {
        "identical_exact_workload": baseline_workload
        == attack_workload
        == expected_workload,
        "identical_application_gtpu_flow": baseline_app_packets
        == attack_app_packets
        == 4096
        and baseline_app_bytes
        == attack_app_bytes
        == 4_194_304,
        "one_baseline_urr": len(baseline_established)
        == len(baseline_pfcp)
        == 1,
        "two_attack_urrs": len(attack_established)
        == len(attack_pfcp)
        == 2
        and {primary_urr, duplicate_urr} == attack_established,
        "producer_trace_distinct_urrs": primary_urr != duplicate_urr
        and trace_count >= 1,
        "duplicate_pfcp_streams_equal": len(attack_streams) == 2
        and attack_streams[0] == attack_streams[1],
        "baseline_pfcp_updates_equal_gy": baseline_update_aggregate
        == baseline_gy_aggregate,
        "attack_pfcp_updates_equal_gy": attack_update_aggregate
        == attack_gy_aggregate,
        "attack_pfcp_responses_accepted": accepted_pfcp_responses(attack)
        == sum(len(stream) for stream in attack_updates.values()),
        "all_cca_accepted": baseline_requests == baseline_successful
        and attack_requests == attack_successful
        and attack_requests > 0,
        "backend_charge_increased": attack_charge["charged_cents"]
        > baseline_charge["charged_cents"],
    }
    for label, passed in relations.items():
        if not passed:
            failures.append(f"semantic relation failed: {label}")

    observed = {
        "application_gtpu_packet_count_each": baseline_app_packets,
        "application_gtpu_payload_bytes_each": baseline_app_bytes,
        "total_gtpu_packet_count": {
            "baseline": baseline_packets,
            "attack": attack_packets,
        },
        "icmp_noise": {
            "baseline_count": baseline_icmp_count,
            "attack_count": attack_icmp_count,
            "baseline_bytes": baseline_icmp_bytes,
            "attack_bytes": attack_icmp_bytes,
        },
        "baseline_urr_count": len(baseline_established),
        "attack_urr_count": len(attack_established),
        "reports_per_attack_urr": len(attack_streams[0]),
        "pfcp_usage_sum": {
            "baseline": baseline_pfcp_aggregate[0],
            "attack": attack_pfcp_aggregate[0],
        },
        "gy_usage_sum": {
            "baseline": baseline_gy_aggregate[0],
            "attack": attack_gy_aggregate[0],
        },
        "gy_usage_request_count": {
            "baseline": baseline_gy_count,
            "attack": attack_gy_count,
        },
        "baseline_charge_cents": baseline_charge["charged_cents"],
        "attack_charge_cents": attack_charge["charged_cents"],
        "charge_delta_cents": attack_charge["charged_cents"]
        - baseline_charge["charged_cents"],
        "semantic_relations": relations,
    }
    failures.extend(compare_expected(observed, {
        key: result[key]
        for key in observed
    }))
    observations = [
        f"checksums={checksum_count}",
        f"parseable_pcaps={pcap_count}",
        f"claim={case['validation']}",
        (
            "semantic[identical-application-workload]=PASS "
            f"(packets={baseline_app_packets}, payload={baseline_app_bytes})"
        ),
        "semantic[duplicate-urr-attribution]=PASS (1 baseline -> 2 attack)",
        (
            "semantic[pfcp-to-gy-aggregate]=PASS "
            f"({baseline_gy_aggregate[0]} -> {attack_gy_aggregate[0]} bytes)"
        ),
        (
            "semantic[paired-backend-charge]=PASS "
            f"({observed['baseline_charge_cents']} -> "
            f"{observed['attack_charge_cents']} cents)"
        ),
        (
            "semantic[claim-boundary]=PFCP Session Report to CCR-U/CCA-U; "
            "CCR-I/T, terminal PFCP-to-Gy, and universal pricing not claimed"
        ),
    ]
    observations.extend(f"FAIL {failure}" for failure in failures)
    return not failures, observations


def verify_t1_mod1(case: dict, config: dict) -> tuple[bool, list[str]]:
    directory = ROOT / config["path"]
    checksum_count = verify_checksums(directory)
    pcap_count = ensure_pcaps_parse(directory)
    result = load_json(directory / config["result"])
    failures = compare_expected(result, config["expected"])
    try:
        expected = config["verification"]
        baseline_request = t1_n7_frame_5qi(
            directory / "baseline-n7.pcap", expected["baseline_request_frame"]
        )
        baseline_response = t1_n7_frame_5qi(
            directory / "baseline-n7.pcap", expected["baseline_response_frame"]
        )
        attack_request = t1_n7_frame_5qi(
            directory / "attack-n7.pcap", expected["attack_request_frame"]
        )
        attack_response = t1_n7_frame_5qi(
            directory / "attack-n7.pcap", expected["attack_response_frame"]
        )
        baseline_usage, baseline_reports, baseline_consistent = t1_pfcp_file_usage(
            directory / "baseline-pfcp.pcap"
        )
        attack_usage, attack_reports, attack_consistent = t1_pfcp_file_usage(
            directory / "attack-pfcp.pcap"
        )
        baseline_ccr, baseline_groups, baseline_qci, baseline_success = (
            t1_gy_file_identity(directory / "baseline-gy.pcap")
        )
        attack_ccr, attack_groups, attack_qci, attack_success = (
            t1_gy_file_identity(directory / "attack-gy.pcap")
        )
        experiment = t1_experiment_values(directory / "experiment.json")
    except PairError as error:
        raise ArtifactError(str(error)) from error

    relations = {
        "baseline_n7_9_to_9": baseline_request == baseline_response == 9,
        "attack_n7_9_to_6": attack_request == 9 and attack_response == 6,
        "identical_pfcp_usage": baseline_usage
        == attack_usage
        == expected["pfcp_usage_bytes"],
        "four_consistent_pfcp_reports": baseline_reports
        == attack_reports
        == baseline_consistent
        == attack_consistent
        == expected["pfcp_report_count"],
        "baseline_gy_identity_9": baseline_groups == baseline_qci == {9},
        "attack_gy_identity_6": attack_groups == {6} and attack_qci == {6},
        "all_cca_successful": baseline_ccr
        == baseline_success
        == attack_ccr
        == attack_success
        == expected["ccr_count"],
        "documented_tariffs": experiment["tariff_unit_bytes"] == 1_000_000
        and experiment["baseline_tariff_cents"] == 1
        and experiment["attack_tariff_cents"] == 10,
        "exact_10x_charge": experiment["baseline_charge_cents"] == 22
        and experiment["attack_charge_cents"] == 220,
    }
    for label, passed in relations.items():
        if not passed:
            failures.append(f"semantic relation failed: {label}")

    observed = {
        "pfcp_usage_bytes_each": baseline_usage,
        "pfcp_usage_report_count_each": baseline_reports,
        "gy_ccr_count_each": baseline_ccr,
        "baseline_charge_cents": experiment["baseline_charge_cents"],
        "attack_charge_cents": experiment["attack_charge_cents"],
        "charge_multiplier": 10,
        "charge_delta_cents": experiment["attack_charge_cents"]
        - experiment["baseline_charge_cents"],
        "semantic_relations": relations,
    }
    failures.extend(compare_expected(observed, {
        key: result[key]
        for key in observed
    }))
    observations = [
        f"checksums={checksum_count}",
        f"parseable_pcaps={pcap_count}",
        f"claim={case['validation']}",
        (
            "semantic[identical-pfcp-usage]=PASS "
            f"({baseline_reports} reports, {baseline_usage} bytes each run)"
        ),
        "semantic[n7-rating-context]=PASS (9->9 baseline, 9->6 attack)",
        (
            "semantic[gy-acceptance]=PASS "
            f"({baseline_ccr}/{baseline_success} baseline, "
            f"{attack_ccr}/{attack_success} attack CCR/CCA)"
        ),
        (
            "semantic[exact-10x-charge]=PASS "
            f"({observed['baseline_charge_cents']} -> "
            f"{observed['attack_charge_cents']} cents)"
        ),
        (
            "semantic[claim-boundary]=documented 1-versus-10 cent testbed "
            "tariffs; monetary values are not universal 5QI prices"
        ),
    ]
    observations.extend(f"FAIL {failure}" for failure in failures)
    return not failures, observations


def verify_t4_mod1(case: dict, config: dict) -> tuple[bool, list[str]]:
    directory = ROOT / config["path"]
    checksum_count = verify_checksums(directory)
    pcap_count = ensure_pcaps_parse(directory)
    result = load_json(directory / config["result"])
    baseline = directory / "baseline"
    attack = directory / "attack"
    failures = compare_expected(result, config["expected"])
    try:
        baseline_pfcp = t4_live_pfcp_usage(baseline)
        baseline_gy = t4_live_gy_usage(baseline)
        attack_pfcp = t4_live_pfcp_usage(attack)
        attack_gy = t4_live_gy_usage(attack)
        trace_actual_ul, trace_reported_ul = t4_live_trace_usage(attack)
        baseline_charge = live_charge(baseline)
        attack_charge = live_charge(attack)
        baseline_packets = live_packet_count(baseline / "gtpu.pcap")
        attack_packets = live_packet_count(attack / "gtpu.pcap")
        baseline_terminal = t4_terminal_pfcp_usage(baseline)
        attack_terminal = t4_terminal_pfcp_usage(attack)
        baseline_session, baseline_numbers, baseline_terminations = (
            t4_gy_session(baseline)
        )
        attack_session, attack_numbers, attack_terminations = t4_gy_session(attack)
    except PairError as error:
        raise ArtifactError(str(error)) from error

    baseline_aggregate = tuple(
        sum(row[index] for row in baseline_pfcp) for index in range(3)
    )
    attack_aggregate = tuple(
        sum(row[index] for row in attack_pfcp) for index in range(3)
    )
    attack_ul = [row[1] for row in attack_pfcp]
    attack_dl = [row[2] for row in attack_pfcp]
    attack_gy_ul = [row[1] for row in attack_gy]
    attack_gy_dl = [row[2] for row in attack_gy]
    relations = {
        "identical_gtpu_packet_count": baseline_packets == attack_packets
        and baseline_packets > 0,
        "identical_report_count": len(baseline_pfcp) == len(attack_pfcp)
        and len(attack_pfcp) > 0,
        "baseline_pfcp_equals_gy": baseline_pfcp == baseline_gy,
        "baseline_pfcp_aggregate_equals_attack": baseline_aggregate
        == attack_aggregate,
        "attack_pfcp_equals_trace_actual_ul": attack_ul == trace_actual_ul,
        "attack_trace_exact_x5": trace_reported_ul
        == [value * 5 for value in trace_actual_ul],
        "attack_trace_equals_gy_input": trace_reported_ul == attack_gy_ul,
        "attack_downlink_unchanged": attack_dl == attack_gy_dl,
        "pfcp_reports_accepted": accepted_pfcp_responses(attack)
        == len(attack_pfcp),
        "cca_updates_accepted": accepted_cca_updates(attack) == len(attack_gy),
        "clean_pfcp_release": t4_clean_release(baseline)
        and t4_clean_release(attack),
        "terminal_pfcp_usage_consistent": baseline_terminal == attack_terminal,
        "fresh_representative_sessions": baseline_session != attack_session,
        "ccr_u_sequence": baseline_numbers == attack_numbers == list(range(1, 6)),
        "ccr_t_not_generated": baseline_terminations == attack_terminations == 0,
        "deterministic_charge": baseline_charge["charged_cents"] == 27
        and attack_charge["charged_cents"] == 69,
    }
    for label, passed in relations.items():
        if not passed:
            failures.append(f"semantic relation failed: {label}")

    observed = {
        "gtpu_packet_count_each": baseline_packets,
        "report_count": len(attack_pfcp),
        "baseline_actual_ul_sum": sum(item[1] for item in baseline_pfcp),
        "attack_reported_ul_sum": sum(trace_reported_ul),
        "baseline_gy_total_bytes": sum(item[0] for item in baseline_gy),
        "attack_gy_total_bytes": sum(item[0] for item in attack_gy),
        "baseline_charge_cents": baseline_charge["charged_cents"],
        "attack_charge_cents": attack_charge["charged_cents"],
        "charge_delta_cents": attack_charge["charged_cents"]
        - baseline_charge["charged_cents"],
    }
    failures.extend(compare_expected(observed, {
        key: result[key]
        for key in observed
    }))

    repetition_sessions: list[str] = []
    repetition_failures: list[str] = []
    repetitions = directory / "repetitions"
    for index in range(1, 4):
        baseline_rep = repetitions / f"baseline-{index}"
        attack_rep = repetitions / f"attack-{index}"
        try:
            baseline_rep_pfcp = t4_live_pfcp_usage(baseline_rep)
            attack_rep_pfcp = t4_live_pfcp_usage(attack_rep)
            baseline_rep_gy = t4_live_gy_usage(baseline_rep)
            attack_rep_gy = t4_live_gy_usage(attack_rep)
            baseline_rep_session = t4_gy_session(baseline_rep)[0]
            attack_rep_session = t4_gy_session(attack_rep)[0]
            baseline_rep_charge = live_charge(baseline_rep)["charged_cents"]
            attack_rep_charge = live_charge(attack_rep)["charged_cents"]
        except PairError as error:
            repetition_failures.append(f"repetition {index}: {error}")
            continue
        repetition_sessions.extend((baseline_rep_session, attack_rep_session))
        checks = {
            "same_pfcp_multiset": sorted(baseline_rep_pfcp)
            == sorted(attack_rep_pfcp) == sorted(baseline_pfcp),
            "baseline_pfcp_equals_gy": baseline_rep_pfcp == baseline_rep_gy,
            "attack_input_exact_x5": [item[1] for item in attack_rep_gy]
            == [item[1] * 5 for item in attack_rep_pfcp],
            "attack_output_preserved": [item[2] for item in attack_rep_gy]
            == [item[2] for item in attack_rep_pfcp],
            "accepted_pfcp": accepted_pfcp_responses(attack_rep) == 5,
            "accepted_gy": accepted_cca_updates(attack_rep) == 5,
            "clean_release": t4_clean_release(baseline_rep)
            and t4_clean_release(attack_rep),
            "charge": baseline_rep_charge == 27 and attack_rep_charge == 69,
        }
        repetition_failures.extend(
            f"repetition {index}: {label}"
            for label, passed in checks.items() if not passed
        )
    if len(set(repetition_sessions)) != 6:
        repetition_failures.append("six sanitized Diameter sessions are not distinct")
    failures.extend(repetition_failures)
    observations = [
        f"checksums={checksum_count}",
        f"parseable_pcaps={pcap_count}",
        f"claim={case['validation']} (Gy semantic analogue)",
        (
            "semantic[identical-workload]=PASS "
            f"(gtpu_packets_each={baseline_packets}, reports={len(attack_pfcp)})"
        ),
        (
            "semantic[exact-x5-pair]=PASS "
            f"(actual_ul={observed['baseline_actual_ul_sum']}, "
            f"attack_gy_ul={observed['attack_reported_ul_sum']})"
        ),
        "semantic[pfcp-trace-gy-directional]=PASS (baseline and attack)",
        (
            "semantic[paired-backend-charge]=PASS "
            f"({observed['baseline_charge_cents']} -> "
            f"{observed['attack_charge_cents']} cents)"
        ),
        "semantic[three-pair-repetition]=PASS (3 baseline + 3 attack)",
        "semantic[clean-release]=PASS (accepted PFCP deletion; CCR-T not generated)",
        (
            "semantic[claim-boundary]=Gy/SigScale CCR-U/CCA-U pair; "
            "native N40/CHF and CCR-I/T not claimed"
        ),
    ]
    observations.extend(f"FAIL {failure}" for failure in failures)
    return not failures, observations


def verify_t4_dup1(case: dict, config: dict) -> tuple[bool, list[str]]:
    directory = ROOT / config["path"]
    checksum_count = verify_checksums(directory)
    pcap_count = ensure_pcaps_parse(directory)
    result = load_json(directory / config["result"])
    baseline, attack = directory / "baseline", directory / "attack"
    failures = compare_expected(result, config["expected"])
    try:
        baseline_pfcp = live_pfcp_usage(baseline)
        attack_pfcp = live_pfcp_usage(attack)
        baseline_gy = t4_2_gy_usage_groups(baseline)
        attack_gy = t4_2_gy_usage_groups(attack)
        baseline_cca = t4_2_cca_result_groups(baseline)
        attack_cca = t4_2_cca_result_groups(attack)
        baseline_charge = live_charge(baseline)
        attack_charge = live_charge(attack)
        baseline_packets = live_packet_count(baseline / "gtpu.pcap")
        attack_packets = live_packet_count(attack / "gtpu.pcap")
    except PairError as error:
        raise ArtifactError(str(error)) from error

    relations = {
        "identical_gtpu_packet_count": baseline_packets == attack_packets
        and baseline_packets > 0,
        "identical_pfcp_report_count": len(baseline_pfcp) == len(attack_pfcp)
        and len(attack_pfcp) > 0,
        "identical_pfcp_producer_usage": baseline_pfcp == attack_pfcp,
        "baseline_one_usu_per_ccr": baseline_gy
        == [[usage] for usage in baseline_pfcp],
        "attack_two_identical_usu_per_ccr": attack_gy
        == [[usage, usage] for usage in attack_pfcp],
        "attack_gy_exact_x2": sum(
            item[0] for group in attack_gy for item in group
        ) == 2 * sum(item[0] for item in attack_pfcp),
        "pfcp_reports_accepted": accepted_pfcp_responses(attack)
        == len(attack_pfcp),
        "baseline_cca_success": len(baseline_cca) == len(baseline_pfcp)
        and all(codes == [2001, 2001] for codes in baseline_cca),
        "attack_both_mscc_accepted": len(attack_cca) == len(attack_pfcp)
        and all(codes == [2001, 2001, 2001] for codes in attack_cca),
        "backend_charge_increased": attack_charge["charged_cents"]
        > baseline_charge["charged_cents"],
    }
    failures.extend(
        f"semantic relation failed: {name}"
        for name, passed in relations.items()
        if not passed
    )
    original_sum = sum(item[0] for item in attack_pfcp)
    duplicated_sum = sum(
        item[0] for group in attack_gy for item in group
    )
    observed = {
        "gtpu_packet_count_each": baseline_packets,
        "report_count": len(attack_pfcp),
        "baseline_mscc_per_ccr": 1,
        "attack_mscc_per_ccr": 2,
        "original_usage_sum": original_sum,
        "duplicated_gy_usage_sum": duplicated_sum,
        "usage_multiplier": 2,
        "baseline_charge_cents": baseline_charge["charged_cents"],
        "attack_charge_cents": attack_charge["charged_cents"],
        "charge_delta_cents": attack_charge["charged_cents"]
        - baseline_charge["charged_cents"],
        "accepted_pfcp_responses": accepted_pfcp_responses(attack),
        "accepted_cca_updates": len(attack_cca),
        "accepted_attack_mscc_results": 2 * len(attack_cca),
        "semantic_relations": relations,
    }
    failures.extend(compare_expected(observed, {
        key: result[key]
        for key in observed
    }))
    observations = [
        f"checksums={checksum_count}",
        f"parseable_pcaps={pcap_count}",
        f"claim={case['validation']} (Gy semantic analogue)",
        (
            "semantic[identical-workload]=PASS "
            f"(gtpu_packets_each={baseline_packets}, reports={len(attack_pfcp)})"
        ),
        (
            "semantic[intra-CCR-identical-MSCC/USU-x2]=PASS "
            f"({original_sum} -> {duplicated_sum} bytes)"
        ),
        (
            "semantic[all-duplicated-MSCC-accepted]=PASS "
            f"(CCA-U={len(attack_cca)}, MSCC-results={2 * len(attack_cca)})"
        ),
        (
            "semantic[paired-backend-charge]=PASS "
            f"({baseline_charge['charged_cents']} -> "
            f"{attack_charge['charged_cents']} cents)"
        ),
        (
            "semantic[claim-boundary]=Gy/SigScale CCR-U/CCA-U pair; "
            "native N40/CHF and CCR-I/T not claimed"
        ),
    ]
    observations.extend(f"FAIL {failure}" for failure in failures)
    return not failures, observations


def verify_t4_seq1(case: dict, config: dict) -> tuple[bool, list[str]]:
    directory = ROOT / config["path"]
    checksum_count = verify_checksums(directory)
    pcap_count = ensure_pcaps_parse(directory)
    result = load_json(directory / config["result"])
    baseline, attack = directory / "baseline", directory / "attack"
    failures = compare_expected(result, config["expected"])
    try:
        baseline_pfcp = live_pfcp_usage(baseline)
        attack_pfcp = live_pfcp_usage(attack)
        baseline_gy = t4_2_gy_usage_groups(baseline)
        attack_gy = t4_2_gy_usage_groups(attack)
        baseline_updates = t4_3_ccr_updates(baseline)
        attack_updates = t4_3_ccr_updates(attack)
        pairs = t4_3_replay_pairs(attack_updates)
        baseline_cca = t4_2_cca_result_groups(baseline)
        attack_cca = t4_2_cca_result_groups(attack)
        baseline_charge = live_charge(baseline)
        attack_charge = live_charge(attack)
        baseline_packets = live_packet_count(baseline / "gtpu.pcap")
        attack_packets = live_packet_count(attack / "gtpu.pcap")
    except PairError as error:
        raise ArtifactError(str(error)) from error

    pair_relations = [
        {
            "request_number": original["request_number"],
            "same_session": original["session_id"] == replay["session_id"],
            "same_request_number":
                original["request_number"] == replay["request_number"],
            "same_usage": original["usage"] == replay["usage"],
            "fresh_hop_by_hop":
                original["hop_by_hop_id"] != replay["hop_by_hop_id"],
            "fresh_end_to_end":
                original["end_to_end_id"] != replay["end_to_end_id"],
        }
        for original, replay in pairs
    ]
    relations = {
        "identical_gtpu_packet_count": baseline_packets == attack_packets
        and baseline_packets > 0,
        "identical_pfcp_report_count": len(baseline_pfcp) == len(attack_pfcp)
        and len(attack_pfcp) > 0,
        "identical_pfcp_aggregate": t4_3_aggregate(baseline_pfcp)
        == t4_3_aggregate(attack_pfcp),
        "baseline_pfcp_equals_gy": [group[0] for group in baseline_gy]
        == baseline_pfcp,
        "attack_pfcp_equals_original_ccr": [
            pair[0]["usage"] for pair in pairs
        ] == attack_pfcp,
        "five_semantic_replay_pairs": len(pairs) == 5
        and all(
            all(value for key, value in item.items() if key != "request_number")
            for item in pair_relations
        ),
        "attack_ten_single_usu_ccr": len(attack_gy) == 10
        and all(len(group) == 1 for group in attack_gy),
        "attack_gy_exact_x2": sum(group[0][0] for group in attack_gy)
        == 2 * sum(item[0] for item in attack_pfcp),
        "pfcp_reports_accepted": accepted_pfcp_responses(attack)
        == len(attack_pfcp),
        "baseline_cca_success": len(baseline_cca) == 5
        and all(codes == [2001, 2001] for codes in baseline_cca),
        "attack_ten_cca_success": len(attack_cca) == 10
        and all(codes == [2001, 2001] for codes in attack_cca),
        "backend_charge_increased": attack_charge["charged_cents"]
        > baseline_charge["charged_cents"],
    }
    failures.extend(
        f"semantic relation failed: {name}"
        for name, passed in relations.items()
        if not passed
    )
    original_sum = sum(item[0] for item in attack_pfcp)
    replayed_sum = sum(group[0][0] for group in attack_gy)
    observed = {
        "gtpu_packet_count_each": baseline_packets,
        "pfcp_report_count": len(attack_pfcp),
        "semantic_replay_pair_count": len(pairs),
        "attack_ccr_update_count": len(attack_updates),
        "pair_relations": pair_relations,
        "original_usage_sum": original_sum,
        "replayed_gy_usage_sum": replayed_sum,
        "usage_multiplier": 2,
        "baseline_charge_cents": baseline_charge["charged_cents"],
        "attack_charge_cents": attack_charge["charged_cents"],
        "charge_delta_cents": attack_charge["charged_cents"]
        - baseline_charge["charged_cents"],
        "accepted_pfcp_responses": accepted_pfcp_responses(attack),
        "accepted_cca_updates": len(attack_cca),
        "semantic_relations": relations,
    }
    failures.extend(compare_expected(observed, {
        key: result[key]
        for key in observed
    }))
    observations = [
        f"checksums={checksum_count}",
        f"parseable_pcaps={pcap_count}",
        f"claim={case['validation']} (Gy semantic analogue)",
        (
            "semantic[identical-workload]=PASS "
            f"(gtpu_packets_each={baseline_packets}, reports={len(attack_pfcp)})"
        ),
        (
            "semantic[fresh-transport-semantic-replay]=PASS "
            f"(pairs={len(pairs)}, CCR-U={len(attack_updates)})"
        ),
        (
            "semantic[exact-replay-x2]=PASS "
            f"({original_sum} -> {replayed_sum} bytes)"
        ),
        (
            "semantic[all-replays-accepted]=PASS "
            f"(CCA-U={len(attack_cca)})"
        ),
        (
            "semantic[paired-backend-charge]=PASS "
            f"({baseline_charge['charged_cents']} -> "
            f"{attack_charge['charged_cents']} cents)"
        ),
        (
            "semantic[claim-boundary]=Gy/SigScale CCR-U/CCA-U pair; "
            "native N40/CHF and CCR-I/T not claimed"
        ),
    ]
    observations.extend(f"FAIL {failure}" for failure in failures)
    return not failures, observations


def verify_cell_public_package(
    case: dict, config: dict
) -> tuple[bool, list[str]]:
    """Verify a sanitized 3x3 public package without trusting its prose."""
    directory = ROOT / config["path"]
    checksum_count = verify_checksums(directory)
    pcap_count = ensure_pcaps_parse(directory)
    result = load_json(directory / config["result"])
    failures: list[str] = []

    expected_repetitions = case["repetitions"]
    baseline = result.get("baseline_charge_series")
    attack = result.get("attack_charge_series")
    observed_charge_series: dict[str, list[int]] = {}
    arithmetic_valid = True
    for mode in ("baseline", "attack"):
        balances = []
        for record_path in sorted(
            (directory / "captures").glob(
                f"{mode}-run-*/ocs_balance_summary.json"
            )
        ):
            record = load_json(record_path)
            charged = record.get("charged_cents")
            before = record.get("before_cents")
            after = record.get("after_cents")
            if (
                not isinstance(charged, int)
                or not isinstance(before, int)
                or not isinstance(after, int)
                or before - after != charged
            ):
                arithmetic_valid = False
            balances.append(charged)
        observed_charge_series[mode] = balances
    relations = {
        "cell_identity": result.get("cell") == case["id"],
        "e2e_classification": result.get("classification") == "E2E",
        "package_passed": result.get("passed") is True,
        "g1_mutation_accepted": result.get("g1_mutated_object_accepted") is True,
        "g2_state_effect": result.get("g2_target_semantic_state") is True,
        "g3_backend_effect": result.get("g3_persistent_backend_effect") is True,
        "baseline_repetitions": isinstance(baseline, list)
        and len(baseline) == expected_repetitions,
        "attack_repetitions": isinstance(attack, list)
        and len(attack) == expected_repetitions,
        "baseline_charge": baseline
        == [case["baseline_charge_cents"]] * expected_repetitions,
        "attack_charge": attack
        == [case["attack_charge_cents"]] * expected_repetitions,
        "ocs_balance_arithmetic": arithmetic_valid,
        "baseline_charge_from_ocs_records": observed_charge_series["baseline"]
        == baseline,
        "attack_charge_from_ocs_records": observed_charge_series["attack"]
        == attack,
    }
    failures.extend(
        f"semantic relation failed: {name}"
        for name, passed in relations.items()
        if not passed
    )
    observations = [
        f"checksums={checksum_count}",
        f"parseable_sanitized_pcaps={pcap_count}",
        f"claim={case['status']}",
        (
            "semantic[recomputed-ocs-balance-result]=PASS "
            f"({case['baseline_charge_cents']} -> "
            f"{case['attack_charge_cents']} cents; "
            f"{expected_repetitions}/{expected_repetitions} per mode)"
        ),
        "validation[V1-mutated-object-accepted]=PASS",
        "validation[V2-semantic-state-effect]=PASS",
        "validation[V3-ocs-balance-effect]=PASS",
        f"semantic[claim-boundary]={case['claim_boundary']}",
    ]
    observations.extend(f"FAIL {failure}" for failure in failures)
    return not failures, observations


def verify_case(case: dict, show_output: bool = True) -> bool:
    if case["status"] == "N/A":
        if show_output:
            print(f"{_display_id(case)} - {case['title']}")
            print(" Status           : N/A (0 native scenarios)")
            print(f" Reason           : {case['summary']}")
            print(" PoC validation   : NOT APPLICABLE")
        return True
    config = case.get("evidence")
    if not config:
        raise ArtifactError(f"{case['id']} has no evidence manifest entry")
    if config["backend"] == "cell_package":
        passed, observations = verify_cell_public_package(case, config)
        if show_output:
            print(f"{_display_id(case)} - {case['title']} / SANITIZED 3x3 VERIFICATION")
            print(f" Validation scope : {case['status']}")
            for observation in observations:
                print(f"  {observation}")
            print(f" PoC validation   : {'PASS' if passed else 'FAIL'}")
    elif config["backend"] in (
        "t1_mod1", "t2_ins1", "t3_mod1",
        "t3_dup1", "t3_seq1", "t3_del1",
        "t4_mod1", "t4_dup1", "t4_seq1",
    ):
        if config["backend"] == "t1_mod1":
            passed, observations = verify_t1_mod1(case, config)
        elif config["backend"] == "t2_ins1":
            passed, observations = verify_t2_ins1(case, config)
        elif config["backend"] == "t3_mod1":
            passed, observations = verify_t3_mod1(case, config)
        elif config["backend"] == "t3_dup1":
            passed, observations = verify_t3_dup1(case, config)
        elif config["backend"] == "t3_seq1":
            passed, observations = verify_t3_seq1(case, config)
        elif config["backend"] == "t3_del1":
            passed, observations = verify_t3_del1(case, config)
        elif config["backend"] == "t4_dup1":
            passed, observations = verify_t4_dup1(case, config)
        elif config["backend"] == "t4_seq1":
            passed, observations = verify_t4_seq1(case, config)
        else:
            passed, observations = verify_t4_mod1(case, config)
        if show_output:
            print(f"{_display_id(case)} - {case['title']} / PAIRED EVIDENCE VERIFICATION")
            print(f" Validation scope : {case['validation']}")
            for observation in observations:
                print(f"  {observation}")
            print(f" PoC validation   : {'PASS' if passed else 'FAIL'}")
    else:
        raise ArtifactError(
            f"unsupported verifier backend for {case['id']}: {config['backend']}"
        )
    return passed


def verify_all(cases: dict[str, dict]) -> bool:
    print("Paper ID   Status  PoC package               Result")
    print("-" * 58)
    all_passed = True
    passed_count = 0
    runnable_count = sum(case["status"] == "E2E" for case in cases.values())
    for case in cases.values():
        if case["status"] == "N/A":
            print(f"{_display_id(case):<10} N/A     no retained scenario      N/A")
            continue
        try:
            passed = verify_case(case, show_output=False)
            backend = case["evidence"]["backend"]
            label = (
                "sanitized 3x3"
                if backend == "cell_package"
                else "paired evidence"
            )
            print(f"{_display_id(case):<10} E2E     {label:<25} {'PASS' if passed else 'FAIL'}")
            all_passed &= passed
            passed_count += int(passed)
        except ArtifactError as error:
            print(f"{_display_id(case):<10} E2E     ERROR                     FAIL")
            print(f"  {error}", file=sys.stderr)
            all_passed = False
    print("-" * 58)
    print(
        f"Summary: {passed_count}/{runnable_count} runnable PASS; "
        "T1-INS N/A (0 scenarios)"
        if all_passed
        else f"Summary: FAIL ({passed_count}/{runnable_count} runnable passed)"
    )
    return all_passed


def _tshark_version() -> tuple[bool, str]:
    executable = shutil.which("tshark")
    if not executable:
        return False, "missing (requires TShark >= 3.6)"
    completed = subprocess.run(
        [executable, "--version"],
        capture_output=True,
        text=True,
        check=False,
    )
    match = re.search(r"TShark \(Wireshark\) (\d+)\.(\d+)(?:\.(\d+))?", completed.stdout)
    if not match:
        return False, "installed, but version could not be parsed"
    version = tuple(int(part or 0) for part in match.groups())
    return version >= (3, 6, 0), ".".join(str(part) for part in version)


def _analysis_csv_check(filename: str, expected_rows: int) -> tuple[bool, str]:
    path = ANALYSIS / filename
    try:
        with path.open(encoding="utf-8", newline="") as stream:
            reader = csv.DictReader(stream)
            rows = list(reader)
    except (OSError, csv.Error) as error:
        return False, str(error)
    has_hangul = any(
        re.search(r"[\uac00-\ud7a3]", value or "")
        for row in rows
        for value in row.values()
    )
    passed = len(rows) == expected_rows and not has_hangul
    detail = f"{len(rows)} rows; English-only={'yes' if not has_hangul else 'no'}"
    return passed, detail


def doctor(messages: list[dict], cases: dict[str, dict]) -> bool:
    checks: list[tuple[str, bool, str]] = []
    checks.append(("python", sys.version_info >= (3, 10), sys.version.split()[0]))
    checks.append(("PyYAML", True, yaml.__version__))
    tshark_ok, tshark_detail = _tshark_version()
    checks.append(("TShark >= 3.6", tshark_ok, tshark_detail))
    summary = load_json(ANALYSIS / "coverage_summary.json")
    counts = summary["counts"]
    checks.append(("messages", len(messages) == 11, str(len(messages))))
    checks.append(("cells", len(cases) == 20, str(len(cases))))
    checks.append((
        "runnable cells",
        sum(case["status"] == "E2E" for case in cases.values()) == 19,
        str(sum(case["status"] == "E2E" for case in cases.values())),
    ))
    checks.append((
        "cell scenario sum",
        sum(case["native_scenario_count"] for case in cases.values()) == 232,
        str(sum(case["native_scenario_count"] for case in cases.values())),
    ))
    checks.append(("native fields", counts["native_fields"] == 2280, str(counts["native_fields"])))
    checks.append(("charging-relevant fields", counts["native_relevant_fields"] == 2050, str(counts["native_relevant_fields"])))
    checks.append(("consistency constraints", counts["native_constraints"] == 81, str(counts["native_constraints"])))
    checks.append(("manipulation primitives", counts["manipulation_primitives"] == 5, str(counts["manipulation_primitives"])))
    checks.append(("native scenarios", counts["native_scenarios"] == 232, str(counts["native_scenarios"])))
    for label, filename, expected_rows in (
        ("all-field dataset", "all_field_positions_2280.csv", 2280),
        (
            "charging-field dataset",
            "charging_relevant_fields_2050.csv",
            2050,
        ),
        (
            "constraint dataset",
            "consistency_constraints_81.csv",
            81,
        ),
        ("scenario dataset", "threat_scenarios_232.csv", 232),
        ("derivation crosswalk", "derivation_crosswalk.csv", 2050),
    ):
        passed, detail = _analysis_csv_check(filename, expected_rows)
        checks.append((label, passed, detail))
    representative_ids = [
        case["representative_id"] for case in cases.values() if case["status"] == "E2E"
    ]
    checks.append((
        "representative IDs",
        len(representative_ids) == len(set(representative_ids)) == 19,
        str(len(representative_ids)),
    ))
    for case in cases.values():
        if case["status"] == "N/A":
            checks.append((f"{case['id']} status", True, "N/A / 0 scenarios"))
            continue
        config = case.get("evidence") or {}
        path = ROOT / config.get("path", "")
        if not path.is_dir():
            detail = "missing"
        else:
            detail = config.get("path", "missing")
        checks.append((f"{_display_id(case)} PoC data", path.is_dir(), detail))
    print("Check                         Result  Detail")
    print("-" * 78)
    for name, passed, detail in checks:
        print(f"{name:<29} {'PASS' if passed else 'FAIL':<7} {detail}")
    return all(item[1] for item in checks)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="lbo-artifact")
    sub = parser.add_subparsers(dest="command", required=True)
    demo = sub.add_parser(
        "demo",
        help="open the reviewer-guided attack selection and PoC",
    )
    demo.add_argument("identifier", nargs="?")
    demo.add_argument(
        "--non-interactive",
        action="store_true",
        help="print every demo step without prompts",
    )
    verify = sub.add_parser("verify")
    verify.add_argument("identifier", nargs="?")
    verify.add_argument("--all", action="store_true")
    sub.add_parser("doctor")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        messages, cases = manifests()
        if args.command == "demo":
            run_demo(cases, args.identifier, args.non_interactive)
        elif args.command == "verify":
            if args.all:
                return 0 if verify_all(cases) else 1
            if not args.identifier:
                raise ValueError("verify requires CASE_ID or --all")
            identifier = _resolve_case_id(cases, args.identifier)
            return 0 if verify_case(cases[identifier]) else 1
        elif args.command == "doctor":
            return 0 if doctor(messages, cases) else 2
        return 0
    except ArtifactError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2
    except ValueError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 4


if __name__ == "__main__":
    raise SystemExit(main())
