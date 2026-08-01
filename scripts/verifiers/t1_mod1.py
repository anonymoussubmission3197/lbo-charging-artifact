#!/usr/bin/env python3
"""Packet-level helpers for the public T1-MOD1 controlled comparison."""

from __future__ import annotations

import json
from pathlib import Path

from t3_mod1 import PairError, tshark_rows


def workload(directory: Path) -> dict[str, int | str]:
    """Shared W3 helper used by the T2-INS1 verifier."""
    return json.loads(
        (directory / "workload_summary.json").read_text(encoding="utf-8")
    )


def application_flow(directory: Path) -> tuple[int, int]:
    """Shared application-flow helper used by the T2-INS1 verifier."""
    rows = tshark_rows(
        directory / "gtpu.pcap",
        "gtp && udp.port == 39000 && !icmp",
        ("udp.length",),
    )
    payload_bytes = 0
    for row in rows:
        lengths = [int(value) for value in row[0].split(",") if value]
        if not lengths or lengths[-1] < 8:
            raise PairError(f"invalid application UDP length in {directory}")
        payload_bytes += lengths[-1] - 8
    return len(rows), payload_bytes


def icmp_noise(directory: Path) -> tuple[int, int]:
    """Shared ICMP-noise helper used by the T2-INS1 verifier."""
    rows = tshark_rows(directory / "gtpu.pcap", "gtp && icmp", ("ip.len",))
    inner_bytes = 0
    for row in rows:
        lengths = [int(value) for value in row[0].split(",") if value]
        if len(lengths) < 2:
            raise PairError(f"invalid encapsulated ICMP length in {directory}")
        inner_bytes += lengths[-2]
    return len(rows), inner_bytes


def n7_frame_5qi(path: Path, frame: int) -> int:
    rows = tshark_rows(
        path,
        f"frame.number == {frame}",
        ("http2.data.data",),
    )
    if len(rows) != 1:
        raise PairError(f"expected one N7 body in frame {frame} of {path}")
    try:
        payload = bytes.fromhex(rows[0][0].replace(",", "")).decode("utf-8")
        value = json.loads(payload)
        if "subsDefQos" in value:
            return int(value["subsDefQos"]["5qi"])
        return int(value["sessRules"]["1"]["authDefQos"]["5qi"])
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError, KeyError) as error:
        raise PairError(f"cannot decode N7 5QI in frame {frame}: {error}") from error


def pfcp_file_usage(path: Path) -> tuple[int, int, int]:
    rows = tshark_rows(
        path,
        "pfcp.msg_type == 56 && pfcp.volume_measurement.tovol",
        (
            "pfcp.volume_measurement.tovol",
            "pfcp.volume_measurement.ulvol",
            "pfcp.volume_measurement.dlvol",
        ),
    )
    try:
        values = [tuple(int(item) for item in row) for row in rows]
    except ValueError as error:
        raise PairError(f"invalid PFCP usage in {path}: {error}") from error
    consistent = sum(total == uplink + downlink for total, uplink, downlink in values)
    return sum(total for total, _uplink, _downlink in values), len(values), consistent


def gy_file_identity(path: Path) -> tuple[int, set[int], set[int], int]:
    requests = tshark_rows(
        path,
        "diameter.cmd.code == 272 && diameter.flags.request == 1",
        ("diameter.Rating-Group", "diameter.QoS-Class-Identifier"),
    )
    groups: set[int] = set()
    qci: set[int] = set()
    try:
        for group_values, qci_values in requests:
            groups.update(int(value, 0) for value in group_values.split(",") if value)
            qci.update(int(value, 0) for value in qci_values.split(",") if value)
    except ValueError as error:
        raise PairError(f"invalid Gy charging identity in {path}: {error}") from error
    answers = tshark_rows(
        path,
        "diameter.cmd.code == 272 && diameter.flags.request == 0",
        ("diameter.Result-Code",),
    )
    successful = sum(1 for row in answers if "2001" in row[0].split(","))
    return len(requests), groups, qci, successful


def experiment_values(path: Path) -> dict[str, int]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return {
            "baseline_charge_cents": int(value["baseline"]["beforeCents"])
            - int(value["baseline"]["afterCents"]),
            "attack_charge_cents": int(value["attack"]["beforeCents"])
            - int(value["attack"]["afterCents"]),
            "baseline_tariff_cents": int(value["tariffs"]["9"]["cents"]),
            "attack_tariff_cents": int(value["tariffs"]["6"]["cents"]),
            "tariff_unit_bytes": int(value["tariffs"]["9"]["unitBytes"]),
        }
    except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError) as error:
        raise PairError(f"invalid T1-MOD1 experiment metadata: {error}") from error
