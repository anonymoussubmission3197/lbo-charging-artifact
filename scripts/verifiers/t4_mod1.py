#!/usr/bin/env python3
"""Packet-level helpers for the public T4-MOD1 x5 comparison."""

from __future__ import annotations

from pathlib import Path
import re

from t3_mod1 import PairError, tshark_rows


TRACE_PATTERN = re.compile(
    r"request_type\[(\d+)\] factor\[(\d+)\] "
    r"actual_ul\[(\d+)\] reported_ul\[(\d+)\]"
)


def pfcp_usage(directory: Path) -> list[tuple[int, int, int]]:
    """Return the five PFCP update reports forwarded to Gy CCR-U."""
    rows = tshark_rows(
        directory / "pfcp.pcap",
        "pfcp.msg_type == 56 && pfcp.volume_measurement.tovol",
        (
            "pfcp.volume_measurement.tovol",
            "pfcp.volume_measurement.ulvol",
            "pfcp.volume_measurement.dlvol",
        ),
    )
    values = [tuple(int(item) for item in row) for row in rows]
    if not values or any(total != uplink + downlink
                         for total, uplink, downlink in values):
        raise PairError(f"invalid PFCP update tuples in {directory}")
    return values


def terminal_pfcp_usage(directory: Path) -> tuple[int, int, int]:
    rows = tshark_rows(
        directory / "pfcp.pcap",
        "pfcp.msg_type == 55 && pfcp.cause == 1 "
        "&& pfcp.volume_measurement.tovol",
        (
            "pfcp.volume_measurement.tovol",
            "pfcp.volume_measurement.ulvol",
            "pfcp.volume_measurement.dlvol",
        ),
    )
    if len(rows) != 1:
        raise PairError(f"expected one accepted terminal PFCP report in {directory}")
    value = tuple(int(item) for item in rows[0])
    if value[0] != value[1] + value[2]:
        raise PairError(f"invalid terminal PFCP tuple in {directory}")
    return value


def clean_release(directory: Path) -> bool:
    requests = tshark_rows(
        directory / "pfcp.pcap", "pfcp.msg_type == 54", ("frame.number",)
    )
    responses = tshark_rows(
        directory / "pfcp.pcap", "pfcp.msg_type == 55 && pfcp.cause == 1",
        ("frame.number",),
    )
    return len(requests) == len(responses) == 1


def gy_usage(directory: Path) -> list[tuple[int, int, int]]:
    rows = tshark_rows(
        directory / "gy.pcap",
        "diameter.cmd.code == 272 && diameter.flags.request == 1 "
        "&& diameter.CC-Request-Type == 2",
        ("diameter.CC-Input-Octets", "diameter.CC-Output-Octets"),
    )
    values = []
    for input_octets, output_octets in rows:
        uplink = int(input_octets or "0")
        downlink = int(output_octets or "0")
        values.append((uplink + downlink, uplink, downlink))
    if not values:
        raise PairError(f"no Gy CCR-U usage in {directory}")
    return values


def gy_session(directory: Path) -> tuple[str, list[int], int]:
    rows = tshark_rows(
        directory / "gy.pcap",
        "diameter.cmd.code == 272 && diameter.flags.request == 1",
        (
            "diameter.Session-Id",
            "diameter.CC-Request-Type",
            "diameter.CC-Request-Number",
        ),
    )
    sessions = {row[0] for row in rows if row[0]}
    types = [int(row[1]) for row in rows]
    numbers = [int(row[2]) for row in rows]
    terminations = sum(kind == 3 for kind in types)
    if len(sessions) != 1 or types != [2] * 5 or numbers != list(range(1, 6)):
        raise PairError(f"unexpected Gy session/request sequence in {directory}")
    return next(iter(sessions)), numbers, terminations


def trace_usage(directory: Path) -> tuple[list[int], list[int]]:
    text = (directory / "inflation_trace.txt").read_text(encoding="utf-8")
    matches = [
        tuple(int(value) for value in match.groups())
        for match in TRACE_PATTERN.finditer(text)
    ]
    updates = [row for row in matches if row[0] == 2]
    if len(updates) != 5:
        raise PairError("attack inflation trace must contain five CCR-U entries")
    if any(factor != 5 or reported != actual * 5
           for _kind, factor, actual, reported in updates):
        raise PairError("producer trace does not satisfy exact x5 UL mutation")
    return (
        [actual for _kind, _factor, actual, _reported in updates],
        [reported for _kind, _factor, _actual, reported in updates],
    )
