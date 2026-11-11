"""Group packet records into bidirectional flows.

A flow is one conversation between two endpoints, identified by the classic
5-tuple: source IP, destination IP, source port, destination port, protocol.
Packets in both directions belong to the same flow. The side that sent the
first packet we saw is called the originator ("orig"), the other side the
responder ("resp"), following the naming Zeek uses in its conn.log.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from analyzer.packets import PacketRecord


@dataclass(frozen=True)
class FlowKey:
    """The 5-tuple, seen from the originator's side."""

    src_ip: str
    dst_ip: str
    src_port: int | None
    dst_port: int | None
    protocol: str

    @classmethod
    def from_record(cls, record: PacketRecord) -> FlowKey:
        return cls(
            record.src_ip,
            record.dst_ip,
            record.src_port,
            record.dst_port,
            record.protocol,
        )

    def reversed(self) -> FlowKey:
        """The same conversation seen from the other side."""
        return FlowKey(
            self.dst_ip, self.src_ip, self.dst_port, self.src_port, self.protocol
        )


@dataclass
class Flow:
    """Counters for one conversation."""

    key: FlowKey
    start: float
    end: float
    orig_packets: int = 0
    orig_bytes: int = 0
    resp_packets: int = 0
    resp_bytes: int = 0

    @property
    def packets(self) -> int:
        return self.orig_packets + self.resp_packets

    @property
    def bytes(self) -> int:
        return self.orig_bytes + self.resp_bytes

    @property
    def duration(self) -> float:
        return self.end - self.start

    def add(self, record: PacketRecord, from_originator: bool) -> None:
        """Count one packet and widen the time window if needed."""
        # min/max rather than assignment, in case the capture is out of order.
        self.start = min(self.start, record.timestamp)
        self.end = max(self.end, record.timestamp)
        if from_originator:
            self.orig_packets += 1
            self.orig_bytes += record.size
        else:
            self.resp_packets += 1
            self.resp_bytes += record.size


def build_flows(records: Iterable[PacketRecord]) -> list[Flow]:
    """Group records into flows, returned in order of start time."""
    flows: dict[FlowKey, Flow] = {}
    for record in records:
        _add_to_flows(flows, record)
    return sorted(flows.values(), key=lambda flow: flow.start)


def _add_to_flows(flows: dict[FlowKey, Flow], record: PacketRecord) -> None:
    key = FlowKey.from_record(record)
    if key in flows:
        flows[key].add(record, from_originator=True)
    elif key.reversed() in flows:
        flows[key.reversed()].add(record, from_originator=False)
    else:
        flow = Flow(key=key, start=record.timestamp, end=record.timestamp)
        flow.add(record, from_originator=True)
        flows[key] = flow
