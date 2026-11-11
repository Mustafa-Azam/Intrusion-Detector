"""Shared test helpers.

Test captures are generated with Scapy at test time and written to pytest's
temporary directory, so no binary pcap files need to be committed and every
packet in a test is visible in the test itself.
"""

import pytest
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap


@pytest.fixture
def write_pcap(tmp_path):
    """Return a function that writes (timestamp, packet) pairs to a pcap file."""

    def _write(timed_packets, name="test.pcap"):
        packets = []
        for timestamp, packet in timed_packets:
            frame = Ether() / packet
            frame.time = timestamp
            packets.append(frame)
        path = tmp_path / name
        wrpcap(str(path), packets)
        return path

    return _write
