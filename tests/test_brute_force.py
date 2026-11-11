from analyzer.alerts import Severity
from analyzer.detections import brute_force
from helpers import make_flow

ATTACKER, SERVER = "203.0.113.7", "10.0.0.22"


def ssh_attempts(count, gap_seconds, duration=2.0, port=22):
    return [make_flow(ATTACKER, SERVER, port, start=i * gap_seconds,
                      sport=50000 + i, duration=duration, packets=20)
            for i in range(count)]


def test_many_short_ssh_connections_is_brute_force():
    [alert] = brute_force.detect(ssh_attempts(15, gap_seconds=3))

    assert alert.type == "brute_force"
    assert alert.severity == Severity.HIGH
    assert (alert.src_ip, alert.dst_ip) == (ATTACKER, SERVER)
    assert alert.evidence == {"dst_port": 22, "connections": 15}


def test_rdp_is_watched_too():
    assert len(brute_force.detect(ssh_attempts(12, gap_seconds=2, port=3389))) == 1


def test_a_few_logins_are_not_brute_force():
    assert brute_force.detect(ssh_attempts(3, gap_seconds=3)) == []


def test_long_sessions_are_not_brute_force():
    # 15 connections, but each lasts 10 minutes: real admin sessions.
    assert brute_force.detect(ssh_attempts(15, gap_seconds=3, duration=600)) == []


def test_unwatched_port_is_ignored():
    assert brute_force.detect(ssh_attempts(15, gap_seconds=3, port=8080)) == []


def test_watched_ports_are_configurable():
    config = brute_force.Config(ports=frozenset({8080}))

    assert len(brute_force.detect(ssh_attempts(15, gap_seconds=3, port=8080), config)) == 1
