import pytest

from analyzer.alerts import Severity
from analyzer.detections import suspicious_dns
from analyzer.detections.suspicious_dns import Config, name_reasons, shannon_entropy
from helpers import dns_query, dns_response


@pytest.mark.parametrize("text, expected", [("", 0.0), ("aaaa", 0.0), ("ab", 1.0), ("abcd", 2.0)])
def test_shannon_entropy_known_values(text, expected):
    assert shannon_entropy(text) == expected


def test_normal_names_have_no_reasons():
    for name in ("www.google.com", "mail.example.org", "windowsupdateservice.microsoft.com"):
        assert name_reasons(name, Config()) == []


def test_random_label_is_high_entropy():
    assert name_reasons("x7f3k9q2m8z1p4w6.example.com", Config()) == ["high_entropy"]


def test_very_long_name_is_long():
    name = "data-chunk-0001-" * 5 + ".example.com"

    assert "long" in name_reasons(name, Config())


def test_tunnel_like_queries_raise_one_alert_per_client():
    queries = [dns_query(f"{label}.tunnel.example.com", ts=i)
               for i, label in enumerate(["x7f3k9q2m8z1p4w6", "q8w7e6r5t4y3u2i1o0p"])]

    [alert] = suspicious_dns.detect(queries)

    assert alert.type == "suspicious_dns_name"
    assert alert.severity == Severity.LOW
    assert alert.src_ip == "10.0.0.5"
    assert alert.evidence["distinct_names"] == 2


def test_normal_queries_raise_nothing():
    queries = [dns_query(name) for name in ("www.google.com", "github.com", "pypi.org")]
    responses = [dns_response(name, rcode=0) for name in ("www.google.com", "github.com")]

    assert suspicious_dns.detect(queries + responses) == []


def test_many_nxdomain_responses_is_a_burst():
    responses = [dns_response(f"name{i}.invalid", rcode=3, ts=i) for i in range(12)]

    [alert] = suspicious_dns.detect(responses)

    assert alert.type == "dns_nxdomain_burst"
    assert alert.severity == Severity.MEDIUM
    assert alert.src_ip == "10.0.0.5"  # the client, not the resolver
    assert alert.evidence["nxdomain_responses"] == 12


def test_a_few_typos_are_not_a_burst():
    responses = [dns_response(f"typo{i}.example", rcode=3, ts=i) for i in range(3)]

    assert suspicious_dns.detect(responses) == []
