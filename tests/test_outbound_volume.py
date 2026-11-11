from analyzer.alerts import Severity
from analyzer.detections import outbound_volume
from helpers import make_flow

LAPTOP, EXTERNAL = "192.168.1.50", "198.51.100.9"
MB = 1_000_000


def test_large_upload_to_one_external_host_is_flagged():
    flows = [make_flow(LAPTOP, EXTERNAL, 443, start=i, orig_bytes=20 * MB) for i in range(3)]

    [alert] = outbound_volume.detect(flows)

    assert alert.type == "outbound_volume"
    assert alert.severity == Severity.MEDIUM
    assert (alert.src_ip, alert.dst_ip) == (LAPTOP, EXTERNAL)
    assert alert.evidence == {"bytes_sent": 60 * MB, "flows": 3}


def test_small_upload_is_not_flagged():
    flows = [make_flow(LAPTOP, EXTERNAL, 443, start=0, orig_bytes=1 * MB)]

    assert outbound_volume.detect(flows) == []


def test_large_download_is_not_outbound():
    flows = [make_flow(LAPTOP, EXTERNAL, 443, start=0, orig_bytes=1000, resp_bytes=500 * MB)]

    assert outbound_volume.detect(flows) == []


def test_upload_on_a_connection_opened_from_outside_counts():
    # The external host connected in, and the internal host sent the data back.
    flows = [make_flow(EXTERNAL, LAPTOP, 22, start=0, orig_bytes=1000, resp_bytes=80 * MB)]

    [alert] = outbound_volume.detect(flows)

    assert (alert.src_ip, alert.dst_ip) == (LAPTOP, EXTERNAL)


def test_internal_to_internal_traffic_is_ignored():
    flows = [make_flow(LAPTOP, "192.168.1.2", 445, start=0, orig_bytes=900 * MB)]

    assert outbound_volume.detect(flows) == []


def test_threshold_is_configurable():
    flows = [make_flow(LAPTOP, EXTERNAL, 443, start=0, orig_bytes=1 * MB)]

    assert len(outbound_volume.detect(flows, outbound_volume.Config(min_bytes=MB))) == 1
