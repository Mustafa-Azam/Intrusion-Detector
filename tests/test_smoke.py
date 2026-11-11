"""Smoke tests: prove the package installs and its dependencies import.

These exist only so step 1 has something real for pytest to run.
"""

import analyzer


def test_package_has_version():
    assert analyzer.__version__ == "0.1.0"


def test_scapy_is_importable():
    from scapy.all import rdpcap  # noqa: F401
