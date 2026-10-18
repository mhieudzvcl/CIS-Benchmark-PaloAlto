"""Tests are against synthetic fixtures; no live Palo Alto credentials or connection."""
from pathlib import Path
from copy import deepcopy

from lxml import etree

from src.cis_scanner import CISScanner
from src.remediation import prepare_change
from src.reporting import summary, make_report, save

BASE = Path(__file__).parent


def sample():
    return etree.parse(str(BASE / "fixtures" / "synthetic_running.xml")).getroot()


def status_map(config=None, ha=None):
    rows = CISScanner(config if config is not None else sample(), ha_state=ha).scan()
    return {r["id"]: r for r in rows}


def test_14_controls():
    rows = status_map()
    assert len(rows) == 14
    for cid in ("1.2.3", "1.3.1", "1.3.2", "1.3.3", "1.3.4", "1.3.5", "1.3.6", "1.3.7", "1.3.8", "1.3.9", "1.4.1", "3.2"):
        assert rows[cid]["status"] == "PASS", cid
    assert rows["1.6.2"]["status"] == "REVIEW"  # no approved site NTP list
    assert rows["3.1"]["status"] == "REVIEW"     # no HA operational evidence


def test_idle_fail():
    root = sample()
    root.xpath(".//idle-timeout")[0].text = "20"
    rows = status_map(root)
    assert rows["1.4.1"]["actual"] == 20
    assert rows["1.4.1"]["status"] == "FAIL"
    changes = prepare_change("1.4.1", root, "FAIL")
    assert changes[0]["element"] == "<idle-timeout>10</idle-timeout>"


def test_idle_missing_review():
    root = sample()
    root.xpath(".//idle-timeout")[0].getparent().remove(root.xpath(".//idle-timeout")[0])
    assert status_map(root)["1.4.1"]["status"] == "REVIEW"


def test_management_http_enabled_fail():
    root = sample()
    root.xpath(".//disable-http")[0].text = "no"
    assert status_map(root)["1.2.3"]["status"] == "FAIL"


def test_management_http_default_pass():
    root = sample()
    root.xpath(".//disable-http")[0].getparent().remove(root.xpath(".//disable-http")[0])
    assert status_map(root)["1.2.3"]["status"] == "PASS"


def test_password_disabled_fail():
    root = sample()
    root.xpath("./mgt-config/password-complexity/enabled")[0].text = "no"
    rows = status_map(root)
    assert rows["1.3.1"]["status"] == "FAIL"
    assert rows["1.3.2"]["status"] == "FAIL"


def test_password_min_length_fail():
    root = sample()
    root.xpath(".//minimum-length")[0].text = "8"
    assert status_map(root)["1.3.2"]["status"] == "FAIL"


def test_ntp_with_approved_sites(tmp_path):
    policy = tmp_path / "policy.yaml"
    policy.write_text("approved_ntp_servers: [ntp1.example.test, ntp2.example.test]\n")
    rows = CISScanner(sample(), site_policy=policy).scan()
    assert next(r for r in rows if r["id"] == "1.6.2")["status"] == "PASS"


def test_ha_operational_complete():
    ha = etree.parse(str(BASE / "fixtures" / "synthetic_ha.xml")).getroot()
    assert status_map(ha=ha)["3.1"]["status"] == "PASS"


def test_ha_unsynced_fail():
    ha = etree.parse(str(BASE / "fixtures" / "synthetic_ha.xml")).getroot()
    ha.xpath("./result/group/peer-info/state")[0].text = "non-functional"
    assert status_map(ha=ha)["3.1"]["status"] == "FAIL"


def test_safe_report_files(tmp_path):
    rows = CISScanner(sample()).scan()
    report = make_report("10.0.10.11", "cis-auditor", rows)
    a, b = save(report, tmp_path)
    assert a.exists() and b.exists()
    assert "CIS Palo Alto Auditor" in b.read_text()
    assert report["summary"]["total"] == 14
    assert report["summary"]["compliance_percent"] == 100
    assert report["summary"]["coverage_percent"] < 100


def test_candidate_guard_design():
    root = sample()
    a = prepare_change("1.2.3", root, "FAIL")
    assert len(a) == 2
    try:
        prepare_change("3.1", root, "FAIL")
    except ValueError:
        pass
    else:
        raise AssertionError("Unsafe remediation accepted")
