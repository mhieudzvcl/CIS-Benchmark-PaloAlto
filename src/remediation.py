"""Allowlisted, opt-in PAN-OS remediation actions. Lab testing required."""
from lxml import etree

from .panos_client import PanOSAPIError


# Chỉ 4 control nhỏ có whitelist; KHÔNG tự sửa HA, interfaces, NAT, policies.
ALLOWED = {
    "1.2.3": "Disable HTTP and Telnet on management interface",
    "1.3.1": "Enable minimum password complexity",
    "1.3.2": "Set minimum password length to 12 (requires complexity enabled)",
    "1.4.1": "Set management idle timeout to 10 minutes",
}


def _device_xpath(config):
    nodes = config.xpath("./devices/entry")
    if len(nodes) != 1:
        matches = [n for n in nodes if n.get("name") == "localhost.localdomain"]
        if len(matches) != 1:
            raise ValueError("Ambiguous local device entry")
        node = matches[0]
    else:
        node = nodes[0]
    name = node.get("name")
    if not name or "'" in name or '"' in name:
        raise ValueError("Unexpected device entry name")
    return f"/config/devices/entry[@name='{name}']"


def prepare_change(control_id, config, before_status):
    if control_id not in ALLOWED:
        raise ValueError(f"Control {control_id} is not in remediation allowlist")
    if before_status == "PASS":
        raise ValueError("Control already PASS; nothing to remediate")
    if before_status == "ERROR":
        raise ValueError("Cannot remediate a scan ERROR")
    base = _device_xpath(config)
    if control_id == "1.4.1":
        parent = base + "/deviceconfig/setting/management"
        elements = ["<idle-timeout>10</idle-timeout>"]
    elif control_id == "1.2.3":
        parent = base + "/deviceconfig/system/service"
        elements = ["<disable-http>yes</disable-http>",
                    "<disable-telnet>yes</disable-telnet>"]
    elif control_id == "1.3.1":
        parent = "/config/mgt-config/password-complexity"
        elements = ["<enabled>yes</enabled>"]
    elif control_id == "1.3.2":
        parent = "/config/mgt-config/password-complexity"
        elements = ["<minimum-length>12</minimum-length>"]
        complexity = config.find("./mgt-config/password-complexity")
        if complexity is None or complexity.findtext("./enabled") != "yes":
            raise ValueError("First remediate 1.3.1 and rescan before 1.3.2")
    return [{"xpath": parent, "element": xml} for xml in elements]


def guard_candidate_clean(client, running):
    candidate = client.get_config("get")
    # Chặn nếu đã có thay đổi candidate bất kỳ từ admin khác, tránh commit nhầm.
    running_bytes = etree.tostring(running, method="c14n")
    candidate_bytes = etree.tostring(candidate, method="c14n")
    if running_bytes != candidate_bytes:
        raise PanOSAPIError(
            "Candidate differs from running configuration. "
            "Resolve existing pending changes before automated remediation."
        )


def apply_remediation(client, changes, username):
    # Do not catch & auto-retry blindly; a failed set/commit needs manual review.
    for change in changes:
        client.set_element(change["xpath"], change["element"])
    job = client.commit_own_changes(username)
    client.wait_for_commit(job)
    return job
