"""CIS Palo Alto Firewall 11 v1.2.0 - selected controls.

Phân tích cẩn trọng: REVIEW khi không đủ bằng chứng, không coi missing == PASS
ngoại trừ HTTP/Telnet có default disabled được Benchmark v1.2.0 ghi nhận.
"""
from pathlib import Path

import yaml
from lxml import etree


class CISScanner:
    def __init__(self, config: etree._Element, rules_path=None, site_policy=None, ha_state=None):
        self.config = config
        if config.tag != "config":
            raise ValueError("Expected PAN-OS <config> root")
        base = Path(__file__).resolve().parent.parent
        rules_path = Path(rules_path or base / "rules" / "cis_controls.yaml")
        policy_path = Path(site_policy or base / "rules" / "site_policy.yaml")
        self.rules = yaml.safe_load(rules_path.read_text(encoding="utf-8"))["controls"]
        self.policy = yaml.safe_load(policy_path.read_text(encoding="utf-8")) or {}
        self.ha_state = ha_state
        device_entries = config.xpath("./devices/entry")
        if len(device_entries) != 1:
            named = [d for d in device_entries if d.get("name") == "localhost.localdomain"]
            if len(named) != 1:
                raise ValueError("Cannot identify unique local firewall device entry")
            self.device = named[0]
        else:
            self.device = device_entries[0]

    @staticmethod
    def text(node, xpath):
        if node is None:
            return None
        matches = node.xpath(xpath)
        if not matches:
            return None
        value = matches[0]
        if isinstance(value, etree._Element):
            value = value.text
        return str(value).strip() if value is not None else None

    @staticmethod
    def make(rule, expected, actual, status, evidence, reason=""):
        return {
            "id": rule["id"],
            "name": rule["title"],
            "expected": expected,
            "actual": actual,
            "status": status,
            "evidence": evidence,
            "reason": reason,
        }

    def scan(self):
        result = []
        for rule in self.rules:
            try:
                handler = getattr(self, "check_" + rule["type"])
                result.append(handler(rule))
            except Exception as exc:
                result.append(self.make(
                    rule, "See benchmark", None, "ERROR", "",
                    f"Check failed: {type(exc).__name__}: {exc}"
                ))
        return result

    def check_management_services(self, rule):
        parent = self.device.find("./deviceconfig/system/service")
        states = {}
        for name in ("http", "telnet"):
            value = self.text(parent, f"./disable-{name}/text()")
            if value in (None, "yes"):
                states[name] = "Disabled (default)" if value is None else "Disabled"
            elif value == "no":
                states[name] = "Enabled"
            else:
                states[name] = "Unknown"
        status = ("FAIL" if "Enabled" in states.values()
                  else "REVIEW" if "Unknown" in states.values() else "PASS")
        return self.make(
            rule, "HTTP=disabled; Telnet=disabled", states, status,
            "devices/entry/deviceconfig/system/service",
            "Benchmark default: HTTP/Telnet disabled when not explicitly set"
            if any("default" in s for s in states.values()) else ""
        )

    def _complexity(self):
        return self.config.find("./mgt-config/password-complexity")

    def check_password_enabled(self, rule):
        value = self.text(self._complexity(), "./enabled/text()")
        state = "PASS" if value == "yes" else "FAIL" if value in (None, "no") else "REVIEW"
        return self.make(rule, "enabled=yes", value or "not configured", state,
                         "mgt-config/password-complexity/enabled")

    def check_password_number(self, rule):
        node = self._complexity()
        enabled = self.text(node, "./enabled/text()")
        field = rule["field"]
        raw = self.text(node, f"./{field}/text()")
        threshold = int(rule["threshold"])
        minimum = int(rule.get("minimum", 0))
        expected = f"{rule['comparator']} {threshold}; complexity=enabled"
        evidence = f"mgt-config/password-complexity/{field}"
        if enabled == "no" or enabled is None:
            return self.make(rule, expected, raw, "FAIL", evidence,
                             "Minimum Password Complexity is not enabled")
        if enabled != "yes":
            return self.make(rule, expected, raw, "REVIEW", evidence,
                             "Unrecognized complexity enabled state")
        if raw is None:
            return self.make(rule, expected, None, "REVIEW", evidence,
                             "Field not explicitly set; default needs verification")
        try:
            value = int(raw)
        except ValueError:
            return self.make(rule, expected, raw, "REVIEW", evidence, "Not an integer")
        comparator = rule["comparator"]
        ok = ((value >= threshold) if comparator == "gte" else
              (minimum <= value <= threshold))
        return self.make(rule, expected, value, "PASS" if ok else "FAIL", evidence)

    def check_idle_timeout(self, rule):
        val = self.text(self.device, "./deviceconfig/setting/management/idle-timeout/text()")
        path = "devices/entry/deviceconfig/setting/management/idle-timeout"
        if val is None:
            return self.make(rule, "1..10 minutes", None, "REVIEW", path,
                             "Not explicitly configured; effective default not proven")
        try:
            mins = int(val)
        except ValueError:
            return self.make(rule, "1..10 minutes", val, "REVIEW", path, "Invalid integer")
        return self.make(rule, "1..10 minutes", mins,
                         "PASS" if 1 <= mins <= 10 else "FAIL", path)

    def check_ntp(self, rule):
        base = self.device.find("./deviceconfig/system/ntp-servers")
        primary = self.text(base, "./primary-ntp-server/ntp-server-address/text()")
        secondary = self.text(base, "./secondary-ntp-server/ntp-server-address/text()")
        addresses = {"primary": primary, "secondary": secondary}
        evidence = "devices/entry/deviceconfig/system/ntp-servers"
        if not primary or not secondary or primary == secondary:
            return self.make(rule, "Two distinct approved NTP servers", addresses,
                             "FAIL", evidence, "Both distinct NTP servers required")
        approved = set(self.policy.get("approved_ntp_servers") or [])
        if not approved:
            return self.make(rule, "Two distinct approved NTP servers", addresses,
                             "REVIEW", evidence,
                             "Set approved_ntp_servers in rules/site_policy.yaml; availability not tested")
        status = "PASS" if {primary, secondary} <= approved else "FAIL"
        return self.make(rule, "Two distinct approved NTP servers", addresses,
                         status, evidence,
                         "Configuration check only; actual NTP reachability not verified")

    def check_ha_sync(self, rule):
        group = self.device.find("./deviceconfig/high-availability/group")
        config_sync = self.text(group, "./configuration-synchronization/enabled/text()")
        session_sync = self.text(group, "./state-synchronization/enabled/text()")
        actual = {"config_sync": config_sync, "session_sync": session_sync,
                  "local_state": None, "peer_state": None, "state_sync": None,
                  "running_sync": None}
        if config_sync == "no" or session_sync == "no":
            return self.make(rule, "HA peer active/passive; fully synchronized", actual,
                             "FAIL", "deviceconfig/high-availability/group", "HA synchronization disabled")
        if self.ha_state is None:
            return self.make(rule, "HA peer active/passive; fully synchronized", actual,
                             "REVIEW", "op:show high-availability state",
                             "HA operational state missing/unsupported; inspect CLI")
        if self.ha_state.findtext("./result/enabled") == "no":
            return self.make(rule, "HA peer active/passive; fully synchronized", actual,
                             "FAIL", "op:show high-availability state",
                             "High Availability is disabled")
        base = self.ha_state.find("./result/group")
        if base is None:
            base = self.ha_state.find(".//group")
        actual["local_state"] = self.text(base, "./local-info/state/text()")
        actual["peer_state"] = self.text(base, "./peer-info/state/text()")
        actual["state_sync"] = self.text(base, "./local-info/state-sync/text()")
        actual["running_sync"] = self.text(base, "./running-sync/text()")
        local = (actual["local_state"] or "").lower()
        peer = (actual["peer_state"] or "").lower()
        state_sync = (actual["state_sync"] or "").lower()
        running_sync = (actual["running_sync"] or "").lower()
        acceptable = {"active", "passive", "active-primary", "active-secondary"}
        if (local and local not in acceptable) or (peer and peer not in acceptable):
            status = "FAIL"
        elif running_sync and running_sync != "synchronized":
            status = "FAIL"
        elif state_sync and state_sync != "complete":
            status = "FAIL"
        elif (local in acceptable and peer in acceptable and state_sync == "complete"
              and running_sync == "synchronized"):
            status = "PASS" if config_sync == "yes" and session_sync == "yes" else "REVIEW"
        else:
            status = "REVIEW"
        return self.make(rule, "HA peer active/passive; fully synchronized", actual,
                         status, "op:show high-availability state",
                         "Check peer configuration, HA2, and sync state on both peers")

    def check_ha_monitoring(self, rule):
        mon = self.device.find("./deviceconfig/high-availability/group/monitoring")
        if mon is None:
            return self.make(rule, "Link or path monitoring configured", None,
                             "FAIL", "deviceconfig/high-availability/group/monitoring")
        link = mon.find("./link-monitoring")
        path = mon.find("./path-monitoring")
        link_enabled = self.text(link, "./enabled/text()")
        path_enabled = self.text(path, "./enabled/text()")
        links = link.xpath("./link-group/entry") if link is not None else []
        paths = path.xpath(".//path-group/entry") if path is not None else []
        link_has_interface = any(bool(e.xpath(".//interface/member/text()")) for e in links)
        path_has_target = any(bool(e.xpath(".//destination-ip/text()")) for e in paths)
        actual = {"link_enabled": link_enabled, "link_groups": len(links),
                  "path_enabled": path_enabled, "path_groups": len(paths)}
        if (link_enabled == "yes" and link_has_interface or
                path_enabled == "yes" and path_has_target):
            status, reason = "PASS", "Review whether monitored targets cover all critical links"
        elif link_enabled == "no" and path_enabled == "no":
            status, reason = "FAIL", "Both monitoring methods disabled"
        else:
            status, reason = "REVIEW", "Verify monitoring group schema and meaningful targets in GUI"
        return self.make(rule, "Link or path monitoring configured", actual,
                         status, "deviceconfig/high-availability/group/monitoring", reason)
