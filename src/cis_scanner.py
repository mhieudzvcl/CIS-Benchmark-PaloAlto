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

    def check_login_banner(self, rule):
        banner = self.text(self.device, "./deviceconfig/system/login-banner/text()")
        evidence = "devices/entry/deviceconfig/system/login-banner"
        if banner and banner.strip():
            return self.make(rule, "Configured and non-empty", banner, "PASS", evidence)
        return self.make(rule, "Configured and non-empty", "Not configured", "FAIL", evidence,
                         "Legal notice login banner is not set")

    def check_permitted_ip(self, rule):
        entries = self.device.xpath("./deviceconfig/system/permitted-ip/entry")
        evidence = "devices/entry/deviceconfig/system/permitted-ip"
        ips = [e.get("name") for e in entries if e.get("name")]
        if ips:
            return self.make(rule, "Explicit permitted IP addresses configured", ips, "PASS", evidence)
        return self.make(rule, "Explicit permitted IP addresses configured", "None", "FAIL", evidence,
                         "No IP restriction applied to management interface")

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

    def check_interface_mgmt_profile(self, rule):
        profiles = self.device.xpath("./network/profiles/interface-management-profile/entry")
        evidence = "network/profiles/interface-management-profile"
        if not profiles:
            return self.make(rule, "HTTP/Telnet disabled on all profiles", "No profiles defined", "PASS", evidence,
                             "No interface management profiles expose insecure services")
        insecure = []
        for p in profiles:
            pname = p.get("name")
            http = self.text(p, "./http/text()")
            telnet = self.text(p, "./telnet/text()")
            if http == "yes" or telnet == "yes":
                insecure.append(f"{pname} (http={http}, telnet={telnet})")
        if insecure:
            return self.make(rule, "HTTP/Telnet disabled on all profiles", insecure, "FAIL", evidence,
                             "Insecure services enabled on interface profiles")
        return self.make(rule, "HTTP/Telnet disabled on all profiles", f"{len(profiles)} profiles safe", "PASS", evidence)

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

    def check_failed_attempts(self, rule):
        val = self.text(self.device, "./deviceconfig/setting/management//failed-attempts/text()")
        path = "devices/entry/deviceconfig/setting/management/admin-lockout/failed-attempts"
        if val is None:
            return self.make(rule, "1..5 attempts", None, "REVIEW", path,
                             "Lockout threshold not explicitly set")
        try:
            cnt = int(val)
        except ValueError:
            return self.make(rule, "1..5 attempts", val, "REVIEW", path, "Invalid integer")
        return self.make(rule, "1..5 attempts", cnt,
                         "PASS" if 1 <= cnt <= 5 else "FAIL", path)

    def check_lockout_time(self, rule):
        val = self.text(self.device, "./deviceconfig/setting/management//lockout-time/text()")
        path = "devices/entry/deviceconfig/setting/management/admin-lockout/lockout-time"
        if val is None:
            return self.make(rule, ">= 15 minutes", None, "REVIEW", path,
                             "Lockout duration not explicitly set")
        try:
            mins = int(val)
        except ValueError:
            return self.make(rule, ">= 15 minutes", val, "REVIEW", path, "Invalid integer")
        return self.make(rule, ">= 15 minutes", mins,
                         "PASS" if mins >= 15 else "FAIL", path)

    def check_snmp_security(self, rule):
        snmp = self.device.find("./deviceconfig/system/snmp-setting")
        evidence = "devices/entry/deviceconfig/system/snmp-setting"
        if snmp is None:
            return self.make(rule, "SNMP disabled or SNMPv3", "SNMP not configured", "PASS", evidence,
                             "No SNMP service active")
        v2 = snmp.find("./version/v2c")
        v3 = snmp.find("./version/v3")
        if v3 is not None and v2 is None:
            return self.make(rule, "SNMP disabled or SNMPv3", "SNMPv3 enabled", "PASS", evidence)
        if v2 is not None:
            return self.make(rule, "SNMP disabled or SNMPv3", "Insecure SNMPv2c active", "FAIL", evidence,
                             "SNMPv2c uses plaintext community strings")
        return self.make(rule, "SNMP disabled or SNMPv3", "SNMP configured", "REVIEW", evidence)

    def check_verify_update_server(self, rule):
        val = self.text(self.device, "./deviceconfig/system/update-server-identity-check/text()")
        evidence = "devices/entry/deviceconfig/system/update-server-identity-check"
        if val in ("yes", None):
            status_desc = "Enabled (default)" if val is None else "Enabled"
            return self.make(rule, "enabled=yes", status_desc, "PASS", evidence)
        return self.make(rule, "enabled=yes", val, "FAIL", evidence, "Update server identity check disabled")

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

    def check_syslog_configured(self, rule):
        syslog_entries = self.config.xpath(".//shared/log-settings/syslog/entry")
        system_syslog = self.device.xpath("./deviceconfig/system/syslog-server/entry")
        total = len(syslog_entries) + len(system_syslog)
        evidence = "shared/log-settings/syslog"
        if total > 0:
            return self.make(rule, "At least one Syslog server profile configured",
                             f"{total} profile(s)", "PASS", evidence)
        return self.make(rule, "At least one Syslog server profile configured",
                         "None", "FAIL", evidence, "No external syslog logging server configured")

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
            # Operational state confirms synchronized peer
            status = "PASS"
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
        if ((link_enabled in (None, "yes") and len(links) > 0 and link_has_interface) or
                (path_enabled in (None, "yes") and len(paths) > 0 and path_has_target)):
            status, reason = "PASS", "Review whether monitored targets cover all critical links"
        elif link_enabled == "no" and path_enabled == "no":
            status, reason = "FAIL", "Both monitoring methods disabled"
        else:
            status, reason = "REVIEW", "Verify monitoring group schema and meaningful targets in GUI"
        return self.make(rule, "Link or path monitoring configured", actual,
                         status, "deviceconfig/high-availability/group/monitoring", reason)

    def check_security_service_any(self, rule):
        rules = self.config.xpath(".//vsys/entry/rulebase/security/rules/entry")
        evidence = "vsys/entry/rulebase/security/rules"
        if not rules:
            return self.make(rule, "No rule allows service ANY from untrust", "No security rules", "PASS", evidence)
        violations = []
        for r in rules:
            rname = r.get("name")
            action = self.text(r, "./action/text()") or "allow"
            from_zones = r.xpath("./from/member/text()")
            services = r.xpath("./service/member/text()")
            if action.lower() == "allow" and ("any" in [z.lower() for z in from_zones] or "untrust" in [z.lower() for z in from_zones]):
                if "any" in [s.lower() for s in services]:
                    violations.append(rname)
        if violations:
            return self.make(rule, "No rule allows service ANY from untrust", violations, "FAIL", evidence,
                             f"Security rules with service 'any': {', '.join(violations)}")
        return self.make(rule, "No rule allows service ANY from untrust", "Compliant", "PASS", evidence)

    def check_default_rule_logging(self, rule):
        default_rules = self.config.xpath(".//vsys/entry/rulebase/default-security-rules/rules/entry")
        evidence = "vsys/entry/rulebase/default-security-rules"
        if not default_rules:
            # Check normal security rules with log-end
            return self.make(rule, "Default security rules log at session end", "Default settings active", "REVIEW", evidence,
                             "Default rules not overridden; verify session end logging in GUI")
        logged = []
        for r in default_rules:
            rname = r.get("name")
            log_end = self.text(r, "./log-end/text()")
            if log_end == "yes":
                logged.append(rname)
        if len(logged) == len(default_rules):
            return self.make(rule, "Default security rules log at session end", f"All {len(logged)} rules log at end", "PASS", evidence)
        return self.make(rule, "Default security rules log at session end", f"{len(logged)}/{len(default_rules)} logged", "REVIEW", evidence)
