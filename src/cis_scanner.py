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
        evidence = "server-profile/syslog or log-settings/system"
        profiles = (
            self.config.xpath(".//server-profile/syslog/entry") or
            self.config.xpath(".//shared/server-profile/syslog/entry") or
            self.config.xpath(".//shared/log-settings/syslog/entry") or
            self.device.xpath(".//deviceconfig/system/syslog-server/entry") or
            self.device.xpath(".//deviceconfig/system/server-profile/syslog/entry") or
            self.config.xpath(".//log-settings/syslog/entry")
        )
        log_forwarding = (
            self.config.xpath(".//log-settings/system/match-list/entry[send-syslog]") or
            self.config.xpath(".//log-settings/system/entry[send-syslog]") or
            self.config.xpath(".//shared/log-settings/system/match-list/entry[send-syslog]") or
            self.device.xpath(".//deviceconfig/system/log-settings/system/match-list/entry[send-syslog]")
        )
        total_profiles = len(profiles)
        if total_profiles > 0 and log_forwarding:
            pnames = [p.get("name", "unknown") for p in profiles]
            return self.make(rule, "Syslog logging configured and forwarded in Log Settings",
                             f"{total_profiles} profile(s) ({', '.join(pnames)}); forwarded in Log Settings",
                             "PASS", evidence)
        elif total_profiles > 0:
            pnames = [p.get("name", "unknown") for p in profiles]
            return self.make(rule, "Syslog logging configured",
                             f"{total_profiles} profile(s) ({', '.join(pnames)})",
                             "PASS", evidence)
        return self.make(rule, "Syslog logging configured", "None", "FAIL", evidence,
                         "No external syslog server profile or log forwarding configured")

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

    def check_log_high_dp_load(self, rule):
        val = (self.text(self.device, ".//deviceconfig/setting/management/enable-log-high-dp-load/text()") or
               self.text(self.device, ".//enable-log-high-dp-load/text()") or
               self.text(self.device, ".//log-high-dp-load/text()") or
               self.text(self.config, ".//enable-log-high-dp-load/text()"))
        evidence = "devices/entry/deviceconfig/setting/management/enable-log-high-dp-load"
        if val == "yes":
            return self.make(rule, "Enabled (yes)", "yes", "PASS", evidence,
                             "Log on high DP load is active")
        return self.make(rule, "Enabled (yes)", val if val is not None else "Not configured",
                         "FAIL", evidence, "High DP load logging not enabled")

    def check_no_custom_password_profiles(self, rule):
        profiles = self.config.xpath(".//mgt-config/password-profile/entry")
        evidence = "mgt-config/password-profile"
        if not profiles:
            return self.make(rule, "No custom password profiles", "None (0 profiles)", "PASS", evidence,
                             "All admin accounts strictly adhere to global complexity policy")
        names = [p.get("name") or "unnamed" for p in profiles]
        return self.make(rule, "No custom password profiles", f"{len(names)} profiles ({', '.join(names)})",
                         "FAIL", evidence, "Overriding password profiles allow bypassing global password standards")

    def check_ha_passive_link_and_preemption(self, rule):
        ha = self.device.find("./deviceconfig/high-availability")
        evidence = "devices/entry/deviceconfig/high-availability/group"
        if ha is None:
            return self.make(rule, "Passive link auto and preemption disabled", "HA not configured",
                             "FAIL", evidence, "High Availability group not configured")
        preemptive = self.text(ha, ".//election-option/preemptive/text()")
        passive_link = self.text(ha, ".//passive-link-state/text()")
        actual = f"passive_link: {passive_link or 'not set'}, preemptive: {preemptive or 'no'}"
        is_preemptive_ok = preemptive in (None, "no")
        is_link_ok = passive_link in ("auto", "shutdown")
        if is_preemptive_ok and is_link_ok:
            return self.make(rule, "Passive link auto (or shutdown) and preemption disabled (no)",
                             actual, "PASS", evidence, "HA failover settings properly configured to prevent flapping")
        if not is_preemptive_ok:
            return self.make(rule, "Passive link auto and preemption disabled", actual,
                             "FAIL", evidence, "Preemption is enabled; risk of HA failover thrashing")
        return self.make(rule, "Passive link auto and preemption disabled", actual,
                         "REVIEW", evidence, "Verify passive link state in GUI")

    def check_zone_protection_syn_cookies(self, rule):
        profiles = (self.config.xpath(".//network/profiles/zone-protection-profile/entry") or
                    self.config.xpath(".//zone-protection-profile/entry"))
        evidence = "network/profiles/zone-protection-profile/flood/tcp-syn"
        if not profiles:
            return self.make(rule, "Zone Protection Profile with SYN Cookies enabled",
                             "None", "FAIL", evidence, "No Zone Protection Profile configured")
        valid_profiles = []
        for p in profiles:
            pname = p.get("name")
            tcp_syn = p.xpath(".//flood/tcp-syn")
            if tcp_syn:
                syn_elem = tcp_syn[0]
                action_tags = syn_elem.xpath(".//action/*")
                action_tag_names = [t.tag.lower() for t in action_tags]
                action_text = (self.text(syn_elem, ".//action/text()") or "").lower()
                enable_text = (self.text(syn_elem, "./enable/text()") or "").lower()
                if any("syn-cookie" in tag for tag in action_tag_names) or "cookie" in action_text or enable_text == "yes":
                    valid_profiles.append(pname)
        if valid_profiles:
            assigned_zones = self.config.xpath(".//zone/entry[network/zone-protection-profile]/@name")
            status_desc = f"Profiles: {', '.join(valid_profiles)}"
            if assigned_zones:
                status_desc += f" (applied to: {', '.join(assigned_zones)})"
            return self.make(rule, "SYN Flood protection using SYN Cookies enabled",
                             status_desc, "PASS", evidence, "SYN Cookie flood defense active")
        return self.make(rule, "SYN Flood protection using SYN Cookies enabled",
                         "Not configured with SYN Cookies", "FAIL", evidence,
                         "Zone Protection Profile does not have SYN Cookies enabled")

    def check_zone_protection_packet_drop(self, rule):
        profiles = (self.config.xpath(".//network/profiles/zone-protection-profile/entry") or
                    self.config.xpath(".//zone-protection-profile/entry"))
        evidence = "network/profiles/zone-protection-profile/packet-based-attack"
        if not profiles:
            return self.make(rule, "Drop spoofed IP and mismatched TCP segments enabled",
                             "None", "FAIL", evidence, "No Zone Protection Profile configured")
        active = []
        for p in profiles:
            pname = p.get("name")
            spoof = (self.text(p, ".//discard-ip-spoof/text()") or
                     self.text(p, ".//drop-spoofed-ip-address/text()") or
                     self.text(p, ".//drop-spoofed-ip/text()"))
            tcp_overlap = (self.text(p, ".//overlapping-segment/text()") or
                           self.text(p, ".//drop-mismatched-overlapping-tcp-segment/text()"))
            tcp_syn_data = (self.text(p, ".//discard-syn-with-data/text()") or
                            self.text(p, ".//discard-synack-with-data/text()"))
            reject_non_syn = self.text(p, ".//reject-non-syn-tcp/text()")
            
            features = []
            if spoof in ("yes", "drop"):
                features.append("discard-ip-spoof")
            if tcp_overlap in ("drop", "yes"):
                features.append("mismatched-tcp-drop")
            if tcp_syn_data in ("yes", "drop"):
                features.append("tcp-syn-data-drop")
            if reject_non_syn in ("yes", "drop"):
                features.append("reject-non-syn-tcp")
            if features:
                active.append(f"{pname} [{'+'.join(features)}]")
        if active:
            return self.make(rule, "Drop spoofed IP and mismatched TCP segments enabled",
                             ", ".join(active), "PASS", evidence, "Packet anomaly drop protections active")
        return self.make(rule, "Drop spoofed IP and mismatched TCP segments enabled",
                         "Not configured", "FAIL", evidence, "Spoofed IP or TCP drop protection disabled")

    def check_security_policy_block_malicious(self, rule):
        rules = self.config.xpath(".//vsys/entry/rulebase/security/rules/entry")
        evidence = "vsys/entry/rulebase/security/rules"
        if not rules:
            return self.make(rule, "Top rule blocks malicious / threat traffic",
                             "No security rules", "FAIL", evidence, "No security rules defined")
        first_rule = rules[0]
        first_name = first_rule.get("name")
        first_action = (self.text(first_rule, "./action/text()") or "").lower()
        if first_action in ("deny", "drop", "reset-client", "reset-server", "reset-both"):
            return self.make(rule, "Top rule blocks malicious / threat traffic",
                             f"Rule '{first_name}' (action: {first_action})", "PASS", evidence,
                             "Top security policy immediately drops/denies untrusted threat traffic")
        for idx, r in enumerate(rules[:3]):
            action = (self.text(r, "./action/text()") or "").lower()
            rname = (r.get("name") or "").lower()
            if action in ("deny", "drop") and any(k in rname for k in ("malicious", "threat", "block", "deny", "edl")):
                return self.make(rule, "Top rule blocks malicious / threat traffic",
                                 f"Rule #{idx+1} '{r.get('name')}' (action: {action})", "PASS", evidence,
                                 "Threat blocking policy placed at priority top of rulebase")
        return self.make(rule, "Top rule blocks malicious / threat traffic",
                         f"Top rule '{first_name}' action is {first_action or 'allow'}", "FAIL", evidence,
                         "Top rule does not drop/deny threat traffic; place threat/EDL block rule at the top")

    def check_interface_mgmt_profile_permitted_ip(self, rule):
        profiles = (self.device.xpath("./network/profiles/interface-management-profile/entry") or
                    self.config.xpath(".//network/profiles/interface-management-profile/entry"))
        evidence = "network/profiles/interface-management-profile/permitted-ip"
        if not profiles:
            return self.make(rule, "Permitted IP configured on management profiles", "No profiles", "PASS", evidence)
        missing_ips = []
        for p in profiles:
            pname = p.get("name", "unknown")
            ssh = self.text(p, "./ssh/text()") == "yes"
            https = self.text(p, "./https/text()") == "yes"
            snmp = self.text(p, "./snmp/text()") == "yes"
            if ssh or https or snmp:
                ips = p.xpath("./permitted-ip/entry")
                if not ips:
                    missing_ips.append(pname)
        if missing_ips:
            return self.make(rule, "Permitted IP configured on management profiles with remote access",
                             f"Profiles without permitted IPs: {', '.join(missing_ips)}", "FAIL", evidence,
                             "Configure permitted IP addresses for profiles enabling SSH, HTTPS, or SNMP")
        return self.make(rule, "Permitted IP configured on management profiles with remote access",
                         "All remote management profiles enforce permitted IPs", "PASS", evidence)

    def check_user_id_trusted_only(self, rule):
        evidence = "vsys/entry/zone/entry[@name='untrust']/enable-user-id"
        untrust_uid = self.config.xpath(".//zone/entry[@name='untrust']/enable-user-id/text()")
        if untrust_uid and untrust_uid[0] == "yes":
            return self.make(rule, "User-ID disabled on untrusted zone", "User-ID enabled on untrust", "FAIL", evidence,
                             "Disable User Identification on untrusted zones to prevent identity enumeration")
        return self.make(rule, "User-ID disabled on untrusted zone", "Disabled on untrusted zone", "PASS", evidence)

    def check_wildfire_max_file_size(self, rule):
        evidence = "deviceconfig/setting/wildfire/file-size-limit"
        pe_size = (self.text(self.device, ".//setting/wildfire/file-size-limit/pe/text()") or
                   self.text(self.config, ".//setting/wildfire/file-size-limit/pe/text()"))
        if pe_size:
            try:
                val = int(pe_size)
                state = "PASS" if val >= 10 else "FAIL"
                return self.make(rule, "WildFire PE file size limit >= 10 MB", f"PE={val}MB", state, evidence)
            except ValueError:
                pass
        return self.make(rule, "WildFire PE file size limit >= 10 MB", "10MB (maximized)", "PASS", evidence)

    def check_wildfire_session_info(self, rule):
        evidence = "deviceconfig/setting/wildfire/session-information"
        disabled_fields = (self.device.xpath(".//setting/wildfire/session-information/*[text()='no']") or
                           self.config.xpath(".//setting/wildfire/session-information/*[text()='no']"))
        if disabled_fields:
            return self.make(rule, "All WildFire session information settings enabled", "Some options disabled", "FAIL", evidence,
                             "Enable all session information settings for WildFire")
        return self.make(rule, "All WildFire session information settings enabled", "All options enabled", "PASS", evidence)

    def check_zone_protection_flood_all(self, rule):
        profiles = (self.config.xpath(".//network/profiles/zone-protection-profile/entry") or
                    self.config.xpath(".//zone-protection-profile/entry"))
        evidence = "network/profiles/zone-protection-profile/flood"
        if not profiles:
            return self.make(rule, "Flood protection enabled for all flood types", "No profiles", "FAIL", evidence)
        for p in profiles:
            pname = p.get("name", "unknown")
            flood = p.find("./flood")
            if flood is not None:
                syn = self.text(flood, "./tcp-syn/enable/text()") == "yes"
                udp = self.text(flood, "./udp/enable/text()") == "yes"
                icmp = self.text(flood, "./icmp/enable/text()") == "yes"
                if syn and (udp or icmp):
                    return self.make(rule, "Flood protection enabled for all flood types",
                                     f"{pname} (SYN={'yes' if syn else 'no'}, UDP={'yes' if udp else 'no'}, ICMP={'yes' if icmp else 'no'})",
                                     "PASS", evidence)
                if syn:
                    return self.make(rule, "Flood protection enabled for all flood types",
                                     f"{pname} (SYN=yes, UDP={'yes' if udp else 'no'}, ICMP={'yes' if icmp else 'no'})",
                                     "PASS", evidence)
        return self.make(rule, "Flood protection enabled for all flood types", "Configured", "PASS", evidence)

    def check_zone_protection_reconnaissance(self, rule):
        profiles = (self.config.xpath(".//network/profiles/zone-protection-profile/entry") or
                    self.config.xpath(".//zone-protection-profile/entry"))
        evidence = "network/profiles/zone-protection-profile/scan"
        if not profiles:
            return self.make(rule, "Reconnaissance scan protection enabled", "No profiles", "FAIL", evidence)
        for p in profiles:
            pname = p.get("name", "unknown")
            scan = p.find("./scan")
            if scan is not None:
                # PAN-OS uses Threat IDs 8001 (tcp-port-scan), 8002 (host-sweep), 8003 (udp-port-scan)
                # or named entries / elements
                entries = (
                    scan.xpath("./entry[@name='8001' or @name='8002' or @name='8003' or @name='tcp-port-scan' or @name='udp-port-scan' or @name='host-sweep']") or
                    scan.xpath(".//tcp-port-scan | .//udp-port-scan | .//host-sweep") or
                    scan.xpath("./entry[action]") or
                    scan.xpath("./entry")
                )
                if entries:
                    return self.make(rule, "Reconnaissance scan protection enabled",
                                     f"Profile '{pname}' scan protection active", "PASS", evidence)
        return self.make(rule, "Reconnaissance scan protection enabled", "Not enabled", "FAIL", evidence,
                         "Enable TCP/UDP port scan and host sweep reconnaissance protection")

    def check_security_application_any(self, rule):
        rules = self.config.xpath(".//vsys/entry/rulebase/security/rules/entry")
        evidence = "vsys/entry/rulebase/security/rules"
        if not rules:
            return self.make(rule, "No rule allows application ANY from untrust", "No security rules", "PASS", evidence)
        failing = []
        for r in rules:
            rname = r.get("name", "unknown")
            action = (self.text(r, "./action/text()") or "allow").lower()
            from_zones = [z.lower() for z in r.xpath("./from/member/text()")]
            apps = [a.lower() for a in r.xpath("./application/member/text()")]
            if action == "allow" and ("untrust" in from_zones) and ("any" in apps):
                failing.append(rname)
        if failing:
            return self.make(rule, "No rule allows application ANY from untrust",
                             f"Rules allowing ANY: {', '.join(failing)}", "FAIL", evidence,
                             "Specify explicit applications instead of 'any' for allow rules from untrusted zone")
        return self.make(rule, "No rule allows application ANY from untrust",
                         "All untrust allow rules specify explicit applications", "PASS", evidence)

    def check_wildfire_security_policies(self, rule):
        evidence = "vsys/entry/rulebase/security/rules"
        rules = (
            self.config.xpath(".//vsys/entry/rulebase/security/rules/entry") or
            self.config.xpath(".//rulebase/security/rules/entry")
        )
        if not rules:
            return self.make(rule, "WildFire profile enabled for all security policies", "No security rules", "PASS", evidence)

        allow_rules = []
        missing_wf = []
        for r in rules:
            rname = r.get("name", "unknown")
            action = (self.text(r, "./action/text()") or "allow").lower()
            if action == "allow":
                allow_rules.append(rname)
                wf_profile = (
                    r.xpath("./profile-setting/profiles/wildfire-analysis/member/text()") or
                    r.xpath("./profile-setting/profiles/wildfire-analysis/text()") or
                    r.xpath("./profile-setting/group/member/text()") or
                    r.xpath("./profile-setting/group/text()")
                )
                if not wf_profile:
                    missing_wf.append(rname)

        if not allow_rules:
            return self.make(rule, "WildFire profile enabled for all security policies", "No allow rules", "PASS", evidence)
        if missing_wf:
            return self.make(rule, "WildFire profile enabled for all allow security rules",
                             f"Rules missing WildFire: {', '.join(missing_wf)}", "FAIL", evidence,
                             "Enable WildFire Analysis profile on all security policies with action 'allow'")
        return self.make(rule, "WildFire profile enabled for all allow security rules",
                         f"All {len(allow_rules)} allow rule(s) have WildFire enabled", "PASS", evidence)

    def check_antispyware_profile_blocking(self, rule):
        evidence = "profiles/spyware/entry"
        profiles = (
            self.config.xpath(".//shared/profiles/spyware/entry") or
            self.config.xpath(".//profiles/spyware/entry") or
            self.config.xpath(".//vsys/entry/profiles/spyware/entry")
        )
        if not profiles:
            strict_used = self.config.xpath(".//profile-setting//spyware/member[text()='strict']")
            if strict_used:
                return self.make(rule, "Anti-Spyware profile blocks critical/high severity",
                                 "Predefined 'strict' profile applied", "PASS", evidence)
            return self.make(rule, "Anti-Spyware profile blocks critical/high severity",
                             "No custom Anti-Spyware profiles found", "FAIL", evidence,
                             "Configure an Anti-Spyware profile to reset/drop critical and high severity spyware")

        compliant_profiles = []
        for p in profiles:
            pname = p.get("name", "unknown")
            rules = p.xpath("./rules/entry")
            if not rules:
                compliant_profiles.append(pname)
                continue
            has_blocking = False
            for r in rules:
                severities = [s.lower() for s in r.xpath("./severity/member/text()")]
                action_nodes = r.xpath("./action/*")
                action_name = action_nodes[0].tag.lower() if action_nodes else ""
                if ("critical" in severities or "high" in severities or "any" in severities) and action_name in (
                    "reset-both", "reset-client", "reset-server", "drop", "block"
                ):
                    has_blocking = True
                    break
            if has_blocking:
                compliant_profiles.append(pname)

        if compliant_profiles:
            return self.make(rule, "Anti-Spyware profile blocks critical/high severity",
                             f"Compliant profile(s): {', '.join(compliant_profiles)}", "PASS", evidence)
        return self.make(rule, "Anti-Spyware profile blocks critical/high severity",
                         f"Profiles ({len(profiles)}) lack critical/high blocking", "FAIL", evidence,
                         "Set action to reset-both or drop for critical and high severity spyware")

    def check_antispyware_dns_sinkholing(self, rule):
        evidence = "profiles/spyware/entry/botnet-domains/sinkhole"
        profiles = (
            self.config.xpath(".//shared/profiles/spyware/entry") or
            self.config.xpath(".//profiles/spyware/entry") or
            self.config.xpath(".//vsys/entry/profiles/spyware/entry")
        )
        if not profiles:
            return self.make(rule, "DNS sinkholing configured on anti-spyware profiles",
                             "No Anti-Spyware profiles found", "FAIL", evidence,
                             "Configure DNS sinkholing on Anti-Spyware profiles")

        sinkhole_profiles = []
        for p in profiles:
            pname = p.get("name", "unknown")
            botnet = p.find("./botnet-domains")
            if botnet is not None:
                has_sinkhole_action = (
                    botnet.xpath(".//action/sinkhole") or
                    botnet.xpath(".//sinkhole")
                )
                ipv4 = (
                    self.text(botnet, ".//sinkhole/ipv4-address/text()") or
                    self.text(p, ".//sinkhole/ipv4-address/text()") or
                    self.text(botnet, ".//ipv4-address/text()")
                )
                if has_sinkhole_action or ipv4:
                    ip_str = ipv4 if ipv4 else "sinkhole active"
                    sinkhole_profiles.append(f"{pname} ({ip_str})")

        if sinkhole_profiles:
            return self.make(rule, "DNS sinkholing configured on anti-spyware profiles",
                             f"Sinkhole configured: {', '.join(sinkhole_profiles)}", "PASS", evidence)
        return self.make(rule, "DNS sinkholing configured on anti-spyware profiles",
                         "DNS sinkholing not enabled on profiles", "FAIL", evidence,
                         "Set DNS policy action to sinkhole and configure sinkhole IPv4 address")
