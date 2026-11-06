"""Rule export covers network rules and match-known-users (User) rules."""
import unittest

from sophos_firewall_audit.rule_export import process_rules


def _response(rules):
    return {"Response": {"FirewallRule": rules}}


class ProcessRulesTest(unittest.TestCase):
    def test_network_rule_still_exports(self):
        rules = _response(
            [
                {
                    "Name": "LAN to WAN",
                    "Description": "outbound",
                    "Status": "Enable",
                    "PolicyType": "Network",
                    "NetworkPolicy": {
                        "Action": "Accept",
                        "SourceNetworks": {"Network": ["LAN", "WiFi"]},
                        "SourceZones": {"Zone": "LAN"},
                        "DestinationNetworks": {"Network": "WAN"},
                        "DestinationZones": {"Zone": "WAN"},
                        "Services": {"Service": "HTTP"},
                        "LogTraffic": "Enable",
                        "Schedule": "All The Time",
                    },
                }
            ]
        )
        rows = process_rules(rules)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][0], "LAN to WAN")
        self.assertEqual(rows[0][3], "Accept")
        self.assertEqual(rows[0][4], "LAN\nWiFi")
        self.assertEqual(rows[0][5], "LAN")
        self.assertEqual(rows[0][11], "")

    def test_match_known_users_rule_is_exported(self):
        """Issue #6: GUI rules with Match known users were dropped."""
        rules = _response(
            [
                {
                    "Name": "Staff web",
                    "Description": "known users only",
                    "Status": "Enable",
                    "PolicyType": "User",
                    "UserPolicy": {
                        "Action": "Accept",
                        "SourceNetworks": {"Network": "LAN Network"},
                        "SourceZones": {"Zone": "LAN"},
                        "DestinationZones": {"Zone": "WAN"},
                        "Services": {"Service": ["HTTP", "HTTPS"]},
                        "LogTraffic": "Enable",
                        "Schedule": "Work hours",
                        "MatchIdentity": "Enable",
                        "ShowCaptivePortal": "Enable",
                        "Member": ["staff", "contractors"],
                    },
                }
            ]
        )
        rows = process_rules(rules)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][0], "Staff web")
        self.assertEqual(rows[0][3], "Accept")
        self.assertEqual(rows[0][6], "Any")
        self.assertEqual(rows[0][8], "HTTP\nHTTPS")
        self.assertIn("Match known users", rows[0][11])
        self.assertIn("staff", rows[0][11])
        self.assertIn("Captive portal", rows[0][11])

    def test_mixed_rules_keep_both_types_and_skip_waf(self):
        rules = _response(
            [
                {
                    "Name": "net",
                    "Description": "",
                    "Status": "Enable",
                    "PolicyType": "Network",
                    "NetworkPolicy": {
                        "Action": "Drop",
                        "LogTraffic": "Disable",
                        "Schedule": "All The Time",
                    },
                },
                {
                    "Name": "user",
                    "Description": "",
                    "Status": "Enable",
                    "PolicyType": "User",
                    "UserPolicy": {
                        "Action": "Reject",
                        "LogTraffic": "Enable",
                        "Schedule": "All The Time",
                        "MatchIdentity": "Enable",
                        "Identity": {"Member": "alice"},
                    },
                },
                {
                    "Name": "waf",
                    "Description": "",
                    "Status": "Enable",
                    "PolicyType": "HTTPBased",
                    "HTTPBasedPolicy": {"Action": "Accept"},
                },
            ]
        )
        names = [row[0] for row in process_rules(rules)]
        self.assertEqual(names, ["net", "user"])

    def test_single_rule_dict_from_xmltodict(self):
        rules = _response(
            {
                "Name": "only",
                "Description": "",
                "Status": "Enable",
                "PolicyType": "Network",
                "NetworkPolicy": {
                    "Action": "Accept",
                    "LogTraffic": "Disable",
                    "Schedule": "All The Time",
                },
            }
        )
        rows = process_rules(rules)
        self.assertEqual([row[0] for row in rows], ["only"])


if __name__ == "__main__":
    unittest.main()
