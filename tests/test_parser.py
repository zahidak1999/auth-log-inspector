import unittest

from authlog_analyzer.parser import parse_line, parse_lines


class ParseLineTests(unittest.TestCase):
    def test_parses_failed_login_for_invalid_user(self):
        event = parse_line(
            "Oct  8 09:14:02 host sshd[1201]: Failed password for invalid user admin from 203.0.113.44 port 50102 ssh2",
            1,
        )
        self.assertIsNotNone(event)
        self.assertEqual(event.kind, "failure")
        self.assertEqual(event.username, "admin")
        self.assertEqual(event.source_ip, "203.0.113.44")

    def test_parses_successful_public_key_login(self):
        event = parse_line(
            "Oct  8 09:15:01 host sshd[1212]: Accepted publickey for zahid from 192.0.2.18 port 50150 ssh2",
            3,
        )
        self.assertIsNotNone(event)
        self.assertEqual(event.kind, "success")
        self.assertEqual(event.username, "zahid")

    def test_ignores_non_authentication_line(self):
        self.assertIsNone(parse_line("Oct  8 09:18:12 host CRON[1238]: job finished", 1))

    def test_ignores_malformed_source_address(self):
        self.assertIsNone(
            parse_line(
                "Oct  8 09:14:02 host sshd[1]: Failed password for root from not-an-ip port 22 ssh2",
                1,
            )
        )

    def test_preserves_input_order(self):
        lines = [
            "Oct  8 09:14:02 host sshd[1]: Failed password for root from 203.0.113.44 port 22 ssh2",
            "Oct  8 09:14:03 host sshd[2]: Accepted password for root from 203.0.113.44 port 22 ssh2",
        ]
        events = parse_lines(lines)
        self.assertEqual([event.line_number for event in events], [1, 2])


if __name__ == "__main__":
    unittest.main()
