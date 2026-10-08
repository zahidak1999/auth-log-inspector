import unittest

from authlog_analyzer.json_parser import parse_content


class JsonParserTests(unittest.TestCase):
    def test_parses_ecs_style_json_array(self):
        content = '''[
          {"@timestamp":"2026-10-08T09:00:00Z","event":{"outcome":"failure"},"source":{"ip":"203.0.113.10"},"user":{"name":"root"}},
          {"@timestamp":"2026-10-08T09:01:00Z","event":{"outcome":"success"},"source":{"ip":"203.0.113.10"},"user":{"name":"zahid"}}
        ]'''
        events, total = parse_content(content)
        self.assertEqual(total, 2)
        self.assertEqual([event.kind for event in events], ["failure", "success"])
        self.assertEqual(events[1].timestamp, "2026-10-08T09:01:00Z")

    def test_parses_nested_api_envelope_with_syslog_message(self):
        content = '''{"data":{"records":[{"message":"Failed password for admin from 198.51.100.9 port 22 ssh2","host":{"name":"node-a"}}]}}'''
        events, total = parse_content(content, "json")
        self.assertEqual(total, 1)
        self.assertEqual(events[0].username, "admin")
        self.assertEqual(events[0].host, "node-a")

    def test_auto_detects_json_lines_and_ignores_unrelated_rows(self):
        content = '\n'.join([
            '{"status":"failed","source_ip":"203.0.113.15","username":"root"}',
            '{"status":"success","source_ip":"203.0.113.15","username":"zahid"}',
            '{"message":"service started"}',
        ])
        events, total = parse_content(content)
        self.assertEqual(total, 3)
        self.assertEqual([event.kind for event in events], ["failure", "success"])

    def test_forced_json_reports_invalid_document(self):
        with self.assertRaisesRegex(ValueError, "invalid JSON"):
            parse_content("{not-json", "json")

    def test_auto_reports_malformed_json_instead_of_silently_ignoring_it(self):
        with self.assertRaisesRegex(ValueError, "invalid JSON"):
            parse_content("{not-json")

    def test_forced_text_keeps_syslog_lines(self):
        content = "Oct  8 09:14:02 host sshd[1]: Failed password for root from 203.0.113.1 port 22 ssh2"
        events, total = parse_content(content, "text")
        self.assertEqual(total, 1)
        self.assertEqual(events[0].username, "root")

    def test_custom_field_mapping_supports_another_api_schema(self):
        content = '''{"clientAddress":"203.0.113.24","principal":"admin","loginState":"failed","observedAt":"2026-10-08T09:00:00Z"}'''
        events, total = parse_content(
            content,
            "json",
            {"ip": "clientAddress", "user": "principal", "status": "loginState", "time": "observedAt"},
        )
        self.assertEqual(total, 1)
        self.assertEqual(events[0].source_ip, "203.0.113.24")
        self.assertEqual(events[0].username, "admin")
        self.assertEqual(events[0].timestamp, "2026-10-08T09:00:00Z")


if __name__ == "__main__":
    unittest.main()
