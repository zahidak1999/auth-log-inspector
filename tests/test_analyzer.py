import unittest

from authlog_analyzer.analyzer import analyze
from authlog_analyzer.parser import parse_lines


def events(*messages):
    lines = [f"Oct  8 09:14:{index:02d} host sshd[{index}]: {message}" for index, message in enumerate(messages)]
    return parse_lines(lines), len(lines)


class AnalyzeTests(unittest.TestCase):
    def test_detects_repeated_failures_by_source_and_user(self):
        parsed, total = events(
            "Failed password for invalid user admin from 203.0.113.44 port 22 ssh2",
            "Failed password for root from 203.0.113.44 port 22 ssh2",
            "Failed password for admin from 203.0.113.44 port 22 ssh2",
        )
        report = analyze(parsed, total, threshold=3)
        self.assertEqual(report.failed_events, 3)
        self.assertEqual(report.repeated_failure_sources[0].source_ip, "203.0.113.44")
        self.assertEqual(report.repeated_failure_sources[0].usernames, ["admin", "root"])
        self.assertEqual(report.failures_by_username["admin"], 2)

    def test_flags_success_after_threshold_failures_and_resets_counter(self):
        parsed, total = events(
            "Failed password for root from 203.0.113.44 port 22 ssh2",
            "Failed password for root from 203.0.113.44 port 22 ssh2",
            "Accepted publickey for zahid from 203.0.113.44 port 22 ssh2",
            "Accepted publickey for zahid from 203.0.113.44 port 22 ssh2",
        )
        report = analyze(parsed, total, threshold=2)
        self.assertEqual(len(report.successes_after_failures), 1)
        finding = report.successes_after_failures[0]
        self.assertEqual(finding.username, "zahid")
        self.assertEqual(finding.preceding_failures, 2)

    def test_counts_ignored_lines(self):
        parsed, _ = events(
            "Failed password for root from 203.0.113.44 port 22 ssh2",
            "pam_unix(cron:session): session opened for user root",
        )
        report = analyze(parsed, total_lines=2)
        self.assertEqual(report.ignored_lines, 1)

    def test_rejects_threshold_below_one(self):
        with self.assertRaises(ValueError):
            analyze([], total_lines=0, threshold=0)


if __name__ == "__main__":
    unittest.main()
