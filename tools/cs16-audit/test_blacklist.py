"""Meaningful append-only and publication regression checks (Arrange, Act, Assert)."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from blacklist import GROUP, append_ips, check_publish, detected_ips, publish


class BlacklistTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / 'blacklisted_iplist.json'
        self.original = {'custom': 'keep me', 'list': [
            {'name': 'Manual', 'reason': 'Original', 'ip': ['8.8.8.8'], 'custom': 42},
            {'name': GROUP, 'reason': 'Existing reason', 'ip': ['1.1.1.1']}]}
        self.path.write_text(json.dumps(self.original), encoding='utf-8')

    def test_append_preserves_groups_and_deduplicates_globally(self):
        # Arrange
        before = copy.deepcopy(self.original)
        incoming = ['8.8.8.8', '9.9.9.9', '1.1.1.1', '9.9.9.9', '4.2.2.2']
        # Act
        added = append_ips(self.path, incoming)
        after = json.loads(self.path.read_text(encoding='utf-8'))
        # Assert
        self.assertEqual(added, ['4.2.2.2', '9.9.9.9'])
        self.assertEqual(after['list'][0], before['list'][0])
        self.assertEqual(after['custom'], 'keep me')
        self.assertEqual(after['list'][1]['reason'], 'Existing reason')
        self.assertEqual(after['list'][1]['ip'], ['1.1.1.1', '4.2.2.2', '9.9.9.9'])

    def test_new_group_does_not_change_existing_groups(self):
        # Arrange
        before = {'list': [self.original['list'][0]]}
        self.path.write_text(json.dumps(before), encoding='utf-8')
        # Act
        append_ips(self.path, ['9.9.9.9'])
        after = json.loads(self.path.read_text(encoding='utf-8'))
        # Assert
        self.assertEqual(after['list'][:1], before['list'])
        self.assertEqual(after['list'][1]['name'], GROUP)
        self.assertEqual(after['list'][1]['ip'], ['9.9.9.9'])

    def test_repeat_and_empty_input_preserve_bytes(self):
        # Arrange
        append_ips(self.path, ['9.9.9.9'])
        before = self.path.read_bytes()
        # Act
        repeated = append_ips(self.path, ['9.9.9.9', '8.8.8.8'])
        empty = append_ips(self.path, [])
        # Assert
        self.assertEqual(repeated, [])
        self.assertEqual(empty, [])
        self.assertEqual(self.path.read_bytes(), before)

    def test_invalid_input_cannot_partially_append(self):
        for invalid in ['not an IP', '127.0.0.1', '10.1.2.3', '::1']:
            with self.subTest(invalid=invalid):
                # Arrange
                before = self.path.read_bytes()
                # Act
                with self.assertRaises(ValueError):
                    append_ips(self.path, iter(['9.9.9.9', invalid]))
                # Assert
                self.assertEqual(self.path.read_bytes(), before)

    def test_existing_duplicate_entries_are_never_removed(self):
        # Arrange
        self.original['list'][0]['ip'].append('8.8.8.8')
        self.path.write_text(json.dumps(self.original), encoding='utf-8')
        # Act
        append_ips(self.path, ['9.9.9.9'])
        after = json.loads(self.path.read_text(encoding='utf-8'))
        # Assert
        self.assertEqual(after['list'][0], self.original['list'][0])

    def test_atomic_write_failure_preserves_original_file(self):
        # Arrange
        before = self.path.read_bytes()
        # Act
        with patch('blacklist.os.replace', side_effect=OSError('simulated failure')):
            with self.assertRaises(OSError):
                append_ips(self.path, ['9.9.9.9'])
        # Assert
        self.assertEqual(self.path.read_bytes(), before)
        self.assertEqual(list(self.path.parent.glob('*.tmp')), [])

    def test_only_positive_public_ips_with_ping_below_100(self):
        # Arrange
        rows = [{'ip': '9.9.9.9', 'status': 'spam', 'median_ping_ms': 99.9},
                {'ip': '9.9.9.9', 'status': 'sospechoso', 'median_ping_ms': 5},
                {'ip': '1.1.1.1', 'status': 'seguro_por_regla_usuario', 'median_ping_ms': 1},
                {'ip': '8.8.8.8', 'status': 'spam', 'median_ping_ms': 100}]
        for ping in [None, -1, True, float('nan'), float('inf')]:
            rows.append({'ip': '4.2.2.2', 'status': 'spam', 'median_ping_ms': ping})
        # Act
        detected = detected_ips({'servers': rows})
        # Assert
        self.assertEqual(detected, ['9.9.9.9'])

    def test_quick_rules_use_explicit_steam_ping(self):
        # Arrange
        rows = [{'ip': '9.9.9.9', 'status': 'spam', 'median_ping_ms': None,
                 'ping_source': 'Steam', 'steam_ping_ms': 32},
                {'ip': '8.8.8.8', 'status': 'spam', 'median_ping_ms': None,
                 'ping_source': 'Steam', 'steam_ping_ms': 100},
                {'ip': '1.1.1.1', 'status': 'spam', 'median_ping_ms': None,
                 'steam_ping_ms': 12}]
        # Act
        detected = detected_ips({'servers': rows})
        # Assert
        self.assertEqual(detected, ['9.9.9.9'])

    def test_concurrent_update_cannot_overwrite_another_run(self):
        # Arrange
        lock = self.path.with_name(self.path.name + '.lock')
        lock.write_text('other run', encoding='utf-8')
        before = self.path.read_bytes()
        # Act
        with self.assertRaisesRegex(RuntimeError, 'lock'):
            append_ips(self.path, ['9.9.9.9'])
        # Assert
        self.assertEqual(self.path.read_bytes(), before)
        self.assertEqual(lock.read_text(encoding='utf-8'), 'other run')

    def test_publication_commits_only_json_and_pushes_without_force(self):
        # Arrange
        calls = []
        def fake_git(root, *args):
            calls.append(args)
            return 'changed' if args[0] == 'diff' else 'abc123'
        # Act
        with patch('blacklist.check_publish', return_value=self.path.parent), \
                patch('blacklist.git', side_effect=fake_git), \
                patch('blacklist.subprocess.run') as push:
            commit = publish(self.path)
        # Assert
        self.assertEqual(commit, 'abc123')
        command = next(args for args in calls if args[0] == 'commit')
        self.assertEqual(command[1], '--only')
        self.assertRegex(command[3], r'^feat: blacklist updated \(\d{4}-\d{2}-\d{2}\)$')
        self.assertEqual(command[4:], ('--', 'blacklisted_iplist.json'))
        push.assert_called_once_with(['git', '-C', str(self.path.parent), 'push', 'origin', 'main'], check=True)

    def test_publication_no_changes_creates_no_commit(self):
        # Arrange
        # Act
        with patch('blacklist.check_publish', return_value=self.path.parent), \
                patch('blacklist.git', return_value='') as command, \
                patch('blacklist.subprocess.run') as push:
            commit = publish(self.path)
        # Assert
        self.assertIsNone(commit)
        command.assert_called_once_with(self.path.parent, 'diff', 'HEAD', '--', 'blacklisted_iplist.json')
        push.assert_not_called()

    def test_publication_rejects_other_branch(self):
        # Arrange
        def fake_git(root, *args):
            return str(self.path.parent) if args[0] == 'rev-parse' else 'feature'
        # Act
        with patch('blacklist.git', side_effect=fake_git):
            with self.assertRaisesRegex(ValueError, 'main'):
                check_publish(self.path)
        # Assert: no publication was possible from a feature branch.


if __name__ == '__main__':
    unittest.main()
