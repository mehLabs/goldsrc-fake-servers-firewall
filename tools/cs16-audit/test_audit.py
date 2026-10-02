"""Meaningful regression checks. Each test follows Arrange, Act, Assert."""
import bz2
import ctypes
import socket
import struct
import time
import unittest
from unittest.mock import patch
import zlib

from a2s_query import SIMPLE, SPLIT, ProtocolError, parse_info, parse_players, query, receive
from audit import classify, classify_steam_rule
from steam_list import ServerItem
from web_list import discover_web


def info(name='Test', map_name='de_dust2', players=12, maximum=32):
    return {'name': name, 'map': map_name, 'players': players, 'max_players': maximum,
            'bots': 0, 'folder': 'cstrike', 'appid': 10, 'steamid': None, 'ping_ms': 20}


def result(observations):
    return {'endpoint': '8.8.8.8:27015', 'ip': '8.8.8.8', 'steam': {}, 'observations': observations}


class FakeSocket:
    def __init__(self, packets):
        self.packets = iter(packets)
        self.sent = []

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def connect(self, address):
        self.address = address

    def send(self, data):
        self.sent.append(data)

    def settimeout(self, value):
        pass

    def recv(self, size):
        return next(self.packets)


class AuditTests(unittest.TestCase):
    def test_source_and_goldsrc_player_counts(self):
        # Arrange: fixed wire data in both Valve response formats.
        source = (b'I\x30Test\0de_dust2\0cstrike\0Counter-Strike\0'
                  + struct.pack('<HBBBccBB', 10, 12, 32, 2, b'd', b'l', 0, 1)
                  + b'1.1.2.7\0\0')
        legacy = (b'm8.8.8.8:27015\0Legacy\0cs_italy\0cstrike\0Counter-Strike\0'
                  + struct.pack('<BBBccBBBB', 0, 24, 47, b'd', b'l', 0, 0, 1, 0))
        # Act
        current, old = parse_info(source), parse_info(legacy)
        # Assert
        self.assertEqual((current['players'], current['bots'], current['appid']), (12, 2, 10))
        self.assertEqual((old['name'], old['players'], old['max_players']), ('Legacy', 0, 24))

    def test_empty_list_is_not_timeout(self):
        # Arrange
        empty = result([{'before': info(), 'after': info(), 'player_list': []} for _ in range(4)])
        failed = result([{'before': info(), 'after': info(), 'player_list_error': 'TimeoutError'} for _ in range(4)])
        # Act
        empty_verdict, failed_verdict = classify(empty, 100), classify(failed, 100)
        # Assert
        self.assertEqual(empty_verdict['status'], 'sospechoso')
        self.assertEqual(failed_verdict['status'], 'inconcluso')
        self.assertEqual(failed_verdict['reasons'], [])

    def test_normal_map_change_is_not_spam(self):
        # Arrange
        observations = [{'before': info(map_name=map_name), 'after': info(map_name=map_name),
                         'player_list': [{'name': 'Player'}] * 12}
                        for map_name in ['de_dust2', 'de_dust2', 'de_inferno', 'de_inferno']]
        # Act
        verdict = classify(result(observations), 100)
        # Assert
        self.assertEqual(verdict['status'], 'sin_indicios')
        self.assertEqual(verdict['reasons'], [])

    def test_rapid_identity_rotation_flags_endpoint(self):
        # Arrange
        observations = [{'before': info(name=f'Fake{i}', map_name='de_dust2'),
                         'after': info(name=f'Other{i}', map_name='de_inferno'),
                         'player_list_error': 'TimeoutError'} for i in range(4)]
        # Act
        verdict = classify(result(observations), 100)
        # Assert
        self.assertEqual(verdict['status'], 'spam')
        self.assertIn('nombre_o_mapa_cambia_en_tres_refrescos_consecutivos', verdict['reasons'])
        self.assertEqual(verdict['consecutive_identity_changes'], 3)

    def test_three_changes_in_name_or_map_are_required(self):
        for identities in [
                [('Test', 'de_dust2'), ('Test', 'de_inferno'), ('Test', 'de_dust2'), ('Test', 'de_inferno')],
                [('A', 'de_dust2'), ('B', 'de_dust2'), ('A', 'de_dust2'), ('B', 'de_dust2')],
                [('A', 'de_dust2'), ('B', 'de_dust2'), ('B', 'de_inferno'), ('A', 'de_inferno')]]:
            with self.subTest(identities=identities):
                # Arrange: baseline + three refreshes, changing either field each time.
                observations = [{'before': info(name=name, map_name=map_name),
                                 'after': info(name=name, map_name=map_name),
                                 'player_list': [{'name': 'Player'}] * 12}
                                for name, map_name in identities]
                # Act
                verdict = classify(result(observations), 100)
                # Assert
                self.assertEqual(verdict['status'], 'spam')
                self.assertEqual(verdict['consecutive_identity_changes'], 3)

    def test_isolated_or_nonconsecutive_changes_are_not_spam(self):
        for maps in [
                ['de_dust2', 'de_inferno', 'de_inferno', 'de_inferno'],
                ['de_dust2', 'de_inferno', 'de_dust2'],
                ['de_dust2', 'de_inferno', 'de_inferno', 'de_dust2', 'de_dust2', 'de_inferno']]:
            with self.subTest(maps=maps):
                # Arrange: one change, only two changes, or three separated changes.
                observations = [{'before': info(map_name=m), 'after': info(map_name=m),
                                 'player_list': [{'name': 'Player'}] * 12} for m in maps]
                # Act
                verdict = classify(result(observations), 100)
                # Assert
                self.assertEqual(verdict['status'], 'sin_indicios')
                self.assertEqual(verdict['reasons'], [])
                self.assertLess(verdict['consecutive_identity_changes'], 3)

    def test_missing_refresh_breaks_identity_change_streak(self):
        # Arrange: changes before and after a failed INFO must not be joined.
        observations = [{'before': info(name=name), 'after': info(name=name),
                         'player_list': [{'name': 'Player'}] * 12}
                        for name in ['A', 'B', 'C', 'D', 'E']]
        observations.insert(2, {'before_error': 'TimeoutError', 'after_error': 'TimeoutError'})
        # Act
        verdict = classify(result(observations), 100)
        # Assert
        self.assertEqual(verdict['status'], 'sin_indicios')
        self.assertEqual(verdict['consecutive_identity_changes'], 2)

    def test_preflight_does_not_count_as_spaced_refreshes(self):
        # Arrange: three fast ping probes followed by only two real changes.
        observations = [{'before': info(name=name), 'phase': 'preflight'} for name in ['X', 'Y', 'Z']]
        observations += [{'before': info(name=name), 'after': info(name=name), 'phase': 'refresh',
                          'player_list': [{'name': 'Player'}] * 12} for name in ['A', 'B', 'C', 'C']]
        # Act
        verdict = classify(result(observations), 100)
        # Assert
        self.assertEqual(verdict['status'], 'sin_indicios')
        self.assertEqual(verdict['consecutive_identity_changes'], 2)

    def test_one_map_change_during_player_query_is_not_spam(self):
        # Arrange: a real map transition occurs inside a single INFO/PLAYER/INFO round.
        observations = [{'before': info(map_name='de_dust2'), 'after': info(map_name='de_inferno'),
                         'player_list': [{'name': 'Player'}] * 12}]
        observations += [{'before': info(map_name='de_inferno'), 'after': info(map_name='de_inferno'),
                          'player_list': [{'name': 'Player'}] * 12} for _ in range(3)]
        # Act
        verdict = classify(result(observations), 100)
        # Assert
        self.assertEqual(verdict['status'], 'sin_indicios')
        self.assertEqual(verdict['consecutive_identity_changes'], 1)

    def test_rotation_preserves_zero_player_rule_and_ping_cutoff(self):
        for players, ping, expected in [(0, 20, 'seguro_por_regla_usuario'), (12, 100, 'fuera_de_ping')]:
            with self.subTest(players=players, ping=ping):
                # Arrange: all three identity changes, but an earlier filter takes precedence.
                observations = [{'before': {**info(name=str(i), players=players), 'ping_ms': ping},
                                 'after': {**info(name=str(i), players=players), 'ping_ms': ping}}
                                for i in range(4)]
                # Act
                verdict = classify(result(observations), 100)
                # Assert
                self.assertEqual(verdict['consecutive_identity_changes'], 3)
                self.assertEqual(verdict['status'], expected)

    def test_user_rules_and_ping_boundary(self):
        # Arrange
        row = {'ip': '8.8.8.8', 'query_port': 27015, 'steam_responded': True, 'steam_ping_ms': 20}
        too_slow = result([{'before': {**info(players=40, maximum=64), 'ping_ms': 100}}] * 4)
        # Act
        zero = classify_steam_rule({**row, 'players': 0})
        thirty_two = classify_steam_rule({**row, 'players': 32})
        thirty_three = classify_steam_rule({**row, 'players': 33})
        outside = classify(too_slow, 100)
        # Assert
        self.assertEqual(zero['status'], 'seguro_por_regla_usuario')
        self.assertIsNone(thirty_two)
        self.assertEqual(thirty_three['status'], 'spam')
        self.assertEqual(outside['status'], 'fuera_de_ping')

    def test_repeated_challenge_is_bounded(self):
        # Arrange
        fake = FakeSocket([SIMPLE + b'A\x01\0\0\0'] * 4)
        # Act / Assert
        with patch('a2s_query.socket.socket', return_value=fake):
            with self.assertRaises(ProtocolError):
                query(('8.8.8.8', 27015), 'players', 1)
        self.assertEqual(len(fake.sent), 4)
        self.assertEqual(fake.sent[0], SIMPLE + b'U\xff\xff\xff\xff')

    def test_goldsrc_fragments_reassemble_out_of_order(self):
        # Arrange
        payload = SIMPLE + b'D\x01\0Alice\0' + struct.pack('<if', 3, 10.5)
        header = SPLIT + struct.pack('<I', 123)
        packets = [header + b'\x12' + payload[8:], header + b'\x02' + payload[:8]]
        # Act
        decoded = parse_players(receive(FakeSocket(packets), time.monotonic() + 1))
        # Assert
        self.assertEqual(decoded, [{'index': 0, 'name': 'Alice', 'score': 3, 'duration': 10.5}])

    def test_compressed_source_response_checks_checksum(self):
        # Arrange
        payload = SIMPLE + b'D\0'
        body = struct.pack('<II', len(payload), zlib.crc32(payload)) + bz2.compress(payload)
        packet = SPLIT + struct.pack('<I', 0x80000001) + b'\x01\0' + struct.pack('<H', 1248) + body
        # Act
        decoded = receive(FakeSocket([packet]), time.monotonic() + 1)
        # Assert
        self.assertEqual(parse_players(decoded), [])

    def test_truncated_packet_is_rejected(self):
        # Arrange
        payload = b'I\x30unterminated'
        # Act / Assert
        with self.assertRaises(ProtocolError):
            parse_info(payload)

    def test_native_abi_matches_sdk_packed_steamid(self):
        # Arrange
        expected_offset, expected_size = 364, 372
        # Act
        offset, size = ServerItem.steamid.offset, ctypes.sizeof(ServerItem)
        # Assert
        self.assertEqual((offset, size), (expected_offset, expected_size))

    def test_web_discovery_excludes_known_ips_on_next_page(self):
        # Arrange: a deliberately full first page and a shorter second page.
        pages = [[{'addr': '8.8.8.8:27015'}, {'addr': '8.8.8.8:27016'}],
                 [{'addr': '1.1.1.1:27015'}]]
        calls = []
        def fetch(key, filter_text, limit):
            calls.append(filter_text)
            return pages[len(calls) - 1]
        # Act
        rows, metadata = discover_web('test-key', limit=2, fetch=fetch)
        # Assert
        self.assertEqual({row['ip'] for row in rows}, {'8.8.8.8', '1.1.1.1'})
        self.assertIn('\\nor\\1\\gameaddr\\8.8.8.8', calls[1])
        self.assertTrue(metadata['complete'])
        self.assertFalse(metadata['all_ports_enumerated'])
        self.assertNotIn('test-key', str(metadata))

    def test_ignored_exclusion_does_not_claim_full_coverage(self):
        # Arrange
        def fetch(key, filter_text, limit):
            return [{'addr': '8.8.8.8:27015'}]
        # Act
        rows, metadata = discover_web('test-key', limit=1, fetch=fetch)
        # Assert
        self.assertEqual(len(rows), 1)
        self.assertFalse(metadata['complete'])
        self.assertTrue(metadata['possibly_capped'])


if __name__ == '__main__':
    unittest.main()
