"""Bounded, read-only UDP queries for Source and GoldSrc. Standard library only."""
from __future__ import annotations

import bz2
import socket
import struct
import time
import zlib

SIMPLE = b'\xff\xff\xff\xff'
SPLIT = b'\xfe\xff\xff\xff'
MAX_RESPONSE = 131072


class ProtocolError(ValueError):
    pass


class Reader:
    def __init__(self, data):
        self.data, self.offset = data, 0

    def take(self, size):
        if self.offset + size > len(self.data):
            raise ProtocolError('Respuesta truncada')
        result = self.data[self.offset:self.offset + size]
        self.offset += size
        return result

    def unpack(self, fmt):
        return struct.unpack(fmt, self.take(struct.calcsize(fmt)))

    def text(self):
        end = self.data.find(b'\0', self.offset)
        if end < 0:
            raise ProtocolError('Cadena sin terminador')
        raw = self.take(end - self.offset + 1)[:-1]
        return raw.decode('utf-8', errors='replace')


def parse_info(data):
    reader = Reader(data)
    kind = reader.take(1)
    if kind == b'I':
        protocol, = reader.unpack('<B')
        name, map_name, folder, game = [reader.text() for _ in range(4)]
        appid, players, maximum, bots = reader.unpack('<HBBB')
        server_type, platform, password, vac = reader.unpack('<ccBB')
        version = reader.text()
        steamid = None
        if reader.offset < len(data):
            edf, = reader.unpack('<B')
            if edf & 0x80:
                reader.unpack('<H')
            if edf & 0x10:
                steamid, = reader.unpack('<Q')
            if edf & 0x40:
                reader.unpack('<H')
                reader.text()
            if edf & 0x20:
                reader.text()
            if edf & 0x01:
                reader.unpack('<Q')
    elif kind == b'm':
        reader.text()  # Server's self-reported address; use the queried address instead.
        name, map_name, folder, game = [reader.text() for _ in range(4)]
        players, maximum, protocol = reader.unpack('<BBB')
        server_type, platform, password, is_mod = reader.unpack('<ccBB')
        if is_mod:
            reader.text()
            reader.text()
            reader.take(1)
            reader.unpack('<IIBB')
        vac, bots = reader.unpack('<BB')
        appid, version, steamid = None, None, None
    else:
        raise ProtocolError(f'Tipo A2S_INFO inesperado: {kind.hex()}')
    return {'name': name, 'map': map_name, 'folder': folder, 'game': game,
            'appid': appid, 'players': players, 'max_players': maximum, 'bots': bots,
            'protocol': protocol, 'version': version,
            'steamid': str(steamid) if steamid else None}


def parse_players(data):
    reader = Reader(data)
    if reader.take(1) != b'D':
        raise ProtocolError('Tipo A2S_PLAYER inesperado')
    count, = reader.unpack('<B')
    rows = []
    for _ in range(count):
        index, = reader.unpack('<B')
        name = reader.text()
        score, duration = reader.unpack('<if')
        rows.append({'index': index, 'name': name, 'score': score, 'duration': duration})
    return rows


def split_fragment(packet, style=None):
    if len(packet) < 10 or packet[:4] != SPLIT:
        raise ProtocolError('Fragmento inválido')
    request_id, = struct.unpack_from('<I', packet, 4)
    if style is None:
        # Source stores total/index in separate bytes. GoldSrc packs them in nibbles.
        style = 'source' if 1 <= packet[8] <= 64 and packet[9] < packet[8] else 'goldsrc'
    if style == 'source':
        total, index = packet[8:10]
        start = 10
        # Modern Source includes a maximum packet size; older engines omit it.
        if len(packet) >= 12 and 256 <= struct.unpack_from('<H', packet, 10)[0] <= 4096:
            start = 12
    else:
        total, index, start = packet[8] & 15, packet[8] >> 4, 9
    if not 1 <= total <= 64 or index >= total:
        raise ProtocolError('Índice de fragmento inválido')
    return request_id, total, index, packet[start:], style


def receive(sock, deadline):
    def read():
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('Tiempo de consulta agotado')
        sock.settimeout(remaining)
        return sock.recv(65535)

    packet = read()
    if packet.startswith(SIMPLE):
        return packet[4:]
    request_id, total, index, fragment, style = split_fragment(packet)
    parts = {index: fragment}
    for _ in range(128):
        if len(parts) == total:
            break
        fragment_id, count, index, fragment, _ = split_fragment(read(), style)
        if fragment_id != request_id or count != total:
            raise ProtocolError('Fragmentos de respuestas distintas')
        if index in parts and parts[index] != fragment:
            raise ProtocolError('Fragmento duplicado contradictorio')
        parts[index] = fragment
        if sum(map(len, parts.values())) > MAX_RESPONSE:
            raise ProtocolError('Respuesta demasiado grande')
    else:
        raise ProtocolError('Demasiados fragmentos duplicados')
    payload = b''.join(parts[index] for index in range(total))
    if style == 'source' and request_id & 0x80000000:
        if len(payload) < 8:
            raise ProtocolError('Cabecera comprimida truncada')
        size, checksum = struct.unpack_from('<II', payload)
        if size > MAX_RESPONSE:
            raise ProtocolError('Respuesta descomprimida demasiado grande')
        decoder = bz2.BZ2Decompressor()
        payload = decoder.decompress(payload[8:], max_length=MAX_RESPONSE + 1)
        if not decoder.eof or len(payload) != size or zlib.crc32(payload) != checksum:
            raise ProtocolError('Respuesta comprimida inválida')
    if payload.startswith(SIMPLE):
        payload = payload[4:]
    return payload


def query(address, kind, timeout=2.0):
    if kind not in ('info', 'players'):
        raise ValueError('Consulta desconocida')
    base = b'TSource Engine Query\0' if kind == 'info' else b'U'
    challenge = b'' if kind == 'info' else b'\xff\xff\xff\xff'
    deadline = time.monotonic() + timeout
    first_rtt = None
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        # Connected UDP accepts replies only from the endpoint being queried.
        sock.connect(address)
        for _ in range(4):
            sent = time.monotonic()
            sock.send(SIMPLE + base + challenge)
            payload = receive(sock, deadline)
            if first_rtt is None:
                first_rtt = (time.monotonic() - sent) * 1000
            if payload[:1] == b'A':
                if len(payload) != 5:
                    raise ProtocolError('Challenge inválido')
                challenge = payload[1:]
                continue
            if kind == 'info':
                result = parse_info(payload)
                result['ping_ms'] = round(first_rtt, 3)
                return result
            return parse_players(payload)
    raise ProtocolError('El servidor repite el challenge')
