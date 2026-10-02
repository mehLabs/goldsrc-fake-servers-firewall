"""Read CS 1.6 server addresses through an installed Windows Steamworks DLL.

Uses the public SteamMatchMakingServers002 ABI, not process memory or UI scraping.
The DLL is loaded from an existing Steam game installation; it is never downloaded.
"""
from __future__ import annotations

import ctypes as C
import ipaddress
import os
from pathlib import Path
import re
import struct
import time


class NetAddress(C.Structure):
    _fields_ = [('connection_port', C.c_uint16), ('query_port', C.c_uint16),
                ('ip', C.c_uint32)]


class ServerItem(C.Structure):
    _pack_ = 4
    _fields_ = [
        ('address', NetAddress), ('ping', C.c_int32), ('responded', C.c_bool),
        ('do_not_refresh', C.c_bool), ('folder', C.c_char * 32),
        ('map', C.c_char * 32), ('description', C.c_char * 64),
        ('appid', C.c_uint32), ('players', C.c_int32), ('max_players', C.c_int32),
        ('bots', C.c_int32), ('password', C.c_bool), ('secure', C.c_bool),
        ('last_played', C.c_uint32), ('version', C.c_int32),
        ('name', C.c_char * 64), ('tags', C.c_char * 128), ('steamid', C.c_uint64),
    ]


class Filter(C.Structure):
    _fields_ = [('key', C.c_char * 256), ('value', C.c_char * 256)]


def locate_api(explicit: str | None) -> Path:
    if os.name != 'nt' or struct.calcsize('P') != 8:
        raise RuntimeError('La consulta de Steam necesita Windows y Python de 64 bits.')
    if explicit:
        path = Path(explicit).resolve()
        if not path.is_file() or path.name.lower() != 'steam_api64.dll':
            raise RuntimeError('--steam-api debe apuntar a una steam_api64.dll instalada.')
        return path
    steam = Path(os.environ.get('ProgramFiles(x86)', r'C:\Program Files (x86)')) / 'Steam'
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r'Software\Valve\Steam') as key:
            steam = Path(winreg.QueryValueEx(key, 'SteamPath')[0])
    except OSError:
        pass
    libraries = {steam}
    config = steam / 'steamapps' / 'libraryfolders.vdf'
    if config.exists():
        for value in re.findall(r'"path"\s+"([^"]+)"', config.read_text(encoding='utf-8')):
            libraries.add(Path(value.replace('\\\\', '\\')))
    # Prefer Valve's modern DLL, which exports the flat public API.
    for library in sorted(libraries):
        common = library / 'steamapps' / 'common'
        for game in ['Counter-Strike Global Offensive', 'Half-Life Alyx', 'dota 2 beta']:
            candidate = common / game / 'game' / 'bin' / 'win64' / 'steam_api64.dll'
            if candidate.is_file():
                return candidate
    for library in sorted(libraries):
        common = library / 'steamapps' / 'common'
        if common.exists():
            for candidate in common.rglob('steam_api64.dll'):
                return candidate
    raise RuntimeError('No encontré steam_api64.dll. Indicá --steam-api con una DLL '
                       'de Steamworks de un juego instalado o del SDK oficial.')


class SteamList:
    def __init__(self, dll_path: Path):
        os.environ['SteamAppId'] = '10'
        os.environ['SteamGameId'] = '10'
        self.dll = C.CDLL(str(dll_path))
        self.initialized = False
        self.mm = None
        self.request = None
        self._bind('SteamAPI_RunCallbacks', None, [])
        self._bind('SteamAPI_Shutdown', None, [])
        self._bind('SteamAPI_SteamMatchmakingServers_v002', C.c_void_p, [])
        for name, result, args in [
            ('RequestInternetServerList', C.c_void_p,
             [C.c_uint32, C.POINTER(C.POINTER(Filter)), C.c_uint32, C.c_void_p]),
            ('GetServerDetails', C.POINTER(ServerItem), [C.c_void_p, C.c_int]),
            ('GetServerCount', C.c_int, [C.c_void_p]),
            ('IsRefreshing', C.c_bool, [C.c_void_p]),
            ('ReleaseRequest', None, [C.c_void_p]),
        ]:
            self._bind('SteamAPI_ISteamMatchmakingServers_' + name, result,
                       [C.c_void_p] + args)
        if hasattr(self.dll, 'SteamAPI_InitFlat'):
            self._bind('SteamAPI_InitFlat', C.c_int, [C.c_void_p])
            error = C.create_string_buffer(1024)
            code = self.dll.SteamAPI_InitFlat(error)
            if code:
                raise RuntimeError(f'SteamAPI_InitFlat: {code}: '
                                   f'{error.value.decode(errors="replace")}')
        else:
            self._bind('SteamAPI_InitSafe', C.c_bool, [])
            if not self.dll.SteamAPI_InitSafe():
                raise RuntimeError('No se pudo iniciar Steamworks. Abrí Steam con tu cuenta.')
        self.initialized = True
        self.mm = self.dll.SteamAPI_SteamMatchmakingServers_v002()
        if not self.mm:
            self.close()
            raise RuntimeError('Steam no devolvió SteamMatchMakingServers002.')

    def _bind(self, name, result, args):
        try:
            method = getattr(self.dll, name)
        except AttributeError as exc:
            raise RuntimeError(f'DLL incompatible: falta {name}. Usá una DLL más reciente.') from exc
        method.restype, method.argtypes = result, args

    def _call(self, name, *args):
        return getattr(self.dll, 'SteamAPI_ISteamMatchmakingServers_' + name)(self.mm, *args)

    def discover(self, timeout=300.0, extra_filters=()):
        # AppID 10 already selects CS 1.6. The public browser filter language
        # differs from the legacy UDP language; do not add legacy 'gamedir'.
        filter_values = [Filter(key.encode(), value.encode()) for key, value in extra_filters]
        # Steam expects a pointer to ONE pointer to a contiguous array, not an
        # array of pointers. Keep both allocations alive until ReleaseRequest.
        filters = (Filter * len(filter_values))(*filter_values)
        filter_pointer = C.cast(filters, C.POINTER(Filter))
        self.request = self._call('RequestInternetServerList', 10,
                                 C.byref(filter_pointer) if filter_values else None, len(filter_values), None)
        if not self.request:
            raise RuntimeError('Steam no creó la consulta de servidores.')
        started = time.monotonic()
        next_progress = started
        complete = False
        try:
            while time.monotonic() - started < timeout:
                self.dll.SteamAPI_RunCallbacks()
                count = self._call('GetServerCount', self.request)
                if time.monotonic() >= next_progress:
                    print(f'Steam: {count} entradas recibidas; '
                          f'{time.monotonic() - started:.0f}s', flush=True)
                    next_progress = time.monotonic() + 10
                # Give the asynchronous request time to start before accepting completion.
                if time.monotonic() - started >= 2 and not self._call('IsRefreshing', self.request):
                    complete = True
                    break
                time.sleep(0.05)
            rows = {}
            for index in range(self._call('GetServerCount', self.request)):
                ptr = self._call('GetServerDetails', self.request, index)
                if not ptr:
                    continue
                item = ptr.contents
                ip = str(ipaddress.IPv4Address(item.address.ip))
                endpoint = f'{ip}:{item.address.query_port}'
                rows[endpoint] = {
                    'ip': ip, 'query_port': item.address.query_port,
                    'connection_port': item.address.connection_port,
                    'steam_ping_ms': item.ping, 'steam_responded': bool(item.responded),
                    'name': item.name.decode('utf-8', errors='replace'),
                    'map': item.map.decode('utf-8', errors='replace'),
                    'players': item.players, 'max_players': item.max_players,
                    'bots': item.bots, 'steamid': str(item.steamid),
                    'appid': item.appid, 'folder': item.folder.decode(errors='replace'),
                }
            return list(rows.values()), {
                'complete': complete, 'elapsed_seconds': round(time.monotonic() - started, 2),
                'endpoint_count': len(rows), 'dll': str(Path(self.dll._name)),
                'source': 'SteamMatchMakingServers002.RequestInternetServerList(appid=10)',
                'filters': list(extra_filters), 'possibly_capped': len(rows) >= 10000,
            }
        finally:
            self._call('ReleaseRequest', self.request)
            self.request = None

    def close(self):
        if self.request:
            self._call('ReleaseRequest', self.request)
            self.request = None
        if self.initialized:
            self.dll.SteamAPI_Shutdown()
            self.initialized = False

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
