"""Optional Steam Web API discovery when STEAM_WEB_API_KEY is provided.

GetServerList is used by Valve's server service, but is not documented on the
public IGameServersService page. Keep native Steam discovery as the fallback.
"""
from __future__ import annotations

import json
import ipaddress
import urllib.error
import urllib.parse
import urllib.request


def get_page(key, filter_text, limit):
    url = 'https://api.steampowered.com/IGameServersService/GetServerList/v1/?'
    url += urllib.parse.urlencode({'key': key, 'filter': filter_text, 'limit': limit})
    try:
        with urllib.request.urlopen(url, timeout=30) as response:
            data = json.load(response)
    except urllib.error.HTTPError as exc:
        # Never include the credential-bearing URL in an error/log/report.
        raise RuntimeError(f'Steam Web API devolvió HTTP {exc.code}; revisá la clave y el acceso.') from None
    except urllib.error.URLError:
        raise RuntimeError('No se pudo conectar con Steam Web API.') from None
    if not isinstance(data.get('response'), dict):
        raise RuntimeError('Respuesta inesperada de Steam Web API.')
    return data['response'].get('servers', [])


def discover_web(key, limit=50000, max_pages=20, fetch=get_page):
    endpoints, known_ips, pages = {}, set(), []
    complete = False
    for index in range(max_pages):
        filter_text = r'\appid\10\gamedir\cstrike'
        if known_ips:
            filter_text += '\\nor\\' + str(len(known_ips))
            filter_text += ''.join('\\gameaddr\\' + ip for ip in sorted(known_ips))
        raw = fetch(key, filter_text, limit)
        new_ips = set()
        for item in raw:
            try:
                ip, port = item['addr'].rsplit(':', 1)
                ip = str(ipaddress.IPv4Address(ip))
                if not 1 <= int(port) <= 65535:
                    continue
                row = {'ip': ip, 'query_port': int(port),
                       'connection_port': int(item.get('gameport', port)),
                       'steam_ping_ms': None, 'steam_responded': False,
                       'name': item.get('name', ''), 'map': item.get('map', ''),
                       'players': item.get('players'), 'max_players': item.get('max_players'),
                       'bots': item.get('bots'), 'steamid': str(item.get('steamid', '')),
                       'appid': item.get('appid'), 'folder': item.get('gamedir', '')}
            except (KeyError, ValueError, TypeError):
                continue
            endpoints[(ip, int(port))] = row
            new_ips.add(ip)
        pages.append({'returned': len(raw), 'new_ips': len(new_ips - known_ips)})
        print(f'Steam Web API, lote {index + 1}: {len(raw)} entradas.', flush=True)
        # Validate exclusion behavior instead of accepting an ignored filter.
        if known_ips.intersection(new_ips):
            break
        known_ips.update(new_ips)
        if len(raw) < limit:
            complete = True
            break
        if not new_ips:
            break
    return list(endpoints.values()), {
        'source': 'IGameServersService.GetServerList/v1', 'complete': complete,
        'possibly_capped': not complete, 'endpoint_count': len(endpoints),
        'ip_count': len(known_ips), 'pages': pages,
        'scope': 'IPs recibidas del master; tras un lote lleno se excluyen IPs ya recibidas.',
        'all_ports_enumerated': len(pages) == 1 and complete,
    }
