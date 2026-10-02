"""Collect low-latency CS 1.6 endpoints and evidence of misleading query replies."""
from __future__ import annotations

import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
import csv
from datetime import datetime, timezone
import ipaddress
import json
import math
import os
from pathlib import Path
import statistics
import threading
import time

from blacklist import DEFAULT_BLACKLIST, check_publish, publish, update_blacklist
from a2s_query import query
from steam_list import SteamList, locate_api
from web_list import discover_web


def stamp():
    return datetime.now(timezone.utc).isoformat()


def valid_endpoint(row):
    address = ipaddress.IPv4Address(row['ip'])
    if not address.is_global or not 1 <= int(row['query_port']) <= 65535:
        raise ValueError(f'Endpoint no público o inválido: {row}')
    return str(address), int(row['query_port'])


class RateLimiter:
    """Cap total UDP queries and space calls to the same IP across all its ports."""
    def __init__(self, qps):
        self.lock = threading.Lock()
        self.next_global = 0.0
        self.next_ip = {}
        self.gap = 1 / qps

    def wait(self, ip):
        with self.lock:
            now = time.monotonic()
            scheduled = max(now, self.next_global, self.next_ip.get(ip, 0))
            self.next_global = scheduled + self.gap
            self.next_ip[ip] = scheduled + 0.1
        time.sleep(max(0, scheduled - time.monotonic()))


def sample_server(row, samples, interval, timeout, limiter):
    address = valid_endpoint(row)
    observations = []
    # Web API supplies no client ping: preflight three INFO measurements and
    # avoid player queries to servers outside the requested latency range.
    if row.get('steam_ping_ms') is None:
        for _ in range(3):
            limiter.wait(address[0])
            o = {'time': stamp(), 'phase': 'preflight'}
            try:
                o['before'] = query(address, 'info', timeout)
            except (OSError, ValueError, EOFError) as exc:
                o['before_error'] = f'{type(exc).__name__}: {exc}'
            observations.append(o)
        pings = [o['before']['ping_ms'] for o in observations if 'before' in o]
        # The classifier applies the actual configurable cutoff afterwards.
        if not pings or len(pings) >= 2 and statistics.median(pings) >= row.get('_max_ping', 100):
            return {'endpoint': f'{address[0]}:{address[1]}', 'ip': address[0],
                    'steam': row, 'observations': observations}
        infos = [o['before'] for o in observations if 'before' in o]
        if any(i['players'] > 32 for i in infos) or infos and all(i['players'] == 0 for i in infos):
            return {'endpoint': f'{address[0]}:{address[1]}', 'ip': address[0],
                    'steam': row, 'observations': observations}
    for index in range(samples):
        observation = {'time': stamp(), 'phase': 'refresh'}
        for kind, key in [('info', 'before'), ('players', 'player_list'), ('info', 'after')]:
            limiter.wait(address[0])
            try:
                observation[key] = query(address, kind, timeout)
            except (OSError, ValueError, EOFError) as exc:
                observation[key + '_error'] = f'{type(exc).__name__}: {exc}'
        observations.append(observation)
        if index + 1 < samples:
            time.sleep(interval)
    return {'endpoint': f'{address[0]}:{address[1]}', 'ip': address[0],
            'steam': row, 'observations': observations}


def classify(result, max_ping):
    observations = result['observations']
    infos = [o[k] for o in observations for k in ('before', 'after') if k in o]
    pings = [i['ping_ms'] for i in infos]
    median = statistics.median(pings) if pings else None
    reasons, signals = [], []
    stable_counts = []
    # Compare the initial INFO in each spaced refresh round. Four snapshots
    # provide a baseline plus three refreshes; failures break the sequence.
    previous_identity = None
    change_streak = 0
    longest_change_streak = 0
    impossible = 0
    for o in observations:
        before, after = o.get('before'), o.get('after')
        if o.get('phase') != 'preflight':
            identity = (before['name'], before['map']) if before else None
            if identity is not None and previous_identity is not None and identity != previous_identity:
                change_streak += 1
                longest_change_streak = max(longest_change_streak, change_streak)
            else:
                change_streak = 0
            previous_identity = identity
        if before and after:
            if 'player_list' in o and all(before[k] == after[k] for k in ('name', 'map', 'players', 'bots')):
                stable_counts.append((before['players'], before['bots'], len(o['player_list'])))
        for info in (before, after):
            if info and (info['players'] > info['max_players'] or info['bots'] > info['players']
                         or info['max_players'] > 32 or info['folder'] != 'cstrike'
                         or info['appid'] not in (None, 10)):
                impossible += 1
    names = sorted({i['name'] for i in infos})
    maps = sorted({i['map'] for i in infos})
    identities = sorted({i['steamid'] for i in infos if i.get('steamid')})
    # Strong for query inconsistency, still not a proof of a redirect/scam.
    if len(identities) > 1:
        reasons.append('steamid_cambia_en_mismo_endpoint')
    if impossible >= 2:
        reasons.append('datos_incompatibles_con_cs16_repetidos')
    rotating_identity = longest_change_streak >= 3
    if rotating_identity:
        reasons.append('nombre_o_mapa_cambia_en_tres_refrescos_consecutivos')
    elif len(names) > 1:
        signals.append('nombre_cambia')
    if len(maps) > 1:
        signals.append('mapa_cambia')
    # Successful, empty lists are distinct from failed or blocked player queries.
    empty_occupied = sum(players - bots >= 2 and listed == 0
                         for players, bots, listed in stable_counts)
    mismatches = sum(players - bots - listed >= 3 for players, bots, listed in stable_counts)
    if empty_occupied >= 3:
        reasons.append('anuncia_jugadores_pero_lista_vacia_repetida')
    elif mismatches >= 3:
        reasons.append('conteo_y_lista_de_jugadores_inconsistentes_repetidos')
    failures = sum('player_list_error' in o for o in observations)
    if failures:
        signals.append('consulta_jugadores_fallo')
    over_capacity = any(i['players'] > 32 for i in infos)
    if not pings:
        status = 'inconcluso'
    elif median >= max_ping:
        status = 'fuera_de_ping'
    elif over_capacity:
        status = 'spam'
        reasons.append('mas_de_32_jugadores_regla_usuario')
    elif infos and all(i['players'] == 0 for i in infos):
        status = 'seguro_por_regla_usuario'
        reasons = ['cero_jugadores_regla_usuario']
    elif rotating_identity:
        status = 'spam'
    elif reasons:
        status = 'sospechoso'
    elif len(infos) < 4 or sum('player_list' in o for o in observations) < 2:
        status = 'inconcluso'
    else:
        status = 'sin_indicios'
    return {**result, 'status': status, 'median_ping_ms': round(median, 3) if median is not None else None,
            'reasons': reasons, 'signals': signals, 'names': names, 'maps': maps,
            'stable_player_checks': len(stable_counts), 'player_query_failures': failures,
            'consecutive_identity_changes': longest_change_streak}


def classify_steam_rule(row):
    """Apply the user's 0/>32 player rules before spending queries on an endpoint."""
    players = row.get('players')
    if not row.get('steam_responded') or players is None or 0 < players <= 32 or players < 0:
        return None
    status = 'seguro_por_regla_usuario' if players == 0 else 'spam'
    reason = 'cero_jugadores_regla_usuario' if players == 0 else 'mas_de_32_jugadores_regla_usuario'
    return {'endpoint': f"{row['ip']}:{row['query_port']}", 'ip': row['ip'], 'steam': row,
            'observations': [], 'status': status, 'median_ping_ms': None,
            'steam_ping_ms': row['steam_ping_ms'], 'ping_source': 'Steam',
            'reasons': [reason], 'signals': [], 'names': [row.get('name', '')],
            'maps': [row.get('map', '')], 'stable_player_checks': 0, 'player_query_failures': 0}


def audit_ip(rows, args, limiter):
    """The requested output is IPs: stop inspecting an IP once evidence exists.

    Other ports are not labelled fraudulent; they simply no longer need probing
    to include this IP in the requested list. --all-ports disables this shortcut.
    """
    results = []
    for row in rows:
        measured = sample_server(row, args.samples, args.interval, args.timeout, limiter)
        verdict = classify(measured, args.max_ping)
        results.append(verdict)
        if not args.all_ports and verdict['status'] in ('spam', 'sospechoso'):
            break
    return results


def write_json(path, data):
    temporary = path.with_suffix(path.suffix + '.tmp')
    temporary.write_text(json.dumps(data, ensure_ascii=False, indent=2, allow_nan=False), encoding='utf-8')
    temporary.replace(path)


def clean_numbers(value):
    if isinstance(value, float) and not math.isfinite(value):
        return None
    if isinstance(value, dict):
        return {k: clean_numbers(v) for k, v in value.items()}
    if isinstance(value, list):
        return [clean_numbers(v) for v in value]
    return value


def export(out, results, metadata):
    results = sorted(results, key=lambda r: (int(ipaddress.IPv4Address(r['ip'])), r['steam']['query_port']))
    suspects = [r for r in results if r['status'] in ('sospechoso', 'spam')]
    write_json(out / 'report.json', clean_numbers({'metadata': metadata, 'servers': results}))
    (out / 'suspicious-endpoints.txt').write_text(''.join(r['endpoint'] + '\n' for r in suspects), encoding='utf-8')
    ips = sorted({r['ip'] for r in suspects}, key=ipaddress.IPv4Address)
    (out / 'suspicious-ips.txt').write_text(''.join(ip + '\n' for ip in ips), encoding='utf-8')
    safe = [r for r in results if r['status'] == 'seguro_por_regla_usuario']
    (out / 'safe-zero-player-endpoints.txt').write_text(''.join(r['endpoint'] + '\n' for r in safe), encoding='utf-8')
    with (out / 'report.csv').open('w', newline='', encoding='utf-8-sig') as stream:
        writer = csv.writer(stream)
        writer.writerow(['endpoint', 'connection_port', 'status', 'median_ping_ms', 'steam_ping_ms', 'reasons', 'names', 'maps'])
        for r in results:
            # Prevent query-controlled names from becoming spreadsheet formulas.
            name_text = ' | '.join(r['names'])
            map_text = ' | '.join(r['maps'])
            writer.writerow([r['endpoint'], r['steam'].get('connection_port', ''), r['status'],
                             r['median_ping_ms'], r['steam'].get('steam_ping_ms'), ' | '.join(r['reasons']),
                             "'" + name_text, "'" + map_text])


def main():
    parser = argparse.ArgumentParser(description='Audita servidores públicos de CS 1.6 con ping <100 ms.')
    parser.add_argument('--steam-api', help='Ruta a steam_api64.dll instalada (detección automática por defecto).')
    parser.add_argument('--web-api', action='store_true', help='Usa STEAM_WEB_API_KEY del entorno para obtener más de 10.000 entradas.')
    parser.add_argument('--input', type=Path, help='Reutiliza discovery.json sin volver a consultar Steam.')
    parser.add_argument('--output', type=Path)
    parser.add_argument('--from-report', type=Path, help='Actualiza el JSON desde un report.json existente, sin consultas de red.')
    parser.add_argument('--blacklist', type=Path, default=DEFAULT_BLACKLIST, help='JSON a actualizar (raíz del repo por defecto).')
    parser.add_argument('--no-update-blacklist', action='store_true', help='Sólo genera informes; no actualiza la blacklist.')
    parser.add_argument('--publish', action='store_true', help='Commitea sólo el JSON y pushea origin/main; requiere main sincronizada.')
    parser.add_argument('--max-ping', type=float, default=100)
    parser.add_argument('--samples', type=int, default=4, help='Rondas de refresco: mínimo 4 (lectura inicial + 3 refrescos).')
    parser.add_argument('--interval', type=float, default=1.5)
    parser.add_argument('--timeout', type=float, default=2)
    parser.add_argument('--discovery-timeout', type=float, default=300)
    parser.add_argument('--workers', type=int, default=12)
    parser.add_argument('--qps', type=float, default=30)
    parser.add_argument('--probe-all', action='store_true', help='Mide también entradas sin respuesta o ping alto en Steam.')
    parser.add_argument('--all-ports', action='store_true', help='Sigue analizando los otros puertos de una IP ya detectada.')
    parser.add_argument('--limit', type=int, help='Limita endpoints sólo para una prueba; marca informe parcial.')
    args = parser.parse_args()
    if args.publish and args.no_update_blacklist:
        parser.error('--publish no se puede combinar con --no-update-blacklist')
    if args.from_report and (args.input or args.web_api or args.no_update_blacklist):
        parser.error('--from-report no se combina con opciones de descubrimiento ni --no-update-blacklist')
    if args.publish:
        check_publish(args.blacklist)
    if args.from_report:
        report = json.loads(args.from_report.read_text(encoding='utf-8-sig'))
        update_blacklist(args.blacklist, report)
        if args.publish:
            publish(args.blacklist)
        return
    if (not all(math.isfinite(v) for v in (args.qps, args.max_ping, args.interval, args.timeout, args.discovery_timeout))
            or args.samples < 4 or not 1 <= args.workers <= 32 or not 0 < args.qps <= 100
            or args.max_ping <= 0 or args.interval < 0 or args.timeout <= 0
            or args.discovery_timeout <= 0 or args.limit is not None and args.limit <= 0):
        parser.error('Valores inválidos: samples>=4, workers=1..32, qps=1..100; tiempos/ping positivos.')
    out = args.output or Path(__file__).resolve().parent / ('results-' + datetime.now().strftime('%Y%m%d-%H%M%S'))
    out.mkdir(parents=True, exist_ok=False)
    if args.input:
        discovery = json.loads(args.input.read_text(encoding='utf-8'))
    elif args.web_api:
        key = os.environ.get('STEAM_WEB_API_KEY')
        if not key:
            parser.error('--web-api requiere STEAM_WEB_API_KEY en el entorno; la clave no se guarda en informes.')
        rows, metadata = discover_web(key)
        discovery = {'metadata': metadata, 'servers': rows}
    else:
        with SteamList(locate_api(args.steam_api)) as steam:
            rows, metadata = steam.discover(args.discovery_timeout)
        discovery = {'metadata': metadata, 'servers': rows}
    write_json(out / 'discovery.json', discovery)
    rows = discovery['servers']
    web_source = discovery['metadata'].get('source', '').startswith('IGameServersService')
    candidates, rejected = [], 0
    for row in rows:
        try:
            valid_endpoint(row)
        except (ValueError, KeyError, TypeError):
            rejected += 1
            continue
        if args.probe_all or web_source or (row.get('steam_responded') and row.get('steam_ping_ms') is not None
                                             and 0 <= row['steam_ping_ms'] < args.max_ping):
            row['_max_ping'] = args.max_ping
            candidates.append(row)
    candidates = list({(r['ip'], r['query_port']): r for r in candidates}.values())
    selected = candidates[:args.limit] if args.limit else candidates
    metadata = {'started': stamp(), 'max_ping_ms_exclusive': args.max_ping,
                'discovery': discovery['metadata'], 'discovered': len(rows),
                'candidate_count': len(candidates), 'selected': len(selected),
                'invalid_or_nonpublic': rejected, 'probe_all': args.probe_all,
                'partial': bool(args.limit and args.limit < len(candidates)) or not discovery['metadata'].get('complete', False)
                           or discovery['metadata'].get('possibly_capped', False),
                'classification': 'Heurística de respuestas A2S; no confirma fraude ni redirección.',
                'coverage': 'Todos los endpoints recibidos del master' if args.probe_all or web_source else
                            'Endpoints con respuesta y ping < umbral en Steam, verificados por A2S.',
                'samples': args.samples, 'interval_seconds': args.interval,
                'timeout_seconds': args.timeout, 'qps': args.qps}
    print(f'Steam devolvió {len(rows)} endpoints. Auditaré {len(selected)} candidatos.', flush=True)
    results, pending = [], []
    for row in selected:
        quick = classify_steam_rule(row)
        # Quick rules can use Steam's ping only if Steam measured a qualifying response.
        if quick and row.get('steam_ping_ms') is not None and 0 <= row['steam_ping_ms'] < args.max_ping:
            results.append(quick)
        else:
            pending.append(row)
    print(f'Reglas iniciales: {dict(Counter(r["status"] for r in results))}; '
          f'consultas detalladas: {len(pending)}', flush=True)
    metadata['user_rules'] = {'zero_players': 'seguro_por_regla_usuario', 'more_than_32_players': 'spam',
                              'three_consecutive_name_or_map_changes': 'spam'}
    export(out, results, metadata)
    limiter = RateLimiter(args.qps)
    last_save = time.monotonic()
    detected_ips = {r['ip'] for r in results if r['status'] == 'spam'}
    groups = {}
    for row in pending:
        if args.all_ports or row['ip'] not in detected_ips:
            groups.setdefault(row['ip'], []).append(row)
    metadata['ip_shortcut'] = not args.all_ports
    metadata['pending_ips'] = len(groups)
    print(f'IPs pendientes: {len(groups)}. Al detectar una IP, '
          'sus otros puertos no necesitan medirse para la lista de IPs.', flush=True)
    executor = ThreadPoolExecutor(max_workers=args.workers)
    futures = {executor.submit(audit_ip, rows, args, limiter): ip for ip, rows in groups.items()}
    interrupted = False
    try:
        for future in as_completed(futures):
            results.extend(future.result())
            counts = Counter(r['status'] for r in results)
            print(f'{len(results)} endpoints clasificados: {dict(counts)}', flush=True)
            if time.monotonic() - last_save >= 10:
                metadata['finished_count'] = len(results)
                export(out, results, metadata)
                last_save = time.monotonic()
    except KeyboardInterrupt:
        interrupted = True
        metadata['partial'] = True
        for future in futures:
            future.cancel()
        print('Interrumpido: guardaré las mediciones completas.', flush=True)
    except Exception:
        metadata['partial'] = True
        for future in futures:
            future.cancel()
        raise
    finally:
        executor.shutdown(wait=True, cancel_futures=True)
        metadata.update(finished=stamp(), finished_count=len(results), interrupted=interrupted)
        if args.all_ports and len(results) != len(selected):
            metadata['partial'] = True
        metadata['ports_not_probed_after_ip_detection'] = len(selected) - len(results) if not args.all_ports else 0
        metadata['counts'] = dict(Counter(r['status'] for r in results))
        export(out, results, metadata)
        print(f'Informe: {out.resolve()}', flush=True)
    if not interrupted and not args.no_update_blacklist:
        update_blacklist(args.blacklist, {'metadata': metadata, 'servers': results})
        if args.publish:
            publish(args.blacklist)


if __name__ == '__main__':
    main()
