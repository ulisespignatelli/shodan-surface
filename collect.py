#!/usr/bin/env python3
"""
collect.py — recolector de superficie de exposición (corre en GitHub Actions).

Lee la lista de activos de targets.txt, consulta Shodan por cada uno usando la
API key del entorno (SHODAN_API_KEY, guardada como secret de Actions) y escribe
el resultado en site/data/surface.json, que el sitio estático (GitHub Pages)
muestra como dashboard.

Uso:
    SHODAN_API_KEY=xxxx python3 collect.py
    python3 collect.py --demo        # genera datos de ejemplo (sin key ni red)

Ética: monitoreá SOLO activos propios o que estés autorizado a auditar.

Autor: Ulises Pignatelli — UP Security. Licencia: MIT.
"""
import argparse
import datetime as dt
import json
import os
import re
import socket
import sys
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "site", "data", "surface.json")
TARGETS = os.path.join(HERE, "targets.txt")
SEARCHES = os.path.join(HERE, "searches.txt")
API = "https://api.shodan.io"
# Cuántas páginas de 100 resultados pedir por búsqueda (cada página = 1 crédito).
SEARCH_MAX_PAGES = int(os.environ.get("SEARCH_MAX_PAGES", "2"))

OT_PORTS = {
    102: "S7 (Siemens S7comm)", 502: "Modbus", 789: "Red Lion Crimson",
    1911: "Tridium Fox", 2404: "IEC 60870-5-104", 4000: "Omron FINS",
    20000: "DNP3", 44818: "EtherNet/IP (CIP)", 47808: "BACnet",
    1962: "PCWorx", 9600: "Omron FINS", 20547: "ProConOS", 5094: "HART-IP",
    1883: "MQTT (IoT)", 5683: "CoAP (IoT)",
}
OT_HINTS = ("modbus", "s7", "dnp3", "bacnet", "ethernetip", "iec-104", "fox",
            "niagara", "pcworx", "fins", "proconos", "hart", "codesys", "crimson",
            "mqtt", "coap")


def is_ip(s):
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", s))


def resolve(target):
    target = target.strip().lower()
    if target.startswith("http"):
        target = urllib.parse.urlparse(target).netloc or target
    target = target.split("/")[0].split(":")[0]
    if is_ip(target):
        return target, None
    return socket.gethostbyname(target), target


def shodan_host(ip, key):
    url = f"{API}/shodan/host/{ip}?key={urllib.parse.quote(key)}"
    req = urllib.request.Request(url, headers={"User-Agent": "shodan-surface"})
    with urllib.request.urlopen(req, timeout=25) as r:
        return json.loads(r.read().decode("utf-8"))


def ot_match(port, module):
    if port in OT_PORTS:
        return OT_PORTS[port]
    m = (module or "").lower()
    for h in OT_HINTS:
        if h in m:
            return h.upper()
    return None


def normalize(host, label):
    services, ot = [], []
    for d in host.get("data", []):
        port = d.get("port")
        module = (d.get("_shodan", {}) or {}).get("module", "")
        banner = (d.get("data", "") or "").strip()
        v = d.get("vulns")
        svc_vulns = sorted(v.keys()) if isinstance(v, dict) else (v or [])
        services.append({
            "port": port, "transport": d.get("transport", "tcp"),
            "product": d.get("product") or module or "—", "version": d.get("version") or "",
            "module": module, "banner": banner[:600], "vulns": svc_vulns,
        })
        lbl = ot_match(port, module)
        if lbl:
            ot.append({"port": port, "label": lbl, "product": d.get("product") or module or "—"})
    services.sort(key=lambda s: (s["port"] is None, s["port"] or 0))
    vulns = host.get("vulns") or []
    if isinstance(vulns, dict):
        vulns = sorted(vulns.keys())
    return {
        "label": label, "ip": host.get("ip_str"),
        "org": host.get("org") or "—", "isp": host.get("isp") or "—",
        "asn": host.get("asn") or "—", "os": host.get("os") or "—",
        "country": host.get("country_name") or "—", "city": host.get("city") or "",
        "hostnames": host.get("hostnames") or [], "domains": host.get("domains") or [],
        "last_update": host.get("last_update") or "",
        "ports": sorted([p for p in (host.get("ports") or []) if p is not None]),
        "services": services, "vulns": sorted(vulns), "ot": ot,
    }


def _read_lines(path):
    if not os.path.exists(path):
        return []
    out = []
    with open(path, encoding="utf-8") as f:
        for ln in f:
            ln = ln.strip()
            if ln and not ln.startswith("#"):
                out.append(ln)
    return out


def read_targets():
    return _read_lines(TARGETS)


def read_searches():
    return _read_lines(SEARCHES)


def shodan_search(query, key, page):
    url = (f"{API}/shodan/host/search?key={urllib.parse.quote(key)}"
           f"&query={urllib.parse.quote(query)}&page={page}")
    req = urllib.request.Request(url, headers={"User-Agent": "shodan-surface"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read().decode("utf-8"))


def search_to_assets(query, key, max_pages):
    """Ejecuta una búsqueda de Shodan y agrupa los resultados por IP en activos."""
    hosts = {}
    for page in range(1, max_pages + 1):
        j = shodan_search(query, key, page)
        matches = j.get("matches", [])
        if not matches:
            break
        for m in matches:
            ip = m.get("ip_str")
            if not ip:
                continue
            loc = m.get("location", {}) or {}
            h = hosts.setdefault(ip, {
                "ip_str": ip, "org": m.get("org"), "isp": m.get("isp"), "asn": m.get("asn"),
                "country_name": loc.get("country_name"), "city": loc.get("city"),
                "hostnames": set(), "domains": set(), "ports": set(), "vulns": set(),
                "data": [], "last_update": "",
            })
            h["hostnames"].update(m.get("hostnames") or [])
            h["domains"].update(m.get("domains") or [])
            if m.get("port") is not None:
                h["ports"].add(m["port"])
            mv = m.get("vulns")
            if isinstance(mv, dict):
                h["vulns"].update(mv.keys())
            elif isinstance(mv, list):
                h["vulns"].update(mv)
            ts = m.get("timestamp", "") or ""
            if ts > h["last_update"]:
                h["last_update"] = ts
            h["data"].append({
                "port": m.get("port"), "transport": m.get("transport", "tcp"),
                "product": m.get("product"), "version": m.get("version"),
                "_shodan": m.get("_shodan", {}) or {}, "data": m.get("data", ""),
                "vulns": m.get("vulns"),
            })
        if len(matches) < 100:    # última página
            break

    assets = []
    for ip, h in hosts.items():
        h["hostnames"] = sorted(h["hostnames"])
        h["domains"] = sorted(h["domains"])
        h["ports"] = sorted(h["ports"])
        h["vulns"] = sorted(h["vulns"])
        label = h["hostnames"][0] if h["hostnames"] else ip
        assets.append(normalize(h, label))
    return assets


DEMO_HOSTS = [
    {
        "ip_str": "198.51.100.42", "org": "Demo Energy Utility S.A.", "isp": "Demo Telecom",
        "asn": "AS64500", "country_name": "Argentina", "city": "Rosario",
        "hostnames": ["scada-gw.demo-energy.example"], "domains": ["demo-energy.example"],
        "last_update": "2026-11-03T08:21:40", "ports": [22, 80, 443, 502, 3389],
        "vulns": ["CVE-2021-44228", "CVE-2019-0708", "CVE-2014-0160"],
        "data": [
            {"port": 22, "transport": "tcp", "product": "OpenSSH", "version": "7.4", "_shodan": {"module": "ssh"}, "data": "SSH-2.0-OpenSSH_7.4"},
            {"port": 80, "transport": "tcp", "product": "Apache httpd", "version": "2.4.29", "_shodan": {"module": "http"}, "data": "Server: Apache/2.4.29 (Ubuntu)"},
            {"port": 443, "transport": "tcp", "product": "Apache httpd", "version": "2.4.29", "_shodan": {"module": "https"}, "data": "CN=demo-energy.example"},
            {"port": 502, "transport": "tcp", "product": "Modbus", "version": "", "_shodan": {"module": "modbus"}, "data": "Vendor: Schneider Electric\nProduct code: BMX P34\nModbus/TCP expuesto sin autenticacion"},
            {"port": 3389, "transport": "tcp", "product": "Microsoft Terminal Services (RDP)", "version": "", "_shodan": {"module": "rdp"}, "data": "NLA: disabled"},
        ],
    },
    {
        "ip_str": "203.0.113.10", "org": "Demo Corp", "isp": "Demo Cloud", "asn": "AS64501",
        "country_name": "Argentina", "city": "Buenos Aires", "hostnames": ["www.demo-corp.example"],
        "domains": ["demo-corp.example"], "last_update": "2026-11-04T19:02:11", "ports": [80, 443],
        "vulns": [], "data": [
            {"port": 80, "transport": "tcp", "product": "nginx", "version": "1.24.0", "_shodan": {"module": "http"}, "data": "Server: nginx/1.24.0"},
            {"port": 443, "transport": "tcp", "product": "nginx", "version": "1.24.0", "_shodan": {"module": "https"}, "data": "TLS 1.3"},
        ],
    },
]


def build(assets, errors, demo):
    totals = {
        "assets": len(assets),
        "ports": sum(len(a["ports"]) for a in assets),
        "vulns": sum(len(a["vulns"]) for a in assets),
        "ot": sum(len(a["ot"]) for a in assets),
    }
    return {
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "demo": demo, "totals": totals, "errors": errors, "assets": assets,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--demo", action="store_true")
    args = ap.parse_args()

    key = os.environ.get("SHODAN_API_KEY", "").strip()
    assets, errors = [], []

    if args.demo or not key:
        for h in DEMO_HOSTS:
            assets.append(normalize(h, h["hostnames"][0] if h["hostnames"] else h["ip_str"]))
        data = build(assets, errors, demo=True)
        if not key and not args.demo:
            print("[i] Sin SHODAN_API_KEY: generando datos de ejemplo.", file=sys.stderr)
    else:
        seen = set()
        targets = read_targets()
        searches = read_searches()
        if not targets and not searches:
            print("[!] targets.txt y searches.txt están vacíos. Agregá tus activos.", file=sys.stderr)

        # 1) hosts exactos (dominio o IP)
        for t in targets:
            try:
                ip, host = resolve(t)
                if ip in seen:
                    continue
                raw = shodan_host(ip, key)
                assets.append(normalize(raw, host or ip))
                seen.add(ip)
                print(f"[+] {t} -> {ip}: {len(raw.get('ports', []))} puertos", file=sys.stderr)
            except socket.gaierror:
                errors.append({"target": t, "error": "no se pudo resolver"})
            except urllib.error.HTTPError as e:
                msg = {401: "API key inválida", 404: "sin información en Shodan", 429: "rate limit"}.get(e.code, f"HTTP {e.code}")
                errors.append({"target": t, "error": msg})
            except Exception as e:
                errors.append({"target": t, "error": str(e)})

        # 2) búsquedas (net:, asn:, org:…) — descubren varios hosts de una
        for q in searches:
            try:
                found = search_to_assets(q, key, SEARCH_MAX_PAGES)
                added = 0
                for a in found:
                    if a["ip"] in seen:
                        continue
                    seen.add(a["ip"])
                    assets.append(a)
                    added += 1
                print(f"[+] búsqueda '{q}': {added} hosts nuevos", file=sys.stderr)
            except urllib.error.HTTPError as e:
                msg = {401: "API key inválida", 429: "rate limit",
                       403: "tu plan no permite esta búsqueda"}.get(e.code, f"HTTP {e.code}")
                errors.append({"target": q, "error": msg})
            except Exception as e:
                errors.append({"target": q, "error": str(e)})

        data = build(assets, errors, demo=False)

    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    print(f"[ok] {OUT} — {len(assets)} activos, {len(errors)} errores")


if __name__ == "__main__":
    main()
