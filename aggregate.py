#!/usr/bin/env python3
"""
pool2 aggregator: fetch public subscription sources, parse share links,
keep US/JP/KR/TW only, TCP-liveness-test in the runner, write nodes.txt.

Pure stdlib. Runs inside GitHub Actions (see .github/workflows/update.yml).

Anti-wipe rule: if the final qualified node count is below MIN_NODES,
the existing nodes.txt is left untouched (only status.json is updated),
so a bad source day can never empty the pool.
"""

import base64
import concurrent.futures as cf
import ipaddress
import json
import os
import re
import socket
import sys
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
SOURCES_FILE = os.path.join(HERE, "sources.txt")
NODES_FILE = os.path.join(HERE, "nodes.txt")
STATUS_FILE = os.path.join(HERE, "status.json")

TARGET_COUNTRIES = ("US", "JP", "KR", "TW")
MAX_TOTAL = 400
COUNTRY_CAPS = {"US": 200, "JP": 100, "KR": 100, "TW": 100}
MIN_NODES = 30
TCP_TIMEOUT = 3.0
TCP_WORKERS = 120
MAX_TEST = 8000          # cap on liveness tests per run
GEO_MAX_IPS = 1000       # cap on ip-api lookups per run
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) pool2-aggregator/1.0"

LINK_RE = re.compile(
    r"(vless|vmess|trojan|ss|hysteria2|hy2|tuic)://[^\s'\"<>\]\)]+"
)

# ---------------------------------------------------------------- fetch ----

def fetch(url, timeout=25):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", errors="ignore")


def extract_links(text):
    """Extract share links from plain text and/or a base64 subscription body."""
    links = LINK_RE.findall(text)
    found = [m.group(0) for m in LINK_RE.finditer(text)]
    # try whole-body base64 (subscriptions are often one big base64 blob)
    compact = re.sub(r"\s+", "", text)
    if len(compact) > 40 and re.fullmatch(r"[A-Za-z0-9+/=_-]+", compact):
        try:
            pad = "=" * (-len(compact) % 4)
            decoded = base64.b64decode(compact + pad).decode("utf-8", "ignore")
            found += [m.group(0) for m in LINK_RE.finditer(decoded)]
        except Exception:
            pass
    return found

# --------------------------------------------------------------- parsing ----

def b64_decode_loose(s):
    s = re.sub(r"\s+", "", s)
    s = s.replace("-", "+").replace("_", "/")
    pad = "=" * (-len(s) % 4)
    return base64.b64decode(s + pad).decode("utf-8", "ignore")


def parse_link(raw):
    """Return dict(proto, host, port, ident, name, raw) or None."""
    raw = raw.strip()
    try:
        if raw.startswith("vmess://"):
            data = json.loads(b64_decode_loose(raw[8:]))
            host = str(data.get("add", "")).strip()
            port = int(data.get("port", 0) or 0)
            if not host or not port:
                return None
            return {"proto": "vmess", "host": host, "port": port,
                    "ident": str(data.get("id", "")), 
                    "name": str(data.get("ps", "")), "raw": raw}
        proto, rest = raw.split("://", 1)
        proto = proto.lower()
        if proto == "hy2":
            proto = "hysteria2"
        name = ""
        if "#" in rest:
            rest, frag = rest.split("#", 1)
            name = urllib.parse.unquote(frag)
        rest = rest.split("?", 1)[0].split("/", 1)[0]
        if proto == "ss":
            return parse_ss(rest, name, raw)
        if "@" not in rest:
            return None
        userinfo, hostport = rest.rsplit("@", 1)
        host, port = split_hostport(hostport)
        if not host or not port:
            return None
        return {"proto": proto, "host": host, "port": port,
                "ident": urllib.parse.unquote(userinfo),
                "name": name, "raw": raw}
    except Exception:
        return None


def split_hostport(hostport):
    hostport = hostport.strip().strip("[]") if not hostport.startswith("[") else hostport
    if hostport.startswith("["):  # IPv6
        end = hostport.find("]")
        host = hostport[1:end]
        tail = hostport[end + 1:]
        port = int(tail[1:]) if tail.startswith(":") else 0
        return host, port
    if ":" not in hostport:
        return hostport, 0
    host, port_s = hostport.rsplit(":", 1)
    try:
        return host, int(port_s)
    except ValueError:
        return host, 0


def parse_ss(rest, name, raw):
    # SIP002: ss://base64(method:password)@host:port  |  plain method:pass@host:port
    # legacy: ss://base64(method:password@host:port)
    if "@" in rest:
        userinfo, hostport = rest.rsplit("@", 1)
        if ":" not in userinfo:  # base64 userinfo
            try:
                userinfo = b64_decode_loose(userinfo)
            except Exception:
                return None
        host, port = split_hostport(hostport)
        ident = userinfo
    else:
        try:
            decoded = b64_decode_loose(rest)
        except Exception:
            return None
        if "@" not in decoded:
            return None
        ident, hostport = decoded.rsplit("@", 1)
        host, port = split_hostport(hostport)
    if not host or not port:
        return None
    return {"proto": "ss", "host": host, "port": port,
            "ident": ident, "name": name, "raw": raw}

# -------------------------------------------------------------- classify ----

FLAG_MAP = {
    "🇺🇸": "US", "🇯🇵": "JP", "🇰🇷": "KR", "🇹🇼": "TW",
}
OTHER_FLAGS = ["🇭🇰", "🇸🇬", "🇬🇧", "🇩🇪", "🇫🇷", "🇨🇳", "🇦🇺", "🇨🇦",
               "🇮🇳", "🇷🇺", "🇳🇱", "🇹🇷", "🇻🇳", "🇹🇭", "🇲🇾", "🇮🇩",
               "🇵🇭", "🇦🇪", "🇧🇷", "🇮🇹", "🇪🇸", "🇸🇪", "🇨🇭", "🇵🇱"]

KEYWORDS = {
    "US": ["美国", "美國", "美利坚", "united states", "america", "usa",
           "los angeles", "new york", "san jose", "san francisco", "seattle",
           "dallas", "chicago", "ashburn", "silicon valley", "phoenix",
           "miami", "atlanta", "denver", "las vegas", "portland",
           "洛杉矶", "洛杉磯", "纽约", "紐約", "西雅图", "西雅圖", "达拉斯",
           "達拉斯", "芝加哥", "圣何塞", "聖何塞", "硅谷", "凤凰城", "鳳凰城",
           "迈阿密", "邁阿密",
           "lax", "sjc", "sfo", "sea", "dfw", "ord", "jfk", "ewr", "iad",
           "atl", "mia", "phx", "den", "pdx"],
    "JP": ["日本", "japan", "tokyo", "osaka", "nagoya",
           "东京", "東京", "大阪", "名古屋", "福冈", "福岡",
           "nrt", "hnd", "kix", "fuk"],
    "KR": ["韩国", "韓國", "korea", "seoul", "首尔", "首爾", "釜山", "busan",
           "icn", "gmp"],
    "TW": ["台湾", "臺灣", "台灣", "taiwan", "taipei", "taichung",
           "kaohsiung", "台北", "臺北", "新北", "台中", "臺中", "高雄",
           "桃园", "桃園", "tpe", "tsa", "khh"],
}
CODE_RE = {c: re.compile(r"(?<![A-Za-z])" + c + r"(?![A-Za-z])")
           for c in TARGET_COUNTRIES}


def classify_by_name(name):
    if not name:
        return None
    for flag, cc in FLAG_MAP.items():
        if flag in name:
            return cc
    for flag in OTHER_FLAGS:
        if flag in name:
            return "OTHER"
    low = name.lower()
    upper = name.upper()
    hits = []
    for cc, words in KEYWORDS.items():
        if any(w in low for w in words):
            hits.append(cc)
    for cc, rx in CODE_RE.items():
        if rx.search(upper):
            hits.append(cc)
    hits = list(dict.fromkeys(hits))
    if len(hits) == 1:
        return hits[0]
    if len(hits) > 1:
        # ambiguous (e.g. transit names) - first target in priority order
        for cc in TARGET_COUNTRIES:
            if cc in hits:
                return cc
    return None

# ------------------------------------------------------------------ geo ----

def resolve_ip(host):
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_INET,
                                   socket.SOCK_STREAM)
        return infos[0][4][0]
    except Exception:
        return None


def geo_lookup(ips):
    """Batch query ip-api.com. Returns {ip: countryCode}."""
    result = {}
    ips = list(ips)[:GEO_MAX_IPS]
    for i in range(0, len(ips), 100):
        batch = ips[i:i + 100]
        payload = json.dumps(
            [{"query": ip, "fields": "query,countryCode,status"}
             for ip in batch]).encode()
        req = urllib.request.Request(
            "http://ip-api.com/batch", data=payload,
            headers={"Content-Type": "application/json", "User-Agent": UA})
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                for item in json.loads(resp.read().decode("utf-8", "ignore")):
                    if item.get("status") == "success":
                        result[item["query"]] = item.get("countryCode", "")
        except Exception as exc:
            print(f"[geo] batch failed: {exc}", file=sys.stderr)
        time.sleep(0.3)
    return result

# ------------------------------------------------------------- liveness ----

def tcp_alive(node):
    try:
        with socket.create_connection((node["host"], node["port"]),
                                      timeout=TCP_TIMEOUT):
            return True
    except Exception:
        return False

# ----------------------------------------------------------------- main ----

def main():
    status = {
        "updated_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "sources_total": 0, "sources_ok": 0, "sources_failed": [],
        "links_raw": 0, "links_deduped": 0,
        "classified_by_name": {}, "classified_by_geo": {},
        "candidates_target": 0, "tested": 0,
        "alive": {}, "final": {}, "nodes_txt_updated": False, "note": "",
    }

    with open(SOURCES_FILE, encoding="utf-8") as fh:
        sources = [ln.strip() for ln in fh
                   if ln.strip() and not ln.strip().startswith("#")]
    status["sources_total"] = len(sources)

    raw_links = []
    for url in sources:
        try:
            body = fetch(url)
            got = extract_links(body)
            raw_links += got
            status["sources_ok"] += 1
            print(f"[src] ok   {url} -> {len(got)} links")
        except Exception as exc:
            status["sources_failed"].append(url)
            print(f"[src] FAIL {url}: {exc}", file=sys.stderr)
    status["links_raw"] = len(raw_links)

    nodes, seen = [], set()
    for raw in raw_links:
        node = parse_link(raw)
        if not node:
            continue
        key = (node["proto"], node["host"].lower(), node["port"], node["ident"])
        if key in seen:
            continue
        seen.add(key)
        nodes.append(node)
    status["links_deduped"] = len(nodes)
    print(f"[parse] deduped nodes: {len(nodes)}")

    by_name = {c: 0 for c in TARGET_COUNTRIES}
    candidates, unknown = [], []
    for node in nodes:
        cc = classify_by_name(node["name"])
        if cc in TARGET_COUNTRIES:
            node["cc"] = cc
            candidates.append(node)
            by_name[cc] += 1
        elif cc is None:
            unknown.append(node)
    status["classified_by_name"] = by_name
    print(f"[name] target candidates: {len(candidates)}; unknown: {len(unknown)}")

    # geo fallback for unnamed nodes
    if unknown:
        host_ip = {}
        with cf.ThreadPoolExecutor(max_workers=60) as ex:
            futs = {ex.submit(resolve_ip, n["host"]): n for n in unknown}
            for fut in cf.as_completed(futs):
                ip = fut.result()
                if ip:
                    futs[fut]["ip"] = ip
                    host_ip[futs[fut]["host"]] = ip
        geo = geo_lookup({n.get("ip") for n in unknown if n.get("ip")})
        by_geo = {c: 0 for c in TARGET_COUNTRIES}
        for node in unknown:
            cc = geo.get(node.get("ip", ""), "")
            if cc in TARGET_COUNTRIES:
                node["cc"] = cc
                candidates.append(node)
                by_geo[cc] += 1
        status["classified_by_geo"] = by_geo
        print(f"[geo] rescued by geo: {sum(by_geo.values())}")

    status["candidates_target"] = len(candidates)

    # liveness: US first, then JP/KR/TW, so the test cap favours US
    priority = {"US": 0, "JP": 1, "KR": 2, "TW": 3}
    candidates.sort(key=lambda n: priority[n["cc"]])
    to_test = candidates[:MAX_TEST]
    status["tested"] = len(to_test)
    alive = []
    with cf.ThreadPoolExecutor(max_workers=TCP_WORKERS) as ex:
        results = list(ex.map(tcp_alive, to_test))
    for node, ok in zip(to_test, results):
        if ok:
            alive.append(node)
    alive_by_cc = {c: [n for n in alive if n["cc"] == c]
                   for c in TARGET_COUNTRIES}
    status["alive"] = {c: len(v) for c, v in alive_by_cc.items()}
    print(f"[tcp] alive: {status['alive']}")

    # selection: per-country caps, US first, then backfill to MAX_TOTAL
    final = []
    for cc in TARGET_COUNTRIES:
        final += alive_by_cc[cc][:COUNTRY_CAPS[cc]]
    if len(final) < MAX_TOTAL:
        used = {id(n) for n in final}
        for cc in TARGET_COUNTRIES:
            for node in alive_by_cc[cc]:
                if len(final) >= MAX_TOTAL:
                    break
                if id(node) not in used:
                    final.append(node)
                    used.add(id(node))
    final_by_cc = {c: sum(1 for n in final if n["cc"] == c)
                   for c in TARGET_COUNTRIES}
    status["final"] = {**final_by_cc, "total": len(final)}
    print(f"[final] {status['final']}")

    # anti-wipe write
    if len(final) >= MIN_NODES:
        with open(NODES_FILE, "w", encoding="utf-8") as fh:
            fh.write("\n".join(n["raw"] for n in final) + "\n")
        status["nodes_txt_updated"] = True
        status["note"] = "nodes.txt updated"
    elif not os.path.exists(NODES_FILE) and final:
        with open(NODES_FILE, "w", encoding="utf-8") as fh:
            fh.write("\n".join(n["raw"] for n in final) + "\n")
        status["nodes_txt_updated"] = True
        status["note"] = "first run seed (below MIN_NODES but no previous file)"
    else:
        status["note"] = (f"kept previous nodes.txt: only {len(final)} "
                          f"qualified nodes (< {MIN_NODES})")

    with open(STATUS_FILE, "w", encoding="utf-8") as fh:
        json.dump(status, fh, ensure_ascii=False, indent=2)
    print(json.dumps(status, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
