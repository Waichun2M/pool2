#!/usr/bin/env python3
"""
pool2 aggregator: fetch public subscription sources, parse share links,
keep US/JP/KR/TW only, liveness-test in the runner, write nodes.txt.

Two-stage liveness: a cheap TCP connect screen, then a real-proxy test
that runs the survivors through sing-box and only keeps nodes that
actually carry traffic (a listening port alone proves nothing). Nodes
that proxy must also prove their real exit country (Cloudflare trace
through the tunnel): name/geo labels lie, so the observed exit country
is the only classification that counts.

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
import shutil
import socket
import subprocess
import sys
import tarfile
import tempfile
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

# --- real-proxy test (sing-box) ---
SING_BOX_VERSION = "1.11.15"
SING_BOX_URL = (
    "https://github.com/SagerNet/sing-box/releases/download/"
    f"v{SING_BOX_VERSION}/sing-box-{SING_BOX_VERSION}-linux-amd64.tar.gz"
)
REAL_MAX_TEST = 1200      # real-test at most this many TCP-alive nodes
REAL_BATCH = 80           # nodes per sing-box instance
REAL_BASE_PORT = 20000    # first mixed-inbound port of each batch
REAL_TIMEOUT = 6          # curl timeout (s) per node probe
REAL_WORKERS = 40         # concurrent curl probes
REAL_TEST_URL = "http://www.gstatic.com/generate_204"
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
    """Return dict(proto, host, port, ident, name, raw, query, vmess)
    or None."""
    node = _parse_link_basic(raw)
    if node is not None:
        _attach_params(node)
    return node


def _attach_params(node):
    """Attach structured URI/JSON parameters to a parsed node so the
    sing-box outbound builder can map tls/reality/transport faithfully.
    Never fatal: on error the node keeps empty params (and simply fails
    the real-proxy test if it actually needed them)."""
    node["query"] = {}
    node["vmess"] = {}
    raw = node.get("raw", "")
    try:
        if node["proto"] == "vmess":
            node["vmess"] = json.loads(
                b64_decode_loose(raw[len("vmess://"):].split("#", 1)[0]))
            return
        parts = urllib.parse.urlsplit(raw)
        qs = urllib.parse.parse_qs(parts.query, keep_blank_values=True)
        node["query"] = {k: v[0] for k, v in qs.items() if v}
    except Exception:
        pass


def _parse_link_basic(raw):
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

# ------------------------------------------------------- real proxy test ----
#
# A listening TCP port does not mean the node can proxy: the protocol
# handshake may fail, the credentials may be dead, or the server may
# accept and drop everything. So survivors of the TCP screen are run
# through a real sing-box instance and must fetch REAL_TEST_URL.

def _split_csv(v):
    return [x.strip() for x in str(v or "").split(",") if x.strip()]


def _boolish(v):
    return str(v).strip().lower() in ("1", "true", "yes")


def _transport_from(net, host="", path="", service_name=""):
    """Map a share-link transport to a sing-box transport block.
    Returns a dict, None for plain tcp, or "UNSUPPORTED"."""
    net = (net or "").lower()
    if net in ("", "tcp", "none", "raw"):
        return None
    if net == "ws":
        t = {"type": "ws", "path": path or "/"}
        if host:
            t["headers"] = {"Host": host}
        return t
    if net == "grpc":
        return {"type": "grpc", "service_name": service_name or path or ""}
    if net in ("http", "h2"):
        t = {"type": "http", "path": path or "/"}
        if host:
            t["host"] = _split_csv(host)
        return t
    if net == "httpupgrade":
        t = {"type": "httpupgrade", "path": path or "/"}
        if host:
            t["host"] = host
        return t
    return "UNSUPPORTED"


def _tls_block(server_name="", insecure=False, alpn=None, fingerprint="",
               reality_pbk=None, reality_sid=""):
    tls = {"enabled": True}
    if server_name:
        tls["server_name"] = server_name
    if insecure:
        tls["insecure"] = True
    if alpn:
        tls["alpn"] = alpn
    if fingerprint:
        tls["utls"] = {"enabled": True, "fingerprint": fingerprint}
    if reality_pbk is not None:
        tls["reality"] = {"enabled": True, "public_key": reality_pbk,
                          "short_id": reality_sid or ""}
    return tls


def build_outbound(node, tag):
    """Map a parsed share-link node to a sing-box outbound dict, keeping
    tls/reality/transport parameters as faithful as the link allows.
    Returns None when parameters cannot be mapped; such a node simply
    fails the real-proxy test instead of being guessed at."""
    proto = node["proto"]
    q = node.get("query") or {}
    ob = {"tag": tag, "server": node["host"], "server_port": node["port"]}
    try:
        if proto == "vless":
            ob["type"] = "vless"
            ob["uuid"] = node["ident"]
            if q.get("flow"):
                ob["flow"] = q["flow"]
            security = q.get("security", "").lower()
            if security in ("tls", "reality"):
                pbk = q.get("pbk", "") if security == "reality" else None
                if security == "reality" and not pbk:
                    return None
                ob["tls"] = _tls_block(
                    server_name=q.get("sni") or q.get("host", ""),
                    insecure=_boolish(q.get("allowInsecure", "")),
                    alpn=_split_csv(q.get("alpn", "")),
                    fingerprint=q.get("fp") or q.get("fingerprint", ""),
                    reality_pbk=pbk, reality_sid=q.get("sid", ""))
            elif security not in ("", "none"):
                return None
            tr = _transport_from(q.get("type", ""), q.get("host", ""),
                                 q.get("path", ""),
                                 q.get("serviceName", ""))
            if tr == "UNSUPPORTED":
                return None
            if tr:
                ob["transport"] = tr
        elif proto == "trojan":
            ob["type"] = "trojan"
            ob["password"] = node["ident"]
            if q.get("security", "tls").lower() != "none":
                ob["tls"] = _tls_block(
                    server_name=(q.get("sni") or q.get("peer")
                                 or q.get("host", "")),
                    insecure=_boolish(q.get("allowInsecure", "")),
                    alpn=_split_csv(q.get("alpn", "")),
                    fingerprint=q.get("fp", ""))
            tr = _transport_from(q.get("type", ""), q.get("host", ""),
                                 q.get("path", ""),
                                 q.get("serviceName", ""))
            if tr == "UNSUPPORTED":
                return None
            if tr:
                ob["transport"] = tr
        elif proto == "vmess":
            d = node.get("vmess") or {}
            ob["type"] = "vmess"
            ob["uuid"] = str(d.get("id", ""))
            if not ob["uuid"]:
                return None
            try:
                ob["alter_id"] = int(d.get("aid", 0) or 0)
            except (TypeError, ValueError):
                return None
            scy = str(d.get("scy", "auto") or "auto").lower()
            if scy not in ("auto", "aes-128-gcm", "chacha20-poly1305",
                          "none", "zero"):
                return None
            ob["security"] = scy
            if str(d.get("tls", "")).lower() == "tls":
                ob["tls"] = _tls_block(
                    server_name=str(d.get("sni", "") or d.get("host", "")),
                    alpn=_split_csv(d.get("alpn", "")))
            net = str(d.get("net", "tcp") or "tcp")
            if net == "tcp" and str(d.get("type", "")).lower() \
                    not in ("", "none"):
                return None  # tcp http-camouflage header: not mapped
            tr = _transport_from(net, str(d.get("host", "")),
                                 str(d.get("path", "")),
                                 str(d.get("path", "")))
            if tr == "UNSUPPORTED":
                return None
            if tr:
                ob["transport"] = tr
        elif proto == "ss":
            if ":" not in node["ident"]:
                return None
            method, password = node["ident"].split(":", 1)
            ob["type"] = "shadowsocks"
            ob["method"] = method
            ob["password"] = password
            plugin = q.get("plugin", "")
            if plugin:
                parts = plugin.split(";")
                ob["plugin"] = parts[0]
                if len(parts) > 1:
                    ob["plugin_opts"] = ";".join(parts[1:])
        elif proto == "hysteria2":
            ob["type"] = "hysteria2"
            ob["password"] = node["ident"]
            ob["tls"] = _tls_block(
                server_name=q.get("sni") or q.get("peer", ""),
                insecure=_boolish(q.get("insecure", "")),
                alpn=_split_csv(q.get("alpn", "")))
            if q.get("obfs"):
                ob["obfs"] = {"type": q["obfs"],
                              "password": q.get("obfs-password", "")}
        else:
            return None
    except Exception:
        return None
    return ob


def download_sing_box(workdir):
    """Download the pinned sing-box release. Returns binary path or
    None (caller falls back to TCP-only results; never fatal)."""
    tarball = os.path.join(workdir, "sing-box.tar.gz")
    try:
        req = urllib.request.Request(SING_BOX_URL,
                                     headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=180) as resp, \
                open(tarball, "wb") as fh:
            shutil.copyfileobj(resp, fh)
        binary = os.path.join(workdir, "sing-box")
        with tarfile.open(tarball, "r:gz") as tf:
            member = next(m for m in tf.getmembers()
                          if m.name.endswith("/sing-box") and m.isfile())
            with tf.extractfile(member) as src, \
                    open(binary, "wb") as fh:
                shutil.copyfileobj(src, fh)
        os.chmod(binary, 0o755)
        return binary
    except Exception as exc:
        print(f"[real] sing-box download failed: {exc}", file=sys.stderr)
        return None


def _batch_config(items):
    """items: list of (node, outbound, port) -> one sing-box config with
    a dedicated mixed inbound per node, routed 1:1 to its outbound."""
    inbounds, outbounds, rules = [], [], []
    for i, (_node, ob, port) in enumerate(items):
        inbounds.append({"type": "mixed", "tag": f"in{i}",
                         "listen": "127.0.0.1", "listen_port": port})
        outbounds.append(ob)
        rules.append({"inbound": [f"in{i}"], "outbound": ob["tag"]})
    outbounds += [{"type": "direct", "tag": "direct"},
                  {"type": "block", "tag": "block"}]
    return {"log": {"level": "error"},
            "inbounds": inbounds, "outbounds": outbounds,
            "route": {"rules": rules, "final": "block"}}


def _write_config(workdir, name, config):
    path = os.path.join(workdir, name)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(config, fh)
    return path


def _check_ok(binary, workdir, name, config):
    path = _write_config(workdir, name, config)
    try:
        r = subprocess.run([binary, "check", "-c", path],
                           capture_output=True, text=True, timeout=60)
        return r.returncode == 0
    except Exception:
        return False


def _filter_valid(binary, workdir, items):
    """Drop items whose outbound sing-box rejects. Whole-batch check
    first; if it fails, per-node checks isolate the bad ones."""
    if not items:
        return items
    if _check_ok(binary, workdir, "check-batch.json", _batch_config(items)):
        return items
    valid = []
    for item in items:
        single = {"log": {"level": "error"},
                  "outbounds": [item[1], {"type": "direct", "tag": "direct"}]}
        if _check_ok(binary, workdir, "check-one.json", single):
            valid.append(item)
    return valid


def _probe(port):
    try:
        r = subprocess.run(
            ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
             "--max-time", str(REAL_TIMEOUT),
             "-x", f"socks5h://127.0.0.1:{port}", REAL_TEST_URL],
            capture_output=True, text=True, timeout=REAL_TIMEOUT + 10)
        return r.stdout.strip() in ("200", "204")
    except Exception:
        return False


# --- exit-country verification -------------------------------------------
#
# A node's advertised country (name flag / server IP geo) is unreliable:
# sources mislabel, and anycast/transit exits land elsewhere. The only
# trustworthy signal is the country the traffic actually exits from,
# observed through the tunnel itself via Cloudflare's trace endpoint.

TRACE_URL = "http://www.cloudflare.com/cdn-cgi/trace"
TRACE_TIMEOUT = 6         # curl timeout (s) for the trace probe
_LOC_RE = re.compile(r"^loc=([A-Za-z]{2})\s*$", re.M)


def parse_trace_loc(text):
    """Extract the exit country code from a /cdn-cgi/trace body.
    Returns an upper-case 2-letter code or None."""
    if not text:
        return None
    m = _LOC_RE.search(text)
    return m.group(1).upper() if m else None


def exit_verdict(loc):
    """Final country for a node given its observed exit loc, or None
    when the node must be dropped: unverifiable exits and exits outside
    the target whitelist are both rejected (better fewer, real nodes)."""
    if not loc:
        return None
    loc = str(loc).strip().upper()
    return loc if loc in TARGET_COUNTRIES else None


def _probe_exit_loc(port):
    """Fetch the trace endpoint through the node's own SOCKS inbound
    and return the observed exit country (or None on any failure)."""
    try:
        r = subprocess.run(
            ["curl", "-s", "--max-time", str(TRACE_TIMEOUT),
             "-x", f"socks5h://127.0.0.1:{port}", TRACE_URL],
            capture_output=True, text=True, timeout=TRACE_TIMEOUT + 10)
        if r.returncode != 0:
            return None
        return parse_trace_loc(r.stdout)
    except Exception:
        return None


def apply_exit_results(ok_items, locs):
    """Apply exit-country verdicts to the nodes of one batch that
    passed the traffic probe. Returns (passed, stats): passed maps
    id(node) -> verified exit country; stats counts how many
    traffic-passing nodes were dropped over their exit (mismatch =
    observed loc outside the whitelist, unverified = no loc at all)
    and tallies every observed exit country in by_exit."""
    passed = {}
    stats = {"passed_204": len(ok_items), "mismatch": 0,
             "unverified": 0, "by_exit": {}}
    for (node, _ob, _port), loc in zip(ok_items, locs):
        if loc:
            stats["by_exit"][loc] = stats["by_exit"].get(loc, 0) + 1
        verdict = exit_verdict(loc)
        if verdict is None:
            if loc:
                stats["mismatch"] += 1
            else:
                stats["unverified"] += 1
            continue
        passed[id(node)] = verdict
    return passed, stats


def _wait_ports(proc, ports, deadline_s=25):
    deadline = time.time() + deadline_s
    pending = set(ports)
    while pending and time.time() < deadline:
        if proc.poll() is not None:
            return False
        for p in list(pending):
            try:
                with socket.create_connection(("127.0.0.1", p), timeout=0.3):
                    pending.discard(p)
            except Exception:
                pass
        if pending:
            time.sleep(0.2)
    return not pending


def _run_batch(binary, workdir, items):
    """Start one sing-box for the batch and probe every node through
    its own inbound port: first the traffic probe (generate_204), then
    for the passers an exit-country probe (Cloudflare trace through the
    same tunnel). Returns (passed, stats) where passed maps id(node) ->
    verified exit country; nodes whose real exit is outside the
    whitelist, or whose exit cannot be verified, are dropped."""
    empty = {"passed_204": 0, "mismatch": 0, "unverified": 0, "by_exit": {}}
    cfg_path = _write_config(workdir, "run-batch.json", _batch_config(items))
    log_path = os.path.join(workdir, "sing-box.log")
    with open(log_path, "ab") as log_fh:
        proc = subprocess.Popen([binary, "run", "-c", cfg_path],
                                stdout=log_fh, stderr=log_fh)
    try:
        ports = [port for (_n, _o, port) in items]
        if not _wait_ports(proc, ports):
            print(f"[real] batch sing-box not ready (rc={proc.poll()})",
                  file=sys.stderr)
            return {}, empty
        with cf.ThreadPoolExecutor(max_workers=REAL_WORKERS) as ex:
            results = list(ex.map(_probe, ports))
        ok_items = [item for item, ok in zip(items, results) if ok]
        if not ok_items:
            return {}, empty
        with cf.ThreadPoolExecutor(max_workers=REAL_WORKERS) as ex:
            locs = list(ex.map(_probe_exit_loc,
                               [port for (_n, _o, port) in ok_items]))
        return apply_exit_results(ok_items, locs)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except Exception:
            proc.kill()


def real_test(nodes, workdir):
    """Real-proxy test of TCP-alive nodes (already in priority order).
    A node passes only if it carries traffic AND its observed exit
    country (Cloudflare trace through the tunnel) is in the target
    whitelist; the verified exit then overwrites node["cc"], so every
    downstream count and cap uses the real exit, never the label.
    Returns (passed_nodes, info), or None when the sing-box download
    failed and the caller must fall back to the TCP results."""
    binary = download_sing_box(workdir)
    if not binary:
        return None
    passed, tested = [], 0
    agg_stats = {"passed_204": 0, "mismatch": 0, "unverified": 0,
                 "by_exit": {}}
    for start in range(0, len(nodes), REAL_BATCH):
        chunk = nodes[start:start + REAL_BATCH]
        tested += len(chunk)
        items = []
        for i, node in enumerate(chunk):
            ob = build_outbound(node, f"out{i}")
            if ob is not None:
                items.append((node, ob, REAL_BASE_PORT + i))
        items = _filter_valid(binary, workdir, items)
        if not items:
            continue
        verdicts, bstats = _run_batch(binary, workdir, items)
        for key in ("passed_204", "mismatch", "unverified"):
            agg_stats[key] += bstats[key]
        for loc, cnt in bstats["by_exit"].items():
            agg_stats["by_exit"][loc] = \
                agg_stats["by_exit"].get(loc, 0) + cnt
        for (node, _o, _p) in items:
            loc = verdicts.get(id(node))
            if loc:
                node["cc"] = loc  # real exit overrides name/geo label
                passed.append(node)
        print(f"[real] batch @{start}: {len(verdicts)}/{len(items)} alive "
              f"(traffic-ok {bstats['passed_204']}, "
              f"exit-dropped {bstats['mismatch'] + bstats['unverified']})")
    info = {"tested": tested,
            "passed_204": agg_stats["passed_204"],
            "exit_mismatch_dropped": agg_stats["mismatch"],
            "exit_unverified_dropped": agg_stats["unverified"],
            "by_exit": agg_stats["by_exit"]}
    return passed, info

# ----------------------------------------------------------------- main ----

FLAG_EMOJI = {"US": "🇺🇸", "JP": "🇯🇵", "KR": "🇰🇷", "TW": "🇹🇼"}


def _rename_link(raw, label):
    """Rewrite a share link's display name (fragment / vmess ps) to a
    safe label. Aggregator names carry YAML-breaking characters
    (unclosed '[', ':', '|', '#', stray emoji) that crash subscription
    converters (edgetunnel /sub returned HTTP 400 for Clash clients);
    the name is cosmetic, so replace it wholesale."""
    try:
        if raw.startswith("vmess://"):
            payload = raw[len("vmess://"):].split("#")[0]
            data = json.loads(base64.b64decode(
                payload + "=" * (-len(payload) % 4)).decode("utf-8"))
            data["ps"] = label
            return "vmess://" + base64.b64encode(json.dumps(
                data, ensure_ascii=False).encode("utf-8")).decode()
        base = raw.split("#", 1)[0]
        return base + "#" + urllib.parse.quote(label, safe="")
    except Exception:
        return raw


def main():
    status = {
        "updated_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "sources_total": 0, "sources_ok": 0, "sources_failed": [],
        "links_raw": 0, "links_deduped": 0,
        "classified_by_name": {}, "classified_by_geo": {},
        "candidates_target": 0, "tested": 0,
        "alive": {}, "final": {}, "nodes_txt_updated": False, "note": "",
        "real_test": "not_run", "real_tested": 0, "real_alive": {},
        "real_tested_by_exit": {}, "exit_mismatch_dropped": 0,
        "exit_unverified_dropped": 0,
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
    tcp_by_cc = {c: [n for n in alive if n["cc"] == c]
                 for c in TARGET_COUNTRIES}
    status["alive"] = {c: len(v) for c, v in tcp_by_cc.items()}
    print(f"[tcp] alive: {status['alive']}")

    # real-proxy test: only nodes that actually carry traffic survive.
    # Any failure here degrades to the TCP results, never to a crash.
    if alive:
        status["real_test"] = "ok"
        workdir = tempfile.mkdtemp(prefix="pool2-sb-")
        try:
            outcome = real_test(alive[:REAL_MAX_TEST], workdir)
        except Exception as exc:
            print(f"[real] test crashed, TCP fallback: {exc}",
                  file=sys.stderr)
            outcome = "error"
        finally:
            shutil.rmtree(workdir, ignore_errors=True)
        if outcome is None:
            status["real_test"] = "skipped_download_failed"
        elif outcome == "error":
            status["real_test"] = "skipped_error"
        else:
            alive, info = outcome
            status["real_tested"] = info["tested"]
            status["real_tested_by_exit"] = info.get("by_exit", {})
            status["exit_mismatch_dropped"] = \
                info.get("exit_mismatch_dropped", 0)
            status["exit_unverified_dropped"] = \
                info.get("exit_unverified_dropped", 0)
            # node["cc"] was overwritten with the verified exit country
            # during the real test, so this counts exits, not labels.
            ra = {c: 0 for c in TARGET_COUNTRIES}
            for n in alive:
                ra[n["cc"]] += 1
            status["real_alive"] = ra
        print(f"[real] status={status['real_test']} "
              f"tested={status['real_tested']} alive={status['real_alive']}")

    alive_by_cc = {c: [n for n in alive if n["cc"] == c]
                   for c in TARGET_COUNTRIES}

    # protocol priority: from CN networks bare ss/vmess get blocked far
    # more often than vless-reality / hysteria2; front-load the protocols
    # that survive so client auto-select groups land on a working node
    # instead of drowning in dead ss (30 of 51 in the 2026-10-23 batch).
    def _proto_rank(n):
        raw = n["raw"]
        if raw.startswith("vless://"):
            return 0 if "security=reality" in raw else 1
        if raw.startswith(("hysteria2://", "hy2://")):
            return 2
        if raw.startswith("trojan://"):
            return 3
        if raw.startswith("vmess://"):
            return 4
        return 5

    for _cc in TARGET_COUNTRIES:
        alive_by_cc[_cc].sort(key=_proto_rank)

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

    # sanitize display names before writing (see _rename_link)
    _counters = {}
    for n in final:
        proto = n["raw"].split("://", 1)[0].lower()
        _counters[n["cc"]] = _counters.get(n["cc"], 0) + 1
        label = (f'{FLAG_EMOJI.get(n["cc"], "")} {n["cc"]} '
                 f'{proto} {_counters[n["cc"]]:02d}').strip()
        n["raw"] = _rename_link(n["raw"], label)

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
