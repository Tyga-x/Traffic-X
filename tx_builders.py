# tx_builders.py — builders for VLESS / VMess / Trojan / Shadowsocks
# Ports the effective parts of the Node sample you shared into your DB-based project
# Supports: tcp / ws / http / xhttp / grpc / kcp / quic
# TLS fields: sni / alpn / fingerprint(fp) / allowInsecure
# REALITY fields: pbk (publicKey), sid (shortId), spx (spiderX) / fingerprint
# Also honors wsHeaders.Host, http/xhttp host, tcp-http host, and externalProxy[0].dest if present
import os, json, base64, io
from typing import Any, Dict, Optional, Tuple
from urllib.parse import quote, urlencode
try:
    import qrcode
except Exception:
    qrcode = None

FALLBACK_DOMAIN = os.getenv("DOMAIN", "localhost")


# ----------------------------- helpers -----------------------------
def _jload(x: Any) -> Dict[str, Any]:
    if not x:
        return {}
    if isinstance(x, dict):
        return x
    try:
        return json.loads(x)
    except Exception:
        try:
            return json.loads(str(x).replace("'", '"'))
        except Exception:
            return {}

def _norm(v):
    if isinstance(v, bool): return "1" if v else "0"
    if v is None: return ""
    return str(v)

def _arr_first(x):
    if isinstance(x, list) and x:
        return x[0]
    return x

def _qr_data_uri(text: str) -> Optional[str]:
    if not (qrcode and text): return None
    qr = qrcode.QRCode(border=1); qr.add_data(text); qr.make(fit=True)
    img = qr.make_image(); buf = io.BytesIO(); img.save(buf, format="PNG")
    return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()

def _get_network(stream: Dict[str, Any]) -> str:
    return (stream.get("network") or "tcp").lower()

def _get_security(stream: Dict[str, Any]) -> str:
    sec = (stream.get("security") or "").lower()
    if sec in ("tls","reality","xtls","none"):
        return sec
    # xray uses "" for none:
    return "none"

def _tls_settings(stream: Dict[str, Any]) -> Dict[str, Any]:
    # Some panels put allowInsecure under tlsSettings.settings.allowInsecure
    tls = stream.get("tlsSettings") or {}
    if isinstance(tls, dict):
        return tls
    return {}

def _reality_settings(stream: Dict[str, Any]) -> Dict[str, Any]:
    return stream.get("realitySettings") or {}

def _ws_settings(stream: Dict[str, Any]) -> Dict[str, Any]:
    return stream.get("wsSettings") or {}

def _grpc_settings(stream: Dict[str, Any]) -> Dict[str, Any]:
    return stream.get("grpcSettings") or {}

def _tcp_settings(stream: Dict[str, Any]) -> Dict[str, Any]:
    return stream.get("tcpSettings") or {}

def _kcp_settings(stream: Dict[str, Any]) -> Dict[str, Any]:
    return stream.get("kcpSettings") or {}

def _quic_settings(stream: Dict[str, Any]) -> Dict[str, Any]:
    return stream.get("quicSettings") or {}

def _http_settings(stream: Dict[str, Any]) -> Dict[str, Any]:
    # Xray “http” transport (or “xhttp” variants some panels expose)
    return stream.get("httpSettings") or {}

def _xhttp_settings(stream: Dict[str, Any]) -> Dict[str, Any]:
    # Some panels store as xhttpSettings (custom)
    return stream.get("xhttpSettings") or {}

def _external_proxy_dest(stream: Dict[str, Any]) -> Optional[str]:
    # Some panels stash an “externalProxy”: [{ dest: "host.com" }]
    ext = stream.get("externalProxy")
    if isinstance(ext, list) and ext and isinstance(ext[0], dict):
        d = ext[0].get("dest")
        if d:
            return str(d)
    return None

def _get_network_path(stream: Dict[str, Any], network: str) -> str:
    if network == "tcp":
        tcp = _tcp_settings(stream)
        hdr = ((tcp.get("header") or {}) if isinstance(tcp, dict) else {})
        if hdr.get("type") == "http":
            # Some panels store request.path as array
            req = tcp.get("request") or {}
            p = _arr_first((req.get("path") or []))
            return p or "/"
        return "/"
    if network == "ws":
        ws = _ws_settings(stream)
        return ws.get("path") or "/"
    if network in ("http","xhttp"):
        # support httpSettings.path (array or string) and xhttpSettings.path (string)
        hs = _http_settings(stream)
        xhs = _xhttp_settings(stream)
        if hs.get("path"):
            return _arr_first(hs.get("path")) or "/"
        if xhs.get("path"):
            return xhs.get("path") or "/"
        return "/"
    if network == "grpc":
        gs = _grpc_settings(stream)
        return gs.get("serviceName") or ""
    if network == "kcp":
        ks = _kcp_settings(stream)
        return ks.get("seed") or ""
    if network == "quic":
        qs = _quic_settings(stream)
        return qs.get("key") or ""
    return "/"

def _get_network_host(stream: Dict[str, Any], network: str) -> str:
    if network == "tcp":
        tcp = _tcp_settings(stream)
        hdr = ((tcp.get("header") or {}) if isinstance(tcp, dict) else {})
        if hdr.get("type") == "http":
            req = tcp.get("request") or {}
            headers = req.get("headers") or {}
            hlist = headers.get("Host")
            return _arr_first(hlist) or ""
        return ""
    if network == "ws":
        ws = _ws_settings(stream)
        # Some panels put host under wsSettings.host, others under headers.Host
        return ws.get("host") or (ws.get("headers") or {}).get("Host") or ""
    if network in ("http","xhttp"):
        hs = _http_settings(stream)
        xhs = _xhttp_settings(stream)
        if xhs.get("host"):
            return xhs.get("host")
        h = hs.get("host")
        return _arr_first(h) if isinstance(h, list) else (h or "")
    return ""

def _server_host(stream: Dict[str, Any], inbound_settings: Dict[str, Any]) -> str:
    # Priority: externalProxy.dest → tlsSettings.serverName → wsHeaders.Host → inbound settings hints → DOMAIN fallback
    ext = _external_proxy_dest(stream)
    if ext:
        return ext
    tls = _tls_settings(stream)
    if tls.get("serverName"):
        return tls["serverName"]
    ws_host = _get_network_host(stream, "ws")
    if ws_host:
        return ws_host
    for key in ("domain","host","address","serverName"):
        if inbound_settings.get(key):
            return inbound_settings[key]
    return FALLBACK_DOMAIN

def _client_id(client: Dict[str, Any]) -> str:
    return client.get("id") or client.get("uuid") or client.get("password") or ""

def _gather_tls_params(stream: Dict[str, Any]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    tls = _tls_settings(stream)
    if tls.get("serverName"):
        out["sni"] = _norm(tls["serverName"])
    fp = tls.get("fingerprint") or tls.get("fp")
    if fp:
        out["fp"] = _norm(fp)
    alpn = tls.get("alpn")
    if isinstance(alpn, list) and alpn:
        out["alpn"] = ",".join(map(str, alpn))
    elif isinstance(alpn, str) and alpn:
        out["alpn"] = alpn
    # allowInsecure might be under tlsSettings or tlsSettings.settings
    ain = tls.get("allowInsecure")
    if ain is None:
        s = tls.get("settings") or {}
        if isinstance(s, dict) and "allowInsecure" in s:
            ain = s.get("allowInsecure")
    if ain is not None:
        out["allowInsecure"] = _norm(ain)
    return out

def _gather_reality_params(stream: Dict[str, Any]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    rs = _reality_settings(stream)
    if rs.get("publicKey"):
        out["pbk"] = _norm(rs["publicKey"])
    if rs.get("shortId"):
        out["sid"] = _norm(rs["shortId"])
    if rs.get("spiderX"):
        out["spx"] = _norm(rs["spiderX"])
    if rs.get("fingerprint"):
        out["fp"] = _norm(rs["fingerprint"])
    return out


# ----------------------------- builders -----------------------------
def build_vless(client: Dict[str, Any], inbound: Dict[str, Any]) -> str:
    stream = _jload(inbound.get("stream_settings"))
    inbound_settings = _jload(inbound.get("settings"))
    net = _get_network(stream)
    sec = _get_security(stream)
    host = _server_host(stream, inbound_settings)
    port = str(inbound.get("port") or inbound.get("listen_port") or "")
    uid = _client_id(client)

    # Special xhttp format (matches your friend's generator)
    if net == "xhttp":
        network_host = _get_network_host(stream, "xhttp") or host
        raw_path = _get_network_path(stream, "xhttp") or "/"
        # Double-encode and lower-case path to match examples
        double_encoded = quote(quote(raw_path)).lower()
        # encryption intentionally empty string for xhttp per example
        q = {
            "security": "none",
            "encryption": "",
            "headerType": "",
            "type": "xhttp",
            "host": network_host,
            "path": double_encoded,
        }
        tag = quote(client.get("email") or inbound.get("remark") or "node")
        return f"vless://{uid}@{host}:{port}/?{urlencode({k:v for k,v in q.items() if v is not None})}#{tag}"

    params = {
        "type": net,
        "encryption": "none",
        "path": _get_network_path(stream, net),
    }

    network_host = _get_network_host(stream, net)
    if network_host:
        params["host"] = network_host

    # tcp headerType http
    if net == "tcp":
        tcp = _tcp_settings(stream)
        hdr = (tcp.get("header") or {})
        if hdr.get("type") == "http":
            params["headerType"] = "http"

    # grpc mode
    if net == "grpc":
        gs = _grpc_settings(stream)
        params["mode"] = "multi" if gs.get("multiMode") else "gun"
        if gs.get("serviceName"):
            params["serviceName"] = gs["serviceName"]

    # kcp / quic extras
    if net == "kcp":
        ks = _kcp_settings(stream)
        params["headerType"] = (ks.get("header") or {}).get("type") or "none"
        if ks.get("seed"):
            params["seed"] = ks["seed"]
    if net == "quic":
        qs = _quic_settings(stream)
        params["quicSecurity"] = qs.get("security") or "none"
        params["key"] = qs.get("key") or ""
        params["headerType"] = (qs.get("header") or {}).get("type") or "none"

    # Security
    if sec == "tls":
        params["security"] = "tls"
        params.update(_gather_tls_params(stream))
    elif sec == "reality":
        params["security"] = "reality"
        params.update(_gather_reality_params(stream))
    else:
        params["security"] = "none"

    # Flow (e.g., xtls-rprx-vision)
    flow = client.get("flow") or inbound_settings.get("flow")
    if flow:
        params["flow"] = str(flow)

    # Encode
    ordered_keys = [
        "type","security","encryption","path","host","headerType",
        "mode","serviceName","flow","seed","quicSecurity","key","alpn","sni","fp","allowInsecure"
    ]
    # ensure TLS/REALITY params appear in stable order
    # build ordered list
    tmp = params.copy()
    ordered = [(k, tmp.pop(k)) for k in ordered_keys if k in tmp]
    ordered += list(tmp.items())
    encoded = "&".join(f"{quote(str(k))}={quote(str(v))}" for k,v in ordered if v not in (None,""))

    tag = quote(client.get("email") or inbound.get("remark") or "node")
    return f"vless://{uid}@{host}:{port}?{encoded}#{tag}"


def build_vmess(client: Dict[str, Any], inbound: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
    stream = _jload(inbound.get("stream_settings"))
    inbound_settings = _jload(inbound.get("settings"))
    net = _get_network(stream)
    sec = _get_security(stream)
    host = _server_host(stream, inbound_settings)
    port = str(inbound.get("port") or inbound.get("listen_port") or "")
    uid = _client_id(client)

    # network fields
    path = _get_network_path(stream, net)
    vm = {
        "v": "2",
        "ps": client.get("email") or inbound.get("remark") or "node",
        "add": host,
        "port": port,
        "id": uid,
        "aid": 0,
        "net": net,
        "type": "none",  # will override below
        "path": path,
        "tls": "tls" if sec == "tls" else ("reality" if sec == "reality" else "none"),
    }

    # per network host/type
    if net == "tcp":
        tcp = _tcp_settings(stream)
        hdr = (tcp.get("header") or {})
        if hdr.get("type") == "http":
            vm["type"] = "http"
            # tcp http Host
            req = tcp.get("request") or {}
            headers = req.get("headers") or {}
            hlist = headers.get("Host")
            h = _arr_first(hlist) or ""
            if h:
                vm["host"] = h
    elif net == "ws":
        vm["type"] = "none"
        ws = _ws_settings(stream)
        h = ws.get("host") or (ws.get("headers") or {}).get("Host") or ""
        if h:
            vm["host"] = h
    elif net == "grpc":
        gs = _grpc_settings(stream)
        vm["type"] = "multi" if gs.get("multiMode") else "gun"
    elif net == "kcp":
        ks = _kcp_settings(stream)
        vm["type"] = (ks.get("header") or {}).get("type") or "none"
    elif net == "quic":
        qs = _quic_settings(stream)
        vm["type"] = (qs.get("header") or {}).get("type") or "none"
        vm["host"] = qs.get("security") or "none"
    elif net in ("http","xhttp"):
        hs = _http_settings(stream)
        xhs = _xhttp_settings(stream)
        h = xhs.get("host") or hs.get("host")
        vm["type"] = "http"
        if isinstance(h, list):
            h = _arr_first(h)
        if h:
            vm["host"] = h

    # TLS / REALITY extras into top-level keys commonly used by some clients
    tls_params = _gather_tls_params(stream)
    if "sni" in tls_params: vm["sni"] = tls_params["sni"]
    if "fp" in tls_params: vm["fp"] = tls_params["fp"]
    if "alpn" in tls_params: vm["alpn"] = tls_params["alpn"]
    if "allowInsecure" in tls_params: vm["allowInsecure"] = tls_params["allowInsecure"]

    if sec == "reality":
        r = _gather_reality_params(stream)
        if r.get("pbk"): vm["pbk"] = r["pbk"]
        if r.get("sid"): vm["sid"] = r["sid"]
        if r.get("spx"): vm["spx"] = r["spx"]
        if r.get("fp"):  vm["fp"]  = r["fp"]

    # Also attach everything under _ext so you can debug in clients that ignore extras
    vm["_ext"] = {}
    vm["_ext"].update(tls_params)
    if sec == "reality":
        vm["_ext"].update(_gather_reality_params(stream))

    b64 = base64.b64encode(json.dumps(vm, separators=(",",":")).encode()).decode()
    return "vmess://" + b64, vm


def build_trojan(client: Dict[str, Any], inbound: Dict[str, Any]) -> str:
    stream = _jload(inbound.get("stream_settings"))
    inbound_settings = _jload(inbound.get("settings"))
    net = _get_network(stream)
    sec = _get_security(stream)
    host = _server_host(stream, inbound_settings)
    port = str(inbound.get("port") or inbound.get("listen_port") or "")
    pwd = _client_id(client)

    params = {
        "type": net,
        "path": _get_network_path(stream, net),
    }
    h = _get_network_host(stream, net)
    if h:
        params["host"] = h

    if net == "grpc":
        gs = _grpc_settings(stream)
        params["mode"] = "multi" if gs.get("multiMode") else "gun"
        if gs.get("serviceName"):
            params["serviceName"] = gs["serviceName"]

    if net == "tcp":
        tcp = _tcp_settings(stream)
        hdr = (tcp.get("header") or {})
        if hdr.get("type") == "http":
            params["headerType"] = "http"

    if sec == "tls":
        params["security"] = "tls"
        params.update(_gather_tls_params(stream))
    elif sec == "reality":
        # trojan+reality is unusual but let’s pass through if present
        params["security"] = "reality"
        params.update(_gather_reality_params(stream))

    # order & encode
    ordered_keys = ["security","sni","alpn","fp","allowInsecure",
                    "type","path","host","mode","serviceName","headerType"]
    tmp = params.copy()
    ordered = [(k, tmp.pop(k)) for k in ordered_keys if k in tmp]
    ordered += list(tmp.items())
    encoded = "&".join(f"{quote(str(k))}={quote(str(v))}" for k,v in ordered if v not in (None,""))

    tag = quote(client.get("email") or inbound.get("remark") or "node")
    return f"trojan://{pwd}@{host}:{port}?{encoded}#{tag}"


def build_ss(client: Dict[str, Any], inbound: Dict[str, Any]) -> Optional[str]:
    stream = _jload(inbound.get("stream_settings"))
    inbound_settings = _jload(inbound.get("settings"))
    host = _server_host(stream, inbound_settings)
    port = str(inbound.get("port") or inbound.get("listen_port") or "")
    method = client.get("method") or inbound_settings.get("method")
    pwd = client.get("password") or inbound_settings.get("password")
    if not (method and pwd):
        return None
    userinfo = base64.urlsafe_b64encode(f"{method}:{pwd}".encode()).decode().rstrip("=")
    tag = quote(client.get("email") or inbound.get("remark") or "node")
    return f"ss://{userinfo}@{host}:{port}#{tag}"


def build_best(inbound: Dict[str, Any], client: Dict[str, Any]) -> Dict[str, Any]:
    proto = (inbound.get("protocol") or "").lower()
    out = {
        "protocol": proto,
        "vless_link": None,
        "vmess_link": None,
        "vmess_json": None,
        "trojan_link": None,
        "ss_link": None,
        "config_text": "",
        "config_filename": "",
        "qr_datauri": None
    }

    if proto == "vless":
        link = out["vless_link"] = build_vless(client, inbound)
        out["config_text"] = link
        out["config_filename"] = f"{client.get('email','user')}_vless.txt"

    elif proto == "vmess":
        link, vmj = build_vmess(client, inbound)
        out["vmess_link"] = link
        out["vmess_json"] = vmj
        out["config_text"] = link
        out["config_filename"] = f"{client.get('email','user')}_vmess.txt"

    elif proto == "trojan":
        link = out["trojan_link"] = build_trojan(client, inbound)
        out["config_text"] = link
        out["config_filename"] = f"{client.get('email','user')}_trojan.txt"

    elif proto in ("shadowsocks","ss"):
        link = out["ss_link"] = build_ss(client, inbound)
        out["config_text"] = link or ""
        out["config_filename"] = f"{client.get('email','user')}_ss.txt"

    else:
        # Fallback: many panels default to vless
        link = out["vless_link"] = build_vless(client, inbound)
        out["config_text"] = link
        out["config_filename"] = f"{client.get('email','user')}_config.txt"
        out["protocol"] = "vless"

    if out["config_text"] and qrcode:
        out["qr_datauri"] = _qr_data_uri(out["config_text"])
    return out
