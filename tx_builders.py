# tx_builders.py
# Robust builders for VLESS / VMess / Trojan / Shadowsocks
# - preserves SNI, WS host, path, alpn, fp, allowInsecure, flow, grpc serviceName, etc.
# - merges known and unknown scalar fields from inbound.settings and client object into query params
# - returns consistent dict used by /user_config
# - dependency: qrcode (optional; if missing, qr_datauri will be None)

import os
import json
import base64
import io
from typing import Any, Dict, Optional, Tuple
from urllib.parse import quote, urlencode

try:
    import qrcode
except Exception:
    qrcode = None

FALLBACK_DOMAIN = os.getenv("DOMAIN", "localhost")


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


def _server_host(stream: Dict[str, Any], inbound_settings: Dict[str, Any]) -> str:
    """
    Determine the best host to use for links:
      1. tlsSettings.serverName (SNI)
      2. wsSettings.headers.Host
      3. inbound_settings.get('domain') or inbound_settings.get('host') (some panels)
      4. fallback env DOMAIN
    """
    tls = stream.get("tlsSettings", {}) or {}
    ws = stream.get("wsSettings", {}) or {}

    if tls.get("serverName"):
        return tls.get("serverName")
    if (ws.get("headers") or {}).get("Host"):
        return (ws.get("headers") or {}).get("Host")
    # Look for common host keys in inbound.settings root
    for key in ("domain", "host", "address", "serverName"):
        if inbound_settings.get(key):
            return inbound_settings.get(key)
    return FALLBACK_DOMAIN


def _client_id(client: Dict[str, Any]) -> str:
    # VLESS/VMess: id/uuid, Trojan: password, SS: password
    return client.get("id") or client.get("uuid") or client.get("password") or ""


def _qr_data_uri(text: str) -> Optional[str]:
    if not text or not qrcode:
        return None
    qr = qrcode.QRCode(border=1)
    qr.add_data(text)
    qr.make(fit=True)
    img = qr.make_image()
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()


# ---------- helper to gather extra params ----------
def _gather_extra_params(inbound_settings: Dict[str, Any], stream: Dict[str, Any], client: Dict[str, Any]) -> Dict[str, str]:
    """
    Return a flat mapping of additional query params that should be appended.
    Strategy:
      - Collect known useful fields from tlsSettings, client dict, and inbound_settings (top-level)
      - Keep any scalar (str/int/bool) keys that are not nested dicts/arrays and not reserved
      - Convert boolean to '1'/'0' if necessary
    """
    out: Dict[str, str] = {}

    # Helper to normalize scalar -> string
    def _norm(v):
        if isinstance(v, bool):
            return "1" if v else "0"
        if v is None:
            return ""
        return str(v)

    # Known useful TLS keys
    tls = stream.get("tlsSettings", {}) or {}
    # e.g., alpn: list -> join
    alpn = tls.get("alpn")
    if isinstance(alpn, (list, tuple)):
        out["alpn"] = ",".join(map(str, alpn))
    elif isinstance(alpn, str) and alpn:
        out["alpn"] = alpn

    # allowInsecure sometimes present in tlsSettings or inbound settings
    if "allowInsecure" in tls:
        out["allowInsecure"] = _norm(tls.get("allowInsecure"))
    if "allowInsecure" in inbound_settings:
        out["allowInsecure"] = _norm(inbound_settings.get("allowInsecure"))

    # fingerprint / fp / flow / security extras from client or inbound
    # Many panels put custom things on client like 'fingerprint' or 'fp'
    for k in ("fp", "fingerprint", "flow", "fallback", "realityPublicKey"):
        if client.get(k) is not None:
            out[k] = _norm(client.get(k))
        elif inbound_settings.get(k) is not None:
            out[k] = _norm(inbound_settings.get(k))

    # top-level inbound_settings scalar keys (not 'clients' or nested)
    reserved = {"clients", "stream_settings", "sniffing"}
    for k, v in inbound_settings.items():
        if k in reserved:
            continue
        if isinstance(v, (dict, list)):
            continue
        out.setdefault(k, _norm(v))

    # client-level scalar keys (excluding long objects)
    for k, v in client.items():
        if k in ("email", "id", "uuid", "password"):
            continue
        if isinstance(v, (dict, list)):
            continue
        out.setdefault(k, _norm(v))

    return out


# ---------- builders ----------
def build_vless(client: Dict[str, Any], inbound: Dict[str, Any]) -> str:
    stream = _jload(inbound.get("stream_settings"))
    inbound_settings = _jload(inbound.get("settings") or {})
    net = stream.get("network", "tcp")
    host = _server_host(stream, inbound_settings)
    port = str(inbound.get("port") or inbound.get("listen_port") or "")
    uid = _client_id(client)

    qs = {}
    # standard
    qs["type"] = net
    qs["encryption"] = "none"
    # security: can be 'none' or 'tls' or 'xtls'
    sec = stream.get("security") or inbound_settings.get("security") or "none"
    qs["security"] = sec

    # ws settings
    if net == "ws":
        ws = stream.get("wsSettings", {}) or {}
        path = ws.get("path", "/")
        qs["path"] = path
        host_header = (ws.get("headers") or {}).get("Host")
        if host_header:
            qs["host"] = host_header

    # grpc settings
    if net == "grpc":
        g = stream.get("grpcSettings", {}) or {}
        svc = g.get("serviceName")
        if svc:
            qs["mode"] = "gun"
            qs["serviceName"] = svc

    # flow (xtls/reality)
    flow = client.get("flow") or inbound_settings.get("flow")
    if flow:
        qs["flow"] = str(flow)

    # Merge in extras (alpn, fp, allowInsecure, etc)
    extras = _gather_extra_params(inbound_settings, stream, client)
    qs.update(extras)

    # Build ordered query string: keep some sane order (type, security, encryption, path, host, then extras)
    ordered_keys = ["type", "security", "encryption", "path", "host", "mode", "serviceName", "flow"]
    ordered = []
    for k in ordered_keys:
        if k in qs:
            ordered.append((k, qs.pop(k)))
    # remaining keys
    for k, v in qs.items():
        ordered.append((k, v))

    # percent-encode values explicitly for safety
    encoded = "&".join(f"{quote(str(k))}={quote(str(v))}" for k, v in ordered if v is not None)
    tag = quote(client.get("email") or inbound.get("remark") or "node")
    return f"vless://{uid}@{host}:{port}?{encoded}#{tag}"


def build_vmess(client: Dict[str, Any], inbound: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
    stream = _jload(inbound.get("stream_settings"))
    inbound_settings = _jload(inbound.get("settings") or {})
    net = stream.get("network", "tcp")
    host = _server_host(stream, inbound_settings)
    port = str(inbound.get("port") or inbound.get("listen_port") or "")
    ws = stream.get("wsSettings", {}) or {}
    path = ws.get("path", "/")
    sec = stream.get("security") or inbound_settings.get("security") or "none"

    vm = {
        "v": "2",
        "ps": client.get("email") or inbound.get("remark") or "node",
        "add": host,
        "port": port,
        "id": _client_id(client),
        "aid": str(client.get("alterId") or client.get("aid") or 0),
        "net": net,
        "type": (ws.get("header", {}).get("type") if isinstance(ws.get("header"), dict) else "none"),
        "host": (ws.get("headers") or {}).get("Host", ""),
        "path": path,
        "tls": "" if sec == "none" else sec
    }

    # include known extras
    extras = _gather_extra_params(inbound_settings, stream, client)
    # merge extras into vm with some mapping (e.g., alpn -> tls.alpn is not part of vmess JSON standard,
    # but we still include it in vmess_json beneath a "ext" key so clients can inspect if needed)
    if extras:
        vm["_ext"] = extras

    b64 = base64.b64encode(json.dumps(vm, separators=(",", ":")).encode()).decode()
    return "vmess://" + b64, vm


def build_trojan(client: Dict[str, Any], inbound: Dict[str, Any]) -> str:
    stream = _jload(inbound.get("stream_settings"))
    inbound_settings = _jload(inbound.get("settings") or {})
    net = stream.get("network", "tcp")
    host = _server_host(stream, inbound_settings)
    port = str(inbound.get("port") or inbound.get("listen_port") or "")
    pwd = _client_id(client)

    # default security usually tls for trojan
    sec = stream.get("security") or inbound_settings.get("security") or "tls"
    qs: Dict[str, str] = {}
    qs["security"] = sec

    # SNI: tlsSettings.serverName or host
    tls = stream.get("tlsSettings", {}) or {}
    sni = tls.get("serverName") or inbound_settings.get("sni") or host
    if sni:
        qs["sni"] = sni

    # alpn handled in extras
    extras = _gather_extra_params(inbound_settings, stream, client)
    # add ws/grpc details
    if net == "ws":
        ws = stream.get("wsSettings", {}) or {}
        qs["type"] = "ws"
        qs["path"] = ws.get("path", "/")
        host_header = (ws.get("headers") or {}).get("Host")
        if host_header:
            qs["host"] = host_header
    elif net == "grpc":
        g = stream.get("grpcSettings", {}) or {}
        qs["type"] = "grpc"
        svc = g.get("serviceName")
        if svc:
            qs["serviceName"] = svc

    # merge extras (alpn, fp, allowInsecure, etc.)
    qs.update(extras)

    # Build ordered query: security, sni, alpn, type, path, host, serviceName, then others
    ordered_keys = ["security", "sni", "alpn", "type", "path", "host", "serviceName"]
    ordered = []
    for k in ordered_keys:
        if k in qs:
            ordered.append((k, qs.pop(k)))
    for k, v in qs.items():
        ordered.append((k, v))

    encoded = "&".join(f"{quote(str(k))}={quote(str(v))}" for k, v in ordered if v is not None)
    tag = quote(client.get("email") or inbound.get("remark") or "node")
    return f"trojan://{pwd}@{host}:{port}?{encoded}#{tag}"


def build_ss(client: Dict[str, Any], inbound: Dict[str, Any]) -> Optional[str]:
    inbound_settings = _jload(inbound.get("settings") or {})
    stream = _jload(inbound.get("stream_settings"))
    host = _server_host(stream, inbound_settings)
    port = str(inbound.get("port") or inbound.get("listen_port") or "")
    method = client.get("method") or inbound_settings.get("method")
    pwd = client.get("password") or inbound_settings.get("password")
    if not method or not pwd:
        return None
    # userinfo = base64(method:password)
    userinfo = base64.urlsafe_b64encode(f"{method}:{pwd}".encode()).decode().rstrip("=")
    tag = quote(client.get("email") or inbound.get("remark") or "node")
    return f"ss://{userinfo}@{host}:{port}#{tag}"


def build_best(inbound: Dict[str, Any], client: Dict[str, Any]) -> Dict[str, Any]:
    """
    Primary entrypoint: returns a dict with these keys:
      protocol, vless_link, vmess_link, vmess_json, trojan_link, ss_link,
      config_text, config_filename, qr_datauri
    """
    proto = (inbound.get("protocol") or "").lower()
    result = {
        "protocol": proto,
        "vless_link": None,
        "vmess_link": None,
        "vmess_json": None,
        "trojan_link": None,
        "ss_link": None,
        "config_text": "",
        "config_filename": "",
        "qr_datauri": None,
    }

    if proto == "vless":
        link = build_vless(client, inbound)
        result["vless_link"] = link
        result["config_text"] = link
        result["config_filename"] = f"{client.get('email','user')}_vless.txt"
    elif proto == "vmess":
        link, vmjson = build_vmess(client, inbound)
        result["vmess_link"] = link
        result["vmess_json"] = vmjson
        result["config_text"] = link
        result["config_filename"] = f"{client.get('email','user')}_vmess.txt"
    elif proto == "trojan":
        link = build_trojan(client, inbound)
        result["trojan_link"] = link
        result["config_text"] = link
        result["config_filename"] = f"{client.get('email','user')}_trojan.txt"
    elif proto in ("shadowsocks", "ss"):
        link = build_ss(client, inbound)
        result["ss_link"] = link
        result["config_text"] = link or ""
        result["config_filename"] = f"{client.get('email','user')}_ss.txt"
    else:
        # best-effort fallback: vless
        link = build_vless(client, inbound)
        result["vless_link"] = link
        result["config_text"] = link
        result["config_filename"] = f"{client.get('email','user')}_config.txt"
        result["protocol"] = "vless"

    result["qr_datauri"] = _qr_data_uri(result["config_text"]) if result["config_text"] else None
    return result
