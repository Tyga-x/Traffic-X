import os, json, base64, io
from urllib.parse import quote, urlencode
from typing import Any, Dict, Optional
try:
    import qrcode
except Exception:
    qrcode = None

FALLBACK_DOMAIN = os.getenv("DOMAIN", "localhost")

def _jload(x: Any) -> Dict[str, Any]:
    if not x: return {}
    if isinstance(x, dict): return x
    try: return json.loads(x)
    except Exception:
        try: return json.loads(str(x).replace("'", '"'))
        except Exception: return {}

def _arr_first(x): 
    return x[0] if isinstance(x, list) and x else x

def _norm(v):
    if isinstance(v, bool): return "1" if v else "0"
    return "" if v is None else str(v)

def _qr_data_uri(text: str) -> Optional[str]:
    if not (qrcode and text): return None
    qr = qrcode.QRCode(border=1); qr.add_data(text); qr.make(fit=True)
    img = qr.make_image(); buf = io.BytesIO(); img.save(buf, format="PNG")
    import base64 as b64
    return "data:image/png;base64," + b64.b64encode(buf.getvalue()).decode()

def _get_network(stream): return (stream.get("network") or "tcp").lower()
def _get_security(stream):
    sec = (stream.get("security") or "").lower()
    return sec if sec in ("tls","reality","xtls","none") else "none"

def _tls_settings(stream): return stream.get("tlsSettings") or {}
def _reality_settings(stream): return stream.get("realitySettings") or {}
def _ws_settings(stream): return stream.get("wsSettings") or {}
def _grpc_settings(stream): return stream.get("grpcSettings") or {}
def _tcp_settings(stream): return stream.get("tcpSettings") or {}
def _kcp_settings(stream): return stream.get("kcpSettings") or {}
def _quic_settings(stream): return stream.get("quicSettings") or {}
def _http_settings(stream): return stream.get("httpSettings") or {}
def _xhttp_settings(stream): return stream.get("xhttpSettings") or {}

def _external_proxy_dest(stream):
    ext = stream.get("externalProxy")
    if isinstance(ext, list) and ext and isinstance(ext[0], dict):
        d = ext[0].get("dest")
        if d: return str(d)
    return None

def _get_network_path(stream, network):
    if network == "tcp":
        tcp = _tcp_settings(stream); hdr = (tcp.get("header") or {})
        if hdr.get("type") == "http":
            req = tcp.get("request") or {}; return _arr_first(req.get("path")) or "/"
        return "/"
    if network == "ws":
        return (_ws_settings(stream) or {}).get("path") or "/"
    if network in ("http","xhttp"):
        hs = _http_settings(stream); xhs = _xhttp_settings(stream)
        if hs.get("path"): return _arr_first(hs.get("path")) or "/"
        if xhs.get("path"): return xhs.get("path") or "/"
        return "/"
    if network == "grpc":
        return (_grpc_settings(stream) or {}).get("serviceName") or ""
    if network == "kcp":
        return (_kcp_settings(stream) or {}).get("seed") or ""
    if network == "quic":
        return (_quic_settings(stream) or {}).get("key") or ""
    return "/"

def _get_network_host(stream, network):
    if network == "tcp":
        tcp = _tcp_settings(stream); hdr = (tcp.get("header") or {})
        if hdr.get("type") == "http":
            req = tcp.get("request") or {}; headers = req.get("headers") or {}
            return _arr_first(headers.get("Host")) or ""
        return ""
    if network == "ws":
        ws = _ws_settings(stream); return ws.get("host") or (ws.get("headers") or {}).get("Host") or ""
    if network in ("http","xhttp"):
        hs = _http_settings(stream); xhs = _xhttp_settings(stream)
        if xhs.get("host"): return xhs.get("host")
        h = hs.get("host"); return _arr_first(h) if isinstance(h, list) else (h or "")
    return ""

def _server_host(stream, inbound_settings):
    return (_external_proxy_dest(stream)
            or _tls_settings(stream).get("serverName")
            or _get_network_host(stream,"ws")
            or inbound_settings.get("domain")
            or inbound_settings.get("host")
            or inbound_settings.get("address")
            or FALLBACK_DOMAIN)

def _client_id(client):
    return client.get("id") or client.get("uuid") or client.get("password") or ""

def _gather_tls_params(stream):
    out = {}
    tls = _tls_settings(stream)
    if tls.get("serverName"): out["sni"] = _norm(tls["serverName"])
    fp = tls.get("fingerprint") or tls.get("fp")
    if fp: out["fp"] = _norm(fp)
    alpn = tls.get("alpn")
    if isinstance(alpn, list) and alpn: out["alpn"] = ",".join(map(str, alpn))
    elif isinstance(alpn, str) and alpn: out["alpn"] = alpn
    ain = tls.get("allowInsecure") or (tls.get("settings") or {}).get("allowInsecure")
    if ain is not None: out["allowInsecure"] = _norm(ain)
    return out

def _gather_reality_params(stream):
    out = {}
    rs = _reality_settings(stream)
    if rs.get("publicKey"): out["pbk"] = _norm(rs["publicKey"])
    if rs.get("shortId"): out["sid"] = _norm(rs["shortId"])
    if rs.get("spiderX"): out["spx"] = _norm(rs["spiderX"])
    if rs.get("fingerprint"): out["fp"] = _norm(rs["fingerprint"])
    return out

def build_vless(client, inbound):
    stream = _jload(inbound.get("stream_settings") or inbound.get("streamSettings"))
    inbound_settings = _jload(inbound.get("settings"))
    net = _get_network(stream); sec = _get_security(stream)
    host = _server_host(stream, inbound_settings)
    port = str(inbound.get("port") or inbound.get("listen") or inbound.get("listen_port") or "")
    uid = _client_id(client)

    if net == "xhttp":
        network_host = _get_network_host(stream, "xhttp") or host
        raw_path = _get_network_path(stream, "xhttp") or "/"
        from urllib.parse import quote
        double_encoded = quote(quote(raw_path)).toLower if hasattr(str, "toLower") else quote(quote(raw_path)).lower()
        q = {
            "security":"none","encryption":"", "headerType":"",
            "type":"xhttp", "host":network_host, "path":double_encoded
        }
        tag = quote(client.get("email") or inbound.get("remark") or "node")
        return f"vless://{uid}@{host}:{port}/?{urlencode({k:v for k,v in q.items() if v is not None})}#{tag}"

    params = {"type": net, "encryption": "none", "path": _get_network_path(stream, net)}
    network_host = _get_network_host(stream, net)
    if network_host: params["host"] = network_host

    if net == "tcp":
        tcp = _tcp_settings(stream); hdr = (tcp.get("header") or {})
        if hdr.get("type") == "http": params["headerType"] = "http"
    if net == "grpc":
        gs = _grpc_settings(stream)
        params["mode"] = "multi" if gs.get("multiMode") else "gun"
        if gs.get("serviceName"): params["serviceName"] = gs["serviceName"]
    if net == "kcp":
        ks = _kcp_settings(stream)
        params["headerType"] = (ks.get("header") or {}).get("type") or "none"
        if ks.get("seed"): params["seed"] = ks["seed"]
    if net == "quic":
        qs = _quic_settings(stream)
        params["quicSecurity"] = qs.get("security") or "none"
        params["key"] = qs.get("key") or ""
        params["headerType"] = (qs.get("header") or {}).get("type") or "none"

    if sec == "tls":
        params["security"] = "tls"; params.update(_gather_tls_params(stream))
    elif sec == "reality":
        params["security"] = "reality"; params.update(_gather_reality_params(stream))
    else:
        params["security"] = "none"

    flow = client.get("flow") or inbound_settings.get("flow")
    if flow: params["flow"] = str(flow)

    ordered = ["type","security","encryption","path","host","headerType","mode","serviceName","flow","seed","quicSecurity","key","alpn","sni","fp","allowInsecure"]
    tmp = params.copy()
    kv = [(k, tmp.pop(k)) for k in ordered if k in tmp] + list(tmp.items())
    enc = "&".join(f"{quote(str(k))}={quote(str(v))}" for k,v in kv if v not in (None,""))
    tag = quote(client.get("email") or inbound.get("remark") or "node")
    return f"vless://{uid}@{host}:{port}?{enc}#{tag}"

def build_vmess(client, inbound):
    stream = _jload(inbound.get("stream_settings") or inbound.get("streamSettings"))
    inbound_settings = _jload(inbound.get("settings"))
    net = _get_network(stream); sec = _get_security(stream)
    host = _server_host(stream, inbound_settings)
    port = str(inbound.get("port") or inbound.get("listen") or inbound.get("listen_port") or "")
    uid = _client_id(client)
    path = _get_network_path(stream, net)

    vm = {
        "v": "2",
        "ps": client.get("email") or inbound.get("remark") or "node",
        "add": host,
        "port": port,
        "id": uid,
        "aid": 0,
        "net": net,
        "type": "none",
        "path": path,
        "tls": "tls" if sec=="tls" else ("reality" if sec=="reality" else "none"),
    }

    if net == "tcp":
        tcp = _tcp_settings(stream); hdr = (tcp.get("header") or {})
        if hdr.get("type") == "http":
            vm["type"] = "http"
            req = tcp.get("request") or {}; headers = req.get("headers") or {}
            h = _arr_first(headers.get("Host")) if isinstance(headers.get("Host"), list) else headers.get("Host")
            if h: vm["host"] = h
    elif net == "ws":
        ws = _ws_settings(stream); h = ws.get("host") or (ws.get("headers") or {}).get("Host") or ""
        if h: vm["host"] = h
    elif net == "grpc":
        gs = _grpc_settings(stream); vm["type"] = "multi" if gs.get("multiMode") else "gun"
        if gs.get("serviceName"): vm["servicename"] = gs["serviceName"]
    elif net == "kcp":
        ks = _kcp_settings(stream); vm["type"] = (ks.get("header") or {}).get("type") or "none"
    elif net == "quic":
        qs = _quic_settings(stream); vm["type"] = (qs.get("header") or {}).get("type") or "none"; vm["host"] = qs.get("security") or "none"
    elif net in ("http","xhttp"):
        hs = _http_settings(stream); xhs = _xhttp_settings(stream); vm["type"] = "http"
        h = xhs.get("host") or hs.get("host"); h = _arr_first(h) if isinstance(h,list) else h
        if h: vm["host"] = h

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

    b64 = base64.b64encode(json.dumps(vm, separators=(",",":")).encode()).decode()
    return "vmess://" + b64, vm

def build_trojan(client, inbound):
    stream = _jload(inbound.get("stream_settings") or inbound.get("streamSettings"))
    inbound_settings = _jload(inbound.get("settings"))
    net = _get_network(stream); sec = _get_security(stream)
    host = _server_host(stream, inbound_settings)
    port = str(inbound.get("port") or inbound.get("listen") or inbound.get("listen_port") or "")
    pwd = (client.get("password") or client.get("id") or "")

    params = {"type": net, "path": _get_network_path(stream, net)}
    h = _get_network_host(stream, net)
    if h: params["host"] = h

    if net == "grpc":
        gs = _grpc_settings(stream)
        params["mode"] = "multi" if gs.get("multiMode") else "gun"
        if gs.get("serviceName"): params["serviceName"] = gs["serviceName"]
    if net == "tcp":
        tcp = _tcp_settings(stream); hdr = (tcp.get("header") or {})
        if hdr.get("type") == "http": params["headerType"] = "http"

    if sec == "tls":
        params["security"] = "tls"; params.update(_gather_tls_params(stream))
    elif sec == "reality":
        params["security"] = "reality"; params.update(_gather_reality_params(stream))

    ordered = ["security","sni","alpn","fp","allowInsecure","type","path","host","mode","serviceName","headerType"]
    tmp = params.copy()
    kv = [(k, tmp.pop(k)) for k in tmp.copy() if k in tmp]  # preserve order
    enc = "&".join(f"{quote(str(k))}={quote(str(v))}" for k,v in params.items() if v not in (None,""))
    tag = quote(client.get("email") or inbound.get("remark") or "node")
    return f"trojan://{pwd}@{host}:{port}?{enc}#{tag}"

def build_ss(client, inbound):
    inbound_settings = _jload(inbound.get("settings"))
    host = _server_host(_jload(inbound.get("stream_settings") or inbound.get("streamSettings")), inbound_settings)
    port = str(inbound.get("port") or inbound.get("listen") or inbound.get("listen_port") or "")
    method = client.get("method") or inbound_settings.get("method")
    pwd = client.get("password") or inbound_settings.get("password")
    if not (method and pwd): return None
    userinfo = base64.urlsafe_b64encode(f"{method}:{pwd}".encode()).decode().rstrip("=")
    tag = quote(client.get("email") or inbound.get("remark") or "node")
    return f"ss://{userinfo}@{host}:{port}#{tag}"

def build_best(inbound, client):
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
        out["config_text"] = link; out["config_filename"] = f"{client.get('email','user')}_vless.txt"
    elif proto == "vmess":
        link, vmj = build_vmess(client, inbound)
        out["vmess_link"] = link; out["vmess_json"] = vmj
        out["config_text"] = link; out["config_filename"] = f"{client.get('email','user')}_vmess.txt"
    elif proto == "trojan":
        link = out["trojan_link"] = build_trojan(client, inbound)
        out["config_text"] = link; out["config_filename"] = f"{client.get('email','user')}_trojan.txt"
    elif proto in ("shadowsocks","ss"):
        link = out["ss_link"] = build_ss(client, inbound)
        out["config_text"] = link or ""; out["config_filename"] = f"{client.get('email','user')}_ss.txt"
    else:
        link = out["vless_link"] = build_vless(client, inbound)
        out["config_text"] = link; out["config_filename"] = f"{client.get('email','user')}_config.txt"; out["protocol"] = "vless"
    if out["config_text"] and qrcode:
        out["qr_datauri"] = _qr_data_uri(out["config_text"])
    return out

def build_links(client, inbound):
    return build_best(inbound, client)
