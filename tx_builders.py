# tx_builders.py
import base64
import json
import qrcode
import io

def _safe(val, default=""): return str(val) if val else default
def _q(s): return s.replace(" ", "%20") if s else ""

def _gen_qr(link):
    qr = qrcode.make(link)
    buf = io.BytesIO()
    qr.save(buf, format="PNG")
    return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()

def build_config_from_inbound(inbound_json, client_email, domain):
    clients = inbound_json.get("clients", [])
    client = next((c for c in clients if c.get("email") == client_email), None)
    if not client: return {}

    protocol = inbound_json.get("protocol")
    port = inbound_json.get("port")
    stream = inbound_json.get("streamSettings", {})

    address = inbound_json.get("address") or domain
    id_ = client.get("id", "")
    aid = client.get("alterId", "0")
    flow = client.get("flow", "")
    pass_ = client.get("password", "")
    net = stream.get("network", "")
    sec = stream.get("security", "")
    tls = stream.get("tlsSettings", {})
    xtls = stream.get("xtlsSettings", {})
    grpc = stream.get("grpcSettings", {})
    ws = stream.get("wsSettings", {})
    tcp = stream.get("tcpSettings", {})
    http = stream.get("httpSettings", {})

    sni = _safe(tls.get("serverName") or tls.get("sni") or address)
    alpn = ",".join(tls.get("alpn", []))
    fp = tls.get("fingerprint", "")

    host = _safe(ws.get("headers", {}).get("Host") or tcp.get("header", {}).get("request", {}).get("headers", {}).get("Host", ""))
    path = _safe(ws.get("path") or grpc.get("serviceName") or http.get("path") or "")

    if protocol == "vless":
        parts = [
            f"vless://{id_}@{address}:{port}",
            f"?type={net}&security={sec}&encryption=none",
            f"&path={_q(path)}" if path else "",
            f"&host={_q(host)}" if host else "",
            f"&sni={_q(sni)}" if sni else "",
            f"&fp={_q(fp)}" if fp else "",
            f"&alpn={_q(alpn)}" if alpn else "",
            f"#Traffic-X"
        ]
        link = "".join(parts)
    elif protocol == "vmess":
        vmess_json = {
            "v": "2",
            "ps": client_email,
            "add": address,
            "port": str(port),
            "id": id_,
            "aid": aid,
            "net": net,
            "type": "none",
            "host": host,
            "path": path,
            "tls": sec,
            "sni": sni,
            "alpn": alpn,
            "fp": fp,
            "scy": client.get("cipher", "auto")
        }
        link = "vmess://" + base64.b64encode(json.dumps(vmess_json).encode()).decode()
    elif protocol == "trojan":
        parts = [
            f"trojan://{pass_}@{address}:{port}",
            f"?type={net}&security={sec}",
            f"&path={_q(path)}" if path else "",
            f"&sni={_q(sni)}" if sni else "",
            f"&alpn={_q(alpn)}" if alpn else "",
            f"&fp={_q(fp)}" if fp else "",
            f"&host={_q(host)}" if host else "",
            f"#Traffic-X"
        ]
        link = "".join(parts)
    else:
        return {}

    return {
        "protocol": protocol,
        f"{protocol}_link": link,
        "qr_datauri": _gen_qr(link),
        "config_text": link,
        "config_filename": f"{client_email}_{protocol}.txt"
    }
