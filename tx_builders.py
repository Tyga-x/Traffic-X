# tx_builders.py
import json
import base64
import qrcode
from io import BytesIO

def build_links(client, inbound):
    email = client.get("email", "")
    protocol = inbound.get("protocol", "")
    address = inbound.get("address", "")
    port = inbound.get("port", "")
    id_ = client.get("id", "")
    flow = client.get("flow", "")
    security = inbound.get("streamSettings", {}).get("security", "")
    sni = inbound.get("streamSettings", {}).get("realitySettings", {}).get("serverNames", [""])[0]

    link = ""
    if protocol == "vless":
        flow = f"?flow={flow}" if flow else ""
        security = f"&security={security}" if security else ""
        sni_part = f"&sni={sni}" if sni else ""
        link = f"vless://{id_}@{address}:{port}?type=ws{flow}{security}{sni_part}#{email}"
    elif protocol == "vmess":
        data = {
            "v": "2",
            "ps": email,
            "add": address,
            "port": str(port),
            "id": id_,
            "aid": "0",
            "net": "ws",
            "type": "none",
            "host": address,
            "path": "/",
            "tls": security,
        }
        json_data = json.dumps(data)
        link = "vmess://" + base64.urlsafe_b64encode(json_data.encode()).decode()
    elif protocol == "trojan":
        link = f"trojan://{id_}@{address}:{port}#{email}"

    return {
        "protocol": protocol,
        "link": link,
        "qr_datauri": generate_qr(link),
        "config_text": link,
        "config_filename": f"{email}_{protocol}.txt"
    }

def generate_qr(data):
    if not data:
        return ""
    img = qrcode.make(data)
    buffer = BytesIO()
    img.save(buffer, format="PNG")
    return "data:image/png;base64," + base64.b64encode(buffer.getvalue()).decode()
