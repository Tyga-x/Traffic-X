# tx_admin.py
import sqlite3
import os
import time
from flask import Blueprint, render_template, request, redirect, url_for, session
from tx_telegram import get_setting, set_setting, TX_DB_PATH, XUI_DB_PATH, send_backup_document

admin_bp = Blueprint('admin', __name__)
DEFAULT_PASSWORD = "admin123"

def is_logged_in():
    return session.get('admin_logged_in') is True

def format_bytes(size):
    try:
        size = float(size)
    except:
        return "0 GB"
    for unit in ['Bytes', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024.0:
            return f"{size:.2f} {unit}"
        size /= 1024.0
    return f"{size:.2f} PB"

@admin_bp.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        password = request.form.get("password")
        admin_pass = get_setting("admin_password", DEFAULT_PASSWORD)
        if password == admin_pass:
            session['admin_logged_in'] = True
            return redirect("/admin")
        return render_template("admin_login.html", error="Invalid password")
    return render_template("admin_login.html")

@admin_bp.route("/admin/logout")
def admin_logout():
    session.pop('admin_logged_in', None)
    return redirect("/admin/login")

@admin_bp.route("/admin", methods=["GET"])
def admin_dashboard():
    if not is_logged_in(): return redirect("/admin/login")
    
    # Pagination Params
    page = request.args.get('page', 1, type=int)
    per_page = 10
    active_tab = request.args.get('tab', 'overview')
    
    # Get current settings
    bot_token = get_setting("bot_token", "")
    renew_link = get_setting("renew_link", "")
    current_theme = get_setting("theme", "dark")
    admin_chat_id = get_setting("admin_chat_id", "")
    tg_bot_link = get_setting("tg_bot_link", "")
    
    # === Calculate Dashboard Statistics ===
    total_users = 0
    active_users = 0
    expired_users = 0
    total_bandwidth = 0
    tg_linked_count = 0
    
    try:
        xui_conn = sqlite3.connect(XUI_DB_PATH, timeout=5)
        xui_conn.row_factory = sqlite3.Row
        xui_cur = xui_conn.cursor()
        xui_cur.execute("SELECT email, up, down, total, expiry_time FROM client_traffics")
        users = xui_cur.fetchall()
        xui_conn.close()
        
        now_ms = time.time() * 1000
        for u in users:
            total_users += 1
            total_bandwidth += u["up"] + u["down"]
            if u["expiry_time"] and float(u["expiry_time"]) > 0:
                if float(u["expiry_time"]) > now_ms:
                    active_users += 1
                else:
                    expired_users += 1
            else:
                active_users += 1
    except Exception:
        pass
        
    try:
        tx_conn = sqlite3.connect(TX_DB_PATH, timeout=5)
        tx_cur = tx_conn.cursor()
        tx_cur.execute("SELECT COUNT(*) FROM tg_users")
        tg_linked_count = tx_cur.fetchone()[0]
        tx_conn.close()
    except Exception:
        pass

    # === Paginate Telegram Users ===
    try:
        tx_conn = sqlite3.connect(TX_DB_PATH, timeout=5)
        tx_cur = tx_conn.cursor()
        total_pages = max(1, (tg_linked_count + per_page - 1) // per_page)
        if page > total_pages: page = total_pages
        offset = (page - 1) * per_page
        
        tx_cur.execute("SELECT xui_email, tg_chat_id FROM tg_users ORDER BY xui_email LIMIT ? OFFSET ?", (per_page, offset))
        tg_rows = tx_cur.fetchall()
        tx_conn.close()
    except:
        tg_rows = []
        total_pages = 1

    # Build lists for current page
    linked_users = []
    tg_users_status = []
    try:
        xui_conn = sqlite3.connect(XUI_DB_PATH, timeout=5)
        xui_conn.row_factory = sqlite3.Row
        xui_cur = xui_conn.cursor()
        now_ms = time.time() * 1000
        
        for t_row in tg_rows:
            email = t_row[0]
            chat_id = t_row[1]
            linked_users.append({"xui_email": email, "tg_chat_id": chat_id})
            
            status = "Active"
            status_color = "green"
            xui_cur.execute("SELECT up, down, total, expiry_time FROM client_traffics WHERE email=?", (email,))
            x_row = xui_cur.fetchone()
            
            if x_row:
                if x_row["expiry_time"] and float(x_row["expiry_time"]) > 0 and float(x_row["expiry_time"]) < now_ms:
                    status = "Expired"
                    status_color = "red"
                elif x_row["total"] and float(x_row["total"]) > 0:
                    if float(x_row["up"]) + float(x_row["down"]) >= float(x_row["total"]):
                        status = "Out of Data"
                        status_color = "red"
            else:
                status = "Not Found in X-UI"
                status_color = "orange"
                
            tg_users_status.append({"email": email, "chat_id": chat_id, "status": status, "color": status_color})
        xui_conn.close()
    except Exception:
        pass

    # === Calculate Recent Alerts ===
    recent_alerts = []
    try:
        tx_conn = sqlite3.connect(TX_DB_PATH, timeout=5)
        tx_conn.row_factory = sqlite3.Row
        tx_cur = tx_conn.cursor()
        tx_cur.execute("SELECT xui_email, type, last_notified FROM notif_log ORDER BY last_notified DESC LIMIT 5")
        logs = tx_cur.fetchall()
        tx_conn.close()
        
        for log in logs:
            recent_alerts.append({
                "email": log["xui_email"],
                "type": "Expiry Alert" if log["type"] == "expiry" else "Data Alert",
                "time": time.strftime('%Y-%m-%d %H:%M', time.localtime(float(log["last_notified"])))
            })
    except Exception:
        pass
    
    return render_template(
        "admin_dashboard.html",
        bot_token=bot_token,
        renew_link=renew_link,
        current_theme=current_theme,
        admin_chat_id=admin_chat_id,
        tg_bot_link=tg_bot_link,
        linked_users=linked_users,
        tg_users_status=tg_users_status,
        recent_alerts=recent_alerts,
        page=page,
        total_pages=total_pages,
        active_tab=active_tab,
        stats={
            "total_users": total_users,
            "active_users": active_users,
            "expired_users": expired_users,
            "total_bandwidth": format_bytes(total_bandwidth),
            "tg_linked": tg_linked_count
        }
    )

@admin_bp.route("/admin/save-settings", methods=["POST"])
def save_settings():
    if not is_logged_in(): return redirect("/admin/login")
    set_setting("bot_token", request.form.get("bot_token", ""))
    set_setting("renew_link", request.form.get("renew_link", ""))
    set_setting("theme", request.form.get("theme", "dark"))
    set_setting("admin_chat_id", request.form.get("admin_chat_id", ""))
    set_setting("tg_bot_link", request.form.get("tg_bot_link", ""))
    return redirect("/admin")

@admin_bp.route("/admin/link-user", methods=["POST"])
def link_user():
    if not is_logged_in(): return redirect("/admin/login")
    email = request.form.get("xui_email")
    chat_id = request.form.get("tg_chat_id")
    if email and chat_id:
        conn = sqlite3.connect(TX_DB_PATH)
        c = conn.cursor()
        c.execute("INSERT OR REPLACE INTO tg_users (xui_email, tg_chat_id) VALUES (?, ?)", (email, chat_id))
        conn.commit()
        conn.close()
    return redirect("/admin")

@admin_bp.route("/admin/delete-link/<email>", methods=["POST"])
def delete_link(email):
    if not is_logged_in(): return redirect("/admin/login")
    conn = sqlite3.connect(TX_DB_PATH)
    c = conn.cursor()
    c.execute("DELETE FROM tg_users WHERE xui_email=?", (email,))
    conn.commit()
    conn.close()
    return redirect("/admin")

@admin_bp.route("/admin/clear-logs", methods=["POST"])
def clear_logs():
    if not is_logged_in(): return redirect("/admin/login")
    conn = sqlite3.connect(TX_DB_PATH)
    c = conn.cursor()
    c.execute("DELETE FROM notif_log")
    conn.commit()
    conn.close()
    return redirect("/admin")

@admin_bp.route("/admin/test-backup", methods=["POST"])
def test_backup():
    if not is_logged_in(): return redirect("/admin/login")
    send_backup_document()
    return redirect("/admin")

@admin_bp.route("/admin/upload-db", methods=["POST"])
def upload_db():
    if not is_logged_in(): return redirect("/admin/login")
    if 'db_file' not in request.files: return redirect("/admin")
    file = request.files['db_file']
    if file.filename == '': return redirect("/admin")
    if file:
        temp_path = TX_DB_PATH + ".tmp"
        file.save(temp_path)
        try:
            if os.path.exists(TX_DB_PATH): os.remove(TX_DB_PATH)
            os.rename(temp_path, TX_DB_PATH)
        except Exception:
            pass
    return redirect("/admin")
