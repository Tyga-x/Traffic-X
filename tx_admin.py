# tx_admin.py
import sqlite3
import os
from flask import Blueprint, render_template, request, redirect, url_for, session
from tx_telegram import get_setting, set_setting, TX_DB_PATH

admin_bp = Blueprint('admin', __name__)

# Default admin password (change this in the admin panel later!)
DEFAULT_PASSWORD = "admin123"

def is_logged_in():
    return session.get('admin_logged_in') is True

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
    if not is_logged_in():
        return redirect("/admin/login")
    
    # Get current settings
    bot_token = get_setting("bot_token", "")
    renew_link = get_setting("renew_link", "")
    current_theme = get_setting("theme", "dark")
    
    # Get linked users
    conn = sqlite3.connect(TX_DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT xui_email, tg_chat_id FROM tg_users ORDER BY xui_email")
    linked_users = c.fetchall()
    conn.close()
    
    return render_template(
        "admin_dashboard.html",
        bot_token=bot_token,
        renew_link=renew_link,
        current_theme=current_theme,
        linked_users=linked_users
    )

@admin_bp.route("/admin/save-settings", methods=["POST"])
def save_settings():
    if not is_logged_in():
        return redirect("/admin/login")
    
    set_setting("bot_token", request.form.get("bot_token", ""))
    set_setting("renew_link", request.form.get("renew_link", ""))
    set_setting("theme", request.form.get("theme", "dark"))
    
    return redirect("/admin")

@admin_bp.route("/admin/link-user", methods=["POST"])
def link_user():
    if not is_logged_in():
        return redirect("/admin/login")
    
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
    if not is_logged_in():
        return redirect("/admin/login")
    
    conn = sqlite3.connect(TX_DB_PATH)
    c = conn.cursor()
    c.execute("DELETE FROM tg_users WHERE xui_email=?", (email,))
    conn.commit()
    conn.close()
    
    return redirect("/admin")
