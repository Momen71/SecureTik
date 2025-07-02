from flask import Flask, render_template, request, redirect, Blueprint, url_for, flash, jsonify
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os
import re
import subprocess
import json
import requests
from requests.auth import HTTPBasicAuth
from functools import lru_cache
import time
from datetime import datetime
import random
from flask_cors import CORS
from threading import Thread
import tempfile


app = Flask(__name__)
CORS(app)
app.secret_key = 'your_strong_secret_key_here'
# Update these paths according to your system
CLIENT_DATA_FILE = "/tmp/client_data.json"
SCRIPT_PATH = "/home/ubuntu/project/SecureTik/traffic_control/tc_script.sh"
IPTABLES_SCRIPT = "/home/ubuntu/project/SecureTik/iptables-rules/new_setup_iptables.sh/setup_iptables.sh"
CUSTOM_RULES_FILE = '/etc/iptables/custom.rules'

# Ensure the client data file exists
if not os.path.exists(CLIENT_DATA_FILE):
    with open(CLIENT_DATA_FILE, 'w') as f:
        json.dump({}, f)
# Mock user data - replace with your actual user management
users = {
    'Jakleen': {
        'password': 'scrypt:32768:8:1$xgFcvpQR2pHiUhaM$e1fadc526e42b365dffa73f47982fee6706ebc702576b6e44f7f7c6be44f8564323f56df6751da405ae6612e1efdfefc109b415ab0ac6bc98c484a37bdbd954c',
        'role': 'admin'
    },
    'Mahmoud': {
        'password': 'scrypt:32768:8:1$pqO7DPFTmlF2BSVc$aa53b0e74df16b654ebd81f8b2df5de5aa97b17f60427491262d6c67ba6e7e8c70983c5651a176d8a3f1cdc1ce059de3d3b4cf01a90f92405ce6bfb5ef5b4f21',
        'role': 'admin'
    },
    'Taga': {
        'password': 'scrypt:32768:8:1$bRFGNvNdm3GoaIi2$6c5542e1ccb65a3d13640c24b4b99fb8a147bdc65d359d709ba9c9b6ac2c25ce54b92c1089fe7a3d28a709735d793d8d3ce95126071479c4c484a5131dd22f6b',
        'role': 'admin'
    },
    'Mo\'men': {
        'password': 'scrypt:32768:8:1$6jIXQoU3Ob1BobHy$d26f7907d08d33c1feb82b4209697869e7a024fdd1318e99f293c503d5ce229b7967484c80edbef72e57cbdd458620ef0a574d549d86f4485da93287d8b9df40',
        'role': 'admin'
    }
}
class User(UserMixin):
    def __init__(self, id):
        self.id = id
        self.username = id
        self.role = users.get(id, {}).get('role', 'user')

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'index'

@login_manager.user_loader
def load_user(user_id):
    if user_id in users:
        return User(user_id)
    return None

# Database Initialization
def init_db():
    conn = sqlite3.connect('security.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS blocked_mac (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            mac TEXT NOT NULL UNIQUE,
            reason TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

init_db()

# Helper Functions

def is_valid_mac(mac):
    """Check if MAC address is valid with multiple format support"""
    mac = mac.strip().upper()
    patterns = [
        r'^([0-9A-F]{2}[:]){5}([0-9A-F]{2})$',  # 00:11:22:33:44:55
        r'^([0-9A-F]{2}[-]){5}([0-9A-F]{2})$',   # 00-11-22-33-44-55
        r'^([0-9A-F]{4}[.]){2}([0-9A-F]{4})$',   # 0011.2233.4455
        r'^([0-9A-F]{12})$'                      # 001122334455
    ]
    return any(re.match(p, mac) for p in patterns)

def normalize_mac(mac):
    """Convert MAC address to standard format (00:11:22:33:44:55)"""
    mac = mac.replace('-', '').replace(':', '').replace('.', '').upper()
    return ':'.join([mac[i:i+2] for i in range(0, 12, 2)])

def apply_iptables_rules(mac, action):
    """Apply iptables rules for MAC filtering"""
    try:
        # Delete any existing rules for this MAC
        subprocess.run(f'sudo iptables-save | grep -v "{mac}" | sudo iptables-restore', 
                      shell=True, check=True)
        
        if action == 'block':
            # Add rules at the beginning of the chain
            subprocess.run([
                'sudo', 'iptables', '-I', 'FORWARD', '1',
                '-m', 'mac', '--mac-source', mac, '-j', 'DROP'
            ], check=True)
            
            subprocess.run([
                'sudo', 'iptables', '-I', 'INPUT', '1',
                '-m', 'mac', '--mac-source', mac, '-j', 'DROP'
            ], check=True)
            
        # Save rules persistently
        subprocess.run(['sudo', 'netfilter-persistent', 'save'], check=True)
    except Exception as e:
        print(f"Error applying iptables rules: {e}")
        raise



def get_firewall_status():
    """الحصول على حالة جدار الحماية"""
    try:
        result = subprocess.run(
            ['sudo', IPTABLES_SCRIPT, 'status'],
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError:
        return "Unknown"

# Update the rules counting function
def get_active_rules_count():
    try:
        result = subprocess.run(
            ['sudo', 'iptables', '-S'],
            capture_output=True,
            text=True,
            check=True
        )
        # حساب عدد القواعد الفعلية (باستخدام -S بدل -L)
        return sum(1 for line in result.stdout.splitlines() if line.startswith('-A'))
    except subprocess.CalledProcessError:
        return 0

def get_chains_info():
    """الحصول على معلومات سلاسل جدار الحماية"""
    chains = []
    try:
        result = subprocess.run(
            ['sudo', 'iptables', '-L', '-n', '-v', '--line-numbers'],
            capture_output=True,
            text=True,
            check=True
        )
        
        current_chain = None
        for line in result.stdout.splitlines():
            if line.startswith('Chain'):
                parts = line.split()
                if len(parts) >= 4:
                    chains.append({
                        'name': parts[1],
                        'policy': parts[3].replace(')', ''),
                        'rules_count': 0,
                        'packets': parts[4],
                        'bytes': parts[5]
                    })
                    current_chain = chains[-1]
                continue
            
            if current_chain and line.strip() and not line.startswith('num') and not line.startswith('target'):
                current_chain['rules_count'] += 1
        
        return chains
    
    except subprocess.CalledProcessError:
        return [
            {'name': 'INPUT', 'policy': 'UNKNOWN', 'rules_count': 0, 'packets': 0, 'bytes': 0},
            {'name': 'FORWARD', 'policy': 'UNKNOWN', 'rules_count': 0, 'packets': 0, 'bytes': 0},
            {'name': 'OUTPUT', 'policy': 'UNKNOWN', 'rules_count': 0, 'packets': 0, 'bytes': 0}
        ]

def get_custom_rules_content():
    """قراءة محتوى القواعد المخصصة"""
    try:
        with open(CUSTOM_RULES_FILE, 'r') as f:
            return f.read()
    except FileNotFoundError:
        return "# Custom rules file not found"
    except Exception as e:
        return f"# Error reading custom rules: {str(e)}"

# Add this new function to parse services
def parse_services_from_output(output):
    services = []
    for line in output.strip().split('\n'):
        if '|' in line:
            name, port, protocol = line.split('|')
            services.append({
                "name": name,
                "port": port,
                "protocol": protocol
            })
    return services

# Update the services function
def get_services_from_script():
    try:
        result = subprocess.run(
            ['sudo', IPTABLES_SCRIPT, 'services'],
            capture_output=True,
            text=True,
            check=True,
            timeout=10  # إضافة مهلة زمنية
        )
        
        services = []
        for line in result.stdout.splitlines():
            if '|' in line:
                try:
                    name, port, protocol = line.split('|')
                    services.append({
                        "name": name.strip(),
                        "port": port.strip(),
                        "protocol": protocol.strip(),
                        "status": "Enabled"
                    })
                except Exception as e:
                    print(f"Error parsing service line: {line} - {str(e)}")
        
        # إضافة الخدمات الأساسية إذا لم يتم العثور على أي خدمات
        if not services:
            services = [
                {"name": "SSH", "port": "2410", "protocol": "TCP", "status": "Enabled"},
                {"name": "HTTP", "port": "80", "protocol": "TCP", "status": "Enabled"},
                {"name": "HTTPS", "port": "443", "protocol": "TCP", "status": "Enabled"}
            ]
        
        print(f"[DEBUG] Services list: {services}")
        return services
    
    except Exception as e:
        print(f"[ERROR] Error getting services: {e}")
        # Fallback to basic services
        return [
            {"name": "SSH", "port": "2410", "protocol": "TCP", "status": "Enabled"},
            {"name": "HTTP", "port": "80", "protocol": "TCP", "status": "Enabled"},
            {"name": "HTTPS", "port": "443", "protocol": "TCP", "status": "Enabled"}
        ]


def get_services_directly():
    try:
        # الحصول على قواعد iptables
        result = subprocess.run(
            ['sudo', 'iptables', '-S', 'INPUT'],
            capture_output=True,
            text=True,
            check=True
        )
        
        services = []
        for line in result.stdout.splitlines():
            if '--dport' in line:
                parts = line.split()
                service_name = "Custom Service"
                port = ""
                protocol = "tcp"
                
                # البحث عن البروتوكول والمنفذ والتعليق
                for i, part in enumerate(parts):
                    if part == '-p':
                        protocol = parts[i+1]
                    elif part == '--dport':
                        port = parts[i+1]
                    elif part == '--comment':
                        service_name = parts[i+1].strip('"')
                
                if port:
                    # تحديد اسم الخدمة الشائعة
                    if port == "80": service_name = "HTTP"
                    elif port == "443": service_name = "HTTPS"
                    elif port == "2410": service_name = "SSH"
                    
                    services.append({
                        "name": service_name,
                        "port": port,
                        "protocol": protocol.upper(),
                        "status": "Enabled"
                    })
        
        return services
    
    except Exception as e:
        print(f"Error getting services: {str(e)}")
        return []

def validate_ip(ip):
    # تطابق CIDR أو IP فردي
    pattern = r'^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$'
    return re.match(pattern, ip)

def validate_port(port):
    # تطابق رقم منفرد أو نطاق
    pattern = r'^(\d+)(:\d+)?$'
    return re.match(pattern, port)

def start_monitoring():
    """Start the background monitoring thread"""
    def monitor():
        while True:
            try:
                subprocess.run(["sudo", SCRIPT_PATH, "monitor"], check=True)
                time.sleep(5)
            except Exception as e:
                print(f"Monitoring error: {e}")
                time.sleep(10)
    
    if not hasattr(app, 'monitor_thread'):
        app.monitor_thread = Thread(target=monitor, daemon=True)
        app.monitor_thread.start()

def read_clients():
    try:
        with open(CLIENT_DATA_FILE, "r") as f:
            return json.load(f)
    except Exception as e:
        print(f"Error reading client data: {e}")
        return {}


def init_client_data():
    """Initialize client data file if not exists"""
    if not os.path.exists(CLIENT_DATA_FILE):
        with open(CLIENT_DATA_FILE, 'w') as f:
            json.dump({}, f)
    # Initialize TC rules
    subprocess.run(["sudo", SCRIPT_PATH, "create"], check=True)
    # Start monitoring
    start_monitoring()

def get_fresh_traffic_data():
    """Get current traffic statistics from TC"""
    traffic_stats = {
        'connected_devices': 0,
        'total_bandwidth': '0 Mbps',
        'peak_usage': '0 Mbps',
        'usage_percentage': 0
    }
    
    try:
        # Get connected devices count from client data
        clients = read_clients()
        traffic_stats['connected_devices'] = len(clients)
        
        # Get total bandwidth from TC
        tc_output = subprocess.check_output(
            ["tc", "class", "show", "dev", "ens33"],  # استبدل eth0 بإنترفيسك
            stderr=subprocess.STDOUT
        ).decode()
        
        total_bandwidth = 0
        for line in tc_output.splitlines():
            if "rate" in line:
                # استخراج قيمة rate مثل 100Mbit
                rate_str = line.split("rate ")[1].split(" ")[0]
                if 'Mbit' in rate_str:
                    total_bandwidth += float(rate_str.replace('Mbit', ''))
                elif 'Kbit' in rate_str:
                    total_bandwidth += float(rate_str.replace('Kbit', '')) / 1000
        
        # Get current usage from TC
        ifstat_output = subprocess.check_output(
            ["ifstat", "-i", "ens33", "-q", "1", "1"],
            stderr=subprocess.STDOUT
        ).decode().splitlines()
        
        if len(ifstat_output) > 2:
            # القيمة الثانية هي Download، الثالثة Upload
            download = float(ifstat_output[2].split()[0])
            upload = float(ifstat_output[2].split()[1])
            current_usage = download + upload  # بالكيلوبت/ثانية
            
            # تحويل إلى ميجابت/ثانية
            current_usage_mbps = current_usage / 1000
            usage_percent = min(100, int((current_usage_mbps / total_bandwidth) * 100))
        else:
            current_usage_mbps = 0
            usage_percent = 0
        
        traffic_stats.update({
            'total_bandwidth': f'{total_bandwidth:.1f} Mbps',
            'peak_usage': f'{current_usage_mbps:.1f} Mbps',
            'usage_percentage': usage_percent
        })
        
        return True, traffic_stats
        
    except Exception as e:
        print(f"Error getting traffic data: {e}")
        return False, traffic_stats

# Call sync on startup after apply_iptables_rules is defined
@lru_cache(maxsize=1)


def get_mac_stats():
    conn = sqlite3.connect('security.db')
    c = conn.cursor()
    c.execute("""
        SELECT 
            COUNT(*) as total,
            SUM(CASE WHEN DATE(timestamp) = DATE('now') THEN 1 ELSE 0 END) as today
        FROM blocked_mac
    """)
    stats = c.fetchone()
    conn.close()
    return {'blocked_count': stats[0], 'new_today': stats[1]}

def parse_suricata_logs():
    alerts = []
    try:
        with open('/var/log/suricata/eve.json', 'r') as f:
            for line in f:
                try:
                    alert = json.loads(line)
                    if alert.get('event_type') == 'alert':
                        alerts.append({
                            "timestamp": alert.get('timestamp', ''),
                            "signature": alert.get('alert', {}).get('signature', ''),
                            "classification": alert.get('alert', {}).get('classification', ''),
                            "priority": str(alert.get('alert', {}).get('priority', '3')),
                            "src_ip": alert.get('src_ip', ''),
                            "src_port": str(alert.get('src_port', '')),
                            "dest_ip": alert.get('dest_ip', ''),
                            "dest_port": str(alert.get('dest_port', '')),
                            "protocol": alert.get('proto', '')
                        })
                except json.JSONDecodeError:
                    continue
    except FileNotFoundError:
        alerts = [{
            "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            "signature": "Sample Alert - File not found",
            "classification": "Testing",
            "priority": "3",
            "src_ip": "0.0.0.0",
            "src_port": "0",
            "dest_ip": "0.0.0.0",
            "dest_port": "0",
            "protocol": "TCP"
        }]
    except Exception as e:
        print(f"Error reading Suricata logs: {e}")
    return alerts

# Routes
@app.route('/')
def index():
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    
    if username in users and check_password_hash(users[username]['password'], password):
        user = User(username)
        login_user(user)
        return redirect(url_for('dashboard'))
    else:
        flash('Invalid username or password', 'error')
        return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():


    mac_stats = get_mac_stats()
    alerts = parse_suricata_logs()
    
    # Get traffic stats (handle failure case)
    success, traffic_stats = get_fresh_traffic_data()
    if not success:
        flash('Could not load traffic statistics', 'warning')

    ai_stats = {
        'total_alerts': 0,
        'malicious': 0,
        'high_confidence': 0
    }
    
    try:
        with open('/home/ubuntu/project/ai_alerts.json', 'r') as f:
            ai_alerts = json.load(f)
            ai_stats['total_alerts'] = len(ai_alerts)
            ai_stats['malicious'] = sum(1 for alert in ai_alerts if alert.get('prediction') == 1)
            ai_stats['high_confidence'] = sum(1 for alert in ai_alerts if alert.get('ai_confidence', 0) >= 0.9)
    except Exception as e:
        print(f"Error loading AI stats: {e}")
        flash('Could not load AI detection data', 'warning')

    return render_template(
        'dashboard.html',
        current_user=current_user.id,
        blocked_count=mac_stats.get('blocked_count', 0),
        new_today=mac_stats.get('new_today', 0),
        suricata_stats={
            'total_alerts': len(alerts),
            'critical_alerts': len([a for a in alerts if a.get('priority') == '1'])
        },
        traffic_stats=traffic_stats,
        ai_stats=ai_stats,
        firewall_status=get_firewall_status(),
        firewall_rules_count=get_active_rules_count(),
        chains_info=get_chains_info(),
        rules_file_path=IPTABLES_SCRIPT,
        services=get_services_directly()
    )

@app.route('/mac-management')
@login_required
def mac_management():
    page = request.args.get('page', 1, type=int)
    per_page = 10
    
    conn = sqlite3.connect('security.db')
    c = conn.cursor()
    
    c.execute("SELECT COUNT(*) FROM blocked_mac")
    total = c.fetchone()[0]
    
    c.execute("""
        SELECT * FROM blocked_mac 
        ORDER BY timestamp DESC 
        LIMIT ? OFFSET ?
    """, (per_page, (page-1)*per_page))
    
    mac_list = c.fetchall()
    conn.close()
    
    return render_template('mac_management.html',
                         mac_list=mac_list,
                         page=page,
                         per_page=per_page,
                         total=total)

@app.route('/block-mac', methods=['POST'])
@login_required
def block_mac_route():
    mac = request.form['mac'].strip().upper()
    reason = request.form.get('reason', 'Manual block')
    mac = normalize_mac(mac)
    
    if not is_valid_mac(mac):
        flash('Invalid MAC format', 'danger')
        return redirect(url_for('mac_management'))
    
    try:
        conn = sqlite3.connect('security.db')
        c = conn.cursor()
        
        c.execute("SELECT 1 FROM blocked_mac WHERE mac=?", (mac,))
        if c.fetchone():
            flash('This MAC is already blocked', 'warning')
            return redirect(url_for('mac_management'))
        
        c.execute("INSERT INTO blocked_mac (mac, reason) VALUES (?, ?)", (mac, reason))
        conn.commit()
        
        apply_iptables_rules(mac, 'block')
        
        flash(f'Successfully blocked MAC: {mac}', 'success')
    except Exception as e:
        conn.rollback()
        flash(f'Failed to block MAC: {str(e)}', 'danger')
    finally:
        conn.close()
    
    return redirect(url_for('mac_management'))

@app.route('/unblock-mac', methods=['POST'])
@login_required
def unblock_mac_route():
    mac = request.form['mac'].strip().upper()
    mac = normalize_mac(mac)
    
    try:
        apply_iptables_rules(mac, 'unblock')
        
        conn = sqlite3.connect('security.db')
        c = conn.cursor()
        c.execute("DELETE FROM blocked_mac WHERE mac=?", (mac,))
        conn.commit()
        conn.close()
        
        flash(f'MAC address {mac} unblocked successfully!', 'success')
    except Exception as e:
        flash(f'Failed to unblock MAC address {mac}: {str(e)}', 'danger')
    
    return redirect(url_for('mac_management'))

@app.route('/api/check-mac/<mac>')
@login_required
def check_mac_status(mac):
    try:
        mac = normalize_mac(mac)
        conn = sqlite3.connect('security.db')
        c = conn.cursor()
        c.execute("SELECT 1 FROM blocked_mac WHERE mac=?", (mac,))
        is_blocked = c.fetchone() is not None
        conn.close()
        
        return jsonify({
            'mac': mac,
            'is_blocked': is_blocked,
            'status': 'blocked' if is_blocked else 'allowed'
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/iptables-rules')
@login_required
def api_iptables_rules():
    mac = request.args.get('mac', '')
    try:
        result = subprocess.run(
            ['sudo', 'iptables', '-L', '-n', '-v', '--line-numbers'],
            capture_output=True, text=True, check=True
        )
        rules = [line for line in result.stdout.split('\n') if mac.lower() in line.lower()]
        return jsonify({'rules': '\n'.join(rules)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/iptables-rules')
@login_required
def iptables_rules():
    try:
        result = subprocess.run(
            ['sudo', 'iptables', '-L', '-n', '-v'],
            capture_output=True,
            text=True,
            check=True
        )
        rules = result.stdout
    except Exception as e:
        rules = str(e)
    return render_template('iptables_rules.html', 
                        current_user=current_user.id,
                        rules=rules)

@app.route('/firewall-management')
@login_required
def firewall_management():
    return render_template(
        'iptables_management.html',
        firewall_status=get_firewall_status(),
        active_rules_count=get_active_rules_count(),
        chains_info=get_chains_info(),
        rules_file_path=IPTABLES_SCRIPT,
        services=get_services_directly()  # Now returns dynamic services
    )

# Update the toggle function for better error handling
@app.route('/toggle_firewall', methods=['POST'])
@login_required
def toggle_firewall():
    try:
        result = subprocess.run(
            ['sudo', IPTABLES_SCRIPT, 'toggle'],
            capture_output=True,
            text=True,
            check=True,
            timeout=30  # Prevent hanging
        )
        flash(f"Firewall toggled successfully: {result.stdout}", "success")
    except subprocess.CalledProcessError as e:
        flash(f"Error toggling firewall: {e.stderr}", "danger")
    except subprocess.TimeoutExpired:
        flash("Firewall toggle timed out. System may be unstable.", "danger")
    return redirect(url_for('firewall_management'))


@app.route('/suricata')
@login_required
def suricata_management():
    alerts = []
    log_path = '/var/log/suricata/eve.json'
    
    if os.path.exists(log_path):
        try:
            with open(log_path, 'r') as f:
                lines = f.readlines()[-100:]
                for line in lines:
                    try:
                        entry = json.loads(line)
                        if entry.get('event_type') == 'alert':
                            alerts.append({
                                'timestamp': entry.get('timestamp', 'N/A'),
                                'signature': entry.get('alert', {}).get('signature', 'No alert message'),
                                'src_ip': entry.get('src_ip', '0.0.0.0'),
                                'dest_ip': entry.get('dest_ip', '0.0.0.0'),
                                'priority': str(entry.get('alert', {}).get('severity', '3'))
                            })
                    except json.JSONDecodeError:
                        continue
        except Exception as e:
            flash(f'Error reading Suricata logs: {str(e)}', 'error')
    else:
        flash('Suricata log file not found', 'warning')
        alerts = [{
            'timestamp': datetime.now().strftime('%Y-%m-%dT%H:%M:%S.%fZ'),
            'signature': 'Sample Alert - Log file not found',
            'src_ip': '0.0.0.0',
            'dest_ip': '0.0.0.0',
            'priority': '3'
        }]

    return render_template('suricata_management.html', alerts=alerts)

@app.route('/ai-detection')
@login_required
def ai_detection():
    alerts = []
    file_path = '/home/ubuntu/project/ai_alerts.json'
    
    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
            for alert in data:
                alerts.append({
                    'timestamp': alert.get('timestamp', 'N/A'),
                    'src_ip': alert.get('src_ip', '0.0.0.0'),
                    'dest_ip': alert.get('dest_ip', '0.0.0.0'),
                    'proto': alert.get('proto', 'N/A'),
                    'signature': alert.get('signature', 'No signature'),
                    'severity': alert.get('severity', 3),
                    'ai_confidence': alert.get('ai_confidence', 0),
                    'prediction': alert.get('prediction', 0)
                })
    except FileNotFoundError:
        flash('AI alerts file not found!', 'error')
    except json.JSONDecodeError:
        flash('Invalid JSON format in AI alerts file!', 'error')
    except Exception as e:
        flash(f'Error loading AI data: {str(e)}', 'error')
    
    return render_template('ai_detection.html', ai_alerts=alerts)


@app.route("/traffic-control")
@login_required
def traffic_control():
    success, traffic_stats = get_fresh_traffic_data()
    if not success:
        traffic_stats = {
            'connected_devices': 0,
            'total_bandwidth': '0 Mbps',
            'usage_percentage': 0
        }

    return render_template("traffic_control.html", traffic_stats=traffic_stats)


@app.route("/clients", methods=["GET"])
@login_required
def clients():
    data = read_clients()
    return jsonify(list(data.keys()))

@app.route("/usage/<client_ip>", methods=["GET"])
@login_required
def usage(client_ip):
    data = read_clients()
    client = data.get(client_ip)
    if not client:
        return jsonify({"error": "Client not found"}), 404
    return jsonify({
        "usage_mb": client.get("usage_mb", 0),
        "quota_limit_mb": client.get("quota_limit_mb", 0),
        "quota_exceeded": client.get("quota_exceeded", False)
    })


@app.route('/usage/stats')
@login_required
def usage_stats():
    success, traffic_stats = get_fresh_traffic_data()
    if not success:
        return jsonify({'error': 'Could not load traffic stats'}), 500
    
    return jsonify({
        'connected_devices': traffic_stats['connected_devices'],
        'total_bandwidth': traffic_stats['total_bandwidth'],
        'usage_percentage': traffic_stats['usage_percentage']
    })

@app.route("/set_quota", methods=["POST"])
@login_required
def set_quota():
    content = request.json
    client_ip = content.get("client_ip")
    rate = content.get("rate")
    ceil = content.get("ceil")
    quota_mb = content.get("quota_mb", 100)

    if not all([client_ip, rate, ceil]):
        return jsonify({"error": "Missing fields"}), 400

    try:
        subprocess.check_output([
            "sudo", SCRIPT_PATH, "add_client", client_ip, rate, ceil, str(quota_mb)
        ], stderr=subprocess.STDOUT)
        return jsonify({"status": "success"})
    except subprocess.CalledProcessError as e:
        return jsonify({"error": f"Failed to set quota: {e.output.decode()}"}), 500

@app.route("/reset_quota", methods=["POST"])
@login_required
def reset_quota():
    content = request.json
    client_ip = content.get("client_ip")
    if not client_ip:
        return jsonify({"error": "Missing client_ip"}), 400

    try:
        subprocess.check_output([
            "sudo", SCRIPT_PATH, "reset_quota", client_ip
        ], stderr=subprocess.STDOUT)
        return jsonify({"status": "success"})
    except subprocess.CalledProcessError as e:
        return jsonify({"error": f"Failed to reset quota: {e.output.decode()}"}), 500


@app.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

if __name__ == '__main__':
    # Initialize database and other necessary setup
    init_db()
    init_client_data()  # This will initialize traffic control   
    app.run(host='0.0.0.0', port=8080, debug=True)
