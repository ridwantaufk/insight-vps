import customtkinter as ctk
from tkinter import messagebox
import subprocess
import threading
import time
import sys
import re
import json
from datetime import datetime

# ==============================================================================
#                      KONFIGURASI UTAMA
# ==============================================================================
SSH_ALIAS = "vps"  # Pastikan nama ini ada di C:\Users\User\.ssh\config
REFRESH_RATE = 3   # Detik (Jangan terlalu cepat agar CPU tidak naik)
# ==============================================================================

# --- Setup CustomTkinter Theme ---
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("dark-blue")

# --- Warna Cyberpunk/Modern ---
COLORS = {
    "bg_dark": "#0d1117",
    "bg_card": "#161b22",
    "bg_hover": "#21262d",
    "accent_blue": "#58a6ff",
    "accent_green": "#2ea043",
    "accent_red": "#f85149",
    "accent_orange": "#d29922",
    "text_main": "#c9d1d9",
    "text_dim": "#8b949e",
    "border": "#30363d"
}

class Tooltip:
    """Tooltip Class untuk memberikan info saat hover"""
    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tooltip = None
        self.widget.bind("<Enter>", self.show)
        self.widget.bind("<Leave>", self.hide)

    def show(self, event=None):
        if self.tooltip: return
        x = self.widget.winfo_rootx() + 20
        y = self.widget.winfo_rooty() + self.widget.winfo_height() + 5
        self.tooltip = ctk.CTkToplevel(self.widget)
        self.tooltip.wm_overrideredirect(True)
        self.tooltip.wm_geometry(f"+{x}+{y}")
        frame = ctk.CTkFrame(self.tooltip, fg_color=COLORS["bg_hover"], corner_radius=6, border_width=1, border_color=COLORS["border"])
        frame.pack()
        label = ctk.CTkLabel(frame, text=self.text, text_color=COLORS["text_main"], font=("Segoe UI", 10))
        label.pack(padx=8, pady=4)
        self.tooltip.attributes('-topmost', True)

    def hide(self, event=None):
        if self.tooltip:
            self.tooltip.destroy()
            self.tooltip = None

class VPSMonitorApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        # --- Window Config ---
        self.title("VPS Sentinel Pro")
        self.compact_geo = "280x700"
        self.expanded_geo = "1100x750"
        self.geometry(self.compact_geo)
        
        # --- States ---
        self.is_expanded = False
        self.is_running = True
        self.connection_status = "Disconnected"
        self.vps_ip = "Unknown"
        self.last_compact_pos = None
        
        # --- Data Cache ---
        self.data = {
            "cpu": 0.0, "ram_used": 0, "ram_total": 0, "disk_pct": 0,
            "uptime": "-", "load": "-",
            "attackers": [], # List of (count, ip)
            "processes": [], # List of process dicts
            "logs": [],
            "ports": [],
            "cron": [],
            "net_rx": 0, "net_tx": 0
        }

        # --- Init UI ---
        self.setup_compact_ui()
        
        # --- Start Backend ---
        self.monitor_thread = threading.Thread(target=self.backend_loop, daemon=True)
        self.monitor_thread.start()

    # ==========================================================================
    #                           BACKEND LOGIC (SSH)
    # ==========================================================================

    def run_ssh_command(self, command, timeout=10):
        """Menjalankan perintah SSH dengan penanganan error yang kuat"""
        try:
            full_cmd = f'ssh -o ConnectTimeout={timeout} -o StrictHostKeyChecking=no {SSH_ALIAS} "{command}"'
            # Di Windows, creationflags=0x08000000 menyembunyikan window CMD popup
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            
            result = subprocess.run(
                full_cmd, 
                shell=True, 
                capture_output=True, 
                text=True, 
                timeout=timeout + 5,
                encoding='utf-8', 
                errors='ignore',
                startupinfo=startupinfo
            )
            return result.stdout.strip()
        except Exception as e:
            print(f"SSH Error: {e}")
            return None

    def execute_action(self, action_type, target):
        """Fungsi untuk mengambil tindakan (Block IP / Kill PID)"""
        cmd = ""
        confirm_msg = ""
        
        if action_type == "BLOCK_IP":
            # Menggunakan UFW untuk memblokir IP
            cmd = f"sudo ufw insert 1 deny from {target} to any"
            confirm_msg = f"Are you sure you want to PERMANENTLY BLOCK IP: {target}?"
        
        elif action_type == "KILL_PID":
            cmd = f"sudo kill -9 {target}"
            confirm_msg = f"Are you sure you want to FORCE KILL Process ID: {target}?"

        # Konfirmasi User
        if not messagebox.askyesno("Confirm Action", confirm_msg):
            return

        # Eksekusi
        self.run_ssh_command(cmd)
        
        # Refresh Data Instan
        self.fetch_vps_data() 
        messagebox.showinfo("Success", f"Action {action_type} on {target} executed.")

    def backend_loop(self):
        """Loop utama pengambilan data"""
        while self.is_running:
            # 1. Cek Koneksi & IP (Ping Ringan)
            ip_check = self.run_ssh_command("hostname -I | awk '{print $1}'", timeout=5)
            
            if ip_check:
                self.connection_status = "Connected"
                self.vps_ip = ip_check
                self.fetch_vps_data()
            else:
                self.connection_status = "Disconnected"
                
            self.update_ui()
            time.sleep(REFRESH_RATE)

    def fetch_vps_data(self):
        """
        Mengambil SEMUA data dalam SATU koneksi SSH (One-Liner) 
        untuk efisiensi maksimal dan mencegah timeout.
        """
        # Command One-Liner Raksasa (Dipisahkan oleh ;)
        # Menggunakan base64 atau format khusus agar parsing mudah
        
        cmd = (
            "export LC_ALL=C; "
            
            # 1. CPU & RAM
            "echo '---SYS---'; "
            "top -bn1 | grep 'Cpu(s)'; "
            "free -m; "
            
            # 2. DISK & UPTIME
            "echo '---DISKUP---'; "
            "df -h / | tail -n1; "
            "uptime -p; "
            "uptime; " # for load average
            
            # 3. NETWORK (RX/TX)
            "echo '---NET---'; "
            "cat /proc/net/dev | grep -E 'eth0|ens|enp' | head -n1; "
            
            # 4. TOP PROCESSES (With Full Path for suspicion check)
            "echo '---PROC---'; "
            "ps -eo pid,ppid,user,%cpu,%mem,cmd --sort=-%cpu | head -n 11; "
            
            # 5. SECURITY - ATTACKERS (Parsing auth.log / journalctl)
            "echo '---ATTACK---'; "
            # Coba journalctl dulu (systemd), kalau gagal coba auth.log klasik
            "sudo journalctl -u ssh -n 200 --no-pager | grep 'Failed password' | grep -oP 'from \K[\d\.]+' | sort | uniq -c | sort -nr | head -n 10 || "
            "grep 'Failed password' /var/log/auth.log | grep -oP 'from \K[\d\.]+' | sort | uniq -c | sort -nr | head -n 10; "
            
            # 6. SECURITY - ACTIVE PORTS
            "echo '---PORTS---'; "
            "sudo ss -tulnp | grep LISTEN; "
            
            # 7. SECURITY - CRON JOBS (User + System)
            "echo '---CRON---'; "
            "crontab -l 2>/dev/null; "
            "ls -1 /etc/cron.d/ 2>/dev/null; "
            
            # 8. LOG SNIPPET
            "echo '---LOGS---'; "
            "sudo tail -n 10 /var/log/auth.log 2>/dev/null || sudo journalctl -n 10 --no-pager; "
        )

        raw_out = self.run_ssh_command(cmd, timeout=15)
        if not raw_out: return

        try:
            # --- PARSING LOGIC ---
            sections = raw_out.split('---')
            
            # Helper untuk cari section
            def get_sec(key):
                for s in sections:
                    if s.startswith(key):
                        return s.replace(key + "---\n", "").strip()
                return ""

            # 1. SYS
            sys_raw = get_sec("SYS")
            if sys_raw:
                cpu_line = [x for x in sys_raw.split('\n') if "Cpu" in x][0]
                cpu_vals = re.findall(r'[\d.]+', cpu_line.replace(',', '.'))
                self.data['cpu'] = float(cpu_vals[0]) + float(cpu_vals[1])
                
                ram_line = [x for x in sys_raw.split('\n') if "Mem:" in x][0].split()
                self.data['ram_total'] = int(ram_line[1])
                self.data['ram_used'] = int(ram_line[2])

            # 2. DISK & UP
            disk_raw = get_sec("DISKUP").split('\n')
            if len(disk_raw) >= 3:
                self.data['disk_pct'] = int(disk_raw[0].split()[4].replace('%', ''))
                self.data['uptime'] = disk_raw[1].replace('up ', '')
                self.data['load'] = disk_raw[2].split('average:')[-1].strip()

            # 3. NET
            net_raw = get_sec("NET")
            if net_raw:
                parts = net_raw.split()
                # Simple parsing, might vary by distro
                rx = int(parts[1])
                tx = int(parts[9])
                self.data['net_rx'] = round(rx / 1024 / 1024, 2) # MB
                self.data['net_tx'] = round(tx / 1024 / 1024, 2) # MB

            # 4. PROC
            proc_raw = get_sec("PROC").split('\n')[1:] # Skip header
            self.data['processes'] = []
            for line in proc_raw:
                parts = line.split(None, 5) # Split max 5 times to keep CMD intact
                if len(parts) == 6:
                    self.data['processes'].append({
                        'pid': parts[0],
                        'user': parts[2],
                        'cpu': parts[3],
                        'mem': parts[4],
                        'cmd': parts[5]
                    })

            # 5. ATTACK
            attack_raw = get_sec("ATTACK").split('\n')
            self.data['attackers'] = []
            for line in attack_raw:
                parts = line.strip().split()
                if len(parts) == 2:
                    self.data['attackers'].append({'count': parts[0], 'ip': parts[1]})

            # 6. PORTS
            self.data['ports'] = get_sec("PORTS").split('\n')

            # 7. CRON
            self.data['cron'] = get_sec("CRON").split('\n')

            # 8. LOGS
            self.data['logs'] = get_sec("LOGS").split('\n')

        except Exception as e:
            print(f"Parsing Error: {e}")

    # ==========================================================================
    #                           UI CONSTRUCTION
    # ==========================================================================

    def setup_compact_ui(self):
        """Membuat Tampilan Widget Kecil"""
        self.overrideredirect(True)
        self.attributes('-topmost', True)
        self.attributes('-alpha', 0.95)

        # Main Container
        self.compact_frame = ctk.CTkFrame(self, fg_color=COLORS["bg_card"], corner_radius=15, border_width=1, border_color=COLORS["border"])
        self.compact_frame.pack(fill="both", expand=True, padx=2, pady=2)

        # Header (Drag Handle)
        header = ctk.CTkFrame(self.compact_frame, fg_color="transparent", height=30)
        header.pack(fill="x", padx=10, pady=(10, 5))
        header.bind("<Button-1>", self.start_drag)
        header.bind("<B1-Motion>", self.do_drag)
        
        ctk.CTkLabel(header, text="SERVER STATUS", font=("Segoe UI", 12, "bold"), text_color=COLORS["accent_blue"]).pack(side="left")
        
        # Expand Button
        ctk.CTkButton(header, text="⤢", width=25, height=25, fg_color=COLORS["bg_hover"], 
                      command=self.toggle_mode).pack(side="right", padx=2)
        # Close Button
        ctk.CTkButton(header, text="✕", width=25, height=25, fg_color=COLORS["bg_hover"], hover_color=COLORS["accent_red"],
                      command=self.quit_app).pack(side="right")

        # Status Line
        self.compact_status_lbl = ctk.CTkLabel(self.compact_frame, text="Disconnected", font=("Segoe UI", 10), text_color=COLORS["text_dim"])
        self.compact_status_lbl.pack(pady=(0, 10))

        # Metrics (CPU, RAM, DISK)
        self.metric_widgets = {}
        for name, color in [("CPU", COLORS["accent_blue"]), ("RAM", COLORS["accent_green"]), ("DISK", COLORS["accent_orange"])]:
            f = ctk.CTkFrame(self.compact_frame, fg_color="transparent")
            f.pack(fill="x", padx=15, pady=2)
            
            top = ctk.CTkFrame(f, fg_color="transparent")
            top.pack(fill="x")
            ctk.CTkLabel(top, text=name, font=("Segoe UI", 10, "bold"), text_color=COLORS["text_main"]).pack(side="left")
            val = ctk.CTkLabel(top, text="0%", font=("Segoe UI", 10, "bold"), text_color=color)
            val.pack(side="right")
            
            bar = ctk.CTkProgressBar(f, height=6, progress_color=color)
            bar.pack(fill="x", pady=(2, 5))
            bar.set(0)
            
            self.metric_widgets[name] = (val, bar)

        # Security Alert Box (Compact)
        alert_box = ctk.CTkFrame(self.compact_frame, fg_color=COLORS["bg_dark"], corner_radius=8)
        alert_box.pack(fill="x", padx=15, pady=15)
        ctk.CTkLabel(alert_box, text="THREAT LEVEL", font=("Segoe UI", 10, "bold"), text_color=COLORS["accent_red"]).pack(pady=(5,0))
        self.compact_threat_lbl = ctk.CTkLabel(alert_box, text="Low", font=("Segoe UI", 14, "bold"), text_color=COLORS["accent_green"])
        self.compact_threat_lbl.pack(pady=(0,5))

    def setup_expanded_ui(self):
        """Membuat Tampilan Dashboard Lengkap"""
        self.overrideredirect(False) # Use Windows native frame
        self.attributes('-topmost', False)
        self.attributes('-alpha', 1.0)
        
        # Reset Content
        for widget in self.winfo_children():
            widget.destroy()

        # --- HEADER ---
        header = ctk.CTkFrame(self, fg_color=COLORS["bg_card"], height=60, corner_radius=0)
        header.pack(fill="x")
        
        title_frame = ctk.CTkFrame(header, fg_color="transparent")
        title_frame.pack(side="left", padx=20, pady=10)
        ctk.CTkLabel(title_frame, text="VPS SENTINEL PRO", font=("Segoe UI", 20, "bold"), text_color=COLORS["accent_blue"]).pack(anchor="w")
        self.dash_ip_lbl = ctk.CTkLabel(title_frame, text=f"Target: {self.vps_ip} | Status: {self.connection_status}", font=("Segoe UI", 12), text_color=COLORS["text_dim"])
        self.dash_ip_lbl.pack(anchor="w")

        # Compact Button
        ctk.CTkButton(header, text="Switch to Widget", command=self.toggle_mode, fg_color=COLORS["bg_hover"]).pack(side="right", padx=20)

        # --- TABVIEW ---
        self.tabs = ctk.CTkTabview(self, fg_color=COLORS["bg_dark"])
        self.tabs.pack(fill="both", expand=True, padx=10, pady=10)
        
        self.tabs.add("Overview")
        self.tabs.add("Threats & Actions")
        self.tabs.add("Processes")
        self.tabs.add("Logs & Cron")

        self.build_overview_tab(self.tabs.tab("Overview"))
        self.build_threats_tab(self.tabs.tab("Threats & Actions"))
        self.build_process_tab(self.tabs.tab("Processes"))
        self.build_logs_tab(self.tabs.tab("Logs & Cron"))

    # --- TAB BUILDERS ---

    def build_overview_tab(self, parent):
        # Grid System
        parent.grid_columnconfigure((0,1,2), weight=1)
        
        # Helper Card
        def make_card(row, col, title, icon, color):
            frame = ctk.CTkFrame(parent, fg_color=COLORS["bg_card"], corner_radius=10)
            frame.grid(row=row, column=col, padx=10, pady=10, sticky="nsew")
            ctk.CTkLabel(frame, text=f"{icon} {title}", font=("Segoe UI", 12, "bold"), text_color=COLORS["text_dim"]).pack(pady=(15,5))
            val = ctk.CTkLabel(frame, text="---", font=("Segoe UI", 24, "bold"), text_color=color)
            val.pack(pady=(0, 15))
            return val

        self.card_cpu = make_card(0, 0, "CPU Load", "⚡", COLORS["accent_blue"])
        self.card_ram = make_card(0, 1, "RAM Usage", "💾", COLORS["accent_green"])
        self.card_disk = make_card(0, 2, "Disk Usage", "💿", COLORS["accent_orange"])
        self.card_net = make_card(1, 0, "Network Traffic", "🌐", COLORS["accent_purple"])
        self.card_uptime = make_card(1, 1, "System Uptime", "⏱️", COLORS["text_main"])
        self.card_load = make_card(1, 2, "Load Avg (1m)", "📊", COLORS["text_main"])

    def build_threats_tab(self, parent):
        # 2 Columns: Attackers (Left), Action Panel (Right)
        parent.grid_columnconfigure(0, weight=2)
        parent.grid_columnconfigure(1, weight=1)
        parent.grid_rowconfigure(0, weight=1)

        # --- Left: Attacker List ---
        left_frame = ctk.CTkFrame(parent, fg_color=COLORS["bg_card"])
        left_frame.grid(row=0, column=0, padx=5, pady=5, sticky="nsew")
        
        ctk.CTkLabel(left_frame, text="🚨 TOP FAILED LOGIN ATTEMPTS (Brute Force)", font=("Segoe UI", 14, "bold"), text_color=COLORS["accent_red"]).pack(pady=10)
        
        # Scrollable list for attackers
        self.attacker_scroll = ctk.CTkScrollableFrame(left_frame, fg_color="transparent")
        self.attacker_scroll.pack(fill="both", expand=True, padx=5, pady=5)
        # (Content filled in update_ui)

        # --- Right: Network Security ---
        right_frame = ctk.CTkFrame(parent, fg_color=COLORS["bg_card"])
        right_frame.grid(row=0, column=1, padx=5, pady=5, sticky="nsew")
        
        ctk.CTkLabel(right_frame, text="🛡️ ACTIVE PORTS & FIREWALL", font=("Segoe UI", 12, "bold")).pack(pady=10)
        self.txt_ports = ctk.CTkTextbox(right_frame, font=("Consolas", 11))
        self.txt_ports.pack(fill="both", expand=True, padx=5, pady=5)

    def build_process_tab(self, parent):
        # Header
        head = ctk.CTkFrame(parent, height=30, fg_color=COLORS["bg_hover"])
        head.pack(fill="x", padx=5, pady=5)
        cols = ["PID", "USER", "CPU%", "MEM%", "COMMAND", "ACTION"]
        for i, c in enumerate(cols):
            ctk.CTkLabel(head, text=c, font=("Consolas", 11, "bold"), width=80 if i < 4 else 300).pack(side="left", padx=5)

        # List
        self.proc_scroll = ctk.CTkScrollableFrame(parent, fg_color="transparent")
        self.proc_scroll.pack(fill="both", expand=True, padx=5, pady=5)

    def build_logs_tab(self, parent):
        parent.grid_columnconfigure(0, weight=1)
        parent.grid_rowconfigure(0, weight=1)
        parent.grid_rowconfigure(1, weight=1)

        # Logs
        f1 = ctk.CTkFrame(parent, fg_color=COLORS["bg_card"])
        f1.grid(row=0, column=0, padx=5, pady=5, sticky="nsew")
        ctk.CTkLabel(f1, text="📜 SYSTEM LOGS (Auth & Journal)", font=("Segoe UI", 12, "bold")).pack(pady=5)
        self.txt_logs = ctk.CTkTextbox(f1, font=("Consolas", 10), wrap="none")
        self.txt_logs.pack(fill="both", expand=True, padx=5, pady=5)

        # Cron
        f2 = ctk.CTkFrame(parent, fg_color=COLORS["bg_card"])
        f2.grid(row=1, column=0, padx=5, pady=5, sticky="nsew")
        ctk.CTkLabel(f2, text="⏰ CRON JOBS (Potential Persistence)", font=("Segoe UI", 12, "bold")).pack(pady=5)
        self.txt_cron = ctk.CTkTextbox(f2, font=("Consolas", 10), wrap="none")
        self.txt_cron.pack(fill="both", expand=True, padx=5, pady=5)

    # ==========================================================================
    #                           UI UPDATER
    # ==========================================================================

    def update_ui(self):
        """Memperbarui data UI dari self.data"""
        
        # Update Connection Status Global
        color = COLORS["accent_green"] if self.connection_status == "Connected" else COLORS["accent_red"]
        
        if not self.is_expanded:
            # --- Compact Mode Updates ---
            self.compact_status_lbl.configure(text=self.connection_status, text_color=color)
            
            self.metric_widgets["CPU"][0].configure(text=f"{self.data['cpu']:.1f}%")
            self.metric_widgets["CPU"][1].set(self.data['cpu'] / 100)
            
            ram_pct = (self.data['ram_used'] / self.data['ram_total']) if self.data['ram_total'] > 0 else 0
            self.metric_widgets["RAM"][0].configure(text=f"{self.data['ram_used']}MB")
            self.metric_widgets["RAM"][1].set(ram_pct)
            
            self.metric_widgets["DISK"][0].configure(text=f"{self.data['disk_pct']}%")
            self.metric_widgets["DISK"][1].set(self.data['disk_pct'] / 100)

            # Update Threat Level
            attacker_count = len(self.data['attackers'])
            if attacker_count > 5:
                self.compact_threat_lbl.configure(text="HIGH", text_color=COLORS["accent_red"])
            elif attacker_count > 0:
                self.compact_threat_lbl.configure(text="MODERATE", text_color=COLORS["accent_orange"])
            else:
                self.compact_threat_lbl.configure(text="LOW", text_color=COLORS["accent_green"])

        else:
            # --- Expanded Mode Updates ---
            self.dash_ip_lbl.configure(text=f"Target: {self.vps_ip} | Status: {self.connection_status}", text_color=color)
            
            # Overview Cards
            self.card_cpu.configure(text=f"{self.data['cpu']:.1f}%")
            self.card_ram.configure(text=f"{self.data['ram_used']}/{self.data['ram_total']} MB")
            self.card_disk.configure(text=f"{self.data['disk_pct']}%")
            self.card_net.configure(text=f"⬇{self.data['net_rx']} / ⬆{self.data['net_tx']} MB")
            self.card_uptime.configure(text=self.data['uptime'])
            self.card_load.configure(text=self.data['load'])

            # --- Update Threat List (Smart Refresh) ---
            # Hapus list lama
            for widget in self.attacker_scroll.winfo_children():
                widget.destroy()
            
            if not self.data['attackers']:
                ctk.CTkLabel(self.attacker_scroll, text="No active threats detected. Safe.", text_color=COLORS["accent_green"]).pack(pady=20)
            
            for item in self.data['attackers']:
                row = ctk.CTkFrame(self.attacker_scroll, fg_color=COLORS["bg_hover"])
                row.pack(fill="x", pady=2, padx=5)
                
                info_text = f"IP: {item['ip']} | Attempts: {item['count']}"
                ctk.CTkLabel(row, text=info_text, font=("Consolas", 12), width=300, anchor="w").pack(side="left", padx=10)
                
                # ACTION BUTTON: BLOCK IP
                btn = ctk.CTkButton(row, text="🚫 BLOCK IP", width=80, height=24, fg_color=COLORS["accent_red"], 
                                    command=lambda ip=item['ip']: self.execute_action("BLOCK_IP", ip))
                btn.pack(side="right", padx=5, pady=5)

            # --- Update Process List (Smart Refresh) ---
            for widget in self.proc_scroll.winfo_children():
                widget.destroy()
            
            for proc in self.data['processes']:
                row = ctk.CTkFrame(self.proc_scroll, fg_color="transparent")
                row.pack(fill="x", pady=1)
                
                # Highlight suspicious processes (running from /tmp or hidden)
                text_col = COLORS["text_main"]
                if "/tmp" in proc['cmd'] or "/." in proc['cmd']:
                    text_col = COLORS["accent_red"]
                
                ctk.CTkLabel(row, text=proc['pid'], width=80, font=("Consolas", 11), text_color=text_col).pack(side="left")
                ctk.CTkLabel(row, text=proc['user'], width=80, font=("Consolas", 11), text_color=text_col).pack(side="left")
                ctk.CTkLabel(row, text=proc['cpu'], width=80, font=("Consolas", 11), text_color=text_col).pack(side="left")
                ctk.CTkLabel(row, text=proc['mem'], width=80, font=("Consolas", 11), text_color=text_col).pack(side="left")
                ctk.CTkLabel(row, text=proc['cmd'][:40], width=300, anchor="w", font=("Consolas", 11), text_color=text_col).pack(side="left")
                
                # ACTION BUTTON: KILL
                btn = ctk.CTkButton(row, text="💀 KILL", width=60, height=20, fg_color=COLORS["bg_card"], hover_color=COLORS["accent_red"],
                                    command=lambda pid=proc['pid']: self.execute_action("KILL_PID", pid))
                btn.pack(side="right", padx=5)

            # --- Text Logs Updates ---
            self.txt_logs.delete("0.0", "end")
            self.txt_logs.insert("0.0", "\n".join(self.data['logs']))
            
            self.txt_ports.delete("0.0", "end")
            self.txt_ports.insert("0.0", "\n".join(self.data['ports']))
            
            self.txt_cron.delete("0.0", "end")
            self.txt_cron.insert("0.0", "\n".join(self.data['cron']))

    # ==========================================================================
    #                           WINDOW UTILS
    # ==========================================================================

    def toggle_mode(self):
        self.is_expanded = not self.is_expanded
        if self.is_expanded:
            self.last_compact_pos = f"+{self.winfo_x()}+{self.winfo_y()}"
            self.setup_expanded_ui()
            self.geometry(self.expanded_geo)
            self.center_window()
        else:
            self.setup_compact_ui()
            self.geometry(self.compact_geo)
            if self.last_compact_pos:
                self.geometry(f"{self.compact_geo}{self.last_compact_pos}")

    def center_window(self):
        self.update_idletasks()
        sw = self.winfo_screenwidth()
        sh = self.winfo_screenheight()
        w = self.winfo_width()
        h = self.winfo_height()
        x = (sw - w) // 2
        y = (sh - h) // 2
        self.geometry(f'{w}x{h}+{x}+{y}')

    def start_drag(self, e):
        self.is_dragging = True
        self.x_drag, self.y_drag = e.x, e.y

    def do_drag(self, e):
        if self.is_dragging and not self.is_expanded:
            x = self.winfo_x() + (e.x - self.x_drag)
            y = self.winfo_y() + (e.y - self.y_drag)
            self.geometry(f"+{x}+{y}")

    def stop_drag(self, e):
        self.is_dragging = False

    def quit_app(self):
        self.is_running = False
        self.destroy()
        sys.exit()

def main():
    app = VPSMonitorApp()
    app.mainloop()

if __name__ == "__main__":
    main()