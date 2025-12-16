import customtkinter as ctk
import subprocess
import threading
import time
import sys
import re
from datetime import datetime

# ==============================================================================
#                      KONFIGURASI
# ==============================================================================
SSH_ALIAS = "vps"  # Pastikan ini sesuai dengan ~/.ssh/config Anda
# ==============================================================================

class Tooltip:
    """Tooltip sederhana untuk info tambahan"""
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
        label = ctk.CTkLabel(self.tooltip, text=self.text, fg_color="#1e1e2e", 
                            corner_radius=8, padx=10, pady=5, font=("Segoe UI", 9))
        label.pack()
        self.tooltip.attributes('-topmost', True)
    
    def hide(self, event=None):
        if self.tooltip:
            self.tooltip.destroy()
            self.tooltip = None

class VPSSecurityMonitor(ctk.CTk):
    def __init__(self, ssh_alias):
        super().__init__()
        
        # --- Config ---
        self.ssh_alias = ssh_alias
        self.vps_ip = "Unknown"
        
        # --- State ---
        self.is_ip_blurred = True
        self.is_expanded = False
        self.running = True
        self.is_dragging = False
        self.is_maximized = False
        self.connection_ok = False
        
        # --- Window Settings ---
        self.blurred_ip = "•••.•••.•••.•••"
        self.snap_threshold = 25
        self.edge_snap = None
        self.is_hidden = False
        self.after_id = None
        self.last_compact_pos = None
        
        # Ukuran Window
        self.compact_geo = "260x680"
        self.expanded_geo = "1000x700"

        # --- Data Storage ---
        self.security_data = {
            'ports': [], 'suspicious_processes': [], 'cronjobs': [], 'last_logins': [], 
            'firewall_status': '---', 'updates_available': 0, 'disk_usage': {}, 
            'network_connections': [], 'active_services': [], 'failed_logins': [],
            'docker_containers': [], 'ssl_certs': [],
            'top_attackers': [], 'realtime_visitors': []
        }
        self.last_cpu = 0
        self.last_ram_used = 0
        self.last_ram_total = 0
        self.last_ram_pct = 0
        self.last_proc_list = []
        self.last_uptime = "---"
        self.last_load_avg = "---"
        self.last_swap_used = 0
        self.last_swap_total = 0
        self.network_stats = {'rx': 0, 'tx': 0}

        # --- Init Window ---
        self.title("VPS Security Monitor")
        self.geometry(self.compact_geo)
        
        # Colors (Dracula/Cyberpunk Theme)
        self.bg_primary = "#0a0a0f"
        self.bg_secondary = "#151520"
        self.bg_tertiary = "#1e1e2e"
        self.accent_blue = "#4a9eff"
        self.accent_green = "#26c281"
        self.accent_red = "#ff4757"
        self.accent_orange = "#ffa502"
        self.accent_purple = "#a55eea"
        self.text_primary = "#e4e4e7"
        self.text_secondary = "#a1a1aa"

        # Start UI
        self._create_compact_ui()
        
        # Start Threads
        threading.Thread(target=self.main_loop, daemon=True).start()

    # ==========================================================================
    #                               UI MANAGEMENT
    # ==========================================================================
    
    def _create_compact_ui(self):
        """UI Mode Widget (Frameless, Always on Top)"""
        self.overrideredirect(True) # Frameless
        self.attributes('-topmost', True)
        self.attributes('-alpha', 0.96)
        
        # Container Utama
        self.compact_container = ctk.CTkFrame(self, corner_radius=16, fg_color=self.bg_secondary, border_width=1, border_color="#2a2a3a")
        self.compact_container.pack(fill="both", expand=True, padx=2, pady=2)
        
        # Header (Drag Area)
        header = ctk.CTkFrame(self.compact_container, fg_color="transparent", height=40)
        header.pack(fill="x", padx=12, pady=(12, 8))
        header.pack_propagate(False)
        header.bind("<Button-1>", self.start_drag)
        header.bind("<B1-Motion>", self.do_drag)
        header.bind("<ButtonRelease-1>", self.stop_drag)
        
        # IP Label
        self.lbl_ip = ctk.CTkLabel(header, text=f"🛡️ {self.blurred_ip}", font=("Segoe UI Semibold", 12), text_color=self.accent_blue)
        self.lbl_ip.pack(side="left")
        self.lbl_ip.bind("<Button-1>", self.toggle_ip_blur)
        
        # Expand Button
        btn_expand = ctk.CTkButton(header, text="⤢", width=30, height=30, fg_color=self.bg_tertiary, hover_color=self.accent_blue, command=self.toggle_expand)
        btn_expand.pack(side="right", padx=(5,0))
        
        # Close Button
        btn_close = ctk.CTkButton(header, text="✕", width=30, height=30, fg_color=self.bg_tertiary, hover_color=self.accent_red, command=self.quit_app)
        btn_close.pack(side="right")
        
        # Status
        self.lbl_status = ctk.CTkLabel(self.compact_container, text="🔄 Connecting...", font=("Segoe UI", 10), text_color=self.text_secondary)
        self.lbl_status.pack(pady=(0, 10))

        # --- SYSTEM METRICS (Compact) ---
        stats_frame = ctk.CTkFrame(self.compact_container, fg_color=self.bg_tertiary, corner_radius=12)
        stats_frame.pack(fill="x", padx=12, pady=5)
        
        # Helper untuk progress bar
        def add_metric(parent, label, color):
            f = ctk.CTkFrame(parent, fg_color="transparent")
            f.pack(fill="x", padx=10, pady=5)
            l_frame = ctk.CTkFrame(f, fg_color="transparent")
            l_frame.pack(fill="x")
            ctk.CTkLabel(l_frame, text=label, font=("Segoe UI", 9, "bold"), text_color=self.text_secondary).pack(side="left")
            val_lbl = ctk.CTkLabel(l_frame, text="---", font=("Segoe UI", 9, "bold"), text_color=color)
            val_lbl.pack(side="right")
            prog = ctk.CTkProgressBar(f, height=5, progress_color=color)
            prog.pack(fill="x", pady=(2,0))
            prog.set(0)
            return val_lbl, prog

        self.lbl_cpu, self.prog_cpu = add_metric(stats_frame, "CPU", self.accent_blue)
        self.lbl_ram, self.prog_ram = add_metric(stats_frame, "RAM", self.accent_green)
        self.lbl_disk, self.prog_disk = add_metric(stats_frame, "DISK", self.accent_orange)
        
        # --- THREATS SUMMARY ---
        threat_frame = ctk.CTkFrame(self.compact_container, fg_color=self.bg_tertiary, corner_radius=12)
        threat_frame.pack(fill="x", padx=12, pady=10)
        ctk.CTkLabel(threat_frame, text="ALERT SUMMARY", font=("Segoe UI", 10, "bold"), text_color=self.accent_red).pack(pady=5)
        
        self.lbl_failed_login = ctk.CTkLabel(threat_frame, text="Failed Logins: 0", font=("Segoe UI", 10))
        self.lbl_failed_login.pack()
        self.lbl_suspicious = ctk.CTkLabel(threat_frame, text="Suspect Procs: 0", font=("Segoe UI", 10))
        self.lbl_suspicious.pack(pady=(0,5))

        # --- PROCESS LIST ---
        proc_frame = ctk.CTkFrame(self.compact_container, fg_color=self.bg_tertiary, corner_radius=12)
        proc_frame.pack(fill="both", expand=True, padx=12, pady=(0, 12))
        ctk.CTkLabel(proc_frame, text="TOP PROCESSES", font=("Segoe UI", 10, "bold"), text_color=self.text_primary).pack(pady=5)
        
        self.txt_proc = ctk.CTkTextbox(proc_frame, font=("Consolas", 9), fg_color="transparent", text_color=self.text_primary, wrap="none")
        self.txt_proc.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Hover events
        self.compact_container.bind("<Enter>", self.on_enter)
        self.compact_container.bind("<Leave>", self.on_leave)

    def _create_expanded_ui(self):
        """UI Mode Dashboard (Normal Window, Resizable)"""
        # --- PENTING: Mengembalikan Frame Window Asli Windows 11 ---
        self.overrideredirect(False) 
        self.attributes('-topmost', False) # Tidak always on top biar tidak ganggu
        self.attributes('-alpha', 1.0)
        
        # Container Tab
        self.tab_view = ctk.CTkTabview(self, fg_color=self.bg_primary)
        self.tab_view.pack(fill="both", expand=True, padx=10, pady=10)
        
        self.tab_view.add("Overview")
        self.tab_view.add("Threats & Logs") # Tab Baru
        self.tab_view.add("Network & Ports")
        self.tab_view.add("Services")

        # --- Header Control (Tombol kembali ke compact) ---
        btn_back = ctk.CTkButton(self, text="Switch to Widget Mode 📉", command=self.toggle_expand, 
                                 fg_color=self.bg_tertiary, hover_color=self.accent_blue)
        btn_back.place(relx=0.98, rely=0.02, anchor="ne")

        # --- TAB 1: OVERVIEW ---
        ov_tab = self.tab_view.tab("Overview")
        
        # Info Box
        info_frame = ctk.CTkFrame(ov_tab, fg_color=self.bg_secondary)
        info_frame.pack(fill="x", pady=10)
        
        self.lbl_exp_ip = ctk.CTkLabel(info_frame, text=f"Connected to: {self.vps_ip}", font=("Segoe UI", 16, "bold"))
        self.lbl_exp_ip.pack(pady=10)
        
        # Grid Stats
        grid_frame = ctk.CTkFrame(ov_tab, fg_color="transparent")
        grid_frame.pack(fill="both", expand=True)
        
        def make_card(parent, title, val_var, r, c):
            card = ctk.CTkFrame(parent, fg_color=self.bg_tertiary)
            card.grid(row=r, column=c, padx=5, pady=5, sticky="nsew")
            ctk.CTkLabel(card, text=title, font=("Segoe UI", 12)).pack(pady=(10,5))
            lbl = ctk.CTkLabel(card, text="---", font=("Segoe UI", 20, "bold"), text_color=self.accent_blue)
            lbl.pack(pady=(0,10))
            setattr(self, val_var, lbl)
            parent.grid_columnconfigure(c, weight=1)

        make_card(grid_frame, "CPU Usage", "lbl_exp_cpu", 0, 0)
        make_card(grid_frame, "RAM Usage", "lbl_exp_ram", 0, 1)
        make_card(grid_frame, "Disk Usage", "lbl_exp_disk", 0, 2)
        make_card(grid_frame, "Load Average", "lbl_exp_load", 1, 0)
        make_card(grid_frame, "Uptime", "lbl_exp_uptime", 1, 1)
        make_card(grid_frame, "Net Traffic", "lbl_exp_net", 1, 2)

        # --- TAB 2: THREATS & LOGS (NEW INSIGHTS) ---
        threat_tab = self.tab_view.tab("Threats & Logs")
        threat_tab.grid_columnconfigure(0, weight=1)
        threat_tab.grid_columnconfigure(1, weight=1)

        # Kiri: Failed Logins & Attackers
        left_t = ctk.CTkFrame(threat_tab, fg_color=self.bg_secondary)
        left_t.grid(row=0, column=0, padx=5, pady=5, sticky="nsew")
        ctk.CTkLabel(left_t, text="🚨 TOP ATTACKERS (Failed SSH Logins)", font=("Consolas", 14, "bold"), text_color=self.accent_red).pack(pady=10)
        self.txt_attackers = ctk.CTkTextbox(left_t, font=("Consolas", 11))
        self.txt_attackers.pack(fill="both", expand=True, padx=10, pady=10)

        # Kanan: Realtime Visitors
        right_t = ctk.CTkFrame(threat_tab, fg_color=self.bg_secondary)
        right_t.grid(row=0, column=1, padx=5, pady=5, sticky="nsew")
        ctk.CTkLabel(right_t, text="👀 REALTIME VISITORS (Active Conn)", font=("Consolas", 14, "bold"), text_color=self.accent_green).pack(pady=10)
        self.txt_visitors = ctk.CTkTextbox(right_t, font=("Consolas", 11))
        self.txt_visitors.pack(fill="both", expand=True, padx=10, pady=10)

        # Bawah: Log Cuplikan
        bot_t = ctk.CTkFrame(threat_tab, fg_color=self.bg_secondary)
        bot_t.grid(row=1, column=0, columnspan=2, padx=5, pady=5, sticky="nsew")
        ctk.CTkLabel(bot_t, text="📜 SYSTEM LOG SNIPPET (Auth & Errors)", font=("Consolas", 12)).pack(pady=5)
        self.txt_logs = ctk.CTkTextbox(bot_t, height=150, font=("Consolas", 10))
        self.txt_logs.pack(fill="both", expand=True, padx=10, pady=5)

        # --- TAB 3: NETWORK ---
        net_tab = self.tab_view.tab("Network & Ports")
        self.txt_ports = ctk.CTkTextbox(net_tab, font=("Consolas", 11))
        self.txt_ports.pack(fill="both", expand=True, padx=10, pady=10)

        # --- TAB 4: SERVICES ---
        srv_tab = self.tab_view.tab("Services")
        self.txt_services = ctk.CTkTextbox(srv_tab, font=("Consolas", 11))
        self.txt_services.pack(fill="both", expand=True, padx=10, pady=10)

        # Force Update
        self.update_ui_data()

    # ==========================================================================
    #                             LOGIC & DATA FETCHING
    # ==========================================================================
    
    def toggle_expand(self):
        """Switch antara Widget Mode dan Window Mode"""
        self.is_expanded = not self.is_expanded
        
        if self.is_expanded:
            # Simpan posisi widget
            self.last_compact_pos = f"+{self.winfo_x()}+{self.winfo_y()}"
            
            # Hapus UI Compact
            for widget in self.winfo_children():
                widget.destroy()
                
            # Buat UI Expanded
            self._create_expanded_ui()
            self.geometry(self.expanded_geo)
            self.center_window()
        else:
            # Hapus UI Expanded
            for widget in self.winfo_children():
                widget.destroy()
            
            # Buat UI Compact
            self._create_compact_ui()
            self.geometry(self.compact_geo)
            if self.last_compact_pos:
                self.geometry(f"{self.compact_geo}{self.last_compact_pos}")

    def run_ssh_command(self, command):
        """Eksekusi perintah SSH dengan teknik One-Liner (Anti-Gagal Windows)"""
        try:
            full_cmd = f'ssh -o StrictHostKeyChecking=no {self.ssh_alias} "{command}"'
            result = subprocess.run(
                full_cmd, shell=True, capture_output=True, text=True,
                timeout=15, encoding='utf-8', errors='ignore'
            )
            return result.stdout.strip()
        except Exception as e:
            print(f"SSH Error: {e}")
            return ""

    def main_loop(self):
        """Looping utama pengambilan data"""
        iter_count = 0
        while self.running:
            if not self.connection_ok:
                if self.test_connection():
                    self.connection_ok = True
                else:
                    time.sleep(5)
                    continue

            # Ambil data
            self.fetch_all_data()
            
            # Update GUI
            self.after(0, self.update_ui_data)
            
            time.sleep(2)
            iter_count += 1

    def test_connection(self):
        out = self.run_ssh_command("echo OK")
        if "OK" in out:
            # Get IP
            self.vps_ip = self.run_ssh_command("hostname -I | awk '{print $1}'")
            return True
        return False

    def fetch_all_data(self):
        """Mengambil SEMUA data dalam satu koneksi agar efisien"""
        
        # --- COMMAND 1: BASIC METRICS (One-Liner) ---
        cmd_basic = (
            "export LC_ALL=C; "
            "echo '---CPU---'; top -bn1 | grep 'Cpu(s)'; "
            "echo '---RAM---'; free -m; "
            "echo '---DISK---'; df -h / | tail -n1; "
            "echo '---UPTIME---'; uptime -p; "
            "echo '---LOAD---'; uptime; "
            "echo '---NET---'; cat /proc/net/dev | grep -E 'eth0|ens|enp'; "
            "echo '---PS---'; ps -eo comm,%cpu,%mem --sort=-%cpu | head -n 8"
        )
        out_basic = self.run_ssh_command(cmd_basic)
        
        # --- COMMAND 2: SECURITY & INSIGHTS (One-Liner) ---
        # Mengambil data penyerang, koneksi aktif, dan log
        cmd_sec = (
            "export LC_ALL=C; "
            "echo '---PORTS---'; sudo ss -tuln | grep LISTEN; "
            "echo '---UFW---'; sudo ufw status 2>/dev/null; "
            "echo '---ATTACKERS---'; "
            "sudo journalctl -u ssh -n 200 --no-pager | grep 'Failed password' | grep -oP 'from \K[\d\.]+' | sort | uniq -c | sort -nr | head -n 10; "
            "echo '---VISITORS---'; "
            "sudo ss -tunap | grep ESTAB | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -nr | head -n 10; "
            "echo '---LOGS---'; "
            "sudo tail -n 15 /var/log/auth.log 2>/dev/null || sudo journalctl -n 15 --no-pager; "
            "echo '---SERVICES---'; systemctl list-units --type=service --state=running | head -n 20"
        )
        out_sec = self.run_ssh_command(cmd_sec)
        
        self.parse_basic(out_basic)
        self.parse_security(out_sec)

    def parse_basic(self, out):
        if not out: return
        try:
            # CPU
            cpu_line = out.split("---CPU---")[1].split("---RAM---")[0]
            vals = re.findall(r'[\d.]+', cpu_line)
            self.last_cpu = float(vals[0]) + float(vals[1]) if len(vals) >= 2 else 0.0
            
            # RAM
            ram_line = out.split("---RAM---")[1].split("---DISK---")[0]
            if "Mem:" in ram_line:
                parts = ram_line.split("Mem:")[1].split()
                self.last_ram_total = int(parts[0])
                self.last_ram_used = int(parts[1])
                self.last_ram_pct = self.last_ram_used / self.last_ram_total
            
            # Disk
            disk_line = out.split("---DISK---")[1].split("---UPTIME---")[0]
            self.security_data['disk_usage']['percentage'] = disk_line.split()[4].replace('%','')
            
            # Process
            self.last_proc_list = out.split("---PS---")[1].strip().split('\n')[1:]
            
            # Uptime & Load
            self.last_uptime = out.split("---UPTIME---")[1].split("---LOAD---")[0].strip()
            self.last_load_avg = out.split("average:")[1].split("---NET---")[0].strip()

        except Exception:
            pass

    def parse_security(self, out):
        if not out: return
        try:
            def get_sec(name): return out.split(f'---{name}---')[1].split('---')[0].strip()
            
            self.security_data['ports'] = get_sec('PORTS').split('\n')
            self.security_data['firewall_status'] = "Active" if "active" in get_sec('UFW').lower() else "Inactive"
            self.security_data['top_attackers'] = get_sec('ATTACKERS').split('\n')
            self.security_data['realtime_visitors'] = get_sec('VISITORS').split('\n')
            self.security_data['logs'] = get_sec('LOGS').split('\n')
            self.security_data['active_services'] = get_sec('SERVICES').split('\n')
            
        except Exception:
            pass

    def update_ui_data(self):
        """Update widget values based on mode"""
        if self.is_expanded:
            # Update Expanded Dashboard
            if hasattr(self, 'lbl_exp_cpu'):
                self.lbl_exp_cpu.configure(text=f"{self.last_cpu:.1f}%")
                self.lbl_exp_ram.configure(text=f"{self.last_ram_used}/{self.last_ram_total} MB")
                self.lbl_exp_disk.configure(text=f"{self.security_data['disk_usage'].get('percentage', 0)}%")
                self.lbl_exp_uptime.configure(text=self.last_uptime)
                self.lbl_exp_load.configure(text=self.last_load_avg.split(',')[0]) # 1m load
                
                # Update Threats Tab
                self.txt_attackers.delete("0.0", "end")
                self.txt_attackers.insert("0.0", "\n".join(self.security_data['top_attackers']))
                
                self.txt_visitors.delete("0.0", "end")
                self.txt_visitors.insert("0.0", "\n".join(self.security_data['realtime_visitors']))
                
                self.txt_logs.delete("0.0", "end")
                self.txt_logs.insert("0.0", "\n".join(self.security_data['logs']))
                
                # Update Network
                self.txt_ports.delete("0.0", "end")
                self.txt_ports.insert("0.0", "\n".join(self.security_data['ports']))
                
                # Services
                self.txt_services.delete("0.0", "end")
                self.txt_services.insert("0.0", "\n".join(self.security_data['active_services']))

        else:
            # Update Compact Widget
            if hasattr(self, 'lbl_cpu'):
                self.lbl_cpu.configure(text=f"{self.last_cpu:.1f}%")
                self.prog_cpu.set(self.last_cpu/100)
                
                self.lbl_ram.configure(text=f"{self.last_ram_used} MB")
                self.prog_ram.set(self.last_ram_pct)
                
                disk_p = float(self.security_data['disk_usage'].get('percentage', 0))
                self.lbl_disk.configure(text=f"{disk_p}%")
                self.prog_disk.set(disk_p/100)
                
                # Update status text
                self.lbl_failed_login.configure(text=f"Attackers Found: {len(self.security_data['top_attackers'])}")
                if len(self.security_data['top_attackers']) > 0:
                    self.lbl_failed_login.configure(text_color=self.accent_red)
                else:
                    self.lbl_failed_login.configure(text_color=self.text_secondary)
                
                # Update Process List
                self.txt_proc.configure(state="normal")
                self.txt_proc.delete("0.0", "end")
                self.txt_proc.insert("0.0", "\n".join(self.last_proc_list[:6]))
                self.txt_proc.configure(state="disabled")

        # Update Connection Status
        if self.connection_ok:
            if hasattr(self, 'lbl_status'): self.lbl_status.configure(text="🟢 Connected", text_color=self.accent_green)
        else:
            if hasattr(self, 'lbl_status'): self.lbl_status.configure(text="🔴 Disconnected", text_color=self.accent_red)

    # ==========================================================================
    #                               UTILS
    # ==========================================================================
    def start_drag(self, e):
        self.is_dragging = True
        self.x, self.y = e.x, e.y
    def stop_drag(self, e):
        self.is_dragging = False
    def do_drag(self, e):
        if self.is_dragging and not self.is_expanded:
            x = self.winfo_x() + (e.x - self.x)
            y = self.winfo_y() + (e.y - self.y)
            self.geometry(f"+{x}+{y}")
    
    def center_window(self):
        self.update_idletasks()
        sw = self.winfo_screenwidth()
        sh = self.winfo_screenheight()
        w = self.winfo_width()
        h = self.winfo_height()
        x = (sw - w) // 2
        y = (sh - h) // 2
        self.geometry(f'{w}x{h}+{x}+{y}')
    
    def toggle_ip_blur(self, e=None):
        self.is_ip_blurred = not self.is_ip_blurred
        ip = self.blurred_ip if self.is_ip_blurred else self.vps_ip
        if hasattr(self, 'lbl_ip'): self.lbl_ip.configure(text=f"🛡️ {ip}")
    
    def on_enter(self, e): pass
    def on_leave(self, e): pass
    
    def quit_app(self):
        self.running = False
        self.destroy()
        sys.exit()

if __name__ == "__main__":
    ctk.set_appearance_mode("Dark")
    ctk.set_default_color_theme("blue")
    app = VPSSecurityMonitor(ssh_alias=SSH_ALIAS)
    app.mainloop()