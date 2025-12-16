import customtkinter as ctk
import subprocess
import threading
import time
import sys
import re
from datetime import datetime

# ==============================================================================
#                      KONFIGURASI - Cukup ketik "ssh vps"
# ==============================================================================
SSH_ALIAS = "vps"  # Sesuaikan dengan alias SSH config Anda
# ==============================================================================

class Tooltip:
    """Tooltip untuk menampilkan info tambahan"""
    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tooltip = None
        self.widget.bind("<Enter>", self.show)
        self.widget.bind("<Leave>", self.hide)
    
    def show(self, event=None):
        if self.tooltip:
            return
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
        
        # --- Window Management ---
        self.blurred_ip = "•••.•••.•••.•••"
        self.snap_threshold = 25
        self.edge_snap = None
        self.is_hidden = False
        self.after_id = None
        self.last_compact_pos = None
        self.last_normal_geometry = None
        self.min_width = 600
        self.min_height = 400

        # --- Data Storage ---
        self.security_data = {
            'ports': [], 'suspicious_processes': [], 'cronjobs': [], 'last_logins': [], 
            'firewall_status': '', 'updates_available': 0, 'disk_usage': {}, 
            'network_connections': [], 'active_services': [], 'failed_logins': [],
            'docker_containers': [], 'ssl_certs': []
        }
        self.last_cpu = 0
        self.last_ram_used = 0
        self.last_ram_total = 0
        self.last_ram_pct = 0
        self.last_ram_available = 0
        self.last_proc_list = []
        self.last_uptime = "---"
        self.last_load_avg = "---"
        self.last_swap_used = 0
        self.last_swap_total = 0
        self.cpu_history = []
        self.ram_history = []
        self.network_stats = {'rx': 0, 'tx': 0}

        # --- Window Setup ---
        self.title("VPS Security Monitor")
        self.geometry("240x680")
        
        # Modern Windows 11 colors
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

        # --- UI Creation ---
        self._create_compact_ui()
        
        # --- Main Loop ---
        threading.Thread(target=self.main_loop, daemon=True).start()

    def _create_compact_ui(self):
        """Compact floating widget view"""
        self.overrideredirect(True)
        self.attributes('-topmost', True)
        self.attributes('-alpha', 0.96)
        
        # Main container with modern styling
        self.compact_container = ctk.CTkFrame(
            self, 
            corner_radius=16, 
            fg_color=self.bg_secondary,
            border_width=1, 
            border_color="#2a2a3a"
        )
        self.compact_container.pack(fill="both", expand=True, padx=2, pady=2)
        
        # Header with drag support
        header = ctk.CTkFrame(self.compact_container, fg_color="transparent", height=40)
        header.pack(fill="x", padx=12, pady=(12, 8))
        header.pack_propagate(False)
        header.bind("<Button-1>", self.start_drag)
        header.bind("<B1-Motion>", self.do_drag)
        header.bind("<ButtonRelease-1>", self.stop_drag)
        
        # IP Label with blur toggle
        self.lbl_ip = ctk.CTkLabel(
            header, 
            text=f"🖥️ {self.blurred_ip}", 
            font=("Segoe UI Semibold", 11), 
            text_color=self.accent_blue
        )
        self.lbl_ip.pack(side="left")
        self.lbl_ip.bind("<Button-1>", self.toggle_ip_blur)
        Tooltip(self.lbl_ip, "Click to show/hide IP")
        
        # Control buttons
        btn_expand = ctk.CTkButton(
            header, text="📊", width=32, height=32, corner_radius=8,
            fg_color=self.bg_tertiary, hover_color=self.accent_blue,
            command=self.toggle_expand, font=("Segoe UI", 14)
        )
        btn_expand.pack(side="right", padx=(5, 0))
        Tooltip(btn_expand, "Expand dashboard")
        
        btn_close = ctk.CTkButton(
            header, text="✕", width=32, height=32, corner_radius=8,
            fg_color=self.bg_tertiary, hover_color=self.accent_red,
            command=self.quit_app, font=("Segoe UI", 12)
        )
        btn_close.pack(side="right")
        Tooltip(btn_close, "Close application")
        
        # Status indicator
        status_frame = ctk.CTkFrame(self.compact_container, fg_color=self.bg_tertiary, corner_radius=10, height=36)
        status_frame.pack(fill="x", padx=12, pady=(0, 8))
        status_frame.pack_propagate(False)
        
        self.lbl_status = ctk.CTkLabel(
            status_frame, text="🔄 Connecting...", 
            font=("Segoe UI", 9), text_color=self.text_secondary
        )
        self.lbl_status.pack(pady=8)
        Tooltip(self.lbl_status, "Connection status")
        
        # System Stats Card
        stats_card = ctk.CTkFrame(self.compact_container, fg_color=self.bg_tertiary, corner_radius=12)
        stats_card.pack(fill="x", padx=12, pady=(0, 8))
        
        ctk.CTkLabel(stats_card, text="⚡ SYSTEM", font=("Segoe UI Semibold", 10), 
                    text_color=self.accent_purple).pack(pady=(10, 8))
        
        # CPU Section
        cpu_frame = ctk.CTkFrame(stats_card, fg_color="transparent")
        cpu_frame.pack(fill="x", padx=10, pady=(0, 8))
        
        cpu_label_frame = ctk.CTkFrame(cpu_frame, fg_color="transparent")
        cpu_label_frame.pack(fill="x")
        ctk.CTkLabel(cpu_label_frame, text="CPU", font=("Segoe UI", 9), 
                    text_color=self.text_secondary).pack(side="left")
        self.lbl_cpu = ctk.CTkLabel(cpu_label_frame, text="---%", 
                                    font=("Segoe UI Semibold", 9), text_color=self.accent_blue)
        self.lbl_cpu.pack(side="right")
        Tooltip(self.lbl_cpu, "CPU usage percentage")
        
        self.prog_cpu = ctk.CTkProgressBar(cpu_frame, height=6, corner_radius=3, 
                                          progress_color=self.accent_blue)
        self.prog_cpu.pack(fill="x", pady=(4, 0))
        self.prog_cpu.set(0)
        
        # RAM Section
        ram_frame = ctk.CTkFrame(stats_card, fg_color="transparent")
        ram_frame.pack(fill="x", padx=10, pady=(0, 8))
        
        ram_label_frame = ctk.CTkFrame(ram_frame, fg_color="transparent")
        ram_label_frame.pack(fill="x")
        ctk.CTkLabel(ram_label_frame, text="RAM", font=("Segoe UI", 9), 
                    text_color=self.text_secondary).pack(side="left")
        self.lbl_ram = ctk.CTkLabel(ram_label_frame, text="--- MB", 
                                   font=("Segoe UI Semibold", 9), text_color=self.accent_green)
        self.lbl_ram.pack(side="right")
        Tooltip(self.lbl_ram, "Memory usage (used/total)")
        
        self.prog_ram = ctk.CTkProgressBar(ram_frame, height=6, corner_radius=3, 
                                          progress_color=self.accent_green)
        self.prog_ram.pack(fill="x", pady=(4, 0))
        self.prog_ram.set(0)
        
        # Disk Section
        disk_frame = ctk.CTkFrame(stats_card, fg_color="transparent")
        disk_frame.pack(fill="x", padx=10, pady=(0, 10))
        
        disk_label_frame = ctk.CTkFrame(disk_frame, fg_color="transparent")
        disk_label_frame.pack(fill="x")
        ctk.CTkLabel(disk_label_frame, text="DISK", font=("Segoe UI", 9), 
                    text_color=self.text_secondary).pack(side="left")
        self.lbl_disk = ctk.CTkLabel(disk_label_frame, text="---%", 
                                    font=("Segoe UI Semibold", 9), text_color=self.accent_orange)
        self.lbl_disk.pack(side="right")
        Tooltip(self.lbl_disk, "Root partition usage")
        
        self.prog_disk = ctk.CTkProgressBar(disk_frame, height=6, corner_radius=3, 
                                           progress_color=self.accent_orange)
        self.prog_disk.pack(fill="x", pady=(4, 0))
        self.prog_disk.set(0)
        
        # Security Card
        sec_card = ctk.CTkFrame(self.compact_container, fg_color=self.bg_tertiary, corner_radius=12)
        sec_card.pack(fill="x", padx=12, pady=(0, 8))
        
        ctk.CTkLabel(sec_card, text="🛡️ SECURITY", font=("Segoe UI Semibold", 10), 
                    text_color=self.accent_red).pack(pady=(10, 8))
        
        self.lbl_ports = ctk.CTkLabel(sec_card, text="Ports: ---", 
                                     font=("Segoe UI", 8), text_color=self.text_secondary)
        self.lbl_ports.pack(pady=2)
        Tooltip(self.lbl_ports, "Number of open ports")
        
        self.lbl_firewall = ctk.CTkLabel(sec_card, text="Firewall: ---", 
                                        font=("Segoe UI", 8), text_color=self.text_secondary)
        self.lbl_firewall.pack(pady=2)
        Tooltip(self.lbl_firewall, "Firewall status (UFW/iptables)")
        
        self.lbl_updates = ctk.CTkLabel(sec_card, text="Updates: ---", 
                                       font=("Segoe UI", 8), text_color=self.text_secondary)
        self.lbl_updates.pack(pady=(2, 10))
        Tooltip(self.lbl_updates, "Available system updates")
        
        # Top Processes Card
        proc_card = ctk.CTkFrame(self.compact_container, fg_color=self.bg_tertiary, corner_radius=12)
        proc_card.pack(fill="both", expand=True, padx=12, pady=(0, 12))
        
        ctk.CTkLabel(proc_card, text="📈 TOP PROCESSES", font=("Segoe UI Semibold", 10), 
                    text_color=self.accent_green).pack(pady=(10, 8))
        
        # Scrollable process list
        self.txt_proc = ctk.CTkTextbox(
            proc_card, font=("Consolas", 8), 
            fg_color="transparent", text_color=self.text_primary,
            wrap="none", activate_scrollbars=True
        )
        self.txt_proc.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        self.txt_proc.configure(state="disabled")
        
        self.bind("<Enter>", self.on_enter)
        self.bind("<Leave>", self.on_leave)

    def _create_expanded_ui(self):
        """Full dashboard view"""
        self.overrideredirect(False)
        self.attributes('-topmost', False)
        self.attributes('-alpha', 0.98)
        self.resizable(True, True)
        self.minsize(self.min_width, self.min_height)
        
        # Create scrollable container
        self.expanded_container = ctk.CTkScrollableFrame(
            self,
            fg_color=self.bg_primary,
            scrollbar_button_color=self.bg_tertiary,
            scrollbar_button_hover_color=self.accent_blue
        )
        self.expanded_container.pack(fill="both", expand=True)
        
        # Header
        header = ctk.CTkFrame(self.expanded_container, fg_color=self.bg_secondary, 
                             corner_radius=12, height=70)
        header.pack(fill="x", padx=15, pady=15)
        header.pack_propagate(False)
        header.bind("<Button-1>", self.start_drag)
        header.bind("<B1-Motion>", self.do_drag)
        
        title_container = ctk.CTkFrame(header, fg_color="transparent")
        title_container.pack(fill="both", expand=True, padx=20, pady=15)
        
        # Title and IP
        title_frame = ctk.CTkFrame(title_container, fg_color="transparent")
        title_frame.pack(side="left", fill="y")
        
        ip_display = self.blurred_ip if self.is_ip_blurred else self.vps_ip
        self.lbl_ip_expanded = ctk.CTkLabel(
            title_frame, 
            text=f"🖥️ VPS Security Dashboard", 
            font=("Segoe UI", 18, "bold"), 
            text_color=self.accent_blue
        )
        self.lbl_ip_expanded.pack(anchor="w")
        
        self.lbl_ip_sub = ctk.CTkLabel(
            title_frame, 
            text=f"Monitoring: {ip_display}", 
            font=("Segoe UI", 11), 
            text_color=self.text_secondary
        )
        self.lbl_ip_sub.pack(anchor="w", pady=(2, 0))
        self.lbl_ip_sub.bind("<Button-1>", self.toggle_ip_blur)
        Tooltip(self.lbl_ip_sub, "Click to show/hide IP")
        
        # Control buttons
        btn_container = ctk.CTkFrame(title_container, fg_color="transparent")
        btn_container.pack(side="right", fill="y")
        
        btn_frame = ctk.CTkFrame(btn_container, fg_color="transparent")
        btn_frame.pack(side="top")
        
        btn_maximize = ctk.CTkButton(
            btn_frame, text="⛶", width=40, height=36, corner_radius=8,
            fg_color=self.bg_tertiary, hover_color=self.accent_purple,
            command=self.toggle_maximize, font=("Segoe UI", 14)
        )
        btn_maximize.pack(side="left", padx=3)
        Tooltip(btn_maximize, "Maximize/Restore")
        
        btn_refresh = ctk.CTkButton(
            btn_frame, text="🔄", width=40, height=36, corner_radius=8,
            fg_color=self.accent_green, hover_color="#1fa86d",
            command=self.force_refresh, font=("Segoe UI", 14)
        )
        btn_refresh.pack(side="left", padx=3)
        Tooltip(btn_refresh, "Force refresh data")
        
        btn_compact = ctk.CTkButton(
            btn_frame, text="📉", width=100, height=36, corner_radius=8,
            fg_color=self.bg_tertiary, hover_color=self.accent_blue,
            command=self.toggle_expand, font=("Segoe UI", 12)
        )
        btn_compact.pack(side="left", padx=3)
        Tooltip(btn_compact, "Switch to compact view")
        
        # Main content area
        content = ctk.CTkFrame(self.expanded_container, fg_color="transparent")
        content.pack(fill="both", expand=True, padx=15, pady=(0, 15))
        
        # Left sidebar - System overview
        left_panel = ctk.CTkFrame(content, fg_color=self.bg_secondary, 
                                 corner_radius=12, width=320)
        left_panel.pack(side="left", fill="y", padx=(0, 10))
        left_panel.pack_propagate(False)
        
        ctk.CTkLabel(left_panel, text="📊 SYSTEM OVERVIEW", 
                    font=("Segoe UI Semibold", 13), 
                    text_color=self.accent_purple).pack(pady=(20, 15))
        
        # Status card
        status_card = ctk.CTkFrame(left_panel, fg_color=self.bg_tertiary, corner_radius=10)
        status_card.pack(fill="x", padx=15, pady=(0, 10))
        
        self.lbl_status_expanded = ctk.CTkLabel(
            status_card, text="🔄 Connecting...", 
            font=("Segoe UI", 10), text_color=self.accent_orange
        )
        self.lbl_status_expanded.pack(pady=12)
        
        # System stats
        stats_container = ctk.CTkFrame(left_panel, fg_color="transparent")
        stats_container.pack(fill="x", padx=15, pady=5)
        
        def create_stat_row(parent, icon, label, value_var_name, color):
            frame = ctk.CTkFrame(parent, fg_color=self.bg_tertiary, corner_radius=8)
            frame.pack(fill="x", pady=4)
            
            left = ctk.CTkFrame(frame, fg_color="transparent")
            left.pack(side="left", fill="y", padx=12, pady=10)
            
            ctk.CTkLabel(left, text=icon, font=("Segoe UI", 16)).pack(side="left")
            ctk.CTkLabel(left, text=label, font=("Segoe UI", 9), 
                        text_color=self.text_secondary).pack(side="left", padx=(8, 0))
            
            value = ctk.CTkLabel(frame, text="---", font=("Segoe UI Semibold", 10), 
                                text_color=color)
            value.pack(side="right", padx=12)
            setattr(self, value_var_name, value)
            return value
        
        cpu_lbl = create_stat_row(stats_container, "⚡", "CPU", "lbl_cpu_exp", self.accent_blue)
        Tooltip(cpu_lbl, "Current CPU usage")
        
        ram_lbl = create_stat_row(stats_container, "💾", "RAM", "lbl_ram_exp", self.accent_green)
        Tooltip(ram_lbl, "Memory: used/total (percentage)")
        
        disk_lbl = create_stat_row(stats_container, "💿", "DISK", "lbl_disk_exp", self.accent_orange)
        Tooltip(disk_lbl, "Root partition usage")
        
        swap_lbl = create_stat_row(stats_container, "🔄", "SWAP", "lbl_swap_exp", self.accent_purple)
        Tooltip(swap_lbl, "Swap memory usage")
        
        load_lbl = create_stat_row(stats_container, "📊", "LOAD", "lbl_load_exp", self.accent_blue)
        Tooltip(load_lbl, "System load average (1m, 5m, 15m)")
        
        uptime_lbl = create_stat_row(stats_container, "⏱️", "UPTIME", "lbl_uptime_exp", self.accent_green)
        Tooltip(uptime_lbl, "Time since last reboot")
        
        net_lbl = create_stat_row(stats_container, "🌐", "NETWORK", "lbl_network_exp", self.accent_purple)
        Tooltip(net_lbl, "Network traffic (RX/TX)")
        
        # Right panel - Tabs
        right_panel = ctk.CTkFrame(content, fg_color="transparent")
        right_panel.pack(side="left", fill="both", expand=True)
        
        # Tab buttons
        tab_frame = ctk.CTkFrame(right_panel, fg_color="transparent")
        tab_frame.pack(fill="x", pady=(0, 10))
        
        self.active_tab = "security"
        self.tab_buttons = {}
        
        tabs = [
            ("🛡️ Security", "security"),
            ("🔌 Ports", "ports"),
            ("⚙️ Processes", "processes"),
            ("⏰ Cron", "cron"),
            ("🌐 Network", "network"),
            ("🐳 Docker", "docker"),
            ("🔐 SSL", "ssl"),
            ("📜 Logs", "logs")
        ]
        
        for text, tab_id in tabs:
            is_active = tab_id == self.active_tab
            btn = ctk.CTkButton(
                tab_frame, text=text, height=38, corner_radius=8,
                fg_color=self.accent_blue if is_active else self.bg_tertiary,
                hover_color=self.accent_blue,
                command=lambda t=tab_id: self.switch_tab(t),
                font=("Segoe UI", 10)
            )
            btn.pack(side="left", padx=3)
            self.tab_buttons[tab_id] = btn
        
        # Tab content area
        self.tab_content = ctk.CTkFrame(right_panel, fg_color=self.bg_secondary, corner_radius=12)
        self.tab_content.pack(fill="both", expand=True)
        
        self.tab_textbox = ctk.CTkTextbox(
            self.tab_content, 
            font=("Consolas", 9), 
            fg_color=self.bg_tertiary, 
            text_color=self.text_primary,
            wrap="none"
        )
        self.tab_textbox.pack(fill="both", expand=True, padx=15, pady=15)
        
        self.update_tab_content()

    def run_ssh_command(self, command):
        """Execute SSH command using subprocess (DEBUG MODE)"""
        try:
            # Tambahkan flag -tt untuk memaksa alokasi pseudo-tty (seringkali memperbaiki output top/sudo)
            # Tapi hati-hati, -tt kadang bikin masalah carriage return (\r). 
            # Kita coba dulu tanpa -tt tapi kita PRINT outputnya.
            full_cmd = f'ssh -o StrictHostKeyChecking=no {self.ssh_alias} "{command}"'
            
            print(f"🔄 Executing: {command[:20]}...") # Print perintah yang jalan
            
            result = subprocess.run(
                full_cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=20,
                encoding='utf-8',
                errors='ignore'
            )
            
            # --- BAGIAN DEBUGGING (PENTING) ---
            if result.returncode != 0:
                print(f"❌ SSH ERROR CODE: {result.returncode}")
                print(f"❌ STDERR: {result.stderr}") # Ini akan memberi tahu kenapa dia gagal!
            
            if not result.stdout.strip():
                print("⚠️  WARNING: Output kosong!")
            # ----------------------------------

            return result.stdout
        except subprocess.TimeoutExpired:
            print("⏱️  SSH command timeout")
            return ""
        except Exception as e:
            print(f"❌ SSH Error: {e}")
            return ""

    def test_connection(self):
        """Test SSH connection"""
        try:
            # Test koneksi dengan command sederhana
            result = subprocess.run(
                f'ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no {self.ssh_alias} "echo OK"',
                shell=True,
                capture_output=True,
                text=True,
                timeout=10
            )
            if "OK" in result.stdout:
                # Get IP address - coba beberapa cara
                ip_result = subprocess.run(
                    f'ssh {self.ssh_alias} "hostname -I 2>/dev/null | awk \'{{print $1}}\' || curl -s ifconfig.me 2>/dev/null || echo Unknown"',
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                self.vps_ip = ip_result.stdout.strip() or "Unknown"
                print(f"✅ Connected to VPS: {self.vps_ip}")
                return True
            print(f"❌ Connection test failed: {result.stderr}")
            return False
        except Exception as e:
            print(f"❌ Connection error: {e}")
            return False

    def toggle_maximize(self):
        """Toggle between maximized and normal window state"""
        if self.is_maximized:
            if self.last_normal_geometry:
                self.geometry(self.last_normal_geometry)
            self.is_maximized = False
        else:
            self.last_normal_geometry = self.geometry()
            sw = self.winfo_screenwidth()
            sh = self.winfo_screenheight()
            self.geometry(f"{sw}x{sh}+0+0")
            self.is_maximized = True

    def center_window(self):
        """Center the window on screen"""
        self.update_idletasks()
        sw = self.winfo_screenwidth()
        sh = self.winfo_screenheight()
        w = self.winfo_width()
        h = self.winfo_height()
        x = (sw - w) // 2
        y = (sh - h) // 2
        self.geometry(f'{w}x{h}+{x}+{y}')

    def switch_tab(self, tab_id):
        """Switch between different tabs"""
        self.active_tab = tab_id
        for tid, btn in self.tab_buttons.items():
            btn.configure(fg_color=self.accent_blue if tid == tab_id else self.bg_tertiary)
        self.update_tab_content()

    def update_tab_content(self):
        """Update tab content based on active tab"""
        if not self.is_expanded:
            return
        
        content = ""
        
        if self.active_tab == "security":
            content = self._format_security_tab()
        elif self.active_tab == "ports":
            content = self._format_ports_tab()
        elif self.active_tab == "processes":
            content = self._format_processes_tab()
        elif self.active_tab == "cron":
            content = self._format_cron_tab()
        elif self.active_tab == "network":
            content = self._format_network_tab()
        elif self.active_tab == "docker":
            content = self._format_docker_tab()
        elif self.active_tab == "ssl":
            content = self._format_ssl_tab()
        elif self.active_tab == "logs":
            content = self._format_logs_tab()
        
        self.tab_textbox.configure(state="normal")
        self.tab_textbox.delete("1.0", "end")
        self.tab_textbox.insert("1.0", content if content else "Loading data...")
        self.tab_textbox.configure(state="disabled")

    def _format_security_tab(self):
        """Format security overview content"""
        content = "═" * 80 + "\n"
        content += "  🛡️  SECURITY OVERVIEW\n"
        content += "═" * 80 + "\n\n"
        
        fw = self.security_data.get('firewall_status', 'Unknown')
        upd = self.security_data.get('updates_available', 0)
        ports = len(self.security_data.get('ports', []))
        
        content += f"🔥 Firewall Status      : {fw}\n"
        content += f"📦 Available Updates    : {upd}\n"
        content += f"🔌 Open Ports           : {ports}\n"
        content += f"👤 Recent Logins        : {len(self.security_data.get('last_logins', []))}\n"
        content += f"⚠️  Failed Login Attempts: {len(self.security_data.get('failed_logins', []))}\n\n"
        
        content += "─" * 80 + "\n"
        content += "  ⚠️  SUSPICIOUS PROCESSES\n"
        content += "─" * 80 + "\n"
        
        susp = self.security_data.get('suspicious_processes', [])
        if susp:
            for proc in susp[:15]:
                content += f"  • {proc}\n"
        else:
            content += "  ✅ No suspicious processes detected\n"
        
        content += "\n" + "─" * 80 + "\n"
        content += "  👤 RECENT LOGIN HISTORY\n"
        content += "─" * 80 + "\n"
        
        logins = self.security_data.get('last_logins', [])
        for login in logins[:10]:
            content += f"  {login}\n"
        
        return content

    def _format_ports_tab(self):
        """Format ports content"""
        content = "═" * 80 + "\n"
        content += "  🔌 OPEN PORTS & LISTENING SERVICES\n"
        content += "═" * 80 + "\n\n"
        
        ports = self.security_data.get('ports', [])
        if ports:
            for port in ports[:40]:
                content += f"  {port}\n"
        else:
            content += "  No open ports detected\n"
        
        return content

    def _format_processes_tab(self):
        """Format processes content"""
        content = "═" * 80 + "\n"
        content += "  ⚙️  TOP PROCESSES BY CPU USAGE\n"
        content += "═" * 80 + "\n\n"
        
        content += f"{'USER':<12} {'PID':<8} {'CPU%':<8} {'MEM%':<8} {'VSZ':<10} {'COMMAND'}\n"
        content += "─" * 80 + "\n"
        
        procs = self.security_data.get('top_processes', [])
        for proc in procs[:30]:
            content += f"{proc}\n"
        
        return content

    def _format_cron_tab(self):
        """Format cron jobs content"""
        content = "═" * 80 + "\n"
        content += "  ⏰ SCHEDULED CRON JOBS\n"
        content += "═" * 80 + "\n\n"
        
        crons = self.security_data.get('cronjobs', [])
        if crons:
            for cron in crons:
                content += f"  {cron}\n"
        else:
            content += "  No cron jobs configured for this user\n"
        
        content += "\n" + "─" * 80 + "\n"
        content += "  💡 TIP: Check system crontabs at /etc/crontab and /etc/cron.d/\n"
        
        return content

    def _format_network_tab(self):
        """Format network connections content"""
        content = "═" * 80 + "\n"
        content += "  🌐 ACTIVE NETWORK CONNECTIONS\n"
        content += "═" * 80 + "\n\n"
        
        content += f"Network Traffic:\n"
        content += f"  RX: {self.network_stats.get('rx', 0)} MB\n"
        content += f"  TX: {self.network_stats.get('tx', 0)} MB\n\n"
        
        content += "─" * 80 + "\n"
        content += "Established Connections:\n"
        content += "─" * 80 + "\n"
        
        conns = self.security_data.get('network_connections', [])
        if conns:
            for conn in conns[:40]:
                content += f"  {conn}\n"
        else:
            content += "  No active connections\n"
        
        return content

    def _format_docker_tab(self):
        """Format Docker containers content"""
        content = "═" * 80 + "\n"
        content += "  🐳 DOCKER CONTAINERS\n"
        content += "═" * 80 + "\n\n"
        
        containers = self.security_data.get('docker_containers', [])
        if containers:
            for container in containers:
                content += f"  {container}\n"
        else:
            content += "  No Docker containers found or Docker not installed\n"
        
        return content

    def _format_ssl_tab(self):
        """Format SSL certificates content"""
        content = "═" * 80 + "\n"
        content += "  🔐 SSL CERTIFICATES\n"
        content += "═" * 80 + "\n\n"
        
        certs = self.security_data.get('ssl_certs', [])
        if certs:
            for cert in certs:
                content += f"  {cert}\n"
        else:
            content += "  No SSL certificates found\n"
            content += "\n  💡 Checking common locations:\n"
            content += "     - /etc/letsencrypt/live/\n"
            content += "     - /etc/ssl/certs/\n"
        
        return content

    def _format_logs_tab(self):
        """Format system logs content"""
        content = "═" * 80 + "\n"
        content += "  📜 RECENT SYSTEM LOGS\n"
        content += "═" * 80 + "\n\n"
        
        content += "Authentication Failures:\n"
        content += "─" * 80 + "\n"
        
        failed = self.security_data.get('failed_logins', [])
        if failed:
            for fail in failed[:20]:
                content += f"  {fail}\n"
        else:
            content += "  No recent failed login attempts\n"
        
        return content

    def toggle_expand(self):
        """Toggle between compact and expanded view"""
        self.is_expanded = not self.is_expanded
        
        self.on_leave(None)
        self.edge_snap = None
        self.is_hidden = False

        if self.is_expanded:
            self.last_compact_pos = f"+{self.winfo_x()}+{self.winfo_y()}"
            
            # Destroy compact UI
            if hasattr(self, 'compact_container'):
                self.compact_container.destroy()
            
            # Create expanded UI
            self._create_expanded_ui()
            self.geometry("950x700")
            self.after(10, self.center_window)
        else:
            # Destroy expanded UI
            if hasattr(self, 'expanded_container'):
                self.expanded_container.destroy()
            
            # Recreate compact UI
            self._create_compact_ui()
            
            self.overrideredirect(True)
            if self.last_compact_pos:
                self.geometry(f"240x680{self.last_compact_pos}")
            else:
                self.geometry("240x680")
            
            self.attributes('-topmost', True)
        
        self.update_ui_with_latest_data()

    def update_ui_with_latest_data(self):
        """Force update UI with latest cached data"""
        if self.is_expanded:
            self.update_expanded_ui(
                self.last_cpu, self.last_ram_used, self.last_ram_total,
                self.security_data.get('disk_usage', {}).get('percentage', '0'),
                self.last_uptime
            )
        else:
            self.update_compact_ui(
                self.last_cpu, self.last_ram_used, self.last_ram_total,
                self.last_ram_pct, self.last_proc_list
            )
        self.update_security_ui()
        
        # Update status
        if hasattr(self, 'lbl_status'):
            status_text = self.lbl_status.cget('text')
            status_color = self.lbl_status.cget('text_color')
            self.update_status(status_text, status_color)

    def toggle_ip_blur(self, e=None):
        """Toggle IP address visibility"""
        self.is_ip_blurred = not self.is_ip_blurred
        ip = self.blurred_ip if self.is_ip_blurred else self.vps_ip
        
        if self.is_expanded:
            if hasattr(self, 'lbl_ip_sub'):
                self.lbl_ip_sub.configure(text=f"Monitoring: {ip}")
        else:
            if hasattr(self, 'lbl_ip'):
                self.lbl_ip.configure(text=f"🖥️ {ip}")

    # --- Drag and Window Management ---
    def start_drag(self, e):
        self.is_dragging = True
        self.x, self.y = e.x, e.y
        if self.edge_snap:
            self.show_widget()
        self.edge_snap = None
        self.is_hidden = False
        self.on_leave(None)

    def stop_drag(self, e):
        self.is_dragging = False
        if not self.is_expanded:
            self.snap_to_edge()

    def do_drag(self, e):
        if not self.is_dragging:
            return
        
        x_new = self.winfo_pointerx() - self.x
        y_new = self.winfo_pointery() - self.y
        
        sw = self.winfo_screenwidth()
        sh = self.winfo_screenheight()
        w = self.winfo_width()
        h = self.winfo_height()
        
        x_new = max(0, min(x_new, sw - w))
        y_new = max(0, min(y_new, sh - h))
        
        self.geometry(f"+{x_new}+{y_new}")

    def snap_to_edge(self):
        """Snap widget to screen edge"""
        if self.is_expanded or self.is_dragging:
            return
        
        sw = self.winfo_screenwidth()
        x = self.winfo_x()
        w = self.winfo_width()

        if x < self.snap_threshold:
            self.edge_snap = "left"
        elif x + w > sw - self.snap_threshold:
            self.edge_snap = "right"
        else:
            self.edge_snap = None
            return

        self.hide_widget()

    def hide_widget(self):
        """Hide widget at screen edge"""
        if not self.edge_snap or self.is_hidden:
            return
        
        self.is_hidden = True
        y = self.winfo_y()
        hide_offset = 20
        
        if self.edge_snap == "left":
            self.geometry(f"+{-self.winfo_width() + hide_offset}+{y}")
        elif self.edge_snap == "right":
            self.geometry(f"+{self.winfo_screenwidth() - hide_offset}+{y}")

    def show_widget(self):
        """Show widget from screen edge"""
        if not self.edge_snap or not self.is_hidden:
            return
        
        self.is_hidden = False
        y = self.winfo_y()
        
        if self.edge_snap == "left":
            self.geometry(f"+0+{y}")
        elif self.edge_snap == "right":
            self.geometry(f"+{self.winfo_screenwidth() - self.winfo_width()}+{y}")

    def on_enter(self, e):
        """Mouse enter event"""
        if self.after_id:
            self.after_cancel(self.after_id)
            self.after_id = None
        if self.edge_snap and self.is_hidden:
            self.show_widget()

    def on_leave(self, e):
        """Mouse leave event"""
        if self.after_id:
            self.after_cancel(self.after_id)
        if self.edge_snap and not self.is_hidden:
            self.after_id = self.after(500, self.hide_widget)

    def quit_app(self):
        """Close application"""
        self.running = False
        self.destroy()
        sys.exit()

    # --- Main Loop and Data Fetching ---
    def main_loop(self):
        """Main monitoring loop"""
        iteration = 0
        
        while self.running:
            if not self.connection_ok:
                self.after(0, self.update_status, "🟡 Connecting...", self.accent_orange)
                if self.test_connection():
                    self.connection_ok = True
                    self.after(0, self.update_status, "🟢 Connected", self.accent_green)
                else:
                    self.after(0, self.update_status, "🔴 Connection Failed", self.accent_red)
                    time.sleep(10)
                    continue
            
            # Fetch basic data every cycle
            self.fetch_basic_data()
            
            # Fetch security data every 30 seconds
            if iteration % 15 == 0:
                self.fetch_security_data()
            
            # Fetch extended data every 60 seconds
            if iteration % 30 == 0:
                self.fetch_extended_data()
            
            iteration += 1
            time.sleep(2)

    def fetch_basic_data(self):
        """Fetch basic system metrics (FIXED: ONE-LINER COMMAND)"""
        try:
            # KITA UBAH JADI SATU BARIS MEMANJANG AGAR WINDOWS TIDAK BINGUNG
            # Gunakan path lengkap (/usr/bin/...) untuk keamanan
            cmd = (
                "export LC_ALL=C; "  # Paksa bahasa Inggris agar angka pakai titik
                "export TERM=xterm; "
                "echo '---CPU---'; "
                "/usr/bin/top -bn1 | grep 'Cpu(s)' || echo '0.0'; "
                "echo '---RAM---'; "
                "/usr/bin/free -m || echo 'Mem: 0 0 0 0 0 0 0'; "
                "echo '---DISK---'; "
                "/usr/bin/df -h / | tail -n1 || echo '/ 0G 0G 0G 0% /'; "
                "echo '---UPTIME---'; "
                "/usr/bin/uptime -p || echo 'unknown'; "
                "echo '---LOAD---'; "
                "/usr/bin/uptime | awk -F'load average:' '{print $2}' || echo '0.00, 0.00, 0.00'; "
                "echo '---SWAP---'; "
                "/usr/bin/free -m | grep Swap || echo 'Swap: 0 0 0'; "
                "echo '---NET---'; "
                "cat /proc/net/dev | grep -E 'eth0|ens|enp|wlan' | head -n1 || echo 'eth0: 0 0 0 0 0 0 0 0 0 0'; "
                "echo '---PS---'; "
                "ps -eo comm,%cpu,%mem --sort=-%cpu | head -n 8 || echo 'COMMAND %CPU %MEM'; "
                "echo '---END---'"
            )
            
            out = self.run_ssh_command(cmd)
            
            # --- DEBUGGING SEMENTARA (Boleh dihapus nanti) ---
            if not out:
                print("⚠️ DEBUG: Data Basic Kosong!")
            # -----------------------------------------------

            if not out:
                self.connection_ok = False
                return
            
            # ... (SISA KODE PARSING DI BAWAH INI SAMA SEPERTI SEBELUMNYA, JANGAN DIUBAH) ...
            # Parse CPU
            try:
                # Ambil bagian CPU
                part_cpu = out.split("---CPU---")[1].split("---RAM---")[0].strip()
                # Hapus kata-kata, sisakan angka dan titik
                cpu_clean = part_cpu.replace(',', '.') 
                cpu_vals = re.findall(r'[\d.]+', cpu_clean)
                # Ambil 2 angka pertama (user + system)
                cpu = float(cpu_vals[0]) + float(cpu_vals[1]) if len(cpu_vals) >= 2 else 0.0
            except:
                cpu = 0.0
            
            # Parse RAM
            try:
                ram_sec = out.split("---RAM---")[1].split("---DISK---")[0].strip()
                ram_lines = ram_sec.split('\n')
                ram_data = None
                for line in ram_lines:
                    if 'Mem:' in line:
                        ram_data = line.split()
                        break
                
                if ram_data and len(ram_data) >= 7:
                    ram_total = int(ram_data[1])
                    ram_used = int(ram_data[2])
                    ram_available = int(ram_data[6])
                    ram_pct = ram_used / ram_total if ram_total > 0 else 0
                else:
                    ram_total = ram_used = ram_available = 0
                    ram_pct = 0.0
            except:
                ram_total = ram_used = ram_available = 0
                ram_pct = 0.0
            
            # Parse Disk
            try:
                disk_sec = out.split("---DISK---")[1].split("---UPTIME---")[0].strip().split()
                disk_pct = disk_sec[4].replace('%', '') if len(disk_sec) > 4 else "0"
            except:
                disk_pct = "0"
            
            # Parse Uptime
            try:
                uptime_sec = out.split("---UPTIME---")[1].split("---LOAD---")[0].strip().replace('up ', '')
            except:
                uptime_sec = "unknown"
            
            # Parse Load Average
            try:
                load_sec = out.split("---LOAD---")[1].split("---SWAP---")[0].strip()
            except:
                load_sec = "0.00, 0.00, 0.00"
            
            # Parse Swap
            try:
                swap_sec = out.split("---SWAP---")[1].split("---NET---")[0].strip()
                swap_data = swap_sec.split()
                swap_total = int(swap_data[1]) if len(swap_data) > 1 else 0
                swap_used = int(swap_data[2]) if len(swap_data) > 2 else 0
            except:
                swap_total = swap_used = 0
            
            # Parse Network
            try:
                net_sec = out.split("---NET---")[1].split("---PS---")[0].strip()
                if net_sec:
                    net_parts = net_sec.split()
                    if len(net_parts) >= 10:
                        rx_bytes = int(net_parts[1])
                        tx_bytes = int(net_parts[9])
                        self.network_stats = {
                            'rx': round(rx_bytes / 1024 / 1024, 2),
                            'tx': round(tx_bytes / 1024 / 1024, 2)
                        }
            except:
                pass
            
            # Parse Processes
            try:
                ps_sec = out.split("---PS---")[1].split("---END---")[0].strip().split('\n')[1:]
                proc_list = [l.strip() for l in ps_sec if l.strip()]
            except:
                proc_list = []
            
            # Update cache
            self.last_cpu = cpu
            self.last_ram_used = ram_used
            self.last_ram_total = ram_total
            self.last_ram_available = ram_available
            self.last_ram_pct = ram_pct
            self.last_proc_list = proc_list
            self.last_uptime = uptime_sec
            self.last_load_avg = load_sec.strip()
            self.last_swap_used = swap_used
            self.last_swap_total = swap_total
            
            self.security_data['disk_usage'] = {'percentage': disk_pct}
            
            # Update history
            self.cpu_history.append(cpu)
            self.ram_history.append(ram_pct * 100)
            if len(self.cpu_history) > 60:
                self.cpu_history.pop(0)
            if len(self.ram_history) > 60:
                self.ram_history.pop(0)
            
            self.after(0, self.update_ui_with_latest_data)
            
        except Exception as e:
            print(f"Error fetching basic data: {e}")
            self.connection_ok = False

    def fetch_security_data(self):
        """Fetch security-related data (FIXED: ONE-LINER COMMAND)"""
        try:
            # Gunakan sudo dan satu baris
            cmd = (
                "echo '---PORTS---'; "
                "sudo ss -tuln | grep LISTEN || echo 'No ports'; "
                "echo '---UFW---'; "
                "sudo ufw status 2>/dev/null || echo 'UFW: not available'; "
                "echo '---IPTABLES---'; "
                "sudo iptables -L -n 2>/dev/null | head -n 5 || echo 'iptables: not available'; "
                "echo '---APT---'; "
                "apt list --upgradable 2>/dev/null | wc -l || echo '0'; "
                "echo '---CRON---'; "
                "crontab -l 2>/dev/null || echo 'No crontab for current user'; "
                "echo '---LAST---'; "
                "sudo last -n 15 -F 2>/dev/null || echo 'No login history'; "
                "echo '---NET---'; "
                "sudo ss -tunap | grep ESTAB || echo 'No established connections'; "
                "echo '---SUSP---'; "
                "sudo ps aux | grep -E 'nc |ncat |/dev/tcp|bash -i|sh -i|perl.*socket|python.*socket' | grep -v grep || echo 'No suspicious processes'; "
                "echo '---TOP---'; "
                "ps aux --sort=-%cpu | head -n 31 || echo 'USER PID %CPU %MEM VSZ RSS TTY STAT START TIME COMMAND'; "
                "echo '---FAILED---'; "
                "sudo grep 'Failed password' /var/log/auth.log 2>/dev/null | tail -n 20 || sudo journalctl -u ssh -n 20 --no-pager 2>/dev/null | grep -i 'failed' || echo 'No failed login data available'; "
                "echo '---END---'"
            )
            
            out = self.run_ssh_command(cmd)
            if not out:
                return
            
            # ... (SISA KODE PARSING DI BAWAH INI SAMA SEPERTI SEBELUMNYA) ...
            def get_section(name):
                try:
                    return out.split(f'---{name}---')[1].split('---')[0].strip()
                except:
                    return ""
            
            self.security_data['ports'] = [l.strip() for l in get_section('PORTS').split('\n') if l.strip()]
            
            fw_ufw = get_section('UFW')
            self.security_data['firewall_status'] = "Active" if "active" in fw_ufw.lower() else "Inactive"
            
            upd = get_section('APT').strip()
            self.security_data['updates_available'] = max(0, int(upd) - 1) if upd.isdigit() else 0
            
            self.security_data['cronjobs'] = [l.strip() for l in get_section('CRON').split('\n') 
                                             if l.strip() and not l.startswith('#') and 'no crontab' not in l.lower()]
            
            self.security_data['last_logins'] = [l.strip() for l in get_section('LAST').split('\n') if l.strip()][:15]
            self.security_data['network_connections'] = [l.strip() for l in get_section('NET').split('\n') if l.strip()]
            self.security_data['suspicious_processes'] = [l.strip() for l in get_section('SUSP').split('\n') if l.strip()]
            self.security_data['top_processes'] = [l.strip() for l in get_section('TOP').split('\n')[1:] if l.strip()]
            self.security_data['failed_logins'] = [l.strip() for l in get_section('FAILED').split('\n') if l.strip()]
            
            self.after(0, self.update_security_ui)
            
        except Exception as e:
            print(f"Error fetching security data: {e}")
    
    def fetch_extended_data(self):
        """Fetch extended system information"""
        try:
            cmd = '''
            echo "---DOCKER---"
            docker ps -a 2>/dev/null || echo "Docker not installed"
            echo "---SSL---"
            sudo find /etc/letsencrypt/live -name cert.pem 2>/dev/null | while read cert; do
                domain=$(dirname "$cert" | xargs basename)
                expiry=$(sudo openssl x509 -enddate -noout -in "$cert" 2>/dev/null | cut -d= -f2)
                echo "$domain - Expires: $expiry"
            done
            echo "---SERVICES---"
            systemctl list-units --type=service --state=running --no-pager | head -n 20
            echo "---END---"
            '''
            
            out = self.run_ssh_command(cmd)
            if not out:
                return
            
            def get_section(name):
                try:
                    return out.split(f'---{name}---')[1].split('---')[0].strip()
                except:
                    return ""
            
            docker_out = get_section('DOCKER')
            self.security_data['docker_containers'] = [l.strip() for l in docker_out.split('\n') 
                                                       if l.strip() and 'not installed' not in l.lower()]
            
            ssl_out = get_section('SSL')
            self.security_data['ssl_certs'] = [l.strip() for l in ssl_out.split('\n') if l.strip()]
            
            services_out = get_section('SERVICES')
            self.security_data['active_services'] = [l.strip() for l in services_out.split('\n') if l.strip()]
            
            self.after(0, self.update_tab_content)
            
        except Exception as e:
            print(f"Error fetching extended data: {e}")

    def update_compact_ui(self, cpu, ram_used, ram_total, ram_pct, proc_list):
        """Update compact view UI"""
        if self.is_expanded or not hasattr(self, 'lbl_cpu'):
            return
        
        # CPU
        self.lbl_cpu.configure(text=f"{cpu:.1f}%")
        self.prog_cpu.set(min(cpu / 100, 1.0))
        if cpu > 80:
            self.prog_cpu.configure(progress_color=self.accent_red)
        elif cpu > 50:
            self.prog_cpu.configure(progress_color=self.accent_orange)
        else:
            self.prog_cpu.configure(progress_color=self.accent_blue)
        
        # RAM
        self.lbl_ram.configure(text=f"{ram_used}/{ram_total}MB")
        self.prog_ram.set(min(ram_pct, 1.0))
        if ram_pct > 0.8:
            self.prog_ram.configure(progress_color=self.accent_red)
        elif ram_pct > 0.6:
            self.prog_ram.configure(progress_color=self.accent_orange)
        else:
            self.prog_ram.configure(progress_color=self.accent_green)
        
        # Disk
        disk_pct = float(self.security_data.get('disk_usage', {}).get('percentage', 0))
        self.lbl_disk.configure(text=f"{disk_pct:.1f}%")
        self.prog_disk.set(min(disk_pct / 100, 1.0))
        if disk_pct > 80:
            self.prog_disk.configure(progress_color=self.accent_red)
        elif disk_pct > 60:
            self.prog_disk.configure(progress_color=self.accent_orange)
        else:
            self.prog_disk.configure(progress_color=self.accent_green)
        
        # Processes
        txt = ""
        for line in proc_list[:7]:
            if not line.strip():
                continue
            try:
                parts = line.strip().rsplit(maxsplit=2)
                if len(parts) == 3:
                    cmd, cpu_p, mem_p = parts
                    txt += f"{cmd[:12]:<12} {cpu_p[:4]:<5} {mem_p[:4]}\n"
            except:
                continue
        
        self.txt_proc.configure(state="normal")
        self.txt_proc.delete("1.0", "end")
        self.txt_proc.insert("1.0", txt)
        self.txt_proc.configure(state="disabled")

    def update_expanded_ui(self, cpu, ram_used, ram_total, disk, uptime):
        """Update expanded view UI"""
        if not self.is_expanded or not hasattr(self, 'lbl_cpu_exp'):
            return
        
        self.lbl_cpu_exp.configure(text=f"{cpu:.1f}%")
        
        ram_pct = (ram_used / ram_total * 100) if ram_total > 0 else 0
        self.lbl_ram_exp.configure(text=f"{ram_used}/{ram_total} MB ({ram_pct:.1f}%)")
        
        self.lbl_disk_exp.configure(text=f"{disk}% used")
        
        swap_pct = (self.last_swap_used / self.last_swap_total * 100) if self.last_swap_total > 0 else 0
        self.lbl_swap_exp.configure(text=f"{self.last_swap_used}/{self.last_swap_total} MB ({swap_pct:.1f}%)")
        
        self.lbl_load_exp.configure(text=self.last_load_avg)
        self.lbl_uptime_exp.configure(text=uptime)
        
        net_rx = self.network_stats.get('rx', 0)
        net_tx = self.network_stats.get('tx', 0)
        self.lbl_network_exp.configure(text=f"↓ {net_rx}MB / ↑ {net_tx}MB")

    def update_security_ui(self):
        """Update security indicators"""
        if self.is_expanded:
            self.update_tab_content()
        else:
            if not hasattr(self, 'lbl_ports'):
                return
            
            port_cnt = len(self.security_data.get('ports', []))
            self.lbl_ports.configure(text=f"Ports: {port_cnt} open")
            
            fw = self.security_data.get('firewall_status', '---')
            fw_color = self.accent_green if "active" in fw.lower() else self.accent_red
            self.lbl_firewall.configure(text=f"Firewall: {fw}", text_color=fw_color)
            
            upd = self.security_data.get('updates_available', 0)
            upd_color = self.accent_red if upd > 10 else self.accent_orange if upd > 0 else self.accent_green
            self.lbl_updates.configure(text=f"Updates: {upd}", text_color=upd_color)

    def update_status(self, txt, color):
        """Update connection status"""
        if self.is_expanded and hasattr(self, 'lbl_status_expanded'):
            clean_txt = txt.replace('🟢 ', '').replace('🔴 ', '').replace('🟡 ', '').replace('⌛ ', '').replace('❌ ', '')
            self.lbl_status_expanded.configure(text=clean_txt, text_color=color)
        elif not self.is_expanded and hasattr(self, 'lbl_status'):
            self.lbl_status.configure(text=txt, text_color=color)

    def force_refresh(self):
        """Force refresh all data"""
        self.after(0, self.update_status, "🔄 Refreshing...", self.accent_blue)
        threading.Thread(target=self.fetch_basic_data, daemon=True).start()
        threading.Thread(target=self.fetch_security_data, daemon=True).start()
        threading.Thread(target=self.fetch_extended_data, daemon=True).start()

def main():
    """Main entry point"""
    ctk.set_appearance_mode("Dark")
    ctk.set_default_color_theme("blue")
    
    try:
        app = VPSSecurityMonitor(ssh_alias=SSH_ALIAS)
        app.mainloop()
    except Exception as e:
        import tkinter as tk
        root = tk.Tk()
        root.title("VPS Monitor - Error")
        root.geometry("400x200")
        tk.Label(
            root,
            text=f"Critical Error:\n\n{str(e)}\n\nPlease check SSH configuration.",
            wraplength=350,
            justify="left"
        ).pack(padx=20, pady=20)
        root.mainloop()

if __name__ == "__main__":
    main()