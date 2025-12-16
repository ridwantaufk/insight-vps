import customtkinter as ctk
import subprocess
import threading
import time
import sys
import re
from datetime import datetime
from pathlib import Path

# ==============================================================================
#                      KONFIGURASI SSH
# ==============================================================================
SSH_HOST = "vps"  # Atau gunakan: "ubuntu@31.97.110.253"
SSH_KEY = r"C:\Users\Ridwan Taufik\.ssh\id_ed25519"
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
        self.tooltip.attributes('-alpha', 0.95)
        label = ctk.CTkLabel(
            self.tooltip, text=self.text, 
            fg_color=("#2a2a3a", "#1a1a2a"), 
            corner_radius=8, padx=12, pady=8, 
            font=("Segoe UI", 9)
        )
        label.pack()
        self.tooltip.attributes('-topmost', True)
    
    def hide(self, event=None):
        if self.tooltip:
            self.tooltip.destroy()
            self.tooltip = None

class VPSSecurityMonitor(ctk.CTk):
    def __init__(self):
        super().__init__()
        
        # --- Config ---
        self.ssh_host = SSH_HOST
        self.ssh_key = SSH_KEY
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
        self.snap_threshold = 20
        self.edge_snap = None
        self.is_hidden = False
        self.after_id = None
        self.last_compact_pos = None
        self.last_normal_geometry = None
        self.min_width = 900
        self.min_height = 600
        self.drag_start_x = 0
        self.drag_start_y = 0

        # --- Data Storage ---
        self.security_data = {
            'ports': [], 'suspicious_processes': [], 'cronjobs': [], 
            'last_logins': [], 'firewall_status': '', 'updates_available': 0, 
            'disk_usage': {}, 'network_connections': [], 'active_services': [], 
            'failed_logins': [], 'docker_containers': [], 'ssl_certs': [],
            'attackers': []
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

        # --- Modern Colors (Windows 11 Mica-inspired) ---
        self.bg_primary = "#0f0f14"
        self.bg_secondary = "#1a1a24"
        self.bg_tertiary = "#25253a"
        self.accent_blue = "#60a5fa"
        self.accent_green = "#34d399"
        self.accent_red = "#f87171"
        self.accent_orange = "#fb923c"
        self.accent_purple = "#a78bfa"
        self.accent_yellow = "#fbbf24"
        self.text_primary = "#f1f5f9"
        self.text_secondary = "#94a3b8"
        self.text_dim = "#64748b"

        # --- Window Setup ---
        self.title("VPS Security Monitor")
        
        # Start with compact view
        self.compact_width = 280
        self.compact_height = 720
        
        # Center window on screen
        screen_width = self.winfo_screenwidth()
        screen_height = self.winfo_screenheight()
        x = screen_width - self.compact_width - 20
        y = (screen_height - self.compact_height) // 2
        
        self.geometry(f"{self.compact_width}x{self.compact_height}+{x}+{y}")
        
        # --- UI Creation ---
        self._create_compact_ui()
        
        # --- Main Loop ---
        threading.Thread(target=self.main_loop, daemon=True).start()

    def _create_compact_ui(self):
        """Compact floating widget view"""
        self.overrideredirect(True)
        self.attributes('-topmost', True)
        self.attributes('-alpha', 0.94)
        
        # Main container
        self.compact_container = ctk.CTkFrame(
            self, 
            corner_radius=16, 
            fg_color=self.bg_secondary,
            border_width=1, 
            border_color=("#3a3a4a", "#2a2a3a")
        )
        self.compact_container.pack(fill="both", expand=True, padx=3, pady=3)
        
        # Header with drag support
        header = ctk.CTkFrame(self.compact_container, fg_color="transparent", height=45)
        header.pack(fill="x", padx=15, pady=(15, 10))
        header.pack_propagate(False)
        header.bind("<Button-1>", self.start_drag)
        header.bind("<B1-Motion>", self.do_drag)
        header.bind("<ButtonRelease-1>", self.stop_drag)
        
        # IP Label
        ip_container = ctk.CTkFrame(header, fg_color="transparent")
        ip_container.pack(side="left", fill="y")
        
        self.lbl_ip = ctk.CTkLabel(
            ip_container, 
            text=f"🖥️ {self.blurred_ip}", 
            font=("Segoe UI Semibold", 12), 
            text_color=self.accent_blue
        )
        self.lbl_ip.pack(anchor="w")
        self.lbl_ip.bind("<Button-1>", self.toggle_ip_blur)
        Tooltip(self.lbl_ip, "Click to show/hide IP")
        
        self.lbl_subtitle = ctk.CTkLabel(
            ip_container,
            text="VPS Monitor",
            font=("Segoe UI", 8),
            text_color=self.text_dim
        )
        self.lbl_subtitle.pack(anchor="w")
        
        # Control buttons
        btn_container = ctk.CTkFrame(header, fg_color="transparent")
        btn_container.pack(side="right")
        
        btn_expand = ctk.CTkButton(
            btn_container, text="⛶", width=34, height=34, corner_radius=8,
            fg_color=self.bg_tertiary, hover_color=self.accent_blue,
            command=self.toggle_expand, font=("Segoe UI", 14)
        )
        btn_expand.pack(side="left", padx=2)
        Tooltip(btn_expand, "Expand dashboard")
        
        btn_close = ctk.CTkButton(
            btn_container, text="✕", width=34, height=34, corner_radius=8,
            fg_color=self.bg_tertiary, hover_color=self.accent_red,
            command=self.quit_app, font=("Segoe UI", 12)
        )
        btn_close.pack(side="left", padx=2)
        Tooltip(btn_close, "Close")
        
        # Status indicator
        status_frame = ctk.CTkFrame(
            self.compact_container, 
            fg_color=self.bg_tertiary, 
            corner_radius=10, 
            height=40
        )
        status_frame.pack(fill="x", padx=15, pady=(0, 10))
        status_frame.pack_propagate(False)
        
        self.lbl_status = ctk.CTkLabel(
            status_frame, text="🔄 Connecting...", 
            font=("Segoe UI", 9), text_color=self.text_secondary
        )
        self.lbl_status.pack(pady=10)
        
        # System Stats Card
        stats_card = ctk.CTkFrame(
            self.compact_container, 
            fg_color=self.bg_tertiary, 
            corner_radius=12
        )
        stats_card.pack(fill="x", padx=15, pady=(0, 10))
        
        ctk.CTkLabel(
            stats_card, text="⚡ SYSTEM", 
            font=("Segoe UI Semibold", 10), 
            text_color=self.accent_purple
        ).pack(pady=(12, 10))
        
        # CPU Section
        self._create_stat_bar(stats_card, "CPU", "lbl_cpu", "prog_cpu", self.accent_blue)
        
        # RAM Section
        self._create_stat_bar(stats_card, "RAM", "lbl_ram", "prog_ram", self.accent_green)
        
        # Disk Section
        self._create_stat_bar(stats_card, "DISK", "lbl_disk", "prog_disk", self.accent_orange)
        
        # Security Card
        sec_card = ctk.CTkFrame(
            self.compact_container, 
            fg_color=self.bg_tertiary, 
            corner_radius=12
        )
        sec_card.pack(fill="x", padx=15, pady=(0, 10))
        
        ctk.CTkLabel(
            sec_card, text="🛡️ SECURITY", 
            font=("Segoe UI Semibold", 10), 
            text_color=self.accent_red
        ).pack(pady=(12, 10))
        
        self.lbl_ports = ctk.CTkLabel(
            sec_card, text="Ports: ---", 
            font=("Segoe UI", 9), text_color=self.text_secondary
        )
        self.lbl_ports.pack(pady=3)
        
        self.lbl_firewall = ctk.CTkLabel(
            sec_card, text="Firewall: ---", 
            font=("Segoe UI", 9), text_color=self.text_secondary
        )
        self.lbl_firewall.pack(pady=3)
        
        self.lbl_updates = ctk.CTkLabel(
            sec_card, text="Updates: ---", 
            font=("Segoe UI", 9), text_color=self.text_secondary
        )
        self.lbl_updates.pack(pady=3)
        
        self.lbl_attackers = ctk.CTkLabel(
            sec_card, text="Threats: ---", 
            font=("Segoe UI", 9), text_color=self.text_secondary
        )
        self.lbl_attackers.pack(pady=(3, 12))
        
        # Top Processes Card
        proc_card = ctk.CTkFrame(
            self.compact_container, 
            fg_color=self.bg_tertiary, 
            corner_radius=12
        )
        proc_card.pack(fill="both", expand=True, padx=15, pady=(0, 15))
        
        ctk.CTkLabel(
            proc_card, text="📈 TOP PROCESSES", 
            font=("Segoe UI Semibold", 10), 
            text_color=self.accent_green
        ).pack(pady=(12, 8))
        
        self.txt_proc = ctk.CTkTextbox(
            proc_card, 
            font=("Consolas", 8), 
            fg_color=self.bg_primary, 
            text_color=self.text_primary,
            wrap="none",
            activate_scrollbars=True
        )
        self.txt_proc.pack(fill="both", expand=True, padx=12, pady=(0, 12))
        self.txt_proc.configure(state="disabled")
        
        # Hover effects
        self.bind("<Enter>", self.on_enter)
        self.bind("<Leave>", self.on_leave)

    def _create_stat_bar(self, parent, label, lbl_name, prog_name, color):
        """Create a stat bar with label and progress"""
        frame = ctk.CTkFrame(parent, fg_color="transparent")
        frame.pack(fill="x", padx=12, pady=(0, 10))
        
        label_frame = ctk.CTkFrame(frame, fg_color="transparent")
        label_frame.pack(fill="x")
        
        ctk.CTkLabel(
            label_frame, text=label, 
            font=("Segoe UI", 9), 
            text_color=self.text_secondary
        ).pack(side="left")
        
        lbl = ctk.CTkLabel(
            label_frame, text="---%", 
            font=("Segoe UI Semibold", 9), 
            text_color=color
        )
        lbl.pack(side="right")
        setattr(self, lbl_name, lbl)
        
        prog = ctk.CTkProgressBar(
            frame, height=6, corner_radius=3, 
            progress_color=color,
            fg_color=self.bg_primary
        )
        prog.pack(fill="x", pady=(4, 0))
        prog.set(0)
        setattr(self, prog_name, prog)

    def _create_expanded_ui(self):
        """Full dashboard view"""
        self.overrideredirect(False)
        self.attributes('-topmost', False)
        self.attributes('-alpha', 0.96)
        self.resizable(True, True)
        self.minsize(self.min_width, self.min_height)
        
        # Main background
        self.configure(fg_color=self.bg_primary)
        
        # Scrollable container
        self.expanded_container = ctk.CTkScrollableFrame(
            self,
            fg_color=self.bg_primary,
            scrollbar_button_color=self.bg_tertiary,
            scrollbar_button_hover_color=self.accent_blue
        )
        self.expanded_container.pack(fill="both", expand=True)
        
        # Header
        header = ctk.CTkFrame(
            self.expanded_container, 
            fg_color=self.bg_secondary, 
            corner_radius=12, 
            height=80
        )
        header.pack(fill="x", padx=20, pady=20)
        header.pack_propagate(False)
        
        title_container = ctk.CTkFrame(header, fg_color="transparent")
        title_container.pack(fill="both", expand=True, padx=25, pady=20)
        
        # Title and IP
        title_frame = ctk.CTkFrame(title_container, fg_color="transparent")
        title_frame.pack(side="left", fill="y")
        
        ip_display = self.blurred_ip if self.is_ip_blurred else self.vps_ip
        
        self.lbl_ip_expanded = ctk.CTkLabel(
            title_frame, 
            text="🖥️ VPS Security Dashboard", 
            font=("Segoe UI", 20, "bold"), 
            text_color=self.accent_blue
        )
        self.lbl_ip_expanded.pack(anchor="w")
        
        self.lbl_ip_sub = ctk.CTkLabel(
            title_frame, 
            text=f"Monitoring: {ip_display}", 
            font=("Segoe UI", 11), 
            text_color=self.text_secondary
        )
        self.lbl_ip_sub.pack(anchor="w", pady=(3, 0))
        self.lbl_ip_sub.bind("<Button-1>", self.toggle_ip_blur)
        Tooltip(self.lbl_ip_sub, "Click to show/hide IP")
        
        # Control buttons
        btn_container = ctk.CTkFrame(title_container, fg_color="transparent")
        btn_container.pack(side="right", fill="y")
        
        btn_frame = ctk.CTkFrame(btn_container, fg_color="transparent")
        btn_frame.pack(expand=True)
        
        btn_maximize = ctk.CTkButton(
            btn_frame, text="⛶", width=42, height=38, corner_radius=8,
            fg_color=self.bg_tertiary, hover_color=self.accent_purple,
            command=self.toggle_maximize, font=("Segoe UI", 14)
        )
        btn_maximize.pack(side="left", padx=3)
        Tooltip(btn_maximize, "Maximize/Restore")
        
        btn_refresh = ctk.CTkButton(
            btn_frame, text="🔄", width=42, height=38, corner_radius=8,
            fg_color=self.accent_green, hover_color="#22c55e",
            command=self.force_refresh, font=("Segoe UI", 14)
        )
        btn_refresh.pack(side="left", padx=3)
        Tooltip(btn_refresh, "Force refresh")
        
        btn_compact = ctk.CTkButton(
            btn_frame, text="📉", width=100, height=38, corner_radius=8,
            fg_color=self.bg_tertiary, hover_color=self.accent_blue,
            command=self.toggle_expand, font=("Segoe UI", 11)
        )
        btn_compact.pack(side="left", padx=3)
        Tooltip(btn_compact, "Compact view")
        
        # Main content
        content = ctk.CTkFrame(self.expanded_container, fg_color="transparent")
        content.pack(fill="both", expand=True, padx=20, pady=(0, 20))
        
        # Left sidebar
        left_panel = ctk.CTkFrame(
            content, 
            fg_color=self.bg_secondary, 
            corner_radius=12, 
            width=340
        )
        left_panel.pack(side="left", fill="y", padx=(0, 15))
        left_panel.pack_propagate(False)
        
        ctk.CTkLabel(
            left_panel, text="📊 SYSTEM OVERVIEW", 
            font=("Segoe UI Semibold", 14), 
            text_color=self.accent_purple
        ).pack(pady=(20, 15))
        
        # Status card
        status_card = ctk.CTkFrame(
            left_panel, 
            fg_color=self.bg_tertiary, 
            corner_radius=10
        )
        status_card.pack(fill="x", padx=15, pady=(0, 12))
        
        self.lbl_status_expanded = ctk.CTkLabel(
            status_card, text="🔄 Connecting...", 
            font=("Segoe UI", 10), text_color=self.accent_orange
        )
        self.lbl_status_expanded.pack(pady=14)
        
        # System stats
        stats_container = ctk.CTkFrame(left_panel, fg_color="transparent")
        stats_container.pack(fill="x", padx=15, pady=5)
        
        self._create_stat_row(stats_container, "⚡", "CPU", "lbl_cpu_exp", self.accent_blue)
        self._create_stat_row(stats_container, "💾", "RAM", "lbl_ram_exp", self.accent_green)
        self._create_stat_row(stats_container, "💿", "DISK", "lbl_disk_exp", self.accent_orange)
        self._create_stat_row(stats_container, "🔄", "SWAP", "lbl_swap_exp", self.accent_purple)
        self._create_stat_row(stats_container, "📊", "LOAD", "lbl_load_exp", self.accent_blue)
        self._create_stat_row(stats_container, "⏱️", "UPTIME", "lbl_uptime_exp", self.accent_green)
        self._create_stat_row(stats_container, "🌐", "NETWORK", "lbl_network_exp", self.accent_purple)
        
        # Right panel
        right_panel = ctk.CTkFrame(content, fg_color="transparent")
        right_panel.pack(side="left", fill="both", expand=True)
        
        # Tab buttons
        tab_frame = ctk.CTkFrame(right_panel, fg_color="transparent")
        tab_frame.pack(fill="x", pady=(0, 12))
        
        self.active_tab = "security"
        self.tab_buttons = {}
        
        tabs = [
            ("🛡️ Security", "security"),
            ("⚠️ Threats", "threats"),
            ("🔌 Ports", "ports"),
            ("⚙️ Processes", "processes"),
            ("🌐 Network", "network"),
            ("⏰ Cron", "cron"),
            ("🐳 Docker", "docker"),
            ("📜 Logs", "logs")
        ]
        
        for text, tab_id in tabs:
            is_active = tab_id == self.active_tab
            btn = ctk.CTkButton(
                tab_frame, text=text, height=40, corner_radius=8,
                fg_color=self.accent_blue if is_active else self.bg_tertiary,
                hover_color=self.accent_blue,
                command=lambda t=tab_id: self.switch_tab(t),
                font=("Segoe UI", 10)
            )
            btn.pack(side="left", padx=3)
            self.tab_buttons[tab_id] = btn
        
        # Tab content
        self.tab_content = ctk.CTkFrame(
            right_panel, 
            fg_color=self.bg_secondary, 
            corner_radius=12
        )
        self.tab_content.pack(fill="both", expand=True)
        
        self.tab_textbox = ctk.CTkTextbox(
            self.tab_content, 
            font=("Consolas", 9), 
            fg_color=self.bg_tertiary, 
            text_color=self.text_primary,
            wrap="none"
        )
        self.tab_textbox.pack(fill="both", expand=True, padx=18, pady=18)
        
        self.update_tab_content()

    def _create_stat_row(self, parent, icon, label, value_var_name, color):
        """Create stat row in expanded view"""
        frame = ctk.CTkFrame(parent, fg_color=self.bg_tertiary, corner_radius=8)
        frame.pack(fill="x", pady=5)
        
        left = ctk.CTkFrame(frame, fg_color="transparent")
        left.pack(side="left", fill="y", padx=14, pady=12)
        
        ctk.CTkLabel(
            left, text=icon, 
            font=("Segoe UI", 16)
        ).pack(side="left")
        
        ctk.CTkLabel(
            left, text=label, 
            font=("Segoe UI", 9), 
            text_color=self.text_secondary
        ).pack(side="left", padx=(10, 0))
        
        value = ctk.CTkLabel(
            frame, text="---", 
            font=("Segoe UI Semibold", 10), 
            text_color=color
        )
        value.pack(side="right", padx=14)
        setattr(self, value_var_name, value)

    def run_ssh_command(self, command):
        """Execute SSH command"""
        try:
            # Build SSH command dengan identity file
            ssh_cmd = [
                'ssh',
                '-o', 'StrictHostKeyChecking=no',
                '-o', 'ConnectTimeout=10',
                '-i', self.ssh_key,
                self.ssh_host,
                command
            ]
            
            result = subprocess.run(
                ssh_cmd,
                capture_output=True,
                text=True,
                timeout=25,
                encoding='utf-8',
                errors='replace'
            )
            
            if result.returncode != 0 and result.stderr:
                print(f"⚠️  SSH stderr: {result.stderr[:300]}")
            
            return result.stdout
            
        except subprocess.TimeoutExpired:
            print("⏱️  SSH timeout")
            return ""
        except Exception as e:
            print(f"❌ SSH Error: {e}")
            return ""

    def test_connection(self):
        """Test SSH connection"""
        try:
            # Test dengan sudo echo
            test_cmd = 'echo "TEST_OK" && sudo -n echo "SUDO_OK" 2>/dev/null || echo "SUDO_PROMPT"'
            
            ssh_cmd = [
                'ssh',
                '-o', 'ConnectTimeout=8',
                '-o', 'StrictHostKeyChecking=no',
                '-i', self.ssh_key,
                self.ssh_host,
                test_cmd
            ]
            
            result = subprocess.run(
                ssh_cmd,
                capture_output=True,
                text=True,
                timeout=12
            )
            
            if "TEST_OK" in result.stdout:
                # Get IP
                ip_cmd = 'hostname -I | awk \'{print $1}\''
                ip_result = subprocess.run(
                    ['ssh', '-i', self.ssh_key, self.ssh_host, ip_cmd],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                self.vps_ip = ip_result.stdout.strip() or "Unknown"
                print(f"✅ Connected: {self.vps_ip}")
                return True
            
            print(f"❌ Connection failed: {result.stderr}")
            return False
            
        except Exception as e:
            print(f"❌ Connection error: {e}")
            return False

    def toggle_maximize(self):
        """Toggle maximize"""
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
        """Center window"""
        self.update_idletasks()
        sw = self.winfo_screenwidth()
        sh = self.winfo_screenheight()
        w = self.winfo_width()
        h = self.winfo_height()
        x = (sw - w) // 2
        y = (sh - h) // 2
        self.geometry(f'{w}x{h}+{x}+{y}')

    def switch_tab(self, tab_id):
        """Switch tabs"""
        self.active_tab = tab_id
        for tid, btn in self.tab_buttons.items():
            btn.configure(
                fg_color=self.accent_blue if tid == tab_id else self.bg_tertiary
            )
        self.update_tab_content()

    def update_tab_content(self):
        """Update tab content"""
        if not self.is_expanded:
            return
        
        content = ""
        
        if self.active_tab == "security":
            content = self._format_security_tab()
        elif self.active_tab == "threats":
            content = self._format_threats_tab()
        elif self.active_tab == "ports":
            content = self._format_ports_tab()
        elif self.active_tab == "processes":
            content = self._format_processes_tab()
        elif self.active_tab == "network":
            content = self._format_network_tab()
        elif self.active_tab == "cron":
            content = self._format_cron_tab()
        elif self.active_tab == "docker":
            content = self._format_docker_tab()
        elif self.active_tab == "logs":
            content = self._format_logs_tab()
        
        self.tab_textbox.configure(state="normal")
        self.tab_textbox.delete("1.0", "end")
        self.tab_textbox.insert("1.0", content if content else "Loading data...")
        self.tab_textbox.configure(state="disabled")

    def _format_security_tab(self):
        """Format security tab"""
        c = "═" * 90 + "\n"
        c += "  🛡️  SECURITY OVERVIEW\n"
        c += "═" * 90 + "\n\n"
        
        fw = self.security_data.get('firewall_status', 'Unknown')
        upd = self.security_data.get('updates_available', 0)
        ports = len(self.security_data.get('ports', []))
        attackers = len(self.security_data.get('attackers', []))
        
        c += f"🔥 Firewall Status      : {fw}\n"
        c += f"📦 Available Updates    : {upd}\n"
        c += f"🔌 Open Ports           : {ports}\n"
        c += f"⚠️  Detected Threats     : {attackers}\n"
        c += f"👤 Recent Logins        : {len(self.security_data.get('last_logins', []))}\n"
        c += f"❌ Failed Login Attempts: {len(self.security_data.get('failed_logins', []))}\n\n"
        
        c += "─" * 90 + "\n"
        c += "  ⚠️  SUSPICIOUS PROCESSES\n"
        c += "─" * 90 + "\n"
        
        susp = self.security_data.get('suspicious_processes', [])
        if susp:
            for proc in susp[:20]:
                c += f"  • {proc}\n"
        else:
            c += "  ✅ No suspicious processes detected\n"
        
        c += "\n" + "─" * 90 + "\n"
        c += "  👤 RECENT LOGIN HISTORY\n"
        c += "─" * 90 + "\n"
        
        logins = self.security_data.get('last_logins', [])
        for login in logins[:15]:
            c += f"  {login}\n"
        
        return c

    def _format_threats_tab(self):
        """Format threats tab with actions"""
        c = "═" * 90 + "\n"
        c += "  ⚠️  DETECTED THREATS & ATTACKERS\n"
        c += "═" * 90 + "\n\n"
        
        attackers = self.security_data.get('attackers', [])
        
        if attackers:
            c += f"Total Detected Threats: {len(attackers)}\n\n"
            c += "─" * 90 + "\n"
            
            for i, attacker in enumerate(attackers[:50], 1):
                c += f"\n[{i}] {attacker['type'].upper()} THREAT\n"
                c += f"    IP Address    : {attacker.get('ip', 'Unknown')}\n"
                c += f"    User          : {attacker.get('user', 'Unknown')}\n"
                c += f"    Timestamp     : {attacker.get('time', 'Unknown')}\n"
                c += f"    Details       : {attacker.get('details', 'N/A')}\n"
                c += f"    Severity      : {attacker.get('severity', 'Medium')}\n"
                
                if attacker.get('recommended_action'):
                    c += f"    📋 Action     : {attacker['recommended_action']}\n"
                
                c += "\n" + "─" * 90 + "\n"
            
            c += "\n💡 RECOMMENDED ACTIONS:\n"
            c += "   1. Review and block suspicious IPs using: sudo ufw deny from <IP>\n"
            c += "   2. Check authentication logs: sudo tail -100 /var/log/auth.log\n"
            c += "   3. Update fail2ban rules if installed\n"
            c += "   4. Consider changing SSH port and disabling root login\n"
            
        else:
            c += "✅ No threats detected\n\n"
            c += "Your VPS appears to be secure. Continue monitoring for any suspicious activity.\n"
        
        return c

    def _format_ports_tab(self):
        """Format ports tab"""
        c = "═" * 90 + "\n"
        c += "  🔌 OPEN PORTS & LISTENING SERVICES\n"
        c += "═" * 90 + "\n\n"
        
        ports = self.security_data.get('ports', [])
        if ports:
            c += f"Total Open Ports: {len(ports)}\n\n"
            for port in ports[:50]:
                c += f"  {port}\n"
        else:
            c += "  No open ports detected\n"
        
        return c

    def _format_processes_tab(self):
        """Format processes tab"""
        c = "═" * 90 + "\n"
        c += "  ⚙️  TOP PROCESSES BY CPU USAGE\n"
        c += "═" * 90 + "\n\n"
        
        c += f"{'USER':<12} {'PID':<8} {'CPU%':<8} {'MEM%':<8} {'VSZ':<12} {'COMMAND'}\n"
        c += "─" * 90 + "\n"
        
        procs = self.security_data.get('top_processes', [])
        for proc in procs[:40]:
            c += f"{proc}\n"
        
        return c

    def _format_network_tab(self):
        """Format network tab"""
        c = "═" * 90 + "\n"
        c += "  🌐 NETWORK STATISTICS\n"
        c += "═" * 90 + "\n\n"
        
        c += f"Network Traffic:\n"
        c += f"  RX (Received): {self.network_stats.get('rx', 0)} MB\n"
        c += f"  TX (Transmitted): {self.network_stats.get('tx', 0)} MB\n\n"
        
        c += "─" * 90 + "\n"
        c += "Established Connections:\n"
        c += "─" * 90 + "\n"
        
        conns = self.security_data.get('network_connections', [])
        if conns:
            for conn in conns[:50]:
                c += f"  {conn}\n"
        else:
            c += "  No active connections\n"
        
        return c

    def _format_cron_tab(self):
        """Format cron tab"""
        c = "═" * 90 + "\n"
        c += "  ⏰ SCHEDULED CRON JOBS\n"
        c += "═" * 90 + "\n\n"
        
        crons = self.security_data.get('cronjobs', [])
        if crons:
            for cron in crons:
                c += f"  {cron}\n"
        else:
            c += "  No cron jobs for current user\n"
        
        c += "\n" + "─" * 90 + "\n"
        c += "  💡 TIP: Check system crontabs at /etc/crontab and /etc/cron.d/\n"
        
        return c

    def _format_docker_tab(self):
        """Format docker tab"""
        c = "═" * 90 + "\n"
        c += "  🐳 DOCKER CONTAINERS\n"
        c += "═" * 90 + "\n\n"
        
        containers = self.security_data.get('docker_containers', [])
        if containers:
            for container in containers:
                c += f"  {container}\n"
        else:
            c += "  No Docker containers found or Docker not installed\n"
        
        return c

    def _format_logs_tab(self):
        """Format logs tab"""
        c = "═" * 90 + "\n"
        c += "  📜 RECENT SYSTEM LOGS\n"
        c += "═" * 90 + "\n\n"
        
        c += "Authentication Failures:\n"
        c += "─" * 90 + "\n"
        
        failed = self.security_data.get('failed_logins', [])
        if failed:
            for fail in failed[:30]:
                c += f"  {fail}\n"
        else:
            c += "  No recent failed login attempts\n"
        
        return c

    def toggle_expand(self):
        """Toggle expand/compact"""
        self.is_expanded = not self.is_expanded
        
        self.on_leave(None)
        self.edge_snap = None
        self.is_hidden = False

        if self.is_expanded:
            self.last_compact_pos = f"+{self.winfo_x()}+{self.winfo_y()}"
            
            if hasattr(self, 'compact_container'):
                self.compact_container.destroy()
            
            self._create_expanded_ui()
            self.geometry("1100x750")
            self.after(10, self.center_window)
        else:
            if hasattr(self, 'expanded_container'):
                self.expanded_container.destroy()
            
            self._create_compact_ui()
            
            self.overrideredirect(True)
            if self.last_compact_pos:
                self.geometry(f"{self.compact_width}x{self.compact_height}{self.last_compact_pos}")
            else:
                sw = self.winfo_screenwidth()
                sh = self.winfo_screenheight()
                x = sw - self.compact_width - 20
                y = (sh - self.compact_height) // 2
                self.geometry(f"{self.compact_width}x{self.compact_height}+{x}+{y}")
            
            self.attributes('-topmost', True)
        
        self.update_ui_with_latest_data()

    def update_ui_with_latest_data(self):
        """Update UI with cached data"""
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
        
        if hasattr(self, 'lbl_status'):
            status_text = self.lbl_status.cget('text')
            status_color = self.lbl_status.cget('text_color')
            self.update_status(status_text, status_color)

    def toggle_ip_blur(self, e=None):
        """Toggle IP blur"""
        self.is_ip_blurred = not self.is_ip_blurred
        ip = self.blurred_ip if self.is_ip_blurred else self.vps_ip
        
        if self.is_expanded:
            if hasattr(self, 'lbl_ip_sub'):
                self.lbl_ip_sub.configure(text=f"Monitoring: {ip}")
        else:
            if hasattr(self, 'lbl_ip'):
                self.lbl_ip.configure(text=f"🖥️ {ip}")

    def start_drag(self, e):
        """Start dragging"""
        self.is_dragging = True
        self.drag_start_x = e.x
        self.drag_start_y = e.y
        if self.edge_snap:
            self.show_widget()
        self.edge_snap = None
        self.is_hidden = False
        self.on_leave(None)

    def stop_drag(self, e):
        """Stop dragging"""
        self.is_dragging = False
        if not self.is_expanded:
            self.snap_to_edge()

    def do_drag(self, e):
        """Handle dragging"""
        if not self.is_dragging:
            return
        
        x_new = self.winfo_x() + (e.x - self.drag_start_x)
        y_new = self.winfo_y() + (e.y - self.drag_start_y)
        
        sw = self.winfo_screenwidth()
        sh = self.winfo_screenheight()
        w = self.winfo_width()
        h = self.winfo_height()
        
        x_new = max(-10, min(x_new, sw - w + 10))
        y_new = max(0, min(y_new, sh - 60))
        
        self.geometry(f"+{x_new}+{y_new}")

    def snap_to_edge(self):
        """Snap to edge"""
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
        """Hide widget"""
        if not self.edge_snap or self.is_hidden:
            return
        
        self.is_hidden = True
        y = self.winfo_y()
        hide_offset = 15
        
        if self.edge_snap == "left":
            self.geometry(f"+{-self.winfo_width() + hide_offset}+{y}")
        elif self.edge_snap == "right":
            self.geometry(f"+{self.winfo_screenwidth() - hide_offset}+{y}")

    def show_widget(self):
        """Show widget"""
        if not self.edge_snap or not self.is_hidden:
            return
        
        self.is_hidden = False
        y = self.winfo_y()
        
        if self.edge_snap == "left":
            self.geometry(f"+5+{y}")
        elif self.edge_snap == "right":
            self.geometry(f"+{self.winfo_screenwidth() - self.winfo_width() - 5}+{y}")

    def on_enter(self, e):
        """Mouse enter"""
        if self.after_id:
            self.after_cancel(self.after_id)
            self.after_id = None
        if self.edge_snap and self.is_hidden:
            self.show_widget()

    def on_leave(self, e):
        """Mouse leave"""
        if self.after_id:
            self.after_cancel(self.after_id)
        if self.edge_snap and not self.is_hidden:
            self.after_id = self.after(600, self.hide_widget)

    def quit_app(self):
        """Quit app"""
        self.running = False
        self.destroy()
        sys.exit()

    def main_loop(self):
        """Main loop"""
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
            
            self.fetch_basic_data()
            
            if iteration % 15 == 0:
                self.fetch_security_data()
            
            if iteration % 30 == 0:
                self.fetch_extended_data()
            
            iteration += 1
            time.sleep(2)

    def fetch_basic_data(self):
        """Fetch basic data"""
        try:
            cmd = '''
            echo "---CPU---"
            top -bn1 | grep "Cpu(s)" 2>/dev/null || echo "0.0 us"
            echo "---RAM---"
            free -m 2>/dev/null
            echo "---DISK---"
            df -h / 2>/dev/null | tail -n1
            echo "---UPTIME---"
            uptime -p 2>/dev/null || echo "unknown"
            echo "---LOAD---"
            uptime 2>/dev/null | awk -F"load average:" "{print \\$2}"
            echo "---SWAP---"
            free -m 2>/dev/null | grep Swap
            echo "---NET---"
            cat /proc/net/dev 2>/dev/null | grep -E "eth0|ens|enp|wlan" | head -n1
            echo "---PS---"
            ps -eo comm,%cpu,%mem --sort=-%cpu 2>/dev/null | head -n 8
            echo "---END---"
            '''
            
            out = self.run_ssh_command(cmd)
            if not out:
                self.connection_ok = False
                return
            
            # Parse CPU
            try:
                cpu_sec = out.split("---CPU---")[1].split("---RAM---")[0].strip().replace(',', '.')
                cpu_vals = re.findall(r'[\d.]+', cpu_sec)
                cpu = float(cpu_vals[0]) + float(cpu_vals[1]) if len(cpu_vals) >= 2 else 0.0
            except:
                cpu = 0.0
            
            # Parse RAM
            try:
                ram_sec = out.split("---RAM---")[1].split("---DISK---")[0].strip()
                ram_lines = [l for l in ram_sec.split('\n') if 'Mem:' in l]
                if ram_lines:
                    ram_data = ram_lines[0].split()
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
            
            # Parse Load
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
            
            self.after(0, self.update_ui_with_latest_data)
            
        except Exception as e:
            print(f"Error fetching basic data: {e}")
            self.connection_ok = False

    def fetch_security_data(self):
        """Fetch security data"""
        try:
            cmd = '''
            echo "---PORTS---"
            sudo ss -tuln 2>/dev/null | grep LISTEN || echo "No ports"
            echo "---UFW---"
            sudo ufw status 2>/dev/null || echo "UFW: not available"
            echo "---APT---"
            apt list --upgradable 2>/dev/null | wc -l
            echo "---CRON---"
            crontab -l 2>/dev/null || echo "No crontab"
            echo "---LAST---"
            last -n 20 -F 2>/dev/null
            echo "---NET---"
            sudo ss -tunap 2>/dev/null | grep ESTAB || echo "No connections"
            echo "---SUSP---"
            ps aux 2>/dev/null | grep -E "nc |ncat |/dev/tcp|bash -i|sh -i|perl.*socket|python.*socket" | grep -v grep || echo "None"
            echo "---TOP---"
            ps aux --sort=-%cpu 2>/dev/null | head -n 31
            echo "---FAILED---"
            sudo grep "Failed password" /var/log/auth.log 2>/dev/null | tail -n 30 || echo "No failed logins"
            echo "---ATTACKERS---"
            sudo lastb -n 50 -F 2>/dev/null || echo "No bad logins"
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
            
            self.security_data['ports'] = [l.strip() for l in get_section('PORTS').split('\n') if l.strip() and 'No ports' not in l]
            
            fw_ufw = get_section('UFW')
            self.security_data['firewall_status'] = "Active" if "active" in fw_ufw.lower() else "Inactive"
            
            upd = get_section('APT').strip()
            self.security_data['updates_available'] = max(0, int(upd) - 1) if upd.isdigit() else 0
            
            self.security_data['cronjobs'] = [l.strip() for l in get_section('CRON').split('\n') 
                                             if l.strip() and not l.startswith('#') and 'no crontab' not in l.lower()]
            
            self.security_data['last_logins'] = [l.strip() for l in get_section('LAST').split('\n') if l.strip()][:20]
            self.security_data['network_connections'] = [l.strip() for l in get_section('NET').split('\n') if l.strip() and 'No connections' not in l]
            self.security_data['suspicious_processes'] = [l.strip() for l in get_section('SUSP').split('\n') if l.strip() and 'None' not in l]
            self.security_data['top_processes'] = [l.strip() for l in get_section('TOP').split('\n')[1:] if l.strip()]
            self.security_data['failed_logins'] = [l.strip() for l in get_section('FAILED').split('\n') if l.strip() and 'No failed' not in l]
            
            # Parse attackers
            attackers_raw = get_section('ATTACKERS')
            attackers = []
            if attackers_raw and 'No bad logins' not in attackers_raw:
                for line in attackers_raw.split('\n'):
                    if not line.strip():
                        continue
                    parts = line.split()
                    if len(parts) >= 3:
                        attacker = {
                            'type': 'failed_login',
                            'user': parts[0],
                            'ip': parts[2] if len(parts) > 2 else 'Unknown',
                            'time': ' '.join(parts[3:8]) if len(parts) > 7 else 'Unknown',
                            'details': line,
                            'severity': 'High' if parts[0] == 'root' else 'Medium',
                            'recommended_action': f'Block IP: sudo ufw deny from {parts[2]}' if len(parts) > 2 else 'Review logs'
                        }
                        attackers.append(attacker)
            
            self.security_data['attackers'] = attackers[:50]
            
            self.after(0, self.update_security_ui)
            
        except Exception as e:
            print(f"Error fetching security data: {e}")

    def fetch_extended_data(self):
        """Fetch extended data"""
        try:
            cmd = '''
            echo "---DOCKER---"
            docker ps -a 2>/dev/null || echo "Docker not installed"
            echo "---SSL---"
            sudo find /etc/letsencrypt/live -name cert.pem 2>/dev/null | while read cert; do
                domain=$(dirname "$cert" | xargs basename)
                expiry=$(sudo openssl x509 -enddate -noout -in "$cert" 2>/dev/null | cut -d= -f2)
                echo "$domain - Expires: $expiry"
            done || echo "No SSL certs"
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
            self.security_data['ssl_certs'] = [l.strip() for l in ssl_out.split('\n') if l.strip() and 'No SSL' not in l]
            
            self.after(0, self.update_tab_content)
            
        except Exception as e:
            print(f"Error fetching extended data: {e}")

    def update_compact_ui(self, cpu, ram_used, ram_total, ram_pct, proc_list):
        """Update compact UI"""
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
        """Update expanded UI"""
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
            
            threat_cnt = len(self.security_data.get('attackers', []))
            threat_color = self.accent_red if threat_cnt > 10 else self.accent_orange if threat_cnt > 0 else self.accent_green
            self.lbl_attackers.configure(text=f"Threats: {threat_cnt}", text_color=threat_color)

    def update_status(self, txt, color):
        """Update status"""
        if self.is_expanded and hasattr(self, 'lbl_status_expanded'):
            clean_txt = txt.replace('🟢 ', '').replace('🔴 ', '').replace('🟡 ', '')
            self.lbl_status_expanded.configure(text=clean_txt, text_color=color)
        elif not self.is_expanded and hasattr(self, 'lbl_status'):
            self.lbl_status.configure(text=txt, text_color=color)

    def force_refresh(self):
        """Force refresh"""
        self.after(0, self.update_status, "🔄 Refreshing...", self.accent_blue)
        threading.Thread(target=self.fetch_basic_data, daemon=True).start()
        threading.Thread(target=self.fetch_security_data, daemon=True).start()
        threading.Thread(target=self.fetch_extended_data, daemon=True).start()


def main():
    """Main entry point"""
    ctk.set_appearance_mode("Dark")
    ctk.set_default_color_theme("blue")
    
    print("=" * 60)
    print("VPS Security Monitor - Enhanced Edition")
    print("=" * 60)
    print(f"SSH Host: {SSH_HOST}")
    print(f"SSH Key: {SSH_KEY}")
    print("-" * 60)
    
    # Check if SSH key exists
    key_path = Path(SSH_KEY)
    if not key_path.exists():
        print(f"⚠️  WARNING: SSH key not found at {SSH_KEY}")
        print("Please update SSH_KEY path in the configuration section.")
        input("Press Enter to exit...")
        return
    
    try:
        app = VPSSecurityMonitor()
        app.mainloop()
    except KeyboardInterrupt:
        print("\n\n👋 Shutting down gracefully...")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Critical Error: {e}")
        import traceback
        traceback.print_exc()
        
        # Show error dialog
        try:
            root = ctk.CTk()
            root.title("VPS Monitor - Error")
            root.geometry("500x300")
            root.configure(fg_color="#1a1a24")
            
            frame = ctk.CTkFrame(root, fg_color="#25253a", corner_radius=12)
            frame.pack(fill="both", expand=True, padx=20, pady=20)
            
            ctk.CTkLabel(
                frame,
                text="❌ Critical Error",
                font=("Segoe UI", 18, "bold"),
                text_color="#f87171"
            ).pack(pady=(20, 10))
            
            error_text = ctk.CTkTextbox(
                frame,
                font=("Consolas", 9),
                fg_color="#1a1a24",
                text_color="#f1f5f9",
                wrap="word"
            )
            error_text.pack(fill="both", expand=True, padx=15, pady=(0, 15))
            error_text.insert("1.0", f"{str(e)}\n\nPlease check:\n")
            error_text.insert("end", "1. SSH configuration is correct\n")
            error_text.insert("end", "2. SSH key path is valid\n")
            error_text.insert("end", "3. VPS is accessible\n")
            error_text.insert("end", "4. Required packages are installed (customtkinter)\n")
            error_text.configure(state="disabled")
            
            ctk.CTkButton(
                frame,
                text="Close",
                command=root.destroy,
                fg_color="#f87171",
                hover_color="#ef4444",
                font=("Segoe UI", 11)
            ).pack(pady=(0, 15))
            
            root.mainloop()
        except:
            pass


if __name__ == "__main__":
    main()