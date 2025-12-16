import customtkinter as ctk
import subprocess
import threading
import time
import sys
import re
from datetime import datetime
from pathlib import Path
import logging
from logging.handlers import RotatingFileHandler
import json
import os
from queue import Queue
import traceback

# ==============================================================================
#                      KONFIGURASI SSH
# ==============================================================================
SSH_HOST = "vps"  # Atau gunakan: "ubuntu@31.97.110.253"
SSH_KEY = r"C:\Users\Ridwan Taufik\.ssh\id_ed25519"
# ==============================================================================

# Database informasi proses dalam Bahasa Indonesia
PROCESS_INFO = {
    'systemd': 'Sistem init utama Linux - mengelola semua service',
    'sshd': 'SSH Daemon - layanan remote login (port 22)',
    'apache2': 'Web server Apache - melayani website',
    'nginx': 'Web server Nginx - melayani website (alternatif Apache)',
    'mysql': 'Database MySQL - penyimpanan data',
    'mysqld': 'MySQL Daemon - server database MySQL',
    'postgres': 'PostgreSQL - database server',
    'docker': 'Docker daemon - container management',
    'containerd': 'Container runtime untuk Docker',
    'node': 'Node.js - runtime JavaScript server-side',
    'python': 'Python interpreter - menjalankan script Python',
    'php-fpm': 'PHP FastCGI - processor script PHP',
    'redis': 'Redis - in-memory database cache',
    'memcached': 'Memcached - sistem caching memory',
    'fail2ban': 'Fail2ban - proteksi brute force attack',
    'ufw': 'Uncomplicated Firewall - firewall Linux',
    'cron': 'Cron daemon - scheduler tugas otomatis',
    'rsyslog': 'System logging service - mencatat log sistem',
    'snapd': 'Snap package manager daemon',
    'networkd': 'Network manager systemd',
    'dbus': 'D-Bus system message bus',
    'journald': 'Systemd journal logging service',
    'bash': 'Bash shell - command line interface',
    'sh': 'Shell interpreter',
    'htop': 'Monitor sistem interaktif',
    'top': 'Monitor proses sistem',
    'ps': 'Process status viewer',
    'grep': 'Pattern search utility',
    'awk': 'Text processing tool',
    'sed': 'Stream editor',
    'vim': 'Text editor Vi Improved',
    'nano': 'Simple text editor',
    'wget': 'File downloader',
    'curl': 'Transfer data utility',
    'git': 'Version control system',
    'java': 'Java runtime environment',
    'mongod': 'MongoDB database daemon',
    'elasticsearch': 'Elasticsearch search engine',
    'kibana': 'Kibana - visualisasi data Elasticsearch',
    'logstash': 'Logstash - log processor',
    'rabbitmq': 'RabbitMQ - message broker',
    'celery': 'Celery - distributed task queue',
    'gunicorn': 'Gunicorn - Python WSGI HTTP server',
    'uwsgi': 'uWSGI - application server',
    'pm2': 'PM2 - Node.js process manager',
    'supervisor': 'Supervisor - process control system',
}

# Tanda-tanda proses mencurigakan dan berbahaya
SUSPICIOUS_PATTERNS = {
    'nc': '⚠️ NETCAT - Tool networking yang bisa digunakan backdoor',
    'ncat': '⚠️ NCAT - Versi modern netcat, potensial backdoor',
    '/dev/tcp': '⚠️ BASH BACKDOOR - Koneksi TCP mencurigakan',
    'bash -i': '⚠️ INTERACTIVE SHELL - Kemungkinan reverse shell',
    'sh -i': '⚠️ SHELL INTERAKTIF - Kemungkinan remote access',
    'perl.*socket': '🔴 PERL BACKDOOR - Script Perl dengan socket',
    'python.*socket': '🔴 PYTHON BACKDOOR - Script Python dengan socket',
    'xmrig': '🔴 CRYPTO MINER - Malware mining cryptocurrency',
    'minerd': '🔴 CRYPTO MINER - Program mining ilegal',
    'stratum': '🔴 MINING POOL - Koneksi ke mining pool',
    'masscan': '⚠️ PORT SCANNER - Tool scanning jaringan',
    'nmap': '⚠️ NETWORK SCANNER - Tool scanning keamanan',
    'metasploit': '🔴 EXPLOITATION TOOL - Framework hacking',
    'msfconsole': '🔴 METASPLOIT - Console exploitation',
    'nikto': '⚠️ WEB SCANNER - Scanner vulnerability website',
    'sqlmap': '⚠️ SQL INJECTION TOOL - Tool exploit database',
    'hydra': '🔴 BRUTE FORCE TOOL - Cracker password',
    'john': '🔴 JOHN THE RIPPER - Password cracker',
    'hashcat': '🔴 PASSWORD CRACKER - Hash cracking tool',
    'aircrack': '⚠️ WIFI CRACKER - Tool crack WiFi',
    'tcpdump': '⚠️ PACKET SNIFFER - Monitoring network traffic',
    'wireshark': '⚠️ NETWORK ANALYZER - Analisa paket jaringan',
    'backdoor': '🔴 BACKDOOR - Akses tersembunyi tidak sah',
    'rootkit': '🔴 ROOTKIT - Malware level kernel',
    'keylog': '🔴 KEYLOGGER - Perekam keystroke',
    'ransom': '🔴 RANSOMWARE - Malware enkripsi file',
    'trojan': '🔴 TROJAN - Malware tersembunyi',
    'bot': '⚠️ BOT - Program otomatis (potensial botnet)',
    'ddos': '🔴 DDoS TOOL - Distributed Denial of Service',
    'exploit': '🔴 EXPLOIT - Kode eksploitasi vulnerability',
}

# ==============================================================================
#                      LOGGING SETUP
# ==============================================================================
class VPSLogger:
    """Centralized logging system"""
    def __init__(self):
        self.log_dir = Path("logs")
        self.log_dir.mkdir(exist_ok=True)
        
        # Setup main logger
        self.logger = logging.getLogger("VPSMonitor")
        self.logger.setLevel(logging.DEBUG)
        
        # Daily rotating file handler
        log_file = self.log_dir / f"vps_monitor_{datetime.now().strftime('%Y%m%d')}.log"
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=10*1024*1024,  # 10MB
            backupCount=30  # Keep 30 days
        )
        file_handler.setLevel(logging.DEBUG)
        
        # Error file handler
        error_file = self.log_dir / f"vps_errors_{datetime.now().strftime('%Y%m%d')}.log"
        error_handler = RotatingFileHandler(
            error_file,
            maxBytes=5*1024*1024,  # 5MB
            backupCount=30
        )
        error_handler.setLevel(logging.ERROR)
        
        # Formatter
        formatter = logging.Formatter(
            '%(asctime)s | %(levelname)-8s | %(funcName)-25s | %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(formatter)
        error_handler.setFormatter(formatter)
        
        self.logger.addHandler(file_handler)
        self.logger.addHandler(error_handler)
        
        self.logger.info("="*80)
        self.logger.info("VPS Security Monitor Started")
        self.logger.info("="*80)
    
    def info(self, msg):
        self.logger.info(msg)
    
    def warning(self, msg):
        self.logger.warning(msg)
    
    def error(self, msg, exc_info=False):
        self.logger.error(msg, exc_info=exc_info)
    
    def critical(self, msg, exc_info=False):
        self.logger.critical(msg, exc_info=exc_info)
    
    def debug(self, msg):
        self.logger.debug(msg)

# Global logger instance
vps_logger = VPSLogger()

# ==============================================================================
#                      SSH CONNECTION MANAGER
# ==============================================================================
# ==============================================================================
#                      SSH CONNECTION MANAGER
# ==============================================================================
class SSHConnectionManager:
    """Manages a single, persistent, interactive SSH session as root."""
    def __init__(self, host, logger):
        self.host = host
        self.logger = logger
        self.process = None
        self.output_queue = Queue()
        self.is_running = True
        self.session_ready = False
        
        self.start_session()

    def _reader_thread(self):
        """Reads stdout/stderr from the SSH process and puts it into a queue."""
        try:
            for line in iter(self.process.stdout.readline, ''):
                if not self.is_running:
                    break
                self.output_queue.put(line)
        except Exception as e:
            self.logger.error(f"SSH reader thread exception: {e}", exc_info=True)
        self.logger.info("SSH reader thread finished.")

    def start_session(self):
        """Starts the persistent `ssh sudo -i` session."""
        if self.process and self.process.poll() is None:
            self.logger.warning("start_session called, but process is already running.")
            return

        try:
            # Use stdbuf to ensure line-buffering for real-time output
            # The command now directly starts a root shell
            cmd = f'ssh -T {self.host} "stdbuf -o0 sudo -i"'
            
            self.logger.info(f"Starting persistent SSH session with: {cmd}")
            
            self.process = subprocess.Popen(
                cmd.split(),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,  # Redirect stderr to stdout
                text=True,
                encoding='utf-8',
                errors='replace',
                bufsize=1,  # Line-buffered
            )
            
            # Start a thread to read output asynchronously
            self.reader = threading.Thread(target=self._reader_thread, daemon=True)
            self.reader.start()
            self.logger.info("Persistent SSH session process started.")
            
            # Test the connection to ensure the shell is ready
            test_result, err = self.execute('echo "READY"', timeout=10)
            if err or "READY" not in test_result:
                self.logger.error(f"Post-connection check failed. Error: {err}, Output: {test_result[:100]}")
                self.session_ready = False
            else:
                self.logger.info("Persistent SSH session is ready and running as root.")
                self.session_ready = True
                
        except Exception as e:
            self.logger.error(f"Failed to start persistent SSH session: {e}", exc_info=True)
            self.process = None
            self.session_ready = False

    def execute(self, command, timeout=15):
        """Executes a command in the persistent root shell."""
        if not self.session_ready or not self.process or self.process.poll() is not None:
            self.logger.error("SSH session is not ready or has terminated.")
            # In a real-world scenario, you might want to trigger a reconnect here.
            return "", "SSH session not running."

        # A unique boundary to know when the command has finished
        boundary = f"END_OF_COMMAND_{uuid.uuid4()}"
        
        # We send the command and then immediately echo the boundary.
        full_command = f"{command}; echo {boundary}\n"
        
        try:
            self.process.stdin.write(full_command)
            self.process.stdin.flush()
            self.logger.debug(f"Executed: {command[:100]}")
            
            output_lines = []
            start_time = time.time()
            
            while True:
                # Check for command timeout
                if time.time() - start_time > timeout:
                    self.logger.error(f"Command '{command[:50]}' timed out after {timeout}s.")
                    return "".join(output_lines), "Timeout"
                
                try:
                    # Wait for a line from the reader thread
                    line = self.output_queue.get(timeout=0.2)
                    
                    # If the boundary is in the line, we're done.
                    if boundary in line:
                        break
                    
                    # Don't include the prompt (e.g., "root@hostname:~# ") in the output
                    if 'root@' not in line and ':~#' not in line:
                        output_lines.append(line)

                except Queue.Empty:
                    # If the queue is empty, check if the process is still alive
                    if self.process.poll() is not None:
                        self.logger.error("SSH process terminated unexpectedly during command execution.")
                        self.session_ready = False
                        return "".join(output_lines), "SSH process terminated."
                    continue

            return "".join(output_lines), None
            
        except Exception as e:
            self.logger.error(f"Error executing command '{command[:50]}': {e}", exc_info=True)
            # Mark session as not ready if we get a broken pipe or other I/O error
            self.session_ready = False
            return "", f"Error: {e}"

    def close(self):
        """Closes the persistent SSH session."""
        self.logger.info("Closing persistent SSH session.")
        self.is_running = False
        self.session_ready = False
        if self.process:
            try:
                self.process.stdin.close()
                self.process.stdout.close()
            except:
                pass # Ignore errors on close
            self.process.terminate()
            self.process.wait(timeout=5)
        if self.reader and self.reader.is_alive():
            self.reader.join()
        self.logger.info("Session closed.")

class Tooltip:
    """Enhanced Tooltip dengan styling lebih baik"""
    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tooltip = None
        self.after_id = None
        self.widget.bind("<Enter>", self.schedule_show)
        self.widget.bind("<Leave>", self.hide)
    
    def schedule_show(self, event=None):
        if self.after_id:
            self.widget.after_cancel(self.after_id)
        self.after_id = self.widget.after(500, lambda: self.show(event))
    
    def show(self, event=None):
        if self.tooltip or not self.text:
            return
        
        try:
            x = self.widget.winfo_rootx() + 20
            y = self.widget.winfo_rooty() + self.widget.winfo_height() + 5
            
            self.tooltip = ctk.CTkToplevel(self.widget)
            self.tooltip.wm_overrideredirect(True)
            self.tooltip.wm_geometry(f"+{x}+{y}")
            self.tooltip.attributes('-alpha', 0.96)
            self.tooltip.attributes('-topmost', True)
            
            # Shadow effect dengan frame tambahan
            shadow = ctk.CTkFrame(
                self.tooltip,
                fg_color="#000000",
                corner_radius=10
            )
            shadow.pack(padx=2, pady=2)
            
            label = ctk.CTkLabel(
                shadow,
                text=self.text,
                fg_color=("#2a2a3a", "#1a1a2a"),
                corner_radius=8,
                padx=14,
                pady=10,
                font=("Segoe UI", 10),
                text_color="#f1f5f9"
            )
            label.pack()
        except:
            pass
    
    def hide(self, event=None):
        if self.after_id:
            self.widget.after_cancel(self.after_id)
            self.after_id = None
        if self.tooltip:
            try:
                self.tooltip.destroy()
            except:
                pass
            self.tooltip = None

class VPSSecurityMonitor(ctk.CTk):
    def __init__(self):
        super().__init__()
        
        vps_logger.info("Initializing VPS Security Monitor")
        
        # --- Config ---
        self.ssh_host = SSH_HOST
        self.vps_ip = "Unknown"
        
        # SSH Connection Manager (New persistent session implementation)
        self.ssh_manager = SSHConnectionManager(self.ssh_host, vps_logger)
        
        # --- State ---
        self.is_ip_blurred = True
        self.is_expanded = False
        self.running = True
        self.is_dragging = False
        self.is_maximized = False
        self.is_resizing = False
        
        # Command queue for terminal
        self.command_queue = Queue()
        self.command_history = []
        self.command_results = []
        
        # --- Tab state ---
        self.active_tab = "security"
        self.tab_buttons = {}
        
        # --- Window Management ---
        self.blurred_ip = "•••.•••.•••.•••"
        self.snap_threshold = 20
        self.edge_snap = None
        self.is_hidden = False
        self.after_id = None
        self.last_compact_pos = None
        self.last_normal_geometry = None
        self.min_width = 1000
        self.min_height = 700
        self.drag_start_x = 0
        self.drag_start_y = 0
        self.window_start_x = 0
        self.window_start_y = 0

        # --- Data Storage ---
        self.security_data = {
            'ports': ['tcp LISTEN 0.0.0.0:22', 'tcp LISTEN 0.0.0.0:80'], 
            'suspicious_processes': [], 
            'cronjobs': [], 
            'last_logins': ['Loading...'], 
            'firewall_status': 'Checking...', 
            'updates_available': 0, 
            'disk_usage': {'percentage': '0'}, 
            'network_connections': [], 
            'active_services': [], 
            'failed_logins': [], 
            'docker_containers': [], 
            'ssl_certs': [],
            'attackers': [], 
            'syslog': [], 
            'kernel_logs': [], 
            'top_processes': []
        }
        self.last_cpu = 0
        self.cpu_cores = 1
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
        self.process_details = {}
        
        # Real-time stats
        self.last_update_time = None
        self.update_interval = 1  # KURANGI dari 2 ke 1 detik untuk lebih realtime
        self.fetch_basic_interval = 1  # Every 1 second
        self.fetch_security_interval = 10  # Every 10 seconds (bukan 30)
        self.fetch_extended_interval = 30  # Every 30 seconds (bukan 60)

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
        self.iconify()  # Hide temporarily
        
        # Start with compact view
        self.compact_width = 300
        self.compact_height = 750
        
        vps_logger.info("Creating UI components")
        
        # --- UI Creation ---
        self._create_compact_ui()
        
        # Position and show window
        self.after(100, self._position_and_show)
        
        # --- Main Loop ---
        vps_logger.info("Starting main monitoring loop")
        threading.Thread(target=self.main_loop, daemon=True).start()
        
        # Command processor
        threading.Thread(target=self.process_commands, daemon=True).start()

    def _position_and_show(self):
        """Position window and show it"""
        screen_width = self.winfo_screenwidth()
        screen_height = self.winfo_screenheight()
        x = screen_width - self.compact_width - 30
        y = (screen_height - self.compact_height) // 2
        
        self.geometry(f"{self.compact_width}x{self.compact_height}+{x}+{y}")
        self.deiconify()

    def _create_compact_ui(self):
        """Compact floating widget view - FIXED"""
        self.overrideredirect(True)
        self.attributes('-topmost', True)
        self.attributes('-alpha', 0.96)
        self.configure(fg_color=self.bg_primary)
        
        # Main container
        self.compact_container = ctk.CTkFrame(
            self, 
            corner_radius=18, 
            fg_color=self.bg_secondary,
            border_width=2, 
            border_color=self.bg_tertiary
        )
        self.compact_container.pack(fill="both", expand=True, padx=4, pady=4)
        
        # Header with drag support
        header = ctk.CTkFrame(
            self.compact_container, 
            fg_color="transparent", 
            height=50
        )
        header.pack(fill="x", padx=18, pady=(18, 12))
        header.pack_propagate(False)
        
        # Make header draggable
        header.bind("<Button-1>", self.start_drag)
        header.bind("<B1-Motion>", self.do_drag)
        header.bind("<ButtonRelease-1>", self.stop_drag)
        
        # IP Label
        ip_container = ctk.CTkFrame(header, fg_color="transparent")
        ip_container.pack(side="left", fill="y")
        ip_container.bind("<Button-1>", self.start_drag)
        ip_container.bind("<B1-Motion>", self.do_drag)
        
        self.lbl_ip = ctk.CTkLabel(
            ip_container, 
            text=f"🖥️ {self.blurred_ip}", 
            font=("Segoe UI Semibold", 13), 
            text_color=self.accent_blue,
            cursor="hand2"
        )
        self.lbl_ip.pack(anchor="w")
        self.lbl_ip.bind("<Button-1>", self.toggle_ip_blur)
        Tooltip(self.lbl_ip, "Klik untuk show/hide IP")
        
        self.lbl_subtitle = ctk.CTkLabel(
            ip_container,
            text="VPS Security Monitor",
            font=("Segoe UI", 9),
            text_color=self.text_dim
        )
        self.lbl_subtitle.pack(anchor="w", pady=(2, 0))
        self.lbl_subtitle.bind("<Button-1>", self.start_drag)
        self.lbl_subtitle.bind("<B1-Motion>", self.do_drag)
        
        # Control buttons
        btn_container = ctk.CTkFrame(header, fg_color="transparent")
        btn_container.pack(side="right")
        
        btn_expand = ctk.CTkButton(
            btn_container, text="⛶", width=36, height=36, corner_radius=9,
            fg_color=self.bg_tertiary, hover_color=self.accent_blue,
            command=self.toggle_expand, font=("Segoe UI", 15),
            cursor="hand2"
        )
        btn_expand.pack(side="left", padx=2)
        Tooltip(btn_expand, "Expand ke dashboard lengkap")
        self.btn_expand = btn_expand
        
        btn_close = ctk.CTkButton(
            btn_container, text="✕", width=36, height=36, corner_radius=9,
            fg_color=self.bg_tertiary, hover_color=self.accent_red,
            command=self.quit_app, font=("Segoe UI", 13),
            cursor="hand2"
        )
        btn_close.pack(side="left", padx=2)
        Tooltip(btn_close, "Tutup aplikasi")
        
        # Status indicator
        status_frame = ctk.CTkFrame(
            self.compact_container, 
            fg_color=self.bg_tertiary, 
            corner_radius=10, 
            height=42
        )
        status_frame.pack(fill="x", padx=18, pady=(0, 12))
        status_frame.pack_propagate(False)
        
        self.lbl_status = ctk.CTkLabel(
            status_frame, text="🔄 Connecting...", 
            font=("Segoe UI", 10), text_color=self.text_secondary
        )
        self.lbl_status.pack(pady=11)
        
        # System Stats Card
        stats_card = ctk.CTkFrame(
            self.compact_container, 
            fg_color=self.bg_tertiary, 
            corner_radius=14
        )
        stats_card.pack(fill="x", padx=18, pady=(0, 12))
        
        ctk.CTkLabel(
            stats_card, text="⚡ SYSTEM", 
            font=("Segoe UI Semibold", 11), 
            text_color=self.accent_purple
        ).pack(pady=(14, 12))
        
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
            corner_radius=14
        )
        sec_card.pack(fill="x", padx=18, pady=(0, 12))
        
        ctk.CTkLabel(
            sec_card, text="🛡️ SECURITY", 
            font=("Segoe UI Semibold", 11), 
            text_color=self.accent_red
        ).pack(pady=(14, 12))
        
        self.lbl_ports = ctk.CTkLabel(
            sec_card, text="Ports: ---", 
            font=("Segoe UI", 10), text_color=self.text_secondary
        )
        self.lbl_ports.pack(pady=4)
        
        self.lbl_firewall = ctk.CTkLabel(
            sec_card, text="Firewall: ---", 
            font=("Segoe UI", 10), text_color=self.text_secondary
        )
        self.lbl_firewall.pack(pady=4)
        
        self.lbl_updates = ctk.CTkLabel(
            sec_card, text="Updates: ---", 
            font=("Segoe UI", 10), text_color=self.text_secondary
        )
        self.lbl_updates.pack(pady=4)
        
        self.lbl_attackers = ctk.CTkLabel(
            sec_card, text="Threats: ---", 
            font=("Segoe UI", 10), text_color=self.text_secondary
        )
        self.lbl_attackers.pack(pady=(4, 14))
        
        # Top Processes Card
        proc_card = ctk.CTkFrame(
            self.compact_container, 
            fg_color=self.bg_tertiary, 
            corner_radius=14
        )
        proc_card.pack(fill="both", expand=True, padx=18, pady=(0, 18))
        
        ctk.CTkLabel(
            proc_card, text="📈 TOP PROCESSES", 
            font=("Segoe UI Semibold", 11), 
            text_color=self.accent_green
        ).pack(pady=(14, 10))
        
        self.txt_proc = ctk.CTkTextbox(
            proc_card, 
            font=("Consolas", 9), 
            fg_color=self.bg_primary, 
            text_color=self.text_primary,
            wrap="none",
            activate_scrollbars=True
        )
        self.txt_proc.pack(fill="both", expand=True, padx=14, pady=(0, 14))
        self.txt_proc.configure(state="disabled")
        
        # Hover effects
        self.bind("<Enter>", self.on_enter)
        self.bind("<Leave>", self.on_leave)

    def _create_stat_bar(self, parent, label, lbl_name, prog_name, color):
        """Create a stat bar with label and progress"""
        frame = ctk.CTkFrame(parent, fg_color="transparent")
        frame.pack(fill="x", padx=14, pady=(0, 12))
        
        label_frame = ctk.CTkFrame(frame, fg_color="transparent")
        label_frame.pack(fill="x")
        
        ctk.CTkLabel(
            label_frame, text=label, 
            font=("Segoe UI", 10), 
            text_color=self.text_secondary
        ).pack(side="left")
        
        lbl = ctk.CTkLabel(
            label_frame, text="---%", 
            font=("Segoe UI Semibold", 10), 
            text_color=color
        )
        lbl.pack(side="right")
        setattr(self, lbl_name, lbl)
        
        prog = ctk.CTkProgressBar(
            frame, height=7, corner_radius=4, 
            progress_color=color,
            fg_color=self.bg_primary
        )
        prog.pack(fill="x", pady=(5, 0))
        prog.set(0)
        setattr(self, prog_name, prog)

    def _create_expanded_ui(self):
        """Full dashboard view - COMPLETELY FIXED"""
        vps_logger.info("Creating expanded UI")
        
        # Reset window properties
        self.overrideredirect(False)
        self.attributes('-topmost', False)
        self.attributes('-alpha', 0.98)
        self.resizable(True, True)
        self.minsize(self.min_width, self.min_height)
        
        # Main background
        self.configure(fg_color=self.bg_primary)
        
        # Top-level container that fills everything
        main_container = ctk.CTkFrame(self, fg_color=self.bg_primary)
        main_container.pack(fill="both", expand=True)
        
        # Header (fixed height)
        header = ctk.CTkFrame(
            main_container, 
            fg_color=self.bg_secondary, 
            corner_radius=0,
            height=90
        )
        header.pack(fill="x", side="top")
        header.pack_propagate(False)
        
        title_container = ctk.CTkFrame(header, fg_color="transparent")
        title_container.pack(fill="both", expand=True, padx=30, pady=20)
        
        # Title and IP
        title_frame = ctk.CTkFrame(title_container, fg_color="transparent")
        title_frame.pack(side="left", fill="y")
        
        ip_display = self.blurred_ip if self.is_ip_blurred else self.vps_ip
        
        self.lbl_ip_expanded = ctk.CTkLabel(
            title_frame, 
            text="🖥️ VPS Security Dashboard", 
            font=("Segoe UI", 22, "bold"), 
            text_color=self.accent_blue
        )
        self.lbl_ip_expanded.pack(anchor="w")
        
        self.lbl_ip_sub = ctk.CTkLabel(
            title_frame, 
            text=f"Monitoring: {ip_display}", 
            font=("Segoe UI", 12), 
            text_color=self.text_secondary,
            cursor="hand2"
        )
        self.lbl_ip_sub.pack(anchor="w", pady=(4, 0))
        self.lbl_ip_sub.bind("<Button-1>", self.toggle_ip_blur)
        Tooltip(self.lbl_ip_sub, "Klik untuk show/hide IP")
        
        self.lbl_last_update = ctk.CTkLabel(
            title_frame, 
            text="Last update: Never", 
            font=("Segoe UI", 9), 
            text_color=self.text_dim
        )
        self.lbl_last_update.pack(anchor="w", pady=(3, 0))
        
        # Control buttons - PERBAIKI BAGIAN INI
        btn_container = ctk.CTkFrame(title_container, fg_color="transparent")
        btn_container.pack(side="right", fill="y")
        
        btn_frame = ctk.CTkFrame(btn_container, fg_color="transparent")
        btn_frame.pack(expand=True)
        
        # Button Minimize
        btn_minimize = ctk.CTkButton(
            btn_frame, text="−", width=45, height=40, corner_radius=10,
            fg_color=self.bg_tertiary, hover_color=self.accent_blue,
            command=self.iconify, font=("Segoe UI", 18),
            cursor="hand2"
        )
        btn_minimize.pack(side="left", padx=3)
        Tooltip(btn_minimize, "Minimize window")
        
        # Button Maximize
        btn_maximize = ctk.CTkButton(
            btn_frame, text="⛶", width=45, height=40, corner_radius=10,
            fg_color=self.bg_tertiary, hover_color=self.accent_purple,
            command=self.toggle_maximize, font=("Segoe UI", 16),
            cursor="hand2"
        )
        btn_maximize.pack(side="left", padx=3)
        Tooltip(btn_maximize, "Maximize/Restore")
        
        # Button Refresh
        btn_refresh = ctk.CTkButton(
            btn_frame, text="🔄", width=45, height=40, corner_radius=10,
            fg_color=self.accent_green, hover_color="#22c55e",
            command=self.force_refresh, font=("Segoe UI", 15),
            cursor="hand2"
        )
        btn_refresh.pack(side="left", padx=3)
        Tooltip(btn_refresh, "Force refresh semua data")
        
        # Button Reconnect
        btn_reconnect = ctk.CTkButton(
            btn_frame, text="🔌", width=45, height=40, corner_radius=10,
            fg_color=self.accent_orange, hover_color="#f97316",
            command=self.force_reconnect, font=("Segoe UI", 15),
            cursor="hand2"
        )
        btn_reconnect.pack(side="left", padx=3)
        Tooltip(btn_reconnect, "Force reconnect to VPS")
        
        # Button Compact
        btn_compact = ctk.CTkButton(
            btn_frame, text="📉", width=45, height=40, corner_radius=10,
            fg_color=self.bg_tertiary, hover_color=self.accent_orange,
            command=self.toggle_expand, font=("Segoe UI", 15),
            cursor="hand2"
        )
        btn_compact.pack(side="left", padx=3)
        Tooltip(btn_compact, "Switch ke compact view")
        self.btn_compact = btn_compact
        
        # Content area - THIS IS THE FIX
        content_frame = ctk.CTkFrame(main_container, fg_color="transparent")
        content_frame.pack(fill="both", expand=True, side="top")
        
        # Left sidebar (fixed width)
        left_panel = ctk.CTkFrame(
            content_frame, 
            fg_color=self.bg_secondary, 
            corner_radius=0,
            width=360
        )
        left_panel.pack(side="left", fill="y", padx=0, pady=0)
        left_panel.pack_propagate(False)
        
        # Scrollable left content
        left_scroll = ctk.CTkScrollableFrame(
            left_panel,
            fg_color="transparent",
            scrollbar_button_color=self.bg_tertiary,
            scrollbar_button_hover_color=self.accent_blue
        )
        left_scroll.pack(fill="both", expand=True, padx=20, pady=20)
        
        ctk.CTkLabel(
            left_scroll, text="📊 SYSTEM OVERVIEW", 
            font=("Segoe UI Semibold", 15), 
            text_color=self.accent_purple
        ).pack(pady=(0, 18))
        
        # Status card
        status_card = ctk.CTkFrame(
            left_scroll, 
            fg_color=self.bg_tertiary, 
            corner_radius=12
        )
        status_card.pack(fill="x", pady=(0, 15))
        
        self.lbl_status_expanded = ctk.CTkLabel(
            status_card, text="🔄 Connecting...", 
            font=("Segoe UI", 11), text_color=self.accent_orange
        )
        self.lbl_status_expanded.pack(pady=16)
        
        # System stats
        self._create_stat_row_exp(left_scroll, "⚡", "CPU", "lbl_cpu_exp", self.accent_blue, True)
        self._create_stat_row_exp(left_scroll, "💾", "RAM", "lbl_ram_exp", self.accent_green, True)
        self._create_stat_row_exp(left_scroll, "💿", "DISK", "lbl_disk_exp", self.accent_orange, True)
        self._create_stat_row_exp(left_scroll, "🔄", "SWAP", "lbl_swap_exp", self.accent_purple, True)
        self._create_stat_row_exp(left_scroll, "📊", "LOAD", "lbl_load_exp", self.accent_blue, False)
        self._create_stat_row_exp(left_scroll, "⏱️", "UPTIME", "lbl_uptime_exp", self.accent_green, False)
        self._create_stat_row_exp(left_scroll, "🌐", "NETWORK", "lbl_network_exp", self.accent_purple, False)
        
        # Alerts section
        ctk.CTkLabel(
            left_scroll, text="🚨 ALERTS", 
            font=("Segoe UI Semibold", 13), 
            text_color=self.accent_red
        ).pack(pady=(20, 12))
        
        self._create_alert_item(left_scroll, "High CPU Usage", "alert_cpu")
        self._create_alert_item(left_scroll, "High RAM Usage", "alert_ram")
        self._create_alert_item(left_scroll, "Low Disk Space", "alert_disk")
        self._create_alert_item(left_scroll, "Security Threats", "alert_security")
        self._create_alert_item(left_scroll, "Updates Available", "alert_updates")
        
        # Right panel - FIXED TO EXPAND
        right_panel = ctk.CTkFrame(content_frame, fg_color="transparent")
        right_panel.pack(side="left", fill="both", expand=True, padx=20, pady=20)
        
        # Tab buttons
        tab_frame = ctk.CTkFrame(right_panel, fg_color="transparent", height=50)
        tab_frame.pack(fill="x", pady=(0, 15))
        tab_frame.pack_propagate(False)
        
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
            ("📜 Logs", "logs"),
            ("💻 Terminal", "terminal")
        ]
        
        for text, tab_id in tabs:
            is_active = tab_id == self.active_tab
            btn = ctk.CTkButton(
                tab_frame, text=text, height=44, corner_radius=10,
                fg_color=self.accent_blue if is_active else self.bg_tertiary,
                hover_color=self.accent_blue,
                command=lambda t=tab_id: self.switch_tab(t),
                font=("Segoe UI", 11),
                cursor="hand2"
            )
            btn.pack(side="left", padx=4, fill="x", expand=True)
            self.tab_buttons[tab_id] = btn
        
        # Tab content - FIXED TO FILL
        self.tab_content = ctk.CTkFrame(
            right_panel, 
            fg_color=self.bg_secondary, 
            corner_radius=14
        )
        self.tab_content.pack(fill="both", expand=True)
        
        # Summary cards
        self.summary_frame = ctk.CTkFrame(self.tab_content, fg_color="transparent")
        self.summary_frame.pack(fill="x", padx=20, pady=(20, 12))
        
        self._create_summary_cards(self.summary_frame)
        
        # Tab textbox - FIXED TO FILL
        self.tab_textbox = ctk.CTkTextbox(
            self.tab_content, 
            font=("Consolas", 10), 
            fg_color=self.bg_tertiary, 
            text_color=self.text_primary,
            wrap="none"
        )
        self.tab_textbox.pack(fill="both", expand=True, padx=20, pady=(0, 20))
        
        self.update_tab_content()

    def _create_stat_row_exp(self, parent, icon, label, value_var, color, show_progress):
        """Create stat row in expanded view"""
        frame = ctk.CTkFrame(parent, fg_color=self.bg_tertiary, corner_radius=10)
        frame.pack(fill="x", pady=6)
        
        content = ctk.CTkFrame(frame, fg_color="transparent")
        content.pack(fill="both", expand=True, padx=16, pady=14)
        
        left = ctk.CTkFrame(content, fg_color="transparent")
        left.pack(side="left", fill="y")
        
        ctk.CTkLabel(
            left, text=icon, 
            font=("Segoe UI", 18)
        ).pack(side="left")
        
        ctk.CTkLabel(
            left, text=label, 
            font=("Segoe UI", 10), 
            text_color=self.text_secondary
        ).pack(side="left", padx=(12, 0))
        
        right = ctk.CTkFrame(content, fg_color="transparent")
        right.pack(side="right", fill="both", expand=True)
        
        value = ctk.CTkLabel(
            right, text="---", 
            font=("Segoe UI Semibold", 11), 
            text_color=color,
            anchor="e"
        )
        value.pack(side="top", fill="x")
        
        if show_progress:
            progress = ctk.CTkProgressBar(
                right, 
                width=140, 
                height=7,
                fg_color=self.bg_primary,
                progress_color=color
            )
            progress.pack(side="bottom", pady=(4, 0), anchor="e")
            progress.set(0)
            
            progress_var = value_var.replace('lbl_', 'pb_')
            setattr(self, progress_var, progress)
        
        setattr(self, value_var, value)

    def _create_alert_item(self, parent, text, alert_var):
        """Create alert item"""
        frame = ctk.CTkFrame(parent, fg_color=self.bg_tertiary, corner_radius=8, height=36)
        frame.pack(fill="x", pady=4)
        frame.pack_propagate(False)
        
        content = ctk.CTkFrame(frame, fg_color="transparent")
        content.pack(fill="both", expand=True, padx=14, pady=8)
        
        indicator = ctk.CTkLabel(
            content, text="●", 
            font=("Segoe UI", 14), 
            text_color=self.bg_primary
        )
        indicator.pack(side="left", padx=(0, 10))
        
        label = ctk.CTkLabel(
            content, text=text, 
            font=("Segoe UI", 10), 
            text_color=self.text_secondary
        )
        label.pack(side="left")
        
        setattr(self, f"indicator_{alert_var}", indicator)
        setattr(self, f"label_{alert_var}", label)

    def _create_summary_cards(self, parent):
        """Create summary cards"""
        # Security
        sec_card = ctk.CTkFrame(parent, fg_color=self.bg_tertiary, corner_radius=10)
        sec_card.pack(side="left", fill="both", expand=True, padx=(0, 10))
        
        ctk.CTkLabel(
            sec_card, text="🛡️ Security", 
            font=("Segoe UI Semibold", 12), 
            text_color=self.accent_blue
        ).pack(pady=(12, 6))
        
        self.lbl_security_summary = ctk.CTkLabel(
            sec_card, text="Loading...", 
            font=("Segoe UI", 10), 
            text_color=self.text_secondary
        )
        self.lbl_security_summary.pack(pady=(0, 12))
        
        # Network
        net_card = ctk.CTkFrame(parent, fg_color=self.bg_tertiary, corner_radius=10)
        net_card.pack(side="left", fill="both", expand=True, padx=(0, 10))
        
        ctk.CTkLabel(
            net_card, text="🌐 Network", 
            font=("Segoe UI Semibold", 12), 
            text_color=self.accent_purple
        ).pack(pady=(12, 6))
        
        self.lbl_network_summary = ctk.CTkLabel(
            net_card, text="Loading...", 
            font=("Segoe UI", 10), 
            text_color=self.text_secondary
        )
        self.lbl_network_summary.pack(pady=(0, 12))
        
        # System
        sys_card = ctk.CTkFrame(parent, fg_color=self.bg_tertiary, corner_radius=10)
        sys_card.pack(side="left", fill="both", expand=True)
        
        ctk.CTkLabel(
            sys_card, text="⚙️ System", 
            font=("Segoe UI Semibold", 12), 
            text_color=self.accent_green
        ).pack(pady=(12, 6))
        
        self.lbl_system_summary = ctk.CTkLabel(
            sys_card, text="Loading...", 
            font=("Segoe UI", 10), 
            text_color=self.text_secondary
        )
        self.lbl_system_summary.pack(pady=(0, 12))

    def _create_command_terminal(self, parent):
        """Create command terminal widget"""
        term_frame = ctk.CTkFrame(parent, fg_color=self.bg_tertiary, corner_radius=14)
        term_frame.pack(fill="both", expand=True, padx=18, pady=(0, 18))
        
        # Header
        header = ctk.CTkFrame(term_frame, fg_color="transparent", height=45)
        header.pack(fill="x", padx=20, pady=(15, 10))
        header.pack_propagate(False)
        
        ctk.CTkLabel(
            header, text="💻 COMMAND TERMINAL", 
            font=("Segoe UI Semibold", 13), 
            text_color=self.accent_green
        ).pack(side="left")
        
        # Quick actions
        actions_frame = ctk.CTkFrame(header, fg_color="transparent")
        actions_frame.pack(side="right")
        
        quick_actions = [
            ("🔄 Update", "sudo apt update && sudo apt upgrade -y"),
            ("🔥 UFW Status", "sudo ufw status verbose"),
            ("🔍 Who", "who"),
            ("📊 Top", "top -bn1 | head -20"),
            ("🌐 Netstat", "sudo netstat -tulnp"),
            ("🔒 Fail2ban", "sudo fail2ban-client status"),
        ]
        
        for label, cmd in quick_actions:
            btn = ctk.CTkButton(
                actions_frame, text=label, width=90, height=30,
                fg_color=self.bg_primary, hover_color=self.accent_blue,
                command=lambda c=cmd: self.execute_quick_command(c),
                font=("Segoe UI", 9), corner_radius=6
            )
            btn.pack(side="left", padx=3)
            Tooltip(btn, f"Execute: {cmd}")
        
        # Output area
        self.term_output = ctk.CTkTextbox(
            term_frame,
            font=("Consolas", 10),
            fg_color=self.bg_primary,
            text_color=self.accent_green,
            wrap="none",
            height=300
        )
        self.term_output.pack(fill="both", expand=True, padx=20, pady=(0, 10))
        
        # Input area
        input_frame = ctk.CTkFrame(term_frame, fg_color="transparent", height=50)
        input_frame.pack(fill="x", padx=20, pady=(0, 15))
        input_frame.pack_propagate(False)
        
        ctk.CTkLabel(
            input_frame, text="$", 
            font=("Consolas", 14, "bold"), 
            text_color=self.accent_green,
            width=30
        ).pack(side="left")
        
        self.term_input = ctk.CTkEntry(
            input_frame,
            placeholder_text="Enter command here...",
            font=("Consolas", 11),
            fg_color=self.bg_primary,
            border_color=self.accent_blue,
            border_width=2,
            height=40
        )
        self.term_input.pack(side="left", fill="both", expand=True, padx=(5, 10))
        self.term_input.bind("<Return>", lambda e: self.execute_terminal_command())
        self.term_input.bind("<Up>", self.navigate_history_up)
        self.term_input.bind("<Down>", self.navigate_history_down)
        
        btn_exec = ctk.CTkButton(
            input_frame, text="▶ Execute", width=100, height=40,
            fg_color=self.accent_green, hover_color="#22c55e",
            command=self.execute_terminal_command,
            font=("Segoe UI Semibold", 11)
        )
        btn_exec.pack(side="right")
        
        btn_clear = ctk.CTkButton(
            input_frame, text="🗑️", width=40, height=40,
            fg_color=self.bg_primary, hover_color=self.accent_red,
            command=self.clear_terminal,
            font=("Segoe UI", 14)
        )
        btn_clear.pack(side="right", padx=(0, 5))
        Tooltip(btn_clear, "Clear terminal")
        
        # Store reference
        self.terminal_frame = term_frame

    def execute_quick_command(self, command):
        """Execute quick command"""
        vps_logger.info(f"Quick command executed: {command}")
        self.command_queue.put(command)
        
        if hasattr(self, 'term_output'):
            self.term_output.configure(state="normal")
            self.term_output.insert("end", f"\n$ {command}\n")
            self.term_output.insert("end", "⏳ Executing...\n")
            self.term_output.configure(state="disabled")
            self.term_output.see("end")

    def execute_terminal_command(self):
        """Execute terminal command"""
        if not hasattr(self, 'term_input'):
            return
        
        command = self.term_input.get().strip()
        if not command:
            return
        
        vps_logger.info(f"Terminal command executed: {command}")
        
        self.command_history.append(command)
        self.command_queue.put(command)
        
        if hasattr(self, 'term_output'):
            self.term_output.configure(state="normal")
            self.term_output.insert("end", f"\n$ {command}\n")
            self.term_output.insert("end", "⏳ Executing...\n")
            self.term_output.configure(state="disabled")
            self.term_output.see("end")
        
        self.term_input.delete(0, "end")

    def navigate_history_up(self, event):
        """Navigate command history up"""
        if self.command_history:
            self.term_input.delete(0, "end")
            self.term_input.insert(0, self.command_history[-1])

    def navigate_history_down(self, event):
        """Navigate command history down"""
        self.term_input.delete(0, "end")

    def clear_terminal(self):
        """Clear terminal output"""
        if hasattr(self, 'term_output'):
            self.term_output.configure(state="normal")
            self.term_output.delete("1.0", "end")
            self.term_output.insert("1.0", "💻 Terminal Ready\n" + "="*80 + "\n")
            self.term_output.configure(state="disabled")

    def process_commands(self):
        """Process command queue"""
        while self.running:
            try:
                if not self.command_queue.empty():
                    command = self.command_queue.get()
                    
                    vps_logger.info(f"Processing command: {command}")
                    
                    result, error = self.ssh_manager.execute(command, timeout=60)
                    
                    if hasattr(self, 'term_output'):
                        self.after(0, self._display_command_result, command, result, error)
                    
                    self.command_results.append({
                        'command': command,
                        'result': result,
                        'error': error,
                        'timestamp': datetime.now().isoformat()
                    })
                    
                    # Save to log
                    if error:
                        vps_logger.error(f"Command '{command}' failed: {error}")
                    else:
                        vps_logger.info(f"Command '{command}' completed successfully")
                
                time.sleep(0.1)
                
            except Exception as e:
                vps_logger.error(f"Command processor error: {str(e)}", exc_info=True)

    def _display_command_result(self, command, result, error):
        """Display command result in terminal"""
        if not hasattr(self, 'term_output'):
            return
        
        try:
            self.term_output.configure(state="normal")
            
            if error:
                self.term_output.insert("end", f"❌ ERROR: {error}\n\n")
            else:
                self.term_output.insert("end", result if result else "(no output)\n")
                self.term_output.insert("end", "\n✅ Command completed\n")
            
            self.term_output.insert("end", "─"*80 + "\n")
            self.term_output.configure(state="disabled")
            self.term_output.see("end")
        except Exception as e:
            vps_logger.error(f"Display result error: {str(e)}")

    def get_process_info(self, proc_name):
        """Get process information in Indonesian"""
        proc_lower = proc_name.lower()
        
        # Check for suspicious patterns first
        for pattern, info in SUSPICIOUS_PATTERNS.items():
            if pattern in proc_lower:
                return info
        
        # Check normal processes
        for key, info in PROCESS_INFO.items():
            if key in proc_lower:
                return info
        
        return "Program tidak dikenal - perlu diperiksa"

    def analyze_process_security(self, proc_list):
        """Analyze processes for security threats"""
        threats = []
        
        for proc in proc_list:
            proc_lower = proc.lower()
            for pattern, description in SUSPICIOUS_PATTERNS.items():
                if pattern in proc_lower:
                    threats.append({
                        'process': proc,
                        'threat': pattern,
                        'description': description,
                        'severity': '🔴 CRITICAL' if '🔴' in description else '⚠️ WARNING'
                    })
        
        return threats

    def _update_alerts(self, cpu, ram_pct, disk_pct, threat_count, updates):
        """Update alert indicators"""
        if not self.is_expanded:
            return
        
        try:
            # CPU Alert
            if cpu > 80:
                self.indicator_alert_cpu.configure(text_color=self.accent_red)
                self.label_alert_cpu.configure(text_color=self.text_primary)
            elif cpu > 60:
                self.indicator_alert_cpu.configure(text_color=self.accent_orange)
                self.label_alert_cpu.configure(text_color=self.text_primary)
            else:
                self.indicator_alert_cpu.configure(text_color=self.bg_primary)
                self.label_alert_cpu.configure(text_color=self.text_secondary)
            
            # RAM Alert
            if ram_pct > 80:
                self.indicator_alert_ram.configure(text_color=self.accent_red)
                self.label_alert_ram.configure(text_color=self.text_primary)
            elif ram_pct > 60:
                self.indicator_alert_ram.configure(text_color=self.accent_orange)
                self.label_alert_ram.configure(text_color=self.text_primary)
            else:
                self.indicator_alert_ram.configure(text_color=self.bg_primary)
                self.label_alert_ram.configure(text_color=self.text_secondary)
            
            # Disk Alert
            if disk_pct > 90:
                self.indicator_alert_disk.configure(text_color=self.accent_red)
                self.label_alert_disk.configure(text_color=self.text_primary)
            elif disk_pct > 70:
                self.indicator_alert_disk.configure(text_color=self.accent_orange)
                self.label_alert_disk.configure(text_color=self.text_primary)
            else:
                self.indicator_alert_disk.configure(text_color=self.bg_primary)
                self.label_alert_disk.configure(text_color=self.text_secondary)
            
            # Security Alert
            if threat_count > 0:
                self.indicator_alert_security.configure(text_color=self.accent_red)
                self.label_alert_security.configure(text_color=self.text_primary)
                self.label_alert_security.configure(text=f"Security Threats ({threat_count})")
            else:
                self.indicator_alert_security.configure(text_color=self.bg_primary)
                self.label_alert_security.configure(text_color=self.text_secondary)
                self.label_alert_security.configure(text="Security Threats")
            
            # Updates Alert
            if updates > 10:
                self.indicator_alert_updates.configure(text_color=self.accent_red)
                self.label_alert_updates.configure(text_color=self.text_primary)
                self.label_alert_updates.configure(text=f"Updates Critical ({updates})")
            elif updates > 0:
                self.indicator_alert_updates.configure(text_color=self.accent_orange)
                self.label_alert_updates.configure(text_color=self.text_primary)
                self.label_alert_updates.configure(text=f"Updates Available ({updates})")
            else:
                self.indicator_alert_updates.configure(text_color=self.bg_primary)
                self.label_alert_updates.configure(text_color=self.text_secondary)
                self.label_alert_updates.configure(text="Updates Available")
        except:
            pass

    def _update_summary_cards(self):
        """Update summary cards"""
        if not self.is_expanded or not hasattr(self, 'lbl_security_summary'):
            return
        
        try:
            # Security
            fw = self.security_data.get('firewall_status', 'Unknown')
            upd = self.security_data.get('updates_available', 0)
            threats = len(self.security_data.get('attackers', []))
            failed = len(self.security_data.get('failed_logins', []))
            
            status = "🟢 Aman"
            if threats > 0 or failed > 10:
                status = "🔴 Berbahaya"
            elif upd > 10 or "inactive" in fw.lower():
                status = "🟡 Peringatan"
            
            self.lbl_security_summary.configure(text=f"{status}\n{threats} ancaman, {failed} login gagal")
            
            # Network
            ports = len(self.security_data.get('ports', []))
            conns = len(self.security_data.get('network_connections', []))
            rx = self.network_stats.get('rx', 0)
            tx = self.network_stats.get('tx', 0)
            
            self.lbl_network_summary.configure(text=f"{ports} port terbuka\n{conns} koneksi aktif\n↓{rx}MB ↑{tx}MB")
            
            # System
            services = len(self.security_data.get('active_services', []))
            cron = len(self.security_data.get('cronjobs', []))
            docker = len(self.security_data.get('docker_containers', []))
            
            self.lbl_system_summary.configure(text=f"{services} services\n{cron} cron jobs\n{docker} containers")
        except:
            pass

    def run_ssh_command(self, command):
        """Execute SSH command using the persistent session manager."""
        result, error = self.ssh_manager.execute(command)
        if error:
            vps_logger.warning(f"Command '{command[:30]}...' failed: {error}")
            # With a persistent session, an error might mean the session is dead.
            # The manager should handle its state, but we return empty here.
            return ""
        return result

    def toggle_maximize(self):
        """Toggle maximize"""
        if not self.is_expanded:
            return
        
        if self.is_maximized:
            if self.last_normal_geometry:
                self.geometry(self.last_normal_geometry)
            self.is_maximized = False
        else:
            self.last_normal_geometry = self.geometry()
            self.state('zoomed')  # Windows 11 native maximize
            self.is_maximized = True

    def switch_tab(self, tab_id):
        """Switch tabs"""
        self.active_tab = tab_id
        
        # Update button colors
        for tid, btn in self.tab_buttons.items():
            btn.configure(
                fg_color=self.accent_blue if tid == tab_id else self.bg_tertiary
            )
        
        if tab_id == "terminal":
            # Show terminal
            try:
                # Hide textbox and summary if exists
                if hasattr(self, 'tab_textbox') and self.tab_textbox.winfo_exists():
                    self.tab_textbox.pack_forget()
                if hasattr(self, 'summary_frame') and self.summary_frame.winfo_exists():
                    self.summary_frame.pack_forget()
                
                # Show or create terminal
                if not hasattr(self, 'terminal_frame') or not self.terminal_frame.winfo_exists():
                    # Bersihkan tab_content dulu
                    for widget in self.tab_content.winfo_children():
                        widget.pack_forget()
                    
                    # Create new terminal
                    self._create_command_terminal(self.tab_content)
                else:
                    # Show existing terminal
                    self.terminal_frame.pack(fill="both", expand=True)
            except Exception as e:
                vps_logger.error(f"Error showing terminal: {str(e)}", exc_info=True)
        else:
            # Show normal tab content
            try:
                # Hide terminal if exists
                if hasattr(self, 'terminal_frame') and self.terminal_frame.winfo_exists():
                    self.terminal_frame.pack_forget()
                
                # Show or create summary frame
                if not hasattr(self, 'summary_frame') or not self.summary_frame.winfo_exists():
                    summary_frame = ctk.CTkFrame(self.tab_content, fg_color="transparent")
                    summary_frame.pack(fill="x", padx=20, pady=(20, 12))
                    self.summary_frame = summary_frame
                    self._create_summary_cards(summary_frame)
                else:
                    self.summary_frame.pack(fill="x", padx=20, pady=(20, 12))
                
                # Show or create textbox
                if not hasattr(self, 'tab_textbox') or not self.tab_textbox.winfo_exists():
                    self.tab_textbox = ctk.CTkTextbox(
                        self.tab_content, 
                        font=("Consolas", 10), 
                        fg_color=self.bg_tertiary, 
                        text_color=self.text_primary,
                        wrap="none"
                    )
                    self.tab_textbox.pack(fill="both", expand=True, padx=20, pady=(0, 20))
                else:
                    self.tab_textbox.pack(fill="both", expand=True, padx=20, pady=(0, 20))
                
                # Update content
                self.update_tab_content()
                
            except Exception as e:
                vps_logger.error(f"Error showing tab content: {str(e)}", exc_info=True)

    def update_tab_content(self):
        """Update tab content with better formatting"""
        if not self.is_expanded or not hasattr(self, 'tab_textbox'):
            return
        
        try:
            if not self.tab_textbox.winfo_exists():
                return
        except:
            return
        
        content = ""
        
        headers = {
            "security": "🛡️ KEAMANAN SISTEM - Status Firewall, Update & Analisis Ancaman",
            "threats": "⚠️ ANCAMAN TERDETEKSI - Analisis Hacker, Malware & Serangan", 
            "ports": "🔌 PORT TERBUKA - Layanan yang Listening & Eksposur Jaringan",
            "processes": "⚙️ PROSES SISTEM - Analisis CPU, Memory & Keamanan Program",
            "network": "🌐 AKTIVITAS JARINGAN - Koneksi, Traffic & Bandwidth",
            "cron": "⏰ TUGAS TERJADWAL - Cron Jobs & Automasi Sistem",
            "docker": "🐳 STATUS CONTAINER - Docker Services & Images",
            "logs": "📜 LOG SISTEM - Authentication, System & Kernel Events"
        }
        
        header = headers.get(self.active_tab, "DETAIL SISTEM")
        content += f"{'═' * 100}\n"
        content += f"  {header}\n"
        content += f"{'═' * 100}\n\n"
        
        if self.active_tab == "security":
            content += self._format_security_tab()
        elif self.active_tab == "threats":
            content += self._format_threats_tab()
        elif self.active_tab == "ports":
            content += self._format_ports_tab()
        elif self.active_tab == "processes":
            content += self._format_processes_tab()
        elif self.active_tab == "network":
            content += self._format_network_tab()
        elif self.active_tab == "cron":
            content += self._format_cron_tab()
        elif self.active_tab == "docker":
            content += self._format_docker_tab()
        elif self.active_tab == "logs":
            content += self._format_logs_tab()
        
        try:
            self.tab_textbox.configure(state="normal")
            self.tab_textbox.delete("1.0", "end")
            
            if content:
                self.tab_textbox.insert("1.0", content)
            else:
                # Default content jika kosong
                self.tab_textbox.insert("1.0", "⏳ Memuat data...\n\nMenghubungkan ke VPS dan mengambil informasi.\nMohon tunggu beberapa saat.")
            
            self.tab_textbox.configure(state="disabled")
        except Exception as e:
            vps_logger.error(f"Error updating tab content: {str(e)}", exc_info=True)

    def _format_security_tab(self):
        """Format security tab dengan analisis lengkap"""
        c = ""
        
        fw = self.security_data.get('firewall_status', 'Unknown')
        upd = self.security_data.get('updates_available', 0)
        ports = len(self.security_data.get('ports', []))
        attackers = len(self.security_data.get('attackers', []))
        failed = len(self.security_data.get('failed_logins', []))
        
        # Status Overview
        c += "📊 RINGKASAN KEAMANAN\n"
        c += "─" * 100 + "\n"
        c += f"🔥 Status Firewall        : {fw}\n"
        c += f"📦 Update Tersedia        : {upd} paket\n"
        c += f"🔌 Port Terbuka           : {ports} port\n"
        c += f"⚠️  Ancaman Terdeteksi     : {attackers} ancaman\n"
        c += f"👤 Riwayat Login          : {len(self.security_data.get('last_logins', []))} sesi\n"
        c += f"❌ Percobaan Login Gagal  : {failed} percobaan\n\n"
        
        # Security Score
        score = 100
        if "inactive" in fw.lower():
            score -= 30
        if upd > 10:
            score -= 20
        if attackers > 0:
            score -= 25
        if failed > 10:
            score -= 15
        
        score = max(0, score)
        status_icon = "🟢" if score >= 80 else "🟡" if score >= 60 else "🔴"
        
        c += f"{status_icon} SKOR KEAMANAN: {score}/100\n"
        if score < 80:
            c += "\n⚠️  REKOMENDASI PERBAIKAN:\n"
            if "inactive" in fw.lower():
                c += "   • Aktifkan firewall: sudo ufw enable\n"
            if upd > 10:
                c += f"   • Update {upd} paket: sudo apt update && sudo apt upgrade\n"
            if attackers > 0:
                c += f"   • Block {attackers} IP attacker dengan fail2ban\n"
            if failed > 10:
                c += "   • Tingkatkan keamanan SSH: disable password login\n"
        
        c += "\n\n" + "─" * 100 + "\n"
        c += "⚠️  PROSES MENCURIGAKAN\n"
        c += "─" * 100 + "\n"
        
        susp = self.security_data.get('suspicious_processes', [])
        if susp:
            threats = self.analyze_process_security(susp)
            if threats:
                for i, threat in enumerate(threats, 1):
                    c += f"\n[{i}] {threat['severity']}\n"
                    c += f"    Proses    : {threat['process']}\n"
                    c += f"    Ancaman   : {threat['threat']}\n"
                    c += f"    Info      : {threat['description']}\n"
                    c += f"    Aksi      : Kill proses dengan: sudo kill -9 <PID>\n"
            else:
                c += "  ✅ Tidak ada proses mencurigakan terdeteksi\n"
        else:
            c += "  ✅ Tidak ada proses mencurigakan terdeteksi\n"
        
        c += "\n" + "─" * 100 + "\n"
        c += "👤 RIWAYAT LOGIN TERAKHIR\n"
        c += "─" * 100 + "\n"
        
        logins = self.security_data.get('last_logins', [])
        for login in logins[:15]:
            c += f"  {login}\n"
        
        return c

    def _format_threats_tab(self):
        """Format threats tab dengan detail serangan"""
        c = ""
        
        attackers = self.security_data.get('attackers', [])
        failed_logins = self.security_data.get('failed_logins', [])
        
        if attackers or failed_logins:
            c += f"📊 Total Ancaman Terdeteksi: {len(attackers) + len(failed_logins)}\n\n"
            
            # Analisis Attackers
            if attackers:
                c += "─" * 100 + "\n"
                c += "🔴 DAFTAR PENYERANG (ATTACKERS)\n"
                c += "─" * 100 + "\n\n"
                
                for i, attacker in enumerate(attackers[:50], 1):
                    c += f"[{i}] 🔴 {attacker['type'].upper()}\n"
                    c += f"    IP Address    : {attacker.get('ip', 'Unknown')}\n"
                    c += f"    Username      : {attacker.get('user', 'Unknown')}\n"
                    c += f"    Waktu         : {attacker.get('time', 'Unknown')}\n"
                    c += f"    Detail        : {attacker.get('details', 'N/A')}\n"
                    c += f"    Tingkat       : {attacker.get('severity', 'Medium')}\n"
                    
                    if attacker.get('recommended_action'):
                        c += f"    📋 Aksi       : {attacker['recommended_action']}\n"
                    
                    c += "\n"
            
            # Failed Logins Analysis
            if failed_logins:
                c += "─" * 100 + "\n"
                c += "❌ PERCOBAAN LOGIN GAGAL\n"
                c += "─" * 100 + "\n\n"
                
                # Group by IP
                ip_counts = {}
                for log in failed_logins:
                    # Extract IP from log
                    ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', log)
                    if ip_match:
                        ip = ip_match.group()
                        ip_counts[ip] = ip_counts.get(ip, 0) + 1
                
                if ip_counts:
                    c += "Top 10 IP Penyerang:\n\n"
                    sorted_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)
                    for i, (ip, count) in enumerate(sorted_ips[:10], 1):
                        severity = "🔴 CRITICAL" if count > 20 else "🟡 WARNING"
                        c += f"  {i}. {severity} - {ip}: {count} percobaan\n"
                        c += f"      Aksi: sudo ufw deny from {ip}\n\n"
            
            c += "\n" + "═" * 100 + "\n"
            c += "💡 PANDUAN TINDAKAN KEAMANAN\n"
            c += "═" * 100 + "\n\n"
            c += "1. BLOKIR IP PENYERANG:\n"
            c += "   sudo ufw deny from <IP_ADDRESS>\n"
            c += "   sudo ufw reload\n\n"
            c += "2. INSTALL & KONFIGURASI FAIL2BAN:\n"
            c += "   sudo apt install fail2ban\n"
            c += "   sudo systemctl enable fail2ban\n"
            c += "   sudo systemctl start fail2ban\n\n"
            c += "3. UBAH PORT SSH (jika perlu):\n"
            c += "   Edit /etc/ssh/sshd_config\n"
            c += "   Ganti: Port 22 → Port 2222\n"
            c += "   sudo systemctl restart sshd\n\n"
            c += "4. DISABLE ROOT LOGIN:\n"
            c += "   Edit /etc/ssh/sshd_config\n"
            c += "   Set: PermitRootLogin no\n"
            c += "   sudo systemctl restart sshd\n\n"
            c += "5. GUNAKAN KEY-BASED AUTH (disable password):\n"
            c += "   Set: PasswordAuthentication no\n"
            c += "   sudo systemctl restart sshd\n"
            
        else:
            c += "✅ SISTEM AMAN - Tidak ada ancaman terdeteksi\n\n"
            c += "VPS Anda dalam kondisi baik. Terus pantau aktivitas mencurigakan.\n\n"
            c += "💡 TIPS KEAMANAN PROAKTIF:\n"
            c += "   • Update sistem secara rutin\n"
            c += "   • Gunakan firewall (UFW/iptables)\n"
            c += "   • Install fail2ban untuk proteksi brute force\n"
            c += "   • Monitor log secara berkala\n"
            c += "   • Gunakan password yang kuat atau SSH keys\n"
        
        return c

    def _format_ports_tab(self):
        """Format ports tab dengan penjelasan"""
        c = ""
        
        ports = self.security_data.get('ports', [])
        if ports:
            c += f"📊 Total Port Terbuka: {len(ports)}\n\n"
            c += "─" * 100 + "\n"
            c += f"{'PROTOKOL':<12} {'PORT':<10} {'STATUS':<15} {'ALAMAT':<25} {'KETERANGAN'}\n"
            c += "─" * 100 + "\n"
            
            port_info = {
                '22': 'SSH - Remote Login (WAJIB diamankan)',
                '80': 'HTTP - Web Server (tidak terenkripsi)',
                '443': 'HTTPS - Web Server Aman (SSL/TLS)',
                '3306': 'MySQL Database (jangan expose public!)',
                '5432': 'PostgreSQL Database (jangan expose public!)',
                '6379': 'Redis Cache (jangan expose public!)',
                '27017': 'MongoDB (jangan expose public!)',
                '8080': 'HTTP Alternatif - Development Server',
                '25': 'SMTP - Mail Server',
                '465': 'SMTPS - Mail Server Secure',
                '587': 'SMTP Submission',
                '21': 'FTP - File Transfer (TIDAK AMAN, gunakan SFTP)',
                '53': 'DNS Server',
                '3000': 'Node.js Development Server',
                '8000': 'Python Development Server',
                '9000': 'PHP-FPM atau lainnya',
            }
            
            for port_line in ports[:50]:
                # Extract port number
                port_match = re.search(r':(\d+)\s', port_line)
                if port_match:
                    port_num = port_match.group(1)
                    info = port_info.get(port_num, 'Service tidak dikenal')
                    
                    # Color code based on security
                    security_icon = "🟢"
                    if port_num in ['3306', '5432', '6379', '27017', '21']:
                        security_icon = "🔴"
                    elif port_num in ['80', '8080', '3000', '8000']:
                        security_icon = "🟡"
                    
                    c += f"{security_icon} {port_line}\n"
                    c += f"      └─ {info}\n\n"
                else:
                    c += f"  {port_line}\n"
            
            c += "\n" + "═" * 100 + "\n"
            c += "⚠️  REKOMENDASI KEAMANAN PORT\n"
            c += "═" * 100 + "\n\n"
            c += "🔴 PORT BERBAHAYA (jika terbuka ke public):\n"
            c += "   • Database ports (3306, 5432, 6379, 27017) - HARUS dibatasi!\n"
            c += "   • FTP (21) - Gunakan SFTP (port 22) sebagai gantinya\n\n"
            c += "🟡 PORT PERLU PERHATIAN:\n"
            c += "   • HTTP (80) - Redirect ke HTTPS jika memungkinkan\n"
            c += "   • Development ports (3000, 8000, 8080) - Jangan expose production\n\n"
            c += "🟢 PORT AMAN:\n"
            c += "   • HTTPS (443) - Gunakan SSL certificate valid\n"
            c += "   • SSH (22) - Gunakan key authentication, disable password\n\n"
            c += "📋 CARA MENUTUP PORT:\n"
            c += "   1. Stop service: sudo systemctl stop <service_name>\n"
            c += "   2. Disable autostart: sudo systemctl disable <service_name>\n"
            c += "   3. Block dengan firewall: sudo ufw deny <port_number>\n"
            
        else:
            c += "❌ Tidak ada port terbuka terdeteksi\n"
            c += "   (Atau tidak memiliki akses untuk melihat netstat/ss)\n"
        
        return c

    def _format_processes_tab(self):
        """Format processes tab dengan analisis keamanan"""
        c = ""
        
        c += "─" * 100 + "\n"
        c += f"{'USER':<12} {'PID':<8} {'CPU%':<8} {'MEM%':<8} {'COMMAND':<30} {'KETERANGAN'}\n"
        c += "─" * 100 + "\n\n"
        
        procs = self.security_data.get('top_processes', [])
        
        for proc_line in procs[:40]:
            c += f"{proc_line}\n"
            
            # Extract command name for info
            parts = proc_line.split()
            if len(parts) > 10:
                cmd = parts[10]
                info = self.get_process_info(cmd)
                c += f"      └─ {info}\n"
            c += "\n"
        
        # Process Security Analysis
        c += "\n" + "═" * 100 + "\n"
        c += "🔍 ANALISIS KEAMANAN PROSES\n"
        c += "═" * 100 + "\n\n"
        
        susp = self.security_data.get('suspicious_processes', [])
        if susp:
            threats = self.analyze_process_security(susp)
            if threats:
                c += "⚠️  PROSES MENCURIGAKAN TERDETEKSI:\n\n"
                for threat in threats:
                    c += f"{threat['severity']}\n"
                    c += f"  Proses: {threat['process']}\n"
                    c += f"  Info: {threat['description']}\n"
                    c += f"  Aksi: Investigate dan kill jika berbahaya\n\n"
            else:
                c += "✅ Tidak ada proses mencurigakan\n"
        else:
            c += "✅ Semua proses terlihat normal\n"
        
        c += "\n💡 TIPS MONITORING PROSES:\n"
        c += "   • Gunakan 'htop' untuk monitoring real-time\n"
        c += "   • Check proses dengan CPU/RAM tinggi\n"
        c += "   • Waspadai proses yang tidak dikenal\n"
        c += "   • Kill proses: sudo kill -9 <PID>\n"
        
        return c

    def _format_network_tab(self):
        """Format network tab"""
        c = ""
        
        c += "📊 STATISTIK JARINGAN\n"
        c += "─" * 100 + "\n"
        c += f"Download (RX): {self.network_stats.get('rx', 0)} MB\n"
        c += f"Upload (TX): {self.network_stats.get('tx', 0)} MB\n\n"
        
        c += "─" * 100 + "\n"
        c += "🌐 KONEKSI AKTIF (ESTABLISHED)\n"
        c += "─" * 100 + "\n\n"
        
        conns = self.security_data.get('network_connections', [])
        if conns:
            for conn in conns[:50]:
                c += f"  {conn}\n"
        else:
            c += "  Tidak ada koneksi aktif\n"
        
        return c

    def _format_cron_tab(self):
        """Format cron tab"""
        c = ""
        
        crons = self.security_data.get('cronjobs', [])
        if crons:
            c += f"📊 Total Cron Jobs: {len(crons)}\n\n"
            c += "─" * 100 + "\n"
            for cron in crons:
                c += f"  {cron}\n"
        else:
            c += "  Tidak ada cron jobs untuk user saat ini\n\n"
            c += "💡 Cek system crontab:\n"
            c += "   • /etc/crontab\n"
            c += "   • /etc/cron.d/\n"
            c += "   • /etc/cron.daily/\n"
            c += "   • /etc/cron.weekly/\n"
        
        return c

    def _format_docker_tab(self):
        """Format docker tab"""
        c = ""
        
        containers = self.security_data.get('docker_containers', [])
        if containers:
            c += f"📊 Total Containers: {len(containers)}\n\n"
            c += "─" * 100 + "\n"
            for container in containers:
                c += f"  {container}\n"
        else:
            c += "  Docker tidak terinstall atau tidak ada container\n"
        
        return c

    def _format_logs_tab(self):
        """Format logs tab"""
        c = ""
        
        c += "❌ PERCOBAAN LOGIN GAGAL (Failed Logins)\n"
        c += "─" * 100 + "\n"
        
        failed = self.security_data.get('failed_logins', [])
        if failed:
            for fail in failed[:25]:
                c += f"  {fail}\n"
        else:
            c += "  Tidak ada percobaan login gagal\n"
        
        c += "\n" + "─" * 100 + "\n"
        c += "📋 SYSTEM LOGS (Journalctl/Syslog)\n"
        c += "─" * 100 + "\n"
        
        syslog = self.security_data.get('syslog', [])
        if syslog:
            for log in syslog[-25:]:
                c += f"  {log}\n"
        else:
            c += "  Tidak ada system logs\n"
        
        c += "\n" + "─" * 100 + "\n"
        c += "⚙️  KERNEL MESSAGES (dmesg)\n"
        c += "─" * 100 + "\n"
        
        kernel = self.security_data.get('kernel_logs', [])
        if kernel:
            for log in kernel[-20:]:
                c += f"  {log}\n"
        else:
            c += "  Tidak ada kernel messages\n"
        
        return c

    def toggle_expand(self):
        """Toggle expand/compact - FIXED"""
        self.is_expanded = not self.is_expanded
        
        # Cleanup
        self.edge_snap = None
        self.is_hidden = False

        if self.is_expanded:
            # Save compact position
            self.last_compact_pos = f"+{self.winfo_x()}+{self.winfo_y()}"
            
            # Destroy compact UI
            if hasattr(self, 'compact_container'):
                self.compact_container.destroy()
                del self.compact_container
            
            self.after(50, self._finish_expand)
        else:
            # Destroy expanded UI
            for widget in self.winfo_children():
                widget.destroy()
            
            self.active_tab = "security"
            self.tab_buttons = {}
            
            self.after(50, self._finish_compact)

    def _finish_expand(self):
        """Finish expanding"""
        self._create_expanded_ui()
        
        # Maximize to fill screen
        screen_width = self.winfo_screenwidth()
        screen_height = self.winfo_screenheight()
        
        # Use Windows 11 native maximize
        try:
            self.state('zoomed')
            self.is_maximized = True
        except:
            # Fallback manual maximize
            self.geometry(f"{screen_width}x{screen_height}+0+0")
        
        # Update UI dengan data yang ada
        self.after(100, self.update_ui_with_latest_data)
        
        # Fetch fresh data
        self.after(200, lambda: threading.Thread(target=self._fetch_all_on_expand, daemon=True).start())

    def _fetch_all_on_expand(self):
        """Fetch all data when expanding"""
        try:
            vps_logger.info("Fetching all data after expand")
            
            # Fetch basic first
            self.fetch_basic_data()
            time.sleep(0.3)
            
            # Then security
            self.fetch_security_data()
            time.sleep(0.3)
            
            # Finally extended
            self.fetch_extended_data()
            
            vps_logger.info("All data fetched successfully")
        except Exception as e:
            vps_logger.error(f"Error fetching data on expand: {str(e)}", exc_info=True)

    def _finish_compact(self):
        """Finish compacting"""
        self.is_maximized = False
        
        self._create_compact_ui()
        
        self.overrideredirect(True)
        self.attributes('-topmost', True)
        self.attributes('-alpha', 0.96)
        
        # Restore position
        if self.last_compact_pos:
            try:
                self.geometry(f"{self.compact_width}x{self.compact_height}{self.last_compact_pos}")
            except:
                self._position_and_show()
        else:
            self._position_and_show()
        
        self.after(100, self.update_ui_with_latest_data)

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
        """Start dragging - FIXED"""
        if self.is_expanded and not self.is_maximized:
            self.is_dragging = True
            self.drag_start_x = e.x
            self.drag_start_y = e.y
            self.window_start_x = self.winfo_x()
            self.window_start_y = self.winfo_y()
        elif not self.is_expanded:
            self.is_dragging = True
            self.drag_start_x = e.x
            self.drag_start_y = e.y
            if self.edge_snap:
                self.show_widget()
            self.edge_snap = None
            self.is_hidden = False

    def stop_drag(self, e):
        """Stop dragging"""
        self.is_dragging = False
        if not self.is_expanded:
            self.snap_to_edge()

    def do_drag(self, e):
        """Handle dragging - FIXED for both modes"""
        if not self.is_dragging:
            return
        
        # Calculate new position
        delta_x = e.x - self.drag_start_x
        delta_y = e.y - self.drag_start_y
        
        if self.is_expanded and not self.is_maximized:
            # Expanded window dragging
            new_x = self.window_start_x + delta_x
            new_y = self.window_start_y + delta_y
            
            # Keep on screen
            screen_width = self.winfo_screenwidth()
            screen_height = self.winfo_screenheight()
            
            new_x = max(0, min(new_x, screen_width - 100))
            new_y = max(0, min(new_y, screen_height - 100))
            
            self.geometry(f"+{new_x}+{new_y}")
            
        else:
            # Compact widget dragging
            x_new = self.winfo_x() + delta_x
            y_new = self.winfo_y() + delta_y
            
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
        # Properly close the persistent SSH session
        if self.ssh_manager:
            self.ssh_manager.close()
        self.destroy()
        sys.exit()

    def main_loop(self):
        """Main loop for data fetching, relies on the persistent SSH manager."""
        last_basic_fetch = 0
        last_security_fetch = 0
        last_extended_fetch = 0
        
        vps_logger.info("Starting main application loop.")

        while self.running:
            try:
                current_time = time.time()
                
                # Check if the persistent session is active and ready
                if self.ssh_manager.session_ready:
                    self.after(0, self.update_status, "🟢 Connected", self.accent_green)
                    
                    # Fetch basic data every second
                    if current_time - last_basic_fetch >= self.fetch_basic_interval:
                        threading.Thread(target=self.fetch_basic_data, daemon=True).start()
                        last_basic_fetch = current_time
                    
                    # Fetch security data every 10 seconds
                    if current_time - last_security_fetch >= self.fetch_security_interval:
                        threading.Thread(target=self.fetch_security_data, daemon=True).start()
                        last_security_fetch = current_time
                    
                    # Fetch extended data every 30 seconds
                    if current_time - last_extended_fetch >= self.fetch_extended_interval:
                        threading.Thread(target=self.fetch_extended_data, daemon=True).start()
                        last_extended_fetch = current_time
                else:
                    # If the session is not ready, display a connecting status.
                    # The SSHConnectionManager is responsible for trying to connect.
                    self.after(0, self.update_status, "🔄 Connecting...", self.accent_orange)
                    vps_logger.warning("Main loop: SSH session not ready. Waiting for manager.")
                
                time.sleep(1)  # Main loop tick rate
                
            except Exception as e:
                vps_logger.critical(f"Critical error in main_loop: {e}", exc_info=True)
                time.sleep(5) # Avoid rapid-fire loops on critical error

    def fetch_basic_data(self):
        """Fetch basic data - OPTIMIZED"""
        if not self.connection_ok:
            return
        
        try:
            # Command yang lebih efisien - hapus 2>/dev/null yang tidak perlu
            cmd = '''
echo "---CPU---"
top -bn1 | grep "Cpu(s)" | awk '{print 100-$8}'
echo "---CORES---"
nproc
echo "---RAM---"
free -m | grep Mem
echo "---DISK---"
df -h / | tail -n1
echo "---UPTIME---"
uptime -p 2>/dev/null || uptime
echo "---LOAD---"
cat /proc/loadavg | awk '{print $1,$2,$3}'
echo "---SWAP---"
free -m | grep Swap
echo "---NET---"
cat /proc/net/dev | grep -E "eth0|ens|enp" | head -n1
echo "---PS---"
ps -eo comm,%cpu,%mem --sort=-%cpu | head -n 11
echo "---END---"
            '''
            
            result, error = self.ssh_manager.execute(cmd, timeout=10)
            
            if error:
                vps_logger.warning(f"fetch_basic_data failed: {error}")
                return
            
            if not result:
                return
            
            # Parse dengan error handling minimal
            try:
                sections = {}
                current_section = None
                for line in result.split('\n'):
                    if line.startswith('---') and line.endswith('---'):
                        current_section = line.strip('-')
                        sections[current_section] = []
                    elif current_section:
                        sections[current_section].append(line)
                
                # CPU
                cpu_val = 0.0
                if 'CPU' in sections and sections['CPU']:
                    try:
                        cpu_str = sections['CPU'][0].strip()
                        cpu_val = float(cpu_str) if cpu_str else 0.0
                    except:
                        pass
                self.last_cpu = cpu_val
                
                # Cores
                if 'CORES' in sections and sections['CORES']:
                    try:
                        self.cpu_cores = int(sections['CORES'][0].strip())
                    except:
                        pass
                
                # RAM
                if 'RAM' in sections and sections['RAM']:
                    try:
                        ram_line = sections['RAM'][0].strip().split()
                        if len(ram_line) >= 7:
                            self.last_ram_total = int(ram_line[1])
                            self.last_ram_used = int(ram_line[2])
                            self.last_ram_available = int(ram_line[6])
                            self.last_ram_pct = self.last_ram_used / self.last_ram_total if self.last_ram_total > 0 else 0
                    except:
                        pass
                
                # DISK
                if 'DISK' in sections and sections['DISK']:
                    try:
                        disk_line = sections['DISK'][0].strip().split()
                        if len(disk_line) >= 5:
                            self.security_data['disk_usage'] = {'percentage': disk_line[4].replace('%', '')}
                    except:
                        pass
                
                # UPTIME
                if 'UPTIME' in sections and sections['UPTIME']:
                    self.last_uptime = sections['UPTIME'][0].strip().replace('up ', '')
                
                # LOAD
                if 'LOAD' in sections and sections['LOAD']:
                    self.last_load_avg = sections['LOAD'][0].strip()
                
                # SWAP
                if 'SWAP' in sections and sections['SWAP']:
                    try:
                        swap_line = sections['SWAP'][0].strip().split()
                        if len(swap_line) >= 3:
                            self.last_swap_total = int(swap_line[1])
                            self.last_swap_used = int(swap_line[2])
                    except:
                        pass
                
                # NETWORK
                if 'NET' in sections and sections['NET']:
                    try:
                        net_line = sections['NET'][0].strip().split()
                        if len(net_line) >= 10:
                            self.network_stats = {
                                'rx': round(int(net_line[1]) / 1024 / 1024, 2),
                                'tx': round(int(net_line[9]) / 1024 / 1024, 2)
                            }
                    except:
                        pass
                
                # PROCESSES
                if 'PS' in sections:
                    self.last_proc_list = [l.strip() for l in sections['PS'][1:] if l.strip()]
                
                # Update UI
                self.after(0, self.update_ui_with_latest_data)
                
            except Exception as e:
                vps_logger.error(f"Parse error in fetch_basic_data: {str(e)}")
            
        except Exception as e:
            vps_logger.error(f"fetch_basic_data exception: {str(e)}", exc_info=True)
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
            ps aux 2>/dev/null | grep -E "nc |ncat |/dev/tcp|bash -i|sh -i|perl.*socket|python.*socket|xmrig|minerd" | grep -v grep || echo "None"
            echo "---TOP---"
            ps aux --sort=-%cpu 2>/dev/null | head -n 31
            echo "---FAILED---"
            sudo grep "Failed password" /var/log/auth.log 2>/dev/null | tail -n 30 || echo "No failed"
            echo "---ATTACKERS---"
            sudo lastb -n 50 -F 2>/dev/null || echo "No bad logins"
            echo "---SYSLOG---"
            sudo journalctl -n 50 --no-pager 2>/dev/null || sudo tail -n 50 /var/log/syslog 2>/dev/null || echo "No logs"
            echo "---KERNEL---"
            sudo dmesg | tail -n 30 2>/dev/null || echo "No kernel"
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
            
            fw = get_section('UFW')
            self.security_data['firewall_status'] = "Active" if "active" in fw.lower() else "Inactive"
            
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
            if attackers_raw and 'No bad' not in attackers_raw:
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
                            'recommended_action': f'Block: sudo ufw deny from {parts[2]}' if len(parts) > 2 else 'Review'
                        }
                        attackers.append(attacker)
            
            self.security_data['attackers'] = attackers[:50]
            self.security_data['syslog'] = [l.strip() for l in get_section('SYSLOG').split('\n') if l.strip() and 'No logs' not in l]
            self.security_data['kernel_logs'] = [l.strip() for l in get_section('KERNEL').split('\n') if l.strip() and 'No kernel' not in l]
            
            self.after(0, self.update_security_ui)
            
        except Exception as e:
            print(f"Error: {e}")

    def fetch_extended_data(self):
        """Fetch extended data"""
        try:
            cmd = '''
            echo "---DOCKER---"
            docker ps -a 2>/dev/null || echo "No docker"
            echo "---END---"
            '''
            
            out = self.run_ssh_command(cmd)
            if not out:
                return
            
            docker_out = out.split("---DOCKER---")[1].split("---END---")[0].strip()
            self.security_data['docker_containers'] = [l.strip() for l in docker_out.split('\n') 
                                                       if l.strip() and 'No docker' not in l]
            
            self.after(0, self.update_tab_content)
            
        except:
            pass

    def update_compact_ui(self, cpu, ram_used, ram_total, ram_pct, proc_list):
        """Update compact UI"""
        if self.is_expanded or not hasattr(self, 'lbl_cpu'):
            return
        
        # CPU
        self.lbl_cpu.configure(text=f"{cpu:.1f}% ({self.cpu_cores}c)")
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
        for line in proc_list[:8]:
            if not line.strip():
                continue
            try:
                parts = line.strip().rsplit(maxsplit=2)
                if len(parts) == 3:
                    cmd, cpu_p, mem_p = parts
                    txt += f"{cmd[:13]:<13} {cpu_p[:4]:<4} {mem_p[:4]}\n"
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
        
        try:
            # CPU
            self.lbl_cpu_exp.configure(text=f"{cpu:.1f}% ({self.cpu_cores} cores)")
            if hasattr(self, 'pb_cpu_exp'):
                cpu_pct = min(cpu / 100, 1.0)
                self.pb_cpu_exp.set(cpu_pct)
                
                if cpu > 80:
                    self.pb_cpu_exp.configure(progress_color=self.accent_red)
                elif cpu > 50:
                    self.pb_cpu_exp.configure(progress_color=self.accent_orange)
                else:
                    self.pb_cpu_exp.configure(progress_color=self.accent_blue)
            
            # RAM
            ram_pct = (ram_used / ram_total * 100) if ram_total > 0 else 0
            self.lbl_ram_exp.configure(text=f"{ram_used}/{ram_total} MB ({ram_pct:.1f}%)")
            if hasattr(self, 'pb_ram_exp'):
                self.pb_ram_exp.set(min(ram_pct / 100, 1.0))
                
                if ram_pct > 80:
                    self.pb_ram_exp.configure(progress_color=self.accent_red)
                elif ram_pct > 60:
                    self.pb_ram_exp.configure(progress_color=self.accent_orange)
                else:
                    self.pb_ram_exp.configure(progress_color=self.accent_green)
            
            # DISK
            self.lbl_disk_exp.configure(text=f"{disk}% used")
            if hasattr(self, 'pb_disk_exp'):
                disk_val = min(float(disk) / 100, 1.0)
                self.pb_disk_exp.set(disk_val)
                
                if float(disk) > 90:
                    self.pb_disk_exp.configure(progress_color=self.accent_red)
                elif float(disk) > 70:
                    self.pb_disk_exp.configure(progress_color=self.accent_orange)
                else:
                    self.pb_disk_exp.configure(progress_color=self.accent_green)
            
            # SWAP
            swap_pct = (self.last_swap_used / self.last_swap_total * 100) if self.last_swap_total > 0 else 0
            self.lbl_swap_exp.configure(text=f"{self.last_swap_used}/{self.last_swap_total} MB ({swap_pct:.1f}%)")
            if hasattr(self, 'pb_swap_exp'):
                self.pb_swap_exp.set(min(swap_pct / 100, 1.0))
            
            self.lbl_load_exp.configure(text=self.last_load_avg)
            self.lbl_uptime_exp.configure(text=uptime)
            
            net_rx = self.network_stats.get('rx', 0)
            net_tx = self.network_stats.get('tx', 0)
            self.lbl_network_exp.configure(text=f"↓ {net_rx}MB / ↑ {net_tx}MB")
            
            # Update alerts
            self._update_alerts(cpu, ram_pct, float(disk), 
                              len(self.security_data.get('attackers', [])), 
                              self.security_data.get('updates_available', 0))
            
            # Update summary
            self._update_summary_cards()
        except:
            pass

    def update_security_ui(self):
        """Update security UI"""
        if not self.is_expanded:
            return
        
        try:
            # Update security info in compact cards - dengan safety check
            if hasattr(self, 'lbl_ports') and self.lbl_ports.winfo_exists():
                ports = len(self.security_data.get('ports', []))
                self.lbl_ports.configure(text=f"Ports: {ports} open")
        except:
            pass
        
        try:
            if hasattr(self, 'lbl_firewall') and self.lbl_firewall.winfo_exists():
                fw = self.security_data.get('firewall_status', 'Unknown')
                fw_color = self.accent_green if "active" in fw.lower() else self.accent_red
                self.lbl_firewall.configure(text=f"Firewall: {fw}", text_color=fw_color)
        except:
            pass
        
        try:
            if hasattr(self, 'lbl_updates') and self.lbl_updates.winfo_exists():
                upd = self.security_data.get('updates_available', 0)
                upd_color = self.accent_red if upd > 10 else self.accent_orange if upd > 0 else self.accent_green
                self.lbl_updates.configure(text=f"Updates: {upd}", text_color=upd_color)
        except:
            pass
        
        try:
            if hasattr(self, 'lbl_attackers') and self.lbl_attackers.winfo_exists():
                threats = len(self.security_data.get('attackers', []))
                threat_color = self.accent_red if threats > 0 else self.accent_green
                self.lbl_attackers.configure(text=f"Threats: {threats}", text_color=threat_color)
        except:
            pass

    def update_ui_with_latest_data(self):
        """Update UI with cached data"""
        cpu = self.last_cpu
        ram_used = self.last_ram_used
        ram_total = self.last_ram_total
        ram_pct = self.last_ram_pct
        disk_pct = self.security_data.get('disk_usage', {}).get('percentage', 0)
        
        if self.is_expanded:
            self.update_expanded_ui(cpu, ram_used, ram_total, disk_pct, self.last_uptime)
            
            try:
                if hasattr(self, 'lbl_last_update') and self.lbl_last_update.winfo_exists():
                    now = datetime.now().strftime("%H:%M:%S")
                    self.lbl_last_update.configure(text=f"Last update: {now}")
            except:
                pass
        else:
            self.update_compact_ui(cpu, ram_used, ram_total, ram_pct, self.last_proc_list)
            
            # Update security in compact with safety checks
            try:
                if hasattr(self, 'lbl_ports') and self.lbl_ports.winfo_exists():
                    ports = len(self.security_data.get('ports', []))
                    self.lbl_ports.configure(text=f"Ports: {ports} open")
            except:
                pass
            
            try:
                if hasattr(self, 'lbl_firewall') and self.lbl_firewall.winfo_exists():
                    fw = self.security_data.get('firewall_status', 'Unknown')
                    fw_color = self.accent_green if "active" in fw.lower() else self.accent_red
                    self.lbl_firewall.configure(text=f"Firewall: {fw}", text_color=fw_color)
            except:
                pass
            
            try:
                if hasattr(self, 'lbl_updates') and self.lbl_updates.winfo_exists():
                    upd = self.security_data.get('updates_available', 0)
                    upd_color = self.accent_red if upd > 10 else self.accent_orange if upd > 0 else self.accent_green
                    self.lbl_updates.configure(text=f"Updates: {upd}", text_color=upd_color)
            except:
                pass
            
            try:
                if hasattr(self, 'lbl_attackers') and self.lbl_attackers.winfo_exists():
                    threats = len(self.security_data.get('attackers', []))
                    threat_color = self.accent_red if threats > 0 else self.accent_green
                    self.lbl_attackers.configure(text=f"Threats: {threats}", text_color=threat_color)
            except:
                pass

    def update_status(self, text, color):
        """Update connection status"""
        try:
            if self.is_expanded:
                if hasattr(self, 'lbl_status_expanded') and self.lbl_status_expanded.winfo_exists():
                    self.lbl_status_expanded.configure(text=text, text_color=color)
            else:
                if hasattr(self, 'lbl_status') and self.lbl_status.winfo_exists():
                    self.lbl_status.configure(text=text, text_color=color)
        except:
            pass

    def force_refresh(self):
        """Force refresh all data using the persistent session."""
        if not self.is_expanded:
            return
        
        vps_logger.info("Force refresh triggered")
        self.after(0, self.update_status, "🔄 Refreshing...", self.accent_blue)
        
        def do_refresh():
            if not self.ssh_manager.session_ready:
                self.after(0, self.update_status, "🔴 Not Connected", self.accent_red)
                return

            # Run all fetch operations in parallel
            threads = [
                threading.Thread(target=self.fetch_basic_data, daemon=True),
                threading.Thread(target=self.fetch_security_data, daemon=True),
                threading.Thread(target=self.fetch_extended_data, daemon=True)
            ]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=10) # Wait for max 10 seconds
            
            self.after(0, self.update_status, "✅ Refreshed", self.accent_green)
        
        threading.Thread(target=do_refresh, daemon=True).start()

    def force_reconnect(self):
        """Closes and restarts the persistent SSH session."""
        vps_logger.info("Force reconnect triggered")
        self.after(0, self.update_status, "🔄 Reconnecting...", self.accent_orange)
        
        def do_reconnect():
            # Close the existing session
            self.ssh_manager.close()
            # Start a new session
            self.ssh_manager.start_session()
            
            # The main loop will automatically detect the new session status.
            # We can trigger an immediate refresh if the connection succeeds.
            if self.ssh_manager.session_ready:
                self.after(0, lambda: self.force_refresh())
            else:
                self.after(0, self.update_status, "🔴 Reconnect Failed", self.accent_red)

        threading.Thread(target=do_reconnect, daemon=True).start() 



# ==============================================================================
#                           MAIN ENTRY POINT
# ==============================================================================
if __name__ == "__main__":
    try:
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        
        app = VPSSecurityMonitor()
        app.mainloop()
        
    except KeyboardInterrupt:
        print("\n[!] Program dihentikan oleh user")
        sys.exit(0)
    except Exception as e:
        print(f"[!] Error fatal: {e}")
        sys.exit(1)