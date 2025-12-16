import customtkinter as ctk
import paramiko
import threading
import time
import sys
import re

# ==============================================================================
#                      KONFIGURASI (WAJIB UBAH BAGIAN INI)
# ==============================================================================
VPS_IP = "31.97.110.253"           # IP VPS Anda
VPS_USER = "ubuntu"                  # Username (sudah pasti root)
SSH_KEY_PATH = "C:/Users/Ridwan Taufik/.ssh/id_ed25519_ridwantaufik_programmer" 
# ==============================================================================
# ==============================================================================

class VPSWidget(ctk.CTk):
    def __init__(self, vps_ip, vps_user, ssh_key_path):
        super().__init__()

        self.vps_ip = vps_ip
        self.vps_user = vps_user
        self.ssh_key_path = ssh_key_path
        self.is_ip_blurred = True
        self.blurred_ip = "•••.•••.•••.•••"

        self.title("VPS Info")
        self.geometry("180x300")
        self.resizable(False, False)
        self.overrideredirect(True)
        self.attributes('-topmost', True)
        
        transparent_color = "#010101"
        self.configure(fg_color=transparent_color)
        self.wm_attributes("-transparentcolor", transparent_color)
        self.attributes('-alpha', 0.92)

        self.main_frame = ctk.CTkFrame(self, corner_radius=12, fg_color="#1a1a1a")
        self.main_frame.pack(fill="both", expand=True, padx=3, pady=3)
        self.main_frame.bind("<Button-1>", self.start_drag)
        self.main_frame.bind("<B1-Motion>", self.do_drag)

        self.main_frame.grid_columnconfigure(0, weight=1)
        self.main_frame.grid_rowconfigure(2, weight=1)

        # Header
        self.header_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        self.header_frame.grid(row=0, column=0, padx=8, pady=(4, 4), sticky="ew")
        self.header_frame.grid_columnconfigure(0, weight=1)
        self.header_frame.bind("<Button-1>", self.start_drag)
        self.header_frame.bind("<B1-Motion>", self.do_drag)

        self.lbl_ip = ctk.CTkLabel(self.header_frame, text=f"VPS: {self.blurred_ip}", font=("Segoe UI", 10, "bold"), text_color="#00a8ff")
        self.lbl_ip.grid(row=0, column=0, sticky="w")
        self.lbl_ip.bind("<Button-1>", self.handle_ip_click)
        self.lbl_ip.bind("<B1-Motion>", self.do_drag)

        self.btn_close = ctk.CTkButton(self.header_frame, text="✕", width=22, height=22, corner_radius=11, fg_color="#333333", text_color="white", hover_color="#ff4757", command=self.quit_app)
        self.btn_close.grid(row=0, column=1, sticky="e")
        
        # Status Section
        self.status_frame = ctk.CTkFrame(self.main_frame, fg_color="#2a2a2a", corner_radius=8)
        self.status_frame.grid(row=1, column=0, padx=8, pady=3, sticky="ew")
        self.status_frame.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(self.status_frame, text="CPU:", font=("Consolas", 10)).grid(row=0, column=0, sticky="w", padx=(8,2), pady=(6,0))
        self.lbl_cpu_val = ctk.CTkLabel(self.status_frame, text="...", font=("Consolas", 10))
        self.lbl_cpu_val.grid(row=0, column=1, sticky="w", padx=(0,8), pady=(6,0))
        self.prog_cpu = ctk.CTkProgressBar(self.status_frame, orientation="horizontal", height=6, corner_radius=3)
        self.prog_cpu.grid(row=1, column=0, columnspan=2, sticky="ew", padx=8, pady=(2, 6))
        self.prog_cpu.set(0)

        ctk.CTkLabel(self.status_frame, text="RAM:", font=("Consolas", 10)).grid(row=2, column=0, sticky="w", padx=(8,2), pady=0)
        self.lbl_ram_val = ctk.CTkLabel(self.status_frame, text="...", font=("Consolas", 10))
        self.lbl_ram_val.grid(row=2, column=1, sticky="w", padx=(0,8), pady=0)
        self.prog_ram = ctk.CTkProgressBar(self.status_frame, orientation="horizontal", height=6, progress_color="#2ecc71", corner_radius=3)
        self.prog_ram.grid(row=3, column=0, columnspan=2, sticky="ew", padx=8, pady=(2, 8))
        self.prog_ram.set(0)

        # Top Processes Section
        self.proc_frame = ctk.CTkFrame(self.main_frame, fg_color="#2a2a2a", corner_radius=8)
        self.proc_frame.grid(row=2, column=0, padx=8, pady=(3, 8), sticky="nsew")
        self.proc_frame.grid_rowconfigure(1, weight=1)
        self.proc_frame.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(self.proc_frame, text="TOP PROCESSES", font=("Segoe UI", 9, "bold", "underline")).grid(row=0, column=0, pady=(4,2))
        self.txt_proc = ctk.CTkTextbox(self.proc_frame, font=("Consolas", 8), activate_scrollbars=False, fg_color="transparent")
        self.txt_proc.grid(row=1, column=0, padx=3, pady=(0,3), sticky="nsew")

        # --- Logic ---
        self.running = True
        self.ssh = paramiko.SSHClient()
        self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.thread = threading.Thread(target=self.main_loop, daemon=True)
        self.thread.start()

    def handle_ip_click(self, event):
        self.start_drag(event)
        self.toggle_ip_blur()

    def toggle_ip_blur(self, event=None):
        self.is_ip_blurred = not self.is_ip_blurred
        self.lbl_ip.configure(text=f"VPS: {self.blurred_ip}" if self.is_ip_blurred else f"VPS: {self.vps_ip}")

    def start_drag(self, event): self.x, self.y = event.x, event.y
    def do_drag(self, event): self.geometry(f"+{self.winfo_pointerx() - self.x}+{self.winfo_pointery() - self.y}")

    def quit_app(self):
        self.running = False
        if self.ssh.get_transport() and self.ssh.get_transport().is_active(): self.ssh.close()
        self.destroy()
        sys.exit()

    def connect_ssh(self):
        try:
            self.ssh.connect(self.vps_ip, username=self.vps_user, key_filename=self.ssh_key_path, timeout=10)
            self.update_ui_error("Connected", color="green")
            time.sleep(1)
            return True
        except Exception:
            self.update_ui_error("Connection Failed", color="red")
            return False

    def main_loop(self):
        while self.running:
            if not (self.ssh.get_transport() and self.ssh.get_transport().is_active()):
                self.update_ui_error("Connecting...", color="orange")
                if not self.connect_ssh():
                    time.sleep(10)
                    continue
            self.fetch_data()
            time.sleep(2)
    
    def fetch_data(self):
        try:
            # Simplified, robust command
            command = 'echo "---TOP---"; top -bn1 | head -n 3; echo "---FREE---"; free -m; echo "---PS---"; ps -eo comm,%cpu,%mem --sort=-%cpu | head -n 7; echo "---END---"'
            
            stdin, stdout, stderr = self.ssh.exec_command(command, timeout=5)
            output = stdout.read().decode('utf-8', 'ignore')
            err = stderr.read().decode('utf-8', 'ignore')
            if err: raise IOError(f"SSH error: {err}")

            # --- CPU PARSING ---
            top_section = output.split("---TOP---")[1].split("---FREE---")[0]
            cpu_line = [line for line in top_section.split('\n') if "Cpu(s)" in line]
            if not cpu_line: raise ValueError("CPU line not found")
            cpu_line_str = cpu_line[0].replace(',', '.')
            cpu_values = [float(x) for x in re.findall(r'[0-9]+\.[0-9]+', cpu_line_str)]
            if len(cpu_values) < 2: raise ValueError("Not enough CPU values")
            cpu_val = cpu_values[0] + cpu_values[1]

            # --- RAM PARSING ---
            free_section = output.split("---FREE---")[1].split("---PS---")[0]
            mem_line = [line for line in free_section.split('\n') if "Mem:" in line]
            if not mem_line: raise ValueError("Mem line not found")
            parts = mem_line[0].split()
            ram_total, ram_used = int(parts[1]), int(parts[2])
            ram_percent = (ram_used / ram_total) if ram_total > 0 else 0

            # --- PROCESS PARSING ---
            ps_section = output.split("---PS---")[1].split("---END---")[0]
            proc_out = ps_section.strip().split('\n')[1:] # Skip header
            if not proc_out: raise ValueError("Process list is empty")
            
            self.after(0, self.update_ui_success, cpu_val, ram_used, ram_total, ram_percent, proc_out)

        except Exception as e:
            error_type = type(e).__name__
            self.update_ui_error(f"Err: {error_type}", color="#ff6b6b")
            if self.ssh.get_transport() and self.ssh.get_transport().is_active():
                self.ssh.close()

    def update_ui_success(self, cpu, ram_used, ram_total, ram_pct, proc_list):
        self.lbl_cpu_val.configure(text=f"{cpu:.1f}%", text_color="white")
        self.prog_cpu.set(cpu / 100)
        self.lbl_ram_val.configure(text=f"{ram_used}/{ram_total}MB")
        self.prog_ram.set(ram_pct)
        
        text_display = f"{'CMD':<12} {'CPU%':<5} {'MEM%'}\n"
        text_display += "─" * 24 + "\n"
        for line in proc_list:
            if not line.strip(): continue
            try:
                parts = line.strip().split(maxsplit=2)
                if len(parts) == 3:
                    cmd, cpu_p, mem_p = parts
                    truncated_cmd = cmd[:11]
                    text_display += f"{truncated_cmd:<12} {cpu_p:<5} {mem_p}\n"
            except (ValueError, IndexError):
                continue
        
        self.txt_proc.configure(state="normal")
        self.txt_proc.delete("1.0", "end")
        self.txt_proc.insert("1.0", text_display)
        self.txt_proc.configure(state="disabled")

    def update_ui_error(self, msg, color="white"):
        self.lbl_cpu_val.configure(text=msg, text_color=color)
        self.prog_cpu.set(0)
        self.lbl_ram_val.configure(text="---")
        self.prog_ram.set(0)
        self.txt_proc.configure(state="normal")
        self.txt_proc.delete("1.0", "end")
        self.txt_proc.insert("1.0", "Awaiting connection...")
        self.txt_proc.configure(state="disabled")

# --- Main Execution ---
def main():
    ctk.set_appearance_mode("Dark")
    try:
        app = VPSWidget(vps_ip=VPS_IP, vps_user=VPS_USER, ssh_key_path=SSH_KEY_PATH)
        app.mainloop()
    except Exception as e:
        import tkinter as tk
        root = tk.Tk()
        root.title("Error")
        tk.Label(root, text=f"A critical error occurred:\n{e}\n\nPlease check your configuration.").pack(padx=20, pady=20)
        root.mainloop()

if __name__ == "__main__":
    main()
