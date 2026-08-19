import sys
import os

# ---------------------------------------------------------------------------
# On Windows frozen builds, suppress ALL black console windows from spawned
# subprocesses (Playwright Node.js driver, uvicorn workers, etc.)
# This MUST run before importing anything that spawns subprocesses.
# ---------------------------------------------------------------------------
if sys.platform == "win32" and getattr(sys, 'frozen', False):
    import subprocess
    _original_popen_init = subprocess.Popen.__init__

    def _silent_popen_init(self, *args, **kwargs):
        CREATE_NO_WINDOW = 0x08000000
        creationflags = kwargs.get("creationflags", 0)
        kwargs["creationflags"] = creationflags | CREATE_NO_WINDOW
        _original_popen_init(self, *args, **kwargs)

    subprocess.Popen.__init__ = _silent_popen_init

    # CRITICAL: Prevent OSError due to missing stdout/stderr in --windowed mode
    try:
        if sys.stdout is None or sys.stderr is None:
            devnull = open(os.devnull, 'w')
            sys.stdout = sys.stdout or devnull
            sys.stderr = sys.stderr or devnull
    except Exception:
        pass

import customtkinter as ctk
import tkinter.messagebox as messagebox
import threading
import uvicorn
import webbrowser
import shutil
from pathlib import Path
import platform
from license_manager import get_machine_id, verify_key

def get_data_dir():
    if getattr(sys, 'frozen', False):
        if platform.system() == "Windows":
            d = Path(os.environ.get("APPDATA", os.path.expanduser("~"))) / "HotZonePro"
        else:
            d = Path(os.path.expanduser("~")) / ".HotZonePro"
        d.mkdir(parents=True, exist_ok=True)
        return d
    return Path(__file__).parent

DATA_DIR = get_data_dir()
LICENSE_FILE = DATA_DIR / "license.key"

# Configure modern appearance
ctk.set_appearance_mode("System")  # Modes: "System" (standard), "Dark", "Light"
ctk.set_default_color_theme("blue")  # Themes: "blue" (standard), "green", "dark-blue"

class ServerGUI(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("HotZone Pro Edition - Server Dashboard")
        self.geometry("500x420")
        self.resizable(False, False)

        self.server_thread = None
        self.server_instance = None

        if not self.check_license():
            self.show_registration()
        else:
            self.show_dashboard()

    def check_license(self):
        if os.path.exists(LICENSE_FILE):
            with open(LICENSE_FILE, "r") as f:
                key = f.read().strip()
                return verify_key(key)
        return False

    def clear_window(self):
        for widget in self.winfo_children():
            widget.destroy()

    def show_registration(self):
        self.clear_window()
        
        # Rounded Container Frame
        frame = ctk.CTkFrame(self, corner_radius=15)
        frame.pack(pady=20, padx=20, fill="both", expand=True)

        label_title = ctk.CTkLabel(frame, text="🔑 Software Registration", font=ctk.CTkFont(size=22, weight="bold"))
        label_title.pack(pady=(25, 10))
        
        machine_id = get_machine_id()
        info_text = ctk.CTkLabel(frame, text="Please send this Machine ID to the seller:", font=ctk.CTkFont(size=14))
        info_text.pack(pady=(10, 5))
        
        id_entry = ctk.CTkEntry(frame, width=420, height=35, font=ctk.CTkFont(size=14, weight="bold"), justify="center")
        id_entry.insert(0, machine_id)
        id_entry.configure(state="readonly")
        id_entry.pack(pady=5)

        key_text = ctk.CTkLabel(frame, text="Enter your License Key below:", font=ctk.CTkFont(size=14))
        key_text.pack(pady=(20, 5))
        
        self.key_entry = ctk.CTkEntry(frame, width=320, height=40, font=ctk.CTkFont(size=15), justify="center", placeholder_text="Enter 16-character license key")
        self.key_entry.pack(pady=5)

        activate_btn = ctk.CTkButton(frame, text="Activate Software", font=ctk.CTkFont(size=15, weight="bold"), height=45, fg_color="#10B981", hover_color="#059669", command=self.activate)
        activate_btn.pack(pady=(25, 15))

    def activate(self):
        key = self.key_entry.get().strip()
        if verify_key(key):
            try:
                with open(LICENSE_FILE, "w") as f:
                    f.write(key)
                messagebox.showinfo("Success", "Software activated successfully! Thank you for purchasing.")
                self.show_dashboard()
            except Exception as e:
                messagebox.showerror("Permission Error", f"Failed to save license locally: {e}\nPlease run the app as Administrator or contact support.")
        else:
            messagebox.showerror("Error", "Invalid License Key!")

    def show_dashboard(self):
        self.clear_window()
        
        frame = ctk.CTkFrame(self, corner_radius=15)
        frame.pack(pady=20, padx=20, fill="both", expand=True)

        title = ctk.CTkLabel(frame, text="🌐 HotZone WiFi Control Panel", font=ctk.CTkFont(size=24, weight="bold"))
        title.pack(pady=(25, 15))

        self.status_label = ctk.CTkLabel(frame, text="Server Status: OFFLINE", text_color="#EF4444", font=ctk.CTkFont(size=18, weight="bold"))
        self.status_label.pack(pady=15)

        self.start_btn = ctk.CTkButton(frame, text="▶ Start Server", fg_color="#10B981", hover_color="#059669", font=ctk.CTkFont(size=16, weight="bold"), height=50, command=self.start_server)
        self.start_btn.pack(pady=(20, 10))

        self.stop_btn = ctk.CTkButton(frame, text="⏹ Stop Server", fg_color="#EF4444", hover_color="#DC2626", font=ctk.CTkFont(size=16, weight="bold"), height=50, state="disabled", command=self.stop_server)
        self.stop_btn.pack(pady=10)
        
        self.import_btn = ctk.CTkButton(frame, text="📂 Import Database Backup", fg_color="#8B5CF6", hover_color="#7C3AED", font=ctk.CTkFont(size=13, weight="bold"), height=35, command=self.import_database)
        self.import_btn.pack(pady=(5, 10))
        
        info = ctk.CTkLabel(frame, text="Customers will connect via Local WiFi Router", font=ctk.CTkFont(size=13), text_color="gray")
        info.pack(pady=(10, 10))

    def import_database(self):
        file_path = ctk.filedialog.askopenfilename(
            title="Select hotzone.db Backup File",
            filetypes=[("SQLite Database", "*.db"), ("All Files", "*.*")]
        )
        if file_path:
            try:
                shutil.copy2(file_path, DATA_DIR / "hotzone.db")
                messagebox.showinfo("Success", "Backup successfully imported! Settings and Vouchers restored.")
            except Exception as e:
                messagebox.showerror("Import Error", f"Failed to import database: {e}")

    def run_uvicorn(self):
        try:
            import server, socket
            app = server.app
            server._free_port_80()
            
            target_port = 80
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind(("0.0.0.0", 80))
                s.close()
            except Exception:
                target_port = 8000

            server._CURRENT_PORT = target_port

            config = uvicorn.Config(app=app, host="0.0.0.0", port=target_port, log_level="info")
            self.server_instance = uvicorn.Server(config=config)
            self.server_instance.run()
        except Exception as e:
            def show_error():
                messagebox.showerror("Server Crash", f"The server failed to start:\n\n{str(e)}\n\n(It may be blocked by a Firewall, Port 80 or 8000 is used, or data is inaccessible)")
                self.stop_server()
            self.after(0, show_error)

    def _open_admin_browser(self):
        try:
            import server
            port = getattr(server, "_CURRENT_PORT", 80)
            url = f"http://127.0.0.1:{port}/admin" if port != 80 else "http://127.0.0.1/admin"
            webbrowser.open(url)
        except Exception:
            pass

    def start_server(self):
        self.start_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        self.import_btn.configure(state="disabled")
        self.status_label.configure(text="Server Status: RUNNING", text_color="#10B981")

        # Open admin portal after server is ready (5s gives uvicorn time to bind)
        self.after(5000, self._open_admin_browser)

        # Remind admin to press Washa System
        self.after(3000, self._remind_washa)

        self.server_thread = threading.Thread(target=self.run_uvicorn, daemon=True)
        self.server_thread.start()

    def _remind_washa(self):
        messagebox.showwarning(
            "⚠️ Kumbuka — Remember!",
            "Server imeanza!\n\n"
            "⚠️ WiFi bado iko WAZI — wateja wote wana internet bila kulipa!\n\n"
            "Nenda kwenye Admin → Settings → Bonyeza 'Washa System'\n"
            "ili kuzuia wateja wasio na voucher."
        )

    def stop_server(self):
        self.start_btn.configure(state="normal")
        self.stop_btn.configure(state="disabled")
        self.import_btn.configure(state="normal")
        self.status_label.configure(text="Server Status: OFFLINE", text_color="#EF4444")
        
        if self.server_instance:
            self.server_instance.should_exit = True
            self.server_instance = None

if __name__ == "__main__":
    app = ServerGUI()
    app.mainloop()
