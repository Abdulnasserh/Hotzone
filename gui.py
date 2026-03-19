import tkinter as tk
from tkinter import messagebox, font
import threading
import uvicorn
import sys
import os
from license_manager import get_machine_id, verify_key

LICENSE_FILE = "license.key"

class ServerGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("HotZone Pro Edition - Server Dashboard")
        self.geometry("450x330")
        self.config(bg="#f4f6f8")

        self.custom_font = font.Font(family="Helvetica", size=12)

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

    def show_registration(self):
        self.clear_window()
        
        tk.Label(self, text="🔑 Software Registration", font=("Helvetica", 16, "bold"), bg="#f4f6f8").pack(pady=10)
        
        machine_id = get_machine_id()
        tk.Label(self, text="Please send this Machine ID to the seller:", bg="#f4f6f8").pack()
        
        id_entry = tk.Entry(self, width=40, font=self.custom_font, justify="center")
        id_entry.insert(0, machine_id)
        id_entry.config(state="readonly")
        id_entry.pack(pady=5)

        tk.Label(self, text="Enter your License Key below:", bg="#f4f6f8").pack(pady=10)
        self.key_entry = tk.Entry(self, width=30, font=self.custom_font, justify="center")
        self.key_entry.pack(pady=5)

        tk.Button(self, text="Activate Software", fg="black", font=self.custom_font, command=self.activate).pack(pady=20)

    def activate(self):
        key = self.key_entry.get().strip()
        if verify_key(key):
            with open(LICENSE_FILE, "w") as f:
                f.write(key)
            messagebox.showinfo("Success", "Software activated successfully! Thank you for purchasing.")
            self.show_dashboard()
        else:
            messagebox.showerror("Error", "Invalid License Key!")

    def show_dashboard(self):
        self.clear_window()
        tk.Label(self, text="🌐 HotZone WiFi Control Panel", font=("Helvetica", 18, "bold"), bg="#f4f6f8").pack(pady=20)

        self.status_label = tk.Label(self, text="Server Status: OFFLINE", fg="red", font=("Helvetica", 14), bg="#f4f6f8")
        self.status_label.pack(pady=10)

        self.start_btn = tk.Button(self, text="▶ Start Server", fg="black", font=self.custom_font, width=15, command=self.start_server)
        self.start_btn.pack(pady=5)

        self.stop_btn = tk.Button(self, text="⏹ Stop Server", fg="black", font=self.custom_font, width=15, state="disabled", command=self.stop_server)
        self.stop_btn.pack(pady=5)
        
        tk.Label(self, text="Running locally on port 8000", fg="#888", bg="#f4f6f8").pack(pady=20)

    def clear_window(self):
        for widget in self.winfo_children():
            widget.destroy()

    def run_uvicorn(self):
        # Import the FASTAPI app inside the thread to avoid blocking GUI init
        from server import app
        config = uvicorn.Config(app=app, host="0.0.0.0", port=8000, log_level="info")
        self.server_instance = uvicorn.Server(config=config)
        self.server_instance.run()

    def start_server(self):
        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.status_label.config(text="Server Status: RUNNING", fg="green")
        
        self.server_thread = threading.Thread(target=self.run_uvicorn, daemon=True)
        self.server_thread.start()

    def stop_server(self):
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        self.status_label.config(text="Server Status: OFFLINE", fg="red")
        
        if self.server_instance:
            self.server_instance.should_exit = True
            self.server_instance = None

if __name__ == "__main__":
    app = ServerGUI()
    app.mainloop()
