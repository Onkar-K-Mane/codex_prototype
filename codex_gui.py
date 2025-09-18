import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from tkinter.scrolledtext import ScrolledText
import pandas as pd
from codex_core import (
    detect_data_collection,
    generate_exfiltration_warnings,
    detect_http_exfiltration,
    detect_dns_exfiltration,
    correlate_events
)
from codex_cti import MOCK_CTI, add_data_collection_warnings

class CodexDashboard:
    def __init__(self, root):
        self.root = root
        self.root.title("Codex Threat Detection Dashboard")
        self.create_widgets()

    def create_widgets(self):
        # File selectors
        file_frame = tk.Frame(self.root)
        file_frame.pack(fill="x", padx=10, pady=5)
        tk.Label(file_frame, text="System Log File:").grid(row=0, column=0, sticky="e")
        self.system_log_entry = tk.Entry(file_frame, width=40)
        self.system_log_entry.grid(row=0, column=1)
        tk.Button(file_frame, text="Browse", command=self.browse_system_log).grid(row=0, column=2)

        tk.Label(file_frame, text="Network Log File:").grid(row=1, column=0, sticky="e")
        self.network_log_entry = tk.Entry(file_frame, width=40)
        self.network_log_entry.grid(row=1, column=1)
        tk.Button(file_frame, text="Browse", command=self.browse_network_log).grid(row=1, column=2)

        tk.Label(file_frame, text="DNS Log File:").grid(row=2, column=0, sticky="e")
        self.dns_log_entry = tk.Entry(file_frame, width=40)
        self.dns_log_entry.grid(row=2, column=1)
        tk.Button(file_frame, text="Browse", command=self.browse_dns_log).grid(row=2, column=2)

        tk.Button(file_frame, text="Run Analysis", command=self.run_analysis, bg="#4CAF50", fg="white").grid(row=3, column=0, columnspan=3, pady=10)

        # Dashboard tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=10)

        self.tabs = {}
        tab_names = [
            "Latest 5 Threats",
            "Data Collection Alerts",
            "CTI-Enriched Alerts",
            "Early Exfiltration Warnings",
            "HTTP/HTTPS Exfiltration",
            "DNS Exfiltration",
            "Correlated Incidents"
        ]
        for name in tab_names:
            tab = tk.Frame(self.notebook)
            self.notebook.add(tab, text=name)
            self.tabs[name] = ScrolledText(tab, width=80, height=25)
            self.tabs[name].pack(fill="both", expand=True)

    def browse_system_log(self):
        filename = filedialog.askopenfilename(filetypes=[("CSV Files", "*.csv")])
        if filename:
            self.system_log_entry.delete(0, tk.END)
            self.system_log_entry.insert(0, filename)

    def browse_network_log(self):
        filename = filedialog.askopenfilename(filetypes=[("CSV Files", "*.csv")])
        if filename:
            self.network_log_entry.delete(0, tk.END)
            self.network_log_entry.insert(0, filename)

    def browse_dns_log(self):
        filename = filedialog.askopenfilename(filetypes=[("CSV Files", "*.csv")])
        if filename:
            self.dns_log_entry.delete(0, tk.END)
            self.dns_log_entry.insert(0, filename)

    def run_analysis(self):
        sys_log = self.system_log_entry.get()
        net_log = self.network_log_entry.get()
        dns_log = self.dns_log_entry.get()
        # Clear all tabs
        for tab in self.tabs.values():
            tab.delete(1.0, tk.END)
        try:
            net_df = pd.read_csv(net_log)
            dns_df = pd.read_csv(dns_log)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load network or DNS log: {e}")
            return
        # Data Collection Alerts
        collection_events = detect_data_collection(sys_log)
        self.tabs["Data Collection Alerts"].insert(tk.END, f"Total Threats: {len(collection_events)}\n\n")
        if collection_events:
            self.tabs["Data Collection Alerts"].insert(tk.END, self.format_events(collection_events))
            enriched_collection_events = add_data_collection_warnings(collection_events, net_df, MOCK_CTI)
            self.tabs["CTI-Enriched Alerts"].insert(tk.END, f"Total Threats: {len(enriched_collection_events)}\n\n")
            self.tabs["CTI-Enriched Alerts"].insert(tk.END, self.format_events(enriched_collection_events))
            exfil_warnings = generate_exfiltration_warnings(enriched_collection_events, net_df, dns_df)
            self.tabs["Early Exfiltration Warnings"].insert(tk.END, f"Total Threats: {len(exfil_warnings)}\n\n")
            self.tabs["Early Exfiltration Warnings"].insert(tk.END, self.format_events(exfil_warnings))
        else:
            enriched_collection_events = []
            self.tabs["Data Collection Alerts"].insert(tk.END, "No data collection events detected.\n")
            self.tabs["CTI-Enriched Alerts"].insert(tk.END, f"Total Threats: {len(enriched_collection_events)}\n\n")
            self.tabs["CTI-Enriched Alerts"].insert(tk.END, "No events detected.\n")
            exfil_warnings = []
            self.tabs["Early Exfiltration Warnings"].insert(tk.END, f"Total Threats: {len(exfil_warnings)}\n\n")
            self.tabs["Early Exfiltration Warnings"].insert(tk.END, "No events detected.\n")
        # HTTP/HTTPS Exfiltration
        suspicious_network_events = detect_http_exfiltration(net_df)
        self.tabs["HTTP/HTTPS Exfiltration"].insert(tk.END, f"Total Threats: {len(suspicious_network_events)}\n\n")
        self.tabs["HTTP/HTTPS Exfiltration"].insert(tk.END, self.format_events(suspicious_network_events))
        # DNS Exfiltration
        suspicious_dns_events = detect_dns_exfiltration(dns_df)
        self.tabs["DNS Exfiltration"].insert(tk.END, f"Total Threats: {len(suspicious_dns_events)}\n\n")
        self.tabs["DNS Exfiltration"].insert(tk.END, self.format_events(suspicious_dns_events))
        # Correlated Incidents
        correlated_incidents = correlate_events(enriched_collection_events, suspicious_network_events, suspicious_dns_events)
        self.tabs["Correlated Incidents"].insert(tk.END, f"Total Correlated Incidents: {len(correlated_incidents)}\n\n")
        self.tabs["Correlated Incidents"].insert(tk.END, self.format_events(correlated_incidents))
        # Latest 5 Threats
        latest_threats = self.get_latest_threats([
            collection_events,
            enriched_collection_events,
            exfil_warnings,
            suspicious_network_events,
            suspicious_dns_events
        ])
        self.tabs["Latest 5 Threats"].insert(tk.END, self.format_events(latest_threats))
    def get_latest_threats(self, event_lists):
        # Flatten all event lists
        all_events = []
        for events in event_lists:
            if events:
                all_events.extend(events)
        # Sort by timestamp descending (most recent first)
        def get_ts(event):
            ts = event.get('timestamp')
            return ts if ts is not None else ''
        all_events = [e for e in all_events if e.get('timestamp')]
        all_events.sort(key=get_ts, reverse=True)
        return all_events[:5] if all_events else []

    def format_events(self, events):
        if not events:
            return "No events detected.\n"
        out = ""
        for i, event in enumerate(events, 1):
            out += f"--- Event #{i} ---\n"
            for k, v in event.items():
                out += f"{k}: {v}\n"
            out += "-"*20 + "\n"
        return out

if __name__ == "__main__":
    root = tk.Tk()
    app = CodexDashboard(root)
    root.mainloop()
