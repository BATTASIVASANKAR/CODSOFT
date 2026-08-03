"""
Network Packet Analyzer - A beginner-friendly GUI packet sniffer.

Developed by Siva Sankar – Network Packet Analyzer
For educational and cybersecurity learning purposes only.

Technologies: Python 3, Scapy, Tkinter
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import threading
import datetime
import sys
import os

# ---------------------------------------------------------------------------
# Attempt to import Scapy – give a clear message if it is missing or if the
# script is not running with administrator / root privileges.
# ---------------------------------------------------------------------------
try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP
except ImportError:
    # If Scapy is not installed, show a helpful error before the GUI loads.
    root = tk.Tk()
    root.withdraw()
    messagebox.showerror(
        "Missing Dependency",
        "Scapy is not installed.\n\n"
        "Install it with:\n  pip install scapy\n\n"
        "Then re-run this application.",
    )
    sys.exit(1)


# ========================== MAIN APPLICATION CLASS =========================


class NetworkPacketAnalyzer:
    """Main application class for the Network Packet Analyzer GUI."""

    def __init__(self, master: tk.Tk) -> None:
        self.master = master
        self.master.title("Network Packet Analyzer")
        self.master.geometry("1050x680")
        self.master.minsize(900, 550)
        self.master.configure(bg="#1e1e2e")

        # ---- State variables ----
        self.capturing = False          # True while a capture is in progress
        self.packet_count = 0           # Total packets captured so far
        self.captured_packets: list = []  # List of formatted packet dicts
        self.sniff_thread: threading.Thread | None = None

        # ---- Build the UI ----
        self._create_styles()
        self._create_title_bar()
        self._create_toolbar()
        self._create_packet_table()
        self._create_status_bar()
        self._create_footer()

        # Graceful shutdown on window close
        self.master.protocol("WM_DELETE_WINDOW", self._on_close)

    # ------------------------------------------------------------------ #
    #                        UI CONSTRUCTION                              #
    # ------------------------------------------------------------------ #

    def _create_styles(self) -> None:
        """Configure ttk styles for a dark, modern look."""
        self.style = ttk.Style()
        self.style.theme_use("clam")

        # Treeview (packet table)
        self.style.configure(
            "Packet.Treeview",
            background="#2a2a3c",
            foreground="#cdd6f4",
            fieldbackground="#2a2a3c",
            rowheight=26,
            font=("Consolas", 10),
        )
        self.style.configure(
            "Packet.Treeview.Heading",
            background="#45475a",
            foreground="#cdd6f4",
            font=("Segoe UI", 10, "bold"),
        )
        self.style.map(
            "Packet.Treeview",
            background=[("selected", "#585b70")],
            foreground=[("selected", "#f5e0dc")],
        )

    def _create_title_bar(self) -> None:
        """Create the application title at the top."""
        title_frame = tk.Frame(self.master, bg="#1e1e2e")
        title_frame.pack(fill=tk.X, padx=16, pady=(14, 4))

        tk.Label(
            title_frame,
            text="🔍  Network Packet Analyzer",
            font=("Segoe UI", 20, "bold"),
            fg="#89b4fa",
            bg="#1e1e2e",
        ).pack(side=tk.LEFT)

        # About button (small, top-right)
        tk.Button(
            title_frame,
            text="ℹ  About",
            font=("Segoe UI", 9),
            fg="#cdd6f4",
            bg="#45475a",
            activebackground="#585b70",
            activeforeground="#f5e0dc",
            bd=0,
            padx=10,
            pady=3,
            cursor="hand2",
            command=self._show_about,
        ).pack(side=tk.RIGHT)

    def _create_toolbar(self) -> None:
        """Create the row of action buttons."""
        toolbar = tk.Frame(self.master, bg="#1e1e2e")
        toolbar.pack(fill=tk.X, padx=16, pady=(6, 8))

        button_specs = [
            ("▶  Start Capture", "#a6e3a1", "#1e1e2e", self.start_capture),
            ("⏹  Stop Capture", "#f38ba8", "#1e1e2e", self.stop_capture),
            ("🗑  Clear Results", "#fab387", "#1e1e2e", self.clear_results),
            ("💾  Export Results", "#89b4fa", "#1e1e2e", self.export_results),
        ]

        for text, bg_color, fg_color, cmd in button_specs:
            btn = tk.Button(
                toolbar,
                text=text,
                font=("Segoe UI", 10, "bold"),
                bg=bg_color,
                fg=fg_color,
                activebackground=bg_color,
                activeforeground=fg_color,
                bd=0,
                padx=16,
                pady=6,
                cursor="hand2",
                command=cmd,
            )
            btn.pack(side=tk.LEFT, padx=(0, 10))

    def _create_packet_table(self) -> None:
        """Create the scrollable Treeview table that displays packets."""
        table_frame = tk.Frame(self.master, bg="#1e1e2e")
        table_frame.pack(fill=tk.BOTH, expand=True, padx=16, pady=(0, 4))

        columns = ("#", "Timestamp", "Source IP", "Destination IP", "Protocol", "Length")
        self.tree = ttk.Treeview(
            table_frame,
            columns=columns,
            show="headings",
            style="Packet.Treeview",
        )

        # Column configuration: (id, heading, width, anchor)
        col_config = [
            ("#", "#", 50, tk.CENTER),
            ("Timestamp", "Timestamp", 180, tk.CENTER),
            ("Source IP", "Source IP", 180, tk.CENTER),
            ("Destination IP", "Destination IP", 180, tk.CENTER),
            ("Protocol", "Protocol", 100, tk.CENTER),
            ("Length", "Length (bytes)", 110, tk.CENTER),
        ]

        for col_id, heading, width, anchor in col_config:
            self.tree.heading(col_id, text=heading)
            self.tree.column(col_id, width=width, anchor=anchor, minwidth=50)

        # Scrollbars
        vsb = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=self.tree.yview)
        hsb = ttk.Scrollbar(table_frame, orient=tk.HORIZONTAL, command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")

        table_frame.rowconfigure(0, weight=1)
        table_frame.columnconfigure(0, weight=1)

    def _create_status_bar(self) -> None:
        """Create the bottom status bar showing state and packet count."""
        status_frame = tk.Frame(self.master, bg="#313244")
        status_frame.pack(fill=tk.X, side=tk.BOTTOM)

        # Status indicator
        self.status_label = tk.Label(
            status_frame,
            text="● Ready",
            font=("Segoe UI", 10, "bold"),
            fg="#a6e3a1",
            bg="#313244",
            padx=12,
            pady=6,
        )
        self.status_label.pack(side=tk.LEFT)

        # Packet count
        self.count_label = tk.Label(
            status_frame,
            text="Packets captured: 0",
            font=("Segoe UI", 10),
            fg="#cdd6f4",
            bg="#313244",
            padx=12,
            pady=6,
        )
        self.count_label.pack(side=tk.RIGHT)

    def _create_footer(self) -> None:
        """Create the footer with developer info."""
        footer_frame = tk.Frame(self.master, bg="#1e1e2e")
        footer_frame.pack(fill=tk.X, side=tk.BOTTOM, pady=(0, 0))

        tk.Label(
            footer_frame,
            text=(
                "Developed by Siva Sankar  •  For educational and cybersecurity "
                "learning purposes only  •  Contact: +91 9666241489"
            ),
            font=("Segoe UI", 8),
            fg="#6c7086",
            bg="#1e1e2e",
            pady=4,
        ).pack()

    # ------------------------------------------------------------------ #
    #                       PACKET CAPTURE LOGIC                          #
    # ------------------------------------------------------------------ #

    def start_capture(self) -> None:
        """Begin capturing packets in a background thread."""
        if self.capturing:
            messagebox.showinfo("Info", "Capture is already running.")
            return

        self.capturing = True
        self._set_status("Capturing…", "#f9e2af")

        # Run Scapy sniff in a daemon thread so the GUI remains responsive.
        self.sniff_thread = threading.Thread(target=self._sniff_packets, daemon=True)
        self.sniff_thread.start()

    def stop_capture(self) -> None:
        """Signal the sniffer to stop."""
        if not self.capturing:
            messagebox.showinfo("Info", "No capture is running.")
            return

        self.capturing = False
        self._set_status("Stopped", "#f38ba8")

    def _sniff_packets(self) -> None:
        """
        Scapy sniff loop – runs on a background thread.
        Uses stop_filter to halt when self.capturing is set to False.
        """
        try:
            sniff(
                prn=self._process_packet,
                store=False,
                stop_filter=lambda _pkt: not self.capturing,
            )
        except PermissionError:
            self.capturing = False
            self.master.after(0, lambda: messagebox.showerror(
                "Permission Error",
                "Administrator / root privileges are required to capture packets.\n\n"
                "• On Windows: right-click the terminal → Run as administrator.\n"
                "• On Linux/macOS: run with sudo.",
            ))
            self.master.after(0, lambda: self._set_status("Ready", "#a6e3a1"))
        except Exception as exc:
            self.capturing = False
            self.master.after(0, lambda: messagebox.showerror(
                "Capture Error",
                f"An error occurred during capture:\n\n{exc}",
            ))
            self.master.after(0, lambda: self._set_status("Ready", "#a6e3a1"))

    def _process_packet(self, packet) -> None:
        """
        Callback invoked by Scapy for each captured packet.
        Extracts key fields and schedules a GUI update on the main thread.
        """
        if not packet.haslayer(IP):
            return  # Skip non-IP packets (ARP, etc.)

        ip_layer = packet[IP]

        # Determine protocol name
        protocol = self._resolve_protocol(ip_layer)

        # Build a data dict for this packet
        self.packet_count += 1
        pkt_data = {
            "num": self.packet_count,
            "time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "src": ip_layer.src,
            "dst": ip_layer.dst,
            "proto": protocol,
            "length": len(packet),
        }
        self.captured_packets.append(pkt_data)

        # Schedule GUI update (thread-safe)
        self.master.after(0, self._add_packet_to_table, pkt_data)

    @staticmethod
    def _resolve_protocol(ip_layer) -> str:
        """Return a human-readable protocol name from the IP layer."""
        proto_num = ip_layer.proto
        if ip_layer.haslayer(TCP):
            return "TCP"
        if ip_layer.haslayer(UDP):
            return "UDP"
        if ip_layer.haslayer(ICMP):
            return "ICMP"
        # Fallback – use the protocol number
        proto_map = {1: "ICMP", 6: "TCP", 17: "UDP", 2: "IGMP", 47: "GRE", 50: "ESP"}
        return proto_map.get(proto_num, f"Other ({proto_num})")

    def _add_packet_to_table(self, pkt: dict) -> None:
        """Insert a packet row into the Treeview and update the counter."""
        self.tree.insert(
            "",
            tk.END,
            values=(
                pkt["num"],
                pkt["time"],
                pkt["src"],
                pkt["dst"],
                pkt["proto"],
                pkt["length"],
            ),
        )
        # Auto-scroll to the latest entry
        children = self.tree.get_children()
        if children:
            self.tree.see(children[-1])

        # Update packet count label
        self.count_label.config(text=f"Packets captured: {self.packet_count}")

    # ------------------------------------------------------------------ #
    #                       CLEAR / EXPORT / ABOUT                        #
    # ------------------------------------------------------------------ #

    def clear_results(self) -> None:
        """Clear all captured packets from the table and reset the counter."""
        if self.capturing:
            messagebox.showwarning("Warning", "Stop the capture before clearing results.")
            return

        for item in self.tree.get_children():
            self.tree.delete(item)

        self.captured_packets.clear()
        self.packet_count = 0
        self.count_label.config(text="Packets captured: 0")
        self._set_status("Ready", "#a6e3a1")

    def export_results(self) -> None:
        """Export captured packets to a .txt file chosen by the user."""
        if not self.captured_packets:
            messagebox.showinfo("Info", "No packets to export.")
            return

        filepath = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")],
            title="Export Captured Packets",
        )
        if not filepath:
            return  # User cancelled

        try:
            with open(filepath, "w", encoding="utf-8") as fh:
                header = (
                    f"{'#':<6} {'Timestamp':<22} {'Source IP':<18} "
                    f"{'Destination IP':<18} {'Protocol':<10} {'Length':<10}\n"
                )
                fh.write("=" * 84 + "\n")
                fh.write("  Network Packet Analyzer – Export\n")
                fh.write(f"  Exported at: {datetime.datetime.now()}\n")
                fh.write("=" * 84 + "\n\n")
                fh.write(header)
                fh.write("-" * 84 + "\n")

                for p in self.captured_packets:
                    line = (
                        f"{p['num']:<6} {p['time']:<22} {p['src']:<18} "
                        f"{p['dst']:<18} {p['proto']:<10} {p['length']:<10}\n"
                    )
                    fh.write(line)

                fh.write("-" * 84 + "\n")
                fh.write(f"Total packets captured: {self.packet_count}\n")

            messagebox.showinfo("Export Successful", f"Results saved to:\n{filepath}")
        except Exception as exc:
            messagebox.showerror("Export Error", f"Failed to export:\n{exc}")

    def _show_about(self) -> None:
        """Display an About dialog."""
        messagebox.showinfo(
            "About – Network Packet Analyzer",
            "Network Packet Analyzer v1.0\n\n"
            "A simple, beginner-friendly packet sniffer\n"
            "built with Python, Scapy, and Tkinter.\n\n"
            "Developed by Siva Sankar\n"
            "For educational and cybersecurity learning purposes only.\n\n"
            "Contact: +91 9666241489",
        )

    # ------------------------------------------------------------------ #
    #                          HELPER METHODS                              #
    # ------------------------------------------------------------------ #

    def _set_status(self, text: str, color: str) -> None:
        """Update the status indicator label."""
        self.status_label.config(text=f"● {text}", fg=color)

    def _on_close(self) -> None:
        """Handle window close – stop any running capture first."""
        self.capturing = False
        self.master.destroy()


# ============================== ENTRY POINT ==============================


def main() -> None:
    """Launch the Network Packet Analyzer application."""
    root = tk.Tk()

    # Set window icon (if an icon file is present in assets/)
    icon_path = os.path.join(os.path.dirname(__file__), "assets", "icon.ico")
    if os.path.isfile(icon_path):
        try:
            root.iconbitmap(icon_path)
        except tk.TclError:
            pass  # Silently ignore if the icon cannot be loaded

    app = NetworkPacketAnalyzer(root)
    root.mainloop()


if __name__ == "__main__":
    main()
