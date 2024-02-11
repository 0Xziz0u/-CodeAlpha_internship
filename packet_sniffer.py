from scapy.all import sniff, IP
import tkinter as tk
from tkinter import scrolledtext

class SimpleSnifferGUI:
    def __init__(self, master):
        self.master = master
        master.title("Simple Network Sniffer")

        self.text_box = scrolledtext.ScrolledText(master, wrap=tk.WORD, width=70, height=30)
        self.text_box.pack(padx=10, pady=10)

        self.start_button = tk.Button(master, text="Start Sniffing", command=self.start_sniffing)
        self.start_button.pack(pady=10)

    def handle_packet(self, packet):
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            info = f"IP Packet: Source IP - {src_ip}, Destination IP - {dst_ip}\n"
            self.text_box.insert(tk.END, info)

    def start_sniffing(self):
        self.text_box.delete(1.0, tk.END)
        sniff(prn=self.handle_packet, count=10)

# Create the main Tkinter window
root = tk.Tk()

# Create an instance of the SimpleSnifferGUI class
app = SimpleSnifferGUI(root)

# Run the Tkinter event loop
root.mainloop()