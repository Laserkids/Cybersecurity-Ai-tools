import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import json
import threading
import requests
from scapy.all import rdpcap, IP, TCP, UDP, ICMP, ARP, DNS, DNSQR, DNSRR
from scapy.layers.http import HTTPRequest, HTTPResponse
import re

class WiresharkAIAnalyzer:
    def __init__(self, root):
        self.root = root
        self.root.title("AI Wireshark Analyzer (Ollama)")
        self.root.geometry("1200x800")
        
        self.packets = []
        self.current_file = None
        self.ollama_url = "http://localhost:11434"
        
        self.setup_ui()
        self.check_ollama_connection()
        
    def setup_ui(self):
        # Top frame for file selection
        top_frame = ttk.Frame(self.root, padding="10")
        top_frame.pack(fill=tk.X)
        
        ttk.Label(top_frame, text="Capture File:").pack(side=tk.LEFT, padx=5)
        self.file_entry = ttk.Entry(top_frame, width=50)
        self.file_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        
        ttk.Button(top_frame, text="Browse", command=self.browse_file).pack(side=tk.LEFT, padx=5)
        ttk.Button(top_frame, text="Load", command=self.load_capture).pack(side=tk.LEFT, padx=5)
        
        # Ollama settings frame
        ollama_frame = ttk.Frame(self.root, padding="10")
        ollama_frame.pack(fill=tk.X)
        
        ttk.Label(ollama_frame, text="Ollama URL:").pack(side=tk.LEFT, padx=5)
        self.ollama_url_entry = ttk.Entry(ollama_frame, width=25)
        self.ollama_url_entry.pack(side=tk.LEFT, padx=5)
        self.ollama_url_entry.insert(0, self.ollama_url)
        
        ttk.Label(ollama_frame, text="Model:").pack(side=tk.LEFT, padx=5)
        self.model_var = tk.StringVar(value="llama3.2")
        self.model_combo = ttk.Combobox(ollama_frame, textvariable=self.model_var, width=15)
        self.model_combo['values'] = ['llama3.2', 'phi3', 'mistral', 'llama3.1']
        self.model_combo.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(ollama_frame, text="Refresh", command=self.refresh_models).pack(side=tk.LEFT, padx=5)
        
        self.ollama_status = ttk.Label(ollama_frame, text="⚫ Checking...", foreground="gray")
        self.ollama_status.pack(side=tk.LEFT, padx=10)
        
        # Fast mode toggle
        self.fast_mode = tk.BooleanVar(value=True)
        ttk.Checkbutton(ollama_frame, text="Fast Mode", variable=self.fast_mode).pack(side=tk.LEFT, padx=10)
        
        # Stats frame
        stats_frame = ttk.LabelFrame(self.root, text="Capture Statistics", padding="10")
        stats_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.stats_label = ttk.Label(stats_frame, text="No capture loaded")
        self.stats_label.pack()
        
        # Query frame
        query_frame = ttk.LabelFrame(self.root, text="AI Query", padding="10")
        query_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(query_frame, text="Ask about your network traffic:").pack(anchor=tk.W)
        
        query_input_frame = ttk.Frame(query_frame)
        query_input_frame.pack(fill=tk.X, pady=5)
        
        self.query_entry = ttk.Entry(query_input_frame)
        self.query_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        self.query_entry.bind('<Return>', lambda e: self.execute_query())
        
        ttk.Button(query_input_frame, text="Analyze", command=self.execute_query).pack(side=tk.LEFT)
        
        # Example queries
        examples_frame = ttk.Frame(query_frame)
        examples_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(examples_frame, text="Quick:", font=('Arial', 8)).pack(side=tk.LEFT, padx=5)
        examples = [
            "HTTP requests",
            "Port 443",
            "DNS queries",
            "TCP SYN",
            "Top IPs"
        ]
        for ex in examples:
            btn = ttk.Button(examples_frame, text=ex, 
                           command=lambda e=ex: self.query_entry.delete(0, tk.END) or self.query_entry.insert(0, e))
            btn.pack(side=tk.LEFT, padx=2)
        
        # Results frame
        results_frame = ttk.LabelFrame(self.root, text="Analysis Results", padding="10")
        results_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.results_text = scrolledtext.ScrolledText(results_frame, wrap=tk.WORD, height=20)
        self.results_text.pack(fill=tk.BOTH, expand=True)
        
        # Status bar
        self.status_var = tk.StringVar(value="Ready - Tip: Fast Mode reduces packets analyzed for quicker results")
        status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(fill=tk.X, side=tk.BOTTOM)
        
    def check_ollama_connection(self):
        def check_thread():
            try:
                response = requests.get(f"{self.ollama_url}/api/tags", timeout=2)
                if response.status_code == 200:
                    models = [model['name'] for model in response.json().get('models', [])]
                    self.root.after(0, lambda: self.update_ollama_status(True, models))
                else:
                    self.root.after(0, lambda: self.update_ollama_status(False))
            except Exception as e:
                self.root.after(0, lambda: self.update_ollama_status(False, error=str(e)))
        
        threading.Thread(target=check_thread, daemon=True).start()
    
    def update_ollama_status(self, connected, models=None, error=None):
        if connected:
            self.ollama_status.config(text="🟢 Connected", foreground="green")
            if models:
                self.model_combo['values'] = models
                if models and self.model_var.get() not in models:
                    self.model_var.set(models[0])
        else:
            self.ollama_status.config(text="🔴 Disconnected", foreground="red")
            if error:
                messagebox.showwarning("Ollama Connection", 
                    f"Cannot connect to Ollama. Make sure it's running:\n"
                    f"Run 'ollama serve' in terminal")
    
    def refresh_models(self):
        self.ollama_url = self.ollama_url_entry.get()
        self.check_ollama_connection()
    
    def browse_file(self):
        filename = filedialog.askopenfilename(
            title="Select Wireshark Capture File",
            filetypes=[
                ("Capture files", "*.pcap *.pcapng *.cap"),
                ("All files", "*.*")
            ]
        )
        if filename:
            self.file_entry.delete(0, tk.END)
            self.file_entry.insert(0, filename)
    
    def load_capture(self):
        filename = self.file_entry.get()
        if not filename:
            messagebox.showerror("Error", "Please select a capture file")
            return
        
        self.status_var.set("Loading capture file...")
        self.results_text.delete(1.0, tk.END)
        
        def load_thread():
            try:
                self.packets = rdpcap(filename)
                self.current_file = filename
                
                stats = self.calculate_stats()
                
                self.root.after(0, lambda: self.update_stats(stats))
                self.root.after(0, lambda: self.status_var.set(f"Loaded {len(self.packets)} packets - Ready to analyze"))
                self.root.after(0, lambda: self.results_text.insert(tk.END, 
                    f"✓ Loaded {len(self.packets)} packets\n\n"
                    "Ready to analyze! Ask questions about your network traffic."))
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("Error", f"Failed to load: {str(e)}"))
                self.root.after(0, lambda: self.status_var.set("Error loading file"))
        
        threading.Thread(target=load_thread, daemon=True).start()
    
    def calculate_stats(self):
        stats = {
            'total': len(self.packets),
            'tcp': 0, 'udp': 0, 'icmp': 0, 'http': 0, 'dns': 0,
            'unique_ips': set()
        }
        
        for pkt in self.packets:
            if IP in pkt:
                stats['unique_ips'].add(pkt[IP].src)
                stats['unique_ips'].add(pkt[IP].dst)
            if TCP in pkt: stats['tcp'] += 1
            if UDP in pkt: stats['udp'] += 1
            if ICMP in pkt: stats['icmp'] += 1
            if HTTPRequest in pkt or HTTPResponse in pkt: stats['http'] += 1
            if DNS in pkt: stats['dns'] += 1
        
        stats['unique_ips'] = len(stats['unique_ips'])
        return stats
    
    def update_stats(self, stats):
        text = f"Packets: {stats['total']} | TCP: {stats['tcp']} | UDP: {stats['udp']} | HTTP: {stats['http']} | DNS: {stats['dns']} | IPs: {stats['unique_ips']}"
        self.stats_label.config(text=text)
    
    def smart_filter_packets(self, query):
        """Filter packets based on query keywords for faster analysis"""
        query_lower = query.lower()
        filtered = []
        
        # Detect what user is looking for
        keywords = {
            'http': lambda p: HTTPRequest in p or HTTPResponse in p,
            'dns': lambda p: DNS in p,
            'tcp': lambda p: TCP in p,
            'udp': lambda p: UDP in p,
            'icmp': lambda p: ICMP in p,
            'syn': lambda p: TCP in p and 'S' in str(p[TCP].flags),
            'arp': lambda p: ARP in p,
        }
        
        # Check for port numbers
        port_match = re.search(r'port\s+(\d+)', query_lower)
        if port_match:
            port = int(port_match.group(1))
            return [p for p in self.packets if (TCP in p and (p[TCP].sport == port or p[TCP].dport == port)) or 
                    (UDP in p and (p[UDP].sport == port or p[UDP].dport == port))]
        
        # Check for IP addresses
        ip_match = re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', query)
        if ip_match:
            ip = ip_match.group(0)
            return [p for p in self.packets if IP in p and (p[IP].src == ip or p[IP].dst == ip)]
        
        # Filter by keyword
        for keyword, filter_func in keywords.items():
            if keyword in query_lower:
                filtered = [p for p in self.packets if filter_func(p)]
                if filtered:
                    return filtered[:200]  # Limit to 200
        
        # Default: return first packets
        return self.packets[:100]
    
    def extract_packet_summary(self, packets):
        """Extract minimal packet info for faster processing"""
        summary = []
        
        for i, pkt in enumerate(packets[:150]):  # Hard limit
            info = {'id': i}
            
            if IP in pkt:
                info['src'] = pkt[IP].src
                info['dst'] = pkt[IP].dst
            
            if TCP in pkt:
                info['proto'] = 'TCP'
                info['sport'] = pkt[TCP].sport
                info['dport'] = pkt[TCP].dport
                info['flags'] = str(pkt[TCP].flags)
            elif UDP in pkt:
                info['proto'] = 'UDP'
                info['sport'] = pkt[UDP].sport
                info['dport'] = pkt[UDP].dport
            elif ICMP in pkt:
                info['proto'] = 'ICMP'
            
            if HTTPRequest in pkt:
                try:
                    info['http'] = pkt[HTTPRequest].Method.decode()
                    info['host'] = pkt[HTTPRequest].Host.decode() if pkt[HTTPRequest].Host else None
                except: pass
            
            if DNS in pkt and pkt.haslayer(DNSQR):
                try:
                    info['dns'] = pkt[DNSQR].qname.decode()
                except: pass
            
            summary.append(info)
        
        return summary
    
    def execute_query(self):
        query = self.query_entry.get().strip()
        if not query:
            messagebox.showwarning("Warning", "Please enter a query")
            return
        
        if not self.packets:
            messagebox.showerror("Error", "Please load a capture file first")
            return
        
        self.status_var.set("Analyzing...")
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(tk.END, f"Query: {query}\n\n⏳ Analyzing...\n")
        
        def query_thread():
            try:
                # Smart filtering
                if self.fast_mode.get():
                    filtered_packets = self.smart_filter_packets(query)
                    packet_summary = self.extract_packet_summary(filtered_packets)
                else:
                    packet_summary = self.extract_packet_summary(self.packets[:300])
                
                self.root.after(0, lambda: self.results_text.insert(tk.END, 
                    f"📊 Analyzing {len(packet_summary)} packets...\n"))
                
                # Shorter, focused prompt
                prompt = f"""Analyze these network packets and answer the query concisely.

Packets: {json.dumps(packet_summary)}

Query: {query}

Provide a brief, focused answer with specific details (packet IDs, IPs, ports). Keep response under 300 words."""

                ollama_url = self.ollama_url_entry.get()
                model = self.model_var.get()
                
                # Stream response for immediate feedback
                response = requests.post(
                    f"{ollama_url}/api/generate",
                    json={
                        "model": model,
                        "prompt": prompt,
                        "stream": True,
                        "options": {
                            "temperature": 0.3,
                            "num_predict": 500
                        }
                    },
                    stream=True,
                    timeout=60
                )
                
                if response.status_code == 200:
                    self.root.after(0, lambda: self.results_text.delete(1.0, tk.END))
                    self.root.after(0, lambda: self.results_text.insert(tk.END, f"Query: {query}\n\n"))
                    
                    full_response = ""
                    for line in response.iter_lines():
                        if line:
                            chunk = json.loads(line)
                            if 'response' in chunk:
                                text = chunk['response']
                                full_response += text
                                self.root.after(0, lambda t=text: self.results_text.insert(tk.END, t))
                                self.root.after(0, lambda: self.results_text.see(tk.END))
                    
                    self.root.after(0, lambda: self.status_var.set("✓ Analysis complete"))
                else:
                    error_msg = f"Error: {response.status_code}"
                    self.root.after(0, lambda: self.results_text.insert(tk.END, f"\n\n{error_msg}"))
                    self.root.after(0, lambda: self.status_var.set("Failed"))
                
            except Exception as e:
                error_msg = f"Error: {str(e)}"
                self.root.after(0, lambda: self.results_text.insert(tk.END, f"\n\n{error_msg}"))
                self.root.after(0, lambda: self.status_var.set("Failed"))
        
        threading.Thread(target=query_thread, daemon=True).start()

def main():
    root = tk.Tk()
    app = WiresharkAIAnalyzer(root)
    root.mainloop()

if __name__ == "__main__":
    main()