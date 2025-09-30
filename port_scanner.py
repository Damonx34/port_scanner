#!/usr/bin/env python3
# port_scanner_stylish.py
# Version stylée "hacker / matrix" du scanner. (Tkinter only)
# Inclut : scanning, banner grabbing simple, PID lookup Windows, export CSV, animation Matrix.
# Usage: py port_scanner_stylish.py

import socket
import ipaddress
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import queue
import time
import sys
import subprocess
import csv
import random
import string

# --------- Utilities (same logic que précédemment) ----------
def resolve_target(target_str):
    target_str = target_str.strip()
    if not target_str:
        raise ValueError("Target vide")
    if '/' in target_str:
        net = ipaddress.ip_network(target_str, strict=False)
        return [str(ip) for ip in net.hosts()]
    if '-' in target_str and target_str.replace('.', '').replace('-', '').replace(' ', '').isdigit():
        try:
            left, right = target_str.split('-')
            base = '.'.join(left.split('.')[:-1])
            start = int(left.split('.')[-1])
            end = int(right)
            return [f"{base}.{i}" for i in range(start, end+1)]
        except Exception:
            pass
    try:
        socket.inet_aton(target_str)
        return [target_str]
    except OSError:
        info = socket.getaddrinfo(target_str, None)
        ips = sorted({item[4][0] for item in info})
        return ips

def parse_ports(ports_str):
    ports = set()
    parts = ports_str.split(',')
    for p in parts:
        p = p.strip()
        if not p:
            continue
        if '-' in p:
            a, b = p.split('-', 1)
            a = int(a.strip()); b = int(b.strip())
            if a > b:
                a, b = b, a
            for port in range(a, b+1):
                if 0 < port <= 65535:
                    ports.add(port)
        else:
            port = int(p)
            if 0 < port <= 65535:
                ports.add(port)
    return sorted(ports)

def scan_port(ip, port, timeout):
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except Exception:
        return False

def grab_banner(ip, port, timeout=1.0):
    try:
        s = socket.socket()
        s.settimeout(timeout)
        s.connect((ip, port))
        try:
            data = s.recv(1024)
            if data:
                return data.decode('utf-8', errors='replace').strip()
        except Exception:
            pass
        try:
            s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            data = s.recv(1024)
            if data:
                return data.decode('utf-8', errors='replace').strip()
        except Exception:
            pass
        try:
            s.sendall(b"\r\n")
            data = s.recv(1024)
            if data:
                return data.decode('utf-8', errors='replace').strip()
        except Exception:
            pass
        s.close()
    except Exception:
        return None
    return None

def lookup_pid_windows(local_port):
    if sys.platform != "win32":
        return (None, None)
    try:
        out = subprocess.check_output(["netstat", "-ano"], encoding="utf-8", errors="ignore")
        pid = None
        for line in out.splitlines():
            if not line.strip():
                continue
            if "LISTENING" in line or "LISTEN" in line:
                parts = line.split()
                if len(parts) >= 4:
                    local_addr = parts[1]
                    try:
                        lp = int(local_addr.rsplit(":", 1)[1])
                    except Exception:
                        continue
                    if lp == int(local_port):
                        pid = parts[-1]
                        break
        if pid:
            tl = subprocess.check_output(["tasklist", "/FI", f"PID eq {pid}"], encoding="utf-8", errors="ignore")
            lines = [l for l in tl.splitlines() if l.strip()]
            if len(lines) >= 3:
                proc_line = lines[2]
                proc_name = proc_line.split()[0]
                return (pid, proc_name)
            else:
                return (pid, None)
    except Exception:
        return (None, None)
    return (None, None)

# --------- Scanner Worker ----------
class Scanner:
    def __init__(self, targets, ports, timeout=0.5, max_workers=100, result_callback=None, progress_callback=None, stop_event=None, do_banner=False, do_pid=False):
        self.targets = targets
        self.ports = ports
        self.timeout = timeout
        self.max_workers = max_workers
        self.result_callback = result_callback
        self.progress_callback = progress_callback
        self.stop_event = stop_event or threading.Event()
        self.do_banner = do_banner
        self.do_pid = do_pid

    def run(self):
        total = len(self.targets) * len(self.ports)
        done = 0
        for ip in self.targets:
            if self.stop_event.is_set():
                break
            with ThreadPoolExecutor(max_workers=min(self.max_workers, len(self.ports))) as ex:
                future_to_port = {ex.submit(scan_port, ip, port, self.timeout): port for port in self.ports}
                for fut in as_completed(future_to_port):
                    if self.stop_event.is_set():
                        break
                    port = future_to_port[fut]
                    try:
                        open_ = fut.result()
                    except Exception:
                        open_ = False
                    done += 1
                    if self.progress_callback:
                        self.progress_callback(done, total)
                    if open_ and self.result_callback:
                        extra = {}
                        if self.do_banner:
                            try:
                                b = grab_banner(ip, port, timeout=min(1.5, max(0.5, self.timeout)))
                                extra['banner'] = b
                            except Exception:
                                extra['banner'] = None
                        if self.do_pid:
                            if ip in ("127.0.0.1", "localhost") or ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172."):
                                pid, pname = lookup_pid_windows(port)
                                extra['pid'] = pid
                                extra['process'] = pname
                            else:
                                extra['pid'] = None
                                extra['process'] = None
                        self.result_callback(ip, port, extra)
            time.sleep(0.01)
        if self.progress_callback:
            self.progress_callback(total, total)

# --------- Matrix animation helper ----------
class MatrixCanvas(tk.Canvas):
    def __init__(self, master, width=120, height=400, font=("Consolas", 10), drop_speed=75, **kw):
        super().__init__(master, width=width, height=height, bg="black", highlightthickness=0, **kw)
        self.width = width
        self.height = height
        self.font = font
        self.drop_speed = drop_speed  # ms between updates
        self.columns = max(2, self.width // (self.font[1] // 1 + 2))
        self.drops = []
        self.running = True
        self._init_columns()
        self.after(self.drop_speed, self._tick)

    def _init_columns(self):
        self.drops = []
        for col in range(self.columns):
            x = (col * (self.font[1] // 1 + 2)) + 4
            y = random.randint(-self.height, 0)
            speed = random.uniform(2, 8)
            length = random.randint(6, 20)
            chars = [random.choice("01{}[]()<>/\\|@#$%^&*abcdefghijklmnopqrstuvwxyz".format('')) for _ in range(1000)]
            self.drops.append({"x": x, "y": y, "speed": speed, "length": length, "chars": chars})

    def _tick(self):
        if not self.running:
            return
        self.delete("all")
        for d in self.drops:
            d["y"] += d["speed"]
            if d["y"] > self.height:
                d["y"] = random.randint(-200, 0)
                d["speed"] = random.uniform(2, 8)
                d["length"] = random.randint(6, 20)
            # draw column
            for i in range(d["length"]):
                ch = random.choice("01{}[]()<>/\\|@#$%^&*abcdefghijklmnopqrstuvwxyz")
                ypos = d["y"] - (i * (self.font[1] // 1 + 2))
                if ypos < 0 or ypos > self.height:
                    continue
                # bright head
                if i == 0:
                    self.create_text(d["x"], ypos, text=ch, font=self.font, fill="#b7ffb7", anchor='nw')
                else:
                    shade = 100 + max(0, 155 - i*8)
                    color = f"#{int(shade):02x}{int(shade+30 if shade+30<255 else 255):02x}{int(shade):02x}"
                    self.create_text(d["x"], ypos, text=ch, font=self.font, fill=color, anchor='nw')
        self.after(self.drop_speed, self._tick)

    def stop(self):
        self.running = False

# --------- GUI main ----------
class StylishScanner(tk.Tk):
    def __init__(self):
        super().__init__()
        # Title (changeable)
        self.title("Damonx - Port Scanner")
        self.geometry("1100x680")
        self.configure(bg="#0b0b0b")
        self.protocol("WM_DELETE_WINDOW", self._on_close)

        # ttk dark style
        style = ttk.Style(self)
        style.theme_use('clam')  # clam is easier to style
        # General colors
        style.configure('.', background='#0b0b0b', foreground='#c7f0c7', fieldbackground='#151515', font=('Consolas', 10))
        style.configure('TButton', background='#202020', foreground='#c7f0c7', padding=6)
        style.map('TButton', background=[('active', '#2b2b2b')])
        style.configure('TLabel', background='#0b0b0b', foreground='#c7f0c7')
        style.configure('TEntry', fieldbackground='#1a1a1a', foreground='#c7f0c7')
        style.configure('Treeview', background='#0f0f0f', fieldbackground='#0f0f0f', foreground='#bfffbf', rowheight=22)
        style.layout("Treeview", [('Treeview.treearea', {'sticky': 'nswe'})])
        style.configure('Vertical.TScrollbar', gripcount=0, background='#151515', troughcolor='#0b0b0b')

        # main frames
        main = ttk.Frame(self, padding=8, style='TFrame')
        main.pack(fill='both', expand=True)

        # left matrix
        left_matrix = MatrixCanvas(main, width=120, height=600, font=("Consolas", 9), drop_speed=60)
        left_matrix.grid(row=0, column=0, rowspan=3, sticky='nsw', padx=(4,8), pady=4)

        # right matrix
        right_matrix = MatrixCanvas(main, width=120, height=600, font=("Consolas", 9), drop_speed=60)
        right_matrix.grid(row=0, column=3, rowspan=3, sticky='nse', padx=(8,4), pady=4)

        # center frame for controls/results
        center = ttk.Frame(main, padding=6)
        center.grid(row=0, column=1, sticky='nsew', padx=4)
        self.grid_columnconfigure(0, weight=0)
        main.grid_columnconfigure(1, weight=1)
        main.grid_rowconfigure(0, weight=1)

        # Title label
        title_lbl = ttk.Label(center, text="Damonx — Port Scanner", font=("Consolas", 16, "bold"))
        title_lbl.pack(anchor='w', pady=(0,8))

        # Controls frame
        ctrl = ttk.LabelFrame(center, text="Cible & Options", padding=8)
        ctrl.pack(fill='x', pady=4)

        ttk.Label(ctrl, text="Cible (IP/host/CIDR):").grid(row=0, column=0, sticky='w')
        self.entry_target = ttk.Entry(ctrl, width=36)
        self.entry_target.grid(row=0, column=1, sticky='w', padx=6, pady=2)
        self.entry_target.insert(0, "127.0.0.1")

        ttk.Label(ctrl, text="Ports (ex: 1-1024,80):").grid(row=1, column=0, sticky='w')
        self.entry_ports = ttk.Entry(ctrl, width=36)
        self.entry_ports.grid(row=1, column=1, sticky='w', padx=6, pady=2)
        self.entry_ports.insert(0, "1-1024")

        ttk.Label(ctrl, text="Timeout (s):").grid(row=0, column=2, sticky='w')
        self.spin_timeout = ttk.Spinbox(ctrl, from_=0.1, to=5.0, increment=0.1, width=6)
        self.spin_timeout.grid(row=0, column=3, padx=6)
        self.spin_timeout.set("0.5")

        ttk.Label(ctrl, text="Threads:").grid(row=1, column=2, sticky='w')
        self.spin_threads = ttk.Spinbox(ctrl, from_=5, to=1000, increment=5, width=6)
        self.spin_threads.grid(row=1, column=3, padx=6)
        self.spin_threads.set("120")

        opt_frame = ttk.Frame(ctrl)
        opt_frame.grid(row=2, column=0, columnspan=4, pady=(6,0), sticky='w')
        self.var_banner = tk.BooleanVar(value=True)
        self.chk_banner = ttk.Checkbutton(opt_frame, text="Banner grabbing", variable=self.var_banner)
        self.chk_banner.pack(side='left', padx=6)
        self.var_pid = tk.BooleanVar(value=True)
        self.chk_pid = ttk.Checkbutton(opt_frame, text="Lookup PID (local Win)", variable=self.var_pid)
        self.chk_pid.pack(side='left', padx=6)

        # Buttons
        btn_frame = ttk.Frame(center)
        btn_frame.pack(fill='x', pady=8)
        self.btn_start = ttk.Button(btn_frame, text="Démarrer", command=self.start_scan)
        self.btn_start.pack(side='left', padx=6)
        self.btn_stop = ttk.Button(btn_frame, text="Arrêter", command=self.stop_scan, state='disabled')
        self.btn_stop.pack(side='left', padx=6)
        self.btn_clear = ttk.Button(btn_frame, text="Effacer", command=self.clear_results)
        self.btn_clear.pack(side='left', padx=6)
        self.btn_export = ttk.Button(btn_frame, text="Exporter CSV", command=self.export_csv)
        self.btn_export.pack(side='left', padx=6)

        # Progress bar
        self.progress = ttk.Progressbar(center, mode='determinate')
        self.progress.pack(fill='x', pady=(2,8))

        # Results area (tree) and log side-by-side
        bottom = ttk.Panedwindow(center, orient='horizontal')
        bottom.pack(fill='both', expand=True)

        res_frame = ttk.LabelFrame(bottom, text="Résultats", padding=6)
        log_frame = ttk.LabelFrame(bottom, text="Journal", padding=6)
        bottom.add(res_frame, weight=2)
        bottom.add(log_frame, weight=1)

        # Treeview
        columns = ("ip","port","pid","proc","banner")
        self.tree = ttk.Treeview(res_frame, columns=columns, show='headings', selectmode='browse')
        self.tree.heading("ip", text="IP")
        self.tree.heading("port", text="Port")
        self.tree.heading("pid", text="PID")
        self.tree.heading("proc", text="Process")
        self.tree.heading("banner", text="Banner")
        self.tree.column("banner", width=340)
        self.tree.pack(fill='both', expand=True)

        # Tag style for open ports (we'll color text manually on insertion)
        # (Treeview styling per-row often uses tags to set foreground)
        self.tree.tag_configure('open', foreground='#7bff7b')

        # Log
        self.text_log = scrolledtext.ScrolledText(log_frame, height=18, bg="#0b0b0b", fg="#c7f0c7", insertbackground="#c7f0c7")
        self.text_log.pack(fill='both', expand=True)

        # Internal
        self.scanner_thread = None
        self.scanner_stop_event = threading.Event()
        self.result_queue = queue.Queue()
        self.results_list = []
        self.matrix_left = left_matrix
        self.matrix_right = right_matrix

        # Start queue processing loop
        self.after(200, self._process_queue)

    def log(self, *args):
        t = time.strftime("%H:%M:%S")
        line = f"[{t}] " + " ".join(str(a) for a in args) + "\n"
        self.text_log.insert(tk.END, line)
        self.text_log.see(tk.END)

    def start_scan(self):
        target = self.entry_target.get().strip()
        ports_str = self.entry_ports.get().strip()
        try:
            targets = resolve_target(target)
        except Exception as e:
            messagebox.showerror("Erreur cible", f"Impossible de résoudre la cible:\n{e}")
            return
        try:
            ports = parse_ports(ports_str)
            if not ports:
                raise ValueError("Aucun port valide.")
        except Exception as e:
            messagebox.showerror("Erreur ports", f"Erreur parsing ports:\n{e}")
            return
        timeout = float(self.spin_timeout.get())
        threads = int(self.spin_threads.get())
        if len(targets) > 1 and len(ports) * len(targets) > 10000:
            if not messagebox.askyesno("Attention", f"Tu vas scanner {len(targets)} adresses et {len(ports)} ports (≈{len(targets)*len(ports)} tests). Continuer ?"):
                return
        do_banner = bool(self.var_banner.get())
        do_pid = bool(self.var_pid.get())
        self.log(f"Démarrage scan: cibles={len(targets)} ports={len(ports)} timeout={timeout}s threads={threads} banner={do_banner} pid={do_pid}")
        self.btn_start.config(state='disabled')
        self.btn_stop.config(state='normal')
        self.scanner_stop_event.clear()
        self.progress['value'] = 0
        self.progress['maximum'] = len(targets) * len(ports)
        self.results_list.clear()
        scanner = Scanner(targets=targets, ports=ports, timeout=timeout, max_workers=threads,
                          result_callback=self._on_result, progress_callback=self._on_progress,
                          stop_event=self.scanner_stop_event, do_banner=do_banner, do_pid=do_pid)
        self.scanner_thread = threading.Thread(target=self._scanner_thread_target, args=(scanner,), daemon=True)
        self.scanner_thread.start()

    def _scanner_thread_target(self, scanner):
        try:
            scanner.run()
            self.result_queue.put(("done", None))
        except Exception as e:
            self.result_queue.put(("error", str(e)))

    def _on_result(self, ip, port, extra):
        self.result_queue.put(("result", (ip, port, extra)))

    def _on_progress(self, done, total):
        self.result_queue.put(("progress", (done, total)))

    def _process_queue(self):
        try:
            while True:
                item = self.result_queue.get_nowait()
                typ, val = item
                if typ == "result":
                    ip, port, extra = val
                    pid = extra.get('pid') if extra else None
                    proc = extra.get('process') if extra else None
                    banner = extra.get('banner') if extra else None
                    banner_short = (banner[:180] + "...") if banner and len(banner) > 180 else (banner or "")
                    # Insert row and color
                    iid = self.tree.insert('', 'end', values=(ip, port or "", pid or "", proc or "", banner_short), tags=('open',))
                    # Keep results for export
                    self.results_list.append({"ip": ip, "port": port, "pid": pid, "process": proc, "banner": banner or ""})
                    self.log(f"Ouvert: {ip}:{port} pid={pid} proc={proc} banner={banner_short}")
                elif typ == "progress":
                    done, total = val
                    self.progress['value'] = done
                elif typ == "done":
                    self.log("Scan terminé.")
                    self.btn_start.config(state='normal')
                    self.btn_stop.config(state='disabled')
                elif typ == "error":
                    self.log("Erreur dans le scanner:", val)
                    messagebox.showerror("Erreur scanner", str(val))
                    self.btn_start.config(state='normal')
                    self.btn_stop.config(state='disabled')
        except queue.Empty:
            pass
        self.after(150, self._process_queue)

    def stop_scan(self):
        self.log("Arrêt demandé.")
        self.scanner_stop_event.set()
        self.btn_stop.config(state='disabled')

    def clear_results(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.text_log.delete('1.0', tk.END)
        self.progress['value'] = 0
        self.results_list.clear()

    def export_csv(self):
        if not self.results_list:
            messagebox.showinfo("Exporter CSV", "Aucun résultat à exporter.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files","*.csv")], title="Enregistrer CSV")
        if not path:
            return
        try:
            with open(path, "w", newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=["ip","port","pid","process","banner"])
                writer.writeheader()
                for row in self.results_list:
                    writer.writerow(row)
            messagebox.showinfo("Exporter CSV", f"Exporté avec succès vers :\n{path}")
        except Exception as e:
            messagebox.showerror("Erreur export", str(e))

    def _on_close(self):
        try:
            self.matrix_left.stop()
            self.matrix_right.stop()
        except Exception:
            pass
        try:
            self.scanner_stop_event.set()
        except Exception:
            pass
        self.destroy()

if __name__ == "__main__":
    app = StylishScanner()
    app.mainloop()



"""
⠉⠉⠉⠉⠁⠀⠀⠀⠀⠒⠂⠰⠤⢤⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠛⠻⢤⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠠⠀⠐⠒⠒⠀⠀⠈⠉⠉⠉⠉⢉⣉⣉⣉⣙⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⢀⡀⠤⠒⠒⠉⠁⠀⠀⠀⠀⠳⣤⣀⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠈⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣶⠛⠛⠉⠛⠛⠶⢦⣤⡐⢀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣰⡿⠁⠀⠀⠀⠀⠀⠀⠀⠈⠉⢳⣦⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠳⡤⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢹⣇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⢷⣤⣀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⠙⠛⠛⠳⠶⢶⣦⠤⣄⡀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠳⣄⠉⠑⢄⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠳⡀⠀⠁
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠱⡄⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡄

"""