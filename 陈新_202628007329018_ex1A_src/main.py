"""UCAS Software & System Security, Experiment 1A: GUI Network Packet Sniffer.
Author: 陈新, Student ID: 202628007329018, 计算机708班.
Usage: python main.py. No third-party Python packages required.
On Windows, live capture requires Npcap from https://npcap.com/.
"""
from __future__ import annotations
import csv
from collections import defaultdict
from datetime import datetime
import os
import queue
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from packet_parser import decode_packet, hexdump, protocol_matches
from pcap_backend import CaptureWorker, PcapError, PcapLibrary, read_pcap, write_pcap

MAX_PACKETS = 5000


class SnifferApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        root.title('NetScope · 网络嗅探与协议分析  |  EX1A  陈新  202628007329018')
        root.geometry('1360x855')
        root.minsize(980, 660)
        self.background = '#f1f5f9'
        root.configure(bg=self.background)
        self._styles()

        self.events = queue.Queue(maxsize=10000)
        self.records = []
        self.flow_totals = {}
        self.row_to_index = {}
        self.capture_worker = None
        self.pcap_lib = None
        self.iface_lookup = {}
        self.flow_focus = None
        self.seen_limit = False
        self.capturing = False
        self.flow_update_pending = False
        self.status_var = tk.StringVar(value='准备就绪。可先使用“生成示例抓包文件”离线体验。')
        self.count_var = tk.StringVar(value='共 0 包 / 显示 0 包')
        self.iface_var = tk.StringVar()
        self.bpf_var = tk.StringVar(value='')
        self.display_var = tk.StringVar(value='全部')
        self.search_var = tk.StringVar(value='')
        self._build()
        self.refresh_interfaces()
        root.after(100, self.poll_events)
        root.protocol('WM_DELETE_WINDOW', self.on_close)

    def _styles(self):
        style = ttk.Style(self.root)
        if 'clam' in style.theme_names():
            style.theme_use('clam')
        style.configure('TFrame', background=self.background)
        style.configure('TLabel', background=self.background, foreground='#334155', font=('Microsoft YaHei UI', 10))
        style.configure('Title.TLabel', background=self.background, foreground='#0f172a', font=('Microsoft YaHei UI', 17, 'bold'))
        style.configure('Subtitle.TLabel', background=self.background, foreground='#64748b', font=('Microsoft YaHei UI', 9))
        style.configure('TButton', padding=(10, 5), font=('Microsoft YaHei UI', 9))
        style.configure('Accent.TButton', background='#0f766e', foreground='white', padding=(12, 6))
        style.map('Accent.TButton', background=[('active', '#115e59'), ('disabled', '#9ca3af')])
        style.configure('Treeview', font=('Consolas', 9), rowheight=26, background='white', fieldbackground='white')
        style.configure('Treeview.Heading', font=('Microsoft YaHei UI', 9, 'bold'), background='#e2e8f0')
        style.configure('TNotebook', background=self.background)
        style.configure('TNotebook.Tab', padding=(16, 9), font=('Microsoft YaHei UI', 10))

    def _build(self):
        outer = ttk.Frame(self.root, padding=(14, 12))
        outer.pack(fill='both', expand=True)
        ttk.Label(outer, text='NetScope  /  嗅探器与协议分析', style='Title.TLabel').pack(anchor='w')
        ttk.Label(outer, text='EX1A · 陈新 · 202628007329018 · 计算机708班  |  仅限本人或已授权网络',
                  style='Subtitle.TLabel').pack(anchor='w', pady=(2, 11))

        row1 = ttk.Frame(outer)
        row1.pack(fill='x', pady=(0, 6))
        ttk.Label(row1, text='网络接口').pack(side='left')
        self.iface_combo = ttk.Combobox(row1, textvariable=self.iface_var, state='readonly', width=53)
        self.iface_combo.pack(side='left', padx=(8, 5), fill='x', expand=True)
        ttk.Button(row1, text='刷新接口', command=self.refresh_interfaces).pack(side='left', padx=3)
        self.start_button = ttk.Button(row1, text='▶ 开始抓包', command=self.start_capture, style='Accent.TButton')
        self.start_button.pack(side='left', padx=3)
        self.stop_button = ttk.Button(row1, text='■ 停止抓包', command=self.stop_capture, state='disabled')
        self.stop_button.pack(side='left', padx=3)
        ttk.Button(row1, text='清空', command=self.clear).pack(side='left', padx=3)

        row2 = ttk.Frame(outer)
        row2.pack(fill='x', pady=(0, 5))
        ttk.Label(row2, text='BPF 捕获过滤').pack(side='left')
        bpf = ttk.Entry(row2, textvariable=self.bpf_var, width=48)
        bpf.pack(side='left', padx=(7, 10), fill='x', expand=True)
        bpf.bind('<Return>', lambda _: self.start_capture() if not self.capturing else None)
        ttk.Label(row2, text='显示过滤').pack(side='left')
        self.display_combo = ttk.Combobox(row2, textvariable=self.display_var, state='readonly', width=13,
                                          values=['全部', 'TCP', 'UDP', 'IPv4', 'IPv6', 'ICMP', 'ICMPv6', 'ARP', 'DNS', 'HTTP', 'TLS'])
        self.display_combo.pack(side='left', padx=(6, 10))
        self.display_combo.bind('<<ComboboxSelected>>', lambda _: self.refresh_visible())
        ttk.Label(row2, text='关键字').pack(side='left')
        search = ttk.Entry(row2, textvariable=self.search_var, width=16)
        search.pack(side='left', padx=(6, 0))
        search.bind('<Return>', lambda _: self.refresh_visible())
        ttk.Button(row2, text='筛选', command=self.refresh_visible).pack(side='left', padx=(4, 0))

        row3 = ttk.Frame(outer)
        row3.pack(fill='x', pady=(0, 7))
        ttk.Label(row3, text='快捷捕获:').pack(side='left')
        for name, value in [('全部', ''), ('TCP', 'tcp'), ('UDP', 'udp'), ('ICMP', 'icmp or icmp6'),
                            ('DNS', 'udp port 53 or tcp port 53'), ('HTTP(80)', 'tcp port 80'),
                            ('IPv4/6', 'ip or ip6')]:
            ttk.Button(row3, text=name, command=lambda f=value: self.bpf_var.set(f)).pack(side='left', padx=2)
        ttk.Label(row3, text='注：修改 BPF 后需重新开始抓包', style='Subtitle.TLabel').pack(side='right')

        row4 = ttk.Frame(outer)
        row4.pack(fill='x', pady=(0, 10))
        ttk.Button(row4, text='打开 PCAP', command=self.open_pcap).pack(side='left', padx=(0, 5))
        ttk.Button(row4, text='保存 PCAP', command=self.save_pcap).pack(side='left', padx=5)
        ttk.Button(row4, text='导出 CSV', command=self.save_csv).pack(side='left', padx=5)
        ttk.Button(row4, text='生成示例抓包文件', command=self.create_demo).pack(side='left', padx=5)
        ttk.Button(row4, text='取消流筛选', command=self.clear_flow_filter).pack(side='left', padx=5)
        ttk.Label(row4, textvariable=self.count_var).pack(side='right')

        notebook = ttk.Notebook(outer)
        notebook.pack(fill='both', expand=True)
        self.notebook = notebook
        packet_tab = ttk.Frame(notebook)
        flow_tab = ttk.Frame(notebook)
        notebook.add(packet_tab, text='数据包 · 协议分析')
        notebook.add(flow_tab, text='TCP 双向流统计（加分项）')

        split = ttk.Panedwindow(packet_tab, orient='vertical')
        split.pack(fill='both', expand=True)
        list_frame = ttk.Frame(split)
        detail_frame = ttk.Frame(split)
        split.add(list_frame, weight=3)
        split.add(detail_frame, weight=2)
        columns = ('no', 'time', 'src', 'dst', 'protocol', 'length', 'info')
        self.tree = ttk.Treeview(list_frame, columns=columns, show='headings', selectmode='browse')
        headers = {'no': ('序号', 56), 'time': ('时间', 100), 'src': ('源地址', 200),
                   'dst': ('目的地址', 200), 'protocol': ('协议', 92),
                   'length': ('长度', 68), 'info': ('概要', 540)}
        for column in columns:
            name, width = headers[column]
            self.tree.heading(column, text=name)
            self.tree.column(column, width=width, minwidth=45,
                             anchor='e' if column in ('no', 'length') else 'w', stretch=(column == 'info'))
        scrolly = ttk.Scrollbar(list_frame, orient='vertical', command=self.tree.yview)
        scrollx = ttk.Scrollbar(list_frame, orient='horizontal', command=self.tree.xview)
        self.tree.configure(yscrollcommand=scrolly.set, xscrollcommand=scrollx.set)
        self.tree.grid(row=0, column=0, sticky='nsew')
        scrolly.grid(row=0, column=1, sticky='ns')
        scrollx.grid(row=1, column=0, sticky='ew')
        list_frame.columnconfigure(0, weight=1)
        list_frame.rowconfigure(0, weight=1)
        self.tree.bind('<<TreeviewSelect>>', self.packet_selected)
        self.tree.tag_configure('HTTP', background='#dcfce7')
        self.tree.tag_configure('DNS', background='#e0f2fe')
        self.tree.tag_configure('ICMP', background='#fef3c7')
        self.tree.tag_configure('ICMPv6', background='#fef3c7')
        self.tree.tag_configure('TLS', background='#ede9fe')

        lower = ttk.Panedwindow(detail_frame, orient='horizontal')
        lower.pack(fill='both', expand=True)
        details_left = ttk.Frame(lower)
        details_right = ttk.Frame(lower)
        lower.add(details_left, weight=1)
        lower.add(details_right, weight=1)
        ttk.Label(details_left, text='协议层次与报文头字段').pack(anchor='w', pady=(1, 3))
        self.detail_tree = ttk.Treeview(details_left, show='tree')
        ds = ttk.Scrollbar(details_left, orient='vertical', command=self.detail_tree.yview)
        self.detail_tree.configure(yscrollcommand=ds.set)
        self.detail_tree.pack(side='left', fill='both', expand=True)
        ds.pack(side='right', fill='y')
        ttk.Label(details_right, text='原始报文十六进制 / ASCII').pack(anchor='w', pady=(1, 3))
        self.hex_area = tk.Text(details_right, wrap='none', font=('Consolas', 9),
                                background='#0f172a', foreground='#e2e8f0', insertbackground='white',
                                padx=8, pady=8, state='disabled')
        self.hex_area.pack(side='left', fill='both', expand=True)
        hs = ttk.Scrollbar(details_right, orient='vertical', command=self.hex_area.yview)
        self.hex_area.configure(yscrollcommand=hs.set)
        hs.pack(side='right', fill='y')

        ttk.Label(flow_tab, text='双击某条 TCP 流，可在数据包页面查看该流的两个方向；不包含进程归属识别。',
                  style='Subtitle.TLabel').pack(anchor='w', padx=8, pady=8)
        self.flow_tree = ttk.Treeview(flow_tab, columns=('endpoints', 'packets', 'bytes', 'first', 'last'), show='headings')
        for col, text, width in [('endpoints', '通信双方 IP:Port', 600), ('packets', '数据包数', 96),
                                  ('bytes', '捕获字节数', 110), ('first', '开始时间', 120), ('last', '结束时间', 120)]:
            self.flow_tree.heading(col, text=text)
            self.flow_tree.column(col, width=width, stretch=col == 'endpoints')
        fs = ttk.Scrollbar(flow_tab, orient='vertical', command=self.flow_tree.yview)
        self.flow_tree.configure(yscrollcommand=fs.set)
        self.flow_tree.pack(side='left', fill='both', expand=True)
        fs.pack(side='right', fill='y')
        self.flow_tree.bind('<Double-1>', self.select_flow)

        bottom = ttk.Frame(outer)
        bottom.pack(fill='x', pady=(9, 1))
        ttk.Label(bottom, textvariable=self.status_var).pack(side='left', fill='x', expand=True)
        ttk.Label(bottom, text='捕获: Npcap/libpcap   |   解析: Python   |   GUI: Tkinter',
                  style='Subtitle.TLabel').pack(side='right')

    def refresh_interfaces(self):
        if self.capturing:
            return
        try:
            if self.pcap_lib is None:
                self.pcap_lib = PcapLibrary()
            interfaces = self.pcap_lib.interfaces()
            self.iface_lookup = {f'{desc}  [{name}]': name for name, desc in interfaces}
            self.iface_combo['values'] = list(self.iface_lookup)
            if self.iface_lookup:
                self.iface_combo.current(0)
                self.start_button.configure(state='normal')
                self.status_var.set(f'已找到 {len(interfaces)} 个接口。选择实际有流量的 Wi-Fi / 以太网接口。')
            else:
                self.start_button.configure(state='disabled')
                self.status_var.set('没有找到抓包接口。请检查 Npcap 安装与管理员权限。')
        except (PcapError, OSError) as exc:
            self.iface_combo['values'] = []
            self.iface_var.set('')
            self.start_button.configure(state='disabled')
            self.status_var.set(f'实时抓包不可用：{exc}（仍可用“生成示例抓包文件”离线测试）')

    def start_capture(self):
        if self.capturing:
            return
        name = self.iface_lookup.get(self.iface_var.get())
        if not name or self.pcap_lib is None:
            messagebox.showwarning('选择接口', '请先刷新并选择实际网络接口。')
            return
        if self.records and not messagebox.askyesno('开始新任务', '开始新的实时抓包将清空当前列表，是否继续？'):
            return
        self.clear()
        self.capturing = True
        self.start_button.configure(state='disabled')
        self.stop_button.configure(state='normal')
        self.iface_combo.configure(state='disabled')
        self.capture_worker = CaptureWorker(self.pcap_lib, name, self.bpf_var.get(), self.events)
        self.capture_worker.start()
        self.status_var.set('正在打开网络接口及编译 BPF 过滤器…')

    def stop_capture(self):
        if self.capture_worker:
            self.capture_worker.request_stop()
            self.status_var.set('正在停止抓包（通常在下一次超时检查后结束）…')
        self.stop_button.configure(state='disabled')

    def poll_events(self):
        for _ in range(200):
            try:
                what, payload = self.events.get_nowait()
            except queue.Empty:
                break
            if what == 'packet':
                if len(self.records) >= MAX_PACKETS:
                    if not self.seen_limit:
                        self.seen_limit = True
                        self.stop_capture()
                        self.status_var.set(f'已到 {MAX_PACKETS} 包上限，自动停止以限制内存。')
                    continue
                self.add_packet(*payload)
            elif what == 'started':
                self.status_var.set(f'抓包中（链路层 DLT={payload}）…… 点击“停止抓包”结束。')
            elif what == 'error':
                self.status_var.set('错误：' + str(payload))
                messagebox.showerror('抓包错误', str(payload))
            elif what == 'stopped':
                self.capturing = False
                self.capture_worker = None
                self.start_button.configure(state='normal' if self.iface_lookup else 'disabled')
                self.stop_button.configure(state='disabled')
                self.iface_combo.configure(state='readonly')
                if not self.status_var.get().startswith(('错误', '已到')):
                    self.status_var.set(f'抓包已结束，共 {len(self.records)} 包。')
        self.root.after(100, self.poll_events)

    def add_packet(self, timestamp, data, linktype, origlen):
        info = decode_packet(timestamp, data, linktype, origlen)
        self.records.append(info)
        idx = len(self.records) - 1
        self._add_flow(info)
        if self._is_visible(info):
            self._add_row(idx)
        if idx % 10 == 0 or idx < 5:
            self._update_counts()

    def _is_visible(self, info):
        if not protocol_matches(info, self.display_var.get()):
            return False
        if self.flow_focus is not None and info.flow_key != self.flow_focus:
            return False
        needle = self.search_var.get().strip().casefold()
        if needle and needle not in (info.src + ' ' + info.dst + ' ' + info.protocol + ' ' + info.summary).casefold():
            return False
        return True

    def _add_row(self, idx):
        p = self.records[idx]
        stamp = datetime.fromtimestamp(p.timestamp).strftime('%H:%M:%S.%f')[:12]
        rid = self.tree.insert('', 'end', values=(idx+1, stamp, p.src, p.dst,
                                                p.protocol, p.caplen, p.summary[:260]),
                               tags=(p.protocol,))
        self.row_to_index[rid] = idx

    def refresh_visible(self):
        rows = self.tree.get_children()
        if rows:
            self.tree.delete(*rows)
        self.row_to_index.clear()
        self.detail_tree.delete(*self.detail_tree.get_children())
        self._hex('')
        for i, p in enumerate(self.records):
            if self._is_visible(p):
                self._add_row(i)
        self._update_counts()

    def _update_counts(self):
        self.count_var.set(f'共 {len(self.records)} 包 / 显示 {len(self.tree.get_children())} 包')

    def packet_selected(self, _event=None):
        selection = self.tree.selection()
        if not selection:
            return
        idx = self.row_to_index.get(selection[0])
        if idx is None:
            return
        info = self.records[idx]
        self.detail_tree.delete(*self.detail_tree.get_children())
        top = self.detail_tree.insert('', 'end', text=f'Frame {idx+1}: {info.caplen} captured bytes / {info.origlen} original bytes', open=True)
        for title, fields in info.details:
            group = self.detail_tree.insert(top, 'end', text=title, open=True)
            for key, value in fields.items():
                self.detail_tree.insert(group, 'end', text=f'{key}: {value}')
        if not info.details:
            self.detail_tree.insert(top, 'end', text=info.summary)
        self._hex(hexdump(info.data[:8192]) + ('\n[仅显示前 8192 字节]' if len(info.data)>8192 else ''))

    def _hex(self, data):
        self.hex_area.configure(state='normal')
        self.hex_area.delete('1.0', 'end')
        self.hex_area.insert('1.0', data)
        self.hex_area.configure(state='disabled')

    def _add_flow(self, info):
        key = info.flow_key
        if key is None:
            return
        if key not in self.flow_totals:
            self.flow_totals[key] = {'packets': 0, 'bytes': 0, 'first': info.timestamp, 'last': info.timestamp}
        flow = self.flow_totals[key]
        flow['packets'] += 1
        flow['bytes'] += info.caplen
        flow['last'] = info.timestamp
        if not self.flow_update_pending:
            self.flow_update_pending = True
            self.root.after(350, self._flush_flows)

    def _flush_flows(self):
        self.flow_update_pending = False
        self._refresh_flows()

    def _refresh_flows(self):
        existing = self.flow_tree.get_children()
        if existing:
            self.flow_tree.delete(*existing)
        self.flow_row_keys = {}
        for key, stat in sorted(self.flow_totals.items(), key=lambda kv: -kv[1]['bytes']):
            a, b = key
            label = f'{a[0]}:{a[1]}  ⇄  {b[0]}:{b[1]}'
            st = datetime.fromtimestamp(stat['first']).strftime('%H:%M:%S')
            en = datetime.fromtimestamp(stat['last']).strftime('%H:%M:%S')
            rid = self.flow_tree.insert('', 'end', values=(label, stat['packets'], stat['bytes'], st, en))
            self.flow_row_keys[rid] = key

    def select_flow(self, _event=None):
        sel = self.flow_tree.selection()
        if not sel:
            return
        self.flow_focus = self.flow_row_keys.get(sel[0])
        self.display_var.set('TCP')
        self.refresh_visible()
        self.notebook.select(0)
        self.status_var.set('正在显示选定 TCP 双向流；点击“取消流筛选”恢复。')

    def clear_flow_filter(self):
        self.flow_focus = None
        self.display_var.set('全部')
        self.search_var.set('')
        self.refresh_visible()

    def clear(self):
        if self.capturing and self.capture_worker is not None:
            # During live capture, clear the view while continuing capture.
            pass
        self.records.clear()
        self.flow_totals.clear()
        self.flow_focus = None
        self.seen_limit = False
        self.refresh_visible()
        self._refresh_flows()
        self.status_var.set('已清空数据包。')

    def open_pcap(self):
        if self.capturing:
            messagebox.showwarning('操作不可用', '请先停止实时抓包。')
            return
        path = filedialog.askopenfilename(title='选择 PCAP 文件', filetypes=[('PCAP capture', '*.pcap'), ('All files', '*.*')])
        if not path:
            return
        try:
            packets = list(read_pcap(path, max_packets=MAX_PACKETS))
            self.clear()
            for record in packets:
                self.add_packet(*record)
            self._update_counts()
            self.status_var.set(f'已导入 {len(packets)} 包：{os.path.basename(path)}（最大读取 {MAX_PACKETS} 包）')
        except (PcapError, OSError) as exc:
            messagebox.showerror('导入失败', str(exc))

    def save_pcap(self):
        if not self.records:
            messagebox.showwarning('无数据', '先抓包或导入 PCAP 再保存。')
            return
        filename = filedialog.asksaveasfilename(title='保存原始数据包', defaultextension='.pcap',
                                                filetypes=[('PCAP capture', '*.pcap')])
        if filename:
            try:
                write_pcap(filename, self.records)
                self.status_var.set('已保存原始 PCAP：' + os.path.basename(filename))
            except (PcapError, OSError) as exc:
                messagebox.showerror('保存失败', str(exc))

    def save_csv(self):
        if not self.records:
            messagebox.showwarning('无数据', '先抓包或导入 PCAP 再导出。')
            return
        filename = filedialog.asksaveasfilename(title='导出协议摘要', defaultextension='.csv',
                                                filetypes=[('CSV', '*.csv')])
        if filename:
            try:
                with open(filename, 'w', newline='', encoding='utf-8-sig') as f:
                    writer = csv.writer(f)
                    writer.writerow(['No', 'Time', 'Source', 'Destination', 'Network', 'Transport',
                                     'Protocol', 'SrcPort', 'DstPort', 'CapturedLength', 'Info'])
                    for i,p in enumerate(self.records, 1):
                        writer.writerow([i, datetime.fromtimestamp(p.timestamp).isoformat(timespec='milliseconds'),
                                         p.src, p.dst, p.network, p.transport, p.protocol,
                                         p.src_port if p.src_port is not None else '',
                                         p.dst_port if p.dst_port is not None else '', p.caplen, p.summary])
                self.status_var.set('CSV 摘要已导出：' + os.path.basename(filename))
            except OSError as exc:
                messagebox.showerror('导出失败', str(exc))

    def create_demo(self):
        if self.capturing:
            messagebox.showwarning('操作不可用', '请先停止实时抓包。')
            return
        from generate_demo_pcap import generate_demo
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'demo_packets.pcap')
        try:
            generate_demo(path)
            self.clear()
            for row in read_pcap(path):
                self.add_packet(*row)
            self._update_counts()
            self.status_var.set('已加载完全合成的离线示例 PCAP（不是实际网络抓包）：' + path)
            messagebox.showinfo('离线演示', '已生成并加载示例 PCAP。可点击报文查看协议和十六进制。\n\n演示包是程序合成的数据，不可当作实际抓包截图。')
        except (OSError, PcapError) as exc:
            messagebox.showerror('生成失败', str(exc))

    def on_close(self):
        if self.capture_worker:
            self.capture_worker.request_stop()
        # Worker is daemon and owns its pcap handle; it will release the handle on exit.
        self.root.destroy()


def main():
    root = tk.Tk()
    SnifferApp(root)
    root.mainloop()


if __name__ == '__main__':
    main()
