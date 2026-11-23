"""Minimal libpcap/Npcap binding through ctypes and portable PCAP file I/O.
Only authorized interface traffic should be captured.
"""
from __future__ import annotations
import ctypes
import ctypes.util
import os
from pathlib import Path
import queue
import struct
import sys
import threading
from typing import Callable

PCAP_ERRBUF_SIZE = 256

class PcapError(RuntimeError):
    pass

class _TimeVal(ctypes.Structure):
    _fields_ = [('tv_sec', ctypes.c_long), ('tv_usec', ctypes.c_long)]

class _PcapPkthdr(ctypes.Structure):
    _fields_ = [('ts', _TimeVal), ('caplen', ctypes.c_uint32), ('len', ctypes.c_uint32)]

class _PcapIf(ctypes.Structure):
    pass
_PcapIf._fields_ = [('next', ctypes.POINTER(_PcapIf)), ('name', ctypes.c_char_p),
                   ('description', ctypes.c_char_p), ('addresses', ctypes.c_void_p),
                   ('flags', ctypes.c_uint)]

class _BpfProgram(ctypes.Structure):
    _fields_ = [('bf_len', ctypes.c_uint), ('bf_insns', ctypes.c_void_p)]


def _decode_text(b):
    if not b:
        return ''
    for enc in ('utf-8', 'mbcs' if sys.platform == 'win32' else 'utf-8', 'latin-1'):
        try:
            return b.decode(enc)
        except (UnicodeError, LookupError):
            continue
    return str(b)


class PcapLibrary:
    def __init__(self):
        if sys.platform == 'win32':
            # Npcap's DLLs commonly reside in System32\\Npcap; keep the DLL directory handle alive.
            path = Path(os.environ.get('SystemRoot', r'C:\Windows')) / 'System32' / 'Npcap'
            self._dll_dir = None
            if path.is_dir() and hasattr(os, 'add_dll_directory'):
                self._dll_dir = os.add_dll_directory(str(path))
            try:
                self.lib = ctypes.WinDLL(str(path / 'wpcap.dll')) if (path / 'wpcap.dll').is_file() else ctypes.WinDLL('wpcap.dll')
            except OSError as exc:
                raise PcapError('找不到 Npcap 的 wpcap.dll。请先从 https://npcap.com/ 安装 Npcap，再重启程序。') from exc
        else:
            name = ctypes.util.find_library('pcap')
            if not name:
                raise PcapError('未检测到 libpcap。Linux 请安装 libpcap 软件包。')
            self.lib = ctypes.CDLL(name)
        L = self.lib
        L.pcap_findalldevs.argtypes = [ctypes.POINTER(ctypes.POINTER(_PcapIf)), ctypes.c_void_p]
        L.pcap_findalldevs.restype = ctypes.c_int
        L.pcap_freealldevs.argtypes = [ctypes.POINTER(_PcapIf)]
        L.pcap_freealldevs.restype = None
        L.pcap_open_live.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_int,
                                     ctypes.c_int, ctypes.c_void_p]
        L.pcap_open_live.restype = ctypes.c_void_p
        L.pcap_close.argtypes = [ctypes.c_void_p]
        L.pcap_close.restype = None
        L.pcap_datalink.argtypes = [ctypes.c_void_p]
        L.pcap_datalink.restype = ctypes.c_int
        L.pcap_next_ex.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.POINTER(_PcapPkthdr)),
                                    ctypes.POINTER(ctypes.POINTER(ctypes.c_ubyte))]
        L.pcap_next_ex.restype = ctypes.c_int
        L.pcap_geterr.argtypes = [ctypes.c_void_p]
        L.pcap_geterr.restype = ctypes.c_char_p
        L.pcap_compile.argtypes = [ctypes.c_void_p, ctypes.POINTER(_BpfProgram), ctypes.c_char_p,
                                   ctypes.c_int, ctypes.c_uint32]
        L.pcap_compile.restype = ctypes.c_int
        L.pcap_setfilter.argtypes = [ctypes.c_void_p, ctypes.POINTER(_BpfProgram)]
        L.pcap_setfilter.restype = ctypes.c_int
        L.pcap_freecode.argtypes = [ctypes.POINTER(_BpfProgram)]
        L.pcap_freecode.restype = None

    def interfaces(self) -> list[tuple[str, str]]:
        lst = ctypes.POINTER(_PcapIf)()
        err = ctypes.create_string_buffer(PCAP_ERRBUF_SIZE)
        if self.lib.pcap_findalldevs(ctypes.byref(lst), err) != 0:
            raise PcapError(_decode_text(err.value))
        out = []
        try:
            current = lst
            while current:
                item = current.contents
                if item.name:
                    out.append((_decode_text(item.name), _decode_text(item.description) or _decode_text(item.name)))
                current = item.next
        finally:
            if lst:
                self.lib.pcap_freealldevs(lst)
        return out

    def capture(self, interface: str, bpf: str, stop: threading.Event,
                event_queue: queue.Queue):
        err = ctypes.create_string_buffer(PCAP_ERRBUF_SIZE)
        # promiscuous=0 intentionally avoids attempting to observe unrelated hosts.
        handle = self.lib.pcap_open_live(interface.encode('utf-8'), 65535, 0, 300, err)
        if not handle:
            raise PcapError(_decode_text(err.value) or '无法打开网络适配器。请检查 Npcap 和抓包权限。')
        try:
            linktype = self.lib.pcap_datalink(handle)
            if bpf.strip():
                program = _BpfProgram()
                result = self.lib.pcap_compile(handle, ctypes.byref(program), bpf.encode('utf-8'), 1, 0xffffffff)
                if result < 0:
                    raise PcapError('BPF 捕获过滤器语法错误：' + _decode_text(self.lib.pcap_geterr(handle)))
                try:
                    if self.lib.pcap_setfilter(handle, ctypes.byref(program)) < 0:
                        raise PcapError('BPF 捕获过滤器设置失败：' + _decode_text(self.lib.pcap_geterr(handle)))
                finally:
                    self.lib.pcap_freecode(ctypes.byref(program))
            event_queue.put(('started', linktype))
            header = ctypes.POINTER(_PcapPkthdr)()
            payload = ctypes.POINTER(ctypes.c_ubyte)()
            while not stop.is_set():
                status = self.lib.pcap_next_ex(handle, ctypes.byref(header), ctypes.byref(payload))
                if status == 0:  # libpcap timeout: allow graceful stop
                    continue
                if status == 1:
                    h = header.contents
                    if h.caplen > 262144:
                        continue
                    raw = ctypes.string_at(payload, h.caplen)
                    timestamp = int(h.ts.tv_sec) + int(h.ts.tv_usec) / 1_000_000
                    try:
                        event_queue.put_nowait(('packet', (timestamp, raw, linktype, int(h.len))))
                    except queue.Full:
                        # This is a UI-consumer queue drop, not a measurement of kernel drops.
                        pass
                elif status in (-1, -2):
                    if not stop.is_set():
                        raise PcapError('抓包中断：' + _decode_text(self.lib.pcap_geterr(handle)))
                    break
        finally:
            self.lib.pcap_close(handle)


class CaptureWorker(threading.Thread):
    def __init__(self, lib: PcapLibrary, interface: str, bpf: str, events: queue.Queue):
        super().__init__(daemon=True)
        self.lib, self.interface, self.bpf = lib, interface, bpf
        self.events = events
        self.stop_event = threading.Event()

    def run(self):
        try:
            self.lib.capture(self.interface, self.bpf, self.stop_event, self.events)
        except Exception as exc:
            self.events.put(('error', str(exc)))
        finally:
            self.events.put(('stopped', None))

    def request_stop(self):
        self.stop_event.set()


# Classic PCAP files; pcapng is intentionally not supported.
MAGICS = {
    b'\xd4\xc3\xb2\xa1': ('<', 1_000_000),
    b'\xa1\xb2\xc3\xd4': ('>', 1_000_000),
    b'\x4d\x3c\xb2\xa1': ('<', 1_000_000_000),
    b'\xa1\xb2\x3c\x4d': ('>', 1_000_000_000),
}


def read_pcap(path: str, max_packets: int = 8000):
    """Yield (timestamp, packet_bytes, linktype, original_length)."""
    with open(path, 'rb') as f:
        global_header = f.read(24)
        if len(global_header) != 24 or global_header[:4] not in MAGICS:
            raise PcapError('不是支持的 .pcap 文件（不支持 .pcapng）。请用 Wireshark 另存为 pcap。')
        endian, scale = MAGICS[global_header[:4]]
        _, _, _, _, _, snaplen, linktype = struct.unpack(endian + 'IHHIIII', global_header)
        if snaplen > 8_000_000:
            raise PcapError('PCAP 文件中的 snaplen 不合理。')
        for i in range(max_packets):
            header = f.read(16)
            if not header:
                return
            if len(header) != 16:
                raise PcapError('PCAP 文件末尾记录不完整。')
            sec, subsec, caplen, origlen = struct.unpack(endian + 'IIII', header)
            if caplen > 4_000_000:
                raise PcapError('PCAP 数据包长度不合理。')
            packet = f.read(caplen)
            if len(packet) != caplen:
                raise PcapError('PCAP 数据包不完整。')
            yield sec + subsec / scale, packet, linktype, origlen


def write_pcap(path: str, packets):
    """Write PacketInfo objects. Requires one uniform link-layer type."""
    packets = list(packets)
    linktype = packets[0].linktype if packets else 1
    if any(p.linktype != linktype for p in packets):
        raise PcapError('数据包含多个链路层类型，不能写入单一 pcap 文件。')
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype))
        for p in packets:
            sec = int(p.timestamp)
            subsec = round((p.timestamp - sec) * 1_000_000)
            if subsec >= 1_000_000:
                sec += 1
                subsec -= 1_000_000
            f.write(struct.pack('<IIII', sec, subsec, len(p.data), p.origlen))
            f.write(p.data)
