"""Pure-Python packet decoder for Ethernet, IPv4, IPv6, TCP, UDP, ICMP, DNS, HTTP and TLS metadata.
No third-party modules required. Only packet *metadata* is decoded; TLS is not decrypted.
"""
from __future__ import annotations
from dataclasses import dataclass, field
import ipaddress
import struct
from typing import Optional

DLT_NULL = 0
DLT_EN10MB = 1
DLT_RAW = 101
DLT_LOOP = 108
DLT_LINUX_SLL = 113
DLT_LINUX_SLL2 = 276

@dataclass
class PacketInfo:
    timestamp: float
    data: bytes
    linktype: int = DLT_EN10MB
    caplen: int = 0
    origlen: int = 0
    src: str = "?"
    dst: str = "?"
    protocol: str = "OTHER"
    network: str = "?"
    transport: str = "?"
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    summary: str = ""
    details: list[tuple[str, dict]] = field(default_factory=list)

    def __post_init__(self):
        if not self.caplen:
            self.caplen = len(self.data)
        if not self.origlen:
            self.origlen = len(self.data)

    @property
    def flow_key(self):
        if self.transport != 'TCP' or self.src_port is None or self.dst_port is None:
            return None
        a, b = (self.src, self.src_port), (self.dst, self.dst_port)
        return tuple(sorted((a, b)))


def _mac(v: bytes) -> str:
    return ':'.join(f'{x:02x}' for x in v)


def _add(p: PacketInfo, title: str, **fields):
    p.details.append((title, {str(k): str(v) for k, v in fields.items()}))


def _dns_question(data: bytes, start: int) -> str:
    if len(data) < start + 12:
        return ''
    cursor = start + 12
    names = []
    for _ in range(64):
        if cursor >= len(data):
            return ''
        ln = data[cursor]
        if ln == 0:
            return '.'.join(names)[:160]
        if ln & 0xc0:  # DNS compression pointer; intentionally do not follow untrusted pointers
            return '.'.join(names)[:160]
        if ln > 63 or cursor + 1 + ln > len(data):
            return ''
        names.append(data[cursor + 1: cursor + 1 + ln].decode('ascii', errors='replace'))
        cursor += ln + 1
    return ''


def _application(p: PacketInfo, payload: bytes):
    sport, dport = p.src_port, p.dst_port
    if (sport == 53 or dport == 53) and payload:
        dns = payload
        if p.transport == 'TCP' and len(payload) >= 2:
            n = struct.unpack_from('!H', payload)[0]
            if n <= len(payload) - 2:
                dns = payload[2:2 + n]
        if len(dns) >= 12:
            tid, flags, qd, an, _, _ = struct.unpack_from('!HHHHHH', dns, 0)
            query = _dns_question(dns, 0)
            response = bool(flags & 0x8000)
            p.protocol = 'DNS'
            p.summary = f"DNS {'Response' if response else 'Query'} id=0x{tid:04x} questions={qd} answers={an}" + (f" {query}" if query else '')
            _add(p, 'Domain Name System', transaction_id=f'0x{tid:04x}', response=response,
                 questions=qd, answers=an, query_name=query)
            return
    if p.transport == 'TCP':
        head = payload[:32]
        verbs = (b'GET ', b'POST ', b'PUT ', b'DELETE ', b'HEAD ', b'OPTIONS ',
                 b'PATCH ', b'CONNECT ', b'TRACE ', b'HTTP/')
        if any(head.startswith(v) for v in verbs):
            first = payload.split(b'\r\n', 1)[0][:180].decode('latin-1', errors='replace')
            p.protocol = 'HTTP'
            p.summary = first
            _add(p, 'HTTP (plaintext only)', start_line=first)
            return
        if len(payload) >= 5 and payload[0] in (20, 21, 22, 23) and payload[1] == 3 and payload[2] <= 4:
            p.protocol = 'TLS'
            kinds = {20: 'ChangeCipherSpec', 21: 'Alert', 22: 'Handshake', 23: 'ApplicationData'}
            length = struct.unpack_from('!H', payload, 3)[0]
            p.summary = f'TLS record: {kinds.get(payload[0], "Unknown")}, payload_length={length} (encrypted data not decrypted)'
            _add(p, 'Transport Layer Security', content_type=kinds.get(payload[0], 'Unknown'),
                 version=f'3.{payload[2]}', record_length=length, decryption='Not attempted')
            return
        if sport == 443 or dport == 443:
            p.summary += ' [port 443; TLS not independently confirmed]'


def decode_packet(timestamp: float, data: bytes, linktype: int = DLT_EN10MB,
                  origlen: int | None = None) -> PacketInfo:
    p = PacketInfo(timestamp=timestamp, data=data, linktype=linktype,
                   caplen=len(data), origlen=origlen if origlen is not None else len(data))
    try:
        _decode(p)
    except (struct.error, ValueError, IndexError) as exc:
        p.summary = (p.summary + f' [truncated/malformed: {type(exc).__name__}]').strip()
    return p


def _decode(p: PacketInfo):
    data = p.data
    off = 0
    ethertype = None
    if p.linktype == DLT_EN10MB:
        if len(data) < 14:
            p.summary = 'Truncated Ethernet frame'
            return
        dst, src, ethertype = data[:6], data[6:12], struct.unpack_from('!H', data, 12)[0]
        p.src, p.dst = _mac(src), _mac(dst)
        _add(p, 'Ethernet II', source_mac=p.src, destination_mac=p.dst,
             ether_type=f'0x{ethertype:04x}')
        off = 14
        for _ in range(2):
            if ethertype not in (0x8100, 0x88a8, 0x9100):
                break
            if len(data) < off + 4:
                p.summary = 'Truncated VLAN header'
                return
            tci, ethertype = struct.unpack_from('!HH', data, off)
            _add(p, '802.1Q VLAN', vlan_id=tci & 0x0fff, priority=(tci >> 13) & 7)
            off += 4
    elif p.linktype == DLT_LINUX_SLL:
        if len(data) < 16:
            p.summary = 'Truncated Linux cooked header'
            return
        ethertype = struct.unpack_from('!H', data, 14)[0]
        off = 16
        _add(p, 'Linux cooked capture v1', protocol=f'0x{ethertype:04x}')
    elif p.linktype == DLT_LINUX_SLL2:
        if len(data) < 20:
            p.summary = 'Truncated Linux cooked header v2'
            return
        ethertype = struct.unpack_from('!H', data, 0)[0]
        off = 20
        _add(p, 'Linux cooked capture v2', protocol=f'0x{ethertype:04x}')
    elif p.linktype == DLT_RAW:
        off = 0
        ethertype = 0x86dd if data and data[0] >> 4 == 6 else 0x0800
    elif p.linktype in (DLT_NULL, DLT_LOOP):
        if len(data) < 4:
            p.summary = 'Truncated loopback header'
            return
        family = struct.unpack_from('<I' if p.linktype == DLT_NULL else '>I', data, 0)[0]
        if family in (2,):
            ethertype = 0x0800
        elif family in (10, 23, 24, 28, 30):  # Windows AF_INET6=23; Unix variants differ
            ethertype = 0x86dd
        off = 4
        _add(p, 'Loopback', family=family)
    else:
        p.summary = f'Unsupported link-layer type {p.linktype}'
        return

    if ethertype == 0x0806:
        if len(data) < off + 28:
            p.summary = 'Truncated ARP'
            return
        hwtype, ptype, hlen, plen, op = struct.unpack_from('!HHBBH', data, off)
        p.protocol = p.network = 'ARP'
        if hlen == 6 and plen == 4 and len(data) >= off + 28:
            source_ip = str(ipaddress.IPv4Address(data[off + 14:off + 18]))
            dest_ip = str(ipaddress.IPv4Address(data[off + 24:off + 28]))
            p.src, p.dst = source_ip, dest_ip
            p.summary = f'ARP {"request" if op == 1 else "reply" if op == 2 else "operation " + str(op)}: {source_ip} -> {dest_ip}'
            _add(p, 'Address Resolution Protocol', opcode=op, sender_ip=source_ip, target_ip=dest_ip)
        else:
            p.summary = f'ARP opcode={op} hwtype={hwtype} ptype={ptype}'
        return
    if ethertype == 0x0800:
        if len(data) < off + 20:
            p.summary = 'Truncated IPv4 packet'
            return
        first = data[off]
        if first >> 4 != 4:
            p.summary = 'Invalid IPv4 version'
            return
        ihl = (first & 15) * 4
        if ihl < 20 or len(data) < off + ihl:
            p.summary = 'Invalid/truncated IPv4 header'
            return
        total, identification, frag, ttl, proto = struct.unpack_from('!HHHBB', data, off + 2)
        p.src, p.dst = str(ipaddress.IPv4Address(data[off+12:off+16])), str(ipaddress.IPv4Address(data[off+16:off+20]))
        p.network = p.protocol = 'IPv4'
        _add(p, 'Internet Protocol Version 4', source=p.src, destination=p.dst,
             header_length=ihl, packet_length=total, ttl=ttl, protocol_number=proto,
             identification=identification, fragment_offset=(frag & 0x1fff) * 8,
             more_fragments=bool(frag & 0x2000))
        off += ihl
        if frag & 0x1fff:
            p.summary = 'Non-initial IPv4 fragment (transport header unavailable)'
            return
        _transport(p, proto, off)
        return
    if ethertype == 0x86dd:
        if len(data) < off + 40:
            p.summary = 'Truncated IPv6 packet'
            return
        if data[off] >> 4 != 6:
            p.summary = 'Invalid IPv6 version'
            return
        payload_len, next_header, hop_limit = struct.unpack_from('!HBB', data, off+4)
        p.src = str(ipaddress.IPv6Address(data[off+8:off+24]))
        p.dst = str(ipaddress.IPv6Address(data[off+24:off+40]))
        p.network = p.protocol = 'IPv6'
        _add(p, 'Internet Protocol Version 6', source=p.src, destination=p.dst,
             payload_length=payload_len, next_header=next_header, hop_limit=hop_limit)
        off += 40
        for _ in range(10):
            if next_header in (0, 43, 60, 135):  # extension header length measured in 8-octet units
                if off + 2 > len(data):
                    p.summary = 'Truncated IPv6 extension header'
                    return
                nxt, length = data[off], (data[off+1] + 1) * 8
                if off + length > len(data):
                    p.summary = 'Truncated IPv6 extension header'
                    return
                _add(p, 'IPv6 extension header', header_type=next_header, header_length=length)
                off += length
                next_header = nxt
            elif next_header == 44:
                if off + 8 > len(data):
                    p.summary = 'Truncated IPv6 fragmentation header'
                    return
                nxt = data[off]
                fragments = struct.unpack_from('!H', data, off + 2)[0]
                off += 8
                if (fragments >> 3) != 0:
                    p.summary = 'Non-initial IPv6 fragment (transport header unavailable)'
                    return
                next_header = nxt
            elif next_header == 51:
                if off + 2 > len(data):
                    return
                nxt, length = data[off], (data[off+1] + 2) * 4
                if off + length > len(data):
                    return
                off += length
                next_header = nxt
            else:
                break
        _transport(p, next_header, off)
        return
    p.summary = f'EtherType 0x{ethertype:04x}' if ethertype is not None else 'Unknown packet'


def _transport(p: PacketInfo, proto: int, off: int):
    data = p.data
    if proto == 6:
        if off + 20 > len(data):
            p.summary = 'Truncated TCP segment'
            return
        sport, dport, seq, ack, flagsword, window = struct.unpack_from('!HHIIHH', data, off)
        hdrlen = ((flagsword >> 12) & 0xf) * 4
        if hdrlen < 20 or off + hdrlen > len(data):
            p.summary = 'Invalid/truncated TCP header'
            return
        mask = flagsword & 0x1ff
        flags = ''.join(n for bit,n in ((0x100,'N'),(0x80,'C'),(0x40,'E'),(0x20,'U'),
                  (0x10,'A'),(0x08,'P'),(0x04,'R'),(0x02,'S'),(0x01,'F')) if mask & bit)
        p.src_port, p.dst_port = sport, dport
        p.transport = p.protocol = 'TCP'
        payload = data[off+hdrlen:]
        p.summary = f'{sport} -> {dport} [{flags or "-"}] Seq={seq} Ack={ack} Win={window} Data={len(payload)}B'
        _add(p, 'Transmission Control Protocol', source_port=sport, destination_port=dport,
             sequence=seq, acknowledgement=ack, flags=flags, window=window,
             header_length=hdrlen, payload_length=len(payload))
        _application(p, payload)
    elif proto == 17:
        if off + 8 > len(data):
            p.summary = 'Truncated UDP datagram'
            return
        sport, dport, length, checksum = struct.unpack_from('!HHHH', data, off)
        p.src_port, p.dst_port = sport, dport
        p.transport = p.protocol = 'UDP'
        payload = data[off+8:]
        p.summary = f'{sport} -> {dport} Length={length}'
        _add(p, 'User Datagram Protocol', source_port=sport, destination_port=dport,
             length=length, checksum=f'0x{checksum:04x}')
        _application(p, payload)
    elif proto in (1, 58):
        if off + 4 > len(data):
            p.summary = 'Truncated ICMP packet'
            return
        kind, code = data[off], data[off+1]
        p.transport = p.protocol = 'ICMPv6' if proto == 58 else 'ICMP'
        p.summary = f'{p.protocol} Type={kind} Code={code}'
        _add(p, 'Internet Control Message Protocol', type=kind, code=code)
    else:
        p.summary = f'IP protocol number {proto}'


def hexdump(data: bytes) -> str:
    lines = []
    for offset in range(0, len(data), 16):
        chunk = data[offset:offset + 16]
        h = ' '.join(f'{byte:02X}' for byte in chunk)
        readable = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
        lines.append(f'{offset:08X}  {h:<47}  |{readable}|')
    return '\n'.join(lines)


def protocol_matches(p: PacketInfo, expression: str) -> bool:
    """Display-only protocol filter. BPF capture expressions are compiled separately by libpcap."""
    expr = expression.strip().lower()
    if not expr or expr in ('all', '全部'):
        return True
    protocols = {x.strip() for x in expr.replace('，', ',').split(',') if x.strip()}
    for protocol in protocols:
        if protocol in ('ipv4', 'ip4') and p.network == 'IPv4':
            return True
        if protocol in ('ipv6', 'ip6') and p.network == 'IPv6':
            return True
        if protocol in ('tcp', 'udp', 'icmp', 'icmpv6') and p.transport.lower() == protocol:
            return True
        if protocol in ('http', 'dns', 'tls', 'arp') and p.protocol.lower() == protocol:
            return True
        if protocol == p.protocol.lower():
            return True
    return False
