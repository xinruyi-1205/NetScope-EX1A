"""Generate ONLY synthetic, non-sensitive packets for offline parser demonstration."""
from __future__ import annotations
import ipaddress
from pathlib import Path
import struct
import time
from packet_parser import decode_packet
from pcap_backend import write_pcap


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b'\x00'
    acc = sum(struct.unpack('!' + 'H' * (len(data) // 2), data))
    while acc >> 16:
        acc = (acc & 0xffff) + (acc >> 16)
    return (~acc) & 0xffff


def _transport_checksum(src: bytes, dst: bytes, proto: int, payload: bytes, ipv6: bool) -> bytes:
    segment = bytearray(payload)
    if proto == 6 and len(segment) >= 20:
        pos = 16
    elif proto == 17 and len(segment) >= 8:
        pos = 6
    elif proto in (1, 58) and len(segment) >= 4:
        pos = 2
    else:
        return payload
    segment[pos:pos + 2] = b'\x00\x00'
    if proto == 1:  # ICMPv4 checksum does not use an IP pseudoheader.
        pseudo = b''
    elif ipv6:
        pseudo = src + dst + struct.pack('!I3xB', len(segment), proto)
    else:
        pseudo = src + dst + struct.pack('!BBH', 0, proto, len(segment))
    value = checksum(pseudo + segment)
    if value == 0 and proto == 17:
        value = 0xffff
    struct.pack_into('!H', segment, pos, value)
    return bytes(segment)


def ethernet(ethertype=0x0800):
    return bytes.fromhex('aabbccddeeff112233445566') + struct.pack('!H', ethertype)


def ipv4(src, dst, protocol, data, ident=1):
    source = ipaddress.IPv4Address(src).packed
    dest = ipaddress.IPv4Address(dst).packed
    data = _transport_checksum(source, dest, protocol, data, False)
    header = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20+len(data), ident, 0, 64, protocol, 0, source, dest)
    header = header[:10] + struct.pack('!H', checksum(header)) + header[12:]
    return ethernet() + header + data


def ipv6(src, dst, next_header, payload):
    source = ipaddress.IPv6Address(src).packed
    dest = ipaddress.IPv6Address(dst).packed
    payload = _transport_checksum(source, dest, next_header, payload, True)
    header = struct.pack('!IHBB16s16s', 6 << 28, len(payload), next_header, 64, source, dest)
    return ethernet(0x86dd) + header + payload


def tcp(sport, dport, payload=b'', flags=0x18, seq=1):
    return struct.pack('!HHIIHHHH', sport, dport, seq, 0, (5 << 12) | flags, 65535, 0, 0) + payload


def udp(sport, dport, payload=b''):
    return struct.pack('!HHHH', sport, dport, 8+len(payload), 0) + payload


def dns_query():
    return (struct.pack('!HHHHHH', 0x1234, 0x0100, 1, 0, 0, 0) +
            b'\x07example\x03org\x00' + struct.pack('!HH', 1, 1))


def dns_response():
    return (struct.pack('!HHHHHH', 0x1234, 0x8180, 1, 1, 0, 0) +
            b'\x07example\x03org\x00' + struct.pack('!HH', 1, 1) +
            b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x5d\xb8\xd8\x22')


def packets():
    items = [
        ipv4('192.0.2.10', '93.184.216.34', 6, tcp(51234,80, b'', 0x02)),
        ipv4('192.0.2.10', '93.184.216.34', 6, tcp(51234,80,b'GET /index.html HTTP/1.1\r\nHost: example.org\r\n\r\n')),
        ipv4('93.184.216.34','192.0.2.10',6,tcp(80,51234,b'HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello')),
        ipv4('192.0.2.10','192.0.2.53',17,udp(55000,53,dns_query())),
        ipv4('192.0.2.53','192.0.2.10',17,udp(53,55000,dns_response())),
        ipv4('192.0.2.10','192.0.2.1',1,b'\x08\x00\x00\x00\x00\x01\x00\x01hello'),
        ipv6('2001:db8::10','2001:db8::53',17,udp(55001,53,dns_query())),
        ipv6('2001:db8::10','2001:db8::20',58,b'\x80\x00\x00\x00\x00\x01\x00\x01'),
        ipv4('192.0.2.10','192.0.2.20',6,tcp(51235,443,b'\x16\x03\x03\x00\x04\x01\x00\x00\x00')),
        ethernet(0x0806) + (struct.pack('!HHBBH',1,0x0800,6,4,1) + bytes.fromhex('112233445566') +
                    ipaddress.IPv4Address('192.0.2.10').packed + b'\x00'*6 +
                    ipaddress.IPv4Address('192.0.2.1').packed),
    ]
    now = time.time()
    return [decode_packet(now + i * 0.12, data) for i, data in enumerate(items)]


def generate_demo(path):
    result = packets()
    write_pcap(path, result)
    return result


if __name__ == '__main__':
    target = Path(__file__).resolve().parent / 'demo_packets.pcap'
    result = generate_demo(str(target))
    print('Created:', target, 'Packets:', len(result))
    print('Protocols:', ', '.join(p.protocol for p in result))
