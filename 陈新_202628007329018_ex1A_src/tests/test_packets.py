import pathlib
import struct
import sys
import tempfile
import unittest
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from packet_parser import decode_packet, hexdump, protocol_matches
from pcap_backend import PcapError, read_pcap, write_pcap
from generate_demo_pcap import packets


class SnifferCoreTests(unittest.TestCase):
    def setUp(self):
        self.items = packets()

    def test_expected_protocols(self):
        self.assertEqual([p.protocol for p in self.items],
            ['TCP','HTTP','HTTP','DNS','DNS','ICMP','DNS','ICMPv6','TLS','ARP'])

    def test_ipv4_tcp_ports(self):
        self.assertEqual(self.items[1].src, '192.0.2.10')
        self.assertEqual(self.items[1].dst_port, 80)

    def test_dns_query(self):
        self.assertIn('example.org', self.items[3].summary)

    def test_ipv6(self):
        self.assertEqual(self.items[6].network, 'IPv6')
        self.assertEqual(self.items[7].transport, 'ICMPv6')
        # Npcap loopback DLT_NULL may use Windows AF_INET6 = 23.
        win_loopback = struct.pack('<I', 23) + self.items[6].data[14:]
        self.assertEqual(decode_packet(0, win_loopback, linktype=0).network, 'IPv6')

    def test_tls_metadata_no_decryption_claim(self):
        self.assertIn('not decrypted', self.items[8].summary)

    def test_arp(self):
        self.assertEqual(self.items[9].src, '192.0.2.10')

    def test_bidirectional_tcp_flow_key(self):
        self.assertEqual(self.items[1].flow_key, self.items[2].flow_key)

    def test_display_filter(self):
        self.assertTrue(protocol_matches(self.items[1], 'TCP'))
        self.assertTrue(protocol_matches(self.items[1], 'HTTP'))
        self.assertFalse(protocol_matches(self.items[1], 'DNS'))
        self.assertTrue(protocol_matches(self.items[6], 'IPv6'))
        self.assertTrue(protocol_matches(self.items[7], 'ICMPv6'))

    def test_pcap_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / 'test.pcap'
            write_pcap(str(path), self.items)
            back = list(read_pcap(str(path)))
            self.assertEqual(len(back), len(self.items))
            self.assertEqual([decode_packet(t, b, l, n).protocol for t,b,l,n in back],
                             [p.protocol for p in self.items])

    def test_malformed_input_fails_safely(self):
        for n in range(0, 35):
            p = decode_packet(0, b'\x01' * n)
            self.assertIsInstance(p.summary, str)

    def test_invalid_pcap(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / 'invalid.pcap'
            path.write_bytes(b'not a pcap')
            with self.assertRaises(PcapError):
                list(read_pcap(str(path)))

    def test_hexdump(self):
        self.assertIn('41 42 43', hexdump(b'ABC'))


if __name__ == '__main__':
    unittest.main()
