import os
import unittest
import json
from scapy.all import Ether, IP, TCP, UDP, ICMP, wrpcap
from app import create_app

class TestNetIntelNOC(unittest.TestCase):
    """
    Automated backend unit test suite for NetIntel NOC platform.
    Uses Scapy to generate test PCAP files strictly within isolated unit tests.
    """
    @classmethod
    def setUpClass(cls):
        cls.app = create_app('development')
        cls.client = cls.app.test_client()
        cls.test_pcap_path = 'test_unit_capture.pcap'

        # Generate isolated test PCAP file with Scapy containing TCP, UDP, ICMP, and port scan pattern
        packets = [
            # Normal HTTP SYN, SYN-ACK, ACK handshake
            Ether()/IP(src="192.168.1.10", dst="10.0.0.1")/TCP(sport=12345, dport=80, flags="S"),
            Ether()/IP(src="10.0.0.1", dst="192.168.1.10")/TCP(sport=80, dport=12345, flags="SA"),
            Ether()/IP(src="192.168.1.10", dst="10.0.0.1")/TCP(sport=12345, dport=80, flags="A"),
            
            # UDP packet
            Ether()/IP(src="192.168.1.10", dst="10.0.0.1")/UDP(sport=5353, dport=53),
            
            # ICMP packet
            Ether()/IP(src="192.168.1.10", dst="10.0.0.1")/ICMP()
        ]

        # Add simulated port scan packets from 192.168.1.50 contacting 20 ports
        for port in range(100, 120):
            packets.append(Ether()/IP(src="192.168.1.50", dst="10.0.0.1")/TCP(sport=50000, dport=port, flags="S"))

        wrpcap(cls.test_pcap_path, packets)

    @classmethod
    def tearDownClass(cls):
        if os.path.exists(cls.test_pcap_path):
            os.remove(cls.test_pcap_path)

    def test_01_health_check(self):
        res = self.client.get('/health')
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data['status'], 'healthy')

    def test_02_upload_pcap(self):
        with open(self.test_pcap_path, 'rb') as f:
            response = self.client.post(
                '/upload',
                data={'file': (f, 'test_unit_capture.pcap')},
                content_type='multipart/form-data'
            )
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertIn('filename', data)
        self.uploaded_filename = data['filename']
        TestNetIntelNOC.uploaded_filename = data['filename']

    def test_03_analyze_pcap(self):
        filename = getattr(TestNetIntelNOC, 'uploaded_filename', None)
        self.assertIsNotNone(filename)

        response = self.client.get(f'/analyze/{filename}')
        self.assertEqual(response.status_code, 200)
        data = response.get_json()

        # Verify summary stats
        summary = data.get('summary', {})
        self.assertEqual(summary['total_packets'], 25)
        self.assertGreater(summary['total_bytes'], 0)
        self.assertEqual(summary['unique_hosts'], 3)  # 192.168.1.10, 10.0.0.1, 192.168.1.50

        # Verify protocol breakdown
        proto = data.get('protocol_distribution', {})
        self.assertEqual(proto['tcp_count'], 23)
        self.assertEqual(proto['udp_count'], 1)
        self.assertEqual(proto['icmp_count'], 1)

        # Verify rule-based anomaly detection (Port Scan pattern for 192.168.1.50)
        anomalies = data.get('anomalies', [])
        self.assertGreater(len(anomalies), 0)
        port_scan_anom = [a for a in anomalies if a['src_ip'] == '192.168.1.50' and 'Port Scan' in a['reason']]
        self.assertTrue(len(port_scan_anom) > 0)

        # Verify topology graph structure
        topology = data.get('topology', {})
        self.assertEqual(len(topology['nodes']), 3)
        self.assertGreater(len(topology['edges']), 0)

        # Verify ML prediction output
        ml_pred = data.get('ml_prediction', {})
        self.assertTrue(ml_pred.get('model_available', False))
        self.assertIn(ml_pred.get('prediction'), ['BENIGN', 'ATTACK'])
        self.assertGreater(ml_pred.get('confidence', 0), 0)

    def test_04_exports(self):
        filename = getattr(TestNetIntelNOC, 'uploaded_filename', None)
        self.assertIsNotNone(filename)

        # Test JSON Export
        res_json = self.client.get(f'/export/json/{filename}')
        self.assertEqual(res_json.status_code, 200)
        self.assertEqual(res_json.mimetype, 'application/json')

        # Test CSV Export
        res_csv = self.client.get(f'/export/csv/{filename}')
        self.assertEqual(res_csv.status_code, 200)
        self.assertEqual(res_csv.mimetype, 'text/csv')

        # Test PDF Export
        res_pdf = self.client.get(f'/export/pdf/{filename}')
        self.assertEqual(res_pdf.status_code, 200)
        self.assertEqual(res_pdf.mimetype, 'application/pdf')

    def test_05_real_pcap_msnms_analysis(self):
        msnms_path = os.path.join('uploads', 'd91d85c7_msnms.pcap')
        if os.path.exists(msnms_path):
            with open(msnms_path, 'rb') as f:
                response = self.client.post(
                    '/upload',
                    data={'file': (f, 'msnms.pcap')},
                    content_type='multipart/form-data'
                )
            self.assertEqual(response.status_code, 200)
            upload_filename = response.get_json()['filename']

            analyze_res = self.client.get(f'/analyze/{upload_filename}')
            self.assertEqual(analyze_res.status_code, 200)
            data = analyze_res.get_json()

            summary = data.get('summary', {})
            self.assertEqual(summary['total_packets'], 364)
            self.assertEqual(summary['total_bytes'], 56503)
            self.assertEqual(summary['unique_hosts'], 7)

            proto = data.get('protocol_distribution', {})
            self.assertEqual(proto['tcp_count'], 364)
            self.assertEqual(proto['udp_count'], 0)

            anomalies = data.get('anomalies', [])
            self.assertEqual(len(anomalies), 1)

    def test_06_non_ip_handling(self):
        from core.flow_aggregator import extract_flows_from_packets
        non_ip_pkts = [
            {"packet_id": 1, "has_ip": False, "src_ip": "Unknown", "dst_ip": "Unknown", "protocol": "ARP", "length": 42}
        ]
        flows = extract_flows_from_packets(non_ip_pkts)
        self.assertEqual(len(flows), 0)

    def test_07_invalid_file_upload(self):
        response = self.client.post(
            '/upload',
            data={'file': (b'INVALID NON-PCAP HEADER DATA', 'invalid.txt')},
            content_type='multipart/form-data'
        )
        self.assertEqual(response.status_code, 400)

if __name__ == '__main__':
    unittest.main()

