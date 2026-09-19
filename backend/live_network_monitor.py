"""
Live Network Traffic Monitor
Captures real packets from your network interface, extracts CICIDS2017-compatible
features, and runs them through the trained MLP model for real-time detection.
"""

import time
import threading
import numpy as np
from collections import defaultdict
from scapy.all import sniff, IP, TCP, UDP, ICMP


class FlowTracker:
    """Tracks network flows and extracts CICIDS2017-compatible features."""
    
    def __init__(self, flow_timeout=30):
        self.flows = {}
        self.flow_timeout = flow_timeout
        self.lock = threading.Lock()
    
    def _get_flow_key(self, pkt):
        """Create a unique flow key from packet."""
        if IP in pkt:
            src = pkt[IP].src
            dst = pkt[IP].dst
            proto = pkt[IP].proto
            
            sport = 0
            dport = 0
            if TCP in pkt:
                sport = pkt[TCP].sport
                dport = pkt[TCP].dport
            elif UDP in pkt:
                sport = pkt[UDP].sport
                dport = pkt[UDP].dport
            
            return (src, dst, sport, dport, proto)
        return None
    
    def process_packet(self, pkt):
        """Process a captured packet and update flow statistics."""
        flow_key = self._get_flow_key(pkt)
        if flow_key is None:
            return
        
        now = time.time()
        pkt_len = len(pkt)
        
        with self.lock:
            if flow_key not in self.flows:
                self.flows[flow_key] = {
                    'start_time': now,
                    'last_time': now,
                    'fwd_packets': 0,
                    'bwd_packets': 0,
                    'fwd_lengths': [],
                    'bwd_lengths': [],
                    'fwd_iat': [],
                    'bwd_iat': [],
                    'flags': {'FIN': 0, 'PSH': 0, 'ACK': 0},
                    'protocol': flow_key[4],
                    'src_ip': flow_key[0],
                    'dst_ip': flow_key[1],
                }
            
            flow = self.flows[flow_key]
            flow['last_time'] = now
            
            # Determine direction (simplified: first packet is fwd)
            if flow['fwd_packets'] == 0 and flow['bwd_packets'] == 0:
                flow['fwd_packets'] += 1
                flow['fwd_lengths'].append(pkt_len)
            elif flow['fwd_packets'] <= flow['bwd_packets']:
                flow['fwd_packets'] += 1
                flow['fwd_lengths'].append(pkt_len)
                if flow['fwd_iat']:
                    flow['fwd_iat'].append(now - flow['last_time'])
            else:
                flow['bwd_packets'] += 1
                flow['bwd_lengths'].append(pkt_len)
                if flow['bwd_iat']:
                    flow['bwd_iat'].append(now - flow['last_time'])
            
            # Track TCP flags
            if TCP in pkt:
                flags = pkt[TCP].flags
                if flags & 0x01: flow['flags']['FIN'] += 1
                if flags & 0x08: flow['flags']['PSH'] += 1
                if flags & 0x10: flow['flags']['ACK'] += 1
    
    def extract_features(self, flow):
        """Extract CICIDS2017-compatible features from a flow."""
        duration = max(flow['last_time'] - flow['start_time'], 0.001)
        total_fwd = flow['fwd_packets']
        total_bwd = flow['bwd_packets']
        total_packets = total_fwd + total_bwd
        
        fwd_lengths = flow['fwd_lengths'] if flow['fwd_lengths'] else [0]
        bwd_lengths = flow['bwd_lengths'] if flow['bwd_lengths'] else [0]
        
        # Build feature vector matching CICIDS2017 columns (52 features)
        features = [
            0,                                          # Destination Port (default)
            duration * 1000,                           # Flow Duration (ms)
            total_fwd,                                 # Total Fwd Packets
            sum(fwd_lengths),                          # Total Length of Fwd Packets
            max(fwd_lengths),                          # Fwd Packet Length Max
            min(fwd_lengths),                          # Fwd Packet Length Min
            np.mean(fwd_lengths),                      # Fwd Packet Length Mean
            np.std(fwd_lengths) if len(fwd_lengths) > 1 else 0,  # Fwd Packet Length Std
            max(bwd_lengths),                          # Bwd Packet Length Max
            min(bwd_lengths),                          # Bwd Packet Length Min
            np.mean(bwd_lengths),                      # Bwd Packet Length Mean
            np.std(bwd_lengths) if len(bwd_lengths) > 1 else 0,  # Bwd Packet Length Std
            sum(fwd_lengths + bwd_lengths) / duration, # Flow Bytes/s
            total_packets / duration,                  # Flow Packets/s
            duration / max(total_fwd, 1),              # Flow IAT Mean
            0,                                         # Flow IAT Std
            duration,                                  # Flow IAT Max
            0,                                         # Flow IAT Min
            sum(flow['fwd_iat']) if flow['fwd_iat'] else 0,  # Fwd IAT Total
            np.mean(flow['fwd_iat']) if flow['fwd_iat'] else 0,  # Fwd IAT Mean
            np.std(flow['fwd_iat']) if len(flow['fwd_iat']) > 1 else 0,  # Fwd IAT Std
            max(flow['fwd_iat']) if flow['fwd_iat'] else 0,  # Fwd IAT Max
            min(flow['fwd_iat']) if flow['fwd_iat'] else 0,  # Fwd IAT Min
            sum(flow['bwd_iat']) if flow['bwd_iat'] else 0,  # Bwd IAT Total
            np.mean(flow['bwd_iat']) if flow['bwd_iat'] else 0,  # Bwd IAT Mean
            np.std(flow['bwd_iat']) if len(flow['bwd_iat']) > 1 else 0,  # Bwd IAT Std
            max(flow['bwd_iat']) if flow['bwd_iat'] else 0,  # Bwd IAT Max
            min(flow['bwd_iat']) if flow['bwd_iat'] else 0,  # Bwd IAT Min
            20 * total_fwd,                            # Fwd Header Length
            20 * total_bwd,                            # Bwd Header Length
            total_fwd / duration,                      # Fwd Packets/s
            total_bwd / duration,                      # Bwd Packets/s
            min(fwd_lengths + bwd_lengths),            # Min Packet Length
            max(fwd_lengths + bwd_lengths),            # Max Packet Length
            np.mean(fwd_lengths + bwd_lengths),        # Packet Length Mean
            np.std(fwd_lengths + bwd_lengths) if total_packets > 1 else 0,  # Packet Length Std
            np.var(fwd_lengths + bwd_lengths) if total_packets > 1 else 0,  # Packet Length Variance
            flow['flags']['FIN'],                      # FIN Flag Count
            flow['flags']['PSH'],                      # PSH Flag Count
            flow['flags']['ACK'],                      # ACK Flag Count
            np.mean(fwd_lengths + bwd_lengths),        # Average Packet Size
            sum(fwd_lengths),                          # Subflow Fwd Bytes
            0,                                         # Init_Win_bytes_forward
            0,                                         # Init_Win_bytes_backward
            total_fwd,                                 # act_data_pkt_fwd
            0,                                         # min_seg_size_forward
            0,                                         # Active Mean
            0,                                         # Active Max
            0,                                         # Active Min
            0,                                         # Idle Mean
            0,                                         # Idle Max
            0,                                         # Idle Min
        ]
        
        return np.array(features, dtype=np.float32)
    
    def get_expired_flows(self):
        """Get flows that have timed out (ready for classification)."""
        now = time.time()
        expired = []
        
        with self.lock:
            expired_keys = []
            for key, flow in self.flows.items():
                if now - flow['last_time'] > self.flow_timeout:
                    expired.append((key, flow))
                    expired_keys.append(key)
            
            for key in expired_keys:
                del self.flows[key]
        
        return expired


class LiveNetworkMonitor:
    """Monitors live network traffic and classifies flows."""
    
    def __init__(self, engine, callback=None, interface=None):
        self.engine = engine
        self.callback = callback
        self.interface = interface
        self.tracker = FlowTracker(flow_timeout=10)  # 10 second flows
        self.running = False
        self._sniffer_thread = None
        self._processor_thread = None
    
    def _packet_handler(self, pkt):
        """Called for each captured packet."""
        self.tracker.process_packet(pkt)
    
    def _process_expired_flows(self):
        """Periodically classify expired flows."""
        while self.running:
            time.sleep(5)  # Check every 5 seconds
            expired = self.tracker.get_expired_flows()
            
            for key, flow in expired:
                if flow['fwd_packets'] + flow['bwd_packets'] < 2:
                    continue  # Skip tiny flows
                
                try:
                    features = self.tracker.extract_features(flow)
                    label, confidence, shap_values = self.engine.predict_network(features)
                    
                    if label is None:
                        continue
                    
                    # Determine severity
                    is_attack = label not in ['Normal Traffic', 'BENIGN', 'normal']
                    severity = "Critical" if is_attack and confidence > 0.95 else "High" if is_attack else "Normal"
                    
                    event = {
                        'source': 'Live Network',
                        'attack_type': label,
                        'confidence': round(confidence, 3),
                        'severity': severity,
                        'host': flow['src_ip'],
                        'explanation': {
                            'shap': shap_values if shap_values else {},
                            'lime': f"Live flow from {flow['src_ip']} to {flow['dst_ip']} classified as '{label}'"
                        },
                        'flow_info': {
                            'src': flow['src_ip'],
                            'dst': flow['dst_ip'],
                            'packets': flow['fwd_packets'] + flow['bwd_packets'],
                            'bytes': sum(flow['fwd_lengths'] + flow['bwd_lengths']),
                        }
                    }
                    
                    if self.callback:
                        self.callback(event)
                        
                except Exception as e:
                    print(f"[LIVE NET] Classification error: {e}")
    
    def start(self):
        """Start live network monitoring."""
        if self.running:
            return
        
        self.running = True
        
        # Start flow processor
        self._processor_thread = threading.Thread(target=self._process_expired_flows, daemon=True)
        self._processor_thread.start()
        
        # Start packet sniffer
        def _sniff():
            try:
                sniff(
                    prn=self._packet_handler,
                    iface=self.interface,
                    store=False,
                    stop_filter=lambda _: not self.running
                )
            except Exception as e:
                print(f"[LIVE NET] Sniffer error: {e}")
                self.running = False
        
        self._sniffer_thread = threading.Thread(target=_sniff, daemon=True)
        self._sniffer_thread.start()
        print("[LIVE NET] Network monitoring started")
    
    def stop(self):
        """Stop live monitoring."""
        self.running = False
        print("[LIVE NET] Network monitoring stopped")
