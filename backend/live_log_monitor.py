"""
Live System Log Monitor
Reads live system logs (syslog, auth.log, kern.log) in real-time
and classifies them using the trained CNN-LSTM model.
"""

import time
import threading
import os
import subprocess


class LiveLogMonitor:
    """Monitors live system logs and detects anomalies."""
    
    def __init__(self, engine, callback=None):
        self.engine = engine
        self.callback = callback
        self.running = False
        self._thread = None
        self._log_files = self._find_log_files()
    
    def _find_log_files(self):
        """Find available system log files."""
        log_paths = [
            '/var/log/auth.log',
            '/var/log/syslog',
            '/var/log/kern.log',
            '/var/log/dmesg',
        ]
        
        available = []
        for path in log_paths:
            if os.path.exists(path) and os.access(path, os.R_OK):
                available.append(path)
        
        # Also try journalctl if available
        try:
            subprocess.run(['journalctl', '--version'], capture_output=True, check=True)
            available.append('journalctl')
        except:
            pass
        
        if not available:
            # Create a simulated log source for testing
            print("[LOG MONITOR] No system logs accessible, using simulation")
        
        return available
    
    def _tail_log(self, filepath):
        """Tail a log file and yield new lines."""
        try:
            # Open file and seek to end
            with open(filepath, 'r') as f:
                f.seek(0, 2)  # Go to end
                while self.running:
                    line = f.readline()
                    if line:
                        yield line.strip()
                    else:
                        time.sleep(0.5)
        except Exception as e:
            print(f"[LOG MONITOR] Error reading {filepath}: {e}")
    
    def _tail_journal(self):
        """Tail journalctl for new log entries."""
        try:
            proc = subprocess.Popen(
                ['journalctl', '-f', '-n', '0', '--no-pager', '-o', 'short-precise'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            while self.running:
                line = proc.stdout.readline()
                if line:
                    yield line.strip()
                else:
                    time.sleep(0.5)
            proc.terminate()
        except Exception as e:
            print(f"[LOG MONITOR] journalctl error: {e}")
    
    def _classify_log(self, log_line):
        """Classify a single log line."""
        if not log_line or len(log_line) < 10:
            return None
        
        # Skip empty or too-short lines
        if log_line.strip() == '':
            return None
        
        try:
            label, confidence, explanation = self.engine.predict_log(log_line)
            
            if label is None:
                return None
            
            # Determine severity
            is_anomaly = label == "Anomaly"
            severity = "High" if is_anomaly else "Normal"
            
            # Try to extract source from log line
            host = "localhost"
            if 'ssh' in log_line.lower():
                host = self._extract_ssh_source(log_line)
            elif 'failed' in log_line.lower() or 'error' in log_line.lower():
                host = self._extract_ip(log_line)
            
            event = {
                'source': 'Live System Log',
                'attack_type': f"Log Anomaly" if is_anomaly else "Normal Log",
                'confidence': round(confidence, 3),
                'severity': severity,
                'host': host,
                'explanation': {
                    'lime': explanation
                },
                'log_content': log_line[:300],
            }
            
            return event
            
        except Exception as e:
            print(f"[LOG MONITOR] Classification error: {e}")
            return None
    
    def _extract_ssh_source(self, line):
        """Extract SSH connection source IP."""
        import re
        ip_pattern = r'from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
        match = re.search(ip_pattern, line)
        return match.group(1) if match else "unknown"
    
    def _extract_ip(self, line):
        """Extract any IP from log line."""
        import re
        ip_pattern = r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
        match = re.search(ip_pattern, line)
        return match.group(1) if match else "localhost"
    
    def _monitor_loop(self):
        """Main monitoring loop."""
        print(f"[LOG MONITOR] Monitoring {len(self._log_files)} log sources")
        
        threads = []
        
        # Monitor each log file in a separate thread
        for source in self._log_files:
            if source == 'journalctl':
                def _monitor_journal():
                    for line in self._tail_journal():
                        if not self.running:
                            break
                        event = self._classify_log(line)
                        if event and self.callback:
                            self.callback(event)
                t = threading.Thread(target=_monitor_journal, daemon=True)
            else:
                def _monitor_file(filepath=source):
                    for line in self._tail_log(filepath):
                        if not self.running:
                            break
                        event = self._classify_log(line)
                        if event and self.callback:
                            self.callback(event)
                t = threading.Thread(target=_monitor_file, daemon=True)
            
            threads.append(t)
            t.start()
        
        # Keep main loop alive
        while self.running:
            time.sleep(1)
    
    def start(self):
        """Start live log monitoring."""
        if self.running:
            return
        
        self.running = True
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._thread.start()
        print("[LOG MONITOR] Log monitoring started")
    
    def stop(self):
        """Stop monitoring."""
        self.running = False
        print("[LOG MONITOR] Log monitoring stopped")
