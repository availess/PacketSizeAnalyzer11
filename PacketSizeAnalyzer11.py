import threading
import time
import curses
from collections import defaultdict, deque
from scapy.all import sniff, IP
from datetime import datetime, timezone, timedelta
import json

class PacketSizeAnalyzer:
    def __init__(self, interface='mirror-eth0', size_threshold=500):
        self.interface = interface
        self.size_threshold = size_threshold  # Threshold in bytes to distinguish large vs small packets
        self.packet_sizes = defaultdict(int)  # Tracks count of packets by size category
        self.total_packets = 0
        self.size_distribution = defaultdict(int)  # Tracks packet count by size range
        self.running = True
        self.lock = threading.Lock()
        self.last_packets = deque(maxlen=5)  # Store last 5 packets (size, timestamp)
        self.last_chart_time = time.time()  # Track last chart generation time

        # Define size ranges for distribution (in bytes)
        self.size_ranges = [
            (0, 100), (101, 500), (501, 1000), (1001, 1500), (1501, float('inf'))
        ]

        # Start packet capture thread and UI
        threading.Thread(target=self.capture_packets, daemon=True).start()
        self.start_ui()

    def categorize_packet(self, packet):
        """Categorize packet based on its size"""
        if IP in packet:
            packet_size = len(packet)
            # Use UTC+8 for timestamp
            utc8 = timezone(timedelta(hours=8))
            timestamp = datetime.now(utc8).strftime("%H:%M:%S")
            self.total_packets += 1
            is_large = packet_size > self.size_threshold
            category = "Large" if is_large else "Small"

            # Update size distribution
            for range_min, range_max in self.size_ranges:
                if range_min <= packet_size <= range_max:
                    range_key = f"{range_min}-{range_max if range_max != float('inf') else '∞'}"
                    return category, range_key, (packet_size, timestamp)
        return None, None, None

    def capture_packets(self):
        """Capture packets and analyze their sizes"""
        def process_packet(packet):
            category, range_key, packet_info = self.categorize_packet(packet)
            if category and range_key and packet_info:
                with self.lock:
                    self.packet_sizes[category] += 1
                    self.size_distribution[range_key] += 1
                    self.last_packets.append(packet_info)
        while self.running:
            sniff(iface=self.interface, prn=process_packet, store=False, filter="ip", count=100)

    def generate_chart(self):
        """Generate Chart.js configuration for packet size distribution"""
        with self.lock:
            sorted_ranges = sorted(self.size_distribution.keys(),
                                 key=lambda x: int(x.split('-')[0]))
            labels = [size_range for size_range in sorted_ranges]
            data = [self.size_distribution[size_range] for size_range in sorted_ranges]

        chart_config = {
            "type": "bar",
            "data": {
                "labels": labels,
                "datasets": [{
                    "label": "Packet Size Distribution",
                    "data": data,
                    "backgroundColor": [
                        "rgba(75, 192, 192, 0.6)",  # Cyan
                        "rgba(255, 99, 132, 0.6)",  # Red
                        "rgba(255, 159, 64, 0.6)",  # Orange
                        "rgba(54, 162, 235, 0.6)",  # Blue
                        "rgba(153, 102, 255, 0.6)"  # Purple
                    ],
                    "borderColor": [
                        "rgba(75, 192, 192, 1)",
                        "rgba(255, 99, 132, 1)",
                        "rgba(255, 159, 64, 1)",
                        "rgba(54, 162, 235, 1)",
                        "rgba(153, 102, 255, 1)"
                    ],
                    "borderWidth": 1
                }]
            },
            "options": {
                "scales": {
                    "x": {
                        "title": {
                            "display": True,
                            "text": "Packet Size Range (bytes)"
                        }
                    },
                    "y": {
                        "title": {
                            "display": True,
                            "text": "Packet Count"
                        },
                        "beginAtZero": True
                    }
                },
                "plugins": {
                    "title": {
                        "display": True,
                        "text": "Packet Size Distribution Histogram"
                    },
                    "legend": {
                        "display": False
                    }
                }
            }
        }
        return chart_config

    def start_ui(self):
        """Start the interactive UI"""
        curses.wrapper(self._update_ui)

    def _update_ui(self, stdscr):
        """Update the real-time UI"""
        stdscr.nodelay(True)  # Non-blocking input
        while self.running:
            stdscr.clear()
            # Display title and current time in UTC+8
            utc8 = timezone(timedelta(hours=8))
            current_time = datetime.now(utc8).strftime("%Y-%m-%d %H:%M:%S %Z")
            stdscr.addstr(0, 0, f"Packet Size Analysis - Current Time: {current_time}")
            stdscr.addstr(1, 0, f"Size Threshold: {self.size_threshold} bytes")
            stdscr.addstr(2, 0, "-" * 50)

            # Display large vs small packet proportions
            stdscr.addstr(3, 0, "Category                  | Count  | Percentage")
            stdscr.addstr(4, 0, "-" * 50)
            with self.lock:
                total = self.total_packets if self.total_packets > 0 else 1  # Avoid division by zero
                total_sl = self.packet_sizes["Small"] + self.packet_sizes["Large"]
                total_sl = total_sl if total_sl > 0 else 1
                for i, category in enumerate(["Small", "Large"], start=5):
                    count = self.packet_sizes[category]
                    percentage = (count / total_sl) * 100
                    display_category = f"{category} ({'<' if category == 'Small' else '>'}{self.size_threshold} bytes)"
                    stdscr.addstr(i, 0, f"{display_category:<24} | {count:<6} | {percentage:.2f}%")

                # Display size distribution, sorted by size range
                stdscr.addstr(8, 0, "Size Distribution (bytes) | Count  | Percentage")
                stdscr.addstr(9, 0, "-" * 50)
                sorted_ranges = sorted(self.size_distribution.keys(),
                                      key=lambda x: int(x.split('-')[0]))
                for i, size_range in enumerate(sorted_ranges, start=10):
                    count = self.size_distribution[size_range]
                    percentage = (count / total) * 100
                    stdscr.addstr(i, 0, f"{size_range:<24} | {count:<6} | {percentage:.2f}%")

                # Display last 5 packets
                stdscr.addstr(16, 0, "Last 5 Packets (Size, Time)")
                stdscr.addstr(17, 0, "-" * 50)
                for i, (size, timestamp) in enumerate(self.last_packets, start=18):
                    stdscr.addstr(i, 0, f"Size: {size} bytes, Time: {timestamp}")

                # Generate and log chart configuration every 10 seconds
                current_time = time.time()
                if current_time - self.last_chart_time >= 10:
                    chart_config = self.generate_chart()
                    print(json.dumps(chart_config, indent=2))  # Print to console
                    self.last_chart_time = current_time

            # Display exit and threshold adjustment prompt
            stdscr.addstr(24, 0, "Press 'q' to exit, 'a' to increase threshold, 'b' to decrease threshold")
            stdscr.refresh()
            time.sleep(1)  # Update every second

            # Check for user input
            try:
                key = stdscr.getkey()
                if key == 'q':
                    self.running = False
                elif key == 'a':
                    with self.lock:
                        self.size_threshold += 100  # Increase threshold by 100 bytes
                        # Reset category counts
                        self.packet_sizes.clear()
                        self.packet_sizes["Small"] = 0
                        self.packet_sizes["Large"] = 0
                elif key == 'b':
                    with self.lock:
                        self.size_threshold = max(100, self.size_threshold - 100)  # Decrease threshold, minimum 100 bytes
                        # Reset category counts
                        self.packet_sizes.clear()
                        self.packet_sizes["Small"] = 0
                        self.packet_sizes["Large"] = 0
            except curses.error:
                pass

if __name__ == "__main__":
    analyzer = PacketSizeAnalyzer()