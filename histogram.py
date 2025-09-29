import threading
import time
import curses
from collections import defaultdict, deque
from scapy.all import sniff, IP
from datetime import datetime, timezone, timedelta
import asciichartpy
import numpy as np


class PacketSizeAnalyzer:
    def __init__(self, interface='mirror-eth0', size_threshold=500):
        self.interface = interface
        self.size_threshold = size_threshold
        self.packet_sizes = defaultdict(int)
        self.total_packets = 0
        self.size_distribution = defaultdict(int)
        self.running = True
        self.lock = threading.Lock()
        self.last_packets = deque(maxlen=5)
        self.packet_size_list = []
        self.total_bytes = 0
        self.start_time = time.time()

        self.size_ranges = [
            (0, 100), (101, 500), (501, 1000), (1001, 1500), (1501, float('inf'))
        ]

        self.packet_sizes["Small"] = 0
        self.packet_sizes["Large"] = 0

        threading.Thread(target=self.capture_packets, daemon=True).start()
        self.start_ui()

    def categorize_packet(self, packet):
        if IP in packet:
            packet_size = len(packet)
            utc8 = timezone(timedelta(hours=8))
            timestamp = datetime.now(utc8).strftime("%H:%M:%S")
            with self.lock:
                self.total_packets += 1
                self.total_bytes += packet_size
            is_large = packet_size > self.size_threshold
            category = "Large" if is_large else "Small"

            for range_min, range_max in self.size_ranges:
                if range_min <= packet_size <= range_max:
                    range_key = f"{range_min}-{int(range_max) if range_max != float('inf') else '∞'}"
                    return category, range_key, (packet_size, timestamp)
        return None, None, None

    def capture_packets(self):
        def process_packet(packet):
            category, range_key, packet_info = self.categorize_packet(packet)
            if category and range_key and packet_info:
                with self.lock:
                    self.packet_sizes[category] += 1
                    self.size_distribution[range_key] += 1
                    self.last_packets.append(packet_info)
                    self.packet_size_list.append(packet_info[0])

        while self.running:
            try:
                sniff(iface=self.interface, prn=process_packet, store=False, filter="ip", count=100)
            except Exception:
                time.sleep(1)

    def get_traffic_rate(self):
        with self.lock:
            elapsed_time = time.time() - self.start_time
            elapsed_time = max(elapsed_time, 1)
            rate_kbps = (self.total_bytes / 1024) / elapsed_time
            return rate_kbps

    def get_ascii_histogram(self, bin_width=50, label_step=200, chart_height=10, max_bins=40):
        with self.lock:
            if not self.packet_size_list:
                return ["无数据可显示"], ""

            max_size = max(self.packet_size_list, default=1500)
            num_bins = max(1, int(np.ceil((max_size + 1) / bin_width)))
            if num_bins > max_bins:
                num_bins = max_bins
                bin_edges = np.linspace(0, max_size + bin_width, num_bins + 1)
            else:
                bin_edges = np.arange(0, (num_bins + 1) * bin_width, bin_width)

            hist, edges = np.histogram(self.packet_size_list, bins=bin_edges)
            total = max(hist.sum(), 1)
            hist_pct = hist / total * 100.0
            data = hist_pct.tolist()

            cfg = {
                'height': chart_height,
                'format': '{:6.2f}'
            }

            try:
                chart = asciichartpy.plot(data, cfg)
            except Exception:
                chart_lines = [f"Bin {idx:02d}: {v:.2f}%" for idx, v in enumerate(data)]
                return chart_lines, ""

            chart_lines = chart.split('\n')
            chart_width = max(len(l) for l in chart_lines) if chart_lines else len(data) * 4
            slot_width = max(1, chart_width // max(1, len(data)))

            labels = []
            for i in range(len(edges) - 1):
                left = int(edges[i])
                right = int(edges[i + 1]) - 1
                center = (left + right) // 2
                if center % label_step == 0:
                    labels.append(str(center))
                else:
                    labels.append("")

            axis_parts = [lab.center(slot_width) for lab in labels]
            axis_line = ''.join(axis_parts).rstrip()

            return chart_lines, axis_line

    def start_ui(self):
        curses.wrapper(self._update_ui)

    def _update_ui(self, stdscr):
        stdscr.nodelay(True)
        show_histogram = False
        while self.running:
            stdscr.erase()
            utc8 = timezone(timedelta(hours=8))
            current_time = datetime.now(utc8).strftime("%Y-%m-%d %H:%M:%S %Z")
            try:
                stdscr.addstr(0, 0, f"数据包大小分析 - 当前时间: {current_time}")
                stdscr.addstr(1, 0, f"大小阈值: {self.size_threshold} 字节")
                stdscr.addstr(2, 0, f"流量速率: {self.get_traffic_rate():.2f} KB/s")
                stdscr.addstr(3, 0, "-" * 50)

                if not show_histogram:
                    stdscr.addstr(4, 0, "分类                     | 数量   | 百分比")
                    stdscr.addstr(5, 0, "-" * 50)
                    with self.lock:
                        total_sl = max(self.packet_sizes.get("Small", 0) + self.packet_sizes.get("Large", 0), 1)
                        for i, category in enumerate(["Small", "Large"], start=6):
                            count = self.packet_sizes.get(category, 0)
                            percentage = (count / total_sl) * 100
                            display_category = f"{category} ({'<' if category == 'Small' else '>'}{self.size_threshold} 字节)"
                            stdscr.addstr(i, 0, f"{display_category:<24} | {count:<6} | {percentage:6.2f}%")

                        stdscr.addstr(9, 0, "大小分布 (字节)         | 数量   | 百分比")
                        stdscr.addstr(10, 0, "-" * 50)
                        sorted_ranges = sorted(self.size_distribution.keys(), key=lambda x: int(x.split('-')[0]))
                        for idx, size_range in enumerate(sorted_ranges, start=11):
                            count = self.size_distribution[size_range]
                            percentage = (count / max(self.total_packets, 1)) * 100
                            stdscr.addstr(idx, 0, f"{size_range:<24} | {count:<6} | {percentage:6.2f}%")

                        stdscr.addstr(17, 0, "最后 5 个数据包 (大小, 时间)")
                        stdscr.addstr(18, 0, "-" * 50)
                        for i, (size, timestamp) in enumerate(list(self.last_packets), start=19):
                            stdscr.addstr(i, 0, f"大小: {size} 字节, 时间: {timestamp}")
                else:
                    chart_lines, axis_line = self.get_ascii_histogram()
                    stdscr.addstr(4, 0, "包大小分布 (%)")
                    for i, line in enumerate(chart_lines, start=5):
                        stdscr.addstr(i, 0, line)
                    stdscr.addstr(5 + len(chart_lines) + 1, 0, axis_line)
                    stdscr.addstr(6 + len(chart_lines) + 1, 0, "(横轴：包大小，步长:200字节)")

                stdscr.addstr(curses.LINES - 2, 0, "按 'q' 退出, 'a' 增加阈值, 'b' 减少阈值, 'h' 切换柱状图")
                stdscr.refresh()
            except curses.error:
                pass

            time.sleep(1)

            try:
                key = stdscr.getkey()
                if key == 'q':
                    self.running = False
                elif key == 'a':
                    with self.lock:
                        self.size_threshold += 100
                        self.packet_sizes.clear()
                        self.packet_sizes["Small"] = 0
                        self.packet_sizes["Large"] = 0
                elif key == 'b':
                    with self.lock:
                        self.size_threshold = max(100, self.size_threshold - 100)
                        self.packet_sizes.clear()
                        self.packet_sizes["Small"] = 0
                        self.packet_sizes["Large"] = 0
                elif key == 'h':
                    show_histogram = not show_histogram
            except curses.error:
                pass


if __name__ == "__main__":
    analyzer = PacketSizeAnalyzer()