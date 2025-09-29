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
        self.packet_size_list = []  # 存储包大小用于柱状图
        self.total_bytes = 0  # 跟踪总字节数用于流量速率
        self.start_time = time.time()  # 记录开始时间

        self.size_ranges = [
            (0, 100), (101, 500), (501, 1000), (1001, 1500), (1501, float('inf'))
        ]

        # 初始化计数器
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

        # 持续抓包，分批处理以避免阻塞
        while self.running:
            try:
                sniff(iface=self.interface, prn=process_packet, store=False, filter="ip", count=100)
            except Exception:
                # 如果接口不存在或权限不足，短暂休眠后重试
                time.sleep(1)

    def get_traffic_rate(self):
        with self.lock:
            elapsed_time = time.time() - self.start_time
            elapsed_time = max(elapsed_time, 1)  # 避免除零
            rate_kbps = (self.total_bytes / 1024) / elapsed_time  # KB/s
            return rate_kbps

    def get_ascii_histogram(self, max_bins=14, bin_width=100):
        """生成包大小分布的 ASCII 柱状图并返回图像行和对齐的横轴标签。

        改进点：
        - 使用固定的 bin_width（默认 100 字节），确保每个箱子的含义明确。
        - 以百分比作为数据（0-100），让 y 轴更直观。
        - 将箱数限制为 max_bins，超出部分合并到最后一箱。
        - 通过简单的间隔对齐横轴数字，避免之前的错位和不可读问题。
        """
        with self.lock:
            if not self.packet_size_list:
                return ["无数据可显示"], ""

            max_size = max(self.packet_size_list, default=1500)
            # 确保至少有几个箱子，以便图形更美观
            num_bins = max(1, int(np.ceil((max_size + 1) / bin_width)))

            # 当箱子过多时合并尾部箱子到最后一个箱
            if num_bins > max_bins:
                num_bins = max_bins
                # 重新计算 bin_width 以覆盖到最大大小
                bin_edges = np.linspace(0, max_size + bin_width, num_bins + 1)
            else:
                bin_edges = np.arange(0, (num_bins + 1) * bin_width, bin_width)

            hist, edges = np.histogram(self.packet_size_list, bins=bin_edges)
            total = max(hist.sum(), 1)
            hist_pct = hist / total * 100.0

            # 将 numpy 数组转为 Python 列表以兼容 asciichartpy
            data = hist_pct.tolist()

            # 如果箱子数少于 max_bins，在尾部补零以保持图形宽度稳定（可选）
            # data += [0] * (min(max_bins, len(data)) - len(data))

            # 配置 asciichartpy，height 固定，width 根据箱子自适应（每箱大约占 4 列）
            cfg = {
                'height': 10,
                'format': '{:6.2f}'
            }

            # asciichartpy 在传入较多数据时会自动横向缩放，这里直接绘制 data
            try:
                chart = asciichartpy.plot(data, cfg)
            except Exception:
                # 万一 asciichartpy 绘图失败，退回到简单的文本条表示
                chart_lines = []
                for idx, v in enumerate(data):
                    chart_lines.append(f"Bin {idx:02d}: {v:.2f}%")
                return chart_lines, ""

            # 生成横轴标签：每个箱子的中值（以百字节为单位）居中对齐
            labels = []
            for i in range(len(edges) - 1):
                left = int(edges[i])
                right = int(edges[i + 1]) - 1
                center = (left + right) // 2
                # 用百字节为单位显示，避免数字过大
                labels.append(str(center // 100))

            # 尝试生成一个与 chart 列数近似对齐的标签行
            # 获取每行最大长度来估算标签间距
            chart_lines = chart.split('\n')
            if chart_lines:
                chart_width = max(len(l) for l in chart_lines)
            else:
                chart_width = len(data) * 4

            # 每个箱子分配的水平空间（向下取整至少 1）
            slot_width = max(1, chart_width // max(1, len(data)))

            axis_parts = []
            for lab in labels:
                # 居中放置标签在 slot_width 宽度内
                axis_parts.append(lab.center(slot_width))
            axis_line = ''.join(axis_parts)
            axis_line = axis_line.rstrip()

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
                    stdscr.addstr(6 + len(chart_lines) + 1, 0, "(横轴：包大小，单位：百字节)")

                stdscr.addstr(curses.LINES - 2, 0, "按 'q' 退出, 'a' 增加阈值, 'b' 减少阈值, 'h' 切换柱状图")
                stdscr.refresh()
            except curses.error:
                # 屏幕太小或写入越界时简单忽略，下一轮重绘
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
