import threading
import time
import curses
from collections import defaultdict, deque
from scapy.all import sniff, IP
from datetime import datetime, timezone, timedelta
import json
import os
import requests


class PacketSizeAnalyzer:
    def __init__(self, interface='mirror-eth0', size_threshold=500, save_interval=3600):
        self.interface = interface
        self.size_threshold = size_threshold
        self.packet_sizes = defaultdict(int)        # Small / Large
        self.total_packets = 0
        self.size_distribution = defaultdict(int)   # 各区间计数
        self.running = True
        self.lock = threading.Lock()
        self.last_packets = deque(maxlen=5)
        self.save_interval = save_interval
        self.save_filename = "packet_data.json"

        # ntfy topic（建议换成你自己的随机字符串）
        self.ntfy_topic = "my_packet_data_xxx"

        self.size_ranges = [
            (0, 100), (101, 500), (501, 1000), (1001, 1500), (1501, float('inf'))
        ]

        # 启动通知
        self.send_to_ntfy({"message": "Packet Analyzer Started", "time": self.now_str()})

        # 启动后台线程
        threading.Thread(target=self.capture_packets, daemon=True).start()
        threading.Thread(target=self.periodic_save, daemon=True).start()

        # 启动 UI（会阻塞直到退出）
        self.start_ui()

    def now_str(self):
        utc8 = timezone(timedelta(hours=8))
        return datetime.now(utc8).strftime("%Y-%m-%d %H:%M:%S")

    def send_to_ntfy(self, data):
        try:
            payload = data
            if "message" in data:
                payload["title"] = "Packet Analyzer"
                payload["tags"] = "chart_with_upwards_trend"
            requests.post(
                f"https://ntfy.sh/{self.ntfy_topic}",
                json=payload,
                timeout=5
            )
        except Exception as e:
            print("[-] ntfy send failed:", e)

    def categorize_packet(self, packet):
        if not IP in packet:
            return None, None, None

        packet_size = len(packet)
        timestamp = self.now_str().split()[1]  # 只取时间部分 HH:MM:SS

        self.total_packets += 1
        is_large = packet_size > self.size_threshold
        category = "Large" if is_large else "Small"

        # 确定所属区间
        range_key = "Unknown"
        for range_min, range_max in self.size_ranges:
            if packet_size <= range_max if range_max != float('inf') else True:
                if range_min <= packet_size:
                    range_key = f"{range_min}-{range_max if range_max != float('inf') else '∞'}"
                    break

        return category, range_key, (packet_size, timestamp)

    def capture_packets(self):
        def process_packet(packet):
            category, range_key, packet_info = self.categorize_packet(packet)
            if category and range_key and packet_info:
                with self.lock:
                    self.packet_sizes[category] += 1
                    self.size_distribution[range_key] += 1
                    self.last_packets.append(packet_info)

        print(f"[+] Start capturing on {self.interface} ...")
        while self.running:
            try:
                # 使用 count=0 表示无限抓包，timeout 防止完全阻塞
                sniff(
                    iface=self.interface,
                    prn=process_packet,
                    store=False,
                    filter="ip",
                    timeout=1.0,      # 关键：避免完全阻塞主线程
                    count=0
                )
            except Exception as e:
                if self.running:
                    print("Sniff error:", e)
                time.sleep(1)

    def start_ui(self):
        curses.wrapper(self._update_ui)

    def _update_ui(self, stdscr):
        curses.curs_set(0)  # 隐藏光标
        stdscr.nodelay(True)

        while self.running:
            stdscr.clear()
            current_time = self.now_str()

            lines = [
                f"Packet Size Real-time Analyzer - {current_time}",
                f"Interface: {self.interface} | Threshold: {self.size_threshold} bytes",
                "-" * 70,
                "",
                "Category (<=> threshold)      | Count      | Percent",
                "-" * 70,
            ]

            with self.lock:
                total_sl = sum(self.packet_sizes.values())
                total_all = self.total_packets or 1

                for cat in ["Small", "Large"]:
                    count = self.packet_sizes[cat]
                    percent = (count / total_sl * 100) if total_sl > 0 else 0
                    sign = "<=" if cat == "Small" else ">"
                    line = f"{cat} ({sign}{self.size_threshold} bytes)         | {count:<10} | {percent:6.2f}%"
                    lines.append(line)

                lines.append("")
                lines.append("Size Range (bytes)           | Count      | Percent")
                lines.append("-" * 70)

                # 排序输出区间
                for r in sorted(self.size_distribution.keys(),
                                key=lambda x: int(x.split('-')[0])):
                    count = self.size_distribution[r]
                    percent = count / total_all * 100
                    lines.append(f"{r:<28} | {count:<10} | {percent:6.2f}%")

                lines.append("")
                lines.append("Last 5 Packets (Size @ Time)")
                lines.append("-" * 70)
                for size, ts in self.last_packets:
                    lines.append(f"  {size:>5} bytes @ {ts}")

            # 显示所有行
            for i, line in enumerate(lines[:curses.LINES]):
                try:
                    stdscr.addstr(i, 0, line[:curses.COLS-1])
                except:
                    pass

            stdscr.addstr(curses.LINES - 1, 0,
                          "Press 'q' to quit | 'a'/+ increase threshold | 'b'/- decrease threshold")

            stdscr.refresh()
            time.sleep(0.5)

            # 键盘处理
            try:
                key = stdscr.getch()
                if key == ord('q'):
                    self.running = False
                elif key in (ord('a'), ord('+')):
                    with self.lock:
                        self.size_threshold += 100
                        self.send_to_ntfy({"message": f"Threshold increased to {self.size_threshold} bytes"})
                elif key in (ord('b'), ord('-')):
                    with self.lock:
                        self.size_threshold = max(100, self.size_threshold - 100)
                        self.send_to_ntfy({"message": f"Threshold decreased to {self.size_threshold} bytes"})
            except:
                pass

        # 退出前保存一次
        self.save_data()
        self.send_to_ntfy({"message": "Analyzer stopped", "time": self.now_str()})

    def save_data(self):
        with self.lock:
            data = {
                "timestamp": self.now_str(),
                "total_packets": self.total_packets,
                "threshold": self.size_threshold,
                "packet_sizes": dict(self.packet_sizes),
                "size_distribution": dict(self.size_distribution),
                "last_packets": [(size, ts) for size, ts in self.last_packets]
            }

        try:
            with open(self.save_filename, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            print(f"\n[+] Data saved to {self.save_filename}")
            self.send_to_ntfy({**data, "message": "Data auto-saved"})
        except Exception as e:
            print("Save failed:", e)

    def periodic_save(self):
        while self.running:
            time.sleep(self.save_interval)
            if self.running:
                self.save_data()


if __name__ == "__main__":
    # 需要 root 权限运行
    try:
        analyzer = PacketSizeAnalyzer(
            interface="mirror-eth0",    # 修改为你的镜像端口
            size_threshold=800,
            save_interval=1800          # 30分钟保存一次
        )
    except KeyboardInterrupt:
        print("\nStopped by user")
    except Exception as e:
        print("Error:", e)