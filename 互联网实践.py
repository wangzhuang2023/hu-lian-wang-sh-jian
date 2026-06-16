#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
多协议网络通信与状态监测平台
功能：TCP/UDP通信、端口监听、数据报文传输、网络状态检测、DNS解析、路由追踪、带宽测试
作者：NetworkEngineering
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog, Menu
import threading
import socket
import struct
import json
import os
import time
import subprocess
import platform
import logging
import base64
import ipaddress
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# ---------- 全局配置 ----------
CONFIG_FILE = "net_tool_config.json"
LOG_FILE = "net_tool.log"
DEFAULT_ENCODINGS = ["UTF-8", "GBK", "ASCII", "Hex", "Base64"]

# 常见端口 → 服务名映射
COMMON_PORTS = {
    20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 67: "DHCP-Server", 68: "DHCP-Client", 69: "TFTP",
    80: "HTTP", 110: "POP3", 123: "NTP", 135: "RPC", 137: "NetBIOS-NS",
    138: "NetBIOS-DGM", 139: "NetBIOS-SSN", 143: "IMAP", 161: "SNMP",
    162: "SNMP-Trap", 389: "LDAP", 443: "HTTPS", 445: "SMB",
    465: "SMTPS", 514: "Syslog", 587: "SMTP-Submit", 636: "LDAPS",
    873: "Rsync", 993: "IMAPS", 995: "POP3S", 1433: "MSSQL",
    1521: "Oracle", 1723: "PPTP", 1883: "MQTT", 2049: "NFS",
    2375: "Docker", 2376: "Docker-TLS", 3306: "MySQL", 3389: "RDP",
    4000: "DiabloII", 4369: "Erlang-EPMD", 4567: "VNC", 5000: "UPnP",
    5432: "PostgreSQL", 5672: "RabbitMQ", 5900: "VNC", 6379: "Redis",
    6443: "K8s-API", 7000: "Cassandra", 7474: "Neo4j", 8000: "HTTP-Dev",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt", 8888: "HTTP-Alt2", 9000: "PHP-FPM",
    9092: "Kafka", 9200: "Elasticsearch", 9300: "ES-Transport",
    11211: "Memcached", 27017: "MongoDB", 50070: "HDFS",
}

# 日志配置
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE, encoding='utf-8'),
        logging.StreamHandler()
    ]
)


# ========================================================================
# 工具函数
# ========================================================================

def is_ipv4(addr):
    """校验 IPv4 地址"""
    try:
        socket.inet_pton(socket.AF_INET, addr)
        return True
    except (OSError, AttributeError):
        try:
            ipaddress.IPv4Address(addr)
            return True
        except (ipaddress.AddressValueError, ipaddress.NetmaskValueError):
            return False


def is_ipv6(addr):
    """校验 IPv6 地址"""
    try:
        socket.inet_pton(socket.AF_INET6, addr)
        return True
    except (OSError, AttributeError):
        try:
            ipaddress.IPv6Address(addr)
            return True
        except (ipaddress.AddressValueError, ipaddress.NetmaskValueError):
            return False


def is_valid_host(addr):
    """统一验证：IPv4 / IPv6 / 域名均接受"""
    if is_ipv4(addr) or is_ipv6(addr):
        return True
    # 简单域名校验：不含空格，至少有一个点或为 localhost
    return bool(addr) and ' ' not in addr and len(addr) <= 253


def resolve_host(host):
    """
    DNS 解析主机名，返回 (ipv4_list, ipv6_list)
    如果 host 已经是 IP 地址则直接返回
    """
    ipv4_list = []
    ipv6_list = []
    if is_ipv4(host):
        ipv4_list.append(host)
        return ipv4_list, ipv6_list
    if is_ipv6(host):
        ipv6_list.append(host)
        return ipv4_list, ipv6_list
    try:
        results = socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        for family, _, _, _, sockaddr in results:
            ip = sockaddr[0]
            if family == socket.AF_INET and ip not in ipv4_list:
                ipv4_list.append(ip)
            elif family == socket.AF_INET6 and ip not in ipv6_list:
                ipv6_list.append(ip)
    except socket.gaierror:
        pass
    return ipv4_list, ipv6_list


def get_local_ip():
    """获取首选本机 IPv4 地址"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def get_all_local_ips():
    """获取本机所有网卡 IP 地址（含 IPv4/IPv6）"""
    interfaces = []
    try:
        hostname = socket.gethostname()
        # 尝试通过 getaddrinfo 获取本机地址
        for family_name, family in [("IPv4", socket.AF_INET), ("IPv6", socket.AF_INET6)]:
            try:
                addrs = socket.getaddrinfo(hostname, None, family, socket.SOCK_DGRAM)
                for addr_info in addrs:
                    ip = addr_info[4][0]
                    if ip not in [iface["ip"] for iface in interfaces]:
                        interfaces.append({"name": hostname, "ip": ip, "family": family_name})
            except socket.gaierror:
                pass
    except Exception:
        pass
    # 如果没有获取到，至少返回 localhost
    if not interfaces:
        interfaces = [
            {"name": "lo", "ip": "127.0.0.1", "family": "IPv4"},
            {"name": "lo", "ip": "::1", "family": "IPv6"},
        ]
    return interfaces


def format_bytes(n):
    """字节数可读格式化"""
    if n < 0:
        return "0 B"
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if abs(n) < 1024.0:
            return f"{n:.2f} {unit}"
        n /= 1024.0
    return f"{n:.2f} PB"


def human_time(seconds):
    """耗时人类可读"""
    if seconds < 0.001:
        return f"{seconds * 1000000:.1f} μs"
    if seconds < 1:
        return f"{seconds * 1000:.1f} ms"
    if seconds < 60:
        return f"{seconds:.2f} s"
    m, s = divmod(seconds, 60)
    return f"{int(m)}m {s:.1f}s"


def encode_data(text, encoding):
    """按指定编码将文本编码为字节"""
    if encoding == "Hex":
        # 用户输入为十六进制字符串如 "48656c6c6f"
        try:
            text = text.replace(" ", "")
            return bytes.fromhex(text)
        except ValueError:
            raise ValueError("无效的十六进制字符串")
    elif encoding == "Base64":
        try:
            return base64.b64decode(text)
        except Exception:
            raise ValueError("无效的 Base64 字符串")
    else:
        return text.encode(encoding, errors='replace')


def decode_data(data, encoding):
    """按指定编码将字节解码为文本"""
    if encoding == "Hex":
        return data.hex()
    elif encoding == "Base64":
        return base64.b64encode(data).decode()
    else:
        return data.decode(encoding, errors='replace')


# ---------- 配置管理 ----------
def load_config():
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


def save_config(config):
    try:
        with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=2, ensure_ascii=False)
    except Exception as e:
        logging.error(f"保存配置失败: {e}")


# ========================================================================
# 网络核心逻辑
# ========================================================================

class StatsCounter:
    """线程安全的收发字节统计"""
    def __init__(self):
        self.sent_bytes = 0
        self.recv_bytes = 0
        self.sent_packets = 0
        self.recv_packets = 0
        self.lock = threading.Lock()

    def add_sent(self, n):
        with self.lock:
            self.sent_bytes += n
            self.sent_packets += 1

    def add_recv(self, n):
        with self.lock:
            self.recv_bytes += n
            self.recv_packets += 1

    def snapshot(self):
        with self.lock:
            return {
                "sent_bytes": self.sent_bytes,
                "recv_bytes": self.recv_bytes,
                "sent_packets": self.sent_packets,
                "recv_packets": self.recv_packets,
            }

    def reset(self):
        with self.lock:
            self.sent_bytes = 0
            self.recv_bytes = 0
            self.sent_packets = 0
            self.recv_packets = 0


class NetworkCore:
    """网络通信核心逻辑，与UI分离"""

    # ========== TCP 通信 ==========

    @staticmethod
    def tcp_server_listen(host, port, callback_log, callback_clients, stop_event,
                          echo_mode=False, stats=None):
        """TCP 服务端监听，支持多客户端、Echo 模式、IPv6"""
        addrinfo = socket.getaddrinfo(host, port, socket.AF_UNSPEC,
                                      socket.SOCK_STREAM, 0, socket.AI_PASSIVE)
        server = None
        for family, socktype, proto, canonname, sockaddr in addrinfo:
            try:
                server = socket.socket(family, socktype, proto)
                server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                # 双栈兼容：IPv6 套接字同时接受 IPv4
                if family == socket.AF_INET6:
                    try:
                        server.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
                    except (AttributeError, OSError):
                        pass
                server.bind(sockaddr)
                server.listen(10)
                break
            except OSError as e:
                if server:
                    server.close()
                if family == socket.AF_INET6:
                    continue  # 尝试下一个地址族
                callback_log(f"绑定失败: {e}")
                return

        if server is None:
            callback_log("无法绑定到任何地址")
            return

        server.settimeout(1.0)
        af_name = "IPv6" if server.family == socket.AF_INET6 else "IPv4"
        callback_log(f"TCP 服务端启动 [{af_name}] {host}:{port}")
        clients = {}

        while not stop_event.is_set():
            try:
                conn, addr = server.accept()
                callback_log(f"新连接: {addr}")
                clients[conn] = addr
                callback_clients(clients)
                t = threading.Thread(
                    target=NetworkCore.tcp_server_recv,
                    args=(conn, addr, callback_log, clients, stop_event, echo_mode, stats),
                    daemon=True
                )
                t.start()
            except socket.timeout:
                continue
            except OSError as e:
                if not stop_event.is_set():
                    callback_log(f"服务端错误: {e}")
                break

        # 关闭所有客户端连接
        for c in list(clients.keys()):
            try:
                c.close()
            except Exception:
                pass
        clients.clear()
        server.close()
        callback_log("TCP 服务端已停止")

    @staticmethod
    def tcp_server_recv(conn, addr, callback_log, clients, stop_event,
                        echo_mode=False, stats=None):
        """TCP 服务端接收线程"""
        while not stop_event.is_set():
            try:
                data = conn.recv(65536)
                if not data:
                    break
                if stats:
                    stats.add_recv(len(data))
                msg = data.decode(errors='replace')
                callback_log(f"收到来自 {addr}: {msg}")
                if echo_mode:
                    conn.sendall(data)
                    if stats:
                        stats.add_sent(len(data))
                    callback_log(f"已回显至 {addr}")
            except (socket.timeout, BlockingIOError):
                continue
            except OSError:
                break
        conn.close()
        if conn in clients:
            del clients[conn]
        callback_log(f"连接断开: {addr}")

    @staticmethod
    def tcp_client_send(host, port, message, callback_log, encoding="UTF-8",
                        timeout=5, stats=None):
        """TCP 客户端：发送消息并等待响应，支持 IPv6"""
        addrinfo = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
        client = None
        last_error = None

        for family, socktype, proto, canonname, sockaddr in addrinfo:
            try:
                client = socket.socket(family, socktype, proto)
                client.settimeout(timeout)
                client.connect(sockaddr)
                break
            except OSError as e:
                last_error = e
                if client:
                    client.close()
                    client = None
                continue

        if client is None:
            callback_log(f"TCP 客户端错误: {last_error}")
            return

        try:
            raw_data = encode_data(message, encoding)
            client.sendall(raw_data)
            if stats:
                stats.add_sent(len(raw_data))
            callback_log(f"已发送至 {host}:{port}: {message}")
            # 接收响应
            client.settimeout(min(timeout, 3))
            try:
                resp = client.recv(65536)
                if resp and stats:
                    stats.add_recv(len(resp))
                resp_text = decode_data(resp, encoding)
                callback_log(f"收到响应: {resp_text}")
            except socket.timeout:
                callback_log("等待响应超时")
            client.close()
        except Exception as e:
            callback_log(f"TCP 客户端错误: {e}")

    @staticmethod
    def tcp_stress_test(host, port, num_conn, msg_size, callback_progress, callback_log, stop_event):
        """TCP 压力/带宽测试"""
        msg = b"X" * msg_size
        success = 0
        fail = 0
        total_bytes = 0
        start_time = time.time()
        lock = threading.Lock()

        def single_connect(idx):
            nonlocal success, fail, total_bytes
            try:
                addrinfo = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
                sock = socket.socket(addrinfo[0][0], addrinfo[0][1], addrinfo[0][2])
                sock.settimeout(5)
                sock.connect(addrinfo[0][4])
                sock.sendall(msg)
                sock.settimeout(3)
                sock.recv(4096)
                sock.close()
                with lock:
                    success += 1
                    total_bytes += msg_size
            except Exception:
                with lock:
                    fail += 1
            finally:
                callback_progress(success + fail, num_conn)

        with ThreadPoolExecutor(max_workers=min(50, num_conn)) as executor:
            futures = [executor.submit(single_connect, i) for i in range(num_conn)]
            for f in futures:
                if stop_event.is_set():
                    break
                try:
                    f.result(timeout=10)
                except Exception:
                    pass

        elapsed = time.time() - start_time
        throughput = (total_bytes * 8 / elapsed / 1_000_000) if elapsed > 0 else 0  # Mbps
        callback_log(f"压力测试完成: 成功={success}, 失败={fail}, "
                     f"耗时={human_time(elapsed)}, 吞吐量={throughput:.2f} Mbps")

    # ========== UDP 通信 ==========

    @staticmethod
    def udp_send(host, port, message, callback_log, encoding="UTF-8",
                 broadcast=False, stats=None):
        """UDP 发送，支持广播、IPv6"""
        addrinfo = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_DGRAM)
        sock = None
        for family, socktype, proto, canonname, sockaddr in addrinfo:
            try:
                sock = socket.socket(family, socktype, proto)
                if broadcast:
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                break
            except OSError:
                if sock:
                    sock.close()
                    sock = None
                continue

        if sock is None:
            callback_log("UDP: 无法创建套接字")
            return

        try:
            raw_data = encode_data(message, encoding)
            sent = sock.sendto(raw_data, sockaddr)
            if stats:
                stats.add_sent(sent)
            callback_log(f"UDP 发送至 {host}:{port}: {message} ({sent} bytes)")
        except Exception as e:
            callback_log(f"UDP 发送错误: {e}")
        finally:
            sock.close()

    @staticmethod
    def udp_listen(port, callback_log, stop_event, encoding="UTF-8", stats=None):
        """UDP 监听，支持 IPv6 双栈"""
        # 优先创建 IPv6 双栈套接字
        sock = None
        try:
            sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            except (AttributeError, OSError):
                pass
            sock.bind(("::", port))
        except OSError:
            if sock:
                sock.close()
            # 回退到 IPv4
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("0.0.0.0", port))

        sock.settimeout(1)
        callback_log(f"UDP 监听启动 [双栈] 0.0.0.0:{port}")

        while not stop_event.is_set():
            try:
                data, addr = sock.recvfrom(65536)
                if stats:
                    stats.add_recv(len(data))
                msg = decode_data(data, encoding)
                callback_log(f"UDP 来自 {addr}: {msg}")
            except socket.timeout:
                continue
            except OSError as e:
                callback_log(f"UDP 监听错误: {e}")
                break

        sock.close()
        callback_log("UDP 监听已停止")

    @staticmethod
    def udp_broadcast(message, port, callback_log, encoding="UTF-8"):
        """UDP 广播到 255.255.255.255"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        try:
            raw_data = encode_data(message, encoding)
            sent = sock.sendto(raw_data, ("255.255.255.255", port))
            callback_log(f"UDP 广播至 255.255.255.255:{port}: {message} ({sent} bytes)")
        except Exception as e:
            callback_log(f"UDP 广播错误: {e}")
        finally:
            sock.close()

    @staticmethod
    def udp_multicast_send(group, port, message, callback_log, encoding="UTF-8"):
        """UDP 组播发送"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        try:
            raw_data = encode_data(message, encoding)
            sent = sock.sendto(raw_data, (group, port))
            callback_log(f"UDP 组播至 {group}:{port}: {message} ({sent} bytes)")
        except Exception as e:
            callback_log(f"UDP 组播错误: {e}")
        finally:
            sock.close()

    # ========== 端口扫描 ==========

    @staticmethod
    def port_scan(target, start_port, end_port, callback_log, callback_result,
                  callback_progress=None, timeout=1, max_workers=100):
        """多线程端口扫描（Connect 方式）"""
        open_ports = []
        lock = threading.Lock()
        total = end_port - start_port + 1
        completed = 0

        def scan_port(p):
            nonlocal completed
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((target, p))
                if result == 0:
                    with lock:
                        open_ports.append(p)
                sock.close()
            except Exception:
                pass
            finally:
                with lock:
                    completed += 1
                    if callback_progress:
                        callback_progress(completed, total)

        callback_log(f"开始扫描 {target} 端口 {start_port}-{end_port} (超时={timeout}s, 线程={max_workers})")
        with ThreadPoolExecutor(max_workers=min(max_workers, total)) as executor:
            futures = [executor.submit(scan_port, p) for p in range(start_port, end_port + 1)]
            for f in as_completed(futures):
                try:
                    f.result()
                except Exception:
                    pass

        open_ports.sort()

        # 标注已知服务
        labeled = []
        for p in open_ports:
            svc = COMMON_PORTS.get(p, "")
            if svc:
                labeled.append(f"{p}({svc})")
            else:
                labeled.append(str(p))

        callback_result(open_ports)
        callback_log(f"扫描完成，{target} 开放端口: {labeled}")

    # ========== Ping 检测 ==========

    @staticmethod
    def ping_host(host, count=4, callback_log=None):
        """跨平台 Ping 检测，返回原始输出"""
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        timeout_param = '-w' if platform.system().lower() == 'windows' else '-W'
        cmd = ['ping', param, str(count), timeout_param, '5', host]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=count * 5 + 10)
            output = result.stdout if result.stdout else result.stderr
            if callback_log:
                callback_log(output)
            return output
        except subprocess.TimeoutExpired:
            msg = f"Ping {host} 超时"
            if callback_log:
                callback_log(msg)
            return msg
        except Exception as e:
            msg = f"Ping 错误: {e}"
            if callback_log:
                callback_log(msg)
            return msg

    @staticmethod
    def ping_with_stats(host, count=4):
        """Ping 并解析统计信息，返回结构化字典"""
        output = NetworkCore.ping_host(host, count)
        stats = {
            "host": host,
            "sent": count,
            "received": 0,
            "lost": count,
            "loss_pct": 100.0,
            "min_ms": None,
            "max_ms": None,
            "avg_ms": None,
            "raw": output,
        }
        # 尝试解析输出
        import re
        # Windows 格式
        m = re.search(r'已发送\s*=\s*(\d+).*?已接收\s*=\s*(\d+).*?丢失\s*=\s*(\d+)', output)
        if not m:
            m = re.search(r'(\d+)\s*packets?\s*transmitted.*?(\d+)\s*(packets?\s*)?received.*?(\d+).*?loss',
                          output, re.IGNORECASE)
        if m:
            stats["sent"] = int(m.group(1))
            stats["received"] = int(m.group(2))
            stats["lost"] = stats["sent"] - stats["received"]
            stats["loss_pct"] = (stats["lost"] / stats["sent"] * 100) if stats["sent"] > 0 else 100

        # 解析延迟
        if platform.system().lower() == 'windows':
            latency_pat = r'最短\s*=\s*(\d+)ms.*?最长\s*=\s*(\d+)ms.*?平均\s*=\s*(\d+)ms'
        else:
            latency_pat = r'(?:rtt|round-trip).*?=\s*([\d.]+)/([\d.]+)/([\d.]+)'
        m2 = re.search(latency_pat, output, re.IGNORECASE)
        if m2:
            try:
                stats["min_ms"] = float(m2.group(1))
                stats["max_ms"] = float(m2.group(3) if platform.system().lower() == 'windows' else m2.group(3))
                stats["avg_ms"] = float(m2.group(3) if platform.system().lower() != 'windows' else m2.group(3))
                if platform.system().lower() != 'windows':
                    stats["min_ms"] = float(m2.group(1))
                    stats["avg_ms"] = float(m2.group(2))
                    stats["max_ms"] = float(m2.group(3))
            except (ValueError, IndexError):
                pass

        return stats

    # ========== 路由追踪 ==========

    @staticmethod
    def traceroute(target, max_hops, callback_hop, stop_event):
        """
        Traceroute 实现：使用 UDP 发送 + 递增 TTL，监听 ICMP Time Exceeded
        """
        import select
        callback_hop(0, "解析目标地址...", None)
        addrinfo = socket.getaddrinfo(target, None, socket.AF_UNSPEC, socket.SOCK_DGRAM)
        if not addrinfo:
            callback_hop(-1, f"无法解析 {target}", None)
            return
        dest_addr = addrinfo[0][4]
        dest_ip = dest_addr[0]
        family = addrinfo[0][0]
        callback_hop(0, f"Traceroute 至 {target} ({dest_ip}), 最大 {max_hops} 跳", None)

        for ttl in range(1, max_hops + 1):
            if stop_event.is_set():
                callback_hop(ttl, "追踪已取消", None)
                return
            # 发送探测包
            send_sock = socket.socket(family, socket.SOCK_DGRAM)
            send_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            # 设置 TTL
            if family == socket.AF_INET:
                send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
            else:
                send_sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_UNICAST_HOPS, ttl)

            # 接收 ICMP 套接字
            recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            recv_sock.settimeout(3)
            recv_sock.bind(("", 0))

            results = []
            for probe in range(3):
                start_t = time.time()
                try:
                    send_sock.sendto(b"TRACEROUTE", (dest_ip, 33434 + ttl))
                except OSError as e:
                    results.append(None)
                    continue

                try:
                    data, addr = recv_sock.recvfrom(512)
                    elapsed = (time.time() - start_t) * 1000  # ms
                    hop_ip = addr[0]
                    results.append((hop_ip, elapsed))
                    if hop_ip == dest_ip:
                        callback_hop(ttl, f"到达目标 {dest_ip}", results)
                        send_sock.close()
                        recv_sock.close()
                        return
                except socket.timeout:
                    results.append(None)

            send_sock.close()
            recv_sock.close()

            # 汇总此跳
            valid = [r for r in results if r is not None]
            if valid:
                times = [f"{r[1]:.1f} ms" for r in valid]
                ip_set = set(r[0] for r in valid)
                ips = ", ".join(ip_set)
                callback_hop(ttl, f"第 {ttl} 跳: {ips}  {times}", valid)
            else:
                callback_hop(ttl, f"第 {ttl} 跳: * * * (超时)", None)

        callback_hop(max_hops + 1, "已达到最大跳数", None)

    # ========== DNS 查询 ==========

    @staticmethod
    def dns_lookup(hostname, record_type, callback_log):
        """DNS 查询，支持 A / AAAA / MX / NS / PTR 记录"""
        callback_log(f"查询 {hostname} ({record_type} 记录)...")
        try:
            if record_type == "A":
                results = socket.getaddrinfo(hostname, None, socket.AF_INET, socket.SOCK_STREAM)
                ips = list(set(r[4][0] for r in results))
                callback_log(f"A 记录 ({len(ips)}): {ips}")
            elif record_type == "AAAA":
                results = socket.getaddrinfo(hostname, None, socket.AF_INET6, socket.SOCK_STREAM)
                ips = list(set(r[4][0] for r in results))
                callback_log(f"AAAA 记录 ({len(ips)}): {ips}")
            elif record_type == "PTR":
                try:
                    name = socket.gethostbyaddr(hostname)[0]
                    callback_log(f"PTR 记录: {name}")
                except socket.herror:
                    callback_log("未找到 PTR 记录")
            elif record_type in ("MX", "NS"):
                callback_log(f"{record_type} 记录查询需要使用外部 DNS 库 (如 dnspython)，"
                            "当前仅支持 A/AAAA/PTR 的基础解析。")
            else:
                callback_log(f"不支持的记录类型: {record_type}")
        except socket.gaierror as e:
            callback_log(f"DNS 查询失败: {e}")
        except Exception as e:
            callback_log(f"DNS 查询错误: {e}")

    # ========== 网络接口信息 ==========

    @staticmethod
    def get_network_interfaces():
        """获取本机网络接口列表（名称、IP、掩码）"""
        interfaces = get_all_local_ips()
        # 尝试获取更详细的接口名
        try:
            hostname = socket.gethostname()
            for iface in interfaces:
                iface["hostname"] = hostname
        except Exception:
            pass
        return interfaces

    # ========== 单端口检测 ==========

    @staticmethod
    def check_port(host, port, timeout=3):
        """单端口连通性检测，返回 (is_open, message)"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            if result == 0:
                svc = COMMON_PORTS.get(port, "")
                svc_str = f" ({svc})" if svc else ""
                return True, f"端口 {port}{svc_str} 开放"
            else:
                return False, f"端口 {port} 关闭"
        except Exception as e:
            return False, f"检测失败: {e}"

    # ========== 带宽测量 ==========

    @staticmethod
    def measure_bandwidth(host, port, duration, callback_log, callback_result, stop_event):
        """测量 TCP 上行带宽"""
        callback_log(f"开始带宽测试 {host}:{port}, 持续 {duration}s...")

        # 准备数据块
        chunk = b"B" * 65536  # 64KB
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((host, port))
            sock.settimeout(2)

            start_time = time.time()
            total_sent = 0
            last_report = start_time

            while time.time() - start_time < duration:
                if stop_event.is_set():
                    break
                try:
                    sent = sock.send(chunk)
                    total_sent += sent

                    now = time.time()
                    if now - last_report >= 1.0:
                        elapsed = now - start_time
                        mbps = (total_sent * 8 / elapsed / 1_000_000)
                        callback_log(f"当前: {format_bytes(total_sent)} 已传输, {mbps:.2f} Mbps")
                        last_report = now
                except socket.timeout:
                    break
                except (ConnectionResetError, BrokenPipeError):
                    callback_log("连接断开")
                    break

            elapsed = time.time() - start_time
            if elapsed > 0:
                throughput_mbps = (total_sent * 8 / elapsed / 1_000_000)
                throughput_MBps = total_sent / elapsed / 1_000_000
                callback_result({
                    "total_bytes": total_sent,
                    "elapsed": elapsed,
                    "throughput_mbps": throughput_mbps,
                    "throughput_MBps": throughput_MBps,
                })
                callback_log(f"测试完成: {format_bytes(total_sent)} 在 {human_time(elapsed)} 内, "
                            f"{throughput_mbps:.2f} Mbps ({throughput_MBps:.2f} MB/s)")
            else:
                callback_log("未传输数据")
        except Exception as e:
            callback_log(f"带宽测试错误: {e}")
        finally:
            if sock:
                sock.close()

    # ========== HTTP HEAD 检测 ==========

    @staticmethod
    def http_head(host, port, callback_log):
        """发送 HTTP HEAD 请求检测 Web 服务"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((host, port))
            request = (f"HEAD / HTTP/1.1\r\nHost: {host}\r\n"
                       f"User-Agent: NetworkTool/2.0\r\nConnection: close\r\n\r\n")
            sock.sendall(request.encode())
            response = sock.recv(4096).decode(errors='replace')
            sock.close()
            for line in response.splitlines():
                callback_log(f"  {line}")
            callback_log("HTTP HEAD 检测完成")
        except Exception as e:
            callback_log(f"HTTP HEAD 错误: {e}")


# ========================================================================
# 主界面
# ========================================================================

class NetworkToolApp:
    def __init__(self, root):
        self.root = root
        self.root.title("多协议网络通信与状态监测平台 v2.0")
        self.root.geometry("1050x750")
        self.root.minsize(900, 600)

        # 状态变量
        self.tcp_server_stop = threading.Event()
        self.udp_listen_stop = threading.Event()
        self.tcp_clients = {}
        self.config = load_config()
        self.tcp_stats = StatsCounter()
        self.udp_stats = StatsCounter()
        self.global_stop_events = []  # 跟踪所有活动的 stop_event

        self.create_menu()
        self.create_widgets()

    # ========== 菜单栏 ==========
    def create_menu(self):
        menubar = Menu(self.root)
        self.root.config(menu=menubar)

        file_menu = Menu(menubar, tearoff=0)
        file_menu.add_command(label="导出日志", command=self.export_log)
        file_menu.add_command(label="保存配置", command=self.save_current_config)
        file_menu.add_command(label="加载配置", command=self.load_saved_config)
        file_menu.add_separator()
        file_menu.add_command(label="退出", command=self.on_closing)
        menubar.add_cascade(label="文件", menu=file_menu)

        help_menu = Menu(menubar, tearoff=0)
        help_menu.add_command(label="关于", command=self.show_about)
        menubar.add_cascade(label="帮助", menu=help_menu)

    def export_log(self):
        path = filedialog.asksaveasfilename(
            defaultextension=".log",
            filetypes=[("日志文件", "*.log"), ("文本文件", "*.txt"), ("所有文件", "*.*")]
        )
        if path:
            try:
                with open(LOG_FILE, 'r', encoding='utf-8') as src:
                    with open(path, 'w', encoding='utf-8') as dst:
                        dst.write(src.read())
                self.set_status(f"日志已导出至: {path}")
            except Exception as e:
                messagebox.showerror("错误", f"导出失败: {e}")

    def save_current_config(self):
        cfg = {
            "tcp_server_ip": self.tcp_server_ip.get(),
            "tcp_server_port": self.tcp_server_port.get(),
            "tcp_client_ip": self.tcp_client_ip.get(),
            "tcp_client_port": self.tcp_client_port.get(),
            "udp_listen_port": self.udp_listen_port.get(),
            "udp_target_ip": self.udp_target_ip.get(),
            "udp_target_port": self.udp_target_port.get(),
            "scan_ip": self.scan_ip.get(),
            "scan_start": self.scan_start.get(),
            "scan_end": self.scan_end.get(),
            "ping_host": self.ping_host_entry.get(),
            "ping_count": self.ping_count.get(),
        }
        save_config(cfg)
        self.set_status("配置已保存")

    def load_saved_config(self):
        cfg = load_config()
        if cfg:
            for key, var in [
                ("tcp_server_ip", self.tcp_server_ip),
                ("tcp_server_port", self.tcp_server_port),
                ("tcp_client_ip", self.tcp_client_ip),
                ("tcp_client_port", self.tcp_client_port),
                ("udp_listen_port", self.udp_listen_port),
                ("udp_target_ip", self.udp_target_ip),
                ("udp_target_port", self.udp_target_port),
                ("scan_ip", self.scan_ip),
                ("scan_start", self.scan_start),
                ("scan_end", self.scan_end),
                ("ping_host", self.ping_host_entry),
                ("ping_count", self.ping_count),
            ]:
                if key in cfg:
                    var.delete(0, tk.END)
                    var.insert(0, cfg[key])
            self.set_status("配置已加载")
        else:
            self.set_status("未找到已保存的配置")

    def show_about(self):
        messagebox.showinfo("关于", "多协议网络通信与状态监测平台 v2.0\n\n"
                            "功能：TCP/UDP通信、端口监听、数据报文传输、\n"
                            "网络状态检测、DNS解析、路由追踪、带宽测试\n\n"
                            "作者：NetworkEngineering\n2026")

    # ========== 主界面布局 ==========
    def create_widgets(self):
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # 创建所有标签页
        self.tcp_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.tcp_frame, text="TCP 通信")
        self.build_tcp_tab()

        self.udp_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.udp_frame, text="UDP 通信")
        self.build_udp_tab()

        self.scan_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.scan_frame, text="端口扫描")
        self.build_scan_tab()

        self.ping_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.ping_frame, text="Ping 检测")
        self.build_ping_tab()

        self.dns_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.dns_frame, text="DNS & 工具")
        self.build_dns_tab()

        self.trace_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.trace_frame, text="路由追踪")
        self.build_trace_tab()

        self.bw_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.bw_frame, text="带宽测试")
        self.build_bw_tab()

        self.dash_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.dash_frame, text="状态仪表盘")
        self.build_dash_tab()

        # 状态栏
        self.status_var = tk.StringVar()
        status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        self.status_var.set("就绪")

        # 统计栏（右侧状态栏上方）
        self.stats_var = tk.StringVar()
        stats_bar = ttk.Label(self.root, textvariable=self.stats_var, relief=tk.SUNKEN, anchor=tk.E)
        stats_bar.pack(side=tk.BOTTOM, fill=tk.X)
        self.update_stats_display()
        # 每秒刷新统计
        self._schedule_stats_update()

    def _schedule_stats_update(self):
        self.update_stats_display()
        self.root.after(1000, self._schedule_stats_update)

    def update_stats_display(self):
        tcp = self.tcp_stats.snapshot()
        udp = self.udp_stats.snapshot()
        total_sent = tcp["sent_bytes"] + udp["sent_bytes"]
        total_recv = tcp["recv_bytes"] + udp["recv_bytes"]
        total_sp = tcp["sent_packets"] + udp["sent_packets"]
        total_rp = tcp["recv_packets"] + udp["recv_packets"]
        self.stats_var.set(
            f"发送: {format_bytes(total_sent)} ({total_sp}包) | "
            f"接收: {format_bytes(total_recv)} ({total_rp}包) | "
            f"TCP连接: {len(self.tcp_clients)}"
        )

    def set_status(self, msg):
        self.root.after(0, lambda: self.status_var.set(msg))

    # ========== TCP 标签页 ==========
    def build_tcp_tab(self):
        left_frame = ttk.Frame(self.tcp_frame)
        left_frame.pack(side=tk.LEFT, fill=tk.Y, padx=5, pady=5)

        row = 0
        # 服务端
        ttk.Label(left_frame, text="═══ TCP 服务端 ═══", font=("", 9, "bold")).grid(row=row, column=0, columnspan=3, pady=5)
        row += 1
        ttk.Label(left_frame, text="监听IP:").grid(row=row, column=0, sticky=tk.W)
        self.tcp_server_ip = ttk.Entry(left_frame, width=15)
        self.tcp_server_ip.insert(0, self.config.get("tcp_server_ip", "0.0.0.0"))
        self.tcp_server_ip.grid(row=row, column=1, padx=5)
        row += 1
        ttk.Label(left_frame, text="端口:").grid(row=row, column=0, sticky=tk.W)
        self.tcp_server_port = ttk.Entry(left_frame, width=8)
        self.tcp_server_port.insert(0, self.config.get("tcp_server_port", "8888"))
        self.tcp_server_port.grid(row=row, column=1, sticky=tk.W, padx=5)
        row += 1
        self.tcp_echo_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(left_frame, text="Echo 模式 (自动回显)",
                        variable=self.tcp_echo_var).grid(row=row, column=0, columnspan=3, sticky=tk.W)
        row += 1
        self.tcp_server_btn = ttk.Button(left_frame, text="启动服务端", command=self.toggle_tcp_server)
        self.tcp_server_btn.grid(row=row, column=0, columnspan=3, pady=5)
        row += 1

        # 分隔
        ttk.Separator(left_frame, orient='horizontal').grid(row=row, column=0, columnspan=3, sticky=tk.EW, pady=10)
        row += 1

        # 编码
        ttk.Label(left_frame, text="编码:").grid(row=row, column=0, sticky=tk.W)
        self.tcp_encoding = ttk.Combobox(left_frame, values=DEFAULT_ENCODINGS, width=8, state="readonly")
        self.tcp_encoding.current(0)
        self.tcp_encoding.grid(row=row, column=1, sticky=tk.W)
        row += 1

        # 超时
        ttk.Label(left_frame, text="客户端超时(s):").grid(row=row, column=0, sticky=tk.W)
        self.tcp_timeout = ttk.Entry(left_frame, width=5)
        self.tcp_timeout.insert(0, "5")
        self.tcp_timeout.grid(row=row, column=1, sticky=tk.W)
        row += 1

        ttk.Separator(left_frame, orient='horizontal').grid(row=row, column=0, columnspan=3, sticky=tk.EW, pady=10)
        row += 1

        # 客户端
        ttk.Label(left_frame, text="═══ TCP 客户端 ═══", font=("", 9, "bold")).grid(row=row, column=0, columnspan=3, pady=5)
        row += 1
        ttk.Label(left_frame, text="目标IP:").grid(row=row, column=0, sticky=tk.W)
        self.tcp_client_ip = ttk.Entry(left_frame, width=15)
        self.tcp_client_ip.insert(0, self.config.get("tcp_client_ip", "127.0.0.1"))
        self.tcp_client_ip.grid(row=row, column=1)
        row += 1
        ttk.Label(left_frame, text="端口:").grid(row=row, column=0, sticky=tk.W)
        self.tcp_client_port = ttk.Entry(left_frame, width=8)
        self.tcp_client_port.insert(0, self.config.get("tcp_client_port", "8888"))
        self.tcp_client_port.grid(row=row, column=1, sticky=tk.W)
        row += 1
        ttk.Label(left_frame, text="发送内容:").grid(row=row, column=0, sticky=tk.W)
        self.tcp_client_msg = ttk.Entry(left_frame, width=22)
        self.tcp_client_msg.insert(0, "Hello TCP")
        self.tcp_client_msg.grid(row=row, column=1)
        row += 1
        self.tcp_client_btn = ttk.Button(left_frame, text="发送", command=self.send_tcp)
        self.tcp_client_btn.grid(row=row, column=0, columnspan=3, pady=5)

        # 右侧日志区
        right_frame = ttk.Frame(self.tcp_frame)
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.tcp_log = scrolledtext.ScrolledText(right_frame, height=22, width=60)
        self.tcp_log.pack(fill=tk.BOTH, expand=True)
        btn_bar = ttk.Frame(right_frame)
        btn_bar.pack(fill=tk.X, pady=2)
        ttk.Button(btn_bar, text="清空日志", command=lambda: self.tcp_log.delete(1.0, tk.END)).pack(side=tk.LEFT)
        ttk.Button(btn_bar, text="重置统计", command=lambda: (self.tcp_stats.reset(), self.update_stats_display())).pack(side=tk.LEFT, padx=5)

    def toggle_tcp_server(self):
        if hasattr(self, 'tcp_server_thread') and self.tcp_server_thread.is_alive():
            self.tcp_server_stop.set()
            self.tcp_server_btn.config(text="启动服务端")
            self.log_tcp("正在停止服务端...")
        else:
            self.tcp_server_stop.clear()
            host = self.tcp_server_ip.get().strip()
            try:
                port = self._parse_port(self.tcp_server_port.get())
            except ValueError as e:
                messagebox.showerror("输入错误", str(e))
                return
            echo_mode = self.tcp_echo_var.get()
            self.tcp_server_thread = threading.Thread(
                target=NetworkCore.tcp_server_listen,
                args=(host, port, self.log_tcp, self.update_tcp_clients,
                      self.tcp_server_stop, echo_mode, self.tcp_stats),
                daemon=True
            )
            self.tcp_server_thread.start()
            self.tcp_server_btn.config(text="停止服务端")

    def send_tcp(self):
        host = self.tcp_client_ip.get().strip()
        try:
            port = self._parse_port(self.tcp_client_port.get())
        except ValueError as e:
            messagebox.showerror("输入错误", str(e))
            return
        msg = self.tcp_client_msg.get().strip()
        encoding = self.tcp_encoding.get()
        try:
            timeout = float(self.tcp_timeout.get())
        except ValueError:
            timeout = 5
        t = threading.Thread(
            target=NetworkCore.tcp_client_send,
            args=(host, port, msg, self.log_tcp, encoding, timeout, self.tcp_stats),
            daemon=True
        )
        t.start()

    def update_tcp_clients(self, clients):
        self.tcp_clients = clients
        self.root.after(0, lambda: self.set_status(f"已连接客户端: {len(clients)}"))

    def log_tcp(self, msg):
        self.root.after(0, lambda: self.tcp_log.insert(tk.END, f"{datetime.now().strftime('%H:%M:%S.%f')[:-3]}  {msg}\n"))
        self.root.after(0, lambda: self.tcp_log.see(tk.END))
        logging.info(f"TCP: {msg}")

    # ========== UDP 标签页 ==========
    def build_udp_tab(self):
        left_frame = ttk.Frame(self.udp_frame)
        left_frame.pack(side=tk.LEFT, fill=tk.Y, padx=5, pady=5)

        # 监听
        ttk.Label(left_frame, text="═══ UDP 监听 ═══", font=("", 9, "bold")).grid(row=0, column=0, columnspan=3, pady=5)
        ttk.Label(left_frame, text="端口:").grid(row=1, column=0, sticky=tk.W)
        self.udp_listen_port = ttk.Entry(left_frame, width=8)
        self.udp_listen_port.insert(0, self.config.get("udp_listen_port", "9999"))
        self.udp_listen_port.grid(row=1, column=1, sticky=tk.W)
        self.udp_listen_btn = ttk.Button(left_frame, text="开始监听", command=self.toggle_udp_listen)
        self.udp_listen_btn.grid(row=2, column=0, columnspan=3, pady=5)

        ttk.Separator(left_frame, orient='horizontal').grid(row=3, column=0, columnspan=3, sticky=tk.EW, pady=10)

        # 编码
        ttk.Label(left_frame, text="编码:").grid(row=4, column=0, sticky=tk.W)
        self.udp_encoding = ttk.Combobox(left_frame, values=DEFAULT_ENCODINGS, width=8, state="readonly")
        self.udp_encoding.current(0)
        self.udp_encoding.grid(row=4, column=1, sticky=tk.W)

        ttk.Separator(left_frame, orient='horizontal').grid(row=5, column=0, columnspan=3, sticky=tk.EW, pady=10)

        # 发送
        ttk.Label(left_frame, text="═══ UDP 发送 ═══", font=("", 9, "bold")).grid(row=6, column=0, columnspan=3, pady=5)
        ttk.Label(left_frame, text="目标IP:").grid(row=7, column=0, sticky=tk.W)
        self.udp_target_ip = ttk.Entry(left_frame, width=15)
        self.udp_target_ip.insert(0, self.config.get("udp_target_ip", "127.0.0.1"))
        self.udp_target_ip.grid(row=7, column=1)
        ttk.Label(left_frame, text="端口:").grid(row=8, column=0, sticky=tk.W)
        self.udp_target_port = ttk.Entry(left_frame, width=8)
        self.udp_target_port.insert(0, self.config.get("udp_target_port", "9999"))
        self.udp_target_port.grid(row=8, column=1, sticky=tk.W)
        ttk.Label(left_frame, text="内容:").grid(row=9, column=0, sticky=tk.W)
        self.udp_msg = ttk.Entry(left_frame, width=22)
        self.udp_msg.insert(0, "Hello UDP")
        self.udp_msg.grid(row=9, column=1)
        self.udp_broadcast_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(left_frame, text="广播模式", variable=self.udp_broadcast_var).grid(row=10, column=0, columnspan=3, sticky=tk.W)
        self.udp_send_btn = ttk.Button(left_frame, text="发送", command=self.send_udp)
        self.udp_send_btn.grid(row=11, column=0, columnspan=3, pady=5)

        # 组播
        ttk.Separator(left_frame, orient='horizontal').grid(row=12, column=0, columnspan=3, sticky=tk.EW, pady=5)
        ttk.Label(left_frame, text="组播地址:").grid(row=13, column=0, sticky=tk.W)
        self.udp_mcast_group = ttk.Entry(left_frame, width=15)
        self.udp_mcast_group.insert(0, "224.0.0.1")
        self.udp_mcast_group.grid(row=13, column=1)
        ttk.Button(left_frame, text="发送组播", command=self.send_udp_multicast).grid(row=14, column=0, columnspan=3, pady=5)

        # 右侧日志
        right_frame = ttk.Frame(self.udp_frame)
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.udp_log = scrolledtext.ScrolledText(right_frame, height=22, width=60)
        self.udp_log.pack(fill=tk.BOTH, expand=True)
        btn_bar = ttk.Frame(right_frame)
        btn_bar.pack(fill=tk.X, pady=2)
        ttk.Button(btn_bar, text="清空日志", command=lambda: self.udp_log.delete(1.0, tk.END)).pack(side=tk.LEFT)
        ttk.Button(btn_bar, text="重置统计", command=lambda: (self.udp_stats.reset(), self.update_stats_display())).pack(side=tk.LEFT, padx=5)

    def toggle_udp_listen(self):
        if hasattr(self, 'udp_listen_thread') and self.udp_listen_thread.is_alive():
            self.udp_listen_stop.set()
            self.udp_listen_btn.config(text="开始监听")
            self.log_udp("正在停止 UDP 监听...")
        else:
            self.udp_listen_stop.clear()
            try:
                port = self._parse_port(self.udp_listen_port.get())
            except ValueError as e:
                messagebox.showerror("输入错误", str(e))
                return
            encoding = self.udp_encoding.get()
            self.udp_listen_thread = threading.Thread(
                target=NetworkCore.udp_listen,
                args=(port, self.log_udp, self.udp_listen_stop, encoding, self.udp_stats),
                daemon=True
            )
            self.udp_listen_thread.start()
            self.udp_listen_btn.config(text="停止监听")

    def send_udp(self):
        host = self.udp_target_ip.get().strip()
        try:
            port = self._parse_port(self.udp_target_port.get())
        except ValueError as e:
            messagebox.showerror("输入错误", str(e))
            return
        msg = self.udp_msg.get().strip()
        encoding = self.udp_encoding.get()
        broadcast = self.udp_broadcast_var.get()
        t = threading.Thread(
            target=NetworkCore.udp_send,
            args=(host, port, msg, self.log_udp, encoding, broadcast, self.udp_stats),
            daemon=True
        )
        t.start()

    def send_udp_multicast(self):
        group = self.udp_mcast_group.get().strip()
        try:
            port = self._parse_port(self.udp_target_port.get())
        except ValueError as e:
            messagebox.showerror("输入错误", str(e))
            return
        msg = self.udp_msg.get().strip()
        encoding = self.udp_encoding.get()
        t = threading.Thread(
            target=NetworkCore.udp_multicast_send,
            args=(group, port, msg, self.log_udp, encoding),
            daemon=True
        )
        t.start()

    def log_udp(self, msg):
        self.root.after(0, lambda: self.udp_log.insert(tk.END, f"{datetime.now().strftime('%H:%M:%S.%f')[:-3]}  {msg}\n"))
        self.root.after(0, lambda: self.udp_log.see(tk.END))
        logging.info(f"UDP: {msg}")

    # ========== 端口扫描标签页 ==========
    def build_scan_tab(self):
        frame = ttk.Frame(self.scan_frame)
        frame.pack(fill=tk.BOTH, padx=10, pady=10)

        ttk.Label(frame, text="目标IP:").grid(row=0, column=0, sticky=tk.W)
        self.scan_ip = ttk.Entry(frame, width=20)
        self.scan_ip.insert(0, self.config.get("scan_ip", "127.0.0.1"))
        self.scan_ip.grid(row=0, column=1, padx=5)
        ttk.Label(frame, text="起始端口:").grid(row=1, column=0, sticky=tk.W)
        self.scan_start = ttk.Entry(frame, width=8)
        self.scan_start.insert(0, self.config.get("scan_start", "1"))
        self.scan_start.grid(row=1, column=1, sticky=tk.W, padx=5)
        ttk.Label(frame, text="结束端口:").grid(row=2, column=0, sticky=tk.W)
        self.scan_end = ttk.Entry(frame, width=8)
        self.scan_end.insert(0, self.config.get("scan_end", "1024"))
        self.scan_end.grid(row=2, column=1, sticky=tk.W, padx=5)

        # 高级选项
        ttk.Label(frame, text="超时(s):").grid(row=3, column=0, sticky=tk.W)
        self.scan_timeout = ttk.Entry(frame, width=5)
        self.scan_timeout.insert(0, "1")
        self.scan_timeout.grid(row=3, column=1, sticky=tk.W, padx=5)
        ttk.Label(frame, text="最大线程:").grid(row=4, column=0, sticky=tk.W)
        self.scan_threads = ttk.Scale(frame, from_=10, to=200, orient=tk.HORIZONTAL, value=100)
        self.scan_threads.grid(row=4, column=1, sticky=tk.EW, padx=5)
        self.scan_threads_label = ttk.Label(frame, text="100")
        self.scan_threads_label.grid(row=4, column=2, sticky=tk.W)
        self.scan_threads.config(command=lambda v: self.scan_threads_label.config(text=str(int(float(v)))))

        # 进度条
        self.scan_progress = ttk.Progressbar(frame, orient=tk.HORIZONTAL, mode='determinate')
        self.scan_progress.grid(row=5, column=0, columnspan=3, sticky=tk.EW, pady=5)

        self.scan_btn = ttk.Button(frame, text="开始扫描", command=self.start_scan)
        self.scan_btn.grid(row=6, column=0, columnspan=3, pady=5)

        # 结果显示
        self.scan_result_text = scrolledtext.ScrolledText(frame, height=18, width=70)
        self.scan_result_text.grid(row=7, column=0, columnspan=3, pady=5)

    def start_scan(self):
        target = self.scan_ip.get().strip()
        try:
            start = self._parse_port(self.scan_start.get())
            end = self._parse_port(self.scan_end.get())
            if start > end:
                messagebox.showerror("输入错误", "起始端口不能大于结束端口")
                return
        except ValueError as e:
            messagebox.showerror("输入错误", str(e))
            return
        try:
            timeout = float(self.scan_timeout.get())
        except ValueError:
            timeout = 1
        max_workers = int(float(self.scan_threads.get()))

        self.scan_result_text.delete(1.0, tk.END)
        self.scan_progress["maximum"] = end - start + 1
        self.scan_progress["value"] = 0
        self.scan_btn.config(state=tk.DISABLED)

        def log_cb(msg):
            self.root.after(0, lambda: self.scan_result_text.insert(tk.END, f"{msg}\n"))
            self.root.after(0, lambda: self.scan_result_text.see(tk.END))

        def result_cb(open_ports):
            svc_list = []
            for p in open_ports:
                svc = COMMON_PORTS.get(p, "")
                svc_list.append(f"{p}({svc})" if svc else str(p))
            self.root.after(0, lambda: self.scan_result_text.insert(tk.END, f"\n开放端口 ({len(open_ports)}): {svc_list}\n"))
            self.root.after(0, lambda: self.scan_btn.config(state=tk.NORMAL))
            self.root.after(0, lambda: self.set_status(f"扫描完成 - {target}: {len(open_ports)} 个开放端口"))

        def progress_cb(cur, tot):
            self.root.after(0, lambda: self.scan_progress.config(value=cur))

        t = threading.Thread(
            target=NetworkCore.port_scan,
            args=(target, start, end, log_cb, result_cb, progress_cb, timeout, max_workers),
            daemon=True
        )
        t.start()

    # ========== Ping 标签页 ==========
    def build_ping_tab(self):
        frame = ttk.Frame(self.ping_frame)
        frame.pack(fill=tk.BOTH, padx=10, pady=10)

        ttk.Label(frame, text="目标主机/IP:").grid(row=0, column=0, sticky=tk.W)
        self.ping_host_entry = ttk.Entry(frame, width=30)
        self.ping_host_entry.insert(0, self.config.get("ping_host", "8.8.8.8"))
        self.ping_host_entry.grid(row=0, column=1, padx=5)
        ttk.Label(frame, text="次数:").grid(row=1, column=0, sticky=tk.W)
        self.ping_count = ttk.Entry(frame, width=5)
        self.ping_count.insert(0, self.config.get("ping_count", "4"))
        self.ping_count.grid(row=1, column=1, sticky=tk.W, padx=5)

        btn_bar = ttk.Frame(frame)
        btn_bar.grid(row=2, column=0, columnspan=2, pady=10)
        self.ping_btn = ttk.Button(btn_bar, text="Ping (原始输出)", command=self.do_ping)
        self.ping_btn.pack(side=tk.LEFT, padx=2)
        self.ping_stats_btn = ttk.Button(btn_bar, text="Ping (统计解析)", command=self.do_ping_stats)
        self.ping_stats_btn.pack(side=tk.LEFT, padx=2)

        self.ping_result = scrolledtext.ScrolledText(frame, height=16, width=80)
        self.ping_result.grid(row=3, column=0, columnspan=2, pady=5)

        # 延迟统计摘要
        self.ping_summary_var = tk.StringVar()
        self.ping_summary_var.set("")
        ttk.Label(frame, textvariable=self.ping_summary_var, font=("Consolas", 10),
                  foreground="blue").grid(row=4, column=0, columnspan=2, pady=5)

    def do_ping(self):
        host = self.ping_host_entry.get().strip()
        try:
            count = int(self.ping_count.get())
        except ValueError:
            count = 4
        self.ping_result.delete(1.0, tk.END)
        self.ping_result.insert(tk.END, f"Ping {host} ({count} 次)...\n")
        self.ping_btn.config(state=tk.DISABLED)
        self.ping_stats_btn.config(state=tk.DISABLED)

        def run():
            output = NetworkCore.ping_host(host, count)
            self.root.after(0, lambda: self.ping_result.insert(tk.END, output))
            self.root.after(0, lambda: self.ping_btn.config(state=tk.NORMAL))
            self.root.after(0, lambda: self.ping_stats_btn.config(state=tk.NORMAL))

        t = threading.Thread(target=run, daemon=True)
        t.start()

    def do_ping_stats(self):
        host = self.ping_host_entry.get().strip()
        try:
            count = int(self.ping_count.get())
        except ValueError:
            count = 4
        self.ping_result.delete(1.0, tk.END)
        self.ping_result.insert(tk.END, f"Ping {host} ({count} 次) — 统计模式...\n")
        self.ping_btn.config(state=tk.DISABLED)
        self.ping_stats_btn.config(state=tk.DISABLED)

        def run():
            stats = NetworkCore.ping_with_stats(host, count)
            self.root.after(0, lambda: self.ping_result.insert(tk.END, stats["raw"]))
            summary = (f"发送: {stats['sent']} | 接收: {stats['received']} | "
                       f"丢失: {stats['lost']} ({stats['loss_pct']:.1f}%)")
            if stats["min_ms"] is not None:
                summary += (f" | 延迟: min={stats['min_ms']}ms max={stats['max_ms']}ms "
                           f"avg={stats['avg_ms']}ms")
            self.root.after(0, lambda: self.ping_summary_var.set(summary))
            self.root.after(0, lambda: self.ping_btn.config(state=tk.NORMAL))
            self.root.after(0, lambda: self.ping_stats_btn.config(state=tk.NORMAL))

        t = threading.Thread(target=run, daemon=True)
        t.start()

    # ========== DNS & 工具标签页 ==========
    def build_dns_tab(self):
        frame = ttk.Frame(self.dns_frame)
        frame.pack(fill=tk.BOTH, padx=10, pady=10)

        # DNS 查询
        ttk.Label(frame, text="═══ DNS 查询 ═══", font=("", 10, "bold")).grid(row=0, column=0, columnspan=3, pady=5, sticky=tk.W)
        ttk.Label(frame, text="主机名:").grid(row=1, column=0, sticky=tk.W)
        self.dns_host = ttk.Entry(frame, width=25)
        self.dns_host.insert(0, "baidu.com")
        self.dns_host.grid(row=1, column=1, padx=5)
        ttk.Label(frame, text="记录类型:").grid(row=2, column=0, sticky=tk.W)
        self.dns_type = ttk.Combobox(frame, values=["A", "AAAA", "PTR", "MX", "NS"], width=6, state="readonly")
        self.dns_type.current(0)
        self.dns_type.grid(row=2, column=1, sticky=tk.W, padx=5)
        ttk.Button(frame, text="查询", command=self.do_dns_lookup).grid(row=3, column=0, columnspan=2, pady=5)

        # 单端口检测
        ttk.Separator(frame, orient='horizontal').grid(row=4, column=0, columnspan=3, sticky=tk.EW, pady=10)
        ttk.Label(frame, text="═══ 端口连通性检测 ═══", font=("", 10, "bold")).grid(row=5, column=0, columnspan=3, pady=5, sticky=tk.W)
        ttk.Label(frame, text="主机:").grid(row=6, column=0, sticky=tk.W)
        self.check_host = ttk.Entry(frame, width=25)
        self.check_host.insert(0, "127.0.0.1")
        self.check_host.grid(row=6, column=1, padx=5)
        ttk.Label(frame, text="端口:").grid(row=7, column=0, sticky=tk.W)
        self.check_port_entry = ttk.Entry(frame, width=8)
        self.check_port_entry.insert(0, "80")
        self.check_port_entry.grid(row=7, column=1, sticky=tk.W, padx=5)
        ttk.Button(frame, text="检测", command=self.do_check_port).grid(row=8, column=0, columnspan=2, pady=5)

        # HTTP HEAD
        ttk.Separator(frame, orient='horizontal').grid(row=9, column=0, columnspan=3, sticky=tk.EW, pady=10)
        ttk.Label(frame, text="═══ HTTP HEAD 检测 ═══", font=("", 10, "bold")).grid(row=10, column=0, columnspan=3, pady=5, sticky=tk.W)
        ttk.Label(frame, text="主机:").grid(row=11, column=0, sticky=tk.W)
        self.http_host = ttk.Entry(frame, width=25)
        self.http_host.insert(0, "www.baidu.com")
        self.http_host.grid(row=11, column=1, padx=5)
        ttk.Label(frame, text="端口:").grid(row=12, column=0, sticky=tk.W)
        self.http_port = ttk.Entry(frame, width=8)
        self.http_port.insert(0, "80")
        self.http_port.grid(row=12, column=1, sticky=tk.W, padx=5)
        ttk.Button(frame, text="发送 HEAD", command=self.do_http_head).grid(row=13, column=0, columnspan=2, pady=5)

        # 日志
        self.dns_log = scrolledtext.ScrolledText(frame, height=12, width=70)
        self.dns_log.grid(row=14, column=0, columnspan=3, pady=5)
        ttk.Button(frame, text="清空", command=lambda: self.dns_log.delete(1.0, tk.END)).grid(row=15, column=0)

    def log_dns(self, msg):
        self.root.after(0, lambda: self.dns_log.insert(tk.END, f"{datetime.now().strftime('%H:%M:%S')}  {msg}\n"))
        self.root.after(0, lambda: self.dns_log.see(tk.END))

    def do_dns_lookup(self):
        host = self.dns_host.get().strip()
        rtype = self.dns_type.get()
        self.dns_log.delete(1.0, tk.END)
        t = threading.Thread(target=NetworkCore.dns_lookup,
                             args=(host, rtype, self.log_dns), daemon=True)
        t.start()

    def do_check_port(self):
        host = self.check_host.get().strip()
        try:
            port = self._parse_port(self.check_port_entry.get())
        except ValueError as e:
            messagebox.showerror("输入错误", str(e))
            return
        self.dns_log.delete(1.0, tk.END)
        def run():
            is_open, msg = NetworkCore.check_port(host, port)
            self.root.after(0, lambda: self.log_dns(msg))
        t = threading.Thread(target=run, daemon=True)
        t.start()

    def do_http_head(self):
        host = self.http_host.get().strip()
        try:
            port = self._parse_port(self.http_port.get())
        except ValueError as e:
            messagebox.showerror("输入错误", str(e))
            return
        self.dns_log.delete(1.0, tk.END)
        t = threading.Thread(target=NetworkCore.http_head,
                             args=(host, port, self.log_dns), daemon=True)
        t.start()

    # ========== 路由追踪标签页 ==========
    def build_trace_tab(self):
        frame = ttk.Frame(self.trace_frame)
        frame.pack(fill=tk.BOTH, padx=10, pady=10)

        ttk.Label(frame, text="目标主机/IP:").grid(row=0, column=0, sticky=tk.W)
        self.trace_target = ttk.Entry(frame, width=30)
        self.trace_target.insert(0, "baidu.com")
        self.trace_target.grid(row=0, column=1, padx=5)
        ttk.Label(frame, text="最大跳数:").grid(row=1, column=0, sticky=tk.W)
        self.trace_max_hops = ttk.Entry(frame, width=5)
        self.trace_max_hops.insert(0, "30")
        self.trace_max_hops.grid(row=1, column=1, sticky=tk.W, padx=5)
        self.trace_btn = ttk.Button(frame, text="开始追踪", command=self.do_traceroute)
        self.trace_btn.grid(row=2, column=0, columnspan=2, pady=10)

        self.trace_result = scrolledtext.ScrolledText(frame, height=20, width=85)
        self.trace_result.grid(row=3, column=0, columnspan=2, pady=5)
        ttk.Button(frame, text="清空", command=lambda: self.trace_result.delete(1.0, tk.END)).grid(row=4, column=0)

        # 停止事件
        self.trace_stop = threading.Event()

    def do_traceroute(self):
        target = self.trace_target.get().strip()
        try:
            max_hops = int(self.trace_max_hops.get())
        except ValueError:
            max_hops = 30
        self.trace_result.delete(1.0, tk.END)
        self.trace_stop.clear()
        self.trace_btn.config(text="停止追踪", command=lambda: self.trace_stop.set())

        def hop_cb(ttl, msg, results):
            self.root.after(0, lambda: self.trace_result.insert(tk.END, f"{msg}\n"))
            self.root.after(0, lambda: self.trace_result.see(tk.END))
            if ttl >= max_hops or "到达目标" in msg or "最大跳数" in msg:
                self.root.after(0, lambda: self.trace_btn.config(text="开始追踪", command=self.do_traceroute))

        t = threading.Thread(
            target=NetworkCore.traceroute,
            args=(target, max_hops, hop_cb, self.trace_stop),
            daemon=True
        )
        t.start()

    # ========== 带宽测试标签页 ==========
    def build_bw_tab(self):
        frame = ttk.Frame(self.bw_frame)
        frame.pack(fill=tk.BOTH, padx=10, pady=10)

        ttk.Label(frame, text="═══ TCP 带宽测试 ═══", font=("", 10, "bold")).grid(row=0, column=0, columnspan=3, pady=5, sticky=tk.W)
        ttk.Label(frame, text="(需先在TCP标签页启动对应的服务端)", foreground="gray").grid(row=1, column=0, columnspan=3, sticky=tk.W)

        ttk.Label(frame, text="目标IP:").grid(row=2, column=0, sticky=tk.W, pady=2)
        self.bw_host = ttk.Entry(frame, width=20)
        self.bw_host.insert(0, "127.0.0.1")
        self.bw_host.grid(row=2, column=1, padx=5)
        ttk.Label(frame, text="端口:").grid(row=3, column=0, sticky=tk.W)
        self.bw_port = ttk.Entry(frame, width=8)
        self.bw_port.insert(0, "8888")
        self.bw_port.grid(row=3, column=1, sticky=tk.W, padx=5)
        ttk.Label(frame, text="持续时长(s):").grid(row=4, column=0, sticky=tk.W)
        self.bw_duration = ttk.Entry(frame, width=5)
        self.bw_duration.insert(0, "5")
        self.bw_duration.grid(row=4, column=1, sticky=tk.W, padx=5)

        self.bw_btn = ttk.Button(frame, text="开始测试", command=self.do_bandwidth_test)
        self.bw_btn.grid(row=5, column=0, columnspan=2, pady=10)

        # 结果展示
        self.bw_result_var = tk.StringVar()
        self.bw_result_var.set("等待测试...")
        ttk.Label(frame, textvariable=self.bw_result_var, font=("Consolas", 12),
                  foreground="darkgreen").grid(row=6, column=0, columnspan=2, pady=10)

        self.bw_log = scrolledtext.ScrolledText(frame, height=12, width=70)
        self.bw_log.grid(row=7, column=0, columnspan=3, pady=5)
        ttk.Button(frame, text="清空", command=lambda: self.bw_log.delete(1.0, tk.END)).grid(row=8, column=0)

        self.bw_stop = threading.Event()

        # TCP 压力测试子区
        ttk.Separator(frame, orient='horizontal').grid(row=9, column=0, columnspan=3, sticky=tk.EW, pady=10)
        ttk.Label(frame, text="═══ TCP 压力测试 (并发连接) ═══", font=("", 10, "bold")).grid(row=10, column=0, columnspan=3, pady=5, sticky=tk.W)
        ttk.Label(frame, text="连接数:").grid(row=11, column=0, sticky=tk.W)
        self.stress_conn = ttk.Entry(frame, width=8)
        self.stress_conn.insert(0, "100")
        self.stress_conn.grid(row=11, column=1, sticky=tk.W, padx=5)
        ttk.Label(frame, text="消息大小(bytes):").grid(row=12, column=0, sticky=tk.W)
        self.stress_msg_size = ttk.Entry(frame, width=8)
        self.stress_msg_size.insert(0, "1024")
        self.stress_msg_size.grid(row=12, column=1, sticky=tk.W, padx=5)
        self.stress_progress = ttk.Progressbar(frame, orient=tk.HORIZONTAL, mode='determinate')
        self.stress_progress.grid(row=13, column=0, columnspan=3, sticky=tk.EW, pady=5)
        self.stress_btn = ttk.Button(frame, text="开始压力测试", command=self.do_stress_test)
        self.stress_btn.grid(row=14, column=0, columnspan=3, pady=5)

    def log_bw(self, msg):
        self.root.after(0, lambda: self.bw_log.insert(tk.END, f"{datetime.now().strftime('%H:%M:%S.%f')[:-3]}  {msg}\n"))
        self.root.after(0, lambda: self.bw_log.see(tk.END))

    def do_bandwidth_test(self):
        host = self.bw_host.get().strip()
        try:
            port = self._parse_port(self.bw_port.get())
        except ValueError as e:
            messagebox.showerror("输入错误", str(e))
            return
        try:
            duration = float(self.bw_duration.get())
        except ValueError:
            duration = 5
        self.bw_log.delete(1.0, tk.END)
        self.bw_stop.clear()
        self.bw_btn.config(text="停止", command=lambda: self.bw_stop.set())

        def result_cb(r):
            self.root.after(0, lambda: self.bw_result_var.set(
                f"结果: {format_bytes(r['total_bytes'])} 在 {human_time(r['elapsed'])} 内\n"
                f"吞吐量: {r['throughput_mbps']:.2f} Mbps ({r['throughput_MBps']:.2f} MB/s)"
            ))
            self.root.after(0, lambda: self.bw_btn.config(text="开始测试", command=self.do_bandwidth_test))

        t = threading.Thread(
            target=NetworkCore.measure_bandwidth,
            args=(host, port, duration, self.log_bw, result_cb, self.bw_stop),
            daemon=True
        )
        t.start()

    def do_stress_test(self):
        host = self.bw_host.get().strip()
        try:
            port = self._parse_port(self.bw_port.get())
        except ValueError as e:
            messagebox.showerror("输入错误", str(e))
            return
        try:
            num_conn = int(self.stress_conn.get())
            msg_size = int(self.stress_msg_size.get())
        except ValueError:
            messagebox.showerror("输入错误", "连接数和消息大小必须为整数")
            return
        self.bw_log.delete(1.0, tk.END)
        self.stress_progress["maximum"] = num_conn
        self.stress_progress["value"] = 0
        self.stress_btn.config(state=tk.DISABLED)
        stop_event = threading.Event()
        self.bw_btn.config(text="停止", command=lambda: stop_event.set())

        def progress_cb(cur, tot):
            self.root.after(0, lambda: self.stress_progress.config(value=cur))

        def done():
            self.root.after(0, lambda: self.stress_btn.config(state=tk.NORMAL))
            self.root.after(0, lambda: self.bw_btn.config(text="开始测试", command=self.do_bandwidth_test))

        t = threading.Thread(
            target=lambda: (NetworkCore.tcp_stress_test(
                host, port, num_conn, msg_size, progress_cb, self.log_bw, stop_event), done()),
            daemon=True
        )
        t.start()

    # ========== 仪表盘标签页 ==========
    def build_dash_tab(self):
        frame = ttk.Frame(self.dash_frame)
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        ttk.Label(frame, text="网络状态仪表盘", font=("Arial", 14, "bold")).pack(pady=5)
        self.dash_text = scrolledtext.ScrolledText(frame, height=18, width=85)
        self.dash_text.pack(fill=tk.BOTH, expand=True)

        btn_bar = ttk.Frame(frame)
        btn_bar.pack(fill=tk.X, pady=5)
        ttk.Button(btn_bar, text="刷新状态", command=self.refresh_dashboard).pack(side=tk.LEFT)
        ttk.Button(btn_bar, text="导出报告", command=self.export_dashboard).pack(side=tk.LEFT, padx=5)

        self.refresh_dashboard()

    def refresh_dashboard(self):
        self.dash_text.delete(1.0, tk.END)

        # 本机信息
        self.dash_text.insert(tk.END, "═══ 本机网络接口 ═══\n")
        for iface in get_all_local_ips():
            self.dash_text.insert(tk.END, f"  [{iface['family']}] {iface['ip']}  (hostname: {iface.get('name', 'N/A')})\n")

        # 统计
        self.dash_text.insert(tk.END, "\n═══ 运行时统计 ═══\n")
        tcp = self.tcp_stats.snapshot()
        udp = self.udp_stats.snapshot()
        self.dash_text.insert(tk.END, f"  TCP - 发送: {format_bytes(tcp['sent_bytes'])} ({tcp['sent_packets']}包)"
                                        f" | 接收: {format_bytes(tcp['recv_bytes'])} ({tcp['recv_packets']}包)\n")
        self.dash_text.insert(tk.END, f"  UDP - 发送: {format_bytes(udp['sent_bytes'])} ({udp['sent_packets']}包)"
                                        f" | 接收: {format_bytes(udp['recv_bytes'])} ({udp['recv_packets']}包)\n")
        self.dash_text.insert(tk.END, f"  活动 TCP 连接数: {len(self.tcp_clients)}\n")

        # 连通性
        self.dash_text.insert(tk.END, "\n═══ 常见站点连通性 ═══\n")
        sites = [("baidu.com", 80), ("google.com", 80), ("github.com", 443)]
        for site, port in sites:
            try:
                addrs = socket.getaddrinfo(site, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
                if addrs:
                    self.dash_text.insert(tk.END, f"  {site}:{port} ✓ 可达\n")
                else:
                    self.dash_text.insert(tk.END, f"  {site}:{port} ✗ 无法解析\n")
            except Exception:
                self.dash_text.insert(tk.END, f"  {site}:{port} ✗ 不可达\n")

        # 平台信息
        self.dash_text.insert(tk.END, f"\n═══ 平台信息 ═══\n")
        self.dash_text.insert(tk.END, f"  系统: {platform.system()} {platform.release()}\n")
        self.dash_text.insert(tk.END, f"  主机名: {socket.gethostname()}\n")
        self.dash_text.insert(tk.END, f"  日志文件: {LOG_FILE}\n")
        self.dash_text.insert(tk.END, f"  配置文件: {CONFIG_FILE}\n")

        self.set_status("仪表盘已刷新")

    def export_dashboard(self):
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("文本文件", "*.txt"), ("所有文件", "*.*")]
        )
        if path:
            try:
                content = self.dash_text.get(1.0, tk.END)
                with open(path, 'w', encoding='utf-8') as f:
                    f.write(content)
                self.set_status(f"报告已导出至: {path}")
            except Exception as e:
                messagebox.showerror("错误", f"导出失败: {e}")

    # ========== 工具方法 ==========

    @staticmethod
    def _parse_port(value):
        """端口号验证"""
        try:
            port = int(value.strip())
        except ValueError:
            raise ValueError(f"端口号必须为整数: {value}")
        if port < 1 or port > 65535:
            raise ValueError(f"端口号超出范围 (1-65535): {port}")
        return port

    def on_closing(self):
        """窗口关闭：优雅停止所有活动任务"""
        self.tcp_server_stop.set()
        self.udp_listen_stop.set()
        if hasattr(self, 'trace_stop'):
            self.trace_stop.set()
        if hasattr(self, 'bw_stop'):
            self.bw_stop.set()
        self.root.destroy()


if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkToolApp(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()
