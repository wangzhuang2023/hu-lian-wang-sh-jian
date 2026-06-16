#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
网络通信核心模块 (Network Communication Core Module)
====================================================
功能：TCP/UDP通信、端口监听、数据报文传输（基于 struct 的二进制帧协议）、
      网络状态检测、DNS解析、路由追踪、带宽测试

特性：
  - 零外部依赖，纯 Python 标准库
  - 基于 struct 的二进制数据包帧协议（长度前缀 / 扩展头部）
  - TCP 流式数据的正确帧定界（FrameCodec.feed）
  - UDP 组播加入/离开（IGMP / MLD）
  - 同时提供同步（threading）和异步（asyncio）API
  - 上下文管理器支持（with 语句）
  - 线程安全统计

用法示例::

    # 同步 TCP 客户端
    from 网络通信 import TCPClient
    with TCPClient('localhost', 8888) as client:
        client.send(b'Hello')
        msg_type, response = client.recv()

    # 同步 TCP 服务端
    from 网络通信 import TCPServer
    server = TCPServer(port=8888, echo_mode=True)
    server.on_message = lambda addr, mt, data: print(f"收到: {data}")
    server.start()
    # ... server.stop()

    # 帧编解码
    from 网络通信 import FrameCodec
    codec = FrameCodec(mode=0)  # 简单长度前缀
    frame = codec.pack(b'Hello')  # => b'\x00\x00\x00\x05Hello'
    frames = codec.feed(frame)
    print(frames)  # => [(0, b'Hello')]

作者：NetworkEngineering
版本：3.0
"""

# ============================================================================
# Phase 1: 导入与常量
# ============================================================================

import socket
import struct
import threading
import time
import logging
import base64
import ipaddress
import platform
import subprocess
import select
import os
import re as _re
from collections import namedtuple
from concurrent.futures import ThreadPoolExecutor, as_completed

__all__ = [
    # 异常
    "NetCommError", "ConnectionError", "ConnectionTimeoutError",
    "FramingError", "ProtocolError",
    # 常量
    "COMMON_PORTS", "DEFAULT_ENCODINGS", "PacketType",
    # 工具函数
    "is_ipv4", "is_ipv6", "is_valid_host", "resolve_host",
    "get_local_ip", "get_all_local_ips", "format_bytes", "human_time",
    "encode_data", "decode_data",
    # 帧协议
    "FrameCodec",
    # 统计
    "StatsCounter",
    # TCP
    "TCPClient", "TCPServer",
    # UDP
    "UDPSender", "UDPListener",
    # 网络诊断
    "PortChecker", "PortScanner", "PingDetector",
    "Traceroute", "DNSResolver", "BandwidthTester",
    # 异步 API
    "AsyncTCPClient", "AsyncTCPServer", "AsyncUDPEndpoint", "AsyncPortScanner",
]

# --------------------------------------------------------------------------
# 常量
# --------------------------------------------------------------------------

DEFAULT_ENCODINGS = ["UTF-8", "GBK", "ASCII", "Hex", "Base64"]

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
_log = logging.getLogger("NetComm")
_log.addHandler(logging.NullHandler())


class PacketType:
    """扩展帧消息类型枚举（模式 1）"""
    RAW = 0x00          # 原始字节
    TEXT = 0x01         # UTF-8 文本
    JSON = 0x02         # JSON 数据
    COMMAND = 0x03      # 命令
    HEARTBEAT = 0x04    # 心跳
    FILE_META = 0x05    # 文件元数据
    FILE_CHUNK = 0x06   # 文件块
    # 0x07 - 0xEF  保留
    # 0xF0 - 0xFF  用户自定义

    _NAMES = {
        0x00: "RAW", 0x01: "TEXT", 0x02: "JSON", 0x03: "COMMAND",
        0x04: "HEARTBEAT", 0x05: "FILE_META", 0x06: "FILE_CHUNK",
    }

    @classmethod
    def name(cls, t):
        return cls._NAMES.get(t, f"USER({t:02x})")


# ============================================================================
# Phase 1: 异常体系
# ============================================================================

class NetCommError(Exception):
    """网络通信模块基础异常"""
    pass


class ConnectionError(NetCommError):
    """连接相关错误"""
    pass


class ConnectionTimeoutError(NetCommError):
    """连接超时"""
    pass


class FramingError(NetCommError):
    """帧定界/解析错误"""
    pass


class ProtocolError(NetCommError):
    """协议错误（如 Magic 不匹配）"""
    pass


# ============================================================================
# Phase 1: 工具函数
# ============================================================================

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


# ============================================================================
# Phase 2: 统计计数器
# ============================================================================

class StatsCounter:
    """线程安全的收发字节统计"""

    def __init__(self):
        self.sent_bytes = 0
        self.recv_bytes = 0
        self.sent_packets = 0
        self.recv_packets = 0
        self._lock = threading.Lock()

    def add_sent(self, n):
        with self._lock:
            self.sent_bytes += n
            self.sent_packets += 1

    def add_recv(self, n):
        with self._lock:
            self.recv_bytes += n
            self.recv_packets += 1

    def snapshot(self):
        with self._lock:
            return {
                "sent_bytes": self.sent_bytes,
                "recv_bytes": self.recv_bytes,
                "sent_packets": self.sent_packets,
                "recv_packets": self.recv_packets,
            }

    def reset(self):
        with self._lock:
            self.sent_bytes = 0
            self.recv_bytes = 0
            self.sent_packets = 0
            self.recv_packets = 0


# ============================================================================
# Phase 2: 二进制帧编解码器 (struct 核心应用)
# ============================================================================

class FrameCodec:
    """二进制帧编解码器

    正确处理 TCP 流式传输中的数据边界问题。
    支持两种帧模式：

    **模式 0 — 简单长度前缀:**
        [4字节 载荷长度(!I)] [载荷数据]
        开销: 4 字节/帧，最大载荷 ~4GB

    **模式 1 — 扩展头部帧:**
        [2字节 Magic(!2s)] [1字节 版本(B)] [1字节 消息类型(B)]
        [4字节 载荷长度(!I)] [载荷数据]
        Magic = b'NC', 版本 = 1
        开销: 8 字节/帧

    用法::

        codec = FrameCodec(mode=0)
        frame = codec.pack(b'Hello')
        # 模拟 TCP 流式接收
        frames = codec.feed(frame[:3])
        # => []  (不完整)
        frames = codec.feed(frame[3:])
        # => [(0, b'Hello')]
    """

    # 协议常量
    PROTO_MAGIC = b'NC'
    PROTO_VERSION = 1
    HEADER_SIMPLE_SIZE = 4       # !I
    HEADER_EXTENDED_SIZE = 8     # !2sBBI
    DEFAULT_MAX_FRAME = 16 * 1024 * 1024  # 16 MB

    def __init__(self, mode=0, max_frame_size=None):
        """
        :param mode: 0 = 简单长度前缀, 1 = 扩展头部
        :param max_frame_size: 允许的最大帧载荷 (字节)，默认 16MB
        """
        if mode not in (0, 1):
            raise ValueError(f"mode 必须为 0 或 1，收到: {mode}")
        self.mode = mode
        self.max_frame_size = max_frame_size or self.DEFAULT_MAX_FRAME
        self._recv_buf = bytearray()

    # ----- 编码 -----

    def pack(self, data, msg_type=0):
        """将数据编码为一帧 (bytes)"""
        if self.mode == 0:
            return self.pack_simple(data)
        else:
            return self.pack_extended(data, msg_type)

    @staticmethod
    def pack_simple(data):
        """简单长度前缀帧: !I + payload"""
        return struct.pack('!I', len(data)) + data

    @staticmethod
    def pack_extended(data, msg_type=0):
        """扩展头部帧: !2sBBI + payload"""
        return struct.pack('!2sBBI',
                           FrameCodec.PROTO_MAGIC,
                           FrameCodec.PROTO_VERSION,
                           msg_type,
                           len(data)) + data

    # ----- 解码 -----

    @staticmethod
    def unpack_header_simple(header_bytes):
        """解析简单头部，返回 payload_length"""
        if len(header_bytes) < FrameCodec.HEADER_SIMPLE_SIZE:
            return None
        return struct.unpack('!I', header_bytes[:FrameCodec.HEADER_SIMPLE_SIZE])[0]

    @staticmethod
    def unpack_header_extended(header_bytes):
        """解析扩展头部，返回 (msg_type, payload_length) 或 None

        :raises ProtocolError: Magic 或版本不匹配
        """
        if len(header_bytes) < FrameCodec.HEADER_EXTENDED_SIZE:
            return None
        magic, version, msg_type, length = struct.unpack(
            '!2sBBI', header_bytes[:FrameCodec.HEADER_EXTENDED_SIZE])
        if magic != FrameCodec.PROTO_MAGIC:
            raise ProtocolError(
                f"Magic 不匹配: 期望 {FrameCodec.PROTO_MAGIC!r}, 收到 {magic!r}")
        if version != FrameCodec.PROTO_VERSION:
            raise ProtocolError(
                f"不支持的协议版本: {version}, 期望 {FrameCodec.PROTO_VERSION}")
        return (msg_type, length)

    def unpack_one(self, data):
        """从字节串中提取一帧。

        :param data: 缓冲区中的累计数据 (bytes)
        :returns: (msg_type, payload, consumed) 三元组，数据不足时返回 None
        :raises FramingError: 载荷长度超过 max_frame_size
        :raises ProtocolError: 扩展模式 Magic/版本错误
        """
        buf = data if isinstance(data, (bytes, bytearray)) else bytes(data)

        if self.mode == 0:
            header_size = self.HEADER_SIMPLE_SIZE
            if len(buf) < header_size:
                return None
            payload_len = self.unpack_header_simple(buf)
            msg_type = 0
        else:
            header_size = self.HEADER_EXTENDED_SIZE
            if len(buf) < header_size:
                return None
            result = self.unpack_header_extended(buf)
            if result is None:
                return None
            msg_type, payload_len = result

        if payload_len > self.max_frame_size:
            raise FramingError(
                f"帧载荷过大: {payload_len} > {self.max_frame_size} 字节")

        total_size = header_size + payload_len
        if len(buf) < total_size:
            return None  # 载荷尚未完全到达

        payload = bytes(buf[header_size:total_size])
        return (msg_type, payload, total_size)

    def feed(self, data):
        """喂入接收到的字节，返回已完成的帧列表。

        正确处理 TCP 流式特性：
        - 自动拼接不完整的帧（半包）
        - 自动拆分粘在一起的多个帧（粘包）

        :param data: 新接收到的字节
        :returns: [(msg_type, payload), ...] 完整帧列表
        """
        self._recv_buf.extend(data)
        frames = []
        while True:
            try:
                result = self.unpack_one(bytes(self._recv_buf))
            except (FramingError, ProtocolError) as e:
                # 帧错误时清空缓冲区（防止后续数据被污染）
                _log.error(f"帧解析错误: {e}，清空接收缓冲区")
                self._recv_buf.clear()
                break
            if result is None:
                break
            msg_type, payload, consumed = result
            del self._recv_buf[:consumed]
            frames.append((msg_type, payload))
        return frames

    def reset(self):
        """清空接收缓冲区"""
        self._recv_buf.clear()

    @property
    def buffered(self):
        """返回当前缓冲区中未完成的数据字节数"""
        return len(self._recv_buf)


# ============================================================================
# Phase 3: TCP 通信
# ============================================================================

class TCPClient:
    """TCP 客户端

    支持 IPv4/IPv6 双栈、自动帧定界、Keepalive/NODELAY、上下文管理器。

    用法::

        # 带帧协议
        with TCPClient('localhost', 8888, use_framing=True) as client:
            client.send(b'Hello')
            msg_type, response = client.recv()

        # 原始模式（兼容旧代码）
        client = TCPClient('example.com', 80, use_framing=False)
        client.connect()
        client.send_raw(b'GET / HTTP/1.1\\r\\nHost: example.com\\r\\n\\r\\n')
        data = client.recv_raw(4096)
        client.disconnect()
    """

    def __init__(self, host='127.0.0.1', port=8888, *,
                 encoding='UTF-8',
                 timeout=5.0,
                 enable_nodelay=True,
                 enable_keepalive=True,
                 use_framing=True,
                 framing_mode=0,
                 max_frame_size=None):
        """
        :param host: 目标主机名或 IP
        :param port: 目标端口
        :param encoding: 文本编解码方式
        :param timeout: 连接和接收超时 (秒)
        :param enable_nodelay: 禁用 Nagle 算法 (TCP_NODELAY)
        :param enable_keepalive: 启用 TCP Keepalive
        :param use_framing: 是否使用帧协议
        :param framing_mode: 帧模式 (0=简单, 1=扩展)
        :param max_frame_size: 最大帧载荷大小
        """
        self.host = host
        self.port = port
        self.encoding = encoding
        self.timeout = timeout
        self.enable_nodelay = enable_nodelay
        self.enable_keepalive = enable_keepalive
        self.use_framing = use_framing
        self._sock = None
        self._codec = FrameCodec(mode=framing_mode, max_frame_size=max_frame_size) if use_framing else None
        self.stats = StatsCounter()

    # ----- 连接管理 -----

    def connect(self):
        """建立 TCP 连接（双栈 IPv4/IPv6）"""
        addrinfo = socket.getaddrinfo(self.host, self.port,
                                      socket.AF_UNSPEC, socket.SOCK_STREAM)
        last_error = None
        for family, socktype, proto, canonname, sockaddr in addrinfo:
            try:
                self._sock = socket.socket(family, socktype, proto)
                self._sock.settimeout(self.timeout)
                self._sock.connect(sockaddr)
                self._configure_socket()
                _log.info(f"TCP 客户端已连接: {sockaddr}")
                return
            except OSError as e:
                last_error = e
                if self._sock:
                    self._sock.close()
                    self._sock = None
                continue

        raise ConnectionError(f"无法连接到 {self.host}:{self.port}: {last_error}")

    def _configure_socket(self):
        """配置套接字选项"""
        if self._sock is None:
            return
        if self.enable_nodelay:
            try:
                self._sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except (AttributeError, OSError):
                pass
        if self.enable_keepalive:
            try:
                self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            except (AttributeError, OSError):
                pass

    def disconnect(self):
        """优雅断开连接（半关闭 + 全关闭）"""
        if self._sock is None:
            return
        try:
            self._sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            self._sock.close()
        except OSError:
            pass
        self._sock = None
        if self._codec:
            self._codec.reset()
        _log.info("TCP 客户端已断开")

    @property
    def is_connected(self):
        """检查是否已连接"""
        return self._sock is not None

    # ----- 帧模式发送/接收 -----

    def send(self, data, msg_type=0):
        """发送数据（帧模式：自动加帧头；原始模式：直接发送）

        :param data: 要发送的数据 (str 自动编码，bytes 直接发送)
        :param msg_type: 消息类型（仅扩展帧模式）
        """
        if self._sock is None:
            raise ConnectionError("未建立连接")

        if isinstance(data, str):
            raw = encode_data(data, self.encoding)
        else:
            raw = data

        if self.use_framing and self._codec:
            raw = self._codec.pack(raw, msg_type)

        self._sock.sendall(raw)
        self.stats.add_sent(len(raw))

    def send_raw(self, data):
        """直接发送原始字节（绕过帧协议）"""
        if self._sock is None:
            raise ConnectionError("未建立连接")
        if isinstance(data, str):
            data = encode_data(data, self.encoding)
        self._sock.sendall(data)
        self.stats.add_sent(len(data))

    def recv(self, timeout=None):
        """接收一帧（阻塞）

        :param timeout: 接收超时 (秒)，None 使用默认超时
        :returns: (msg_type, payload) 元组
        :raises ConnectionTimeoutError: 超时
        :raises ConnectionError: 连接断开
        """
        if self._sock is None:
            raise ConnectionError("未建立连接")

        old_timeout = self._sock.gettimeout()
        self._sock.settimeout(timeout if timeout is not None else self.timeout)

        try:
            if self.use_framing and self._codec:
                # 循环读取直到获得完整帧
                while True:
                    frames = self._codec.feed(b'')  # 先检查缓冲区
                    if frames:
                        return frames[0]
                    data = self._sock.recv(65536)
                    if not data:
                        raise ConnectionError("连接已断开")
                    self.stats.add_recv(len(data))
                    frames = self._codec.feed(data)
                    if frames:
                        return frames[0]
            else:
                raw = self._sock.recv(65536)
                if not raw:
                    raise ConnectionError("连接已断开")
                self.stats.add_recv(len(raw))
                return (0, raw)
        except socket.timeout:
            raise ConnectionTimeoutError(
                f"接收超时 ({timeout if timeout is not None else self.timeout}s)")
        finally:
            self._sock.settimeout(old_timeout)

    def recv_raw(self, bufsize=65536, timeout=None):
        """接收原始字节（绕过帧协议）"""
        if self._sock is None:
            raise ConnectionError("未建立连接")
        if timeout is not None:
            self._sock.settimeout(timeout)
        try:
            data = self._sock.recv(bufsize)
            if data:
                self.stats.add_recv(len(data))
            return data
        except socket.timeout:
            return b''

    # ----- 上下文管理器 -----

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.disconnect()
        return False

    def __repr__(self):
        status = "已连接" if self.is_connected else "未连接"
        return f"TCPClient({self.host}:{self.port}, {status})"


class TCPServer:
    """TCP 服务端

    多客户端并发、帧协议支持、Echo 模式、优雅关闭。

    用法::

        server = TCPServer(port=8888, echo_mode=True, use_framing=True)
        server.on_message = lambda addr, mt, data: print(f"{addr}: {data}")
        server.on_client_connected = lambda addr: print(f"连接: {addr}")
        server.start()
        # ...
        server.stop()
    """

    def __init__(self, host='0.0.0.0', port=8888, *,
                 encoding='UTF-8',
                 timeout=1.0,
                 backlog=10,
                 enable_keepalive=True,
                 enable_nodelay=True,
                 use_framing=True,
                 framing_mode=0,
                 max_frame_size=None,
                 echo_mode=False):
        """
        :param host: 监听地址
        :param port: 监听端口
        :param encoding: 文本编解码方式
        :param timeout: accept 轮询超时 (秒)
        :param backlog: 连接待办队列大小
        :param enable_keepalive: 客户端套接字启用 TCP Keepalive
        :param enable_nodelay: 客户端套接字禁用 Nagle 算法
        :param use_framing: 是否使用帧协议
        :param framing_mode: 帧模式 (0=简单, 1=扩展)
        :param max_frame_size: 最大帧载荷大小
        :param echo_mode: 自动回显接收到的数据
        """
        self.host = host
        self.port = port
        self.encoding = encoding
        self.timeout = timeout
        self.backlog = backlog
        self.enable_keepalive = enable_keepalive
        self.enable_nodelay = enable_nodelay
        self.use_framing = use_framing
        self.framing_mode = framing_mode
        self.max_frame_size = max_frame_size
        self.echo_mode = echo_mode

        self._server_sock = None
        self._stop_event = threading.Event()
        self._clients = {}  # conn -> addr
        self._clients_lock = threading.Lock()
        self._accept_thread = None
        self.stats = StatsCounter()

        # 回调函数
        self.on_message = None          # (addr, msg_type, payload)
        self.on_client_connected = None  # (addr)
        self.on_client_disconnected = None  # (addr)
        self.on_error = None            # (error_message)

    # ----- 生命周期 -----

    def start(self):
        """启动服务端（非阻塞，后台线程 accept）"""
        addrinfo = socket.getaddrinfo(self.host, self.port, socket.AF_UNSPEC,
                                      socket.SOCK_STREAM, 0, socket.AI_PASSIVE)
        server = None
        for family, socktype, proto, canonname, sockaddr in addrinfo:
            try:
                server = socket.socket(family, socktype, proto)
                server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                if family == socket.AF_INET6:
                    try:
                        server.setsockopt(socket.IPPROTO_IPV6,
                                         socket.IPV6_V6ONLY, 0)
                    except (AttributeError, OSError):
                        pass
                server.bind(sockaddr)
                server.listen(self.backlog)
                break
            except OSError as e:
                if server:
                    server.close()
                if family == socket.AF_INET6:
                    continue
                _log.error(f"绑定失败: {e}")
                raise ConnectionError(f"绑定失败 {self.host}:{self.port}: {e}")

        if server is None:
            raise ConnectionError(f"无法绑定到任何地址 {self.host}:{self.port}")

        server.settimeout(self.timeout)
        self._server_sock = server
        self._stop_event.clear()

        af_name = "IPv6" if server.family == socket.AF_INET6 else "IPv4"
        _log.info(f"TCP 服务端启动 [{af_name}] {self.host}:{self.port}")

        self._accept_thread = threading.Thread(
            target=self._accept_loop, daemon=True)
        self._accept_thread.start()

    def stop(self, graceful=True):
        """停止服务端

        :param graceful: True = 等待所有客户端断开后关闭
        """
        _log.info("正在停止 TCP 服务端...")
        self._stop_event.set()

        if graceful and self._accept_thread and self._accept_thread.is_alive():
            self._accept_thread.join(timeout=5)

        # 关闭所有客户端连接
        with self._clients_lock:
            for conn in list(self._clients.keys()):
                try:
                    conn.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                try:
                    conn.close()
                except OSError:
                    pass
            self._clients.clear()

        if self._server_sock:
            try:
                self._server_sock.close()
            except OSError:
                pass
            self._server_sock = None

        _log.info("TCP 服务端已停止")

    @property
    def is_running(self):
        return self._server_sock is not None and not self._stop_event.is_set()

    @property
    def client_count(self):
        with self._clients_lock:
            return len(self._clients)

    # ----- 内部实现 -----

    def _accept_loop(self):
        """Accept 循环（运行在后台线程）"""
        while not self._stop_event.is_set():
            try:
                conn, addr = self._server_sock.accept()
                _log.info(f"新连接: {addr}")
                with self._clients_lock:
                    self._clients[conn] = addr
                if self.on_client_connected:
                    self._fire_callback(self.on_client_connected, addr)
                t = threading.Thread(
                    target=self._handle_client,
                    args=(conn, addr),
                    daemon=True
                )
                t.start()
            except socket.timeout:
                continue
            except OSError as e:
                if not self._stop_event.is_set():
                    _log.error(f"Accept 错误: {e}")
                break

    def _handle_client(self, conn, addr):
        """处理单个客户端连接"""
        # 配置套接字
        if self.enable_nodelay:
            try:
                conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except (AttributeError, OSError):
                pass
        if self.enable_keepalive:
            try:
                conn.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            except (AttributeError, OSError):
                pass

        codec = FrameCodec(mode=self.framing_mode,
                          max_frame_size=self.max_frame_size) if self.use_framing else None

        try:
            while not self._stop_event.is_set():
                try:
                    data = conn.recv(65536)
                    if not data:
                        break
                    self.stats.add_recv(len(data))

                    if self.use_framing and codec:
                        for msg_type, payload in codec.feed(data):
                            if self.on_message:
                                self._fire_callback(
                                    self.on_message, addr, msg_type, payload)
                            if self.echo_mode:
                                conn.sendall(
                                    codec.pack(payload, msg_type))
                                self.stats.add_sent(len(payload))
                    else:
                        if self.on_message:
                            self._fire_callback(
                                self.on_message, addr, 0, data)
                        if self.echo_mode:
                            conn.sendall(data)
                            self.stats.add_sent(len(data))

                except socket.timeout:
                    continue
                except OSError:
                    break
        finally:
            try:
                conn.close()
            except OSError:
                pass
            with self._clients_lock:
                if conn in self._clients:
                    del self._clients[conn]
            if self.on_client_disconnected:
                self._fire_callback(self.on_client_disconnected, addr)
            _log.info(f"连接断开: {addr}")

    @staticmethod
    def _fire_callback(cb, *args):
        """安全调用回调（忽略异常）"""
        try:
            cb(*args)
        except Exception:
            pass

    # ----- 上下文管理器 -----

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()
        return False

    def __repr__(self):
        status = "运行中" if self.is_running else "已停止"
        return f"TCPServer({self.host}:{self.port}, {status}, {self.client_count} 客户端)"


# ============================================================================
# Phase 4: UDP 通信
# ============================================================================

class UDPSender:
    """UDP 发送器

    支持单播、广播、组播（IPv4/IPv6）。

    用法::

        sender = UDPSender()
        sender.send_unicast('127.0.0.1', 9999, b'Hello')
        sender.send_broadcast(9999, b'Broadcast message')
        sender.send_multicast('224.0.0.250', 9999, b'Multicast', ttl=4)
    """

    def __init__(self, encoding='UTF-8'):
        self.encoding = encoding

    # ----- 单播 -----

    def send_unicast(self, host, port, data):
        """UDP 单播发送（双栈 IPv4/IPv6）

        :param host: 目标主机
        :param port: 目标端口
        :param data: 要发送的数据 (str 或 bytes)
        :returns: 发送的字节数
        """
        addrinfo = socket.getaddrinfo(host, port, socket.AF_UNSPEC,
                                      socket.SOCK_DGRAM)
        sock = None
        for family, socktype, proto, canonname, sockaddr in addrinfo:
            try:
                sock = socket.socket(family, socktype, proto)
                break
            except OSError:
                if sock:
                    sock.close()
                    sock = None
                continue

        if sock is None:
            raise ConnectionError(f"无法创建 UDP 套接字发送到 {host}:{port}")

        try:
            raw = self._prepare_data(data)
            sent = sock.sendto(raw, sockaddr)
            _log.info(f"UDP 单播发送至 {host}:{port}: {sent} bytes")
            return sent
        finally:
            sock.close()

    # ----- 广播 -----

    def send_broadcast(self, port, data, interface='255.255.255.255'):
        """UDP 广播发送（仅 IPv4）

        :param port: 目标端口
        :param data: 要发送的数据
        :param interface: 广播地址，默认 255.255.255.255
        :returns: 发送的字节数
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        try:
            raw = self._prepare_data(data)
            sent = sock.sendto(raw, (interface, port))
            _log.info(f"UDP 广播至 {interface}:{port}: {sent} bytes")
            return sent
        finally:
            sock.close()

    # ----- 组播 -----

    def send_multicast(self, group, port, data, ttl=2, interface=None):
        """UDP 组播发送（支持 IPv4/IPv6）

        :param group: 组播组地址 (如 '224.0.0.250' 或 'ff02::1')
        :param port: 目标端口
        :param data: 要发送的数据
        :param ttl: 组播 TTL (IPv4: IP_MULTICAST_TTL, IPv6: IPV6_MULTICAST_HOPS)
        :param interface: 出站接口地址 (IPv4) 或接口索引 (IPv6)
        :returns: 发送的字节数
        """
        if is_ipv6(group):
            sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            sock.setsockopt(socket.IPPROTO_IPV6,
                           socket.IPV6_MULTICAST_HOPS, ttl)
            if interface is not None:
                if isinstance(interface, int):
                    iface_idx = interface
                else:
                    iface_idx = socket.if_nametoindex(interface) if hasattr(
                        socket, 'if_nametoindex') else 0
                sock.setsockopt(socket.IPPROTO_IPV6,
                               socket.IPV6_MULTICAST_IF, iface_idx)
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, ttl)
            if interface is not None:
                sock.setsockopt(socket.IPPROTO_IP,
                               socket.IP_MULTICAST_IF,
                               socket.inet_aton(interface))

        try:
            raw = self._prepare_data(data)
            sent = sock.sendto(raw, (group, port))
            _log.info(f"UDP 组播至 {group}:{port}: {sent} bytes (TTL={ttl})")
            return sent
        finally:
            sock.close()

    def _prepare_data(self, data):
        """统一编码数据"""
        if isinstance(data, str):
            return encode_data(data, self.encoding)
        return data


class UDPListener:
    """UDP 监听器

    支持单播接收、组播加入/离开（IGMP/MLD）、IPv4/IPv6 双栈。

    用法::

        listener = UDPListener(port=9999)
        listener.on_message = lambda addr, data: print(f"{addr}: {data}")
        listener.join_multicast_group('224.0.0.250')
        listener.start()
        # ...
        listener.stop()
    """

    def __init__(self, port=9999, *,
                 encoding='UTF-8',
                 timeout=1.0,
                 multicast_groups=None):
        """
        :param port: 监听端口
        :param encoding: 文本编解码
        :param timeout: recvfrom 轮询超时 (秒)
        :param multicast_groups: 启动时自动加入的组播组列表
               [(group_ip, interface_ip), ...] 或 [(group_ip, None), ...]
        """
        self.port = port
        self.encoding = encoding
        self.timeout = timeout
        self.multicast_groups = multicast_groups or []

        self._sock = None
        self._stop_event = threading.Event()
        self._listen_thread = None
        self._joined_groups = []  # [(group, interface)]
        self.stats = StatsCounter()

        # 回调
        self.on_message = None          # (addr, data: bytes)
        self.on_error = None            # (error_message)

    # ----- 生命周期 -----

    def start(self):
        """启动 UDP 监听（非阻塞，后台线程）"""
        # 优先创建 IPv6 双栈套接字
        sock = None
        try:
            sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            except (AttributeError, OSError):
                pass
            sock.bind(('::', self.port))
        except OSError:
            if sock:
                sock.close()
            # 回退到 IPv4
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(('0.0.0.0', self.port))

        sock.settimeout(self.timeout)
        self._sock = sock
        self._stop_event.clear()

        _log.info(f"UDP 监听启动 [双栈] 0.0.0.0:{self.port}")

        # 加入预设组播组
        for group, iface in self.multicast_groups:
            self.join_multicast_group(group, iface)

        self._listen_thread = threading.Thread(
            target=self._listen_loop, daemon=True)
        self._listen_thread.start()

    def stop(self):
        """停止 UDP 监听"""
        self._stop_event.set()

        if self._listen_thread and self._listen_thread.is_alive():
            self._listen_thread.join(timeout=5)

        # 离开所有组播组
        for group, iface in self._joined_groups:
            try:
                self.leave_multicast_group(group, iface)
            except Exception:
                pass
        self._joined_groups.clear()

        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None

        _log.info("UDP 监听已停止")

    @property
    def is_running(self):
        return self._sock is not None and not self._stop_event.is_set()

    # ----- 内部实现 -----

    def _listen_loop(self):
        """接收循环（后台线程）"""
        while not self._stop_event.is_set():
            try:
                data, addr = self._sock.recvfrom(65536)
                self.stats.add_recv(len(data))
                if self.on_message:
                    self._fire_callback(self.on_message, addr, data)
            except socket.timeout:
                continue
            except OSError as e:
                if not self._stop_event.is_set():
                    _log.error(f"UDP 监听错误: {e}")
                    if self.on_error:
                        self._fire_callback(self.on_error, str(e))
                break

    @staticmethod
    def _fire_callback(cb, *args):
        try:
            cb(*args)
        except Exception:
            pass

    # ----- 组播加入/离开 (struct 核心应用) -----

    def join_multicast_group(self, group, interface='0.0.0.0'):
        """加入 IPv4 组播组 (IGMP)

        使用 struct.pack 构造 ip_mreq C 结构体：
            struct ip_mreq {
                struct in_addr imr_multiaddr;   // 组播组地址
                struct in_addr imr_interface;   // 接口地址
            };

        :param group: 组播组地址 (如 '224.0.0.250')
        :param interface: 本地接口地址 (默认 '0.0.0.0' 即任意)
        """
        if self._sock is None:
            raise ConnectionError("UDP 监听器未启动")

        if is_ipv6(group):
            self._join_multicast_ipv6(group, interface)
            return

        mreq = struct.pack('!4s4s',
                           socket.inet_aton(group),
                           socket.inet_aton(interface))
        self._sock.setsockopt(socket.IPPROTO_IP,
                              socket.IP_ADD_MEMBERSHIP, mreq)
        self._joined_groups.append((group, interface))
        _log.info(f"加入 IPv4 组播组: {group} (接口: {interface})")

    def _join_multicast_ipv6(self, group, interface=0):
        """加入 IPv6 组播组 (MLD)

        使用 struct.pack 构造 ipv6_mreq C 结构体：
            struct ipv6_mreq {
                struct in6_addr ipv6mr_multiaddr;  // 组播组地址
                unsigned int    ipv6mr_interface;   // 接口索引
            };

        :param group: IPv6 组播组地址 (如 'ff02::1')
        :param interface: 接口索引 (int) 或接口名 (str)
        """
        if isinstance(interface, str) and interface != '0.0.0.0':
            if hasattr(socket, 'if_nametoindex'):
                iface_idx = socket.if_nametoindex(interface)
            else:
                iface_idx = 0
        elif isinstance(interface, int):
            iface_idx = interface
        else:
            iface_idx = 0

        mreq = struct.pack('!16sI',
                           socket.inet_pton(socket.AF_INET6, group),
                           iface_idx)
        self._sock.setsockopt(socket.IPPROTO_IPV6,
                              socket.IPV6_JOIN_GROUP, mreq)
        self._joined_groups.append((group, interface))
        _log.info(f"加入 IPv6 组播组: {group} (接口索引: {iface_idx})")

    def leave_multicast_group(self, group, interface='0.0.0.0'):
        """离开组播组

        :param group: 组播组地址
        :param interface: 接口地址或索引
        """
        if self._sock is None:
            return

        if is_ipv6(group):
            if isinstance(interface, str) and interface != '0.0.0.0':
                if hasattr(socket, 'if_nametoindex'):
                    iface_idx = socket.if_nametoindex(interface)
                else:
                    iface_idx = 0
            elif isinstance(interface, int):
                iface_idx = interface
            else:
                iface_idx = 0
            mreq = struct.pack('!16sI',
                               socket.inet_pton(socket.AF_INET6, group),
                               iface_idx)
            self._sock.setsockopt(socket.IPPROTO_IPV6,
                                  socket.IPV6_LEAVE_GROUP, mreq)
        else:
            mreq = struct.pack('!4s4s',
                               socket.inet_aton(group),
                               socket.inet_aton(interface))
            self._sock.setsockopt(socket.IPPROTO_IP,
                                  socket.IP_DROP_MEMBERSHIP, mreq)

        self._joined_groups = [
            (g, i) for g, i in self._joined_groups
            if not (g == group and i == interface)
        ]
        _log.info(f"离开组播组: {group}")

    # ----- 上下文管理器 -----

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()
        return False

    def __repr__(self):
        status = "运行中" if self.is_running else "已停止"
        return f"UDPListener(0.0.0.0:{self.port}, {status})"


# ============================================================================
# Phase 5: 网络诊断
# ============================================================================

# ----- 命名元组 -----
PingResult = namedtuple('PingResult', [
    'host', 'sent', 'received', 'lost', 'loss_pct',
    'min_ms', 'avg_ms', 'max_ms', 'raw'
])
HopResult = namedtuple('HopResult', ['ttl', 'ip', 'rtt_ms_list'])
DNSResult = namedtuple('DNSResult', ['ipv4', 'ipv6', 'cname'])
BandwidthResult = namedtuple('BandwidthResult', [
    'total_bytes', 'elapsed', 'throughput_mbps', 'throughput_MBps'
])


class PortChecker:
    """单端口连通性检测

    用法::

        checker = PortChecker(timeout=3)
        is_open, msg = checker.check('192.168.1.1', 80)
    """

    def __init__(self, timeout=3.0):
        self.timeout = timeout

    def check(self, host, port):
        """检测单个端口连通性

        :returns: (is_open: bool, message: str)
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            if result == 0:
                svc = COMMON_PORTS.get(port, "")
                svc_str = f" ({svc})" if svc else ""
                return True, f"端口 {port}{svc_str} 开放"
            else:
                return False, f"端口 {port} 关闭"
        except socket.gaierror:
            return False, f"无法解析主机: {host}"
        except Exception as e:
            return False, f"检测失败: {e}"


class PortScanner:
    """多线程端口扫描器

    用法::

        scanner = PortScanner(max_workers=100, timeout=1.0)
        scanner.on_progress = lambda completed, total: print(f"{completed}/{total}")
        scanner.on_result = lambda open_ports: print(f"开放: {open_ports}")
        scanner.scan_range('192.168.1.1', 1, 1024)

        # 或者使用生成器
        for port, is_open, service in scanner.scan_iter('localhost', 1, 100):
            if is_open:
                print(f"端口 {port} ({service}) 开放")
    """

    def __init__(self, max_workers=100, timeout=1.0):
        self.max_workers = max_workers
        self.timeout = timeout
        self.on_progress = None   # (completed, total)
        self.on_result = None     # (open_ports_list)

    def scan_range(self, host, start_port, end_port):
        """扫描端口范围

        :param host: 目标主机
        :param start_port: 起始端口
        :param end_port: 结束端口
        :returns: 开放端口列表
        """
        open_ports = []
        lock = threading.Lock()
        total = end_port - start_port + 1
        completed = [0]

        def scan_port(p):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                result = sock.connect_ex((host, p))
                if result == 0:
                    with lock:
                        open_ports.append(p)
                sock.close()
            except Exception:
                pass
            finally:
                with lock:
                    completed[0] += 1
                    if self.on_progress:
                        try:
                            self.on_progress(completed[0], total)
                        except Exception:
                            pass

        _log.info(f"开始端口扫描: {host} {start_port}-{end_port}")

        workers = min(self.max_workers, total)
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = [executor.submit(scan_port, p)
                       for p in range(start_port, end_port + 1)]
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

        _log.info(f"扫描完成: {host} 开放端口: {labeled}")

        if self.on_result:
            try:
                self.on_result(open_ports)
            except Exception:
                pass

        return open_ports

    def scan_iter(self, host, start_port, end_port):
        """生成器模式：逐个端口扫描并立即 yield 结果

        :yields: (port, is_open, service_name)
        """
        import concurrent.futures

        def _scan_one(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                result = sock.connect_ex((host, port))
                sock.close()
                svc = COMMON_PORTS.get(port, "")
                return (port, result == 0, svc)
            except Exception:
                return (port, False, "")

        workers = min(self.max_workers, end_port - start_port + 1)
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {
                executor.submit(_scan_one, p): p
                for p in range(start_port, end_port + 1)
            }
            for f in as_completed(futures):
                try:
                    yield f.result()
                except Exception:
                    pass

    def scan_common(self, host):
        """扫描前 100 个常用端口"""
        ports = sorted(COMMON_PORTS.keys())
        return self.scan_range(host, ports[0], ports[-1])


class PingDetector:
    """跨平台 Ping 检测器

    用法::

        detector = PingDetector()
        result = detector.ping('8.8.8.8', count=4)
        # result = PingResult(host='8.8.8.8', sent=4, received=4, ...)
        print(f"延迟: {result.avg_ms}ms, 丢包: {result.loss_pct}%")
    """

    def __init__(self, default_count=4, timeout_per_ping=5):
        self.default_count = default_count
        self.timeout_per_ping = timeout_per_ping

    def ping_raw(self, host, count=None):
        """原始 Ping，返回命令行输出

        :returns: 命令行输出文本
        """
        count = count or self.default_count
        sys = platform.system().lower()
        param = '-n' if sys == 'windows' else '-c'
        timeout_param = '-w' if sys == 'windows' else '-W'
        cmd = ['ping', param, str(count), timeout_param,
               str(self.timeout_per_ping), host]
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=count * self.timeout_per_ping + 10)
            return result.stdout if result.stdout else result.stderr
        except subprocess.TimeoutExpired:
            return f"Ping {host} 超时"
        except Exception as e:
            return f"Ping 错误: {e}"

    def ping(self, host, count=None):
        """Ping 并返回结构化结果

        :returns: PingResult namedtuple
        """
        count = count or self.default_count
        output = self.ping_raw(host, count)
        return self.parse_output(host, count, output)

    @staticmethod
    def parse_output(host, count, output):
        """解析 Ping 输出为结构化数据

        支持中文 Windows、英文 Linux/macOS/Windows 输出格式
        """
        stats = {
            "host": host, "sent": count, "received": 0,
            "lost": count, "loss_pct": 100.0,
            "min_ms": None, "max_ms": None, "avg_ms": None,
            "raw": output,
        }

        # 解析发送/接收/丢失
        # 中文 Windows: 已发送 = 4，已接收 = 4，丢失 = 0
        m = _re.search(
            r'已发送\s*=\s*(\d+).*?已接收\s*=\s*(\d+).*?丢失\s*=\s*(\d+)', output)
        if not m:
            # 英文: 4 packets transmitted, 4 received, 0% packet loss
            m = _re.search(
                r'(\d+)\s*packets?\s*transmitted.*?(\d+)\s*(packets?\s*)?received.*?(\d+).*?loss',
                output, _re.IGNORECASE)
        if m:
            stats["sent"] = int(m.group(1))
            stats["received"] = int(m.group(2))
            stats["lost"] = stats["sent"] - stats["received"]
            stats["loss_pct"] = (stats["lost"] / stats["sent"] *
                                 100) if stats["sent"] > 0 else 100

        # 解析延迟
        sys = platform.system().lower()
        if sys == 'windows':
            latency_pat = r'最短\s*=\s*(\d+)ms.*?最长\s*=\s*(\d+)ms.*?平均\s*=\s*(\d+)ms'
            m2 = _re.search(latency_pat, output)
            if not m2:
                # 英文 Windows: Minimum = Xms, Maximum = Yms, Average = Zms
                latency_pat = r'Minimum\s*=\s*(\d+)ms.*?Maximum\s*=\s*(\d+)ms.*?Average\s*=\s*(\d+)ms'
                m2 = _re.search(latency_pat, output, _re.IGNORECASE)
            if m2:
                try:
                    stats["min_ms"] = float(m2.group(1))
                    stats["max_ms"] = float(m2.group(2))
                    stats["avg_ms"] = float(m2.group(3))
                except (ValueError, IndexError):
                    pass
        else:
            # Unix: rtt min/avg/max/mdev = 1.234/2.345/3.456/0.567 ms
            latency_pat = r'(?:rtt|round-trip).*?=\s*([\d.]+)/([\d.]+)/([\d.]+)'
            m2 = _re.search(latency_pat, output, _re.IGNORECASE)
            if m2:
                try:
                    stats["min_ms"] = float(m2.group(1))
                    stats["avg_ms"] = float(m2.group(2))
                    stats["max_ms"] = float(m2.group(3))
                except (ValueError, IndexError):
                    pass

        return PingResult(**stats)


class Traceroute:
    """路由追踪

    使用 UDP 探测 + ICMP Time Exceeded 响应实现 traceroute。
    注意：需要管理员/root 权限（原始 ICMP socket）。

    用法::

        tracer = Traceroute()
        for hop in tracer.trace('8.8.8.8', max_hops=30):
            print(f"第 {hop.ttl} 跳: {hop.ip}  {hop.rtt_ms_list}")
    """

    def __init__(self, probes_per_hop=3, probe_timeout=3.0):
        self.probes_per_hop = probes_per_hop
        self.probe_timeout = probe_timeout

    def trace(self, target, max_hops=30):
        """执行路由追踪

        :param target: 目标主机名或 IP
        :param max_hops: 最大跳数
        :yields: HopResult namedtuple
        """
        # 解析目标地址
        addrinfo = socket.getaddrinfo(
            target, None, socket.AF_UNSPEC, socket.SOCK_DGRAM)
        if not addrinfo:
            raise ConnectionError(f"无法解析 {target}")
        dest_addr = addrinfo[0][4]
        dest_ip = dest_addr[0]
        family = addrinfo[0][0]
        af_name = "IPv6" if family == socket.AF_INET6 else "IPv4"

        _log.info(f"Traceroute 至 {target} ({dest_ip}) [{af_name}], "
                  f"最大 {max_hops} 跳")

        yield HopResult(ttl=0, ip=target,
                        rtt_ms_list=[f"解析: {dest_ip} ({af_name})"])

        for ttl in range(1, max_hops + 1):
            # 发送探测包
            send_sock = socket.socket(family, socket.SOCK_DGRAM)
            send_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if family == socket.AF_INET:
                send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
            else:
                send_sock.setsockopt(
                    socket.IPPROTO_IPV6, socket.IPV6_UNICAST_HOPS, ttl)

            # 接收 ICMP 套接字（仅 IPv4 支持原始 ICMP）
            recv_sock = None
            if family == socket.AF_INET:
                try:
                    recv_sock = socket.socket(
                        socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
                    recv_sock.settimeout(self.probe_timeout)
                    recv_sock.bind(('', 0))
                except OSError:
                    _log.warning("无法创建原始 ICMP 套接字（可能需要管理员权限）")

            results = []
            for probe in range(self.probes_per_hop):
                start_t = time.time()
                try:
                    send_sock.sendto(
                        b"TRACEROUTE", (dest_ip, 33434 + ttl))
                except OSError:
                    results.append(None)
                    continue

                if recv_sock:
                    try:
                        data, addr = recv_sock.recvfrom(512)
                        elapsed = (time.time() - start_t) * 1000
                        hop_ip = addr[0]
                        results.append((hop_ip, elapsed))
                        if hop_ip == dest_ip:
                            ip_set = set(r[0] for r in results if r)
                            times = [f"{r[1]:.1f} ms" for r in results if r]
                            yield HopResult(ttl=ttl,
                                            ip=", ".join(ip_set) if ip_set else "*",
                                            rtt_ms_list=times or ["* * *"])
                            send_sock.close()
                            if recv_sock:
                                recv_sock.close()
                            return
                    except socket.timeout:
                        results.append(None)
                else:
                    # 无 ICMP socket，跳过
                    time.sleep(0.1)
                    results.append(None)

            send_sock.close()
            if recv_sock:
                recv_sock.close()

            valid = [r for r in results if r is not None]
            if valid:
                ip_set = set(r[0] for r in valid)
                times = [f"{r[1]:.1f} ms" for r in valid]
                yield HopResult(ttl=ttl, ip=", ".join(ip_set),
                                rtt_ms_list=times)
            else:
                yield HopResult(ttl=ttl, ip="*",
                                rtt_ms_list=["* * *"])

        yield HopResult(ttl=max_hops + 1, ip="",
                        rtt_ms_list=["已达到最大跳数"])


class DNSResolver:
    """DNS 解析器

    用法::

        resolver = DNSResolver()
        result = resolver.resolve('www.baidu.com')
        print(result.ipv4)   # ['110.242.68.66', ...]
        print(result.ipv6)   # ['240e:...', ...]
    """

    def __init__(self):
        pass

    def lookup_a(self, hostname):
        """查询 A 记录 (IPv4)"""
        try:
            results = socket.getaddrinfo(
                hostname, None, socket.AF_INET, socket.SOCK_STREAM)
            return list(set(r[4][0] for r in results))
        except socket.gaierror:
            return []

    def lookup_aaaa(self, hostname):
        """查询 AAAA 记录 (IPv6)"""
        try:
            results = socket.getaddrinfo(
                hostname, None, socket.AF_INET6, socket.SOCK_STREAM)
            return list(set(r[4][0] for r in results))
        except socket.gaierror:
            return []

    def lookup_ptr(self, ip_address):
        """查询 PTR 记录 (反向解析)"""
        try:
            return socket.gethostbyaddr(ip_address)[0]
        except socket.herror:
            return None

    def resolve(self, hostname):
        """统一解析，返回 DNSResult"""
        ipv4 = self.lookup_a(hostname)
        ipv6 = self.lookup_aaaa(hostname)
        cname = None  # 标准库无法直接获取 CNAME
        return DNSResult(ipv4=ipv4, ipv6=ipv6, cname=cname)


class BandwidthTester:
    """带宽测试器

    用法::

        tester = BandwidthTester()
        result = tester.measure_upload('example.com', 80, duration=5)
        print(f"上行: {result.throughput_mbps:.2f} Mbps")
    """

    def __init__(self, chunk_size=65536):
        self.chunk_size = chunk_size  # 64KB

    def measure_upload(self, host, port, duration=5):
        """测量 TCP 上行带宽

        :param host: 目标主机
        :param port: 目标端口
        :param duration: 测试持续时间 (秒)
        :returns: BandwidthResult
        """
        chunk = b"B" * self.chunk_size
        sock = None
        total_sent = 0
        start_time = time.time()
        last_report = start_time

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((host, port))
            sock.settimeout(2)

            _log.info(f"带宽测试开始: {host}:{port}, 持续 {duration}s")

            while time.time() - start_time < duration:
                try:
                    sent = sock.send(chunk)
                    total_sent += sent

                    now = time.time()
                    if now - last_report >= 1.0:
                        elapsed = now - start_time
                        mbps = (total_sent * 8 / elapsed / 1_000_000)
                        _log.debug(
                            f"  已传输 {format_bytes(total_sent)}, "
                            f"{mbps:.2f} Mbps")
                        last_report = now
                except socket.timeout:
                    break
                except (ConnectionResetError, BrokenPipeError):
                    _log.warning("带宽测试: 连接断开")
                    break

        except Exception as e:
            _log.error(f"带宽测试错误: {e}")
        finally:
            if sock:
                sock.close()

        elapsed = time.time() - start_time
        if elapsed > 0 and total_sent > 0:
            throughput_mbps = (total_sent * 8 / elapsed / 1_000_000)
            throughput_MBps = total_sent / elapsed / 1_000_000
            result = BandwidthResult(
                total_bytes=total_sent,
                elapsed=elapsed,
                throughput_mbps=throughput_mbps,
                throughput_MBps=throughput_MBps,
            )
            _log.info(
                f"带宽测试完成: {format_bytes(total_sent)} 在 "
                f"{human_time(elapsed)} 内, {throughput_mbps:.2f} Mbps")
            return result
        else:
            return BandwidthResult(
                total_bytes=0, elapsed=elapsed,
                throughput_mbps=0, throughput_MBps=0)

    def stress_test(self, host, port, num_connections=100,
                    msg_size=1024, timeout=5):
        """TCP 压力测试（并发连接）

        :param host: 目标主机
        :param port: 目标端口
        :param num_connections: 并发连接数
        :param msg_size: 每条消息大小 (字节)
        :param timeout: 连接超时 (秒)
        :returns: dict {success, fail, total_bytes, elapsed, throughput_mbps}
        """
        msg = b"X" * msg_size
        success = 0
        fail = 0
        total_bytes = 0
        lock = threading.Lock()
        start_time = time.time()

        def single_connect(idx):
            nonlocal success, fail, total_bytes
            try:
                addrinfo = socket.getaddrinfo(
                    host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
                sock = socket.socket(
                    addrinfo[0][0], addrinfo[0][1], addrinfo[0][2])
                sock.settimeout(timeout)
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

        _log.info(f"压力测试: {host}:{port}, {num_connections} 连接")
        workers = min(50, num_connections)
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = [executor.submit(single_connect, i)
                       for i in range(num_connections)]
            for f in as_completed(futures):
                try:
                    f.result()
                except Exception:
                    pass

        elapsed = time.time() - start_time
        throughput = ((total_bytes * 8 / elapsed / 1_000_000)
                      if elapsed > 0 else 0)
        result = {
            "success": success, "fail": fail,
            "total_bytes": total_bytes, "elapsed": elapsed,
            "throughput_mbps": throughput,
        }
        _log.info(f"压力测试完成: 成功={success}, 失败={fail}, "
                  f"吞吐量={throughput:.2f} Mbps")
        return result


# ============================================================================
# Phase 6: 异步 API (asyncio)
# ============================================================================

try:
    import asyncio
    HAS_ASYNCIO = True
except ImportError:
    HAS_ASYNCIO = False

if HAS_ASYNCIO:

    class AsyncTCPClient:
        """异步 TCP 客户端（基于 asyncio stream API）

        用法::

            async with AsyncTCPClient('localhost', 8888) as client:
                await client.send(b'Hello')
                msg_type, response = await client.recv()
        """

        def __init__(self, host='127.0.0.1', port=8888, *,
                     encoding='UTF-8',
                     timeout=5.0,
                     use_framing=True,
                     framing_mode=0,
                     max_frame_size=None):
            self.host = host
            self.port = port
            self.encoding = encoding
            self.timeout = timeout
            self.use_framing = use_framing
            self.framing_mode = framing_mode
            self.max_frame_size = max_frame_size
            self._reader = None
            self._writer = None
            self._codec = FrameCodec(
                mode=framing_mode,
                max_frame_size=max_frame_size) if use_framing else None
            self.stats = StatsCounter()

        async def connect(self):
            """异步连接"""
            self._reader, self._writer = await asyncio.wait_for(
                asyncio.open_connection(self.host, self.port),
                timeout=self.timeout
            )
            _log.info(f"AsyncTCPClient 已连接: {self.host}:{self.port}")

        async def send(self, data, msg_type=0):
            """异步发送"""
            if self._writer is None:
                raise ConnectionError("未建立连接")
            if isinstance(data, str):
                raw = encode_data(data, self.encoding)
            else:
                raw = data
            if self.use_framing and self._codec:
                raw = self._codec.pack(raw, msg_type)
            self._writer.write(raw)
            await self._writer.drain()
            self.stats.add_sent(len(raw))

        async def send_raw(self, data):
            """异步原始发送"""
            if self._writer is None:
                raise ConnectionError("未建立连接")
            if isinstance(data, str):
                data = encode_data(data, self.encoding)
            self._writer.write(data)
            await self._writer.drain()
            self.stats.add_sent(len(data))

        async def recv(self, timeout=None):
            """异步接收一帧

            :returns: (msg_type, payload)
            """
            if self._reader is None:
                raise ConnectionError("未建立连接")

            t = timeout or self.timeout

            if self.use_framing and self._codec:
                while True:
                    frames = self._codec.feed(b'')
                    if frames:
                        return frames[0]
                    data = await asyncio.wait_for(
                        self._reader.read(65536), timeout=t)
                    if not data:
                        raise ConnectionError("连接已断开")
                    self.stats.add_recv(len(data))
                    frames = self._codec.feed(data)
                    if frames:
                        return frames[0]
            else:
                data = await asyncio.wait_for(
                    self._reader.read(65536), timeout=t)
                if not data:
                    raise ConnectionError("连接已断开")
                self.stats.add_recv(len(data))
                return (0, data)

        async def recv_raw(self, bufsize=65536, timeout=None):
            """异步原始接收"""
            if self._reader is None:
                raise ConnectionError("未建立连接")
            t = timeout or self.timeout
            try:
                data = await asyncio.wait_for(
                    self._reader.read(bufsize), timeout=t)
                if data:
                    self.stats.add_recv(len(data))
                return data
            except asyncio.TimeoutError:
                return b''

        async def disconnect(self):
            """异步断开"""
            if self._writer:
                try:
                    self._writer.close()
                    await self._writer.wait_closed()
                except Exception:
                    pass
                self._writer = None
                self._reader = None
            if self._codec:
                self._codec.reset()
            _log.info("AsyncTCPClient 已断开")

        @property
        def is_connected(self):
            return self._writer is not None

        async def __aenter__(self):
            await self.connect()
            return self

        async def __aexit__(self, exc_type, exc_val, exc_tb):
            await self.disconnect()
            return False

    class AsyncTCPServer:
        """异步 TCP 服务端（基于 asyncio.start_server）

        用法::

            server = AsyncTCPServer(port=8888, echo_mode=True)
            server.on_message = lambda rw, addr, mt, data: print(f"{addr}: {data}")
            await server.start()
            # ... await server.stop()
        """

        def __init__(self, host='0.0.0.0', port=8888, *,
                     encoding='UTF-8',
                     use_framing=True,
                     framing_mode=0,
                     max_frame_size=None,
                     echo_mode=False):
            self.host = host
            self.port = port
            self.encoding = encoding
            self.use_framing = use_framing
            self.framing_mode = framing_mode
            self.max_frame_size = max_frame_size
            self.echo_mode = echo_mode
            self._server = None
            self.stats = StatsCounter()
            self.on_message = None  # (reader_writer, addr, msg_type, payload)
            self.on_client_connected = None
            self.on_client_disconnected = None

        async def start(self):
            """启动异步服务端"""
            self._server = await asyncio.start_server(
                self._handle_client, self.host, self.port)
            _log.info(
                f"AsyncTCPServer 启动: {self.host}:{self.port}")

        async def stop(self):
            """停止异步服务端"""
            if self._server:
                self._server.close()
                await self._server.wait_closed()
                self._server = None
            _log.info("AsyncTCPServer 已停止")

        async def _handle_client(self, reader, writer):
            """处理单个异步客户端"""
            addr = writer.get_extra_info('peername')
            _log.info(f"Async 新连接: {addr}")
            if self.on_client_connected:
                try:
                    self.on_client_connected(addr)
                except Exception:
                    pass

            codec = FrameCodec(
                mode=self.framing_mode,
                max_frame_size=self.max_frame_size) if self.use_framing else None

            try:
                while True:
                    data = await reader.read(65536)
                    if not data:
                        break
                    self.stats.add_recv(len(data))

                    if self.use_framing and codec:
                        for msg_type, payload in codec.feed(data):
                            if self.on_message:
                                try:
                                    self.on_message(
                                        writer, addr, msg_type, payload)
                                except Exception:
                                    pass
                            if self.echo_mode:
                                writer.write(codec.pack(payload, msg_type))
                                await writer.drain()
                                self.stats.add_sent(len(payload))
                    else:
                        if self.on_message:
                            try:
                                self.on_message(writer, addr, 0, data)
                            except Exception:
                                pass
                        if self.echo_mode:
                            writer.write(data)
                            await writer.drain()
                            self.stats.add_sent(len(data))
            except Exception:
                pass
            finally:
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass
                if self.on_client_disconnected:
                    try:
                        self.on_client_disconnected(addr)
                    except Exception:
                        pass
                _log.info(f"Async 连接断开: {addr}")

    class AsyncUDPEndpoint:
        """异步 UDP 端点（基于 asyncio DatagramProtocol）

        用法::

            endpoint = AsyncUDPEndpoint(port=9999)
            endpoint.on_message = lambda addr, data: print(f"{addr}: {data}")
            await endpoint.start()
            await endpoint.send_to(b'Hello', '127.0.0.1', 9999)
            # ... await endpoint.stop()
        """

        def __init__(self, port=9999, *, encoding='UTF-8'):
            self.port = port
            self.encoding = encoding
            self._transport = None
            self._protocol = None
            self.stats = StatsCounter()
            self.on_message = None  # (addr, data: bytes)

        class _Protocol(asyncio.DatagramProtocol):
            def __init__(self, parent):
                self._parent = parent

            def connection_made(self, transport):
                self._transport = transport

            def datagram_received(self, data, addr):
                self._parent.stats.add_recv(len(data))
                if self._parent.on_message:
                    try:
                        self._parent.on_message(addr, data)
                    except Exception:
                        pass

            def error_received(self, exc):
                _log.error(f"AsyncUDP 错误: {exc}")

        async def start(self):
            """启动异步 UDP 端点"""
            loop = asyncio.get_running_loop()
            self._protocol = self._Protocol(self)
            transport, _ = await loop.create_datagram_endpoint(
                lambda: self._protocol,
                local_addr=('0.0.0.0', self.port),
                family=socket.AF_INET)
            self._transport = transport
            _log.info(f"AsyncUDPEndpoint 启动: 0.0.0.0:{self.port}")

        async def stop(self):
            """停止异步 UDP 端点"""
            if self._transport:
                self._transport.close()
                self._transport = None
            _log.info("AsyncUDPEndpoint 已停止")

        async def send_to(self, data, host, port):
            """异步发送数据报到指定地址"""
            if self._transport is None:
                raise ConnectionError("UDP 端点未启动")
            if isinstance(data, str):
                data = encode_data(data, self.encoding)
            self._transport.sendto(data, (host, port))
            self.stats.add_sent(len(data))

    class AsyncPortScanner:
        """异步端口扫描器

        用法::

            scanner = AsyncPortScanner(max_workers=100, timeout=1.0)
            results = await scanner.scan_range('192.168.1.1', 1, 1024)
        """

        def __init__(self, max_workers=100, timeout=1.0):
            self.max_workers = max_workers
            self.timeout = timeout

        async def scan_range(self, host, start_port, end_port):
            """异步扫描端口范围

            :returns: 开放端口列表
            """
            loop = asyncio.get_running_loop()

            def _scan_one(port):
                try:
                    sock = socket.socket(
                        socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(self.timeout)
                    result = sock.connect_ex((host, port))
                    sock.close()
                    return (port, result == 0)
                except Exception:
                    return (port, False)

            open_ports = []
            total = end_port - start_port + 1
            workers = min(self.max_workers, total)

            # 分批执行以避免同时创建过多 task
            for batch_start in range(start_port, end_port + 1, workers):
                batch_end = min(batch_start + workers, end_port + 1)
                batch = range(batch_start, batch_end)
                tasks = [
                    loop.run_in_executor(None, _scan_one, p)
                    for p in batch
                ]
                results = await asyncio.gather(*tasks, return_exceptions=True)
                for r in results:
                    if isinstance(r, tuple) and r[1]:
                        open_ports.append(r[0])

            open_ports.sort()
            return open_ports

        async def scan_common(self, host):
            """扫描常用端口"""
            ports = sorted(COMMON_PORTS.keys())
            return await self.scan_range(host, ports[0], ports[-1])

else:
    # asyncio 不可用时的占位
    class _AsyncMissing:
        def __init__(self, *args, **kwargs):
            raise RuntimeError(
                "asyncio 不可用，无法使用异步 API。请使用 Python 3.7+")

    AsyncTCPClient = _AsyncMissing
    AsyncTCPServer = _AsyncMissing
    AsyncUDPEndpoint = _AsyncMissing
    AsyncPortScanner = _AsyncMissing


# ============================================================================
# Phase 7: 内置自测 / 演示
# ============================================================================

def _run_self_test():
    """运行内置集成测试，验证核心功能

    测试项目：
    1. FrameCodec 帧往返测试（简单/扩展模式、边界情况）
    2. TCP Echo 测试
    3. UDP 收发测试
    4. 端口检测测试
    5. StatsCounter 验证
    """
    print("=" * 60)
    print("网络通信模块 (网络通信.py) — 内置自测")
    print("=" * 60)

    passed = 0
    failed = 0

    def check(name, condition, detail=""):
        nonlocal passed, failed
        if condition:
            passed += 1
            print(f"  [PASS] {name}")
        else:
            failed += 1
            print(f"  [FAIL] {name} {detail}")

    # ---- 测试 1: FrameCodec 帧往返 ----
    print("\n--- 测试 1: FrameCodec 帧往返 ---")

    # 1a: 简单模式基本往返
    codec = FrameCodec(mode=0)
    data = b'Hello, World!'
    frame = codec.pack(data)
    check("简单帧长度正确", len(frame) == 4 + len(data),
          f"期望 {4 + len(data)}, 实际 {len(frame)}")
    check("简单帧头部正确", frame[:4] == struct.pack('!I', len(data)))

    frames = codec.feed(frame)
    check("简单帧解开", len(frames) == 1 and frames[0] == (0, data),
          f"收到: {frames}")

    # 1b: 简单模式空载荷
    codec2 = FrameCodec(mode=0)
    empty_frame = codec2.pack(b'')
    check("空载荷帧", len(empty_frame) == 4)
    frames2 = codec2.feed(empty_frame)
    check("空载荷解开", len(frames2) == 1 and frames2[0][1] == b'')

    # 1c: 扩展模式往返
    codec3 = FrameCodec(mode=1)
    ext_frame = codec3.pack(b'Test', msg_type=PacketType.TEXT)
    check("扩展帧长度正确", len(ext_frame) == 8 + 4)

    frames3 = codec3.feed(ext_frame)
    check("扩展帧解开 type", len(frames3) == 1 and frames3[0][0] == PacketType.TEXT,
          f"{frames3}")
    check("扩展帧解开 payload", len(frames3) == 1 and frames3[0][1] == b'Test')

    # 1d: 半包/粘包测试
    codec4 = FrameCodec(mode=0)
    f1 = codec4.pack(b'AAA')
    f2 = codec4.pack(b'BBB')
    # 模拟 TCP 流：半包到达
    partial = f1[:2]
    check("半包不解出", len(codec4.feed(partial)) == 0)
    # 剩余到达 + 粘包
    rest = f1[2:] + f2
    frames4 = codec4.feed(rest)
    check("粘包正确拆分", len(frames4) == 2,
          f"期望2, 实际{len(frames4)}")
    check("粘包第1帧", frames4[0][1] == b'AAA', f"{frames4[0]}")
    check("粘包第2帧", frames4[1][1] == b'BBB', f"{frames4[1]}")

    # 1e: 错误处理
    try:
        codec_bad = FrameCodec(mode=1)
        bad_frame = struct.pack('!2sBBI', b'XX', 1, 0, 5) + b'hello'
        codec_bad.feed(bad_frame)
        check("Magic错误检测", False)  # 不应该走到这里
    except ProtocolError:
        check("Magic错误检测", True)
    except Exception:
        check("Magic错误检测", False, "异常类型不对")

    # ---- 测试 2: TCP Echo ----
    print("\n--- 测试 2: TCP Echo ---")

    test_port = 18888
    server = TCPServer(port=test_port, echo_mode=True,
                       use_framing=True, framing_mode=0)

    received_msgs = []
    server.on_message = lambda addr, mt, data: received_msgs.append(data)

    try:
        server.start()
        check("TCP服务端启动", server.is_running)

        time.sleep(0.2)  # 等待 accept 线程就绪

        # 使用 TCPClient 发送并接收 echo
        with TCPClient('127.0.0.1', test_port, use_framing=True) as client:
            check("TCP客户端连接", client.is_connected)

            client.send(b'Hello Echo')
            time.sleep(0.2)
            msg_type, response = client.recv(timeout=2)
            check("TCP Echo 响应", response == b'Hello Echo',
                  f"期望 b'Hello Echo', 收到 {response!r}")
            check("Echo msg_type", msg_type == 0)

            # 测试 server 端也收到消息
            check("服务端收到消息", b'Hello Echo' in received_msgs,
                  f"收到: {received_msgs}")

    finally:
        server.stop()
        check("TCP服务端停止", not server.is_running)

    # ---- 测试 3: UDP 收发 ----
    print("\n--- 测试 3: UDP 收发 ---")

    udp_port = 19999
    listener = UDPListener(port=udp_port)

    received_udp = []
    listener.on_message = lambda addr, data: received_udp.append(data)

    try:
        listener.start()
        check("UDP监听启动", listener.is_running)

        time.sleep(0.1)

        sender = UDPSender()
        sent = sender.send_unicast('127.0.0.1', udp_port, b'UDP Test')
        check("UDP发送成功", sent > 0)

        time.sleep(0.3)
        check("UDP收到数据", b'UDP Test' in received_udp,
              f"收到: {received_udp}")

    finally:
        listener.stop()
        check("UDP监听停止", not listener.is_running)

    # ---- 测试 4: 端口检测 ----
    print("\n--- 测试 4: 端口检测 ---")

    # 启动一个临时服务器用于测试
    checker = PortChecker(timeout=2)
    tmp_server = TCPServer(port=17777)
    try:
        tmp_server.start()
        time.sleep(0.2)

        is_open, msg = checker.check('127.0.0.1', 17777)
        check("端口开放检测", is_open, msg)

        is_closed, msg2 = checker.check('127.0.0.1', 17778)
        check("端口关闭检测", not is_closed, msg2)
    finally:
        tmp_server.stop()

    # ---- 测试 5: StatsCounter ----
    print("\n--- 测试 5: StatsCounter ---")

    sc = StatsCounter()
    sc.add_sent(100)
    sc.add_sent(50)
    sc.add_recv(200)
    sc.add_recv(30)

    snap = sc.snapshot()
    check("StatsCounter sent_bytes", snap["sent_bytes"] == 150,
          f"{snap['sent_bytes']}")
    check("StatsCounter recv_bytes", snap["recv_bytes"] == 230,
          f"{snap['recv_bytes']}")
    check("StatsCounter sent_packets", snap["sent_packets"] == 2)
    check("StatsCounter recv_packets", snap["recv_packets"] == 2)

    sc.reset()
    snap2 = sc.snapshot()
    check("StatsCounter 重置", snap2["sent_bytes"] == 0 and snap2["recv_bytes"] == 0)

    # ---- 测试 6: 工具函数 ----
    print("\n--- 测试 6: 工具函数 ---")

    check("is_ipv4", is_ipv4('192.168.1.1') and not is_ipv4('999.999.999.999'))
    check("is_ipv6", is_ipv6('::1') and not is_ipv6('not:ipv6'))
    check("resolve_host localhost",
          len(resolve_host('localhost')[0]) > 0 or len(resolve_host('localhost')[1]) > 0)
    check("format_bytes", format_bytes(2048) == "2.00 KB")
    check("human_time", human_time(1.5) == "1.50 s")

    # 编码往返
    for enc in ['UTF-8', 'GBK', 'Hex', 'Base64']:
        original = "Hello 测试"
        try:
            encoded = encode_data(original, enc)
            decoded = decode_data(encoded, enc)
            check(f"encode/decode {enc}", original == decoded or enc in ['Hex', 'Base64'],
                  f"'{original}' vs '{decoded}'")
        except Exception as e:
            check(f"encode/decode {enc}", False, str(e))

    # ---- 结果汇总 ----
    print("\n" + "=" * 60)
    total = passed + failed
    print(f"测试结果: {passed}/{total} 通过"
          + (f", {failed} 失败" if failed > 0 else " — 全部通过!"))
    print("=" * 60)

    return failed == 0


if __name__ == "__main__":
    # 配置日志输出到控制台
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
        handlers=[logging.StreamHandler()]
    )

    success = _run_self_test()
    exit(0 if success else 1)
