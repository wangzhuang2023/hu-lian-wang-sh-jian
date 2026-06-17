#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
网络通信核心库
提供 TCP/UDP 网络通信、端口扫描、文件传输等核心功能。
纯 Python 实现，无 UI 依赖，可直接被其他脚本 import 使用。

用法示例:
    from netcore import NetworkCore, StatsCounter
    import threading

    stop = threading.Event()
    NetworkCore.tcp_server("0.0.0.0", 8888, stop, echo=True)
"""

import socket
import struct
import threading
import os
import time
import base64
import ipaddress
import hashlib
from typing import Optional, Callable, List, Tuple, Dict, Any
from concurrent.futures import ThreadPoolExecutor, as_completed

# ========================================================================
# 全局常量
# ========================================================================

COMMON_PORTS: Dict[int, str] = {
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

DEFAULT_ENCODINGS = ["UTF-8", "GBK", "ASCII", "Hex", "Base64"]

# 文件传输协议常量
_FILE_PROTO_FILESIZE_FMT = "!Q"       # 8 字节大端无符号长整型 (文件大小)
_FILE_PROTO_NAMELEN_FMT = "!H"        # 2 字节大端无符号短整型 (文件名长度)
_FILE_PROTO_HEADER_SIZE = 10          # 8 + 2 = 10 字节固定头部


# ========================================================================
# 工具函数
# ========================================================================

def is_ipv4(addr: str) -> bool:
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


def is_ipv6(addr: str) -> bool:
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


def is_valid_host(addr: str) -> bool:
    """统一验证：IPv4 / IPv6 / 域名均接受"""
    if is_ipv4(addr) or is_ipv6(addr):
        return True
    return bool(addr) and ' ' not in addr and len(addr) <= 253


def resolve_host(host: str) -> Tuple[List[str], List[str]]:
    """DNS 解析主机名，返回 (ipv4_list, ipv6_list)"""
    ipv4_list: List[str] = []
    ipv6_list: List[str] = []
    if is_ipv4(host):
        ipv4_list.append(host)
        return ipv4_list, ipv6_list
    if is_ipv6(host):
        ipv6_list.append(host)
        return ipv4_list, ipv6_list
    try:
        for family, _, _, _, sockaddr in socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM):
            ip = sockaddr[0]
            if family == socket.AF_INET and ip not in ipv4_list:
                ipv4_list.append(ip)
            elif family == socket.AF_INET6 and ip not in ipv6_list:
                ipv6_list.append(ip)
    except socket.gaierror:
        pass
    return ipv4_list, ipv6_list


def get_local_ip() -> str:
    """获取首选本机 IPv4 地址"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def get_all_local_ips() -> List[Dict[str, str]]:
    """获取本机所有网卡 IP 地址（含 IPv4/IPv6）"""
    interfaces: List[Dict[str, str]] = []
    try:
        hostname = socket.gethostname()
        for family_name, family in [("IPv4", socket.AF_INET), ("IPv6", socket.AF_INET6)]:
            try:
                for addr_info in socket.getaddrinfo(hostname, None, family, socket.SOCK_DGRAM):
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


def format_bytes(n: float) -> str:
    """字节数可读格式化"""
    if n < 0:
        return "0 B"
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if abs(n) < 1024.0:
            return f"{n:.2f} {unit}"
        n /= 1024.0
    return f"{n:.2f} PB"


def human_time(seconds: float) -> str:
    """耗时人类可读"""
    if seconds < 0.001:
        return f"{seconds * 1000000:.1f} μs"
    if seconds < 1:
        return f"{seconds * 1000:.1f} ms"
    if seconds < 60:
        return f"{seconds:.2f} s"
    m, s = divmod(seconds, 60)
    return f"{int(m)}m {s:.1f}s"


def encode_data(text: str, encoding: str) -> bytes:
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


def decode_data(data: bytes, encoding: str) -> str:
    """按指定编码将字节解码为文本"""
    if encoding == "Hex":
        return data.hex()
    elif encoding == "Base64":
        return base64.b64encode(data).decode()
    else:
        return data.decode(encoding, errors='replace')


def validate_port(port_str: str) -> int:
    """校验端口号字符串，返回整数端口号。无效时抛出 ValueError。"""
    try:
        port = int(port_str)
    except (ValueError, TypeError):
        raise ValueError(f"无效的端口号: {port_str}")
    if port < 1 or port > 65535:
        raise ValueError(f"端口号超出范围 (1-65535): {port}")
    return port


# ========================================================================
# 文件传输协议辅助函数
# ========================================================================

def pack_file_header(filename: str, filesize: int) -> bytes:
    """打包文件传输头部：[8B filesize][2B name_len][filename UTF-8]"""
    name_bytes = filename.encode('utf-8')
    header = struct.pack(_FILE_PROTO_FILESIZE_FMT, filesize)
    header += struct.pack(_FILE_PROTO_NAMELEN_FMT, len(name_bytes))
    header += name_bytes
    return header


def unpack_file_header(sock: socket.socket) -> Tuple[str, int]:
    """
    从套接字读取并解包文件传输头部。
    返回 (filename, filesize)。
    读取失败时抛出异常。
    """
    # 先读取固定 10 字节头部
    header_data = b""
    while len(header_data) < _FILE_PROTO_HEADER_SIZE:
        chunk = sock.recv(_FILE_PROTO_HEADER_SIZE - len(header_data))
        if not chunk:
            raise ConnectionError("连接在接收文件头部前关闭")
        header_data += chunk

    filesize = struct.unpack(_FILE_PROTO_FILESIZE_FMT, header_data[:8])[0]
    name_len = struct.unpack(_FILE_PROTO_NAMELEN_FMT, header_data[8:10])[0]

    # 读取文件名
    name_data = b""
    while len(name_data) < name_len:
        chunk = sock.recv(name_len - len(name_data))
        if not chunk:
            raise ConnectionError("连接在接收文件名前关闭")
        name_data += chunk

    filename = name_data.decode('utf-8', errors='replace')
    # 安全化文件名：移除路径分隔符
    filename = os.path.basename(filename) or "received_file"
    return filename, filesize


# ========================================================================
# 数据报文协议 (Datagram Protocol) 辅助函数
# ========================================================================

# 报文格式:
#   [2B magic 0xD46D][1B ver][1B flags][4B seq][2B total_frags]
#   [2B frag_index][2B data_len][N bytes payload][4B CRC32]
# 头部: 14 字节, CRC: 4 字节, 总计开销: 18 字节

_DGRAM_MAGIC = b'\xD4\x6D'
_DGRAM_HEADER_FMT = '!2sBB I H H H'
_DGRAM_HEADER_SIZE = struct.calcsize(_DGRAM_HEADER_FMT)  # 14
_DGRAM_CRC_SIZE = 4
_DGRAM_OVERHEAD = _DGRAM_HEADER_SIZE + _DGRAM_CRC_SIZE   # 18

# ACK 报文格式:
#   [2B magic 0xD46D][1B ver=0xFF][1B flags=0xA0][4B seq][2B frag_index]
_ACK_MAGIC = b'\xD4\x6D'
_ACK_FMT = '!2sBB I H'
_ACK_SIZE = struct.calcsize(_ACK_FMT)  # 10

# 报文标志位
_DGRAM_FLAG_FRAGMENT = 0x01   # 是分片报文
_DGRAM_FLAG_LAST     = 0x02   # 最后一片
_DGRAM_FLAG_ACK      = 0x80   # 需要 ACK 确认


def _build_datagram_packet(
    seq: int,
    total_frags: int,
    frag_index: int,
    payload: bytes,
    flags: int = 1,
    version: int = 1,
) -> bytes:
    """构建数据报文（含头部和 CRC32 校验）"""
    header = struct.pack(
        _DGRAM_HEADER_FMT,
        _DGRAM_MAGIC,
        version,
        flags,
        seq & 0xFFFFFFFF,
        total_frags & 0xFFFF,
        frag_index & 0xFFFF,
        len(payload) & 0xFFFF,
    )
    crc = struct.pack('!I', _crc32(header + payload) & 0xFFFFFFFF)
    return header + payload + crc


def _parse_datagram_packet(data: bytes) -> Optional[Dict[str, Any]]:
    """解析数据报文，返回字段字典。无效报文返回 None。"""
    if len(data) < _DGRAM_OVERHEAD:
        return None

    try:
        magic, ver, flags, seq, total_frags, frag_index, data_len = struct.unpack(
            _DGRAM_HEADER_FMT, data[:_DGRAM_HEADER_SIZE]
        )
    except struct.error:
        return None

    if magic != _DGRAM_MAGIC:
        return None

    payload_end = _DGRAM_HEADER_SIZE + data_len
    if payload_end + _DGRAM_CRC_SIZE > len(data):
        return None

    payload = data[_DGRAM_HEADER_SIZE:payload_end]
    received_crc = struct.unpack('!I', data[payload_end:payload_end + _DGRAM_CRC_SIZE])[0]

    # 校验 CRC
    expected_crc = _crc32(data[:payload_end]) & 0xFFFFFFFF
    if received_crc != expected_crc:
        return None

    return {
        'version': ver,
        'flags': flags,
        'seq': seq,
        'total_frags': total_frags,
        'frag_index': frag_index,
        'data_len': data_len,
        'payload': payload,
    }


def _build_ack_packet(seq: int, frag_index: int) -> bytes:
    """构建 ACK 确认报文"""
    return struct.pack(
        _ACK_FMT,
        _ACK_MAGIC,
        0xFF,  # ACK 版本标记
        0xA0,  # ACK 标志
        seq & 0xFFFFFFFF,
        frag_index & 0xFFFF,
    )


def _is_ack_packet(data: bytes, expected_seq: int, expected_frag: int) -> bool:
    """检查是否为对应报文的 ACK"""
    if len(data) < _ACK_SIZE:
        return False
    try:
        magic, ver, flags, seq, frag = struct.unpack(_ACK_FMT, data[:_ACK_SIZE])
    except struct.error:
        return False
    return (magic == _ACK_MAGIC and ver == 0xFF and flags == 0xA0
            and seq == (expected_seq & 0xFFFFFFFF)
            and frag == (expected_frag & 0xFFFF))


def _crc32(data: bytes) -> int:
    """计算 CRC32 校验值"""
    import zlib
    return zlib.crc32(data) & 0xFFFFFFFF


# ========================================================================
# StatsCounter — 线程安全的收发统计
# ========================================================================

class StatsCounter:
    """线程安全的收发字节/数据包统计"""

    def __init__(self) -> None:
        self._sent_bytes = 0
        self._recv_bytes = 0
        self._sent_packets = 0
        self._recv_packets = 0
        self._lock = threading.Lock()

    def add_sent(self, n: int) -> None:
        with self._lock:
            self._sent_bytes += n
            self._sent_packets += 1

    def add_recv(self, n: int) -> None:
        with self._lock:
            self._recv_bytes += n
            self._recv_packets += 1

    def snapshot(self) -> Dict[str, int]:
        with self._lock:
            return {
                "sent_bytes": self._sent_bytes,
                "recv_bytes": self._recv_bytes,
                "sent_packets": self._sent_packets,
                "recv_packets": self._recv_packets,
            }

    def reset(self) -> None:
        with self._lock:
            self._sent_bytes = 0
            self._recv_bytes = 0
            self._sent_packets = 0
            self._recv_packets = 0

    @property
    def sent_bytes(self) -> int:
        with self._lock:
            return self._sent_bytes

    @property
    def recv_bytes(self) -> int:
        with self._lock:
            return self._recv_bytes

    @property
    def sent_packets(self) -> int:
        with self._lock:
            return self._sent_packets

    @property
    def recv_packets(self) -> int:
        with self._lock:
            return self._recv_packets

    def __repr__(self) -> str:
        s = self.snapshot()
        return (f"StatsCounter(sent={format_bytes(s['sent_bytes'])}/{s['sent_packets']}pkts, "
                f"recv={format_bytes(s['recv_bytes'])}/{s['recv_packets']}pkts)")


# ========================================================================
# NetworkCore — 网络通信核心逻辑
# ========================================================================

class NetworkCore:
    """网络通信核心逻辑，所有方法均为静态方法，与 UI/CLI 分离"""

    # ======================== TCP 通信 ========================

    @staticmethod
    def tcp_server(
        host: str,
        port: int,
        stop_event: threading.Event,
        echo: bool = False,
        encoding: str = "UTF-8",
        backlog: int = 10,
        stats: Optional[StatsCounter] = None,
        on_client_connect: Optional[Callable[[Tuple[str, int]], None]] = None,
        on_client_disconnect: Optional[Callable[[Tuple[str, int]], None]] = None,
        on_data: Optional[Callable[[Tuple[str, int], str], None]] = None,
        on_error: Optional[Callable[[str], None]] = None,
        accept_timeout: float = 1.0,
    ) -> None:
        """
        TCP 服务端监听，支持多客户端、Echo 模式、IPv6 双栈。

        参数:
            host: 绑定地址
            port: 监听端口
            stop_event: 停止事件，set() 后服务端优雅关闭
            echo: 是否回显收到的数据
            encoding: 数据编解码方式
            backlog: 最大等待连接数
            stats: 可选的 StatsCounter 实例
            on_client_connect: 客户端连接回调，参数为 (addr_ip, addr_port)
            on_client_disconnect: 客户端断开回调
            on_data: 收到数据回调，参数为 (addr, decoded_message)
            on_error: 错误回调，参数为错误描述字符串
            accept_timeout: accept() 超时时间（秒），用于检查 stop_event
        """
        addrinfo = socket.getaddrinfo(host, port, socket.AF_UNSPEC,
                                       socket.SOCK_STREAM, 0, socket.AI_PASSIVE)
        server = None
        for family, socktype, proto, canonname, sockaddr in addrinfo:
            try:
                server = socket.socket(family, socktype, proto)
                server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                if family == socket.AF_INET6:
                    try:
                        server.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
                    except (AttributeError, OSError):
                        pass
                server.bind(sockaddr)
                server.listen(backlog)
                break
            except OSError as e:
                if server:
                    server.close()
                if family == socket.AF_INET6:
                    continue
                if on_error:
                    on_error(f"绑定失败: {e}")
                return

        if server is None:
            if on_error:
                on_error("无法绑定到任何地址")
            return

        server.settimeout(accept_timeout)
        clients: Dict[socket.socket, Tuple[str, int]] = {}

        def _handle_client(conn: socket.socket, addr: Tuple[str, int]) -> None:
            """单个客户端接收线程"""
            while not stop_event.is_set():
                try:
                    data = conn.recv(65536)
                    if not data:
                        break
                    if stats:
                        stats.add_recv(len(data))
                    msg = decode_data(data, encoding)
                    if on_data:
                        on_data(addr, msg)
                    if echo:
                        conn.sendall(data)
                        if stats:
                            stats.add_sent(len(data))
                except (socket.timeout, BlockingIOError):
                    continue
                except OSError:
                    break
            conn.close()
            if conn in clients:
                del clients[conn]
            if on_client_disconnect:
                on_client_disconnect(addr)

        while not stop_event.is_set():
            try:
                conn, addr = server.accept()
                clients[conn] = addr
                if on_client_connect:
                    on_client_connect(addr)
                t = threading.Thread(
                    target=_handle_client,
                    args=(conn, addr),
                    daemon=True,
                )
                t.start()
            except socket.timeout:
                continue
            except OSError as e:
                if not stop_event.is_set() and on_error:
                    on_error(f"服务端错误: {e}")
                break

        # 优雅关闭所有客户端连接
        for c in list(clients.keys()):
            try:
                c.close()
            except Exception:
                pass
        clients.clear()
        server.close()

    @staticmethod
    def tcp_client(
        host: str,
        port: int,
        message: str,
        encoding: str = "UTF-8",
        timeout: float = 5.0,
        expect_response: bool = True,
        stats: Optional[StatsCounter] = None,
    ) -> Optional[bytes]:
        """
        TCP 客户端：连接服务器，发送消息，可选等待响应。

        参数:
            host: 目标主机名或 IP
            port: 目标端口
            message: 要发送的消息文本
            encoding: 编码方式
            timeout: 连接和读超时（秒）
            expect_response: 是否等待服务器响应
            stats: 可选的统计计数器

        返回:
            响应字节数据，如果不等待响应则返回 None

        异常:
            ConnectionError: 连接失败
            socket.timeout: 连接或读取超时
        """
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
            raise ConnectionError(f"无法连接到 {host}:{port}: {last_error}")

        try:
            raw_data = encode_data(message, encoding)
            client.sendall(raw_data)
            if stats:
                stats.add_sent(len(raw_data))

            if not expect_response:
                client.close()
                return None

            client.settimeout(min(timeout, 3.0))
            try:
                resp = client.recv(65536)
                if resp and stats:
                    stats.add_recv(len(resp))
                client.close()
                return resp
            except socket.timeout:
                client.close()
                return None
        except Exception as e:
            try:
                client.close()
            except Exception:
                pass
            raise ConnectionError(f"TCP 客户端错误: {e}")

    # ======================== TCP 监听 (Netcat -l 模式) ========================

    @staticmethod
    def tcp_listen(
        port: int,
        stop_event: threading.Event,
        bind_host: str = "0.0.0.0",
        encoding: str = "UTF-8",
        keep_open: bool = False,
        timeout: float = 0.0,
        read_timeout: float = 1.0,
        stats: Optional[StatsCounter] = None,
        on_connect: Optional[Callable[[Tuple[str, int]], None]] = None,
        on_disconnect: Optional[Callable[[Tuple[str, int]], None]] = None,
        on_data: Optional[Callable[[Tuple[str, int], bytes], None]] = None,
        on_error: Optional[Callable[[str], None]] = None,
        get_reply: Optional[Callable[[], Optional[bytes]]] = None,
    ) -> None:
        """
        TCP 端口监听（类似 netcat -l），支持单连接或持续监听模式。

        参数:
            port: 监听端口
            stop_event: 停止事件
            bind_host: 绑定地址
            encoding: 默认编解码（仅用于日志，on_data 回调接收原始 bytes）
            keep_open: True=持续接受新连接，False=第一个连接断开后退出
            timeout: 总超时秒数（0=永久）
            read_timeout: 每次 recv 的超时（用于检查 stop_event）
            stats: 可选的统计计数器
            on_connect: 客户端连接回调
            on_disconnect: 客户端断开回调
            on_data: 收到数据回调，参数为 (addr, raw_bytes)
            on_error: 错误回调
            get_reply: 可选的回复数据回调，返回 bytes 发送回客户端；返回 None 表示不回复
        """
        # 创建监听套接字（支持 IPv6 双栈）
        server = None
        try:
            server = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                server.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            except (AttributeError, OSError):
                pass
            server.bind(("::", port))
        except OSError:
            if server:
                server.close()
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind((bind_host if bind_host != "0.0.0.0" else "0.0.0.0", port))

        server.listen(1)
        start_time = time.time()

        while not stop_event.is_set():
            # 检查总超时
            if timeout > 0 and (time.time() - start_time) >= timeout:
                break

            try:
                server.settimeout(1.0)
                conn, addr = server.accept()
            except socket.timeout:
                continue
            except OSError as e:
                if not stop_event.is_set() and on_error:
                    on_error(f"监听错误: {e}")
                break

            if on_connect:
                on_connect(addr)

            # 接收循环
            try:
                conn.settimeout(read_timeout)
                while not stop_event.is_set():
                    try:
                        data = conn.recv(65536)
                        if not data:
                            break
                        if stats:
                            stats.add_recv(len(data))
                        if on_data:
                            on_data(addr, data)

                        # 交互回复模式
                        if get_reply:
                            reply_data = get_reply()
                            if reply_data:
                                conn.sendall(reply_data)
                                if stats:
                                    stats.add_sent(len(reply_data))
                    except socket.timeout:
                        continue
                    except OSError:
                        break
            finally:
                conn.close()
                if on_disconnect:
                    on_disconnect(addr)

            if not keep_open:
                break

        server.close()

    # ======================== TCP 交互客户端 ========================

    @staticmethod
    def tcp_client_interactive(
        host: str,
        port: int,
        stop_event: threading.Event,
        encoding: str = "UTF-8",
        timeout: float = 5.0,
        stats: Optional[StatsCounter] = None,
        on_connect: Optional[Callable[[str, int], None]] = None,
        on_data: Optional[Callable[[bytes], None]] = None,
        on_disconnect: Optional[Callable[[], None]] = None,
        on_error: Optional[Callable[[str], None]] = None,
        get_input: Optional[Callable[[], Optional[bytes]]] = None,
    ) -> None:
        """
        TCP 交互客户端：连接后持续收发，直到连接断开或 stop_event。

        参数:
            host: 目标主机
            port: 目标端口
            stop_event: 停止事件
            encoding: 默认编码（仅用于日志）
            timeout: 连接超时
            stats: 可选的统计计数器
            on_connect: 连接成功回调 on_connect(host, port)
            on_data: 收到数据回调 on_data(raw_bytes)
            on_disconnect: 连接断开回调
            on_error: 错误回调
            get_input: 获取用户输入回调，返回 bytes 发送；返回 None 表示不发送
        """
        addrinfo = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
        sock = None
        last_error = None

        for family, socktype, proto, canonname, sockaddr in addrinfo:
            try:
                sock = socket.socket(family, socktype, proto)
                sock.settimeout(timeout)
                sock.connect(sockaddr)
                break
            except OSError as e:
                last_error = e
                if sock:
                    sock.close()
                    sock = None
                continue

        if sock is None:
            if on_error:
                on_error(f"无法连接到 {host}:{port}: {last_error}")
            return

        if on_connect:
            on_connect(sockaddr[0], sockaddr[1])

        try:
            sock.settimeout(1.0)
            while not stop_event.is_set():
                # 发送用户输入（如果有）
                if get_input:
                    input_data = get_input()
                    if input_data:
                        sock.sendall(input_data)
                        if stats:
                            stats.add_sent(len(input_data))

                # 接收数据
                try:
                    data = sock.recv(65536)
                    if not data:
                        break
                    if stats:
                        stats.add_recv(len(data))
                    if on_data:
                        on_data(data)
                except socket.timeout:
                    continue
                except OSError:
                    break
        finally:
            sock.close()
            if on_disconnect:
                on_disconnect()

    # ======================== TCP 文件传输 ========================

    @staticmethod
    def tcp_send_file(
        host: str,
        port: int,
        filepath: str,
        progress_cb: Optional[Callable[[int, int], None]] = None,
        chunk_size: int = 65536,
        timeout: float = 30.0,
        stats: Optional[StatsCounter] = None,
    ) -> Dict[str, Any]:
        """
        TCP 发送文件到接收端（便捷方法，委托给 tcp_send_file_stream）。

        协议: [8B filesize][2B name_len][filename UTF-8][file data]
        """
        return NetworkCore.tcp_send_file_stream(
            host=host,
            port=port,
            filepath=filepath,
            progress_cb=progress_cb,
            chunk_size=chunk_size,
            timeout=timeout,
            stats=stats,
        )

    @staticmethod
    def tcp_send_file_stream(
        host: str,
        port: int,
        filepath: str,
        progress_cb: Optional[Callable[[int, int], None]] = None,
        chunk_size: int = 65536,
        timeout: float = 30.0,
        stats: Optional[StatsCounter] = None,
    ) -> Dict[str, Any]:
        """
        TCP 流式发送文件（先发头部，再分块发数据，支持进度回调）。

        与 tcp_send_file 协议兼容，但使用分块方式以便汇报进度。
        """
        if not os.path.isfile(filepath):
            raise FileNotFoundError(f"文件不存在: {filepath}")

        filename = os.path.basename(filepath)
        filesize = os.path.getsize(filepath)
        header = pack_file_header(filename, filesize)

        addrinfo = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
        sock = None
        last_error = None
        for family, socktype, proto, canonname, sockaddr in addrinfo:
            try:
                sock = socket.socket(family, socktype, proto)
                sock.settimeout(timeout)
                sock.connect(sockaddr)
                break
            except OSError as e:
                last_error = e
                if sock:
                    sock.close()
                    sock = None
                continue

        if sock is None:
            raise ConnectionError(f"无法连接到 {host}:{port}: {last_error}")

        start_time = time.time()
        bytes_sent = 0
        try:
            # 发送头部
            sock.sendall(header)
            bytes_sent += len(header)
            if stats:
                stats.add_sent(len(header))

            # 分块发送文件数据
            with open(filepath, 'rb') as f:
                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                    sock.sendall(chunk)
                    bytes_sent += len(chunk)
                    if stats:
                        stats.add_sent(len(chunk))
                    if progress_cb:
                        progress_cb(bytes_sent - len(header), filesize)
        except Exception as e:
            try:
                sock.close()
            except Exception:
                pass
            raise ConnectionError(f"文件发送错误: {e}")

        sock.close()
        elapsed = time.time() - start_time
        throughput = (filesize * 8 / elapsed / 1_000_000) if elapsed > 0 else 0

        return {
            "filename": filename,
            "filesize": filesize,
            "bytes_sent": bytes_sent,
            "elapsed": elapsed,
            "throughput_mbps": throughput,
        }

    @staticmethod
    def tcp_recv_file(
        port: int,
        save_dir: str = ".",
        bind_host: str = "0.0.0.0",
        progress_cb: Optional[Callable[[int, int], None]] = None,
        chunk_size: int = 65536,
        timeout: float = 0.0,
        stats: Optional[StatsCounter] = None,
    ) -> Dict[str, Any]:
        """
        TCP 接收文件：监听一次连接，接收文件后保存。

        参数:
            port: 监听端口
            save_dir: 保存目录
            bind_host: 绑定地址
            progress_cb: 进度回调 progress_cb(bytes_received, total_bytes)
            chunk_size: 接收块大小
            timeout: 等待连接超时（0 = 永远等待）
            stats: 可选的统计计数器

        返回:
            {'filename': str, 'saved_path': str, 'bytes_received': int,
             'elapsed': float, 'throughput_mbps': float}
        """
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((bind_host, port))
        server.listen(1)

        if timeout > 0:
            server.settimeout(timeout)
        else:
            server.settimeout(None)

        conn = None
        try:
            conn, addr = server.accept()
        except socket.timeout:
            server.close()
            raise TimeoutError(f"等待连接超时 ({timeout}s)")
        finally:
            server.close()

        if conn is None:
            raise ConnectionError("接受连接失败")

        start_time = time.time()
        try:
            # 读取文件头部，获取文件名和大小
            filename, filesize = unpack_file_header(conn)
            conn.settimeout(30.0)

            # 确保保存目录存在
            os.makedirs(save_dir, exist_ok=True)
            save_path = os.path.join(save_dir, filename)

            # 避免覆盖：如果文件已存在，添加序号
            base, ext = os.path.splitext(filename)
            counter = 1
            while os.path.exists(save_path):
                save_path = os.path.join(save_dir, f"{base}_{counter}{ext}")
                counter += 1

            bytes_received = 0
            with open(save_path, 'wb') as f:
                while bytes_received < filesize:
                    to_read = min(chunk_size, filesize - bytes_received)
                    chunk = conn.recv(to_read)
                    if not chunk:
                        break
                    f.write(chunk)
                    bytes_received += len(chunk)
                    if stats:
                        stats.add_recv(len(chunk))
                    if progress_cb:
                        progress_cb(bytes_received, filesize)

            conn.close()
        except Exception as e:
            try:
                conn.close()
            except Exception:
                pass
            raise ConnectionError(f"文件接收错误: {e}")

        elapsed = time.time() - start_time
        throughput = (bytes_received * 8 / elapsed / 1_000_000) if elapsed > 0 else 0

        return {
            "filename": filename,
            "saved_path": save_path,
            "bytes_received": bytes_received,
            "filesize": filesize,
            "elapsed": elapsed,
            "throughput_mbps": throughput,
        }

    # ======================== 端口扫描 ========================

    @staticmethod
    def port_scan(
        target: str,
        start_port: int,
        end_port: int,
        timeout: float = 1.0,
        max_workers: int = 100,
        progress_cb: Optional[Callable[[int, int, int], None]] = None,
    ) -> List[int]:
        """
        多线程 TCP 端口扫描（Connect 方式）。

        参数:
            target: 目标 IP 或主机名
            start_port: 起始端口
            end_port: 结束端口
            timeout: 每个端口的连接超时（秒）
            max_workers: 最大并发线程数
            progress_cb: 进度回调 progress_cb(completed, total, open_count)

        返回:
            开放端口列表（已排序）
        """
        total = end_port - start_port + 1
        open_ports: List[int] = []
        lock = threading.Lock()
        completed = 0

        def _scan_one(p: int) -> None:
            nonlocal completed
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(timeout)
                result = s.connect_ex((target, p))
                s.close()
                if result == 0:
                    with lock:
                        open_ports.append(p)
            except Exception:
                pass
            finally:
                with lock:
                    completed += 1
                    if progress_cb:
                        progress_cb(completed, total, len(open_ports))

        workers = min(max_workers, total, 500)
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = [executor.submit(_scan_one, p) for p in range(start_port, end_port + 1)]
            for f in futures:
                try:
                    f.result(timeout=timeout + 2)
                except Exception:
                    pass

        return sorted(open_ports)

    # ======================== UDP 通信 ========================

    @staticmethod
    def udp_send(
        host: str,
        port: int,
        message: str,
        encoding: str = "UTF-8",
        broadcast: bool = False,
        multicast_group: Optional[str] = None,
        multicast_ttl: int = 2,
        stats: Optional[StatsCounter] = None,
    ) -> int:
        """
        UDP 发送数据报。

        参数:
            host: 目标地址
            port: 目标端口
            message: 要发送的消息
            encoding: 编码方式
            broadcast: 是否启用广播模式
            multicast_group: 组播组地址（设置后使用组播发送）
            multicast_ttl: 组播 TTL
            stats: 可选的统计计数器

        返回:
            发送的字节数
        """
        raw_data = encode_data(message, encoding)

        if multicast_group:
            # 组播发送
            family = socket.AF_INET6 if is_ipv6(multicast_group) else socket.AF_INET
            sock = socket.socket(family, socket.SOCK_DGRAM)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, multicast_ttl)
            target = (multicast_group, port)
        elif broadcast:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            target = ("255.255.255.255", port)
        else:
            addrinfo = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_DGRAM)
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
            target = sockaddr

        try:
            sent = sock.sendto(raw_data, target)
            if stats:
                stats.add_sent(sent)
            return sent
        finally:
            sock.close()

    @staticmethod
    def udp_listen(
        port: int,
        stop_event: threading.Event,
        bind_host: str = "0.0.0.0",
        encoding: str = "UTF-8",
        timeout: float = 0.0,
        stats: Optional[StatsCounter] = None,
        on_data: Optional[Callable[[Tuple[str, int], str], None]] = None,
        on_error: Optional[Callable[[str], None]] = None,
    ) -> None:
        """
        UDP 监听数据报，支持 IPv6 双栈。

        参数:
            port: 监听端口
            stop_event: 停止事件
            bind_host: 绑定地址
            encoding: 解码方式
            timeout: 超时秒数（0 = 永久）
            stats: 可选的统计计数器
            on_data: 收到数据回调 on_data(addr_tuple, decoded_message)
            on_error: 错误回调
        """
        sock = None
        # 优先创建 IPv6 双栈套接字
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
            sock.bind((bind_host if bind_host != "0.0.0.0" else "0.0.0.0", port))

        sock.settimeout(1.0)
        start_time = time.time()

        while not stop_event.is_set():
            if timeout > 0 and (time.time() - start_time) >= timeout:
                break
            try:
                data, addr = sock.recvfrom(65536)
                if stats:
                    stats.add_recv(len(data))
                msg = decode_data(data, encoding)
                if on_data:
                    on_data(addr, msg)
            except socket.timeout:
                continue
            except OSError as e:
                if on_error:
                    on_error(f"UDP 监听错误: {e}")
                break

        sock.close()

    @staticmethod
    def udp_multicast_listen(
        group: str,
        port: int,
        stop_event: threading.Event,
        encoding: str = "UTF-8",
        stats: Optional[StatsCounter] = None,
        on_data: Optional[Callable[[Tuple[str, int], str], None]] = None,
    ) -> None:
        """
        加入组播组并监听数据报。

        参数:
            group: 组播组地址 (如 224.0.0.1)
            port: 端口
            stop_event: 停止事件
            encoding: 解码方式
            stats: 可选的统计计数器
            on_data: 收到数据回调
        """
        is_v6 = is_ipv6(group)
        family = socket.AF_INET6 if is_v6 else socket.AF_INET

        sock = socket.socket(family, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # 绑定到组播端口
        if is_v6:
            sock.bind(("::", port))
        else:
            sock.bind(("0.0.0.0", port))

        # 加入组播组
        if is_v6:
            # IPv6 组播
            import struct as _struct
            group_bytes = socket.inet_pton(socket.AF_INET6, group)
            mreq = group_bytes + _struct.pack('@I', 0)  # interface index 0
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, mreq)
        else:
            # IPv4 组播
            import struct as _struct
            mreq = _struct.pack('4sI', socket.inet_aton(group), socket.INADDR_ANY)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

        sock.settimeout(1.0)

        while not stop_event.is_set():
            try:
                data, addr = sock.recvfrom(65536)
                if stats:
                    stats.add_recv(len(data))
                msg = decode_data(data, encoding)
                if on_data:
                    on_data(addr, msg)
            except socket.timeout:
                continue
            except OSError:
                break

        sock.close()

    # ======================== 数据报文协议 (Datagram Protocol) ========================

    @staticmethod
    def udp_send_datagram(
        host: str,
        port: int,
        data: bytes,
        mtu: int = 1400,
        require_ack: bool = False,
        ack_timeout: float = 3.0,
        stats: Optional[StatsCounter] = None,
    ) -> Dict[str, Any]:
        """
        UDP 发送数据报文，自动分片大于 MTU 的数据。

        报文格式 (每片):
          [2B magic 0xD46D][1B ver][1B flags][4B seq][2B total_frags]
          [2B frag_index][2B data_len][N bytes payload][4B CRC32]

        头部大小: 14 字节，尾部 CRC32: 4 字节
        每片最大有效载荷: mtu - 18

        参数:
            host: 目标地址
            port: 目标端口
            data: 要发送的原始字节数据
            mtu: 最大传输单元 (默认 1400)
            require_ack: 是否要求确认
            ack_timeout: ACK 超时秒数
            stats: 可选的统计计数器

        返回:
            {'fragments': int, 'bytes_sent': int, 'elapsed': float,
             'acked': int (if require_ack)}
        """
        # 解析目标地址
        addrinfo = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_DGRAM)
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

        max_payload = mtu - 18  # 14B header + 4B CRC
        total_frags = max(1, (len(data) + max_payload - 1) // max_payload)
        seq_base = int(time.time() * 1000) & 0xFFFFFFFF

        start_time = time.time()
        total_sent = 0
        acks_received = 0

        try:
            # 如果需要 ACK，设置接收超时
            if require_ack:
                sock.settimeout(ack_timeout)

            for frag_idx in range(total_frags):
                start = frag_idx * max_payload
                end = min(start + max_payload, len(data))
                chunk = data[start:end]

                # 构建报文
                packet = _build_datagram_packet(
                    seq=seq_base,
                    total_frags=total_frags,
                    frag_index=frag_idx,
                    payload=chunk,
                    flags=(1 if frag_idx < total_frags - 1 else 3),  # bit0=fragment, bit1=last
                )
                sock.sendto(packet, sockaddr)
                total_sent += len(packet)
                if stats:
                    stats.add_sent(len(packet))

                # 等待 ACK
                if require_ack:
                    try:
                        ack_data, ack_addr = sock.recvfrom(256)
                        if stats:
                            stats.add_recv(len(ack_data))
                        if _is_ack_packet(ack_data, seq_base, frag_idx):
                            acks_received += 1
                    except socket.timeout:
                        pass  # ACK 超时，继续发送下一片

        finally:
            sock.close()

        elapsed = time.time() - start_time
        result: Dict[str, Any] = {
            "fragments": total_frags,
            "bytes_sent": total_sent,
            "elapsed": elapsed,
            "payload_size": len(data),
        }
        if require_ack:
            result["acked"] = acks_received
        return result

    @staticmethod
    def udp_recv_datagram(
        port: int,
        stop_event: threading.Event,
        bind_host: str = "0.0.0.0",
        timeout: float = 0.0,
        send_ack: bool = True,
        stats: Optional[StatsCounter] = None,
        on_message: Optional[Callable[[Tuple[str, int], bytes, Dict[str, Any]], None]] = None,
        on_error: Optional[Callable[[str], None]] = None,
    ) -> None:
        """
        UDP 接收数据报文，自动重组分片。

        参数:
            port: 监听端口
            stop_event: 停止事件
            bind_host: 绑定地址
            timeout: 总超时秒数
            send_ack: 是否发送 ACK 确认
            stats: 可选的统计计数器
            on_message: 完整消息回调 on_message(addr, data, meta)
                        meta 包含: {'seq': int, 'total_frags': int, 'frags_received': int}
            on_error: 错误回调
        """
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
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((bind_host if bind_host != "0.0.0.0" else "0.0.0.0", port))

        sock.settimeout(1.0)
        start_time = time.time()

        # 重组缓冲区: {(addr_key, seq): {total: N, frags: {idx: bytes}, last_seen: time}}
        reassembly: Dict[Tuple[str, int, int], Dict[str, Any]] = {}
        reassembly_timeout = 30.0  # 30 秒后丢弃不完整的消息

        while not stop_event.is_set():
            if timeout > 0 and (time.time() - start_time) >= timeout:
                break

            try:
                raw_data, addr = sock.recvfrom(65536)
                if stats:
                    stats.add_recv(len(raw_data))
            except socket.timeout:
                # 清理过期的不完整消息
                now = time.time()
                expired_keys = [
                    k for k, v in reassembly.items()
                    if now - v.get('last_seen', 0) > reassembly_timeout
                ]
                for k in expired_keys:
                    del reassembly[k]
                continue
            except OSError:
                break

            # 解析报文
            packet_info = _parse_datagram_packet(raw_data)
            if packet_info is None:
                continue  # 无效报文，静默丢弃

            # 发送 ACK
            if send_ack and packet_info['flags'] & 0x01:  # 是分片报文
                ack_packet = _build_ack_packet(
                    packet_info['seq'],
                    packet_info['frag_index'],
                )
                try:
                    sock.sendto(ack_packet, addr)
                    if stats:
                        stats.add_sent(len(ack_packet))
                except OSError:
                    pass

            # 如果不分片，直接回调
            if packet_info['total_frags'] == 1:
                if on_message:
                    on_message(addr, packet_info['payload'], {
                        'seq': packet_info['seq'],
                        'total_frags': 1,
                        'frags_received': 1,
                        'frag_index': 0,
                    })
                continue

            # 分片重组
            key = (addr[0], addr[1], packet_info['seq'])
            if key not in reassembly:
                reassembly[key] = {
                    'total': packet_info['total_frags'],
                    'frags': {},
                    'last_seen': time.time(),
                    'addr': addr,
                }
            else:
                reassembly[key]['last_seen'] = time.time()

            buf = reassembly[key]
            buf['frags'][packet_info['frag_index']] = packet_info['payload']

            # 检查是否收集完所有分片
            if len(buf['frags']) == buf['total']:
                # 按顺序组装
                ordered = b''.join(
                    buf['frags'][i] for i in range(buf['total'])
                    if i in buf['frags']
                )
                if on_message:
                    on_message(buf['addr'], ordered, {
                        'seq': packet_info['seq'],
                        'total_frags': buf['total'],
                        'frags_received': len(buf['frags']),
                    })
                del reassembly[key]

        sock.close()

    # ======================== UDP 二进制发送 ========================

    @staticmethod
    def udp_send_binary(
        host: str,
        port: int,
        data: bytes,
        stats: Optional[StatsCounter] = None,
    ) -> int:
        """
        UDP 发送原始二进制数据。

        参数:
            host: 目标地址
            port: 目标端口
            data: 原始字节数据
            stats: 可选的统计计数器

        返回:
            发送的字节数
        """
        addrinfo = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_DGRAM)
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
            sent = sock.sendto(data, sockaddr)
            if stats:
                stats.add_sent(sent)
            return sent
        finally:
            sock.close()

    @staticmethod
    def udp_recv_binary(
        port: int,
        stop_event: threading.Event,
        bind_host: str = "0.0.0.0",
        timeout: float = 0.0,
        buffer_size: int = 65536,
        stats: Optional[StatsCounter] = None,
        on_data: Optional[Callable[[Tuple[str, int], bytes], None]] = None,
        on_error: Optional[Callable[[str], None]] = None,
    ) -> None:
        """
        UDP 接收原始二进制数据报。

        参数:
            port: 监听端口
            stop_event: 停止事件
            bind_host: 绑定地址
            timeout: 总超时秒数
            buffer_size: 接收缓冲区大小
            stats: 可选的统计计数器
            on_data: 收到数据回调 on_data(addr, raw_bytes)
            on_error: 错误回调
        """
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
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((bind_host if bind_host != "0.0.0.0" else "0.0.0.0", port))

        sock.settimeout(1.0)
        start_time = time.time()

        while not stop_event.is_set():
            if timeout > 0 and (time.time() - start_time) >= timeout:
                break
            try:
                data, addr = sock.recvfrom(buffer_size)
                if stats:
                    stats.add_recv(len(data))
                if on_data:
                    on_data(addr, data)
            except socket.timeout:
                continue
            except OSError as e:
                if on_error:
                    on_error(f"UDP 接收错误: {e}")
                break

        sock.close()

    # ======================== HTTP 简易请求 ========================

    @staticmethod
    def http_head(
        host: str,
        port: int = 80,
        path: str = "/",
        timeout: float = 5.0,
    ) -> Dict[str, str]:
        """
        发送 HTTP HEAD 请求并返回响应头字典。

        参数:
            host: 目标主机
            port: 端口
            path: 请求路径
            timeout: 超时

        返回:
            响应头字典，包含 'status_line' 键
        """
        addrinfo = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
        sock = socket.socket(addrinfo[0][0], addrinfo[0][1], addrinfo[0][2])
        sock.settimeout(timeout)
        sock.connect(addrinfo[0][4])

        request = f"HEAD {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
        sock.sendall(request.encode())

        response = b""
        try:
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
        except socket.timeout:
            pass
        sock.close()

        headers: Dict[str, str] = {}
        lines = response.decode(errors='replace').split('\r\n')
        if lines:
            headers['status_line'] = lines[0]
            for line in lines[1:]:
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip()] = value.strip()

        return headers

    # ======================== 网络状态检测 ========================

    @staticmethod
    def ping_host(
        host: str,
        count: int = 4,
        timeout: float = 3.0,
        tcp_port: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Ping 检测主机可达性。Windows 使用系统 ping，或使用 TCP 端口探测。

        参数:
            host: 目标主机
            count: 探测次数
            timeout: 每次探测超时
            tcp_port: 如果指定，使用 TCP 连接代替 ICMP ping

        返回:
            {'host': str, 'method': 'icmp'|'tcp', 'sent': int, 'received': int,
             'loss_pct': float, 'times_ms': [float], 'min_ms': float,
             'avg_ms': float, 'max_ms': float, 'stddev_ms': float}
        """
        if tcp_port:
            # TCP ping 模式
            times_ms: List[float] = []
            received = 0
            for i in range(count):
                try:
                    t_start = time.time()
                    addrinfo = socket.getaddrinfo(host, tcp_port, socket.AF_UNSPEC, socket.SOCK_STREAM)
                    sock = socket.socket(addrinfo[0][0], addrinfo[0][1], addrinfo[0][2])
                    sock.settimeout(timeout)
                    sock.connect(addrinfo[0][4])
                    elapsed = (time.time() - t_start) * 1000
                    times_ms.append(elapsed)
                    sock.close()
                    received += 1
                except Exception:
                    times_ms.append(-1.0)  # 超时标记
            method = "tcp"
        else:
            # 系统 ICMP ping
            import subprocess
            param = '-n' if os.name == 'nt' else '-c'
            timeout_param = '-w' if os.name == 'nt' else '-W'
            timeout_val = str(int(timeout * 1000)) if os.name == 'nt' else str(int(timeout))
            try:
                cmd = ['ping', param, str(count), timeout_param, timeout_val, host]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout * count + 5)
                output = result.stdout
            except subprocess.TimeoutExpired:
                output = ""
            except FileNotFoundError:
                # 回退到 TCP ping (端口 80)
                return NetworkCore.ping_host(host, count, timeout, tcp_port=80)

            times_ms = _parse_ping_output(output, host)
            received = sum(1 for t in times_ms if t >= 0)
            method = "icmp"

        avg_ms = sum(t for t in times_ms if t >= 0) / max(received, 1)
        min_ms = min((t for t in times_ms if t >= 0), default=0)
        max_ms = max((t for t in times_ms if t >= 0), default=0)

        # 标准差
        valid = [t for t in times_ms if t >= 0]
        if len(valid) > 1:
            mean = sum(valid) / len(valid)
            stddev = (sum((t - mean) ** 2 for t in valid) / len(valid)) ** 0.5
        else:
            stddev = 0.0

        return {
            'host': host,
            'method': method,
            'sent': count,
            'received': received,
            'loss_pct': round((count - received) / count * 100, 1) if count > 0 else 0,
            'times_ms': times_ms,
            'min_ms': round(min_ms, 2),
            'avg_ms': round(avg_ms, 2),
            'max_ms': round(max_ms, 2),
            'stddev_ms': round(stddev, 2),
        }

    @staticmethod
    def check_connectivity(
        test_targets: Optional[List[Tuple[str, int]]] = None,
        timeout: float = 3.0,
    ) -> Dict[str, Any]:
        """
        检测网络连通性：尝试连接多个知名服务。

        参数:
            test_targets: [(host, port), ...] 测试目标列表
            timeout: 每目标超时

        返回:
            {'online': bool, 'results': {target: {'reachable': bool, 'latency_ms': float}}, ...}
        """
        if test_targets is None:
            test_targets = [
                ("8.8.8.8", 53),       # Google DNS
                ("1.1.1.1", 53),       # Cloudflare DNS
                ("223.5.5.5", 53),     # Ali DNS
            ]

        results = {}
        reachable_count = 0
        for host, port in test_targets:
            key = f"{host}:{port}"
            try:
                t_start = time.time()
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                sock.connect((host, port))
                latency = (time.time() - t_start) * 1000
                sock.close()
                results[key] = {'reachable': True, 'latency_ms': round(latency, 2)}
                reachable_count += 1
            except Exception:
                results[key] = {'reachable': False, 'latency_ms': -1}

        return {
            'online': reachable_count > 0,
            'reachable_count': reachable_count,
            'total': len(test_targets),
            'results': results,
        }

    @staticmethod
    def measure_latency(
        host: str,
        port: int = 80,
        count: int = 5,
        timeout: float = 3.0,
    ) -> Dict[str, Any]:
        """
        测量 TCP 连接延迟。

        参数:
            host: 目标主机
            port: 目标端口
            count: 测量次数
            timeout: 每次超时

        返回:
            {'host': str, 'port': int, 'count': int, 'times_ms': [float],
             'min_ms': float, 'avg_ms': float, 'max_ms': float, 'stddev_ms': float}
        """
        times_ms: List[float] = []
        for _ in range(count):
            try:
                t_start = time.time()
                addrinfo = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
                sock = socket.socket(addrinfo[0][0], addrinfo[0][1], addrinfo[0][2])
                sock.settimeout(timeout)
                sock.connect(addrinfo[0][4])
                elapsed = (time.time() - t_start) * 1000
                times_ms.append(elapsed)
                sock.close()
            except Exception:
                times_ms.append(-1.0)

        valid = [t for t in times_ms if t >= 0]
        if not valid:
            return {
                'host': host, 'port': port, 'count': count,
                'times_ms': times_ms,
                'min_ms': 0, 'avg_ms': 0, 'max_ms': 0, 'stddev_ms': 0,
            }

        avg = sum(valid) / len(valid)
        stddev = (sum((t - avg) ** 2 for t in valid) / len(valid)) ** 0.5 if len(valid) > 1 else 0

        return {
            'host': host,
            'port': port,
            'count': count,
            'times_ms': times_ms,
            'min_ms': round(min(valid), 2),
            'avg_ms': round(avg, 2),
            'max_ms': round(max(valid), 2),
            'stddev_ms': round(stddev, 2),
        }

    @staticmethod
    def measure_bandwidth(
        host: str = "8.8.8.8",
        port: int = 53,
        duration: float = 3.0,
        chunk_size: int = 8192,
        timeout: float = 5.0,
        progress_cb: Optional[Callable[[int, int], None]] = None,
    ) -> Dict[str, Any]:
        """
        测量上行带宽：持续发送数据并统计吞吐量。

        参数:
            host: 目标主机
            port: 目标端口
            duration: 测试持续时间（秒）
            chunk_size: 每块数据大小
            timeout: 连接超时
            progress_cb: 进度回调 progress_cb(bytes_sent, elapsed_seconds)

        返回:
            {'bytes_sent': int, 'duration': float, 'throughput_mbps': float,
             'throughput_mbps_peak': float}
        """
        addrinfo = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
        sock = None
        for family, stype, proto, canonname, sockaddr in addrinfo:
            try:
                sock = socket.socket(family, stype, proto)
                sock.settimeout(timeout)
                sock.connect(sockaddr)
                break
            except OSError:
                if sock:
                    sock.close()
                    sock = None
                continue

        if sock is None:
            raise ConnectionError(f"带宽测试: 无法连接到 {host}:{port}")

        data = b'\x00' * chunk_size
        total_sent = 0
        start_time = time.time()
        peak_mbps = 0.0
        last_check = start_time
        last_bytes = 0

        try:
            sock.settimeout(1.0)
            while time.time() - start_time < duration:
                try:
                    sock.sendall(data)
                    total_sent += chunk_size
                except (socket.timeout, OSError):
                    break

                now = time.time()
                if progress_cb:
                    progress_cb(total_sent, int(now - start_time))

                # 每秒更新峰值
                if now - last_check >= 1.0:
                    interval_bytes = total_sent - last_bytes
                    interval_mbps = (interval_bytes * 8 / (now - last_check) / 1_000_000)
                    if interval_mbps > peak_mbps:
                        peak_mbps = interval_mbps
                    last_check = now
                    last_bytes = total_sent
        finally:
            sock.close()

        elapsed = time.time() - start_time
        throughput = (total_sent * 8 / elapsed / 1_000_000) if elapsed > 0 else 0
        if peak_mbps == 0:
            peak_mbps = throughput

        return {
            'bytes_sent': total_sent,
            'duration': round(elapsed, 2),
            'throughput_mbps': round(throughput, 2),
            'throughput_mbps_peak': round(peak_mbps, 2),
        }

    @staticmethod
    def get_network_status(
        connectivity_targets: Optional[List[Tuple[str, int]]] = None,
        latency_targets: Optional[List[Tuple[str, int]]] = None,
        timeout: float = 3.0,
    ) -> Dict[str, Any]:
        """
        获取综合网络状态快照：接口、连通性、延迟。

        返回:
            {'timestamp': str, 'local_ip': str, 'interfaces': [...],
             'connectivity': {...}, 'latency': {...}}
        """
        status: Dict[str, Any] = {
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'local_ip': get_local_ip(),
            'interfaces': get_all_local_ips(),
        }

        # 连通性
        status['connectivity'] = NetworkCore.check_connectivity(
            test_targets=connectivity_targets, timeout=timeout,
        )

        # 延迟（到常用服务）
        if latency_targets is None:
            latency_targets = [("8.8.8.8", 53), ("1.1.1.1", 53), ("baidu.com", 80)]
        latency_results = {}
        for host, port in latency_targets:
            result = NetworkCore.measure_latency(host, port, count=3, timeout=timeout)
            latency_results[f"{host}:{port}"] = result['avg_ms']
        status['latency'] = latency_results

        return status


# ========================================================================
# Ping 输出解析辅助函数
# ========================================================================

def _parse_ping_output(output: str, host: str) -> List[float]:
    """解析系统 ping 命令输出，返回延迟列表（毫秒）"""
    import re
    times: List[float] = []

    # Windows: "时间=XXms" 或 "time=XXms"
    # Linux: "time=XX.X ms"
    patterns = [
        r'时间[=<]\s*(\d+\.?\d*)\s*ms',
        r'time[=<]\s*(\d+\.?\d*)\s*ms',
        r'时间[=<](\d+)ms',
        r'time[=<](\d+\.?\d*)',
    ]

    for line in output.split('\n'):
        for pat in patterns:
            m = re.search(pat, line, re.IGNORECASE)
            if m:
                times.append(float(m.group(1)))
                break

    return times
