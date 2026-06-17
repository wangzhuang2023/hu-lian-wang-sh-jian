#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
netcli — 命令行 TCP/UDP 网络通信工具

用法:
    python netcli.py tcp server -p 8888 --echo
    python netcli.py tcp client -H 127.0.0.1 -p 8888 -m "hello"
    python netcli.py tcp send-file -H 127.0.0.1 -p 9999 -f ./test.bin
    python netcli.py tcp recv-file -p 9999 -o ./out
    python netcli.py tcp scan -H 127.0.0.1 -s 1 -e 1024
    python netcli.py udp send -H 127.0.0.1 -p 9999 -m "hello"
    python netcli.py udp listen -p 9999
    python netcli.py udp broadcast -p 9999 -m "hello"
    python netcli.py udp multicast -g 224.0.0.1 -p 9999 -m "hello" --listen
"""

import argparse
import sys
import signal
import threading
import time
import json
import os
from datetime import datetime

# 导入核心库
from netcore import (
    NetworkCore, StatsCounter, COMMON_PORTS, DEFAULT_ENCODINGS,
    format_bytes, human_time, validate_port, is_valid_host,
)


# ========================================================================
# 全局停止事件（用于 Ctrl+C 优雅关闭）
# ========================================================================
_stop_event = threading.Event()


def setup_signal_handlers():
    """注册 SIGINT/SIGTERM 信号处理，实现 Ctrl+C 优雅关闭"""
    def handler(signum, frame):
        if not _stop_event.is_set():
            print("\n正在关闭... (按两次 Ctrl+C 强制退出)", file=sys.stderr)
            _stop_event.set()
        else:
            print("\n强制退出", file=sys.stderr)
            sys.exit(1)
    signal.signal(signal.SIGINT, handler)
    try:
        signal.signal(signal.SIGTERM, handler)
    except AttributeError:
        pass  # Windows 无 SIGTERM


# ========================================================================
# 输出格式化器
# ========================================================================

class OutputFormatter:
    """双模式输出：人类可读（默认）和 JSON 行（--json）"""

    def __init__(self, json_mode: bool = False):
        self.json_mode = json_mode
        self._progress_last_len = 0

    def _now(self) -> str:
        """当前时间戳 ISO 格式"""
        return datetime.now().isoformat()

    def _ts(self) -> str:
        """人类可读的短时间戳"""
        return datetime.now().strftime('%H:%M:%S.%f')[:-3]

    def log(self, event: str, **kwargs):
        """输出事件日志"""
        if self.json_mode:
            entry = {"timestamp": self._now(), "event": event}
            entry.update(kwargs)
            # 将 tuple 地址转为字符串
            if 'addr' in entry and isinstance(entry['addr'], tuple):
                entry['addr'] = f"{entry['addr'][0]}:{entry['addr'][1]}"
            print(json.dumps(entry, ensure_ascii=False))
            sys.stdout.flush()
        else:
            msg = self._format_event(event, kwargs)
            print(f"[{self._ts()}] {msg}")
            sys.stdout.flush()

    def _format_event(self, event: str, kwargs: dict) -> str:
        """格式化人类可读事件"""
        if event == "server_start":
            return f"TCP 服务端启动 {kwargs.get('host', '?')}:{kwargs.get('port', '?')} (backlog={kwargs.get('backlog', '?')})"
        elif event == "server_stop":
            return f"TCP 服务端已停止 — {kwargs.get('summary', '')}"
        elif event == "client_connect":
            addr = kwargs.get('addr', '?')
            if isinstance(addr, tuple):
                addr = f"{addr[0]}:{addr[1]}"
            return f"新连接: {addr}"
        elif event == "client_disconnect":
            addr = kwargs.get('addr', '?')
            if isinstance(addr, tuple):
                addr = f"{addr[0]}:{addr[1]}"
            return f"连接断开: {addr}"
        elif event == "tcp_recv":
            addr = kwargs.get('addr', '?')
            if isinstance(addr, tuple):
                addr = f"{addr[0]}:{addr[1]}"
            msg = kwargs.get('message', '')
            return f"收到来自 {addr}: {msg}"
        elif event == "tcp_echo":
            addr = kwargs.get('addr', '?')
            if isinstance(addr, tuple):
                addr = f"{addr[0]}:{addr[1]}"
            return f"已回显至 {addr}"
        elif event == "tcp_client_connect":
            return f"已连接到 {kwargs.get('host', '?')}:{kwargs.get('port', '?')}"
        elif event == "tcp_client_sent":
            return f"已发送 {kwargs.get('bytes', 0)} 字节"
        elif event == "tcp_client_resp":
            return f"收到响应 ({kwargs.get('bytes', 0)} 字节): {kwargs.get('message', '')}"
        elif event == "tcp_client_no_resp":
            return "等待响应超时"
        elif event == "tcp_client_error":
            return f"错误: {kwargs.get('error', '未知错误')}"
        elif event == "udp_listen_start":
            return f"UDP 监听启动 {kwargs.get('host', '?')}:{kwargs.get('port', '?')}"
        elif event == "udp_listen_stop":
            return f"UDP 监听已停止 — {kwargs.get('summary', '')}"
        elif event == "udp_recv":
            addr = kwargs.get('addr', '?')
            if isinstance(addr, tuple):
                addr = f"{addr[0]}:{addr[1]}"
            return f"UDP 来自 {addr}: {kwargs.get('message', '')}"
        elif event == "udp_sent":
            return f"UDP 发送至 {kwargs.get('host', '?')}:{kwargs.get('port', '?')}: {kwargs.get('message', '')} ({kwargs.get('bytes', 0)} 字节)"
        elif event == "udp_broadcast":
            return f"UDP 广播至 255.255.255.255:{kwargs.get('port', '?')}: {kwargs.get('message', '')} ({kwargs.get('bytes', 0)} 字节)"
        elif event == "udp_multicast":
            return f"UDP 组播至 {kwargs.get('group', '?')}:{kwargs.get('port', '?')}: {kwargs.get('message', '')} ({kwargs.get('bytes', 0)} 字节)"
        elif event == "file_send_start":
            return f"发送 {kwargs.get('filename', '?')} ({format_bytes(kwargs.get('filesize', 0))}) 到 {kwargs.get('host', '?')}:{kwargs.get('port', '?')}"
        elif event == "file_send_done":
            return (f"发送完成: {kwargs.get('filename', '?')} "
                    f"({format_bytes(kwargs.get('bytes_sent', 0))}) "
                    f"耗时 {human_time(kwargs.get('elapsed', 0))} "
                    f"({kwargs.get('throughput_mbps', 0):.2f} Mbps)")
        elif event == "file_recv_waiting":
            return f"等待文件接收连接 {kwargs.get('host', '?')}:{kwargs.get('port', '?')} ..."
        elif event == "file_recv_done":
            return (f"接收完成: {kwargs.get('filename', '?')} -> {kwargs.get('saved_path', '?')} "
                    f"({format_bytes(kwargs.get('bytes_received', 0))}) "
                    f"耗时 {human_time(kwargs.get('elapsed', 0))} "
                    f"({kwargs.get('throughput_mbps', 0):.2f} Mbps)")
        elif event == "file_recv_error":
            return f"文件接收错误: {kwargs.get('error', '?')}"
        elif event == "listen_start":
            return f"TCP 端口监听启动 {kwargs.get('host', '?')}:{kwargs.get('port', '?')} (持续={kwargs.get('keep_open', False)}, hex={kwargs.get('hex', False)}, 回复={kwargs.get('reply', False)})"
        elif event == "listen_stop":
            return f"TCP 监听已停止 — {kwargs.get('summary', '')}"
        elif event == "listen_connect":
            addr = kwargs.get('addr', '?')
            if isinstance(addr, tuple):
                addr = f"{addr[0]}:{addr[1]}"
            return f"监听> 新连接: {addr}"
        elif event == "listen_disconnect":
            addr = kwargs.get('addr', '?')
            if isinstance(addr, tuple):
                addr = f"{addr[0]}:{addr[1]}"
            return f"监听> 连接断开: {addr}"
        elif event == "chat_connect":
            return f"聊天> 已连接到 {kwargs.get('host', '?')}:{kwargs.get('port', '?')}"
        elif event == "chat_disconnect":
            return f"聊天> 连接已断开"
        elif event == "dgram_sent":
            return (f"数据报文发送完成: 分片={kwargs.get('fragments', 0)}, "
                    f"有效载荷={format_bytes(kwargs.get('payload_size', 0))}, "
                    f"总字节={format_bytes(kwargs.get('bytes_sent', 0))}, "
                    f"耗时={human_time(kwargs.get('elapsed', 0))}")
        elif event == "dgram_recv":
            return (f"收到报文 #{kwargs.get('index', '?')}: "
                    f"{format_bytes(kwargs.get('size', 0))} "
                    f"({kwargs.get('frags_received', 0)}/{kwargs.get('total_frags', 0)} 分片)")
        elif event == "dgram_listen_start":
            return f"数据报文监听启动 {kwargs.get('host', '?')}:{kwargs.get('port', '?')}"
        elif event == "dgram_listen_stop":
            return f"数据报文监听已停止 — {kwargs.get('summary', '')}"
        elif event == "udp_binary_sent":
            return (f"UDP 二进制发送至 {kwargs.get('host', '?')}:{kwargs.get('port', '?')}: "
                    f"{format_bytes(kwargs.get('payload', 0))} ({kwargs.get('bytes', 0)} 字节)")
        elif event == "udp_binary_recv":
            return f"UDP 二进制接收: {format_bytes(kwargs.get('size', 0))} 来自 {kwargs.get('addr', '?')}"
        elif event == "scan_start":
            return f"扫描 {kwargs.get('target', '?')} 端口 {kwargs.get('start', '?')}-{kwargs.get('end', '?')} (超时={kwargs.get('timeout', '?')}s, {kwargs.get('workers', '?')} 并发)"
        elif event == "scan_result":
            return f"开放端口 ({kwargs.get('count', 0)} 个): {kwargs.get('ports', '')}"
        elif event == "scan_done":
            return f"扫描完成，耗时 {human_time(kwargs.get('elapsed', 0))}"
        elif event == "error":
            return f"错误: {kwargs.get('message', '未知错误')}"
        else:
            return f"{event}: {kwargs}"

    def progress(self, current: int, total: int, info: str = ""):
        """在 stderr 显示进度条（仅人类可读模式）"""
        if self.json_mode:
            return
        if total <= 0:
            return
        pct = current / total * 100
        bar_len = 30
        filled = int(bar_len * current / total)
        bar = '█' * filled + '░' * (bar_len - filled)
        line = f"\r  [{bar}] {pct:5.1f}%  {format_bytes(current)}/{format_bytes(total)}  {info}"
        # 清除之前行尾
        if len(line) < self._progress_last_len:
            line += ' ' * (self._progress_last_len - len(line))
        self._progress_last_len = len(line)
        sys.stderr.write(line)
        sys.stderr.flush()
        if current >= total:
            sys.stderr.write('\n')
            sys.stderr.flush()
            self._progress_last_len = 0

    def scan_progress(self, completed: int, total: int, open_count: int):
        """端口扫描进度（仅人类可读模式）"""
        if self.json_mode:
            return
        pct = completed / total * 100 if total > 0 else 0
        bar_len = 30
        filled = int(bar_len * completed / total) if total > 0 else 0
        bar = '█' * filled + '░' * (bar_len - filled)
        line = f"\r  [{bar}] {pct:5.1f}%  {completed}/{total}  开放: {open_count}"
        sys.stderr.write(line)
        sys.stderr.flush()
        if completed >= total:
            sys.stderr.write('\n')
            sys.stderr.flush()


# ========================================================================
# 公共参数
# ========================================================================

def add_encoding_arg(parser):
    parser.add_argument('--encoding', '-e', default='UTF-8', choices=DEFAULT_ENCODINGS,
                        help='数据编码 (默认: UTF-8)')


def add_host_port_args(parser, host_required=True):
    parser.add_argument('--host', '-H', required=host_required, help='目标主机名或 IP')
    parser.add_argument('--port', '-p', type=int, required=True, help='目标端口 (1-65535)')


def add_bind_port_args(parser):
    parser.add_argument('--bind', '-b', default='0.0.0.0', help='绑定地址 (默认: 0.0.0.0)')
    parser.add_argument('--port', '-p', type=int, required=True, help='监听端口 (1-65535)')


def add_timeout_arg(parser, default=5.0, help_text=None):
    parser.add_argument('--timeout', '-t', type=float, default=default,
                        help=help_text or f'超时秒数 (默认: {default})')


def add_json_arg(parser):
    parser.add_argument('--json', '-j', action='store_true', help='以 JSON 行格式输出')


# ========================================================================
# 子命令处理函数
# ========================================================================

def cmd_tcp_server(args):
    """处理 'tcp server' 子命令"""
    fmt = OutputFormatter(json_mode=args.json)
    stats = StatsCounter() if not args.json else None

    def on_connect(addr):
        fmt.log("client_connect", addr=addr)

    def on_disconnect(addr):
        fmt.log("client_disconnect", addr=addr)

    def on_data(addr, msg):
        fmt.log("tcp_recv", addr=addr, message=msg)
        if args.echo:
            fmt.log("tcp_echo", addr=addr)

    def on_error(msg):
        fmt.log("error", message=msg)

    fmt.log("server_start", host=args.bind, port=args.port,
            echo=args.echo, backlog=args.max_clients)

    try:
        NetworkCore.tcp_server(
            host=args.bind,
            port=args.port,
            stop_event=_stop_event,
            echo=args.echo,
            encoding=args.encoding,
            backlog=args.max_clients,
            stats=stats,
            on_client_connect=on_connect,
            on_client_disconnect=on_disconnect,
            on_data=on_data,
            on_error=on_error,
        )
    except Exception as e:
        fmt.log("error", message=str(e))

    if stats:
        s = stats.snapshot()
        summary = (f"发送 {format_bytes(s['sent_bytes'])}/{s['sent_packets']}包, "
                   f"接收 {format_bytes(s['recv_bytes'])}/{s['recv_packets']}包")
    else:
        summary = ""
    fmt.log("server_stop", summary=summary)


def cmd_tcp_client(args):
    """处理 'tcp client' 子命令"""
    fmt = OutputFormatter(json_mode=args.json)
    stats = StatsCounter() if not args.json else None

    # 处理消息输入（支持 stdin）
    message = args.message
    if message == '-':
        message = sys.stdin.read().rstrip('\n')

    try:
        resp = NetworkCore.tcp_client(
            host=args.host,
            port=args.port,
            message=message,
            encoding=args.encoding,
            timeout=args.timeout,
            expect_response=not args.no_response,
            stats=stats,
        )
        fmt.log("tcp_client_connect", host=args.host, port=args.port)
        if stats:
            fmt.log("tcp_client_sent", bytes=stats.sent_bytes)
        if resp:
            resp_text = resp.decode(args.encoding, errors='replace') if args.encoding not in ('Hex', 'Base64') else resp.hex()
            fmt.log("tcp_client_resp", bytes=len(resp), message=resp_text)
        elif not args.no_response:
            fmt.log("tcp_client_no_resp")
    except Exception as e:
        fmt.log("tcp_client_error", error=str(e))
        sys.exit(1)


def cmd_tcp_listen(args):
    """处理 'tcp listen' 子命令 — 端口监听（类似 netcat -l）"""
    fmt = OutputFormatter(json_mode=args.json)
    stats = StatsCounter() if not args.json else None

    def on_connect(addr):
        fmt.log("listen_connect", addr=addr)

    def on_disconnect(addr):
        fmt.log("listen_disconnect", addr=addr)

    def on_data(addr, data):
        if args.hex:
            # 十六进制转储格式
            hex_str = data.hex(' ')
            # 同时显示 ASCII 可打印字符
            ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data)
            msg = f"{hex_str}  |{ascii_str}|"
        else:
            # 尝试用指定编码解码
            try:
                msg = data.decode(args.encoding, errors='replace')
            except Exception:
                msg = data.hex(' ')
        fmt.log("tcp_recv", addr=addr, message=msg)

    def on_error(msg):
        fmt.log("error", message=msg)

    # 交互回复：从 stdin 读取一行发送回去
    reply_lock = threading.Lock()

    def get_reply():
        if not args.reply:
            return None
        try:
            line = sys.stdin.readline()
            if not line:
                return None
            return line.rstrip('\n').encode(args.encoding, errors='replace')
        except Exception:
            return None

    fmt.log("listen_start", host=args.bind, port=args.port,
            keep_open=args.keep_open, hex=args.hex, reply=args.reply)

    # 如果启用交互回复，在另一个线程中提示用户
    if args.reply:
        print(f"交互回复模式已启用 (编码: {args.encoding})", file=sys.stderr)
        print(f"输入回复内容后按回车发送，Ctrl+C 退出", file=sys.stderr)

    try:
        NetworkCore.tcp_listen(
            port=args.port,
            stop_event=_stop_event,
            bind_host=args.bind,
            encoding=args.encoding,
            keep_open=args.keep_open,
            timeout=args.timeout,
            stats=stats,
            on_connect=on_connect,
            on_disconnect=on_disconnect,
            on_data=on_data,
            on_error=on_error,
            get_reply=get_reply if args.reply else None,
        )
    except Exception as e:
        fmt.log("error", message=str(e))

    if stats:
        s = stats.snapshot()
        summary = (f"发送 {format_bytes(s['sent_bytes'])}/{s['sent_packets']}包, "
                   f"接收 {format_bytes(s['recv_bytes'])}/{s['recv_packets']}包")
    else:
        summary = f"接收 {0} 字节" if not stats else ""
    fmt.log("listen_stop", summary=summary)


def cmd_tcp_chat(args):
    """处理 'tcp chat' 子命令 — 交互式双向通信"""
    fmt = OutputFormatter(json_mode=args.json)
    stats = StatsCounter() if not args.json else None

    def on_connect(host, port):
        fmt.log("chat_connect", host=host, port=port)

    def on_data(data):
        # 输出到 stdout，加换行
        try:
            text = data.decode(args.encoding, errors='replace')
        except Exception:
            text = data.hex(' ')
        sys.stdout.write(text)
        sys.stdout.flush()

    def on_disconnect():
        fmt.log("chat_disconnect")

    def on_error(msg):
        fmt.log("error", message=msg)

    def get_input():
        """从 stdin 读取一行用户输入"""
        try:
            line = sys.stdin.readline()
            if not line:
                return None
            stripped = line.rstrip('\n')
            if stripped == '\\q':
                _stop_event.set()
                return None
            return (stripped + '\n').encode(args.encoding, errors='replace')
        except Exception:
            return None

    if not args.json:
        print(f"已连接到 {args.host}:{args.port} (输入 \\q 退出)", file=sys.stderr)

    try:
        NetworkCore.tcp_client_interactive(
            host=args.host,
            port=args.port,
            stop_event=_stop_event,
            encoding=args.encoding,
            timeout=args.timeout,
            stats=stats,
            on_connect=on_connect,
            on_data=on_data,
            on_disconnect=on_disconnect,
            on_error=on_error,
            get_input=get_input,
        )
    except Exception as e:
        fmt.log("error", message=str(e))

    if not args.json and stats:
        s = stats.snapshot()
        print(f"\n会话结束 — 发送 {format_bytes(s['sent_bytes'])}/{s['sent_packets']}包, "
              f"接收 {format_bytes(s['recv_bytes'])}/{s['recv_packets']}包", file=sys.stderr)


def cmd_tcp_send_file(args):
    """处理 'tcp send-file' 子命令"""
    fmt = OutputFormatter(json_mode=args.json)
    stats = StatsCounter() if not args.json else None

    filepath = args.file
    if not os.path.isfile(filepath):
        print(f"错误: 文件不存在: {filepath}", file=sys.stderr)
        sys.exit(1)

    filesize = os.path.getsize(filepath)
    filename = os.path.basename(filepath)

    def progress_cb(sent, total):
        fmt.progress(sent, total, info=f"{format_bytes(sent)}/{format_bytes(total)}")

    fmt.log("file_send_start", host=args.host, port=args.port,
            filename=filename, filesize=filesize)

    try:
        result = NetworkCore.tcp_send_file_stream(
            host=args.host,
            port=args.port,
            filepath=filepath,
            progress_cb=progress_cb,
            chunk_size=args.chunk_size,
            timeout=args.timeout,
            stats=stats,
        )
        fmt.log("file_send_done", **result)
    except Exception as e:
        fmt.log("error", message=str(e))
        sys.exit(1)


def cmd_tcp_recv_file(args):
    """处理 'tcp recv-file' 子命令"""
    fmt = OutputFormatter(json_mode=args.json)
    stats = StatsCounter() if not args.json else None

    def progress_cb(received, total):
        fmt.progress(received, total, info=f"{format_bytes(received)}/{format_bytes(total)}")

    fmt.log("file_recv_waiting", host=args.bind, port=args.port)

    try:
        result = NetworkCore.tcp_recv_file(
            port=args.port,
            save_dir=args.output,
            bind_host=args.bind,
            progress_cb=progress_cb,
            timeout=args.timeout,
            stats=stats,
        )
        fmt.log("file_recv_done", **result)
    except TimeoutError as e:
        fmt.log("file_recv_error", error=f"等待连接超时 ({args.timeout}s)")
        sys.exit(1)
    except Exception as e:
        fmt.log("file_recv_error", error=str(e))
        sys.exit(1)


def cmd_tcp_scan(args):
    """处理 'tcp scan' 子命令"""
    fmt = OutputFormatter(json_mode=args.json)

    def progress_cb(completed, total, open_count):
        fmt.scan_progress(completed, total, open_count)

    fmt.log("scan_start", target=args.host, start=args.start_port,
            end=args.end_port, timeout=args.timeout, workers=args.workers)

    start = time.time()
    try:
        open_ports = NetworkCore.port_scan(
            target=args.host,
            start_port=args.start_port,
            end_port=args.end_port,
            timeout=args.timeout,
            max_workers=args.workers,
            progress_cb=progress_cb,
        )
    except Exception as e:
        fmt.log("error", message=str(e))
        sys.exit(1)

    elapsed = time.time() - start

    if args.json:
        for p in open_ports:
            service = COMMON_PORTS.get(p, "unknown")
            print(json.dumps({"port": p, "service": service}, ensure_ascii=False))
        fmt.log("scan_done", elapsed=elapsed, count=len(open_ports))
    else:
        if open_ports:
            print(f"\n开放端口 ({len(open_ports)} 个):")
            print(f"  {'端口':<8} {'服务'}")
            print(f"  {'-'*6}  {'-'*20}")
            for p in open_ports:
                service = COMMON_PORTS.get(p, "—")
                print(f"  {p:<8} {service}")
        else:
            print("\n未发现开放端口")
        fmt.log("scan_done", elapsed=elapsed)


def cmd_udp_send(args):
    """处理 'udp send' 子命令"""
    fmt = OutputFormatter(json_mode=args.json)
    stats = StatsCounter() if not args.json else None

    message = args.message
    if message == '-':
        message = sys.stdin.read().rstrip('\n')

    for i in range(args.count):
        try:
            sent = NetworkCore.udp_send(
                host=args.host,
                port=args.port,
                message=message,
                encoding=args.encoding,
                broadcast=False,
                stats=stats,
            )
            fmt.log("udp_sent", host=args.host, port=args.port,
                    message=message[:100] if len(message) > 100 else message,
                    bytes=sent)
        except Exception as e:
            fmt.log("error", message=str(e))
            sys.exit(1)

        if i < args.count - 1 and args.interval > 0:
            time.sleep(args.interval)


def cmd_udp_listen(args):
    """处理 'udp listen' 子命令"""
    fmt = OutputFormatter(json_mode=args.json)
    stats = StatsCounter() if not args.json else None

    def on_data(addr, msg):
        fmt.log("udp_recv", addr=addr, message=msg)

    def on_error(msg):
        fmt.log("error", message=msg)

    fmt.log("udp_listen_start", host=args.bind, port=args.port)

    try:
        NetworkCore.udp_listen(
            port=args.port,
            stop_event=_stop_event,
            bind_host=args.bind,
            encoding=args.encoding,
            timeout=args.timeout,
            stats=stats,
            on_data=on_data,
            on_error=on_error,
        )
    except Exception as e:
        fmt.log("error", message=str(e))

    if stats:
        s = stats.snapshot()
        summary = f"接收 {format_bytes(s['recv_bytes'])}/{s['recv_packets']}包"
    else:
        summary = ""
    fmt.log("udp_listen_stop", summary=summary)


def cmd_udp_broadcast(args):
    """处理 'udp broadcast' 子命令"""
    fmt = OutputFormatter(json_mode=args.json)
    stats = StatsCounter() if not args.json else None

    message = args.message
    if message == '-':
        message = sys.stdin.read().rstrip('\n')

    for i in range(args.count):
        try:
            sent = NetworkCore.udp_send(
                host="255.255.255.255",
                port=args.port,
                message=message,
                encoding=args.encoding,
                broadcast=True,
                stats=stats,
            )
            fmt.log("udp_broadcast", port=args.port,
                    message=message[:100] if len(message) > 100 else message,
                    bytes=sent)
        except Exception as e:
            fmt.log("error", message=str(e))
            sys.exit(1)

        if i < args.count - 1 and args.interval > 0:
            time.sleep(args.interval)


def cmd_udp_multicast(args):
    """处理 'udp multicast' 子命令"""
    fmt = OutputFormatter(json_mode=args.json)
    stats = StatsCounter() if not args.json else None

    message = args.message
    if message == '-':
        message = sys.stdin.read().rstrip('\n')

    # 如果指定了 --listen，在后台线程中启动组播监听
    listen_thread = None
    if args.listen:
        def on_data(addr, msg):
            fmt.log("udp_recv", addr=addr, message=msg)

        listen_thread = threading.Thread(
            target=NetworkCore.udp_multicast_listen,
            args=(args.group, args.port, _stop_event, args.encoding, stats, on_data),
            daemon=True,
        )
        listen_thread.start()
        time.sleep(0.3)  # 给监听线程一些启动时间

    for i in range(args.count):
        try:
            sent = NetworkCore.udp_send(
                host=args.group,
                port=args.port,
                message=message,
                encoding=args.encoding,
                multicast_group=args.group,
                multicast_ttl=args.ttl,
                stats=stats,
            )
            fmt.log("udp_multicast", group=args.group, port=args.port,
                    message=message[:100] if len(message) > 100 else message,
                    bytes=sent)
        except Exception as e:
            fmt.log("error", message=str(e))
            sys.exit(1)

        if i < args.count - 1 and args.interval > 0:
            time.sleep(args.interval)


def cmd_udp_dgram_send(args):
    """处理 'udp dgram-send' 子命令 — 发送数据报文（支持分片/ACK）"""
    fmt = OutputFormatter(json_mode=args.json)
    stats = StatsCounter() if not args.json else None

    # 获取数据
    if args.data == '-':
        data = sys.stdin.buffer.read()
    elif args.file:
        if not os.path.isfile(args.file):
            print(f"错误: 文件不存在: {args.file}", file=sys.stderr)
            sys.exit(1)
        with open(args.file, 'rb') as f:
            data = f.read()
    elif args.message:
        data = args.message.encode(args.encoding, errors='replace')
    else:
        data = sys.stdin.buffer.read()

    if not data:
        print("错误: 无数据可发送", file=sys.stderr)
        sys.exit(1)

    if not args.json:
        print(f"发送 {format_bytes(len(data))} 到 {args.host}:{args.port} "
              f"(MTU={args.mtu}, ACK={args.ack}, 分片阈值={args.mtu - 18}B)",
              file=sys.stderr)

    try:
        result = NetworkCore.udp_send_datagram(
            host=args.host,
            port=args.port,
            data=data,
            mtu=args.mtu,
            require_ack=args.ack,
            ack_timeout=args.ack_timeout,
            stats=stats,
        )
    except Exception as e:
        fmt.log("error", message=str(e))
        sys.exit(1)

    if args.json:
        fmt.log("dgram_sent", **result)
    else:
        print(f"\n发送完成:")
        print(f"  有效载荷: {format_bytes(result['payload_size'])}")
        print(f"  分片数:   {result['fragments']}")
        print(f"  总字节:   {format_bytes(result['bytes_sent'])}")
        print(f"  耗时:     {human_time(result['elapsed'])}")
        if args.ack:
            print(f"  ACK 确认: {result.get('acked', 0)}/{result['fragments']}")


def cmd_udp_dgram_recv(args):
    """处理 'udp dgram-recv' 子命令 — 接收数据报文（自动重组）"""
    fmt = OutputFormatter(json_mode=args.json)
    stats = StatsCounter() if not args.json else None
    messages_received = [0]  # 用列表以便在闭包中修改
    total_bytes = [0]

    def on_message(addr, data, meta):
        messages_received[0] += 1
        total_bytes[0] += len(data)
        if args.output:
            # 保存到文件
            os.makedirs(args.output, exist_ok=True)
            fname = f"dgram_{addr[0].replace(':', '_')}_{addr[1]}_{meta['seq']}.bin"
            fpath = os.path.join(args.output, fname)
            with open(fpath, 'wb') as f:
                f.write(data)
            if not args.json:
                print(f"[{fmt._ts()}] 收到消息 #{messages_received[0]}: "
                      f"{format_bytes(len(data))} (分片={meta['frags_received']}/{meta['total_frags']}) "
                      f"-> {fpath}")
        elif args.json:
            fmt.log("dgram_recv", addr=f"{addr[0]}:{addr[1]}",
                    size=len(data), seq=meta['seq'],
                    frags_received=meta['frags_received'],
                    total_frags=meta['total_frags'],
                    index=messages_received[0])
        else:
            # 尝试显示文本内容
            try:
                text = data.decode(args.encoding, errors='replace')
                if len(text) > 500:
                    text = text[:500] + f"\n... (截断，共 {len(data)} 字节)"
            except Exception:
                text = f"<二进制数据 {len(data)} 字节>"
            print(f"\n[{fmt._ts()}] 消息 #{messages_received[0]} "
                  f"({format_bytes(len(data))}, {meta['frags_received']}/{meta['total_frags']} 分片):")
            print(f"  来源: {addr[0]}:{addr[1]}")
            print(f"  内容: {text}")

    fmt.log("dgram_listen_start", host=args.bind, port=args.port)

    try:
        NetworkCore.udp_recv_datagram(
            port=args.port,
            stop_event=_stop_event,
            bind_host=args.bind,
            timeout=args.timeout,
            send_ack=args.ack,
            stats=stats,
            on_message=on_message,
        )
    except Exception as e:
        fmt.log("error", message=str(e))

    if stats:
        s = stats.snapshot()
    else:
        s = {"sent_bytes": 0, "sent_packets": 0, "recv_bytes": 0, "recv_packets": 0}
    summary = (f"接收 {format_bytes(s['recv_bytes'])}/{s['recv_packets']}包, "
               f"{messages_received[0]} 条完整消息")
    fmt.log("dgram_listen_stop", summary=summary)


def cmd_udp_binary_send(args):
    """处理 'udp binary-send' 子命令 — 发送原始二进制数据"""
    fmt = OutputFormatter(json_mode=args.json)
    stats = StatsCounter() if not args.json else None

    if args.data == '-':
        data = sys.stdin.buffer.read()
    elif args.file:
        if not os.path.isfile(args.file):
            print(f"错误: 文件不存在: {args.file}", file=sys.stderr)
            sys.exit(1)
        with open(args.file, 'rb') as f:
            data = f.read()
    else:
        print("错误: 需要 --data 或 --file 指定数据源", file=sys.stderr)
        sys.exit(1)

    try:
        sent = NetworkCore.udp_send_binary(
            host=args.host,
            port=args.port,
            data=data,
            stats=stats,
        )
        if args.json:
            fmt.log("udp_binary_sent", host=args.host, port=args.port,
                    bytes=sent, payload=len(data))
        else:
            print(f"已发送 {format_bytes(len(data))} ({sent} 字节) 到 {args.host}:{args.port}")
    except Exception as e:
        fmt.log("error", message=str(e))
        sys.exit(1)


def cmd_udp_binary_recv(args):
    """处理 'udp binary-recv' 子命令 — 接收原始二进制数据"""
    fmt = OutputFormatter(json_mode=args.json)
    stats = StatsCounter() if not args.json else None

    def on_data(addr, data):
        if args.output:
            os.makedirs(args.output, exist_ok=True)
            fname = f"udp_{addr[0].replace(':', '_')}_{addr[1]}.bin"
            fpath = os.path.join(args.output, fname)
            with open(fpath, 'wb') as f:
                f.write(data)
            if not args.json:
                print(f"[{fmt._ts()}] 收到 {format_bytes(len(data))} 来自 {addr[0]}:{addr[1]} -> {fpath}")
        elif args.json:
            fmt.log("udp_binary_recv", addr=f"{addr[0]}:{addr[1]}", size=len(data))
        else:
            hex_preview = data[:64].hex(' ')
            if len(data) > 64:
                hex_preview += f" ... ({len(data)} 字节)"
            print(f"[{fmt._ts()}] 收到 {format_bytes(len(data))} 来自 {addr[0]}:{addr[1]}:")
            print(f"  {hex_preview}")

    fmt.log("dgram_listen_start", host=args.bind, port=args.port)

    try:
        NetworkCore.udp_recv_binary(
            port=args.port,
            stop_event=_stop_event,
            bind_host=args.bind,
            timeout=args.timeout,
            buffer_size=args.buffer_size,
            stats=stats,
            on_data=on_data,
        )
    except Exception as e:
        fmt.log("error", message=str(e))

    if stats:
        s = stats.snapshot()
        summary = f"接收 {format_bytes(s['recv_bytes'])}/{s['recv_packets']}包"
    else:
        summary = ""
    fmt.log("dgram_listen_stop", summary=summary)


# ========================================================================
# argparse 解析器构建
# ========================================================================

def build_parser() -> argparse.ArgumentParser:
    """构建完整的命令行参数解析器"""
    parser = argparse.ArgumentParser(
        prog='netcli',
        description='命令行 TCP/UDP 网络通信工具',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
示例:
  python netcli.py tcp server -p 8888 --echo
  python netcli.py tcp client -H 127.0.0.1 -p 8888 -m "hello"
  python netcli.py tcp send-file -H 127.0.0.1 -p 9999 -f ./test.bin
  python netcli.py tcp recv-file -p 9999 -o ./out
  python netcli.py tcp scan -H 127.0.0.1 -s 1 -e 1024
  python netcli.py udp listen -p 9999
  python netcli.py udp send -H 127.0.0.1 -p 9999 -m "hello"
  python netcli.py udp broadcast -p 9999 -m "hello"
  python netcli.py udp multicast -g 224.0.0.1 -p 9999 -m "hello" --listen
        ''',
    )

    subparsers = parser.add_subparsers(dest='command', help='可用子命令')

    # ---- TCP 子命令组 ----
    tcp_parser = subparsers.add_parser('tcp', help='TCP 通信命令')
    tcp_sub = tcp_parser.add_subparsers(dest='subcommand', help='TCP 子命令')

    # tcp server
    p = tcp_sub.add_parser('server', help='启动 TCP 服务端')
    p.add_argument('--bind', '-b', default='0.0.0.0', help='绑定地址 (默认: 0.0.0.0)')
    p.add_argument('--port', '-p', type=int, required=True, help='监听端口 (1-65535)')
    p.add_argument('--echo', action='store_true', help='回显收到的数据')
    p.add_argument('--max-clients', type=int, default=10, help='最大等待连接数 (默认: 10)')
    add_encoding_arg(p)
    add_json_arg(p)
    p.set_defaults(func=cmd_tcp_server)

    # tcp client
    p = tcp_sub.add_parser('client', help='TCP 客户端发送消息')
    p.add_argument('--host', '-H', required=True, help='目标主机名或 IP')
    p.add_argument('--port', '-p', type=int, required=True, help='目标端口 (1-65535)')
    p.add_argument('--message', '-m', required=True, help='要发送的消息 (使用 "-" 从 stdin 读取)')
    p.add_argument('--no-response', '-n', action='store_true', help='不等待响应')
    add_timeout_arg(p, default=5.0, help_text='连接/读取超时秒数')
    add_encoding_arg(p)
    add_json_arg(p)
    p.set_defaults(func=cmd_tcp_client)

    # tcp send-file
    p = tcp_sub.add_parser('send-file', help='TCP 发送文件')
    p.add_argument('--host', '-H', required=True, help='目标主机名或 IP')
    p.add_argument('--port', '-p', type=int, required=True, help='目标端口 (1-65535)')
    p.add_argument('--file', '-f', required=True, help='要发送的文件路径')
    p.add_argument('--chunk-size', type=int, default=65536, help='传输块大小 (默认: 65536)')
    add_timeout_arg(p, default=30.0, help_text='连接超时秒数')
    add_json_arg(p)
    p.set_defaults(func=cmd_tcp_send_file)

    # tcp recv-file
    p = tcp_sub.add_parser('recv-file', help='TCP 接收文件')
    p.add_argument('--port', '-p', type=int, required=True, help='监听端口 (1-65535)')
    p.add_argument('--output', '-o', default='.', help='保存目录 (默认: 当前目录)')
    p.add_argument('--bind', '-b', default='0.0.0.0', help='绑定地址 (默认: 0.0.0.0)')
    add_timeout_arg(p, default=0.0, help_text='等待连接超时秒数 (0=永久)')
    add_json_arg(p)
    p.set_defaults(func=cmd_tcp_recv_file)

    # tcp listen — 端口监听（netcat -l 模式）
    p = tcp_sub.add_parser('listen', help='TCP 端口监听 (类似 nc -l)')
    p.add_argument('--port', '-p', type=int, required=True, help='监听端口 (1-65535)')
    p.add_argument('--bind', '-b', default='0.0.0.0', help='绑定地址 (默认: 0.0.0.0)')
    p.add_argument('--keep-open', '-k', action='store_true', help='持续监听，断开后接受新连接')
    p.add_argument('--reply', '-r', action='store_true', help='交互回复模式 (从 stdin 读取回复)')
    p.add_argument('--hex', action='store_true', help='以十六进制转储格式显示数据')
    add_timeout_arg(p, default=0.0, help_text='总监听超时秒数 (0=永久)')
    add_encoding_arg(p)
    add_json_arg(p)
    p.set_defaults(func=cmd_tcp_listen)

    # tcp chat — 交互式双向通信
    p = tcp_sub.add_parser('chat', help='TCP 交互式聊天')
    p.add_argument('--host', '-H', required=True, help='目标主机名或 IP')
    p.add_argument('--port', '-p', type=int, required=True, help='目标端口 (1-65535)')
    add_timeout_arg(p, default=5.0, help_text='连接超时秒数')
    add_encoding_arg(p)
    add_json_arg(p)
    p.set_defaults(func=cmd_tcp_chat)

    # tcp scan
    p = tcp_sub.add_parser('scan', help='TCP 端口扫描')
    p.add_argument('--host', '-H', required=True, help='目标 IP 或主机名')
    p.add_argument('--start-port', '-s', type=int, required=True, help='起始端口')
    p.add_argument('--end-port', '-e', type=int, required=True, help='结束端口')
    add_timeout_arg(p, default=1.0, help_text='每端口连接超时秒数')
    p.add_argument('--workers', '-w', type=int, default=100, help='最大并发扫描线程 (默认: 100)')
    add_json_arg(p)
    p.set_defaults(func=cmd_tcp_scan)

    # ---- UDP 子命令组 ----
    udp_parser = subparsers.add_parser('udp', help='UDP 通信命令')
    udp_sub = udp_parser.add_subparsers(dest='subcommand', help='UDP 子命令')

    # udp send
    p = udp_sub.add_parser('send', help='UDP 发送数据报')
    p.add_argument('--host', '-H', required=True, help='目标主机名或 IP')
    p.add_argument('--port', '-p', type=int, required=True, help='目标端口 (1-65535)')
    p.add_argument('--message', '-m', required=True, help='要发送的消息 (使用 "-" 从 stdin 读取)')
    p.add_argument('--count', '-c', type=int, default=1, help='发送次数 (默认: 1)')
    p.add_argument('--interval', '-i', type=float, default=1.0, help='发送间隔秒数 (默认: 1.0)')
    add_encoding_arg(p)
    add_json_arg(p)
    p.set_defaults(func=cmd_udp_send)

    # udp listen
    p = udp_sub.add_parser('listen', help='UDP 监听数据报')
    p.add_argument('--port', '-p', type=int, required=True, help='监听端口 (1-65535)')
    p.add_argument('--bind', '-b', default='0.0.0.0', help='绑定地址 (默认: 0.0.0.0)')
    add_timeout_arg(p, default=0.0, help_text='监听超时秒数 (0=永久)')
    add_encoding_arg(p)
    add_json_arg(p)
    p.set_defaults(func=cmd_udp_listen)

    # udp broadcast
    p = udp_sub.add_parser('broadcast', help='UDP 广播')
    p.add_argument('--port', '-p', type=int, required=True, help='目标端口 (1-65535)')
    p.add_argument('--message', '-m', required=True, help='广播消息 (使用 "-" 从 stdin 读取)')
    p.add_argument('--count', '-c', type=int, default=1, help='广播次数 (默认: 1)')
    p.add_argument('--interval', '-i', type=float, default=1.0, help='广播间隔秒数 (默认: 1.0)')
    add_encoding_arg(p)
    add_json_arg(p)
    p.set_defaults(func=cmd_udp_broadcast)

    # udp multicast
    p = udp_sub.add_parser('multicast', help='UDP 组播')
    p.add_argument('--group', '-g', required=True, help='组播组地址 (如 224.0.0.1)')
    p.add_argument('--port', '-p', type=int, required=True, help='目标端口 (1-65535)')
    p.add_argument('--message', '-m', required=True, help='组播消息 (使用 "-" 从 stdin 读取)')
    p.add_argument('--ttl', type=int, default=2, help='组播 TTL (默认: 2)')
    p.add_argument('--listen', action='store_true', help='同时加入组播组并监听响应')
    p.add_argument('--count', '-c', type=int, default=1, help='发送次数 (默认: 1)')
    p.add_argument('--interval', '-i', type=float, default=1.0, help='发送间隔秒数 (默认: 1.0)')
    add_encoding_arg(p)
    add_json_arg(p)
    p.set_defaults(func=cmd_udp_multicast)

    # udp dgram-send — 数据报文发送（分片/ACK）
    p = udp_sub.add_parser('dgram-send', help='UDP 数据报文发送 (支持分片与 ACK)')
    p.add_argument('--host', '-H', required=True, help='目标主机名或 IP')
    p.add_argument('--port', '-p', type=int, required=True, help='目标端口 (1-65535)')
    p.add_argument('--data', '-d', default=None, help='要发送的数据 (使用 "-" 从 stdin 读取)')
    p.add_argument('--message', '-m', default=None, help='要发送的文本消息')
    p.add_argument('--file', '-f', default=None, help='从文件读取数据')
    p.add_argument('--mtu', type=int, default=1400, help='最大传输单元 (默认: 1400)')
    p.add_argument('--ack', action='store_true', help='要求接收方发送 ACK 确认')
    p.add_argument('--ack-timeout', type=float, default=3.0, help='ACK 等待超时秒数 (默认: 3.0)')
    add_encoding_arg(p)
    add_json_arg(p)
    p.set_defaults(func=cmd_udp_dgram_send)

    # udp dgram-recv — 数据报文接收（重组/ACK）
    p = udp_sub.add_parser('dgram-recv', help='UDP 数据报文接收 (自动重组)')
    p.add_argument('--port', '-p', type=int, required=True, help='监听端口 (1-65535)')
    p.add_argument('--bind', '-b', default='0.0.0.0', help='绑定地址 (默认: 0.0.0.0)')
    p.add_argument('--output', '-o', default=None, help='保存目录 (默认: 输出到终端)')
    p.add_argument('--ack', action='store_true', help='发送 ACK 确认给发送方')
    add_timeout_arg(p, default=0.0, help_text='监听超时秒数 (0=永久)')
    add_encoding_arg(p)
    add_json_arg(p)
    p.set_defaults(func=cmd_udp_dgram_recv)

    # udp binary-send — 原始二进制发送
    p = udp_sub.add_parser('binary-send', help='UDP 原始二进制数据发送')
    p.add_argument('--host', '-H', required=True, help='目标主机名或 IP')
    p.add_argument('--port', '-p', type=int, required=True, help='目标端口 (1-65535)')
    p.add_argument('--data', '-d', default=None, help='要发送的数据 (使用 "-" 从 stdin 读取)')
    p.add_argument('--file', '-f', default=None, help='从文件读取二进制数据')
    add_json_arg(p)
    p.set_defaults(func=cmd_udp_binary_send)

    # udp binary-recv — 原始二进制接收
    p = udp_sub.add_parser('binary-recv', help='UDP 原始二进制数据接收')
    p.add_argument('--port', '-p', type=int, required=True, help='监听端口 (1-65535)')
    p.add_argument('--bind', '-b', default='0.0.0.0', help='绑定地址 (默认: 0.0.0.0)')
    p.add_argument('--output', '-o', default=None, help='保存目录 (默认: 输出十六进制预览)')
    p.add_argument('--buffer-size', type=int, default=65536, help='接收缓冲区大小 (默认: 65536)')
    add_timeout_arg(p, default=0.0, help_text='监听超时秒数 (0=永久)')
    add_json_arg(p)
    p.set_defaults(func=cmd_udp_binary_recv)

    return parser


# ========================================================================
# 入口
# ========================================================================

def main():
    """CLI 入口"""
    setup_signal_handlers()
    parser = build_parser()
    args = parser.parse_args()

    if not hasattr(args, 'func'):
        parser.print_help()
        sys.exit(1)

    # 执行子命令处理函数
    args.func(args)


if __name__ == '__main__':
    main()
