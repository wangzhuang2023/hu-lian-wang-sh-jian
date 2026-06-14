#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
多协议网络通信与状态监测平台
功能：TCP服务端/客户端、UDP收发、端口扫描、Ping检测、实时仪表盘
作者：NetworkEngineering
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import socket
import struct
import json
import os
import time
import subprocess
import platform
import logging
from datetime import datetime

# ---------- 全局配置 ----------
CONFIG_FILE = "net_tool_config.json"
LOG_FILE = "net_tool.log"

# 日志配置
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE, encoding='utf-8'),
        logging.StreamHandler()
    ]
)

# ---------- 工具函数 ----------
def is_ipv4(addr):
    try:
        socket.inet_pton(socket.AF_INET, addr)
        return True
    except:
        return False

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"

# ---------- 配置管理 ----------
def load_config():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_config(config):
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f, indent=2)

# ---------- 网络核心 ----------
class NetworkCore:
    """网络通信核心逻辑，与UI分离"""

    @staticmethod
    def tcp_server_listen(host, port, callback_log, callback_clients, stop_event):
        """TCP服务端监听，支持多客户端"""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((host, port))
        server.listen(5)
        server.settimeout(1.0)  # 可中断
        callback_log(f"TCP服务端启动 {host}:{port}")
        clients = {}  # {conn: addr}
        while not stop_event.is_set():
            try:
                conn, addr = server.accept()
                callback_log(f"新连接: {addr}")
                clients[conn] = addr
                callback_clients(clients)
                # 为新连接启动接收线程
                t = threading.Thread(target=NetworkCore.tcp_server_recv,
                                     args=(conn, addr, callback_log, clients, stop_event),
                                     daemon=True)
                t.start()
            except socket.timeout:
                continue
            except Exception as e:
                if not stop_event.is_set():
                    callback_log(f"服务端错误: {e}")
                break
        server.close()
        callback_log("TCP服务端已停止")

    @staticmethod
    def tcp_server_recv(conn, addr, callback_log, clients, stop_event):
        while not stop_event.is_set():
            try:
                data = conn.recv(4096)
                if not data:
                    break
                msg = data.decode(errors='replace')
                callback_log(f"收到来自{addr}: {msg}")
                # 可以自动回复
                # conn.sendall(data)
            except:
                break
        conn.close()
        if conn in clients:
            del clients[conn]
        callback_log(f"连接断开: {addr}")

    @staticmethod
    def tcp_client_send(host, port, message, callback_log, stop_event):
        try:
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.settimeout(5)
            client.connect((host, port))
            client.sendall(message.encode())
            callback_log(f"已发送至{host}:{port}: {message}")
            # 接收响应（可选）
            client.settimeout(2)
            try:
                resp = client.recv(4096)
                callback_log(f"收到响应: {resp.decode(errors='replace')}")
            except:
                pass
            client.close()
        except Exception as e:
            callback_log(f"TCP客户端错误: {e}")

    @staticmethod
    def udp_send(host, port, message, callback_log):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(message.encode(), (host, port))
            callback_log(f"UDP发送至{host}:{port}: {message}")
            sock.close()
        except Exception as e:
            callback_log(f"UDP发送错误: {e}")

    @staticmethod
    def udp_listen(port, callback_log, stop_event):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("0.0.0.0", port))
        sock.settimeout(1)
        callback_log(f"UDP监听启动 0.0.0.0:{port}")
        while not stop_event.is_set():
            try:
                data, addr = sock.recvfrom(2048)
                callback_log(f"UDP来自{addr}: {data.decode(errors='replace')}")
            except socket.timeout:
                continue
            except Exception as e:
                callback_log(f"UDP监听错误: {e}")
                break
        sock.close()
        callback_log("UDP监听已停止")

    @staticmethod
    def port_scan(target, start_port, end_port, callback_log, callback_result):
        """多线程端口扫描"""
        open_ports = []
        lock = threading.Lock()

        def scan_port(p):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((target, p))
                if result == 0:
                    with lock:
                        open_ports.append(p)
                sock.close()
            except:
                pass

        threads = []
        for port in range(start_port, end_port + 1):
            t = threading.Thread(target=scan_port, args=(port,))
            t.start()
            threads.append(t)
        for t in threads:
            t.join()
        open_ports.sort()
        callback_result(open_ports)
        callback_log(f"端口扫描完成，{target} 开放端口: {open_ports}")

    @staticmethod
    def ping_host(host, count=4, callback_log=None):
        """跨平台Ping检测"""
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        cmd = ['ping', param, str(count), host]
        try:
            output = subprocess.check_output(cmd, universal_newlines=True, stderr=subprocess.STDOUT)
            if callback_log:
                callback_log(output)
            return output
        except subprocess.CalledProcessError as e:
            if callback_log:
                callback_log(f"Ping失败: {e.output}")
            return e.output

# ---------- 主界面 ----------
class NetworkToolApp:
    def __init__(self, root):
        self.root = root
        self.root.title("多协议网络通信与状态监测平台")
        self.root.geometry("1000x700")

        # 状态变量
        self.tcp_server_stop = threading.Event()
        self.udp_listen_stop = threading.Event()
        self.tcp_clients = {}
        self.config = load_config()

        # 日志队列（UI线程安全）
        self.log_lock = threading.Lock()

        self.create_widgets()

    def create_widgets(self):
        # 笔记本（标签页）
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # ---------- TCP 标签页 ----------
        self.tcp_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.tcp_frame, text="TCP 通信")
        self.build_tcp_tab()

        # ---------- UDP 标签页 ----------
        self.udp_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.udp_frame, text="UDP 通信")
        self.build_udp_tab()

        # ---------- 端口扫描标签页 ----------
        self.scan_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.scan_frame, text="端口扫描")
        self.build_scan_tab()

        # ---------- Ping 标签页 ----------
        self.ping_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.ping_frame, text="Ping 检测")
        self.build_ping_tab()

        # ---------- 仪表盘标签页 ----------
        self.dash_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.dash_frame, text="状态仪表盘")
        self.build_dash_tab()

        # 状态栏
        self.status_var = tk.StringVar()
        status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        self.status_var.set("就绪")

    # ========== TCP 标签页构建 ==========
    def build_tcp_tab(self):
        # 左侧控制区
        left_frame = ttk.Frame(self.tcp_frame)
        left_frame.pack(side=tk.LEFT, fill=tk.Y, padx=5, pady=5)

        # 服务端设置
        ttk.Label(left_frame, text="TCP 服务端").grid(row=0, column=0, columnspan=2, pady=5)
        ttk.Label(left_frame, text="监听IP:").grid(row=1, column=0, sticky=tk.W)
        self.tcp_server_ip = ttk.Entry(left_frame, width=15)
        self.tcp_server_ip.insert(0, "0.0.0.0")
        self.tcp_server_ip.grid(row=1, column=1, padx=5)
        ttk.Label(left_frame, text="端口:").grid(row=2, column=0, sticky=tk.W)
        self.tcp_server_port = ttk.Entry(left_frame, width=8)
        self.tcp_server_port.insert(0, "8888")
        self.tcp_server_port.grid(row=2, column=1, sticky=tk.W, padx=5)
        self.tcp_server_btn = ttk.Button(left_frame, text="启动服务端", command=self.toggle_tcp_server)
        self.tcp_server_btn.grid(row=3, column=0, columnspan=2, pady=5)

        # 分隔线
        ttk.Separator(left_frame, orient='horizontal').grid(row=4, column=0, columnspan=2, sticky=tk.EW, pady=10)

        # 客户端设置
        ttk.Label(left_frame, text="TCP 客户端").grid(row=5, column=0, columnspan=2, pady=5)
        ttk.Label(left_frame, text="目标IP:").grid(row=6, column=0, sticky=tk.W)
        self.tcp_client_ip = ttk.Entry(left_frame, width=15)
        self.tcp_client_ip.insert(0, "127.0.0.1")
        self.tcp_client_ip.grid(row=6, column=1)
        ttk.Label(left_frame, text="端口:").grid(row=7, column=0, sticky=tk.W)
        self.tcp_client_port = ttk.Entry(left_frame, width=8)
        self.tcp_client_port.insert(0, "8888")
        self.tcp_client_port.grid(row=7, column=1, sticky=tk.W)
        ttk.Label(left_frame, text="发送内容:").grid(row=8, column=0, sticky=tk.W)
        self.tcp_client_msg = ttk.Entry(left_frame, width=20)
        self.tcp_client_msg.insert(0, "Hello TCP")
        self.tcp_client_msg.grid(row=8, column=1)
        self.tcp_client_btn = ttk.Button(left_frame, text="发送", command=self.send_tcp)
        self.tcp_client_btn.grid(row=9, column=0, columnspan=2, pady=5)

        # 右侧日志区
        right_frame = ttk.Frame(self.tcp_frame)
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.tcp_log = scrolledtext.ScrolledText(right_frame, height=20, width=60)
        self.tcp_log.pack(fill=tk.BOTH, expand=True)
        ttk.Button(right_frame, text="清空日志", command=lambda: self.tcp_log.delete(1.0, tk.END)).pack(pady=2)

    def toggle_tcp_server(self):
        if hasattr(self, 'tcp_server_thread') and self.tcp_server_thread.is_alive():
            self.tcp_server_stop.set()
            self.tcp_server_btn.config(text="启动服务端")
            self.log_tcp("正在停止服务端...")
        else:
            self.tcp_server_stop.clear()
            host = self.tcp_server_ip.get().strip()
            port = int(self.tcp_server_port.get())
            self.tcp_server_thread = threading.Thread(
                target=NetworkCore.tcp_server_listen,
                args=(host, port, self.log_tcp, self.update_tcp_clients, self.tcp_server_stop),
                daemon=True
            )
            self.tcp_server_thread.start()
            self.tcp_server_btn.config(text="停止服务端")

    def send_tcp(self):
        host = self.tcp_client_ip.get().strip()
        port = int(self.tcp_client_port.get())
        msg = self.tcp_client_msg.get()
        stop_event = threading.Event()  # 临时用
        t = threading.Thread(target=NetworkCore.tcp_client_send,
                             args=(host, port, msg, self.log_tcp, stop_event),
                             daemon=True)
        t.start()

    def update_tcp_clients(self, clients):
        self.tcp_clients = clients
        # 可在状态栏显示
        self.root.after(0, lambda: self.status_var.set(f"已连接客户端: {len(clients)}"))

    def log_tcp(self, msg):
        self.tcp_log.insert(tk.END, f"{datetime.now().strftime('%H:%M:%S')}  {msg}\n")
        self.tcp_log.see(tk.END)
        logging.info(f"TCP: {msg}")

    # ========== UDP 标签页 ==========
    def build_udp_tab(self):
        left_frame = ttk.Frame(self.udp_frame)
        left_frame.pack(side=tk.LEFT, fill=tk.Y, padx=5, pady=5)

        ttk.Label(left_frame, text="UDP 监听").grid(row=0, column=0, columnspan=2, pady=5)
        ttk.Label(left_frame, text="端口:").grid(row=1, column=0, sticky=tk.W)
        self.udp_listen_port = ttk.Entry(left_frame, width=8)
        self.udp_listen_port.insert(0, "9999")
        self.udp_listen_port.grid(row=1, column=1, sticky=tk.W)
        self.udp_listen_btn = ttk.Button(left_frame, text="开始监听", command=self.toggle_udp_listen)
        self.udp_listen_btn.grid(row=2, column=0, columnspan=2, pady=5)

        ttk.Separator(left_frame, orient='horizontal').grid(row=3, column=0, columnspan=2, sticky=tk.EW, pady=10)

        ttk.Label(left_frame, text="UDP 发送").grid(row=4, column=0, columnspan=2, pady=5)
        ttk.Label(left_frame, text="目标IP:").grid(row=5, column=0, sticky=tk.W)
        self.udp_target_ip = ttk.Entry(left_frame, width=15)
        self.udp_target_ip.insert(0, "127.0.0.1")
        self.udp_target_ip.grid(row=5, column=1)
        ttk.Label(left_frame, text="端口:").grid(row=6, column=0, sticky=tk.W)
        self.udp_target_port = ttk.Entry(left_frame, width=8)
        self.udp_target_port.insert(0, "9999")
        self.udp_target_port.grid(row=6, column=1, sticky=tk.W)
        ttk.Label(left_frame, text="内容:").grid(row=7, column=0, sticky=tk.W)
        self.udp_msg = ttk.Entry(left_frame, width=20)
        self.udp_msg.insert(0, "Hello UDP")
        self.udp_msg.grid(row=7, column=1)
        self.udp_send_btn = ttk.Button(left_frame, text="发送", command=self.send_udp)
        self.udp_send_btn.grid(row=8, column=0, columnspan=2, pady=5)

        right_frame = ttk.Frame(self.udp_frame)
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.udp_log = scrolledtext.ScrolledText(right_frame, height=20, width=60)
        self.udp_log.pack(fill=tk.BOTH, expand=True)
        ttk.Button(right_frame, text="清空日志", command=lambda: self.udp_log.delete(1.0, tk.END)).pack(pady=2)

    def toggle_udp_listen(self):
        if hasattr(self, 'udp_listen_thread') and self.udp_listen_thread.is_alive():
            self.udp_listen_stop.set()
            self.udp_listen_btn.config(text="开始监听")
            self.log_udp("正在停止UDP监听...")
        else:
            self.udp_listen_stop.clear()
            port = int(self.udp_listen_port.get())
            self.udp_listen_thread = threading.Thread(
                target=NetworkCore.udp_listen,
                args=(port, self.log_udp, self.udp_listen_stop),
                daemon=True
            )
            self.udp_listen_thread.start()
            self.udp_listen_btn.config(text="停止监听")

    def send_udp(self):
        host = self.udp_target_ip.get().strip()
        port = int(self.udp_target_port.get())
        msg = self.udp_msg.get()
        t = threading.Thread(target=NetworkCore.udp_send,
                             args=(host, port, msg, self.log_udp),
                             daemon=True)
        t.start()

    def log_udp(self, msg):
        self.udp_log.insert(tk.END, f"{datetime.now().strftime('%H:%M:%S')}  {msg}\n")
        self.udp_log.see(tk.END)
        logging.info(f"UDP: {msg}")

    # ========== 端口扫描标签页 ==========
    def build_scan_tab(self):
        frame = ttk.Frame(self.scan_frame)
        frame.pack(fill=tk.BOTH, padx=10, pady=10)

        ttk.Label(frame, text="目标IP:").grid(row=0, column=0, sticky=tk.W)
        self.scan_ip = ttk.Entry(frame, width=20)
        self.scan_ip.insert(0, "127.0.0.1")
        self.scan_ip.grid(row=0, column=1, padx=5)
        ttk.Label(frame, text="起始端口:").grid(row=1, column=0, sticky=tk.W)
        self.scan_start = ttk.Entry(frame, width=8)
        self.scan_start.insert(0, "1")
        self.scan_start.grid(row=1, column=1, sticky=tk.W, padx=5)
        ttk.Label(frame, text="结束端口:").grid(row=2, column=0, sticky=tk.W)
        self.scan_end = ttk.Entry(frame, width=8)
        self.scan_end.insert(0, "1024")
        self.scan_end.grid(row=2, column=1, sticky=tk.W, padx=5)
        self.scan_btn = ttk.Button(frame, text="开始扫描", command=self.start_scan)
        self.scan_btn.grid(row=3, column=0, columnspan=2, pady=10)

        # 结果显示
        self.scan_result_text = scrolledtext.ScrolledText(frame, height=15, width=60)
        self.scan_result_text.grid(row=4, column=0, columnspan=2, pady=5)

    def start_scan(self):
        target = self.scan_ip.get().strip()
        start = int(self.scan_start.get())
        end = int(self.scan_end.get())
        self.scan_result_text.delete(1.0, tk.END)
        self.scan_result_text.insert(tk.END, f"正在扫描 {target} 端口 {start}-{end}...\n")
        self.scan_btn.config(state=tk.DISABLED)
        def callback_result(open_ports):
            self.root.after(0, lambda: self.scan_result_text.insert(tk.END, f"开放端口: {open_ports}\n"))
            self.root.after(0, lambda: self.scan_btn.config(state=tk.NORMAL))
        t = threading.Thread(target=NetworkCore.port_scan,
                             args=(target, start, end, self.log_scan, callback_result),
                             daemon=True)
        t.start()

    def log_scan(self, msg):
        self.scan_result_text.insert(tk.END, f"{msg}\n")
        self.scan_result_text.see(tk.END)

    # ========== Ping 标签页 ==========
    def build_ping_tab(self):
        frame = ttk.Frame(self.ping_frame)
        frame.pack(fill=tk.BOTH, padx=10, pady=10)
        ttk.Label(frame, text="目标主机/IP:").grid(row=0, column=0, sticky=tk.W)
        self.ping_host_entry = ttk.Entry(frame, width=25)
        self.ping_host_entry.insert(0, "8.8.8.8")
        self.ping_host_entry.grid(row=0, column=1, padx=5)
        ttk.Label(frame, text="次数:").grid(row=1, column=0, sticky=tk.W)
        self.ping_count = ttk.Entry(frame, width=5)
        self.ping_count.insert(0, "4")
        self.ping_count.grid(row=1, column=1, sticky=tk.W, padx=5)
        self.ping_btn = ttk.Button(frame, text="Ping", command=self.do_ping)
        self.ping_btn.grid(row=2, column=0, columnspan=2, pady=10)
        self.ping_result = scrolledtext.ScrolledText(frame, height=15, width=80)
        self.ping_result.grid(row=3, column=0, columnspan=2, pady=5)

    def do_ping(self):
        host = self.ping_host_entry.get().strip()
        count = int(self.ping_count.get())
        self.ping_result.delete(1.0, tk.END)
        self.ping_result.insert(tk.END, f"Ping {host} ...\n")
        t = threading.Thread(target=lambda: self.ping_result.insert(tk.END, NetworkCore.ping_host(host, count)))
        t.start()

    # ========== 仪表盘标签页 ==========
    def build_dash_tab(self):
        frame = ttk.Frame(self.dash_frame)
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        ttk.Label(frame, text="简易网络状态仪表盘", font=("Arial", 14)).pack(pady=10)
        self.dash_text = scrolledtext.ScrolledText(frame, height=15, width=80)
        self.dash_text.pack(fill=tk.BOTH, expand=True)
        ttk.Button(frame, text="刷新状态", command=self.refresh_dashboard).pack(pady=5)
        self.refresh_dashboard()

    def refresh_dashboard(self):
        self.dash_text.delete(1.0, tk.END)
        local_ip = get_local_ip()
        self.dash_text.insert(tk.END, f"本机IP: {local_ip}\n")
        self.dash_text.insert(tk.END, f"活动TCP连接数: {len(self.tcp_clients)}\n")
        # 简单检查常见网站连通性
        sites = ['baidu.com', 'google.com']
        for site in sites:
            try:
                socket.gethostbyname(site)
                status = '可达'
            except:
                status = '不可达'
            self.dash_text.insert(tk.END, f"{site}: {status}\n")
        self.dash_text.insert(tk.END, f"日志文件: {LOG_FILE}\n")
        self.dash_text.insert(tk.END, f"配置文件: {CONFIG_FILE}\n")

    # ========== 关闭窗口处理 ==========
    def on_closing(self):
        self.tcp_server_stop.set()
        self.udp_listen_stop.set()
        self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkToolApp(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()