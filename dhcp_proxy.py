#!/usr/bin/env python3
"""
DHCP代理服务器 - 修复事件循环问题，纯文本日志输出
"""

import asyncio
import socket
import struct
import time
import ipaddress
import json
import os
import re
import subprocess
from typing import Dict, Optional, Tuple, List
from dataclasses import dataclass
import aiofiles
from datetime import datetime
import logging
from logging.handlers import RotatingFileHandler

# 全局变量
config = {}

def load_config():
    """加载配置文件"""
    global config
    try:
        with open('config.json', 'r') as f:
            config = json.load(f)
        print("✅ 配置文件加载成功")
        return config
    except FileNotFoundError:
        print("❌ 配置文件 config.json 不存在")
        raise
    except json.JSONDecodeError as e:
        print(f"❌ 配置文件格式错误: {e}")
        raise

def setup_logging():
    """设置纯文本日志系统"""
    # 创建logs目录
    log_dir = config.get("logging", {}).get("log_dir", "./logs")
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
    
    # 确定日志文件名（年-月-日-启动次数.log）
    today = datetime.now().strftime("%Y-%m-%d")
    
    # 查找今天已有的日志文件
    existing_logs = []
    for f in os.listdir(log_dir):
        if f.startswith(today) and f.endswith('.log'):
            existing_logs.append(f)
    
    # 计算启动次数
    start_count = len(existing_logs) + 1
    log_filename = f"{today}-{start_count}.log"
    log_path = os.path.join(log_dir, log_filename)
    
    # 配置根日志记录器
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    
    # 清除现有的处理器
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
    
    # 创建控制台处理器（纯文本）
    console_handler = logging.StreamHandler()
    console_level = config.get("logging", {}).get("console_level", "INFO")
    console_handler.setLevel(getattr(logging, console_level.upper()))
    
    # 创建文件处理器（使用轮转）
    max_size = config.get("logging", {}).get("max_log_size_mb", 10) * 1024 * 1024
    backup_count = config.get("logging", {}).get("backup_count", 5)
    file_handler = RotatingFileHandler(
        log_path, 
        maxBytes=max_size, 
        backupCount=backup_count,
        encoding='utf-8'
    )
    file_level = config.get("logging", {}).get("file_level", "DEBUG")
    file_handler.setLevel(getattr(logging, file_level.upper()))
    
    # 设置日志格式
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    console_handler.setFormatter(formatter)
    file_handler.setFormatter(formatter)
    
    # 添加处理器
    logger.addHandler(console_handler)
    logger.addHandler(file_handler)
    
    # 记录启动信息
    logging.info(f"🚀 DHCP代理服务器启动 - 日志文件: {log_path}")
    logging.info(f"📅 这是今天的第 {start_count} 次启动")
    
    return log_path

@dataclass
class DHCPClient:
    mac_address: str
    ip_address: str
    hostname: str = ""
    lease_time: int = 3600
    last_seen: float = 0
    state: str = "discovering"
    xid: int = 0  # 事务ID

@dataclass 
class RealDHCPServer:
    ip: str
    port: int = 67

class LinuxConfigReader:
    """从Linux系统配置读取网络信息"""
    
    @staticmethod
    def get_default_gateway() -> Optional[str]:
        """获取默认网关地址"""
        try:
            # 方法1: 使用ip route命令
            result = subprocess.run(
                ["ip", "route", "show", "default"],
                capture_output=True, text=True, check=True
            )
            lines = result.stdout.strip().split('\n')
            for line in lines:
                if line and 'via' in line:
                    parts = line.split()
                    if len(parts) >= 3:
                        return parts[2]
            
            # 方法2: 读取/proc/net/route
            with open('/proc/net/route', 'r') as f:
                for line in f.readlines()[1:]:  # 跳过标题行
                    parts = line.split()
                    if len(parts) >= 3 and parts[1] == '00000000':  # 默认路由
                        # 将十六进制IP转换为点分十进制
                        ip_hex = parts[2]
                        if len(ip_hex) == 8:
                            ip_bytes = bytes.fromhex(ip_hex)
                            # 反转字节顺序（小端序）
                            ip_bytes = ip_bytes[::-1]
                            return socket.inet_ntoa(ip_bytes)
            
            return None
        except Exception as e:
            logging.error(f"获取默认网关失败: {e}")
            return None
    
    @staticmethod
    def get_dhcp_server_from_lease() -> Optional[str]:
        """从DHCP租约文件获取DHCP服务器地址"""
        lease_files = [
            '/var/lib/dhcp/dhclient.leases',
            '/var/lib/dhcp3/dhclient.leases',
            '/var/lib/NetworkManager/dhclient-*.lease',
            '/var/lib/NetworkManager/dhclient-*.conf',
            '/var/lib/NetworkManager/internal-*.conf',
            '/var/lib/NetworkManager/dhcp-*.conf'
        ]
        
        for pattern in lease_files:
            if '*' in pattern:
                import glob
                files = glob.glob(pattern)
                for file in files:
                    server = LinuxConfigReader._parse_lease_file(file)
                    if server:
                        return server
            else:
                if os.path.exists(pattern):
                    server = LinuxConfigReader._parse_lease_file(pattern)
                    if server:
                        return server
        
        return None
    
    @staticmethod
    def _parse_lease_file(filepath: str) -> Optional[str]:
        """解析DHCP租约文件"""
        try:
            with open(filepath, 'r') as f:
                content = f.read()
            
            # 查找dhcp-server-identifier
            patterns = [
                r'option dhcp-server-identifier (\d+\.\d+\.\d+\.\d+);',
                r'dhcp-server-identifier (\d+\.\d+\.\d+\.\d+);',
                r'server-identifier (\d+\.\d+\.\d+\.\d+);',
            ]
            
            for pattern in patterns:
                match = re.search(pattern, content)
                if match:
                    return match.group(1)
            
            return None
        except Exception as e:
            logging.debug(f"解析租约文件 {filepath} 失败: {e}")
            return None
    
    @staticmethod
    def get_dhcp_server_from_network_manager() -> Optional[str]:
        """从NetworkManager配置获取DHCP服务器"""
        try:
            # 获取当前连接
            result = subprocess.run(
                ["nmcli", "-t", "-f", "UUID,DEVICE", "con", "show", "--active"],
                capture_output=True, text=True, check=True
            )
            
            for line in result.stdout.strip().split('\n'):
                if line:
                    uuid, device = line.split(':')
                    # 获取连接的详细配置
                    result_detail = subprocess.run(
                        ["nmcli", "con", "show", uuid],
                        capture_output=True, text=True, check=True
                    )
                    
                    # 查找DHCP服务器信息
                    for detail_line in result_detail.stdout.split('\n'):
                        if 'dhcp_server_identifier' in detail_line:
                            parts = detail_line.split(':')
                            if len(parts) >= 2:
                                return parts[1].strip()
            
            return None
        except Exception as e:
            logging.debug(f"从NetworkManager获取DHCP服务器失败: {e}")
            return None
    
    @staticmethod
    def get_dhcp_server() -> str:
        """获取真实DHCP服务器地址"""
        logging.info("🔍 正在探测真实DHCP服务器地址...")
        
        # 如果配置中指定了DHCP服务器，直接使用
        if not config.get("real_dhcp", {}).get("auto_detect", True):
            fallback_ip = config.get("real_dhcp", {}).get("fallback_ip", "192.168.1.1")
            logging.info(f"✅ 使用配置的DHCP服务器: {fallback_ip}")
            return fallback_ip
        
        # 方法1: 从NetworkManager获取
        server = LinuxConfigReader.get_dhcp_server_from_network_manager()
        if server:
            logging.info(f"✅ 从NetworkManager获取DHCP服务器: {server}")
            return server
        
        # 方法2: 从DHCP租约文件获取
        server = LinuxConfigReader.get_dhcp_server_from_lease()
        if server:
            logging.info(f"✅ 从DHCP租约获取DHCP服务器: {server}")
            return server
        
        # 方法3: 使用默认网关作为DHCP服务器
        gateway = LinuxConfigReader.get_default_gateway()
        if gateway:
            logging.info(f"✅ 使用默认网关作为DHCP服务器: {gateway}")
            return gateway
        
        # 方法4: 回退到配置的地址
        fallback_ip = config.get("real_dhcp", {}).get("fallback_ip", "192.168.1.1")
        logging.warning(f"⚠️ 无法探测DHCP服务器，使用回退地址: {fallback_ip}")
        return fallback_ip
    
    @staticmethod
    def get_proxy_server_ip() -> str:
        """获取代理服务器IP地址"""
        logging.info("🔍 正在探测代理服务器IP地址...")
        
        # 如果配置中禁用了自动检测，使用回退地址
        if not config.get("proxy", {}).get("auto_detect_proxy_ip", True):
            fallback_ip = config.get("proxy", {}).get("fallback_proxy_ip", "192.168.1.100")
            logging.info(f"✅ 使用配置的代理服务器IP: {fallback_ip}")
            return fallback_ip
        
        try:
            # 方法1: 获取默认路由的源IP
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                # 连接到一个外部地址，但不发送数据
                s.connect(("8.8.8.8", 80))
                local_ip = s.getsockname()[0]
                
            if local_ip and local_ip != "127.0.0.1":
                logging.info(f"✅ 获取代理服务器IP: {local_ip}")
                return local_ip
            
            # 方法2: 通过主机名获取
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            if local_ip and local_ip != "127.0.0.1":
                logging.info(f"✅ 通过主机名获取代理服务器IP: {local_ip}")
                return local_ip
            
            # 方法3: 获取所有网络接口的IP
            interfaces = socket.getaddrinfo(socket.gethostname(), None)
            for interface in interfaces:
                ip = interface[4][0]
                if ip and not ip.startswith("127.") and ":" not in ip:
                    logging.info(f"✅ 通过接口获取代理服务器IP: {ip}")
                    return ip
            
            # 方法4: 回退到配置的地址
            fallback_ip = config.get("proxy", {}).get("fallback_proxy_ip", "192.168.1.100")
            logging.warning(f"⚠️ 无法自动探测代理服务器IP，使用回退地址: {fallback_ip}")
            return fallback_ip
            
        except Exception as e:
            logging.error(f"❌ 获取代理服务器IP失败: {e}")
            fallback_ip = config.get("proxy", {}).get("fallback_proxy_ip", "192.168.1.100")
            logging.warning(f"⚠️ 使用回退代理服务器IP: {fallback_ip}")
            return fallback_ip

class RouteMonitor:
    """路由数据包监控和转发类"""
    
    def __init__(self, real_router_ip: str = "192.168.1.1"):
        self.real_router_ip = real_router_ip
        self.packet_stats = {
            "total_packets": 0,
            "tcp_packets": 0,
            "udp_packets": 0,
            "icmp_packets": 0,
            "forwarded_packets": 0,
            "dropped_packets": 0
        }
        self.connection_tracker = {}
        
    async def log_packet_details(self, packet_data: bytes, direction: str, src_ip: str, dst_ip: str):
        """详细记录数据包信息"""
        try:
            if len(packet_data) < 20:
                return
                
            # 解析IP头部（如果是IP包）
            if len(packet_data) >= 20:
                ip_header = packet_data[:20]
                version_ihl = ip_header[0]
                protocol = ip_header[9]
                src_ip_str = src_ip
                dst_ip_str = dst_ip
                
                protocol_name = self._get_protocol_name(protocol)
                
                # 记录基本信息
                logging.info(f"📦 {direction}: {src_ip_str} -> {dst_ip_str} [{protocol_name}]")
                
                # 解析传输层协议
                if protocol == 6:  # TCP
                    self._log_tcp_packet(packet_data, src_ip_str, dst_ip_str)
                elif protocol == 17:  # UDP
                    self._log_udp_packet(packet_data, src_ip_str, dst_ip_str)
                elif protocol == 1:  # ICMP
                    self._log_icmp_packet(packet_data, src_ip_str, dst_ip_str)
                    
                self.packet_stats["total_packets"] += 1
                self.packet_stats[f"{protocol_name.lower()}_packets"] += 1
            
        except Exception as e:
            logging.debug(f"记录数据包详情失败: {e}")
    
    def _get_protocol_name(self, protocol: int) -> str:
        """获取协议名称"""
        protocol_map = {
            1: "ICMP",
            6: "TCP", 
            17: "UDP",
            2: "IGMP",
            47: "GRE",
            50: "ESP",
            51: "AH"
        }
        return protocol_map.get(protocol, f"Unknown({protocol})")
    
    def _log_tcp_packet(self, packet_data: bytes, src_ip: str, dst_ip: str):
        """记录TCP数据包详情"""
        try:
            if len(packet_data) < 40:
                return
                
            ip_header_len = (packet_data[0] & 0x0F) * 4
            if len(packet_data) < ip_header_len + 20:
                return
                
            tcp_header = packet_data[ip_header_len:ip_header_len+20]
            
            src_port = struct.unpack('!H', tcp_header[0:2])[0]
            dst_port = struct.unpack('!H', tcp_header[2:4])[0]
            seq_num = struct.unpack('!I', tcp_header[4:8])[0]
            ack_num = struct.unpack('!I', tcp_header[8:12])[0]
            flags = tcp_header[13]
            
            flag_names = []
            if flags & 0x01: flag_names.append("FIN")
            if flags & 0x02: flag_names.append("SYN") 
            if flags & 0x04: flag_names.append("RST")
            if flags & 0x08: flag_names.append("PSH")
            if flags & 0x10: flag_names.append("ACK")
            if flags & 0x20: flag_names.append("URG")
            
            flags_str = "|".join(flag_names) if flag_names else "None"
            
            logging.debug(f"    🚩 TCP {src_ip}:{src_port} -> {dst_ip}:{dst_port} "
                        f"[Seq: {seq_num}, Ack: {ack_num}, Flags: {flags_str}]")
                        
        except Exception as e:
            logging.debug(f"解析TCP包失败: {e}")
    
    def _log_udp_packet(self, packet_data: bytes, src_ip: str, dst_ip: str):
        """记录UDP数据包详情"""
        try:
            if len(packet_data) < 28:
                return
                
            ip_header_len = (packet_data[0] & 0x0F) * 4
            if len(packet_data) < ip_header_len + 8:
                return
                
            udp_header = packet_data[ip_header_len:ip_header_len+8]
            
            src_port = struct.unpack('!H', udp_header[0:2])[0]
            dst_port = struct.unpack('!H', udp_header[2:4])[0]
            length = struct.unpack('!H', udp_header[4:6])[0]
            
            logging.debug(f"    📨 UDP {src_ip}:{src_port} -> {dst_ip}:{dst_port} "
                        f"[Length: {length} bytes]")
                        
        except Exception as e:
            logging.debug(f"解析UDP包失败: {e}")
    
    def _log_icmp_packet(self, packet_data: bytes, src_ip: str, dst_ip: str):
        """记录ICMP数据包详情"""
        try:
            if len(packet_data) < 28:
                return
                
            ip_header_len = (packet_data[0] & 0x0F) * 4
            if len(packet_data) < ip_header_len + 4:
                return
                
            icmp_header = packet_data[ip_header_len:ip_header_len+4]
            
            icmp_type = icmp_header[0]
            icmp_code = icmp_header[1]
            
            icmp_types = {
                0: "Echo Reply",
                3: "Destination Unreachable", 
                8: "Echo Request",
                11: "Time Exceeded"
            }
            
            icmp_type_name = icmp_types.get(icmp_type, f"Type{icmp_type}")
            
            logging.debug(f"    🎯 ICMP {src_ip} -> {dst_ip} "
                        f"[{icmp_type_name} Code: {icmp_code}]")
                        
        except Exception as e:
            logging.debug(f"解析ICMP包失败: {e}")

class DNSHijacker:
    """DNS解析篡改类"""
    
    def __init__(self, config_file: str = None):
        self.config_file = config_file or config.get("dns", {}).get("config_file", "dnsconfig.json")
        self.hijack_rules: Dict[str, str] = {}
        self.upstream_dns = config.get("dns", {}).get("upstream_dns", "223.5.5.5")
        self.dns_stats = {
            "total_queries": 0,
            "hijacked_queries": 0,
            "forwarded_queries": 0,
            "failed_queries": 0
        }
        
    async def load_config(self):
        """加载DNS配置"""
        try:
            async with aiofiles.open(self.config_file, 'r', encoding='utf-8') as f:
                content = await f.read()
                config_data = json.loads(content)
                
            self.hijack_rules = config_data.get("hijack_domains", {})
            self.upstream_dns = config_data.get("upstream_dns", self.upstream_dns)
            
            logging.info(f"✅ 加载DNS配置: {len(self.hijack_rules)} 个篡改规则")
            for domain, ip in self.hijack_rules.items():
                logging.info(f"   🎯 {domain} -> {ip}")
                
        except FileNotFoundError:
            logging.warning(f"⚠️ DNS配置文件 {self.config_file} 不存在，创建默认配置")
            await self.create_default_config()
        except Exception as e:
            logging.error(f"❌ 加载DNS配置失败: {e}")
            await self.create_default_config()
    
    async def create_default_config(self):
        """创建默认DNS配置"""
        default_config = {
            "upstream_dns": self.upstream_dns,
            "hijack_domains": {
                "example.com": "127.0.0.1",
                "test.local": "192.168.1.100"
            }
        }
        
        try:
            async with aiofiles.open(self.config_file, 'w', encoding='utf-8') as f:
                await f.write(json.dumps(default_config, indent=2, ensure_ascii=False))
            logging.info(f"✅ 创建默认DNS配置文件: {self.config_file}")
            self.hijack_rules = default_config["hijack_domains"]
        except Exception as e:
            logging.error(f"❌ 创建默认配置失败: {e}")
    
    def should_hijack(self, domain: str) -> Tuple[bool, str]:
        """检查域名是否需要篡改"""
        self.dns_stats["total_queries"] += 1
        
        # 精确匹配
        if domain in self.hijack_rules:
            self.dns_stats["hijacked_queries"] += 1
            logging.warning(f"🎭 DNS篡改: {domain} -> {self.hijack_rules[domain]}")
            return True, self.hijack_rules[domain]
        
        # 子域名匹配
        for rule_domain, fake_ip in self.hijack_rules.items():
            if domain.endswith('.' + rule_domain) or domain == rule_domain:
                self.dns_stats["hijacked_queries"] += 1
                logging.warning(f"🎭 DNS篡改(子域): {domain} -> {fake_ip}")
                return True, fake_ip
        
        self.dns_stats["forwarded_queries"] += 1
        logging.info(f"🔍 DNS转发: {domain} -> {self.upstream_dns}")
        return False, ""

class DHCPProxy:
    """DHCP代理 - 从真实DHCP服务器获取信息并修改DNS"""
    
    def __init__(self):
        # 从Linux配置获取真实DHCP服务器和代理服务器IP
        real_dhcp_ip = LinuxConfigReader.get_dhcp_server()
        self.real_dhcp = RealDHCPServer(
            ip=real_dhcp_ip,
            port=config.get("real_dhcp", {}).get("port", 67)
        )
        
        # 获取代理服务器IP
        self.proxy_ip = LinuxConfigReader.get_proxy_server_ip()
        
        # 代理服务器配置
        proxy_config = config.get("proxy", {})
        self.proxy_interface = proxy_config.get("interface", "0.0.0.0")
        self.proxy_port = proxy_config.get("dhcp_port", 67)
        
        # 客户端状态管理
        self.clients: Dict[str, DHCPClient] = {}
        self.pending_requests: Dict[int, str] = {}  # xid -> mac
        
        # DNS篡改配置
        self.dns_hijack_enabled = proxy_config.get("dns_hijack_enabled", True)
        self.dns_hijacker = DNSHijacker()
        
        # 路由监控
        self.route_monitor = RouteMonitor(real_router_ip=real_dhcp_ip)
        
        # 统计信息
        self.stats = {
            "client_requests": 0,
            "proxy_to_real": 0,
            "real_to_proxy": 0,
            "modified_responses": 0,
            "response_times": [],
            "errors": 0
        }
        
        # 网络组件
        self.proxy_sock = None
        self.real_sock = None
        
        # 运行状态
        self.running = False
        
        logging.info(f"DHCP代理初始化 - 真实服务器: {real_dhcp_ip}, 代理IP: {self.proxy_ip}, 代理端口: {self.proxy_port}")

    def setup_sockets(self):
        """设置代理和真实服务器socket"""
        try:
            # 代理socket - 监听客户端请求
            self.proxy_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.proxy_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.proxy_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            self.proxy_sock.bind((self.proxy_interface, self.proxy_port))
            self.proxy_sock.setblocking(False)
            
            # 真实服务器socket - 用于向真实DHCP服务器发送请求
            self.real_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.real_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            self.real_sock.setblocking(False)
            
            # 绑定到临时端口用于接收真实服务器响应
            self.real_sock.bind(('0.0.0.0', 0))
            
            logging.info(f"✅ Socket设置完成 - 代理: {self.proxy_interface}:{self.proxy_port}")
            logging.info(f"✅ 真实服务器: {self.real_dhcp.ip}:{self.real_dhcp.port}")
            
        except Exception as e:
            logging.error(f"❌ 设置Socket失败: {e}")
            raise

    def _parse_dhcp_packet(self, data: bytes) -> Dict:
        """解析DHCP数据包"""
        try:
            if len(data) < 240:
                return {}
                
            # 解析固定头部
            op, htype, hlen, hops, xid, secs, flags = struct.unpack('!BBBBLHH', data[:12])
            ciaddr = socket.inet_ntoa(data[12:16])
            yiaddr = socket.inet_ntoa(data[16:20])
            siaddr = socket.inet_ntoa(data[20:24])
            giaddr = socket.inet_ntoa(data[24:28])
            
            # 解析MAC地址
            chaddr = data[28:28+16]
            mac_address = ':'.join(f'{b:02x}' for b in chaddr[:hlen])
            
            # 解析选项
            options = {}
            options_data = data[240:]
            
            i = 0
            while i < len(options_data):
                if options_data[i] == 0xff:  # END选项
                    break
                if options_data[i] == 0x00:  # PAD选项
                    i += 1
                    continue
                
                code = options_data[i]
                if i + 1 >= len(options_data):
                    break
                    
                length = options_data[i+1]
                if i + 2 + length > len(options_data):
                    break
                    
                value = options_data[i+2:i+2+length]
                options[code] = value
                i += 2 + length
            
            return {
                'op': op,
                'htype': htype,
                'hlen': hlen,
                'hops': hops,
                'xid': xid,
                'secs': secs,
                'flags': flags,
                'ciaddr': ciaddr,
                'yiaddr': yiaddr,
                'siaddr': siaddr,
                'giaddr': giaddr,
                'chaddr': chaddr,
                'mac_address': mac_address,
                'options': options,
                'raw_data': data
            }
            
        except Exception as e:
            logging.error(f"解析DHCP数据包失败: {e}")
            return {}

    def _build_dhcp_packet(self, original_packet: Dict, modifications: Dict = None) -> bytes:
        """基于原始数据包构建新的DHCP数据包"""
        try:
            # 使用原始数据包作为基础
            data = bytearray(original_packet['raw_data'])
            
            if modifications:
                # 修改服务器标识符（选项54）- 改为代理服务器IP
                if 'server_id' in modifications:
                    server_id = modifications['server_id']
                    # 在选项中查找并修改服务器标识符
                    options_data = data[240:]
                    new_options = bytearray()
                    
                    i = 0
                    while i < len(options_data):
                        if options_data[i] == 0xff:
                            break
                        if options_data[i] == 0x00:
                            new_options.append(0x00)
                            i += 1
                            continue
                            
                        code = options_data[i]
                        length = options_data[i+1]
                        value = options_data[i+2:i+2+length]
                        
                        # 如果是服务器标识符，修改它
                        if code == 54:  # 服务器标识符
                            new_options.extend([54, 4])
                            new_options.extend(socket.inet_aton(server_id))
                        # 如果是DNS服务器，修改它
                        elif code == 6 and self.dns_hijack_enabled:  # DNS服务器
                            # 修改为代理服务器的DNS
                            new_options.extend([6, 4])
                            new_options.extend(socket.inet_aton(self.proxy_ip))  # 使用代理服务器IP作为DNS
                        else:
                            # 保持原样
                            new_options.append(code)
                            new_options.append(length)
                            new_options.extend(value)
                            
                        i += 2 + length
                    
                    # 添加结束标记
                    new_options.append(0xff)
                    
                    # 替换选项部分
                    data[240:240+len(new_options)] = new_options
                    # 如果新选项较短，用0填充剩余部分
                    if len(new_options) < len(options_data):
                        data[240+len(new_options):240+len(options_data)] = b'\x00' * (len(options_data) - len(new_options))
            
            return bytes(data)
            
        except Exception as e:
            logging.error(f"构建DHCP数据包失败: {e}")
            return original_packet['raw_data']

    async def forward_to_real_dhcp(self, packet: Dict, client_addr: Tuple[str, int]):
        """将客户端请求转发到真实DHCP服务器"""
        try:
            start_time = time.perf_counter_ns()
            
            mac_address = packet['mac_address']
            xid = packet['xid']
            
            logging.info(f"🔄 转发DHCP请求到真实服务器 - MAC: {mac_address}, XID: {xid:08x}")
            
            # 记录事务ID以便匹配响应
            self.pending_requests[xid] = mac_address
            
            # 发送到真实DHCP服务器
            real_server_addr = (self.real_dhcp.ip, self.real_dhcp.port)
            self.real_sock.sendto(packet['raw_data'], real_server_addr)
            
            # 记录路由信息
            await self.route_monitor.log_packet_details(
                packet['raw_data'], "DHCP-FORWARD", client_addr[0], self.real_dhcp.ip
            )
            
            self.stats["proxy_to_real"] += 1
            forward_time = time.perf_counter_ns() - start_time
            logging.debug(f"✅ 转发完成 (耗时: {forward_time} ns)")
            
        except Exception as e:
            logging.error(f"❌ 转发到真实DHCP服务器失败: {e}")
            self.stats["errors"] += 1

    async def handle_client_request(self, data: bytes, client_addr: Tuple[str, int]):
        """处理来自客户端的DHCP请求"""
        try:
            start_time = time.perf_counter_ns()
            
            packet = self._parse_dhcp_packet(data)
            if not packet:
                return
                
            mac_address = packet['mac_address']
            xid = packet['xid']
            
            self.stats["client_requests"] += 1
            
            # 记录客户端信息
            if mac_address not in self.clients:
                self.clients[mac_address] = DHCPClient(
                    mac_address=mac_address,
                    ip_address="0.0.0.0",
                    xid=xid,
                    last_seen=time.time(),
                    state="forwarding"
                )
            else:
                self.clients[mac_address].xid = xid
                self.clients[mac_address].last_seen = time.time()
                self.clients[mac_address].state = "forwarding"
            
            # 记录详细的包信息
            logging.info(f"📡 收到客户端DHCP请求 - MAC: {mac_address}, XID: {xid:08x}")
            await self.route_monitor.log_packet_details(
                data, "DHCP-CLIENT", client_addr[0], "255.255.255.255"
            )
            
            # 检查消息类型
            msg_type = None
            if 53 in packet['options']:
                msg_type = packet['options'][53][0]
                msg_types = {1: "DISCOVER", 3: "REQUEST", 8: "INFORM"}
                logging.info(f"   📨 消息类型: {msg_types.get(msg_type, f'Unknown({msg_type})')}")
            
            # 转发到真实DHCP服务器
            await self.forward_to_real_dhcp(packet, client_addr)
            
            response_time = time.perf_counter_ns() - start_time
            self.stats["response_times"].append(response_time)
            
        except Exception as e:
            logging.error(f"❌ 处理客户端请求失败: {e}")
            self.stats["errors"] += 1

    async def handle_real_server_response(self, data: bytes, server_addr: Tuple[str, int]):
        """处理来自真实DHCP服务器的响应"""
        try:
            start_time = time.perf_counter_ns()
            
            packet = self._parse_dhcp_packet(data)
            if not packet:
                return
                
            xid = packet['xid']
            
            # 查找对应的客户端
            if xid not in self.pending_requests:
                logging.warning(f"⚠️ 收到未知XID的响应: {xid:08x}")
                return
                
            mac_address = self.pending_requests[xid]
            del self.pending_requests[xid]
            
            self.stats["real_to_proxy"] += 1
            
            logging.info(f"📨 收到真实服务器响应 - MAC: {mac_address}, XID: {xid:08x}")
            await self.route_monitor.log_packet_details(
                data, "DHCP-RESPONSE", server_addr[0], "255.255.255.255"
            )
            
            # 检查消息类型
            msg_type = None
            if 53 in packet['options']:
                msg_type = packet['options'][53][0]
                msg_types = {2: "OFFER", 5: "ACK", 6: "NAK"}
                logging.info(f"   📨 消息类型: {msg_types.get(msg_type, f'Unknown({msg_type})')}")
            
            # 修改数据包（主要是DNS服务器设置）
            modified_packet = self._build_dhcp_packet(packet, {
                'server_id': self.proxy_ip  # 使用代理服务器IP
            })
            
            # 发送修改后的响应到客户端
            broadcast_addr = ('255.255.255.255', 68)
            self.proxy_sock.sendto(modified_packet, broadcast_addr)
            
            # 更新客户端状态
            if mac_address in self.clients:
                if packet['yiaddr'] != '0.0.0.0':
                    self.clients[mac_address].ip_address = packet['yiaddr']
                
                if msg_type == 2:  # OFFER
                    self.clients[mac_address].state = "offered"
                elif msg_type == 5:  # ACK
                    self.clients[mac_address].state = "acknowledged"
                elif msg_type == 6:  # NAK
                    self.clients[mac_address].state = "rejected"
            
            self.stats["modified_responses"] += 1
            logging.info(f"✅ 发送修改后的DHCP响应到客户端 {mac_address}")
            
            response_time = time.perf_counter_ns() - start_time
            self.stats["response_times"].append(response_time)
            
        except Exception as e:
            logging.error(f"❌ 处理真实服务器响应失败: {e}")
            self.stats["errors"] += 1

    async def start_proxy(self):
        """启动DHCP代理服务器"""
        self.running = True
        
        # 加载DNS配置
        if self.dns_hijack_enabled:
            await self.dns_hijacker.load_config()
        
        # 设置socket
        self.setup_sockets()
        
        logging.info("🚀 启动DHCP代理服务器...")
        
        try:
            while self.running:
                # 检查代理socket（客户端请求）
                try:
                    # 使用select来检查socket是否可读
                    import select
                    ready_socks, _, _ = select.select([self.proxy_sock, self.real_sock], [], [], 1.0)
                    
                    for sock in ready_socks:
                        if sock == self.proxy_sock:
                            data, addr = sock.recvfrom(1024)
                            await self.handle_client_request(data, addr)
                        elif sock == self.real_sock:
                            data, addr = sock.recvfrom(1024)
                            await self.handle_real_server_response(data, addr)
                    
                    # 短暂休眠以避免CPU过度使用
                    await asyncio.sleep(0.01)
                    
                except Exception as e:
                    if self.running:  # 只在运行状态下记录错误
                        logging.error(f"处理socket错误: {e}")
                        await asyncio.sleep(0.1)
                    
        except KeyboardInterrupt:
            logging.info("收到停止信号，正在关闭代理服务器...")
        except Exception as e:
            logging.error(f"代理服务器运行错误: {e}")
        finally:
            self.running = False
            
            if self.proxy_sock:
                self.proxy_sock.close()
            if self.real_sock:
                self.real_sock.close()
                
            logging.info("DHCP代理服务器已停止")

async def main():
    """主函数"""
    # 加载配置
    load_config()
    
    # 设置日志系统
    log_path = setup_logging()
    
    print(f"🚀 DHCP代理服务器启动 - 日志文件: {log_path}")
    
    # 创建并启动代理服务器
    proxy = DHCPProxy()
    
    await proxy.start_proxy()

if __name__ == "__main__":
    # 注意：在Linux上需要root权限来绑定67端口
    try:
        asyncio.run(main())
    except PermissionError:
        print("❌ 需要root权限来绑定DHCP端口(67)")
        print("请使用sudo运行此脚本")
    except Exception as e:
        print(f"代理服务器运行错误: {e}")
