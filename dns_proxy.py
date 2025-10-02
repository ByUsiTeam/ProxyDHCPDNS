#!/usr/bin/env python3
"""
DNS代理服务器 - 修复事件循环问题，纯文本日志输出
"""

import asyncio
import socket
import struct
import time
from typing import Dict, Tuple
import logging
import select
import json

# 全局配置变量
config = {}

def load_config_for_dns():
    """为DNS代理加载配置文件"""
    global config
    try:
        with open('config.json', 'r') as f:
            config = json.load(f)
        logging.info("✅ DNS代理配置文件加载成功")
        return config
    except FileNotFoundError:
        logging.error("❌ 配置文件 config.json 不存在")
        raise
    except json.JSONDecodeError as e:
        logging.error(f"❌ 配置文件格式错误: {e}")
        raise

class DNSProxy:
    def __init__(self, dhcp_proxy, interface: str = None, port: int = None):
        self.dhcp_proxy = dhcp_proxy
        
        # 加载配置
        load_config_for_dns()
        
        # 从配置获取接口和端口
        proxy_config = config.get("proxy", {})
        self.interface = interface or proxy_config.get("dns_listen_interface", "0.0.0.0")
        self.port = port or proxy_config.get("dns_port", 53)
        
        self.running = False
        self.sock = None
        
    def _create_socket(self):
        """创建DNS服务器socket"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((self.interface, self.port))
            sock.setblocking(False)
            logging.info(f"✅ DNS Socket创建成功 - {self.interface}:{self.port}")
            return sock
        except Exception as e:
            logging.error(f"❌ 创建DNS Socket失败: {e}")
            raise
    
    def parse_dns_query(self, data: bytes) -> Tuple[str, bytes]:
        """解析DNS查询"""
        try:
            if len(data) < 12:
                return "", b""
                
            # 解析DNS头部
            transaction_id = data[:2]
            flags = data[2:4]
            
            # 解析查询部分
            query_section = data[12:]
            domain_parts = []
            pos = 0
            
            while pos < len(query_section):
                length = query_section[pos]
                if length == 0:
                    break
                if pos + 1 + length > len(query_section):
                    break
                domain_parts.append(query_section[pos+1:pos+1+length])
                pos += length + 1
                if pos >= len(query_section):
                    break
            
            if not domain_parts:
                return "", b""
                
            domain = b'.'.join(domain_parts).decode('utf-8', errors='ignore')
            
            # 查找查询类型和类
            if pos + 4 <= len(query_section):
                qtype = query_section[pos+1:pos+3]
                qclass = query_section[pos+3:pos+5]
                query_data = transaction_id + flags + data[4:12] + query_section[:pos+5]
            else:
                query_data = data
                
            return domain, query_data
            
        except Exception as e:
            logging.error(f"解析DNS查询失败: {e}")
            return "", b""
    
    def build_dns_response(self, query_data: bytes, domain: str, ip_address: str) -> bytes:
        """构建DNS响应"""
        try:
            # 头部 - 设置响应标志
            transaction_id = query_data[:2]
            flags = b'\x81\x80'  # 标准响应标志
            questions = b'\x00\x01'  # 1个问题
            answers = b'\x00\x01'    # 1个回答
            authority_rrs = b'\x00\x00'
            additional_rrs = b'\x00\x00'
            
            header = transaction_id + flags + questions + answers + authority_rrs + additional_rrs
            
            # 查询部分 (原样返回)
            query_section = query_data[12:]
            
            # 回答部分
            # 名称 (使用指针到查询中的域名)
            name_ptr = b'\xc0\x0c'
            
            # 类型 A记录 (0x0001)
            answer_type = b'\x00\x01'
            
            # 类 IN (0x0001) 
            answer_class = b'\x00\x01'
            
            # TTL (300秒)
            ttl = struct.pack('!I', 300)
            
            # 数据长度 (4字节IPv4地址)
            data_length = b'\x00\x04'
            
            # IP地址
            ip_packed = socket.inet_aton(ip_address)
            
            answer = name_ptr + answer_type + answer_class + ttl + data_length + ip_packed
            
            return header + query_section + answer
            
        except Exception as e:
            logging.error(f"构建DNS响应失败: {e}")
            return b""
    
    async def handle_dns_query(self, data: bytes, client_addr: Tuple[str, int]):
        """处理DNS查询"""
        start_time = time.perf_counter_ns()
        
        domain, query_data = self.parse_dns_query(data)
        if not domain:
            return
        
        logging.info(f"🔍 DNS查询: {domain} 来自 {client_addr[0]}")
        
        # 记录路由数据包信息
        await self.dhcp_proxy.route_monitor.log_packet_details(
            data, "DNS-QUERY", client_addr[0], self.interface
        )
        
        # 检查是否需要篡改
        should_hijack, fake_ip = self.dhcp_proxy.dns_hijacker.should_hijack(domain)
        
        if should_hijack:
            # 返回篡改的IP
            response = self.build_dns_response(query_data, domain, fake_ip)
            logging.warning(f"🎭 返回篡改DNS响应: {domain} -> {fake_ip}")
        else:
            # 转发到上游DNS
            try:
                response = await self.forward_to_upstream(data)
                logging.info(f"🔁 转发DNS响应: {domain}")
            except Exception as e:
                logging.error(f"DNS转发失败: {e}")
                return
        
        # 发送响应
        try:
            self.sock.sendto(response, client_addr)
            response_time = time.perf_counter_ns() - start_time
            logging.info(f"✅ DNS响应发送完成 (响应时间: {response_time} ns)")
        except Exception as e:
            logging.error(f"发送DNS响应失败: {e}")
    
    async def forward_to_upstream(self, data: bytes) -> bytes:
        """转发到上游DNS服务器"""
        upstream_dns = self.dhcp_proxy.dns_hijacker.upstream_dns
        
        try:
            # 创建临时socket进行转发
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as temp_sock:
                temp_sock.settimeout(2.0)
                temp_sock.sendto(data, (upstream_dns, 53))
                response, _ = temp_sock.recvfrom(512)
                return response
        except Exception as e:
            logging.error(f"向上游DNS转发失败: {e}")
            raise
    
    async def start_server(self):
        """启动DNS服务器"""
        self.running = True
        self.sock = self._create_socket()
        
        logging.info("🚀 启动DNS代理服务器...")
        
        try:
            while self.running:
                try:
                    # 使用select来检查socket是否可读
                    ready_socks, _, _ = select.select([self.sock], [], [], 1.0)
                    
                    for sock in ready_socks:
                        if sock == self.sock:
                            data, addr = sock.recvfrom(512)
                            await self.handle_dns_query(data, addr)
                    
                    # 短暂休眠以避免CPU过度使用
                    await asyncio.sleep(0.01)
                    
                except Exception as e:
                    logging.error(f"处理DNS查询时出错: {e}")
                    await asyncio.sleep(0.1)
                    
        except KeyboardInterrupt:
            logging.info("DNS代理服务器停止")
        finally:
            self.running = False
            if self.sock:
                self.sock.close()
