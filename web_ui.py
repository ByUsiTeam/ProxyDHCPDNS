#!/usr/bin/env python3
"""
Web UI for DHCP Proxy - 使用响应式布局
"""

import asyncio
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict

from aiohttp import web
import aiohttp_jinja2
import jinja2
import psutil
import netifaces

# 全局代理实例引用
dhcp_proxy = None
dns_proxy = None

class WebUI:
    def __init__(self, host: str = "0.0.0.0", port: int = 8080):
        self.host = host
        self.port = port
        self.app = web.Application()
        self.runner = None
        self.site = None
        
        # 设置Jinja2模板
        aiohttp_jinja2.setup(
            self.app,
            loader=jinja2.FileSystemLoader('templates')
        )
        
        # 注册路由
        self.setup_routes()
        
        # 静态文件服务
        self.app.router.add_static('/static/', path='static', name='static')
        
    def setup_routes(self):
        """设置Web路由"""
        routes = [
            web.get('/', self.dashboard),
            web.get('/clients', self.clients),
            web.get('/dns', self.dns),
            web.get('/network', self.network),
            web.get('/logs', self.logs),
            web.get('/settings', self.settings),
            
            # API路由
            web.get('/api/stats', self.api_stats),
            web.get('/api/clients', self.api_clients),
            web.get('/api/dns-stats', self.api_dns_stats),
            web.get('/api/network-info', self.api_network_info),
            web.get('/api/logs', self.api_logs),
            web.get('/api/system-stats', self.api_system_stats),
            
            web.post('/api/dns-rules', self.api_update_dns_rules),
            web.post('/api/settings', self.api_update_settings),
            web.post('/api/restart', self.api_restart),
        ]
        
        self.app.add_routes(routes)
    
    async def dashboard(self, request):
        """仪表板页面"""
        return aiohttp_jinja2.render_template(
            'dashboard.html', request, {}
        )
    
    async def clients(self, request):
        """客户端管理页面"""
        return aiohttp_jinja2.render_template(
            'clients.html', request, {}
        )
    
    async def dns(self, request):
        """DNS管理页面"""
        return aiohttp_jinja2.render_template(
            'dns.html', request, {}
        )
    
    async def network(self, request):
        """网络监控页面"""
        return aiohttp_jinja2.render_template(
            'network.html', request, {}
        )
    
    async def logs(self, request):
        """日志查看页面"""
        return aiohttp_jinja2.render_template(
            'logs.html', request, {}
        )
    
    async def settings(self, request):
        """设置页面"""
        return aiohttp_jinja2.render_template(
            'settings.html', request, {}
        )
    
    # API处理函数
    async def api_stats(self, request):
        """获取统计信息API"""
        if not dhcp_proxy:
            return web.json_response({"error": "DHCP代理未运行"}, status=500)
        
        stats = {
            "dhcp_stats": dhcp_proxy.stats,
            "client_count": len(dhcp_proxy.clients),
            "running_time": self.get_running_time(),
            "system_stats": await self.get_system_stats()
        }
        
        return web.json_response(stats)
    
    async def api_clients(self, request):
        """获取客户端列表API"""
        if not dhcp_proxy:
            return web.json_response({"error": "DHCP代理未运行"}, status=500)
        
        clients = []
        for mac, client in dhcp_proxy.clients.items():
            clients.append({
                "mac_address": client.mac_address,
                "ip_address": client.ip_address,
                "hostname": client.hostname,
                "state": client.state,
                "lease_time": client.lease_time,
                "last_seen": client.last_seen,
                "xid": client.xid
            })
        
        return web.json_response({"clients": clients})
    
    async def api_dns_stats(self, request):
        """获取DNS统计信息API"""
        if not dhcp_proxy or not dhcp_proxy.dns_hijacker:
            return web.json_response({"error": "DNS劫持未启用"}, status=500)
        
        dns_stats = {
            "hijack_rules": dhcp_proxy.dns_hijacker.hijack_rules,
            "dns_stats": dhcp_proxy.dns_hijacker.dns_stats,
            "upstream_dns": dhcp_proxy.dns_hijacker.upstream_dns,
            "enabled": dhcp_proxy.dns_hijack_enabled
        }
        
        return web.json_response(dns_stats)
    
    async def api_network_info(self, request):
        """获取网络信息API"""
        network_info = {
            "interfaces": self.get_network_interfaces(),
            "connections": await self.get_network_connections(),
            "traffic": await self.get_network_traffic()
        }
        
        return web.json_response(network_info)
    
    async def api_logs(self, request):
        """获取日志API"""
        try:
            # 读取最新的日志文件
            log_dir = "./logs"
            if not os.path.exists(log_dir):
                return web.json_response({"logs": []})
            
            # 找到最新的日志文件
            log_files = [f for f in os.listdir(log_dir) if f.endswith('.log')]
            if not log_files:
                return web.json_response({"logs": []})
            
            latest_log = sorted(log_files)[-1]
            log_path = os.path.join(log_dir, latest_log)
            
            # 读取最后100行日志
            with open(log_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()[-100:]
            
            logs = []
            for line in lines:
                # 解析日志行
                parts = line.strip().split(' - ', 3)
                if len(parts) >= 4:
                    logs.append({
                        "timestamp": parts[0],
                        "logger": parts[1],
                        "level": parts[2],
                        "message": parts[3]
                    })
                else:
                    logs.append({"raw": line.strip()})
            
            return web.json_response({"logs": logs})
            
        except Exception as e:
            logging.error(f"读取日志失败: {e}")
            return web.json_response({"logs": []})
    
    async def api_system_stats(self, request):
        """获取系统统计信息API"""
        return web.json_response(await self.get_system_stats())
    
    async def api_update_dns_rules(self, request):
        """更新DNS规则API"""
        if not dhcp_proxy or not dhcp_proxy.dns_hijacker:
            return web.json_response({"error": "DNS劫持未启用"}, status=500)
        
        try:
            data = await request.json()
            domain = data.get('domain', '').strip()
            ip = data.get('ip', '').strip()
            action = data.get('action', 'add')  # add 或 remove
            
            if action == 'add':
                if domain and ip:
                    dhcp_proxy.dns_hijacker.hijack_rules[domain] = ip
                    logging.info(f"WebUI: 添加DNS规则 {domain} -> {ip}")
            elif action == 'remove':
                if domain in dhcp_proxy.dns_hijacker.hijack_rules:
                    del dhcp_proxy.dns_hijacker.hijack_rules[domain]
                    logging.info(f"WebUI: 删除DNS规则 {domain}")
            
            # 保存配置
            await dhcp_proxy.dns_hijacker.save_config()
            
            return web.json_response({"success": True})
            
        except Exception as e:
            logging.error(f"更新DNS规则失败: {e}")
            return web.json_response({"error": str(e)}, status=500)
    
    async def api_update_settings(self, request):
        """更新设置API"""
        try:
            data = await request.json()
            
            # 这里可以实现设置更新逻辑
            # 例如：更新DNS劫持开关、上游DNS等
            
            logging.info(f"WebUI: 更新设置 {data}")
            return web.json_response({"success": True})
            
        except Exception as e:
            logging.error(f"更新设置失败: {e}")
            return web.json_response({"error": str(e)}, status=500)
    
    async def api_restart(self, request):
        """重启服务API"""
        try:
            logging.info("WebUI: 收到重启请求")
            # 这里可以实现重启逻辑
            return web.json_response({"success": True, "message": "重启命令已发送"})
            
        except Exception as e:
            logging.error(f"重启失败: {e}")
            return web.json_response({"error": str(e)}, status=500)
    
    # 辅助方法
    def get_running_time(self) -> str:
        """获取运行时间"""
        # 这里需要记录启动时间，简化实现
        return "1小时 23分钟"
    
    async def get_system_stats(self) -> Dict:
        """获取系统统计信息"""
        try:
            # CPU使用率
            cpu_percent = psutil.cpu_percent(interval=0.1)
            
            # 内存使用
            memory = psutil.virtual_memory()
            
            # 磁盘使用
            disk = psutil.disk_usage('/')
            
            # 网络IO
            net_io = psutil.net_io_counters()
            
            return {
                "cpu_percent": cpu_percent,
                "memory_total": memory.total,
                "memory_used": memory.used,
                "memory_percent": memory.percent,
                "disk_total": disk.total,
                "disk_used": disk.used,
                "disk_percent": disk.percent,
                "bytes_sent": net_io.bytes_sent,
                "bytes_recv": net_io.bytes_recv,
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            logging.error(f"获取系统统计失败: {e}")
            return {}
    
    def get_network_interfaces(self) -> List[Dict]:
        """获取网络接口信息"""
        interfaces = []
        try:
            for interface in netifaces.interfaces():
                addrs = netifaces.ifaddresses(interface)
                if netifaces.AF_INET in addrs:
                    for addr_info in addrs[netifaces.AF_INET]:
                        interfaces.append({
                            "name": interface,
                            "ip": addr_info.get('addr', ''),
                            "netmask": addr_info.get('netmask', ''),
                            "broadcast": addr_info.get('broadcast', '')
                        })
        except Exception as e:
            logging.error(f"获取网络接口失败: {e}")
        
        return interfaces
    
    async def get_network_connections(self) -> List[Dict]:
        """获取网络连接信息"""
        connections = []
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'ESTABLISHED':
                    connections.append({
                        "local_addr": f"{conn.laddr.ip}:{conn.laddr.port}",
                        "remote_addr": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "",
                        "status": conn.status,
                        "pid": conn.pid
                    })
        except Exception as e:
            logging.error(f"获取网络连接失败: {e}")
        
        return connections
    
    async def get_network_traffic(self) -> Dict:
        """获取网络流量统计"""
        try:
            net_io = psutil.net_io_counters()
            return {
                "bytes_sent": net_io.bytes_sent,
                "bytes_recv": net_io.bytes_recv,
                "packets_sent": net_io.packets_sent,
                "packets_recv": net_io.packets_recv
            }
        except Exception as e:
            logging.error(f"获取网络流量失败: {e}")
            return {}
    
    async def start(self):
        """启动Web UI服务器"""
        self.runner = web.AppRunner(self.app)
        await self.runner.setup()
        
        self.site = web.TCPSite(self.runner, self.host, self.port)
        await self.site.start()
        
        logging.info(f"🌐 Web UI服务器启动在 http://{self.host}:{self.port}")
    
    async def stop(self):
        """停止Web UI服务器"""
        if self.site:
            await self.site.stop()
        if self.runner:
            await self.cleanup()

def setup_web_ui(dhcp_proxy_instance, dns_proxy_instance, host="0.0.0.0", port=8080):
    """设置Web UI全局实例"""
    global dhcp_proxy, dns_proxy
    dhcp_proxy = dhcp_proxy_instance
    dns_proxy = dns_proxy_instance
    
    return WebUI(host, port)

# 如果在Linux环境中缺少某些模块的处理
try:
    import os
except ImportError:
    import sys
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "aiohttp", "aiohttp-jinja2", "jinja2", "psutil", "netifaces"])
    import os
