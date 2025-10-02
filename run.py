#!/usr/bin/env python3
"""
启动脚本 - 同时启动DHCP代理、DNS代理和Web UI
"""

import asyncio
import logging
import signal
import sys
from dhcp_proxy import DHCPProxy, setup_logging, load_config
from dns_proxy import DNSProxy
from web_ui import setup_web_ui, WebUI

class ProxyManager:
    """代理管理器"""
    
    def __init__(self):
        self.dhcp_proxy = None
        self.dns_proxy = None
        self.web_ui = None
        self.running = False
        
    async def start_all(self):
        """启动所有服务"""
        # 加载配置
        load_config()
        
        # 设置日志系统
        log_path = setup_logging()
        
        logging.info("🚀 启动DHCP、DNS代理和Web UI服务...")
        
        try:
            # 创建DHCP代理
            self.dhcp_proxy = DHCPProxy()
            
            # 创建DNS代理
            self.dns_proxy = DNSProxy(self.dhcp_proxy)
            
            # 创建Web UI
            self.web_ui = setup_web_ui(
                self.dhcp_proxy, 
                self.dns_proxy,
                host="0.0.0.0",
                port=6560
            )
            
            # 设置信号处理
            self.setup_signal_handlers()
            
            # 启动所有服务
            await asyncio.gather(
                self.dhcp_proxy.start_proxy(),
                self.dns_proxy.start_server(),
                self.web_ui.start(),
                return_exceptions=True
            )
            
        except Exception as e:
            logging.error(f"启动服务失败: {e}")
            await self.stop_all()
    
    def setup_signal_handlers(self):
        """设置信号处理器"""
        def signal_handler(signum, frame):
            logging.info(f"收到信号 {signum}, 正在关闭服务...")
            asyncio.create_task(self.stop_all())
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
    
    async def stop_all(self):
        """停止所有服务"""
        logging.info("正在停止所有服务...")
        
        self.running = False
        
        # 停止Web UI
        if self.web_ui:
            await self.web_ui.stop()
        
        # 停止代理服务（需要在代理类中添加停止方法）
        if self.dhcp_proxy:
            self.dhcp_proxy.running = False
        
        logging.info("所有服务已停止")
        sys.exit(0)

async def main():
    """主启动函数"""
    manager = ProxyManager()
    await manager.start_all()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logging.info("收到停止信号")
    except Exception as e:
        logging.error(f"服务运行错误: {e}")
