#!/usr/bin/env python3
"""
启动脚本 - 同时启动DHCP代理和DNS代理
"""

import asyncio
import logging
from dhcp_proxy import DHCPProxy, setup_logging, load_config
from dns_proxy import DNSProxy

async def main():
    """主启动函数"""
    # 加载配置
    load_config()
    
    # 设置日志系统
    log_path = setup_logging()
    
    logging.info("🚀 启动DHCP和DNS代理服务器...")
    
    # 创建DHCP代理
    dhcp_proxy = DHCPProxy()
    
    # 创建DNS代理
    dns_proxy = DNSProxy(dhcp_proxy)
    
    # 同时启动两个服务
    await asyncio.gather(
        dhcp_proxy.start_proxy(),
        dns_proxy.start_server(),
        return_exceptions=True
    )

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logging.info("所有服务已停止")
    except Exception as e:
        logging.error(f"启动失败: {e}")
