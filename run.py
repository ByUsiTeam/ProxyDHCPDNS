#!/usr/bin/env python3
"""
启动脚本 - 简化修复版本
"""

import asyncio
import logging
import signal
import sys
import os
from datetime import datetime

# 导入代理模块
try:
    from dhcp_proxy import DHCPProxy, setup_logging, load_config
    from dns_proxy import DNSProxy
    from web_ui import setup_web_ui
except ImportError as e:
    print(f"❌ 导入模块失败: {e}")
    print("请确保所有依赖已安装: pip install aiohttp aiohttp-jinja2 jinja2")
    sys.exit(1)

async def main():
    """主启动函数"""
    # 加载配置
    try:
        load_config()
    except Exception as e:
        print(f"❌ 加载配置文件失败: {e}")
        return
    
    # 设置日志系统
    try:
        log_path = setup_logging()
        print(f"📝 日志文件: {log_path}")
    except Exception as e:
        print(f"❌ 设置日志系统失败: {e}")
        return
    
    logging.info("🚀 启动DHCP、DNS代理和Web UI服务...")
    
    # 创建服务实例
    dhcp_proxy = DHCPProxy()
    dns_proxy = DNSProxy(dhcp_proxy)
    web_ui = setup_web_ui(dhcp_proxy, dns_proxy)
    
    # 设置信号处理
    def signal_handler(signum, frame):
        logging.info("收到停止信号，正在关闭服务...")
        # 设置停止标志
        dhcp_proxy.running = False
        # 这里可以添加其他服务的停止逻辑
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # 启动所有服务
    try:
        await asyncio.gather(
            dhcp_proxy.start_proxy(),
            dns_proxy.start_server(),
            web_ui.start(),
            return_exceptions=True
        )
    except KeyboardInterrupt:
        logging.info("收到键盘中断信号")
    except Exception as e:
        logging.error(f"服务运行异常: {e}")
    finally:
        # 停止服务
        await web_ui.stop()
        logging.info("所有服务已停止")

if __name__ == "__main__":
    # 检查权限
    if os.geteuid() != 0:
        print("⚠️  警告: 非root用户运行，可能无法绑定特权端口(53, 67)")
    
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n👋 服务已停止")
    except Exception as e:
        print(f"❌ 启动失败: {e}")
        sys.exit(1)
