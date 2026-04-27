# 🐟 PcapPal

面向 CTF 竞赛的 Web 流量分析工具。Python (FastAPI + Scapy) 后端 + 浏览器前端。

## 功能特性

### 基础分析
- **协议识别**：Ethernet、IPv4/IPv6、TCP、UDP、ICMP、HTTP、DNS、TLS
- **数据包列表**：Wireshark 风格表格，支持分页与过滤
- **TCP 流追踪**：自动重组流，支持 ASCII/Hex 导出
- **流量统计**：协议分布、Top IP、Top 端口

### CTF 专项
- **🎯 Flag 猎人**：自动检测明文/Hex/Base64/ROT13 编码的 flag
- **🔌 USB 流量**：USB HID 键盘/鼠标流量解析
- **📡 ICMP 隐写**：按 TTL、Code、Seq、Payload 提取隐藏数据
- **🌐 DNS 分析**：DNS 查询/响应提取，检测 DNS 隧道
- **📁 文件提取**：从 HTTP、TCP 流中提取文件（支持 zip/png/jpg/gif/pdf 等）
- **📠 FTP / Telnet**：提取登录凭据、命令交互记录
- **🐚 Webshell 检测**：识别菜刀/蚁剑/冰蝎/哥斯拉特征流量
- **💉 SQL 注入**：检测常见 SQL 注入模式（union select、sleep、盲注等）
- **🚪 端口扫描**：统计 SYN 包判断端口扫描行为

## 快速开始

### 安装依赖

```bash
pip install fastapi uvicorn python-multipart aiofiles scapy
```

### 启动服务

```bash
# 开发模式（热重载）
uvicorn main:app --reload --host 0.0.0.0 --port 8080

# 生产模式
uvicorn main:app --host 0.0.0.0 --port 8080 --workers 4
```

然后浏览器访问 `http://localhost:8080`

## 部署方式

### Docker

```dockerfile
FROM python:3.12-slim
WORKDIR /app
COPY . .
RUN pip install fastapi uvicorn python-multipart aiofiles scapy
EXPOSE 8080
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]
```

### 一键启动脚本

```bash
python3 -m venv venv
source venv/bin/activate
pip install fastapi uvicorn python-multipart aiofiles scapy
python -m uvicorn main:app --host 0.0.0.0 --port 8080
```

## 项目结构

```
PcapPal/
├── main.py                    # FastAPI 入口
├── backend/
│   ├── __init__.py
│   ├── session.py             # 会话管理
│   ├── parser.py              # Scapy pcap/pcapng 解析
│   ├── utils.py               # 通用工具
│   ├── flag_hunter.py         # Flag 自动检测
│   ├── usb_analyzer.py        # USB HID 分析
│   ├── icmp_analyzer.py       # ICMP 隐写分析
│   ├── dns_analyzer.py        # DNS 分析
│   ├── file_extractor.py      # 文件提取
│   ├── ftp_telnet.py          # FTP/Telnet 分析
│   ├── webshell_detect.py     # Webshell 检测
│   ├── sql_inject.py          # SQL 注入检测
│   └── portscan.py            # 端口扫描检测
├── static/
│   ├── index.html             # 前端页面
│   ├── css/style.css          # 样式主题
│   └── js/app.js              # 前端逻辑
└── README.md
```

## API 文档

启动服务后自动生成的 API 文档：
- Swagger UI: `http://localhost:8080/api/docs`
- ReDoc: `http://localhost:8080/api/redoc`

## 性能参考

| 流量包大小 | 包数量 | 解析耗时 |
|-----------|--------|---------|
| 1.1 MB    | 10,000 | ~2.4 s  |
| 5.2 MB    | 50,000 | ~12 s   |

> 注：CTF 竞赛流量包通常在 1-10 MB、数千到数万包范围内，完全满足使用需求。

## 技术栈

- **后端**：Python 3.12 + FastAPI + Scapy
- **前端**：原生 JavaScript (ES6) + CSS3
- **通信**：REST API + JSON
- **无数据库**：解析结果保存在内存会话中，重启后清空

## 许可

MIT License
