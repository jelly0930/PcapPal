# PcapPal

面向 CTF 竞赛的 Web 流量分析工具。Python (FastAPI + Scapy) 后端 + 浏览器前端，无需数据库，上传即可分析。

## 功能特性

### 基础分析
- **协议识别**：Ethernet、IPv4/IPv6、TCP、UDP、ICMP、HTTP、DNS、TLS、ARP
- **数据包列表**：Wireshark 风格表格，支持分页与协议过滤
- **TCP 流追踪**：自动重组流，支持 ASCII/Hex 导出
- **HTTP 事务分析**：自动重组 TCP 流、解析 HTTP 请求/响应、配对事务、支持 Chunked 编码与重传去重
- **流量统计**：协议分布、Top IP、Top 端口
- **TLS 解密**：上传 SSLKEYLOGFILE，调用 tshark 解密 HTTPS 流量

### CTF 专项
- **Flag 猎人**：自动检测明文 / Hex / Base64 / ROT13 编码的 flag
- **USB 流量**：USB HID 键盘 / 鼠标流量解析
- **ICMP 隐写**：按 TTL、Code、Seq、Payload 提取隐藏数据
- **DNS 分析**：DNS 查询 / 响应提取，检测 DNS 隧道（超长子域名、Base32 编码）
- **文件提取**：从 HTTP、TCP 流中提取文件（支持 zip/png/jpg/gif/pdf 等常见格式）
- **FTP / Telnet**：提取登录凭据、命令交互记录
- **Webshell 检测**：识别菜刀 / 蚁剑 / 冰蝎 / 哥斯拉特征流量
- **Webshell 解密**：解密常见 Webshell 加密流量（ASP / JSPX / PHP，含 Base64、XOR、AES）
- **SQL 注入检测**：检测常见 SQL 注入模式（union select、sleep、盲注等）
- **端口扫描检测**：统计 SYN 包判断端口扫描行为与开放端口
- **ARP 分析**：检测 ARP 欺骗、IP/MAC 冲突、ARP 扫描

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
├── main.py                    # FastAPI 入口：上传、包列表、TCP 重组、HTTP 事务、统计、TLS 解密
├── backend/
│   ├── __init__.py
│   ├── session.py             # 内存会话管理（1 小时超时）
│   ├── parser.py              # Scapy pcap/pcapng 解析
│   ├── utils.py               # 通用工具（hex/ascii、base64/rot13 解码）
│   ├── flag_hunter.py         # Flag 自动检测
│   ├── usb_analyzer.py        # USB HID 分析
│   ├── icmp_analyzer.py       # ICMP 隐写分析
│   ├── dns_analyzer.py        # DNS 分析与隧道检测
│   ├── file_extractor.py      # 文件提取
│   ├── ftp_telnet.py          # FTP/Telnet 凭据与交互提取
│   ├── webshell_detect.py     # Webshell 检测
│   ├── webshell_decryptor.py  # Webshell 流量解密
│   ├── sql_inject.py          # SQL 注入检测
│   ├── portscan.py            # 端口扫描检测
│   └── arp_analyzer.py        # ARP 欺骗与冲突检测
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

## 技术栈

- **后端**：Python 3.12 + FastAPI + Scapy
- **前端**：原生 JavaScript (ES6) + CSS3
- **通信**：REST API + JSON
- **无数据库**：解析结果保存在内存会话中，重启后清空

## 许可

MIT License
