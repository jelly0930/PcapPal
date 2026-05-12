# PcapPal — AI Agent 项目指南

## 项目概述

PcapPal 是一款面向 CTF 竞赛的 Web 流量分析工具。它通过浏览器上传 pcap/pcapng 文件，由后端使用 Scapy 解析后在内存中存储，前端以单页面应用（SPA）形式展示分析结果。无需数据库，无需构建步骤，启动即可使用。

- **中文名**：CTF 流量分析工具
- **核心功能**：协议识别、数据包列表、TCP 流追踪、HTTP 事务分析、TLS 解密、Flag 自动检测、USB HID 解析、ICMP 隐写、DNS 隧道检测、文件提取、FTP/Telnet 凭据提取、Webshell 检测与解密、SQL 注入检测、端口扫描检测、ARP 分析等。

## 技术栈

- **后端**：Python 3.12 + FastAPI + Scapy（数据包解析）+ uvicorn
- **前端**：原生 JavaScript (ES6) + HTML5 + CSS3，无框架、无打包器
- **通信**：REST API + JSON
- **无数据库**：所有解析结果保存在内存会话中（1 小时超时），服务重启后清空
- **外部依赖**：tshark（可选，用于 TLS 解密）

## 项目结构

```
PcapPal/
├── main.py                    # FastAPI 入口：上传、包列表、TCP 重组、HTTP 事务、统计、TLS 解密
├── backend/                   # 后端分析模块
│   ├── __init__.py            # 空文件
│   ├── session.py             # 内存会话管理（1 小时超时，后台清理线程）
│   ├── parser.py              # Scapy pcap/pcapng 解析器，输出轻量 dict
│   ├── utils.py               # 通用工具：hex/ascii、base64/rot13、正则匹配
│   ├── flag_hunter.py         # Flag 自动检测（明文/Hex/Base64/ROT13）
│   ├── usb_analyzer.py        # USB HID 键盘/鼠标解析
│   ├── icmp_analyzer.py       # ICMP 隐写与隧道检测
│   ├── dns_analyzer.py        # DNS 查询/响应提取，DNS 隧道检测
│   ├── file_extractor.py      # 从 HTTP/TCP/UDP 中提取文件（magic + Content-Type）
│   ├── ftp_telnet.py          # FTP/Telnet 凭据与命令提取
│   ├── webshell_detect.py     # 菜刀/蚁剑/冰蝎/哥斯拉特征检测
│   ├── webshell_decryptor.py  # Webshell 流量解密引擎（AES/DES/RC4/XOR/Base64 等）
│   ├── sql_inject.py          # SQL 注入模式检测
│   ├── portscan.py            # 端口扫描行为检测（SYN 统计）
│   └── arp_analyzer.py        # ARP 欺骗/冲突/扫描检测
├── static/                    # 前端静态资源
│   ├── index.html             # 单页面 HTML
│   ├── css/style.css          # 暗色主题样式
│   └── js/app.js              # 前端逻辑（~2500 行），含所有分析器渲染、表格、分页
├── README.md                  # 中文项目文档
├── CLAUDE.md                  # Claude Code 专用指南
└── AGENTS.md                  # 本文件
```

## 安装与运行

**无 requirements.txt / pyproject.toml / package.json。** 依赖需手动安装：

```bash
# 安装核心依赖
pip install fastapi uvicorn python-multipart aiofiles scapy

# 可选：Webshell 解密中的 AES/DES/RC4 支持
pip install pycryptodome

# 可选：TLS 解密需要系统安装 tshark（Wireshark CLI）
```

### 启动命令

```bash
# 开发模式（热重载）
uvicorn main:app --reload --host 0.0.0.0 --port 8080

# 生产模式
uvicorn main:app --host 0.0.0.0 --port 8080 --workers 4
```

访问 `http://localhost:8080`。FastAPI 自动生成的 API 文档：
- Swagger UI: `/api/docs`
- ReDoc: `/api/redoc`

### Docker 示例

```dockerfile
FROM python:3.12-slim
WORKDIR /app
COPY . .
RUN pip install fastapi uvicorn python-multipart aiofiles scapy
EXPOSE 8080
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]
```

## 架构与请求流程

1. **上传**：`POST /api/upload` → 保存到临时文件 → `backend/parser.py` 用 Scapy 解析 → 存入内存会话
2. **会话**：每个会话由 16 位 UUID 前缀标识，存储在 `backend/session.py` 的全局 `SESSIONS` dict 中
3. **查询**：前端调用 `/api/session/{sid}/...` 获取包列表、流、统计、各类分析结果
4. **解析**：`parser.py` 将每包解析为 dict，含 `index`, `timestamp`, `length`, `protocol`, `src`, `dst`, `srcPort`, `dstPort`, `info`, `layers`, `_raw` 等字段。`_raw` 为原始字节，JSON 响应前由 `_clean()` 剥离

## Analyzer 注册模式

每个 `backend/` 下的分析器模块通常导出 `register(app)` 函数，在 `main.py` 底部统一导入并注册：

```python
from backend import flag_hunter, usb_analyzer, icmp_analyzer, ...

_analyzers = [
    ("flag", flag_hunter),
    ("usb", usb_analyzer),
    ...
]
for _name, _mod in _analyzers:
    if hasattr(_mod, "register"):
        _mod.register(app)
```

**新增分析器步骤**：
1. 创建 `backend/new_analyzer.py`，实现 `analyze(session: dict) -> dict` 和 `register(app: FastAPI)`
2. 在 `main.py` 中导入并加入 `_analyzers` 列表
3. 在 `static/js/app.js` 的 `renderAnalyzerResult()` 和 `renderCurrentTool()` 中添加对应渲染逻辑
4. 在 `static/index.html` 的侧边栏添加导航项（如需要）

## 数据约定

### Packet Dict 结构

```python
{
    "index": 1,
    "timestamp": 1714381234.567,
    "length": 64,
    "protocol": "HTTP",      # UNKNOWN / Ethernet / ARP / IP / TCP / UDP / ICMP / HTTP / TLS / DNS
    "src": "192.168.1.1",
    "dst": "192.168.1.2",
    "srcPort": 12345,
    "dstPort": 80,
    "info": "GET / HTTP/1.1",
    "delta": 0.0,            # 与上一包的时间差
    "_raw": b"...",          # 原始字节，仅内部使用
    "layers": {
        "ethernet": {"srcMac": "...", "dstMac": "...", "type": 0x0800, "_offset": 0, "_length": 14},
        "ip": {"src": "...", "dst": "...", "proto": 6, "ttl": 64, "_offset": 14, "_length": 20},
        "tcp": {"sport": 12345, "dport": 80, "seq": 1, "ack": 1, "flags": "PA", "payload_hex": "...", "payload_ascii": "...", "_offset": 34, "_length": 32},
        "http": {"isRequest": True, "method": "GET", "uri": "/", ...},
        "dns": {"qr": 0, "queries": [...], "answers": [...]},
        "arp": {...},
        "icmp": {"type": 8, "code": 0, "payload_hex": "...", ...}
    }
}
```

### 内部字段规范
- 所有以 `_` 开头的字段（如 `_raw`, `_offset`, `_length`）为内部字段，JSON 序列化前必须剥离
- `parser.py` 中的 `_layer_offset()` 和 `_get_hex()` 用于计算层偏移和 hex 转换

## 前端约定

- **无构建工具**：直接编辑 `static/js/app.js` 和 `static/css/style.css`，刷新浏览器即生效
- **JSZip**：文件批量导出 ZIP 依赖 CDN 加载的 JSZip（`https://cdnjs.cloudflare.com/ajax/libs/jszip/3.10.1/jszip.min.js`）
- **状态管理**：全局 `state` 对象管理当前会话、分页、过滤、排序、选中的包等
- **渲染模式**：分析器结果通过 `renderAnalyzerResult(tool, data)` 分发到各 `renderXxxResult()` 函数，以字符串拼接 HTML 方式渲染
- **最近文件**：使用 `localStorage` 保存最近 10 个上传文件的会话 ID，支持页面刷新后恢复会话
- **书签**：同样使用 `localStorage`，按 `pcappal_bookmarks_${sid}` 键存储

## 代码风格

- **后端**：Python，使用类型提示（`typing` 模块），函数与变量采用 `snake_case`
- **前端**：JavaScript (ES6+)，函数采用 `camelCase`，常量采用 `UPPER_SNAKE_CASE`
- **注释**：后端模块使用英文 docstring；UI 文本、README、用户可见提示以中文为主
- **错误处理**：后端大量使用 `try/except` 静默忽略解析异常；HTTP 异常通过 FastAPI 的 `HTTPException` 抛出

## 测试与质量

- **当前无测试套件**：未配置 pytest、unittest 或任何自动化测试
- **无 linter/formatter**：未配置 flake8、black、ruff、prettier、eslint 等
- **手动验证方式**：启动服务后，使用项目目录下的示例 pcap 文件在浏览器中上传测试：
  - `test_mixed.pcap`
  - `test_large.pcap`
  - `perf_test.pcap`
  - `perf_big.pcap`
  - `SmoothlyAgain.pcap`
  - `flowzip.pcapng`
  - `kindzilla.pcapng`
  - `邮件.pcapng`

## 安全注意事项

- **无身份验证**：任何人可上传文件并访问分析接口，仅适合本地或受信任环境使用
- **内存会话限制**：大 pcap 文件会占用大量 RAM；`test_large.pcap` 等文件可用于压力测试
- **临时文件**：上传的 pcap 保存在系统临时目录，`session.py` 在会话过期或删除时清理，但异常退出可能残留
- **命令注入防护**：TLS 解密调用 `tshark` 时使用列表传参（`subprocess.run(cmd, ...)`），未使用 shell，相对安全
- **XSS 防护**：前端 `escapeHtml()` 对所有动态文本进行转义；事件绑定使用 `addEventListener` 而非内联 `onclick`

## 常见开发任务速查

| 任务 | 操作 |
|---|---|
| 新增分析器 | 创建 `backend/xxx.py` → 写 `register(app)` → `main.py` 导入注册 → `app.js` 添加渲染 |
| 修改解析逻辑 | 编辑 `backend/parser.py`，注意 `_raw` 保留和 `_offset`/`_length` 计算 |
| 调整前端样式 | 直接编辑 `static/css/style.css`，使用 CSS 变量（`--bg-primary` 等） |
| 添加前端功能 | 编辑 `static/js/app.js`，在 `renderCurrentTool()` 和对应 `renderXxx()` 中添加逻辑 |
| 支持新文件类型提取 | 编辑 `backend/file_extractor.py` 的 `FILE_SIGNATURES` 和 `_detect_file_type()` |
| 添加新 Webshell 解密规则 | 编辑 `backend/webshell_decryptor.py` 的 `WEBSHELL_DECRYPT_RULES`，实现解密函数 |
| 本地调试 | `uvicorn main:app --reload --host 0.0.0.0 --port 8080`，浏览器访问即可 |

## 关键外部依赖版本参考

开发时验证可用的版本组合：
- Python 3.12
- fastapi（最新稳定版）
- uvicorn（最新稳定版）
- python-multipart（最新稳定版）
- aiofiles（最新稳定版）
- scapy（最新稳定版）
- pycryptodome（可选，用于 AES/DES/RC4 解密）
