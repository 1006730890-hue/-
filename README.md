# 多多银行智能体：部署说明

## 1. 准备环境

- Windows 10/11、Python 3.11。
- 安装 [Ollama](https://ollama.com/download)，保持服务运行。
- ZIP已包含构建后的页面；从仓库部署或重建页面时，安装Node.js 20及以上版本。

下载业务模型：

```powershell
ollama pull qwen3:8b
```

## 2. 安装并启动

解压后，在项目根目录打开PowerShell：

```powershell
powershell -ExecutionPolicy Bypass -File .\setup.ps1
powershell -ExecutionPolicy Bypass -File .\start.ps1 -OpenBrowser
```

访问 **http://127.0.0.1:8018/**。首次启动生成账户、账本和登录信息：

```text
backend/data/initial-customer-access.txt
```

使用文件内的登录名和初始密码登录。确认模型连接：

```powershell
Invoke-RestMethod http://127.0.0.1:8018/health
```

`llm_online`应为`true`。默认启动本地规则、模型规划、动作授权、确认和账本服务。

## 3. 启用完整安全组件

安装独立的推理环境和记忆环境：

```powershell
powershell -ExecutionPolicy Bypass -File .\setup.ps1 -Full
```

先在[模型页面](https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-86M)取得访问权限，再登录并下载检测模型：

```powershell
.\backend\.venv-infer\Scripts\huggingface-cli.exe login
.\backend\.venv-infer\Scripts\python.exe .\tools\download_detector.py
powershell -ExecutionPolicy Bypass -File .\stop.ps1
powershell -ExecutionPolicy Bypass -File .\start.ps1 -Full -OpenBrowser
```

完整模式使用8018业务、8150检测、8155参数扫描、8164记忆服务。模型文件位于`models/meta-llama--Llama-Prompt-Guard-2-86M/`，启动时从本地加载。

## 4. 修改配置

安装脚本首次复制`backend/.env.example`为`backend/.env`。修改后停止并重新启动。

| 配置项 | 默认值 | 用途 |
|---|---|---|
| `LLM_BASE_URL` | `http://127.0.0.1:11434/v1` | 模型API地址 |
| `LLM_MODEL` | `qwen3:8b` | 已下载的模型名称 |
| `DB_PATH` | `data/bank.db` | 相对于backend的账本路径 |
| `MFA_PROVIDER` | `local_outbox` | 本机验证码投递；可改为`totp` |
| `DEMO_MODE` | `false` | 部署时保持关闭 |

本机验证码写入`backend/data/local-mfa/`。使用验证器时，将`MFA_PROVIDER`改为`totp`，在本机环境配置`MFA_TOTP_SECRETS`，内容为用户编号到Base32密钥的JSON映射。

修改客户密码：

```powershell
.\backend\.venv\Scripts\python.exe .\tools\set_customer_password.py --name 张伟
```

## 5. 测试与停止

```powershell
Push-Location backend
.\.venv\Scripts\python.exe -m pytest -q
Pop-Location
powershell -ExecutionPolicy Bypass -File .\stop.ps1
```

测试使用临时数据库。运行数据保存在`backend/data/`，日志保存在`backend/.duplex-runtime/`。

## 6. 常见启动问题

| 问题 | 处理 |
|---|---|
| Python未被找到 | 安装Python 3.11；或执行`setup.ps1 -Python "Python解释器的完整路径"` |
| `llm_online=false` | 启动Ollama；用`ollama list`核对模型名与`.env`一致 |
| 页面不存在 | 执行`setup.ps1 -RebuildFrontend` |
| 端口占用 | 先运行`stop.ps1`；业务端口也可用`start.ps1 -Port 8028`更换 |
| 完整组件启动失败 | 查看对应`.err.log`；核对模型授权、下载目录与三个独立环境 |

重建客户页面：`cd frontend`后执行`npm ci`、`npm run build`；开发预览执行`npm run dev`，代理默认连接8018。
