# 简易 Web 服务示例

本项目提供一个基于 Flask 的示例 Web 服务，实现用户注册、登录、数据展示、查询和简单权限管理。

运行步骤：

1. 创建虚拟环境并安装依赖：

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

2. 运行服务：

```powershell
python Web.py
```

默认运行在 `http://0.0.0.0:5000`，首次运行会在同目录创建 `app.db` 数据库并预置一个管理员 `admin/admin123`。
# hu-lian-wang-sh-jian
互联网实践
