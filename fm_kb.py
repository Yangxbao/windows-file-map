# -*- coding: utf-8 -*-
"""
文件地图助手 · 共享知识库 (fm_kb.py)
=====================================
被 fm_scan.py（扫描时打标签）与 fm_report.py（出报告时补说明）共同使用。
只包含"名称 -> 中文解释/分类"的知识与判断规则，不含任何扫描 IO。
"""

import re

VERSION = "2.0.0"

# ---------------- 节点标志位 ----------------
F_DENIED = 1    # 枚举/读取被拒绝
F_LINK  = 2     # 符号链接/目录联接（已记录目标，未跟随）
F_SENS  = 4     # 疑似敏感（未读取内容）
F_EST   = 32    # 大小不完整（子树内存在无法访问/读取失败的部分）
F_SKIP  = 64    # 按明确规则排除（回收站/卷信息等）
F_PROJ  = 128   # 项目根目录

# scanned 列取值（枚举完成状态）
S_NONE = 0      # 占位，尚未枚举
S_DONE = 1      # 目录枚举完成（子条目全部列出）
S_PART = 2      # 枚举中断（部分完成）
S_FAIL = 3      # 枚举失败（拒绝访问/丢失/IO错误）
S_EXCL = 4      # 按明确规则排除（未枚举内容，理由见 err）
S_GONE = 5      # 增量扫描时发现目录已不存在

# 错误类别
ERR_LABELS = {
    "denied": "拒绝访问（权限不足）",
    "missing": "对象不存在/扫描中被删除",
    "locked": "被占用（共享冲突）",
    "longpath": "路径超长",
    "ioerror": "其他 IO 错误",
    "readlink": "链接目标读取失败",
}

# 明确排除枚举内容的目录（记录目录本身，理由写入报告）
EXCLUDE_DIRS = {
    "$recycle.bin": "回收站内容（具有特殊删除语义，避免误读待清理数据）",
    "system volume information": "系统还原点/卷影副本（系统受保护存储，普通权限无法访问）",
}

# 按目录名称给出的中文解释（小写键）-> (说明, 类别, 置信度)
ZH_DIRS = {
    "windows": ("Windows 系统目录（系统核心，请勿改动）", "sys", "高"),
    "program files": ("64 位软件默认安装目录", "sys", "高"),
    "program files (x86)": ("32 位软件默认安装目录", "sys", "高"),
    "programdata": ("系统级应用共享数据目录", "sys", "高"),
    "perflogs": ("系统性能日志目录（通常为空）", "sys", "高"),
    "users": ("所有用户的主目录", "sys", "高"),
    "$recycle.bin": ("回收站（按明确规则未枚举内容）", "sys", "高"),
    "system volume information": ("系统还原点与卷影副本（按明确规则未枚举）", "sys", "高"),
    "config.msi": ("Windows 安装器回滚备份", "sys", "中"),
    "$sysreset": ("Windows 系统重置相关数据", "sys", "中"),
    "$winreagent": ("Windows 恢复环境暂存数据", "sys", "中"),
    "recovery": ("系统恢复环境相关文件", "sys", "中"),
    "inetpub": ("IIS Web 服务器默认目录", "sys", "中"),
    "temp": ("临时文件目录", "cache", "中"),
    "ahcache": ("应用兼容性缓存（系统生成）", "cache", "中"),
    "desktop": ("桌面文件夹（桌面上的文件实际存放处）", "user", "高"),
    "documents": ("文档文件夹（我的文档）", "user", "高"),
    "downloads": ("下载文件夹（浏览器默认下载位置）", "user", "高"),
    "pictures": ("图片文件夹", "user", "高"),
    "videos": ("视频文件夹", "user", "高"),
    "music": ("音乐文件夹", "user", "高"),
    "favorites": ("浏览器收藏夹", "user", "高"),
    "links": ("资源管理器侧边栏链接", "user", "高"),
    "searches": ("保存的搜索条件", "user", "高"),
    "saved games": ("游戏存档目录", "user", "高"),
    "contacts": ("联系人目录", "user", "高"),
    "3d objects": ("3D 对象目录", "user", "高"),
    "onedrive": ("OneDrive 云盘同步目录", "user", "高"),
    "appdata": ("应用程序数据目录（配置与缓存，只读元数据盘点）", "sys", "高"),
    "local": ("本机应用数据（多为缓存）", "cache", "高"),
    "roaming": ("应用漫游配置数据", "cfg", "高"),
    "locallow": ("低权限应用数据", "cache", "高"),
    "application data": ("旧版 Windows 兼容联接（实际数据在别处）", "sys", "高"),
    "local settings": ("旧版 Windows 兼容联接（实际数据在别处）", "sys", "高"),
    "my documents": ("旧版 Windows 兼容联接（实际数据在别处）", "sys", "高"),
    "my pictures": ("旧版 Windows 兼容联接（实际数据在别处）", "sys", "高"),
    "my music": ("旧版 Windows 兼容联接（实际数据在别处）", "sys", "高"),
    "cookies": ("旧版 Windows 兼容联接（实际数据在别处）", "sys", "高"),
    "nethood": ("旧版 Windows 兼容联接（实际数据在别处）", "sys", "高"),
    "printhood": ("旧版 Windows 兼容联接（实际数据在别处）", "sys", "高"),
    "sendto": ("右键发送到菜单项目录", "sys", "高"),
    "templates": ("用户模板目录", "sys", "高"),
    "recent": ("最近使用文件记录目录", "sys", "高"),
    "「开始」菜单": ("开始菜单目录（联接）", "sys", "高"),
    "wechat files": ("微信聊天记录与接收的文件", "user", "高"),
    "xwechat_files": ("微信（新版）聊天记录与接收的文件", "user", "高"),
    "tencent files": ("QQ 聊天记录与接收的文件", "user", "高"),
    "baidunetdiskdownload": ("百度网盘默认下载目录", "user", "高"),
    "ideaprojects": ("IntelliJ IDEA 默认项目存放目录", "devtool", "高"),
    "webstormprojects": ("WebStorm 默认项目存放目录", "devtool", "高"),
    "pycharmprojects": ("PyCharm 默认项目存放目录", "devtool", "高"),
    "androidstudioprojects": ("Android Studio 默认项目存放目录", "devtool", "高"),
    "datagripprojects": ("DataGrip 数据库项目存放目录", "devtool", "高"),
    "androidkeystores": ("安卓应用签名密钥目录（含签名文件，未读取内容）", "sensitive", "高"),
    "workspace": ("开发工作区目录（按名称推断，常用于存放项目）", "devtool", "中"),
    "workspaces": ("开发工作区目录（按名称推断）", "devtool", "中"),
    "projects": ("项目存放目录（按名称推断）", "devtool", "中"),
    "project": ("项目存放目录（按名称推断）", "devtool", "中"),
    "code": ("代码目录（按名称推断）", "devtool", "中"),
    "codes": ("代码目录（按名称推断）", "devtool", "中"),
    "repos": ("代码仓库目录（按名称推断）", "devtool", "中"),
    "develop": ("开发目录（按名称推断，可能存放开发项目与工具）", "devtool", "中"),
    "development": ("开发目录（按名称推断）", "devtool", "中"),
    "dev": ("开发目录（按名称推断）", "devtool", "中"),
    "source": ("源代码目录（按名称推断）", "devtool", "中"),
    "githubprojects": ("GitHub 项目存放目录（按名称推断）", "devtool", "中"),
    "github开源项目库": ("GitHub 开源项目收藏目录（按名称推断）", "devtool", "中"),
    "go": ("Go 语言工作区（GOPATH，含模块缓存）", "devtool", "高"),
    "tools": ("工具软件目录", "exe", "中"),
    "tool": ("工具软件目录", "exe", "中"),
    "software": ("软件目录", "exe", "中"),
    "soft": ("软件目录", "exe", "中"),
    "mysql": ("MySQL 数据库相关目录（可能是安装文件或数据目录）", "data", "中"),
    "redis": ("Redis 数据库相关目录（可能是安装文件或数据目录）", "data", "中"),
    "steam": ("Steam 游戏平台相关目录", "other", "高"),
    "logs": ("日志目录", "data", "中"),
    "log": ("日志目录", "data", "中"),
    "backup": ("备份目录（建议人工确认内容）", "data", "中"),
    "bak": ("备份目录（建议人工确认内容）", "data", "中"),
    "备份": ("备份目录（建议人工确认内容）", "data", "中"),
    "下载": ("下载目录", "user", "高"),
    "文档": ("文档目录", "docs", "高"),
    "图片": ("图片目录", "media", "高"),
    "照片": ("照片目录", "media", "高"),
    "视频": ("视频目录", "video", "高"),
    "电影": ("电影视频目录", "video", "高"),
    "音乐": ("音乐目录", "audio", "高"),
    "学习": ("学习资料目录", "docs", "中"),
    "学习资料": ("学习资料目录", "docs", "中"),
    "资料": ("资料文档目录", "docs", "中"),
    "教程": ("教程资料目录", "docs", "中"),
    "项目": ("项目目录（按名称推断）", "devtool", "中"),
    "项目代码": ("项目代码目录（按名称推断）", "devtool", "中"),
    "代码": ("代码目录（按名称推断）", "devtool", "中"),
    "软件": ("软件目录", "exe", "中"),
    "安装包": ("安装包存放目录", "exe", "中"),
    "游戏": ("游戏相关目录", "other", "中"),
    "宣传物料": ("宣传/设计物料目录（按名称推断）", "media", "中"),
    "src": ("源代码目录", "code", "中"),
    "main": ("主代码目录", "code", "中"),
    "test": ("测试代码目录", "code", "中"),
    "tests": ("测试代码目录", "code", "中"),
    "docs": ("文档目录", "docs", "中"),
    "doc": ("文档目录", "docs", "中"),
    "examples": ("示例代码目录", "code", "中"),
    "example": ("示例代码目录", "code", "中"),
    "demo": ("演示/示例目录", "code", "中"),
    "scripts": ("脚本目录", "code", "中"),
    "config": ("配置目录", "cfg", "中"),
    "configs": ("配置目录", "cfg", "中"),
    "conf": ("配置目录", "cfg", "中"),
    "assets": ("静态资源目录", "other", "中"),
    "static": ("静态资源目录", "other", "中"),
    "public": ("公开静态资源目录（前端常见）", "other", "中"),
    "lib": ("库文件目录", "other", "中"),
    "libs": ("库文件目录", "other", "中"),
    "utils": ("工具/辅助代码目录", "code", "中"),
    "helpers": ("辅助代码目录", "code", "中"),
    "bin": ("可执行文件/脚本目录", "exe", "中"),
    "data": ("数据目录", "data", "中"),
    "db": ("数据库相关目录", "data", "中"),
    "database": ("数据库相关目录", "data", "中"),
    "sql": ("SQL 脚本目录", "data", "中"),
    "migrations": ("数据库迁移脚本目录", "data", "中"),
    "api": ("接口定义目录", "code", "中"),
    "controller": ("后端控制器代码目录", "code", "中"),
    "controllers": ("后端控制器代码目录", "code", "中"),
    "service": ("后端服务层代码目录", "code", "中"),
    "services": ("后端服务层代码目录", "code", "中"),
    "mapper": ("MyBatis 映射/数据层目录", "code", "中"),
    "entity": ("实体类代码目录", "code", "中"),
    "model": ("数据模型代码目录", "code", "中"),
    "components": ("前端组件目录", "code", "中"),
    "pages": ("前端页面目录", "code", "中"),
    "views": ("前端视图目录", "code", "中"),
    "router": ("前端路由目录", "code", "中"),
    "store": ("前端状态管理目录", "code", "中"),
    "css": ("样式文件目录", "other", "中"),
    "js": ("JavaScript 文件目录", "other", "中"),
    "img": ("图片资源目录", "media", "中"),
    "images": ("图片资源目录", "media", "中"),
    "fonts": ("字体文件目录", "other", "中"),
    "media": ("媒体文件目录", "media", "中"),
    "uploads": ("上传文件目录", "data", "中"),
    "upload": ("上传文件目录", "data", "中"),
    "tmp": ("临时目录", "cache", "中"),
    "cache": ("缓存目录", "cache", "中"),
    ".github": ("GitHub 仓库配置目录（工作流、模板等）", "cfg", "高"),
    ".vscode": ("VS Code 编辑器配置目录", "cfg", "高"),
    "gradle": ("Gradle 构建工具相关目录", "build", "中"),
    ".mvn": ("Maven Wrapper 支持文件目录", "cfg", "高"),
    "webapp": ("Java Web 应用目录", "code", "中"),
    "webapps": ("Web 应用部署目录", "code", "中"),
    "resources": ("资源文件目录", "other", "中"),
    "ansel": ("NVIDIA Ansel 游戏截图目录", "media", "中"),
    "crossdevice": ("Windows 跨设备功能数据（手机连接等）", "sys", "低"),
    "coze": ("扣子（Coze）AI 应用相关目录", "devtool", "中"),
    "doubao": ("豆包（AI 助手）相关数据目录", "cache", "中"),
    "workbuddy": ("WorkBuddy 应用数据目录", "cache", "中"),
    ".ssh": ("SSH 密钥与配置目录（含私钥，未读取内容）", "sensitive", "高"),
    ".gnupg": ("GPG 加密密钥目录（未读取内容）", "sensitive", "高"),
    ".aws": ("AWS 云服务凭证配置目录（未读取内容）", "sensitive", "高"),
    ".kube": ("Kubernetes 集群凭证配置目录（未读取内容）", "sensitive", "高"),
    ".docker": ("Docker 配置目录（可能含登录凭证，未读取内容）", "cfg", "高"),
    "objects": ("Git 对象数据目录", "git", "高"),
    "refs": ("Git 分支引用目录", "git", "高"),
    "hooks": ("Git 钩子脚本目录", "git", "高"),
    "wzry-5v5": ("疑似王者荣耀 5v5 相关网页 demo（按名称推断）", "code", "低"),
}

# 大型自动生成目录：全量枚举元数据，但不在其内部做项目识别，且给出专门解释
HEAVY_DIRS = {
    ".git": ("Git 版本库数据目录（保存提交历史，请勿手动修改）", "git"),
    "node_modules": ("Node.js 依赖包目录（自动生成，可通过 npm install 重新安装）", "deps"),
    "venv": ("Python 虚拟环境目录（自动生成，可删除后重建）", "deps"),
    ".venv": ("Python 虚拟环境目录（自动生成，可删除后重建）", "deps"),
    "__pycache__": ("Python 字节码缓存（自动生成）", "cache"),
    ".gradle": ("Gradle 构建工具缓存与配置目录", "cache"),
    ".m2": ("Maven 本地仓库（下载的 Java 依赖包集中存放处）", "deps"),
    ".npm": ("npm 包管理器缓存目录", "cache"),
    ".cache": ("通用缓存目录", "cache"),
    ".cargo": ("Rust 工具链与依赖缓存目录", "deps"),
    "site-packages": ("Python 第三方库目录（虚拟环境内部）", "deps"),
    ".tox": ("Python 多环境测试工具缓存", "cache"),
    ".pytest_cache": ("pytest 测试框架缓存", "cache"),
    ".mypy_cache": ("mypy 类型检查缓存", "cache"),
    ".next": ("Next.js 框架构建缓存与产物", "build"),
    ".nuxt": ("Nuxt.js 框架构建缓存与产物", "build"),
    ".yarn": ("yarn 包管理器缓存", "cache"),
    ".pnpm-store": ("pnpm 包管理器的包存储目录", "deps"),
    "bower_components": ("前端 Bower 依赖包目录", "deps"),
    ".terraform": ("Terraform 基础设施工具数据", "deps"),
    ".dart_tool": ("Flutter/Dart 构建缓存", "cache"),
    ".idea": ("JetBrains 系列 IDE 的项目配置目录", "cfg"),
    ".android": ("Android 开发工具数据目录（可能含模拟器镜像，体积较大）", "cache"),
    ".jdks": ("JetBrains 管理的 JDK 安装目录", "devtool"),
    ".nuget": ("NuGet 包缓存目录（.NET 依赖包）", "deps"),
    "target": ("Maven/Java 项目的编译输出目录（可重新构建生成）", "build"),
    ".expo": ("Expo 前端工具缓存", "cache"),
    ".parcel-cache": ("Parcel 打包工具缓存", "cache"),
    ".sass-cache": ("Sass 编译缓存", "cache"),
    "coverage": ("测试覆盖率报告输出目录", "build"),
    ".vscode-server": ("VS Code 远程开发服务端数据", "cache"),
    "vendor": ("第三方依赖源码目录（Go/PHP vendor 等）", "deps"),
    "dist": ("打包发布输出目录（构建自动生成）", "build"),
    "build": ("构建输出目录（项目构建自动生成）", "build"),
    "out": ("构建/编译输出目录（自动生成）", "build"),
    "obj": ("C# 编译中间产物目录（自动生成）", "build"),
    "packages": ("NuGet 等包管理器的包存放目录", "deps"),
    "env": ("Python 虚拟环境目录（按名称推断，自动生成）", "deps"),
    "pkg": ("编译/依赖产物目录（go\\pkg 为 Go 模块缓存）", "deps"),
    "winSxS": ("Windows 组件存储（系统文件仓库，体积大属正常）", "sys"),
    "installer": ("Windows Installer 缓存（卸载/修复软件所需，勿清理）", "sys"),
    "servicing": ("Windows 系统服务组件目录", "sys"),
    "wbem": ("WMI 系统组件目录", "sys"),
    "fonts": ("系统字体目录", "sys"),
    "assembly": (".NET 全局程序集缓存（GAC）", "sys"),
    "Microsoft": ("微软软件/组件数据目录", "sys"),
    "WindowsApps": ("Microsoft Store 应用安装目录（受系统保护）", "sys"),
}

# 在项目目录内部按"构建/依赖目录"理解、且其内部不做项目识别的名称
CONTEXT_HEAVY = {"build", "dist", "out", "vendor", "obj", "packages", "env", "pkg"}

# 不在其内部做项目识别的目录名（无论是否在项目里）
IN_HEAVY_ALWAYS = {k for k in HEAVY_DIRS} | {
    "node_modules", ".git", "__pycache__", "site-packages", "venv", ".venv",
}

# 项目标识文件（小写）-> 说明
PROJECT_MARKERS = {
    "pom.xml": "Maven 构建配置",
    "build.gradle": "Gradle 构建配置",
    "build.gradle.kts": "Gradle 构建配置",
    "settings.gradle": "Gradle 工程设置",
    "package.json": "Node.js 项目配置",
    "requirements.txt": "Python 依赖清单",
    "pyproject.toml": "Python 项目配置",
    "setup.py": "Python 打包配置",
    "pipfile": "Python 依赖配置",
    "cargo.toml": "Rust 项目配置",
    "go.mod": "Go 模块定义",
    "composer.json": "PHP 依赖配置",
    "manage.py": "Django 管理脚本",
    "makefile": "Make 构建脚本",
    "dockerfile": "Docker 镜像构建文件",
}

# 特定文件名（小写）-> 中文说明（存库；未命中者由扩展名表在展示层补齐）
ZH_FILES = {
    "readme.md": "项目说明文档（Markdown 格式）",
    "readme.txt": "项目说明文档",
    "readme": "项目说明文档",
    "package.json": "Node.js 项目的依赖与脚本配置文件",
    "package-lock.json": "npm 依赖版本锁定文件（自动生成）",
    "yarn.lock": "yarn 依赖版本锁定文件",
    "pnpm-lock.yaml": "pnpm 依赖版本锁定文件",
    "pom.xml": "Maven 项目的构建配置文件",
    "build.gradle": "Gradle 构建配置文件",
    "settings.gradle": "Gradle 工程设置文件",
    "requirements.txt": "Python 依赖清单",
    "pyproject.toml": "Python 项目配置文件",
    "setup.py": "Python 打包安装脚本",
    "cargo.toml": "Rust 项目配置文件",
    "go.mod": "Go 模块定义文件",
    "go.sum": "Go 依赖校验文件",
    "composer.json": "PHP 依赖配置文件",
    "manage.py": "Django 项目的管理脚本",
    ".gitignore": "Git 忽略规则文件",
    ".gitattributes": "Git 属性配置文件",
    "license": "开源许可证文件",
    "license.md": "开源许可证文件",
    "license.txt": "开源许可证文件",
    "dockerfile": "Docker 镜像构建文件",
    "docker-compose.yml": "Docker 容器编排配置文件",
    "docker-compose.yaml": "Docker 容器编排配置文件",
    "makefile": "Make 构建脚本",
    "vite.config.js": "Vite 前端构建配置文件",
    "vite.config.ts": "Vite 前端构建配置文件",
    "vue.config.js": "Vue CLI 配置文件",
    "tsconfig.json": "TypeScript 编译配置文件",
    "webpack.config.js": "Webpack 打包配置文件",
    "application.yml": "Spring Boot 应用配置文件",
    "application.yaml": "Spring Boot 应用配置文件",
    "application.properties": "Spring Boot 应用配置文件",
    "desktop.ini": "Windows 文件夹视图配置文件（系统自动生成）",
    "thumbs.db": "Windows 缩略图缓存文件（系统自动生成）",
    "ntuser.dat": "用户注册表数据文件（系统核心文件，未读取）",
    "ntuser.ini": "用户注册表相关配置",
    "pagefile.sys": "虚拟内存页面文件（系统文件）",
    "hiberfil.sys": "休眠文件（系统文件，大小与休眠功能相关）",
    "swapfile.sys": "系统交换文件（系统文件）",
    "dumpstack.log.tmp": "系统转储日志临时文件（系统文件）",
    ".env": "环境变量配置文件（可能包含密钥，未读取内容）",
    "id_rsa": "SSH 私钥文件（高度敏感，未读取内容）",
    "accesskey.csv": "疑似云服务访问密钥清单（高度敏感，未读取内容）",
}

# 扩展名 -> (类别, 中文说明)。扫描时只给特殊文件存 zh；此表同时导出给网页展示层。
EXT_TABLE = {
    "pdf": ("docs", "PDF 文档"), "doc": ("docs", "Word 文档"), "docx": ("docs", "Word 文档"),
    "xls": ("docs", "Excel 表格"), "xlsx": ("docs", "Excel 表格"), "csv": ("data", "CSV 表格"),
    "ppt": ("docs", "PPT 演示文稿"), "pptx": ("docs", "PPT 演示文稿"),
    "txt": ("docs", "文本文件"), "md": ("docs", "Markdown 文档"),
    "epub": ("docs", "电子书"), "mobi": ("docs", "电子书"), "azw3": ("docs", "电子书"),
    "jpg": ("media", "图片"), "jpeg": ("media", "图片"), "png": ("media", "图片"),
    "gif": ("media", "图片"), "bmp": ("media", "图片"), "webp": ("media", "图片"),
    "svg": ("media", "矢量图片"), "heic": ("media", "图片"), "ico": ("media", "图标文件"),
    "psd": ("media", "Photoshop 源文件"),
    "mp4": ("video", "视频"), "mkv": ("video", "视频"), "avi": ("video", "视频"),
    "mov": ("video", "视频"), "wmv": ("video", "视频"), "flv": ("video", "视频"),
    "webm": ("video", "视频"),
    "mp3": ("audio", "音频"), "wav": ("audio", "音频"), "flac": ("audio", "无损音频"),
    "m4a": ("audio", "音频"), "ape": ("audio", "无损音频"), "ogg": ("audio", "音频"),
    "zip": ("archive", "压缩包"), "rar": ("archive", "压缩包"), "7z": ("archive", "压缩包"),
    "tar": ("archive", "压缩包"), "gz": ("archive", "压缩包"), "bz2": ("archive", "压缩包"),
    "xz": ("archive", "压缩包"), "iso": ("archive", "光盘镜像"),
    "exe": ("exe", "可执行程序/安装包"), "msi": ("exe", "Windows 安装包"),
    "msix": ("exe", "Windows 应用包"), "appx": ("exe", "Windows 应用包"),
    "apk": ("exe", "安卓安装包"), "dmg": ("exe", "macOS 磁盘镜像"),
    "bat": ("code", "Windows 批处理脚本"), "cmd": ("code", "Windows 批处理脚本"),
    "ps1": ("code", "PowerShell 脚本"), "sh": ("code", "Shell 脚本"),
    "jar": ("exe", "Java 归档包（可运行程序或依赖库）"), "war": ("exe", "Java Web 归档包"),
    "class": ("code", "Java 编译产物"),
    "java": ("code", "Java 源代码"), "py": ("code", "Python 源代码"),
    "js": ("code", "JavaScript 代码"), "mjs": ("code", "JavaScript 模块"),
    "cjs": ("code", "JavaScript 模块"), "ts": ("code", "TypeScript 代码"),
    "tsx": ("code", "TypeScript React 代码"), "jsx": ("code", "React 代码"),
    "vue": ("code", "Vue 单文件组件"), "html": ("code", "网页文件"), "htm": ("code", "网页文件"),
    "css": ("code", "样式表"), "less": ("code", "样式源文件"), "scss": ("code", "样式源文件"),
    "c": ("code", "C 源代码"), "cpp": ("code", "C++ 源代码"), "h": ("code", "C/C++ 头文件"),
    "hpp": ("code", "C++ 头文件"), "cs": ("code", "C# 源代码"),
    "go": ("code", "Go 源代码"), "rs": ("code", "Rust 源代码"),
    "php": ("code", "PHP 源代码"), "kt": ("code", "Kotlin 源代码"),
    "rb": ("code", "Ruby 源代码"), "scala": ("code", "Scala 源代码"),
    "swift": ("code", "Swift 源代码"), "ipynb": ("code", "Jupyter 笔记本"),
    "json": ("cfg", "JSON 数据/配置文件"), "xml": ("cfg", "XML 配置/数据文件"),
    "yml": ("cfg", "YAML 配置文件"), "yaml": ("cfg", "YAML 配置文件"),
    "toml": ("cfg", "TOML 配置文件"), "ini": ("cfg", "INI 配置文件"),
    "conf": ("cfg", "配置文件"), "properties": ("cfg", "Java 属性配置文件"),
    "sql": ("data", "SQL 脚本"), "db": ("data", "数据库文件"),
    "sqlite": ("data", "SQLite 数据库文件"), "dat": ("data", "数据文件"),
    "log": ("data", "日志文件"), "bak": ("data", "备份文件"),
    "dll": ("exe", "动态链接库"), "sys": ("sys", "系统驱动文件"),
    "lnk": ("sys", "快捷方式"), "ttf": ("other", "字体文件"), "otf": ("other", "字体文件"),
    "woff": ("other", "网页字体"), "woff2": ("other", "网页字体"),
    "torrent": ("data", "BT 种子文件"), "sln": ("code", "Visual Studio 解决方案"),
    "csproj": ("code", "C# 项目文件"), "iml": ("cfg", "IDEA 模块文件"),
    "gradle": ("code", "Gradle 构建脚本"),
    "pem": ("sensitive", "证书/密钥文件（未读取内容）"),
    "key": ("sensitive", "密钥文件（未读取内容）"),
    "pfx": ("sensitive", "证书文件（未读取内容）"),
    "p12": ("sensitive", "证书文件（未读取内容）"),
    "jks": ("sensitive", "Java 密钥库（未读取内容）"),
    "keystore": ("sensitive", "Java 签名密钥库（未读取内容）"),
    "kdbx": ("sensitive", "密码管理器数据库（未读取内容）"),
    "ppk": ("sensitive", "PuTTY 私钥（未读取内容）"),
    "blf": ("sys", "注册表事务日志（系统文件）"),
    "regtrans-ms": ("sys", "注册表事务日志（系统文件）"),
    "vhdx": ("data", "虚拟硬盘文件（WSL/虚拟机/备份用）"),
    "vhd": ("data", "虚拟硬盘文件"),
    "ova": ("data", "虚拟机导出包"),
    "ovf": ("data", "虚拟机描述文件"),
    "sqlite3": ("data", "SQLite 数据库文件"),
}

CODE_EXTS = {"java", "py", "js", "mjs", "cjs", "ts", "tsx", "jsx", "vue", "go", "rs",
             "c", "cpp", "h", "hpp", "cs", "php", "kt", "swift", "rb", "scala", "ipynb"}

SENS_PATTERNS = [
    re.compile(r"^\.env(\.|$)"), re.compile(r"\.env$"),
    re.compile(r"^id_(rsa|dsa|ecdsa|ed25519)"),
    re.compile(r"access[_-]?key", re.I), re.compile(r"credential", re.I),
    re.compile(r"secret", re.I), re.compile(r"private[_-]?key", re.I),
    re.compile(r"\.git-credentials$"), re.compile(r"^\.netrc$"), re.compile(r"^\.npmrc$"),
    re.compile(r"^\.pypirc$"), re.compile(r"wallet\.dat$"),
    re.compile(r"^authorized_keys$"), re.compile(r"^\.htpasswd$"),
]

TYPE_ZH = {
    "maven": "Java 项目（Maven 构建）", "springboot": "Spring Boot 项目（Java）",
    "gradle": "Java/Kotlin 项目（Gradle 构建）", "nodejs": "Node.js 项目",
    "vue": "Vue 前端项目", "react": "React 前端项目", "electron": "Electron 桌面应用",
    "python": "Python 项目", "django": "Python 项目（Django 框架）",
    "rust": "Rust 项目", "go": "Go 项目", "dotnet": "C#/.NET 项目",
    "php": "PHP 项目", "gitrepo": "Git 仓库（未识别构建配置）", "static": "静态网页目录",
    "unknown": "待识别（疑似代码目录）",
}

CAT_LABELS = {
    "sys": "系统目录", "user": "个人目录", "devtool": "开发环境", "project": "开发项目",
    "deps": "依赖目录", "build": "构建产物", "git": "Git 版本库", "docs": "文档资料",
    "code": "代码", "media": "图片", "video": "视频", "audio": "音频",
    "archive": "压缩包", "exe": "程序/安装包", "data": "数据文件", "cfg": "配置文件",
    "sensitive": "疑似敏感", "cache": "缓存", "unknown": "用途待确认", "other": "其他",
}

GO_PKG_RE = re.compile(r"\\go\\pkg(\\|$)")


def ext_of(name):
    i = name.rfind(".")
    return name[i + 1:].lower() if i > 0 else ""


def is_sensitive_name(name):
    low = name.lower()
    if ext_of(name) in ("pem", "key", "pfx", "p12", "jks", "keystore", "kdbx", "ppk", "ovpn"):
        return True
    for p in SENS_PATTERNS:
        if p.search(low):
            return True
    return False


def zh_for_dir(name, low, in_proj):
    """返回 (中文说明, 类别, 置信度)；无法判断时返回 None"""
    if low in EXCLUDE_DIRS:
        return ZH_DIRS[low]
    if low in HEAVY_DIRS and low not in CONTEXT_HEAVY:
        z = HEAVY_DIRS[low]
        return (z[0], z[1], "高")
    if low in ZH_DIRS:
        return ZH_DIRS[low]
    if low.startswith("新建文件夹"):
        return ("新建文件夹（多为临时手动创建，建议人工确认内容）", "unknown", "低")
    if in_proj and low in CONTEXT_HEAVY:
        z = HEAVY_DIRS[low]
        return (z[0], z[1], "中")
    if in_proj and low in ("src", "main", "test", "tests", "docs", "lib", "app",
                           "components", "controller", "service", "mapper", "utils",
                           "resources", "static", "config"):
        z = ZH_DIRS.get(low)
        if z:
            return (z[0], z[1], "高")
    if GO_PKG_RE.search("\\" + low) or low == "pkg":
        z = HEAVY_DIRS["pkg"]
        return (z[0], z[1], "中")
    return None


def norm_name(n):
    s = re.sub(r"[\s_\-\.（）()【】\[\]]+", "", n.lower())
    while s:
        s2 = re.sub(r"(v?\d+[\d\._]*)$", "", s)
        s2 = re.sub(r"(副本|复制|备份|backup|bak|old|new|final|test|demo|copy|旧版|新版|旧|新)$", "", s2)
        if s2 == s or not s2:
            break
        s = s2
    return s or n.lower()
