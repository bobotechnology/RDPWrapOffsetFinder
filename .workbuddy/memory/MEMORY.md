# RDPWrapOffsetFinder 项目记忆

## 项目概述
Windows 逆向工程工具，分析 termsrv.dll 为 RDPWrap 自动定位补丁偏移并生成 rdpwrap.ini 配置节。

## 技术栈
- Python 3.9+, pefile, iced-x86 (x86/x64 指令解码)
- 两种分析模式: symbol-based (PDB) 和 heuristic (无符号)
- 依赖 Windows DbgHelp API (symbol 模式)
- tkinter GUI 无需额外依赖

## 关键架构决策 (2026-06-22)
- `nosymbol.py` 用 ArchStrategy 协议统一 x86/x64 路径（nosymbol_arch.py）
- PDB 下载模块命名为 `ms_pdb.py`（避免与 stdlib pdb 冲突）
- 测试用 iced-x86 Encoder（非 BlockEncoder）强制 rel32 编码
- 测试 venv: `~/.workbuddy/binaries/python/envs/default`
- `build_exe.py` 同时构建 console 和 GUI 两个单文件 exe

## 文件结构
- `termsrv.py`: 顶层编排（PE 加载 → 版本 → symbol/nosymbol → 格式化）
- `nosymbol.py` + `nosymbol_arch.py`: 无符号启发式分析
- `symbols.py`: 基于 PDB 符号的分析
- `patches.py`: 补丁模式匹配引擎 (LocalOnly/SingleUser/DefPolicy)
- `ms_pdb.py`: PDB 下载（重试+续传+校验）
- `tests/`: 55 个单元测试
- `gui.py`: tkinter GUI 入口
- `build_exe.py`: PyInstaller 构建脚本（console + GUI）
