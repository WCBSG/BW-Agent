# -*- coding: utf-8 -*-
r"""
关卡注册表
==================================================================

每个关卡是 `levels/` 下的一个模块，对外只需暴露一个 `LEVEL` 字典：

    LEVEL = {
        "id":         1,                  # 序号（决定门户上的排列顺序）
        "key":        "l1",               # URL 前缀：/l1/...
        "name":       "公开的秘密",        # 关卡名
        "difficulty": "★☆☆☆☆",
        "summary":    "一句话说明这一关考什么难度层次",
        "hints":      "给测试者的提示（不剧透具体答案）",
        "tags":       ["敏感信息", ...],   # 考点分类
        "banner":     "Apache/2.4.29",    # 伪造的 Server 响应头
        "headers":    {...},              # 附加到本关所有响应的响应头
        "methods":    ("GET", "HEAD"),    # 允许的 HTTP 方法
        "autoindex":  True,               # 是否开启目录列表
        "assets":     "l1",               # 静态文件目录：static/l1/
        "routes":     [(方法, 正则, 处理函数), ...],
        "not_found":  函数,                # 可选：自定义 404（软 404 用）
        "dir_locked": 函数,                # 可选：目录列表被关了，但满足条件可解锁
        "handle":     函数,                # 可选：完全接管请求
    }

核心（`serve.py`）的匹配顺序是：

    方法白名单 → handle() → routes() → 静态文件 → not_found()

所以一个关卡只要不写 `routes`，就退化成一个纯静态站点；
写得越多，行为越"像真的"。
==================================================================
"""

import importlib
import sys

# 关卡模块清单。加新关卡只需要在这里加一行 + 建一个模块。
_MODULES = (
    "levels.l0_denied",     # L0 未授权站点    —— 禁区：不应被扫描（授权闸门）
    "levels.l1_open",       # L1 公开的秘密      —— 一切都摆在明面上
    "levels.l2_hidden",     # L2 藏与找          —— 需要翻目录、看源码
    "levels.l3_evasive",    # L3 抗侦察          —— 专门对抗自动化扫描器
    "levels.l4_logic",      # L4 逻辑门          —— 需要构造请求才能看到
    "levels.l5_forensic",   # L5 取证            —— 微痕迹，得靠比对和拼接
    "levels.l6_chain",      # L6 链路            —— 多步串联才能到终点
)


def _build():
    registry = {}
    for name in _MODULES:
        module = importlib.import_module(name)
        level = dict(module.LEVEL)
        level.setdefault("key", name.rsplit(".", 1)[-1])
        level.pop("key_override", None)
        registry[level["key"]] = level
    return dict(sorted(registry.items(), key=lambda kv: kv[1]["id"]))


REGISTRY = _build()


def all_keys():
    """当前已加载的关卡 key（供 --only 报错时提示）。"""
    return list(REGISTRY.keys())


def get(key):
    return REGISTRY.get((key or "").lower())


# 供 `py serve.py --port x` 之外的程序化调用
__all__ = ["REGISTRY", "all_keys", "get"]
