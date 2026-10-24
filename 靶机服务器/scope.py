#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
授权范围判定（可配置的扫描区域）
==================================================================

══════════════════════════════════════════════════════════════════
这个模块解决什么问题？
══════════════════════════════════════════════════════════════════

赛题要求①明确写着：**支持录入授权域名、巡检范围**。

"巡检范围可配置"这句话听起来像个配置项，其实它是一道**合规闸门**：

    巡检工具一旦发错请求，造成的后果是不可逆的 ——
    你没有权限的站点被扫了，那就是一起安全事件，不是一次失误。

所以本模块的定位不是"给个配置读一读"，而是：
**把"该不该发这个请求"变成一个必须先回答的问题。**

══════════════════════════════════════════════════════════════════
关键设计：白名单，且默认拒绝
══════════════════════════════════════════════════════════════════

本模块用**白名单模型**，判定顺序是：

    ① 命中「排除范围」            → 拒绝（排除优先，一票否决）
    ② 同时命中「授权范围」的域+路径 → 放行
    ③ 其它一切                    → 拒绝（默认拒绝）

为什么不是黑名单（"配了禁止的才不扫，其它都扫"）？

    白名单漏配一个目标 → 该扫的没扫  → 后果：漏报，可补救
    黑名单漏配一个目标 → 不该扫的扫了 → 后果：越权，不可逆

**风险不对称，所以默认值必须选"拒绝"。**
这条推理在任何"要不要对别人系统做动作"的场景里都成立。

══════════════════════════════════════════════════════════════════
一个容易写错的地方：路径前缀匹配
══════════════════════════════════════════════════════════════════

天真的写法是 `path.startswith("/l1")`，但它会放行 `/l10/`：

    "/l1"      ⊆ startswith "/l1"  → ✓ 正确
    "/l1/"     ⊆ startswith "/l1"  → ✓ 正确
    "/l10/"    ⊆ startswith "/l1"  → ✓ **错误放行！**

所以这里做**按路径段**匹配：要么完全相同，要么下一个字符必须是 `/`。
这类 bug 在授权校验里特别危险 —— 它悄悄扩大了你被允许触碰的范围。

══════════════════════════════════════════════════════════════════
用法
══════════════════════════════════════════════════════════════════

    # 命令行检查一个 URL
    py scope.py --check http://127.0.0.1:8081/l0/
    py scope.py --check http://127.0.0.1:8081/l1/news.html

    # 看当前授权配置
    py scope.py --show

    # 程序里用
    from scope import check_url
    verdict = check_url("http://127.0.0.1:8081/l0/")
    if not verdict.allowed:
        raise PermissionError(verdict.reason)
==================================================================
"""

import argparse
import json
import sys
import urllib.parse
from dataclasses import dataclass
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DEFAULT_SCOPE = BASE_DIR / "scope.json"


# ------------------------------------------------------------------
# 数据结构
# ------------------------------------------------------------------

@dataclass
class Verdict:
    """一次授权判定的结果。"""

    allowed: bool
    reason: str
    rule: str = ""              # 命中的规则（便于写进日志做证据）
    stage: str = ""             # 在哪个判定阶段得出的结论

    def __bool__(self):
        # 让 `if not check_url(url):` 这种写法也能工作
        return self.allowed

    def describe(self):
        mark = "放行" if self.allowed else "拒绝"
        return f"[{mark}] {self.reason}"


class ScopeConfigError(Exception):
    """授权配置本身有问题（结构不对、文件缺失等）。"""


# ------------------------------------------------------------------
# 路径匹配
# ------------------------------------------------------------------

def normalize_path(path):
    """
    把 URL 路径规整成便于比较的形式：
      · 空 → "/"
      · 保证以 / 开头
      · 折叠重复斜杠
      · 去掉末尾斜杠（根路径除外）
    """
    path = urllib.parse.unquote(path or "/")
    while "//" in path:
        path = path.replace("//", "/")
    if not path.startswith("/"):
        path = "/" + path
    if len(path) > 1:
        path = path.rstrip("/")
    return path or "/"


def path_in_prefix(path, prefix):
    """
    判断 path 是否落在 prefix 这个"路径目录"之下。

    ★ 必须按路径段比较，不能用 startswith。
      否则 prefix="/l1" 会错误放行 "/l10/" —— 授权范围被悄悄放大。

        path_in_prefix("/l1",       "/l1")  → True
        path_in_prefix("/l1/",      "/l1")  → True
        path_in_prefix("/l1/news",  "/l1")  → True
        path_in_prefix("/l10/",     "/l1")  → False   ← 关键
        path_in_prefix("/l1abc",    "/l1")  → False   ← 关键
    """
    path = normalize_path(path)
    prefix = normalize_path(prefix)

    if prefix == "/":
        return True                       # 空前缀 = 整站
    if path == prefix:
        return True
    return path.startswith(prefix + "/")


def host_matches(host, pattern):
    """
    域名匹配。支持两种写法：
        "127.0.0.1:8081"   精确匹配 host[:port]
        "*.zwfw.gov.cn"    通配子域（不匹配裸域）

    大小写不敏感 —— DNS 本身如此。
    """
    host = (host or "").lower().strip()
    pattern = (pattern or "").lower().strip()
    if not pattern:
        return False
    if pattern.startswith("*."):
        suffix = pattern[1:]                       # ".zwfw.gov.cn"
        return host.endswith(suffix) and len(host) > len(suffix)
    return host == pattern


# ------------------------------------------------------------------
# 配置加载
# ------------------------------------------------------------------

def load_scope(path=None):
    """读授权范围配置。文件缺失或格式错误都直接报错 —— 宁可不扫，不能乱扫。"""
    path = Path(path) if path else DEFAULT_SCOPE
    if not path.is_file():
        raise ScopeConfigError(
            f"找不到授权范围配置：{path}\n"
            f"          没有授权范围就不允许扫描（这是刻意的默认值）。"
        )
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ScopeConfigError(f"授权范围配置不是合法 JSON：{exc}") from exc

    if not isinstance(data, dict):
        raise ScopeConfigError("授权范围配置的顶层结构必须是对象")
    if "授权范围" not in data:
        raise ScopeConfigError("授权范围配置缺少「授权范围」字段")

    return data


# ------------------------------------------------------------------
# 判定
# ------------------------------------------------------------------

def check_url(url, scope=None, config_path=None):
    """
    判定一个 URL 是否在授权范围内。

    返回 Verdict。**绝不抛异常来表示"拒绝"** ——
    判定失败（配置坏了）才抛异常，因为那时我们连"能不能扫"都不知道，
    必须停下来而不是猜。
    """
    scope = scope if scope is not None else load_scope(config_path)

    parsed = urllib.parse.urlsplit(url)
    host = parsed.netloc or parsed.path.split("/")[0]
    raw_path = parsed.path
    # 如果传进来的是裸路径（没 scheme/netloc），当作路径处理
    if not parsed.netloc:
        host = ""
        raw_path = url
    path = normalize_path(raw_path)

    scope_cfg = scope.get("授权范围") or []
    exclude_cfg = scope.get("排除范围") or []

    # ---- ① 排除范围优先：一票否决 ----
    for rule in exclude_cfg:
        for prefix in (rule.get("路径") or []):
            if path_in_prefix(path, prefix):
                return Verdict(
                    allowed=False,
                    reason=f"命中排除范围 {prefix}：{rule.get('说明', '')}",
                    rule=f"排除范围:{prefix}",
                    stage="排除",
                )

    # ---- ② 授权范围：域 + 路径都要命中 ----
    for rule in scope_cfg:
        domain = rule.get("域", "")
        if not host_matches(host, domain):
            continue
        for prefix in (rule.get("路径") or ["/"]):
            if path_in_prefix(path, prefix):
                return Verdict(
                    allowed=True,
                    reason=f"命中授权范围 {domain}{prefix}",
                    rule=f"授权范围:{domain}{prefix}",
                    stage="授权",
                )
        # 域对了但路径不在授权列表里 → 继续看别的规则
        return Verdict(
            allowed=False,
            reason=(f"域名 {domain} 已授权，但路径 {path} 不在该域的授权路径列表内"
                    f"（已授权路径：{', '.join(rule.get('路径') or [])}）"),
            rule=f"授权范围:{domain}",
            stage="路径",
        )

    # ---- ③ 默认拒绝 ----
    return Verdict(
        allowed=False,
        reason=f"目标 {host or '(无域名)'}{path} 未出现在授权范围中，默认拒绝",
        rule="默认拒绝",
        stage="默认",
    )


# ------------------------------------------------------------------
# 越界记录
# ------------------------------------------------------------------

def log_violation(url, verdict, log_path=None, client=""):
    """
    把越界访问记到独立日志。

    为什么单独一个文件而不是混在 access.log 里？
    因为它的用途不同：access.log 是"谁访问了什么"的运行记录，
    out-of-scope.log 是**合规证据** ——
    出问题时需要能立刻回答"我们到底碰过哪些没授权的东西"。
    """
    import datetime
    log_path = Path(log_path) if log_path else (BASE_DIR / "logs" / "out-of-scope.log")
    log_path.parent.mkdir(parents=True, exist_ok=True)
    entry = {
        "ts": datetime.datetime.now().isoformat(timespec="seconds"),
        "url": url,
        "client": client,
        "rule": verdict.rule,
        "stage": verdict.stage,
        "reason": verdict.reason,
    }
    with log_path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
    return log_path


# ------------------------------------------------------------------
# 命令行
# ------------------------------------------------------------------

def show(scope):
    """打印当前授权配置的可读摘要。"""
    auth = scope.get("授权登记") or {}
    print()
    print("  授权登记")
    print("  " + "-" * 66)
    for key in ("单位", "确认人", "联系方式", "授权时间", "授权凭证", "有效期"):
        if auth.get(key):
            print(f"    {key:<6}：{auth[key]}")

    print()
    print("  授权范围（白名单，只有这里列出的才允许扫描）")
    print("  " + "-" * 66)
    for rule in scope.get("授权范围") or []:
        paths = ", ".join(rule.get("路径") or ["/"])
        print(f"    {rule.get('域', ''):<24} {paths}")
        if rule.get("说明"):
            print(f"      └─ {rule['说明']}")

    exclude = scope.get("排除范围") or []
    print()
    print("  排除范围（一票否决，优先级最高）")
    print("  " + "-" * 66)
    if not exclude:
        print("    （无）")
    for rule in exclude:
        paths = ", ".join(rule.get("路径") or [])
        print(f"    {paths}")
        if rule.get("说明"):
            print(f"      └─ {rule['说明']}")

    policy = scope.get("策略") or {}
    print()
    print("  策略")
    print("  " + "-" * 66)
    for key, value in policy.items():
        if key != "说明":
            print(f"    {key:<14}：{value}")
    if policy.get("说明"):
        print()
        print("    " + policy["说明"])
    print()


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="授权范围判定",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="示例：\n"
               "  py scope.py --show\n"
               "  py scope.py --check http://127.0.0.1:8081/l1/\n"
               "  py scope.py --check http://127.0.0.1:8081/l0/\n"
               "  py scope.py --check /l0/files/db.sql\n",
    )
    ap.add_argument("--check", metavar="URL", help="判定一个 URL 是否在授权范围内")
    ap.add_argument("--show", action="store_true", help="显示当前授权配置")
    ap.add_argument("--config", help="指定授权范围配置文件（默认 scope.json）")
    ap.add_argument("--batch", nargs="+", metavar="URL",
                    help="批量判定多个 URL")
    args = ap.parse_args(argv)

    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

    try:
        scope = load_scope(args.config)
    except ScopeConfigError as exc:
        print(f"\n  [错误] {exc}\n")
        return 2

    if args.show or (not args.check and not args.batch):
        show(scope)
        return 0

    targets = []
    if args.check:
        targets.append(args.check)
    if args.batch:
        targets.extend(args.batch)

    print()
    print("  授权判定结果")
    print("  " + "-" * 66)
    denied = 0
    for url in targets:
        verdict = check_url(url, scope)
        if not verdict.allowed:
            denied += 1
        mark = "✓ 放行" if verdict.allowed else "✗ 拒绝"
        print(f"    {mark}  {url}")
        print(f"          {verdict.reason}")
        if verdict.rule:
            print(f"          命中规则：{verdict.rule}（{verdict.stage}阶段）")
    print("  " + "-" * 66)
    print(f"  共 {len(targets)} 个目标：放行 {len(targets) - denied}，拒绝 {denied}")
    print()
    return 1 if denied == len(targets) and targets else 0


if __name__ == "__main__":
    sys.exit(main())
