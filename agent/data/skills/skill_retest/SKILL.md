---
name: skill_retest
title: 复测与闭环
purpose: 复检历史问题并把复测结果回写闭环状态。
when: 用户说「复测一下」「修好了吗」「再看看那几个问题」时用。
tools: page_diff,sensitive_file_probe,dir_probe,nuclei_scan
---

# 复测与闭环

判据:
- 只取未闭环的发现,用与首次相同的判据,不放宽也不收紧。
- 原判据仍命中 = 未修复;不再命中且站点正常 = 已修复;站点下线/大改版 = 判不了(unknown)。
- 复测结论是权威:说修好了就推进到 retest_passed。
- 没有历史发现就直说,不要硬造一条来复测。