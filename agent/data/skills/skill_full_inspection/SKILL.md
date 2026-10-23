---
name: skill_full_inspection
title: 全流程巡检
purpose: 完成授权站点的全流程风险体检并归拢结论。
when: 用户说「整体看看」「跑一遍巡检」「做个安全体检」时用;顺序自定,目标不可达就停并如实说明。
tools: site_crawl,page_diff,sensitive_file_probe,dir_probe,nuclei_scan
---

# 全流程巡检

判据:
- 执行顺序由实现决定(摸底→比对→敏感文件→目录→模板),不用你排。
- 只有内容里确有敏感特征才算泄露;403/404/登录页都不算。
- 同类问题合并成一条,不同路径写进证据。
- 目标不可达、被 WAF 拦、内容与预期不符 → 如实写"未验成",不要猜。