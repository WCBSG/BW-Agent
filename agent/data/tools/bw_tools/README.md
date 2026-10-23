# bw_tools.exe

内置工具的统一宿主:一个 exe 承载全部 15 个工具,按调用请求里的 `tool` 字段分派。

- 构建时生成(`agent\build.bat`),并从 exe 资源释放到这里(首次运行)
- 协议见 `docs/工具协议.md`:stdin 收 `{"tool","args","context"}`,stdout 回 `{"text","say","data","is_error"}`
- 单独试一个工具:

```powershell
.\bw_tools.exe fs_read '{"path":"rules/detect.json","startline":0,"endline":5}'
.\bw_tools.exe --list
```
