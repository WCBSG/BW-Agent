// 从 WebView2 SDK 头里抽出"只用到的那几个接口",生成 src/webview2_min.h
// 为什么抽:整个 WebView2.h 有 2.9MB、上百个接口,编进项目既慢又看不出用了什么;
// 但接口的方法顺序不能手抄(抄错一个虚表位就是崩溃),所以按原文整块搬,
// 再把"这些接口签名里提到、但没搬的类型"补成前置声明 / 枚举定义。
const fs = require('fs');
const src = process.argv[2];
const out = process.argv[3];
const text = fs.readFileSync(src, 'utf8');

const want = [
  'ICoreWebView2Environment',
  'ICoreWebView2Controller',
  'ICoreWebView2Settings',
  'ICoreWebView2',
  'ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler',
  'ICoreWebView2CreateCoreWebView2ControllerCompletedHandler',
  'ICoreWebView2NewWindowRequestedEventArgs',
  'ICoreWebView2NewWindowRequestedEventHandler',
  'ICoreWebView2EnvironmentOptions',
];
const wantEnums = [
  'COREWEBVIEW2_WEB_ERROR_STATUS',
  'COREWEBVIEW2_MOVE_FOCUS_REASON',
  'COREWEBVIEW2_MOUSE_EVENT_KIND',
  'COREWEBVIEW2_MOUSE_EVENT_VIRTUAL_KEYS',
];

/* 从 name 那一行往上找最近的 MIDL_INTERFACE("..."),一起带走 ——
   那一行是 __declspec(uuid(...)) 的来源,去掉它接口就没声明了。 */
function iface(name) {
  const re = new RegExp('^[ \\t]*' + name + ' : public IUnknown[ \\t]*$\\s*\\{', 'm');
  const m = re.exec(text);
  if (!m) throw new Error('找不到接口 ' + name);
  const before = text.slice(0, m.index);
  const midl = /MIDL_INTERFACE\("[^"]+"\)[ \t]*\r?\n[ \t]*$/.exec(before);
  if (!midl) throw new Error('接口 ' + name + ' 前没有 MIDL_INTERFACE');
  const start = m.index - midl[0].length;
  let i = m.index + m[0].length;
  let depth = 1;
  for (; i < text.length && depth > 0; i++) {
    if (text[i] === '{') depth++;
    else if (text[i] === '}') depth--;
  }
  let end = i;
  if (text[end] === ';') end++;
  return text.slice(start, end);
}

function enumBlock(name) {
  const re = new RegExp('typedef[^\\n]*\\n[ \\t]*enum ' + name + '\\s*\\{', 'm');
  const m = re.exec(text);
  if (!m) throw new Error('找不到枚举 ' + name);
  const start = m.index;
  let i = m.index + m[0].length;
  let depth = 1;
  for (; i < text.length && depth > 0; i++) {
    if (text[i] === '{') depth++;
    else if (text[i] === '}') depth--;
  }
  let end = i;
  while (end < text.length && text[end] !== ';') end++;
  return text.slice(start, end + 1);
}

const bodies = want.map(iface);

const mentioned = new Set();
for (const b of bodies) {
  const re = /\b(ICoreWebView2\w*|COREWEBVIEW2_\w+)\b/g;
  let m;
  while ((m = re.exec(b))) mentioned.add(m[1]);
}
const fwd = [];
const enums = [];
for (const name of mentioned) {
  if (/^COREWEBVIEW2_/.test(name)) {
    if (enums.some((e) => e.name === name)) continue;
    try { enums.push({ name, body: enumBlock(name) }); } catch (e) { /* 有的只是 typedef 别名 */ }
    continue;
  }
  if (fwd.some((f) => f.name === name)) continue;
  if (!new RegExp('^[ \\t]*' + name + ' : public IUnknown', 'm').test(text)) continue;
  fwd.push({ name, decl: `struct ${name};` });
}

const header = `/* webview2_min.h —— WebView2 里"我们真正用到的那几个接口"。
 *
 * 为什么不全量引入 WebView2.h(2.9MB、上百个接口):
 *   编译慢、看不出用了什么;而这些接口绝大多数我们不碰。
 *   但**方法顺序绝对不能手抄** —— 抄错一个虚表位就是崩溃,所以下面这些
 *   接口体是从官方 SDK(1.0.4258.31)的 WebView2.h 里整块搬来的。
 *
 * 运行时不需要链接任何库:WebView2Loader.dll 作为资源编进 exe,
 * 启动时释放到数据目录再 LoadLibrary + GetProcAddress(见 webview.cpp)。
 * 因此"交付一个 exe"仍然成立;只是这台机器要装 WebView2 运行时
 * (Win10/11 随 Edge 自带,极少数精简系统需要单独装一次)。
 */
#ifndef AGENT_WEBVIEW2_MIN_H
#define AGENT_WEBVIEW2_MIN_H

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <objbase.h>

/* 官方头里由 midl 生成,这里给一个同义的定义 */
#ifndef MIDL_INTERFACE
#define MIDL_INTERFACE(x) struct __declspec(uuid(x)) __declspec(novtable)
#endif

typedef struct EventRegistrationToken { LONGLONG value; } EventRegistrationToken;

/* 下面这些只在方法签名里出现(指针),前置声明就够 */
${fwd.map((f) => f.decl).join('\n')}

${enums.map((e) => e.body).join('\n\n')}

${bodies.join('\n\n')}

#endif /* AGENT_WEBVIEW2_MIN_H */
`;

fs.writeFileSync(out, header, 'utf8');
console.log('wrote', out, header.length, 'bytes', '前声明', fwd.length, '枚举', enums.length);

