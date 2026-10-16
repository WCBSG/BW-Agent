/* app.js —— 界面层：把智能体的决策循环直播成"看得见的过程"，并把闭环数据摊开展示。
 *
 * 与后端只通过 HTTP + SSE 说话，事件协议就是三册合同里的六个事件
 * (message_start / block_start / block_delta / block_stop / tool_status / message_stop)，
 * 前端不认识任何"巡检业务细节" —— 后端换实现，这里一行都不用改。
 *
 * 数据视图（报告/历史/资产/评测/规则）全部走只读接口：
 *   /api/status · /api/manifest · /api/rules · /api/data?name=集合&limit=N
 * 只画后端真正落过盘的东西，没有的就说"还没有"，不编占位数字。
 */
'use strict';

const $ = (id) => document.getElementById(id);
const stream = $('stream');
const trace = $('trace');
const stepsBox = $('steps');

const SEV_ORDER = ['严重', '高', '中', '低', '信息'];
const KIND_COLOR = {
  '漏洞': '#ff4d4f', '弱配置': '#f5c451', '挂马': '#ff8a3d',
  '篡改': '#ff8a3d', '敏感信息': '#ff5c8a',
};
const STATUS_LABEL = {
  new: '新发现', confirmed: '已确认', fixed: '已修复',
  retest_passed: '复测通过', retest_failed: '复测未通过', false_positive: '误报',
};
const RUN_STATUS_LABEL = { running: '进行中', done: '已完成', failed: '失败', canceled: '已取消', paused: '已暂停' };
const RESULT_LABEL = { passed: '通过', failed: '未修复', inconclusive: '判不了' };

let state = {
  status: null,
  manifest: null,
  view: 'loop',
  cache: {},          // 视图数据缓存
};

let current = null;   // 当前正在播的消息
let busy = false;

/* ============ 通用 ============ */

function el(tag, cls, text) {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined) n.textContent = text;
  return n;
}

function atBottom() {
  return stream.scrollHeight - stream.scrollTop - stream.clientHeight < 80;
}
function scrollBottom(force) {
  if (force || atBottom()) stream.scrollTop = stream.scrollHeight;
}

/* 接口令牌:由后端在发送 index.html 时注入 meta —— 用来挡住"别的网页借我们的手扫别人" */
const BW_TOKEN = (document.querySelector('meta[name="bw-token"]') || {}).content || '';

async function api(path, opts) {
  const o = Object.assign({}, opts);
  o.headers = Object.assign({ 'X-BW-Token': BW_TOKEN }, (opts && opts.headers) || {});
  const r = await fetch(path, o);
  const j = await r.json().catch(() => null);
  if (!r.ok) throw new Error((j && j.error) || ('HTTP ' + r.status));
  return j;
}

function fmtTime(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  if (isNaN(d.getTime())) return iso;
  const p = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

function sevBadge(sev) {
  const s = el('span', 'sev', sev || '信息');
  s.style.background = `var(--sev-${sev || '信息'}, #8b98ad)`;
  return s;
}

function statusChip(status) {
  const key = status || 'new';
  return el('span', 'chip st-' + key, STATUS_LABEL[key] || key);
}

function kv(label, value, cls) {
  const d = el('div', cls || 'cm');
  d.textContent = label + '：' + (value === undefined || value === null || value === '' ? '—' : value);
  return d;
}

function emptyCard(text) {
  return el('div', 'card muted', text);
}

function bars(container, dict, colorFn) {
  container.innerHTML = '';
  const entries = Object.entries(dict || {});
  if (!entries.length) {
    container.appendChild(el('div', 'muted', '（无）'));
    return;
  }
  const max = Math.max(...entries.map(([, v]) => Number(v) || 0), 1);
  for (const [k, v] of entries) {
    const row = el('div', 'bar');
    row.appendChild(el('div', 'bl', k));
    const t = el('div', 'bt');
    const f = el('div', 'bf');
    f.style.width = Math.round(((Number(v) || 0) / max) * 100) + '%';
    f.style.background = colorFn ? colorFn(k) : 'var(--accent)';
    t.appendChild(f);
    row.appendChild(t);
    row.appendChild(el('div', 'bn', String(v)));
    container.appendChild(row);
  }
}

/* ============ 头部与状态 ============ */

function renderStatus(s) {
  state.status = s;
  $('subtitle').textContent =
    `会话 ${s.sessionId} · 任务 ${s.taskId} · 工具 ${s.tools} 个 / 技能 ${s.skills} 个 · 步数上限 ${s.maxSteps}`;

  const pm = $('pill-model');
  pm.textContent = '模型 · ' + s.modelName;
  pm.className = 'pill ' + (s.model ? 'on' : 'off');

  const ps = $('pill-scope');
  ps.textContent = '授权 · ' + (s.authorized ? s.domain : '未设置');
  ps.className = 'pill ' + (s.authorized ? 'on' : 'off');

  const pc = $('pill-count');
  const n = s.findingCount !== undefined ? s.findingCount : (s.findings || []).length;
  pc.textContent = '发现 · ' + n;
  pc.className = 'pill ' + (n > 0 ? 'on' : '');

  $('scope-domain').value = s.authorized ? s.domain : '';
  $('scope-ok').checked = !!s.authorized;
}

function renderManifest(m) {
  state.manifest = m;
  $('cap-count').textContent = `${(m.skills || []).length} 技能 / ${(m.tools || []).length} 工具`;
  const fill = (pane, list, isSkill) => {
    pane.innerHTML = '';
    for (const x of list || []) {
      const d = el('div', 'cap');
      d.appendChild(el('div', 'n', x.name + (x.title ? '（' + x.title + '）' : '')));
      d.appendChild(el('div', 'd', x.description || x.purpose || ''));
      const meta = [];
      if (x.when) meta.push('何时用：' + x.when);
      if (x.purpose) meta.push('解决什么：' + x.purpose);
      if (x.tools) meta.push('用到：' + x.tools);
      if (x.kind) meta.push('类型：' + x.kind);
      if (x.multi_step) meta.push('可多步');
      if (x.source_url) meta.push(x.source_url);
      if (meta.length) d.appendChild(el('div', 'k', meta.join(' · ')));
      void isSkill;
      pane.appendChild(d);
    }
    if (!(list || []).length) pane.appendChild(el('div', 'muted', '（空）'));
  };
  fill($('pane-skills'), m.skills, true);
  fill($('pane-tools'), m.tools, false);
}

/* ============ 事件流渲染 ============ */

function beginMessage(messageId) {
  if ($('stream-empty')) $('stream-empty').remove();
  const wrap = el('div', 'msg agent');
  wrap.appendChild(el('div', 'who', '智能体 · ' + messageId));
  const body = el('div', 'body');
  wrap.appendChild(body);
  stream.appendChild(wrap);
  scrollBottom(true);

  current = {
    id: messageId,
    body,
    blocks: {},
    tools: {},
    steps: 0,
    stopReason: '',
    startedAt: Date.now(),
  };
}

function getBlock(index) {
  return (current && current.blocks[index]) || null;
}

function onBlockStart(e) {
  if (!current) beginMessage(e.messageId);
  if (e.blockType === 'tool_use') {
    const card = el('div', 'tool');
    const head = el('div', 'tool-head');
    const dot = el('span', 'dot running');
    head.appendChild(dot);
    head.appendChild(el('span', 'tool-name', e.toolName || '?'));
    const note = el('span', 'tool-note', '已决定调用');
    head.appendChild(note);
    card.appendChild(head);
    const args = el('div', 'tool-args hidden');
    card.appendChild(args);
    const out = el('div', 'tool-out hidden');
    card.appendChild(out);
    current.body.appendChild(card);
    current.blocks[e.index] = { kind: 'tool_use', node: card, dot, note, args, out, name: e.toolName };
    if (e.toolUseId) current.tools[e.toolUseId] = current.blocks[e.index];
    current.steps++;
    scrollBottom();
  } else {
    const n = el('div');
    current.body.appendChild(n);
    current.blocks[e.index] = { kind: 'text', node: n, text: '' };
  }
}

function onBlockDelta(e) {
  const b = getBlock(e.index);
  if (!b || !e.delta) return;
  if (e.delta.type === 'text_delta') {
    b.text = (b.text || '') + e.delta.text;
    b.node.textContent = b.text;
    if (/^\[第 \d+ 步/.test(b.text.trim()) || /^\[需要你补充信息\]/.test(b.text.trim())) {
      trace.textContent = b.text;
    }
    scrollBottom();
  } else if (e.delta.type === 'input_json_delta') {
    b.args.textContent = e.delta.partialJson || '';
    if (e.delta.partialJson && e.delta.partialJson !== '{}') b.args.classList.remove('hidden');
  }
}

function onBlockStop(e) {
  const b = getBlock(e.index);
  if (!b) return;
  if (b.kind === 'tool_use') b.dot.className = 'dot ' + (b.dot.dataset.state || 'done');
}

function onToolStatus(e) {
  if (!current) return;
  const b = current.tools[e.toolUseId];
  if (!b) return;
  b.dot.className = 'dot ' + e.status;
  b.dot.dataset.state = e.status;
  if (e.note && e.status !== 'done') {
    b.note.textContent = e.note.split('\n')[0].slice(0, 120);
  }
  if (e.status === 'done' || e.status === 'error') {
    b.out.textContent = e.note || '(无输出)';
    b.out.classList.remove('hidden');
    b.note.textContent = (e.note || '').split('\n')[0].slice(0, 60) || '完成';
  }
  trace.textContent = (trace.textContent || '') + '\n' + (e.status === 'running' ? '→ ' : '✓ ') +
    e.toolUseId + ' [' + e.status + '] ' + (e.note || '').split('\n')[0].slice(0, 100);
  renderStepCard(e, b);
  scrollBottom();
}

/* 过程要点：把每一步的"为什么"留下来（评审最想看的是这个） */
function renderStepCard(e, block) {
  if (!stepsBox) return;
  if (stepsBox.querySelector('.muted')) stepsBox.innerHTML = '';
  let card = stepsBox.querySelector(`[data-tuid="${e.toolUseId}"]`);
  if (!card) {
    card = el('div', 'step' + (block && /^skill_/.test(block.name || '') ? ' skill' : ''));
    card.dataset.tuid = e.toolUseId;
    card.appendChild(el('div', 'sn', '第 ' + (current ? current.steps : '?') + ' 步'));
    card.appendChild(el('div', 'sa', (block && block.name) || e.toolName || '工具'));
    card.appendChild(el('div', 'sr', ''));
    stepsBox.appendChild(card);
    stepsBox.scrollTop = stepsBox.scrollHeight;
  }
  const r = card.lastChild;
  const line = (e.note || '').split('\n').filter(Boolean)[0] || e.status;
  r.textContent = e.status === 'running' ? '执行中…' : line.slice(0, 200);
}

function onMessageStop(e) {
  if (!current) return;
  current.stopReason = e.stopReason;
  const seconds = ((Date.now() - current.startedAt) / 1000).toFixed(1);
  const line = el('div', 'stopline');
  line.textContent = `消息结束 · 停止原因 ${e.stopReason} · 调用技能/工具 ${current.steps} 次 · 耗时 ${seconds}s`;
  current.body.appendChild(line);
  $('trace-hint').textContent = `${current.steps} 步 / ${seconds}s / ${e.stopReason}`;
  current = null;
  endTurn();
  scrollBottom(true);
}

/* ============ 一轮对话 ============ */

function setBusy(on) {
  busy = on;
  $('btn-send').disabled = on;
  $('btn-send').textContent = on ? '执行中…' : '执行';
  $('q').disabled = on;
}

function endTurn() {
  setBusy(false);
  state.cache = {};                    // 一轮结束：闭环数据可能变了,下次进视图重新取
  api('/api/status').then(renderStatus).catch(() => {});
}

function send(text) {
  const q = (text || '').trim();
  if (!q || busy) return;

  if ($('stream-empty')) $('stream-empty').remove();
  const wrap = el('div', 'msg user');
  wrap.appendChild(el('div', 'body', q));
  stream.appendChild(wrap);
  scrollBottom(true);

  $('q').value = '';
  $('q').style.height = 'auto';
  setBusy(true);
  trace.textContent = '';
  if (stepsBox) stepsBox.innerHTML = '<div class="muted">执行后这里按步列出「为什么这么做」。</div>';

  /* EventSource 不能自定义请求头,所以令牌走查询串 */
  const es = new EventSource('/api/chat?q=' + encodeURIComponent(q) +
                             (BW_TOKEN ? '&t=' + encodeURIComponent(BW_TOKEN) : ''));
  let closed = false;

  es.onmessage = (ev) => {
    let e;
    try { e = JSON.parse(ev.data); } catch { return; }
    switch (e.type) {
      case 'message_start': beginMessage(e.messageId); break;
      case 'block_start':   onBlockStart(e); break;
      case 'block_delta':   onBlockDelta(e); break;
      case 'block_stop':    onBlockStop(e); break;
      case 'tool_status':   onToolStatus(e); break;
      case 'message_stop':  onMessageStop(e); es.close(); closed = true; break;
    }
  };
  es.onerror = () => {
    es.close();
    if (closed) return;
    if (current) {
      current.body.appendChild(el('div', 'stopline', '连接中断 —— 后端可能已停止。'));
      current = null;
    }
    endTurn();
  };
}

/* ============ 数据视图 ============ */

async function fetchCollection(name, limit) {
  const key = name + ':' + limit;
  if (state.cache[key]) return state.cache[key];
  const r = await api(`/api/data?name=${encodeURIComponent(name)}&limit=${limit}`);
  state.cache[key] = r;
  return r;
}

async function renderReportView() {
  const box = $('findings-list');
  box.innerHTML = '';
  $('report-tiles').innerHTML = '';
  $('report-sev').innerHTML = '';
  $('report-kind').innerHTML = '';
  $('report-summary').textContent = '';
  $('report-hint').textContent = '';
  $('alerts-list').innerHTML = '';

  const [reports, findings, alerts] = await Promise.all([
    fetchCollection('reports', 1).catch(() => ({ items: [] })),
    fetchCollection('findings', 200).catch(() => ({ items: [] })),
    fetchCollection('alerts', 100).catch(() => ({ items: [] })),
  ]);

  const rep = (reports.items || [])[0];
  const fl = findings.items || [];

  // 统计块：优先用报告里的 ReportStats（它就是"报告的口径"），没有就现场数
  const sev = {}, kind = {};
  let fp = 0, open = 0;
  for (const f of fl) {
    sev[f.severity || '信息'] = (sev[f.severity || '信息'] || 0) + 1;
    kind[f.kind || '弱配置'] = (kind[f.kind || '弱配置'] || 0) + 1;
    if (f.status === 'false_positive') fp++;
    if (f.status !== 'false_positive' && f.status !== 'retest_passed') open++;
  }
  const stats = (rep && rep.stats) || {
    total: fl.length, by_severity: sev, by_kind: kind, false_positive: fp, open,
  };

  const tiles = [
    { l: '发现总数', v: stats.total !== undefined ? stats.total : fl.length },
    { l: '待处理', v: stats.open !== undefined ? stats.open : open, cls: (stats.open || open) ? 'warn' : 'ok' },
    { l: '误报', v: stats.false_positive !== undefined ? stats.false_positive : fp, cls: (stats.false_positive || fp) ? 'warn' : 'ok' },
    { l: '严重', v: (stats.by_severity || {})['严重'] || 0, cls: ((stats.by_severity || {})['严重'] || 0) ? 'bad' : 'ok' },
    { l: '高危', v: (stats.by_severity || {})['高'] || 0, cls: ((stats.by_severity || {})['高'] || 0) ? 'warn' : 'ok' },
    { l: '告警条数', v: (alerts.items || []).length || 0 },
  ];
  for (const t of tiles) {
    const d = el('div', 'tile ' + (t.cls || ''));
    d.appendChild(el('div', 'v', String(t.v === undefined ? 0 : t.v)));
    d.appendChild(el('div', 'l', t.l));
    $('report-tiles').appendChild(d);
  }

  if (rep) {
    $('report-hint').textContent = `${rep.id} · ${fmtTime(rep.generated_at)} · 规则来源 ${rep.rules_source || '—'}`;
    $('report-summary').textContent = rep.summary || '';
    $('report-summary').dataset.reportId = rep.id;
  } else {
    $('report-hint').textContent = '还没有生成报告';
    $('report-summary').textContent =
      '还没有报告：报告由「发现清单」汇总而来。先跑一次巡检，然后对智能体说「出报告」即可。';
  }

  bars($('report-sev'), stats.by_severity || sev, (k) => `var(--sev-${k}, #8b98ad)`);
  bars($('report-kind'), stats.by_kind || kind, (k) => KIND_COLOR[k] || 'var(--accent)');

  // 发现清单：按等级排序，把证据/影响/修复都摊出来（都是后端去敏过的）
  fl.sort((a, b) => SEV_ORDER.indexOf(a.severity || '信息') - SEV_ORDER.indexOf(b.severity || '信息'));
  $('findings-hint').textContent = fl.length ? `${fl.length} 条（按等级排序）` : '';
  if (!fl.length) box.appendChild(emptyCard('还没有落盘的发现。'));
  for (const f of fl) box.appendChild(findingCard(f));

  const al = alerts.items || [];
  const alertsBox = $('alerts-list');
  if (!al.length) alertsBox.appendChild(emptyCard('还没有推送过告警（严重/高危走邮件、中危走站内）。'));
  for (const a of al.slice().reverse()) {
    const c = el('div', 'card');
    const head = el('div', 'ch');
    head.appendChild(sevBadge(a.severity));
    head.appendChild(el('span', 'ct', a.title || a.finding_id || ''));
    const meta = el('div', 'side-meta');
    meta.appendChild(el('span', 'chip', a.channel || '站内'));
    meta.appendChild(el('span', 'chip st-' + (a.status === 'pending' ? 'new' : 'fixed'), a.status || 'pending'));
    head.appendChild(meta);
    c.appendChild(head);
    c.appendChild(kv('关联发现', a.finding_id, 'cm'));
    c.appendChild(kv('时间', fmtTime(a.created_at), 'cm'));
    if (a.note) c.appendChild(el('div', 'cd', a.note));
    alertsBox.appendChild(c);
  }
}

function findingCard(f) {
  const c = el('div', 'card');
  const head = el('div', 'ch');
  head.appendChild(sevBadge(f.severity));
  head.appendChild(el('span', 'ct', f.title || '(无标题)'));
  const meta = el('div', 'side-meta');
  meta.appendChild(el('span', 'chip', f.kind || '弱配置'));
  meta.appendChild(statusChip(f.status));
  head.appendChild(meta);
  c.appendChild(head);
  c.appendChild(kv('编号 / 目标', `${f.id || '—'}  →  ${f.target || '—'}`));
  if (f.evidence) c.appendChild(kv('证据', f.evidence));
  if (f.impact) c.appendChild(kv('影响', f.impact));
  if (f.fix) c.appendChild(kv('修复建议', f.fix));
  c.appendChild(kv('来源工具 / 首次发现', `${f.source_tool || '—'} · ${fmtTime(f.first_seen)} · 最近复现 ${fmtTime(f.last_seen)}`));
  const rt = f.retests || [];
  if (rt.length) {
    const box = el('div', 'retests');
    for (const r of rt) {
      const row = el('div', 'retest');
      row.appendChild(el('span', 'rt', fmtTime(r.time)));
      row.appendChild(el('span', 'rr ' + (r.result || ''), RESULT_LABEL[r.result] || r.result || ''));
      row.appendChild(el('span', 'rd', r.note || ''));
      box.appendChild(row);
    }
    c.appendChild(box);
  }
  return c;
}

async function renderHistoryView() {
  const [runs, tasks, baselines] = await Promise.all([
    fetchCollection('runs', 50).catch(() => ({ items: [] })),
    fetchCollection('tasks', 20).catch(() => ({ items: [] })),
    fetchCollection('baselines', 30).catch(() => ({ items: [] })),
  ]);

  const tasksBox = $('tasks-list');
  tasksBox.innerHTML = '';
  const tl = tasks.items || [];
  if (!tl.length) tasksBox.appendChild(emptyCard('还没有任务：设置巡检目标时会自动建立"任务（授权范围 + 定义）"。'));
  for (const t of tl.slice().reverse()) {
    const c = el('div', 'card');
    const head = el('div', 'ch');
    head.appendChild(el('span', 'ct', `${t.id} · ${t.name || ''}`));
    const meta = el('div', 'side-meta');
    meta.appendChild(el('span', 'chip', t.cycle || '手动'));
    meta.appendChild(el('span', 'chip st-' + (t.status === 'running' ? 'new' : 'fixed'), t.status || ''));
    head.appendChild(meta);
    c.appendChild(head);
    c.appendChild(kv('授权域名', (t.authorized_domains || []).join('、')));
    c.appendChild(kv('范围约束', t.scope));
    c.appendChild(kv('敏感信息定义 / 建立时间', `${t.sensitive_profile_id || '—'} · ${fmtTime(t.created_at)}`));
    tasksBox.appendChild(c);
  }

  const table = $('runs-table');
  table.innerHTML = '';
  const rl = (runs.items || []).slice().reverse();
  $('runs-hint').textContent = rl.length ? `${rl.length} 次运行（最新的在最上面）` : '还没有运行记录';
  const head = el('tr');
  for (const h of ['运行编号', '任务', '触发方式', '状态', '页数', '调用工具', '新增发现', '开始 / 结束', '错误']) {
    head.appendChild(el('th', null, h));
  }
  const thead = el('thead'); thead.appendChild(head); table.appendChild(thead);
  const tbody = el('tbody'); table.appendChild(tbody);
  for (const r of rl) {
    const tr = el('tr');
    tr.appendChild(el('td', 'mono', r.id));
    tr.appendChild(el('td', 'mono', r.task_id));
    tr.appendChild(el('td', null, r.triggered_by || ''));
    const st = el('td');
    st.appendChild(el('span', 'chip st-' + (r.status === 'done' ? 'fixed' : (r.status === 'failed' ? 'retest_failed' : 'new')),
      RUN_STATUS_LABEL[r.status] || r.status || ''));
    tr.appendChild(st);
    tr.appendChild(el('td', null, String(r.pages_found === undefined ? '—' : r.pages_found)));
    tr.appendChild(el('td', null, String(r.tools_called === undefined ? '—' : r.tools_called)));
    tr.appendChild(el('td', null, String(r.findings_new === undefined ? '—' : r.findings_new)));
    tr.appendChild(el('td', 'mono', `${fmtTime(r.started_at)}\n${r.finished_at ? fmtTime(r.finished_at) : '—'}`));
    tr.appendChild(el('td', 'mono', r.error || ''));
    tbody.appendChild(tr);
  }
  if (!rl.length) {
    const tr = el('tr');
    const td = el('td', 'muted', '还没有运行记录。');
    td.colSpan = 9;
    tr.appendChild(td);
    tbody.appendChild(tr);
  }

  const bl = $('baselines-list');
  bl.innerHTML = '';
  const bls = baselines.items || [];
  if (!bls.length) bl.appendChild(emptyCard('还没有内容基线：对某个页面做完整性检查时会自动采集。'));
  for (const b of bls.slice().reverse()) {
    const c = el('div', 'card');
    const head = el('div', 'ch');
    head.appendChild(el('span', 'ct', `${b.id} · ${b.target || ''}`));
    head.appendChild(el('div', 'side-meta')).appendChild(el('span', 'chip', fmtTime(b.captured_at)));
    c.appendChild(head);
    c.appendChild(kv('内容指纹', b.content_hash || b.hash || ''));
    c.appendChild(kv('快照引用 / 标题 / 字节', `${b.content_ref || '—'} · ${b.title || '—'} · ${b.bytes === undefined ? '—' : b.bytes}`));
    bl.appendChild(c);
  }
}

async function renderAssetsView() {
  const assets = await fetchCollection('assets', 500).catch(() => ({ items: [] }));
  const all = (assets.items || []).slice().reverse();
  const kinds = ['全部', ...Array.from(new Set(all.map((a) => a.kind || '其他')))];
  const filters = $('asset-filters');
  filters.innerHTML = '';
  let active = '全部';
  const table = $('assets-table');

  const draw = () => {
    table.innerHTML = '';
    const head = el('tr');
    for (const h of ['编号', '类型', '地址', '状态码', '深度', '发现来源', '首次 / 最近']) head.appendChild(el('th', null, h));
    const thead = el('thead'); thead.appendChild(head); table.appendChild(thead);
    const tbody = el('tbody'); table.appendChild(tbody);
    const list = active === '全部' ? all : all.filter((a) => (a.kind || '其他') === active);
    for (const a of list) {
      const tr = el('tr');
      tr.appendChild(el('td', 'mono', a.id || ''));
      const kt = el('td');
      const chip = el('span', 'chip', a.kind || '其他');
      chip.style.color = a.kind === '接口' ? '#7ee2b8' : (a.kind === '静态资源' ? 'var(--dim)' : 'var(--txt)');
      kt.appendChild(chip);
      tr.appendChild(kt);
      tr.appendChild(el('td', 'mono', a.url || ''));
      const sc = el('td', 'mono', a.status_code === undefined || a.status_code === 0 ? '—' : String(a.status_code));
      if (a.status_code >= 500 || a.status_code === 0) sc.style.color = 'var(--bad)';
      else if (a.status_code >= 400) sc.style.color = 'var(--warn)';
      else if (a.status_code >= 200) sc.style.color = 'var(--ok)';
      tr.appendChild(sc);
      tr.appendChild(el('td', 'mono', a.depth === undefined ? '—' : String(a.depth)));
      tr.appendChild(el('td', 'mono', a.parent_url || '（起点）'));
      tr.appendChild(el('td', 'mono', `${fmtTime(a.first_seen)}\n${fmtTime(a.last_seen)}`));
      tbody.appendChild(tr);
    }
    if (!list.length) {
      const tr = el('tr');
      const td = el('td', 'muted', '还没有资产记录：跑一次「资产发现」或完整巡检即可建立底账。');
      td.colSpan = 7;
      tr.appendChild(td);
      tbody.appendChild(tr);
    }
  };

  for (const k of kinds) {
    const b = el('button', 'ghost', k);
    if (k === active) b.classList.add('active');
    b.addEventListener('click', () => {
      active = k;
      filters.querySelectorAll('button').forEach((x) => x.classList.remove('active'));
      b.classList.add('active');
      draw();
    });
    filters.appendChild(b);
  }
  $('assets-hint').textContent = all.length ? `${all.length} 个资产（同地址只保留一条底账，最近访问时间会刷新）` : '';
  draw();
}

async function renderEvalView() {
  const [evals, tcs] = await Promise.all([
    fetchCollection('evals', 5).catch(() => ({ items: [] })),
    fetchCollection('testcases', 100).catch(() => ({ items: [] })),
  ]);
  const ev = (evals.items || [])[0];
  $('eval-tiles').innerHTML = '';
  const box = $('eval-outcomes');
  box.innerHTML = '';
  $('eval-formula').innerHTML = '';

  if (!ev) {
    $('eval-hint').textContent = '还没跑过评测';
    box.appendChild(emptyCard('还没有评测结果：需要先准备测试集（testcases.jsonl），再对智能体说「跑评测」。'));
  } else {
    const s = ev.stats || {};
    $('eval-hint').textContent = `${ev.id} · 测试集 ${ev.testset || '—'} · ${fmtTime(ev.evaluated_at)}`;
    const pct = (x) => (x === undefined ? '—' : (Number(x) * 100).toFixed(1) + '%');
    const tiles = [
      { l: '召回率 recall', v: pct(s.recall), cls: Number(s.recall) >= 0.8 ? 'ok' : (Number(s.recall) >= 0.5 ? 'warn' : 'bad') },
      { l: '准确率 precision', v: pct(s.precision), cls: Number(s.precision) >= 0.8 ? 'ok' : 'warn' },
      { l: '误报率 false positive', v: pct(s.false_positive_rate), cls: Number(s.false_positive_rate) > 0 ? 'warn' : 'ok' },
      { l: '期望项 / 命中', v: `${s.expected_total || 0} / ${s.matched || 0}` },
      { l: '漏检 missed', v: s.missed || 0, cls: (s.missed || 0) ? 'bad' : 'ok' },
      { l: '多检 extra', v: s.extra || 0, cls: (s.extra || 0) ? 'warn' : 'ok' },
      { l: '干净靶误报', v: `${s.benign_hit || 0} / ${s.benign_total || 0}` },
      { l: '用例数', v: s.cases_total || 0 },
    ];
    for (const t of tiles) {
      const d = el('div', 'tile ' + (t.cls || ''));
      d.appendChild(el('div', 'v', String(t.v)));
      d.appendChild(el('div', 'l', t.l));
      $('eval-tiles').appendChild(d);
    }
    $('eval-formula').innerHTML =
      '统计口径（固定）：<code>recall = 命中 / 期望总数</code>　' +
      '<code>precision = 命中 / (命中 + 多检)</code>　' +
      '<code>false_positive_rate = 干净靶上被误报的 / 干净靶总数</code>';

    for (const o of ev.outcomes || []) {
      const c = el('div', 'card');
      const head = el('div', 'ch');
      head.appendChild(el('span', 'ct', o.case_id || ''));
      const meta = el('div', 'side-meta');
      if ((o.missed || []).length) meta.appendChild(el('span', 'chip st-retest_failed', '漏检 ' + o.missed.length));
      if ((o.extra || []).length) meta.appendChild(el('span', 'chip st-confirmed', '多检 ' + o.extra.length));
      if (!(o.missed || []).length && !(o.extra || []).length) meta.appendChild(el('span', 'chip st-fixed', '对账一致'));
      head.appendChild(meta);
      c.appendChild(head);
      for (const m of o.matched || []) c.appendChild(kv('命中', m, 'cm'));
      for (const m of o.missed || []) c.appendChild(kv('漏检', m, 'cm'));
      for (const m of o.extra || []) c.appendChild(kv('多检', m, 'cm'));
      box.appendChild(c);
    }
  }

  const tl = $('testcases-list');
  tl.innerHTML = '';
  const list = tcs.items || [];
  if (!list.length) tl.appendChild(emptyCard('还没有测试集。测试集是结果类对象（一行一个用例，含 target / expected / benign）。'));
  for (const t of list) {
    const c = el('div', 'card');
    const head = el('div', 'ch');
    head.appendChild(el('span', 'ct', `${t.id} · ${t.title || ''}`));
    const meta = el('div', 'side-meta');
    meta.appendChild(el('span', 'chip', t.benign ? '干净靶' : '问题靶'));
    head.appendChild(meta);
    c.appendChild(head);
    c.appendChild(kv('目标', t.target, 'cm'));
    const exp = t.expected || [];
    if (exp.length) {
      for (const e of exp) c.appendChild(kv('期望', `${e.kind || ''} · ${e.severity || ''} · ${e.match_key || ''}`, 'cm'));
    } else {
      c.appendChild(kv('期望', '（无 —— 干净靶不应有任何发现）', 'cm'));
    }
    tl.appendChild(c);
  }
}

async function renderRulesView() {
  const r = state.cache['rules'] || (state.cache['rules'] = await api('/api/rules'));
  $('rules-source').textContent = `${r.source} · ${r.from_file ? '来自文件（可改）' : '内置默认'} · ${r.signature_count} 条内容特征`;

  const table = $('rules-table');
  table.innerHTML = '';
  const head = el('tr');
  for (const h of ['特征名', '类别', '等级', '指纹标签']) head.appendChild(el('th', null, h));
  const thead = el('thead'); thead.appendChild(head); table.appendChild(thead);
  const tbody = el('tbody'); table.appendChild(tbody);
  for (const s of r.signatures || []) {
    const tr = el('tr');
    const c1 = el('td');
    c1.appendChild(el('span', null, s.name || ''));
    tr.appendChild(c1);
    tr.appendChild(el('td', null, s.kind || ''));
    const cs = el('td');
    cs.appendChild(sevBadge(s.severity));
    tr.appendChild(cs);
    tr.appendChild(el('td', 'mono', s.tag || ''));
    tbody.appendChild(tr);
  }

  const paths = $('rules-paths');
  paths.innerHTML = '';
  for (const p of r.sensitive_paths || []) paths.appendChild(el('span', 'chip', p));
  $('rules-paths-hint').textContent = `${(r.sensitive_paths || []).length} 个落点`;

  const dirs = $('rules-dirs');
  dirs.innerHTML = '';
  for (const d of r.dir_candidates || []) dirs.appendChild(el('span', 'chip', d));
  $('rules-dirs-hint').textContent = `${(r.dir_candidates || []).length} 个目录`;
}

async function loadView(name) {
  const map = {
    report: renderReportView,
    history: renderHistoryView,
    assets: renderAssetsView,
    eval: renderEvalView,
    rules: renderRulesView,
  };
  const fn = map[name];
  if (!fn) return;
  try {
    await fn();
  } catch (e) {
    const box = document.querySelector('#view-' + name + ' .panel');
    if (box) box.appendChild(el('div', 'note', '取数失败：' + e.message));
  }
}

function switchView(name) {
  state.view = name;
  document.querySelectorAll('.vtab').forEach((b) => b.classList.toggle('active', b.dataset.view === name));
  document.querySelectorAll('.view').forEach((v) => v.classList.toggle('active', v.id === 'view-' + name));
}

/* 报告导出：前端按当前报告 + 发现清单拼 Markdown（后端只提供数据，导出格式不写死后端） */
function exportMarkdown() {
  const findings = (state.cache['findings:200'] || {}).items || [];
  const reports = (state.cache['reports:1'] || {}).items || [];
  const rep = reports[0];
  const lines = [];
  lines.push(`# ${rep ? rep.title : '网站安全巡检报告'}`);
  lines.push('');
  lines.push(`- 报告编号：${rep ? rep.id : '（未生成）'}`);
  lines.push(`- 生成时间：${rep ? fmtTime(rep.generated_at) : fmtTime(new Date().toISOString())}`);
  lines.push(`- 授权域名：${state.status && state.status.authorized ? state.status.domain : '—'}`);
  lines.push(`- 规则来源：${rep ? rep.rules_source || '—' : (state.cache['rules'] ? state.cache['rules'].source : '—')}`);
  lines.push('');
  if (rep && rep.summary) { lines.push('## 摘要'); lines.push(''); lines.push(rep.summary); lines.push(''); }
  const sev = {};
  for (const f of findings) sev[f.severity || '信息'] = (sev[f.severity || '信息'] || 0) + 1;
  lines.push('## 统计');
  lines.push('');
  for (const k of SEV_ORDER) if (sev[k]) lines.push(`- ${k}：${sev[k]}`);
  lines.push('');
  lines.push('## 发现清单');
  lines.push('');
  for (const f of findings) {
    lines.push(`### ${f.id || ''} [${f.severity || ''}] ${f.title || ''}`);
    lines.push('');
    lines.push(`- 类别 / 状态：${f.kind || ''} / ${STATUS_LABEL[f.status] || f.status || ''}`);
    lines.push(`- 目标：${f.target || ''}`);
    if (f.evidence) lines.push(`- 证据：${f.evidence}`);
    if (f.impact) lines.push(`- 影响：${f.impact}`);
    if (f.fix) lines.push(`- 修复建议：${f.fix}`);
    lines.push(`- 来源 / 首次发现：${f.source_tool || ''} / ${f.first_seen || ''}`);
    for (const r of f.retests || []) {
      lines.push(`- 复测（${fmtTime(r.time)}）：${RESULT_LABEL[r.result] || r.result} —— ${r.note || ''}`);
    }
    lines.push('');
  }
  lines.push('> 由「网站安全巡检智能体（C 版）」生成：结论均来自只读检查与规则判定，证据已去敏。');
  const blob = new Blob([lines.join('\n')], { type: 'text/markdown;charset=utf-8' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = (rep ? rep.id : 'report') + '.md';
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 2000);
}

/* ============ 绑定 ============ */

$('form').addEventListener('submit', (e) => {
  e.preventDefault();
  send($('q').value);
});

$('q').addEventListener('keydown', (e) => {
  if (e.key === 'Enter' && !e.shiftKey) {
    e.preventDefault();
    send($('q').value);
  }
});

const ta = $('q');
ta.addEventListener('input', () => {
  ta.style.height = 'auto';
  ta.style.height = Math.min(ta.scrollHeight, 120) + 'px';
});

document.querySelectorAll('.vtab').forEach((b) => {
  b.addEventListener('click', () => {
    switchView(b.dataset.view);
    loadView(b.dataset.view);
  });
});

document.querySelectorAll('.tab').forEach((t) => {
  t.addEventListener('click', () => {
    document.querySelectorAll('.tab').forEach((x) => x.classList.remove('active'));
    t.classList.add('active');
    for (const n of ['skills', 'tools']) {
      $('pane-' + n).classList.toggle('hidden', n !== t.dataset.tab);
    }
  });
});

$('btn-refresh').addEventListener('click', async () => {
  state.cache = {};
  try { renderStatus(await api('/api/status')); } catch { /* 后端可能刚停 */ }
  await loadView(state.view);
});

$('btn-export').addEventListener('click', exportMarkdown);

/* 授权弹窗：这是合规的第一道闸，前端也必须拦一次 */
$('btn-scope').addEventListener('click', () => $('modal').classList.remove('hidden'));
$('scope-cancel').addEventListener('click', () => $('modal').classList.add('hidden'));
$('scope-save').addEventListener('click', async () => {
  const domain = $('scope-domain').value.trim();
  const ok = $('scope-ok').checked;
  const err = $('scope-err');
  err.textContent = '';
  if (!domain) { err.textContent = '请填写目标域名。'; return; }
  if (!ok) { err.textContent = '必须确认已获授权，智能体才会对该目标发起请求。'; return; }
  try {
    const s = await api('/api/scope', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ domain, authorized: true }),
    });
    renderStatus(s);
    state.cache = {};
    $('modal').classList.add('hidden');
  } catch (e) {
    err.textContent = '设置失败：' + e.message;
  }
});

/* ============ 主题（亮色 / 暗色）============
   颜色全部走 CSS 变量，切主题只是给 <html> 换一个 class。
   默认跟随系统，用户手动切过就记在 localStorage 里。 */
function applyTheme(dark) {
  document.documentElement.classList.toggle('dark', dark);
  $('btn-theme').textContent = dark ? '亮色' : '暗色';
}
function initTheme() {
  let saved = null;
  try { saved = localStorage.getItem('theme'); } catch { /* 隐私模式下忽略 */ }
  const dark = saved ? saved === 'dark' : window.matchMedia('(prefers-color-scheme: dark)').matches;
  applyTheme(dark);
  $('btn-theme').addEventListener('click', () => {
    const next = !document.documentElement.classList.contains('dark');
    applyTheme(next);
    try { localStorage.setItem('theme', next ? 'dark' : 'light'); } catch { /* 忽略 */ }
  });
}

/* ============ 启动 ============ */
(async () => {
  initTheme();
  try {
    renderManifest(await api('/api/manifest'));
  } catch { /* 清单拿不到不影响主流程 */ }
  try {
    renderStatus(await api('/api/status'));
  } catch (e) {
    $('subtitle').textContent = '连不上后端服务：' + e.message;
  }
  if (!state.status || !state.status.authorized) {
    $('modal').classList.remove('hidden');
  }
})();
