/* app.js —— 界面层：把智能体的决策循环直播成"看得见的过程"，并把闭环数据摊开展示。
 *
 * 与后端只通过 HTTP + SSE 说话，事件协议就是三册合同里的六个事件
 * (message_start / block_start / block_delta / block_stop / tool_status / message_stop)，
 * 前端不认识任何"巡检业务细节" —— 后端换实现，这里一行都不用改。
 *
 * 数据视图（报告/历史/资产/证据/规则）全部走只读接口：
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
  if (!PREFS.autoscroll) return;
  if (force || atBottom()) stream.scrollTop = stream.scrollHeight;
}

/* 接口令牌:由后端在发送 index.html 时注入 meta —— 用来挡住"别的网页借我们的手扫别人" */
const BW_TOKEN = (document.querySelector('meta[name="bw-token"]') || {}).content || '';

/* 会话 id:每个标签页一个。同一条会话的上下文在后端是独立的,
   所以两个标签页可以各查各的站,互不打断。
   "新建巡检"会换一个 id —— 换了 id 就是新对话,旧对话留在左栏可回看。 */
function newChatId() {
  return 's-' + Math.random().toString(36).slice(2, 10) + Date.now().toString(36).slice(-4);
}
let BW_SID = (() => {
  try {
    let v = sessionStorage.getItem('bw-sid');
    if (!v) {
      v = newChatId();
      sessionStorage.setItem('bw-sid', v);
    }
    return v;
  } catch (e) {
    return newChatId();
  }
})();

/* 界面偏好：定义在最前面，滚动这类早期函数会用到 */
const PREFS_KEY = 'bw-prefs';
const PREFS_DEFAULT = { trace: true, autoscroll: true, motion: true };
let PREFS = (() => {
  try { return Object.assign({}, PREFS_DEFAULT, JSON.parse(localStorage.getItem(PREFS_KEY) || '{}')); }
  catch (e) { return Object.assign({}, PREFS_DEFAULT); }
})();

/* 本轮待发送的附件:先上传换一个 id,聊天时只带 id。
   不把长文本塞进 URL —— 几千行的日志会直接把查询串撑爆。 */
const pendingAtt = [];

function renderAttachList() {
  const box = $('attach-list');
  if (!box) return;
  box.innerHTML = '';
  for (let i = 0; i < pendingAtt.length; i++) {
    const a = pendingAtt[i];
    const chip = el('span', 'attach-chip');
    chip.appendChild(el('span', 'nm', a.name));
    chip.appendChild(el('b', null, a.kind === 'image' ? '图片' : a.size + 'B'));
    const x = el('button', null, '×');
    x.type = 'button';
    x.title = '移除';
    x.addEventListener('click', () => { pendingAtt.splice(i, 1); renderAttachList(); });
    chip.appendChild(x);
    box.appendChild(chip);
  }
}

function clearAttachments() {
  pendingAtt.length = 0;
  renderAttachList();
}

async function uploadAttachment(file) {
  const isImg = /^image\//.test(file.type || '') || /\.(png|jpe?g|webp)$/i.test(file.name || '');
  let text;
  if (isImg) {
    text = await new Promise((resolve, reject) => {
      const fr = new FileReader();
      fr.onload = () => resolve(fr.result);
      fr.onerror = () => reject(fr.error);
      fr.readAsDataURL(file);
    });
  } else {
    text = (await file.text()).slice(0, 200000);   /* 单文件 200KB 上限,够放日志了 */
  }
  const r = await api('/api/attach', {
    method: 'POST',
    body: JSON.stringify({ sid: BW_SID, name: file.name, kind: isImg ? 'image' : 'text', text })
  });
  pendingAtt.push({
    id: r.id,
    name: r.name || file.name,
    kind: r.kind || (isImg ? 'image' : 'text'),
    size: r.size || text.length
  });
  renderAttachList();
}

async function api(path, opts) {
  const o = Object.assign({}, opts);
  o.headers = Object.assign({ 'X-BW-Token': BW_TOKEN }, (opts && opts.headers) || {});
  /* 后端门禁要求 POST 必须是 application/json —— 统一在这里补,
     免得每个调用点都记着写一遍(漏一处就是一个 415)。 */
  if (o.body && !o.headers['Content-Type']) o.headers['Content-Type'] = 'application/json';
  const r = await fetch(path, o);
  const j = await r.json().catch(() => null);
  if (!r.ok) throw new Error((j && (j.error || j.detail)) || ('HTTP ' + r.status));
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

  const pm = $('pill-model');
  pm.innerHTML = s.model
    ? '<svg class="status-icon" viewBox="0 0 24 24" aria-hidden="true"><path d="M4 12a8 8 0 0 1 16 0"/><path d="M7 12a5 5 0 0 1 10 0"/><circle cx="12" cy="16.5" r="1.5"/></svg><span>在线</span>'
    : '<svg class="status-icon" viewBox="0 0 24 24" aria-hidden="true"><path d="m4 4 16 16"/><path d="M5 12a7 7 0 0 1 2.1-5"/><path d="M9 16a4 4 0 0 1 1.1-2.8"/><path d="M19 12a7 7 0 0 0-1.2-3.9"/><circle cx="12" cy="17" r="1.5"/></svg><span>离线</span>';
  pm.className = 'pill status-pill ' + (s.model ? 'on' : 'off');
  pm.title = s.model ? '模型在线' : '模型离线，当前使用本地规则';
  if (s.modelFailed && s.modelError) {
    /* 把平台给的原因挂在提示上:用户一眼知道是凭证问题还是网络问题 */
    pm.title += '；最近一次调用失败：' + s.modelError;
  }

  const ps = $('pill-scope');
  ps.innerHTML = s.authorized
    ? '<svg class="status-icon" viewBox="0 0 24 24" aria-hidden="true"><path d="M12 3 19 6v5c0 4.5-2.7 7.8-7 10-4.3-2.2-7-5.5-7-10V6l7-3Z"/><path d="m8.5 12 2.2 2.2 4.8-4.8"/></svg>'
    : '<svg class="status-icon" viewBox="0 0 24 24" aria-hidden="true"><path d="M12 3 19 6v5c0 4.5-2.7 7.8-7 10-4.3-2.2-7-5.5-7-10V6l7-3Z"/><path d="m9 9 6 6M15 9l-6 6"/></svg>';
  ps.className = 'pill status-pill ' + (s.authorized ? 'on' : 'off');
  const poolSize = s.poolSize !== undefined ? s.poolSize : 0;
  ps.title = poolSize
    ? `授权池 ${poolSize} 个主机：池内的站都能查，池外的请求发不出去`
    : '授权池是空的：任何请求都不会发出去';

  const pc = $('pill-count');
  const n = s.findingCount !== undefined ? s.findingCount : (s.findings || []).length;
  pc.innerHTML = '<svg class="status-icon" viewBox="0 0 24 24" aria-hidden="true"><path d="M4 5.5h16v13H4z"/><path d="M8 9h8M8 12h5M8 15h3"/></svg><b>' + n + '</b>';
  pc.className = 'pill status-pill ' + (n > 0 ? 'has-findings' : '');
  pc.title = n > 0 ? `发现 ${n} 个问题` : '暂无发现问题';

  POOL.entries = ((s.pool || {}).hosts || []).slice();
  renderPoolList();
  $('scope-ok').checked = false;
  /* 审批策略读数：顶栏选择器 + 警告标记都由 renderApprovals 负责，
     这里只在状态里带上"当前是哪一档"，避免两处各说一套。 */
  if (s.approval && $('approval-select')) {
    const sel = $('approval-select');
    if (!sel.options.length) renderApprovals().catch(() => {});
    else if (sel.value !== s.approval.active) sel.value = s.approval.active;
    sel.classList.toggle('warn', !!s.approval.allowAll);
  }

  const sideStatus = $('side-scope-status');
  const sideName = $('side-scope-name');
  if (sideStatus) {
    sideStatus.textContent = poolSize ? `授权池 ${poolSize} 个主机` : '授权池为空';
    sideStatus.dataset.ready = poolSize ? 'true' : 'false';
  }
  if (sideName) sideName.textContent = poolSize ? `授权池 ${poolSize} 个主机` : '先加一个授权主机';
  const introModel = $('intro-model');
  if (introModel) introModel.textContent = s.model ? '恒脑在线' : '离线规则';

  /* 起手式与工作台各自的读数：同一份状态，两处写法不同 */
  const hs = $('home-scope');
  if (hs) hs.textContent = poolSize ? `授权池 ${poolSize} 个主机` : '授权池为空';
  const ws = $('work-scope');
  if (ws) {
    /* 不再有"当前目标"这个概念:边界是池子,看哪个站由指令决定。
       这个 chip 只说明规则,不显示任何"当前值"。 */
    ws.textContent = poolSize ? `授权池 ${poolSize} 个主机` : '授权池为空';
  }
  /* 工作台右上角不再有目标选择器 —— 目标由用户这句话决定 */
  const wm = $('work-model');
  if (wm) wm.textContent = s.model ? '恒脑在线' : '离线规则';
  const rb = $('rail-boundary');
  if (rb) {
    rb.innerHTML = '';
    const rows = [
      ['授权池', poolSize ? poolSize + ' 个主机' : '空'],
      ['目标', '由指令指定'],
      ['方法', 'GET / HEAD / OPTIONS'],
      ['限速', '2 请求/秒'],
      ['越界', '立刻掐断整轮'],
    ];
    for (const [k, v] of rows) {
      rb.appendChild(el('dt', null, k));
      rb.appendChild(el('dd', null, v));
    }
  }
}

/* ============ 授权池 ============
   边界是"允许检查谁"这张表,不是"当前目标"。
   目标只是从池里挑出来的焦点,换站不用改全局设定,越池的请求会被后端掐断。 */
const POOL = { entries: [] };

function renderPoolList() {
  const box = $('pool-list');
  if (!box) return;
  box.innerHTML = '';
  if (!POOL.entries.length) {
    box.appendChild(el('div', 'pool-empty', '池子还是空的。没有授权主机时，任何请求都不会发出去。'));
    return;
  }
  for (const entry of POOL.entries) {
    const row = el('div', 'pool-row' + (entry[0] === '!' ? ' deny' : ''));
    row.appendChild(el('span', 'pool-host', entry));
    if (entry[0] === '!') row.appendChild(el('span', 'pool-flag', '不允许'));
    const b = el('button', 'ghost tiny', '移出');
    b.addEventListener('click', async () => {
      try {
        const r = await api('/api/pool', { method: 'POST', body: JSON.stringify({ action: 'remove', entry }) });
        POOL.entries = ((r.pool || {}).hosts || []).slice();
        renderPoolList();
        renderStatus(await api('/api/status'));
      } catch (e) { console.warn(e.message); }
    });
    row.appendChild(b);
    box.appendChild(row);
  }
}

/* 批量:把一段文本(或导入的文件内容)交给后端解析。
   后端接受换行/逗号/分号分隔,并且逐条校验,回话里带 added/skipped/rejected。 */
async function addPoolBatch(text) {
  const err = $('scope-err');
  err.textContent = '';
  if (!text || !text.trim()) {
    err.textContent = '先粘一段主机清单，或者从文件导入';
    return;
  }
  if (!$('scope-ok').checked) {
    err.textContent = '请先勾选"已获得该目标的巡检授权"';
    return;
  }
  try {
    const r = await api('/api/pool', { method: 'POST', body: JSON.stringify({ action: 'batch', text }) });
    POOL.entries = ((r.pool || {}).hosts || []).slice();
    renderPoolList();
    renderStatus(await api('/api/status'));
    $('pool-batch-text').value = '';
    const parts = [`加入 ${r.added || 0} 个`];
    if (r.skipped) parts.push(`跳过 ${r.skipped} 个`);
    if (r.rejected) parts.push(`格式不对：${r.rejected}`);
    $('pool-batch-hint').textContent = parts.join(' · ');
  } catch (e) {
    err.textContent = '批量加入失败：' + e.message;
  }
}

async function addPoolEntry() {
  const err = $('scope-err');
  const entry = $('scope-domain').value.trim();
  err.textContent = '';
  if (!entry) {
    /* 单条输入空着就按批量处理:用户可能直接把清单粘在大框里 */
    const batch = $('pool-batch-text').value.trim();
    if (batch) { addPoolBatch(batch); return; }
    $('scope-domain').focus();
    return;
  }
  if (!$('scope-ok').checked) {
    err.textContent = '请先勾选"已获得该目标的巡检授权"';
    return;
  }
  try {
    const r = await api('/api/pool', { method: 'POST', body: JSON.stringify({ action: 'add', entry }) });
    POOL.entries = ((r.pool || {}).hosts || []).slice();
    renderPoolList();
    renderStatus(await api('/api/status'));
    $('scope-domain').value = '';
    $('scope-ok').checked = false;
    shutModal();
  } catch (e) {
    err.textContent = '没加进去：' + e.message;
  }
}

/* 从本地文本文件导入:浏览器读文本 → 交给同一个批量接口,后端不需要处理 multipart */
function bindPoolImport() {
  const input = $('pool-import');
  if (!input) return;
  input.addEventListener('change', () => {
    const f = input.files && input.files[0];
    if (!f) return;
    const reader = new FileReader();
    reader.onload = () => {
      $('pool-batch-text').value = String(reader.result || '').slice(0, 20000);
      $('pool-batch-hint').textContent = `已读入 ${f.name}，点「批量加入」生效`;
    };
    reader.onerror = () => { $('pool-batch-hint').textContent = '读文件失败，可以直接粘贴内容'; };
    reader.readAsText(f, 'utf-8');
    input.value = '';
  });
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
  /* 停止:只在"有东西在跑"的时候出现 —— 和主流 agent 一样,
     已经开始的动作必须能被人中途叫停。 */
  const stop = $('btn-stop');
  if (stop) {
    stop.hidden = !on;
    if (on) { stop.disabled = false; stop.textContent = '停止'; }
  }
}

function endTurn() {
  setBusy(false);
  state.cache = {};                    // 一轮结束：闭环数据可能变了,下次进视图重新取
  api('/api/status').then(renderStatus).catch(() => {});
  renderRail();
  renderRecent();
  renderTasks();
}

function send(text) {
  const q = (text || '').trim();
  if (!q && !pendingAtt.length) return;
  if (busy) return;

  showWork();
  const title = q || (pendingAtt.length ? '（附件）' + pendingAtt[0].name : '巡检');
  if ($('task-title')) $('task-title').textContent = title.length > 26 ? title.slice(0, 26) + '…' : title;
  if ($('stream-empty')) $('stream-empty').remove();
  const wrap = el('div', 'msg user');
  const ub = el('div', 'body');
  ub.appendChild(el('div', null, q || '（只说附件）'));
  for (const a of pendingAtt) {
    const tag = el('div', 'attach-chip');
    tag.appendChild(el('span', 'nm', a.name));
    tag.appendChild(el('b', null, a.kind === 'image' ? '图片' : a.size + 'B'));
    ub.appendChild(tag);
  }
  wrap.appendChild(ub);
  stream.appendChild(wrap);
  scrollBottom(true);
  /* 先把这一轮的附件 id 抄下来再清空 —— URL 是后面才拼的,
     顺序反了就会"文件传上去了,但这一轮没带上"。 */
  const attIds = pendingAtt.map((a) => a.id).join(',');
  clearAttachments();

  $('q').value = '';
  $('q').style.height = 'auto';
  setBusy(true);
  /* 后端建好这一轮再刷新左栏，否则新任务不会出现在列表里 */
  setTimeout(() => { renderTasks().catch(() => {}); }, 900);
  trace.textContent = '';
  if (stepsBox) stepsBox.innerHTML = '<div class="muted">执行后按步列出。</div>';

  /* EventSource 不能自定义请求头,所以令牌走查询串 */
  /* 目标不再是全局设定:这一轮看哪个站,由用户这句话决定。
     边界交给授权池,越池的请求在取数通道就被掐断。 */
  const es = new EventSource('/api/chat?q=' + encodeURIComponent(q) +
                             '&sid=' + encodeURIComponent(BW_SID) +
                             (attIds ? '&att=' + encodeURIComponent(attIds) : '') +
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
      case 'approval_request': showApprovalBar(e); break;
      case 'message_stop':  onMessageStop(e); es.close(); closed = true; break;
    }
  };
  es.onerror = () => {
    es.close();
    if (closed) return;
    if (current) {
      current.body.appendChild(el('div', 'stopline', '连接中断，请确认服务仍在运行。'));
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

/* 证据与闭环：只报可核查的事实，不给"效果指标"。
   效果指标取决于评测集与口径，应由评测方给出 —— 界面上不出现这类数字。 */
async function renderEvalView() {
  const findings = (state.cache['findings:200'] || (state.cache['findings:200'] = await fetchCollection('findings', 200))).items || [];
  const real = findings.filter((f) => f.status !== 'false_positive');
  const withEv = real.filter((f) => (f.evidence || '').trim()).length;
  const withImpact = real.filter((f) => (f.impact || '').trim()).length;
  const withFix = real.filter((f) => (f.fix || '').trim()).length;
  const retested = real.filter((f) => (f.retests || []).length).length;
  const missing = real.filter((f) => !(f.evidence || '').trim());

  $('eval-hint').textContent = `${real.length} 条结论（不含误报）`;
  $('eval-tiles').innerHTML = '';
  const tiles = [
    { l: '结论条数', v: real.length },
    { l: '带证据', v: withEv, cls: withEv === real.length ? 'ok' : 'warn' },
    { l: '带影响说明', v: withImpact },
    { l: '带修复建议', v: withFix },
    { l: '已复测', v: retested },
    { l: '缺证据', v: missing.length, cls: missing.length ? 'bad' : 'ok' },
  ];
  for (const t of tiles) {
    const d = el('div', 'tile ' + (t.cls || ''));
    d.appendChild(el('div', 'v', String(t.v)));
    d.appendChild(el('div', 'l', t.l));
    $('eval-tiles').appendChild(d);
  }

  const byStatus = {};
  for (const f of real) byStatus[f.status || 'new'] = (byStatus[f.status || 'new'] || 0) + 1;
  const labelled = {};
  for (const [k, v] of Object.entries(byStatus)) labelled[STATUS_LABEL[k] || k] = v;
  bars($('eval-status'), labelled);

  const box = $('eval-missing');
  box.innerHTML = '';
  if (!missing.length) {
    box.appendChild(emptyCard('每条结论都应带证据。'));
  } else {
    for (const f of missing) {
      const c = el('div', 'card');
      const head = el('div', 'ch');
      head.appendChild(sevBadge(f.severity));
      head.appendChild(el('span', 'ct', f.title || f.id));
      const meta = el('div', 'side-meta');
      meta.appendChild(el('span', 'chip', f.kind || '未分类'));
      head.appendChild(meta);
      c.appendChild(head);
      c.appendChild(kv('目标', f.target, 'cm'));
      c.appendChild(kv('状态', STATUS_LABEL[f.status] || f.status || '—', 'cm'));
      c.appendChild(el('div', 'cd', '这条缺少证据：补一次复现，或标为误报。'));
      box.appendChild(c);
    }
  }
}

/* ============ 起手式与工作台的列表 ============
   两个列表都只画后端真的落过盘的东西：没有运行记录就写"还没有"，不摆假数据。 */

function runChip(status) {
  return RUN_STATUS_LABEL[status] || status || '未知';
}

async function recentData() {
  const [runs, tasks] = await Promise.all([
    fetchCollection('runs', 12).catch(() => ({ items: [] })),
    fetchCollection('tasks', 20).catch(() => ({ items: [] })),
  ]);
  const taskMap = {};
  for (const t of tasks.items || []) taskMap[t.id] = t;
  return { list: (runs.items || []).slice().reverse(), taskMap };
}

async function renderRecent() {
  const box = $('recent');
  if (!box) return;
  const { list, taskMap } = await recentData();
  box.innerHTML = '';
  $('recent-meta').textContent = list.length ? `${list.length} 次 · 共 ${list.reduce((a, r) => a + (Number(r.findings_new) || 0), 0)} 条新发现` : '还没有记录';
  if (!list.length) {
    box.appendChild(el('div', 'recent-empty', '跑完第一轮，这里会按时间排出历史。'));
    return;
  }
  for (const r of list.slice(0, 6)) {
    const t = taskMap[r.task_id] || {};
    const target = (t.authorized_domains || [])[0] || (state.status && state.status.domain) || r.task_id || '—';
    const card = el('button', 'rcard');
    card.type = 'button';
    const top = el('span', 'rtop');
    top.appendChild(el('span', 'tg', target));
    top.appendChild(el('span', 'rst', runChip(r.status)));
    card.appendChild(top);
    card.appendChild(el('span', 'nm', r.id || '—'));
    card.appendChild(el('span', 'rmeta', `${r.pages_found || 0} 页 · ${r.tools_called || 0} 次调用 · ${r.findings_new || 0} 条新发现`));
    card.appendChild(el('span', 'rfoot', fmtTime(r.started_at)));
    card.addEventListener('click', () => { showWork(); switchView('history'); loadView('history'); });
    void t;
    box.appendChild(card);
  }
}

/* 分组折叠状态记在本机 —— 关掉页面再回来，还是你上次展开的样子 */
const GROUP_KEY = 'bw-groups';
function groupOpen(key) {
  try {
    const m = JSON.parse(localStorage.getItem(GROUP_KEY) || '{}');
    return m[key] !== false;
  } catch (e) { return true; }
}
function toggleGroup(key) {
  try {
    const m = JSON.parse(localStorage.getItem(GROUP_KEY) || '{}');
    m[key] = m[key] === false;
    localStorage.setItem(GROUP_KEY, JSON.stringify(m));
  } catch (e) { /* 隐私模式也能用 */ }
}

/* 归档状态:存在后端(换浏览器也还在),前端只负责分组 */
async function archiveState() {
  try {
    const r = await api('/api/chats?archived=1');
    const m = {};
    for (const x of r.items || []) m[x.id] = !!x.archived;
    return m;
  } catch (e) { return {}; }
}
async function setArchived(id, on) {
  return api('/api/chats', {
    method: 'POST',
    body: JSON.stringify({ action: on ? 'archive' : 'unarchive', id })
  });
}

async function renderTasks() {
  const box = $('tasks');
  if (!box) return;
  const [{ list, taskMap }, arch] = await Promise.all([recentData(), archiveState()]);
  box.innerHTML = '';
  if (!list.length) {
    box.appendChild(el('div', 'grp', '还没有运行记录'));
    return;
  }
  const archivedRows = list.filter((r) => arch[r.id]);
  const active = list.filter((r) => !arch[r.id]);

  const groups = [['running', '进行中'], ['paused', '待复核'], ['failed', '失败'], ['done', '已完成']];
  const known = groups.map(([k]) => k);
  const other = active.filter((r) => !known.includes(r.status || 'done'));

  const addGroup = (key, label, rows, isArchived) => {
    const head = el('button', 'grp');
    head.type = 'button';
    head.title = groupOpen(key) ? '收起这一组' : '展开这一组';
    const gl = el('span', 'gl');
    gl.innerHTML = '<svg class="cv" viewBox="0 0 24 24" aria-hidden="true"><path d="m6 9 6 6 6-6"/></svg>';
    gl.appendChild(el('span', null, label));
    head.appendChild(gl);
    head.appendChild(el('b', null, String(rows.length)));
    if (!groupOpen(key)) head.classList.add('closed');
    head.addEventListener('click', () => { toggleGroup(key); renderTasks(); });
    box.appendChild(head);
    if (!groupOpen(key)) return;
    for (const r of rows) box.appendChild(taskRow(r, taskMap[r.task_id], isArchived));
  };

  for (const [key, label] of groups) {
    const rows = active.filter((r) => (r.status || 'done') === key);
    if (rows.length) addGroup(key, label, rows, false);
  }
  if (other.length) addGroup('other', '其它', other, false);
  if (archivedRows.length) addGroup('archived', '已归档', archivedRows, true);

  const first = box.querySelector('.titem');
  if (first) first.setAttribute('aria-current', 'true');
}

function taskRow(r, t, archived) {
  const row = el('button', 'titem' + (archived ? ' archived' : ''));
  row.type = 'button';
  const r1 = el('span', 'r1');
  r1.appendChild(el('span', 't', `${r.id} · ${(t && t.name) || r.triggered_by || '巡检'}`));
  const dot = el('span', 'sdot ' + (r.status || 'done'));
  r1.appendChild(dot);
  row.appendChild(r1);
  const r2 = el('span', 'r2');
  r2.appendChild(el('span', 'sub', `${r.pages_found || 0} 页 · ${r.tools_called || 0} 次调用 · ${fmtTime(r.started_at)}`));
  if (r.findings_new) {
    const df = el('span', 'df');
    df.appendChild(el('em', null, '+' + r.findings_new));
    r2.appendChild(df);
  }
  row.appendChild(r2);

  /* 归档:悬停才出现，不抢注意力；点一下挪进/挪出「已归档」 */
  const ab = el('button', 'ar');
  ab.type = 'button';
  ab.title = archived ? '取消归档' : '归档';
  ab.innerHTML = archived
    ? '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 5v9"/><path d="m8 10 4 4 4-4"/><path d="M5 19h14"/></svg>'
    : '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 7h16"/><path d="M9 7V5h6v2"/><path d="M6.5 7 7.5 20h9L17.5 7"/></svg>';
  ab.addEventListener('click', async (ev) => {
    ev.stopPropagation();
    ab.disabled = true;
    try {
      await setArchived(r.id, !archived);
      state.cache = {};
      await renderTasks();
    } catch (e) { /* 失败就保持原样 */ }
    ab.disabled = false;
  });
  row.appendChild(ab);

  row.addEventListener('click', () => {
    document.querySelectorAll('.titem').forEach((x) => x.setAttribute('aria-current', 'false'));
    row.setAttribute('aria-current', 'true');
    openRun(r.id);
  });
  return row;
}

/* 右栏的"产物"：报告卡直接来自最新一份报告，没有就写成未生成 */
async function renderRail() {
  const [rep, fl] = await Promise.all([
    fetchCollection('reports', 1).catch(() => ({ items: [] })),
    fetchCollection('findings', 200).catch(() => ({ items: [] })),
  ]);
  const r = (rep.items || [])[0];
  const findings = fl.items || [];
  const bars = $('rail-report-bars');
  const kvBox = $('rail-report-kv');
  if (bars) bars.innerHTML = '';
  if (kvBox) kvBox.innerHTML = '';
  if (!r) return;
  const stats = r.stats || {};
  const sev = stats.by_severity || {};
  $('rail-report-state').textContent = '已生成';
  $('rail-report-title').textContent = `报告 ${r.id || ''}`;
  $('rail-report-meta').textContent = `${fmtTime(r.created_at)} · ${findings.length} 条发现`;
  const total = Object.values(sev).reduce((a, v) => a + (Number(v) || 0), 0) || 1;
  for (const [k, color] of [['严重', 'var(--sev-严重)'], ['中', 'var(--sev-中)'], ['低', 'var(--sev-低)']]) {
    const i = el('i');
    i.style.width = Math.round(((Number(sev[k]) || 0) / total) * 100) + '%';
    i.style.background = color;
    if (bars) bars.appendChild(i);
  }
  if (kvBox) {
    for (const [k, v] of [['严重', sev['严重'] || 0], ['中', sev['中'] || 0], ['低', sev['低'] || 0], ['未处理', stats.open === undefined ? '—' : stats.open]]) {
      kvBox.appendChild(el('dt', null, k));
      kvBox.appendChild(el('dd', null, String(v)));
    }
  }
  $('rail-count').textContent = `${findings.length} 条`;
}

async function loadView(name) {
  const map = {
    report: renderReportView,
    history: renderHistoryView,
    assets: renderAssetsView,
    eval: renderEvalView,
    automation: renderAutomationView,
    config: renderConfigView,
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

/* 三层壳：起手式 → 任务工作台 → 数据视图（整页抽屉）。
   起手式与工作台互斥（同一块屏的两种排布），抽屉叠在它们上面。
   切换靠 .on 驱动 CSS 动画（见 app.css「零 · 层」），不是 display 硬切。 */
const BASE = ['home', 'work'];

/** 起手式 ⇄ 工作台。进工作台时新层从下方升起，回起手式时从上方落下 —— 方向一致，不混淆来路。 */
function raise(name, dir) {
  for (const id of BASE) {
    const node = $(id);
    if (!node) continue;
    if (id === name) {
      node.classList.toggle('enter-down', dir === 'down');
      void node.offsetWidth;              // 重放同一段动画：类不变时浏览器不会重播
      node.classList.add('on');
    } else {
      node.classList.remove('on', 'enter-down');
    }
  }
  if (name === 'work') renderTasks();
}

function showHome() {
  raise('home', 'down');
  const q = $('hq');
  if (q && !q.value.trim()) setTimeout(() => q.focus(), 210);
}
function showWork() {
  raise('work');
}

/* 清空中间的流，回到"还没有开始"的样子 —— 新建对话时用 */
function resetStream(title, text) {
  stream.innerHTML = '';
  const empty = el('div', 'empty');
  empty.id = 'stream-empty';
  empty.appendChild(el('b', null, title || '还没有开始'));
  empty.appendChild(el('p', null, text || '输入要查什么，过程和证据会显示在这里。'));
  stream.appendChild(empty);
  current = null;
  if (stepsBox) stepsBox.innerHTML = '<div class="muted">执行后按步列出。</div>';
  if (trace) trace.textContent = '';
  if ($('task-title')) $('task-title').textContent = '巡检会话';
}

/* 新建对话:换一个会话 id、清空中间那一片。
   注意这是"同一块屏换个新会话"，不是回首页 —— 回首页是 HOME 按钮的事。 */
function newChat() {
  BW_SID = newChatId();
  try { sessionStorage.setItem('bw-sid', BW_SID); } catch (e) { /* 隐私模式下也能用 */ }
  setBusy(false);
  closeSheet();
  clearAttachments();
  resetStream();
  showWork();
  renderTasks();
  const q = $('q');
  if (q) setTimeout(() => q.focus(), 180);
}

/* 点左栏任意一条运行记录:有对话就进对话;老记录没有转录,
   就地展示它当时的统计与发现 —— 不能点了没反应,也不能假装有对话。 */
async function openRun(runId) {
  if (!runId) return;
  closeSheet();
  showWork();
  setBusy(false);
  resetStream('正在打开…', '读取这次运行的记录。');
  let r;
  try {
    r = await api('/api/chats?run=' + encodeURIComponent(runId));
  } catch (e) {
    resetStream('这条记录打不开', String((e && e.message) || e));
    return;
  }
  if (r.session) { await openChat(r.session); return; }

  const run = r.run || {};
  const items = r.findings || [];
  stream.innerHTML = '';

  const head = el('div', 'msg user');
  const hb = el('div', 'body');
  hb.appendChild(el('div', null, runId + ' · ' + (run.triggered_by || '巡检')));
  hb.appendChild(el('div', 'stopline',
    `${run.pages_found || 0} 页 · ${run.tools_called || 0} 次调用 · ` +
    `${run.findings_new || 0} 条新发现 · ${fmtTime(run.started_at)}`));
  head.appendChild(hb);
  stream.appendChild(head);

  const wrap = el('div', 'msg agent');
  wrap.appendChild(el('div', 'who', '运行记录 · ' + runId));
  const body = el('div', 'body runplain');
  body.appendChild(el('p', null,
    '这次运行没有留下对话转录（当时的版本还没记录会话）。下面是它当时交出的结果：'));
  if (!items.length) {
    body.appendChild(el('p', 'muted', '这次运行没有产生发现。'));
  } else {
    const t = el('table');
    const hr = el('tr');
    ['等级', '问题', '目标'].forEach((h) => hr.appendChild(el('th', null, h)));
    t.appendChild(hr);
    for (const f of items) {
      const tr = el('tr');
      tr.appendChild(el('td', null, f.severity || '—'));
      tr.appendChild(el('td', null, f.title || f.kind || '—'));
      tr.appendChild(el('td', null, f.target || '—'));
      t.appendChild(tr);
    }
    body.appendChild(t);
  }
  wrap.appendChild(body);
  stream.appendChild(wrap);
  if ($('task-title')) $('task-title').textContent = runId + ' · ' + (run.triggered_by || '巡检');
  scrollBottom(true);
}

/* 打开某一次历史对话:把后端落下来的转录原样铺回中间，
   并且把当前会话切到它 —— 接着往下说，就是在这条对话上继续。 */
async function openChat(sid) {
  if (!sid) { switchView('history'); loadView('history'); return; }
  closeSheet();
  showWork();
  setBusy(false);
  BW_SID = sid;
  try { sessionStorage.setItem('bw-sid', sid); } catch (e) { /* 忽略 */ }
  resetStream('正在打开对话…', '从数据目录里读这次对话的转录。');
  let r;
  try {
    r = await api('/api/chats?sid=' + encodeURIComponent(sid));
  } catch (e) {
    resetStream('这条对话打不开', String((e && e.message) || e));
    return;
  }
  const msgs = r.messages || [];
  if (!msgs.length) {
    resetStream('这条对话没有留下转录', '可能这一轮当时还没跑完，或者是旧版本产生的运行记录。');
    return;
  }
  stream.innerHTML = '';
  let title = '';
  for (const m of msgs) {
    /* 新结构:正文在 blocks[] 里(text / attachment),停止原因在 usage 里。
       老数据只有 m.text,这里一并兼容 —— 迁移前后的会话都能打开。 */
    const blocks = Array.isArray(m.blocks) ? m.blocks : null;
    const textOf = (x) => {
      if (!blocks) return x.text || '';
      return blocks.filter((b) => b.type === 'text').map((b) => b.text || '').join('\n');
    };
    const attsOf = (x) => {
      if (!blocks) return x.attachments || [];
      const out = [];
      for (const b of blocks) if (b.type === 'attachment') out.push(...(b.items || []));
      return out;
    };
    const usage = m.usage || {};
    const stop = m.stop || usage.stop_reason || '';
    const steps = m.steps || usage.steps || 0;

    if (m.role === 'user') {
      const utext = textOf(m);
      if (!title && utext) title = utext;
      const wrap = el('div', 'msg user');
      const ub = el('div', 'body');
      ub.appendChild(el('div', null, utext || '（只说附件）'));
      for (const a of attsOf(m)) {
        const chip = el('span', 'attach-chip');
        chip.appendChild(el('span', 'nm', a.id || a.name || '附件'));
        chip.appendChild(el('b', null, a.kind === 'image' ? '图片' : '文本'));
        ub.appendChild(chip);
      }
      wrap.appendChild(ub);
      stream.appendChild(wrap);
    } else if (m.role === 'assistant') {
      const wrap = el('div', 'msg agent');
      wrap.appendChild(el('div', 'who', '智能体 · ' + (usage.target || m.target || '')));
      const body = el('div', 'body');
      body.appendChild(el('div', null, textOf(m) || '(这一轮没有给出结论)'));
      if (stop) {
        body.appendChild(el('div', 'stopline',
          '停止原因 ' + stop + (steps ? ' · ' + steps + ' 步' : '')));
      }
      wrap.appendChild(body);
      stream.appendChild(wrap);
    }
  }
  if ($('task-title')) $('task-title').textContent = (title || '巡检会话').slice(0, 30);
  scrollBottom(true);
}

/** 抽屉叠在基线之上，从上方压下来。关掉时原样露出下面那层，不必判断"从哪来"。 */
function openSheet() {
  const s = $('sheet');
  s.classList.add('enter-down');
  void s.offsetWidth;
  s.classList.add('on');
}
function closeSheet() { $('sheet').classList.remove('on'); }

function switchView(name) {
  if (name === 'loop') { closeSheet(); return; }
  state.view = name;
  openSheet();
  document.querySelectorAll('#views .view').forEach((v) => v.classList.toggle('active', v.id === 'view-' + name));  const meta = {
    report: ['巡检 / 报告与告警', '报告与告警'],
    history: ['巡检 / 历史记录', '巡检历史'],
    assets: ['数据 / 资产底账', '资产底账'],
    eval: ['数据 / 证据与闭环', '证据与闭环'],
    rules: ['数据 / 生效规则', '生效规则'],
    caps: ['系统 / 能力清单', '能力清单'],
    automation: ['系统 / 周期巡检', '周期巡检'],
    config: ['系统 / 配置编辑', '配置编辑'],
  }[name];
  if (meta) {
    const kicker = $('current-view-kicker');
    const title = $('current-view-title');
    if (kicker) kicker.textContent = meta[0];
    if (title) title.textContent = meta[1];
  }
  /* 导出只在报告页出现：别的页面没有"要导出的东西"，
     常驻一个按钮只会让人猜它导出什么。 */
  const exp = $('export-menu');
  if (exp) {
    const on = name === 'report';
    exp.style.display = on ? '' : 'none';
    if (!on) exp.classList.remove('open');
  }
}

/* ============ 本单位敏感信息定义 ============ */
/* 一台机器上可能有多个站点/多家单位,所以定义是可保存的多份对象,
   周期规则各自选一套。保存前后端会逐条验(正则能不能编译、落点是否合法)。 */
const PROF = { items: [], editing: '' };

async function renderProfiles() {
  const box = $('prof-list');
  if (!box) return;
  const r = await api('/api/profiles');
  PROF.items = r.items || [];
  $('prof-hint').textContent = PROF.items.length ? `${PROF.items.length} 套定义` : '还没有自定义定义';
  box.innerHTML = '';

  const sel = $('auto-profile');
  const keep = sel.value;
  sel.innerHTML = '';
  const opt0 = document.createElement('option');
  opt0.value = '';
  opt0.textContent = '出厂口径（只用 rules.json）';
  sel.appendChild(opt0);
  for (const p of PROF.items) {
    const o = document.createElement('option');
    o.value = p.id;
    o.textContent = `${p.name}（${(p.keywords || []).length} 关键词 / ${(p.regex || []).length} 正则 / ${(p.paths || []).length} 落点）`;
    sel.appendChild(o);
  }
  sel.value = keep;

  if (!PROF.items.length) {
    const e = el('div', 'auto-empty');
    e.appendChild(el('b', null, '还没有本单位定义'));
    e.appendChild(el('span', null, '下面填一套：只有这家站点才会出现的项目代号、内部工号格式、不该外放的文件名。'));
    box.appendChild(e);
    return;
  }
  for (const p of PROF.items) {
    const c = el('div', 'rule');
    const h = el('div', 'rh');
    h.appendChild(el('span', 'rn', p.name || p.id));
    h.appendChild(el('span', 'rt', p.id));
    const rs = el('div', 'rs');
    h.appendChild(rs);
    c.appendChild(h);
    const m = el('div', 'rm');
    const add = (label, value) => {
      const s = el('span');
      s.appendChild(el('i', null, label));
      s.appendChild(document.createTextNode(' '));
      s.appendChild(el('b', null, value));
      m.appendChild(s);
    };
    add('关键词', String((p.keywords || []).length));
    add('正则', String((p.regex || []).length));
    add('落点', String((p.paths || []).length));
    add('文件类型', (p.file_types || []).join(' / ') || '—');
    if (p.updated_at) add('更新', fmtTime(p.updated_at));
    c.appendChild(m);
    const act = el('div', 'ract');
    const bEdit = el('button', 'ghost', '编辑');
    bEdit.addEventListener('click', () => fillProfileForm(p));
    const bDel = el('button', 'ghost danger', '删除');
    bDel.addEventListener('click', async () => {
      if (!window.confirm(`删除定义「${p.name}」？引用它的周期规则会回到出厂口径。`)) return;
      try {
        await api('/api/profiles', { method: 'POST', body: JSON.stringify({ action: 'delete', id: p.id }) });
        if (PROF.editing === p.id) fillProfileForm({});
        renderProfiles();
      } catch (e) { console.warn(e.message); }
    });
    for (const b of [bEdit, bDel]) act.appendChild(b);
    c.appendChild(act);
    box.appendChild(c);
  }
}

function linesToArr(id) {
  return ($(id).value || '')
    .split('\n')
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

function fillProfileForm(p) {
  PROF.editing = p && p.id ? p.id : '';
  $('prof-name').value = (p && p.name) || '';
  $('prof-keywords').value = ((p && p.keywords) || []).join('\n');
  $('prof-regex').value = ((p && p.regex) || []).join('\n');
  $('prof-samples').value = ((p && p.samples) || []).join('\n');
  $('prof-paths').value = ((p && p.paths) || []).join('\n');
  $('prof-types').value = ((p && p.file_types) || []).join('\n');
  $('prof-msg').className = 'note';
  $('prof-msg').textContent = PROF.editing ? `正在编辑 ${PROF.editing}` : '';
}

async function saveProfile() {
  const msg = $('prof-msg');
  const profile = {
    id: PROF.editing || '',
    name: $('prof-name').value.trim(),
    keywords: linesToArr('prof-keywords'),
    regex: linesToArr('prof-regex'),
    samples: linesToArr('prof-samples'),
    paths: linesToArr('prof-paths'),
    file_types: linesToArr('prof-types'),
  };
  msg.className = 'note';
  msg.textContent = '保存中…';
  try {
    const r = await api('/api/profiles', { method: 'POST', body: JSON.stringify({ action: 'save', profile }) });
    PROF.editing = r.item.id;
    msg.textContent = `已保存：${r.item.id}`;
    await renderProfiles();
    $('auto-profile').value = r.item.id;
  } catch (e) {
    msg.className = 'err';
    msg.textContent = '没保存：' + e.message;
  }
}

/* ============ 周期巡检 ============ */
/* 数据来自 /api/automations:后端算好 next_at 与 next_run_at,前端只负责摆放。
   所有时间都用「还有多久」而不是裸时间戳 —— 巡检员关心的是"什么时候跑",不是绝对值。 */
const AUTO = { items: [], editing: '' };

function fmtIn(iso) {
  if (!iso) return '—';
  const t = Date.parse(iso);
  if (!t) return '—';
  const d = Math.round((t - Date.now()) / 1000);
  if (d <= 0) return '即将开始';
  if (d < 60) return d + ' 秒后';
  if (d < 3600) return Math.round(d / 60) + ' 分钟后';
  if (d < 86400) return (d / 3600).toFixed(1).replace(/\.0$/, '') + ' 小时后';
  return Math.round(d / 86400) + ' 天后';
}

async function renderAutomationView() {
  const box = $('auto-list');
  if (!box) return;
  const r = await api('/api/automations');
  AUTO.items = r.items || [];
  box.innerHTML = '';
  const enabled = AUTO.items.filter((x) => x.enabled).length;
  $('auto-hint').textContent = AUTO.items.length
    ? `${AUTO.items.length} 条规则 · ${enabled} 条在跑`
    : '还没有规则';
  const badge = $('auto-badge');
  if (badge) { badge.textContent = enabled ? enabled + ' 条在跑' : ''; badge.classList.toggle('on', enabled > 0); }

  if (!AUTO.items.length) {
    const e = el('div', 'auto-empty');
    e.appendChild(el('b', null, '还没有周期规则'));
    e.appendChild(el('span', null, '在下面填一个目标和周期，它能自己跑；跑完会与上一轮比对，变了才告警。'));
    box.appendChild(e);
    renderProfiles().catch(() => {});
    return;
  }
  for (const a of AUTO.items) box.appendChild(ruleCard(a));
  renderProfiles().catch(() => {});
}

function ruleCard(a) {
  const c = el('div', 'rule' + (a.enabled ? '' : ' off'));
  const h = el('div', 'rh');
  h.appendChild(el('span', 'rn', a.name || a.domain));
  h.appendChild(el('span', 'rt', a.domain));
  h.appendChild(el('span', 'st-dot' + (a.enabled ? ' on' : ''), a.enabled ? '在跑' : '已停'));
  const rs = el('div', 'rs');
  if (a.due) rs.appendChild(el('span', 'chip', '即将触发'));
  h.appendChild(rs);
  c.appendChild(h);

  const m = el('div', 'rm');
  const add = (label, value) => {
    const s = el('span');
    s.appendChild(el('i', null, label));
    s.appendChild(document.createTextNode(' '));
    s.appendChild(el('b', null, value));
    m.appendChild(s);
  };
  add('周期', a.cycle_text || '—');
  add('范围', a.scope_label || '—');
  add('下次', a.enabled ? fmtIn(a.next_run_at) : '已停用');
  add('已跑', `${a.run_count || 0} 轮`);
  add('告警', `${a.change_count || 0} 次变化`);
  if (a.last_run_at) add('上次', fmtTime(a.last_run_at));
  c.appendChild(m);

  const act = el('div', 'ract');
  const bRun = el('button', 'ghost', '马上跑一次');
  bRun.addEventListener('click', async () => {
    bRun.disabled = true;
    bRun.textContent = '已排队…';
    try {
      await api('/api/automations', { method: 'POST', body: JSON.stringify({ action: 'run', id: a.id }) });
      setTimeout(() => { renderAutomationView(); state.cache = {}; renderRail(); }, 2000);
    } catch (e) {
      bRun.textContent = '没排上';
      console.warn(e.message);
    }
  });
  const bToggle = el('button', 'ghost', a.enabled ? '停用' : '启用');
  bToggle.addEventListener('click', async () => {
    try {
      await api('/api/automations', { method: 'POST', body: JSON.stringify({ action: 'toggle', id: a.id }) });
      renderAutomationView();
    } catch (e) { console.warn(e.message); }
  });
  const bEdit = el('button', 'ghost', '编辑');
  bEdit.addEventListener('click', () => fillAutoForm(a));
  const bDel = el('button', 'ghost danger', '删除');
  bDel.addEventListener('click', async () => {
    if (!window.confirm(`删除周期规则「${a.name || a.domain}」？已跑过的记录会保留。`)) return;
    try {
      await api('/api/automations', { method: 'POST', body: JSON.stringify({ action: 'delete', id: a.id }) });
      renderAutomationView();
    } catch (e) { console.warn(e.message); }
  });
  for (const b of [bRun, bToggle, bEdit, bDel]) act.appendChild(b);
  c.appendChild(act);
  return c;
}

function autoKindChanged() {
  const kind = $('auto-kind').value;
  $('auto-every-wrap').hidden = kind !== 'interval';
  $('auto-at-wrap').hidden = kind === 'interval';
  $('auto-wd-wrap').hidden = kind !== 'weekly';
}

/* 范围预设与检查项是同一件事的两种说法:
   选预设就自动勾上对应的检查项;自己勾检查项时把预设标成"自定义"。 */
const SCOPE_CHECKS = {
  full: ['full'], leak: ['leak'], integrity: ['integrity'],
  recon: ['recon'], retest: ['retest'],
};

function syncChecksFromScope() {
  const want = SCOPE_CHECKS[$('auto-scope').value] || ['full'];
  document.querySelectorAll('.auto-check').forEach((c) => { c.checked = want.includes(c.value); });
}

function checkedChecks() {
  return Array.from(document.querySelectorAll('.auto-check')).filter((c) => c.checked).map((c) => c.value);
}

function fillAutoForm(a) {
  AUTO.editing = a.id || '';
  $('auto-form-title').textContent = a.id ? `编辑规则 ${a.id}` : '新建周期规则';
  $('auto-domain').value = a.domain || '';
  $('auto-scope').value = a.scope || 'full';
  $('auto-kind').value = a.kind || 'interval';
  $('auto-every').value = a.every_min || 360;
  $('auto-hour').value = a.at_hour != null ? a.at_hour : 3;
  $('auto-min').value = a.at_min != null ? a.at_min : 0;
  $('auto-weekday').value = String(a.weekday != null ? a.weekday : 1);
  $('auto-name').value = a.name || '';
  $('auto-enabled').checked = a.enabled !== 0 && a.enabled !== false;
  const checks = (a.checks && a.checks.length) ? a.checks : SCOPE_CHECKS[a.scope || 'full'];
  document.querySelectorAll('.auto-check').forEach((c) => { c.checked = checks.includes(c.value); });
  const sel = $('auto-profile');
  if (sel) sel.value = a.profile_id || '';
  autoKindChanged();
  $('auto-msg').textContent = '';
  $('auto-msg').className = 'note';
}

async function saveAutomation() {
  const msg = $('auto-msg');
  const checks = checkedChecks();
  const rule = {
    id: AUTO.editing || '',
    name: $('auto-name').value.trim(),
    domain: $('auto-domain').value.trim(),
    scope: $('auto-scope').value,
    checks,
    profile_id: $('auto-profile') ? $('auto-profile').value : '',
    kind: $('auto-kind').value,
    every_min: Number($('auto-every').value) || 0,
    at_hour: Number($('auto-hour').value) || 0,
    at_min: Number($('auto-min').value) || 0,
    weekday: Number($('auto-weekday').value) || 0,
    enabled: $('auto-enabled').checked ? 1 : 0,
  };
  msg.className = 'note';
  msg.textContent = '保存中…';
  try {
    const r = await api('/api/automations', { method: 'POST', body: JSON.stringify({ action: 'save', rule }) });
    msg.textContent = `已保存：${r.item.id}，下次 ${fmtIn(r.item.next_run_at)}`;
    AUTO.editing = r.item.id;
    $('auto-form-title').textContent = `编辑规则 ${r.item.id}`;
    await renderAutomationView();
  } catch (e) {
    msg.className = 'err';
    msg.textContent = '没保存：' + e.message;
  }
}

$('auto-kind').addEventListener('change', autoKindChanged);
$('auto-scope').addEventListener('change', syncChecksFromScope);
$('auto-save').addEventListener('click', saveAutomation);
$('auto-reset').addEventListener('click', () => { fillAutoForm({}); syncChecksFromScope(); });
$('prof-save').addEventListener('click', saveProfile);
$('prof-reset').addEventListener('click', () => fillProfileForm({}));

/* 周期巡检是后台在跑的：界面要自己跟上，不能让用户以为"点了没反应"。
   页面停在自动化视图时每 8 秒刷新一次规则状态；停在工作台时每 30 秒刷新
   右栏与最近记录 —— 定时那一轮跑完会自然出现在这里。 */
let autoTick = 0;
setInterval(() => {
  const sheetOpen = $('sheet').classList.contains('on');
  const onAuto = sheetOpen && $('view-automation') && $('view-automation').classList.contains('active');
  if (onAuto) { renderAutomationView().catch(() => {}); return; }
  autoTick++;
  if (autoTick % 4 === 0 && !sheetOpen) {
    state.cache = {};
    renderRecent();
    renderRail();
    api('/api/status').then(renderStatus).catch(() => {});
  }
}, 8000);

/* ============ 权限审批 ============ */
const APPR = { items: [], active: 'ask', pendingWarn: '' };

async function renderApprovals() {
  const r = await api('/api/approvals');
  APPR.items = r.items || [];
  APPR.active = r.active || 'ask';
  const sel = $('approval-select');
  if (sel) {
    sel.innerHTML = '';
    for (const p of APPR.items) {
      const o = document.createElement('option');
      o.value = p.id;
      o.textContent = p.mode === 'allow_all' ? '⚠ ' + p.name : p.name;
      sel.appendChild(o);
    }
    sel.value = APPR.active;
    sel.classList.toggle('warn', APPR.active === 'allow_all');
    sel.title = '审批策略：' + (r.modeText || '');
  }
  const box = $('appr-list');
  if (box) {
    box.innerHTML = '';
    for (const p of APPR.items) box.appendChild(apprCard(p));
    $('appr-hint').textContent = APPR.items.length + ' 条策略 · 当前：' + (r.modeText || '');
  }
}

function apprCard(p) {
  const c = el('div', 'rule' + (p.active ? '' : ' off'));
  const h = el('div', 'rh');
  h.appendChild(el('span', 'rn', p.name));
  h.appendChild(el('span', 'rt', p.id));
  h.appendChild(el('span', 'st-dot' + (p.active ? ' on' : ''), p.active ? '生效中' : '未启用'));
  c.appendChild(h);
  const m = el('div', 'rm');
  const add = (label, value) => {
    const s = el('span');
    s.appendChild(el('i', null, label));
    s.appendChild(document.createTextNode(' '));
    s.appendChild(el('b', null, value));
    m.appendChild(s);
  };
  add('模式', p.mode === 'ask' ? '每个动作都问' : p.mode === 'allow_all' ? '全部自动放行' : '自定义规则');
  add('性质', p.builtin ? '内置' : '预设');
  if (p.rules) add('规则', String(p.rules.split('\n').filter(Boolean).length) + ' 条');
  c.appendChild(m);
  if (p.note) c.appendChild(el('div', 'cd', p.note));

  const act = el('div', 'ract');
  if (!p.active) {
    const bUse = el('button', 'ghost', '启用');
    bUse.addEventListener('click', () => applyApproval(p.id));
    act.appendChild(bUse);
  }
  if (!p.builtin) {
    const bEdit = el('button', 'ghost', '编辑');
    bEdit.addEventListener('click', () => {
      $('appr-name').value = p.name || '';
      $('appr-rules').value = p.rules || '';
      $('appr-msg').className = 'note';
      $('appr-msg').textContent = `正在编辑 ${p.id}（保存会覆盖它）`;
      APPR.editing = p.id;
    });
    const bDel = el('button', 'ghost danger', '删除');
    bDel.addEventListener('click', async () => {
      if (!window.confirm(`删除策略「${p.name}」？`)) return;
      try {
        await api('/api/approvals', { method: 'POST', body: JSON.stringify({ action: 'delete', id: p.id }) });
        await renderApprovals();
        renderStatus(await api('/api/status'));
      } catch (e) { console.warn(e.message); }
    });
    act.appendChild(bEdit);
    act.appendChild(bDel);
  }
  c.appendChild(act);
  return c;
}

async function applyApproval(id) {
  try {
    const r = await api('/api/approvals', { method: 'POST', body: JSON.stringify({ action: 'activate', id }) });
    APPR.active = r.active;
    await renderApprovals();
    renderStatus(await api('/api/status'));
  } catch (e) {
    console.warn(e.message);
  }
}

/* 顶栏切换:选到"全部允许"要先过一次警告 */
$('approval-select').addEventListener('change', (e) => {
  const id = e.target.value;
  const p = APPR.items.find((x) => x.id === id);
  if (p && p.mode === 'allow_all') {
    APPR.pendingWarn = id;
    $('warn-modal').classList.add('on');
    return;
  }
  applyApproval(id);
});
$('warn-cancel').addEventListener('click', () => {
  $('warn-modal').classList.remove('on');
  $('approval-select').value = APPR.active;
  APPR.pendingWarn = '';
});
$('warn-ok').addEventListener('click', async () => {
  const id = APPR.pendingWarn;
  $('warn-modal').classList.remove('on');
  APPR.pendingWarn = '';
  if (id) await applyApproval(id);
});
$('appr-save').addEventListener('click', async () => {
  const msg = $('appr-msg');
  const policy = {
    id: APPR.editing || '',
    name: $('appr-name').value.trim(),
    mode: 'custom',
    rules: $('appr-rules').value,
  };
  msg.className = 'note';
  msg.textContent = '保存中…';
  try {
    const r = await api('/api/approvals', { method: 'POST', body: JSON.stringify({ action: 'save', policy }) });
    APPR.editing = r.id;
    msg.textContent = '已保存：' + r.id;
    await renderApprovals();
  } catch (e) {
    msg.className = 'err';
    msg.textContent = '没保存：' + e.message;
  }
});
$('appr-reset').addEventListener('click', () => {
  APPR.editing = '';
  $('appr-name').value = '';
  $('appr-rules').value = '';
  $('appr-msg').textContent = '';
});

/* 审批条：贴在输入框上方浮着。
   它是"现在要做的决定"，不是历史，所以不进聊天流；一轮里只有一条，
   连续多个动作被拦时用计数表示"还有 N 个在排队"。 */
const AB = { id: '', queue: 0, busy: false };

function showApprovalBar(e) {
  AB.id = e.id;
  AB.queue += 1;
  $('ab-tool').textContent = e.tool || '';
  $('ab-policy').textContent = e.policy ? '策略：' + e.policy : '';
  $('ab-count').textContent = AB.queue > 1 ? `还有 ${AB.queue} 个动作在等` : '';
  $('ab-args').textContent = e.args || '{}';
  $('ab-yes').disabled = false;
  $('ab-no').disabled = false;
  $('ab-yes').textContent = '允许';
  $('ab-no').textContent = '拒绝';
  $('approval-bar').classList.remove('ok', 'no');
  $('approval-bar').classList.add('on');
  $('ab-yes').focus();
}

function hideApprovalBar(delay) {
  setTimeout(() => {
    $('approval-bar').classList.remove('on');
    AB.id = '';
    AB.queue = 0;
  }, delay || 0);
}

async function decideApproval(ok) {
  if (!AB.id || AB.busy) return;
  AB.busy = true;
  $('ab-yes').disabled = true;
  $('ab-no').disabled = true;
  try {
    await api('/api/approval', { method: 'POST', body: JSON.stringify({ id: AB.id, decision: ok ? 'allow' : 'deny' }) });
    $('approval-bar').classList.add(ok ? 'ok' : 'no');
    $('ab-yes').textContent = ok ? '已允许' : '允许';
    $('ab-no').textContent = ok ? '拒绝' : '已拒绝';
    AB.queue = Math.max(0, AB.queue - 1);
    AB.id = '';
    hideApprovalBar(ok ? 900 : 1400);
  } catch (err) {
    $('ab-args').textContent = '提交失败：' + err.message;
    $('ab-yes').disabled = false;
    $('ab-no').disabled = false;
  } finally {
    AB.busy = false;
  }
}

$('ab-yes').addEventListener('click', () => decideApproval(true));
$('ab-no').addEventListener('click', () => decideApproval(false));

/* ============ 导出 ============ */
/* 五种格式都由后端渲染(/api/export),前端只负责点一个链接 —— 
   这样"页面上的数字"和"文件里的数字"不会有两套统计逻辑。 */
function closeExportMenu() { $('export-menu').classList.remove('open'); }

$('btn-export').addEventListener('click', (e) => {
  e.stopPropagation();
  $('export-menu').classList.toggle('open');
});
document.addEventListener('click', (e) => {
  if (!$('export-menu').contains(e.target)) closeExportMenu();
});
document.querySelectorAll('#export-list button').forEach((b) => {
  b.addEventListener('click', () => {
    closeExportMenu();
    const fmt = b.dataset.fmt;
    const rep = (state.cache['reports:1'] || {}).items || [];
    const id = rep.length ? rep[0].id : '';
    const url = '/api/export?format=' + encodeURIComponent(fmt) + (id ? '&report=' + encodeURIComponent(id) : '') +
                (BW_TOKEN ? '&t=' + encodeURIComponent(BW_TOKEN) : '');
    window.location.href = url;
  });
});

/* ============ 配置编辑 ============ */
/* 支持编辑:rules.json(检测口径)、mcp.json(MCP 服务器)、skills\*.md(技能)、tools\*.json(外部工具)。
   安全边界在后端:只有这些白名单文件可写,JSON 必须先校验通过,写前自动留 .bak。 */
const CFG = { files: [], current: null, dirty: false };

/* ============ 规则设置：把 rules.json 按类型拆成子页 ============ */

const SET_SCHEMA = [
  { id: 'basic', title: '基础', desc: '规则版本',
    fields: [{ k: 'version', label: '规则版本', type: 'text' }] },
  { id: 'ui', title: '界面', desc: '布局与观感（记在本机）' },
  { id: 'severity', title: '严重等级', desc: '等级名称与排序权重',
    fields: [{ k: 'severity_levels', label: '等级（权重越大越严重）', type: 'table',
      cols: [{ k: 'name', label: '名称', w: 220 }, { k: 'rank', label: '权重', type: 'number', w: 120 }] }] },
  { id: 'alerts', title: '告警', desc: '什么等级走什么渠道',
    fields: [
      { k: 'alerts.min_rank', label: '告警最低权重', type: 'number', hint: '低于它的只进报告，不进告警' },
      { k: 'alerts.immediate_rank', label: '立即通知权重', type: 'number' },
      { k: 'alerts.channel_immediate', label: '立即通知渠道', type: 'text' },
      { k: 'alerts.channel_normal', label: '普通通知渠道', type: 'text' }] },
  { id: 'patterns', title: '敏感信息', desc: '正文里出现即命中',
    fields: [{ k: 'patterns.sensitive', label: '识别规则', type: 'table',
      cols: [{ k: 'kind', label: '类型', w: 140 }, { k: 'pattern', label: '正则（内置方言）', mono: true },
             { k: 'severity', label: '等级', w: 100 }] }] },
  { id: 'markers', title: '页面标记', desc: '目录索引与口令字段',
    fields: [
      { k: 'markers.dir_listing', label: '目录索引标记（一行一个）', type: 'lines' },
      { k: 'markers.login_password_field', label: '口令字段名', type: 'text' }] },
  { id: 'payloads', title: '注入载荷', desc: '布尔差分成对使用',
    fields: [{ k: 'payloads.boolean_diff', label: '载荷族', type: 'table',
      cols: [{ k: 'context', label: '场景', w: 110 }, { k: 'true', label: '恒真', mono: true },
             { k: 'false', label: '恒假', mono: true }] }] },
  { id: 'passwords', title: '弱口令', desc: '口令强度评估用的字典',
    fields: [{ k: 'weak_passwords', label: '字典（一行一个）', type: 'lines' }] },
  { id: 'probing', title: '探测参数', desc: '每轮探多少、等多久',
    fields: [
      { k: 'probing.max_paths', label: '最多落点', type: 'number' },
      { k: 'probing.max_dirs', label: '最多目录', type: 'number' },
      { k: 'probing.max_params', label: '最多参数', type: 'number' },
      { k: 'probing.timeout_ms', label: '单请求超时（毫秒）', type: 'number' },
      { k: 'probing.similar_bytes', label: '软 404 比对字节', type: 'number' },
      { k: 'probing.similar_ratio', label: '相似度阈值', type: 'number', step: '0.01' }] },
  { id: 'paths', title: '落点与目录', desc: '可能误发布的文件与目录',
    fields: [
      { k: 'sensitive_paths', label: '落点（一行一个）', type: 'lines' },
      { k: 'dir_candidates', label: '目录（一行一个）', type: 'lines' }] },
  { id: 'signatures', title: '内容特征', desc: '按正文特征判定文件性质',
    fields: [{ k: 'signatures', label: '特征', type: 'table',
      cols: [{ k: 'name', label: '名称' }, { k: 'kind', label: '类别' }, { k: 'severity', label: '等级' },
             { k: 'tag', label: '指纹' }, { k: 'body_any', label: '命中任一（一行一个）', type: 'lines' },
             { k: 'body_not_any', label: '排除（一行一个）', type: 'lines' },
             { k: 'min_bytes', label: '最小字节', type: 'number' }] }] },
  { id: 'headers', title: '安全响应头', desc: '缺哪一条算弱配置',
    fields: [{ k: 'weak_headers', label: '期望头', type: 'table',
      cols: [{ k: 'name', label: '头名', w: 170 }, { k: 'title', label: '说明', w: 190 }, { k: 'severity', label: '等级', w: 90 },
             { k: 'only_https', label: '仅 HTTPS', type: 'bool', w: 90 },
             { k: 'impact', label: '影响' }, { k: 'fix', label: '修复建议' }] }] },
  { id: 'org', title: '单位口径', desc: '本单位的关键词与特征',
    fields: [
      { k: 'profile_keywords', label: '敏感信息关键词', type: 'lines' },
      { k: 'profile_file_types', label: '敏感文件类型', type: 'lines' },
      { k: 'server_header_keys', label: '版本泄露头', type: 'lines' },
      { k: 'error_signatures', label: '错误回显特征', type: 'lines' },
      { k: 'dangerous_methods', label: '危险方法', type: 'lines' },
      { k: 'suspicious_tlds', label: '可疑域名后缀', type: 'lines' }] },
  { id: 'tamper', title: '篡改判定', desc: '外链数量阈值',
    fields: [{ k: 'tamper.report_external_hosts', label: '外链超过多少算异常', type: 'number' }] },
  { id: 'skills', title: '技能', desc: '智能体的专业能力' },
  { id: 'tools', title: '工具', desc: '智能体能做的动作' },
  { id: 'models', title: '模型', desc: '接哪家的模型（可多家兜底）' },
  { id: 'advanced', title: '高级 · 文件', desc: '直接编辑原始文件' },
];

let RULES = null;
let SET_CURRENT = 'basic';

function getPath(obj, path) {
  return path.split('.').reduce((o, k) => (o && typeof o === 'object' ? o[k] : undefined), obj);
}
function setPath(obj, path, val) {
  const ks = path.split('.');
  let o = obj;
  for (let i = 0; i < ks.length - 1; i++) {
    if (!o[ks[i]] || typeof o[ks[i]] !== 'object') o[ks[i]] = {};
    o = o[ks[i]];
  }
  o[ks[ks.length - 1]] = val;
}

function setFieldEl(f) {
  const wrap = el('div', 'set-field');
  const head = el('div', 'set-field-head');
  head.appendChild(el('span', 'set-label', f.label));
  wrap.appendChild(head);
  if (f.hint) wrap.appendChild(el('div', 'set-hint', f.hint));
  const v = getPath(RULES || {}, f.k);

  if (f.type === 'lines') {
    const ta = el('textarea', 'set-lines');
    ta.rows = Math.min(12, Math.max(3, (Array.isArray(v) ? v.length : 3)));
    ta.value = Array.isArray(v) ? v.join('\n') : '';
    ta.dataset.path = f.k;
    wrap.appendChild(ta);
  } else if (f.type === 'number') {
    const inp = el('input', 'set-input');
    inp.type = 'number';
    inp.step = f.step || '1';
    inp.value = (v === undefined || v === null) ? '' : v;
    inp.dataset.path = f.k;
    wrap.appendChild(inp);
  } else if (f.type === 'bool') {
    const inp = el('input');
    inp.type = 'checkbox';
    inp.checked = !!v;
    inp.dataset.path = f.k;
    wrap.appendChild(inp);
  } else if (f.type === 'table') {
    wrap.appendChild(setTableEl(f, v));
  } else {
    const inp = el('input', 'set-input');
    inp.value = (v === undefined || v === null) ? '' : v;
    inp.dataset.path = f.k;
    wrap.appendChild(inp);
  }
  return wrap;
}

function setTableRow(f, row, idx) {
  const tr = el('tr');
  if (idx !== undefined && idx !== null) tr.dataset.idx = idx;
  for (const c of f.cols) {
    const td = el('td');
    let ctl;
    if (c.type === 'lines') {
      ctl = el('textarea', 'set-cell-lines');
      ctl.rows = 2;
      ctl.value = Array.isArray(row[c.k]) ? row[c.k].join('\n') : '';
      ctl.dataset.kind = 'lines';
    } else if (c.type === 'number') {
      ctl = el('input', 'set-cell');
      ctl.type = 'number';
      ctl.value = (row[c.k] === undefined || row[c.k] === null) ? '' : row[c.k];
      ctl.dataset.kind = 'number';
    } else if (c.type === 'bool') {
      ctl = el('input');
      ctl.type = 'checkbox';
      ctl.checked = !!Number(row[c.k]);
      ctl.dataset.kind = 'bool';
    } else {
      ctl = el('input', 'set-cell' + (c.mono ? ' mono' : ''));
      ctl.value = (row[c.k] === undefined || row[c.k] === null) ? '' : row[c.k];
      ctl.dataset.kind = 'text';
    }
    ctl.dataset.col = c.k;
    td.appendChild(ctl);
    tr.appendChild(td);
  }
  const td = el('td', 'set-cell-x');
  const del = el('button', 'ghost tiny', '×');
  del.type = 'button';
  del.title = '删除这一行';
  del.addEventListener('click', () => tr.remove());
  td.appendChild(del);
  tr.appendChild(td);
  return tr;
}

function setTableEl(f, rows) {
  const box = el('div', 'set-table-wrap');
  const t = el('table', 'set-table');
  const thead = el('thead');
  const hr = el('tr');
  for (const c of f.cols) {
    const th = el('th', null, c.label);
    if (c.w) th.style.width = c.w + 'px';
    hr.appendChild(th);
  }
  hr.appendChild(el('th', null, ''));
  thead.appendChild(hr);
  t.appendChild(thead);
  const tb = el('tbody');
  tb.dataset.path = f.k;
  (Array.isArray(rows) ? rows : []).forEach((r, i) => tb.appendChild(setTableRow(f, r, i)));
  t.appendChild(tb);
  box.appendChild(t);
  const add = el('button', 'ghost tiny', '＋ 增加一行');
  add.type = 'button';
  add.addEventListener('click', () => tb.appendChild(setTableRow(f, {})));
  box.appendChild(add);
  return box;
}

function setRenderNav() {
  const nav = $('set-nav');
  if (!nav) return;
  nav.innerHTML = '';
  for (const g of SET_SCHEMA) {
    const b = el('button', 'set-tab' + (SET_CURRENT === g.id ? ' active' : ''), g.title);
    b.type = 'button';
    b.addEventListener('click', () => {
      SET_CURRENT = g.id;
      setRenderNav();
      setRenderPage();
    });
    nav.appendChild(b);
  }
}

function setRenderPage() {
  const page = SET_SCHEMA.find((g) => g.id === SET_CURRENT) || SET_SCHEMA[0];
  const form = $('set-form');
  const adv = $('cfg-advanced');
  const head = document.querySelector('.set-head');
  const foot = $('set-foot');
  const isAdv = page.id === 'advanced';
  const isUi = page.id === 'ui';
  const isSkills = page.id === 'skills';
  const isTools = page.id === 'tools';
  const isModels = page.id === 'models';
  if ($('set-title')) $('set-title').textContent = page.title;
  if ($('set-desc')) $('set-desc').textContent = page.desc || '';
  if (head) head.style.display = '';
  if (foot) foot.style.display = (isAdv || isUi || isSkills || isTools || isModels) ? 'none' : '';
  if (form) form.style.display = (isAdv || isUi || isSkills || isTools || isModels) ? 'none' : '';
  if (adv) adv.style.display = isAdv ? 'block' : 'none';
  const uiPanel = $('ui-panel');
  if (uiPanel) uiPanel.style.display = isUi ? 'block' : 'none';
  const capPanel = $('cap-panel');
  if (capPanel) capPanel.style.display = (isSkills || isTools) ? 'block' : 'none';
  const modelPanel = $('model-panel');
  if (modelPanel) modelPanel.style.display = isModels ? 'block' : 'none';
  if (isUi) return;
  if (isSkills || isTools) { capsOpen(isSkills ? 'skill' : 'tool'); return; }
  if (isModels) { modelsOpen(); return; }
  if (isAdv) {
    renderConfigFiles().catch(() => {});
    return;
  }
  form.innerHTML = '';
  for (const f of page.fields || []) form.appendChild(setFieldEl(f));
  if ($('set-msg')) $('set-msg').textContent = '';
}

function setCollect() {
  const out = JSON.parse(JSON.stringify(RULES || {}));
  const page = SET_SCHEMA.find((g) => g.id === SET_CURRENT);
  for (const f of (page && page.fields) || []) {
    if (f.type === 'table') {
      const tb = document.querySelector(`tbody[data-path="${f.k}"]`);
      if (!tb) continue;
      const orig = getPath(RULES || {}, f.k);
      const rows = [];
      for (const tr of Array.from(tb.querySelectorAll('tr'))) {
        /* 以原始那一行为底：schema 没覆盖到的字段原样保留，不因为"界面没画"就被删掉 */
        const idx = tr.dataset.idx === undefined ? -1 : Number(tr.dataset.idx);
        const base = Array.isArray(orig) && idx >= 0 && orig[idx] ? JSON.parse(JSON.stringify(orig[idx])) : {};
        const row = base;
        for (const c of f.cols) {
          const ctl = tr.querySelector(`[data-col="${c.k}"]`);
          if (!ctl) continue;
          if (ctl.dataset.kind === 'number') row[c.k] = Number(ctl.value) || 0;
          else if (ctl.dataset.kind === 'bool') row[c.k] = ctl.checked ? 1 : 0;
          else if (ctl.dataset.kind === 'lines') {
            const arr = ctl.value.split('\n').map((s) => s.trim()).filter(Boolean);
            if (arr.length) row[c.k] = arr;
          } else if (ctl.value !== '') row[c.k] = ctl.value;
        }
        if (Object.keys(row).length) rows.push(row);
      }
      setPath(out, f.k, rows);
      continue;
    }
    const node = document.querySelector(`[data-path="${f.k}"]`);
    if (!node) continue;
    if (f.type === 'lines') {
      setPath(out, f.k, node.value.split('\n').map((s) => s.trim()).filter(Boolean));
    } else if (f.type === 'number') {
      setPath(out, f.k, Number(node.value) || 0);
    } else if (f.type === 'bool') {
      setPath(out, f.k, node.checked ? 1 : 0);
    } else {
      setPath(out, f.k, node.value);
    }
  }
  return out;
}

async function setSave() {
  const btn = $('set-save');
  if (btn) btn.disabled = true;
  const msg = $('set-msg');
  if (msg) msg.textContent = '正在保存…';
  try {
    const rules = setCollect();
    const r = await api('/api/settings', { method: 'POST', body: JSON.stringify({ rules }) });
    RULES = rules;
    if (msg) msg.textContent = '已保存并生效 · ' + (r.source || '');
    state.cache = {};
  } catch (e) {
    if (msg) msg.textContent = '保存失败：' + ((e && e.message) || e);
  } finally {
    if (btn) btn.disabled = false;
  }
}

async function setLoad(force) {
  if (RULES && !force) { setRenderNav(); setRenderPage(); return; }
  try {
    const r = await api('/api/settings');
    RULES = r.rules || {};
  } catch (e) {
    RULES = {};
  }
  setRenderNav();
  setRenderPage();
}

const setSaveBtn = $('set-save');
if (setSaveBtn) setSaveBtn.addEventListener('click', setSave);
const setResetBtn = $('set-reset');
if (setResetBtn) setResetBtn.addEventListener('click', () => setLoad(true).catch(() => {}));

/* ============ 技能 / 工具：图形化管理 ============
   加一个能力不该要求会写 front-matter、会拼 JSON。这里把同一份落盘文件用表单生成，
   并提供"用大模型起草"和"从市场导入"两条更省事的路。 */

const CAP = { kind: 'skill', data: null, editing: null };

function capApi(body) {
  return api('/api/caps', { method: 'POST', body: JSON.stringify(body) });
}

async function capsOpen(kind) {
  const changed = CAP.kind !== kind;
  CAP.kind = kind;
  if (changed) { CAP.data = null; CAP.editing = null; }
  if (!CAP.data) {
    try { CAP.data = await api('/api/caps'); }
    catch (e) { CAP.data = { skills: [], tools: [] }; }
  }
  const label = kind === 'skill' ? '技能' : '工具';
  if ($('cap-kind-label')) $('cap-kind-label').textContent = label;
  const st = (CAP.data && CAP.data.stats) || {};
  if ($('cap-stat')) {
    $('cap-stat').textContent = kind === 'skill'
      ? `共 ${st.skills || 0} 个（技能包 ${st.extSkills || 0}）`
      : `共 ${st.tools || 0} 个（外部 ${st.extTools || 0} · MCP ${st.mcpTools || 0}）`;
  }
  capsRenderList();
  capsRenderForm(CAP.editing);
}

function capsSrcTag(x) {
  const src = x.source || '内置';
  const cls = src === 'MCP' ? 'mcp' : (src === '外部' || src === '技能包' ? 'ext' : '');
  return { text: x.customized ? '已改说明' : src, cls: x.customized ? 'mine' : cls };
}

function capsRenderList() {
  const box = $('cap-list');
  if (!box) return;
  box.innerHTML = '';
  const list = CAP.kind === 'skill' ? (CAP.data.skills || []) : (CAP.data.tools || []);
  if (!list.length) {
    box.appendChild(el('div', 'muted', '还没有可用的' + (CAP.kind === 'skill' ? '技能' : '工具') + '。'));
    return;
  }
  for (const x of list) {
    const row = el('div', 'cap-item');
    const main = el('div', 'ci-main');
    const head = el('div');
    head.appendChild(el('span', 'ci-name', x.name || ''));
    if (x.title) head.appendChild(el('span', 'ci-title', x.title));
    const tag = capsSrcTag(x);
    head.appendChild(el('span', 'ci-tag' + (tag.cls ? ' ' + tag.cls : ''), tag.text));
    main.appendChild(head);
    const desc = CAP.kind === 'skill'
      ? (x.purpose || x.when || '')
      : (x.description || x.extDescription || '');
    main.appendChild(el('div', 'ci-desc', desc));
    row.appendChild(main);

    const act = el('div', 'ci-act');
    const edit = el('button', null, '编辑');
    edit.type = 'button';
    edit.addEventListener('click', () => capsEditExisting(x));
    act.appendChild(edit);
    if (x.source === '外部' || x.source === '技能包' || x.customized) {
      const del = el('button', null, '删除');
      del.type = 'button';
      del.addEventListener('click', () => capsDelete(x));
      act.appendChild(del);
    }
    row.appendChild(act);
    box.appendChild(row);
  }
}

function capsEditExisting(x) {
  if (CAP.kind === 'skill') {
    CAP.editing = {
      name: x.name || '', title: x.title || '', purpose: x.purpose || '',
      when: x.when || '', tools: x.tools || '', body: x.body || '',
      command: x.command || '', allow: !!x.allow, timeout_ms: 20000
    };
  } else {
    CAP.editing = {
      name: x.name || '', description: x.extDescription || x.description || '',
      command: x.command || '', schema: x.schema || '', kind: x.kind || '',
      allow: x.allow !== undefined ? !!x.allow : true,
      timeout_ms: x.timeout_ms || 20000
    };
  }
  capsRenderForm(CAP.editing);
  const panel = $('cap-edit');
  if (panel) panel.scrollIntoView({ block: 'nearest' });
}

function capField(label, id, value, opts) {
  const o = opts || {};
  const wrap = el('div', 'cap-field' + (o.wide ? ' wide' : ''));
  const lb = document.createElement('label');
  lb.textContent = label;
  lb.setAttribute('for', id);
  wrap.appendChild(lb);
  let ctl;
  if (o.area) {
    ctl = el('textarea');
    ctl.rows = o.rows || 4;
    ctl.value = value === undefined || value === null ? '' : value;
  } else if (o.check) {
    ctl = document.createElement('input');
    ctl.type = 'checkbox';
    ctl.checked = !!value;
  } else {
    ctl = el('input');
    if (o.num) { ctl.type = 'number'; ctl.step = o.step || '1'; } else { ctl.type = 'text'; }
    if (o.mono) ctl.classList.add('mono');
    ctl.value = value === undefined || value === null ? '' : value;
  }
  ctl.id = id;
  if (o.ph) ctl.placeholder = o.ph;
  wrap.appendChild(ctl);
  return wrap;
}

function capsRenderForm(model) {
  const box = $('cap-edit');
  if (!box) return;
  box.innerHTML = '';
  if (!model) { box.classList.remove('on'); return; }
  box.classList.add('on');

  const grid = el('div', 'cap-grid');
  if (CAP.kind === 'skill') {
    grid.appendChild(capField('名称（skill_ 开头）', 'cap-name', model.name, { ph: 'skill_my_check' }));
    grid.appendChild(capField('标题', 'cap-title', model.title, { ph: '自定义检查' }));
    grid.appendChild(capField('解决什么问题', 'cap-purpose', model.purpose, { wide: true, ph: '一句话说明' }));
    grid.appendChild(capField('什么时候该用', 'cap-when', model.when, { wide: true, ph: '用户提出…时' }));
    grid.appendChild(capField('用到的工具（逗号分隔）', 'cap-tools', model.tools, { wide: true, ph: 'site_crawl,sensitive_file_probe' }));
    grid.appendChild(capField('做法说明（给模型看）', 'cap-body', model.body, { wide: true, area: true, rows: 6 }));
    grid.appendChild(capField('额外执行的命令（可留空）', 'cap-command', model.command, { wide: true, ph: 'powershell -NoProfile -File ...' }));
    grid.appendChild(capField('允许执行命令', 'cap-allow', model.allow, { check: true }));
    grid.appendChild(capField('命令超时（毫秒）', 'cap-timeout', model.timeout_ms || 20000, { num: true }));
  } else {
    grid.appendChild(capField('名称', 'cap-name', model.name, { ph: 'my_check' }));
    grid.appendChild(capField('类型', 'cap-kind', model.kind, { ph: '外部工具' }));
    grid.appendChild(capField('说明（模型据此决定用不用）', 'cap-desc', model.description, { wide: true }));
    grid.appendChild(capField('命令（参数用 $参数名 占位）', 'cap-command', model.command, { wide: true, ph: 'powershell -NoProfile -Command "..."' }));
    grid.appendChild(capField('参数定义（JSON Schema）', 'cap-schema', model.schema, { wide: true, area: true, rows: 4, ph: '{"type":"object","properties":{...}}' }));
    grid.appendChild(capField('允许执行命令', 'cap-allow', model.allow, { check: true }));
    grid.appendChild(capField('超时（毫秒）', 'cap-timeout', model.timeout_ms || 20000, { num: true }));
  }
  box.appendChild(grid);

  const foot = el('div', 'cap-foot');
  const save = el('button', null, '保存并生效');
  save.type = 'button';
  save.id = 'cap-save';
  save.addEventListener('click', capsSave);
  foot.appendChild(save);
  const cancel = el('button', 'ghost', '取消');
  cancel.type = 'button';
  cancel.addEventListener('click', () => { CAP.editing = null; capsRenderForm(null); });
  foot.appendChild(cancel);
  const msg = el('span', 'cap-msg');
  msg.id = 'cap-msg';
  foot.appendChild(msg);
  box.appendChild(foot);
}

function capsCollect() {
  const val = (id) => { const n = $(id); return n ? n.value : ''; };
  const chk = (id) => { const n = $(id); return n ? !!n.checked : false; };
  if (CAP.kind === 'skill') {
    return {
      action: 'save_skill', name: val('cap-name').trim(), title: val('cap-title').trim(),
      purpose: val('cap-purpose').trim(), when: val('cap-when').trim(),
      tools: val('cap-tools').trim(), body: val('cap-body'),
      command: val('cap-command').trim(), allow: chk('cap-allow') ? 1 : 0,
      timeout_ms: Number(val('cap-timeout')) || 20000
    };
  }
  return {
    action: 'save_tool', name: val('cap-name').trim(), description: val('cap-desc').trim(),
    command: val('cap-command').trim(), schema: val('cap-schema').trim(),
    kind: val('cap-kind').trim(), allow: chk('cap-allow') ? 1 : 0,
    timeout_ms: Number(val('cap-timeout')) || 20000
  };
}

async function capsSave() {
  const msg = $('cap-msg');
  const btn = $('cap-save');
  if (btn) btn.disabled = true;
  if (msg) msg.textContent = '正在保存…';
  try {
    const r = await capApi(capsCollect());
    CAP.data = await api('/api/caps');
    CAP.editing = null;
    capsRenderForm(null);
    capsRenderList();
    if ($('cap-msg')) $('cap-msg').textContent = '';
    const st = CAP.data.stats || {};
    if ($('cap-stat')) {
      $('cap-stat').textContent = CAP.kind === 'skill'
        ? `共 ${st.skills || 0} 个（技能包 ${st.extSkills || 0}）`
        : `共 ${st.tools || 0} 个（外部 ${st.extTools || 0} · MCP ${st.mcpTools || 0}）`;
    }
    void r;
  } catch (e) {
    if ($('cap-msg')) $('cap-msg').textContent = '保存失败：' + ((e && e.message) || e);
  } finally {
    if (btn) btn.disabled = false;
  }
}

async function capsDelete(x) {
  if (!window.confirm('确定删除「' + (x.name || '') + '」？数据目录里的定义文件会被删掉。')) return;
  try {
    await capApi({ action: CAP.kind === 'skill' ? 'delete_skill' : 'delete_tool', name: x.name });
    CAP.data = await api('/api/caps');
    CAP.editing = null;
    capsRenderList();
    capsRenderForm(null);
  } catch (e) {
    window.alert('删除失败：' + ((e && e.message) || e));
  }
}

/* —— 辅助面板：用大模型创建 / 从市场导入 —— */
function capsAux(kind) {
  const box = $('cap-aux');
  if (!box) return;
  box.innerHTML = '';
  box.classList.add('on');
  const inner = el('div', 'cap-aux-box');

  if (kind === 'gen') {
    inner.appendChild(el('h4', null, '用大模型创建'));
    inner.appendChild(el('p', null,
      '写一句你想要的能力，模型会产出一份草稿；模型不可用时给一份可直接改的模板。草稿不会自动保存，你确认后才落盘。'));
    const row = el('div', 'cap-aux-row');
    const inp = el('input');
    inp.id = 'cap-brief';
    inp.placeholder = CAP.kind === 'skill' ? '例如：检查站点是否把 .git 目录暴露出来' : '例如：调用本机 nmap 做一次端口探测';
    row.appendChild(inp);
    const go = el('button', null, '生成草稿');
    go.type = 'button';
    row.appendChild(go);
    inner.appendChild(row);
    const msg = el('div', 'cap-aux-msg');
    msg.id = 'cap-aux-msg';
    inner.appendChild(msg);

    go.addEventListener('click', async () => {
      const brief = inp.value.trim();
      if (!brief) { inp.focus(); return; }
      go.disabled = true;
      msg.textContent = '正在生成…';
      try {
        const r = await capApi({ action: 'draft', kind: CAP.kind, brief });
        const d = r.draft || {};
        CAP.editing = CAP.kind === 'skill'
          ? { name: d.name || '', title: d.title || '', purpose: d.purpose || '',
              when: d.when || '', tools: d.tools || '', body: d.body || '',
              command: '', allow: false, timeout_ms: 20000 }
          : { name: d.name || '', description: d.description || '', command: d.command || '',
              schema: typeof d.schema === 'string' ? d.schema : JSON.stringify(d.schema || {}, null, 2),
              kind: '', allow: false, timeout_ms: d.timeout_ms || 20000 };
        capsRenderForm(CAP.editing);
        msg.textContent = r.fromModel ? '已按你的描述生成草稿，确认后点「保存并生效」。'
                                      : ('用了模板（' + (r.note || '模型不可用') + '），改完再保存。');
      } catch (e) {
        msg.textContent = '生成失败：' + ((e && e.message) || e);
      } finally {
        go.disabled = false;
      }
    });
  } else {
    inner.appendChild(el('h4', null, '从市场导入'));
    inner.appendChild(el('p', null,
      '粘贴一份技能（Markdown）或工具（JSON），或者填一个 http(s) 地址下载。内容会先填进表单，确认后才保存。'));
    const row = el('div', 'cap-aux-row');
    const inp = el('input');
    inp.id = 'cap-url';
    inp.placeholder = 'https://…/skill_xxx.md';
    row.appendChild(inp);
    const go = el('button', null, '下载');
    go.type = 'button';
    row.appendChild(go);
    inner.appendChild(row);
    const ta = el('textarea');
    ta.id = 'cap-paste';
    ta.rows = 6;
    ta.placeholder = '或者直接把内容粘到这里：\n---\nname: skill_xxx\ntitle: …\n---\n\n正文…';
    inner.appendChild(ta);
    const row2 = el('div', 'cap-aux-row');
    const usePaste = el('button', null, '用这段内容');
    usePaste.type = 'button';
    row2.appendChild(usePaste);
    const links = el('span', 'cap-aux-msg');
    links.innerHTML = '市场：<a href="https://skillsmp.com/zh" target="_blank" rel="noopener noreferrer">Skill 市场 ↗</a> · ' +
                      '<a href="https://gc.das-ai.com/marketplace/tools/mcp" target="_blank" rel="noopener noreferrer">MCP 工具 ↗</a>';
    row2.appendChild(links);
    inner.appendChild(row2);
    const msg = el('div', 'cap-aux-msg');
    msg.id = 'cap-aux-msg';
    inner.appendChild(msg);

    const fill = (text, source) => {
      const parsed = capParseImport(text);
      if (!parsed) { msg.textContent = '没认出格式：技能要有 --- 开头的 front-matter，工具要是一段 JSON。'; return; }
      CAP.editing = parsed;
      capsRenderForm(CAP.editing);
      msg.textContent = '已从' + source + '读入，确认后点「保存并生效」。';
    };

    go.addEventListener('click', async () => {
      const url = inp.value.trim();
      if (!url) { inp.focus(); return; }
      go.disabled = true;
      msg.textContent = '正在下载…';
      try {
        const r = await capApi({ action: 'fetch', url });
        fill(r.text || '', '下载内容');
      } catch (e) {
        msg.textContent = '下载失败：' + ((e && e.message) || e);
      } finally {
        go.disabled = false;
      }
    });
    usePaste.addEventListener('click', () => {
      const text = ta.value.trim();
      if (!text) { ta.focus(); return; }
      fill(text, '粘贴内容');
    });
  }

  const close = el('button', 'ghost', '收起');
  close.type = 'button';
  close.style.marginTop = '8px';
  close.addEventListener('click', () => { box.classList.remove('on'); box.innerHTML = ''; });
  inner.appendChild(close);
  box.appendChild(inner);
}

/* 市场里的两种格式：技能的 front-matter Markdown、工具的 JSON */
function capParseImport(text) {
  const raw = String(text || '').replace(/^\uFEFF/, '');
  const t = raw.trim();
  if (!t) return null;

  if (CAP.kind === 'skill') {
    const m = /^---\r?\n([\s\S]*?)\r?\n---/.exec(t);
    const f = {};
    let body = t;
    if (m) {
      for (const line of m[1].split(/\r?\n/)) {
        const i = line.indexOf(':');
        if (i < 0) continue;
        f[line.slice(0, i).trim().toLowerCase()] = line.slice(i + 1).trim();
      }
      body = t.slice(m[0].length).trim();
    }
    return {
      name: f.name || '', title: f.title || '', purpose: f.purpose || '',
      when: f.when || '', tools: f.tools || '', body,
      command: f.command || '', allow: String(f.allow || '').toLowerCase() === 'true',
      timeout_ms: Number(f.timeout_ms) || 20000
    };
  }

  let j = null;
  try { j = JSON.parse(t); } catch { return null; }
  if (Array.isArray(j)) j = j[0];
  if (!j || typeof j !== 'object') return null;
  return {
    name: j.name || '', description: j.description || '', command: j.command || '',
    schema: typeof j.schema === 'string' ? j.schema : JSON.stringify(j.schema || {}, null, 2),
    kind: j.kind || '', allow: !!j.allow, timeout_ms: Number(j.timeout_ms) || 20000
  };
}

function capsBind() {
  const mk = $('cap-btn-new');
  if (mk) {
    mk.addEventListener('click', () => {
      CAP.editing = CAP.kind === 'skill'
        ? { name: 'skill_', title: '', purpose: '', when: '', tools: '', body: '',
            command: '', allow: false, timeout_ms: 20000 }
        : { name: '', description: '', command: '', schema:
            '{\n  "type": "object",\n  "properties": {\n    "target": { "type": "string" }\n  },\n  "required": ["target"]\n}',
            kind: '', allow: false, timeout_ms: 20000 };
      capsRenderForm(CAP.editing);
      const n = $('cap-name');
      if (n) { n.focus(); n.select(); }
    });
  }
  const gen = $('cap-btn-gen');
  if (gen) gen.addEventListener('click', () => capsAux('gen'));
  const mkt = $('cap-btn-market');
  if (mkt) mkt.addEventListener('click', () => capsAux('market'));
}
capsBind();

/* ===== 模型:接哪一家的模型 =====
   三类协议覆盖了绝大多数情况,所以界面上先选"协议",地址和字段跟着变;
   不内置任何厂商的密钥和地址,填什么就连什么。 */
const MODELS = { data: null, editing: null, index: -1 };

const MODEL_PRESETS = {
  das: {
    title: '恒脑智能体', url: 'https://www.das-ai.com', model: '',
    hint: '填 appKey / appSecret / 智能体 ID；接口地址填平台首页即可，路径会自动补全'
  },
  openai: {
    title: 'OpenAI 兼容', url: 'https://api.openai.com/v1', model: 'gpt-4o-mini',
    hint: 'DeepSeek、Kimi、通义、智谱、硅基流动、OneAPI、vLLM、Ollama 都走这一类，地址填到 /v1 为止'
  },
  anthropic: {
    title: 'Anthropic', url: 'https://api.anthropic.com', model: 'claude-3-5-sonnet-latest',
    hint: 'Messages 接口，只需要 API Key 和模型名'
  }
};

function modelApi(body) {
  return api('/api/models', { method: 'POST', body: JSON.stringify(body) });
}

async function modelsOpen() {
  try { MODELS.data = await api('/api/models'); }
  catch (e) { MODELS.data = { providers: [], active: '', path: '' }; }
  modelsRenderList();
  modelsRenderForm(MODELS.editing);
}

function modelKindLabel(kind) {
  const k = MODEL_PRESETS[kind];
  return k ? k.title : (kind || '');
}

function modelsRenderList() {
  const box = $('model-list');
  if (!box) return;
  box.innerHTML = '';
  const d = MODELS.data || {};
  const list = d.providers || [];
  const active = d.active || '';
  if ($('model-stat')) {
    const ready = list.filter((x) => x.ready).length;
    $('model-stat').textContent = list.length
      ? `${list.length} 家（${ready} 家可用）` : '还没接模型';
  }
  if ($('model-note')) {
    $('model-note').textContent = list.length
      ? `配置存在 ${d.path || 'models.json'}。当前优先用「${(list.find((x) => x.id === active) || {}).name || '未指定'}」，它调不通时自动顺延下一家。`
      : '接一家模型后，智能体就能自己判断下一步做什么；不接也不影响使用，会走本地规则。';
  }
  if (!list.length) {
    box.appendChild(el('div', 'muted', '还没有接入任何模型。'));
    return;
  }
  for (const x of list) {
    const row = el('div', 'cap-item');
    const main = el('div', 'ci-main');
    const head = el('div');
    head.appendChild(el('span', 'ci-name', x.name || x.id));
    head.appendChild(el('span', 'ci-tag', modelKindLabel(x.kind)));
    if (x.id === active) head.appendChild(el('span', 'ci-tag mine', '当前'));
    if (!x.enabled) head.appendChild(el('span', 'ci-tag', '已停用'));
    if (x.ready) head.appendChild(el('span', 'ci-tag ext', '可用'));
    main.appendChild(head);
    const bits = [x.model, x.base_url].filter(Boolean).join(' · ');
    main.appendChild(el('div', 'ci-desc', bits || '（还没填地址）'));
    row.appendChild(main);

    const act = el('div', 'ci-act');
    const test = el('button', null, '测试');
    test.type = 'button';
    test.addEventListener('click', () => modelsTest(x.id, test));
    act.appendChild(test);
    if (x.id !== active) {
      const use = el('button', null, '设为当前');
      use.type = 'button';
      use.addEventListener('click', () => modelsActivate(x.id));
      act.appendChild(use);
    }
    const edit = el('button', null, '编辑');
    edit.type = 'button';
    edit.addEventListener('click', () => {
      MODELS.index = list.indexOf(x);
      MODELS.editing = Object.assign({}, x);
      modelsRenderForm(MODELS.editing);
    });
    act.appendChild(edit);
    const del = el('button', null, '删除');
    del.type = 'button';
    del.addEventListener('click', () => modelsDelete(x));
    act.appendChild(del);
    row.appendChild(act);
    box.appendChild(row);
  }
}

function modelsRenderForm(m) {
  const box = $('model-edit');
  if (!box) return;
  box.innerHTML = '';
  if (!m) { box.classList.remove('on'); return; }
  box.classList.add('on');

  const grid = el('div', 'cap-grid');
  grid.appendChild(capField('名字（自己认得出就行）', 'model-name', m.name, { ph: 'DeepSeek 主力' }));

  const kindWrap = el('div', 'cap-field');
  const kindLabel = document.createElement('label');
  kindLabel.textContent = '协议';
  kindLabel.setAttribute('for', 'model-kind');
  kindWrap.appendChild(kindLabel);
  const sel = document.createElement('select');
  sel.id = 'model-kind';
  for (const k of ['das', 'openai', 'anthropic']) {
    const o = document.createElement('option');
    o.value = k;
    o.textContent = modelKindLabel(k);
    if ((m.kind || 'openai') === k) o.selected = true;
    sel.appendChild(o);
  }
  kindWrap.appendChild(sel);
  grid.appendChild(kindWrap);

  grid.appendChild(capField('接口地址', 'model-url', m.base_url, { wide: true, ph: MODEL_PRESETS[m.kind || 'openai'].url }));
  grid.appendChild(capField('模型名', 'model-model', m.model, { ph: MODEL_PRESETS[m.kind || 'openai'].model }));
  grid.appendChild(capField('API Key / appKey', 'model-key', m.api_key, { ph: '留空或保持掩码 = 不改' }));
  grid.appendChild(capField('appSecret（恒脑用）', 'model-secret', m.api_secret, { ph: '留空或保持掩码 = 不改' }));
  grid.appendChild(capField('userAppKey（可信配置 5.1 可选）', 'model-userkey', m.user_app_key));
  grid.appendChild(capField('智能体 ID（恒脑用）', 'model-agent', m.agent_id));
  grid.appendChild(capField('智能体关键词（恒脑按名字找）', 'model-keyword', m.agent_keyword));
  grid.appendChild(capField('附加请求头（一行一个 Name: value）', 'model-headers', m.headers, { wide: true, area: true, rows: 2 }));
  grid.appendChild(capField('超时（毫秒）', 'model-timeout', m.timeout_ms || 45000, { num: true, step: '1000' }));
  grid.appendChild(capField('温度（-1 = 不带）', 'model-temp', m.temperature === undefined ? 0.2 : m.temperature, { num: true, step: '0.1' }));
  grid.appendChild(capField('最大 tokens（0 = 不带）', 'model-maxtok', m.max_tokens || 0, { num: true }));
  grid.appendChild(capField('启用这一条', 'model-enabled', m.enabled !== false, { check: true }));
  box.appendChild(grid);

  const hint = el('div', 'set-hint', MODEL_PRESETS[m.kind || 'openai'].hint);
  box.appendChild(hint);

  const foot = el('div', 'cap-foot');
  const save = el('button', null, '保存并生效');
  save.type = 'button';
  save.id = 'model-save';
  save.addEventListener('click', modelsSave);
  foot.appendChild(save);
  const test = el('button', 'ghost', '保存并测试');
  test.type = 'button';
  test.addEventListener('click', () => { modelsSave(test, true); });
  foot.appendChild(test);
  const cancel = el('button', 'ghost', '取消');
  cancel.type = 'button';
  cancel.addEventListener('click', () => { MODELS.editing = null; modelsRenderForm(null); });
  foot.appendChild(cancel);
  const msg = el('span', 'cap-msg');
  msg.id = 'model-msg';
  foot.appendChild(msg);
  box.appendChild(foot);

  sel.addEventListener('change', () => {
    const p = MODEL_PRESETS[sel.value] || MODEL_PRESETS.openai;
    const url = $('model-url');
    const mdl = $('model-model');
    /* 地址/模型名还是空的、或者还是上一套模板的,就换成新协议的建议值;
       用户自己填过的不动 */
    const old = MODEL_PRESETS[m.kind || 'openai'];
    if (url && (!url.value.trim() || url.value.trim() === old.url)) url.value = p.url;
    if (mdl && (!mdl.value.trim() || mdl.value.trim() === old.model)) mdl.value = p.model;
    m.kind = sel.value;
    const h = box.querySelector('.set-hint');
    if (h) h.textContent = p.hint;
  });
}

function modelsCollect() {
  const val = (id) => { const n = $(id); return n ? n.value : ''; };
  const chk = (id) => { const n = $(id); return n ? !!n.checked : false; };
  const base = Object.assign({}, MODELS.editing || {});
  return Object.assign(base, {
    name: val('model-name').trim(),
    kind: val('model-kind'),
    base_url: val('model-url').trim(),
    model: val('model-model').trim(),
    api_key: val('model-key').trim(),
    api_secret: val('model-secret').trim(),
    user_app_key: val('model-userkey').trim(),
    agent_id: val('model-agent').trim(),
    agent_keyword: val('model-keyword').trim(),
    headers: val('model-headers').trim(),
    timeout_ms: Number(val('model-timeout')) || 45000,
    temperature: val('model-temp') === '' ? 0.2 : Number(val('model-temp')),
    max_tokens: Number(val('model-maxtok')) || 0,
    enabled: chk('model-enabled') ? 1 : 0
  });
}

/* save 之后再 test 是有意的:测试打的是"刚填进去的这份",不是上一次保存的旧值 */
async function modelsSave(btn, thenTest) {
  const msg = $('model-msg');
  if (btn) btn.disabled = true;
  if (msg) msg.textContent = '正在保存…';
  try {
    const cur = MODELS.data || { providers: [] };
    const list = (cur.providers || []).map((x) => Object.assign({}, x));
    const item = modelsCollect();
    if (MODELS.index >= 0 && MODELS.index < list.length) list[MODELS.index] = item;
    else list.push(item);
    const r = await modelApi({ action: 'save', active: cur.active || '', providers: list });
    MODELS.data = (r && r.models) || cur;
    const idx = MODELS.index;
    await modelsOpen();
    const after = MODELS.data.providers || [];
    const saved = (idx >= 0 && after[idx]) ? after[idx] : (after[after.length - 1] || item);
    MODELS.editing = null;
    modelsRenderForm(null);
    if (thenTest) { await modelsTest(saved.id, null); return; }
    if ($('model-msg')) $('model-msg').textContent = '';
  } catch (e) {
    if (msg) msg.textContent = '保存失败：' + e.message;
  } finally {
    if (btn) btn.disabled = false;
  }
}

async function modelsTest(id, btn) {
  if (btn) btn.disabled = true;
  const msg = $('model-msg') || $('model-note');
  if (msg) msg.textContent = '正在测试…';
  try {
    const r = await modelApi({ action: 'test', id });
    if (msg) {
      msg.textContent = r.ok
        ? `通了（${r.ms} ms）：${r.detail || ''}`
        : `没通：${r.detail || '没有响应'}`;
    }
  } catch (e) {
    if (msg) msg.textContent = '没通：' + e.message;
  } finally {
    if (btn) btn.disabled = false;
  }
}

async function modelsActivate(id) {
  try {
    const r = await modelApi({ action: 'activate', id });
    MODELS.data = (r && r.models) || MODELS.data;
    modelsRenderList();
    await api('/api/status').then(renderStatus).catch(() => {});
  } catch (e) {
    if ($('model-note')) $('model-note').textContent = '切换失败：' + e.message;
  }
}

async function modelsDelete(x) {
  if (!confirm(`删除「${x.name || x.id}」？密钥也会一起删掉。`)) return;
  try {
    const r = await modelApi({ action: 'delete', id: x.id });
    MODELS.data = (r && r.models) || MODELS.data;
    MODELS.editing = null;
    modelsRenderForm(null);
    modelsRenderList();
  } catch (e) {
    if ($('model-note')) $('model-note').textContent = '删除失败：' + e.message;
  }
}

function modelsBind() {
  const mk = $('model-btn-new');
  if (mk) {
    mk.addEventListener('click', () => {
      MODELS.index = -1;
      MODELS.editing = {
        name: '', kind: 'openai', base_url: MODEL_PRESETS.openai.url,
        model: MODEL_PRESETS.openai.model, api_key: '', api_secret: '',
        user_app_key: '', agent_id: '', agent_keyword: '', headers: '',
        timeout_ms: 45000, temperature: 0.2, max_tokens: 0, enabled: 1
      };
      modelsRenderForm(MODELS.editing);
      const n = $('model-name');
      if (n) n.focus();
    });
  }
  const t = $('model-btn-test');
  if (t) {
    t.addEventListener('click', () => {
      const d = MODELS.data || {};
      const list = d.providers || [];
      const cur = list.find((x) => x.id === d.active) || list[0];
      if (!cur) { if ($('model-note')) $('model-note').textContent = '还没接模型，先接一家再测。'; return; }
      modelsTest(cur.id, t);
    });
  }
}
modelsBind();

async function renderConfigView() {
  await setLoad(false);
  await renderConfigFiles();
}
async function renderConfigFiles() {
  const r = await api('/api/config/list');
  CFG.files = r.files || [];
  const box = $('cfg-list');
  box.innerHTML = '';
  const groups = {};
  for (const f of CFG.files) {
    const g = f.group || '其它';
    (groups[g] = groups[g] || []).push(f);
  }
  for (const g of Object.keys(groups)) {
    box.appendChild(el('div', 'filegroup', g));
    for (const f of groups[g]) {
      const row = el('button', 'fileitem' + (CFG.current === f.name ? ' active' : ''));
      row.appendChild(el('span', 'fname', f.name.replace(/\\/g, ' / ')));
      row.appendChild(el('span', 'fmeta', f.exists ? (f.size + ' B') : '不存在'));
      row.onclick = () => loadConfigFile(f.name);
      box.appendChild(row);
    }
  }
  if (!CFG.current && CFG.files.length) await loadConfigFile('rules.json');
  else if (CFG.current) markActiveFile();
}

function markActiveFile() {
  document.querySelectorAll('.fileitem').forEach((n) => {
    const t = n.querySelector('.fname');
    n.classList.toggle('active', t && t.textContent.replace(/\s*\/\s*/g, '\\') === CFG.current);
  });
}

async function loadConfigFile(name) {
  if (CFG.dirty && !confirm('有未保存的改动，放弃吗？')) return;
  const r = await api('/api/config?name=' + encodeURIComponent(name));
  CFG.current = name;
  CFG.dirty = false;
  $('cfg-name').textContent = name;
  $('cfg-text').value = r.content || '';
  $('cfg-meta').textContent = r.exists ? ('已存在 · ' + (r.size || 0) + ' B') : '新文件（保存后创建）';
  $('cfg-msg').textContent = '';
  $('cfg-msg').className = 'note';
  $('cfg-tip').textContent = /\.json$/.test(name)
    ? 'JSON 必须合法才能保存（后端会先校验）'
    : 'Markdown 技能：开头 front-matter 写 name/title/when/purpose/tools';
  markActiveFile();
}

async function saveConfigFile() {
  if (!CFG.current) return;
  const msg = $('cfg-msg');
  msg.className = 'note';
  msg.textContent = '保存中…';
  try {
    const r = await api('/api/config', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: CFG.current, content: $('cfg-text').value }),
    });
    CFG.dirty = false;
    msg.className = 'note ok';
    msg.textContent = '已保存（' + r.size + ' B，' + (r.backup || '') + '）'
      + (/rules\.json$/.test(CFG.current) ? '，可点「让规则生效」立即应用' : '，重启后生效');
    await renderConfigView();
  } catch (e) {
    msg.className = 'note bad';
    msg.textContent = '保存被拒绝：' + e.message;
  }
}

async function reloadRules() {
  const msg = $('cfg-msg');
  try {
    const r = await api('/api/reload', { method: 'POST' });
    msg.className = 'note ok';
    msg.textContent = '规则已重新载入：' + r.rulesSource;
    await refreshAll();
  } catch (e) {
    msg.className = 'note bad';
    msg.textContent = '重新载入失败：' + e.message;
  }
}

function newConfigFile() {
  const kind = prompt('新建哪一类？输入 1 = 技能包（skills\\我的技能.md），2 = 外部工具（tools\\我的工具.json）', '1');
  if (!kind) return;
  let name;
  let tpl;
  if (kind.trim() === '2') {
    name = prompt('工具名（英文，不含空格）', 'my_tool');
    if (!name) return;
    name = 'tools\\' + name.replace(/[^\w\-]/g, '_') + '.json';
    tpl = '{\n  "name": "' + name.replace(/^tools\\|\.json$/g, '') + '",\n'
        + '  "description": "这个工具做什么（模型据此决定用不用）",\n'
        + '  "schema": {"type":"object","properties":{"target":{"type":"string"}},"required":["target"]},\n'
        + '  "command": "curl -sS -o NUL -w \\"HTTP %{http_code}\\" --max-time 15 $target",\n'
        + '  "timeout_ms": 20000,\n'
        + '  "allow": false\n}\n';
  } else {
    name = prompt('技能名（英文，不含空格）', 'skill_我的技能');
    if (!name) return;
    name = 'skills\\' + name.replace(/[^\w\u4e00-\u9fa5\-]/g, '_') + '.md';
    tpl = '---\nname: ' + name.replace(/^skills\\|\.md$/g, '') + '\n'
        + 'title: 我的技能\nwhen: 用户说「…」时用\npurpose: 解决什么问题\ntools: site_crawl\nallow: false\n---\n\n'
        + '步骤（没有 command 时，这份文本作为方法论交给模型执行）：\n\n1. 先…\n2. 再…\n3. 结论分级汇总；取不到内容要如实说明「没结论」。\n';
  }
  CFG.current = name;
  CFG.dirty = true;
  $('cfg-name').textContent = name;
  $('cfg-text').value = tpl;
  $('cfg-meta').textContent = '新文件（保存后创建）';
  $('cfg-msg').className = 'note';
  $('cfg-msg').textContent = '模板已就绪，改完点「保存」';
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

/* ============ 布局：左右栏宽度、输入框高度（可拖拽 / 可调） ============ */
const LAYOUT_KEY = 'bw-layout';
const LAYOUT_DEFAULT = { side: 252, rail: 320, compose: 56 };
let LAYOUT = (() => {
  try { return Object.assign({}, LAYOUT_DEFAULT, JSON.parse(localStorage.getItem(LAYOUT_KEY) || '{}')); }
  catch (e) { return Object.assign({}, LAYOUT_DEFAULT); }
})();

function saveLayout() {
  try { localStorage.setItem(LAYOUT_KEY, JSON.stringify(LAYOUT)); } catch (e) { /* 忽略 */ }
}

function applyLayout() {
  const w = $('work');
  if (w) {
    w.style.setProperty('--side-w', LAYOUT.side + 'px');
    w.style.setProperty('--rail-w', LAYOUT.rail + 'px');
  }
  const q = $('q');
  if (q) q.style.minHeight = LAYOUT.compose + 'px';
  const set = (id, v) => { const n = $(id); if (n) n.value = v; };
  /* 正在手输的那个数值不要被覆盖，否则输入框会当场消失 */
  const txt = (id, v) => {
    const n = $(id);
    if (!n || n.dataset.editing) return;
    n.textContent = v + 'px';
  };
  set('ui-side', LAYOUT.side); txt('ui-side-v', LAYOUT.side);
  set('ui-rail', LAYOUT.rail); txt('ui-rail-v', LAYOUT.rail);
  set('ui-compose', LAYOUT.compose); txt('ui-compose-v', LAYOUT.compose);
}

/* 拖分隔线：按住左键横向拖动，松手落盘；双击回默认 */
function bindSplitter(id, key, min, max, invert) {
  const el = $(id);
  if (!el) return;
  el.addEventListener('pointerdown', (ev) => {
    if (ev.button !== 0) return;
    if (key === 'rail' && $('work').classList.contains('rail-collapsed')) {
      railCollapsed = false;
      try { localStorage.setItem(RAIL_KEY, '0'); } catch (e) { /* 忽略 */ }
      applyRail();
    }
    const startX = ev.clientX;
    const start = LAYOUT[key];
    el.setPointerCapture(ev.pointerId);
    el.classList.add('dragging');
    document.body.classList.add('col-resizing');

    const onMove = (e) => {
      const delta = e.clientX - startX;
      const next = invert ? start - delta : start + delta;
      LAYOUT[key] = Math.max(min, Math.min(max, Math.round(next)));
      applyLayout();
    };
    const onUp = () => {
      el.classList.remove('dragging');
      document.body.classList.remove('col-resizing');
      el.removeEventListener('pointermove', onMove);
      el.removeEventListener('pointerup', onUp);
      el.removeEventListener('pointercancel', onUp);
      saveLayout();
    };
    el.addEventListener('pointermove', onMove);
    el.addEventListener('pointerup', onUp);
    el.addEventListener('pointercancel', onUp);
    ev.preventDefault();
  });
  el.addEventListener('dblclick', () => {
    LAYOUT[key] = LAYOUT_DEFAULT[key];
    applyLayout();
    saveLayout();
  });
}

bindSplitter('sp-left', 'side', 180, 420, false);
bindSplitter('sp-right', 'rail', 240, 560, true);

/* 输入区高度：拖上沿（向上=变高），双击回默认 */
(function bindComposeGrip() {
  const grip = $('compose-grip');
  if (!grip) return;
  grip.addEventListener('pointerdown', (ev) => {
    if (ev.button !== 0) return;
    const startY = ev.clientY;
    const start = LAYOUT.compose;
    grip.setPointerCapture(ev.pointerId);
    grip.classList.add('dragging');
    document.body.classList.add('row-resizing');
    const onMove = (e) => {
      LAYOUT.compose = Math.max(44, Math.min(300, Math.round(start - (e.clientY - startY))));
      applyLayout();
    };
    const onUp = () => {
      grip.classList.remove('dragging');
      document.body.classList.remove('row-resizing');
      grip.removeEventListener('pointermove', onMove);
      grip.removeEventListener('pointerup', onUp);
      grip.removeEventListener('pointercancel', onUp);
      saveLayout();
    };
    grip.addEventListener('pointermove', onMove);
    grip.addEventListener('pointerup', onUp);
    grip.addEventListener('pointercancel', onUp);
    ev.preventDefault();
  });
  grip.addEventListener('dblclick', () => {
    LAYOUT.compose = LAYOUT_DEFAULT.compose;
    applyLayout();
    saveLayout();
  });
})();

/* 设置页的三条滑杆：和拖拽共用同一份状态 */
[['ui-side', 'side'], ['ui-rail', 'rail'], ['ui-compose', 'compose']].forEach(([id, key]) => {
  const el = $(id);
  if (!el) return;
  el.addEventListener('input', () => {
    LAYOUT[key] = Number(el.value) || LAYOUT_DEFAULT[key];
    applyLayout();
    saveLayout();
  });
});
const uiReset = $('ui-reset');
if (uiReset) {
  uiReset.addEventListener('click', () => {
    LAYOUT = Object.assign({}, LAYOUT_DEFAULT);
    applyLayout();
    saveLayout();
  });
}

/* 数值可以直接点开手输：滑杆拖不准时，输一个数更快 */
function bindValueEdit(valueId, sliderId, key) {
  const node = $(valueId);
  const slider = $(sliderId);
  if (!node || !slider) return;
  node.classList.add('editable');
  node.title = '点一下直接输入';
  node.addEventListener('click', (ev) => {
    /* 这行是 <label>，点它默认会把焦点转给滑杆；必须挡住，
       否则输入框刚出现就被抢走焦点，一个字也打不进去。 */
    ev.preventDefault();
    ev.stopPropagation();
    if (node.dataset.editing) return;
    node.dataset.editing = '1';
    const old = LAYOUT[key];
    const inp = document.createElement('input');
    inp.type = 'number';
    inp.className = 'ui-num';
    inp.value = old;
    inp.min = slider.min;
    inp.max = slider.max;
    inp.step = slider.step;
    node.textContent = '';
    node.appendChild(inp);
    setTimeout(() => { inp.focus(); inp.select(); }, 0);
    const commit = (ok) => {
      if (!node.dataset.editing) return;
      delete node.dataset.editing;
      const raw = Number(inp.value);
      const min = Number(slider.min);
      const max = Number(slider.max);
      const v = ok && isFinite(raw) && raw > 0 ? Math.round(raw) : old;
      LAYOUT[key] = Math.max(min, Math.min(max, v));
      applyLayout();
      saveLayout();
    };
    inp.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') { e.preventDefault(); commit(true); }
      else if (e.key === 'Escape') { e.preventDefault(); commit(false); }
    });
    inp.addEventListener('blur', () => commit(true));
  });
}

bindValueEdit('ui-side-v', 'ui-side', 'side');
bindValueEdit('ui-rail-v', 'ui-rail', 'rail');
bindValueEdit('ui-compose-v', 'ui-compose', 'compose');

applyLayout();

/* 偏好开关：不改后端，只改这一台机器上的观感 */
function savePrefs() {
  try { localStorage.setItem(PREFS_KEY, JSON.stringify(PREFS)); } catch (e) { /* 忽略 */ }
}

function applyPrefs() {
  const traceNode = $('trace');
  const traceCard = traceNode ? traceNode.closest('.rail-card') : null;
  if (traceCard) traceCard.style.display = PREFS.trace ? '' : 'none';
  document.body.classList.toggle('no-motion', !PREFS.motion);
  [['ui-trace', 'trace'], ['ui-autoscroll', 'autoscroll'], ['ui-motion', 'motion']].forEach(([id, key]) => {
    const node = $(id);
    if (node) node.checked = !!PREFS[key];
  });
}

[['ui-trace', 'trace'], ['ui-autoscroll', 'autoscroll'], ['ui-motion', 'motion']].forEach(([id, key]) => {
  const node = $(id);
  if (!node) return;
  node.addEventListener('change', () => {
    PREFS[key] = node.checked;
    applyPrefs();
    savePrefs();
  });
});
applyPrefs();

/* 右栏收起/展开:窄栏里也留一个能点回来的按钮 */
const RAIL_KEY = 'bw-rail';
let railCollapsed = false;
try { railCollapsed = localStorage.getItem(RAIL_KEY) === '1'; } catch (e) { /* 忽略 */ }
function applyRail() {
  const work = $('work');
  if (work) work.classList.toggle('rail-collapsed', railCollapsed);
  const b = $('btn-rail');
  if (b) b.title = railCollapsed ? '展开侧边栏' : '收起侧边栏';
}
const railBtn = $('btn-rail');
if (railBtn) {
  railBtn.addEventListener('click', () => {
    railCollapsed = !railCollapsed;
    try { localStorage.setItem(RAIL_KEY, railCollapsed ? '1' : '0'); } catch (e) { /* 忽略 */ }
    applyRail();
  });
}
applyRail();

/* 附件:选了就先传上去,拿到 id 挂在这一轮里 */
const attachBtn = $('btn-attach');
const attachInput = $('attach');
if (attachBtn && attachInput) {
  attachBtn.addEventListener('click', () => attachInput.click());
  attachInput.addEventListener('change', async () => {
    for (const f of Array.from(attachInput.files || [])) {
      try { await uploadAttachment(f); }
      catch (e) { if (trace) trace.textContent = '附件没传上去：' + ((e && e.message) || e); }
    }
    attachInput.value = '';
  });
}

/* 停止:把信号打给后端,循环会在下一次请求前撒手。
   不关 EventSource —— 让后端把"已停下"这一句正常播完,界面才知道停在哪一步。 */
const stopBtn = $('btn-stop');
if (stopBtn) {
  stopBtn.addEventListener('click', () => {
    stopBtn.disabled = true;
    stopBtn.textContent = '正在停…';
    api('/api/cancel', {
      method: 'POST',
      body: JSON.stringify({ sid: BW_SID })
    }).catch(() => {}).finally(() => {
      stopBtn.disabled = false;
      stopBtn.textContent = '停止';
    });
  });
}

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

/* 起手式：给目标就开始；快捷短语只是把话填进去，不替你决定 */
const hq = $('hq');
if (hq) {
  hq.addEventListener('input', () => {
    hq.style.height = 'auto';
    hq.style.height = Math.min(hq.scrollHeight, 160) + 'px';
  });
  hq.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      $('home-form').requestSubmit();
    }
  });
}
$('home-form').addEventListener('submit', (e) => {
  e.preventDefault();
  const text = (hq.value || '').trim();
  /* 什么都没写就点「开始」= 想直接进对话页，不要拦着他 */
  if (!text) { newChat(); return; }
  if (!state.status || !state.status.authorized) {
    openModal();
    return;
  }
  hq.value = '';
  send(text);
});
/* 任何 data-goto 都走同一个入口：先切视图，再取数 */
document.querySelectorAll('[data-goto]').forEach((b) => {
  b.addEventListener('click', () => {
    const name = b.dataset.goto;
    switchView(name);
    loadView(name);
  });
});

$('btn-back').addEventListener('click', closeSheet);
/* 新建巡检 = 新开一条对话（留在工作台），不是回首页 */
$('btn-new').addEventListener('click', newChat);
/* HOME = 回起手式（首页） */
const homeBtn = $('btn-home');
if (homeBtn) homeBtn.addEventListener('click', showHome);
$('btn-refresh2').addEventListener('click', async () => {
  state.cache = {};
  try { renderStatus(await api('/api/status')); } catch { /* 后端可能刚停 */ }
  await loadView(state.view);
});

const scrollTimer = new WeakMap();
document.querySelectorAll('.main, .stream, .trace, .steps, .table-wrap, .tool-args, .tool-out, .config-side .filelist').forEach((node) => {
  node.classList.add('scroll-surface');
  node.addEventListener('wheel', () => {
    node.classList.add('is-scrolling');
    clearTimeout(scrollTimer.get(node));
    scrollTimer.set(node, setTimeout(() => node.classList.remove('is-scrolling'), 700));
  }, { passive: true });
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



/* 配置编辑页的按钮 */
$('cfg-save').addEventListener('click', saveConfigFile);
$('cfg-reload-file').addEventListener('click', () => { if (CFG.current) loadConfigFile(CFG.current); });
$('cfg-reload-rules').addEventListener('click', reloadRules);
$('cfg-new').addEventListener('click', newConfigFile);
$('cfg-text').addEventListener('input', () => {
  CFG.dirty = true;
  $('cfg-msg').className = 'note';
  $('cfg-msg').textContent = '有未保存的改动';
});

/* 授权弹窗：池子是合规的第一道闸，前端也必须拦一次 */
function openModal() { $('modal').classList.add('on'); renderPoolList(); setTimeout(() => $('scope-domain').focus(), 200); }
function shutModal() { $('modal').classList.remove('on'); }
$('btn-scope').addEventListener('click', openModal);
$('scope-cancel').addEventListener('click', shutModal);
$('scope-save').addEventListener('click', addPoolEntry);
$('scope-batch').addEventListener('click', () => addPoolBatch($('pool-batch-text').value));
bindPoolImport();
$('scope-domain').addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); addPoolEntry(); } });
$('modal').addEventListener('click', (e) => {
  if (e.target.classList.contains('modal-backdrop')) shutModal();
});

/* ============ 主题 ============
   界面只有一套纸白（工作台）与一处纯黑（起手式）——两套并存会让同一页出现两种性格，
   所以不再提供主题开关。这里只保留"跟随系统滚动条/选区"的一致性设置。 */
function initTheme() {
  document.documentElement.style.colorScheme = 'light';
}

/* ============ 搜索（Ctrl+K） ============
   只查已经落盘的东西：任务 / 运行 / 发现 / 资产 + 视图跳转。
   不做"智能补全"，也不假装能搜后端没存的数据。 */
const PAL = { open: false, rows: [], sel: 0 };

const PAL_VIEWS = [
  ['report', '视图 · 报告与告警'], ['history', '视图 · 巡检历史'], ['assets', '视图 · 资产底账'],
  ['eval', '视图 · 证据与闭环'],
  ['automation', '视图 · 周期巡检'],
  ['config', '视图 · 配置与能力'],
];

async function palLoad() {
  const [runs, tasks, findings, assets] = await Promise.all([
    fetchCollection('runs', 60).catch(() => ({ items: [] })),
    fetchCollection('tasks', 60).catch(() => ({ items: [] })),
    fetchCollection('findings', 120).catch(() => ({ items: [] })),
    fetchCollection('assets', 120).catch(() => ({ items: [] })),
  ]);
  return {
    runs: runs.items || [], tasks: tasks.items || [],
    findings: findings.items || [], assets: assets.items || [],
  };
}

let PAL_DATA = null;

function palBuild(q) {
  const kw = q.trim().toLowerCase();
  const rows = [];
  for (const [view, label] of PAL_VIEWS) {
    rows.push({ kind: '视图', text: label, note: '', act: () => { switchView(view); loadView(view); } });
  }
  const d = PAL_DATA || { runs: [], tasks: [], findings: [], assets: [] };
  const taskMap = {};
  for (const t of d.tasks) taskMap[t.id] = t;
  for (const r of d.runs.slice().reverse()) {
    const t = taskMap[r.task_id] || {};
    const target = (t.authorized_domains || [])[0] || t.name || r.task_id || '—';
    rows.push({
      kind: '运行', text: `${r.id} · ${target}`,
      note: `${RUN_STATUS_LABEL[r.status] || r.status || ''} ${r.pages_found || 0} 页`,
      act: () => { showWork(); switchView('history'); loadView('history'); },
    });
  }
  for (const f of d.findings.slice().reverse()) {
    rows.push({
      kind: '发现', text: f.title || f.name || f.id || '未命名',
      note: [f.severity, f.kind].filter(Boolean).join(' · '),
      act: () => { showWork(); switchView('report'); loadView('report'); },
    });
  }
  for (const a of d.assets.slice().reverse()) {
    rows.push({ kind: '资产', text: a.url || a.id || '—', note: a.kind || '', act: () => { switchView('assets'); loadView('assets'); } });
  }
  const hit = kw ? rows.filter((r) => (r.text + ' ' + r.note + ' ' + r.kind).toLowerCase().includes(kw)) : rows;
  return hit.slice(0, 60);
}

function palRender() {
  const box = $('palette-list');
  box.innerHTML = '';
  $('palette-foot').textContent = PAL.rows.length
    ? '回车打开第一项 · ↑↓ 选择'
    : '没有匹配项。这里只搜已经落盘的任务、运行、发现和资产。';
  if (!PAL.rows.length) {
    box.appendChild(el('div', 'palette-empty', '换个词试试，或者直接搜域名、路径、严重度。'));
    return;
  }
  PAL.rows.forEach((r, i) => {
    const row = el('button', 'palette-row' + (i === PAL.sel ? ' sel' : ''));
    row.type = 'button';
    row.appendChild(el('span', 'pi', r.kind));
    row.appendChild(el('span', 'pt', r.text));
    if (r.note) row.appendChild(el('span', 'pd', r.note));
    row.addEventListener('click', () => palPick(i));
    row.addEventListener('mouseenter', () => { PAL.sel = i; palMark(); });
    box.appendChild(row);
  });
}
function palMark() {
  document.querySelectorAll('.palette-row').forEach((r, i) => r.classList.toggle('sel', i === PAL.sel));
}
function palPick(i) {
  const r = PAL.rows[i];
  palClose();
  if (r && r.act) r.act();
}
async function palOpen() {
  PAL.open = true;
  PAL.sel = 0;
  $('palette').classList.add('on');
  $('palette-q').value = '';
  $('palette-list').innerHTML = '<div class="palette-empty">正在读取已落盘的数据…</div>';
  setTimeout(() => $('palette-q').focus(), 60);
  PAL_DATA = null;                        // 每次打开都重算一遍（底层有缓存，不会重复请求）
  PAL_DATA = await palLoad().catch(() => ({ runs: [], tasks: [], findings: [], assets: [] }));
  if (!PAL.open) return;
  PAL.rows = palBuild('');
  palRender();
}
function palClose() {
  PAL.open = false;
  $('palette').classList.remove('on');
}

$('btn-search').addEventListener('click', palOpen);
$('palette').addEventListener('click', (e) => {
  if (e.target.classList.contains('palette-backdrop')) palClose();
});
$('palette-q').addEventListener('input', (e) => {
  PAL.rows = palBuild(e.target.value);
  PAL.sel = 0;
  palRender();
});
$('palette-q').addEventListener('keydown', (e) => {
  if (e.key === 'Escape') { palClose(); return; }
  if (e.key === 'ArrowDown') { e.preventDefault(); PAL.sel = Math.min(PAL.sel + 1, PAL.rows.length - 1); palMark(); }
  if (e.key === 'ArrowUp') { e.preventDefault(); PAL.sel = Math.max(PAL.sel - 1, 0); palMark(); }
  if (e.key === 'Enter') { e.preventDefault(); palPick(PAL.sel); }
});
document.addEventListener('keydown', (e) => {
  if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
    e.preventDefault();
    if (PAL.open) palClose(); else palOpen();
  }
  if (e.key === 'Escape' && PAL.open) palClose();
});

/* ============ 启动 ============ */
(async () => {
  initTheme();
  try {
    renderStatus(await api('/api/status'));
  } catch (e) {
    console.warn('连不上后端服务：' + e.message);
  }
  renderRecent();
  renderRail();
  renderAutomationView().catch(() => {});
  renderApprovals().catch(() => {});
  if (!state.status || !state.status.authorized) {
    openModal();
  }
})();
