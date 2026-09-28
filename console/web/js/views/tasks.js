/* 视图：任务台 — 以"工具"为主轴的调用看板。

   这一页回答的问题是：**我这些工具被谁调了、调了什么、多久、成没成**。
   （"某次任务走到第几步"是宿主 Agent 的视角；那一份完整链路在审计链与报告里。）

   画法：左栏是"被调用过的工具"索引；中栏是这一次调用的输入与输出（这一页的主角）；
   右栏是它属于哪次任务，加上这个工具的调用流水（可逐条移出视线，轨迹本身不动）。
   数据全部来自 skill 自己的轨迹（core.store）：控制台只读，不下达任何调用。 */
window.ViewTasks = {
  name: 'ViewTasks',
  data: function () {
    return {
      groups: [], live: null, summary: null, scope: '',
      /* 选中的工具与选中的那一次调用（selKey 用 "run#step" 定格，
         轮询刷新后还能落回同一条，不会跳走） */
      current: '', selKey: '', selIndex: 0, filter: 'all',
      detail: null, detailKey: '', detailState: '', detailBusy: false, runInfo: null,
      /* 所属任务这一轮的执行情况：整轮计划有几步、每步什么状态、卡在第几步。
         轨迹里就有（plan + tool_call/tool_result），不必后端再加接口。 */
      runSteps: [], stepsKey: '', stepsBusy: false,
      auditTail: [], busy: false, loadError: '', hiddenCount: 0, hideMsg: '',
      /* 输出框是否跟着最新一行走；logObserver 盯着 <pre> 的内容变化 */
      followLog: true, logObserver: null,
      stages: ['判定', '授权', '执行', '复核', '交叉验证', '报告'],
      now: Date.now(), error: ''
    };
  },
  computed: {
    shownTools: function () {
      var f = this.filter;
      if (f === 'failed') {
        return this.groups.filter(function (g) { return g.failed || g.blocked; });
      }
      if (f === 'live') return this.groups.filter(function (g) { return g.running; });
      return this.groups;
    },
    currentGroup: function () {
      var id = this.current;
      return this.groups.filter(function (g) { return g.tool === id; })[0] || null;
    },
    records: function () {
      var g = this.currentGroup;
      return g ? g.records : [];
    },
    selRecord: function () {
      return this.records[this.selIndex] || null;
    },
    /* 顶栏四格：口径写在卡片脚注里，不留"这数字哪来的"这种疑问 */
    metrics: function () {
      var s = this.summary || {};
      return [
        { k: '用过的工具', v: s.tools_used || 0 },
        { k: '调用次数', v: s.calls || 0 },
        { k: '失败', v: s.failed || 0, bad: !!s.failed },
        { k: '被拦截', v: s.blocked || 0, bad: !!s.blocked }
      ];
    },
    /* 正在跑的那次调用：有开始时间就按秒计，让人看得出"已经卡了多久" */
    liveElapsed: function () {
      if (!this.live || !this.live.started_at) return '';
      var secs = Math.max(0, Math.round((this.now - Date.parse(this.live.started_at)) / 1000));
      return this.secs(secs);
    },
    /* 此刻那条实时输出：跑着的调用才有。它是工具真实打出来的行，
       不是"运行中"三个字的替身 —— 跑长任务时全靠它判断有没有卡住。 */
    liveTail: function () {
      if (!this.live) return '';
      return this.live.tail || '';
    },
    authNeeded: function () {
      if (this.runInfo && ((this.runInfo.counts || {}).blocked || 0) > 0) return true;
      return !!(this.detail && this.detail.safety === 'risky');
    },
    /* 选中这条的结果是不是被截断了。
       全文能从 skill 的输出文件里取到时（detail.full）就不算截断 ——
       控制台现在的目标是"能看到的都是原样全文"，截断只发生在浏览器这一侧的
       2MB 上限上（detail_truncated）。 */
    selTruncated: function () {
      var rec = this.selRecord;
      if (!rec) return false;
      if (this.detail && this.detail.full) return !!this.detail.detail_truncated;
      if (rec.state === 'running') return false;
      return !!rec.truncated;
    },
    selFull: function () {
      return !!(this.detail && this.detail.full);
    },
    /* 头部那个"多少字符"：跑着的调用还没落盘全文，用实时原文当前的长度，
       这样"输出在长"这件事本身也看得见 */
    selOutputSize: function () {
      var rec = this.selRecord;
      if (!rec) return 0;
      if (this.detail && this.detailKey === (rec.run_id + '#' + rec.step)
          && this.detail.live && this.detail.output_size) return this.detail.output_size;
      return rec.output_size || 0;
    },
    /* 这一轮的执行进度：完成几步 / 共几步，外加现在跑的是第几步 */
    stepProgress: function () {
      var steps = this.runSteps || [];
      var done = steps.filter(function (s) { return s.state === 'done' || s.state === 'blocked'; }).length;
      var running = steps.filter(function (s) { return s.state === 'running'; })[0] || null;
      return { done: done, total: steps.length, running: running };
    },
    stageIndex: function () {
      var s = (this.runInfo && this.runInfo.stage) || 'init';
      if (s === 'exec' || s === 'tool') return 2;
      if (s === 'verify') return 3;
      if (s === 'crosscheck') return 4;
      if (s === 'report' || s === 'done') return 5;
      return 0;
    }
  },
  mounted: function () {
    this.load();
    this.refreshAudit();
    var self = this;
    this.clock = setInterval(function () { self.now = Date.now(); }, 1000);
    /* 轮询节奏跟着"有没有东西在跑"走：闲着 5 秒一次足够；有工具在跑就缩到
       1.2 秒，实时状态才是实时的（后端自己会节流，1.2 秒不会给机器添负担）。 */
    this.schedule(5000);
  },
  unmounted: function () {
    clearInterval(this.clock);
    clearTimeout(this.poller);
    if (this.logObserver) { this.logObserver.disconnect(); this.logObserver = null; }
  },
  methods: {
    schedule: function (delay) {
      var self = this;
      clearTimeout(this.poller);
      this.poller = setTimeout(function () {
        self.load().then(function () { self.schedule(self.live ? 1200 : 5000); });
      }, delay);
    },
    explain: function (e) {
      var m = (e && e.message) || String(e);
      if (/not found|404/i.test(m)) {
        return '后端没有这个接口：控制台服务大概率还是改动前的旧进程，重启一次即可。';
      }
      return '读取调用记录失败：' + m;
    },
    load: function () {
      var self = this;
      if (this.busy) return Promise.resolve();
      this.busy = true;
      return API.get('/api/calls').then(function (data) {
        self.groups = data.items || [];
        self.hiddenCount = data.hidden || 0;
        self.live = data.live || null;
        self.summary = data.summary || null;
        self.scope = data.scope || '';
        self.loadError = '';
        /* 选中项优先级：正在跑的工具 > 原来那个 > 第一个。
           进来必须看得到东西，而不是一片空白等用户去点。 */
        var exist = self.groups.some(function (g) { return g.tool === self.current; });
        var ids = self.groups.map(function (g) { return g.tool; });
        if (!exist) self.current = (self.live && ids.indexOf(self.live.tool) >= 0)
          ? self.live.tool : (ids[0] || '');
        if (self.live && ids.indexOf(self.live.tool) >= 0 && !self.selKey) self.current = self.live.tool;
        self.restoreSelection();
        self.scrollLog();      // 跑着的输出在长，看的人跟着往下走
        if (self.selRecord) self.loadSteps(self.selRecord.run_id, !!self.live);
      }).catch(function (e) { self.loadError = self.explain(e); })
        .then(function () { self.busy = false; });
    },
    /* 轮询会把 records 整个换掉，靠 run#step 把选中项落回原位 */
    restoreSelection: function () {
      var rows = this.records;
      if (!rows.length) { this.selIndex = 0; this.selKey = ''; this.detail = null; this.detailKey = ''; return; }
      var i = 0;
      if (this.selKey) {
        for (var k = 0; k < rows.length; k++) {
          if (rows[k].run_id + '#' + rows[k].step === this.selKey) { i = k; break; }
        }
      }
      this.selIndex = i;
      this.selKey = rows[i].run_id + '#' + rows[i].step;
      this.loadDetail();
    },
    pickTool: function (g) {
      this.current = g.tool;
      this.selKey = '';
      this.selIndex = 0;
      this.detail = null;
      this.detailKey = '';
      this.detailState = '';
      this.restoreSelection();
    },
    selectRow: function (i) {
      var row = this.records[i];
      if (!row) return;
      this.selIndex = i;
      this.selKey = row.run_id + '#' + row.step;
      this.loadDetail();
    },
    /* 列表里只带了输出开头，全文按需取；同时把所属任务的状态取回来画阶段条 */
    loadDetail: function () {
      var rec = this.selRecord;
      if (!rec) { this.detail = null; this.detailKey = ''; this.runInfo = null; return; }
      var key = rec.run_id + '#' + rec.step;
      var running = rec.state === 'running';
      /* 已经结束的那条取一次就够；还在跑的要一轮一取 —— 输出在长，
         缓存住就等于"永远停在点开时那一屏"，实时就没了。
         状态变了（跑完 / 失败）还得再取一次：跑完那一刻才拿得到原文文件。 */
      if (key === this.detailKey && rec.state === this.detailState
          && (!running || this.detailBusy)) return;
      if (key !== this.detailKey) { this.detail = null; this.followLog = true; }   // 换了一条才清，免得跑着的看着闪
      this.detailKey = key;
      this.detailState = rec.state;
      this.detailBusy = true;
      this.runInfo = null;
      var self = this;
      var one = API.get('/api/calls/detail?run_id=' + encodeURIComponent(rec.run_id)
                        + '&step=' + (rec.step || 0))
        .then(function (d) { if (self.detailKey === key) self.detail = d; });
      var two = API.get('/api/tasks/' + encodeURIComponent(rec.run_id))
        .then(function (d) { if (self.detailKey === key) self.runInfo = d; });
      this.loadSteps(rec.run_id, running);   // 跑着的任务，步骤状态也在变
      return Promise.all([one.catch(function () { /* 详情取不到就退回列表里的摘要 */ }),
                          two.catch(function () { })]
      ).then(function () { self.detailBusy = false; self.scrollLog(); });
    },
    /* 所属任务这一轮：把整轮的步骤与每步状态从轨迹里还原出来。
       "执行到哪一步、下一步是什么、哪一步被拦下了"是执行现场最需要看的东西，
       光看某一个工具的输出，等于只见树木不见森林。 */
    loadSteps: function (runId, refresh) {
      var self = this;
      if (!runId || this.stepsBusy) return Promise.resolve();
      if (runId === this.stepsKey && !refresh) return Promise.resolve();
      this.stepsBusy = true;
      return API.get('/api/tasks/' + encodeURIComponent(runId) + '/events?limit=2000')
        .then(function (data) {
          self.stepsKey = runId;
          self.runSteps = self.buildSteps(data.items || []);
        })
        .catch(function () { /* 轨迹取不到不影响看输出 */ })
        .then(function () { self.stepsBusy = false; });
    },
    buildSteps: function (events) {
      var plan = [], calls = {}, results = {};
      events.forEach(function (e) {
        var d = (e && e.data) || {};
        if (e.type === 'plan' && d.steps && d.steps.length) plan = d.steps;
        else if (e.type === 'tool_call' || (e.type === 'error' && d.blocked)) {
          var i = d.step || (Object.keys(calls).length + 1);
          calls[i] = { tool: d.tool || '', blocked: !!d.blocked };
        } else if (e.type === 'tool_result') {
          var j = d.step || 0;
          results[j] = { ok: !!d.ok, elapsed: d.elapsed, error: d.error || '' };
        }
      });
      var total = Math.max(plan.length, Object.keys(calls).length);
      var steps = [];
      for (var k = 1; k <= total; k++) {
        var call = calls[k], res = results[k], planned = plan[k - 1];
        var state = 'todo';
        if (call && call.blocked) state = 'blocked';
        else if (res) state = res.ok ? 'done' : 'failed';
        else if (call) state = 'running';
        steps.push({
          n: k,
          tool: (call && call.tool) || (planned && planned.tool) || '未知工具',
          why: (planned && planned.why) || '',
          state: state,
          elapsed: res ? res.elapsed : null,
          error: res ? res.error : ''
        });
      }
      return steps;
    },
    /* ── 流水里"不要看这条"：只隐藏，不动 skill 的轨迹 ── */
    hideCall: function (rec) {
      var self = this;
      if (!rec || this.hiding) return;
      this.hiding = true;
      return API.post('/api/calls/hide', {
        run_id: rec.run_id, step: rec.step, tool: rec.tool
      }).then(function () {
        self.hideMsg = '已从流水删除（可恢复）';
        self.selKey = '';
        return self.load();
      }).catch(function (e) { self.loadError = self.explain(e); })
        .then(function () {
          self.hiding = false;
          setTimeout(function () { self.hideMsg = ''; }, 4000);
        });
    },
    restoreHidden: function () {
      var self = this;
      if (this.hiding) return;
      if (!confirm('把隐藏的 ' + this.hiddenCount + ' 条调用恢复显示？\n\n轨迹从来没被改过，恢复只是控制台这边不藏了。')) return;
      this.hiding = true;
      return API.post('/api/calls/unhide', {}).then(function () {
        self.hideMsg = '已全部恢复';
        return self.load();
      }).catch(function (e) { self.loadError = self.explain(e); })
        .then(function () {
          self.hiding = false;
          setTimeout(function () { self.hideMsg = ''; }, 4000);
        });
    },

    refreshAudit: function () {
      var self = this;
      return API.get('/api/audit?limit=8').then(function (data) { self.auditTail = data.items || []; })
        .catch(function () { /* 审计拉不到不影响看板 */ });
    },

    /* ── 展示格式 ── */
    secs: function (n) {
      if (n === null || n === undefined) return '-';
      if (n < 1) return Number(n).toFixed(1) + 's';
      if (n < 60) return Math.round(n) + 's';
      return Math.floor(n / 60) + 'm' + Math.round(n % 60) + 's';
    },
    elapsedText: function (rec) {
      if (typeof rec.elapsed === 'number') return this.secs(rec.elapsed);
      if (rec.state === 'running' && rec.at) {
        return this.secs(Math.max(0, Math.round((this.now - Date.parse(rec.at)) / 1000)));
      }
      return '-';
    },
    hms: function (ts) {
      if (!ts) return '-';
      var d = new Date(ts);
      if (isNaN(d.getTime())) return String(ts).slice(11, 19);
      var p = function (x) { return String(x).padStart(2, '0'); };
      return p(d.getHours()) + ':' + p(d.getMinutes()) + ':' + p(d.getSeconds());
    },
    paramsText: function (rec) {
      var params = (this.detail && this.detailKey === (rec.run_id + '#' + rec.step))
        ? this.detail.params : rec.params;
      var keys = Object.keys(params || {});
      if (!keys.length) return '';
      return keys.slice(0, 3).map(function (k) {
        var v = String(params[k]);
        return k + '=' + (v.length > 34 ? v.slice(0, 34) + '…' : v);
      }).join(' ');
    },
    paramsJson: function () {
      var d = this.detail || {};
      var params = d.params || (this.selRecord && this.selRecord.params) || {};
      var keys = Object.keys(params);
      if (!keys.length) return '（这次调用没有参数）';
      return keys.map(function (k) { return k + ' = ' + JSON.stringify(params[k]); }).join('  ·  ');
    },
    resultLabel: function (s) {
      return { running: '运行中', done: '成功', failed: '失败', blocked: '已拦截',
               no_result: '无结果' }[s] || s || '-';
    },
    /* 整轮里单步的状态说法：待执行 / 执行中 / 完成 / 失败 / 已拦截 */
    stepLabel: function (s) {
      return { todo: '待执行', running: '执行中', done: '完成', failed: '失败',
               blocked: '已拦截' }[s] || s;
    },
    stepTag: function (s) {
      return { todo: 'info', running: 'warn', done: 'ok', failed: 'bad',
               blocked: 'bad' }[s] || '';
    },
    resultTag: function (s) {
      return { running: 'warn', done: 'ok', failed: 'bad', blocked: 'bad',
               no_result: 'info' }[s] || '';
    },
    /* 工具索引上的那枚状态标签。口径必须和流水里每一条对得上：
       "只有调用、没有结果"的孤儿调用也算异常，不能因为 failed/blocked 都是 0
       就盖章"正常"—— 点开一看写的是"无结果"，两头打架。 */
    groupLabel: function (g) {
      if (g.running) return '在跑';
      if (g.failed) return g.failed + ' 次失败';
      if (g.blocked) return g.blocked + ' 次被拦';
      if (g.no_result) return g.no_result + ' 次无结果';
      return '正常';
    },
    groupTag: function (g) {
      if (g.failed || g.blocked) return 'bad';
      if (g.running) return 'warn';
      if (g.no_result) return 'warn';
      return 'ok';
    },
    /* 没有输出时如实说清是"还在跑/被拦下/就是空的"，不要留一块空白让人瞎猜 */
    outputText: function () {
      var rec = this.selRecord;
      if (!rec) return '';
      /* 跑着的优先给实时尾巴：这是工具此刻真实打出来的行。
         后端还没吐出东西时给一句等待提示，省得对着空白以为界面坏了。 */
      if (rec.state === 'running') {
        /* 运行中的原文：后端读的是 executor 边跑边写的那份文件，
           每轮轮询追加一截 —— 输出是一点点长出来的，不是跑完才一股脑出现。 */
        var liveDetail = (this.detail && this.detailKey === (rec.run_id + '#' + rec.step)
                          && this.detail.live && this.detail.output) ? this.detail.output : '';
        if (liveDetail) return liveDetail;
        var live = (this.live && this.live.run_id === rec.run_id
                    && this.live.step === rec.step && this.live.tail) ? this.live.tail : '';
        return live || '工具正在输出，请稍等(已运行 ' + this.elapsedText(rec) + ')···';
      }
      if (this.detail && this.detailKey === (rec.run_id + '#' + rec.step)) {
        if (this.detail.output) return this.detail.output;
        if (this.detail.error) return '（工具报错：' + this.detail.error + '）';
      }
      if (rec.output_head) {
        return rec.output_head + (rec.truncated ? '\n…（输出太长，这里只给开头，完整内容见下方说明）' : '');
      }
      if (rec.error) return '（工具报错：' + rec.error + '）';
      if (rec.state === 'blocked') return '这次调用被安全策略拦下了，没有执行。';
      if (rec.state === 'no_result') return '轨迹里只有调用、没有结果：宿主进程可能被中断了。';
      return '这次调用没有留下输出。';
    },
    /* 输出这块的来路要说清楚：实时尾巴、全文、还是截断的开头 */
    outputSource: function () {
      var rec = this.selRecord;
      if (!rec) return '';
      if (rec.state === 'running') {
        if (this.detail && this.detail.live && this.detail.output) return '实时追加中，约 1 秒刷新一次';
        return (this.live && this.live.tail) ? '实时追加中，约 1 秒刷新一次'
          : '运行中，等待工具输出…';
      }
      if (this.selFull) {
        return this.selTruncated ? '完整原文（超出 2MB，只显示前段）' : '完整原文（未截断）';
      }
      if (rec.truncated) return '轨迹里的开头（未取到原文文件）';
      return '工具原样输出';
    },
    /* 左栏"在跑"的工具要显示跑了多久，不然只能看到"在跑"三个字 */
    runningElapsed: function (g) {
      var row = null;
      for (var i = 0; i < g.records.length; i++) {
        if (g.records[i].state === 'running') { row = g.records[i]; break; }
      }
      if (!row || !row.at) return '';
      return '已跑 ' + this.secs(Math.max(0, Math.round((this.now - Date.parse(row.at)) / 1000)));
    },
    /* 后端按工具认出来的结果摘要：{text, level, highlight} */
    digestOf: function (r) {
      var d = r && r.digest;
      return (d && d.text) ? d : null;
    },
    /* 流水/顶栏那一行摘要。跑着的是"此刻在做什么"，跑完的是"出了什么" */
    rowSummary: function (r) {
      var d = this.digestOf(r);
      if (d) return d.text;
      return (r && r.state === 'running') ? '运行中，等待工具输出…' : '';
    },
    /* 输出框跟着最新一行走。
       以前只在 loadDetail 结束那一瞬间贴一次底：只要有一条刷新路径没走到这里
       （切记录、跑完落全文、轮询回来的时机不同），视图就停在开头那一屏不动了。
       现在直接盯着这个 <pre> 的内容变化 —— 内容一改就贴底，谁改的都算。
       用户自己往上翻时不再硬拽回去；翻回底部会自动恢复跟随。 */
    scrollLog: function () {
      var self = this;
      this.$nextTick(function () { self.bindLog(); self.pinLog(); });
    },
    bindLog: function () {
      var el = this.$refs && this.$refs.logEl;
      if (this.logObserver) { this.logObserver.disconnect(); this.logObserver = null; }
      if (!el || !window.MutationObserver) return;
      var self = this;
      this.logObserver = new MutationObserver(function () { self.pinLog(); });
      this.logObserver.observe(el, { childList: true, characterData: true, subtree: true });
    },
    pinLog: function () {
      var el = this.$refs && this.$refs.logEl;
      if (!el || !this.followLog) return;
      el.scrollTop = el.scrollHeight;
    },
    /* 往上翻（离底超过一屏内的一段）就不再自动跟；翻回底部则恢复跟随。
       阈值给宽一点：鼠标滚一格、触控板蹭一下都会超过几十像素，
       那样就把跟随关掉反而更烦人。 */
    onLogScroll: function () {
      var el = this.$refs && this.$refs.logEl;
      if (!el) return;
      this.followLog = (el.scrollHeight - el.scrollTop - el.clientHeight) < 120;
    },
    backToLatest: function () {
      this.followLog = true;
      this.pinLog();
    },
    stageClass: function (i) {
      var over = this.runInfo && this.runInfo.status && this.runInfo.status !== 'running';
      if (i === 1) {
        if (!this.authNeeded) return '';
        return (over || this.stageIndex > 1) ? 'done' : 'active';
      }
      if (this.stageIndex === 5 && over) return 'done';
      if (i < this.stageIndex) return 'done';
      return i === this.stageIndex ? 'active' : '';
    }
  },
  template: [
    '<div class="task-page">',

    /* ── 顶栏：此刻在跑 + 四格口径 ── */
    '  <div class="card live-hero">',
    '    <div class="hero-top">',
    '      <span class="live-dot" :class="{mute: !live}"></span>',
    '      <div class="grow">',
    '        <div class="hero-title" v-if="live">',
    '          正在调用 <b class="mono">{{ live.tool }}</b>',
    '          <span class="muted small" v-if="live.why">　{{ live.why }}</span></div>',
    '        <div class="hero-title idle" v-else>此刻没有工具在跑</div>',
    '        <div class="hero-sub mono" v-if="live">',
    '          {{ live.run_id }}<i>·</i>',
    '          <span v-if="live.total_steps">第 {{ live.step }}/{{ live.total_steps }} 步</span>',
    '          <span v-else>第 {{ live.step }} 步</span><i>·</i>',
    '          <span class="ellipsis">{{ live.run_title }}</span></div>',
    '      </div>',
    '      <div class="hero-tick" v-if="live"><div class="v mono">{{ liveElapsed }}</div><div class="k">已运行</div></div>',
    '      <button class="btn ghost sm" @click="load">刷新</button>',
    '    </div>',
    '    <div class="live-strip">',
    '      <div class="stat" v-for="m in metrics" :key="m.k">',
    '        <div class="v" :class="{bad: m.bad}">{{ m.v }}</div><div class="k">{{ m.k }}</div></div>',
    '      <div class="grow"></div>',
    '      <div class="scope">{{ scope }}</div>',
    '    </div>',
    '  </div>',

    /* 左+中：工具索引 | 输入与输出。两块并排，外面那层只是用来分列 */
    '  <div class="task-main">',

    /* ── 左：工具索引 ── */
    '    <div class="card tool-index">',
    '      <div class="card-head"><span class="title">工具索引</span>',
    '        <span class="grow"></span>',
    '        <div class="seg">',
    '          <button :class="{on: filter === \'all\'}" @click="filter = \'all\'">全部 <span class="n">{{ groups.length }}</span></button>',
    '          <button :class="{on: filter === \'failed\'}" @click="filter = \'failed\'">失败</button>',
    '          <button :class="{on: filter === \'live\'}" @click="filter = \'live\'">在跑</button>',
    '        </div>',
    '      </div>',
    '      <div class="card-body tool-list">',
    '        <button class="tool-item" v-for="g in shownTools" :key="g.tool"',
    '                :class="{active: g.tool === current, live: g.running}" @click="pickTool(g)">',
    '          <span class="live-dot" :class="{mute: !g.running}"></span>',
    '          <div class="grow">',
    '            <div class="row"><span class="mono name ellipsis">{{ g.tool }}</span>',
    '              <span class="grow"></span><span class="mono n">{{ g.calls }}</span></div>',
    '            <div class="tiny muted ellipsis">{{ g.last_why || "未记录调用理由" }}</div>',
    '            <div class="tiny muted"><span class="mono">{{ hms(g.last_at) }}</span>',
    '              <span v-if="g.running" class="mono warn-text">　{{ runningElapsed(g) }}</span>',
    '              <span v-else-if="g.avg_elapsed !== null && g.avg_elapsed !== undefined">　均 {{ secs(g.avg_elapsed) }}</span></div>',
    '          </div>',
    '          <span class="tag" :class="groupTag(g)">{{ groupLabel(g) }}</span>',
    '        </button>',
    '        <div v-if="!shownTools.length" class="empty">还没有工具被调用过。</div>',
    '      </div>',
    '    </div>',

    /* ── 中：这一次调用的输入与输出（这一页的主角，给足面积）── */
    '    <div class="card detail-card">',
    '      <div class="card-head"><span class="title">输入与输出</span>',
    '        <template v-if="selRecord">',
    '          <span class="mono small">#{{ selRecord.step }} {{ selRecord.tool }}</span>',
    '          <span class="grow"></span>',
    '          <span class="tag warn" v-if="selRecord.state === \'running\'">实时刷新中</span>',
        '          <span class="tag ok" v-else-if="selFull && !selTruncated">完整原文</span>',
    '          <span class="tag warn" v-if="selTruncated">输出已截断</span>',
    '          <span class="tag" :class="resultTag(selRecord.state)">{{ resultLabel(selRecord.state) }}</span>',
    '          <span class="muted tiny mono">{{ elapsedText(selRecord) }}</span>',
    '        </template>',
    '        <span class="grow" v-else></span>',
    '      </div>',
    '      <div class="card-body detail-body" v-if="selRecord">',
    '        <div class="detail-params">',
    '          <div class="tiny muted">输入（工具参数）',
    '            <span class="muted" v-if="selRecord.why">　调用理由：{{ selRecord.why }}</span></div>',
    '          <div class="mono small">{{ paramsJson() }}</div>',
    '        </div>',
    '        <div class="tiny muted">原始输出',
    '          <span v-if="selRecord.returncode !== null && selRecord.returncode !== undefined">　退出码 {{ selRecord.returncode }}</span>',
    '          <span v-if="selOutputSize">　{{ selOutputSize }} 字符</span>',
    '          <span v-if="detailBusy">　读取中…</span>',
    '          <span class="muted">　{{ outputSource() }}</span></div>',
    '        <pre class="log detail-log" ref="logEl" @scroll="onLogScroll"',
    '             :class="{running: selRecord.state === \'running\'}">{{ outputText() }}</pre>',
    '      </div>',
    '      <div class="card-body" v-else><div class="empty">在右边点一条调用，这里显示那次调用的输入与输出</div></div>',
    '      <div class="card-foot howto-foot">',
    '        <span>任务由宿主 Agent 或命令行发起：</span>',
    '        <span class="mono">python3 scripts/agents/runner.py "巡检 192.168.1.1 的开放端口和服务"</span>',
    '        <span class="mono">python3 scripts/mcp_server.py</span>',
    '        <span class="muted">仅用于已获授权的目标</span>',
    '      </div>',
    '    </div>',

    '  </div>',

    /* ── 右：这次调用属于谁 + 调用流水。贯通两行，顶到页顶 ── */
    '  <div class="col task-side">',
    '      <div class="card">',
    /* 标题栏不挂任务状态：这里回答的是"这次调用属于谁"。整轮成没成，看下面的
       执行情况条就够了；挂一个"失败"在最显眼处，反而会被读成"这通调用失败了"。 */
    '        <div class="card-head"><span class="title">所属任务</span></div>',
    '        <div class="card-body col" style="gap:10px" v-if="selRecord">',
    '          <div class="run-title" :title="selRecord.run_title">{{ selRecord.run_title || "-" }}</div>',
    '          <div class="run-sub">',
    '            <span class="mono">{{ selRecord.run_id }}</span><i>·</i>',
    '            <span>触发 <b>{{ selRecord.run_source || "-" }}</b></span><i>·</i>',
    '            <span>共 {{ selRecord.total_steps || (runInfo && runInfo.counts && runInfo.counts.tools) || "-" }} 步</span>',
    '          </div>',
    '          <div class="trace-strip">',
    '            <div class="trace-step" v-for="(s, i) in stages" :key="s" :class="stageClass(i)">{{ s }}</div>',
    '          </div>',
    /* 执行情况：这一轮排了几步、每步成没成、现在卡在第几步。
       "第 N/M 步" 只说当前位置，这里回答"整轮走到哪儿了"。 */
    '          <div class="run-steps" v-if="runSteps.length">',
    '            <div class="steps-head"><span>执行情况</span>',
    '              <span class="grow"></span>',
    '              <span class="mono">{{ stepProgress.done }}/{{ stepProgress.total }} 步完成</span></div>',
    '            <div class="steps-bar">',
    '              <span v-for="s in runSteps" :key="s.n" :class="\'seg \' + s.state"></span>',
    '            </div>',
    '            <div class="steps-list">',
    '            <div class="step-row" v-for="s in runSteps" :key="\'r\' + s.n" :class="s.state">',
    '              <span class="n mono">{{ s.n }}</span>',
    '              <span class="tool mono ellipsis">{{ s.tool }}</span>',
    '              <span class="grow"></span>',
    '              <span class="mono tiny dur">{{ s.elapsed !== null && s.elapsed !== undefined ? secs(s.elapsed) : "" }}</span>',
    '              <span class="tag" :class="stepTag(s.state)">{{ stepLabel(s.state) }}</span>',
    '            </div>',
    '            </div>',
    '          </div>',
    '        </div>',
    '      </div>',

    '      <div class="card flow-card">',
    '        <div class="card-head"><span class="title">调用流水</span>',
    '          <span class="mono small" v-if="current">{{ current }}</span>',
    '          <span class="grow"></span>',
    '          <span class="tag ok" v-if="hideMsg">{{ hideMsg }}</span>',
    '          <button class="btn ghost sm" v-if="hiddenCount" :disabled="hiding" @click="restoreHidden">',
    '            恢复删掉的 {{ hiddenCount }} 条</button>',
    '          <span class="muted small" v-else-if="currentGroup">成功 {{ currentGroup.ok }} / 共 {{ currentGroup.calls }}</span>',
    '        </div>',
    '        <div class="card-body flow-body">',
    '          <div class="call-row" v-for="(r, i) in records" :key="r.run_id + \'#\' + r.step"',
    '               :class="{sel: i === selIndex, live: r.state === \'running\'}"',
    '               role="button" tabindex="0" @click="selectRow(i)" @keyup.enter="selectRow(i)">',
    '            <span class="st" :class="resultTag(r.state)"></span>',
    '            <div class="grow">',
    '              <div class="row"><span class="mono t">{{ hms(r.at) }}</span>',
    '                <span class="muted tiny">#{{ r.step }}<span v-if="r.total_steps">/{{ r.total_steps }}</span></span>',
    /* 结果标签紧跟"时间 · 第几步"：一行流水的身份就是这三样 ——
       什么时候、第几步、成没成。以前它吊在右端（耗时左边，右边还有个
       隐形的删除位），看着像浮在行中间。 */
    '                <span class="tag" :class="resultTag(r.state)">{{ resultLabel(r.state) }}</span>',
    '                <span class="grow"></span>',
    '                <span class="mono tiny dur">{{ elapsedText(r) }}</span></div>',
    '              <div class="tiny mono muted ellipsis">{{ paramsText(r) || "-" }}</div>',
    /* 每一条都贴一句结果摘要：跑着的说"此刻在做什么"，跑完的说"出了什么"。
       流水是拿来扫的，不该逼人点开每一条才知道结果。 */
    '              <div class="tiny summary-line ellipsis" v-if="rowSummary(r)"',
    '                   :class="[digestOf(r) ? digestOf(r).level : \'info\', {live: r.state === \'running\'}]">',
    '                {{ rowSummary(r) }}</div>',
    '            </div>',
    '            <button class="row-x" :disabled="hiding"',
    '                    title="删掉这条流水（轨迹不动，随时可恢复）"',
    '                    aria-label="删除这条流水" @click.stop="hideCall(r)">',
    '              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"',
    '                   stroke-linecap="round"><path d="M6 6l12 12M18 6L6 18"/></svg>',
    '            </button>',
    '          </div>',
    '          <div v-if="!records.length" class="empty">这个工具还没有调用记录。</div>',
    '        </div>',
    '      </div>',

    '      <div class="card side-chain">',
    '        <div class="card-head"><span class="title">审计留痕</span><span class="grow"></span>',
    '          <button class="btn ghost sm" @click="refreshAudit">刷新</button></div>',
    '        <div class="card-body"><div class="chain">',
    '          <div class="chain-row ok" v-for="e in auditTail" :key="e.id">',
    '            <div class="top"><span class="mono">#{{ e.id }}</span><span>{{ e.action }}</span></div>',
    '            <div class="hash">{{ (e.hash || "").slice(0, 16) }}…</div>',
    '          </div>',
    '          <div v-if="!auditTail.length" class="muted small">暂无记录</div>',
    '        </div></div>',
    '      </div>',
    '  </div>',

    '  <div class="banner bad" v-if="error || loadError">{{ error || loadError }}</div>',
    '</div>'
  ].join('\n')
};
