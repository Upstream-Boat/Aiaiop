/* 视图：审计链 — 校验结论 + 记录时间线 + 演示用"篡改/还原"。
   演示要点：先校验全绿，再点篡改，同一页立刻标红。

   记录是分页的：审计链只会越滚越长（现在就有几百条），一屏铺到底既划不完也
   找不到东西。每页 50 条起，筛选一变就回到第一页。 */

/* 分页条只放在列表底部：顶部那条离"最近记录"的标题太近，看着像标题的一部分。
   整页都装得下（只有一页）时整条都不出现 —— 没什么可翻的时候，
   摆一排按不动的翻页按钮和条数选择只是噪音。 */
var PAGER = [
  '      <div class="pager" v-if="pageCount > 1">',
  '        <button class="btn ghost sm" :disabled="page <= 1" @click="go(page - 1)">上一页</button>',
  '        <span class="pg">第 <b>{{ page }}</b> / {{ pageCount }} 页</span>',
  '        <button class="btn ghost sm" :disabled="page >= pageCount" @click="go(page + 1)">下一页</button>',
  '        <span class="grow"></span>',
  '        <span class="muted tiny mono">{{ rangeText }}</span>',
  /* 条数选择只列出"真的还能翻页"的档位：选 200 条而总共不到 200 条时，
     200 这个按钮就不该在那儿（点了也还是这一页，等于没得选）。 */
  '        <div class="seg" v-if="sizeOptions.length > 1">',
  '          <button v-for="s in sizeOptions" :key="s" :class="{on: s === pageSize}"',
  '                  @click="setSize(s)">{{ s }}/页</button>',
  '        </div>',
  '      </div>'].join('\n')

window.ViewAudit = {
  name: 'ViewAudit',
  data: function () {
    return { entries: [], verdict: null, busy: false, error: '', marked: [], filter: 'all',
             page: 1, pageSize: 20, pageSizes: [20, 50, 100, 200] };
  },
  mounted: function () { this.load(); this.verify(); },
  computed: {
    /* 记录按"谁的动作"分类：工具跑出来的、规则库动过的、控制台自己留的。
       工具那一类里 ok=False / 拦截 的都算"坏消息"，单独能筛出来。 */
    counted: function () {
      var c = { tool: 0, bad: 0, rules: 0, other: 0 };
      this.entries.forEach(function (e) {
        var k = this.kindOf(e);
        if (k === 'tool' || k === 'blocked') c.tool += 1;
        if (k === 'rules') c.rules += 1;
        if (k !== 'tool' && k !== 'blocked' && k !== 'rules') c.other += 1;
        if (this.isBad(e)) c.bad += 1;
      }, this);
      return c;
    },
    shown: function () {
      var self = this;
      var f = this.filter;
      if (f === 'bad') return this.entries.filter(function (e) { return self.isBad(e); });
      if (f === 'tool') return this.entries.filter(function (e) {
        var k = self.kindOf(e);
        return k === 'tool' || k === 'blocked';
      });
      if (f === 'rules') return this.entries.filter(function (e) { return self.kindOf(e) === 'rules'; });
      if (f === 'other') return this.entries.filter(function (e) {
        var k = self.kindOf(e);
        return k !== 'tool' && k !== 'blocked' && k !== 'rules';
      });
      return this.entries;
    },
    pageCount: function () {
      return Math.max(1, Math.ceil(this.shown.length / this.pageSize));
    },
    /* 只有"比当前条数还小"的档位才有意义：50 条记录给个 100/页 的按钮，
       点下去页面纹丝不动，只会让人怀疑是不是点坏了。 */
    sizeOptions: function () {
      var total = this.shown.length;
      return this.pageSizes.filter(function (s) { return s < total; });
    },
    paged: function () {
      var from = (this.page - 1) * this.pageSize;
      return this.shown.slice(from, from + this.pageSize);
    },
    rangeText: function () {
      if (!this.shown.length) return '0 条';
      var from = (this.page - 1) * this.pageSize + 1;
      var to = Math.min(this.shown.length, this.page * this.pageSize);
      return from + '–' + to + ' / ' + this.shown.length + ' 条';
    }
  },
  watch: {
    /* 换了筛选口径，页码留在第 4 页只会看到一片空白，一律回到第一页 */
    filter: function () { this.page = 1; },
    /* 记录是轮询来的：条数变少时页码可能越界，夹回最后一页 */
    pageCount: function () { if (this.page > this.pageCount) this.page = this.pageCount; }
  },
  methods: {
    go: function (n) {
      this.page = Math.min(Math.max(1, n), this.pageCount);
      var card = this.$refs.listCard;
      if (card && card.scrollIntoView) card.scrollIntoView({ block: 'start', behavior: 'smooth' });
    },
    setSize: function (n) {
      this.pageSize = n;
      this.page = 1;
    },
    load: function () {
      var self = this;
      return API.get('/api/audit?limit=500').then(function (data) {
        self.entries = data.items || [];
      }).catch(function (e) { self.error = e.message; });
    },
    verify: function () {
      var self = this;
      this.busy = true;
      return API.post('/api/audit/verify', {}).then(function (data) {
        self.verdict = data;
        self.marked = (data.tampered || []).map(function (t) { return t.id; });
        return self.load();
      }).catch(function (e) { self.error = e.message; })
        .then(function () { self.busy = false; });
    },
    tamper: function () {
      var self = this;
      return API.post('/api/audit/tamper-demo', {}).then(function () { return self.verify(); });
    },
    restore: function () {
      var self = this;
      return API.post('/api/audit/tamper-restore', {}).then(function () { return self.verify(); });
    },
    isMarked: function (id) { return this.marked.indexOf(id) >= 0; },
    kindOf: function (e) {
      var a = (e && e.action) || '';
      if (a.indexOf('rules.') === 0) return 'rules';
      if (a === 'tool_blocked') return 'blocked';
      if (a === 'tool_call') return 'tool';
      if (a === 'plan' || a === 'report') return 'task';
      if (a === 'calls.hide' || a === 'calls.unhide') return 'console';
      return 'other';
    },
    kindLabel: function (e) {
      return { tool: '工具调用', blocked: '已拦截', rules: '规则库', task: '任务',
               console: '控制台', other: '其他' }[this.kindOf(e)];
    },
    /* 坏消息的判定：被拦下的，或者工具自己报了失败。
       审计链只负责记账，把 ok=False 挑出来是控制台这一侧的读法。 */
    isBad: function (e) {
      if (!e) return false;
      if (this.kindOf(e) === 'blocked') return true;
      var d = String(e.detail || '') + ' ' + String(e.action || '');
      return /ok=False|ok=false|失败|出错|拦截|error/i.test(d);
    }
  },
  template: [
    '<div class="page audit-page">',

    '  <div class="card">',
    '    <div class="card-head"><span class="title">完整性校验</span>',
    '      <span class="muted small">{{ entries.length }} 条记录</span><span class="grow"></span>',
    '      <span class="tag" :class="verdict ? (verdict.ok ? \'ok\' : \'bad\') : \'\'">{{ verdict ? (verdict.ok ? "链路完整" : "发现异常") : "未校验" }}</span>',
    '      <button class="btn sm" :disabled="busy" @click="verify">校验</button>',
    '      <button class="btn sm danger" :disabled="busy" @click="tamper">篡改演示</button>',
    '      <button class="btn ghost sm" :disabled="busy" @click="restore">还原</button>',
    '    </div>',
    '    <div class="stat-strip audit-strip" v-if="verdict">',
    '      <div class="stat"><div class="v">{{ verdict.total }}</div><div class="k">记录总数</div></div>',
    '      <div class="stat"><div class="v">{{ verdict.checked }}</div><div class="k">本次校验</div></div>',
    '      <div class="stat"><div class="v" :style="{color: verdict.tampered.length ? \'var(--danger)\' : \'var(--signal)\'}">{{ verdict.tampered.length }}</div><div class="k">篡改嫌疑</div></div>',
    '      <div class="stat"><div class="v" :style="{color: verdict.broken.length ? \'var(--danger)\' : \'var(--signal)\'}">{{ verdict.broken.length }}</div><div class="k">断链</div></div>',
    '      <div class="stat"><div class="v">{{ verdict.anchors.recorded }}</div><div class="k">链头锚点</div></div>',
    '      <div class="stat"><div class="v">{{ counted.tool }}</div><div class="k">工具调用</div></div>',
    '      <div class="stat"><div class="v" :class="{bad: counted.bad}">{{ counted.bad }}</div><div class="k">失败/拦截</div></div>',
    '      <div class="stat"><div class="v">{{ counted.rules }}</div><div class="k">规则库动作</div></div>',
    '      <div class="stat"><div class="v" style="font-size:15px">{{ verdict.algo }}</div><div class="k">算法</div></div>',
    '    </div>',
    '    <div class="card-body col" style="gap:12px">',
    '      <div class="verify-panel" v-if="verdict && (verdict.tampered.length || verdict.broken.length)">',
    '        <div class="finding-line bad" v-for="(t, i) in verdict.tampered" :key="\'t\' + i">',
    '          篡改嫌疑 #{{ t.id }} {{ t.action }} · {{ t.reason }} · 期望 {{ t.expect }} 实际 {{ t.actual }}</div>',
    '        <div class="finding-line bad" v-for="(b, i) in verdict.broken" :key="\'b\' + i">',
    '          断链 #{{ b.id }} {{ b.action }} · {{ b.kind }}</div>',
    '      </div>',
    '      <div class="banner ok" v-else-if="verdict">',
    '        逐行复算通过，锚点比对一致：内容自签名以来没有被改动过</div>',
    '      <div class="muted tiny" v-if="verdict">',
    '        每条记录用前一条的哈希签名，链头另有锚点；校验逐行重算并串接比对。',
    '        “篡改演示”改的是一条历史记录。</div>',
    '    </div>',
    '  </div>',

    '  <div class="card" ref="listCard">',
    '    <div class="card-head"><span class="title">最近记录</span>',
    '      <span class="muted small">{{ shown.length }}/{{ entries.length }} 条</span>',
    '      <span class="grow"></span>',
    '      <div class="seg">',
    '        <button :class="{on: filter === \'all\'}" @click="filter = \'all\'">全部</button>',
    '        <button :class="{on: filter === \'bad\'}" @click="filter = \'bad\'">失败/拦截 <span class="n">{{ counted.bad }}</span></button>',
    '        <button :class="{on: filter === \'tool\'}" @click="filter = \'tool\'">工具调用</button>',
    '        <button :class="{on: filter === \'rules\'}" @click="filter = \'rules\'">规则库</button>',
    '        <button :class="{on: filter === \'other\'}" @click="filter = \'other\'">其他</button>',
    '      </div></div>',
    '    <div class="card-body">',
    '      <div class="chain">',
    '        <div class="chain-row"',
    '             :class="{ ok: !isMarked(e.id) && !isBad(e), bad: isMarked(e.id) || isBad(e),',
    '                       marked: isMarked(e.id) }"',
    '             v-for="e in paged" :key="e.id">',
    '          <div class="top"><span class="mono">#{{ e.id }}</span>',
    '            <span class="tag" :class="isBad(e) ? \'bad\' : \'info\'">{{ kindLabel(e) }}</span>',
    '            <span>{{ e.action }}</span>',
    '            <span class="tag">{{ e.actor }}</span>',
    '            <span class="muted small mono">{{ Fmt.clock(e.created_at) }}</span></div>',
    '          <div class="detail" :class="{bad: isBad(e)}" v-if="e.detail">{{ e.detail }}</div>',
    '          <div class="hash">prev {{ (e.prev_hash || "").slice(0, 12) }}… → {{ (e.hash || "").slice(0, 12) }}…</div>',
    '        </div>',
    '        <div v-if="!entries.length" class="empty">还没有审计记录</div>',
    '        <div v-else-if="!shown.length" class="empty">这个筛选下没有记录</div>',
    '      </div>',
    '    </div>',
    PAGER,
    '  </div>',
    '</div>'
  ].join('\n')
};
