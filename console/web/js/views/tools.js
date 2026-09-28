/* 视图：工具状态 — "这台机器上现在哪些工具能用"。
   上：环境体检（外部命令 + 自带资源，复用 skill 的 check_deps）
   下左：43 个工具铺成卡片墙 —— 一眼看完谁可用、谁缺依赖，不用翻列表筛分类；
        点任意一张卡片，右下角给出这个工具的完整信息（参数、依赖、源码、历史调用）。
   排序把"有问题的"顶到最前面：体检页第一眼要看到的应该是坏消息。 */

window.ViewTools = {
  name: 'ViewTools',
  data: function () {
    return {
      deps: null, tools: null, selected: '', busy: '', error: '', deep: false,
      showDeps: false
    };
  },
  computed: {
    /* 缺依赖的排在前面，其余按名字（后端已按名字排好） */
    wall: function () {
      var list = (this.tools && this.tools.items) || [];
      var missing = [], ready = [];
      list.forEach(function (t) { (t.deps_ready ? ready : missing).push(t); });
      return missing.concat(ready);
    },
    picked: function () {
      var name = this.selected;
      return this.wall.filter(function (t) { return t.name === name; })[0] || null;
    },
    readyCount: function () {
      if (!this.tools) return '-';
      return this.tools.summary.total - this.tools.summary.deps_missing.length;
    },
    cmdIndex: function () {
      var out = {};
      var list = (this.deps && this.deps.commands) || [];
      list.forEach(function (c) { out[c.cmd] = c; });
      return out;
    }
  },
  mounted: function () { this.load(false); this.loadTools(); },
  methods: {
    load: function (deep) {
      var self = this;
      this.busy = 'deps';
      this.deep = !!deep;
      this.error = '';
      return API.get('/api/deps' + (deep ? '?probe=1' : '?probe=0'))
        .then(function (data) { self.deps = data; })
        .catch(function (e) { self.error = self.explain(e, '/api/deps'); })
        .then(function () { self.busy = ''; });
    },
    loadTools: function () {
      var self = this;
      return API.get('/api/tools')
        .then(function (data) {
          self.tools = data;
          if (!self.selected && self.wall.length) self.selected = self.wall[0].name;
        })
        .catch(function (e) { self.error = self.explain(e, '/api/tools'); });
    },
    explain: function (e, api) {
      var m = (e && e.message) || String(e);
      if (/not found|404/i.test(m)) {
        return '后端没有 ' + api + ' 这个接口：控制台服务大概率还在跑改动前的旧进程。'
          + 'Ctrl+C 停掉后重新启动（python3 console/server/app.py）即可。';
      }
      return '读取失败：' + m;
    },
    pick: function (t) { this.selected = t.name; },
    cmdTag: function (c) {
      if (!c.present) return 'bad';
      return c.ok ? 'ok' : 'warn';
    },
    cmdLabel: function (c) {
      if (!c.present) return '缺失';
      return c.ok ? '就绪' : '异常';
    },
    /* 卡片上的健康口径：依赖齐 = 能用；缺东西 = 一调就失败 */
    health: function (t) { return t.deps_ready ? 'ok' : 'bad'; },
    healthLabel: function (t) { return t.deps_ready ? '可用' : '缺依赖'; },
    depsText: function (t) {
      if (!t.deps.length) return '无需外部命令';
      return t.deps.map(function (d) { return d.cmd + (d.present ? '' : '（缺）'); }).join('、');
    },
    /* 缺哪个命令、怎么装：从 /api/deps 的清单里取安装提示，不另编一套 */
    missingHint: function (cmd) {
      var info = this.cmdIndex[cmd];
      if (!info) return '';
      if (info.present) return info.path || '';
      return info.hint ? '装：' + info.hint : '未安装';
    },
    requiredOf: function (t) { return t.required || []; },
    isRequired: function (t, p) { return this.requiredOf(t).indexOf(p) >= 0; }
  },
  template: [
    '<div class="tools-page">',
    '  <div class="banner bad" v-if="error">{{ error }}</div>',

    /* ── 顶部：体检结论 ── */
    '  <div class="card" v-if="deps">',
    '    <div class="card-head"><span class="title">环境体检</span>',
    '      <span class="grow"></span>',
    '      <button class="btn sm" :disabled="busy === \'deps\'" @click="load(false)">快速检查</button>',
    '      <button class="btn sm" :disabled="busy === \'deps\'" @click="load(true)">真实执行探测</button>',
    '      <button class="btn ghost sm" @click="showDeps = !showDeps">',
    '        {{ showDeps ? "收起依赖清单" : "展开依赖清单" }}</button>',
    '    </div>',
    '    <div class="stat-strip">',
    '      <div class="stat" v-if="tools"><div class="v" :class="{bad: readyCount !== tools.summary.total}">',
    '        {{ readyCount }}/{{ tools.summary.total }}</div><div class="k">工具可执行</div></div>',
    '      <div class="stat"><div class="v">{{ deps.summary.commands_ready }}/{{ deps.summary.commands_total }}</div>',
    '        <div class="k">外部命令就绪</div></div>',
    '      <div class="stat"><div class="v" :class="{bad: deps.summary.missing.length}">{{ deps.summary.missing.length }}</div>',
    '        <div class="k">命令缺失</div></div>',
    '      <div class="stat"><div class="v" :class="{bad: deps.summary.broken.length}">{{ deps.summary.broken.length }}</div>',
    '        <div class="k">存在但执行异常</div></div>',
    '      <div class="stat"><div class="v">{{ deps.resources.filter(function(r){return r.exists}).length }}/{{ deps.resources.length }}</div>',
    '        <div class="k">自带资源</div></div>',
    '    </div>',
    '    <div class="card-body" style="flex:none; padding:12px 14px">',
    '      <div class="banner" :class="deps.summary.ready ? \'ok\' : \'warn\'">',
    '        {{ deps.summary.ready ? "外部命令与规则库都就绪。" : "有缺失项：缺依赖的工具在卡片墙上标红，直接跑会失败。" }}',
    '      </div>',
    '    </div>',
    /* 依赖清单默认收起：这两个清单很长，摊开会把"工具能不能用"挤没了 */
    '    <div class="dep-split" v-if="showDeps">',
    '      <div class="dep-col">',
    '        <div class="dep-head"><span class="title">外部命令</span>',
    '          <span class="muted small">{{ deps.summary.commands_ready }}/{{ deps.summary.commands_total }}</span>',
    '          <span class="grow"></span>',
    '          <span class="muted tiny">缺失的会给出安装命令</span></div>',
    '        <div class="dep-list">',
    '          <div class="dep-row" v-for="c in deps.commands" :key="c.cmd">',
    '            <span class="dep-dot" :class="cmdTag(c)"></span>',
    '            <div class="grow">',
    '              <div class="row"><span class="dep-name ellipsis">{{ c.cmd }}</span>',
    '                <span class="grow"></span>',
    '                <span class="tag" :class="cmdTag(c)">{{ cmdLabel(c) }}</span></div>',
    '              <div class="dep-sub ellipsis">{{ c.purpose }}{{ c.path ? " · " + c.path : "" }}</div>',
    '              <div class="dep-sub mono bad-text" v-if="!c.present && c.hint">装：{{ c.hint }}</div>',
    '            </div>',
    '          </div>',
    '        </div>',
    '      </div>',
    '      <div class="dep-col">',
    '        <div class="dep-head"><span class="title">自带资源</span>',
    '          <span class="muted small">{{ deps.resources.filter(function(r){return r.exists}).length }}/{{ deps.resources.length }}</span>',
    '          <span class="grow"></span>',
    '          <span class="muted tiny">随工具集自带，无需配置</span></div>',
    '        <div class="dep-list">',
    '          <div class="dep-row" v-for="r in deps.resources" :key="r.label">',
    '            <span class="dep-dot" :class="r.exists ? \'ok\' : \'bad\'"></span>',
    '            <div class="grow">',
    '              <div class="row"><span class="dep-name ellipsis">{{ r.label }}</span>',
    '                <span class="grow"></span>',
    '                <span class="mono tiny muted">{{ r.exists ? Fmt.bytes(r.size) : "-" }}</span>',
    '                <span class="tag" :class="r.exists ? \'ok\' : \'bad\'">{{ r.exists ? "就绪" : "缺失" }}</span></div>',
    '              <div class="dep-sub ellipsis" :title="r.hint">{{ r.hint }}</div>',
    '            </div>',
    '          </div>',
    '        </div>',
    '      </div>',
    '    </div>',
    '  </div>',

    '  <div class="tools-grid">',

    /* ── 左：卡片墙 ── */
    '    <div class="card wall-card">',
    '      <div class="card-head"><span class="title">工具墙</span>',
    '        <span class="muted small" v-if="tools">共 {{ tools.summary.total }} 个',
    '          <span v-if="tools.summary.deps_missing.length">　<span class="bad-text">{{ tools.summary.deps_missing.length }} 个缺依赖，已置顶</span></span>',
    '        </span>',
    '        <span class="grow"></span>',
    '        <span class="muted tiny">{{ tools ? tools.scope : "" }}</span>',
    '        <button class="btn ghost sm" @click="loadTools">刷新</button>',
    '      </div>',
    '      <div class="card-body wall-body" v-if="tools">',
    '        <button class="tool-card" v-for="t in wall" :key="t.name"',
    '                :class="{on: t.name === selected, bad: !t.deps_ready}" @click="pick(t)">',
    '          <div class="tc-top">',
    '            <span class="tc-dot" :class="health(t)"></span>',
    '            <span class="mono tc-name ellipsis" :title="t.name">{{ t.name }}</span>',
    '            <span class="grow"></span>',
    '          </div>',
    '          <div class="tc-desc" :title="t.description">{{ t.description }}</div>',
    '          <div class="tc-foot">',
    '            <span class="tag" :class="health(t)">{{ healthLabel(t) }}</span>',
    '            <span class="tiny muted ellipsis" v-if="!t.deps_ready">{{ depsText(t) }}</span>',
    '            <span class="grow"></span>',
    '            <span class="mono tiny muted" v-if="t.calls">调用 {{ t.calls }}</span>',
    '            <span class="tiny muted" v-else>未调用</span>',
    '          </div>',
    '        </button>',
    '      </div>',
    '      <div class="card-body" v-else><div class="empty">正在读取工具清单…</div></div>',
    '      <div class="card-foot tiny muted" v-if="tools">{{ tools.note }}</div>',
    '    </div>',

    /* ── 右：选中工具的详情 + 环境清单 ── */
    '    <div class="col side" v-if="deps">',
    '      <div class="card detail-card" v-if="picked">',
    '        <div class="card-head"><span class="title">工具详情</span>',
    '          <span class="mono small">{{ picked.name }}</span>',
    '          <span class="grow"></span>',
    '          <span class="tag" :class="health(picked)">{{ healthLabel(picked) }}</span>',
    '        </div>',
    '        <div class="card-body tool-detail">',
    '          <div class="td-desc">{{ picked.description }}</div>',
    '          <div class="td-block">',
    '            <div class="tiny muted">参数（<span class="bad-text">*</span> 为必填）</div>',
    '            <div class="chips" v-if="picked.params.length">',
    '              <span class="chip mono" v-for="p in picked.params" :key="p" :class="{req: isRequired(picked, p)}">',
    '                {{ p }}<b v-if="isRequired(picked, p)">*</b></span>',
    '            </div>',
    '            <div class="muted small" v-else>这个工具不需要参数</div>',
    '          </div>',
    '          <div class="td-block">',
    '            <div class="tiny muted">依赖的外部命令</div>',
    '            <div class="td-dep" v-for="d in picked.deps" :key="d.cmd">',
    '              <span class="tc-dot" :class="d.present ? \'ok\' : \'bad\'"></span>',
    '              <span class="mono small">{{ d.cmd }}</span>',
    '              <span class="grow"></span>',
    '              <span class="tiny mono muted ellipsis">{{ missingHint(d.cmd) }}</span>',
    '            </div>',
    '            <div class="muted small" v-if="!picked.deps.length">内置实现，不需要外部命令</div>',
    '          </div>',
    '          <div class="td-block">',
    '            <div class="tiny muted">历史调用</div>',
    '            <div class="td-stats">',
    '              <span>调用 <b class="mono">{{ picked.calls || 0 }}</b></span>',
    '              <span>成功 <b class="mono ok-text">{{ picked.ok || 0 }}</b></span>',
    '              <span>拦截 <b class="mono" :class="{\'bad-text\': picked.blocked}">{{ picked.blocked || 0 }}</b></span>',
    '              <span>均耗时 <b class="mono">{{ picked.avg_elapsed === null ? "-" : picked.avg_elapsed + "s" }}</b></span>',
    '              <span v-if="picked.last_at">最近 <b class="mono">{{ Fmt.clock(picked.last_at) }}</b></span>',
    '            </div>',
    '          </div>',
    '          <div class="td-block">',
    '            <div class="tiny muted">实现文件</div>',
    '            <div class="mono tiny muted ellipsis" v-for="s in picked.source" :key="s">{{ s }}</div>',
    '          </div>',
    '        </div>',
    '      </div>',
    '      <div class="card" v-else><div class="card-body"><div class="empty">点左边任意一张卡片看详情</div></div></div>',
    '    </div>',

    '  </div>',
    '</div>'
  ].join('\n')
};
