/* 应用入口 — 左侧导航 + 页头 + 视图切换。
   视图按需挂载（v-if 切换），切走即卸载，避免后台轮询互相干扰。 */

/* 内联图标：离线环境不引 CDN，也不用 icon 字体。描边式，跟正文一个粗细。 */
var ICONS = {
  shield: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3 5 5.8v6c0 4.2 2.9 7.7 7 9.2 4.1-1.5 7-5 7-9.2v-6L12 3Z"/><path d="M9.4 12.1l1.9 1.9 3.4-3.6"/></svg>',
  tasks: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 12 7.5 12 10.5 5 14 19 16.5 12 21 12"/></svg>',
  tools: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><rect x="3.5" y="3.5" width="7" height="7" rx="2"/><rect x="13.5" y="3.5" width="7" height="7" rx="2"/><rect x="3.5" y="13.5" width="7" height="7" rx="2"/><rect x="13.5" y="13.5" width="7" height="7" rx="2"/></svg>',
  rules: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3 3.5 7.5 12 12l8.5-4.5L12 3Z"/><path d="M3.5 12.4 12 16.9l8.5-4.5"/><path d="M3.5 16.9 12 21.4l8.5-4.5"/></svg>',
  audit: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><path d="M10.2 13.3a4.6 4.6 0 0 0 6.9.5l2.6-2.6a4.6 4.6 0 0 0-6.5-6.5l-1.6 1.6"/><path d="M13.8 10.7a4.6 4.6 0 0 0-6.9-.5l-2.6 2.6a4.6 4.6 0 0 0 6.5 6.5l1.6-1.6"/></svg>'
};

var App = {
  data: function () {
    return {
      /* 四页一条线排开，不再套分组标题：四页的规模下"观测 / 留痕"只是多余的一行字，
         而且会让人以为审计链属于另一套东西 —— 它同样是这个工具自己的记录。
         没有报告页：报告由宿主 Agent 那边产出，控制台只负责这个工具自身的运转 */
      nav: [
        { key: 'tasks', label: '任务台' },
        { key: 'tools', label: '工具状态' },
        { key: 'rules', label: '规则库' },
        { key: 'audit', label: '审计链' }
      ],
      icons: ICONS,
      health: null,
      clock: '',
      // 构建标记：页脚可见。改完前端刷新后能一眼确认"我加载的是哪一版"，
      // 不用再靠猜（前一轮就是浏览器咬着旧 JS，页面看着正常却点不动）。
      build: 'v2026-09-28.1'
    };
  },
  computed: {
    path: function () { return router.path; },
    current: function () {
      var hit = this.nav.filter(function (n) { return n.key === router.path; })[0];
      return hit || this.nav[0];
    },
    /* 侧栏那条路径只留末尾两段：整条绝对路径会带出仓库目录名，页面不需要知道这些 */
    runtimeShort: function () {
      var p = (this.health && this.health.runtime_dir) || '';
      var parts = p.split('/').filter(Boolean);
      return parts.length <= 2 ? p : '…/' + parts.slice(-2).join('/');
    }
  },
  mounted: function () {
    this.ping();
    this.tick();
    // 10 秒探一次健康：后端一挂/一换版本，页脚立刻能看出来，不用等下一次请求失败
    setInterval(this.ping, 10000);
    setInterval(this.tick, 1000);
  },
  methods: {
    ping: function () {
      var self = this;
      API.get('/api/health').then(function (h) { self.health = h; })
        .catch(function () { self.health = null; });
    },
    tick: function () {
      this.clock = new Date().toLocaleTimeString('zh-CN', { hour12: false });
    }
  },
  template: [
    '<div class="app">',
    '  <aside class="nav">',
    '    <div class="nav-brand">',
    '      <span class="nav-logo" v-html="icons.shield"></span>',
    '      <span class="nav-id"><b>工具管理台</b><i>安全评估工具集</i></span>',
    '    </div>',
    '    <nav class="nav-list">',
    '      <button class="nav-item" v-for="n in nav" :key="n.key"',
    '              :class="{active: path === n.key}" @click="router.go(n.key)">',
    '        <span class="ico" v-html="icons[n.key]"></span>',
    '        <span class="label">{{ n.label }}</span>',
    '      </button>',
    '    </nav>',
    /* 在线状态由顶栏那颗 chip 独家负责，这里只放"这台机器上跑着的东西" */
    '    <div class="nav-foot">',
    '      <div class="muted tiny">运行时目录</div>',
    '      <div class="path" v-if="health" :title="health.runtime_dir">{{ runtimeShort }}</div>',
    '      <div class="path" v-else>后端未连接</div>',
    '      <div class="hr"></div>',
    '      <div class="split">',
    '        <span>构建 <span class="mono">{{ build }}</span></span>',
    '        <span v-if="health && health.build && health.build !== build" class="tag bad"',
    '              title="后端进程还是改动前的版本，接口会 404 —— 重启控制台服务">后端陈旧</span>',
    '      </div>',
    '    </div>',
    '  </aside>',
    '  <main class="main">',
    '    <header class="topbar">',
    '      <span class="page-ico" v-html="icons[current.key]"></span>',
    '      <span class="page-id"><h1>{{ current.label }}</h1></span>',
    '      <span class="grow"></span>',
    '      <span class="chip"><span class="live-dot" :class="{off: !health}"></span>',
    '        {{ health ? "后端在线" : "未连接" }}</span>',
    '      <span class="chip mono">{{ clock }}</span>',
    '    </header>',
    '    <section class="view">',
    '      <view-tasks v-if="path === \'tasks\'" />',
    '      <view-tools v-else-if="path === \'tools\'" />',
    '      <view-rules v-else-if="path === \'rules\'" />',
    '      <view-audit v-else-if="path === \'audit\'" />',
    '    </section>',
    '  </main>',
    '</div>'
  ].join('\n')
};

var app = Vue.createApp(App);
app.component('view-tasks', window.ViewTasks);
app.component('view-tools', window.ViewTools);
app.component('view-rules', window.ViewRules);
app.component('view-audit', window.ViewAudit);
app.config.globalProperties.Fmt = window.Fmt;
// Vue 3 的模板表达式只在组件实例作用域里求值，取不到 window 上的全局变量。
// 导航按钮写的是 @click="router.go(...)"，不挂这一行的话每次点击都会抛
// TypeError: Cannot read properties of undefined (reading 'go') —— 整个控制台
// 五个页签全点不动。Fmt 也是同样的原因才挂在这里。
app.config.globalProperties.router = window.router;
app.mount('#app');
