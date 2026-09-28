/* 视图：规则库 — 四张卡 + 更新（SSE 进度）+ 定期更新 + NVD 密钥。
   规则库是判断依据，所以状态必须能一眼看到版本、条数与更新时间。
   NVD 密钥也放在这一页：它唯一的用途就是给规则库更新提速（无限速 5 请求/30 秒），
   是"下载凭据"而不是"这个 skill 的前置配置"，所以它属于这里，不属于一个单独的配置页。 */

/* 圆点占位用同一个字符：既好认，也方便送去接口前判定"这串还是占位、不是密钥" */
var NVD_MASK = '\u2022';

window.ViewRules = {
  name: 'ViewRules',
  data: function () {
    return {
      libs: [], log: [], logMeta: null, running: false,
      error: '', clearing: false, logMsg: '', zoom: false, follow: true,
      nvd: null, nvdInput: '', nvdBusy: false, nvdMsg: '',
      /* 定时更新是分级的：先选频率（每分钟/每小时/每天/每周/每月），
         下面才出现这一档真正需要的选择 —— 选"每小时"时分钟只给 10 分钟档，
         不用在一屏里同时摆出周几、几号、小时、分钟四排控件。
         0–23、0–59 就地生成，不写死几十个 <option>。 */
      sched: null, schedFreq: 'day', schedMin: 30, schedHour: 3,
      schedWeekday: 'mon', schedDom: 1, schedTargets: [],
      schedBusy: false, schedMsg: '',
      hours: (function () { var a = []; for (var h = 0; h < 24; h++) a.push(h); return a; })(),
      minutes: (function () { var a = []; for (var m = 0; m < 60; m++) a.push(m); return a; })(),
      hourSteps: [0, 10, 20, 30, 40, 50],
      /* nvdDirty=false 表示框里那串圆点还没被动过（是占位、不是密钥），
         保存时不该把它发出去；动过就把用户输入当真值。 */
      nvdDirty: false
    };
  },
  mounted: function () {
    this.load(); this.loadNvd(); this.loadLog(); this.loadSchedule();
    var self = this;
    /* Esc 关掉放大的更新输出：看得见关得掉，不做"只能点右上角"的窗口 */
    this.onKey = function (e) { if (e.key === 'Escape') self.zoom = false; };
    window.addEventListener('keydown', this.onKey);
  },
  unmounted: function () { window.removeEventListener('keydown', this.onKey); },
  computed: {
    /* 当前这一组选择说成人话（还没保存也看得见自己挑的是什么）。
       必须放 computed —— 放 methods 里模板里的 {{ schedPreview }} 拿到的是函数体本身。 */
    schedPreview: function () {
      var clock = this.pad(this.schedHour) + ':' + this.pad(this.schedMin);
      if (this.schedFreq === 'minute') return '每分钟';
      if (this.schedFreq === 'hour') return '每小时的第 ' + this.pad(this.schedMin) + ' 分钟';
      if (this.schedFreq === 'week') return '每' + this.weekdayLabel(this.schedWeekday) + ' ' + clock;
      if (this.schedFreq === 'month') return '每月 ' + this.schedDom + ' 号 ' + clock;
      return '每天 ' + clock;
    },
  },
  watch: {
    /* 从"每天"切到"每小时"时，原来的 37 分不在 10 分钟档里，界面会选不出值，
       就近落到 30 分。切档不是改需求，别让人再手动调一次。 */
    schedFreq: function (freq) {
      if (freq !== 'hour') return;
      var want = Number(this.schedMin);
      if (this.hourSteps.indexOf(want) >= 0) return;
      this.schedMin = this.hourSteps.reduce(function (best, m) {
        return Math.abs(m - want) < Math.abs(best - want) ? m : best;
      }, this.hourSteps[0]);
    }
  },
  methods: {
    load: function () {
      var self = this;
      return API.get('/api/rules').then(function (data) {
        self.libs = data.libraries || [];
      }).catch(function (e) { self.error = e.message; });
    },
    update: function (targets) {
      var self = this;
      if (this.running) return;
      this.running = true;
      this.error = '';
      /* 不清空 this.log：一场 CVE 更新要跑几十分钟、中途常常几分钟才吐一行，
         清空之后面板会空着，看着像"点了没反应"。历史留在这儿，本次的输出接在后面，
         结束后 loadLog() 再用落盘的那份对齐。 */
      return API.stream('/api/rules/update', { targets: targets }, function (type, payload) {
        if (type === 'line' || type === 'start' || type === 'result' || type === 'error') {
          var text = payload.message !== undefined ? payload.message
            : (payload.targets ? '开始更新：' + payload.targets.join(', ') : JSON.stringify(payload));
          self.log.push({ at: '', text: String(text), err: type === 'error' });
          self.scrollLog();
        }
        if (type === 'status') { self.libs = payload.libraries || self.libs; }
      }).catch(function (e) { self.error = e.message; })
        /* 结束后以后端落盘的那份为准：时间戳、跨刷新的历史都在里面 */
        .then(function () { self.running = false; self.load(); self.loadLog(); });
    },
    /* ── 更新输出日志（控制台自己那份，刷新不丢）── */
    loadLog: function () {
      var self = this;
      return API.get('/api/rules/log?limit=400').then(function (data) {
        self.log = (data && data.items) || [];
        self.logMeta = data;
        self.scrollLog();
        self.watchLog();
      }).catch(function () { /* 日志读不到不影响状态与更新 */ });
    },
    /* 日志面板默认跟着最新一行走（日志从下往上看才有用）。
       用户自己往上翻过就不抢滚动了：悄悄把画面拽回去比不滚更烦人。 */
    scrollLog: function () {
      var self = this;
      var toBottom = function () {
        var el = self.$refs.ruleLog;
        if (el && self.follow) el.scrollTop = el.scrollHeight;
      };
      this.$nextTick(toBottom);
      /* 再落一次：等宽字体换行稳定前算出的高度偏小，只落一次会停在半截 */
      setTimeout(toBottom, 180);
    },
    /* 布局会变：这页的卡片高度是"先按内容撑开、随后收到剩余空间里"的，
       一开始算出来的面板高度偏大，那会儿滚到底，等布局落定就不是底了。
       所以盯着尺寸变化再落一次底，而不是猜一个延迟。 */
    watchLog: function () {
      var self = this;
      if (typeof ResizeObserver === 'undefined') return;
      var el = this.$refs.ruleLog;
      var target = (el && el.parentElement) || el;
      if (!target) return;
      if (this.ro) this.ro.disconnect();
      this.ro = new ResizeObserver(function () { self.scrollLog(); });
      this.ro.observe(target);
    },
    onLogScroll: function () {
      var el = this.$refs.ruleLog;
      if (!el) return;
      this.follow = (el.scrollHeight - el.scrollTop - el.clientHeight) < 48;
    },
    clearLog: function () {
      var self = this;
      if (this.running || this.clearing) return;
      if (!confirm('清空更新输出日志？\n\n审计链里对应的记录不会动 —— 那一份按设计就不允许删改。')) return;
      this.clearing = true;
      return API.post('/api/rules/log/clear', {}).then(function (data) {
        self.log = [];
        self.logMeta = null;
        self.logMsg = '已清空 ' + (data.cleared || 0) + ' 行';
        setTimeout(function () { self.logMsg = ''; }, 4000);
      }).catch(function (e) { self.error = e.message; })
        .then(function () { self.clearing = false; });
    },

    /* ── 定时更新 ── */
    loadSchedule: function () {
      var self = this;
      return API.get('/api/rules/schedule').then(function (d) {
        self.sched = d;
        self.schedFreq = d.freq || 'day';
        self.schedMin = d.minute === undefined ? 30 : d.minute;
        self.schedHour = d.hour === undefined ? 3 : d.hour;
        self.schedWeekday = d.weekday || 'mon';
        self.schedDom = d.dom === undefined ? 1 : d.dom;
        self.schedTargets = (d.targets || []).slice();
      }).catch(function () { /* 读不到不影响手动更新 */ });
    },
    toggleTarget: function (key) {
      var i = this.schedTargets.indexOf(key);
      if (i >= 0) this.schedTargets.splice(i, 1); else this.schedTargets.push(key);
    },
    saveSchedule: function () {
      var self = this;
      this.schedBusy = true;
      this.error = '';
      return API.post('/api/rules/schedule', {
        enabled: !!(this.sched && this.sched.enabled),
        freq: String(this.schedFreq),
        minute: Number(this.schedMin),
        hour: Number(this.schedHour),
        weekday: String(this.schedWeekday),
        dom: Number(this.schedDom),
        targets: this.schedTargets
      }).then(function (d) {
        self.sched = d;
        self.schedFreq = d.freq; self.schedMin = d.minute; self.schedHour = d.hour;
        self.schedWeekday = d.weekday; self.schedDom = d.dom;
        self.schedMsg = '已保存';
        setTimeout(function () { self.schedMsg = ''; }, 3000);
      }).catch(function (e) { self.error = e.message; })
        .then(function () { self.schedBusy = false; });
    },
    toggleSchedule: function () {
      if (!this.sched) return;
      this.sched.enabled = !this.sched.enabled;
      return this.saveSchedule();
    },
    schedTargetLabel: function (key) {
      var opts = (this.sched && this.sched.options) || [];
      var hit = opts.filter(function (o) { return o.key === key; })[0];
      return hit ? hit.label : key;
    },
    /* 这一档要显示哪些子控件 —— 模板里写三串判断太吵，收成方法。
       注意必须放 methods：放 computed 里模板写 needHour() 会报 not a function。 */
    needHour: function () { return this.schedFreq !== 'minute' && this.schedFreq !== 'hour'; },
    needMinute: function () { return this.schedFreq !== 'minute'; },
    minuteChoices: function () { return this.schedFreq === 'hour' ? this.hourSteps : this.minutes; },
    weekdayLabel: function (key) {
      var opts = (this.sched && this.sched.choices && this.sched.choices.weekdays) || [];
      var hit = opts.filter(function (o) { return o.value === key; })[0];
      return hit ? hit.label : key;
    },
    pad: function (n) {
      n = Number(n);
      return (n < 10 ? '0' : '') + n;
    },
    /* 还有多久：定时任务最想知道的其实是"下一次什么时候" */
    untilNext: function () {
      if (!this.sched || !this.sched.next_run) return '';
      var ms = Date.parse(this.sched.next_run.replace(' ', 'T')) - Date.now();
      if (isNaN(ms) || ms < 0) return '';
      var mins = Math.round(ms / 60000);
      if (mins < 60) return '还有 ' + mins + ' 分钟';
      return '还有 ' + Math.floor(mins / 60) + ' 小时 ' + (mins % 60) + ' 分';
    },

    /* ── 更新输出放大看：一整屏，方便对着日志找问题 ── */
    openZoom: function () {
      var self = this;
      this.zoom = true;
      this.$nextTick(function () {
        var el = self.$refs.zoomLog;
        if (el) el.scrollTop = el.scrollHeight;      /* 打开就落在最新一行 */
      });
    },

    /* ── NVD 密钥（可选凭据，只写不读）── */
    loadNvd: function () {
      var self = this;
      return API.get('/api/nvd').then(function (data) {
        self.nvd = data;
        self.applyNvdMask();
      }).catch(function (e) { self.error = e.message; });
    },
    /* 占位圆点串：密钥有几个字符就摆几个圆点（封顶 64，免得异常长的值把框撑成一条线） */
    mask: function () {
      var n = (this.nvd && this.nvd.key_len) || 0;
      if (!n) return '';
      return new Array(Math.min(n, 64) + 1).join(NVD_MASK);
    },
    nvdIsMasked: function () {
      return !!(this.nvd && this.nvd.has_key) && !this.nvdDirty;
    },
    /* 摆回占位圆点。这里不能问 nvdIsMasked()：删过圆点之后 dirty 已经是 true，
       拿它来判断会算出"不用摆"，输入框就空在那儿了。 */
    applyNvdMask: function () {
      this.nvdInput = (this.nvd && this.nvd.has_key) ? this.mask() : '';
      this.nvdDirty = false;
    },
    /* 点进来整段选中：换密钥直接粘贴覆盖，想清空按一下退格 —— 都是一个动作 */
    onNvdFocus: function (ev) {
      var el = ev && ev.target;
      if (!el || !this.nvdIsMasked()) return;
      setTimeout(function () { try { el.select(); } catch (e) { /* 不支持就算了 */ } }, 0);
    },
    /* 框里的值被动过没有：动过就不再当它是占位圆点 */
    markNvdDirty: function (ev) {
      var value = String((ev && ev.target && ev.target.value) || this.nvdInput || '');
      this.nvdDirty = value !== this.mask();
    },
    onNvdBlur: function () {
      /* 删空了就走人 = 没打算改，把占位补回去（真想清空是右边的"清除"按钮） */
      if (!this.nvd || !this.nvd.has_key) return;
      var value = String(this.nvdInput || '').trim();
      /* 空着、或者剩下的全是圆点 —— 都算"没真打算改"，补回完整占位 */
      if (!value || value.split('').every(function (c) { return c === NVD_MASK; })) {
        this.applyNvdMask();
      }
    },
    nvdSourceLabel: function () {
      var src = this.nvd && this.nvd.source;
      return { env: '环境变量', file: '配置文件', none: '未配置' }[src] || src || '';
    },
    nvdSourceTag: function () {
      var src = this.nvd && this.nvd.source;
      return src === 'none' ? 'warn' : (src === 'env' ? 'info' : 'ok');
    },
    saveNvd: function () {
      var self = this;
      var value = String(this.nvdInput || '').trim();
      if (!this.nvdDirty || value === this.mask()) {   /* 还是占位圆点：等于没改动 */
        this.nvdMsg = '密钥没有改动';
        setTimeout(function () { self.nvdMsg = ''; }, 3000);
        return;
      }
      if (!value) { this.error = '请先粘贴密钥'; return; }
      if (value.indexOf(NVD_MASK) >= 0) {              /* 只删了一半圆点：那不是密钥 */
        this.error = '输入框里的圆点是占位，不是密钥内容 —— 请全选后再粘贴完整密钥';
        return;
      }
      this.nvdBusy = true;
      this.error = '';
      return API.post('/api/nvd/key', { key: value })
        .then(function (data) {
          self.nvd = data.nvd;
          self.nvdMsg = '已写入密钥文件（0600，不回显明文）';
          self.applyNvdMask();   /* 按新长度摆回圆点 */
          setTimeout(function () { self.nvdMsg = ''; }, 4000);
        }).catch(function (e) { self.error = e.message; })
        .then(function () { self.nvdBusy = false; });
    },
    clearNvd: function () {
      var self = this;
      if (!confirm('清除已保存的 NVD 密钥？清除后规则库更新会退回限速模式。')) return;
      this.nvdBusy = true;
      return API.post('/api/nvd/key', { key: '' })
        .then(function (data) {
          self.nvd = data.nvd;
          self.nvdInput = '';
          self.nvdMsg = '已清除密钥文件';
          setTimeout(function () { self.nvdMsg = ''; }, 4000);
        }).catch(function (e) { self.error = e.message; })
        .then(function () { self.nvdBusy = false; });
    }
  },
  template: [
    '<div class="page fill">',
    /* 这一页的动作几乎都是异步的（更新、清日志、存密钥、存定时），失败要看得见：
       以前只把消息写进 this.error，模板里却没有渲染它的地方，等于点了没反应。 */
    '  <div class="banner bad" v-if="error">{{ error }}</div>',
    '  <div class="rules-split">',

    /* ── 左：库状态 + 更新输出 ── */
    '    <div class="col" style="gap:16px">',
    '      <div class="card">',
    '        <div class="card-head wrap"><span class="title">规则库</span>',
    '          <span class="muted small">{{ libs.length }} 个库</span><span class="grow"></span>',
    '          <button class="btn sm" :disabled="running" @click="update([\'cve\'])">更新 CVE</button>',
    '          <button class="btn sm" :disabled="running" @click="update([\'exploit-db\'])">更新 Exploit-DB</button>',
    '          <button class="btn sm" :disabled="running" @click="update([\'nuclei\'])">更新 nuclei</button>',
    '          <button class="btn sm primary" :disabled="running" @click="update([\'all\'])">全部更新</button>',
    '          <button class="btn ghost sm" @click="load">刷新</button>',
    '        </div>',
    '        <div class="card-body">',
    '          <div class="rules-grid" v-if="libs.length">',
    '            <div class="rule-card" v-for="l in libs" :key="l.key">',
    '              <div class="head"><span class="name">{{ l.label }}</span>',
    '                <span class="tag" :class="l.installed ? \'ok\' : \'bad\'">{{ l.installed ? "已就绪" : "缺失" }}</span></div>',
    '              <div class="metric"><span class="v">{{ Fmt.num(l.count) }}</span><span class="u">条 / 项</span></div>',
    /* 体积与版本合成一行：四张卡并排时，省下的这一行让整块矮掉近一半的卡高 */
    '              <div class="kv-row"><span class="k">体积</span>',
    '                <span class="v">{{ Fmt.bytes(l.size) }}</span><span class="sep">·</span>',
    '                <span class="k">版本</span>',
    '                <span class="v ellipsis">{{ l.version || l.mtime || "-" }}</span></div>',
    '              <div class="note">{{ l.note }}</div>',
    '            </div>',
    '          </div>',
    /* 骨架：扫库目录要半秒，先占住位置，别让下面的"更新输出"先跳上来 */
    '          <div class="rules-grid" v-else>',
    '            <div class="rule-card skeleton" v-for="n in 4" :key="n">',
    '              <div class="sk bar w60"></div>',
    '              <div class="sk big w40"></div>',
    '              <div class="sk bar w80"></div>',
    '            </div>',
    '          </div>',
    '        </div>',
    '      </div>',

    '      <div class="card update-card">',
    '        <div class="card-head wrap"><span class="title">更新输出</span>',
    '          <span class="muted small" v-if="log.length">{{ log.length }} 行</span>',
    '          <span class="grow"></span>',
    '          <span class="tag warn" v-if="running">执行中</span>',
    '          <span class="tag ok" v-if="logMsg">{{ logMsg }}</span>',
    '          <button class="btn ghost sm icon" :disabled="!log.length" title="放大看（整屏）"',
    '                  aria-label="放大更新输出" @click="openZoom">',
    '            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7"',
    '                 stroke-linecap="round" stroke-linejoin="round">',
    '              <path d="M4 9V5.5A1.5 1.5 0 0 1 5.5 4H9M15 4h3.5A1.5 1.5 0 0 1 20 5.5V9"/>',
    '              <path d="M20 15v3.5a1.5 1.5 0 0 1-1.5 1.5H15M9 20H5.5A1.5 1.5 0 0 1 4 18.5V15"/></svg>',
    '          </button>',
    '          <button class="btn ghost sm" :disabled="running || clearing || !log.length"',
    '                  title="只清这份输出记录；审计链里对应的记录不删"',
    '                  @click="clearLog">清除日志</button></div>',
    '        <div class="card-body update-body">',
    '          <div class="log" ref="ruleLog" @scroll="onLogScroll">',
    '            <div v-for="(line, i) in log" :key="i" :class="{err: line.err}">',
    '              <span class="ts" v-if="line.at">{{ line.at.slice(11, 19) }}</span>{{ line.text }}</div>',
    '            <div v-if="!log.length" class="muted">还没有更新记录。点上方按钮开始更新。</div>',
    '          </div>',
    '        </div>',
    '        <div class="card-foot tiny muted">',
    '          记录留在 <span class="mono">{{ logMeta ? logMeta.file_rel : "console/data/rules_update.log" }}</span>，',
    '          重启也还在，最多 {{ logMeta ? logMeta.keep : 10000 }} 行。',
    '        </div>',
    '      </div>',
    '    </div>',

    /* ── 右：定时更新 + 凭据 ── */
    '    <div class="col" style="gap:16px">',
    '      <div class="card sched-card" v-if="sched">',
    '        <div class="card-head"><span class="title">定时更新</span>',
    '          <span class="grow"></span>',
    '          <span class="tag ok" v-if="schedMsg">{{ schedMsg }}</span>',
    '          <span class="tag" :class="sched.enabled ? \'ok\' : \'info\'">{{ sched.enabled ? "已开启" : "已关闭" }}</span>',
    '          <button class="btn sm" :class="{primary: !sched.enabled}" :disabled="schedBusy"',
    '                  @click="toggleSchedule">{{ sched.enabled ? "关闭定时" : "开启定时" }}</button>',
    '        </div>',
    '        <div class="card-body col" style="gap:10px">',
    '          <div class="sched-grid">',
    '            <label class="sched-field"><span>频率</span>',
    '              <select class="input" v-model="schedFreq" :disabled="schedBusy">',
    '                <option v-for="o in ((sched && sched.choices && sched.choices.freqs) || [])"',
    '                        :key="o.value" :value="o.value">{{ o.label }}</option>',
    '              </select></label>',
    /* 子选项跟着频率出现：既不摆出用不上的控件，也不会因为切换频率而丢失已选值 */
    '            <label class="sched-field" v-if="schedFreq === \'week\'"><span>周几</span>',
    '              <select class="input" v-model="schedWeekday" :disabled="schedBusy">',
    '                <option v-for="o in ((sched && sched.choices && sched.choices.weekdays) || [])"',
    '                        :key="o.value" :value="o.value">{{ o.label }}</option>',
    '              </select></label>',
    '            <label class="sched-field" v-if="schedFreq === \'month\'"><span>几号</span>',
    '              <select class="input" v-model.number="schedDom" :disabled="schedBusy">',
    '                <option v-for="o in ((sched && sched.choices && sched.choices.doms) || [])"',
    '                        :key="o.value" :value="o.value">{{ o.label }}</option>',
    '              </select></label>',
    '            <label class="sched-field" v-if="needHour()"><span>小时</span>',
    '              <select class="input" v-model.number="schedHour" :disabled="schedBusy">',
    '                <option v-for="h in hours" :key="h" :value="h">{{ pad(h) }}</option>',
    '              </select></label>',
    '            <label class="sched-field" v-if="needMinute()"><span>分钟</span>',
    '              <select class="input" v-model.number="schedMin" :disabled="schedBusy">',
    '                <option v-for="m in minuteChoices()" :key="m" :value="m">{{ pad(m) }}</option>',
    '              </select></label>',
    '          </div>',
    '          <div class="sched-line">当前设置：<b class="mono">{{ schedPreview }}</b></div>',
    '          <div class="sched-row">',
    '            <span class="muted small">更新</span>',
    '          </div>',
    '          <div class="chips">',
    '            <button class="chip" v-for="o in (sched.options || [])" :key="o.key"',
    '                    :class="{on: schedTargets.indexOf(o.key) >= 0}"',
    '                    @click="toggleTarget(o.key)">{{ o.label }}</button>',
    '          </div>',
    '          <div class="kv" v-if="sched.next_run"><span class="k">下次运行</span>',
    '            <span class="v mono">{{ sched.next_run }}<span class="muted" v-if="untilNext()"> · {{ untilNext() }}</span></span></div>',
    '          <div class="kv" v-if="sched.last_run"><span class="k">上次运行</span>',
    '            <span class="v mono">{{ sched.last_run }} {{ sched.last_result }}</span></div>',
    '          <button class="btn sm sched-save" :disabled="schedBusy" @click="saveSchedule">保存定时设置</button>',
    '          <div class="muted tiny">{{ sched.note }}</div>',
    '        </div>',
    '      </div>',

    /* 右列两张卡都吃一点剩余高度：底边与左列齐平，空白摊在各卡底部而不是
       在中间挖一个洞（只让一张卡吃掉全部空白时，那一张会显得空得莫名其妙）。 */
    '      <div class="card cred-card" v-if="nvd">',
    '        <div class="card-head"><span class="title">NVD 密钥</span>',
    '          <span class="grow"></span>',
    '          <span class="tag" :class="nvd.has_key ? \'ok\' : \'warn\'">{{ nvd.has_key ? "已配置" : "未配置" }}</span>',
    '          <span class="tag" :class="nvdSourceTag()">来源：{{ nvdSourceLabel() }}</span>',
    '        </div>',
    '        <div class="card-body col" style="gap:10px">',
    '          <div class="muted small">{{ nvd.effect }}</div>',
    '          <div class="banner warn" v-if="nvd.env_locked">',
    '            当前密钥由环境变量 {{ nvd.env_var }} 提供 —— 在这里写文件不会生效，',
    '            要改请改环境变量（或先取消设置该变量）。</div>',
    '          <div class="banner ok" v-if="nvdMsg">{{ nvdMsg }}</div>',
    '          <div class="nvd-row">',
    '            <input class="input" type="password" v-model="nvdInput" ref="nvdInput"',
    '                   :class="{\'has-key\': nvdIsMasked()}"',
    '                   placeholder="粘贴 NVD API Key（uuid 形式）"',
    '                   title="已配置时按密钥字符数显示同数量的圆点；点进来整段选中，可直接删掉或粘贴覆盖"',
    '                   @focus="onNvdFocus" @blur="onNvdBlur" @input="markNvdDirty"',
    '                   @keyup.enter="saveNvd" />',
    '            <button class="btn primary sm" :disabled="nvdBusy" @click="saveNvd">保存</button>',
    '            <button class="btn danger sm" :disabled="nvdBusy || !nvd.file_exists" @click="clearNvd">清除</button>',
    '          </div>',
    /* 不显示具体文件名与路径：这是页面，不是文件管理器。写没写、从哪来、
       会不会生效已经在上面几行说清了，位置信息留给机器上看。 */
    '          <div class="kv"><span class="k">存放位置</span>',
    '            <span class="v">密钥文件 · 权限 0600 · 不回显</span></div>',
    '        </div>',
    '      </div>',

    '    </div>',

    '  </div>',

    /* ── 放大看：一块小面板里翻长日志很难受，给一整屏 ── */
    '  <div class="log-zoom" v-if="zoom" @click.self="zoom = false">',
    '    <div class="zoom-panel">',
    '      <div class="card-head"><span class="title">更新输出（放大）</span>',
    '        <span class="muted small">{{ log.length }} 行</span>',
    '        <span class="grow"></span>',
    '        <span class="muted tiny mono">{{ logMeta ? logMeta.file_rel : "console/data/rules_update.log" }}</span>',
    '        <span class="tag warn" v-if="running">执行中</span>',
    '        <button class="btn ghost sm icon" title="关闭（Esc）" aria-label="关闭"',
    '                @click="zoom = false">',
    '          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"',
    '               stroke-linecap="round"><path d="M6 6l12 12M18 6L6 18"/></svg>',
    '        </button></div>',
    '      <div class="log zoom-log" ref="zoomLog">',
    '        <div v-for="(line, i) in log" :key="i" :class="{err: line.err}">',
    '          <span class="ts" v-if="line.at">{{ line.at.slice(11, 19) }}</span>{{ line.text }}</div>',
    '        <div v-if="!log.length" class="muted">还没有更新记录。</div>',
    '      </div>',
    '    </div>',
    '  </div>',
    '</div>'
  ].join('\n')
};
