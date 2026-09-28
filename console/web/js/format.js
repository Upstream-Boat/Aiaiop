/* 展示格式化 — 单位换算与时间显示集中一处，避免各视图各写一套。 */

window.Fmt = {
  bytes: function (n) {
    if (n === null || n === undefined) return '-';
    var units = ['B', 'KB', 'MB', 'GB', 'TB'], i = 0, v = n;
    while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
    return (v >= 100 || i === 0 ? Math.round(v) : v.toFixed(1)) + ' ' + units[i];
  },
  num: function (n) {
    return (n === null || n === undefined) ? '-' : Number(n).toLocaleString('zh-CN');
  },
  clock: function (ts) {
    if (!ts) return '-';
    var d = (typeof ts === 'number') ? new Date(ts * 1000) : new Date(ts);
    if (isNaN(d.getTime())) return String(ts);
    var p = function (x) { return String(x).padStart(2, '0'); };
    return p(d.getMonth() + 1) + '-' + p(d.getDate()) + ' ' + p(d.getHours()) + ':' + p(d.getMinutes());
  },
  tokens: function (u) {
    if (!u) return '-';
    return Fmt.num(u.totalTokens) + (u.source === 'estimated' ? '（估算）' : '');
  },
  pct: function (v) { return (v === null || v === undefined) ? '-' : Math.round(v) + '%'; },
  duration: function (ms) {
    if (ms === null || ms === undefined) return '-';
    return ms < 1000 ? ms + 'ms' : (ms / 1000).toFixed(1) + 's';
  }
};
