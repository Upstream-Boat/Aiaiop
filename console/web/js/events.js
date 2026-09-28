/* 实时事件 — 任务轨迹用 EventSource 跟随；断线重连由浏览器负责。 */

window.Events = {
  subscribeRun: function (runId, onEvent, onEnd) {
    var source = new EventSource(API.url('/api/tasks/' + runId + '/events/stream'));
    var types = ['run', 'stage', 'plan', 'tool_call', 'tool_result', 'text',
      'reasoning', 'usage', 'rules', 'error', 'done', 'end'];
    types.forEach(function (type) {
      source.addEventListener(type, function (ev) {
        var payload = {};
        try { payload = JSON.parse(ev.data); } catch (e) { payload = { raw: ev.data }; }
        if (type === 'end') { source.close(); if (onEnd) onEnd(payload); return; }
        onEvent(type, payload);
      });
    });
    return function () { source.close(); };
  }
};
