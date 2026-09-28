/* 接口封装 — 统一的 fetch：JSON 请求、SSE 流式请求、文件上传、错误归一。
   前端只通过这里说话，不把 fetch 散落到各视图。 */

window.API = (function () {
  // 直接用 file:// 打开页面时，后端固定在本机 8787
  var base = (location.protocol === 'http:' || location.protocol === 'https:')
    ? '' : 'http://127.0.0.1:8787';

  function url(path) { return base + path; }   // 页面和接口同源时 base 为空，直接相对路径

  // 后端的报错统一是 {"detail": ...}：出错时先摘 detail，页面才不会显示一坨 JSON
  function parse(resp) {
    return resp.text().then(function (text) {
      if (!resp.ok) {
        var detail = text;
        try { detail = JSON.parse(text).detail || text; } catch (e) { /* 保留原文 */ }
        throw new Error(detail || ('HTTP ' + resp.status));
      }
      try { return JSON.parse(text); } catch (e) { return text; }
    });
  }

  function get(path) { return fetch(url(path)).then(parse); }

  function post(path, body) {
    return fetch(url(path), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body || {})
    }).then(parse);
  }

  /* 解析 SSE：按空行切帧，逐帧取 event 与 data 两行。 */
  function parseFrames(buffer, onEvent) {
    var idx;
    while ((idx = buffer.indexOf('\n\n')) >= 0) {
      var raw = buffer.slice(0, idx);
      buffer = buffer.slice(idx + 2);
      var name = 'message', data = '';
      raw.split('\n').forEach(function (line) {
        if (line.indexOf('event:') === 0) name = line.slice(6).trim();
        else if (line.indexOf('data:') === 0) data += line.slice(5).trim();
      });
      if (!data) continue;
      try { onEvent(name, JSON.parse(data)); } catch (e) { onEvent(name, { text: data }); }
    }
    return buffer;
  }

  /* 流式请求（POST + SSE 回包）：对话与规则库更新走这里。 */
  function stream(path, body, onEvent, signal) {
    return fetch(url(path), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body || {}),
      signal: signal
    }).then(function (resp) {
      if (!resp.ok || !resp.body) {
        return resp.text().then(function (text) {
          /* 后端的报错都是 {"detail": "..."}：把 detail 摘出来，
             否则界面上会显示一坨 JSON，读不出到底哪儿不对 */
          var msg = text;
          try { msg = JSON.parse(text).detail || text; } catch (e) { /* 原样 */ }
          throw new Error(msg || ('HTTP ' + resp.status));
        });
      }
      var reader = resp.body.getReader();
      var decoder = new TextDecoder();
      var buffer = '';
      function pump() {
        return reader.read().then(function (chunk) {
          if (chunk.done) {
            if (buffer.trim()) parseFrames(buffer + '\n\n', onEvent);
            return;
          }
          buffer += decoder.decode(chunk.value, { stream: true });
          buffer = parseFrames(buffer, onEvent);
          return pump();
        });
      }
      return pump();
    });
  }

  /* 上传离线规则库包 */
  return { base: base, url: url, get: get, post: post, stream: stream };
})();
