/* 极简 hash 路由 — 七个视图，刷新后停留在同一页。 */

window.router = Vue.reactive({
  path: (location.hash || '#/tasks').replace('#/', '') || 'tasks',
  go: function (path) { location.hash = '#/' + path; }
});

window.addEventListener('hashchange', function () {
  router.path = (location.hash || '#/tasks').replace('#/', '') || 'tasks';
});
