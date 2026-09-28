# vendor/ —— 第三方运行时（本地自带）

## vue.global.prod.js

| 项 | 值 |
| --- | --- |
| 名称 | Vue（全局构建，生产版） |
| 版本 | 3.5.41 |
| 许可证 | MIT（© 2018-present Yuxi (Evan) You and Vue contributors） |
| 官方文件 | `vue.global.prod.js`（与 npm 包 `vue@3.5.41` 的 dist 一致） |
| 大小 | 166,624 字节 |
| SHA-256 | `45c5186437878319a4b86339f475e8e2f0b27e1752f9e6387ebb15854425847f` |
| 校验命令 | `sha256sum vue.global.prod.js` |

**为什么放在这里，而不是用 CDN**

现场演示的机器可能没有外网。控制台是"零构建"的静态页，运行时必须能在
断网环境下直接打开，所以 Vue 运行时随作品一起分发，`index.html` 直接引用本地文件。

**这个文件为什么看起来像乱码**

它是官方 minify 后的生产版：整份代码压成 14 行，变量名被压成 `aZ`、`t$` 这种。
这是压缩结果，不是损坏 —— `node --check vendor/vue.global.prod.js` 可以通过，
文件头的版权注释即为官方 banner。**不要手工编辑这个文件**，
升级时用官方 npm 包里的同名文件整体替换，并同步更新上表的版本与 SHA-256。

**升级步骤**

```bash
npm pack vue@<新版本> && tar -xzf vue-*.tgz package/dist/vue.global.prod.js
cp package/dist/vue.global.prod.js <skill>/console/web/vendor/vue.global.prod.js
sha256sum <skill>/console/web/vendor/vue.global.prod.js   # 更新上表
```

改完记得同步 `index.html` 里的 `?v=` 版本号，否则浏览器会继续用旧缓存。
