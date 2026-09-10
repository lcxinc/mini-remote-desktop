# Rdesk UI 原型

来源 `lcxinc/Rdesk`，本次已获允许审查后公开的授权。保留设备卡片、设备详情、会话、文件传输、登录/设置对话框与主题交互。所有数据与登录/传输行为均为设计演示，没有接入信令、认证、IPC 或屏幕传输。

正式客户端仍是 `apps/Rdesk`，会话仍由 `mrd-service` 和共享 crates 管理。

```sh
cd prototypes/rdesk
npm ci --ignore-scripts
npm run dev
# http://127.0.0.1:4323
npm run build
```

Vite 生产构建通过，输出 `dist/`。React 显式声明，路由依赖更新为 7.18.3，npm audit 当前为 0。原始 package.json、README 和构建配置见 [迁移档案](../../docs/repository-consolidation/Rdesk/README.md)，来源署名保留在 ATTRIBUTIONS.md。无原生打包或真实远程会话验收。
