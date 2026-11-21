---
type: guide
status: Accepted
updated: 2026-11-21
---

# 工程约定

遵循主工作区的 [AGENTS.md](https://github.com/StuHelper/stuhelper/blob/develop/AGENTS.md)。审核和反馈数据归 moderation 管理，SQL 留在 `postgres/`。正文与可见状态通过内容模块的公开接口读取和修改。

管理入口核对当前操作和学校授权，反馈收件箱按全站权限授权。回执、事件和审计只返回各自允许的字段。以 `contracts/moderation.openapi.json` 维护 HTTP 契约，使用 `make generate` 更新 SDK。用 `module.yaml` 登记依赖及业务场景对应的测试函数。

使用 `make setup` 安装锁定依赖，使用 `bash scripts/check-with-postgres.sh` 执行隔离检查。运行身份和迁移身份分离，测试使用合成身份、举报证据与邮件。
