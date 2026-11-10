# 工程约定

遵循主工作区 AGENTS.md。模块只管理自己的数据，SQL 位于 postgres，公共接口隐藏账号及选课证据。通过 OpenAPI 生成 SDK。使用独立运行与迁移身份，以隔离 PostgreSQL 验证业务、并发、越权和删除。不得提交真实教务记录或凭据。
