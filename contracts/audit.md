---
type: spec
status: Accepted
updated: 2026-11-09
---

# 审核审计查询

## 公开审计查询

Repository.ReadAudit(ctx, AuditRequest) 返回 AuditBatch，供已完成授权的 backend 适配器调用。请求的 Principal 是已验证主体的稳定键，Scopes 是当前授权范围的并集；接口自身不授予权限。HTTP 路径不变。

统一记录包含 ID、Source（模块）、Target（对象）、Actor（操作者）、CreatedAt、Action、Reason、Result 和 Scope。查询仅投影这些独立字段，不返回原始审计 JSON、正文、举报证据、认证材料或实名原值。

学校缺失记为 `*`，群范围为 `*`，模块固定为所属模块。学校或群的具体授权不能包含 `*` 范围的记录。全部范围和时间、操作者、对象、操作类型条件在 LIMIT 前过滤。时间区间为 [From, Until)，Until 必填。

Limit 为 1–101，支持 platform 的额外一条预读。Before 为严格倒序 (时间, Source, ID) 的排他边界，字符串按字节排序。Snapshot 为最长 256 字节的不可拆分令牌，后续页原样传回。

快照使用 PostgreSQL 事务可见性，排除后插入、回填和首次读取时未提交的记录。快照有效期 15 分钟，审计更新、删除或清空使旧快照失效并返回错误，不重建快照或伪装完整结果。游标对请求主体、筛选和授权范围的绑定由 platform 执行。

原因未记录时为空字符串。业务自由文本可能包含隐私，不复制到审计原因。仅显式记录的安全原因码可以查询。结果缺失为 unknown；决定已保存不表示决定已执行。可证明已提交的状态变化才记录 success，明确执行失败记录 failed。

审计表按最终结构定义独立查询字段及 recorded_xid，不提供历史数据转换。运行身份需访问审计表与 audit_retention。查询有 250 毫秒上限并响应取消，不保存分页会话。

CM-17：筛选与授权范围先于分页；快照排除回填和延迟提交；验证跨模块游标、清理失效、空原因、unknown、脱敏、批量上限和取消。
