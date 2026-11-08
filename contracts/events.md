---
type: spec
status: Accepted
updated: 2026-11-09
---

# 审核事件契约

事件采用 CloudEvents 1.0，source 为 moderation，subject 为 task/<任务 ID>，type 带 .v1 主版本。决定 ID 在决定事务内确定。结果 ID 由决定 ID 与终态修订确定，同一结果重复投递沿用原 ID。data.revision 为任务修订号。

moderation.decided.v1 与决定同事务写入，表示决定已保存。moderation.result.v1 与终态 applied/failed 同事务写入。dismiss 在决定事务中直接产生结果；其他动作在内容模块确认执行后产生结果。

结果 data 包含 task_id、owner（申请人）、content_owner、object_id、content_kind、request_kind、action、state、revision、decision_id。事件不含举报证据、正文、身份原值或管理员账号。通知消费者只订阅 result.v1，并区分执行成功与失败。

内容通过、驳回、下架分别对应 publish、dismiss、hide。举报与资料下架申请通过 request_kind=report/delete_request 区分，侵权投诉的任务类型沿用 report。

所有 outbox 写入在同一事务执行 pg_notify('moderation_outbox', '')。通知仅用于唤醒，数据以 outbox 为准。回滚不产生事件或通知。

Go OutboxReader 提供 PendingOutbox(ctx, limit) 与 ConfirmOutbox(ctx, id)。limit 为 1–100，按 subject、revision、ID 排序，查询 sent_at IS NULL 部分索引。确认仅在消费者事务成功后调用，重复确认成功，未知 ID 返回 not_found。

relay 启动、重连和每 60 秒兜底读取未发送事件，收到通知立即排空积压。相同 source/subject 串行处理，失败阻止后续修订超前。5 秒指数退避至 1 小时，24 小时后转人工处理，重试保留原 ID。

消费者在本地事务写 inbox，以 source/ID 去重，并忽略不高于已处理修订的事件。生产模块的确认不替代消费者 inbox。backend 装配与消费者验证由后续任务完成。

CM-16：事务回滚没有通知和 outbox，提交后收到通知；未监听期间的积压可补读；批量上限 100；重复读取保持封套及 ID，重复确认幂等，旧决定不产生新结果。
