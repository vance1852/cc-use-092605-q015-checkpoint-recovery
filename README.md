# 建立机组遥测任务断点恢复基础平台

本项目是一套可离线运行的 Python 服务端平台，用于管理海上风电场、送出通道、机组资源批次、场站申报、功率分配、调度情景与机组健康准入。业务状态、登录权限、幂等结果和审计事件保存在 SQLite 中，适合生产调度、设备质量、风险与审计人员在单个 Linux 应用容器内协作。

## 目录

- `src/wind_dispatch/`：场站、送出通道、机组可用量、功率申报、日前分配和调度情景；
- `src/turbine_health/`：机组健康协议、测点导入、异常复核、**可恢复的分片分析工作图**和健康决定；
- `src/grid_qualification/`：并网机组批次、检测数据、分析、账号登录与质量审批；
- `fixtures/`：离线验收使用的检测协议和结构化测点；
- `tests/`：核心规则、权限、错误边界、事务、API 和命令行验收测试。

## 环境

- Linux
- Python 3.11 或更高版本
- 运行时仅使用 Python 标准库和 SQLite

## 可恢复的批量分析工作图

遥测校核按“分层叶子分片 + 聚合分片”组成有向无环图，全部状态持久化在 SQLite（schema v3），服务重启后可从记录准确重建：

- **创建即固定**：`POST /workflows` 在创建工作流时冻结输入清单（`manifest_json`）、整单输入摘要、协议摘要与算法版本；每个分片记录自己的分片输入摘要、所属层级与前置依赖。
- **限时租约领取**：`POST /shards/claim` 只领取依赖全部成功且在退避窗口外的分片；每次领取领取代次 `lease_generation` 自增。过期租约可被其他工作进程接管，旧代次未闭合的尝试标记为 `lease_expired`。
- **原子提交与下游解锁**：`POST /shards/{id}/complete` 在单个事务内写入内容寻址输出、标记分片成功并解锁下游；提交时再次核对领取代次、输入摘要与算法版本。代次不符或租约已过期的迟到提交一律拒绝，不影响接管者。
- **重试与人工处理**：`POST /shards/{id}/fail` 对可重试错误按工作流退避策略安排下一次尝试，超过 `max_attempts` 或显式不可重试时转入 `manual`；人工处理后用 `POST /shards/{id}/resume` 重新入队。
- **取消只阻止领取**：`POST /workflows/{id}/cancel` 仅阻止新的领取，已完成的分片输出和聚合结果全部保留。
- **输出内容寻址复用**：`shard_outputs` 以 `(分片输入摘要, 算法版本)` 唯一约束缓存结果，同输入同版本绝不重复计算，从根上避免新旧算法输出混用。
- **状态重建与血缘**：`GET /workflows/{id}` 返回 waiting/ready/leased/failed/manual/succeeded（含过期租约的有效状态）分组、逐次尝试历史，以及最终结果由哪份输入与哪次尝试产生的 provenance。

分片状态集合：`waiting`、`ready`、`leased`、`succeeded`、`failed`、`manual`；工作流状态：`active`、`cancelled`、`completed`。

## 测试

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

## 构建检查

```bash
python3 -m compileall -q src tests
```

## 离线验收

```bash
PYTHONPATH=src python3 -m wind_dispatch.acceptance --workspace .
PYTHONPATH=src python3 -m turbine_health.acceptance --workspace .
PYTHONPATH=src python3 -m grid_qualification.acceptance
```

三条命令使用临时 SQLite 数据库完成场站与通道登记、功率申报分配、健康测点分析和并网审批，不访问外部网络。

## HTTP 服务

```bash
PYTHONPATH=src python3 -m wind_dispatch.api --database wind.sqlite3 --host 127.0.0.1 --port 8080
PYTHONPATH=src python3 -m turbine_health.api --database health.sqlite3 --host 127.0.0.1 --port 8081
PYTHONPATH=src python3 -m grid_qualification.api --database grid.sqlite3 --host 127.0.0.1 --port 8082
```

服务均提供 `GET /health`，其余接口使用 JSON。账号登录和角色权限由服务端校验，进程重启后可以继续查询 SQLite 中的业务状态与审计历史。
