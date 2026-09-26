# 建立机组遥测任务断点恢复基础平台

本项目是一套可离线运行的 Python 服务端平台，用于管理海上风电场、送出通道、机组资源批次、场站申报、功率分配、调度情景与机组健康准入。业务状态、登录权限、幂等结果和审计事件保存在 SQLite 中，适合生产调度、设备质量、风险与审计人员在单个 Linux 应用容器内协作。

## 目录

- `src/wind_dispatch/`：场站、送出通道、机组可用量、功率申报、日前分配和调度情景；
- `src/turbine_health/`：机组健康协议、测点导入、异常复核、分析任务租约、可恢复分片工作图和健康决定；
- `src/grid_qualification/`：并网机组批次、检测数据、分析、账号登录与质量审批；
- `fixtures/`：离线验收使用的检测协议和结构化测点；
- `tests/`：核心规则、权限、错误边界、事务、API 和命令行验收测试。

## 环境

- Linux
- Python 3.11 或更高版本
- 运行时仅使用 Python 标准库和 SQLite

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

## 可恢复分析工作图

`turbine_health` 的分片工作图把批量分析（如 131 台机组遥测校核加下游功率曲线统计）改造成可恢复执行：

- 创建任务（`POST /analysis-tasks`）时固定输入清单摘要与算法版本，每个分片记录前置依赖；
- 工作进程凭限时租约领取（`POST /analysis-shards/claim`）依赖已完成的分片，每次领取递增领取代次；
- 提交（`POST /analysis-tasks/{task}/shards/{shard}/complete`）把结果入库与下游解锁放在同一事务，并重新核对领取代次、输入摘要与算法版本；租约失效后的迟到提交会被拒绝且不影响接管者；
- 可重试错误按任务策略退避重试，超过限额转人工处理（`POST .../requeue` 重新入队）；取消任务只阻止新的领取，已有成果保留；
- `GET /analysis-tasks/{task}` 从持久化记录重建等待、运行、失败、人工处理和完成状态，并给出每个输出由哪份输入与哪次尝试产生。
