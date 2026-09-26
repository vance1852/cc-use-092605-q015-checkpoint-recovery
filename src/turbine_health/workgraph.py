"""可恢复的分片工作图：固定输入清单、限时租约与原子提交。

设计要点：

- 创建任务时把输入清单（每个分片的输入描述与依赖关系）和算法版本一并
  固定，之后任何提交都必须与之核对，避免新旧算法或新旧输入混用；
- 分片只有在前置依赖全部产出后才能被工作进程凭限时租约领取，每次领取
  递增领取代次（fencing token）；
- 结果入库与下游解锁是同一个事务：提交时重新确认领取代次、输入摘要与
  算法版本，租约失效后的迟到提交会被拒绝且不影响接管者；
- 可重试错误按任务策略进入下一次尝试，超过限额转入人工处理；取消任务
  只阻止新的领取，已有成果全部保留；
- 不保存任何内存状态，等待、运行、失败、人工处理和完成状态都能从持久化
  记录准确重建，每个输出都能说明由哪份输入与哪次尝试产生。
"""

from __future__ import annotations

import json
import re
import sqlite3
from datetime import timedelta
from typing import Any, Mapping, Sequence

from .clock import SystemClock, isoformat
from .errors import Conflict, Forbidden, InvalidState, NotFound, ValidationFailed
from .jsonio import canonical_json, content_digest
from .storage import initialize, transaction


WORKGRAPH_PERMISSIONS = {
    "operator": set(),
    "statistician": {
        "analysis.task.create",
        "analysis.task.cancel",
        "analysis.task.read",
        "analysis.shard.requeue",
    },
    "approver": {"analysis.task.read"},
    "auditor": {"analysis.task.read"},
}

SHARD_STATES = ("waiting", "running", "failed", "manual", "complete")

_KEY_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")

DEFAULT_MAX_ATTEMPTS = 3
DEFAULT_RETRY_DELAY_SECONDS = 30


class WorkGraphService:
    """在单个 SQLite 连接上提供可恢复的分片工作图。"""

    def __init__(self, connection: sqlite3.Connection, clock=None) -> None:
        self.connection = connection
        self.clock = clock or SystemClock()
        initialize(connection)

    # ---- 基础辅助 ------------------------------------------------------

    def _now(self) -> str:
        return isoformat(self.clock.now())

    def _require(self, user_id: str, permission: str) -> sqlite3.Row:
        row = self.connection.execute(
            "SELECT user_id, role, active FROM users WHERE user_id=?", (user_id,)
        ).fetchone()
        if row is None:
            raise NotFound(f"用户不存在: {user_id}")
        if not row["active"]:
            raise Forbidden("用户已停用")
        if permission not in WORKGRAPH_PERMISSIONS[row["role"]]:
            raise Forbidden(f"角色 {row['role']} 无权执行 {permission}")
        return row

    def _audit(
        self, entity_type: str, entity_id: str, event_type: str, actor_id: str, payload: Mapping[str, Any]
    ) -> None:
        self.connection.execute(
            "INSERT INTO audit_events(entity_type,entity_id,event_type,actor_id,payload_json,created_at) "
            "VALUES(?,?,?,?,?,?)",
            (entity_type, entity_id, event_type, actor_id, canonical_json(payload), self._now()),
        )

    @staticmethod
    def _valid_key(value: object, path: str) -> str:
        if not isinstance(value, str) or not _KEY_PATTERN.match(value):
            raise ValidationFailed(f"{path} 只能包含字母、数字、点、下划线和连字符")
        return value

    @staticmethod
    def _valid_generation(value: object) -> int:
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise ValidationFailed("领取代次必须是正整数")
        return value

    def _task_row(self, task_id: str) -> sqlite3.Row:
        row = self.connection.execute(
            "SELECT * FROM analysis_tasks WHERE task_id=?", (task_id,)
        ).fetchone()
        if row is None:
            raise NotFound(f"分析任务不存在: {task_id}")
        return row

    def _shard_row(self, task_id: str, shard_key: str) -> sqlite3.Row:
        row = self.connection.execute(
            "SELECT * FROM task_shards WHERE task_id=? AND shard_key=?", (task_id, shard_key)
        ).fetchone()
        if row is None:
            raise NotFound(f"分片不存在: {task_id}/{shard_key}")
        return row

    # ---- 任务创建 ------------------------------------------------------

    @staticmethod
    def _validate_policy(policy: object) -> tuple[int, int]:
        if policy is None:
            return DEFAULT_MAX_ATTEMPTS, DEFAULT_RETRY_DELAY_SECONDS
        if not isinstance(policy, Mapping):
            raise ValidationFailed("重试策略必须是对象")
        max_attempts = policy.get("max_attempts", DEFAULT_MAX_ATTEMPTS)
        if isinstance(max_attempts, bool) or not isinstance(max_attempts, int) or max_attempts < 1:
            raise ValidationFailed("policy.max_attempts 必须是正整数")
        retry_delay = policy.get("retry_delay_seconds", DEFAULT_RETRY_DELAY_SECONDS)
        if isinstance(retry_delay, bool) or not isinstance(retry_delay, int) or retry_delay < 0:
            raise ValidationFailed("policy.retry_delay_seconds 必须是非负整数")
        return max_attempts, retry_delay

    def _validate_shards(self, shards: object) -> list[dict[str, Any]]:
        if not isinstance(shards, Sequence) or isinstance(shards, (str, bytes, bytearray)) or not shards:
            raise ValidationFailed("分片清单必须是非空数组")
        specs: list[dict[str, Any]] = []
        seen: set[str] = set()
        for index, raw in enumerate(shards):
            if not isinstance(raw, Mapping):
                raise ValidationFailed(f"shards[{index}] 必须是对象")
            key = self._valid_key(raw.get("shard_key"), f"shards[{index}].shard_key")
            if key in seen:
                raise ValidationFailed(f"分片键重复: {key}")
            seen.add(key)
            descriptor = raw.get("input")
            if not isinstance(descriptor, Mapping):
                raise ValidationFailed(f"shards[{index}].input 必须是对象")
            depends_on = raw.get("depends_on", [])
            if not isinstance(depends_on, Sequence) or isinstance(depends_on, (str, bytes, bytearray)):
                raise ValidationFailed(f"shards[{index}].depends_on 必须是数组")
            deps: list[str] = []
            for dep in depends_on:
                if not isinstance(dep, str):
                    raise ValidationFailed(f"shards[{index}].depends_on 元素必须是字符串")
                if dep in deps:
                    raise ValidationFailed(f"分片 {key} 的依赖 {dep} 重复")
                deps.append(dep)
            specs.append({"shard_key": key, "input": descriptor, "depends_on": tuple(deps)})
        keys = {spec["shard_key"] for spec in specs}
        for spec in specs:
            for dep in spec["depends_on"]:
                if dep == spec["shard_key"]:
                    raise ValidationFailed(f"分片 {dep} 不能依赖自身")
                if dep not in keys:
                    raise ValidationFailed(f"分片 {spec['shard_key']} 依赖了未知分片 {dep}")
        self._assert_acyclic(specs)
        return specs

    @staticmethod
    def _assert_acyclic(specs: list[dict[str, Any]]) -> None:
        indegree = {spec["shard_key"]: 0 for spec in specs}
        dependents: dict[str, list[str]] = {spec["shard_key"]: [] for spec in specs}
        for spec in specs:
            for dep in spec["depends_on"]:
                indegree[spec["shard_key"]] += 1
                dependents[dep].append(spec["shard_key"])
        queue = [key for key, degree in indegree.items() if degree == 0]
        visited = 0
        while queue:
            node = queue.pop()
            visited += 1
            for nxt in dependents[node]:
                indegree[nxt] -= 1
                if indegree[nxt] == 0:
                    queue.append(nxt)
        if visited != len(specs):
            raise ValidationFailed("分片依赖存在环")

    def create_task(
        self,
        actor_id: str,
        task_id: str,
        title: str,
        algorithm_version: str,
        shards: object,
        policy: object = None,
    ) -> dict[str, Any]:
        """固定输入清单与算法版本，创建一张可恢复的工作图。"""

        self._require(actor_id, "analysis.task.create")
        task_id = self._valid_key(task_id, "task_id")
        if not isinstance(title, str) or not title.strip():
            raise ValidationFailed("任务标题不能为空")
        if not isinstance(algorithm_version, str) or not algorithm_version.strip():
            raise ValidationFailed("算法版本不能为空")
        specs = self._validate_shards(shards)
        max_attempts, retry_delay = self._validate_policy(policy)
        manifest_entries = [
            {
                "shard_key": spec["shard_key"],
                "input_sha256": content_digest([spec["input"]]),
                "depends_on": sorted(spec["depends_on"]),
            }
            for spec in specs
        ]
        manifest_sha256 = content_digest(manifest_entries)
        now = self._now()
        try:
            with transaction(self.connection, immediate=True):
                self.connection.execute(
                    "INSERT INTO analysis_tasks(task_id,title,algorithm_version,manifest_json,manifest_sha256,"
                    "max_attempts,retry_delay_seconds,state,created_by,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (
                        task_id,
                        title.strip(),
                        algorithm_version.strip(),
                        canonical_json(manifest_entries),
                        manifest_sha256,
                        max_attempts,
                        retry_delay,
                        "open",
                        actor_id,
                        now,
                    ),
                )
                for spec, entry in zip(specs, manifest_entries):
                    self.connection.execute(
                        "INSERT INTO task_shards(task_id,shard_key,input_json,input_sha256,state,available_at,"
                        "created_at,updated_at) VALUES(?,?,?,?,'waiting',?,?,?)",
                        (
                            task_id,
                            spec["shard_key"],
                            canonical_json(spec["input"]),
                            entry["input_sha256"],
                            now,
                            now,
                            now,
                        ),
                    )
                    for dep in spec["depends_on"]:
                        self.connection.execute(
                            "INSERT INTO shard_dependencies(task_id,shard_key,depends_on_key) VALUES(?,?,?)",
                            (task_id, spec["shard_key"], dep),
                        )
                self._audit(
                    "analysis_task",
                    task_id,
                    "analysis_task.created",
                    actor_id,
                    {
                        "algorithm_version": algorithm_version.strip(),
                        "manifest_sha256": manifest_sha256,
                        "shard_count": len(specs),
                        "max_attempts": max_attempts,
                        "retry_delay_seconds": retry_delay,
                    },
                )
        except sqlite3.IntegrityError as exc:
            raise Conflict(f"分析任务已存在: {task_id}") from exc
        return self.task_status(actor_id, task_id)

    # ---- 领取 ----------------------------------------------------------

    def _expected_input_digest(self, task_id: str, shard: sqlite3.Row) -> str:
        """源分片返回创建时固定的摘要；派生分片按上游已入库输出计算。"""

        dependencies = [
            row["depends_on_key"]
            for row in self.connection.execute(
                "SELECT depends_on_key FROM shard_dependencies WHERE task_id=? AND shard_key=? "
                "ORDER BY depends_on_key",
                (task_id, shard["shard_key"]),
            ).fetchall()
        ]
        if not dependencies:
            return shard["input_sha256"]
        upstream: dict[str, str] = {}
        for dep in dependencies:
            output = self.connection.execute(
                "SELECT output_sha256 FROM shard_outputs WHERE task_id=? AND shard_key=?",
                (task_id, dep),
            ).fetchone()
            if output is None:
                raise InvalidState(f"前置分片尚未完成: {dep}")
            upstream[dep] = output["output_sha256"]
        return content_digest([{"descriptor_sha256": shard["input_sha256"], "upstream": upstream}])

    def _upstream_payloads(self, task_id: str, shard_key: str) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            "SELECT d.depends_on_key, o.output_sha256, o.output_json FROM shard_dependencies d "
            "JOIN shard_outputs o ON o.task_id=d.task_id AND o.shard_key=d.depends_on_key "
            "WHERE d.task_id=? AND d.shard_key=? ORDER BY d.depends_on_key",
            (task_id, shard_key),
        ).fetchall()
        return [
            {
                "shard_key": row["depends_on_key"],
                "output_sha256": row["output_sha256"],
                "output": json.loads(row["output_json"]),
            }
            for row in rows
        ]

    def claim_shard(
        self, worker_id: str, lease_seconds: int = 60, task_id: str | None = None
    ) -> dict[str, Any] | None:
        """领取一个依赖已完成的分片；每次领取递增领取代次并写下尝试记录。"""

        if not isinstance(worker_id, str) or not worker_id.strip():
            raise ValidationFailed("工作进程编号不能为空")
        if isinstance(lease_seconds, bool) or not isinstance(lease_seconds, int) or lease_seconds <= 0:
            raise ValidationFailed("租约时长必须大于零")
        worker_id = worker_id.strip()
        now_dt = self.clock.now()
        now = isoformat(now_dt)
        expires = isoformat(now_dt + timedelta(seconds=lease_seconds))
        with transaction(self.connection, immediate=True):
            params: list[Any] = [now, now]
            task_filter = ""
            if task_id is not None:
                self._task_row(task_id)
                task_filter = "AND s.task_id = ?"
                params.append(task_id)
            row = self.connection.execute(
                "SELECT s.task_id, s.shard_key FROM task_shards s "
                "JOIN analysis_tasks t ON t.task_id = s.task_id "
                "WHERE t.state = 'open' "
                "AND (s.state IN ('waiting', 'failed') "
                "     OR (s.state = 'running' AND s.lease_expires_at <= ?)) "
                "AND s.available_at <= ? "
                "AND NOT EXISTS ("
                "    SELECT 1 FROM shard_dependencies d "
                "    WHERE d.task_id = s.task_id AND d.shard_key = s.shard_key "
                "    AND NOT EXISTS ("
                "        SELECT 1 FROM shard_outputs o "
                "        WHERE o.task_id = d.task_id AND o.shard_key = d.depends_on_key)) "
                f"{task_filter} "
                "ORDER BY s.available_at, s.task_id, s.shard_key LIMIT 1",
                params,
            ).fetchone()
            if row is None:
                return None
            shard = self._shard_row(row["task_id"], row["shard_key"])
            task = self._task_row(row["task_id"])
            generation = shard["claim_generation"] + 1
            self.connection.execute(
                "UPDATE task_shards SET state='running',claim_generation=?,lease_owner=?,lease_expires_at=?,"
                "updated_at=? WHERE task_id=? AND shard_key=?",
                (generation, worker_id, expires, now, row["task_id"], row["shard_key"]),
            )
            self.connection.execute(
                "INSERT INTO shard_attempts(task_id,shard_key,attempt_no,worker_id,leased_at,lease_expires_at,"
                "outcome) VALUES(?,?,?,?,?,?,'leased')",
                (row["task_id"], row["shard_key"], generation, worker_id, now, expires),
            )
            expected_input = self._expected_input_digest(row["task_id"], shard)
            upstream = self._upstream_payloads(row["task_id"], row["shard_key"])
        return {
            "task_id": row["task_id"],
            "shard_key": row["shard_key"],
            "attempt": generation,
            "algorithm_version": task["algorithm_version"],
            "lease_owner": worker_id,
            "lease_expires_at": expires,
            "input": json.loads(shard["input_json"]),
            "expected_input_sha256": expected_input,
            "upstream": upstream,
            "policy": {
                "max_attempts": task["max_attempts"],
                "retry_delay_seconds": task["retry_delay_seconds"],
            },
        }

    # ---- 提交与失败上报 -------------------------------------------------

    def complete_shard(
        self,
        worker_id: str,
        task_id: str,
        shard_key: str,
        generation: int,
        algorithm_version: str,
        input_sha256: str,
        output: Mapping[str, Any],
    ) -> dict[str, Any]:
        """原子提交：结果入库与下游解锁在同一事务，并重新核对代次、输入与算法。"""

        generation = self._valid_generation(generation)
        if not isinstance(output, Mapping):
            raise ValidationFailed("分片输出必须是 JSON 对象")
        if not isinstance(input_sha256, str) or len(input_sha256) != 64:
            raise ValidationFailed("输入摘要必须是 64 位 SHA-256")
        output_sha256 = content_digest([output])
        now = self._now()
        with transaction(self.connection, immediate=True):
            task = self._task_row(task_id)
            shard = self._shard_row(task_id, shard_key)
            if shard["state"] == "complete":
                existing = self.connection.execute(
                    "SELECT * FROM shard_outputs WHERE task_id=? AND shard_key=?", (task_id, shard_key)
                ).fetchone()
                if (
                    existing["attempt_no"] == generation
                    and existing["input_sha256"] == input_sha256
                    and existing["output_sha256"] == output_sha256
                ):
                    return {
                        "replay": True,
                        "task_id": task_id,
                        "shard_key": shard_key,
                        "attempt_no": generation,
                        "output_sha256": output_sha256,
                    }
                raise Conflict("分片已完成，内容不同的重复提交被拒绝")
            if (
                shard["state"] != "running"
                or shard["lease_owner"] != worker_id
                or shard["claim_generation"] != generation
            ):
                raise Conflict("领取代次已失效，迟到提交不会影响当前持有者")
            if shard["lease_expires_at"] <= now:
                raise InvalidState("租约已过期，迟到提交被拒绝")
            if algorithm_version != task["algorithm_version"]:
                raise Conflict("算法版本与任务固定版本不一致")
            expected_input = self._expected_input_digest(task_id, shard)
            if input_sha256 != expected_input:
                raise Conflict("输入摘要与任务固定清单不一致")
            missing = self.connection.execute(
                "SELECT count(*) FROM shard_dependencies d WHERE d.task_id=? AND d.shard_key=? "
                "AND NOT EXISTS (SELECT 1 FROM shard_outputs o "
                "WHERE o.task_id=d.task_id AND o.shard_key=d.depends_on_key)",
                (task_id, shard_key),
            ).fetchone()[0]
            if missing:
                raise InvalidState("前置分片尚未完成，不能提交")
            self.connection.execute(
                "INSERT INTO shard_outputs(task_id,shard_key,input_sha256,algorithm_version,output_json,"
                "output_sha256,attempt_no,worker_id,completed_at) VALUES(?,?,?,?,?,?,?,?,?)",
                (
                    task_id,
                    shard_key,
                    input_sha256,
                    algorithm_version,
                    canonical_json(output),
                    output_sha256,
                    generation,
                    worker_id,
                    now,
                ),
            )
            self.connection.execute(
                "UPDATE shard_attempts SET finished_at=?,outcome='succeeded',input_sha256=?,output_sha256=? "
                "WHERE task_id=? AND shard_key=? AND attempt_no=?",
                (now, input_sha256, output_sha256, task_id, shard_key, generation),
            )
            self.connection.execute(
                "UPDATE task_shards SET state='complete',lease_owner=NULL,lease_expires_at=NULL,updated_at=? "
                "WHERE task_id=? AND shard_key=?",
                (now, task_id, shard_key),
            )
            self._audit(
                "analysis_shard",
                f"{task_id}/{shard_key}",
                "analysis_shard.completed",
                worker_id,
                {
                    "attempt_no": generation,
                    "algorithm_version": algorithm_version,
                    "input_sha256": input_sha256,
                    "output_sha256": output_sha256,
                },
            )
        return {
            "replay": False,
            "task_id": task_id,
            "shard_key": shard_key,
            "attempt_no": generation,
            "output_sha256": output_sha256,
        }

    def fail_shard(
        self,
        worker_id: str,
        task_id: str,
        shard_key: str,
        generation: int,
        error: str,
        retryable: bool = True,
    ) -> dict[str, Any]:
        """上报失败：可重试错误按策略进入下一次尝试，超过限额转人工处理。"""

        generation = self._valid_generation(generation)
        if not isinstance(error, str) or not error.strip():
            raise ValidationFailed("错误说明不能为空")
        now_dt = self.clock.now()
        now = isoformat(now_dt)
        with transaction(self.connection, immediate=True):
            task = self._task_row(task_id)
            shard = self._shard_row(task_id, shard_key)
            attempts_used = shard["claim_generation"] - shard["attempt_base"]
            if retryable and attempts_used < task["max_attempts"]:
                new_state = "failed"
                outcome = "failed_retryable"
                available = isoformat(now_dt + timedelta(seconds=task["retry_delay_seconds"]))
            else:
                new_state = "manual"
                outcome = "failed_final"
                available = now
            cursor = self.connection.execute(
                "UPDATE task_shards SET state=?,available_at=?,lease_owner=NULL,lease_expires_at=NULL,"
                "last_error=?,updated_at=? "
                "WHERE task_id=? AND shard_key=? AND state='running' AND lease_owner=? AND claim_generation=?",
                (
                    new_state,
                    available,
                    error.strip()[:1000],
                    now,
                    task_id,
                    shard_key,
                    worker_id,
                    generation,
                ),
            )
            if cursor.rowcount != 1:
                raise InvalidState("任务未由当前工作进程持有或领取代次已过期")
            self.connection.execute(
                "UPDATE shard_attempts SET finished_at=?,outcome=?,error=? "
                "WHERE task_id=? AND shard_key=? AND attempt_no=?",
                (now, outcome, error.strip()[:1000], task_id, shard_key, generation),
            )
            self._audit(
                "analysis_shard",
                f"{task_id}/{shard_key}",
                "analysis_shard.failed",
                worker_id,
                {"attempt_no": generation, "outcome": outcome, "error": error.strip()[:1000]},
            )
        return {
            "task_id": task_id,
            "shard_key": shard_key,
            "attempt_no": generation,
            "state": new_state,
            "available_at": available,
        }

    # ---- 人工处理与取消 --------------------------------------------------

    def requeue_shard(self, actor_id: str, task_id: str, shard_key: str) -> dict[str, Any]:
        """人工处理后把分片重新放回等待队列，历史尝试记录全部保留。"""

        self._require(actor_id, "analysis.shard.requeue")
        now = self._now()
        with transaction(self.connection, immediate=True):
            shard = self._shard_row(task_id, shard_key)
            if shard["state"] != "manual":
                raise InvalidState("只有人工处理中的分片可以重新入队")
            self.connection.execute(
                "UPDATE task_shards SET state='waiting',available_at=?,attempt_base=claim_generation,"
                "lease_owner=NULL,lease_expires_at=NULL,updated_at=? WHERE task_id=? AND shard_key=?",
                (now, now, task_id, shard_key),
            )
            self._audit(
                "analysis_shard",
                f"{task_id}/{shard_key}",
                "analysis_shard.requeued",
                actor_id,
                {"from_attempt": shard["claim_generation"]},
            )
        return self.task_status(actor_id, task_id)

    def cancel_task(self, actor_id: str, task_id: str) -> dict[str, Any]:
        """取消任务：只阻止新的领取，已完成成果与在飞租约全部保留。"""

        self._require(actor_id, "analysis.task.cancel")
        now = self._now()
        with transaction(self.connection, immediate=True):
            cursor = self.connection.execute(
                "UPDATE analysis_tasks SET state='cancelled',cancelled_at=? WHERE task_id=? AND state='open'",
                (now, task_id),
            )
            if cursor.rowcount != 1:
                self._task_row(task_id)
                raise InvalidState("任务已经取消")
            self._audit("analysis_task", task_id, "analysis_task.cancelled", actor_id, {})
        return self.task_status(actor_id, task_id)

    # ---- 状态重建 ------------------------------------------------------

    @staticmethod
    def _effective_state(shard: sqlite3.Row, now: str, dependencies_complete: bool) -> tuple[str, str]:
        state = shard["state"]
        if state == "complete":
            return "complete", "output_recorded"
        if state == "manual":
            return "manual", "awaiting_human"
        if state == "running":
            if shard["lease_expires_at"] is not None and shard["lease_expires_at"] > now:
                return "running", "lease_active"
            return "waiting", "lease_expired"
        if state == "failed":
            if shard["available_at"] > now:
                return "failed", "retry_scheduled"
            return "failed", "awaiting_claim"
        if not dependencies_complete:
            return "waiting", "waiting_dependencies"
        if shard["available_at"] > now:
            return "waiting", "waiting_retry_delay"
        return "waiting", "ready"

    def task_status(self, actor_id: str, task_id: str) -> dict[str, Any]:
        """从持久化记录重建每个分片的等待、运行、失败、人工处理和完成状态。"""

        self._require(actor_id, "analysis.task.read")
        task = self._task_row(task_id)
        shards = self.connection.execute(
            "SELECT * FROM task_shards WHERE task_id=? ORDER BY shard_key", (task_id,)
        ).fetchall()
        dependencies = self.connection.execute(
            "SELECT shard_key, depends_on_key FROM shard_dependencies WHERE task_id=? "
            "ORDER BY shard_key, depends_on_key",
            (task_id,),
        ).fetchall()
        outputs = self.connection.execute(
            "SELECT * FROM shard_outputs WHERE task_id=?", (task_id,)
        ).fetchall()
        deps_by_shard: dict[str, list[str]] = {}
        for row in dependencies:
            deps_by_shard.setdefault(row["shard_key"], []).append(row["depends_on_key"])
        outputs_by_shard = {row["shard_key"]: row for row in outputs}
        now = self._now()
        summary = {state: 0 for state in SHARD_STATES}
        shard_views: list[dict[str, Any]] = []
        for shard in shards:
            deps = deps_by_shard.get(shard["shard_key"], [])
            dependencies_complete = all(dep in outputs_by_shard for dep in deps)
            state, detail = self._effective_state(shard, now, dependencies_complete)
            summary[state] += 1
            output_row = outputs_by_shard.get(shard["shard_key"])
            shard_views.append(
                {
                    "shard_key": shard["shard_key"],
                    "state": state,
                    "detail": detail,
                    "depends_on": deps,
                    "dependencies_complete": dependencies_complete,
                    "input_sha256": shard["input_sha256"],
                    "attempts": shard["claim_generation"],
                    "available_at": shard["available_at"],
                    "lease_owner": shard["lease_owner"],
                    "lease_expires_at": shard["lease_expires_at"],
                    "last_error": shard["last_error"],
                    "output": None
                    if output_row is None
                    else {
                        "input_sha256": output_row["input_sha256"],
                        "output_sha256": output_row["output_sha256"],
                        "algorithm_version": output_row["algorithm_version"],
                        "attempt_no": output_row["attempt_no"],
                        "worker_id": output_row["worker_id"],
                        "completed_at": output_row["completed_at"],
                    },
                }
            )
        summary["total"] = len(shard_views)
        return {
            "task_id": task["task_id"],
            "title": task["title"],
            "algorithm_version": task["algorithm_version"],
            "manifest_sha256": task["manifest_sha256"],
            "state": task["state"],
            "policy": {
                "max_attempts": task["max_attempts"],
                "retry_delay_seconds": task["retry_delay_seconds"],
            },
            "created_by": task["created_by"],
            "created_at": task["created_at"],
            "cancelled_at": task["cancelled_at"],
            "summary": summary,
            "shards": shard_views,
        }
