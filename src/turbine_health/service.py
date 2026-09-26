"""统计分析准入服务的领域用例。"""

from __future__ import annotations

import json
import hashlib
import sqlite3
from datetime import timedelta
from decimal import Decimal
from typing import Any, Iterable, Mapping

from .analysis import ALGORITHM_VERSION, aggregate_output, stratum_output
from .clock import SystemClock, isoformat
from .contracts import Observation, Protocol, ValidationError
from .errors import Conflict, Forbidden, InvalidState, NotFound, ValidationFailed
from .jsonio import canonical_json, content_digest
from .storage import initialize, transaction


# 工作图默认重试与租约策略（可在创建工作流时覆盖）。
DEFAULT_MAX_ATTEMPTS = 3
DEFAULT_LEASE_SECONDS = 60
DEFAULT_RETRY_BACKOFF_SECONDS = 5

LEAF_SHARD_KIND = "stratum"
AGGREGATE_SHARD_KIND = "aggregate"
AGGREGATE_SHARD_KEY = "aggregate"


ROLE_PERMISSIONS = {
    "operator": {
        "catalog.write", "batch.create", "batch.start", "observation.import",
        "exclusion.request", "exclusion.revoke",
    },
    "statistician": {"protocol.publish", "batch.seal", "exclusion.review", "analysis.run"},
    "approver": {"decision.write"},
    "auditor": {"report.read", "audit.read"},
}


class TrialService:
    """在单个 SQLite 连接上提供全部业务操作。"""

    def __init__(self, connection: sqlite3.Connection, clock=None) -> None:
        self.connection = connection
        self.clock = clock or SystemClock()
        initialize(connection)

    def _now(self) -> str:
        return isoformat(self.clock.now())

    def _user(self, user_id: str) -> sqlite3.Row:
        row = self.connection.execute(
            "SELECT user_id, display_name, role, active FROM users WHERE user_id=?", (user_id,)
        ).fetchone()
        if row is None:
            raise NotFound(f"用户不存在: {user_id}")
        if not row["active"]:
            raise Forbidden("用户已停用")
        return row

    def _require(self, user_id: str, permission: str) -> sqlite3.Row:
        user = self._user(user_id)
        if permission not in ROLE_PERMISSIONS[user["role"]]:
            raise Forbidden(f"角色 {user['role']} 无权执行 {permission}")
        return user

    def _audit(
        self, entity_type: str, entity_id: str, event_type: str, actor_id: str, payload: Mapping[str, Any]
    ) -> None:
        self.connection.execute(
            "INSERT INTO audit_events(entity_type,entity_id,event_type,actor_id,payload_json,created_at) "
            "VALUES(?,?,?,?,?,?)",
            (entity_type, entity_id, event_type, actor_id, canonical_json(payload), self._now()),
        )

    def create_user(self, user_id: str, display_name: str, role: str) -> dict[str, Any]:
        if role not in ROLE_PERMISSIONS:
            raise ValidationFailed(f"未知角色: {role}")
        if not user_id.strip() or not display_name.strip():
            raise ValidationFailed("用户编号和名称不能为空")
        try:
            with transaction(self.connection, immediate=True):
                self.connection.execute(
                    "INSERT INTO users(user_id,display_name,role) VALUES(?,?,?)",
                    (user_id.strip(), display_name.strip(), role),
                )
        except sqlite3.IntegrityError as exc:
            raise Conflict(f"用户已存在: {user_id}") from exc
        return {"user_id": user_id.strip(), "role": role}

    def register_robot(
        self, actor_id: str, robot_id: str, model_name: str, vendor: str
    ) -> dict[str, Any]:
        self._require(actor_id, "catalog.write")
        try:
            with transaction(self.connection, immediate=True):
                self.connection.execute(
                    "INSERT INTO robots(robot_id,model_name,vendor,created_at) VALUES(?,?,?,?)",
                    (robot_id, model_name, vendor, self._now()),
                )
                self._audit("robot", robot_id, "robot.registered", actor_id, {"model_name": model_name})
        except sqlite3.IntegrityError as exc:
            raise Conflict(f"传感器已存在: {robot_id}") from exc
        return {"robot_id": robot_id, "model_name": model_name, "vendor": vendor}

    def register_build(
        self, actor_id: str, build_id: str, robot_id: str, version: str, content_sha256: str
    ) -> dict[str, Any]:
        self._require(actor_id, "catalog.write")
        if len(content_sha256) != 64:
            raise ValidationFailed("构建摘要必须是 64 位 SHA-256")
        try:
            with transaction(self.connection, immediate=True):
                self.connection.execute(
                    "INSERT INTO builds(build_id,robot_id,version,content_sha256,created_at) VALUES(?,?,?,?,?)",
                    (build_id, robot_id, version, content_sha256.lower(), self._now()),
                )
                self._audit("build", build_id, "build.registered", actor_id, {"robot_id": robot_id, "version": version})
        except sqlite3.IntegrityError as exc:
            raise Conflict("构建编号、版本或摘要冲突") from exc
        return {"build_id": build_id, "robot_id": robot_id, "version": version}

    def publish_protocol(self, actor_id: str, raw: Mapping[str, Any]) -> dict[str, Any]:
        self._require(actor_id, "protocol.publish")
        try:
            protocol = Protocol.from_dict(raw)
        except ValidationError as exc:
            raise ValidationFailed(str(exc)) from exc
        text = canonical_json(raw)
        digest = content_digest([raw])
        try:
            with transaction(self.connection, immediate=True):
                self.connection.execute(
                    "INSERT INTO protocol_catalog(protocol_id,version,title,task_family,canonical_json,content_sha256,created_at) "
                    "VALUES(?,?,?,?,?,?,?)",
                    (
                        protocol.protocol_id,
                        protocol.version,
                        protocol.title,
                        protocol.task_family,
                        text,
                        digest,
                        self._now(),
                    ),
                )
                identity = f"{protocol.protocol_id}@{protocol.version}"
                self._audit("protocol", identity, "protocol.published", actor_id, {"sha256": digest})
        except sqlite3.IntegrityError as exc:
            raise Conflict("协议版本或内容摘要已经存在") from exc
        return {"protocol_id": protocol.protocol_id, "version": protocol.version, "sha256": digest}

    def _protocol(self, protocol_id: str, version: int) -> tuple[Protocol, str]:
        row = self.connection.execute(
            "SELECT canonical_json,content_sha256 FROM protocol_catalog WHERE protocol_id=? AND version=?",
            (protocol_id, version),
        ).fetchone()
        if row is None:
            raise NotFound("协议版本不存在")
        return Protocol.from_dict(json.loads(row["canonical_json"])), row["content_sha256"]

    def create_batch(
        self,
        actor_id: str,
        batch_id: str,
        protocol_id: str,
        protocol_version: int,
        build_id: str,
    ) -> dict[str, Any]:
        self._require(actor_id, "batch.create")
        self._protocol(protocol_id, protocol_version)
        try:
            with transaction(self.connection, immediate=True):
                self.connection.execute(
                    "INSERT INTO batches(batch_id,protocol_id,protocol_version,build_id,state,created_by,created_at) "
                    "VALUES(?,?,?,?,?,?,?)",
                    (batch_id, protocol_id, protocol_version, build_id, "draft", actor_id, self._now()),
                )
                self._audit("batch", batch_id, "batch.created", actor_id, {"build_id": build_id})
        except sqlite3.IntegrityError as exc:
            raise Conflict("批次编号冲突或构建不存在") from exc
        return self.get_batch(batch_id)

    def get_batch(self, batch_id: str) -> dict[str, Any]:
        row = self.connection.execute("SELECT * FROM batches WHERE batch_id=?", (batch_id,)).fetchone()
        if row is None:
            raise NotFound("批次不存在")
        return dict(row)

    def start_batch(self, actor_id: str, batch_id: str, expected_revision: int) -> dict[str, Any]:
        self._require(actor_id, "batch.start")
        with transaction(self.connection, immediate=True):
            cursor = self.connection.execute(
                "UPDATE batches SET state='running',revision=revision+1,started_at=? "
                "WHERE batch_id=? AND state='draft' AND revision=?",
                (self._now(), batch_id, expected_revision),
            )
            if cursor.rowcount != 1:
                raise InvalidState("批次不是当前草稿版本")
            self._audit("batch", batch_id, "batch.started", actor_id, {"from_revision": expected_revision})
        return self.get_batch(batch_id)

    def _idempotent_response(self, scope: str, key: str, request_digest: str) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT request_sha256,response_json FROM idempotency_keys WHERE scope=? AND key=?",
            (scope, key),
        ).fetchone()
        if row is None:
            return None
        if row["request_sha256"] != request_digest:
            raise Conflict("同一幂等键对应了不同请求内容")
        return json.loads(row["response_json"])

    def import_observations(
        self,
        actor_id: str,
        batch_id: str,
        idempotency_key: str,
        raw_rows: Iterable[Mapping[str, Any]],
    ) -> dict[str, Any]:
        self._require(actor_id, "observation.import")
        rows = tuple(raw_rows)
        if not rows:
            raise ValidationFailed("测点数组不能为空")
        request_digest = content_digest(rows)
        scope = f"observations:{batch_id}"
        existing = self._idempotent_response(scope, idempotency_key, request_digest)
        if existing is not None:
            return existing
        batch = self.get_batch(batch_id)
        if batch["state"] != "running":
            raise InvalidState("只有运行中的批次可以导入测点")
        protocol, _ = self._protocol(batch["protocol_id"], batch["protocol_version"])
        parsed: list[Observation] = []
        for raw in rows:
            try:
                item = Observation.from_dict(raw, protocol)
            except ValidationError as exc:
                raise ValidationFailed(str(exc)) from exc
            if item.robot_id != self.connection.execute(
                "SELECT robot_id FROM builds WHERE build_id=?", (batch["build_id"],)
            ).fetchone()["robot_id"]:
                raise ValidationFailed("测点传感器与批次构建不一致")
            parsed.append(item)
        response = {"batch_id": batch_id, "inserted": len(parsed), "request_sha256": request_digest}
        try:
            with transaction(self.connection, immediate=True):
                for item, raw in zip(parsed, rows):
                    self.connection.execute(
                        "INSERT INTO observations(batch_id,source_batch,source_row,robot_id,stratum_key,observed_at," 
                        "metrics_json,content_sha256,imported_by,imported_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                        (
                            batch_id,
                            item.source_batch,
                            item.source_row,
                            item.robot_id,
                            item.stratum_key,
                            item.observed_at,
                            canonical_json({key: format(value, "f") for key, value in item.metrics.items()}),
                            content_digest([raw]),
                            actor_id,
                            self._now(),
                        ),
                    )
                self.connection.execute(
                    "INSERT INTO idempotency_keys(scope,key,request_sha256,response_json,created_at) VALUES(?,?,?,?,?)",
                    (scope, idempotency_key, request_digest, canonical_json(response), self._now()),
                )
                self._audit("batch", batch_id, "observations.imported", actor_id, response)
        except sqlite3.IntegrityError as exc:
            raise Conflict("来源行重复或幂等键并发冲突") from exc
        return response

    def request_exclusion(self, actor_id: str, observation_id: int, reason: str) -> dict[str, Any]:
        self._require(actor_id, "exclusion.request")
        observation = self.connection.execute(
            "SELECT observation_id,batch_id FROM observations WHERE observation_id=?", (observation_id,)
        ).fetchone()
        if observation is None:
            raise NotFound("测点不存在")
        try:
            with transaction(self.connection, immediate=True):
                cursor = self.connection.execute(
                    "INSERT INTO exclusion_requests(observation_id,status,reason,requested_by,requested_at) "
                    "VALUES(?,?,?,?,?)",
                    (observation_id, "pending", reason, actor_id, self._now()),
                )
                exclusion_id = cursor.lastrowid
                self._audit("observation", str(observation_id), "exclusion.requested", actor_id, {"reason": reason})
        except sqlite3.IntegrityError as exc:
            raise Conflict("该测点已有待处理或生效排除") from exc
        return {"exclusion_id": exclusion_id, "status": "pending"}

    def review_exclusion(
        self, actor_id: str, exclusion_id: int, approve: bool, note: str
    ) -> dict[str, Any]:
        self._require(actor_id, "exclusion.review")
        row = self.connection.execute(
            "SELECT * FROM exclusion_requests WHERE exclusion_id=?", (exclusion_id,)
        ).fetchone()
        if row is None:
            raise NotFound("排除申请不存在")
        if row["status"] != "pending":
            raise InvalidState("排除申请已经处理")
        if row["requested_by"] == actor_id:
            raise Forbidden("申请人不能复核自己的排除申请")
        status = "approved" if approve else "rejected"
        with transaction(self.connection, immediate=True):
            self.connection.execute(
                "UPDATE exclusion_requests SET status=?,reviewed_by=?,reviewed_at=?,review_note=? "
                "WHERE exclusion_id=? AND status='pending'",
                (status, actor_id, self._now(), note, exclusion_id),
            )
            self._audit("exclusion", str(exclusion_id), f"exclusion.{status}", actor_id, {"note": note})
        return {"exclusion_id": exclusion_id, "status": status}

    def revoke_exclusion(self, actor_id: str, exclusion_id: int, reason: str) -> dict[str, Any]:
        self._require(actor_id, "exclusion.revoke")
        row = self.connection.execute(
            "SELECT e.*,o.batch_id FROM exclusion_requests e "
            "JOIN observations o ON o.observation_id=e.observation_id WHERE e.exclusion_id=?",
            (exclusion_id,),
        ).fetchone()
        if row is None:
            raise NotFound("排除记录不存在")
        if row["status"] != "approved":
            raise InvalidState("只有已批准的排除可以撤销")
        if row["requested_by"] != actor_id:
            raise Forbidden("只有原申请人可以撤销排除")
        batch = self.get_batch(row["batch_id"])
        if batch["state"] != "running":
            raise InvalidState("批次封存后不能改变排除状态")
        with transaction(self.connection, immediate=True):
            cursor = self.connection.execute(
                "UPDATE exclusion_requests SET status='revoked',review_note=?,reviewed_at=? "
                "WHERE exclusion_id=? AND status='approved'",
                (reason, self._now(), exclusion_id),
            )
            if cursor.rowcount != 1:
                raise InvalidState("排除状态已变化")
            self._audit(
                "observation",
                str(row["observation_id"]),
                "exclusion.revoked",
                actor_id,
                {"exclusion_id": exclusion_id, "reason": reason},
            )
        return {"exclusion_id": exclusion_id, "status": "revoked"}

    def seal_batch(self, actor_id: str, batch_id: str, expected_revision: int) -> dict[str, Any]:
        self._require(actor_id, "batch.seal")
        with transaction(self.connection, immediate=True):
            pending = self.connection.execute(
                "SELECT count(*) FROM exclusion_requests e JOIN observations o ON o.observation_id=e.observation_id "
                "WHERE o.batch_id=? AND e.status='pending'", (batch_id,)
            ).fetchone()[0]
            if pending:
                raise InvalidState("仍有待复核的排除申请")
            cursor = self.connection.execute(
                "UPDATE batches SET state='sealed',revision=revision+1,sealed_at=? "
                "WHERE batch_id=? AND state='running' AND revision=?",
                (self._now(), batch_id, expected_revision),
            )
            if cursor.rowcount != 1:
                raise InvalidState("批次状态或版本已变化")
            new_revision = expected_revision + 1
            self._audit("batch", batch_id, "batch.sealed", actor_id, {"revision": new_revision})
        return self.get_batch(batch_id)

    # ------------------------------------------------------------------
    # 可恢复的批量分析工作图
    # ------------------------------------------------------------------

    def _analysis_observations(self, batch_id: str, protocol: Protocol) -> tuple[Observation, ...]:
        rows = self.connection.execute(
            "SELECT o.*,e.reason AS excluded_reason FROM observations o "
            "LEFT JOIN exclusion_requests e ON e.observation_id=o.observation_id AND e.status='approved' "
            "WHERE o.batch_id=? ORDER BY o.observation_id",
            (batch_id,),
        ).fetchall()
        items: list[Observation] = []
        for row in rows:
            metrics = json.loads(row["metrics_json"])
            items.append(Observation(
                source_batch=row["source_batch"],
                source_row=row["source_row"],
                robot_id=row["robot_id"],
                protocol_id=protocol.protocol_id,
                protocol_version=protocol.version,
                stratum_key=row["stratum_key"],
                observed_at=row["observed_at"],
                metrics={key: Decimal(str(value)) for key, value in metrics.items()},
                excluded_reason=row["excluded_reason"],
            ))
        return tuple(items)

    @staticmethod
    def _snapshot_rows(observations: tuple[Observation, ...]) -> list[dict[str, Any]]:
        return [
            {
                "source_batch": item.source_batch,
                "source_row": item.source_row,
                "stratum": item.stratum_key,
                "metrics": {key: format(value, "f") for key, value in item.metrics.items()},
                "excluded_reason": item.excluded_reason,
            }
            for item in observations
        ]

    def create_analysis_workflow(
        self,
        actor_id: str,
        batch_id: str,
        *,
        max_attempts: int = DEFAULT_MAX_ATTEMPTS,
        lease_seconds: int = DEFAULT_LEASE_SECONDS,
        retry_backoff_seconds: int = DEFAULT_RETRY_BACKOFF_SECONDS,
    ) -> dict[str, Any]:
        """封存后创建工作图：固定输入清单、协议摘要与算法版本，按分层切分叶子分片。"""

        self._require(actor_id, "analysis.run")
        batch = self.get_batch(batch_id)
        if batch["state"] not in {"sealed", "analyzing"}:
            raise InvalidState("只有已封存的批次可以创建分析工作流")
        if max_attempts <= 0 or lease_seconds <= 0 or retry_backoff_seconds < 0:
            raise ValidationFailed("工作流重试与租约策略不合法")
        protocol, protocol_digest = self._protocol(batch["protocol_id"], batch["protocol_version"])
        observations = self._analysis_observations(batch_id, protocol)
        manifest_rows = self._snapshot_rows(observations)
        input_digest = content_digest(manifest_rows)
        now = self._now()
        try:
            with transaction(self.connection, immediate=True):
                cursor = self.connection.execute(
                    "INSERT INTO analysis_workflows(batch_id,batch_revision,protocol_sha256,algorithm_version,"
                    "manifest_json,input_sha256,max_attempts,lease_seconds,retry_backoff_seconds,state,"
                    "created_by,created_at) VALUES(?,?,?,?,?,?,?,?,?, 'active',?,?)",
                    (
                        batch_id, batch["revision"], protocol_digest, ALGORITHM_VERSION,
                        canonical_json(manifest_rows), input_digest, max_attempts, lease_seconds,
                        retry_backoff_seconds, actor_id, now,
                    ),
                )
                workflow_id = int(cursor.lastrowid)
                leaf_keys: list[str] = []
                leaf_digests: dict[str, str] = {}
                for stratum in protocol.strata:
                    stratum_rows = [row for row in manifest_rows if row["stratum"] == stratum.key]
                    leaf_input = content_digest([
                        {"protocol_sha256": protocol_digest, "stratum": stratum.key, "rows": stratum_rows}
                    ])
                    leaf_digests[stratum.key] = leaf_input
                    leaf_keys.append(stratum.key)
                    self.connection.execute(
                        "INSERT INTO workflow_shards(workflow_id,shard_key,layer,shard_kind,shard_input_sha256,"
                        "depends_on_json,state,attempts,available_at,created_at,updated_at) "
                        "VALUES(?,?,0,?,?,?, 'ready',0,?,?,?)",
                        (
                            workflow_id, f"{LEAF_SHARD_KIND}:{stratum.key}", LEAF_SHARD_KIND,
                            leaf_input, "[]", now, now, now,
                        ),
                    )
                aggregate_input = content_digest([
                    {
                        "protocol_sha256": protocol_digest,
                        "strata": [{"stratum": key, "input": leaf_digests[key]} for key in leaf_keys],
                    }
                ])
                leaf_shard_keys = [f"{LEAF_SHARD_KIND}:{name}" for name in leaf_keys]
                self.connection.execute(
                    "INSERT INTO workflow_shards(workflow_id,shard_key,layer,shard_kind,shard_input_sha256,"
                    "depends_on_json,state,attempts,available_at,created_at,updated_at) "
                    "VALUES(?,?,1,?,?,?, 'waiting',0,?,?,?)",
                    (
                        workflow_id, AGGREGATE_SHARD_KEY, AGGREGATE_SHARD_KIND,
                        aggregate_input, canonical_json(leaf_shard_keys), now, now, now,
                    ),
                )
                shard_ids = dict(self.connection.execute(
                    "SELECT shard_key,shard_id FROM workflow_shards WHERE workflow_id=?", (workflow_id,)
                ).fetchall())
                for key in leaf_shard_keys:
                    self.connection.execute(
                        "INSERT INTO shard_dependencies(shard_id,depends_on_shard_id) VALUES(?,?)",
                        (shard_ids[AGGREGATE_SHARD_KEY], shard_ids[key]),
                    )
                # 稳定输出可跨工作流复用：同输入同算法版本的分片直接判定成功，不再重复计算。
                for key in [*leaf_shard_keys, AGGREGATE_SHARD_KEY]:
                    self._attach_cached_output(shard_ids[key], now)
                self._unblock_dependents(workflow_id, now)
                self._finalize_workflow(workflow_id, now, actor_id)
                self._audit(
                    "workflow", str(workflow_id), "workflow.created", actor_id,
                    {"batch_id": batch_id, "input_sha256": input_digest, "algorithm_version": ALGORITHM_VERSION},
                )
        except sqlite3.IntegrityError as exc:
            raise Conflict("该批次版本、输入清单与算法版本的工作流已经存在") from exc
        return self.get_workflow(workflow_id)

    def _attach_cached_output(self, shard_id: int, now: str) -> None:
        """若分片输入与算法版本已有内容寻址输出，则直接复用并标记成功。"""

        shard = self.connection.execute(
            "SELECT * FROM workflow_shards WHERE shard_id=?", (shard_id,)
        ).fetchone()
        if shard["state"] not in {"waiting", "ready"}:
            return
        cached = self.connection.execute(
            "SELECT output_id FROM shard_outputs WHERE shard_input_sha256=? AND algorithm_version=?",
            (shard["shard_input_sha256"], ALGORITHM_VERSION),
        ).fetchone()
        if cached is None:
            return
        eligible_states = ("ready",) if shard["shard_kind"] == AGGREGATE_SHARD_KIND else ("waiting", "ready")
        self.connection.execute(
            "UPDATE workflow_shards SET state='succeeded',output_id=?,completed_attempt=NULL,"
            "lease_owner=NULL,lease_expires_at=NULL,last_error=NULL,updated_at=? "
            "WHERE shard_id=? AND state IN (" + ",".join("?" for _ in eligible_states) + ")",
            (cached["output_id"], now, shard_id, *eligible_states),
        )

    def _unblock_dependents(self, workflow_id: int, now: str) -> None:
        """前置分片全部成功的等待分片转为可领取；若有缓存输出则一并复用。"""

        waiting = self.connection.execute(
            "SELECT s.shard_id FROM workflow_shards s WHERE s.workflow_id=? AND s.state='waiting'",
            (workflow_id,),
        ).fetchall()
        for row in waiting:
            unmet = self.connection.execute(
                "SELECT count(*) FROM shard_dependencies d "
                "JOIN workflow_shards p ON p.shard_id=d.depends_on_shard_id "
                "WHERE d.shard_id=? AND p.state!='succeeded'",
                (row["shard_id"],),
            ).fetchone()[0]
            if unmet:
                continue
            self.connection.execute(
                "UPDATE workflow_shards SET state='ready',available_at=?,updated_at=? WHERE shard_id=? AND state='waiting'",
                (now, now, row["shard_id"]),
            )
            self._attach_cached_output(row["shard_id"], now)

    def _finalize_workflow(self, workflow_id: int, now: str, actor_id: str) -> None:
        """聚合分片成功后，原子写入总结果与血缘，并收尾工作流。"""

        workflow = self.connection.execute(
            "SELECT * FROM analysis_workflows WHERE workflow_id=?", (workflow_id,)
        ).fetchone()
        shards = self.connection.execute(
            "SELECT * FROM workflow_shards WHERE workflow_id=? ORDER BY shard_id", (workflow_id,)
        ).fetchall()
        aggregate = next((row for row in shards if row["shard_kind"] == AGGREGATE_SHARD_KIND), None)
        if aggregate is None or aggregate["state"] != "succeeded":
            return
        # 取消只阻止新的领取；在途分片即便晚到完成，其输出保留，但不再装配最终分析或推进批次。
        if workflow["state"] != "active":
            return
        if self.connection.execute(
            "SELECT analysis_id FROM analyses WHERE workflow_id=?", (workflow_id,)
        ).fetchone() is not None:
            return
        final = json.loads(self.connection.execute(
            "SELECT output_json FROM shard_outputs WHERE output_id=?", (aggregate["output_id"],)
        ).fetchone()["output_json"])
        cursor = self.connection.execute(
            "INSERT INTO analyses(workflow_id,batch_id,batch_revision,protocol_sha256,input_sha256,"
            "algorithm_version,seed,result_json,created_by,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (
                workflow_id, workflow["batch_id"], workflow["batch_revision"], workflow["protocol_sha256"],
                workflow["input_sha256"], workflow["algorithm_version"], final["seed"],
                canonical_json(final), actor_id, now,
            ),
        )
        analysis_id = int(cursor.lastrowid)
        for shard in shards:
            attempt_id = None
            if shard["completed_attempt"] is not None:
                attempt_row = self.connection.execute(
                    "SELECT attempt_id FROM workflow_attempts WHERE shard_id=? AND attempt_number=?",
                    (shard["shard_id"], shard["completed_attempt"]),
                ).fetchone()
                attempt_id = None if attempt_row is None else attempt_row["attempt_id"]
            self.connection.execute(
                "INSERT INTO analysis_shard_provenance(analysis_id,shard_id,output_id,attempt_id,"
                "shard_input_sha256,algorithm_version,reused) VALUES(?,?,?,?,?,?,?)",
                (
                    analysis_id, shard["shard_id"], shard["output_id"], attempt_id,
                    shard["shard_input_sha256"], workflow["algorithm_version"],
                    1 if shard["completed_attempt"] is None else 0,
                ),
            )
        if workflow["state"] == "active":
            self.connection.execute(
                "UPDATE analysis_workflows SET state='completed',completed_at=? WHERE workflow_id=? AND state='active'",
                (now, workflow_id),
            )
            self.connection.execute(
                "UPDATE batches SET state='analyzed' WHERE batch_id=? AND state IN ('sealed','analyzing')",
                (workflow["batch_id"],),
            )
        self._audit(
            "batch", workflow["batch_id"], "analysis.completed", actor_id,
            {
                "workflow_id": workflow_id,
                "analysis_id": analysis_id,
                "input_sha256": workflow["input_sha256"],
                "algorithm_version": workflow["algorithm_version"],
            },
        )

    def claim_shard(self, worker_id: str, workflow_id: int | None = None, *, lease_seconds: int | None = None) -> dict[str, Any] | None:
        """领取一个可运行分片：依赖已满足、在退避窗口外，或接管过期租约。"""

        if not worker_id.strip():
            raise ValidationFailed("工作进程标识不能为空")
        now = self._now()
        with transaction(self.connection, immediate=True):
            query = (
                "SELECT s.*,w.lease_seconds AS wf_lease_seconds,w.state AS wf_state "
                "FROM workflow_shards s JOIN analysis_workflows w ON w.workflow_id=s.workflow_id "
                "WHERE w.state='active' AND ("
                "(s.state IN ('ready','failed') AND s.available_at<=?) "
                "OR (s.state='leased' AND s.lease_expires_at<=?))"
            )
            params: list[Any] = [now, now]
            if workflow_id is not None:
                query += " AND s.workflow_id=?"
                params.append(workflow_id)
            query += " ORDER BY s.available_at,s.shard_id LIMIT 1"
            shard = self.connection.execute(query, params).fetchone()
            if shard is None:
                return None
            if lease_seconds is None or lease_seconds <= 0:
                lease_seconds = shard["wf_lease_seconds"]
            expires = isoformat(self.clock.now() + timedelta(seconds=lease_seconds))
            if shard["state"] == "leased":
                # 接管过期租约：把上一代未闭合的尝试记为租约过期。
                self.connection.execute(
                    "UPDATE workflow_attempts SET state='lease_expired',finished_at=?,error='租约过期后被其他工作进程接管' "
                    "WHERE shard_id=? AND finished_at IS NULL",
                    (now, shard["shard_id"]),
                )
            self.connection.execute(
                "UPDATE workflow_shards SET state='leased',attempts=attempts+1,lease_generation=lease_generation+1,"
                "lease_owner=?,lease_expires_at=?,last_error=NULL,updated_at=? WHERE shard_id=?",
                (worker_id, expires, now, shard["shard_id"]),
            )
            claimed = self.connection.execute(
                "SELECT * FROM workflow_shards WHERE shard_id=?", (shard["shard_id"],)
            ).fetchone()
            attempt_cursor = self.connection.execute(
                "INSERT INTO workflow_attempts(workflow_id,shard_id,attempt_number,lease_generation,worker_id,"
                "state,started_at) VALUES(?,?,?,?,?, 'leased',?)",
                (
                    claimed["workflow_id"], claimed["shard_id"], claimed["attempts"],
                    claimed["lease_generation"], worker_id, now,
                ),
            )
            workflow = self.connection.execute(
                "SELECT * FROM analysis_workflows WHERE workflow_id=?", (claimed["workflow_id"],)
            ).fetchone()
            dependencies = self.connection.execute(
                "SELECT p.shard_key,p.output_id,o.output_sha256 FROM shard_dependencies d "
                "JOIN workflow_shards p ON p.shard_id=d.depends_on_shard_id "
                "JOIN shard_outputs o ON o.output_id=p.output_id WHERE d.shard_id=?",
                (claimed["shard_id"],),
            ).fetchall()
        ticket = {
            "workflow_id": claimed["workflow_id"],
            "shard_id": claimed["shard_id"],
            "shard_key": claimed["shard_key"],
            "shard_kind": claimed["shard_kind"],
            "generation": claimed["lease_generation"],
            "attempt": claimed["attempts"],
            "lease_owner": worker_id,
            "lease_expires_at": expires,
            "shard_input_sha256": claimed["shard_input_sha256"],
            "algorithm_version": workflow["algorithm_version"],
            "inputs": [
                {"shard_key": row["shard_key"], "output_id": row["output_id"], "output_sha256": row["output_sha256"]}
                for row in dependencies
            ],
        }
        return ticket

    @staticmethod
    def _manifest_observations(protocol: Protocol, manifest_rows: list[dict[str, Any]]) -> tuple[Observation, ...]:
        """从创建时冻结的清单重建测点，保证提交时输入不可漂移。"""

        return tuple(
            Observation(
                source_batch=row["source_batch"],
                source_row=row["source_row"],
                robot_id="",
                protocol_id=protocol.protocol_id,
                protocol_version=protocol.version,
                stratum_key=row["stratum"],
                observed_at="",
                metrics={key: Decimal(str(value)) for key, value in row["metrics"].items()},
                excluded_reason=row["excluded_reason"],
            )
            for row in manifest_rows
        )

    def _compute_shard_output(self, shard: sqlite3.Row, workflow: sqlite3.Row) -> tuple[dict[str, Any], str]:
        """依据冻结清单重新执行分片，并核对输入摘要；返回结果对象与输出校验值。"""

        protocol, protocol_digest = self._protocol_for_workflow(workflow)
        manifest_rows = json.loads(workflow["manifest_json"])
        observations = self._manifest_observations(protocol, manifest_rows)
        if shard["shard_kind"] == LEAF_SHARD_KIND:
            shard_key = shard["shard_key"].split(":", 1)[1]
            stratum_rows = [row for row in manifest_rows if row["stratum"] == shard_key]
            # 再次确认分片输入摘要与创建时冻结值一致。
            recomputed_input = content_digest([
                {"protocol_sha256": protocol_digest, "stratum": shard_key, "rows": stratum_rows}
            ])
            if recomputed_input != shard["shard_input_sha256"]:
                raise ValidationFailed("分片输入摘要与冻结清单不一致，拒绝提交")
            stratum_index = next(
                index for index, item in enumerate(protocol.strata) if item.key == shard_key
            )
            included = tuple(item for item in observations if item.excluded_reason is None)
            result = {
                "algorithm_version": ALGORITHM_VERSION,
                "stratum": stratum_output(protocol, stratum_index, included),
            }
        else:
            leaf_digests: dict[str, str] = {}
            leaves = self.connection.execute(
                "SELECT p.shard_key,p.shard_input_sha256,o.output_json FROM shard_dependencies d "
                "JOIN workflow_shards p ON p.shard_id=d.depends_on_shard_id "
                "JOIN shard_outputs o ON o.output_id=p.output_id WHERE d.shard_id=?",
                (shard["shard_id"],),
            ).fetchall()
            strata = {}
            for row in leaves:
                leaf_key = row["shard_key"].split(":", 1)[1]
                leaf_digests[leaf_key] = row["shard_input_sha256"]
                strata[leaf_key] = json.loads(row["output_json"])["stratum"]
            ordered_keys = [s.key for s in protocol.strata if s.key in leaf_digests]
            # 再次确认聚合分片的输入摘要（其输入是各前置分片的输入摘要集合）。
            recomputed_input = content_digest([
                {
                    "protocol_sha256": protocol_digest,
                    "strata": [{"stratum": key, "input": leaf_digests[key]} for key in ordered_keys],
                }
            ])
            if recomputed_input != shard["shard_input_sha256"]:
                raise ValidationFailed("聚合分片输入摘要与冻结依赖不一致，拒绝提交")
            result = aggregate_output(protocol, strata)
            result["excluded_count"] = sum(
                1 for item in observations if item.excluded_reason is not None
            )
        output_json = canonical_json(result)
        return result, hashlib.sha256(output_json.encode("utf-8")).hexdigest()

    def _protocol_for_workflow(self, workflow: sqlite3.Row) -> tuple[Protocol, str]:
        batch = self.get_batch(workflow["batch_id"])
        return self._protocol(batch["protocol_id"], batch["protocol_version"])

    def complete_shard(
        self,
        worker_id: str,
        shard_id: int,
        generation: int,
        statistician_id: str,
        output_sha256: str | None = None,
    ) -> dict[str, Any]:
        """结果入库与下游解锁的原子动作；提交时再次确认代次、输入摘要与算法版本。"""

        self._require(statistician_id, "analysis.run")
        now = self._now()
        with transaction(self.connection, immediate=True):
            shard = self.connection.execute(
                "SELECT * FROM workflow_shards WHERE shard_id=?", (shard_id,)
            ).fetchone()
            if shard is None:
                raise NotFound("分片不存在")
            if shard["state"] != "leased" or shard["lease_owner"] != worker_id:
                raise InvalidState("分片未由当前工作进程持有，拒绝提交")
            if shard["lease_generation"] != generation:
                raise InvalidState("领取代次不匹配：租约已失效或被接管，拒绝迟到提交")
            if shard["lease_expires_at"] <= now:
                raise InvalidState("分片租约已经过期，拒绝迟到提交")
            workflow = self.connection.execute(
                "SELECT * FROM analysis_workflows WHERE workflow_id=?", (shard["workflow_id"],)
            ).fetchone()
            result, computed_digest = self._compute_shard_output(shard, workflow)
            # 再次确认输入摘要与算法版本，杜绝新旧算法输出混用。
            if result.get("algorithm_version") != ALGORITHM_VERSION:
                raise ValidationFailed("结果算法版本与工作图固定版本不一致")
            if workflow["algorithm_version"] != ALGORITHM_VERSION:
                raise ValidationFailed("工作流算法版本与当前执行版本不一致")
            if output_sha256 is not None and output_sha256 != computed_digest:
                raise Conflict("工作进程提交的输出校验值与服务端复算结果不一致")
            self.connection.execute(
                "INSERT INTO shard_outputs(shard_kind,shard_input_sha256,algorithm_version,output_sha256,"
                "output_json,produced_by_workflow,created_at) VALUES(?,?,?,?,?,?,?) "
                "ON CONFLICT(shard_input_sha256,algorithm_version) DO NOTHING",
                (
                    shard["shard_kind"], shard["shard_input_sha256"], ALGORITHM_VERSION,
                    computed_digest, canonical_json(result), workflow["workflow_id"], now,
                ),
            )
            stored = self.connection.execute(
                "SELECT output_id,output_sha256 FROM shard_outputs "
                "WHERE shard_input_sha256=? AND algorithm_version=?",
                (shard["shard_input_sha256"], ALGORITHM_VERSION),
            ).fetchone()
            if stored["output_sha256"] != computed_digest:
                # 同输入同版本却得到不同输出：算法失去确定性，必须人工介入而非污染下游。
                raise Conflict("内容寻址输出与历史结果校验值不一致，疑似算法版本漂移")
            cursor = self.connection.execute(
                "UPDATE workflow_shards SET state='succeeded',output_id=?,completed_attempt=attempts,"
                "lease_owner=NULL,lease_expires_at=NULL,last_error=NULL,updated_at=? "
                "WHERE shard_id=? AND state='leased' AND lease_owner=? AND lease_generation=?",
                (stored["output_id"], now, shard_id, worker_id, generation),
            )
            if cursor.rowcount != 1:
                raise InvalidState("分片状态已变化，拒绝迟到提交")
            self.connection.execute(
                "UPDATE workflow_attempts SET state='succeeded',output_id=?,finished_at=? "
                "WHERE shard_id=? AND attempt_number=? AND lease_generation=? AND finished_at IS NULL",
                (stored["output_id"], now, shard_id, shard["attempts"], generation),
            )
            self._unblock_dependents(shard["workflow_id"], now)
            self._finalize_workflow(shard["workflow_id"], now, statistician_id)
            self._audit(
                "shard", str(shard_id), "shard.succeeded", statistician_id,
                {
                    "workflow_id": shard["workflow_id"], "attempt": shard["attempts"],
                    "shard_input_sha256": shard["shard_input_sha256"],
                    "output_sha256": computed_digest,
                },
            )
        return {"shard_id": shard_id, "state": "succeeded", "output_sha256": computed_digest}

    def fail_shard(
        self,
        worker_id: str,
        shard_id: int,
        generation: int,
        error: str,
        *,
        retryable: bool = True,
        retry_seconds: int | None = None,
    ) -> dict[str, Any]:
        """可重试错误按策略进入下一次尝试，超过限额转人工处理。"""

        now = self._now()
        with transaction(self.connection, immediate=True):
            shard = self.connection.execute(
                "SELECT * FROM workflow_shards WHERE shard_id=?", (shard_id,)
            ).fetchone()
            if shard is None:
                raise NotFound("分片不存在")
            if shard["state"] != "leased" or shard["lease_owner"] != worker_id:
                raise InvalidState("分片未由当前工作进程持有，拒绝失败上报")
            if shard["lease_generation"] != generation:
                raise InvalidState("领取代次不匹配：租约已失效或被接管，拒绝迟到上报")
            workflow = self.connection.execute(
                "SELECT * FROM analysis_workflows WHERE workflow_id=?", (shard["workflow_id"],)
            ).fetchone()
            message = error[:1000]
            if not retryable or shard["attempts"] >= workflow["max_attempts"]:
                new_state = "manual"
                available_at = shard["available_at"]
                attempt_state = "manual"
            else:
                new_state = "failed"
                delay = workflow["retry_backoff_seconds"] if retry_seconds is None else retry_seconds
                available_at = isoformat(self.clock.now() + timedelta(seconds=max(0, delay)))
                attempt_state = "retry"
            self.connection.execute(
                "UPDATE workflow_shards SET state=?,available_at=?,lease_owner=NULL,lease_expires_at=NULL,"
                "last_error=?,updated_at=? WHERE shard_id=? AND state='leased' AND lease_owner=? AND lease_generation=?",
                (new_state, available_at, message, now, shard_id, worker_id, generation),
            )
            self.connection.execute(
                "UPDATE workflow_attempts SET state=?,error=?,finished_at=? "
                "WHERE shard_id=? AND attempt_number=? AND lease_generation=? AND finished_at IS NULL",
                (attempt_state, message, now, shard_id, shard["attempts"], generation),
            )
            self._audit(
                "shard", str(shard_id), f"shard.{attempt_state}", shard["lease_owner"],
                {"workflow_id": shard["workflow_id"], "attempt": shard["attempts"], "error": message},
            )
        return {"shard_id": shard_id, "state": new_state, "attempts": shard["attempts"], "available_at": available_at}

    def resume_manual_shard(self, actor_id: str, shard_id: int) -> dict[str, Any]:
        """人工处理后把分片重新放回队列（例如修复数据或补发新版本后重试）。"""

        self._require(actor_id, "analysis.run")
        now = self._now()
        with transaction(self.connection, immediate=True):
            shard = self.connection.execute(
                "SELECT * FROM workflow_shards WHERE shard_id=?", (shard_id,)
            ).fetchone()
            if shard is None:
                raise NotFound("分片不存在")
            if shard["state"] != "manual":
                raise InvalidState("只有人工处理中的分片可以恢复")
            self.connection.execute(
                "UPDATE workflow_shards SET state='ready',attempts=0,available_at=?,last_error=NULL,updated_at=? "
                "WHERE shard_id=?",
                (now, now, shard_id),
            )
            self._audit("shard", str(shard_id), "shard.resumed", actor_id, {"workflow_id": shard["workflow_id"]})
        return {"shard_id": shard_id, "state": "ready"}

    def cancel_workflow(self, actor_id: str, workflow_id: int) -> dict[str, Any]:
        """取消只阻止新的领取；已完成的分片输出与聚合结果全部保留。"""

        self._require(actor_id, "analysis.run")
        with transaction(self.connection, immediate=True):
            cursor = self.connection.execute(
                "UPDATE analysis_workflows SET state='cancelled' WHERE workflow_id=? AND state='active'",
                (workflow_id,),
            )
            if cursor.rowcount != 1:
                raise InvalidState("工作流不存在、已完成或已取消")
            self._audit("workflow", str(workflow_id), "workflow.cancelled", actor_id, {})
        return self.get_workflow(workflow_id)

    @staticmethod
    def _shard_view(row: sqlite3.Row, now: str) -> dict[str, Any]:
        effective = row["state"]
        if effective == "leased" and row["lease_expires_at"] is not None and row["lease_expires_at"] <= now:
            effective = "expired"
        return {
            "shard_id": row["shard_id"],
            "shard_key": row["shard_key"],
            "shard_kind": row["shard_kind"],
            "layer": row["layer"],
            "state": row["state"],
            "effective_state": effective,
            "depends_on": json.loads(row["depends_on_json"]),
            "attempts": row["attempts"],
            "lease_generation": row["lease_generation"],
            "lease_owner": row["lease_owner"],
            "lease_expires_at": row["lease_expires_at"],
            "available_at": row["available_at"],
            "last_error": row["last_error"],
            "shard_input_sha256": row["shard_input_sha256"],
            "algorithm_version": ALGORITHM_VERSION,
            "output_id": row["output_id"],
            "completed_attempt": row["completed_attempt"],
        }

    def get_workflow(self, workflow_id: int) -> dict[str, Any]:
        """从持久化记录重建工作图：等待/运行/失败/人工处理/完成状态与逐分片血缘。"""

        now = self._now()
        workflow = self.connection.execute(
            "SELECT * FROM analysis_workflows WHERE workflow_id=?", (workflow_id,)
        ).fetchone()
        if workflow is None:
            raise NotFound("工作流不存在")
        shard_rows = self.connection.execute(
            "SELECT * FROM workflow_shards WHERE workflow_id=? ORDER BY layer,shard_id", (workflow_id,)
        ).fetchall()
        output_digests = {
            row["output_id"]: row["output_sha256"]
            for row in self.connection.execute(
                "SELECT output_id,output_sha256 FROM shard_outputs"
            ).fetchall()
        }
        shards = []
        for row in shard_rows:
            view = self._shard_view(row, now)
            view["output_sha256"] = (
                None if row["output_id"] is None else output_digests.get(row["output_id"])
            )
            attempts = self.connection.execute(
                "SELECT attempt_number,lease_generation,worker_id,state,error,started_at,finished_at,output_id "
                "FROM workflow_attempts WHERE shard_id=? ORDER BY attempt_id", (row["shard_id"],)
            ).fetchall()
            view["attempt_history"] = [dict(item) for item in attempts]
            shards.append(view)
        groups = {"waiting": 0, "ready": 0, "running": 0, "failed": 0, "manual": 0, "completed": 0}
        for view in shards:
            effective = view["effective_state"]
            if effective == "succeeded":
                groups["completed"] += 1
            elif effective == "manual":
                groups["manual"] += 1
            elif effective == "failed":
                groups["failed"] += 1
            elif effective == "leased":
                groups["running"] += 1
            elif effective == "ready":
                groups["ready"] += 1
            else:
                groups["waiting"] += 1
        analysis_row = self.connection.execute(
            "SELECT * FROM analyses WHERE workflow_id=?", (workflow_id,)
        ).fetchone()
        provenance = []
        if analysis_row is not None:
            provenance_rows = self.connection.execute(
                "SELECT p.shard_id,s.shard_key,p.shard_input_sha256,p.algorithm_version,p.reused,"
                "p.attempt_id,a.attempt_number,a.worker_id,o.output_sha256 "
                "FROM analysis_shard_provenance p "
                "JOIN workflow_shards s ON s.shard_id=p.shard_id "
                "JOIN shard_outputs o ON o.output_id=p.output_id "
                "LEFT JOIN workflow_attempts a ON a.attempt_id=p.attempt_id "
                "WHERE p.analysis_id=? ORDER BY s.layer,s.shard_id",
                (analysis_row["analysis_id"],),
            ).fetchall()
            provenance = [dict(row) for row in provenance_rows]
        return {
            "workflow_id": workflow["workflow_id"],
            "batch_id": workflow["batch_id"],
            "batch_revision": workflow["batch_revision"],
            "state": workflow["state"],
            "input_sha256": workflow["input_sha256"],
            "protocol_sha256": workflow["protocol_sha256"],
            "algorithm_version": workflow["algorithm_version"],
            "max_attempts": workflow["max_attempts"],
            "lease_seconds": workflow["lease_seconds"],
            "retry_backoff_seconds": workflow["retry_backoff_seconds"],
            "created_at": workflow["created_at"],
            "completed_at": workflow["completed_at"],
            "groups": groups,
            "shards": shards,
            "analysis": None if analysis_row is None else {
                "analysis_id": analysis_row["analysis_id"],
                "input_sha256": analysis_row["input_sha256"],
                "algorithm_version": analysis_row["algorithm_version"],
                "created_by": analysis_row["created_by"],
                "result": json.loads(analysis_row["result_json"]),
                "provenance": provenance,
            },
        }

    def decide(
        self, actor_id: str, batch_id: str, analysis_id: int, decision: str, reason: str
    ) -> dict[str, Any]:
        self._require(actor_id, "decision.write")
        if decision not in {"needs_more_data", "approved", "rejected"}:
            raise ValidationFailed("未知分析准入决定")
        analysis_row = self.connection.execute(
            "SELECT * FROM analyses WHERE analysis_id=? AND batch_id=?", (analysis_id, batch_id)
        ).fetchone()
        if analysis_row is None:
            raise NotFound("分析版本不存在")
        if analysis_row["created_by"] == actor_id:
            raise Forbidden("统计负责人不能批准自己的分析")
        batch = self.get_batch(batch_id)
        if batch["state"] != "analyzed" or batch["revision"] != analysis_row["batch_revision"]:
            raise InvalidState("分析不是批次当前可审批版本")
        try:
            with transaction(self.connection, immediate=True):
                cursor = self.connection.execute(
                    "INSERT INTO decisions(batch_id,analysis_id,decision,reason,decided_by,decided_at) "
                    "VALUES(?,?,?,?,?,?)",
                    (batch_id, analysis_id, decision, reason, actor_id, self._now()),
                )
                self.connection.execute("UPDATE batches SET state='decided' WHERE batch_id=?", (batch_id,))
                self._audit(
                    "batch",
                    batch_id,
                    "decision.recorded",
                    actor_id,
                    {"decision_id": cursor.lastrowid, "analysis_id": analysis_id, "decision": decision},
                )
        except sqlite3.IntegrityError as exc:
            raise Conflict("该分析版本已经形成决定") from exc
        return {"batch_id": batch_id, "analysis_id": analysis_id, "decision": decision}

    def report(self, actor_id: str, batch_id: str) -> dict[str, Any]:
        user = self._user(actor_id)
        if user["role"] not in {"statistician", "approver", "auditor"}:
            raise Forbidden("当前角色不能读取完整报告")
        batch = self.get_batch(batch_id)
        protocol, protocol_digest = self._protocol(batch["protocol_id"], batch["protocol_version"])
        analysis_row = self.connection.execute(
            "SELECT * FROM analyses WHERE batch_id=? ORDER BY analysis_id DESC LIMIT 1", (batch_id,)
        ).fetchone()
        decision_row = None
        provenance_rows: list[sqlite3.Row] = []
        if analysis_row is not None:
            decision_row = self.connection.execute(
                "SELECT * FROM decisions WHERE analysis_id=?", (analysis_row["analysis_id"],)
            ).fetchone()
            provenance_rows = self.connection.execute(
                "SELECT p.shard_id,s.shard_key,p.shard_input_sha256,p.algorithm_version,p.reused,"
                "a.attempt_number,a.worker_id,o.output_sha256 "
                "FROM analysis_shard_provenance p "
                "JOIN workflow_shards s ON s.shard_id=p.shard_id "
                "JOIN shard_outputs o ON o.output_id=p.output_id "
                "LEFT JOIN workflow_attempts a ON a.attempt_id=p.attempt_id "
                "WHERE p.analysis_id=? ORDER BY s.layer,s.shard_id",
                (analysis_row["analysis_id"],),
            ).fetchall()
        workflow_rows = self.connection.execute(
            "SELECT workflow_id,state,input_sha256,algorithm_version,created_at,completed_at "
            "FROM analysis_workflows WHERE batch_id=? ORDER BY workflow_id", (batch_id,)
        ).fetchall()
        exclusions = self.connection.execute(
            "SELECT e.exclusion_id,e.observation_id,e.status,e.reason,e.requested_by,e.reviewed_by "
            "FROM exclusion_requests e JOIN observations o ON o.observation_id=e.observation_id "
            "WHERE o.batch_id=? ORDER BY e.exclusion_id", (batch_id,)
        ).fetchall()
        events = self.connection.execute(
            "SELECT event_type,actor_id,payload_json,created_at FROM audit_events "
            "WHERE entity_type='batch' AND entity_id=? "
            "ORDER BY event_id", (batch_id,)
        ).fetchall()
        return {
            "batch": batch,
            "protocol": {
                "protocol_id": protocol.protocol_id,
                "version": protocol.version,
                "sha256": protocol_digest,
                "seed": protocol.seed,
                "bootstrap_samples": protocol.bootstrap_samples,
            },
            "analysis": None if analysis_row is None else {
                "analysis_id": analysis_row["analysis_id"],
                "workflow_id": analysis_row["workflow_id"],
                "input_sha256": analysis_row["input_sha256"],
                "algorithm_version": analysis_row["algorithm_version"],
                "created_by": analysis_row["created_by"],
                "result": json.loads(analysis_row["result_json"]),
                "provenance": [dict(row) for row in provenance_rows],
            },
            "workflows": [dict(row) for row in workflow_rows],
            "decision": None if decision_row is None else dict(decision_row),
            "exclusions": [dict(row) for row in exclusions],
            "events": [dict(row) | {"payload": json.loads(row["payload_json"])} for row in events],
        }
