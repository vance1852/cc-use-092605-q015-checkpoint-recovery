from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from turbine_health.api import JsonApplication
from turbine_health.clock import FrozenClock
from turbine_health.errors import Conflict, Forbidden, InvalidState, NotFound, ValidationFailed
from turbine_health.jsonio import content_digest
from turbine_health.service import TrialService
from turbine_health.storage import connect
from turbine_health.workgraph import WorkGraphService


UNIT_001_INPUT = {"dataset": "telemetry/unit-001.jsonl", "sha256": "a" * 64}
UNIT_002_INPUT = {"dataset": "telemetry/unit-002.jsonl", "sha256": "b" * 64}


def demo_shards() -> list[dict[str, object]]:
    return [
        {"shard_key": "unit-001", "input": dict(UNIT_001_INPUT)},
        {"shard_key": "unit-002", "input": dict(UNIT_002_INPUT)},
        {
            "shard_key": "power-curve",
            "input": {"statistics": "power-curve"},
            "depends_on": ["unit-001", "unit-002"],
        },
    ]


class WorkGraphTests(unittest.TestCase):
    def setUp(self) -> None:
        self.connection = sqlite3.connect(":memory:", isolation_level=None)
        self.connection.row_factory = sqlite3.Row
        self.clock = FrozenClock(datetime(2026, 9, 26, 8, 0, tzinfo=timezone.utc))
        self.service = TrialService(self.connection, self.clock)
        for user_id, role in (("stat", "statistician"), ("op", "operator"), ("auditor", "auditor")):
            self.service.create_user(user_id, user_id, role)
        self.graph = WorkGraphService(self.connection, self.clock)

    def tearDown(self) -> None:
        self.connection.close()

    def _create(self, task_id: str = "task-1", policy=None, version: str = "telemetry-verify/2"):
        return self.graph.create_task(
            "stat", task_id, "131 台机组遥测校核", version, demo_shards(), policy
        )

    def _claim_and_complete(self, worker: str = "w1", task_id: str = "task-1", output=None):
        claim = self.graph.claim_shard(worker, 60, task_id=task_id)
        self.assertIsNotNone(claim)
        self.graph.complete_shard(
            worker,
            claim["task_id"],
            claim["shard_key"],
            claim["attempt"],
            claim["algorithm_version"],
            claim["expected_input_sha256"],
            output if output is not None else {"verified": True},
        )
        return claim

    def _shard_view(self, task_id: str, shard_key: str) -> dict[str, object]:
        status = self.graph.task_status("auditor", task_id)
        return {shard["shard_key"]: shard for shard in status["shards"]}[shard_key]

    def test_create_pins_manifest_and_gates_downstream(self) -> None:
        created = self._create()
        self.assertEqual(created["algorithm_version"], "telemetry-verify/2")
        self.assertEqual(len(created["manifest_sha256"]), 64)
        self.assertEqual(created["summary"]["waiting"], 3)
        downstream = self._shard_view("task-1", "power-curve")
        self.assertEqual(downstream["state"], "waiting")
        self.assertEqual(downstream["detail"], "waiting_dependencies")
        self.assertFalse(downstream["dependencies_complete"])
        claim = self.graph.claim_shard("w1", 60, task_id="task-1")
        self.assertEqual(claim["shard_key"], "unit-001")
        self.assertEqual(claim["algorithm_version"], "telemetry-verify/2")
        self.assertEqual(claim["expected_input_sha256"], content_digest([UNIT_001_INPUT]))
        self.assertEqual(claim["attempt"], 1)

    def test_create_rejects_invalid_graph(self) -> None:
        with self.assertRaises(ValidationFailed):
            self.graph.create_task(
                "stat", "dup", "重复分片", "v1",
                [{"shard_key": "a", "input": {}}, {"shard_key": "a", "input": {}}],
            )
        with self.assertRaises(ValidationFailed):
            self.graph.create_task(
                "stat", "missing-dep", "未知依赖", "v1",
                [{"shard_key": "a", "input": {}, "depends_on": ["ghost"]}],
            )
        with self.assertRaises(ValidationFailed):
            self.graph.create_task(
                "stat", "cyclic", "环形依赖", "v1",
                [
                    {"shard_key": "a", "input": {}, "depends_on": ["b"]},
                    {"shard_key": "b", "input": {}, "depends_on": ["a"]},
                ],
            )
        with self.assertRaises(ValidationFailed):
            self.graph.create_task(
                "stat", "bad-policy", "错误策略", "v1", [{"shard_key": "a", "input": {}}],
                {"max_attempts": 0},
            )
        with self.assertRaises(Forbidden):
            self.graph.create_task("op", "forbidden", "越权", "v1", [{"shard_key": "a", "input": {}}])
        self._create()
        with self.assertRaises(Conflict):
            self._create()

    def test_commit_unlocks_downstream_atomically_with_provenance(self) -> None:
        self._create()
        first = self._claim_and_complete("w1")
        second = self._claim_and_complete("w2")
        self.assertEqual({first["shard_key"], second["shard_key"]}, {"unit-001", "unit-002"})
        downstream = self.graph.claim_shard("w3", 60, task_id="task-1")
        self.assertEqual(downstream["shard_key"], "power-curve")
        self.assertEqual(len(downstream["upstream"]), 2)
        wrong_digest = content_digest([{"descriptor_sha256": "0" * 64, "upstream": {}}])
        with self.assertRaises(Conflict):
            self.graph.complete_shard(
                "w3", "task-1", "power-curve", downstream["attempt"],
                downstream["algorithm_version"], wrong_digest, {"mean_power": "1.5"},
            )
        self.graph.complete_shard(
            "w3", "task-1", "power-curve", downstream["attempt"],
            downstream["algorithm_version"], downstream["expected_input_sha256"],
            {"mean_power": "1.5"},
        )
        status = self.graph.task_status("auditor", "task-1")
        self.assertEqual(status["summary"]["complete"], 3)
        provenance = self._shard_view("task-1", "power-curve")["output"]
        self.assertEqual(provenance["attempt_no"], 1)
        self.assertEqual(provenance["worker_id"], "w3")
        self.assertEqual(provenance["algorithm_version"], "telemetry-verify/2")
        self.assertEqual(provenance["input_sha256"], downstream["expected_input_sha256"])
        self.assertEqual(len(provenance["output_sha256"]), 64)

    def test_commit_rechecks_algorithm_version_and_input_digest(self) -> None:
        self._create()
        claim = self.graph.claim_shard("w1", 60, task_id="task-1")
        with self.assertRaises(Conflict):
            self.graph.complete_shard(
                "w1", "task-1", claim["shard_key"], claim["attempt"],
                "telemetry-verify/1", claim["expected_input_sha256"], {"verified": True},
            )
        with self.assertRaises(Conflict):
            self.graph.complete_shard(
                "w1", "task-1", claim["shard_key"], claim["attempt"],
                claim["algorithm_version"], "0" * 64, {"verified": True},
            )
        shard = self._shard_view("task-1", claim["shard_key"])
        self.assertEqual(shard["state"], "running")
        self.assertEqual(shard["lease_owner"], "w1")
        self.graph.complete_shard(
            "w1", "task-1", claim["shard_key"], claim["attempt"],
            claim["algorithm_version"], claim["expected_input_sha256"], {"verified": True},
        )

    def test_late_commit_after_lease_expiry_does_not_touch_successor(self) -> None:
        self._create()
        first = self.graph.claim_shard("w1", 10, task_id="task-1")
        self.clock.advance(seconds=11)
        second = self.graph.claim_shard("w2", 10, task_id="task-1")
        self.assertEqual(second["shard_key"], first["shard_key"])
        self.assertGreater(second["attempt"], first["attempt"])
        with self.assertRaises(Conflict):
            self.graph.complete_shard(
                "w1", "task-1", first["shard_key"], first["attempt"],
                first["algorithm_version"], first["expected_input_sha256"], {"verified": "late"},
            )
        with self.assertRaises(InvalidState):
            self.graph.fail_shard("w1", "task-1", first["shard_key"], first["attempt"], "过时上报")
        shard = self._shard_view("task-1", first["shard_key"])
        self.assertEqual(shard["state"], "running")
        self.assertEqual(shard["lease_owner"], "w2")
        self.graph.complete_shard(
            "w2", "task-1", second["shard_key"], second["attempt"],
            second["algorithm_version"], second["expected_input_sha256"], {"verified": "current"},
        )
        done = self._shard_view("task-1", first["shard_key"])
        self.assertEqual(done["state"], "complete")
        self.assertEqual(done["output"]["attempt_no"], second["attempt"])
        self.assertEqual(done["output"]["worker_id"], "w2")

    def test_expired_lease_commit_rejected_even_without_successor(self) -> None:
        self._create()
        claim = self.graph.claim_shard("w1", 10, task_id="task-1")
        self.clock.advance(seconds=11)
        with self.assertRaises(InvalidState):
            self.graph.complete_shard(
                "w1", "task-1", claim["shard_key"], claim["attempt"],
                claim["algorithm_version"], claim["expected_input_sha256"], {"verified": True},
            )
        shard = self._shard_view("task-1", claim["shard_key"])
        self.assertEqual(shard["state"], "waiting")
        self.assertEqual(shard["detail"], "lease_expired")

    def test_retry_policy_then_manual_then_requeue(self) -> None:
        self.graph.create_task(
            "stat", "retry-task", "重试策略", "telemetry-verify/2",
            [{"shard_key": "unit-001", "input": dict(UNIT_001_INPUT)}],
            {"max_attempts": 2, "retry_delay_seconds": 5},
        )
        first = self.graph.claim_shard("w1", 60, task_id="retry-task")
        failed = self.graph.fail_shard("w1", "retry-task", "unit-001", first["attempt"], "临时计算失败")
        self.assertEqual(failed["state"], "failed")
        self.assertIsNone(self.graph.claim_shard("w2", 60, task_id="retry-task"))
        self.clock.advance(seconds=5)
        second = self.graph.claim_shard("w2", 60, task_id="retry-task")
        self.assertEqual(second["shard_key"], "unit-001")
        self.assertEqual(second["attempt"], 2)
        exhausted = self.graph.fail_shard("w2", "retry-task", "unit-001", second["attempt"], "再次失败")
        self.assertEqual(exhausted["state"], "manual")
        self.assertIsNone(self.graph.claim_shard("w3", 60, task_id="retry-task"))
        shard = self._shard_view("retry-task", "unit-001")
        self.assertEqual(shard["state"], "manual")
        self.assertEqual(shard["last_error"], "再次失败")
        status = self.graph.task_status("auditor", "retry-task")
        self.assertEqual(status["summary"]["manual"], 1)
        with self.assertRaises(Forbidden):
            self.graph.requeue_shard("op", "retry-task", "unit-001")
        self.graph.requeue_shard("stat", "retry-task", "unit-001")
        shard = self._shard_view("retry-task", "unit-001")
        self.assertEqual(shard["state"], "waiting")
        third = self.graph.claim_shard("w3", 60, task_id="retry-task")
        self.assertEqual(third["shard_key"], "unit-001")
        self.assertEqual(third["attempt"], 3)
        self.graph.complete_shard(
            "w3", "retry-task", "unit-001", third["attempt"],
            third["algorithm_version"], third["expected_input_sha256"], {"verified": True},
        )
        attempts = self.connection.execute(
            "SELECT outcome FROM shard_attempts WHERE task_id='retry-task' AND shard_key='unit-001' "
            "ORDER BY attempt_no"
        ).fetchall()
        self.assertEqual([row[0] for row in attempts], ["failed_retryable", "failed_final", "succeeded"])

    def test_non_retryable_error_goes_straight_to_manual(self) -> None:
        self._create(policy={"max_attempts": 5, "retry_delay_seconds": 5})
        claim = self.graph.claim_shard("w1", 60, task_id="task-1")
        result = self.graph.fail_shard(
            "w1", "task-1", claim["shard_key"], claim["attempt"], "输入数据损坏", retryable=False
        )
        self.assertEqual(result["state"], "manual")

    def test_cancel_blocks_new_claims_but_keeps_results(self) -> None:
        self._create()
        self._claim_and_complete("w1")
        in_flight = self.graph.claim_shard("w2", 60, task_id="task-1")
        cancelled = self.graph.cancel_task("stat", "task-1")
        self.assertEqual(cancelled["state"], "cancelled")
        self.assertIsNotNone(cancelled["cancelled_at"])
        self.assertIsNone(self.graph.claim_shard("w3", 60, task_id="task-1"))
        self.graph.complete_shard(
            "w2", "task-1", in_flight["shard_key"], in_flight["attempt"],
            in_flight["algorithm_version"], in_flight["expected_input_sha256"], {"verified": True},
        )
        status = self.graph.task_status("auditor", "task-1")
        self.assertEqual(status["summary"]["complete"], 2)
        finished = self._shard_view("task-1", "unit-001")
        self.assertEqual(finished["output"]["worker_id"], "w1")
        with self.assertRaises(InvalidState):
            self.graph.cancel_task("stat", "task-1")

    def test_complete_replay_is_idempotent(self) -> None:
        self._create()
        claim = self.graph.claim_shard("w1", 60, task_id="task-1")
        first = self.graph.complete_shard(
            "w1", "task-1", claim["shard_key"], claim["attempt"],
            claim["algorithm_version"], claim["expected_input_sha256"], {"verified": True},
        )
        replay = self.graph.complete_shard(
            "w1", "task-1", claim["shard_key"], claim["attempt"],
            claim["algorithm_version"], claim["expected_input_sha256"], {"verified": True},
        )
        self.assertFalse(first["replay"])
        self.assertTrue(replay["replay"])
        self.assertEqual(first["output_sha256"], replay["output_sha256"])
        count = self.connection.execute("SELECT count(*) FROM shard_outputs").fetchone()[0]
        self.assertEqual(count, 1)
        with self.assertRaises(Conflict):
            self.graph.complete_shard(
                "w1", "task-1", claim["shard_key"], claim["attempt"],
                claim["algorithm_version"], claim["expected_input_sha256"], {"verified": "changed"},
            )

    def test_read_permissions(self) -> None:
        self._create()
        with self.assertRaises(Forbidden):
            self.graph.task_status("op", "task-1")
        with self.assertRaises(NotFound):
            self.graph.task_status("auditor", "ghost")
        with self.assertRaises(NotFound):
            self.graph.claim_shard("w1", 60, task_id="ghost")


class WorkGraphRecoveryTests(unittest.TestCase):
    """换连接模拟服务重启，验证状态完全从持久化记录重建。"""

    def test_states_and_provenance_survive_restart(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "workgraph.sqlite3"
            clock = FrozenClock(datetime(2026, 9, 26, 8, 0, tzinfo=timezone.utc))
            connection = connect(database)
            service = TrialService(connection, clock)
            service.create_user("stat", "stat", "statistician")
            service.create_user("auditor", "auditor", "auditor")
            graph = WorkGraphService(connection, clock)
            graph.create_task(
                "stat", "fleet", "131 台机组遥测校核", "telemetry-verify/2",
                [
                    {"shard_key": "done", "input": {"dataset": "done.jsonl"}},
                    {"shard_key": "busy", "input": {"dataset": "busy.jsonl"}},
                    {"shard_key": "flaky", "input": {"dataset": "flaky.jsonl"}},
                    {"shard_key": "stuck", "input": {"dataset": "stuck.jsonl"}},
                    {"shard_key": "blocked", "input": {"kind": "aggregate"}, "depends_on": ["busy"]},
                ],
                {"max_attempts": 2, "retry_delay_seconds": 100},
            )
            claims: dict[str, dict[str, object]] = {}
            for worker in ("w1", "w2", "w3", "w4"):
                claim = graph.claim_shard(worker, 600, task_id="fleet")
                claims[claim["shard_key"]] = {"worker": worker, **claim}
            # 领取顺序按分片键确定：busy、done、flaky、stuck；blocked 依赖 busy 不可领取
            self.assertEqual(set(claims), {"busy", "done", "flaky", "stuck"})
            done = claims["done"]
            graph.complete_shard(
                done["worker"], "fleet", "done", done["attempt"], done["algorithm_version"],
                done["expected_input_sha256"], {"verified": True},
            )
            expected_done_input = done["expected_input_sha256"]
            stuck = claims["stuck"]
            graph.fail_shard(stuck["worker"], "fleet", "stuck", stuck["attempt"], "第一次失败")
            clock.advance(seconds=100)
            # 此时只有 stuck 退避到期，flaky 仍被 w3 持有
            stuck_retry = graph.claim_shard("w4", 600, task_id="fleet")
            self.assertEqual(stuck_retry["shard_key"], "stuck")
            graph.fail_shard("w4", "fleet", "stuck", stuck_retry["attempt"], "第二次失败")
            flaky = claims["flaky"]
            graph.fail_shard(flaky["worker"], "fleet", "flaky", flaky["attempt"], "临时失败")
            connection.close()

            recovered = WorkGraphService(connect(database), clock)
            status = recovered.task_status("auditor", "fleet")
            states = {shard["shard_key"]: shard["state"] for shard in status["shards"]}
            self.assertEqual(
                states,
                {
                    "done": "complete",
                    "busy": "running",
                    "flaky": "failed",
                    "stuck": "manual",
                    "blocked": "waiting",
                },
            )
            self.assertEqual(status["summary"]["complete"], 1)
            self.assertEqual(status["summary"]["running"], 1)
            self.assertEqual(status["summary"]["failed"], 1)
            self.assertEqual(status["summary"]["manual"], 1)
            self.assertEqual(status["summary"]["waiting"], 1)
            shards = {shard["shard_key"]: shard for shard in status["shards"]}
            self.assertEqual(shards["done"]["output"]["input_sha256"], expected_done_input)
            self.assertEqual(shards["done"]["output"]["attempt_no"], 1)
            self.assertEqual(shards["done"]["output"]["worker_id"], "w2")
            self.assertEqual(shards["done"]["output"]["algorithm_version"], "telemetry-verify/2")
            self.assertEqual(shards["blocked"]["detail"], "waiting_dependencies")
            self.assertEqual(shards["flaky"]["last_error"], "临时失败")
            self.assertEqual(shards["stuck"]["attempts"], 2)
            recovered.connection.close()


class WorkGraphApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.connection = sqlite3.connect(":memory:", isolation_level=None)
        self.connection.row_factory = sqlite3.Row
        self.clock = FrozenClock(datetime(2026, 9, 26, 8, 0, tzinfo=timezone.utc))
        service = TrialService(self.connection, self.clock)
        service.create_user("stat", "stat", "statistician")
        service.create_user("auditor", "auditor", "auditor")
        self.app = JsonApplication(service, WorkGraphService(self.connection, self.clock))

    def tearDown(self) -> None:
        self.connection.close()

    def test_full_cycle_over_http(self) -> None:
        created = self.app.handle(
            "POST", "/analysis-tasks", {"x-actor-id": "stat"},
            json.dumps({
                "task_id": "fleet",
                "title": "131 台机组遥测校核",
                "algorithm_version": "telemetry-verify/2",
                "shards": demo_shards(),
                "policy": {"max_attempts": 2, "retry_delay_seconds": 5},
            }).encode(),
        )
        self.assertEqual(created.status, 201)
        claimed = self.app.handle(
            "POST", "/analysis-shards/claim", {},
            json.dumps({"worker_id": "w1", "lease_seconds": 30, "task_id": "fleet"}).encode(),
        )
        self.assertEqual(claimed.status, 200)
        claim = claimed.body["claim"]
        self.assertEqual(claim["shard_key"], "unit-001")
        completed = self.app.handle(
            "POST", f"/analysis-tasks/fleet/shards/{claim['shard_key']}/complete", {},
            json.dumps({
                "worker_id": "w1",
                "generation": claim["attempt"],
                "algorithm_version": claim["algorithm_version"],
                "input_sha256": claim["expected_input_sha256"],
                "output": {"verified": True},
            }).encode(),
        )
        self.assertEqual(completed.status, 200)
        status = self.app.handle("GET", "/analysis-tasks/fleet", {"x-actor-id": "auditor"})
        self.assertEqual(status.status, 200)
        self.assertEqual(status.body["summary"]["complete"], 1)
        self.assertEqual(status.body["summary"]["waiting"], 2)

    def test_error_shape_for_late_commit(self) -> None:
        self.app.handle(
            "POST", "/analysis-tasks", {"x-actor-id": "stat"},
            json.dumps({
                "task_id": "fleet", "title": "t", "algorithm_version": "v1",
                "shards": [{"shard_key": "unit-001", "input": {"dataset": "a"}}],
            }).encode(),
        )
        claimed = self.app.handle(
            "POST", "/analysis-shards/claim", {},
            json.dumps({"worker_id": "w1", "lease_seconds": 30, "task_id": "fleet"}).encode(),
        )
        claim = claimed.body["claim"]
        response = self.app.handle(
            "POST", f"/analysis-tasks/fleet/shards/{claim['shard_key']}/complete", {},
            json.dumps({
                "worker_id": "w2",
                "generation": claim["attempt"],
                "algorithm_version": claim["algorithm_version"],
                "input_sha256": claim["expected_input_sha256"],
                "output": {"verified": True},
            }).encode(),
        )
        self.assertEqual(response.status, 409)
        self.assertEqual(response.body["error"]["code"], "conflict")


if __name__ == "__main__":
    unittest.main()
