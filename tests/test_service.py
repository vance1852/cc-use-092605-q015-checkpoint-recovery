from __future__ import annotations

import json
import sqlite3
import unittest
from datetime import datetime, timezone
from pathlib import Path

from turbine_health.clock import FrozenClock
from turbine_health.errors import Conflict, Forbidden, InvalidState
from turbine_health.jsonio import load_json
from turbine_health.service import TrialService

ROOT = Path(__file__).resolve().parents[1]


class ServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.connection = sqlite3.connect(":memory:", isolation_level=None)
        self.connection.row_factory = sqlite3.Row
        self.clock = FrozenClock(datetime(2026, 9, 24, 8, 0, tzinfo=timezone.utc))
        self.service = TrialService(self.connection, self.clock)
        for user_id, role in (
            ("operator", "operator"),
            ("stat", "statistician"),
            ("approver", "approver"),
            ("auditor", "auditor"),
        ):
            self.service.create_user(user_id, user_id, role)
        self.protocol = load_json(ROOT / "fixtures" / "demo_protocol.json")
        self.rows = [
            json.loads(line)
            for line in (ROOT / "fixtures" / "demo_observations.jsonl").read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        self.service.register_robot("operator", "robot-a", "A 型", "厂商")
        self.service.register_build("operator", "build-a", "robot-a", "1.0", "b" * 64)
        self.service.publish_protocol("stat", self.protocol)
        self.service.create_batch("operator", "batch-a", "demo-delivery-v1", 1, "build-a")
        self.service.start_batch("operator", "batch-a", 1)

    def tearDown(self) -> None:
        self.connection.close()

    def _seal_and_create(self, **policy):
        self.service.import_observations("operator", "batch-a", "key-1", self.rows)
        self.service.seal_batch("stat", "batch-a", 2)
        return self.service.create_analysis_workflow("stat", "batch-a", **policy)

    def _drain(self, workflow_id, worker="worker"):
        completed = []
        while True:
            ticket = self.service.claim_shard(worker, workflow_id, lease_seconds=30)
            if ticket is None:
                break
            self.service.complete_shard(worker, ticket["shard_id"], ticket["generation"], "stat")
            completed.append(ticket)
        return completed

    def test_complete_workflow(self) -> None:
        workflow = self._seal_and_create()
        tickets = self._drain(workflow["workflow_id"])
        kinds = [ticket["shard_kind"] for ticket in tickets]
        # 两个叶子分片先执行，聚合分片在依赖满足后最后执行。
        self.assertEqual(sorted(kinds[:2]), ["stratum", "stratum"])
        self.assertEqual(kinds[2], "aggregate")
        rebuilt = self.service.get_workflow(workflow["workflow_id"])
        self.assertEqual(rebuilt["state"], "completed")
        self.assertEqual(rebuilt["groups"]["completed"], 3)
        analysis = rebuilt["analysis"]
        self.assertEqual(analysis["result"]["conclusion"], "pass")
        # 血缘说明每个输出由哪份输入与哪次尝试产生。
        provenance = {entry["shard_key"]: entry for entry in analysis["provenance"]}
        self.assertEqual(len(provenance), 3)
        aggregate_entry = next(entry for entry in analysis["provenance"] if entry["shard_key"] == "aggregate")
        self.assertEqual(aggregate_entry["attempt_number"], 1)
        self.assertEqual(len(aggregate_entry["shard_input_sha256"]), 64)
        self.service.decide("approver", "batch-a", analysis["analysis_id"], "approved", "满足规则")
        report = self.service.report("auditor", "batch-a")
        self.assertEqual(report["batch"]["state"], "decided")
        self.assertEqual(report["analysis"]["result"]["conclusion"], "pass")
        self.assertEqual(len(report["analysis"]["provenance"]), 3)

    def test_aggregate_is_blocked_until_dependencies_succeed(self) -> None:
        workflow = self._seal_and_create()
        first = self.service.claim_shard("worker", workflow["workflow_id"], lease_seconds=30)
        self.assertEqual(first["shard_kind"], "stratum")
        self.service.complete_shard("worker", first["shard_id"], first["generation"], "stat")
        second = self.service.claim_shard("worker", workflow["workflow_id"], lease_seconds=30)
        self.assertEqual(second["shard_kind"], "stratum")
        # 仍有叶子在运行，聚合分片不可领取。
        self.service.fail_shard("worker", second["shard_id"], second["generation"], "临时失败", retry_seconds=0)
        third = self.service.claim_shard("worker", workflow["workflow_id"], lease_seconds=30)
        self.assertEqual(third["shard_id"], second["shard_id"])
        self.service.complete_shard("worker", third["shard_id"], third["generation"], "stat")
        aggregate = self.service.claim_shard("worker", workflow["workflow_id"], lease_seconds=30)
        self.assertEqual(aggregate["shard_kind"], "aggregate")
        # 聚合分片的领取票据携带前置输出校验值。
        self.assertEqual(len(aggregate["inputs"]), 2)
        self.assertTrue(all(len(item["output_sha256"]) == 64 for item in aggregate["inputs"]))

    def test_failed_shard_returns_to_queue_after_backoff(self) -> None:
        workflow = self._seal_and_create(retry_backoff_seconds=5)
        first = self.service.claim_shard("worker-a", workflow["workflow_id"], lease_seconds=10)
        failed = self.service.fail_shard(
            "worker-a", first["shard_id"], first["generation"], "临时计算失败"
        )
        self.assertEqual(failed["state"], "failed")
        self.assertEqual(failed["attempts"], 1)
        # 占住另一个仍就绪的叶子分片。
        other = self.service.claim_shard("worker-b", workflow["workflow_id"], lease_seconds=10)
        self.assertNotEqual(other["shard_id"], first["shard_id"])
        # 退避窗口内、且无其它就绪分片时不能领取。
        self.assertIsNone(self.service.claim_shard("worker-c", workflow["workflow_id"], lease_seconds=10))
        self.clock.advance(seconds=5)
        retried = self.service.claim_shard("worker-b", workflow["workflow_id"], lease_seconds=10)
        self.assertEqual(retried["shard_id"], first["shard_id"])
        self.assertEqual(retried["attempt"], 2)
        self.assertEqual(retried["generation"], 2)

    def test_exceeding_attempt_limit_goes_manual(self) -> None:
        workflow = self._seal_and_create(max_attempts=2, retry_backoff_seconds=0)
        shard_id = None
        for expected_attempt in (1, 2):
            ticket = self.service.claim_shard("worker", workflow["workflow_id"], lease_seconds=30)
            shard_id = ticket["shard_id"]
            self.assertEqual(ticket["attempt"], expected_attempt)
            outcome = self.service.fail_shard(
                "worker", ticket["shard_id"], ticket["generation"], "持续失败"
            )
        self.assertEqual(outcome["state"], "manual")
        rebuilt = self.service.get_workflow(workflow["workflow_id"])
        self.assertEqual(rebuilt["groups"]["manual"], 1)
        manual = next(shard for shard in rebuilt["shards"] if shard["state"] == "manual")
        self.assertEqual(manual["attempts"], 2)
        # 占住另一个就绪叶子后，人工处理分片不会被领取。
        other = self.service.claim_shard("worker", workflow["workflow_id"], lease_seconds=30)
        self.assertNotEqual(other["shard_id"], shard_id)
        self.assertIsNone(self.service.claim_shard("worker", workflow["workflow_id"], lease_seconds=30))
        # 人工恢复后重新计数并可再次领取。
        self.service.resume_manual_shard("stat", shard_id)
        again = self.service.claim_shard("worker", workflow["workflow_id"], lease_seconds=30)
        self.assertEqual(again["shard_id"], shard_id)
        self.assertEqual(again["attempt"], 1)

    def test_non_retryable_failure_goes_manual_immediately(self) -> None:
        workflow = self._seal_and_create()
        ticket = self.service.claim_shard("worker", workflow["workflow_id"], lease_seconds=30)
        outcome = self.service.fail_shard(
            "worker", ticket["shard_id"], ticket["generation"], "数据损坏", retryable=False
        )
        self.assertEqual(outcome["state"], "manual")

    def test_lease_can_be_reclaimed_after_expiry(self) -> None:
        workflow = self._seal_and_create()
        first = self.service.claim_shard("worker-a", workflow["workflow_id"], lease_seconds=10)
        self.clock.advance(seconds=11)
        second = self.service.claim_shard("worker-b", workflow["workflow_id"], lease_seconds=10)
        self.assertEqual(first["shard_id"], second["shard_id"])
        self.assertEqual(second["generation"], first["generation"] + 1)
        # 旧持有者用旧代次迟到提交，必须被拒绝。
        with self.assertRaises(InvalidState):
            self.service.complete_shard("worker-a", first["shard_id"], first["generation"], "stat")
        rebuilt = self.service.get_workflow(workflow["workflow_id"])
        shard = next(item for item in rebuilt["shards"] if item["shard_id"] == first["shard_id"])
        self.assertEqual(shard["effective_state"], "leased")
        self.assertEqual(
            [entry["state"] for entry in shard["attempt_history"]], ["lease_expired", "leased"]
        )
        # 接管者用新代次正常提交。
        self.service.complete_shard("worker-b", second["shard_id"], second["generation"], "stat")

    def test_late_submit_after_expiry_without_takeover_is_rejected(self) -> None:
        workflow = self._seal_and_create()
        ticket = self.service.claim_shard("worker-a", workflow["workflow_id"], lease_seconds=10)
        self.clock.advance(seconds=11)
        with self.assertRaises(InvalidState):
            self.service.complete_shard("worker-a", ticket["shard_id"], ticket["generation"], "stat")

    def test_cancel_only_blocks_new_claims_and_keeps_outputs(self) -> None:
        workflow = self._seal_and_create()
        first = self.service.claim_shard("worker", workflow["workflow_id"], lease_seconds=30)
        self.service.complete_shard("worker", first["shard_id"], first["generation"], "stat")
        self.service.cancel_workflow("stat", workflow["workflow_id"])
        # 取消后无法领取剩余分片。
        self.assertIsNone(self.service.claim_shard("worker", workflow["workflow_id"], lease_seconds=30))
        rebuilt = self.service.get_workflow(workflow["workflow_id"])
        self.assertEqual(rebuilt["state"], "cancelled")
        # 已完成的分片输出保留。
        self.assertEqual(rebuilt["groups"]["completed"], 1)
        kept = next(
            shard for shard in rebuilt["shards"] if shard["shard_id"] == first["shard_id"]
        )
        self.assertEqual(kept["state"], "succeeded")
        self.assertIsNotNone(kept["output_sha256"])

    def test_stable_output_is_reused_without_reprocessing(self) -> None:
        first_workflow = self._seal_and_create()
        self._drain(first_workflow["workflow_id"], worker="worker-1")
        first_analysis = self.service.get_workflow(first_workflow["workflow_id"])["analysis"]
        # 建立第二个输入清单完全一致的批次。
        self.service.create_batch("operator", "batch-b", "demo-delivery-v1", 1, "build-a")
        self.service.start_batch("operator", "batch-b", 1)
        self.service.import_observations("operator", "batch-b", "key-b", self.rows)
        self.service.seal_batch("stat", "batch-b", 2)
        # 相同输入摘要 + 相同算法版本：全部命中内容寻址缓存，无需领取即完成。
        second = self.service.create_analysis_workflow("stat", "batch-b")
        self.assertEqual(second["input_sha256"], first_workflow["input_sha256"])
        self.assertEqual(second["state"], "completed")
        self.assertEqual(second["groups"]["completed"], 3)
        self.assertIsNone(self.service.claim_shard("worker-2", second["workflow_id"], lease_seconds=30))
        provenance = second["analysis"]["provenance"]
        self.assertTrue(all(entry["reused"] == 1 for entry in provenance))
        self.assertTrue(all(entry["attempt_id"] is None for entry in provenance))
        # 两个工作流的聚合结果一致。
        self.assertEqual(first_analysis["result"], second["analysis"]["result"])

    def test_state_rebuilds_after_restart(self) -> None:
        import pathlib
        import tempfile
        from turbine_health.storage import connect as connect_db

        workflow = self._seal_and_create()
        ticket = self.service.claim_shard("worker", workflow["workflow_id"], lease_seconds=30)
        self.service.complete_shard("worker", ticket["shard_id"], ticket["generation"], "stat")
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "restart.sqlite3"
            backup = connect_db(path)
            self.connection.backup(backup)
            backup.close()
            # 全新连接与服务实例：状态只能从持久化记录重建。
            restarted_conn = connect_db(path)
            try:
                restarted = TrialService(restarted_conn, self.clock)
                rebuilt = restarted.get_workflow(workflow["workflow_id"])
                self.assertEqual(rebuilt["groups"]["completed"], 1)
                self.assertTrue(
                    any(shard["state"] == "ready" for shard in rebuilt["shards"])
                )
                # 恢复后工作进程继续领取并完成剩余分片。
                tickets = []
                while True:
                    claimed = restarted.claim_shard("worker", workflow["workflow_id"], lease_seconds=30)
                    if claimed is None:
                        break
                    restarted.complete_shard("worker", claimed["shard_id"], claimed["generation"], "stat")
                    tickets.append(claimed)
                self.assertEqual(len(tickets), 2)
                final = restarted.get_workflow(workflow["workflow_id"])
                self.assertEqual(final["state"], "completed")
                self.assertEqual(final["groups"]["completed"], 3)
            finally:
                restarted_conn.close()

    def test_input_manifest_and_algorithm_version_are_fixed(self) -> None:
        workflow = self._seal_and_create()
        rebuilt = self.service.get_workflow(workflow["workflow_id"])
        self.assertEqual(len(rebuilt["input_sha256"]), 64)
        self.assertEqual(rebuilt["algorithm_version"], "robot-trials-analysis/1")
        for shard in rebuilt["shards"]:
            self.assertEqual(len(shard["shard_input_sha256"]), 64)

    def test_cancel_keeps_inflight_output_but_never_assembles_analysis(self) -> None:
        workflow = self._seal_and_create()
        first = self.service.claim_shard("worker", workflow["workflow_id"], lease_seconds=30)
        self.service.complete_shard("worker", first["shard_id"], first["generation"], "stat")
        second = self.service.claim_shard("worker", workflow["workflow_id"], lease_seconds=30)
        self.service.complete_shard("worker", second["shard_id"], second["generation"], "stat")
        aggregate = self.service.claim_shard("worker", workflow["workflow_id"], lease_seconds=30)
        self.assertEqual(aggregate["shard_kind"], "aggregate")
        # 聚合分片在途时取消。
        self.service.cancel_workflow("stat", workflow["workflow_id"])
        # 在途提交仍被接受并保留分片输出，但不会装配最终分析或推进批次。
        outcome = self.service.complete_shard(
            "worker", aggregate["shard_id"], aggregate["generation"], "stat"
        )
        self.assertEqual(outcome["state"], "succeeded")
        rebuilt = self.service.get_workflow(workflow["workflow_id"])
        self.assertEqual(rebuilt["state"], "cancelled")
        self.assertIsNone(rebuilt["analysis"])
        self.assertEqual(self.service.get_batch("batch-a")["state"], "sealed")
        self.assertEqual(rebuilt["groups"]["completed"], 3)

    def test_duplicate_workflow_with_same_manifest_conflicts(self) -> None:
        self._seal_and_create()
        with self.assertRaises(Conflict):
            self.service.create_analysis_workflow("stat", "batch-a")

    def test_idempotent_replay_and_conflict(self) -> None:
        first = self.service.import_observations("operator", "batch-a", "key-1", self.rows)
        second = self.service.import_observations("operator", "batch-a", "key-1", self.rows)
        self.assertEqual(first, second)
        changed = [dict(item) for item in self.rows]
        changed[0] = dict(changed[0])
        changed[0]["metrics"] = dict(changed[0]["metrics"])
        changed[0]["metrics"]["completion_seconds"] = "99"
        with self.assertRaises(Conflict):
            self.service.import_observations("operator", "batch-a", "key-1", changed)
        count = self.connection.execute("SELECT count(*) FROM observations").fetchone()[0]
        self.assertEqual(count, 6)

    def test_import_rolls_back_when_one_source_row_duplicates(self) -> None:
        self.service.import_observations("operator", "batch-a", "key-1", self.rows[:1])
        with self.assertRaises(Conflict):
            self.service.import_observations("operator", "batch-a", "key-2", self.rows[:2])
        count = self.connection.execute("SELECT count(*) FROM observations").fetchone()[0]
        self.assertEqual(count, 1)

    def test_role_separation(self) -> None:
        with self.assertRaises(Forbidden):
            self.service.seal_batch("operator", "batch-a", 2)
        with self.assertRaises(Forbidden):
            self.service.report("operator", "batch-a")

    def test_exclusion_review_and_revoke_leave_history(self) -> None:
        self.service.import_observations("operator", "batch-a", "key-1", self.rows)
        observation_id = self.connection.execute(
            "SELECT observation_id FROM observations ORDER BY observation_id LIMIT 1"
        ).fetchone()[0]
        requested = self.service.request_exclusion("operator", observation_id, "现场记录失效")
        reviewed = self.service.review_exclusion("stat", requested["exclusion_id"], True, "证据充分")
        self.assertEqual(reviewed["status"], "approved")
        revoked = self.service.revoke_exclusion("operator", requested["exclusion_id"], "已找回原始记录")
        self.assertEqual(revoked["status"], "revoked")
        events = self.connection.execute(
            "SELECT event_type FROM audit_events WHERE entity_type='observation' AND entity_id=? ORDER BY event_id",
            (str(observation_id),),
        ).fetchall()
        self.assertEqual([row[0] for row in events], ["exclusion.requested", "exclusion.revoked"])


if __name__ == "__main__":
    unittest.main()
