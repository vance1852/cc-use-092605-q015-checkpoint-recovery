"""完整产品流程的离线验收入口。"""

from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path

from .jsonio import load_json
from .service import TrialService
from .storage import connect, inspect_schema
from .workgraph import WorkGraphService


def _run_workgraph_recovery(database: Path) -> dict[str, object]:
    """创建分片工作图，部分完成后模拟服务重启，验证状态从持久化记录恢复。"""

    connection = connect(database)
    try:
        graph = WorkGraphService(connection)
        graph.create_task(
            "stat-1",
            "fleet-telemetry-check",
            "机组遥测校核与功率曲线统计",
            "telemetry-verify/1",
            [
                {"shard_key": "unit-001", "input": {"dataset": "telemetry/unit-001.jsonl", "sha256": "c" * 64}},
                {"shard_key": "unit-002", "input": {"dataset": "telemetry/unit-002.jsonl", "sha256": "d" * 64}},
                {
                    "shard_key": "power-curve",
                    "input": {"statistics": "power-curve"},
                    "depends_on": ["unit-001", "unit-002"],
                },
            ],
            {"max_attempts": 3, "retry_delay_seconds": 10},
        )
        first = graph.claim_shard("worker-1", lease_seconds=30, task_id="fleet-telemetry-check")
        if first is None:
            raise RuntimeError("未能领取工作图分片")
        graph.complete_shard(
            "worker-1",
            first["task_id"],
            first["shard_key"],
            first["attempt"],
            first["algorithm_version"],
            first["expected_input_sha256"],
            {"verified": True},
        )
    finally:
        connection.close()
    # 服务重启：换一个连接，状态必须只从 SQLite 记录重建
    connection = connect(database)
    try:
        recovered = WorkGraphService(connection)
        rebuilt = recovered.task_status("auditor-1", "fleet-telemetry-check")
        if rebuilt["summary"]["complete"] != 1 or rebuilt["summary"]["waiting"] != 2:
            raise RuntimeError("工作图状态重建与持久化记录不一致")
        while True:
            claim = recovered.claim_shard("worker-2", lease_seconds=30, task_id="fleet-telemetry-check")
            if claim is None:
                break
            recovered.complete_shard(
                "worker-2",
                claim["task_id"],
                claim["shard_key"],
                claim["attempt"],
                claim["algorithm_version"],
                claim["expected_input_sha256"],
                {"verified": True},
            )
        final_status = recovered.task_status("auditor-1", "fleet-telemetry-check")
        if final_status["summary"]["complete"] != final_status["summary"]["total"]:
            raise RuntimeError("恢复后工作图未能全部完成")
        return {
            "task_id": final_status["task_id"],
            "algorithm_version": final_status["algorithm_version"],
            "rebuilt_after_restart": True,
            "completed": final_status["summary"]["complete"],
            "total": final_status["summary"]["total"],
        }
    finally:
        connection.close()


def run(workspace: Path) -> dict[str, object]:
    fixtures = workspace / "fixtures"
    protocol = load_json(fixtures / "demo_protocol.json")
    observation_rows = [
        json.loads(line)
        for line in (fixtures / "demo_observations.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    with tempfile.TemporaryDirectory(prefix="robot-trials-") as temporary:
        database = Path(temporary) / "foundation.sqlite3"
        connection = connect(database)
        try:
            service = TrialService(connection)
            service.create_user("operator-1", "测试操作员", "operator")
            service.create_user("stat-1", "统计负责人", "statistician")
            service.create_user("approver-1", "分析准入审批人", "approver")
            service.create_user("auditor-1", "审计人员", "auditor")
            service.register_robot("operator-1", "robot-a", "A 型人形传感器", "示例厂商")
            service.register_build("operator-1", "build-a1", "robot-a", "1.0.0", "a" * 64)
            service.publish_protocol("stat-1", protocol)
            service.create_batch("operator-1", "batch-demo", protocol["protocol_id"], protocol["version"], "build-a1")
            service.start_batch("operator-1", "batch-demo", 1)
            imported = service.import_observations(
                "operator-1", "batch-demo", "demo-import-1", observation_rows
            )
            service.seal_batch("stat-1", "batch-demo", 2)
            job = service.claim_job("worker-1", lease_seconds=60)
            if job is None:
                raise RuntimeError("未能领取分析任务")
            analysis = service.complete_job("worker-1", job["job_id"], "stat-1")
            decision_value = "approved" if analysis["result"]["conclusion"] == "pass" else "rejected"
            service.decide(
                "approver-1", "batch-demo", analysis["analysis_id"], decision_value, "离线验收决定"
            )
            report = service.report("auditor-1", "batch-demo")
        finally:
            connection.close()
        workgraph = _run_workgraph_recovery(database)
        connection = connect(database)
        try:
            schema = inspect_schema(connection)
        finally:
            connection.close()
    if schema["missing_tables"] or schema["schema_version"] != "3":
        raise RuntimeError("SQLite 基础结构检查失败")
    return {
        "status": "ok",
        "protocol": f"{protocol['protocol_id']}@{protocol['version']}",
        "observation_count": imported["inserted"],
        "analysis_id": analysis["analysis_id"],
        "input_sha256": analysis["input_sha256"],
        "conclusion": analysis["result"]["conclusion"],
        "decision": report["decision"]["decision"],
        "event_count": len(report["events"]),
        "workgraph": workgraph,
        "schema": schema,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="执行校准数据基础工具的离线自检")
    parser.add_argument("--workspace", type=Path, default=Path.cwd())
    args = parser.parse_args(argv)
    result = run(args.workspace.resolve())
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
