"""统计分析准入服务的 SQLite 模式与事务辅助。"""

from __future__ import annotations

import contextlib
import sqlite3
from collections.abc import Iterator
from pathlib import Path


SCHEMA_VERSION = 3

SCHEMA_SQL = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS schema_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS protocol_catalog (
    protocol_id TEXT NOT NULL,
    version INTEGER NOT NULL CHECK (version > 0),
    title TEXT NOT NULL,
    task_family TEXT NOT NULL,
    canonical_json TEXT NOT NULL,
    content_sha256 TEXT NOT NULL CHECK (length(content_sha256) = 64),
    created_at TEXT NOT NULL,
    PRIMARY KEY (protocol_id, version),
    UNIQUE (content_sha256)
);

CREATE TABLE IF NOT EXISTS users (
    user_id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('operator', 'statistician', 'approver', 'auditor')),
    active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1))
);

CREATE TABLE IF NOT EXISTS robots (
    robot_id TEXT PRIMARY KEY,
    model_name TEXT NOT NULL,
    vendor TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS builds (
    build_id TEXT PRIMARY KEY,
    robot_id TEXT NOT NULL REFERENCES robots(robot_id),
    version TEXT NOT NULL,
    content_sha256 TEXT NOT NULL CHECK (length(content_sha256) = 64),
    created_at TEXT NOT NULL,
    UNIQUE (robot_id, version),
    UNIQUE (content_sha256)
);

CREATE TABLE IF NOT EXISTS batches (
    batch_id TEXT PRIMARY KEY,
    protocol_id TEXT NOT NULL,
    protocol_version INTEGER NOT NULL,
    build_id TEXT NOT NULL REFERENCES builds(build_id),
    state TEXT NOT NULL CHECK (state IN ('draft', 'running', 'sealed', 'analyzing', 'analyzed', 'decided')),
    revision INTEGER NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_by TEXT NOT NULL REFERENCES users(user_id),
    created_at TEXT NOT NULL,
    started_at TEXT,
    sealed_at TEXT,
    FOREIGN KEY (protocol_id, protocol_version) REFERENCES protocol_catalog(protocol_id, version)
);

CREATE TABLE IF NOT EXISTS observations (
    observation_id INTEGER PRIMARY KEY AUTOINCREMENT,
    batch_id TEXT NOT NULL REFERENCES batches(batch_id),
    source_batch TEXT NOT NULL,
    source_row TEXT NOT NULL,
    robot_id TEXT NOT NULL REFERENCES robots(robot_id),
    stratum_key TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    metrics_json TEXT NOT NULL,
    content_sha256 TEXT NOT NULL CHECK (length(content_sha256) = 64),
    imported_by TEXT NOT NULL REFERENCES users(user_id),
    imported_at TEXT NOT NULL,
    UNIQUE (batch_id, source_batch, source_row)
);

CREATE TABLE IF NOT EXISTS idempotency_keys (
    scope TEXT NOT NULL,
    key TEXT NOT NULL,
    request_sha256 TEXT NOT NULL CHECK (length(request_sha256) = 64),
    response_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (scope, key)
);

CREATE TABLE IF NOT EXISTS exclusion_requests (
    exclusion_id INTEGER PRIMARY KEY AUTOINCREMENT,
    observation_id INTEGER NOT NULL REFERENCES observations(observation_id),
    status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'rejected', 'revoked')),
    reason TEXT NOT NULL,
    requested_by TEXT NOT NULL REFERENCES users(user_id),
    requested_at TEXT NOT NULL,
    reviewed_by TEXT REFERENCES users(user_id),
    reviewed_at TEXT,
    review_note TEXT
);

CREATE UNIQUE INDEX IF NOT EXISTS one_open_exclusion_per_observation
ON exclusion_requests(observation_id)
WHERE status IN ('pending', 'approved');

-- 可恢复的批量分析工作图：创建时固定输入清单与算法版本。
CREATE TABLE IF NOT EXISTS analysis_workflows (
    workflow_id INTEGER PRIMARY KEY AUTOINCREMENT,
    batch_id TEXT NOT NULL REFERENCES batches(batch_id),
    batch_revision INTEGER NOT NULL,
    protocol_sha256 TEXT NOT NULL CHECK (length(protocol_sha256) = 64),
    algorithm_version TEXT NOT NULL,
    manifest_json TEXT NOT NULL,
    input_sha256 TEXT NOT NULL CHECK (length(input_sha256) = 64),
    max_attempts INTEGER NOT NULL CHECK (max_attempts > 0),
    lease_seconds INTEGER NOT NULL CHECK (lease_seconds > 0),
    retry_backoff_seconds INTEGER NOT NULL DEFAULT 0 CHECK (retry_backoff_seconds >= 0),
    state TEXT NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'cancelled', 'completed')),
    created_by TEXT NOT NULL REFERENCES users(user_id),
    created_at TEXT NOT NULL,
    completed_at TEXT,
    UNIQUE (batch_id, batch_revision, input_sha256, algorithm_version)
);

-- 每个分片固定自己的输入摘要、所属层级与前置依赖。
CREATE TABLE IF NOT EXISTS workflow_shards (
    shard_id INTEGER PRIMARY KEY AUTOINCREMENT,
    workflow_id INTEGER NOT NULL REFERENCES analysis_workflows(workflow_id),
    shard_key TEXT NOT NULL,
    layer INTEGER NOT NULL CHECK (layer >= 0),
    shard_kind TEXT NOT NULL,
    shard_input_sha256 TEXT NOT NULL CHECK (length(shard_input_sha256) = 64),
    depends_on_json TEXT NOT NULL,
    state TEXT NOT NULL CHECK (
        state IN ('waiting', 'ready', 'leased', 'succeeded', 'failed', 'manual')
    ),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    available_at TEXT NOT NULL,
    lease_generation INTEGER NOT NULL DEFAULT 0 CHECK (lease_generation >= 0),
    lease_owner TEXT,
    lease_expires_at TEXT,
    last_error TEXT,
    output_id INTEGER REFERENCES shard_outputs(output_id),
    completed_attempt INTEGER,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE (workflow_id, shard_key)
);

-- 内容寻址的分片输出：同输入摘要 + 同算法版本只产生一份校验值。
CREATE TABLE IF NOT EXISTS shard_outputs (
    output_id INTEGER PRIMARY KEY AUTOINCREMENT,
    shard_kind TEXT NOT NULL,
    shard_input_sha256 TEXT NOT NULL CHECK (length(shard_input_sha256) = 64),
    algorithm_version TEXT NOT NULL,
    output_sha256 TEXT NOT NULL CHECK (length(output_sha256) = 64),
    output_json TEXT NOT NULL,
    produced_by_workflow INTEGER REFERENCES analysis_workflows(workflow_id),
    created_at TEXT NOT NULL,
    UNIQUE (shard_input_sha256, algorithm_version)
);

-- 分片依赖边：只有全部前置分片成功，分片才可被领取。
CREATE TABLE IF NOT EXISTS shard_dependencies (
    shard_id INTEGER NOT NULL REFERENCES workflow_shards(shard_id),
    depends_on_shard_id INTEGER NOT NULL REFERENCES workflow_shards(shard_id),
    PRIMARY KEY (shard_id, depends_on_shard_id)
);

-- 每次尝试的流水：等待/运行/失败/人工处理/完成均可据此重建。
CREATE TABLE IF NOT EXISTS workflow_attempts (
    attempt_id INTEGER PRIMARY KEY AUTOINCREMENT,
    workflow_id INTEGER NOT NULL REFERENCES analysis_workflows(workflow_id),
    shard_id INTEGER NOT NULL REFERENCES workflow_shards(shard_id),
    attempt_number INTEGER NOT NULL CHECK (attempt_number > 0),
    lease_generation INTEGER NOT NULL,
    worker_id TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('leased', 'succeeded', 'retry', 'manual', 'lease_expired')),
    error TEXT,
    output_id INTEGER REFERENCES shard_outputs(output_id),
    started_at TEXT NOT NULL,
    finished_at TEXT
);

-- 下游聚合产物与所用分片输出的血缘：每个结果由哪份输入与哪次尝试产生。
CREATE TABLE IF NOT EXISTS analyses (
    analysis_id INTEGER PRIMARY KEY AUTOINCREMENT,
    workflow_id INTEGER NOT NULL REFERENCES analysis_workflows(workflow_id),
    batch_id TEXT NOT NULL REFERENCES batches(batch_id),
    batch_revision INTEGER NOT NULL,
    protocol_sha256 TEXT NOT NULL CHECK (length(protocol_sha256) = 64),
    input_sha256 TEXT NOT NULL CHECK (length(input_sha256) = 64),
    algorithm_version TEXT NOT NULL,
    seed INTEGER NOT NULL,
    result_json TEXT NOT NULL,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE (workflow_id)
);

CREATE TABLE IF NOT EXISTS analysis_shard_provenance (
    analysis_id INTEGER NOT NULL REFERENCES analyses(analysis_id),
    shard_id INTEGER NOT NULL REFERENCES workflow_shards(shard_id),
    output_id INTEGER NOT NULL REFERENCES shard_outputs(output_id),
    attempt_id INTEGER REFERENCES workflow_attempts(attempt_id),
    shard_input_sha256 TEXT NOT NULL,
    algorithm_version TEXT NOT NULL,
    reused INTEGER NOT NULL DEFAULT 0 CHECK (reused IN (0, 1)),
    PRIMARY KEY (analysis_id, shard_id)
);

CREATE TABLE IF NOT EXISTS decisions (
    decision_id INTEGER PRIMARY KEY AUTOINCREMENT,
    batch_id TEXT NOT NULL REFERENCES batches(batch_id),
    analysis_id INTEGER NOT NULL REFERENCES analyses(analysis_id),
    decision TEXT NOT NULL CHECK (decision IN ('needs_more_data', 'approved', 'rejected')),
    reason TEXT NOT NULL,
    decided_by TEXT NOT NULL REFERENCES users(user_id),
    decided_at TEXT NOT NULL,
    UNIQUE (batch_id, analysis_id)
);

CREATE TABLE IF NOT EXISTS audit_events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    entity_type TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

-- 工作进程领取分片的热路径：按工作流过滤、可领取状态与到期时间排序。
CREATE INDEX IF NOT EXISTS idx_shards_claim
ON workflow_shards(workflow_id, state, available_at);

CREATE INDEX IF NOT EXISTS idx_shards_lease_expiry
ON workflow_shards(state, lease_expires_at);

CREATE INDEX IF NOT EXISTS idx_attempts_shard
ON workflow_attempts(shard_id, attempt_number);

CREATE INDEX IF NOT EXISTS idx_provenance_output
ON analysis_shard_provenance(output_id);
"""

REQUIRED_TABLES = frozenset({
    "schema_meta", "protocol_catalog", "users", "robots", "builds", "batches",
    "observations", "idempotency_keys", "exclusion_requests", "analysis_workflows",
    "workflow_shards", "shard_outputs", "shard_dependencies", "workflow_attempts",
    "analyses", "analysis_shard_provenance", "decisions", "audit_events",
})


def connect(path: str | Path) -> sqlite3.Connection:
    """打开连接并启用严格的事务与外键设置。"""

    connection = sqlite3.connect(str(path), isolation_level=None)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 5000")
    return connection


@contextlib.contextmanager
def transaction(connection: sqlite3.Connection, *, immediate: bool = False) -> Iterator[None]:
    """显式事务；异常时保证回滚。"""

    connection.execute("BEGIN IMMEDIATE" if immediate else "BEGIN")
    try:
        yield
    except BaseException:
        connection.rollback()
        raise
    else:
        connection.commit()


def initialize(connection: sqlite3.Connection) -> None:
    """初始化基础资料表，重复执行不改变已有数据。"""

    connection.executescript(SCHEMA_SQL)
    with transaction(connection, immediate=True):
        connection.execute(
            "INSERT INTO schema_meta(key, value) VALUES('schema_version', ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (str(SCHEMA_VERSION),),
        )


def inspect_schema(connection: sqlite3.Connection) -> dict[str, object]:
    """返回适合机器检查的数据库结构摘要。"""

    table_rows = connection.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
    ).fetchall()
    tables = tuple(row["name"] for row in table_rows)
    version_row = connection.execute(
        "SELECT value FROM schema_meta WHERE key='schema_version'"
    ).fetchone()
    missing = sorted(REQUIRED_TABLES - set(tables))
    foreign_keys = connection.execute("PRAGMA foreign_keys").fetchone()[0]
    return {
        "tables": tables,
        "missing_tables": missing,
        "schema_version": None if version_row is None else version_row["value"],
        "foreign_keys": bool(foreign_keys),
    }
