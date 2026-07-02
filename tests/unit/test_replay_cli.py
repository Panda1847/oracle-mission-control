import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from rich.console import Console

from memory.replay import ReplayStore
from oracle.cli.replay import run as run_replay


def _seed_replay(store: ReplayStore, mission: str, *, replay_id: str, phase: str = "EXPLOIT_ANALYSIS"):
    return store.create(
        mission,
        {
            "replay_id": replay_id,
            "mission": mission,
            "phase": phase,
            "branch": "normal",
            "decision_source": "deterministic",
            "ai_backend": "deterministic",
            "action": {"tool": "nmap", "target": "10.0.0.5"},
            "result": {"success": True, "exit_code": 0},
            "ingest_delta": [{"fid": "f1"}],
            "planner_extra": {"phase": phase},
            "graph_snapshot_before": {"hosts": {}, "findings": []},
            "graph_snapshot_after": {"hosts": {"10.0.0.5": {}}, "findings": [{"fid": "f1"}]},
            "state_hash": "state-1",
            "audit_hash": "audit-1",
        },
        branch="normal",
    )


def test_replay_cli_lists_artifacts(tmp_path):
    store = ReplayStore(tmp_path / "replay")
    _seed_replay(store, "mission-a", replay_id="abc123def456")
    console = Console(record=True, width=160)

    rc = run_replay(["--mission", "mission-a", "--list"], data_dir=tmp_path, console=console)

    output = console.export_text()
    assert rc == 0
    assert "ORACLE Replay Artifacts: mission-a" in output
    assert "abc123def456"[:12] in output


def test_replay_cli_renders_latest_summary(tmp_path):
    store = ReplayStore(tmp_path / "replay")
    _seed_replay(store, "mission-b", replay_id="first00000000", phase="DISCOVERY")
    _seed_replay(store, "mission-b", replay_id="second999999", phase="REPORTING")
    console = Console(record=True, width=160)

    rc = run_replay(["--mission", "mission-b"], data_dir=tmp_path, console=console)

    output = console.export_text()
    assert rc == 0
    assert "ORACLE Replay Summary" in output
    assert "second999999" in output
    assert "REPORTING" in output


def test_replay_cli_selects_replay_id_and_json(tmp_path):
    store = ReplayStore(tmp_path / "replay")
    _seed_replay(store, "mission-c", replay_id="target123456")
    _seed_replay(store, "mission-c", replay_id="other6543210")
    console = Console(record=True, width=160)

    rc = run_replay(
        ["--mission", "mission-c", "--replay-id", "target123", "--json"],
        data_dir=tmp_path,
        console=console,
    )

    output = console.export_text()
    payload = json.loads(output)
    assert rc == 0
    assert payload["replay_id"] == "target123456"
    assert payload["mission"] == "mission-c"
