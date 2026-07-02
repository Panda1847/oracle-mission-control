"""Local worker adapter that executes through the current executor/runtime."""

from __future__ import annotations

from typing import Optional


class LocalWorker:
    """Fallback worker living in the master process."""

    def __init__(self, executor, worker_id: str = "local-node"):
        self.executor = executor
        self.worker_id = worker_id
        self.capabilities = ["*"]

    def execute(self, action, command: str):
        if hasattr(self.executor, "execute_command") and hasattr(self.executor, "build_action_result"):
            normalize = getattr(self.executor, "_normalize_command", None)
            if callable(normalize):
                argv, normalize_error = normalize(command)
            else:
                argv, normalize_error = (None, "missing command normalizer")
            if argv is None:
                result = self.executor.build_action_result(
                    action,
                    command,
                    "",
                    normalize_error,
                    -1,
                    0.0,
                    error_kind="unsafe_command",
                )
            else:
                execution = self.executor.execute_command(command, argv, action.timeout)
                result = self.executor.build_action_result(
                    action,
                    command,
                    execution.get("stdout", ""),
                    execution.get("stderr", ""),
                    int(execution.get("returncode", -1)),
                    float(execution.get("duration", 0.0)),
                    timeout_hit=bool(execution.get("timeout_hit", False)),
                    binary_missing=bool(execution.get("binary_missing", False)),
                    error_kind=str(execution.get("error_kind", "")),
                    worker_id=self.worker_id,
                )
        else:
            result = self.executor.run(action)
        result.parsed["_worker_id"] = self.worker_id
        return result
