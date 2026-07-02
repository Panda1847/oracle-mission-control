"""Strict plugin parse contract validation and repair."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple


@dataclass
class ValidationResult:
    valid: bool
    parsed: Dict[str, Any]
    reason: str = ""
    repaired: bool = False


class PluginResultValidator:
    """Validates and optionally repairs plugin parse outputs before ingestion."""

    MAX_RAW = 12000
    MAX_LIST_ITEMS = 2048
    SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}

    def validate(self, plugin_name: str, parsed: Dict[str, Any], *, target: str = "") -> ValidationResult:
        if not isinstance(parsed, dict):
            return ValidationResult(False, self._error("parsed payload must be an object"), "parsed payload must be an object")
        status = parsed.get("status")
        data = parsed.get("data")
        error = parsed.get("error")
        if status not in {"ok", "error"}:
            return ValidationResult(False, self._error("status must be 'ok' or 'error'"), "invalid status")
        if not isinstance(data, dict):
            return ValidationResult(False, self._error("data must be an object"), "invalid data type")
        if not isinstance(error, str):
            return ValidationResult(False, self._error("error must be a string"), "invalid error type")

        if plugin_name == "nmap":
            valid, reason = self._validate_nmap(data, target=target)
        elif plugin_name == "http":
            valid, reason = self._validate_http(data)
        elif plugin_name == "fuzz":
            valid, reason = self._validate_fuzz(data)
        else:
            valid, reason = self._validate_generic(data)
        if valid:
            valid, reason = self._validate_common_data(data)

        if not valid:
            repaired = self.repair(plugin_name, parsed, target=target)
            if repaired is not None:
                common_ok, common_reason = self._validate_common_data(repaired.get("data", {}))
                if common_ok:
                    return ValidationResult(True, repaired, reason, repaired=True)
                return ValidationResult(False, self._error(common_reason), common_reason)
            return ValidationResult(False, self._error(reason), reason)
        return ValidationResult(True, parsed)

    def repair(self, plugin_name: str, parsed: Dict[str, Any], *, target: str = "") -> Dict[str, Any] | None:
        data = parsed.get("data", {})
        if not isinstance(data, dict):
            return None
        fixed = {"status": parsed.get("status", "ok"), "data": dict(data), "error": str(parsed.get("error", ""))}
        if plugin_name == "nmap":
            ports = fixed["data"].get("ports", [])
            if not isinstance(ports, list):
                return None
            cleaned = []
            for item in ports[: self.MAX_LIST_ITEMS]:
                if not isinstance(item, dict):
                    continue
                port = item.get("port")
                if not isinstance(port, int) or not (1 <= port <= 65535):
                    continue
                protocol = str(item.get("protocol", "tcp")).lower()
                if protocol not in {"tcp", "udp"}:
                    protocol = "tcp"
                cleaned.append(
                    {
                        "port": port,
                        "protocol": protocol,
                        "service": str(item.get("service", ""))[:120],
                        "version": str(item.get("version", ""))[:400],
                        "state": "open" if str(item.get("state", "open")).lower() == "open" else "closed",
                    }
                )
            fixed["data"]["ports"] = cleaned
            fixed["data"]["os_guess"] = str(fixed["data"].get("os_guess", ""))[:200]
            fixed["data"]["raw"] = str(fixed["data"].get("raw", ""))[: self.MAX_RAW]
            return fixed

        if plugin_name == "http":
            headers = fixed["data"].get("headers", {})
            if not isinstance(headers, dict):
                headers = {}
            cleaned_headers = {str(k).lower()[:80]: str(v)[:300] for k, v in headers.items()}
            status_code = fixed["data"].get("status_code", 0)
            try:
                status_code = int(status_code)
            except Exception:
                status_code = 0
            if status_code < 0 or status_code > 999:
                status_code = 0
            fixed["data"] = {
                "status_code": status_code,
                "headers": cleaned_headers,
                "server": str(fixed["data"].get("server", ""))[:200],
                "powered": str(fixed["data"].get("powered", ""))[:200],
            }
            return fixed

        if plugin_name == "fuzz":
            raw_paths = fixed["data"].get("paths", [])
            if not isinstance(raw_paths, list):
                raw_paths = []
            cleaned_paths = []
            for item in raw_paths[: self.MAX_LIST_ITEMS]:
                if not isinstance(item, dict):
                    continue
                path = str(item.get("path", ""))
                if not path.startswith("/"):
                    continue
                status = item.get("status", 0)
                try:
                    status = int(status)
                except Exception:
                    status = 0
                if status < 0 or status > 999:
                    status = 0
                cleaned_paths.append({"path": path[:500], "status": status})
            fixed["data"]["paths"] = cleaned_paths
            fixed["data"]["interesting"] = [p for p in cleaned_paths if p["status"] in {0, 200, 301, 302, 403}]
            fixed["data"]["count"] = len(cleaned_paths)
            return fixed
        return None

    def _validate_nmap(self, data: Dict[str, Any], *, target: str = "") -> Tuple[bool, str]:
        ports = data.get("ports")
        if not isinstance(ports, list):
            return False, "nmap.data.ports must be a list"
        if len(ports) > self.MAX_LIST_ITEMS:
            return False, "nmap ports list exceeds max size"
        for item in ports:
            if not isinstance(item, dict):
                return False, "nmap port entry must be an object"
            port = item.get("port")
            if not isinstance(port, int) or not (1 <= port <= 65535):
                return False, "nmap port must be an int between 1 and 65535"
            protocol = str(item.get("protocol", "tcp")).lower()
            if protocol not in {"tcp", "udp"}:
                return False, "nmap protocol must be tcp or udp"
            if str(item.get("state", "open")).lower() not in {"open", "closed", "filtered"}:
                return False, "nmap state is invalid"
        raw = str(data.get("raw", ""))
        if len(raw) > self.MAX_RAW:
            return False, "nmap raw payload too long"
        os_guess = data.get("os_guess", "")
        if not isinstance(os_guess, str):
            return False, "nmap os_guess must be a string"
        if target:
            self._validate_target_ip(target)
        return True, ""

    def _validate_http(self, data: Dict[str, Any]) -> Tuple[bool, str]:
        status_code = data.get("status_code", 0)
        if not isinstance(status_code, int) or not (0 <= status_code <= 999):
            return False, "http status_code must be int between 0 and 999"
        headers = data.get("headers", {})
        if not isinstance(headers, dict):
            return False, "http headers must be an object"
        for key, value in headers.items():
            if not isinstance(key, str) or not isinstance(value, str):
                return False, "http header keys and values must be strings"
        for key in ("server", "powered"):
            if not isinstance(data.get(key, ""), str):
                return False, f"http {key} must be a string"
        return True, ""

    def _validate_fuzz(self, data: Dict[str, Any]) -> Tuple[bool, str]:
        paths = data.get("paths", [])
        interesting = data.get("interesting", [])
        count = data.get("count", 0)
        if not isinstance(paths, list) or not isinstance(interesting, list):
            return False, "fuzz paths and interesting must be lists"
        if not isinstance(count, int) or count < 0:
            return False, "fuzz count must be a non-negative int"
        for item in paths + interesting:
            if not isinstance(item, dict):
                return False, "fuzz path entry must be an object"
            path = item.get("path", "")
            status = item.get("status", 0)
            if not isinstance(path, str) or not path.startswith("/"):
                return False, "fuzz path must start with '/'"
            if not isinstance(status, int) or status < 0 or status > 999:
                return False, "fuzz status must be int between 0 and 999"
        return True, ""

    def _validate_generic(self, data: Dict[str, Any]) -> Tuple[bool, str]:
        serialized = str(data)
        if len(serialized) > self.MAX_RAW:
            return False, "generic plugin payload too long"
        return True, ""

    def _validate_common_data(self, data: Dict[str, Any]) -> Tuple[bool, str]:
        def check_item(item: Any) -> Tuple[bool, str]:
            if isinstance(item, dict):
                if "port" in item:
                    try:
                        port = int(item.get("port"))
                    except Exception:
                        return False, "port must be int"
                    if port < 1 or port > 65535:
                        return False, "port must be between 1 and 65535"
                if "severity" in item:
                    severity = str(item.get("severity", "")).upper()
                    if severity not in self.SEVERITIES:
                        return False, "severity enum is invalid"
                if "confidence" in item:
                    try:
                        conf = float(item.get("confidence"))
                    except Exception:
                        return False, "confidence must be float"
                    if conf < 0.0 or conf > 1.0:
                        return False, "confidence must be between 0 and 1"
                if "raw" in item and len(str(item.get("raw", ""))) > self.MAX_RAW:
                    return False, "raw payload too long"
                host_value = item.get("host") or item.get("ip") or ""
                if host_value:
                    try:
                        self._validate_target_ip(str(host_value))
                    except Exception:
                        return False, "host/ip field is invalid"
                for value in item.values():
                    ok, reason = check_item(value)
                    if not ok:
                        return ok, reason
            elif isinstance(item, list):
                if len(item) > self.MAX_LIST_ITEMS:
                    return False, "list exceeds max size"
                for value in item:
                    ok, reason = check_item(value)
                    if not ok:
                        return ok, reason
            return True, ""

        return check_item(data)

    def _validate_target_ip(self, target: str):
        if "/" in target:
            return
        try:
            ipaddress.ip_address(target)
        except Exception:
            # hostnames are allowed, but must be reasonable length.
            if len(target) > 255:
                raise ValueError("target host is too long")

    def _error(self, reason: str) -> Dict[str, Any]:
        return {
            "status": "error",
            "data": {},
            "error": f"parse_contract_failed: {reason}",
            "quarantined": True,
        }


GLOBAL_PLUGIN_RESULT_VALIDATOR = PluginResultValidator()
