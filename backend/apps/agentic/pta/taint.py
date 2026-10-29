"""M1: Provenance Taint Labelling for Agentic SOC Platform.

Classifies all alert, case, and log fields into three non-overlapping provenance tiers:
  - T0: Kernel-attested / unforgeable system truth (PID, cgroup, syscall, hash, status)
  - T1: Infrastructure-generated telemetry (network peer IP, timestamps, rule IDs)
  - T2: Attacker-controllable text (User-Agent, request bodies, query params, usernames)

Invariant:
  T2 fields must NEVER be included in instruction contexts of tool-wielding agents.
"""

from __future__ import annotations

import enum
from typing import Any


class ProvenanceTag(str, enum.Enum):
    T0_KERNEL = "T0"      # Unforgeable kernel/system attested
    T1_INFRA = "T1"       # Infrastructure-observed/generated
    T2_ATTACKER = "T2"    # Attacker-controllable text / payload


# Field classification rules based on threat modeling
T0_FIELDS = {
    "case_id", "created_at", "updated_at", "status", "severity",
    "pid", "process_id", "process_name", "ppid", "cgroup", "syscall",
    "executable_hash", "sha256", "md5", "uid", "gid", "event_id",
}

T1_FIELDS = {
    "src_ip", "dst_ip", "source_ip", "destination_ip", "peer_ip",
    "src_port", "dst_port", "source_port", "destination_port",
    "rule_id", "rule_name", "alert_count", "source", "category",
    "protocol", "network_interface", "timestamp", "duration",
    "status_code", "http_status", "bytes_in", "bytes_out",
}

T2_FIELDS = {
    "user_agent", "path", "request_uri", "uri", "url", "http_method",
    "body", "http_body", "query_string", "query", "dns_query",
    "username", "user", "command_line", "cmdline", "raw_log",
    "message", "description", "raw_payload", "comment_text",
    "user_input", "headers", "referrer", "cookie",
}


def classify_field(field_name: str) -> ProvenanceTag:
    """Classify a field name into its provenance tier.
    
    Fails closed: any unknown field is treated as T2 (attacker-controllable)
    to prevent security bypasses by naming variations.
    """
    clean_name = field_name.strip().lower()
    if clean_name in T0_FIELDS:
        return ProvenanceTag.T0_KERNEL
    if clean_name in T1_FIELDS:
        return ProvenanceTag.T1_INFRA
    if clean_name in T2_FIELDS:
        return ProvenanceTag.T2_ATTACKER
    
    # Substring heuristic checks for nested keys
    for t0_key in T0_FIELDS:
        if clean_name.endswith(f"_{t0_key}"):
            return ProvenanceTag.T0_KERNEL
    for t1_key in T1_FIELDS:
        if clean_name.endswith(f"_{t1_key}"):
            return ProvenanceTag.T1_INFRA
            
    # Fail-closed default
    return ProvenanceTag.T2_ATTACKER


class TaintLabeller:
    """Partitions and labels structured case and alert data."""

    def __init__(self, t2_budget_bytes: int = 4096):
        self.t2_budget_bytes = t2_budget_bytes

    def label_dict(self, data: dict[str, Any]) -> dict[str, tuple[ProvenanceTag, Any]]:
        """Return a mapping of field_name -> (ProvenanceTag, value)."""
        labeled = {}
        for k, v in data.items():
            tag = classify_field(k)
            labeled[k] = (tag, v)
        return labeled

    def partition(self, data: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
        """Split a dict into (t0_dict, t1_dict, t2_dict)."""
        t0, t1, t2 = {}, {}, {}
        for k, v in data.items():
            tag = classify_field(k)
            if tag == ProvenanceTag.T0_KERNEL:
                t0[k] = v
            elif tag == ProvenanceTag.T1_INFRA:
                t1[k] = v
            else:
                t2[k] = v
        return t0, t1, t2


def partition_case_payload(case_payload: dict[str, Any]) -> dict[str, Any]:
    """Take a serialized case payload and partition into trusted and untrusted views."""
    labeller = TaintLabeller()
    
    trusted_view = {}
    untrusted_t2_fields = {}

    for section, content in case_payload.items():
        if isinstance(content, dict):
            t0, t1, t2 = labeller.partition(content)
            trusted_view[f"{section}_t0"] = t0
            trusted_view[f"{section}_t1"] = t1
            if t2:
                untrusted_t2_fields[section] = t2
        elif isinstance(content, list):
            # E.g. list of alerts or artifacts
            t0_list, t1_list, t2_list = [], [], []
            for item in content:
                if isinstance(item, dict):
                    t0, t1, t2 = labeller.partition(item)
                    t0_list.append(t0)
                    t1_list.append(t1)
                    if t2:
                        t2_list.append(t2)
                else:
                    t2_list.append(item)
            trusted_view[f"{section}_t0"] = t0_list
            trusted_view[f"{section}_t1"] = t1_list
            if t2_list:
                untrusted_t2_fields[section] = t2_list
        else:
            tag = classify_field(section)
            if tag in (ProvenanceTag.T0_KERNEL, ProvenanceTag.T1_INFRA):
                trusted_view[section] = content
            else:
                untrusted_t2_fields[section] = content

    return {
        "trusted_metadata": trusted_view,
        "untrusted_t2": untrusted_t2_fields,
    }


def assert_no_t2(context: Any, context_name: str = "decider") -> None:
    """Hard structural assertion that no T2 string leaked into a trusted context."""
    if isinstance(context, dict):
        for k, v in context.items():
            if classify_field(k) == ProvenanceTag.T2_ATTACKER:
                raise PermissionError(
                    f"PTA M2 Invariant Violation: T2 field '{k}' present in {context_name} context!"
                )
            assert_no_t2(v, context_name=f"{context_name}.{k}")
    elif isinstance(context, list):
        for idx, item in enumerate(context):
            assert_no_t2(item, context_name=f"{context_name}[{idx}]")
