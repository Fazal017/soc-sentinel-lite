"""Sentinel Graph — temporal entity graph (v2).

Original concept: instead of scoring isolated log lines, Sentinel v2
builds a *temporal entity graph* of the whole environment and reasons
over paths through it.

Nodes are typed entities — ``user``, ``host``, ``ip``, ``service`` —
and every parsed auth event becomes a timestamped edge between them:

    user:deploy --[failed_login @ 02:10, src 203.0.113.77]--> host:web01
    ip:203.0.113.77 --[failed_login @ 02:10]--> host:web01
    user:deploy --[successful_login @ 08:22]--> host:web01
    user:deploy --[successful_login @ 09:05]--> host:db01   (lateral move)

An attack is therefore not a single edge, but a *path* — a walk through
the graph that visits new hosts, new IPs and new privileges over time.
A normal user also walks the graph, but their walk stays inside the
small, well-trodden subgraph they have always used (same IP, same host,
same hours). That contrast — novel path vs. familiar path — is what
``src/baseline.py`` and ``src/chain.py`` score.

The graph is exportable as plain JSON (``graph.json``) with a
GraphML-like shape — ``{"nodes": [...], "edges": [...]}`` — so it can
be opened in Gephi / NetworkX / yEd without any Sentinel code, and so
a reviewer can verify the reconstruction independently.

Stdlib only. No network, no real hosts — sample IPs are RFC 5737 only.
"""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from datetime import datetime


def node_id(kind: str, label: str) -> str:
    return f"{kind}:{label}"


class TemporalGraph:
    """A directed, timestamped multigraph of auth entities."""

    def __init__(self) -> None:
        self.nodes: dict[str, dict] = {}
        self.edges: list[dict] = []

    # -- construction -------------------------------------------------
    def _add_node(self, kind: str, label: str) -> str:
        nid = node_id(kind, label)
        if nid not in self.nodes:
            self.nodes[nid] = {
                "id": nid, "type": kind, "label": label,
                "degree": 0, "first_seen": None, "last_seen": None,
                "event_types": Counter(),
            }
        return nid

    def _touch(self, nid: str, ts: datetime | None, event_type: str) -> None:
        n = self.nodes[nid]
        n["degree"] += 1
        n["event_types"][event_type] += 1
        if ts is not None:
            iso = ts.isoformat()
            if n["first_seen"] is None or iso < n["first_seen"]:
                n["first_seen"] = iso
            if n["last_seen"] is None or iso > n["last_seen"]:
                n["last_seen"] = iso

    def add_event(self, event: dict) -> None:
        """Add one parsed event as edges user->host, ip->host, user->ip."""
        ts = event.get("timestamp")
        etype = event.get("event_type") or "other"
        host = event.get("host")
        user = event.get("user")
        ip = event.get("src_ip")
        service = event.get("service")
        if not host:
            return
        host_id = self._add_node("host", host)
        self._touch(host_id, ts, etype)
        if service:
            svc_id = self._add_node("service", service)
            self._touch(svc_id, ts, etype)
            self.edges.append({
                "source": svc_id, "target": host_id, "type": etype,
                "timestamp": ts.isoformat() if ts else None,
                "user": user, "src_ip": ip,
            })
        if user:
            user_id = self._add_node("user", user)
            self._touch(user_id, ts, etype)
            self.edges.append({
                "source": user_id, "target": host_id, "type": etype,
                "timestamp": ts.isoformat() if ts else None,
                "user": user, "src_ip": ip,
            })
            if ip:
                ip_id = self._add_node("ip", ip)
                self._touch(ip_id, ts, etype)
                self.edges.append({
                    "source": ip_id, "target": host_id, "type": etype,
                    "timestamp": ts.isoformat() if ts else None,
                    "user": user, "src_ip": ip,
                })
                self.edges.append({
                    "source": user_id, "target": ip_id, "type": etype,
                    "timestamp": ts.isoformat() if ts else None,
                    "user": user, "src_ip": ip,
                })
        elif ip:
            ip_id = self._add_node("ip", ip)
            self._touch(ip_id, ts, etype)
            self.edges.append({
                "source": ip_id, "target": host_id, "type": etype,
                "timestamp": ts.isoformat() if ts else None,
                "user": user, "src_ip": ip,
            })

    # -- queries ------------------------------------------------------
    def neighbours(self, nid: str) -> set[str]:
        out = set()
        for e in self.edges:
            if e["source"] == nid:
                out.add(e["target"])
            if e["target"] == nid:
                out.add(e["source"])
        return out

    def hosts_for_user(self, user: str) -> set[str]:
        return {e["target"] for e in self.edges
                if e["source"] == node_id("user", user)
                and e["target"].startswith("host:")}

    def ips_for_user(self, user: str) -> set[str]:
        return {e["target"] for e in self.edges
                if e["source"] == node_id("user", user)
                and e["target"].startswith("ip:")}

    def events_for_user(self, user: str) -> list[dict]:
        return [e for e in self.edges if e.get("user") == user]

    def summary(self) -> dict:
        by_type = Counter(n["type"] for n in self.nodes.values())
        return {
            "nodes": len(self.nodes),
            "edges": len(self.edges),
            "nodes_by_type": dict(by_type),
            "users": sorted(n["label"] for n in self.nodes.values() if n["type"] == "user"),
            "hosts": sorted(n["label"] for n in self.nodes.values() if n["type"] == "host"),
            "ips": sorted(n["label"] for n in self.nodes.values() if n["type"] == "ip"),
        }

    # -- export -------------------------------------------------------
    def to_dict(self) -> dict:
        nodes = []
        for n in self.nodes.values():
            nodes.append({
                "id": n["id"], "type": n["type"], "label": n["label"],
                "degree": n["degree"],
                "first_seen": n["first_seen"], "last_seen": n["last_seen"],
                "event_types": dict(n["event_types"]),
            })
        return {"nodes": nodes, "edges": list(self.edges),
                "summary": self.summary()}

    def save(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(self.to_dict(), fh, indent=2)

    @classmethod
    def load(cls, path: str) -> "TemporalGraph":
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        g = cls()
        for n in data.get("nodes", []):
            g.nodes[n["id"]] = {
                "id": n["id"], "type": n["type"], "label": n["label"],
                "degree": n.get("degree", 0),
                "first_seen": n.get("first_seen"), "last_seen": n.get("last_seen"),
                "event_types": Counter(n.get("event_types", {})),
            }
        g.edges = list(data.get("edges", []))
        return g


def build_graph(events: list[dict]) -> TemporalGraph:
    """Build a temporal entity graph from parsed events (chronological)."""
    g = TemporalGraph()
    for e in sorted(events, key=lambda x: (x["timestamp"] is None, x["timestamp"])):
        g.add_event(e)
    return g
