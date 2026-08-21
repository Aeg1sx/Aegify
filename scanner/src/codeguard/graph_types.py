"""Shared type aliases for the attributed program graphs."""

from typing import Any

import networkx as nx

# Calls are call-site facts, not merely caller/callee pairs.  A MultiDiGraph
# preserves repeated invocations and distinct dispatch evidence between the
# same two functions instead of silently overwriting the earlier edge.
type CodeGraph = nx.MultiDiGraph[str, dict[str, Any], dict[str, Any]]
type SemanticGraph = nx.MultiDiGraph[str, dict[str, Any], dict[str, Any]]
type ProgramGraph = nx.MultiDiGraph[str, dict[str, Any], dict[str, Any]]
