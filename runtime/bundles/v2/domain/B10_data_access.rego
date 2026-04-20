# ═══════════════════════════════════════════════════════════════════
# ARHIA v11.4 — Bundle B10: Data Access Governance
# OWASP ASI-06 (RAG) + data boundary enforcement
# Lines: ~75
# ═══════════════════════════════════════════════════════════════════
package arhia.domain.data_access

import rego.v1

default data_access_permitted := false

access_modes := {"READ", "WRITE", "DELETE", "ADMIN"}

mode_hierarchy := {"READ": 0, "WRITE": 1, "DELETE": 2, "ADMIN": 3}

agent_max_mode(agent_id) := mode if {
    mode := data.arhia.agents[agent_id].dataAccessMode
}

agent_max_mode(agent_id) := "READ" if {
    not data.arhia.agents[agent_id].dataAccessMode
}

mode_permitted if {
    agent_level := mode_hierarchy[agent_max_mode(input.request.agentId)]
    requested_level := mode_hierarchy[input.request.accessMode]
    agent_level >= requested_level
}

dataset_accessible if {
    datasets := data.arhia.agents[input.request.agentId].accessibleDatasets
    input.request.datasetId in datasets
}

rag_source_verified if {
    not input.request.ragSource
}

rag_source_verified if {
    input.request.ragSource
    source := data.arhia.rag.verifiedSources[input.request.ragSource]
    source.verified == true
    source.lastVerified > input.context.currentTime - 86400
}

data_access_permitted if {
    mode_permitted
    dataset_accessible
    rag_source_verified
}

evidence := {
    "@type": "LOG",
    "controlId": "B10",
    "datasetId": input.request.datasetId,
    "permitted": data_access_permitted,
    "retentionTier": "Tier2",
}
