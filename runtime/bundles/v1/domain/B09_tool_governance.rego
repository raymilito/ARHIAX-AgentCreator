# ═══════════════════════════════════════════════════════════════════
# ARHIA v11.4 — Bundle B09: Tool Call Governance
# Tool allowlist, rate limiting, parameter validation
# Lines: ~85
# ═══════════════════════════════════════════════════════════════════
package arhia.domain.tool_governance

import rego.v1

default tool_call_allowed := false

max_calls_per_minute := 100
max_concurrent_tools := 5
max_chain_depth := 10

tool_registered if {
    data.arhia.tools.registry[input.toolCall.toolName]
    data.arhia.tools.registry[input.toolCall.toolName].status == "ACTIVE"
}

tool_permitted_for_agent if {
    tool_registered
    permitted := data.arhia.agents[input.toolCall.agentId].permittedTools
    input.toolCall.toolName in permitted
}

rate_limit_ok if {
    input.metrics.callsPerMinute <= max_calls_per_minute
}

concurrency_ok if {
    input.metrics.concurrentCalls <= max_concurrent_tools
}

chain_depth_ok if {
    input.toolCall.chainDepth <= max_chain_depth
}

parameter_schema_valid if {
    tool_def := data.arhia.tools.registry[input.toolCall.toolName]
    every required_param in tool_def.requiredParams {
        input.toolCall.parameters[required_param]
    }
}

dangerous_parameter_detected if {
    param_json := json.marshal(input.toolCall.parameters)
    contains(param_json, "rm -rf")
}

dangerous_parameter_detected if {
    param_json := json.marshal(input.toolCall.parameters)
    contains(param_json, "DROP TABLE")
}

tool_call_allowed if {
    tool_permitted_for_agent
    rate_limit_ok
    concurrency_ok
    chain_depth_ok
    parameter_schema_valid
    not dangerous_parameter_detected
}

evidence := {
    "@type": "LOG",
    "controlId": "B09",
    "toolName": input.toolCall.toolName,
    "allowed": tool_call_allowed,
    "retentionTier": "Tier2",
}
