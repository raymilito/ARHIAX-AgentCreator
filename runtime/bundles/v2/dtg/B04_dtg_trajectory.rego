# ═══════════════════════════════════════════════════════════════════
# ARHIA v11.4 — Bundle B04: D-TCG Trajectory & Anomaly Detection
# Controls: DTG-C01, DTG-C02
# Lines: ~110
# ═══════════════════════════════════════════════════════════════════
package arhia.dtg.trajectory

import rego.v1

# ─── Configuration ───
default trajectory_valid := false

required_trajectory_fields := [
    "traceId", "agentId", "toolName", "parameters",
    "returnValue", "startTime", "endTime", "callerId"
]

max_trajectory_duration_ms := 30000
max_parameter_size_bytes := 65536
max_tool_calls_per_minute := 100

# ─── Trajectory Schema Validation (DTG-C01) ───
trajectory_schema_valid if {
    every field in required_trajectory_fields {
        input.trajectory[field]
    }
    is_string(input.trajectory.traceId)
    is_string(input.trajectory.agentId)
    is_string(input.trajectory.toolName)
    is_number(input.trajectory.startTime)
    is_number(input.trajectory.endTime)
}

trajectory_timing_valid if {
    input.trajectory.endTime >= input.trajectory.startTime
    duration := input.trajectory.endTime - input.trajectory.startTime
    duration <= max_trajectory_duration_ms
}

trajectory_size_valid if {
    param_json := json.marshal(input.trajectory.parameters)
    count(param_json) <= max_parameter_size_bytes
}

trajectory_valid if {
    trajectory_schema_valid
    trajectory_timing_valid
    trajectory_size_valid
}

# ─── Tool Call Allowlist (DTG-C01) ───
tool_registered if {
    input.trajectory.toolName
    registered := data.arhia.tools.registry[input.trajectory.toolName]
    registered.status == "ACTIVE"
}

tool_permitted_for_agent if {
    tool_registered
    agent_tools := data.arhia.agents[input.trajectory.agentId].permittedTools
    input.trajectory.toolName in agent_tools
}

# ─── Anomaly Detection (DTG-C02) ───
baseline := data.arhia.baselines[input.trajectory.agentId]

call_frequency_anomaly if {
    baseline
    current_rate := input.metrics.toolCallsPerMinute
    current_rate > baseline.toolCallProfile.meanRate * 2.5
}

duration_anomaly if {
    baseline
    duration := input.trajectory.endTime - input.trajectory.startTime
    mean := baseline.toolCallProfile.meanDuration
    stddev := baseline.toolCallProfile.stddevDuration
    abs(duration - mean) > stddev * 2.5
}

parameter_anomaly if {
    baseline
    param_size := count(json.marshal(input.trajectory.parameters))
    mean := baseline.toolCallProfile.meanParamSize
    stddev := baseline.toolCallProfile.stddevParamSize
    abs(param_size - mean) > stddev * 3.0
}

novel_tool_anomaly if {
    baseline
    not input.trajectory.toolName in baseline.toolCallProfile.knownTools
}

anomaly_detected if { call_frequency_anomaly }
anomaly_detected if { duration_anomaly }
anomaly_detected if { parameter_anomaly }
anomaly_detected if { novel_tool_anomaly }

anomaly_flags := flags if {
    flags := {flag |
        call_frequency_anomaly; flag := "FREQ_SPIKE"
    } | {flag |
        duration_anomaly; flag := "DURATION_DEVIATION"
    } | {flag |
        parameter_anomaly; flag := "PARAM_SIZE_ANOMALY"
    } | {flag |
        novel_tool_anomaly; flag := "NOVEL_TOOL"
    }
}

# ─── Rate Limiting ───
rate_limit_exceeded if {
    input.metrics.toolCallsPerMinute > max_tool_calls_per_minute
}

# ─── Evidence ───
evidence := {
    "@type": "LOG",
    "controlId": "DTG-C01",
    "agentId": input.trajectory.agentId,
    "traceId": input.trajectory.traceId,
    "toolName": input.trajectory.toolName,
    "anomalyDetected": anomaly_detected,
    "anomalyFlags": anomaly_flags,
    "retentionTier": "Tier2",
}
