# ═══════════════════════════════════════════════════════════════════
# ARHIA v11.4 — Bundle B06: Prompt Safety & Guardrails
# OWASP ASI-01 defense layer
# Lines: ~80
# ═══════════════════════════════════════════════════════════════════
package arhia.domain.prompt_safety

import rego.v1

default prompt_safe := false

max_prompt_length := 32768
max_system_prompt_ratio := 0.4

# Prompt injection indicators
injection_signatures := [
    "ignore all previous", "disregard instructions",
    "you are now", "new instructions:", "system prompt:",
    "override:", "bypass:", "jailbreak",
    "DAN", "developer mode", "pretend you",
    "forget everything", "act as if",
]

indirect_injection_patterns := [
    "hidden instruction", "invisible text",
    "base64:", "rot13:", "hex:",
    "<!-- ", "-->", "<hidden>",
]

prompt_length_valid if {
    count(input.prompt.content) <= max_prompt_length
}

direct_injection_detected if {
    sig := injection_signatures[_]
    contains(lower(input.prompt.content), lower(sig))
}

indirect_injection_detected if {
    pattern := indirect_injection_patterns[_]
    contains(lower(input.prompt.content), lower(pattern))
}

encoding_attack_detected if {
    contains(input.prompt.content, "\\u") 
    count(regex.find_all_string_submatch_n(`\\u[0-9a-fA-F]{4}`, input.prompt.content, -1)) > 10
}

prompt_safe if {
    prompt_length_valid
    not direct_injection_detected
    not indirect_injection_detected
    not encoding_attack_detected
}

threat_flags := flags if {
    flags := {f |
        direct_injection_detected; f := "DIRECT_INJECTION"
    } | {f |
        indirect_injection_detected; f := "INDIRECT_INJECTION"
    } | {f |
        encoding_attack_detected; f := "ENCODING_ATTACK"
    } | {f |
        not prompt_length_valid; f := "PROMPT_TOO_LONG"
    }
}

evidence := {
    "@type": "LOG",
    "controlId": "B06",
    "promptSafe": prompt_safe,
    "threatFlags": threat_flags,
    "retentionTier": "Tier2",
}
