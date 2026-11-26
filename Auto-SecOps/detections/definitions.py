from detections.models import DetectionRule

SYNTHETIC_DETECTION_RULES = [
    {
        "rule_id": "SYN-DET-001",
        "name": "High-risk authentication failure",
        "description": "Detects high-risk brute force and authentication failure alerts.",
        "rule_type": DetectionRule.RuleType.SINGLE,
        "severity": DetectionRule.Severity.HIGH,
        "conditions": {
            "alert_types": ["authentication_failure"],
            "min_risk_score": 50,
        },
        "mitre_techniques": ["T1110 - Brute Force"],
        "recommendations": [
            "Review source IP reputation",
            "Validate account lockout status",
        ],
    },
    {
        "rule_id": "SYN-DET-002",
        "name": "Malware beacon and C2 activity",
        "description": "Detects endpoint malware beaconing and command-and-control indicators.",
        "rule_type": DetectionRule.RuleType.SINGLE,
        "severity": DetectionRule.Severity.CRITICAL,
        "conditions": {
            "alert_types": ["edr_malware"],
            "description_contains": "beacon",
        },
        "mitre_techniques": ["T1071 - Application Layer Protocol"],
        "recommendations": [
            "Isolate host after analyst approval",
            "Collect endpoint telemetry",
        ],
    },
    {
        "rule_id": "SYN-DET-003",
        "name": "Repeated activity from one source",
        "description": "Correlates multiple alerts from the same source IP within one hour.",
        "rule_type": DetectionRule.RuleType.CORRELATION,
        "severity": DetectionRule.Severity.HIGH,
        "conditions": {
            "group_by": "source_ip",
            "min_count": 2,
            "window_minutes": 60,
            "min_distinct_counterpart": 1,
        },
        "mitre_techniques": ["T1595 - Active Scanning"],
        "recommendations": [
            "Review firewall and IDS telemetry",
            "Confirm authorized scanning",
        ],
    },
    {
        "rule_id": "SYN-DET-004",
        "name": "Multi-signal user identity",
        "description": "Correlates multiple alerts involving the same user identity.",
        "rule_type": DetectionRule.RuleType.CORRELATION,
        "severity": DetectionRule.Severity.MEDIUM,
        "conditions": {
            "group_by": "user_identity",
            "min_count": 2,
            "window_minutes": 60,
            "min_distinct_counterpart": 1,
        },
        "mitre_techniques": ["T1078 - Valid Accounts"],
        "recommendations": ["Verify user activity", "Check for credential compromise"],
    },
    {
        "rule_id": "SYN-DET-005",
        "name": "Confirmed malicious intelligence",
        "description": "Creates detections for high-confidence malicious threat intelligence records.",
        "rule_type": DetectionRule.RuleType.THREAT_INTEL,
        "severity": DetectionRule.Severity.HIGH,
        "conditions": {"min_confidence": 80},
        "mitre_techniques": ["T1204 - User Execution"],
        "recommendations": [
            "Hunt for indicator hits",
            "Block only through approved change process",
        ],
    },
]
