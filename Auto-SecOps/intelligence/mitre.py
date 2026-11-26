MITRE_TECHNIQUES = {
    "SUSPICIOUS_LOGIN": ["T1110 - Brute Force", "T1078 - Valid Accounts"],
    "MALWARE": ["T1204 - User Execution", "T1547 - Boot or Logon Autostart"],
    "NETWORK_INTRUSION": [
        "T1190 - Exploit Public-Facing Application",
        "T1046 - Network Service Discovery",
    ],
    "PHISHING": ["T1566 - Phishing", "T1056 - Input Capture"],
    "PRIVILEGE_ESCALATION": [
        "T1068 - Exploitation for Privilege Escalation",
        "T1098 - Account Manipulation",
    ],
    "OTHER": [],
}

TACTIC_MAP = {
    "SUSPICIOUS_LOGIN": "Credential Access",
    "MALWARE": "Execution",
    "NETWORK_INTRUSION": "Initial Access",
    "PHISHING": "Initial Access",
    "PRIVILEGE_ESCALATION": "Privilege Escalation",
    "OTHER": "Unknown",
}


def techniques_for_category(category):
    return MITRE_TECHNIQUES.get(category, [])


def tactics_for_category(category):
    return TACTIC_MAP.get(category, "Unknown")
