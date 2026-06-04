"""A compact slice of the MITRE ATT&CK Enterprise matrix."""
from __future__ import annotations
from dataclasses import dataclass
from typing import Dict, List


@dataclass(frozen=True)
class Technique:
    id: str
    name: str


TACTICS: Dict[str, List[Technique]] = {
    "Initial Access": [Technique("T1566", "Phishing"), Technique("T1190", "Exploit Public-Facing App"),
                       Technique("T1078", "Valid Accounts")],
    "Execution": [Technique("T1059", "Command & Scripting Interpreter"), Technique("T1204", "User Execution"),
                  Technique("T1053", "Scheduled Task/Job")],
    "Persistence": [Technique("T1098", "Account Manipulation"), Technique("T1136", "Create Account"),
                    Technique("T1547", "Boot/Logon Autostart")],
    "Privilege Escalation": [Technique("T1068", "Exploitation for Priv Esc"), Technique("T1548", "Abuse Elevation Control")],
    "Defense Evasion": [Technique("T1070", "Indicator Removal"), Technique("T1027", "Obfuscated Files"),
                        Technique("T1562", "Impair Defenses")],
    "Credential Access": [Technique("T1110", "Brute Force"), Technique("T1003", "OS Credential Dumping"),
                          Technique("T1555", "Credentials from Stores")],
    "Lateral Movement": [Technique("T1021", "Remote Services"), Technique("T1570", "Lateral Tool Transfer")],
    "Exfiltration": [Technique("T1041", "Exfil Over C2"), Technique("T1567", "Exfil to Cloud")],
}


def all_techniques() -> Dict[str, Technique]:
    return {t.id: t for techs in TACTICS.values() for t in techs}


def technique_name(tid: str) -> str:
    t = all_techniques().get(tid)
    return t.name if t else tid
