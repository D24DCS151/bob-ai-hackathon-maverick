"""
MITRE ATT&CK mapping models.

These models represent the enriched output of mapping observed behaviour to the
ATT&CK framework. They are populated by the MitreMapper component using a
configuration-driven mapping file — no hard-coded technique data.
"""
from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class MitreTactic(str, Enum):
    RECONNAISSANCE          = "TA0043"
    RESOURCE_DEVELOPMENT    = "TA0042"
    INITIAL_ACCESS          = "TA0001"
    EXECUTION               = "TA0002"
    PERSISTENCE             = "TA0003"
    PRIVILEGE_ESCALATION    = "TA0004"
    DEFENSE_EVASION         = "TA0005"
    CREDENTIAL_ACCESS       = "TA0006"
    DISCOVERY               = "TA0007"
    LATERAL_MOVEMENT        = "TA0008"
    COLLECTION              = "TA0009"
    COMMAND_AND_CONTROL     = "TA0011"
    EXFILTRATION            = "TA0010"
    IMPACT                  = "TA0040"


TACTIC_NAMES: dict[str, str] = {
    "TA0043": "Reconnaissance",
    "TA0042": "Resource Development",
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0003": "Persistence",
    "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion",
    "TA0006": "Credential Access",
    "TA0007": "Discovery",
    "TA0008": "Lateral Movement",
    "TA0009": "Collection",
    "TA0011": "Command and Control",
    "TA0010": "Exfiltration",
    "TA0040": "Impact",
}


class MitreTechnique(BaseModel):
    """Enriched technique record from the ATT&CK knowledge base."""

    technique_id: str = Field(..., description="e.g. T1059.001")
    technique_name: str
    tactic_ids: list[str] = Field(
        default_factory=list,
        description="Parent tactic IDs (a technique can belong to multiple tactics).",
    )
    tactic_names: list[str] = Field(default_factory=list)
    is_sub_technique: bool = Field(default=False)
    parent_technique_id: str | None = Field(
        default=None,
        description="Populated when is_sub_technique=True.",
    )
    description: str = Field(default="")
    detection_notes: str = Field(default="")
    mitigations: list[str] = Field(default_factory=list)
    platforms: list[str] = Field(default_factory=list)
    data_sources: list[str] = Field(default_factory=list)
    url: str = Field(default="")


class MitreMapping(BaseModel):
    """
    The full ATT&CK mapping result attached to a CorrelatedThreat or Alert.

    Records both the raw technique IDs observed and the enriched technique
    objects, enabling downstream consumers to use either form.
    """
    technique_ids: list[str] = Field(
        default_factory=list,
        description="All mapped technique IDs (technique + sub-technique).",
    )
    tactic_ids: list[str] = Field(
        default_factory=list,
        description="Unique tactic IDs derived from mapped techniques.",
    )
    tactic_names: list[str] = Field(default_factory=list)
    techniques: list[MitreTechnique] = Field(default_factory=list)
    kill_chain_stage: str | None = Field(
        default=None,
        description="Highest kill-chain stage represented (for quick triage).",
    )
    mapping_confidence: float = Field(
        default=0.5,
        ge=0.0,
        le=1.0,
        description="Aggregate confidence in the ATT&CK mapping.",
    )
    mapping_notes: str = Field(default="")
