"""
MITRE ATT&CK mapper — enriches CorrelatedThreat objects with ATT&CK metadata.

The mapper loads technique definitions from a YAML/JSON configuration file.
It supports technique, sub-technique, and tactic level mapping with full
descriptions, mitigations, and kill-chain positioning.

Extension point:
    Replace or supplement the config file with the official MITRE ATT&CK STIX
    bundle (https://github.com/mitre/cti) for a complete, always-current dataset.
    The stix2 library can parse the bundle and populate the same MitreTechnique
    model used here.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import yaml

from threaticap.models.mitre import MitreMapping, MitreTechnique, TACTIC_NAMES

logger = logging.getLogger(__name__)

# Kill-chain "highest stage" ordering — used to set kill_chain_stage on mapping
KILL_CHAIN_STAGE_ORDER: list[str] = [
    "Impact",
    "Exfiltration",
    "Command and Control",
    "Collection",
    "Lateral Movement",
    "Discovery",
    "Credential Access",
    "Defense Evasion",
    "Privilege Escalation",
    "Persistence",
    "Execution",
    "Initial Access",
    "Resource Development",
    "Reconnaissance",
]


class MitreMapper:
    """
    Maps technique IDs to enriched MitreTechnique objects.

    Loading priority (later layers override earlier):
    1. Official MITRE ATT&CK STIX bundle (enterprise-attack.json)
    2. YAML knowledge base (config/mitre_attack_kb.yaml) — overrides/extends STIX
    3. Custom overrides via load_knowledge_base()

    This design means you get the full ATT&CK dataset from the official source
    with the ability to overlay organisation-specific notes and mitigations.
    """

    def __init__(
        self,
        knowledge_base_path: str | Path | None = None,
        stix_bundle_path: str | Path | None = None,
    ) -> None:
        self._kb: dict[str, MitreTechnique] = {}
        # Load STIX bundle first (base layer)
        if stix_bundle_path:
            self.load_stix_bundle(Path(stix_bundle_path))
        # Load YAML KB (override layer)
        if knowledge_base_path:
            self.load_knowledge_base(Path(knowledge_base_path))

    def load_knowledge_base(self, path: Path) -> None:
        """
        Load technique definitions from a YAML or JSON file.

        File format (YAML):
            techniques:
              - id: T1059
                name: "Command and Scripting Interpreter"
                tactic_ids: ["TA0002"]
                description: "..."
                mitigations: [...]
                platforms: ["Windows", "Linux", "macOS"]
                ...
        """
        if not path.exists():
            logger.warning("MITRE knowledge base file not found: %s", path)
            return

        with open(path, "r", encoding="utf-8") as fh:
            if path.suffix in (".yaml", ".yml"):
                data = yaml.safe_load(fh)
            else:
                data = json.load(fh)

        techniques = data.get("techniques", [])
        loaded = 0
        for raw in techniques:
            try:
                tech = self._parse_technique(raw)
                self._kb[tech.technique_id] = tech
                loaded += 1
            except Exception as exc:
                logger.warning("Failed to parse technique %s: %s", raw.get("id"), exc)

        logger.info("MITRE knowledge base loaded: %d techniques from %s", loaded, path)

    def load_stix_bundle(self, path: Path) -> None:
        """
        Load the official MITRE ATT&CK enterprise-attack STIX 2.1 bundle.

        Download from: https://github.com/mitre/cti/tree/master/enterprise-attack
        File: enterprise-attack.json (the full bundle, ~10MB)

        This method parses STIX attack-pattern SDOs directly without requiring
        the stix2 library (though stix2 can also be used — see commented code).
        """
        if not path.exists():
            logger.warning("STIX bundle file not found: %s", path)
            return

        logger.info("Loading MITRE ATT&CK STIX bundle from %s...", path)

        with open(path, "r", encoding="utf-8") as fh:
            bundle = json.load(fh)

        objects = bundle.get("objects", [])
        if not objects and isinstance(bundle, list):
            objects = bundle

        # Build tactic lookup: tactic_id -> tactic_name
        # x-mitre-tactic SDOs contain the authoritative tactic names
        tactic_lookup: dict[str, str] = {}  # shortname -> (id, name)
        tactic_id_lookup: dict[str, str] = {}  # shortname -> TA#### id

        for obj in objects:
            if obj.get("type") == "x-mitre-tactic":
                shortname = obj.get("x_mitre_shortname", "")
                name = obj.get("name", "")
                # Map shortname to tactic name
                tactic_lookup[shortname] = name

        # Map kill_chain_phase names to TA#### IDs
        PHASE_TO_TACTIC_ID: dict[str, str] = {
            "reconnaissance": "TA0043",
            "resource-development": "TA0042",
            "initial-access": "TA0001",
            "execution": "TA0002",
            "persistence": "TA0003",
            "privilege-escalation": "TA0004",
            "defense-evasion": "TA0005",
            "credential-access": "TA0006",
            "discovery": "TA0007",
            "lateral-movement": "TA0008",
            "collection": "TA0009",
            "command-and-control": "TA0011",
            "exfiltration": "TA0010",
            "impact": "TA0040",
        }

        loaded = 0
        skipped = 0

        for obj in objects:
            if obj.get("type") != "attack-pattern":
                continue
            if obj.get("x_mitre_deprecated", False) or obj.get("revoked", False):
                skipped += 1
                continue

            # Extract technique ID from external_references
            tech_id = None
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    tech_id = ref.get("external_id")
                    break

            if not tech_id or not tech_id.startswith("T"):
                continue

            # Extract tactic IDs from kill_chain_phases
            tactic_ids: list[str] = []
            tactic_names_list: list[str] = []
            for phase in obj.get("kill_chain_phases", []):
                if phase.get("kill_chain_name") != "mitre-attack":
                    continue
                phase_name = phase.get("phase_name", "")
                tac_id = PHASE_TO_TACTIC_ID.get(phase_name, "")
                if tac_id:
                    tactic_ids.append(tac_id)
                    tactic_names_list.append(TACTIC_NAMES.get(tac_id, phase_name.replace("-", " ").title()))

            # Extract mitigations from description (STIX bundles embed them differently)
            # Mitigation SDOs are separate objects — we note their IDs here
            mitigations_text: list[str] = []

            # Extract description (first paragraph is most relevant)
            description = obj.get("description", "")

            # Extract platforms
            platforms = obj.get("x_mitre_platforms", [])

            # Extract data sources
            data_sources = obj.get("x_mitre_data_sources", [])

            # Detect sub-technique
            is_sub = "." in tech_id
            parent = tech_id.split(".")[0] if is_sub else None

            # Detection notes from x_mitre_detection
            detection = obj.get("x_mitre_detection", "")

            url = f"https://attack.mitre.org/techniques/{tech_id.replace('.', '/')}/"

            tech = MitreTechnique(
                technique_id=tech_id,
                technique_name=obj.get("name", ""),
                tactic_ids=tactic_ids,
                tactic_names=tactic_names_list,
                is_sub_technique=is_sub,
                parent_technique_id=parent,
                description=description[:2000],
                detection_notes=detection[:1000],
                mitigations=mitigations_text,
                platforms=platforms,
                data_sources=data_sources,
                url=url,
            )
            self._kb[tech_id] = tech
            loaded += 1

        logger.info(
            "MITRE ATT&CK STIX bundle loaded: %d techniques (%d skipped/deprecated) from %s",
            loaded, skipped, path
        )

    def _parse_technique(self, raw: dict[str, Any]) -> MitreTechnique:
        tactic_ids = raw.get("tactic_ids", [])
        tactic_names = [TACTIC_NAMES.get(tid, tid) for tid in tactic_ids]
        tech_id = str(raw["id"])
        is_sub = "." in tech_id
        parent = tech_id.split(".")[0] if is_sub else None

        return MitreTechnique(
            technique_id=tech_id,
            technique_name=str(raw.get("name", "")),
            tactic_ids=tactic_ids,
            tactic_names=tactic_names,
            is_sub_technique=is_sub,
            parent_technique_id=parent,
            description=str(raw.get("description", "")),
            detection_notes=str(raw.get("detection_notes", "")),
            mitigations=raw.get("mitigations", []),
            platforms=raw.get("platforms", []),
            data_sources=raw.get("data_sources", []),
            url=(
                raw.get("url") or
                f"https://attack.mitre.org/techniques/{tech_id.replace('.', '/')}/"
            ),
        )

    def map_techniques(self, technique_ids: list[str]) -> MitreMapping:
        """
        Produce a full MitreMapping for a list of technique IDs.

        Handles:
        - Direct technique lookup (T1059)
        - Sub-technique lookup (T1059.001)
        - Parent enrichment for sub-techniques
        - Deduplication of tactics
        """
        if not technique_ids:
            return MitreMapping()

        enriched: list[MitreTechnique] = []
        tactic_ids: set[str] = set()
        missing_ids: list[str] = []

        for tid in technique_ids:
            tech = self._kb.get(tid)
            if tech is None:
                # Try parent for sub-techniques
                parent_id = tid.split(".")[0] if "." in tid else None
                if parent_id and parent_id in self._kb:
                    parent = self._kb[parent_id]
                    # Create a lightweight sub-technique entry
                    tech = MitreTechnique(
                        technique_id=tid,
                        technique_name=f"{parent.technique_name} (sub-technique {tid})",
                        tactic_ids=parent.tactic_ids,
                        tactic_names=parent.tactic_names,
                        is_sub_technique=True,
                        parent_technique_id=parent_id,
                        description=parent.description,
                        detection_notes=parent.detection_notes,
                        mitigations=parent.mitigations,
                        platforms=parent.platforms,
                        url=f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/"
                    )
                else:
                    missing_ids.append(tid)
                    tech = MitreTechnique(
                        technique_id=tid,
                        technique_name=f"Unknown technique {tid}",
                        url=f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/"
                    )

            enriched.append(tech)
            tactic_ids.update(tech.tactic_ids)

        if missing_ids:
            logger.warning(
                "MITRE technique IDs not found in knowledge base: %s", missing_ids
            )

        tactic_names = [TACTIC_NAMES.get(tid, tid) for tid in sorted(tactic_ids)]

        # Determine highest kill-chain stage
        kill_chain_stage = self._highest_kill_chain_stage(tactic_names)

        # Aggregate mapping confidence
        known_ratio = (len(technique_ids) - len(missing_ids)) / max(1, len(technique_ids))
        mapping_confidence = round(0.5 + known_ratio * 0.5, 3)

        notes_parts = []
        if missing_ids:
            notes_parts.append(f"Unknown technique IDs: {missing_ids}")

        return MitreMapping(
            technique_ids=technique_ids,
            tactic_ids=sorted(tactic_ids),
            tactic_names=tactic_names,
            techniques=enriched,
            kill_chain_stage=kill_chain_stage,
            mapping_confidence=mapping_confidence,
            mapping_notes="; ".join(notes_parts),
        )

    def _highest_kill_chain_stage(self, tactic_names: list[str]) -> str | None:
        """Return the most advanced kill-chain stage from the tactic list."""
        tactic_set = set(tactic_names)
        for stage in KILL_CHAIN_STAGE_ORDER:
            if stage in tactic_set:
                return stage
        return tactic_names[0] if tactic_names else None

    @property
    def technique_count(self) -> int:
        return len(self._kb)
