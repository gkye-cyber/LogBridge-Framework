from pathlib import Path
from typing import Any, Dict, List, Optional
import copy
import json
import re

### loading JSON Mapping files
class FrameworkMapper:
    def __init__(self, mappings_dir: Optional[Path] = None) -> None:
        base_dir = Path(mappings_dir) if mappings_dir else (Path(__file__).resolve().parent.parent / "mappings")
        mitre_path = base_dir / "mitre_attck_map.json"
        nist_path = base_dir / "nist_csf_map.json"

        with open(mitre_path, "r", encoding="utf-8") as f:
            self.mitre_map: Dict[str, Any] = json.load(f)

        with open(nist_path, "r", encoding="utf-8") as f:
            self.nist_map: Dict[str, Any] = json.load(f)

    ## helper methods
    def _map_mitre(self, event: Dict[str, Any]) -> Dict[str, str]:
        event_id = str(event.get("event_id", "DEFAULT"))
        rule_entry = self.mitre_map.get(event_id)

        # unknown event_id
        if not rule_entry or event_id == "DEFAULT":
            return self.mitre_map["DEFAULT"]
    
        for pattern in rule_entry.get("patterns", []):
            field_val = str(event.get(pattern["field"], ""))
            if re.search(pattern["regex"], field_val):
                return {
                    "tactic": pattern["tactic"],
                    "technique_id": pattern["technique_id"],
                    "technique_name": pattern["technique_name"]
                }
            
        return rule_entry.get("default", self.mitre_map["DEFAULT"])

    def _map_nist(self, event: Dict[str, Any]) -> Dict[str, str]:
        event_id = str(event.get("event_id", "DEFAULT"))
        return self.nist_map.get(event_id, self.nist_map["DEFAULT"])

    ## enrichment methods
    def enrich_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        enriched = dict(event) # shallow copy of org dict
        enriched["mitre_mapping"] = copy.deepcopy(self._map_mitre(enriched))
        enriched["nist_csf_mapping"] = copy.deepcopy(self._map_nist(enriched))
        return enriched

    def enrich_batch(self, events:List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        return [self.enrich_event(e) for e in events]