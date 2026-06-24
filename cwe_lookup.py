"""
cwe_lookup.py

Provides plain-English explanations for CWE identifiers to make 
security findings accessible to non-technical users.
"""

import json
import os

class CWELookup:
    """
    Translates technical CWE identifiers into plain English descriptions
    with business impact and remediation steps.
    """

    def __init__(self, database_path=None):
        if database_path is None:
            # Default to data/cwe_database.json relative to this file
            base_dir = os.path.dirname(__file__)
            self.database_path = os.path.join(base_dir, "data", "cwe_database.json")
        else:
            self.database_path = database_path
            
        self._database = None

    def _load_database(self) -> dict:
        if self._database is None:
            try:
                with open(self.database_path, "r", encoding="utf-8") as f:
                    self._database = json.load(f)
            except FileNotFoundError:
                print(f"[!] CWE database not found: {self.database_path}")
                self._database = {}
        return self._database

    def get_plain_english(self, cwe_id: str) -> dict:
        """
        Get a plain-English explanation for a CWE identifier.
        """
        if cwe_id is not None:
            cwe_id = str(cwe_id)
            if not cwe_id.startswith("CWE-") and cwe_id != "-1":
                cwe_id = f"CWE-{cwe_id}"

        if not cwe_id or cwe_id == "CWE--1" or cwe_id == "-1":
            return self._generic_response()

        db = self._load_database()
        entry = db.get(cwe_id)

        if entry:
            return {
                "cwe_id": cwe_id,
                **entry
            }

        return self._generic_response(cwe_id)

    def _generic_response(self, cwe_id: str = None) -> dict:
        """Fallback for unknown CWEs."""
        return {
            "cwe_id": cwe_id,
            "title": "Security Vulnerability Detected",
            "plain_english": (
                "A potential security issue was detected in your application. "
                "While we don't have specific details for this vulnerability type, "
                "it should be reviewed by your security team."
            ),
            "impact": (
                "The specific impact depends on the vulnerability type and "
                "your application's architecture. Review the technical details "
                "provided by the scanning tool."
            ),
            "fix": (
                "Review the vulnerability details and apply the recommended "
                "remediation steps. Consult OWASP and MITRE CWE resources "
                "for specific guidance."
            ),
            "severity_context": "REVIEW",
            "owasp_category": None
        }
