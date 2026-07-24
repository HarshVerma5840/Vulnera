"""
test_risk_scorer.py

Tests the Phase 2 risk scoring engine, including API integrations
and the composite risk formula.
"""

import os
import sys
import unittest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(__file__))

from risk_scorer import RiskScorer
from cache_manager import cache

class TestRiskScorer(unittest.TestCase):
    
    def setUp(self):
        self.scorer = RiskScorer()
        
    @patch('requests.get')
    def test_fetch_cvss_success(self, mock_get):
        """Test fetching CVSS from NVD API."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "vulnerabilities": [{
                "cve": {
                    "metrics": {
                        "cvssMetricV31": [{
                            "cvssData": {
                                "baseScore": 9.8
                            }
                        }]
                    }
                }
            }]
        }
        mock_get.return_value = mock_response
        
        # Test clear cache so we hit the mock
        cache.clear_prefix("cvss")
        
        score = self.scorer.fetch_cvss("CVE-2021-44228")
        self.assertEqual(score, 0.98)
        
    def test_fetch_cvss_invalid(self):
        """Test fallback for invalid CVE."""
        score = self.scorer.fetch_cvss("")
        self.assertEqual(score, 0.5)
        
        score = self.scorer.fetch_cvss("NOT-A-CVE")
        self.assertEqual(score, 0.5)

    @patch('requests.get')
    def test_fetch_epss_success(self, mock_get):
        """Test fetching EPSS from FIRST.org."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "data": [{
                "epss": "0.95231"
            }]
        }
        mock_get.return_value = mock_response
        
        cache.clear_prefix("epss")
        
        score = self.scorer.fetch_epss("CVE-2021-44228")
        self.assertEqual(score, 0.9523)
        
    def test_fetch_epss_invalid(self):
        score = self.scorer.fetch_epss("INVALID")
        self.assertEqual(score, 0.1)

    def test_normalise_confidence(self):
        """Test confidence normalisation mapping."""
        self.assertEqual(self.scorer._normalise_confidence({"confidence": "High"}), 0.9)
        self.assertEqual(self.scorer._normalise_confidence({"confidence": "Medium"}), 0.6)
        
        # Nmap minimum confidence boost
        nmap_alert = {"source": "nmap", "confidence": "Low"}
        self.assertEqual(self.scorer._normalise_confidence(nmap_alert), 0.7)

    @patch.object(RiskScorer, 'fetch_cvss')
    @patch.object(RiskScorer, 'fetch_epss')
    def test_score_alert_critical(self, mock_epss, mock_cvss):
        """Test the composite formula calculates a CRITICAL score."""
        mock_cvss.return_value = 1.0  # 10.0 CVSS
        mock_epss.return_value = 0.9  # 90% chance of exploit
        
        alert = {
            "source": "zap",
            "confidence": "High",
            "cve_id": "CVE-2021-44228"
        }
        
        # Calculate expected:
        # 0.35(CVSS) * 1.0 + 0.25(EPSS) * 0.9 + 0.20(EP) * 0.9 + 0.10(Conf) * 0.9 + 0.10(Amp) * 0.0
        # = 0.35 + 0.225 + 0.18 + 0.09 + 0 = 0.845
        # risk_score = 0.845 * amplification(1.0) = 0.845 (High, just shy of 0.85 Critical)
        # Wait, let's bump EPSS to 0.95 and Endpoint to 0.95 to definitely hit CRITICAL
        mock_epss.return_value = 0.95
        
        result = self.scorer.score_alert(alert, endpoint_score=0.95, amplification=1.0)
        
        self.assertTrue(result["risk_score"] >= 0.85)
        self.assertEqual(result["risk_level"], "CRITICAL")
        
    @patch.object(RiskScorer, 'fetch_cvss')
    @patch.object(RiskScorer, 'fetch_epss')
    def test_score_alert_amplification(self, mock_epss, mock_cvss):
        """Test that cross-tool amplification boosts the score."""
        mock_cvss.return_value = 0.5
        mock_epss.return_value = 0.1
        
        alert = {"source": "zap", "confidence": "Medium"}
        
        # Without amplification
        base_result = self.scorer.score_alert(alert, endpoint_score=0.5, amplification=1.0)
        
        # With maximum amplification
        boosted_result = self.scorer.score_alert(alert, endpoint_score=0.5, amplification=1.5)
        
        self.assertTrue(boosted_result["risk_score"] > base_result["risk_score"])

if __name__ == "__main__":
    unittest.main()
