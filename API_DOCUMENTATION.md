# Vulnera Security Scanner - API Documentation

**Version:** 1.0.0  
**Last Updated:** June 5, 2026  
**Status:** Framework Ready (NMAP execution pending)

---

## Table of Contents

1. [Overview](#overview)
2. [What Changed](#what-changed)
3. [Database Models](#database-models)
4. [Pydantic Schemas](#pydantic-schemas)
5. [NMAP API Endpoints](#nmap-api-endpoints)
6. [ZAP API Endpoints](#zap-api-endpoints)
7. [Response Modes](#response-modes)
8. [Error Handling](#error-handling)
9. [Example Usage](#example-usage)

---

## Overview

Vulnera is a security scanning platform with REST API endpoints for:
- **NMAP Port Scanning** - Enumerate open ports and services
- **ZAP Web Scanning** - Detect web vulnerabilities (TODO)
- **Feedback System** - Learn from user verdicts
- **Report Generation** - Export results in JSON/CSV

### Base URL
```
http://localhost:8000
```

### Response Modes
- **Vulnera Mode** - Simple, non-technical language for business users
- **Pro Mode** - Detailed technical data for security professionals

---

## What Changed

### Database Layer
- ✅ Created `NmapScan` table - Store scan metadata and results
- ✅ Created `NmapFinding` table - Individual findings per scan
- ✅ Created `NmapFeedback` table - User feedback (TP/FP/Unsure)
- ✅ Kept `ZapHistory` table - Unchanged for ZAP integration

### Pydantic Models
- ✅ `StartScanRequest` - POST request schema
- ✅ `ScanStatusResponse` - Status check schema
- ✅ `NmapFindingDetail` - Finding structure
- ✅ `VulneraModeResponse` - Simple response format
- ✅ `ProModeResponse` - Detailed response format
- ✅ `FeedbackRequest/Response` - Feedback schemas
- ✅ `ListScansResponse` - Paginated list format

### API Endpoints
- ✅ 8 NMAP endpoints implemented
- ✅ 3 ZAP endpoints kept unchanged
- ✅ Full error handling with HTTP status codes
- ✅ Pagination support
- ✅ Export functionality (JSON/CSV)

---

## Database Models

### 1. NmapScan
**Table:** `nmap_scans`

| Column | Type | Purpose |
|--------|------|---------|
| `id` | Integer | Primary Key |
| `scan_id` | String | Unique scan identifier (e.g., `scan_abc123xyz789`) |
| `target_url` | String | Target domain/IP to scan |
| `app_type` | String | Application type (ecommerce, blog, etc.) |
| `scan_speed` | String | Scan speed (fast, standard, thorough) |
| `extended_ports` | Integer | Include extended port range (0/1) |
| `max_timeout` | Integer | Max timeout in seconds |
| `status` | String | queued, running, complete, failed |
| `progress` | Integer | Progress percentage (0-100) |
| `current_stage` | String | Current scan stage (e.g., "Running NMAP scan") |
| `started_at` | DateTime | Scan start time |
| `completed_at` | DateTime | Scan completion time |
| `duration_seconds` | Integer | Total scan duration |
| `findings_count` | Integer | Total findings |
| `critical_count` | Integer | Critical severity count |
| `high_count` | Integer | High severity count |
| `medium_count` | Integer | Medium severity count |
| `low_count` | Integer | Low severity count |
| `findings` | JSON | Findings data (port, service, product, version) |
| `overall_score` | Integer | Overall score (0-100) |

### 2. NmapFinding
**Table:** `nmap_findings`

| Column | Type | Purpose |
|--------|------|---------|
| `id` | Integer | Primary Key |
| `scan_id` | String | Foreign key to scan |
| `finding_id` | String | Unique finding ID |
| `port` | Integer | Port number |
| `service` | String | Service name (http, https, ssh, etc.) |
| `product` | String | Product name (nginx, Apache, etc.) |
| `version` | String | Product version |
| `severity` | String | CRITICAL, HIGH, MEDIUM, LOW |
| `cve_ids` | JSON | Associated CVE IDs |
| `evidence` | Text | Evidence/proof of finding |
| `created_at` | DateTime | Finding creation time |

### 3. NmapFeedback
**Table:** `nmap_feedback`

| Column | Type | Purpose |
|--------|------|---------|
| `id` | Integer | Primary Key |
| `scan_id` | String | Associated scan ID |
| `finding_id` | String | Associated finding ID |
| `verdict` | String | true_positive, false_positive, unsure |
| `notes` | Text | User notes |
| `created_at` | DateTime | Feedback creation time |

### 4. ZapHistory
**Table:** `zaphistory` (Unchanged)

| Column | Type | Purpose |
|--------|------|---------|
| `id` | Integer | Primary Key |
| `target` | String | Target URL |
| `scan_date` | DateTime | Scan date |
| `result` | Text | Scan results |
| `status` | String | Scan status |

---

## Pydantic Schemas

### Request Schemas

#### StartScanRequest
```python
{
    "target_url": "example.com",              # Required
    "app_type": "ecommerce",                  # Required
    "scan_speed": "standard",                 # Optional: fast, standard, thorough
    "extended_ports": false,                  # Optional: bool
    "max_timeout": 300                        # Optional: seconds
}
```

#### FeedbackRequest
```python
{
    "finding_id": "vuln_001",                 # Required
    "verdict": "true_positive",               # Required: true_positive, false_positive, unsure
    "notes": "Confirmed vulnerability"        # Optional
}
```

### Response Schemas

#### NmapFindingDetail
```python
{
    "id": "vuln_001",
    "port": 80,
    "service": "http",
    "product": "nginx",
    "version": "1.18.0",
    "severity": "HIGH",
    "cve_ids": ["CVE-2021-XXXX"],
    "evidence": "Service banner detected"
}
```

---

## NMAP API Endpoints

### Health Check
```
GET /
```
**Response:**
```json
{
    "message": "Welcome to Vulnera Security Scanner",
    "version": "1.0.0"
}
```

---

### 1. Start a New Scan
```
POST /api/scans
```

**Status:** ✅ Implemented  
**Headers:** `Content-Type: application/json`

**Request Body:**
```json
{
    "target_url": "example.com",
    "app_type": "ecommerce",
    "scan_speed": "standard"
}
```

**Response (200 OK):**
```json
{
    "status": "queued",
    "scan_id": "scan_abc123xyz789",
    "message": "Scan queued successfully",
    "estimated_time": 600,
    "target_url": "example.com",
    "app_type": "ecommerce"
}
```

**Error Responses:**
- `400 Bad Request` - Missing required fields
- `500 Server Error` - Database error

---

### 2. Check Scan Status
```
GET /api/scans/{scan_id}
```

**Status:** ✅ Implemented  
**Path Parameters:** 
- `scan_id` (string) - Scan identifier

**Response (200 OK) - Running:**
```json
{
    "scan_id": "scan_abc123xyz789",
    "status": "running",
    "progress": 45,
    "current_stage": "Running NMAP scan",
    "started_at": "2026-06-05T10:30:00",
    "estimated_completion": "2026-06-05T10:45:00",
    "findings_count": 12
}
```

**Response (200 OK) - Complete:**
```json
{
    "scan_id": "scan_abc123xyz789",
    "status": "complete",
    "progress": 100,
    "current_stage": null,
    "started_at": "2026-06-05T10:30:00",
    "estimated_completion": null,
    "findings_count": 27
}
```

**Error Responses:**
- `404 Not Found` - Scan doesn't exist

---

### 3. Get Results (Vulnera Mode - Simple)
```
GET /api/scans/{scan_id}/results/vulnera
```

**Status:** ✅ Implemented  
**Path Parameters:**
- `scan_id` (string) - Scan identifier

**Response (200 OK):**
```json
{
    "scan_id": "scan_abc123xyz789",
    "mode": "vulnera",
    "target": "example.com",
    "app_type": "ecommerce",
    "overall_score": 68,
    "compliance_score": 53,
    "summary": {
        "critical_count": 1,
        "high_count": 3,
        "medium_count": 8,
        "low_count": 15
    },
    "critical_findings": [
        {
            "title": "Port 3306 (mysql) is exposed",
            "description": "Service MySQL v5.7.32 is running and vulnerable to attacks",
            "action": "Secure this port immediately",
            "time_to_fix": "1-2 days"
        }
    ],
    "high_findings": [],
    "compliance": {
        "dpdp_compliant": false,
        "dpdp_score": 68,
        "dpdp_requirement": 85
    }
}
```

**Error Responses:**
- `404 Not Found` - Scan not found
- `400 Bad Request` - Scan not complete yet

---

### 4. Get Results (Pro Mode - Detailed)
```
GET /api/scans/{scan_id}/results/pro
```

**Status:** ✅ Implemented  
**Path Parameters:**
- `scan_id` (string) - Scan identifier

**Response (200 OK):**
```json
{
    "scan_id": "scan_abc123xyz789",
    "mode": "pro",
    "target": "example.com",
    "app_type": "ecommerce",
    "started_at": "2026-06-05T10:30:00",
    "completed_at": "2026-06-05T10:45:00",
    "duration_seconds": 900,
    "findings": [
        {
            "id": "vuln_000",
            "type": "service_enumeration",
            "port": 80,
            "service": "http",
            "product": "nginx",
            "version": "1.18.0",
            "severity": "HIGH",
            "score": 75,
            "evidence": "Service banner: nginx/1.18.0",
            "tool_source": "nmap",
            "tool_confidence": 0.95,
            "remediation": "Update nginx to latest version or disable the service"
        }
    ]
}
```

**Error Responses:**
- `404 Not Found` - Scan not found
- `400 Bad Request` - Scan not complete yet

---

### 5. Send Feedback
```
POST /api/scans/{scan_id}/feedback
```

**Status:** ✅ Implemented  
**Path Parameters:**
- `scan_id` (string) - Scan identifier

**Request Body:**
```json
{
    "finding_id": "vuln_001",
    "verdict": "true_positive",
    "notes": "Confirmed SQLi on checkout page"
}
```

**Response (200 OK):**
```json
{
    "status": "recorded",
    "finding_id": "vuln_001",
    "verdict": "true_positive",
    "message": "Feedback recorded. System is learning.",
    "feedback_count": 45,
    "next_retraining": "After 5 more feedback events"
}
```

**Error Responses:**
- `404 Not Found` - Scan not found

---

### 6. List All Scans
```
GET /api/scans
```

**Status:** ✅ Implemented  
**Query Parameters:**
- `limit` (int, optional) - Results per page (default: 10)
- `offset` (int, optional) - Pagination offset (default: 0)
- `status` (string, optional) - Filter by status (queued, running, complete, failed)

**Response (200 OK):**
```json
{
    "total": 42,
    "limit": 10,
    "offset": 0,
    "scans": [
        {
            "scan_id": "scan_abc123xyz789",
            "target_url": "example.com",
            "app_type": "ecommerce",
            "status": "complete",
            "created_at": "2026-06-05T10:30:00",
            "completed_at": "2026-06-05T10:45:00",
            "findings_count": 27,
            "critical_count": 1,
            "score": 68
        }
    ]
}
```

---

### 7. Delete a Scan
```
DELETE /api/scans/{scan_id}
```

**Status:** ✅ Implemented  
**Path Parameters:**
- `scan_id` (string) - Scan identifier

**Response (200 OK):**
```json
{
    "status": "deleted",
    "scan_id": "scan_abc123xyz789",
    "message": "Scan deleted successfully"
}
```

**Error Responses:**
- `404 Not Found` - Scan not found

---

### 8. Export Results (JSON)
```
GET /api/scans/{scan_id}/results.json
```

**Status:** ✅ Implemented  
**Path Parameters:**
- `scan_id` (string) - Scan identifier

**Response (200 OK):**
```json
{
    "scan_id": "scan_abc123xyz789",
    "target": "example.com",
    "app_type": "ecommerce",
    "status": "complete",
    "overall_score": 68,
    "findings_count": 27,
    "findings": [...],
    "metadata": {
        "started_at": "2026-06-05T10:30:00",
        "completed_at": "2026-06-05T10:45:00",
        "duration_seconds": 900
    }
}
```

---

### 9. Export Results (CSV)
```
GET /api/scans/{scan_id}/results.csv
```

**Status:** ✅ Implemented  
**Path Parameters:**
- `scan_id` (string) - Scan identifier

**Response (200 OK):**
```
Content-Type: application/json
Content-Disposition: attachment; filename=scan_abc123xyz789.csv

port,service,product,version,severity,evidence
80,http,nginx,1.18.0,HIGH,"Service banner detected"
443,https,nginx,1.18.0,HIGH,"Service banner detected"
3306,mysql,MySQL,5.7.32,CRITICAL,"MySQL exposed to network"
```

---

## ZAP API Endpoints

### 1. Add ZAP Scan
```
POST /zap/scan
```

**Status:** ✅ Implemented (Framework only)  
**Request Body:**
```json
{
    "target": "example.com",
    "result": "scan results",
    "status": "complete"
}
```

**Response (200 OK):**
```json
{
    "id": 1,
    "target": "example.com",
    "result": "scan results",
    "status": "complete"
}
```

---

### 2. Get ZAP History
```
GET /zap/history
```

**Status:** ✅ Implemented  
**Response (200 OK):**
```json
[
    {
        "id": 1,
        "target": "example.com",
        "scan_date": "2026-06-05T10:30:00",
        "result": "scan results",
        "status": "complete"
    }
]
```

---

### 3. Get Specific ZAP Scan
```
GET /zap/history/{scan_id}
```

**Status:** ✅ Implemented  
**Path Parameters:**
- `scan_id` (int) - Scan ID

**Response (200 OK):**
```json
{
    "id": 1,
    "target": "example.com",
    "scan_date": "2026-06-05T10:30:00",
    "result": "scan results",
    "status": "complete"
}
```

**Error Responses:**
- `404 Not Found` - Returns `{"error": "Scan not found"}`

---

## Response Modes

### Vulnera Mode (Simple)
- **Audience:** Business users, non-technical stakeholders
- **Endpoint:** `GET /api/scans/{scan_id}/results/vulnera`
- **Features:**
  - Plain English descriptions
  - Action recommendations
  - Time-to-fix estimates
  - Compliance scoring (DPDP)
  - Critical findings highlighted

### Pro Mode (Detailed)
- **Audience:** Security professionals, developers
- **Endpoint:** `GET /api/scans/{scan_id}/results/pro`
- **Features:**
  - Technical vulnerability details
  - CVSS scores
  - Remediation code samples
  - Tool confidence metrics
  - Cross-tool confirmation data

---

## Error Handling

All endpoints follow standard HTTP status codes:

### 400 Bad Request
```json
{
    "error": "Invalid input",
    "message": "target_url is required",
    "details": {
        "field": "target_url",
        "error": "Required field missing"
    }
}
```

### 404 Not Found
```json
{
    "error": "Not found",
    "message": "Scan with ID scan_abc123xyz789 not found"
}
```

### 500 Server Error
```json
{
    "error": "Internal server error",
    "message": "An unexpected error occurred",
    "request_id": "req_12345"
}
```

---

## Example Usage

### CURL
```bash
# Start a scan
curl -X POST http://localhost:8000/api/scans \
  -H "Content-Type: application/json" \
  -d '{
    "target_url": "example.com",
    "app_type": "ecommerce",
    "scan_speed": "standard"
  }'

# Check status
curl -X GET http://localhost:8000/api/scans/scan_abc123xyz789

# Get results (Vulnera mode)
curl -X GET http://localhost:8000/api/scans/scan_abc123xyz789/results/vulnera

# Get results (Pro mode)
curl -X GET http://localhost:8000/api/scans/scan_abc123xyz789/results/pro

# Send feedback
curl -X POST http://localhost:8000/api/scans/scan_abc123xyz789/feedback \
  -H "Content-Type: application/json" \
  -d '{
    "finding_id": "vuln_001",
    "verdict": "true_positive",
    "notes": "Confirmed vulnerability"
  }'

# List all scans
curl -X GET "http://localhost:8000/api/scans?limit=10&offset=0&status=complete"

# Export JSON
curl -X GET http://localhost:8000/api/scans/scan_abc123xyz789/results.json > report.json

# Export CSV
curl -X GET http://localhost:8000/api/scans/scan_abc123xyz789/results.csv > report.csv

# Delete scan
curl -X DELETE http://localhost:8000/api/scans/scan_abc123xyz789
```

---

## Implementation Status

| Component | Status | Notes |
|-----------|--------|-------|
| Database Models | ✅ Complete | NmapScan, NmapFinding, NmapFeedback, ZapHistory |
| Pydantic Schemas | ✅ Complete | All request/response types |
| POST /api/scans | ✅ Complete | Creates scan record, queues scan |
| GET /api/scans/{id} | ✅ Complete | Returns status and progress |
| GET /api/scans/{id}/results/vulnera | ✅ Complete | Simple mode responses |
| GET /api/scans/{id}/results/pro | ✅ Complete | Pro mode responses |
| POST /api/scans/{id}/feedback | ✅ Complete | Records user feedback |
| GET /api/scans | ✅ Complete | List with pagination |
| DELETE /api/scans/{id} | ✅ Complete | Deletes scan and feedback |
| GET /api/scans/{id}/results.json | ✅ Complete | JSON export |
| GET /api/scans/{id}/results.csv | ✅ Complete | CSV export |
| NMAP Execution | ⏳ TODO | Implement actual NMAP scanning |
| NMAP Output Parsing | ⏳ TODO | Parse NMAP XML/text output |
| Finding Extraction | ⏳ TODO | Extract ports, services, versions |
| Severity Calculation | ⏳ TODO | Calculate severity scores |
| ZAP Integration | ⏳ TODO | Implement ZAP scanning |

---

## Next Steps

1. **Implement NMAP Execution**
   - Execute `nmap` command with proper arguments
   - Handle async/background execution
   - Update scan status in real-time

2. **Implement Output Parsing**
   - Parse NMAP XML output
   - Extract port, service, product, version info
   - Store findings in database

3. **Severity Classification**
   - Map CVE data to ports/services
   - Calculate CVSS scores
   - Assign severity levels

4. **ZAP Integration**
   - Connect to ZAP API
   - Execute web scans
   - Parse ZAP findings

---

**Document Version:** 1.0.0  
**Last Updated:** June 5, 2026  
**Author:** Harsh
