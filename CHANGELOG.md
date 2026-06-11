# Changelog - Vulnera Security Scanner

All notable changes to this project are documented in this file.

## [1.0.0] - 2026-06-05

### Added

#### Database Models
- **NmapScan** - Main scan tracking table
  - Stores scan metadata (scan_id, target_url, app_type)
  - Tracks scan status (queued, running, complete, failed)
  - Stores findings as JSON
  - Records scan progress (0-100%)
  - Maintains severity counts (critical, high, medium, low)
  - Tracks scan duration

- **NmapFinding** - Individual vulnerability findings
  - Port number, service name, product, version
  - Severity level and CVE IDs
  - Evidence of vulnerability
  - Associated scan_id for linking

- **NmapFeedback** - User feedback on findings
  - Verdict (true_positive, false_positive, unsure)
  - User notes
  - Feedback timestamp for tracking

#### Pydantic Schemas
- **StartScanRequest** - Request body for initiating scans
- **ScanStatusResponse** - Status check response
- **NmapFindingDetail** - Finding data structure
- **VulneraModeResponse** - Simple response format for non-technical users
- **ProModeResponse** - Detailed response format for security professionals
- **FeedbackRequest/FeedbackResponse** - Feedback schemas
- **ListScansResponse** - Paginated scan list format
- **ErrorResponse** - Standardized error format

#### API Endpoints - NMAP

1. **POST /api/scans** - Start a new scan
   - Accepts target_url, app_type, scan_speed, extended_ports, max_timeout
   - Returns scan_id and estimated completion time
   - Creates database record and queues scan

2. **GET /api/scans/{scan_id}** - Check scan status
   - Returns status, progress percentage, current stage
   - Calculates estimated completion time
   - Provides findings count

3. **GET /api/scans/{scan_id}/results/vulnera** - Get results (Vulnera Mode)
   - Plain English descriptions for business users
   - Action recommendations
   - Time-to-fix estimates
   - DPDP compliance scoring

4. **GET /api/scans/{scan_id}/results/pro** - Get results (Pro Mode)
   - Technical details for security professionals
   - Severity scores and CVSS
   - Remediation code samples
   - Tool confidence metrics

5. **POST /api/scans/{scan_id}/feedback** - Send feedback
   - Record verdict (TP/FP/Unsure) on findings
   - Optional user notes
   - Feedback counter for retraining threshold

6. **GET /api/scans** - List all scans
   - Pagination support (limit, offset)
   - Optional status filtering
   - Returns total count and scan summaries

7. **DELETE /api/scans/{scan_id}** - Delete a scan
   - Removes scan and all associated feedback
   - Cascading deletion

8. **GET /api/scans/{scan_id}/results.json** - Export to JSON
   - Complete scan results with metadata
   - All findings with details

9. **GET /api/scans/{scan_id}/results.csv** - Export to CSV
   - Tabular format for spreadsheet import
   - Port, service, product, version, severity, evidence

#### Configuration
- `.env` file for database credentials
- `.env.example` for template
- `.gitignore` to exclude sensitive files

#### Documentation
- **API_DOCUMENTATION.md** - Complete API reference
- Endpoint descriptions with examples
- Response formats and error handling
- CURL examples for all endpoints

### Changed

#### Renamed
- "Guardian" → "Vulnera" throughout codebase
  - App title
  - Endpoint paths (`/results/guardian` → `/results/vulnera`)
  - Response mode names
  - Class names (GuardianModeResponse → VulneraModeResponse)

#### Database
- Replaced old product-based tables with security scanning models
- Normalized schema for better query performance

#### API Structure
- RESTful endpoint design (/api/scans prefix)
- Consistent response format
- Proper HTTP status codes

### Kept Unchanged

#### ZAP Integration
- `/zap/scan` POST endpoint
- `/zap/history` GET endpoint  
- `/zap/history/{scan_id}` GET endpoint
- ZapHistory database model
- Reserved for future ZAP implementation

### Pending Implementation

- ⏳ Actual NMAP command execution
- ⏳ NMAP output parsing (XML/text)
- ⏳ Port and service enumeration
- ⏳ Severity classification logic
- ⏳ CVE database integration
- ⏳ Background task queue for async scans
- ⏳ Real-time progress updates
- ⏳ ZAP vulnerability scanning
- ⏳ Authentication/Authorization
- ⏳ Rate limiting

---

## File Structure

### New Files
```
API_DOCUMENTATION.md       # Complete API reference
CHANGELOG.md               # This file
.env                       # Database credentials (git ignored)
.env.example               # Credentials template
.gitignore                 # Git exclusions
```

### Modified Files
```
database_models.py         # New NMAP models
models.py                  # New Pydantic schemas
main.py                    # Complete endpoint implementation
database.py                # Environment-based config
```

### Unchanged Files
```
myenv/                     # Virtual environment
```

---

## Deployment Notes

### Before Running
1. Install dependencies: `pip install python-dotenv`
2. Create `.env` file with PostgreSQL credentials
3. Ensure PostgreSQL is running
4. Create target database: `fastapilearn`

### Database Initialization
- Tables auto-create on first run via `Base.metadata.create_all(bind=engine)`
- Existing data is preserved

### Starting Server
```bash
uvicorn main:app --reload
```

### Testing
```bash
# Start scan
curl -X POST http://localhost:8000/api/scans \
  -H "Content-Type: application/json" \
  -d '{"target_url":"example.com","app_type":"ecommerce"}'

# Check status
curl -X GET http://localhost:8000/api/scans/scan_abc123...

# Get results
curl -X GET http://localhost:8000/api/scans/scan_abc123.../results/vulnera
```

---

## Version History

| Version | Date | Status | Notes |
|---------|------|--------|-------|
| 1.0.0 | 2026-06-05 | 🟡 Framework | API endpoints ready, NMAP integration pending |

---

## Contributing Guidelines

### Adding New Endpoints
1. Add Pydantic model in `models.py`
2. Add database model in `database_models.py` if needed
3. Implement endpoint in `main.py`
4. Update API_DOCUMENTATION.md
5. Update CHANGELOG.md

### Code Style
- Use type hints
- Add docstrings
- Follow PEP 8
- Include error handling

### Testing
- Test all paths (happy path + errors)
- Verify database operations
- Check response formats
- Test pagination/filtering

---

## Support

For issues or questions:
1. Check API_DOCUMENTATION.md
2. Review endpoint examples
3. Check database models
4. Verify .env configuration

---

**Last Updated:** June 5, 2026  
**Current Version:** 1.0.0
