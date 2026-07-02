# ORACLE Community Edition — Build Workflow
## Codex Master Prompt Sequence
### NULLSEC // Public Release Build

---

## WHAT THIS WORKFLOW BUILDS

ORACLE Community Edition is a stripped, hardened, public-safe version
of ORACLE V4 Pro. It contains everything needed to be genuinely useful
for authorized security research — with active exploitation permanently
gated behind the Pro license system.

**Community Edition = ORACLE sees everything, touches nothing.**

## PHASE 1 — Establish Community Edition Identity

### Prompt 1.1 — Project Setup

```
We are building ORACLE Community Edition from the ORACLE V4 Pro codebase.
Community Edition is the public, open-core version of ORACLE.

First, establish the Community Edition identity:

1. Update oracle/core/config.py to add:
   ORACLE_EDITION = "community"  # or "pro" for Pro version
   ORACLE_VERSION = "1.0.0"
   ORACLE_BUILD = "community"
   LICENSE_REQUIRED_FEATURES = [
       "exploit_execution",
       "active_payload_delivery", 
       "lateral_movement",
       "autonomous_destructive_actions"
   ]

2. Create oracle/core/edition.py:
   - is_pro() -> bool: checks for valid LICENSE_KEY env var
   - is_community() -> bool: not is_pro()
   - get_edition() -> str: returns "pro" or "community"
   - check_feature(feature_name) -> bool: True if available in current edition
   - A decorator @requires_pro that gates any function behind license check

3. Update oracle/cli/main.py banner to show:
   "ORACLE Community Edition v1.0.0 // NULLSEC"
   And a line: "Upgrade to Pro: nullsec.io/pro"

4. Add --version flag that outputs:
   ORACLE Community Edition 1.0.0
   License: BUSL 1.1
   © 2026 NULLSEC — nullsec.io
```

---

## PHASE 2 — Capability Audit & Removal

### Prompt 2.1 — Identify and Gate Offensive Capabilities

```
Audit the entire codebase for any capability that could cause active
harm to systems without user interaction. Apply the following rules:

REMOVE ENTIRELY (delete these if they exist):
- Any payload generation or delivery code
- Any exploit execution code that runs without the license gate
- Any code that modifies, damages, or deletes remote system files
- Any lateral movement automation
- Any credential dumping or exfiltration automation
- Any code in .agents/ that performs autonomous destructive actions

GATE WITH LICENSE CHECK (wrap with @requires_pro from edition.py):
- Any code in core/policy/license_gate.py that executes exploits
- Any plugin that performs active interaction beyond read-only probing
- Any worker action classified as risk_level="destructive"

KEEP FULLY INTACT — DO NOT MODIFY:
- All recon and enumeration (nmap, http, fuzz plugins)
- All analysis and correlation (core/correlation.py, core/attackgraph.py)
- All AI council decision making (core/ai/council.py)
- All evidence graph operations (memory/graph_store.py)
- All reporting (core/reporting/)
- All audit chain operations (cryptographic logging)
- All scope enforcement (core/policy/scope_guard.py)
- All API endpoints
- All CLI commands except those that trigger Pro features
- Demo mode (oracle/demos/demo_mission.py)

After making changes, document every removal and gate in:
COMMUNITY_CAPABILITY_MANIFEST.md
```

---

### Prompt 2.2 — Pro Gate Integration Throughout

```
Apply the @requires_pro decorator from oracle/core/edition.py
to every function that should be gated in Community Edition.

For each gated function, implement this pattern:

def execute_exploit(self, target, cve_id, pathway):
    """Execute a discovered exploit pathway."""
    if not is_pro():
        self._show_pro_gate(target, cve_id)
        return GateResult(
            gated=True,
            cve_id=cve_id,
            message="Exploit execution requires ORACLE Pro license",
            upgrade_url="https://nullsec.io/pro"
        )
    # Pro execution code here

The _show_pro_gate() method must display this Rich terminal panel:

╔══════════════════════════════════════════════════════╗
║     ORACLE // EXPLOIT MODULE — PRO LICENSE REQUIRED  ║
╠══════════════════════════════════════════════════════╣
║                                                      ║
║  Target:    {target}                                 ║
║  CVE:       {cve_id}                                 ║
║  Severity:  {severity} (CVSS: {cvss_score})         ║
║  Type:      {vuln_type}                              ║
║                                                      ║
║  ORACLE has identified an exploitable attack path.   ║
║  Full analysis complete. Execution gated.            ║
║                                                      ║
║  Upgrade to Pro to unlock:                          ║
║  → nullsec.io/pro                                   ║
║                                                      ║
║  [ VIEW CVE DETAILS ]  [ REQUEST LICENSE ]          ║
╚══════════════════════════════════════════════════════╝

This panel must use Rich library for rendering.
Log every gate trigger to the audit chain.
```

---

## PHASE 3 — Security Hardening for Public Release

### Prompt 3.1 — Remove All Sensitive Internal Content

```
Prepare the codebase for public GitHub release. Scan and clean:

1. Remove ALL of these if present:
   - Any hardcoded IP addresses (except localhost/127.0.0.1)
   - Any hardcoded credentials, tokens, or API keys
   - Any internal NULLSEC infrastructure references
   - Any paths specific to the development environment
   - Any .env files or .env.example files with real values
   - Any private keys, certificates, or secrets

2. Scan with:
   grep -rn "sk-ant" . --include="*.py"
   grep -rn "password\s*=" . --include="*.py"
   grep -rn "secret\s*=" . --include="*.py"
   grep -rn "192\.168\." . --include="*.py"
   grep -rn "10\.0\." . --include="*.py"
   
   Fix every finding.

3. Create a clean .env.example with ALL required variables
   documented but with placeholder values:
   
   # ORACLE Community Edition — Environment Variables
   # Copy to .env and fill in your values
   
   # AI Model Configuration (at least one required)
   ANTHROPIC_API_KEY=your_anthropic_api_key_here
   OLLAMA_HOST=http://localhost:11434
   
   # ORACLE Configuration
   ORACLE_EDITION=community
   ORACLE_LOG_LEVEL=INFO
   ORACLE_DATA_DIR=.oracle
   
   # Database
   DATABASE_URL=sqlite:///.oracle/oracle.db
   
   # API Server
   API_HOST=127.0.0.1
   API_PORT=8080
   API_SECRET_KEY=generate_a_random_secret_here

4. Remove .aider.tags.cache.v4/ from git tracking
5. Ensure .oracle/ directory is in .gitignore
6. Ensure .oracle-artifacts/ is in .gitignore
```

---

### Prompt 3.2 — Scope Guard Hardening for Public

```
Harden core/policy/scope_guard.py for public release. In Community
Edition, the scope guard is the PRIMARY protection against misuse.

Make the scope guard:

1. Default to DENY — if scope is not explicitly configured,
   all targets are rejected. No target is allowed without explicit
   scope configuration.

2. Require scope acknowledgment on first run:
   - First-time users must run: oracle scope add --target <target>
     --confirm-authorized
   - The --confirm-authorized flag requires typing: "I have authorization"
   - This is logged permanently to the audit chain

3. Scope validation on every action:
   - Check target IP/domain against scope list
   - Check CIDR ranges
   - Reject private IP ranges (RFC 1918) unless explicitly added
     with a warning: "Warning: Adding private network range. 
     Ensure you own or have authorization for this network."
   - Reject cloud provider metadata endpoints (169.254.169.254 etc.)
   - Reject localhost/loopback unless explicitly added

4. Scope tampering detection:
   - Scope configuration is checksummed
   - Any modification outside the CLI is flagged as tampering
   - Tampering events are logged to audit chain

5. Add prominent startup warning if no scope is configured:
   ⚠ WARNING: No scope configured. All targets will be rejected.
   Configure scope with: oracle scope add --target <target>
```

---

## PHASE 4 — Community-Specific Features

### Prompt 4.1 — Enhanced CVE Intelligence (Community Exclusive Value)

```
Implement an enhanced CVE intelligence system for Community Edition.
This is a genuine value-add that makes Community Edition useful
even without Pro exploit execution.

Create: oracle/core/cve_intelligence.py

Features:
1. CVE lookup and enrichment:
   - Query NVD API (https://services.nvd.nist.gov/rest/json/cves/2.0)
   - Cache results in oracle/data/ with 24-hour TTL
   - Enrich with CVSS v3.1 scores, vectors, and descriptions

2. Vulnerability correlation:
   - Match nmap service/version output against CVE database
   - Calculate exploitability score based on:
     * CVSS base score
     * Attack vector (network > adjacent > local)
     * Attack complexity (low > high)
     * Privileges required (none > low > high)
   - Produce a prioritized vulnerability list

3. Remediation intelligence:
   - For each CVE, fetch and display:
     * Recommended patches or mitigations
     * CISA KEV (Known Exploited Vulnerabilities) status
     * Vendor advisories (links)
   - Flag CISA KEV vulnerabilities prominently

4. Executive summary generation:
   - Input: list of CVEs with scores
   - Output: plain-English risk summary suitable for non-technical
     stakeholders
   - Include: risk level, key findings, recommended priorities

Integrate into plugins/nmap/ CVE correlation step.
```

---

### Prompt 4.2 — Passive Intelligence Gathering

```
Implement passive OSINT gathering as a Community Edition exclusive.
No active probing — purely passive intelligence from public sources.

Create: oracle/plugins/passive/ directory with:

1. dns_intelligence.py:
   - DNS record enumeration (A, AAAA, MX, TXT, NS, SOA, CNAME)
   - Subdomain enumeration via certificate transparency logs
     (query crt.sh API: https://crt.sh/?q={domain}&output=json)
   - DNS history lookup
   - All results stored in evidence graph

2. shodan_passive.py (if SHODAN_API_KEY configured):
   - Host lookup by IP
   - Domain search
   - Parse open ports and services from Shodan data
   - Mark all results as "passive_intelligence" in evidence graph

3. whois_intelligence.py:
   - WHOIS data for domains and IP ranges
   - ASN lookup
   - Netblock identification
   - Registrar and registration date

4. ssl_intelligence.py:
   - Certificate details without connecting (via crt.sh)
   - Certificate transparency monitoring
   - Subject alternative names for subdomain discovery

All passive plugins must:
- Mark their evidence as source="passive_osint"
- Never make direct connections to target systems
- Work entirely from public data sources
- Include data source attribution in evidence nodes
```

---

### Prompt 4.3 — Attack Surface Visualization

```
Build an attack surface visualization system for Community Edition.
This is a key differentiator — showing users what ORACLE discovered
in a compelling visual format.

1. Terminal visualization (always available):
   Update oracle/cli/dashboard.py to show:
   - Live evidence graph as ASCII tree during mission
   - CVE severity heatmap
   - Service/port matrix
   - Risk score timeline

2. HTML report generation:
   Update core/reporting/intelligence_report.py to produce
   a self-contained HTML report with:
   - Interactive network graph (use D3.js via CDN)
   - CVE table sortable by severity
   - Service fingerprint summary
   - Attack surface map
   - Timeline of discovery
   - Audit trail summary
   
   The HTML file must be fully self-contained (no external dependencies
   after generation) and work offline.

3. Evidence graph export:
   Add oracle/cli/export.py command:
   oracle export --mission <id> --format [html|json|pdf]
   
   Each format must be production quality — something a security
   engineer would be proud to put in a client report.
```

---

## PHASE 5 — Onboarding & Developer Experience

### Prompt 5.1 — Installation Script

```
Create scripts/install.sh — a complete one-command installer
for ORACLE Community Edition on:
- Kali Linux (primary)
- Ubuntu 22.04/24.04
- Debian 12
- macOS (secondary support)

The installer must:
1. Detect OS and version
2. Install system dependencies (nmap, python3, git)
3. Create Python virtual environment
4. Install Python dependencies
5. Initialize .oracle/ directory structure
6. Run oracle doctor to verify installation
7. Display quick start guide on completion

Also create oracle/cli/doctor.py (or update if exists):
- Checks all dependencies are installed
- Verifies nmap is available and correct version
- Tests Ollama connection if OLLAMA_HOST set
- Tests Anthropic API if ANTHROPIC_API_KEY set
- Verifies database is initialized
- Verifies scope enforcement is active
- Returns clear PASS/FAIL for each check

Run: oracle doctor
Output format:
  ✓ Python 3.11+
  ✓ nmap 7.94
  ✓ Database initialized
  ✓ Scope enforcement active
  ✗ Ollama: not reachable (set OLLAMA_HOST or install Ollama)
  ✓ Audit chain: operational
  
  ORACLE Community Edition ready. 5/6 checks passed.
  Run 'oracle demo' to verify end-to-end functionality.
```

---

### Prompt 5.2 — Community Demo Mode

```
Update oracle/demos/demo_mission.py for Community Edition.

The Community demo must:

1. Work with zero configuration (no API keys, no Ollama required):
   - Use oracle/core/local_fallback.py for AI decisions
   - Use built-in mock network data (no live scanning)

2. Showcase Community Edition's genuine value:
   - Run passive intelligence gathering on a mock domain
   - Run nmap against a local mock target (127.0.0.1 loopback)
   - Show CVE correlation and intelligence enrichment
   - Show the AI council deliberating on findings
   - Show the evidence graph building in real time
   - Trigger the Pro gate naturally on a "critical" finding
   - Generate a complete HTML report

3. Demo flow (total time: under 3 minutes):
   [0:00] Banner and scope acknowledgment
   [0:15] Passive OSINT gathering (mock domain)
   [0:45] Network recon (loopback mock)
   [1:15] CVE correlation and enrichment
   [1:45] AI council analysis
   [2:15] Pro gate trigger (dramatic pause, clear upsell)
   [2:30] Report generation
   [2:45] Summary and next steps

4. The demo report must be impressive enough to share with
   potential customers. Save to: .oracle-artifacts/reports/community_demo.html

5. End with:
   ═══════════════════════════════════════════════
   ORACLE Community Edition Demo Complete
   
   Discovered: 12 services, 3 critical CVEs
   Exploit pathways: 3 identified (Pro required to execute)
   Report: .oracle-artifacts/reports/community_demo.html
   
   Unlock full execution: nullsec.io/pro
   ═══════════════════════════════════════════════
```

---

## PHASE 6 — Legal & Compliance Integration

### Prompt 6.1 — Legal Framework Integration

```
Integrate the NULLSEC legal framework into ORACLE Community Edition.

1. Add these files to the project root (they already exist — verify
   they are present and correctly formatted):
   - LICENSE.md (BUSL 1.1)
   - TERMS_OF_SERVICE.md
   - ACCEPTABLE_USE_POLICY.md

2. First-run acceptance flow in oracle/cli/main.py:
   On first run, before anything else:
   
   ┌─────────────────────────────────────────────────────────┐
   │         ORACLE Community Edition — First Run            │
   │                                                         │
   │  ORACLE is a professional security tool for authorized  │
   │  penetration testing and security research only.        │
   │                                                         │
   │  By continuing you confirm:                             │
   │  ✓ You will only target systems you own or are          │
   │    explicitly authorized to test                        │
   │  ✓ You have read the Terms of Service                   │
   │  ✓ You agree to the Acceptable Use Policy               │
   │                                                         │
   │  Full terms: https://nullsec.io/terms                   │
   └─────────────────────────────────────────────────────────┘
   
   Type "I AGREE" to continue: 

3. Store acceptance in .oracle/acceptance.json with:
   - Timestamp of acceptance
   - ORACLE version accepted
   - Hash of ToS version accepted

4. The acceptance is logged to the audit chain as the first entry
   in every installation's audit history.

5. Add --skip-legal flag for CI/automated environments only,
   which requires ORACLE_ACCEPT_TERMS=true environment variable.
```

---

## PHASE 7 — Documentation for Public GitHub

### Prompt 7.1 — Community README

```
Create README.md for ORACLE Community Edition.

Structure:
1. Logo placeholder comment + ORACLE headline
2. Badges: Python 3.11+, License BUSL 1.1, Version 1.0.0
3. Tagline: "Mythos proved it. ORACLE lets you own it."
4. Description (3 sentences max): what ORACLE is, who it's for,
   what makes it different
5. Feature list (8 items, one line each):
   - Autonomous multi-agent recon
   - AI council with 5-agent consensus voting
   - Cryptographic audit chain (tamper-evident)
   - Evidence intelligence graph with TTL decay
   - CVE correlation and OSINT enrichment  
   - Passive intelligence gathering
   - Attack surface visualization and HTML reporting
   - Scope enforcement with operator-defined boundaries
6. Quick Start (5 commands):
   git clone, install, oracle doctor, oracle scope add, oracle demo
7. Architecture overview (one ASCII diagram)
8. Configuration (key env vars table)
9. Plugin development (link to docs/)
10. Community vs Pro comparison table
11. License section
12. NULLSEC contact and links

Tone: senior security engineer writing for peers.
No hype. Confident technical precision.
Max 400 lines.
```

---

### Prompt 7.2 — Contributing Guide & Security Policy

```
Create two documents:

1. CONTRIBUTING.md:
   - How to report bugs
   - How to submit pull requests
   - Code style requirements (PEP8, type hints required)
   - Plugin development guide:
     * Must implement OraclePlugin interface
     * Must include scope validation
     * Must be classified as passive/active/destructive
     * Must include tests
     * Destructive plugins will not be merged to Community Edition
   - Contributor license agreement (contributions become NULLSEC IP)
   - Code of conduct (professional, security community standard)

2. SECURITY.md:
   - Responsible disclosure policy for ORACLE itself
   - Contact: security@nullsec.io
   - PGP key: [placeholder]
   - Response timeline: 48h acknowledgment, 90 days remediation
   - Scope of what counts as a vulnerability in ORACLE
   - Out of scope: vulnerabilities in targets discovered BY ORACLE
   - Safe harbor: good-faith researchers will not be pursued legally
   - Hall of fame for credited researchers
```

---

## PHASE 8 — Final Testing & GitHub Preparation

### Prompt 8.1 — Community Edition Test Suite

```
Adapt the test suite for Community Edition:

1. Remove or mock any tests that require Pro features
2. Add tests specific to Community Edition:
   - test_edition.py: verify is_community() returns True
   - test_pro_gate.py: verify gate fires on critical CVE
   - test_pro_gate.py: verify gate cannot be bypassed
   - test_legal_acceptance.py: verify first-run flow works
   - test_scope_guard_defaults.py: verify default-deny works
   - test_demo_mode.py: demo completes without errors

3. Run full test suite:
   pytest tests/ -v --tb=short

4. Verify the demo runs clean:
   python -m oracle.cli.main --demo --quick

5. Verify doctor passes all checks (except optional ones):
   python -m oracle.cli.main doctor

All tests must pass before release.
```

---

### Prompt 8.2 — GitHub Repository Preparation

```
Prepare the repository for public GitHub release:

1. Verify .gitignore is comprehensive:
   .oracle/
   .oracle-artifacts/
   .env
   *.key
   *.pem
   __pycache__/
   *.pyc
   .pytest_cache/
   .aider*
   .claude/
   dist/
   *.egg-info/

2. Create .github/workflows/ci.yml:
   - Run on push and pull_request to main
   - Jobs: lint (flake8), test (pytest), security-scan (bandit)
   - Python versions: 3.11, 3.12
   - Cache pip dependencies

3. Create .github/ISSUE_TEMPLATE/bug_report.md
   and .github/ISSUE_TEMPLATE/feature_request.md

4. Create .github/PULL_REQUEST_TEMPLATE.md

5. Final git operations:
   git add -A
   git status  # Review everything being committed
   git commit -m "feat: ORACLE Community Edition v1.0.0 — public release"
   git tag -a community-v1.0.0 -m "ORACLE Community Edition v1.0.0"

6. Verify no sensitive files are staged:
   git diff --cached --name-only

Report: READY FOR PUBLIC GITHUB or list blockers.
```

---

## FINAL CHECKLIST — Before Pushing to GitHub

Before `git push`, manually verify:

```
[ ] oracle doctor passes
[ ] oracle --demo runs without errors
[ ] Pro gate fires on critical CVE discovery
[ ] No real credentials or secrets in codebase
[ ] LICENSE.md present and correct
[ ] TERMS_OF_SERVICE.md present
[ ] ACCEPTABLE_USE_POLICY.md present
[ ] README.md complete
[ ] CONTRIBUTING.md present
[ ] SECURITY.md present
[ ] All tests pass
[ ] .gitignore covers all sensitive paths
[ ] First-run legal acceptance flow works
[ ] Scope guard defaults to DENY
```

---

*NULLSEC // ORACLE Community Edition Build Workflow*
*Document Version 1.0 // Use with Claude Code (claude-sonnet-4-5)*
*Complete V4 Pro workflow first before running this workflow.*
