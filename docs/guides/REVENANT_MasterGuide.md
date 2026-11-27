# 🧙‍♂️ Welcome to REVENANT — The Complete Beginner's Spellbook
### *"It is our choices, Harry, that show what we truly are, far more than our abilities."*
### — Albus Dumbledore (also, sound advice for reading source code)

---

> **Professor's Note:** This guide assumes you know *almost nothing*. Every concept is explained
> from scratch with real-world analogies before we touch a single line of code. Read it top to bottom,
> once, without skipping. By the end you will understand this entire project.

---

## 📖 Table of Contents

1. [What Is REVENANT? (The One-Paragraph Spell)](#1-what-is-revenant)
2. [The Big Picture — How Everything Connects](#2-the-big-picture)
3. [Technologies Used — Your Spell Components](#3-technologies-used)
4. [Layer 1 — The Entry Point (revenant.py)](#4-layer-1-entry-point)
5. [Layer 2 — The Control Plane (The Ministry of Magic)](#5-layer-2-control-plane)
6. [Layer 3 — The Blackboard (The Magical Bulletin Board)](#6-layer-3-the-blackboard)
7. [Layer 4 — The Orchestrator (The Headmaster)](#7-layer-4-the-orchestrator)
8. [Layer 5 — The Agents (The 15 Professors)](#8-layer-5-the-agents)
9. [Layer 6 — The Adapters (The Magical Tools)](#9-layer-6-the-adapters)
10. [Layer 7 — Attack Graph & Reporting (The Final Exam Report)](#10-layer-7-attack-graph--reporting)
11. [Layer 8 — Docker Deployment (The Hogwarts Castle)](#11-layer-8-docker-deployment)
12. [The Complete Data Flow — One Story, Start to Finish](#12-the-complete-data-flow)
13. [File Reading Order — Your Study Schedule](#13-file-reading-order)
14. [Self-Quiz — Are You Ready for the N.E.W.T.s?](#14-self-quiz)
15. [Quick Command Reference](#15-quick-command-reference)

---

## 1. What Is REVENANT?

Imagine you're a security company hired to hack a client's website — legally, with permission — to find
weaknesses before real attackers do. This is called **penetration testing** (pentest).

Normally, a human security expert would:
1. Map the target (what servers are running? what ports are open?)
2. Look for web vulnerabilities (XSS, SQL injection, open redirects...)
3. Check cloud misconfiguration (is that AWS S3 bucket public?)
4. Check Active Directory (can I steal credentials? escalate privileges?)
5. Write a big report of everything found

**REVENANT does ALL of this automatically, with AI.**

It coordinates **15 specialized AI agents** (think of them as expert professors each with a specialty)
who work together through a shared bulletin board (the **Blackboard**). Each agent uses real industry
security tools (Nmap, YARA, Katana, Semgrep, etc.) and reports findings in 5 professional formats.

> **In one sentence:** REVENANT is an autonomous robot hacker that coordinates 15 AI specialists, runs
> 66+ real security tools, and produces professional vulnerability reports — all within legally
> authorized boundaries.

---

## 2. The Big Picture

Before we touch code, here is the entire system in one diagram. Memorize this shape:

```
┌─────────────────────────────────────────────────────────────┐
│                     YOU (the operator)                       │
│               python revenant.py scan --target ...          │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                   CONTROL PLANE                              │
│  (FastAPI REST API — receives commands, validates scope)     │
│  Files: control-plane/control_plane/                        │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                   ORCHESTRATOR                               │
│  (The brain — runs the main agent loop)                     │
│  Files: orchestrator/engine.py                              │
└───────────┬───────────────────────────────┬─────────────────┘
            │                               │
            ▼                               ▼
┌───────────────────────┐     ┌─────────────────────────────┐
│      BLACKBOARD        │◄────│        15 AGENTS            │
│  (Shared event bus)   │────►│  (Specialist AI professors) │
│  orchestrator/         │     │  orchestrator/agents/       │
│  blackboard.py        │     └──────────────┬──────────────┘
└───────────────────────┘                    │
                                             ▼
                              ┌──────────────────────────────┐
                              │         ADAPTERS             │
                              │  (Wrappers for real tools)   │
                              │  adapters/                   │
                              │  Nmap, YARA, Katana,         │
                              │  Semgrep, Certipy, etc.      │
                              └──────────────┬───────────────┘
                                             │
                                             ▼
                              ┌──────────────────────────────┐
                              │     ATTACK GRAPH + REPORTING │
                              │  (Correlate findings,        │
                              │   generate 5-format reports) │
                              │  orchestrator/correlation/   │
                              │  reporting/                  │
                              └──────────────────────────────┘
```

Every layer talks to the one below it. Data flows DOWN. Events flow UP through the Blackboard.

---

## 3. Technologies Used — Your Spell Components

Think of these as the ingredients in your potion. You need to know what each does.

### 🐍 Python 3.11+
The primary language of REVENANT. Every agent, adapter, and the control plane API is Python.

**What you need to know:**
- Classes and inheritance (`class ReconAgent(BaseAgent)`)
- Abstract classes (`ABC`, `@abstractmethod`)
- Type hints (`def run(self, target: str) -> AdapterResult`)
- `subprocess` module (how Python runs external programs like Nmap)

---

### 📦 Pydantic
A Python library that validates data structures automatically.

**Real-world analogy:** A Pydantic model is like a form with required fields. If you submit the form
without filling a required field, it rejects it immediately with a clear error.

```python
# Example: This is how a "Finding" (a discovered vulnerability) is defined
class Finding(BaseModel):
    id: str              # required — unique ID for this finding
    title: str           # required — e.g. "XSS in Login Form"
    severity: str        # required — CRITICAL / HIGH / MEDIUM / LOW / INFO
    target: str          # required — what was attacked
    description: str     # required — what was found
```

If any code tries to create a `Finding` without a `title`, Pydantic throws an error instantly.
This prevents bugs from silently propagating through the system.

**Key file:** `control-plane/control_plane/schemas/models.py`

---

### ⚡ FastAPI
A modern Python web framework for building REST APIs. The Control Plane uses FastAPI to expose
REVENANT's functionality over HTTP.

**Real-world analogy:** FastAPI is like a hotel front desk. You (the client) walk up and say
"I want to start a scan." The front desk (FastAPI) takes your request, validates it, passes it
to the back office (Orchestrator), and returns a receipt (job ID).

---

### 🗄️ SQLite (in the Blackboard)
A lightweight database file. The Blackboard uses SQLite to save events, findings, and assets so
that if the system crashes mid-mission, it can pick up where it left off.

---

### 🐳 Docker & Docker Compose
Containers that package the application and all its dependencies into isolated boxes. REVENANT
runs as 4 containers: control-plane, worker, postgres, redis.

**Real-world analogy:** Docker is like shipping containers. You pack everything the app needs
(code, libraries, config) into a container. It runs identically on any machine.

---

### 🔬 pytest
The testing framework. REVENANT has 234 tests across 25 test files — one set per milestone.
Tests are your best learning tool because they show the code WORKING with real inputs/outputs.

---

### 🛡️ Security Tools (the real ones!)
REVENANT wraps real, industry-standard security tools. Here are the key ones:

| Tool | Category | What It Does |
|------|----------|--------------|
| **Nmap** | Recon | Scans ports, detects services on hosts |
| **httpx** | Recon | Probes HTTP endpoints, fingerprints tech |
| **Subfinder** | Recon | Discovers subdomains passively |
| **ffuf** | Web | Fuzzes web endpoints (finds hidden URLs) |
| **Katana** | Web | Crawls websites, discovers all links/parameters |
| **Semgrep** | SAST | Scans source code for security bugs |
| **Gitleaks/TruffleHog** | SAST | Finds secrets (API keys, passwords) in code |
| **Nuclei** | DAST | Runs vulnerability templates against live targets |
| **YARA** | Malware | Detects malware patterns in files |
| **Trivy** | Cloud | Scans Docker images for CVEs |
| **Checkov** | Cloud | Audits Terraform/Kubernetes for misconfigs |
| **Prowler** | Cloud | Audits AWS/Azure security posture |
| **NetExec (NXC)** | Identity | Attacks Windows/AD environments |
| **BloodHound** | Identity | Maps Active Directory attack paths |
| **Certipy** | Identity | Exploits AD Certificate Services (ESC1–ESC8) |
| **Schemathesis** | API | Fuzzes REST APIs using their OpenAPI spec |
| **Volatility3** | Forensics | Analyzes Windows/Linux memory dumps |
| **Velociraptor** | Forensics | Live endpoint forensics and triage |
| **Binwalk** | Firmware | Extracts and analyzes firmware images |
| **AFL++** | Fuzzing | Fuzzes binaries to find crashes |
| **Caldera** | Purple | Simulates adversary tactics (MITRE ATT&CK) |
| **Atomic Red Team** | Purple | Runs ATT&CK technique simulations |
| **MobSF** | Mobile | Analyzes Android/iOS apps for vulnerabilities |

---

## 4. Layer 1 — The Entry Point

**File:** [`revenant.py`](file:///d:/REVENANT/revenant.py)

This is the simplest file in the entire project. Only 21 lines. It exists for one reason:
to make sure Python can find all the other modules, then hand off to the real CLI.

```python
# It adds the project root and control-plane to Python's search path:
for p in [str(ROOT_DIR), str(CONTROL_PLANE_DIR)]:
    if p not in sys.path:
        sys.path.insert(0, p)

# Then calls the real CLI:
from control_plane.cli import main
main()
```

**Analogy:** `revenant.py` is the Hogwarts Express platform. It gets you from London to Hogwarts.
The real magic happens once you arrive.

**How to use it:**
```bash
python revenant.py --help                   # See all commands
python revenant.py profiles                 # List mission profiles
python revenant.py scan --target http://x   # Launch a scan
```

---

## 5. Layer 2 — The Control Plane (The Ministry of Magic)

**Folder:** `control-plane/control_plane/`

The Control Plane is the "face" of REVENANT. It's a FastAPI REST API that:
1. Receives requests from operators (via CLI or HTTP)
2. Validates that the target is in the authorized scope
3. Launches the Orchestrator to run the actual mission
4. Returns findings and reports

### 5.1 The Most Important Concept: Scope Enforcement

> ⚠️ **The #1 safety mechanism of REVENANT.**

Before ANYTHING runs — before any tool is launched, before any network packet is sent —
REVENANT checks: "Is this target in the authorized scope manifest?"

If not, it throws a `ScopeViolationError` and **refuses to proceed**.

**File:** `control-plane/control_plane/schemas/scope.py`

```python
# The scope manifest is a simple config: what are you allowed to attack?
class ScopeManifest(BaseModel):
    allowed_hosts: List[str]      # e.g. ["example.com", "192.168.1.0/24"]
    allowed_ports: List[int]      # e.g. [80, 443, 8080]
    max_depth: int = 3            # How deep to crawl

# The ScopeEngine enforces it:
class ScopeEngine:
    def validate_or_raise(self, target: str) -> None:
        if not self._is_in_scope(target):
            raise ScopeViolationError(f"Target {target} is out of scope!")
```

**Analogy:** The scope manifest is like your "Rules of Engagement" document in a real pentest.
Before firing a single probe, you check if the target is on the approved list.

Scope is checked at **3 layers** (defense in depth):
- Layer 1: Control Plane (when mission is submitted)
- Layer 2: Orchestrator (when campaign starts)
- Layer 3: Each Adapter (right before running a tool)

Even if someone hacked layers 1 and 2, layer 3 would still refuse.

### 5.2 Core Data Models

**File:** `control-plane/control_plane/schemas/models.py`

These are the universal data types used everywhere in the project:

```
Finding      — A discovered vulnerability
  ├── id           (unique UUID)
  ├── title        ("XSS in /login endpoint")
  ├── severity     (CRITICAL/HIGH/MEDIUM/LOW/INFO)
  ├── target       ("https://example.com/login")
  ├── tool         ("dast-fuzzer")
  ├── mitre_id     ("T1059.007")    ← Maps to MITRE ATT&CK framework
  └── description  (full details)

HostAsset    — A discovered machine/server
  ├── id           (unique UUID)
  ├── ip           ("192.168.1.5")
  ├── hostname     ("api.example.com")
  ├── ports        [PortInfo(port=443, service="https")]
  └── endpoints    [WebEndpoint(url="https://api.example.com/v1")]

PortInfo     — A single open port on a host
  ├── port         (443)
  ├── service      ("https")
  └── version      ("nginx/1.24")

WebEndpoint  — A single HTTP endpoint
  ├── url          ("https://example.com/admin")
  ├── status_code  (200)
  ├── title        ("Admin Dashboard")
  └── tech_stack   (["React", "nginx"])
```

**Why this matters:** EVERY adapter, EVERY agent, EVERY report generator works with these
exact same types. There's one universal language for vulnerabilities and assets in REVENANT.

---

## 6. Layer 3 — The Blackboard (The Magical Bulletin Board)

**File:** [`orchestrator/blackboard.py`](file:///d:/REVENANT/orchestrator/blackboard.py)

This is the **most architecturally important** file in the project. Read it carefully.

### The Problem It Solves

Imagine you have 15 specialist professors. How do they coordinate?

Bad way: Professor A calls Professor B directly, B calls C, C calls D... This creates a
mess of direct dependencies. If B changes, A breaks.

Good way (what REVENANT does): There's a big bulletin board in the common room. Each
professor writes notes (events) on the board. Other professors check the board, see relevant
notes, and act on them — without ever talking to each other directly.

This pattern is called **Stigmergic Blackboard Architecture**. "Stigmergic" means
"coordination through the environment" (how ants leave pheromone trails rather than talking).

### Events — The Notes on the Bulletin Board

Every note on the Blackboard is a `BlackboardEvent`:

```python
class BlackboardEvent(BaseModel):
    id: str            # Unique ID for this event
    event_type: EventType   # WHAT happened (see below)
    source_agent: str       # WHO posted it ("recon-agent")
    target: str             # WHAT it's about ("https://example.com")
    payload: dict           # Extra details (JSON data)
    timestamp: datetime     # WHEN it happened
    handled_by: List[str]   # Which agents have already reacted to it
```

### Event Types — The Types of Notes

```python
class EventType(Enum):
    TARGET_REGISTERED         # "New target added to mission"
    HOST_DISCOVERED           # "Found a server at 192.168.1.5"
    PORT_OPEN                 # "Port 443 is open on that server"
    HTTP_ENDPOINT             # "Found a web page at /admin"
    TECH_DETECTED             # "Server is running nginx 1.24"
    SECRET_EXPOSED            # "Found AWS key in source code!"
    CRAWL_COMPLETED           # "Katana finished crawling the site"
    DAST_CANDIDATE            # "This endpoint looks testable for XSS"
    CLOUD_ASSET_DISCOVERED    # "Found an S3 bucket"
    IDENTITY_ASSET_DISCOVERED # "Found an Active Directory domain"
    VULNERABILITY_CANDIDATE   # "Possible vulnerability found"
    VULNERABILITY_CONFIRMED   # "Vulnerability confirmed — real finding!"
    CAMPAIGN_COMPLETE         # "All agents done, mission over"
    # ... 15+ more event types
```

### The 4 Key Methods

```python
class Blackboard:

    def post_event(self, event: BlackboardEvent) -> None:
        # Adds an event to the board + saves to SQLite database
        # Think: "Professor writes a note on the board"

    def get_events(self, event_type=None) -> List[BlackboardEvent]:
        # Returns all events, optionally filtered by type
        # Think: "Read all notes of a specific type"

    def get_unhandled_events(self, agent_name: str) -> List[BlackboardEvent]:
        # Returns events this specific agent hasn't reacted to yet
        # Think: "Show me notes I haven't read yet"

    def mark_handled(self, event_id: str, agent_name: str) -> None:
        # Records that this agent has handled this event
        # Think: "Put a checkmark next to the note"
```

### Why SQLite?

Events are saved to disk. If the system crashes mid-mission (during a 10-hour full-spectrum scan),
you don't lose everything. The Blackboard can reload from disk and resume.

---

## 7. Layer 4 — The Orchestrator (The Headmaster)

**File:** [`orchestrator/engine.py`](file:///d:/REVENANT/orchestrator/engine.py)

The Orchestrator is the "main loop" of REVENANT. It:
1. Takes a target and scope
2. Creates the initial event ("we have a new target!")
3. Keeps looping: ask each agent "do you want to handle any unhandled events?"
4. Stops when nobody does anything new (the swarm has "quiesced")

Here is the actual `start_campaign` logic, simplified:

```python
def start_campaign(self, target: str, scope: ScopeManifest) -> dict:

    # Step 1: Safety check — is the target in scope?
    ScopeEngine(scope).validate_or_raise(target)

    # Step 2: Post the first event — "new target registered"
    self.blackboard.post_event(BlackboardEvent(
        event_type=EventType.TARGET_REGISTERED,
        source_agent="orchestrator",
        target=target,
    ))

    # Step 3: The main loop — runs up to 25 iterations
    while iteration < 25:
        events_acted_on = 0

        for agent in self.agents:
            for event in blackboard.get_unhandled_events(agent.name):
                blackboard.mark_handled(event.id, agent.name)

                if agent.can_handle(event):
                    new_events = agent.handle(event, blackboard, scope)
                    for e in new_events:
                        blackboard.post_event(e)
                    events_acted_on += 1

        if events_acted_on == 0:
            break  # Nobody did anything new → mission complete!

    return blackboard.get_summary()
```

**The cascade effect:** ReconAgent posts `HOST_DISCOVERED` → WebAgent picks it up, posts
`HTTP_ENDPOINT` → DastAgent picks it up, posts `VULNERABILITY_CONFIRMED`. Each agent triggers
the next one through the Blackboard, without anyone orchestrating it manually.

---

## 8. Layer 5 — The Agents (The 15 Professors)

**Folder:** [`orchestrator/agents/`](file:///d:/REVENANT/orchestrator/agents/)

Every agent has the exact same contract (interface):

```python
class BaseAgent(ABC):          # ABC = Abstract Base Class

    def __init__(self, name: str, role: str):
        self.name = name       # "recon-agent"
        self.role = role       # "Network & HTTP Reconnaissance"

    @abstractmethod
    def can_handle(self, event: BlackboardEvent) -> bool:
        # "Does this event belong to me?"
        # If True, the Orchestrator will call handle()
        pass

    @abstractmethod
    def handle(self, event, blackboard, scope) -> List[BlackboardEvent]:
        # "Do my thing and return new events for the Blackboard"
        pass
```

**Analogy:** `can_handle` is like each professor raising their hand when a topic they know
comes up. `handle` is them giving the lecture.

### The 15 Agents — Complete Roster

| # | Agent | Listens For | Does |
|---|-------|-------------|------|
| 1 | **ReconAgent** | `TARGET_REGISTERED` | Runs httpx + Subfinder to map the attack surface |
| 2 | **CrawlAgent** | `HTTP_ENDPOINT` | Runs Katana to crawl websites and find all links |
| 3 | **WebAgent** | `CRAWL_COMPLETED` | Probes endpoints for web vulnerabilities |
| 4 | **DastAgent** | `DAST_CANDIDATE` | Runs DAST fuzzer for XSS, open redirects, traversal |
| 5 | **ApiAgent** | `HTTP_ENDPOINT` | Runs Schemathesis to fuzz REST APIs |
| 6 | **CodeAgent** | `REPO_DISCOVERED` | Runs Gitleaks + Semgrep to scan source code |
| 7 | **CloudAgent** | `CLOUD_ASSET_DISCOVERED` | Runs Trivy + Checkov + Prowler for cloud posture |
| 8 | **IdentityAgent** | `IDENTITY_ASSET_DISCOVERED` | Runs NetExec + Certipy for AD attacks |
| 9 | **AiRedTeamAgent** | `AI_ENDPOINT_DISCOVERED` | Tests AI/LLM systems for prompt injection |
| 10 | **MobileAgent** | `MOBILE_APP_DISCOVERED` | Runs MobSF for Android/iOS app analysis |
| 11 | **PurpleAgent** | `TTP_EMULATED` | Runs Caldera + Atomic Red Team simulations |
| 12 | **KubernetesAgent** | `CONTAINER_DISCOVERED` | Runs Kubescape + Kube-bench for K8s posture |
| 13 | **ForensicsAgent** | `FORENSICS_ARTIFACT_DISCOVERED` | Runs Volatility3 + Velociraptor |
| 14 | **MalwareAgent** | `VULNERABILITY_CONFIRMED` | Runs YARA + CAPEv2 sandbox |
| 15 | **TriageAgent** | `VULNERABILITY_CONFIRMED` | Scores findings by severity, deduplicates |

### A Real Agent Walk-Through: ReconAgent

```python
class ReconAgent(BaseAgent):

    def __init__(self):
        super().__init__(name="recon-agent", role="Network & HTTP Reconnaissance")
        self.httpx = HTTPXAdapter()
        self.subfinder = SubfinderAdapter()

    def can_handle(self, event: BlackboardEvent) -> bool:
        return event.event_type == EventType.TARGET_REGISTERED

    def handle(self, event, blackboard, scope) -> List[BlackboardEvent]:
        target = event.target
        new_events = []

        # 1. Find subdomains
        result = self.subfinder.run(target, scope)
        for asset in result.discovered_assets:
            blackboard.add_asset(asset)
            new_events.append(BlackboardEvent(
                event_type=EventType.HOST_DISCOVERED,
                target=asset.hostname,
            ))

        # 2. Probe HTTP endpoints
        result = self.httpx.run(target, scope)
        for endpoint in result.endpoints:
            new_events.append(BlackboardEvent(
                event_type=EventType.HTTP_ENDPOINT,
                target=endpoint.url,
            ))

        return new_events   # Post these back to the Blackboard
```

The ReconAgent posts `HOST_DISCOVERED` and `HTTP_ENDPOINT` events. These then trigger CrawlAgent and
WebAgent automatically, without ReconAgent knowing or caring about their existence.

---

## 9. Layer 6 — The Adapters (The Magical Tools)

**Folder:** [`adapters/`](file:///d:/REVENANT/adapters/)

An adapter is a Python class that wraps ONE external security tool (like Nmap) and normalizes
its output into REVENANT's standard `Finding` and `HostAsset` objects.

**Analogy:** Think of adapters like electrical outlet adapters. A UK plug won't work in a US socket.
An adapter converts the UK plug to US format. Similarly, Nmap outputs XML, YARA outputs text,
Semgrep outputs JSON — the adapter converts all of them to REVENANT's universal format.

### The Adapter Contract — 4 Methods Every Adapter Must Have

```python
class BaseAdapter(ABC):

    def build_command(self, target: str, params: dict) -> List[str]:
        # Returns the CLI command to run the tool
        # Example: ["nmap", "-sV", "-oX", "/tmp/out.xml", "192.168.1.5"]
        pass

    def parse_output(self, stdout: str, stderr: str, target: str):
        # Parses the tool's raw output
        # Returns: (List[Finding], List[HostAsset])
        pass

    def run(self, target: str, scope: ScopeManifest) -> AdapterResult:
        # The main method — called by agents
        # 1. Check scope (REFUSES if out of scope — cannot be bypassed)
        # 2. Call build_command()
        # 3. Run it with subprocess.run()
        # 4. Call parse_output()
        # 5. Return AdapterResult
        pass
```

### The AdapterResult — What Comes Back

```python
class AdapterResult(BaseModel):
    tool_name: str                    # "nmap"
    target: str                       # "192.168.1.5"
    exit_code: int                    # 0 = success
    duration_seconds: float           # how long it took
    findings: List[Finding]           # vulnerabilities found
    discovered_assets: List[HostAsset]  # servers/endpoints found
    raw_stdout: str                   # raw tool output (for debugging)
    raw_stderr: str                   # raw tool errors
    error: Optional[str]              # error message if something went wrong
```

### Adapter Categories

```
adapters/
├── network/      Nmap (port scanning)
├── recon/        httpx (HTTP probing), subfinder (subdomain discovery)
├── web/          Katana (crawling), ffuf (endpoint fuzzing), dast_adapter (XSS fuzzer)
├── sast/         Semgrep (code analysis), Gitleaks, TruffleHog (secret scanning)
├── api/          Schemathesis (OpenAPI fuzzing)
├── cloud/        Trivy (CVE scanning), Checkov (IaC auditing), Prowler (AWS posture)
├── identity/     NetExec (AD attacks), Certipy (AD CS attacks)
├── malware/      YARA (pattern matching), CAPEv2 (sandbox)
├── forensics/    Volatility3 (memory), Velociraptor (endpoint triage)
├── firmware/     Binwalk (firmware extraction), AFL++ (fuzzing)
├── mobile/       MobSF (static analysis), mobsfscan
├── kubernetes/   Kubescape, Kube-bench (CIS benchmarks), Falco (runtime)
├── purple/       Atomic Red Team, Caldera (adversary simulation)
├── fuzzing/      AFL++, ASan crash triage
└── soar/         Splunk Phantom, Cortex XSOAR webhooks
```

### WSL2 Bridge (Windows-specific magic)

Most security tools (Nmap, YARA, etc.) are Linux-only. You're on Windows. The adapters
have a built-in WSL2 bridge:

```python
if self.use_wsl and os.name == "nt":
    # Run the Linux tool inside WSL2 from Windows:
    exec_cmd = ["wsl.exe", "-d", "Ubuntu", "--", "nmap", "-sV", target]
```

This is why you see `use_wsl=True` in many adapters — they're Linux tools being called from
Windows via the WSL2 bridge automatically.

---

## 10. Layer 7 — Attack Graph & Reporting (The Final Exam Report)

**Folders:** `orchestrator/correlation/` and `reporting/`

After all agents finish, REVENANT does two more things:

### 10.1 Attack Graph — Connecting the Dots

**File:** `orchestrator/correlation/attack_graph_engine.py`

Individual findings are isolated facts. The attack graph connects them into a story:

```
Finding 1: Git secret leaked → AWS_ACCESS_KEY exposed (gitleaks, T1552.001)
                   ↓
Finding 2: S3 bucket is public-read (prowler, T1530)
                   ↓
Finding 3: XSS in login form (dast-fuzzer, T1059.007)
                   ↓
                ATTACK CHAIN:
         "Attacker steals AWS key from leaked Git secret,
          accesses S3 bucket, finds credentials stored there,
          uses XSS to attack users"
```

Key concepts:
- **GraphNode** — an asset or vulnerability (a dot on the graph)
- **GraphEdge** — a connection (how one finding enables another)
- **Choke Point** — a node with MANY edges through it — the highest priority fix.
  Fixing this one thing would break the most attack chains.

### 10.2 MITRE ATT&CK Mapping

Every finding is tagged with a MITRE ATT&CK technique ID (like `T1059.007`). MITRE ATT&CK
is the industry standard framework that catalogues how real attackers operate.

**File:** `reporting/mitre_mapper.py` — looks up technique names from IDs.

### 10.3 Report Generation — 5 Formats

**File:** `reporting/generator.py`

REVENANT outputs the same findings in 5 different formats for different audiences:

| Format | Audience | File |
|--------|----------|------|
| **Executive Markdown** | Management (easy to read) | `report.md` |
| **SARIF v2.1.0** | SIEM tools (automated processing) | `report.sarif` |
| **ATT&CK Navigator** | Security teams (visual heatmap) | `report.attack_nav.json` |
| **Faraday JSON** | Vulnerability management platform | `faraday.json` |
| **Dradis JSON** | Pentest reporting platform | `dradis.json` |

### 10.4 Autonomous Remediation

**Folder:** `orchestrator/remediation/`

For every confirmed vulnerability, REVENANT also generates the FIX:

| Vuln Type | Generated Fix |
|-----------|---------------|
| S3 bucket public | Terraform `.tf` file to lock it down |
| K8s missing network policy | YAML NetworkPolicy manifest |
| Windows SMBv1 enabled | Ansible playbook to disable it |
| Webshell detected | YARA rule to detect future uploads |
| Malware behavior | Sigma rule for SIEM detection |

---

## 11. Layer 8 — Docker Deployment (The Hogwarts Castle)

**File:** `deployments/docker-compose.yml`

REVENANT in production runs as 4 containers talking to each other:

```
┌────────────────────────────────────────────────────────────┐
│                Docker Network: revenant-internal            │
│                                                            │
│  ┌──────────────────┐    ┌──────────────────────────────┐  │
│  │  control-plane   │    │         worker               │  │
│  │  FastAPI REST API│    │  Orchestrator + 15 Agents    │  │
│  │  Port 8000       │    │  Adapters + Tool Runners     │  │
│  └────────┬─────────┘    └────────────┬─────────────────┘  │
│           │                           │                    │
│           ▼                           ▼                    │
│  ┌──────────────────┐    ┌──────────────────────────────┐  │
│  │   PostgreSQL     │    │          Redis               │  │
│  │   + pgvector     │    │  Event queue / cache         │  │
│  │   Findings store │    │  Blackboard backend          │  │
│  │   Port 5432      │    │  Port 6379                   │  │
│  └──────────────────┘    └──────────────────────────────┘  │
└────────────────────────────────────────────────────────────┘
```

**Quick start:**
```bash
# 1. Configure secrets
cp deployments/.env.example deployments/.env

# 2. Start all 4 containers
docker compose -f deployments/docker-compose.yml up -d --build

# 3. Verify health
docker compose -f deployments/docker-compose.yml ps
curl http://localhost:8000/api/v1/health
```

---

## 12. The Complete Data Flow — One Story, Start to Finish

Let's trace exactly what happens when you run:
```bash
python revenant.py scan --target https://shop.example.com --profile web-dast
```

```
1. revenant.py
   └── Adds paths to sys.path, calls control_plane.cli.main()

2. control_plane/cli.py
   └── Parses arguments: target="https://shop.example.com", profile="web-dast"
   └── Loads scope manifest (which targets are authorized)
   └── Creates Orchestrator, calls orchestrator.start_campaign(target, scope)

3. orchestrator/engine.py — start_campaign()
   └── Layer 2 scope check: "is shop.example.com in scope?" → YES
   └── Posts BlackboardEvent(type=TARGET_REGISTERED, target="https://shop.example.com")

4. ITERATION 1 — The Blackboard loop begins

   ReconAgent.can_handle(TARGET_REGISTERED) → True
   ReconAgent.handle():
     └── SubfinderAdapter.run("shop.example.com", scope)
         └── Layer 3 scope check (again!) → OK
         └── subprocess.run(["subfinder", "-d", "shop.example.com", ...])
         └── Found: api.shop.example.com, admin.shop.example.com
     └── HTTPXAdapter.run("https://shop.example.com", scope)
         └── Found: 200 OK, nginx, /checkout /cart /api/v1
     └── Posts:
         - HOST_DISCOVERED (api.shop.example.com)
         - HOST_DISCOVERED (admin.shop.example.com)
         - HTTP_ENDPOINT (https://shop.example.com/checkout)
         - HTTP_ENDPOINT (https://shop.example.com/api/v1)

5. ITERATION 2

   CrawlAgent.can_handle(HTTP_ENDPOINT) → True
   CrawlAgent.handle():
     └── KatanaAdapter.run("https://shop.example.com/", scope)
         └── Found 47 more URLs, 12 form parameters
     └── Posts CRAWL_COMPLETED

   WebAgent.can_handle(CRAWL_COMPLETED) → True
   WebAgent.handle():
     └── Posts DAST_CANDIDATE for each endpoint with parameters

6. ITERATION 3

   DastAgent.can_handle(DAST_CANDIDATE) → True
   DastAgent.handle():
     └── DastAdapter.run("/search?q=", scope)
         └── Injects: <script>alert(1)</script>
         └── Server echoes it back → XSS CONFIRMED!
     └── blackboard.add_finding(Finding(
           title="Reflected XSS in /search",
           severity="HIGH",
           mitre_id="T1059.007"
         ))
     └── Posts VULNERABILITY_CONFIRMED

7. ITERATION 4

   TriageAgent.can_handle(VULNERABILITY_CONFIRMED) → True
   TriageAgent.handle():
     └── Scores severity, deduplicates, prioritizes findings

8. No more unhandled events → loop breaks (quiesced)

9. AttackGraphEngine.correlate(all_findings)
   └── Connects findings into attack chains
   └── Identifies choke points

10. ReportGenerator.generate(attack_graph, findings)
    └── Writes report.md, report.sarif, report.attack_nav.json
    └── Generates Terraform/Ansible remediation artifacts

11. Returns summary:
    {
      "total_findings": 7,
      "critical": 1, "high": 2, "medium": 4,
      "assets_discovered": 23,
      "report": "evidence/report.md"
    }
```

**You just traced the entire system from CLI command to final report.**

---

## 13. File Reading Order — Your Study Schedule

Read files in this EXACT order. Each file builds on the previous.

### Week 1 — Foundation (Days 1–5)

| Day | File | Why |
|-----|------|-----|
| 1 | [README.md](file:///d:/REVENANT/README.md) | Big picture, mission profiles, tool list |
| 1 | [revenant.py](file:///d:/REVENANT/revenant.py) | Entry point — only 21 lines, easy start |
| 2 | [pyproject.toml](file:///d:/REVENANT/pyproject.toml) | Dependencies, project config |
| 2 | [docs/ARCHITECTURE.md](file:///d:/REVENANT/docs/ARCHITECTURE.md) | System design document |
| 3 | [control-plane/control_plane/schemas/models.py](file:///d:/REVENANT/control-plane/control_plane/schemas/models.py) | **Core data types used everywhere** |
| 3 | [tests/test_scope.py](file:///d:/REVENANT/tests/test_scope.py) | Run: `pytest tests/test_scope.py -v -s` |
| 4 | [control-plane/control_plane/schemas/scope.py](file:///d:/REVENANT/control-plane/control_plane/schemas/scope.py) | Scope enforcement — the safety system |
| 5 | [orchestrator/blackboard.py](file:///d:/REVENANT/orchestrator/blackboard.py) | **The Blackboard — most important file** |
| 5 | [orchestrator/engine.py](file:///d:/REVENANT/orchestrator/engine.py) | The main loop — how agents are run |

### Week 2 — Adapters (Days 6–9)

| Day | File | Why |
|-----|------|-----|
| 6 | [adapters/base.py](file:///d:/REVENANT/adapters/base.py) | The template every adapter follows |
| 7 | `adapters/network/nmap_adapter.py` | Simplest adapter — study this first |
| 7 | `adapters/recon/httpx_adapter.py` | Second simplest |
| 8 | [adapters/web/ffuf_adapter.py](file:///d:/REVENANT/adapters/web/ffuf_adapter.py) | Web endpoint fuzzer |
| 8 | `adapters/web/dast_adapter.py` | In-process XSS fuzzer (no external binary) |
| 9 | [adapters/sast/trufflehog_adapter.py](file:///d:/REVENANT/adapters/sast/trufflehog_adapter.py) | Secret scanner |
| 9 | [adapters/api/schemathesis_adapter.py](file:///d:/REVENANT/adapters/api/schemathesis_adapter.py) | API fuzzer |
| 9 | `pytest tests/test_milestone3_adapters.py -v -s` | Run adapter tests |

### Week 3 — Agents (Days 10–13)

| Day | File | Why |
|-----|------|-----|
| 10 | [orchestrator/agents/base_agent.py](file:///d:/REVENANT/orchestrator/agents/base_agent.py) | The agent contract |
| 10 | [orchestrator/agents/recon_agent.py](file:///d:/REVENANT/orchestrator/agents/recon_agent.py) | Simplest agent |
| 11 | [orchestrator/agents/web_agent.py](file:///d:/REVENANT/orchestrator/agents/web_agent.py) | Web agent |
| 11 | [orchestrator/agents/code_agent.py](file:///d:/REVENANT/orchestrator/agents/code_agent.py) | Code/SAST agent |
| 12 | `orchestrator/agents/cloud_agent.py` | Cloud scanning agent |
| 12 | [orchestrator/agents/identity_agent.py](file:///d:/REVENANT/orchestrator/agents/identity_agent.py) | AD attacks |
| 13 | `orchestrator/agents/malware_agent.py` | Complex 3-adapter agent |
| 13 | `pytest tests/test_orchestrator.py -v -s` | Watch the cascade live! |

### Week 4 — Intelligence & Deployment (Days 14–15)

| Day | File | Why |
|-----|------|-----|
| 14 | `orchestrator/correlation/attack_graph_engine.py` | How findings become attack chains |
| 14 | `reporting/generator.py` | How 5-format reports are made |
| 14 | `pytest tests/test_milestone2_5_attack_graph.py -v -s` | See correlation working |
| 15 | `deployments/docker-compose.yml` | The full 4-container deployment |
| 15 | `pytest tests/ -q` | Run ALL 234 tests — celebrate when they pass! |

---

## 14. Self-Quiz — Are You Ready for the N.E.W.T.s?

Test yourself. Answer these WITHOUT looking at the code.

### O.W.L. Level (Basic)

- [ ] What is REVENANT in one sentence?
- [ ] Name 5 mission profiles and what each one tests
- [ ] What is a `Finding`? What fields does it have?
- [ ] What is a `HostAsset`? What's the difference from a `Finding`?
- [ ] What does `ScopeEngine.validate_or_raise()` do when the target is NOT in scope?
- [ ] At how many layers is scope checked?

### N.E.W.T. Level (Intermediate)

- [ ] What is the Blackboard? Why do agents use it instead of calling each other?
- [ ] What does `get_unhandled_events(agent_name)` return?
- [ ] What does `mark_handled(event_id, agent_name)` do and why is it important?
- [ ] What are the 4 methods every adapter must implement?
- [ ] What does `AdapterResult` contain?
- [ ] What is `can_handle()` on a BaseAgent? What would break without it?

### Mastery Level (Advanced)

- [ ] Trace the full data flow from `TARGET_REGISTERED` to `VULNERABILITY_CONFIRMED` step by step
- [ ] What is a "choke point" in the attack graph? Why is it the most important finding to fix?
- [ ] What is the WSL2 bridge and why does it exist in the adapters?
- [ ] Why does the Blackboard save events to SQLite?
- [ ] What is "stigmergic" orchestration and why is it better than direct agent-to-agent calls?
- [ ] Run `docker compose up` and hit the `/api/v1/health` endpoint yourself

---

## 15. Quick Command Reference

```bash
# ──────────────────────────────────────────────────────────────
# RUNNING TESTS (your main learning tool)
# ──────────────────────────────────────────────────────────────

# Run ALL 234 tests
.venv\Scripts\pytest tests/ -q

# Run one test file with full live output (BEST for learning)
.venv\Scripts\pytest tests/test_orchestrator.py -v -s

# Run a specific test
.venv\Scripts\pytest tests/test_milestone4_3_malware.py::TestLiveYaraScan -v -s

# Run by milestone
.venv\Scripts\pytest tests/test_milestone2_1_sast.py -v -s
.venv\Scripts\pytest tests/test_milestone2_2_dast.py -v -s
.venv\Scripts\pytest tests/test_milestone2_3_cloud.py -v -s
.venv\Scripts\pytest tests/test_milestone2_4_identity.py -v -s
.venv\Scripts\pytest tests/test_milestone2_5_attack_graph.py -v -s

# ──────────────────────────────────────────────────────────────
# USING THE CLI
# ──────────────────────────────────────────────────────────────

python revenant.py --help
python revenant.py profiles
python revenant.py scan --target http://target.com --profile web-dast
python revenant.py remediate ./evidence/findings.json --output ./remediation/
python revenant.py serve --host 0.0.0.0 --port 8000

# ──────────────────────────────────────────────────────────────
# DOCKER
# ──────────────────────────────────────────────────────────────

docker compose -f deployments/docker-compose.yml up -d --build
docker compose -f deployments/docker-compose.yml ps
docker compose -f deployments/docker-compose.yml logs -f control-plane
docker compose -f deployments/docker-compose.yml down
curl http://localhost:8000/api/v1/health

# ──────────────────────────────────────────────────────────────
# VIRTUAL ENVIRONMENT
# ──────────────────────────────────────────────────────────────

.venv\Scripts\activate        # Activate Python venv (Windows)
pip install -e ".[dev]"       # Install project + dev dependencies
```

---

## Final Words from the Professor

You now have a complete mental map of REVENANT. Here is the ONE thing to remember:

> **REVENANT is a loop.** Events go onto the Blackboard. Agents react to events and post more events.
> The loop runs until there's nothing left to react to. That's the entire system.

Everything else — the 15 agents, the 66 adapters, the attack graph, the 5 report formats, the Docker
containers — all of it is just filling in the details of that core loop.

When you get confused reading any file, ask yourself:
1. Is this a **Model** (data structure)?
2. Is this an **Adapter** (wraps a tool)?
3. Is this an **Agent** (reacts to events, uses adapters)?
4. Is this **Orchestration** (runs the loop)?
5. Is this **Reporting** (turns findings into output)?

Every single file in the project fits into one of those 5 categories.

Now go run `pytest tests/test_orchestrator.py -v -s` and watch the cascade happen live. 🧙‍♂️

---

*"It does not do to dwell on dreams and forget to live."*
*— Read the actual source code.*
