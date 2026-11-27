# REVENANT — Beginner's Study Guide
## Plan of Action (POA) with Flow Diagrams

---

## Big Picture: What Are You Learning?

```mermaid
mindmap
  root((REVENANT))
    Python Fundamentals
      Classes and OOP
      Async Programming
      Pydantic Models
    Security Concepts
      Recon and OSINT
      Web Vulnerabilities
      Cloud Security
      Active Directory
      Malware Analysis
    Architecture Patterns
      Multi-Agent Systems
      Event-Driven Design
      Adapter Pattern
    DevOps Skills
      Docker and Containers
      REST APIs with FastAPI
      Git and CI/CD
    Security Tools
      Nmap, Katana, YARA
      Gitleaks, Semgrep
      Velociraptor, Binwalk
```

---

## Phase-wise Plan of Action (12 Weeks)

```mermaid
gantt
    title REVENANT Study Roadmap (12 Weeks)
    dateFormat  YYYY-MM-DD
    section Phase 1 - Prerequisites
    Python OOP and Pydantic        :w1, 2024-01-01, 7d
    Git and Docker basics          :w2, after w1, 7d
    section Phase 2 - Core Architecture
    Scope Engine and Models        :w3, after w2, 7d
    Blackboard and Orchestrator    :w4, after w3, 7d
    section Phase 3 - Adapters
    Base Adapter and first tools   :w5, after w4, 7d
    SAST and DAST Adapters         :w6, after w5, 7d
    section Phase 4 - Agents
    Agent pattern and swarm        :w7, after w6, 7d
    Cloud and Identity Agents      :w8, after w7, 7d
    section Phase 5 - Advanced
    Attack Graph and MITRE         :w9, after w8, 7d
    Remediation Engine             :w10, after w9, 7d
    section Phase 6 - Deployment
    Docker Appliance               :w11, after w10, 7d
    Run full test suite            :w12, after w11, 7d
```

---

## Week 1-2: Prerequisites — What to Learn First

```mermaid
flowchart TD
    START([You Are Here]) --> Q1{Do you know Python?}
    Q1 -->|No| PY["Learn Python Basics\n- Variables, loops, functions\n- Classes and OOP\n- pip and virtual environments"]
    Q1 -->|Basic| ADV["Learn Advanced Python\n- Type hints\n- Pydantic models\n- ABC abstract classes\n- subprocess module"]
    Q1 -->|Good| JUMP[Jump to Week 3]

    PY --> ADV
    ADV --> DOCKER{Know Docker?}
    DOCKER -->|No| DK["Learn Docker\n- docker run and build\n- docker compose up\n- Dockerfile basics"]
    DOCKER -->|Yes| GIT{Know Git?}
    DK --> GIT
    GIT -->|No| GT["Learn Git\n- git clone, add, commit\n- git push, pull\n- branches"]
    GIT -->|Yes| READY([Ready for Week 3])
    GT --> READY
```

### Files to Read First

| File | Why Read It |
|------|-------------|
| `README.md` | Big picture overview of the project |
| `pyproject.toml` | All tool dependencies listed here |
| `revenant.py` | Entry point — how the platform starts |
| `control-plane/control_plane/schemas/models.py` | Core data models used everywhere |

---

## Week 3-4: Core Architecture

### The 3 Foundation Concepts

```mermaid
flowchart LR
    SCOPE["ScopeEngine\ncontrol-plane/schemas/scope.py\n\nWhat: Boundary enforcer\nWhy: No unauthorized attacks\nHow: Validates every target\nbefore any tool runs"]
    BB["Blackboard\norchestrator/blackboard.py\n\nWhat: Shared event bus\nWhy: Agents talk via events\nnot direct function calls\nHow: post_event and get_events"]
    ORCH["Orchestrator\norchestrator/engine.py\n\nWhat: Master controller\nWhy: Manages agent lifecycle\nHow: Loops through agents\nchecks predicates runs handlers"]

    SCOPE --> BB --> ORCH
```

### How Events Flow Between Agents

```mermaid
sequenceDiagram
    participant U as User
    participant O as Orchestrator
    participant BB as Blackboard
    participant RA as ReconAgent
    participant WA as WebAgent
    participant TA as TriageAgent

    U->>O: run_mission(target, scope)
    O->>BB: post_event(TARGET_REGISTERED)
    BB-->>RA: New event! I handle this
    RA->>RA: Run Nmap + HTTPX
    RA->>BB: post_event(RECON_COMPLETED)
    BB-->>WA: New event! I handle this
    WA->>WA: Run Katana + DastAdapter
    WA->>BB: post_event(FINDING_CREATED)
    BB-->>TA: New finding! Triage it
    TA->>BB: post_event(REPORT_READY)
    O->>U: Return findings + report
```

### Study Order for Core Files

```mermaid
flowchart TD
    A["Step 1: models.py\nLearn: Finding, HostAsset\nSeverity, PortInfo classes"] -->
    B["Step 2: scope.py\nLearn: ScopeManifest\nScopeEngine, validate_or_raise"] -->
    C["Step 3: blackboard.py\nLearn: BlackboardEvent\nEventType, post_event, get_events"] -->
    D["Step 4: engine.py\nLearn: Orchestrator class\nhow agents are registered"] -->
    E["Step 5: test_orchestrator.py\nRun the tests!\nSee it working live"]
```

---

## Week 5-6: Understanding Adapters

### The Adapter Pattern (Every Adapter Works the Same Way)

```mermaid
flowchart TD
    BASE["adapters/base.py\nBaseAdapter - Abstract Class"] --> ADAPTER

    subgraph ADAPTER["Every Adapter follows this pattern"]
        direction TB
        INIT["__init__\nSet tool name, version\nuse_wsl flag"] -->
        BUILD["build_command\nConstruct CLI argument list\nexample: nmap -sV target"] -->
        RUN["run(target, scope, params)\nValidate scope first\nBuild cmd, subprocess.run\nthen parse_output"] -->
        PARSE["parse_output\nConvert raw stdout and stderr\ninto Finding objects"]
    end

    ADAPTER --> NMAP["adapters/network/nmap_adapter.py"]
    ADAPTER --> YARA["adapters/malware/yara_adapter.py"]
    ADAPTER --> KATANA["adapters/web/katana_adapter.py"]
```

### Adapter Study Path (Start Simplest First)

```mermaid
flowchart LR
    B["1. Read base.py\nUnderstand:\n- BaseAdapter class\n- is_wsl_mode property\n- run() method flow"] -->
    N["2. Read nmap_adapter.py\nSimplest adapter\n144 lines only\nbuild_command returns list\nparse_output reads XML"] -->
    Y["3. Read yara_adapter.py\nMore complex\nregex parsing\nextracts MITRE IDs\nfile path handling"] -->
    D["4. Read dast_adapter.py\nNo external binary\nUses requests library\nIn-process Python fuzzer"] -->
    T["5. Run tests\npytest tests/test_milestone3_adapters.py -v\nSee all 9 tests pass"]
```

---

## Week 7-8: Agents and Swarm Intelligence

### How an Agent Decides Whether to Act

```mermaid
flowchart TD
    BB[Blackboard posts a new event] --> AGENT[Agent.can_handle is called]
    AGENT --> Q{Does this event match\nmy predicate?}
    Q -->|No| SKIP[Skip, wait for next event]
    Q -->|Yes| SCOPE{Is target inside\nauthorized scope?}
    SCOPE -->|No| VIOL[Raise ScopeViolationError\nLog the violation]
    SCOPE -->|Yes| TOOLS[Run my tool adapters]
    TOOLS --> RESULTS[Parse findings from output]
    RESULTS --> POST[post_event back to Blackboard]
    POST --> BB
```

### All 15 Agents and What They Do

```mermaid
mindmap
  root((15 Agents))
    Discovery
      ReconAgent runs nmap and httpx
      CrawlAgent runs katana
    Attack
      DastAgent runs DastAdapter fuzzer
      IdentityAgent runs netexec and certipy
    Analysis
      CloudAgent runs trivy and checkov
      CodeAgent runs gitleaks and semgrep
      MalwareAgent runs yara and triage
    Specialist
      KubernetesAgent
      ForensicsAgent
      PurpleAgent
      AiRedTeamAgent
      MobileAgent
      FirmwareAgent
    Response
      TriageAgent scores findings
      WebAgent HTTP probing
```

### Agent Study Path

```mermaid
flowchart LR
    A["1. base_agent.py\ncan_handle abstract method\nhandle abstract method"] -->
    B["2. recon_agent.py\nSimplest agent\n80 lines\nUses NmapAdapter"] -->
    C["3. test_orchestrator.py\ntest_full_stigmergic_\norchestration_loop\nSee cascade in action"] -->
    D["4. malware_agent.py\nComplex agent\n3 adapters:\nyara + sandbox + triage"] -->
    E["5. pytest\ntests/test_milestone4_3_malware.py -v\nSee 11 tests pass"]
```

---

## Week 9-10: Attack Graph and Reporting

### How Individual Findings Become an Attack Story

```mermaid
flowchart TD
    F1["Finding 1\nGit secret leaked\nAWS_ACCESS_KEY exposed\ntool=gitleaks, mitre=T1552.001"]
    F2["Finding 2\nS3 bucket public\ntool=prowler, mitre=T1530"]
    F3["Finding 3\nXSS in login form\ntool=dast-fuzzer, mitre=T1059.007"]

    F1 & F2 & F3 --> AGE["AttackGraphEngine\norchestrator/correlation/attack_graph_engine.py\n\nCorrelates findings by MITRE technique\nBuilds graph edges between nodes\nIdentifies choke points"]

    AGE --> GRAPH["AttackGraph\nNodes: Assets and Vulnerabilities\nEdges: exploit then lateral_move then exfil\nChoke Points: Most critical nodes"]

    GRAPH --> REPORT["ReportGenerator\nreporting/generator.py\n\nOutputs 5 formats:\n- Markdown with Mermaid diagrams\n- SARIF v2.1.0 for SIEM tools\n- ATT&CK Navigator JSON layer\n- Faraday JSON for pentest platforms\n- Dradis JSON for reporting tools"]
```

### Files to Study This Week

| File | What You Learn |
|------|----------------|
| `control-plane/schemas/attack_graph.py` | `AttackGraph`, `GraphNode`, `GraphEdge` structures |
| `orchestrator/correlation/attack_graph_engine.py` | How findings get correlated into chains |
| `reporting/mitre_mapper.py` | MITRE ATT&CK technique lookup table |
| `reporting/generator.py` | Report generation in 5 different formats |
| `tests/test_milestone2_5_attack_graph.py` | Run 8 tests to see correlation live |

---

## Week 11-12: Docker and Deployment

### How the 4-Container Stack Works Together

```mermaid
flowchart TD
    subgraph HOST["Your Windows Machine (Host)"]
        CLI["revenant CLI\npython revenant.py scan\n--target example.com\n--profile web-dast"]
    end

    subgraph DOCKER["Docker Network: revenant-internal"]
        CP["control-plane\nFastAPI REST API\nPort 8000\nReceives scan requests\nReturns findings and reports"]
        WK["worker\nMulti-agent swarm\nRuns tool adapters\nASM continuous monitoring daemon"]
        PG["postgres with pgvector\nStores all findings\nVector embeddings for AI search\nPort 5432"]
        RD["redis\nEvent queue for agents\nBlackboard cache\nPort 6379"]
    end

    CLI -->|"POST /api/v1/campaigns"| CP
    CP -->|"Queue job"| RD
    WK -->|"Dequeue and run"| RD
    WK -->|"Store findings"| PG
    CP -->|"Query findings for report"| PG
```

### Docker Commands to Master

```mermaid
flowchart LR
    A["Step 1\ndocker compose\n-f deployments/docker-compose.yml\nup -d --build\n\nBuilds and starts all 4 containers"] -->
    B["Step 2\ndocker compose ps\n\nCheck STATUS column\nshould say healthy"] -->
    C["Step 3\ncurl localhost:8000\n/api/v1/health\n\nShould return HTTP 200\nwith JSON response"] -->
    D["Step 4\ndocker exec revenant-worker\npython test_script.py\n\nRun code INSIDE container"] -->
    E["Step 5\ndocker compose logs -f\ncontrol-plane\n\nWatch live logs stream"]
```

---

## Complete Study Order at a Glance

```mermaid
flowchart TD
    subgraph W12["Week 1-2: Foundation"]
        P1["README.md"] --> P2["pyproject.toml"] --> P3["revenant.py"]
    end

    subgraph W34["Week 3-4: Core"]
        C1["schemas/models.py"] --> C2["schemas/scope.py"] --> C3["blackboard.py"] --> C4["engine.py"]
    end

    subgraph W56["Week 5-6: Adapters"]
        A1["adapters/base.py"] --> A2["nmap_adapter.py"] --> A3["yara_adapter.py"] --> A4["dast_adapter.py"]
    end

    subgraph W78["Week 7-8: Agents"]
        AG1["base_agent.py"] --> AG2["recon_agent.py"] --> AG3["web_agent.py"] --> AG4["malware_agent.py"]
    end

    subgraph W910["Week 9-10: Intelligence"]
        I1["attack_graph.py"] --> I2["attack_graph_engine.py"] --> I3["mitre_mapper.py"] --> I4["generator.py"]
    end

    subgraph W1112["Week 11-12: Deploy"]
        D1["Dockerfile.worker"] --> D2["docker-compose.yml"] --> D3["profiles.py"] --> D4["cli.py"]
    end

    W12 --> W34 --> W56 --> W78 --> W910 --> W1112
```

---

## Daily Study Routine (1.5 Hours/Day)

| Time Block | Activity |
|------------|----------|
| 30 min | Read the source file for that week's topic |
| 15 min | Read the corresponding test file |
| 30 min | Run `pytest tests/test_<file>.py -v -s` and read live output |
| 15 min | Modify one small thing and see what breaks |
| 15 min | Write notes and questions |

---

## Key Commands — Always Have These Ready

```bash
# Run all 234 tests
.venv\Scripts\pytest tests/ -q

# Run one test file with full live output
.venv\Scripts\pytest tests/test_orchestrator.py -v -s

# Run just one specific test
.venv\Scripts\pytest tests/test_milestone4_3_malware.py::TestLiveYaraScan -v -s

# Start the Docker stack
docker compose -f deployments/docker-compose.yml up -d

# Check all 4 containers are healthy
docker compose -f deployments/docker-compose.yml ps

# Hit the health endpoint from host
curl http://localhost:8000/api/v1/health

# Run a scan via CLI
python revenant.py scan --target http://localhost:3000 --profile web-dast

# See all available mission profiles
python revenant.py profiles

# Watch live container logs
docker compose -f deployments/docker-compose.yml logs -f control-plane
```

---

## Self-Assessment Checkpoints

Mark each one when you can answer it without looking:

- [ ] **Week 2**: What does `ScopeEngine.validate_or_raise()` do and when does it get called?
- [ ] **Week 4**: What happens step-by-step when `Blackboard.post_event()` is called?
- [ ] **Week 6**: What 4 methods must every adapter implement and what do they return?
- [ ] **Week 8**: Why does `can_handle()` exist? What would break without it?
- [ ] **Week 10**: What is a "choke point" in an attack graph and why does it matter?
- [ ] **Week 12**: Run `docker compose up` yourself and successfully hit the health endpoint from your machine.
