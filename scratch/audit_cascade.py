import os
import sqlite3
from control_plane.schemas.scope import ScopeManifest
from orchestrator.blackboard import Blackboard, BlackboardEvent, EventType
from orchestrator.agents.recon_agent import ReconAgent
from orchestrator.agents.web_agent import WebAgent
from orchestrator.agents.triage_agent import TriageAgent
from orchestrator.engine import Orchestrator

db_file = "scratch/cascade_live.db"
if os.path.exists(db_file):
    os.remove(db_file)

scope = ScopeManifest(allowed_hosts=["127.0.0.1"])
bb = Blackboard(campaign_id="cascade-live-audit", db_path=db_file)

class FastWebAgent(WebAgent):
    def handle(self, event, blackboard, scope):
        # Target the openapi exposure template against live lab
        result = self.nuclei.run(
            event.target, 
            scope, 
            params={"templates": ["http/exposures/apis/openapi.yaml"]}
        )
        new_events = []
        for finding in result.findings:
            new_events.append(
                BlackboardEvent(
                    event_type=EventType.VULNERABILITY_CANDIDATE,
                    source_agent=self.name,
                    target=finding.target,
                    payload={"finding": finding.model_dump()},
                )
            )
        return new_events

orch = Orchestrator(blackboard=bb, agents=[ReconAgent(), FastWebAgent(), TriageAgent()])
print("=== STARTING LIVE MULTI-AGENT STIGMERGIC CASCADE ===")
summary = orch.start_campaign("http://127.0.0.1:3000", scope, max_iterations=10)

print("\n=== EVENT TRAIL (IN EXACT ORDER OF EXECUTION) ===")
for idx, ev in enumerate(bb.get_events(), 1):
    ts = ev.timestamp.strftime("%H:%M:%S")
    print(f"{idx:2d}. [{ts}] {ev.source_agent:<15} -> {ev.event_type.value:<24} Target: {ev.target}")

print("\n=== CONFIRMED FINDINGS ON BLACKBOARD ===")
for f in bb.get_findings():
    print(f" - [{f.severity.value}] {f.title} (tool: {f.tool}, endpoint: {f.endpoint})")

print("\n=== VERIFYING DURABLE SQLITE PERSISTENCE ===")
conn = sqlite3.connect(db_file)
cur = conn.cursor()
cur.execute("SELECT count(*) FROM events")
n_ev = cur.fetchone()[0]
cur.execute("SELECT count(*) FROM assets")
n_as = cur.fetchone()[0]
cur.execute("SELECT count(*) FROM findings")
n_fi = cur.fetchone()[0]
conn.close()
print(f"SQLite DB file '{db_file}' exists: (Events: {n_ev}, Assets: {n_as}, Findings: {n_fi})")

# Rehydrate a completely new Blackboard instance pointing to the same SQLite file
bb_reloaded = Blackboard(campaign_id="cascade-live-audit", db_path=db_file)
print(f"Rehydrated Blackboard from disk: {len(bb_reloaded.get_events())} events, {len(bb_reloaded.get_assets())} assets, {len(bb_reloaded.get_findings())} findings.")
