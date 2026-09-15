#!/usr/bin/env bash
# ───────────────────────────────────────────────────────────────────────
# REVENANT — Scope Enforcement Test
# PROVES the platform refuses out-of-scope targets.
#
# Test 1 : mission to in-scope lab target  → runs
# Test 2 : mission to out-of-scope target  → REFUSED
# Test 3 : mission with no scope at all    → REFUSED
#
# A platform that fails ANY of these must not be used for real work.
# ───────────────────────────────────────────────────────────────────────
set -euo pipefail
REVENANT_HOME="${REVENANT_HOME:-/opt/revenant}"
BIN="$REVENANT_HOME/bin/pentestswarm"
IN_SCOPE="${IN_SCOPE:-http://localhost:30013}"
OUT_OF_SCOPE="${OUT_OF_SCOPE:-http://203.0.113.10}"   # TEST-NET, non-routable

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
pass() { echo -e "${GREEN}[PASS]${NC} $*"; }
fail() { echo -e "${RED}[FAIL]${NC} $*"; exit 1; }

echo "== TEST 1: in-scope target runs =="
if $BIN run --target crapi --scopes "$IN_SCOPE" --dry-run 2>&1 | grep -qi "would run\|proceeding\|ok"; then
  pass "In-scope target accepted."
else
  fail "In-scope target was NOT accepted. Investigate before continuing."
fi

echo "== TEST 2: out-of-scope target refused =="
if $BIN run --target evil --scopes "$IN_SCOPE" --target-override "$OUT_OF_SCOPE" --dry-run 2>&1 \
   | grep -qiE "refus|denied|out of scope|not in scope"; then
  pass "Out-of-scope target refused."
else
  fail "Out-of-scope target was NOT refused — CRITICAL"
fi

echo "== TEST 3: no scope at all refused =="
if $BIN run --target evil --dry-run 2>&1 | grep -qiE "refus|denied|scope is required|no scope"; then
  pass "Mission without scope refused."
else
  fail "Mission without scope was NOT refused — CRITICAL"
fi

echo ""
echo "══════════════════════════════════════════════════════"
echo " SCOPE ENFORCEMENT: ALL TESTS PASSED "
echo "══════════════════════════════════════════════════════"