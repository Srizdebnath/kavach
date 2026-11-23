#!/usr/bin/env bash
# Configure github.com/Srizdebnath/kavach for open-source contributions.
# Idempotent: every call is a PUT/PATCH of the desired state, labels are upserted and the
# ruleset is updated in place if one with the same name already exists.
#
# Usage: ./gh-repo-rules.sh [--dry-run]
#   --dry-run  print the mutating calls instead of executing them (read-only calls still run)
set -euo pipefail

REPO="${REPO:-Srizdebnath/kavach}"
RULESET_NAME="main protection"
DRY=0
[ "${1:-}" = "--dry-run" ] && DRY=1

gh auth status >/dev/null 2>&1 || { echo "gh is not authenticated; run 'gh auth login'" >&2; exit 1; }

# run METHOD PATH [gh api args...]: mutating call, honours --dry-run
run() {
  local method=$1 path=$2; shift 2
  if [ "$DRY" -eq 1 ]; then
    echo "DRY: gh api -X $method $path $*"
  else
    echo "==> $method $path"
    gh api -X "$method" "$path" "$@" >/dev/null
  fi
}

# --- description, topics, features, merge policy ------------------------------------------
run PATCH "repos/$REPO" \
  -f description='Kernel-native firewall for the agentic, encrypted, zero-trust era. C eBPF fast path, Rust for everything that parses.' \
  -F has_issues=true \
  -F has_discussions=true \
  -F allow_squash_merge=true \
  -F allow_merge_commit=false \
  -F allow_rebase_merge=false \
  -f squash_merge_commit_title=PR_TITLE \
  -f squash_merge_commit_message=PR_BODY \
  -F delete_branch_on_merge=true

run PUT "repos/$REPO/topics" \
  -f 'names[]=ebpf' -f 'names[]=xdp' -f 'names[]=bpf-lsm' -f 'names[]=firewall' \
  -f 'names[]=linux-kernel' -f 'names[]=rust' -f 'names[]=security' -f 'names[]=zero-trust' \
  -f 'names[]=network-security' -f 'names[]=linux'

# --- security features ------------------------------------------------------------------
run PUT "repos/$REPO/private-vulnerability-reporting"
run PUT "repos/$REPO/vulnerability-alerts"          # Dependabot alerts
run PUT "repos/$REPO/automated-security-fixes"      # Dependabot security updates
run PATCH "repos/$REPO" --input - <<'JSON'
{"security_and_analysis": {
  "secret_scanning": {"status": "enabled"},
  "secret_scanning_push_protection": {"status": "enabled"}
}}
JSON

# --- labels used by the issue forms --------------------------------------------------------
upsert_label() {
  local name=$1 color=$2 desc=$3
  if gh api "repos/$REPO/labels/$(printf %s "$name" | jq -sRr @uri)" >/dev/null 2>&1; then
    run PATCH "repos/$REPO/labels/$(printf %s "$name" | jq -sRr @uri)" -f color="$color" -f description="$desc"
  else
    run POST "repos/$REPO/labels" -f name="$name" -f color="$color" -f description="$desc"
  fi
}
upsert_label triage fbca04 "Needs a maintainer to look at it"

# --- branch ruleset for main ------------------------------------------------------------
# Status check contexts are the job names in .github/workflows/ci.yml.
# integration_id 15368 = GitHub Actions; actor_id 5 = the repository "admin" role.
RULESET=$(cat <<JSON
{
  "name": "$RULESET_NAME",
  "target": "branch",
  "enforcement": "active",
  "conditions": {"ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": []}},
  "bypass_actors": [
    {"actor_id": 5, "actor_type": "RepositoryRole", "bypass_mode": "always"}
  ],
  "rules": [
    {"type": "deletion"},
    {"type": "non_fast_forward"},
    {"type": "required_linear_history"},
    {"type": "pull_request", "parameters": {
      "required_approving_review_count": 1,
      "dismiss_stale_reviews_on_push": true,
      "require_code_owner_review": true,
      "require_last_push_approval": false,
      "required_review_thread_resolution": false
    }},
    {"type": "required_status_checks", "parameters": {
      "strict_required_status_checks_policy": false,
      "required_status_checks": [
        {"context": "lint", "integration_id": 15368},
        {"context": "test", "integration_id": 15368},
        {"context": "miri", "integration_id": 15368},
        {"context": "deny", "integration_id": 15368}
      ]
    }}
  ]
}
JSON
)

existing=$(gh api "repos/$REPO/rulesets" --jq ".[] | select(.name == \"$RULESET_NAME\") | .id" | head -1)
if [ -n "$existing" ]; then
  run PUT "repos/$REPO/rulesets/$existing" --input - <<<"$RULESET"
else
  run POST "repos/$REPO/rulesets" --input - <<<"$RULESET"
fi

[ "$DRY" -eq 1 ] && echo "dry run complete" || echo "done"
