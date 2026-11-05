#!/usr/bin/env bash
# AdShield Pro — publish the website to GitHub Pages.
#
# This wraps the repository's existing pipeline instead of replacing it: scripts/stage-site.mjs
# assembles _site/, scripts/verify-site.mjs audits it, .github/workflows/deploy-website.yml
# uploads that same tree. Nothing here creates a repository, rewrites history or touches a
# gh-pages branch.
#
#   bash skills/web-deploy-github-pages/scripts/deploy.sh --check      stage + verify only
#   bash skills/web-deploy-github-pages/scripts/deploy.sh --publish    push, then watch the deploy
#   bash skills/web-deploy-github-pages/scripts/deploy.sh --status     Pages state + last runs
#   bash skills/web-deploy-github-pages/scripts/deploy.sh --serve      serve _site/ on :8080
#
# Exit codes: 0 ok · 1 verification/publish failure · 2 bad usage or missing prerequisites.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$REPO_ROOT"

BRANCH="${BRANCH:-$(git rev-parse --abbrev-ref HEAD)}"
MODE="check"
WAIT_TIMEOUT="${WAIT_TIMEOUT:-900}"

die() { printf '\033[31merror\033[0m %s\n' "$*" >&2; exit "${2:-1}"; }
say() { printf '\033[36m•\033[0m %s\n' "$*"; }
ok()  { printf '\033[32m✓\033[0m %s\n' "$*"; }
warn() { printf '\033[33m!\033[0m %s\n' "$*"; }

usage() { sed -n '3,12p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 2; }

while [ $# -gt 0 ]; do
  case "$1" in
    --check|--publish|--status|--serve) MODE="${1#--}"; shift ;;
    --branch) BRANCH="${2:?--branch needs a value}"; shift 2 ;;
    -h|--help) usage ;;
    *) die "unknown argument: $1" 2 ;;
  esac
done

need() { command -v "$1" >/dev/null 2>&1 || die "$1 is required but not installed" 2; }
need node
need npm

# ---------------------------------------------------------------------------- stage + verify
run_check() {
  say "staging _site/ from docs/ + the web platform"
  node scripts/stage-site.mjs --out _site

  say "auditing the staged tree"
  node scripts/verify-site.mjs _site
  ok "the tree in _site/ is deployable"
}

# Reports the HTTP status of one deployed URL. curl writes the code even when it fails, so the
# code is captured first and only defaulted when curl produced nothing.
probe() {
  command -v curl >/dev/null 2>&1 || return 0
  local url="$1" label="$2" code
  code="$(curl -s -o /dev/null -w '%{http_code}' -L --max-time 20 "$url" 2>/dev/null)" || true
  [ -n "$code" ] || code="000"
  case "$code" in
    200) ok "${label}: ${url} (HTTP 200)" ;;
    404) warn "${label}: ${url} returns 404 — not deployed for this origin yet" ;;
    000) warn "${label}: ${url} could not be reached (offline, DNS or firewall)" ;;
    *)   warn "${label}: ${url} returned HTTP ${code}" ;;
  esac
}

# ------------------------------------------------------------------------------------ status
show_status() {
  need gh
  say "repository: $(gh repo view --json nameWithOwner --jq .nameWithOwner)"
  local origin
  origin="$(grep -v '^#' docs/canonical.txt | grep -v '^[[:space:]]*$' | head -1 | sed 's:/*$::')"
  say "declared origin: ${origin}"

  local pages
  pages="$(gh api "repos/{owner}/{repo}/pages" --jq '"Pages: \(.status) · source: \(.build_type) · \(.html_url)"' 2>/dev/null || true)"
  if printf '%s' "$pages" | grep -q '^Pages:'; then
    ok "$pages"
  else
    warn "Pages is not enabled for this repository."
    warn "A repository admin must open Settings -> Pages -> Source: GitHub Actions."
  fi

  say "recent Deploy website runs:"
  gh run list --workflow deploy-website.yml -L 5 \
    --json databaseId,displayTitle,headBranch,status,conclusion,createdAt \
    --jq '.[] | "  \(.databaseId)  \(.headBranch)  \(.status)/\(.conclusion // "-")  \(.displayTitle[0:52])"' \
    || warn "could not list runs"

  probe "${origin}/" "site"
  probe "${origin}/app/" "web platform"
}

# ----------------------------------------------------------------------------------- publish
publish() {
  need gh
  need git
  git diff --quiet && git diff --cached --quiet || die "worktree is dirty — the deploy artifact is built from a commit, so commit or stash first"
  [ -z "$(git status --porcelain)" ] || die "worktree has untracked files — commit or stash first"

  run_check

  local upstream
  upstream="$(git rev-parse --abbrev-ref --symbolic-full-name '@{upstream}' 2>/dev/null || true)"
  if [ -z "$upstream" ]; then
    say "no upstream for ${BRANCH}; pushing with -u"
  fi
  say "pushing ${BRANCH}"
  if [ -n "$upstream" ]; then git push; else git push -u origin "$BRANCH"; fi

  say "waiting for the Deploy website run on ${BRANCH} (timeout ${WAIT_TIMEOUT}s)"
  local run_id="" waited=0
  while [ "$waited" -lt "$WAIT_TIMEOUT" ]; do
    run_id="$(gh run list --workflow deploy-website.yml --branch "$BRANCH" -L 1 --json databaseId,status --jq '.[0].databaseId // empty')"
    [ -n "$run_id" ] && break
    sleep 5; waited=$((waited + 5))
  done
  [ -n "$run_id" ] || die "no Deploy website run appeared for ${BRANCH} — check that the push touched docs/ or the web platform, or run 'gh workflow run deploy-website.yml --ref ${BRANCH}'"

  gh run watch "$run_id" --exit-status --interval 10 || {
    gh run view "$run_id" --log-failed | tail -40
    die "deploy run ${run_id} failed"
  }

  # Report the URL the deployment itself computed, so the environment URL is not guessed.
  gh run view "$run_id" --json url --jq '"run: \(.url)"' 2>/dev/null || true
  local page_url
  page_url="$(gh api "repos/{owner}/{repo}/pages" --jq .html_url 2>/dev/null || true)"
  [ -n "$page_url" ] && ok "deployed: ${page_url}"
  show_status
}

case "$MODE" in
  check)   run_check ;;
  status)  show_status ;;
  publish) publish ;;
  serve)
    run_check
    say "serving _site/ on http://localhost:8080 (Ctrl-C to stop)"
    exec npx --yes http-server _site -p 8080 -c-1 --silent
    ;;
  *) usage ;;
esac
