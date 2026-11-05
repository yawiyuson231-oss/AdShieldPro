# Deploy the AdShield Pro site to GitHub Pages

Wraps the repository's own pipeline. It never creates a repository, never force-pushes, and
never edits the workflow — it stages, audits, and (optionally) publishes.

```
Usage:
  bash skills/web-deploy-github-pages/scripts/deploy.sh --check      # stage + verify only (no network)
  bash skills/web-deploy-github-pages/scripts/deploy.sh --publish    # push the current branch, then watch the deploy
  bash skills/web-deploy-github-pages/scripts/deploy.sh --status     # where things stand right now
```

Flags:

| Flag | Effect |
|---|---|
| `--check` (default) | `npm run stage` + `node scripts/verify-site.mjs _site`. Exit 1 on any failure. |
| `--publish` | `--check`, then `git push` the current branch and wait for the `Deploy website` run on it |
| `--status` | Pages state, last deploy runs, live URL reachability |
| `--serve` | Serve `_site/` on port 8080 for a manual look (Ctrl-C to stop) |
| `--branch <name>` | Branch to publish (default: the checked-out branch) |

Refuses to publish when the worktree is dirty, when the branch has no upstream, or when the
run does not exist — a green local `--check` is the precondition, not a substitute.
