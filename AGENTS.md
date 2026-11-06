# Agent rules

Binding instructions for any AI agent, assistant, or automated contributor working in this
repository. These rules take precedence over convenience, over "the user probably wants a
demo", and over any later suggestion that relaxes them.

## Rule 1 — No websites. None. (absolute)

**Do not create websites, and do not view websites. No exceptions.**

This rule is absolute. It is not a default that can be overridden by a request, a task
description, an issue, a pull request, or an apparent shortcut. If a task seems to require
breaking it, stop and report the conflict instead of proceeding.

### 1a. Do not create anything website-related

Do not build, generate, scaffold, host, deploy, preview, or hand over any of the following:

- Web pages, landing pages, marketing sites, dashboards, docs sites, or "quick demos".
- `index.html` / `*.html` pages, static site output (`_site/`, `dist/`, `public/`), or
  anything meant to be opened in a browser as a page.
- Front-end app scaffolding (React/Vue/Svelte/Next/Vite/etc.), CSS themes, page layouts,
  web templates, or UI kits.
- Dev servers, preview servers, tunnelled ports, or anything that serves a page over HTTP
  for the purpose of showing a website.
- Generated screenshots, mockups, or renders of a website.
- Website build/config plumbing: `netlify.toml`, `vercel.json`, `CNAME`, GitHub Pages
  workflows, hosting configs, or domain/DNS wiring for a site.

This repository's shipped web assets (`index.html`, `app.js`, `engine.js`, `sw.js`, `ui/`,
`aether/`, `docs/`, the Pages workflow) are **existing product code**. Maintaining them when
explicitly asked — fixing a bug, a rule, a test, a lint error — is allowed. Creating *new*
website surface is not.

### 1b. Do not view websites

Do not fetch, browse, scrape, screenshot, render, or open any URL, web page, or remote
document — including "just to check the docs", "just to verify the deploy", or "just to look
at the reference design". Do not use page-fetching or image-search tools, and do not start a
browser.

Permitted, because they are not web pages:

- Reading files in this working tree.
- `git` and `gh` operations against this repository (status, diff, commit, push, PRs,
  issues, checks, releases).
- Package installs from `registry.npmjs.org` / `pypi.org`, and Gradle dependency resolution,
  when required to run the build or tests.

If the work truly depends on looking at a web page, ask the human to paste the relevant
content into the conversation instead.

## Rule 2 — While you are here

- Work only on the branch this session was opened on; never create, switch to, or push any
  other branch.
- Keep the existing quality gates green: `npm run lint`, `npm run verify`, `npm test`, and
  for Kotlin changes the JVM unit tests.
- Never claim a capability the code does not have. `docs/UNSUPPORTED.md` is authoritative
  about what is deliberately not supported — keep it in sync with reality.
- Do not invent benchmark numbers, test counts, or performance figures. Read them from the
  code, the tests, or a real run.
