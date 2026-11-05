#!/usr/bin/env node
/**
 * AdShieldPro — FreeLLMAPI setup helper.
 *
 * Thin wrapper around `npx freellmapi` with AdShieldPro defaults and nicer
 * error messages. Delegates to the real CLI (freellmapi devDependency).
 *
 * Usage:
 *   node scripts/freellmapi-setup.mjs --agent claude --dry-run
 *   node scripts/freellmapi-setup.mjs --agent codex --url http://localhost:3001/v1 --api-key <key>
 *   node scripts/freellmapi-setup.mjs --list
 *   node scripts/freellmapi-setup.mjs --help
 *   npm run freellmapi:setup -- --agent claude --dry-run
 */

import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';

const AGENT_MAP = {
  claude: 'setup-claude',
  codex: 'setup-codex',
  cline: 'setup-cline',
  continue: 'setup-continue',
  aider: 'setup-aider',
  opencode: 'setup-opencode',
  goose: 'setup-goose',
  qwen: 'setup-qwen',
  roo: 'setup-roo',
  kilo: 'setup-kilo',
  crush: 'setup-crush',
  dsh: 'setup-dsh',
  mimo: 'setup-mimo',
  atomcode: 'setup-atomcode',
  openclaw: 'setup-openclaw',
  hermes: 'setup-hermes',
  pi: 'setup-pi',
  reasonix: 'setup-reasonix',
  zcode: 'setup-zcode',
  cursor: 'setup-cursor',
  generic: 'setup-generic',
};

function usage() {
  console.log(`
AdShieldPro — FreeLLMAPI setup helper
Upstream: https://github.com/tashfeenahmed/freellmapi

Usage:
  node scripts/freellmapi-setup.mjs --agent <name> [options]
  node scripts/freellmapi-setup.mjs --list
  node scripts/freellmapi-setup.mjs --help

Agents:
  ${Object.keys(AGENT_MAP).join(', ')}

Options:
  --agent <name>     Agent to configure (default: claude)
  --url <url>        Gateway URL (default: http://localhost:3001, /v1 added for OpenAI agents)
  --api-key <key>    Unified API key (or set FREELLMAPI_API_KEY)
  --profile <name>   Named profile (default: default)
  --model <id>       Pin a specific model
  --dry-run          Print diff, write nothing
  --list             List supported agents (npx freellmapi list)
  --help, -h         This help

Env:
  FREELLMAPI_URL, FREELLMAPI_API_KEY

Examples:
  node scripts/freellmapi-setup.mjs --agent claude --dry-run
  node scripts/freellmapi-setup.mjs --agent claude --url http://localhost:3001 --api-key freellmapi-...
  node scripts/freellmapi-setup.mjs --agent codex --url http://localhost:3001/v1
  npm run freellmapi:setup -- --agent cursor --dry-run

Advisory:
  This configures your local coding agent to route through a self-hosted gateway.
  Provider keys stay in FreeLLMAPI's encrypted SQLite, not in Git.
  See skills/freellmapi/SKILL.md and docs/FREELLMAPI_SKILL.md.
`.trim());
}

function parseArgs(argv) {
  const out = { agent: 'claude' };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--help' || a === '-h') out.help = true;
    else if (a === '--list') out.list = true;
    else if (a === '--dry-run') out.dryRun = true;
    else if (a === '--agent') out.agent = argv[++i];
    else if (a === '--url') out.url = argv[++i];
    else if (a === '--api-key') out.apiKey = argv[++i];
    else if (a === '--profile') out.profile = argv[++i];
    else if (a === '--model') out.model = argv[++i];
    else if (a.startsWith('--')) {
      console.error(`Unknown option: ${a}`);
      process.exit(1);
    }
  }
  return out;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    usage();
    process.exit(0);
  }

  const freellmapiBin = existsSync('node_modules/.bin/freellmapi')
    ? 'node_modules/.bin/freellmapi'
    : 'npx';

  if (args.list) {
    const cmd = freellmapiBin === 'npx' ? ['freellmapi', 'list'] : ['list'];
    const child = spawn(freellmapiBin, cmd, { stdio: 'inherit' });
    child.on('exit', (c) => process.exit(c ?? 0));
    return;
  }

  const agent = (args.agent || 'claude').toLowerCase();
  const command = AGENT_MAP[agent];
  if (!command) {
    console.error(`Unknown agent: ${agent}\nKnown: ${Object.keys(AGENT_MAP).join(', ')}`);
    process.exit(1);
  }

  const url = args.url || process.env.FREELLMAPI_URL || 'http://localhost:3001';
  const cliArgs = [command, '--url', url];

  const apiKey = args.apiKey || process.env.FREELLMAPI_API_KEY;
  if (apiKey) cliArgs.push('--api-key', apiKey);

  if (args.profile) cliArgs.push('--profile', args.profile);
  if (args.model) cliArgs.push('--model', args.model);
  if (args.dryRun) cliArgs.push('--dry-run');

  console.error(`> ${freellmapiBin} ${cliArgs.join(' ')}`);
  if (!apiKey && !args.dryRun) {
    console.error('Tip: set FREELLMAPI_API_KEY or pass --api-key. --dry-run needs no key.');
  }

  const spawnArgs = freellmapiBin === 'npx' ? ['freellmapi', ...cliArgs] : cliArgs;
  const child = spawn(freellmapiBin, spawnArgs, { stdio: 'inherit' });
  child.on('exit', (code) => process.exit(code ?? 1));
}

main();
