#!/usr/bin/env node
import { runScan } from './scanner.js';
import { formatTerminalOutput } from './formatter.js';
import { execSync } from 'child_process';
import fs from 'fs';
import path from 'path';

function main() {
  const args = process.argv.slice(2);

  if (args.includes('--help') || args.includes('-h')) {
    printHelp();
    process.exit(0);
  }

  if (args.includes('--version') || args.includes('-v')) {
    console.log('env-scanner v1.0.0 (@lazycoder20/env-scanner)');
    process.exit(0);
  }

  if (args.includes('--install-hook')) {
    installGitHook();
    process.exit(0);
  }

  const scanAll = args.includes('--all') || args.includes('-a');
  const jsonOutput = args.includes('--json');
  const quiet = args.includes('--quiet') || args.includes('-q');

  try {
    const violations = runScan({ scanAll, jsonOutput, quiet });

    if (jsonOutput) {
      console.log(JSON.stringify(violations, null, 2));
    } else {
      console.log(formatTerminalOutput(violations));
    }

    if (violations.length > 0) {
      process.exit(1);
    } else {
      process.exit(0);
    }
  } catch (err: any) {
    console.error(`\x1b[31mError: ${err.message}\x1b[0m`);
    process.exit(1);
  }
}

function printHelp() {
  console.log(`
\x1b[1m\x1b[36mEnv Leak / Secret Scanner CLI\x1b[0m (@lazycoder20/env-scanner)
Scans staged git changes for accidentally committed API keys or secrets before you push.

\x1b[1mUSAGE:\x1b[0m
  $ npx @lazycoder20/env-scanner [options]
  $ env-scanner [options]

\x1b[1mOPTIONS:\x1b[0m
  --staged, -s      Scan git staged changes (default)
  --all, -a         Scan all workspace files
  --json            Output violations in JSON format
  --quiet, -q       Suppress non-error output
  --install-hook    Install git pre-commit hook automatically
  --version, -v     Show version number
  --help, -h        Show help and usage guide

\x1b[1mINLINE SUPPRESSION:\x1b[0m
  Append \x1b[2m// env-scanner-ignore\x1b[0m to any line to ignore deliberate test tokens.
`);
}

function installGitHook() {
  const gitHooksDir = path.join(process.cwd(), '.git', 'hooks');
  if (!fs.existsSync(gitHooksDir)) {
    console.error('\x1b[31mError: .git directory not found. Initialize git first.\x1b[0m');
    process.exit(1);
  }

  const hookPath = path.join(gitHooksDir, 'pre-commit');
  const hookScript = `#!/bin/sh
# env-scanner pre-commit hook
npx @lazycoder20/env-scanner --staged
`;

  fs.writeFileSync(hookPath, hookScript, { mode: 0o755 });
  console.log('\x1b[32m✔ Git pre-commit hook installed successfully in .git/hooks/pre-commit!\x1b[0m');
}

main();
