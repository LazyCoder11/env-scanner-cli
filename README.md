# Env Leak / Secret Scanner CLI 🔒

> Small npx tool that scans staged git changes or your entire codebase for accidentally committed API keys or secrets before you push. Every dev has leaked a key once.

[![npm version](https://img.shields.io/npm/v/@lazycoder20/env-scanner.svg)](https://www.npmjs.com/package/@lazycoder20/env-scanner)
[![license](https://img.shields.io/npm/l/@lazycoder20/env-scanner.svg)](LICENSE)

---

## 🚀 Quick Start

Run directly without installing via `npx`:

```bash
# 1. Scan staged git changes before commit (default)
npx @lazycoder20/env-scanner

# 2. Audit your entire workspace codebase for exposed secrets
npx @lazycoder20/env-scanner --all

# 3. Automatically install git pre-commit hook in your repo
npx @lazycoder20/env-scanner --install-hook
```

---

## 🖥️ Terminal Output Preview

When an exposed key or secret is detected, the CLI blocks the commit and provides exact line numbers and remediation steps:

```text
  SECURITY ALERT: ACCIDENTAL SECRET COMMIT BLOCKED  
Found 1 secret/credential violation(s) in staged files:

📁 src/config/api.ts
  ● [Line 14] OpenAI Secret Key (ai)
    Description: OpenAI API project or account secret key.
    Detected:    sk-proj-****...9821
    Code:        const apiKey = "sk-proj-98127391827398127398127398129821"; <!-- env-scanner-ignore -->

How to resolve before committing:
  1. Remove secret from code or replace with process.env.YOUR_KEY
  2. Unstage file: git restore --staged <file>
  3. Store real keys in .env (added to .gitignore)
  4. If this is a false positive, append // env-scanner-ignore to the line.
```

---

## ⚡ Features

- **Git Staged Interception**: Only scans added/modified lines in `git diff --staged` for instant sub-second execution.
- **Full Workspace Audits**: Pass `--all` to audit your entire repository codebase for pre-existing leaks.
- **116+ Built-in Secret Patterns**: Covers Cloud (AWS, GCP, Azure), AI (OpenAI, Anthropic, HuggingFace, Groq), Payments (Stripe, PayPal, Square), VCS (GitHub, GitLab, NPM, PyPI), Messaging (Slack, Discord, Twilio), Databases (Postgres, Mongo, Redis), and Auth/Crypto (JWTs, PEM/RSA).
- **Shannon Entropy Engine**: Calculates character randomness ($H \ge 4.2$) to catch unpatterned custom API key assignments.
- **Inline Suppression**: Append `// env-scanner-ignore` to mock/test lines to suppress false positives.
- **Zero Config Required**: Works out of the box with zero setup, with opt-in `.envscanner.json` and `.envignore` support.

---

## 📋 CLI Options

```text
  --staged, -s      Scan git staged changes (default)
  --all, -a         Scan all workspace files across project
  --json            Output violations in JSON format
  --quiet, -q       Suppress non-error output
  --install-hook    Install git pre-commit hook automatically
  --version, -v     Show version number
  --help, -h        Show help guide
```

---

## 📦 Package Info

- **Package Name**: `@lazycoder20/env-scanner`
- **Executables**: `env-scanner`, `secret-scanner`
