# Env Leak / Secret Scanner CLI 🔒

> Small npx tool that scans staged git changes for accidentally committed API keys or secrets before you push. Every dev has leaked a key once.

[![npm version](https://img.shields.io/npm/v/@lazycoder20/env-scanner.svg)](https://www.npmjs.com/package/@lazycoder20/env-scanner)
[![license](https://img.shields.io/npm/l/@lazycoder20/env-scanner.svg)](LICENSE)

---

## 🚀 Quick Start

Run directly without installing via `npx`:

```bash
npx @lazycoder20/env-scanner
```

### Install as Pre-commit Hook

Automatically block secret commits in your repository with one command:

```bash
npx @lazycoder20/env-scanner --install-hook
```

---

## ⚡ Features

- **Git Staged Scanning**: Only checks added/modified lines in `git diff --staged` for lightning speed.
- **116+ Built-in Secret Patterns**: Covers Cloud (AWS, GCP, Azure), AI (OpenAI, Anthropic, HuggingFace, Groq), Payments (Stripe, PayPal, Square), VCS (GitHub, GitLab, NPM, PyPI), Messaging (Slack, Discord, Twilio), Databases (Postgres, Mongo, Redis), and Auth/Crypto (JWTs, PEM/RSA).
- **Shannon Entropy Detection**: Catches randomized high-entropy API key assignments even if they don't match standard prefixes.
- **Inline Ignorability**: Append `// env-scanner-ignore` to mock/test lines to suppress alerts.
- **Zero Config Required**: Works out of the box with zero setup, with opt-in `.envscanner.json` and `.envignore` support.

---

## 📋 Options

```text
  --staged, -s      Scan git staged changes (default)
  --all, -a         Scan all workspace files
  --json            Output violations in JSON format
  --quiet, -q       Suppress non-error output
  --install-hook    Install git pre-commit hook automatically
  --version, -v     Show version number
  --help, -h        Show help guide
```

---

## 🎥 20-Second Terminal Demo

![Demo GIF](demo/demo.gif)

*(To record or update the demo GIF, run VHS using `vhs demo/demo.tape`)*

---

## 📦 Package Details

- **Package Name**: `@lazycoder20/env-scanner`
- **Org**: `lazycoder20`
- **Bin Command**: `env-scanner`, `secret-scanner`
