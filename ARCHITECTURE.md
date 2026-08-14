# Architecture Specification: Env Leak / Secret Scanner CLI

## System Overview

`@lazycoder11/env-scanner` is a lightweight, zero-dependency git pre-commit secret interceptor designed to run seamlessly via `npx` or as an automated git hook.

### Core Objectives
1. **Pre-commit Interception**: Intercepts staged changes (`git diff --staged`) before `git commit` records them into repository history.
2. **Deterministic & Statistical Detection**: Merges high-precision regex signatures with Shannon Entropy score evaluation to catch both known API key formats and randomized secret assignments.
3. **Zero Friction UX**: Provides colored, line-level terminal callouts with masked secret previews and one-command pre-commit hook installation.

---

## Component Architecture

```
+-----------------------------------------------------------------------+
|                              CLI Engine                               |
|                            (src/cli.ts)                               |
+-----------------------------------v-----------------------------------+
                                    |
            +-----------------------+-----------------------+
            |                                               |
+-----------v-----------+                       +-----------v-----------+
|    Git Diff Engine    |                       | Config & Ignore Engine|
|     (src/git.ts)      |                       |    (src/config.ts)    |
+-----------+-----------+                       +-----------+-----------+
            |                                               |
            +-----------------------+-----------------------+
                                    |
                        +-----------v-----------+
                        | Secret Scanner Engine |
                        |   (src/scanner.ts)    |
                        |  • Patterns (built-in)|
                        |  • Entropy Calculator |
                        +-----------+-----------+
                                    |
                        +-----------v-----------+
                        |  Terminal Formatter   |
                        |  (src/formatter.ts)   |
                        +-----------------------+
```

### Module Responsibilities

1. **`src/cli.ts`**: Entry point handling CLI flags (`--staged`, `--all`, `--json`, `--install-hook`), setting process exit codes (`0` for clean, `1` for violations found).
2. **`src/git.ts`**: Executes `git diff --staged -U0` to parse unified diff hunks (`@@ -old +new @@`), isolating added lines (`+`) with precise line numbers while skipping deleted lines and unchanged context.
3. **`src/patterns.ts`**: Pattern registry containing regular expressions for AWS, OpenAI, Anthropic, Stripe, GitHub, Slack, Google Cloud, PEM/RSA Private Keys, JWTs, and DB URIs.
4. **`src/entropy.ts`**: Computes Shannon entropy $H(X) = -\sum P(x_i) \log_2 P(x_i)$ to measure character randomness in string values, triggering on high-entropy strings ($H \ge 4.2$).
5. **`src/config.ts`**: Loads custom ignore list from `.envscanner.json` or `.envignore` and respects inline code comments (`// env-scanner-ignore`).
6. **`src/formatter.ts`**: Produces high-visibility terminal output with file icons, line numbers, highlighted inline code, masked secrets, and step-by-step resolution guides.

---

## Secret Detection Rules (116 Built-in Patterns)

| Category | Pattern Count | Example Providers / Key Types | Severity |
| :--- | :---: | :--- | :--- |
| **Cloud Infrastructure** | 18 | AWS (Access/Secret/MWS), GCP, Azure, DigitalOcean, Linode, Alibaba, Tencent, OCI, Cloudflare | CRITICAL / HIGH |
| **AI & Machine Learning** | 15 | OpenAI, Anthropic, Cohere, HuggingFace, Replicate, Pinecone, LangChain, Groq, Perplexity, Mistral | CRITICAL / HIGH |
| **Payment & Financial** | 14 | Stripe (Live/Restricted/Webhooks), PayPal, Square, Razorpay, Plaid, Brex, Braintree, Coinbase, Paddle | CRITICAL / HIGH |
| **VCS & Package Registries** | 15 | GitHub (PAT/Fine-Grained/OAuth/App), GitLab, Bitbucket, NPM, PyPI, RubyGems, DockerHub, Terraform, Vault | CRITICAL |
| **Messaging & Notifications** | 13 | Slack (Bot/Webhooks), Discord, Telegram, Twilio, SendGrid, Mailchimp, Postmark, Resend, Mailgun | CRITICAL / HIGH |
| **PaaS & Monitoring** | 15 | Firebase, Supabase (Service/Anon), Vercel, Netlify, Heroku, DataDog, Sentry, NewRelic, Grafana, Postman | CRITICAL / HIGH |
| **Databases & Caches** | 10 | Postgres, MySQL, MongoDB, Redis, Snowflake, Neo4j, Cassandra, ClickHouse, MSSQL, Elasticsearch | CRITICAL |
| **Social & OAuth** | 8 | Google OAuth, Facebook, Twitter/X, LinkedIn, Spotify, Auth0, Okta | CRITICAL |
| **Cryptographic & Generic** | 8 | RSA/PEM, OpenSSH, PGP, Age Keys, WireGuard, JWTs, Shannon Entropy ($H \ge 4.2$) | CRITICAL / MEDIUM |

---

## Git Integration Workflow

```
Dev runs `git commit`
       │
       ▼
Git executes .git/hooks/pre-commit
       │
       ▼
Runs `npx @lazycoder11/env-scanner --staged`
       │
       ├──────────────────────────┐
       ▼                          ▼
  Violations Found           Clean Scan
       │                          │
  Terminal Alert             Passes execution
  Exit Code 1                Exit Code 0
  Commit Blocked             Commit Proceeds
```
