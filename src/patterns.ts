import { SecretPattern } from './types.js';

export const BUILTIN_PATTERNS: SecretPattern[] = [
  // ==========================================
  // 1. CLOUD INFRASTRUCTURE (18 Rules)
  // ==========================================
  {
    id: 'aws-access-key',
    name: 'AWS Access Key ID',
    category: 'cloud',
    severity: 'CRITICAL',
    regex: /\b(AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b/g,
    description: 'AWS IAM user or temporary credentials access key.'
  },
  {
    id: 'aws-secret-key',
    name: 'AWS Secret Access Key',
    category: 'cloud',
    severity: 'CRITICAL',
    regex: /(?:aws_secret_access_key|aws_secret_key|secret_key)\s*[:=]\s*["']?([A-Za-z0-9\/+=]{40})["']?/gi,
    description: 'AWS IAM Secret Access Key assigned in code or config.'
  },
  {
    id: 'aws-mws-key',
    name: 'AWS MWS Auth Token',
    category: 'cloud',
    severity: 'HIGH',
    regex: /\bamzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi,
    description: 'Amazon Marketplace Web Service authorization token.'
  },
  {
    id: 'gcp-api-key',
    name: 'Google Cloud API Key',
    category: 'cloud',
    severity: 'HIGH',
    regex: /\bAIzaSy[a-zA-Z0-9_-]{33}\b/g,
    description: 'Google Cloud Platform API key.'
  },
  {
    id: 'gcp-service-account',
    name: 'GCP Service Account Private Key',
    category: 'cloud',
    severity: 'CRITICAL',
    regex: /"private_key"\s*:\s*"-----BEGIN PRIVATE KEY-----\\n[a-zA-Z0-9\/+=\\n]+-----END PRIVATE KEY-----\\n"/g, // env-scanner-ignore
    description: 'Google Cloud Service Account JSON credentials private key.'
  },
  {
    id: 'azure-client-secret',
    name: 'Azure Service Principal Client Secret',
    category: 'cloud',
    severity: 'CRITICAL',
    regex: /(?:azure_client_secret|AZURE_CLIENT_SECRET|client_secret)\s*[:=]\s*["']([a-zA-Z0-9_~\-\.\/+=]{34,44})["']/gi,
    entropyThreshold: 4.2,
    description: 'Microsoft Azure Active Directory app registration client secret.'
  },
  {
    id: 'azure-storage-account-key',
    name: 'Azure Storage Account Key',
    category: 'cloud',
    severity: 'CRITICAL',
    regex: /AccountKey=[a-zA-Z0-9\/+=]{86,90};/g,
    description: 'Azure Blob/Table storage connection string account key.'
  },
  {
    id: 'azure-management-cert',
    name: 'Azure Management Certificate',
    category: 'cloud',
    severity: 'HIGH',
    regex: /<ManagementCertificate>[a-zA-Z0-9\/+=]{100,}<\/ManagementCertificate>/g,
    description: 'Legacy Azure XML Management Certificate.'
  },
  {
    id: 'digitalocean-access-token',
    name: 'DigitalOcean Personal Access Token',
    category: 'cloud',
    severity: 'CRITICAL',
    regex: /\bdop_v1_[a-f0-9]{64}\b/g,
    description: 'DigitalOcean API personal access token.'
  },
  {
    id: 'digitalocean-pat',
    name: 'DigitalOcean OAuth Access Token',
    category: 'cloud',
    severity: 'HIGH',
    regex: /\bdo_pat_[a-f0-9]{64}\b/g,
    description: 'DigitalOcean OAuth application token.'
  },
  {
    id: 'linode-access-token',
    name: 'Linode Personal Access Token',
    category: 'cloud',
    severity: 'HIGH',
    regex: /\b[a-f0-9]{64}\b/g,
    entropyThreshold: 4.8,
    description: 'Linode API access token.'
  },
  {
    id: 'alibaba-access-key-id',
    name: 'Alibaba Cloud Access Key ID',
    category: 'cloud',
    severity: 'HIGH',
    regex: /\bLTAI[a-zA-Z0-9]{16,20}\b/g,
    description: 'Alibaba Cloud RAM user AccessKey ID.'
  },
  {
    id: 'alibaba-secret-key',
    name: 'Alibaba Cloud Secret Key',
    category: 'cloud',
    severity: 'CRITICAL',
    regex: /(?:alibaba_secret_key|ALIBABA_SECRET)\s*[:=]\s*["']([a-zA-Z0-9]{30})["']/gi,
    description: 'Alibaba Cloud Secret Key.'
  },
  {
    id: 'tencent-secret-id',
    name: 'Tencent Cloud Secret ID',
    category: 'cloud',
    severity: 'HIGH',
    regex: /\bAKID[a-zA-Z0-9]{32}\b/g,
    description: 'Tencent Cloud API Secret ID.'
  },
  {
    id: 'tencent-secret-key',
    name: 'Tencent Cloud Secret Key',
    category: 'cloud',
    severity: 'CRITICAL',
    regex: /(?:tencent_secret_key|TENCENT_SECRET)\s*[:=]\s*["']([a-zA-Z0-9]{32})["']/gi,
    description: 'Tencent Cloud API Secret Key.'
  },
  {
    id: 'oracle-cloud-api-key',
    name: 'Oracle Cloud Infrastructure (OCI) Fingerprint',
    category: 'cloud',
    severity: 'MEDIUM',
    regex: /\b(?:[0-9a-f]{2}:){15}[0-9a-f]{2}\b/gi,
    description: 'Oracle Cloud Infrastructure API signing key fingerprint.'
  },
  {
    id: 'cloudflare-api-key',
    name: 'Cloudflare API Token',
    category: 'cloud',
    severity: 'HIGH',
    regex: /\b[a-zA-Z0-9_-]{40}\b/g,
    entropyThreshold: 4.9,
    description: 'Cloudflare Scoped API Token.'
  },
  {
    id: 'cloudflare-global-api-key',
    name: 'Cloudflare Global API Key',
    category: 'cloud',
    severity: 'CRITICAL',
    regex: /(?:cloudflare_api_key|CLOUDFLARE_KEY)\s*[:=]\s*["']([a-f0-9]{37})["']/gi,
    description: 'Cloudflare Global API Key.'
  },

  // ==========================================
  // 2. AI & MACHINE LEARNING SERVICES (15 Rules)
  // ==========================================
  {
    id: 'openai-api-key',
    name: 'OpenAI Secret Key',
    category: 'ai',
    severity: 'CRITICAL',
    regex: /\bsk-(?:proj-|svcacct-|admin-)?[a-zA-Z0-9_-]{32,64}\b/g,
    description: 'OpenAI API project or account secret key.'
  },
  {
    id: 'openai-organization-id',
    name: 'OpenAI Organization ID',
    category: 'ai',
    severity: 'MEDIUM',
    regex: /\borg-[a-zA-Z0-9]{24}\b/g,
    description: 'OpenAI Organization Identifier.'
  },
  {
    id: 'anthropic-api-key',
    name: 'Anthropic API Key',
    category: 'ai',
    severity: 'CRITICAL',
    regex: /\bsk-ant-api03-[a-zA-Z0-9_-]{80,100}\b/g,
    description: 'Anthropic Claude API key.'
  },
  {
    id: 'cohere-api-key',
    name: 'Cohere API Key',
    category: 'ai',
    severity: 'CRITICAL',
    regex: /(?:COHERE_API_KEY|cohere_key)\s*[:=]\s*["']([a-zA-Z0-9]{40})["']/gi,
    description: 'Cohere LLM platform API key.'
  },
  {
    id: 'huggingface-user-access-token',
    name: 'HuggingFace User Access Token',
    category: 'ai',
    severity: 'CRITICAL',
    regex: /\bhf_[a-zA-Z0-9]{34}\b/g,
    description: 'HuggingFace Hub read/write access token.'
  },
  {
    id: 'replicate-api-token',
    name: 'Replicate API Token',
    category: 'ai',
    severity: 'CRITICAL',
    regex: /\br8_[a-zA-Z0-9]{37}\b/g,
    description: 'Replicate AI model hosting API token.'
  },
  {
    id: 'pinecone-api-key',
    name: 'Pinecone Vector DB API Key',
    category: 'ai',
    severity: 'CRITICAL',
    regex: /\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi,
    entropyThreshold: 4.0,
    description: 'Pinecone Vector Database API Key.'
  },
  {
    id: 'langchain-api-key',
    name: 'LangChain / LangSmith API Key',
    category: 'ai',
    severity: 'HIGH',
    regex: /\blsv2_pt_[a-zA-Z0-9]{32}_[a-zA-Z0-9]{10}\b/g,
    description: 'LangSmith / LangChain tracing API key.'
  },
  {
    id: 'weights-biases-api-key',
    name: 'Weights & Biases API Key',
    category: 'ai',
    severity: 'HIGH',
    regex: /(?:WANDB_API_KEY|wandb_key)\s*[:=]\s*["']([a-f0-9]{40})["']/gi,
    description: 'Weights & Biases ML experiment tracking key.'
  },
  {
    id: 'groq-api-key',
    name: 'Groq Cloud API Key',
    category: 'ai',
    severity: 'CRITICAL',
    regex: /\bgsk_[a-zA-Z0-9]{52}\b/g,
    description: 'Groq LPU AI inference API key.'
  },
  {
    id: 'together-ai-api-key',
    name: 'Together AI API Key',
    category: 'ai',
    severity: 'CRITICAL',
    regex: /(?:TOGETHER_API_KEY|together_key)\s*[:=]\s*["']([a-f0-9]{64})["']/gi,
    description: 'Together AI API Key.'
  },
  {
    id: 'perplexity-api-key',
    name: 'Perplexity AI API Key',
    category: 'ai',
    severity: 'CRITICAL',
    regex: /\bpplx-[a-zA-Z0-9]{48}\b/g,
    description: 'Perplexity AI Search API key.'
  },
  {
    id: 'mistral-api-key',
    name: 'Mistral AI API Key',
    category: 'ai',
    severity: 'CRITICAL',
    regex: /(?:MISTRAL_API_KEY|mistral_key)\s*[:=]\s*["']([a-zA-Z0-9]{32})["']/gi,
    description: 'Mistral AI platform API key.'
  },
  {
    id: 'stability-ai-api-key',
    name: 'Stability AI API Key',
    category: 'ai',
    severity: 'CRITICAL',
    regex: /\bsk-[a-zA-Z0-9]{48}\b/g,
    description: 'Stability AI image generation API key.'
  },
  {
    id: 'elevenlabs-api-key',
    name: 'ElevenLabs Voice API Key',
    category: 'ai',
    severity: 'HIGH',
    regex: /(?:ELEVENLABS_API_KEY|elevenlabs_key)\s*[:=]\s*["']([a-f0-9]{32})["']/gi,
    description: 'ElevenLabs Text-to-Speech API key.'
  },

  // ==========================================
  // 3. PAYMENT & FINANCIAL APIS (14 Rules)
  // ==========================================
  {
    id: 'stripe-secret-key',
    name: 'Stripe Secret API Key',
    category: 'payment',
    severity: 'CRITICAL',
    regex: /\b(?:sk|rk)_live_[0-9a-zA-Z]{24,99}\b/g,
    description: 'Live Stripe API secret key for payment processing.'
  },
  {
    id: 'stripe-restricted-key',
    name: 'Stripe Restricted API Key',
    category: 'payment',
    severity: 'CRITICAL',
    regex: /\brk_live_[0-9a-zA-Z]{24,99}\b/g,
    description: 'Stripe Restricted API key.'
  },
  {
    id: 'stripe-webhook-secret',
    name: 'Stripe Webhook Signing Secret',
    category: 'payment',
    severity: 'HIGH',
    regex: /\bwhsec_[0-9a-zA-Z]{32,64}\b/g,
    description: 'Stripe webhook verification secret.'
  },
  {
    id: 'paypal-client-secret',
    name: 'PayPal Client Secret',
    category: 'payment',
    severity: 'CRITICAL',
    regex: /\bE[A-Za-z0-9_-]{79}\b/g,
    description: 'PayPal REST API application client secret.'
  },
  {
    id: 'square-access-token',
    name: 'Square Production Access Token',
    category: 'payment',
    severity: 'CRITICAL',
    regex: /\bEAAA[a-zA-Z0-9_-]{60}\b/g,
    description: 'Square Payments production access token.'
  },
  {
    id: 'square-oauth-secret',
    name: 'Square OAuth Secret',
    category: 'payment',
    severity: 'CRITICAL',
    regex: /\bsq0csp-[0-9a-zA-Z_-]{43}\b/g,
    description: 'Square OAuth client secret.'
  },
  {
    id: 'razorpay-key-secret',
    name: 'Razorpay Key Secret',
    category: 'payment',
    severity: 'CRITICAL',
    regex: /(?:razorpay_secret|RAZORPAY_KEY_SECRET)\s*[:=]\s*["']([a-zA-Z0-9]{24})["']/gi,
    description: 'Razorpay merchant API secret key.'
  },
  {
    id: 'plaid-secret',
    name: 'Plaid API Secret',
    category: 'payment',
    severity: 'CRITICAL',
    regex: /(?:PLAID_SECRET|plaid_secret)\s*[:=]\s*["']([a-zA-Z0-9]{30})["']/gi,
    description: 'Plaid banking integration client secret.'
  },
  {
    id: 'brex-api-key',
    name: 'Brex API User Token',
    category: 'payment',
    severity: 'CRITICAL',
    regex: /\bbrex_[a-zA-Z0-9_-]{32,64}\b/g,
    description: 'Brex corporate financial API token.'
  },
  {
    id: 'braintree-access-token',
    name: 'Braintree Access Token',
    category: 'payment',
    severity: 'CRITICAL',
    regex: /\baccess_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}\b/g,
    description: 'Braintree payment gateway access token.'
  },
  {
    id: 'coinbase-api-secret',
    name: 'Coinbase API Secret',
    category: 'payment',
    severity: 'CRITICAL',
    regex: /(?:coinbase_secret|COINBASE_API_SECRET)\s*[:=]\s*["']([a-zA-Z0-9\/+=]{88})["']/gi,
    description: 'Coinbase Pro/Exchange API secret key.'
  },
  {
    id: 'paddle-api-key',
    name: 'Paddle API Vendor Auth Code',
    category: 'payment',
    severity: 'HIGH',
    regex: /(?:PADDLE_AUTH_CODE|paddle_api_key)\s*[:=]\s*["']([a-f0-9]{64})["']/gi,
    description: 'Paddle e-commerce billing API auth code.'
  },
  {
    id: 'lemon-squeezy-api-key',
    name: 'Lemon Squeezy API Key',
    category: 'payment',
    severity: 'HIGH',
    regex: /(?:LEMONSQUEEZY_API_KEY|lemon_squeezy_key)\s*[:=]\s*["']([a-zA-Z0-9]{40,100})["']/gi,
    description: 'Lemon Squeezy store API token.'
  },
  {
    id: 'twispay-secret-key',
    name: 'Twispay Secret Key',
    category: 'payment',
    severity: 'HIGH',
    regex: /(?:TWISPAY_SECRET_KEY|twispay_secret)\s*[:=]\s*["']([a-f0-9]{32})["']/gi,
    description: 'Twispay merchant secret key.'
  },

  // ==========================================
  // 4. VCS & PACKAGE REGISTRIES (15 Rules)
  // ==========================================
  {
    id: 'github-personal-token',
    name: 'GitHub Personal Access Token',
    category: 'vcs',
    severity: 'CRITICAL',
    regex: /\b(?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36}\b/g,
    description: 'GitHub Personal Access Token or OAuth token.'
  },
  {
    id: 'github-fine-grained-token',
    name: 'GitHub Fine-Grained Access Token',
    category: 'vcs',
    severity: 'CRITICAL',
    regex: /\bgithub_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}\b/g,
    description: 'GitHub Fine-grained access token.'
  },
  {
    id: 'github-oauth-access-token',
    name: 'GitHub OAuth Access Token',
    category: 'vcs',
    severity: 'CRITICAL',
    regex: /\bgho_[a-zA-Z0-9]{36}\b/g,
    description: 'GitHub OAuth user access token.'
  },
  {
    id: 'github-app-token',
    name: 'GitHub App Installation Token',
    category: 'vcs',
    severity: 'HIGH',
    regex: /\bghs_[a-zA-Z0-9]{36}\b/g,
    description: 'GitHub App server installation token.'
  },
  {
    id: 'gitlab-personal-access-token',
    name: 'GitLab Personal Access Token',
    category: 'vcs',
    severity: 'CRITICAL',
    regex: /\bglpat-[a-zA-Z0-9_-]{20}\b/g,
    description: 'GitLab personal access token.'
  },
  {
    id: 'gitlab-pipeline-trigger-token',
    name: 'GitLab Pipeline Trigger Token',
    category: 'vcs',
    severity: 'HIGH',
    regex: /\bglptt-[a-f0-9]{40}\b/g,
    description: 'GitLab CI pipeline trigger token.'
  },
  {
    id: 'bitbucket-client-secret',
    name: 'Bitbucket OAuth Secret',
    category: 'vcs',
    severity: 'CRITICAL',
    regex: /(?:bitbucket_secret|BITBUCKET_CLIENT_SECRET)\s*[:=]\s*["']([a-zA-Z0-9_-]{32})["']/gi,
    description: 'Bitbucket Cloud OAuth client secret.'
  },
  {
    id: 'npm-access-token',
    name: 'NPM Access Token',
    category: 'vcs',
    severity: 'CRITICAL',
    regex: /\bnpm_[a-zA-Z0-9]{36}\b/g,
    description: 'NPM package publisher automation access token.'
  },
  {
    id: 'pypi-api-token',
    name: 'PyPI API Token',
    category: 'vcs',
    severity: 'CRITICAL',
    regex: /\bpypi-AgEIcHlwaS5vcmc[a-zA-Z0-9_-]{50,150}\b/g,
    description: 'Python Package Index (PyPI) package upload API token.'
  },
  {
    id: 'rubygems-api-key',
    name: 'RubyGems API Key',
    category: 'vcs',
    severity: 'CRITICAL',
    regex: /\brubygems_[a-f0-9]{48}\b/g,
    description: 'RubyGems gem publisher API key.'
  },
  {
    id: 'dockerhub-auth-token',
    name: 'Docker Hub Personal Access Token',
    category: 'vcs',
    severity: 'CRITICAL',
    regex: /\bdckr_pat_[a-zA-Z0-9_-]{27}\b/g,
    description: 'Docker Hub personal access token.'
  },
  {
    id: 'terraform-cloud-api-token',
    name: 'Terraform Cloud API Token',
    category: 'vcs',
    severity: 'CRITICAL',
    regex: /\b[a-zA-Z0-9]{14}\.atlasv1\.[a-zA-Z0-9_-]{60,70}\b/g,
    description: 'HashiCorp Terraform Cloud / Enterprise user API token.'
  },
  {
    id: 'hashicorp-vault-token',
    name: 'HashiCorp Vault Token',
    category: 'vcs',
    severity: 'CRITICAL',
    regex: /\bhvb\.[a-zA-Z0-9_-]{138,142}\b/g,
    description: 'HashiCorp Vault batch or client token.'
  },
  {
    id: 'cargo-api-token',
    name: 'Cargo / Crates.io API Token',
    category: 'vcs',
    severity: 'CRITICAL',
    regex: /\bcid_[a-zA-Z0-9_-]{32}\b/g,
    description: 'Crates.io Rust package registry API token.'
  },
  {
    id: 'nuget-api-key',
    name: 'NuGet API Key',
    category: 'vcs',
    severity: 'CRITICAL',
    regex: /\boy2[a-z0-9]{43}\b/g,
    description: '.NET NuGet package publishing key.'
  },

  // ==========================================
  // 5. MESSAGING & NOTIFICATIONS (13 Rules)
  // ==========================================
  {
    id: 'slack-bot-token',
    name: 'Slack Bot / OAuth Token',
    category: 'messaging',
    severity: 'HIGH',
    regex: /\bxox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*\b/g,
    description: 'Slack Bot, App, or User OAuth access token.'
  },
  {
    id: 'slack-webhook-url',
    name: 'Slack Incoming Webhook URL',
    category: 'messaging',
    severity: 'HIGH',
    regex: /https:\/\/hooks\.slack\.com\/services\/T[a-zA-Z0-9_]{8,12}\/B[a-zA-Z0-9_]{8,12}\/[a-zA-Z0-9_]{24}/g,
    description: 'Slack Incoming Webhook URL containing embedded routing secret.'
  },
  {
    id: 'discord-bot-token',
    name: 'Discord Bot Token',
    category: 'messaging',
    severity: 'CRITICAL',
    regex: /\b[MNO][a-zA-Z0-9_-]{23,25}\.[a-zA-Z0-9_-]{6}\.[a-zA-Z0-9_-]{27,38}\b/g,
    description: 'Discord Bot authorization token.'
  },
  {
    id: 'discord-webhook-url',
    name: 'Discord Webhook URL',
    category: 'messaging',
    severity: 'HIGH',
    regex: /https:\/\/discord(?:app)?\.com\/api\/webhooks\/[0-9]{17,20}\/[a-zA-Z0-9_-]{60,70}/g,
    description: 'Discord Webhook endpoint URL.'
  },
  {
    id: 'telegram-bot-token',
    name: 'Telegram Bot API Token',
    category: 'messaging',
    severity: 'HIGH',
    regex: /\b[0-9]{8,10}:[a-zA-Z0-9_-]{35}\b/g,
    description: 'Telegram Bot API HTTP authorization token.'
  },
  {
    id: 'twilio-api-key',
    name: 'Twilio API Key',
    category: 'messaging',
    severity: 'HIGH',
    regex: /\bSK[0-9a-fA-F]{32}\b/g,
    description: 'Twilio API SID Key.'
  },
  {
    id: 'twilio-account-sid-secret',
    name: 'Twilio Auth Token',
    category: 'messaging',
    severity: 'CRITICAL',
    regex: /(?:twilio_auth_token|TWILIO_AUTH_TOKEN)\s*[:=]\s*["']([0-9a-f]{32})["']/gi,
    description: 'Twilio Account Auth Token.'
  },
  {
    id: 'sendgrid-api-key',
    name: 'SendGrid API Key',
    category: 'messaging',
    severity: 'CRITICAL',
    regex: /\bSG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}\b/g,
    description: 'SendGrid email service API key.'
  },
  {
    id: 'mailchimp-api-key',
    name: 'Mailchimp API Key',
    category: 'messaging',
    severity: 'HIGH',
    regex: /\b[0-9a-f]{32}-us[0-9]{1,2}\b/g,
    description: 'Mailchimp marketing platform API key.'
  },
  {
    id: 'postmark-server-token',
    name: 'Postmark Server Token',
    category: 'messaging',
    severity: 'HIGH',
    regex: /\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi,
    entropyThreshold: 4.1,
    description: 'Postmark transactional email server API token.'
  },
  {
    id: 'resend-api-key',
    name: 'Resend Email API Key',
    category: 'messaging',
    severity: 'HIGH',
    regex: /\bre_[a-zA-Z0-9]{36}\b/g,
    description: 'Resend transaction email API key.'
  },
  {
    id: 'mailgun-api-key',
    name: 'Mailgun Private API Key',
    category: 'messaging',
    severity: 'CRITICAL',
    regex: /\bkey-[0-9a-f]{32}\b/g,
    description: 'Mailgun email API key.'
  },

  // ==========================================
  // 6. PAAS, HOSTING & MONITORING (15 Rules)
  // ==========================================
  {
    id: 'firebase-server-key',
    name: 'Firebase Cloud Messaging Server Key',
    category: 'paas',
    severity: 'CRITICAL',
    regex: /\bAAAA[a-zA-Z0-9_-]{7}:[a-zA-Z0-9_-]{140}\b/g,
    description: 'Firebase Cloud Messaging (FCM) legacy server key.'
  },
  {
    id: 'supabase-service-role-key',
    name: 'Supabase Service Role JWT Secret',
    category: 'paas',
    severity: 'CRITICAL',
    regex: /(?:SUPABASE_SERVICE_ROLE_KEY|supabase_service_key)\s*[:=]\s*["'](eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)["']/gi,
    description: 'Supabase admin service role secret key (bypasses RLS).'
  },
  {
    id: 'supabase-anon-key',
    name: 'Supabase Public Anon Key',
    category: 'paas',
    severity: 'MEDIUM',
    regex: /(?:SUPABASE_ANON_KEY|supabase_anon_key)\s*[:=]\s*["'](eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)["']/gi,
    description: 'Supabase public anon client key.'
  },
  {
    id: 'vercel-access-token',
    name: 'Vercel Personal Access Token',
    category: 'paas',
    severity: 'CRITICAL',
    regex: /(?:VERCEL_TOKEN|vercel_access_token)\s*[:=]\s*["']([a-zA-Z0-9]{24})["']/gi,
    description: 'Vercel CLI & API personal access token.'
  },
  {
    id: 'netlify-access-token',
    name: 'Netlify Personal Access Token',
    category: 'paas',
    severity: 'CRITICAL',
    regex: /(?:NETLIFY_AUTH_TOKEN|netlify_access_token)\s*[:=]\s*["']([a-zA-Z0-9_-]{40,45})["']/gi,
    description: 'Netlify deployment personal access token.'
  },
  {
    id: 'heroku-api-key',
    name: 'Heroku API Key',
    category: 'paas',
    severity: 'CRITICAL',
    regex: /\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi,
    entropyThreshold: 4.1,
    description: 'Heroku Platform API key.'
  },
  {
    id: 'datadog-api-key',
    name: 'DataDog API Key',
    category: 'paas',
    severity: 'HIGH',
    regex: /\b[a-f0-9]{32}\b/g,
    entropyThreshold: 4.6,
    description: 'DataDog monitoring ingestion API key.'
  },
  {
    id: 'datadog-app-key',
    name: 'DataDog Application Key',
    category: 'paas',
    severity: 'CRITICAL',
    regex: /\b[a-f0-9]{40}\b/g,
    entropyThreshold: 4.8,
    description: 'DataDog Application key with management privileges.'
  },
  {
    id: 'sentry-auth-token',
    name: 'Sentry Auth Token',
    category: 'paas',
    severity: 'HIGH',
    regex: /\b[a-f0-9]{64}\b/g,
    entropyThreshold: 4.7,
    description: 'Sentry error tracking integration token.'
  },
  {
    id: 'newrelic-user-api-key',
    name: 'New Relic User API Key',
    category: 'paas',
    severity: 'HIGH',
    regex: /\bNRAK-[A-Z0-9]{27}\b/g,
    description: 'New Relic User API Key.'
  },
  {
    id: 'grafana-api-key',
    name: 'Grafana Cloud API Service Account Token',
    category: 'paas',
    severity: 'HIGH',
    regex: /\beyJrIjoi[a-zA-Z0-9_-]{60,100}\b/g,
    description: 'Grafana Service Account Token.'
  },
  {
    id: 'logtail-source-token',
    name: 'Logtail / Better Stack Source Token',
    category: 'paas',
    severity: 'MEDIUM',
    regex: /(?:LOGTAIL_SOURCE_TOKEN|logtail_token)\s*[:=]\s*["']([a-zA-Z0-9]{24})["']/gi,
    description: 'Better Stack / Logtail log ingestion token.'
  },
  {
    id: 'mixpanel-api-secret',
    name: 'Mixpanel API Secret',
    category: 'paas',
    severity: 'HIGH',
    regex: /(?:MIXPANEL_SECRET|mixpanel_api_secret)\s*[:=]\s*["']([a-f0-9]{32})["']/gi,
    description: 'Mixpanel product analytics secret.'
  },
  {
    id: 'segment-write-key',
    name: 'Segment Public Write Key',
    category: 'paas',
    severity: 'MEDIUM',
    regex: /(?:SEGMENT_WRITE_KEY|segment_key)\s*[:=]\s*["']([a-zA-Z0-9]{32})["']/gi,
    description: 'Segment customer data platform write key.'
  },
  {
    id: 'postman-api-key',
    name: 'Postman API Key',
    category: 'paas',
    severity: 'HIGH',
    regex: /\bPMAK-[a-f0-9]{24}-[a-f0-9]{34}\b/g,
    description: 'Postman workspace API key.'
  },

  // ==========================================
  // 7. DATABASES & CACHE URIS (10 Rules)
  // ==========================================
  {
    id: 'postgres-uri-credentials',
    name: 'PostgreSQL Connection URI with Password',
    category: 'database',
    severity: 'CRITICAL',
    regex: /\bpostgres(?:ql)?:\/\/[a-zA-Z0-9_.-]+:[^@\s"']+@[a-zA-Z0-9_.-]+:[0-9]{2,5}\/[a-zA-Z0-9_.-]+/gi,
    description: 'PostgreSQL connection string with cleartext username and password.'
  },
  {
    id: 'mysql-uri-credentials',
    name: 'MySQL Connection URI with Password',
    category: 'database',
    severity: 'CRITICAL',
    regex: /\bmysql:\/\/[a-zA-Z0-9_.-]+:[^@\s"']+@[a-zA-Z0-9_.-]+:[0-9]{2,5}\/[a-zA-Z0-9_.-]+/gi,
    description: 'MySQL database connection URL with credentials.'
  },
  {
    id: 'mongodb-uri-credentials',
    name: 'MongoDB Connection URI with Password',
    category: 'database',
    severity: 'CRITICAL',
    regex: /\bmongodb(?:\+srv)?:\/\/[a-zA-Z0-9_.-]+:[^@\s"']+@[a-zA-Z0-9_.-]+/gi,
    description: 'MongoDB Atlas or standalone database connection string with password.'
  },
  {
    id: 'redis-uri-password',
    name: 'Redis Connection URI with Password',
    category: 'database',
    severity: 'CRITICAL',
    regex: /\brediss?:\/\/(?::[^@\s"']+)?[@][a-zA-Z0-9_.-]+:[0-9]{2,5}\b/gi,
    description: 'Redis in-memory cache connection URL containing auth credentials.'
  },
  {
    id: 'snowflake-connection-url',
    name: 'Snowflake Database Connection URL',
    category: 'database',
    severity: 'CRITICAL',
    regex: /\b[a-z0-9_-]+\.snowflakecomputing\.com\/[a-z0-9_?&=]+/gi,
    entropyThreshold: 4.0,
    description: 'Snowflake Data Warehouse connection URL.'
  },
  {
    id: 'neo4j-bolt-credentials',
    name: 'Neo4j Bolt Protocol URI with Credentials',
    category: 'database',
    severity: 'CRITICAL',
    regex: /\bbolt(?:\+s|\+ssc)?:\/\/[a-zA-Z0-9_.-]+:[^@\s"']+@[a-zA-Z0-9_.-]+:[0-9]{2,5}\b/gi,
    description: 'Neo4j Graph Database Bolt connection URL with password.'
  },
  {
    id: 'cassandra-connection-uri',
    name: 'Cassandra CQL Connection String',
    category: 'database',
    severity: 'HIGH',
    regex: /\bcassandra:\/\/[a-zA-Z0-9_.-]+:[^@\s"']+@[a-zA-Z0-9_.-]+:[0-9]{2,5}\b/gi,
    description: 'Apache Cassandra database connection string.'
  },
  {
    id: 'clickhouse-uri-password',
    name: 'ClickHouse HTTP/Native Connection URI',
    category: 'database',
    severity: 'HIGH',
    regex: /\bclickhouse:\/\/[a-zA-Z0-9_.-]+:[^@\s"']+@[a-zA-Z0-9_.-]+:[0-9]{2,5}\b/gi,
    description: 'ClickHouse OLAP database connection URI with credentials.'
  },
  {
    id: 'mssql-connection-string',
    name: 'Microsoft SQL Server Connection String',
    category: 'database',
    severity: 'CRITICAL',
    regex: /Server=[^;]+;Database=[^;]+;User Id=[^;]+;Password=[^;]+/gi,
    description: 'SQL Server connection string containing cleartext password.'
  },
  {
    id: 'elasticsearch-basic-auth',
    name: 'Elasticsearch Connection URI with Password',
    category: 'database',
    severity: 'CRITICAL',
    regex: /\bhttps?:\/\/[a-zA-Z0-9_.-]+:[^@\s"']+@[a-zA-Z0-9_.-]+:9200\b/gi,
    description: 'Elasticsearch cluster URL containing HTTP basic authentication credentials.'
  },

  // ==========================================
  // 8. SOCIAL MEDIA & AUTH PROVIDERS (8 Rules)
  // ==========================================
  {
    id: 'google-oauth-client-secret',
    name: 'Google OAuth 2.0 Client Secret',
    category: 'social',
    severity: 'CRITICAL',
    regex: /\bGOCSPX-[a-zA-Z0-9_-]{28}\b/g,
    description: 'Google Cloud OAuth 2.0 Client Secret.'
  },
  {
    id: 'facebook-app-secret',
    name: 'Facebook / Meta App Secret',
    category: 'social',
    severity: 'CRITICAL',
    regex: /(?:facebook_app_secret|FACEBOOK_SECRET)\s*[:=]\s*["']([a-f0-9]{32})["']/gi,
    description: 'Meta Facebook App secret key.'
  },
  {
    id: 'twitter-bearer-token',
    name: 'Twitter / X API Bearer Token',
    category: 'social',
    severity: 'CRITICAL',
    regex: /\bAAAAAAAAAAAAAAAAAAAAA[a-zA-Z0-9%]{50,100}\b/g,
    description: 'Twitter / X API v2 Bearer token.'
  },
  {
    id: 'twitter-api-secret',
    name: 'Twitter / X API Consumer Secret',
    category: 'social',
    severity: 'CRITICAL',
    regex: /(?:TWITTER_CONSUMER_SECRET|twitter_api_secret)\s*[:=]\s*["']([a-zA-Z0-9]{50})["']/gi,
    description: 'Twitter OAuth 1.0a Consumer secret key.'
  },
  {
    id: 'linkedin-client-secret',
    name: 'LinkedIn App Client Secret',
    category: 'social',
    severity: 'CRITICAL',
    regex: /(?:LINKEDIN_SECRET|linkedin_client_secret)\s*[:=]\s*["']([a-zA-Z0-9]{16})["']/gi,
    description: 'LinkedIn Developer Application client secret.'
  },
  {
    id: 'spotify-client-secret',
    name: 'Spotify API Client Secret',
    category: 'social',
    severity: 'HIGH',
    regex: /(?:SPOTIFY_CLIENT_SECRET|spotify_secret)\s*[:=]\s*["']([a-f0-9]{32})["']/gi,
    description: 'Spotify Web API client secret key.'
  },
  {
    id: 'auth0-client-secret',
    name: 'Auth0 Client Secret',
    category: 'auth',
    severity: 'CRITICAL',
    regex: /(?:AUTH0_CLIENT_SECRET|auth0_secret)\s*[:=]\s*["']([a-zA-Z0-9_-]{64})["']/gi,
    description: 'Auth0 tenant application client secret.'
  },
  {
    id: 'okta-api-token',
    name: 'Okta API Token',
    category: 'auth',
    severity: 'CRITICAL',
    regex: /\b00[a-zA-Z0-9_-]{40}\b/g,
    description: 'Okta Identity Management API token.'
  },

  // ==========================================
  // 9. CRYPTOGRAPHIC KEYS & GENERIC SECRETS (8 Rules)
  // ==========================================
  {
    id: 'private-key-pem',
    name: 'RSA / PEM Private Key Block',
    category: 'private_key',
    severity: 'CRITICAL',
    regex: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g,
    description: 'Unencrypted PEM/RSA Private Key block.'
  },
  {
    id: 'ssh-private-key',
    name: 'OpenSSH Private Key',
    category: 'private_key',
    severity: 'CRITICAL',
    regex: /-----BEGIN OPENSSH PRIVATE KEY-----/g, // env-scanner-ignore
    description: 'OpenSSH cryptographic private key.'
  },
  {
    id: 'pgp-private-key',
    name: 'PGP Private Key Block',
    category: 'private_key',
    severity: 'CRITICAL',
    regex: /-----BEGIN PGP PRIVATE KEY BLOCK-----/g, // env-scanner-ignore
    description: 'Pretty Good Privacy (PGP) private key block.'
  },
  {
    id: 'jwt-hardcoded-secret',
    name: 'Hardcoded JWT Bearer Token',
    category: 'auth',
    severity: 'HIGH',
    regex: /\beyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b/g,
    description: 'Hardcoded JSON Web Token (JWT) with signature.'
  },
  {
    id: 'age-secret-key',
    name: 'Age Encryption Secret Key',
    category: 'private_key',
    severity: 'CRITICAL',
    regex: /\AGE-SECRET-KEY-1[0-9A-Z]{58}\b/g,
    description: 'Age file encryption tool secret key.'
  },
  {
    id: 'wireguard-private-key',
    name: 'WireGuard VPN Private Key',
    category: 'private_key',
    severity: 'CRITICAL',
    regex: /(?:PrivateKey|wireguard_private_key)\s*=\s*([a-zA-Z0-9\/+=]{44})/gi,
    description: 'WireGuard VPN interface private key.'
  },
  {
    id: 'generic-high-entropy-assignment',
    name: 'Generic API Key / Secret Assignment',
    category: 'generic',
    severity: 'MEDIUM',
    regex: /(?:API_KEY|SECRET_KEY|AUTH_TOKEN|PRIVATE_TOKEN|CLIENT_SECRET|ACCESS_TOKEN)\s*[:=]\s*["']([a-zA-Z0-9_\-\.]{16,128})["']/gi,
    entropyThreshold: 4.0,
    description: 'Variable assignment to common secret terms matching high entropy threshold.'
  },
  {
    id: 'generic-bearer-auth-header',
    name: 'Hardcoded HTTP Bearer Authorization Header',
    category: 'auth',
    severity: 'HIGH',
    regex: /["']Authorization["']\s*:\s*["']Bearer\s+([a-zA-Z0-9_\-\.=]{20,})["']/gi,
    description: 'Hardcoded Bearer authentication header in API request.'
  }
];
