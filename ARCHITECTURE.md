# Architecture

Personal PR security gate: one Supabase Edge Function. No VM and no Gitleaks binary.

1. GitHub App sends `pull_request` webhooks to `github-pr-gate`.
2. The function verifies `X-Hub-Signature-256`, deduplicates on `X-GitHub-Delivery`, and allowlists the repo.
3. It publishes a GitHub Check named `SJ Standards Gate` on the PR head SHA (`in_progress`, then success or failure).
4. Standards: branch name, merge into `main`, Ticket, AI-assisted yes/no, checklist, required files, pinned standards-file hash.
5. Secrets: pinned Gitleaks v8.28.0 rule corpus plus assignment / entropy / PEM detectors. Rules are vendored in the function. A PR cannot change them. Findings never include the secret value.
6. Before the final conclusion it re-reads the PR head SHA so an old result cannot approve a newer commit. Errors and timeouts fail closed.
7. A repository ruleset on `main` requires `SJ Standards Gate`. Enable GitHub secret scanning and push protection as a second lock.

Gitleaks rules source: https://github.com/gitleaks/gitleaks/blob/v8.28.0/config/gitleaks.toml
