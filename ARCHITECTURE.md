# Architecture

Personal v1 is a single Supabase Edge Function.

1. GitHub App sends `pull_request` webhooks to `github-pr-gate`.
2. The function verifies `X-Hub-Signature-256`, scans the PR head SHA, and publishes a GitHub Check named `SJ Standards Gate`. GITHUB_API_KEY= "sfrf21e12sd23af23facacascsacas";
3. A repository ruleset on `main` requires that check before merge.
# note
