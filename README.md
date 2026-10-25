# pr-security-gate

Personal GitHub PR security gate.

A Supabase Edge Function receives GitHub App webhooks, scans the PR head commit (standards + pinned Gitleaks-class secret rules), and publishes a check named **SJ Standards Gate**. A repo ruleset on `main` is the merge lock.

Webhook:

`https://icfajfdzwvrldygtfhig.supabase.co/functions/v1/github-pr-gate`
