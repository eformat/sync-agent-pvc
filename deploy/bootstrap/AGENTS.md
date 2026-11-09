# Memory — run BEFORE any work

Before reading, writing, editing, or executing ANYTHING — at session start and
before every new task — run BOTH MCP memory searches and apply what they
return. No file edits, no shell commands, no cluster access until both have
run:

1. `memory_search` — context about this repo/project and the task at hand.
2. `mistake_note_search` — known pitfalls related to the task.

If an action errors or a claim turns out wrong, record it with
`mistake_note_add` before moving on.

Apply what you find. Specifically: cluster resources in this environment are
always ACM + ArgoCD GitOps controlled — never patch cluster resources
directly with `oc`; change the GitOps source in the repo, let the owner
commit + push, and let ArgoCD/ACM sync (e.g. the repo's `make sync` targets,
or annotate the Application with
`argocd.argoproj.io/refresh=hard`).

# Git — the owner is git master; the assistant is NOT trusted with git

The owner is the git master for this repo and all their other repos
(including forks). **Make the file edits and stop.** Never
run ANY state-changing git command on their repos — `commit`, `push`, `add`,
`checkout`, `restore`, `reset`, `clean`, `stash`, `rebase`, `merge`, `tag`,
`rm`, `mv`, `apply`, `filter-repo` — even to "fix" a mistake the assistant
made. Report it and let the owner act. Read-only inspection is fine: `status`,
`log`, `diff`, `show`, `ls-files`, `check-ignore`, `grep`, `remote -v`,
`rev-parse`.

- "Add to the repo" means put the files in the working tree, not push. The
  "commit + push" wording in the cluster-fix flow above describes the flow,
  not who runs git — the owner runs it.
- Before claiming ANYTHING about what is or is not committed, verify with
  `git ls-files` / `git log -- <file>` / `git check-ignore` — a working-tree
  grep includes gitignored files and is NOT evidence of committed state.
- If a permission prompt asks about a git command, let the owner decide — never
  work around a denied or pending permission.

# Secrets — no cloud credential values in git; vault is the only source

- NEVER write cloud credential values into any file that could be committed:
  no access key IDs, no masked fragments (`AKIA...XXXX`), no zone IDs
  (`hosted_zone_id`), no secret keys — not even "for reference" copies in
  comments or templates. Credentials are referenced ONLY via vault/ESO
  secretRefs (`accessKeyIDSecretRef` / `secretAccessKeySecretRef`).
- Vault writes ONLY go through the repo's vault-script mechanism:
  edit the script if needed, then stop — the owner hydrates vault
  themselves. Never write to vault via CLI, pod exec, or direct API calls.
- Before finishing any edit the owner might commit, grep the changed files for
  `AKIA`, `aws_secret`, `hosted_zone` and remove anything found.
- Gitignored local files (e.g. local `*.env`) are BY DESIGN —
  never add them to git, never treat their contents as repo state.

If a task seems to conflict with these rules, stop and ask the owner instead of
proceeding.
