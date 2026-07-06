---
name: codebase-docs
description: Maintain the repository documentation in the docs/ directory by initializing it or updating it surgically based on recent git changes.
metadata:
  audience: agents
  auth: none
---

## What I do

- Initialize codebase documentation under the `/docs` directory from scratch
- Run Git checks to find recently modified or added files
- Build a documentation update plan (`docs/_plan.md`) matching source changes
- Surgically update stale sections in `/docs` while keeping accurate content intact
- Keep `/docs/update.json` run metadata updated
- Ensure `AGENTS.md` and/or `CLAUDE.md` reference the quickstart page

## Before documenting

Analyze the codebase and directory structure. Ensure you have access to git commands and the workspace filesystem.

## Documentation workflow

### Phase 1 -- Git analysis & change audit
Execute the following to determine the repository state:
1. Check if the `/docs` directory and `docs/update.json` exist.
2. Get the current Git commit: `git rev-parse HEAD`
3. Get current unstaged/staged status: `git status --short`
4. If `docs/update.json` exists, extract the previous `gitHead` and `updatedAt`.
5. Run the change log command:
   - If `gitHead` is found: `git log <lastGitHead>..HEAD --name-status --oneline`
   - If `gitHead` is missing but `updatedAt` is present: `git log --since="<updatedAt>" --name-status --oneline`
   - If neither: `git log -n 20 --name-status --oneline`

### Phase 2 -- Skip check (Updates only)
For update requests:
- If there are no worktree changes (empty `git status`) and the current `HEAD` matches `gitHead` (or the only changed files are within the `/docs` directory), notify the user that no changes are detected and skip the run.

### Phase 3 -- Plan documentation structure
Before editing files:
1. Create a temporary plan file: `docs/_plan.md`
2. List the intended pages, source files acting as evidence for each page, and open questions.
3. Keep the initial documentation set focused. For smaller codebases, prefer a single `docs/quickstart.md` plus at most 1–2 supporting pages. Avoid thin pages.

### Phase 4 -- Write / Update pages
- **Entrypoint**: `docs/quickstart.md` must be the entry point. It should contain a repository overview, setup steps, and links to all other doc pages.
- **Section Pages**: Create organized directories under `docs/` (e.g., `docs/architecture/`, `docs/workflows/`, `docs/data-models/`) if the project is large.
- **Surgical edits**: Map changed files to specific documentation pages. Update only the stale sentences or sections. Preserve everything else.

### Phase 5 -- Link instructions
Ensure the top-level `/AGENTS.md` and/or `/CLAUDE.md` files (if present, or create `/AGENTS.md` if neither exists) reference the documentation:
```markdown
## Codebase Documentation

This repository has documentation located in the /docs directory.

Start here:
- [Codebase Quickstart](docs/quickstart.md)

When working in this repository, read the quickstart first, then follow its links to relevant design and operation notes.
```

### Phase 6 -- Metadata and Cleanup
1. Delete the temporary plan file `docs/_plan.md`.
2. Write or update `docs/update.json` with the following structure:
```json
{
  "updatedAt": "ISO_TIMESTAMP",
  "command": "init" | "update",
  "gitHead": "current_git_commit_hash",
  "model": "active_model_id"
}
```
3. Provide a concise summary of the documentation changes.

## Subagent & model routing

When analyzing large or multi-domain repositories, delegate domain exploration to subagents:

1. **Research-Only Constraint**: Subagents must only read and summarize. They must never write, edit, or delete any files in `/docs` or the workspace to avoid write collisions.
2. **Model Selection & Routing**: If the harness supports routing different tasks to different models:
   - **Main Agent (Synthesis & Writing)**: Use a high-reasoning, premium model or specialized coding model (e.g., GLM, Claude Sonnet, Kimi Code, Gemini Pro, or equivalent). Upstream default preferences favor specialized coding models like GLM 5.2 or Kimi K2.7 Code.
   - **Subagents (Research & Extraction)**: Use a fast, large-context, cost-effective model (e.g., GPT mini, Claude Haiku, Gemini Flash, or equivalent).
   - If the exact models are not available, map the task to the closest available tiers in your model pool (premium reasoning for the main agent, fast/cheap/large-context for the subagents).
3. **Narrow Briefs**: Give each subagent a specific codebase subset to audit (e.g., "Analyze the database schema and summarize the data model relations").
4. **Scale Thresholds**: Do not spawn subagents for small codebases (~10 source files). Use them only when there are multiple distinct, large directories.

## When to use me

- The user wants to initialize codebase documentation in the `/docs` directory
- The codebase has undergone changes and you need to update the `/docs` documentation surgically
- You want to ensure new developers or agents can quickly understand the repository starting from `docs/quickstart.md`

## Limitations

- Relies on Git command availability to determine historical changes. If Git is not initialized or available, fall back to checking filesystem timestamps and directory trees.
- Does not edit files outside the `/docs` directory except for top-level `AGENTS.md` and `CLAUDE.md` references.

## Upstream Project Reference
This skill implements the concepts and prompt patterns from the `openwiki` project:
- **Upstream Repository**: https://github.com/langchain-ai/openwiki
- **Prompt Reference**: https://github.com/langchain-ai/openwiki/blob/main/src/agent/prompt.ts
- **Utility Logic Reference**: https://github.com/langchain-ai/openwiki/blob/main/src/agent/utils.ts
