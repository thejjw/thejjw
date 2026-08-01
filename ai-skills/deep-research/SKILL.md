---
name: deep-research
description: Deep research harness -- clarify scope, confirm a research plan, fan out web searches, cross-reference and verify claims, and write a long-form cited report to a file. Use only when the user explicitly asks for deep research, a thorough analysis, or a comprehensive research report, or names this skill. Do not auto-select for ordinary questions or quick lookups.
metadata:
  audience: agents
  auth: none
---

## What I do

- Clarify the research question and freeze it into a written research brief
- Decompose the brief into research threads and present the plan for user confirmation
- Research each thread with web searches and full-page reads, using parallel subagents when the harness supports them
- Cross-reference sources, verify claims, and flag contradictions and gaps
- Write a comprehensive, cited, long-form report to a Markdown file and summarize it in chat

## When to use me

- The user explicitly asks for "deep research", "thorough analysis", or "comprehensive report", or invokes this skill by name
- The topic requires cross-referencing multiple sources
- Accuracy matters more than speed -- claims need verification
- The user wants citations and evidence, not a quick summary

Do not use me for:

- Simple factual lookups (one search suffices)
- Questions answerable from local code or existing context
- Tasks that are primarily code generation or editing

Do not auto-select this skill merely because information is current or unavailable locally. It runs a long, interactive workflow and should start only on explicit user intent.

## Research workflow

Follow these phases in order. Do not skip phases.

### Phase 0 -- Scope and research brief

Note today's date and use it for all recency judgments.

If the request is underspecified -- broad topic, no constraints, ambiguous scope, unclear acronyms -- ask up to 2-3 concise clarifying questions before proceeding, as a bullet or numbered list. Examples:

| Too vague | Narrowed |
|---|---|
| "what car to buy" | budget, use-case, region, must-haves |
| "compare frameworks" | language, project type, team size, priorities |
| "is X safe?" | for what use, threat model, compliance needs |

Rules for clarifying:

- Never ask for information the user already provided.
- If you already asked a clarifying question in this conversation, ask another only if absolutely necessary.
- Once the scope is clear enough to produce actionable findings, stop asking and proceed.

Then write a **research brief** and show it to the user. The brief:

- Is a single short paragraph in the first person, from the user's perspective.
- Includes every constraint, preference, and dimension the user stated -- do not drop details.
- Marks essential but unstated dimensions as open-ended (e.g., "no constraint on budget") instead of inventing assumptions.
- States source preferences: prefer primary sources (official docs, original papers, manufacturer pages, maintainer statements) over aggregators and SEO-heavy blogs; if the request is in a specific language, prioritize sources published in that language.

### Phase 1 -- Plan and confirm

Decompose the brief into 3-6 research threads. Each thread covers a different facet:

- **Factual**: direct answers, data, statistics
- **Comparative**: alternatives, benchmarks, head-to-head analyses
- **Critical**: known issues, criticisms, downsides, counter-arguments
- **Temporal**: recent changes, roadmap, deprecation signals
- **Authoritative**: official docs, maintainer statements, spec/RFC text
- **Historical**: origin, key milestones, chronological evolution -- include when the topic has meaningful chronology

Threads must be independent, non-overlapping, and narrow enough to research in depth.

Present the brief (1-2 lines), the thread plan as a numbered list with a one-sentence scope each, and the search budget. Then **stop and wait for the user to confirm or adjust the plan. Do not run any searches before confirmation.** If the user adjusts the plan, update it and confirm again only if the change is large.

Search budgets:

- 2-3 searches for a simple thread, at most 5 for a complex one.
- Stop a thread early when it has 3+ solid sources or when 2 consecutive searches return the same information.

### Phase 2 -- Research

Use whatever web search and page-fetch tools the harness provides (built-in search, MCP tools, or installed search skills). Run independent searches in parallel when the harness allows it.

After every search, reflect in one line: what was found, what is missing, is there enough.

**If the harness supports subagents / parallel agents:** delegate one subagent per thread, launched together. Each subagent prompt must be fully standalone -- subagents cannot see this conversation or each other's work, so include the research brief, the thread scope, the search budget, and the return format below. Write out full names; no unexplained acronyms.

```text
## <Thread title>

### Findings
- <finding, with inline source URLs>

### Evidence
- Claim: ...
  Source: <URL> (<publication date>)
  Quote/Data: "..."

### Gaps
- <what could not be found, and any contradictions>
```

Subagents only research and return text; they must not write files.

**If the harness has no subagents:** research the threads sequentially in your own context. After finishing each thread, write a compact thread-notes block in the same format above before starting the next thread. Preserve facts and quotes verbatim -- do not paraphrase them away -- and keep every source URL. These notes are a compression buffer so each new thread starts with a clean working set.

Either way, fetch and read the most promising pages in full (aim for 5-10 pages across all threads). Prioritize official or authoritative sources, detailed technical articles, and primary data over summaries.

### Phase 3 -- Cross-reference and verify

Combine all thread notes and build a **source registry**: every unique URL with one line on what it contributed.

For every factual claim that will appear in the report:

1. **Corroborate**: does at least one independent source confirm it?
2. **Contradict**: does any source dispute it? If yes, record the disagreement.
3. **Date-check**: is the claim current? Flag anything older than 2 years in a fast-moving domain.
4. **Source-check**: is the source primary (official docs, spec, maintainer) or secondary (blog, summary)?

Mark each claim with a confidence level:

- **Confirmed**: 2+ independent sources agree
- **Likely**: single authoritative source, no contradictions
- **Disputed**: sources disagree -- present both sides
- **Unverified**: single non-authoritative source -- flag clearly

If a critical claim cannot be verified, run at most 1-2 targeted follow-up searches before proceeding.

### Phase 4 -- Write the report

Write the report in the **same language as the user's messages**, even when the sources and notes are in another language.

Match the structure to the question -- sections are a fluid concept:

- Comparison: intro, overview of each option, head-to-head comparison, conclusion.
- List or ranking: the list itself (items as sections or one table); intro and conclusion optional.
- Overview or explainer: context, one section per concept, conclusion.
- A single-section answer when that suffices.

Writing rules:

- `#` for the title, `##` for sections, `###` for subsections.
- Prose-forward: paragraphs by default, bullet points when they aid scanning. Sections should be as long as needed to deeply answer the question -- users expect a thorough deep-research report.
- Executive summary first: 3-5 self-contained sentences with the bottom-line conclusion.
- Brief methodology note: threads investigated, number of sources reviewed, date range covered.
- Include a "Contradictions & Gaps" section (where sources disagree, what could not be verified, what was not found) and a "Limitations" section (scope, recency, blind spots).
- No self-referential language ("I searched", "this report will") -- just write the report.

Citation rules:

- Assign each unique URL a single citation number and cite inline as `[1]`, `[2]`; use `[1][2]` for corroborated claims.
- Every factual claim in the findings needs at least one inline citation.
- End with `### Sources` listing one source per line as `[1] Title -- URL (date)`, numbered sequentially without gaps.

Quality gates before delivering:

- At least 6 unique sources cited, or an explicit note on why fewer exist.
- No placeholder URLs or "citation needed" markers.
- The executive summary stands alone.

### Phase 5 -- Deliver

1. Write the report to `deep-research-YYYYMMDD-<slug>.md` in the workspace root, where `<slug>` is 2-4 descriptive lowercase words joined with hyphens (at most ~20 characters). If the file already exists, append `-2`, `-3`, and so on instead of overwriting.
2. In chat, return the file path plus a 3-4 sentence summary of the most important findings. Do not paste the full report into chat.

## Limitations

- Quality depends on what is available on the public web -- paywalled or non-indexed content is inaccessible.
- Web search results reflect search engine ranking, which may introduce bias.
- The verification step uses available sources only; it is not a substitute for expert domain review.
- Fetching may fail on sites that block automated access -- skip gracefully and note the gap.
- No access to academic databases (PubMed, arXiv full-text search, etc.) beyond what is publicly indexable.
- Depth and speed depend on the harness's search/fetch tools and on whether it can run subagents in parallel.

## Upstream Project Reference

This skill adapts the concepts and prompt patterns from the `open_deep_research` project:

- **Upstream Repository**: https://github.com/langchain-ai/open_deep_research
- **Prompt Reference**: https://github.com/langchain-ai/open_deep_research/blob/main/src/open_deep_research/prompts.py
