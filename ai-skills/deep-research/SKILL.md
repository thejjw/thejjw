---
name: deep-research
description: Deep research harness -- fan-out web searches, fetch sources, adversarially verify claims, synthesize a cited report. Use when the user wants a deep, multi-source, fact-checked research report on any topic.
metadata:
  audience: agents
  auth: none
---

## What I do

- Take a research question and decompose it into distinct search angles
- Fan out multiple web searches to cover the topic broadly
- Fetch and read the most relevant source pages in full
- Cross-reference claims across independent sources
- Flag contradictions, unsupported claims, and gaps
- Synthesize findings into a structured, cited report

## Before researching

If the question is underspecified -- broad topic, no constraints, or ambiguous scope -- ask 2-3 clarifying questions before proceeding. Examples:

| Too vague | Narrowed |
|---|---|
| "what car to buy" | budget, use-case, region, must-haves |
| "compare frameworks" | language, project type, team size, priorities |
| "is X safe?" | for what use, threat model, compliance needs |

Only research once the scope is clear enough to produce actionable findings.

## Research workflow

Follow these phases in order. Do not skip phases.

### Phase 1 -- Plan searches

Break the research question into 3-5 distinct search angles. Each angle should cover a different facet:

- **Factual**: direct answers, data, statistics
- **Comparative**: alternatives, benchmarks, head-to-head analyses
- **Critical**: known issues, criticisms, downsides, counter-arguments
- **Temporal**: recent changes, roadmap, deprecation signals
- **Authoritative**: official docs, maintainer statements, spec/RFC text

For each angle, write 1-2 concrete search queries (3-5 keywords each).

### Phase 2 -- Fan-out search

Execute all search queries using whatever web search tools are available -- built-in search, MCP servers, or other installed search skills.

Run searches in parallel when possible to minimize latency.

Collect results into a single candidate pool. Deduplicate by URL.

### Phase 3 -- Fetch and extract

From the candidate pool, select the most promising sources (aim for 5-10 pages total). Prioritize:

1. Official documentation or authoritative sources
2. Detailed technical articles or benchmark posts
3. GitHub repos, issues, or RFCs for implementation details
4. Independent reviews or analyses that offer original data

Fetch each selected source using available web reader / fetch tools.

For each source, extract:

- Key claims and data points
- The author's credentials or institutional affiliation
- Date of publication or last update
- Any cited sources that might be worth following

### Phase 4 -- Verify claims

For every factual claim that will appear in the final report:

1. **Corroborate**: Does at least one independent source confirm it?
2. **Contradict**: Does any source dispute it? If yes, note the disagreement.
3. **Date-check**: Is the claim current? Flag anything older than 2 years in a fast-moving domain.
4. **Source-check**: Is the source primary (official docs, spec, maintainer) or secondary (blog, summary)?

Mark each claim with a confidence level:

- **Confirmed**: 2+ independent sources agree
- **Likely**: single authoritative source, no contradictions
- **Disputed**: sources disagree -- present both sides
- **Unverified**: single non-authoritative source -- flag clearly

If a critical claim cannot be verified, run one more targeted search before proceeding.

### Phase 5 -- Synthesize report

Write the final report using this structure:

```
# [Research Topic]

## Executive Summary
2-4 sentence overview of findings with bottom-line conclusion.

## Methodology
Brief note on search angles, number of sources reviewed, and date range covered.

## Findings

### [Section per major theme]

- Claim with inline citation [1]
- Supporting data [2]
- Nuance or caveat [3]

### Contradictions & Gaps
- Where sources disagree
- What could not be verified
- Areas where no information was found

## Conclusion
Synthesized answer to the original research question.

## Sources
[1] Title -- URL (date)
[2] Title -- URL (date)
...
```

### Citation format

Use numbered inline citations `[1]` that map to the Sources list. Every factual claim must have at least one citation. Use `[1][2]` for multi-source corroboration.

## When to use me

- The user explicitly asks for "deep research", "thorough analysis", or "comprehensive report"
- The topic requires cross-referencing multiple sources
- Accuracy matters more than speed -- claims need verification
- The user wants citations and evidence, not a quick summary

Do not use me for:

- Simple factual lookups (one search suffices)
- Questions answerable from local code or existing context
- Tasks that are primarily code generation or editing

## Limitations

- Quality depends on what is available on the public web -- paywalled or non-indexed content is inaccessible.
- Web search results reflect search engine ranking, which may introduce bias.
- The verification step uses available sources only; it is not a substitute for expert domain review.
- Fetching may fail on sites that block automated access -- skip gracefully and note the gap.
- No access to academic databases (PubMed, arXiv full-text search, etc.) beyond what is publicly indexable.
