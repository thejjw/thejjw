# Source reconciliation

Use this reference when the primary document has sibling sources, translations, citations, or claims that require verification.

## Establish authority

Use this order as a starting point, then adjust for explicit user instructions:

1. The user's stated objective and constraints.
2. Current authoritative external sources for verifiable claims.
3. The primary artifact for audience, format, and intended deliverable.
4. Direct source documents, specifications, datasets, and cited materials.
5. Related drafts, translations, exports, and derivative files.

File modification time alone does not establish authority. A newer translation can still derive from an older source, and a deeper Markdown report can still contain claims intentionally removed from its HTML summary.

## Match related files conservatively

Prioritize candidates in this order:

1. Explicitly named or linked files.
2. Exact filename stem in another recognized document format.
3. The same stem after removing a terminal locale token such as `-ko`, `_en`, or `.fr-FR`.
4. Files the user confirms after an ambiguous match.

Do not treat a generic shared prefix as sufficient. Avoid broad recursive discovery unless the user asks for it or project structure clearly requires it.

## Compare content

Create a private reconciliation map with these columns when the documents differ materially:

- topic or section;
- primary-artifact wording;
- related-source wording;
- evidence or citation;
- action: preserve, restore, correct, condense, or flag.

Check specifically for:

- missing qualifications and threat assumptions;
- numerical, version, date, port, API, license, and standards discrepancies;
- translations that change certainty, agency, causality, or scope;
- citations retained after their supporting claim changed;
- diagrams whose labels disagree with prose;
- executive summaries that overstate the detailed analysis.

## Resolve conflicts

- Make a verified correction when a current primary source clearly settles the matter.
- Prefer the more qualified formulation when evidence supports a range rather than a certainty.
- Preserve deliberate audience-level simplification when it remains accurate.
- Flag unresolved ambiguity instead of averaging incompatible claims.
- For legal, compliance, medical, or security conclusions, state the evidence and limits; do not substitute model judgment for specialist review.

## Report material changes

Summarize corrections that alter facts, risk, feasibility, recommendations, or interpretation. Routine grammar and formatting changes do not need an exhaustive change log.
