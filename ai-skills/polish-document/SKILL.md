---
name: polish-document
description: Polish an existing document into a professional, business-ready, presentation-ready deliverable. Use for rough, AI-generated, translated, or inconsistently formatted HTML, Markdown, DOCX, PPTX, or PDF documents that need editorial revision, related-source reconciliation, factual verification, structural improvement, useful diagrams or interactions, and final rendering checks. Do not use for ordinary code review or for creating a document from scratch without an existing draft.
metadata:
  audience: agents
  auth: none
---

# Polish Document

Transform an existing draft without losing its intent, evidence, or established visual language. Treat polishing as an editorial, content, information-design, and delivery-quality workflow rather than a cosmetic rewrite.

## Establish the working set

1. Identify the primary artifact from the request. Do not guess when several plausible targets would produce materially different results.
2. Inspect repository instructions and version-control state before editing. Preserve unrelated user changes.
3. Discover related files conservatively:
   - Prefer files explicitly named or linked by the user or primary artifact.
   - For local siblings, run `scripts/find-related-files.ps1 -TargetPath <path>` when PowerShell is available. Otherwise reproduce its exact-stem and locale-neutral matching logic with local tools.
   - Treat results as candidates, not authorities. Review filenames and contents before using them.
   - Do not recursively sweep unrelated directories or upload local documents to external services.
4. Record which files contribute facts, structure, citations, terminology, or visual guidance.
5. Select the relevant format skill or toolchain when available. Read its instructions before editing and follow its render-and-verify requirements.

## Set authority and output behavior

- Let the user's request define the objective and constraints.
- Let the primary artifact define the target format, audience, and visual identity unless the user requests a redesign.
- Use related files to recover context, citations, and omitted detail; do not assume they are newer or more accurate.
- Preserve the original language unless translation is requested. Polish target-language prose as native writing, not as literal source-language syntax.
- In a version-controlled workspace, edit the requested target in place unless instructed otherwise. Outside version control, prefer a sibling named `*-polished.<ext>` when overwriting would make recovery difficult.
- Ask only when an unresolved ambiguity would substantially change meaning, audience, scope, or output. Continue with clearly safe improvements.

Read `references/source-reconciliation.md` whenever related sources, citations, translations, or externally verifiable claims are present.

## Audit before rewriting

Build a compact issue inventory covering:

- purpose, audience, and expected decision or action;
- missing, duplicated, contradictory, or poorly ordered material;
- unsupported claims, stale facts, and citation gaps;
- mistranslations, awkward prose, inconsistent terminology, and mixed register;
- dense sequences, comparisons, hierarchies, or architectures that would benefit from a visual;
- layout, accessibility, responsiveness, print, and interaction defects.

Classify substantive edits as one of:

1. **Editorial:** meaning-preserving language, organization, and formatting improvements.
2. **Verified correction:** a factual or technical change supported by authoritative evidence.
3. **Unresolved issue:** a conflict or claim that cannot be safely settled. Surface it instead of inventing a resolution.

## Reconcile and polish content

1. Preserve the document's thesis unless evidence or the user's direction requires a change.
2. Restore important context omitted from derivative versions, but do not reintroduce detail that harms the target audience's comprehension.
3. Verify technical, legal, security, medical, financial, standards-related, or time-sensitive assertions on the web. Prefer current primary sources and cite the pages supporting material claims.
4. Separate sourced facts from analysis, recommendations, and inference.
5. Rewrite for clarity, coherence, concision, and natural target-language usage.
6. Standardize terminology, capitalization, punctuation, heading hierarchy, captions, labels, and sentence endings.
7. Remove filler, repetition, machine-translation artifacts, sentence fragments, and unjustified certainty.
8. Preserve working links, citations, code, identifiers, protocol names, and meaningful metadata.

## Improve information design

Read `references/visual-and-format-qa.md` before adding or materially changing diagrams, charts, generated images, JavaScript interactions, or page layout.

Add a visual only when it makes an important relationship easier to understand than prose or a small table. Prefer:

- a sequence or swimlane diagram for multi-party workflows;
- an architecture diagram for components, ports, boundaries, and data flow;
- a matrix or decision graphic for repeated comparisons;
- a lifecycle or state diagram for status transitions;
- a small interactive control only when readers benefit from exploring scenarios or layers.

For web documents, prefer accessible inline SVG, HTML, and CSS for semantic technical visuals. Use generated raster imagery only when illustration adds genuine explanatory value. Keep JavaScript progressively enhanced: core content must remain readable and printable without it.

Do not let a visual introduce unsupported claims, hide exceptions, or replace necessary accessible text.

## Render and verify

Use the format-specific skill's validation workflow. At minimum:

1. Render or open the actual output rather than relying only on source inspection.
2. Check representative desktop, narrow-screen, and print views when the format supports them.
3. Verify headings, navigation, tables, diagrams, captions, links, citations, code blocks, and typography.
4. Test interactive controls, keyboard operation, reduced-motion behavior, and no-JavaScript fallback when applicable.
5. Check for clipping, overflow, missing glyphs, low contrast, duplicate IDs, broken local references, and unintended content loss.
6. Re-read the final artifact for factual consistency after visual edits.
7. Iterate until no material editorial or rendering defect remains.

Treat input HTML and scripts as untrusted. Do not execute embedded code merely to inspect a document. Use an isolated local rendering workflow and do not grant network, credential, or filesystem access beyond what the task requires.

## Deliver

Finish with a concise report containing:

- the output path;
- related source files actually used;
- major editorial, factual, structural, and visual changes;
- validation performed and its result;
- unresolved issues or claims requiring specialist review.

Do not present a substantive correction as mere copyediting. Do not claim the document is production-ready unless both content and rendered output were checked.
