# Visual and format quality

Use this reference for layout changes, diagrams, charts, interactive elements, or final rendering review.

## Choose the smallest useful visual

Use a visual when readers must understand one of these structures:

- three or more dependent steps or actors;
- repeated comparisons across several criteria;
- hierarchy, ownership, containment, or trust boundaries;
- state changes or lifecycle transitions;
- data patterns that are hard to perceive in prose.

Prefer a table for exact mappings, a flow or timeline for sequence, a tree for hierarchy, a diagram for architecture, and a chart for quantitative patterns. Keep prose when the idea is a single fact or short linear explanation.

## Select the medium

- **Inline SVG:** technical diagrams, flows, architectures, lifecycles, and scalable print output.
- **HTML/CSS:** cards, tables, callouts, responsive layout, and content that must remain selectable.
- **JavaScript:** filtering, scenario toggles, progressive disclosure, or simulation with meaningful reader control.
- **Generated raster image:** illustrative scenes, conceptual artwork, textures, or visual storytelling that cannot be represented semantically.

Do not rasterize text-heavy technical diagrams. Do not add interaction that merely reveals content that could be shown clearly at once.

## Diagram requirements

- Give every diagram a clear title or caption and a textual explanation nearby.
- Label actors, direction, boundaries, and exceptional paths explicitly.
- Use color redundantly with labels, shapes, patterns, or line styles.
- Keep text readable at normal viewport size and in print.
- Use a responsive `viewBox`; avoid hard-coded dimensions that cause clipping.
- Match terminology exactly between the diagram and prose.
- Avoid unsupported precision and decorative data ink.

## Interaction requirements

- Preserve core meaning without JavaScript.
- Use semantic controls and support keyboard navigation.
- Expose state with text, not color alone.
- Respect reduced-motion preferences.
- Avoid external libraries unless they materially improve the result and are permitted by the project.
- Do not add analytics, trackers, remote fonts, or third-party requests without authorization.

## Rendering checklist

Inspect the artifact itself at representative sizes. Verify:

- no horizontal overflow, clipping, overlap, orphan headings, or unreadably small labels;
- consistent spacing, alignment, hierarchy, and content density;
- usable tables and code blocks on narrow screens;
- accessible contrast, focus indication, alternative text, and document landmarks;
- print-safe page breaks, backgrounds, links, and diagrams;
- no missing glyphs or fallback-font surprises in the target language;
- working internal navigation and unique element IDs;
- meaningful static fallback for interactive material;
- all citations and links still support the edited claims.

After rendering, perform a final editorial read. Layout work often exposes duplicated labels, missing context, or prose that no longer matches the visual.
