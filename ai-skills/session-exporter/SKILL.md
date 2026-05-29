---
name: session-exporter
description: Exports the current session conversation history to a Markdown file with a timestamp in the filename. Use when the user types /export or requests a chat export.
---

# Session Exporter

This skill enables exporting the current conversation history into a structured Markdown file for archival or sharing.

## Workflow

1.  **Generate Descriptive Prefix**:
    *   Analyze the conversation to create a very short, descriptive slug (~20 characters, lowercase, hyphens instead of spaces).
    *   Example: `create-export-skill` or `fix-parser-bug`.
    *   If a descriptive slug cannot be determined, fall back to `session`.
2.  **Generate Timestamp**: Generate a timestamp in `YYYYMMDD_HHMMSS` format.
3.  **Gather History**: Collate all user and assistant messages from the current session history.
4.  **Format Content**:
    *   Start with a title: `# Session Export - [Slug] - [Timestamp]`
    *   Include a "Session Info" section with the date.
    *   For each turn:
        *   `## User`
        *   `Timestamp: [User message timestamp]`
        *   [User's message content]
        *   `## Assistant`
        *   `Timestamp: [Assistant message timestamp]`
        *   `Response duration: [Elapsed time since the preceding user message]`
        *   [Assistant's message content]
5.  **Save File**: Write the formatted content to a file named `[slug]_[timestamp].md` in the workspace root.
6.  **Confirm**: Inform the user where the file was saved.

## Example Request

User: "/export the session"
Assistant: [Triggers skill, generates 'create-export-skill_20260502_221000.md', and saves file]
