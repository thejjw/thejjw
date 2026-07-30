---
name: web-search-ddg
description: Fallback-only public web search through DuckDuckGo. Use this skill only when the agent has no usable built-in web search or relevant MCP tool, or after those preferred tools were attempted and failed. Do not select it merely because information is current, unavailable locally, or the user asks to search the web. Select it directly when the user explicitly requests DuckDuckGo or names web-search-ddg.
metadata:
  audience: agents
  auth: none
---

## What I do

- Search the internet via DuckDuckGo's HTML endpoint (no API key needed)
- Parse search results (title, link, snippet) from the HTML response
- Resolve DuckDuckGo redirect URLs to actual destination URLs
- Return structured results with citations

## How to search

Send a GET request to DuckDuckGo's HTML endpoint, with a browser User-Agent header (requests without one may get a response page that contains no parseable results):

```
GET https://html.duckduckgo.com/html?q=<encoded_query>
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)
```

### Parse results

Split the HTML response by `<div class="result results_links` to isolate each result block. Skip the first element (before any results).

For each block, extract three fields using regex:

1. **Title**: Match `<a[^>]*class="result__a"[^>]*>(.*?)<\/a>`
2. **URL**: Match `<a[^>]*class="result__a"[^>]*href="([^"]*)">`
3. **Snippet**: Match `<a[^>]*class="result__snippet"[^>]*>(.*?)<\/a>` — strip `<b>` tags

Only include a result if all three fields (title, link, snippet) are non-empty.

### Resolve redirect URLs

DuckDuckGo wraps links in redirects like `//duckduckgo.com/l/?uddg=https%3A%2F%2Fexample.com&...`. Extract the actual URL:

```
1. If link starts with "//", prepend "https:"
2. Parse as URL, get the "uddg" query parameter
3. Decode it — that's the real destination
4. If no "uddg" param, return the raw link as-is
```

## Output format

Return results as a JSON array:

```json
[
  {
    "title": "Page Title",
    "link": "https://example.com/actual-url",
    "snippet": "A brief description of the page content."
  }
]
```

## When to use me

- Prefer the agent's built-in web search or a relevant MCP tool.
- Use this skill only when those preferred options are unavailable or have failed.
- Use this skill directly when the user explicitly requests DuckDuckGo or names `web-search-ddg`.

Do not use this skill merely because information is current, unavailable locally, or the user asks to search the web. Do not use it for information already available in the local codebase or conversation context.

## Limitations

- This relies on DuckDuckGo's HTML structure. If DDG changes their markup, parsing may silently fail and return no results.
- No result count limit — all parsed results are returned.
- There is no API rate limit, but excessive requests may trigger CAPTCHAs or blocks from DDG.
- When parsing yields zero results, do not assume the query matched nothing: save the raw HTML and check for `result__a` markers (markup changed), a CAPTCHA/challenge page (blocked — back off or switch to another search skill), or a missing User-Agent header.
