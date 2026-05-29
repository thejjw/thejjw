---
name: web-search-ddg
description: Search the internet for real-time information using DuckDuckGo with no API key required. Use for current news, recent updates, live data, prices, weather, or any information not available locally.
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

Send a GET request to DuckDuckGo's HTML endpoint:

```
GET https://html.duckduckgo.com/html?q=<encoded_query>
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

- The user asks about current events, recent changes, or live data
- Information is needed that would not exist in local code or docs
- Any web search is requested

Do not use me for information already available in the local codebase or conversation context.

## Limitations

- This relies on DuckDuckGo's HTML structure. If DDG changes their markup, parsing may silently fail and return no results.
- No result count limit — all parsed results are returned.
- There is no API rate limit, but excessive requests may trigger CAPTCHAs or blocks from DDG.
