---
name: web-search-startpage
description: Fallback-only public web search through Startpage. Use this skill only when the agent has no usable built-in web search or relevant MCP tool, or after those preferred tools were attempted and failed. Do not select it merely because information is current, unavailable locally, or the user asks to search the web. Select it directly when the user explicitly requests Startpage or names web-search-startpage.
metadata:
  audience: agents
  auth: none
---

## What I do

- Search the internet via Startpage's web search endpoint (no API key needed)
- Handle Startpage's required `sc` search token and interstitial redirect
- Parse search results (title, link, snippet) from returned HTML
- Return structured results with citations

## How to search

Startpage search is a two-step form workflow (three if interstitial fires).

### 1. Fetch search token (`sc`)

Send a GET request to Startpage home page:

```
GET https://www.startpage.com/
```

Before requesting the home page, check whether a previously fetched `sc` token is still valid in cache (keep it for about 30 minutes). Reuse the cached token when available and unexpired.

Extract token from any `<input>` whose `name="sc"` -- the attribute order varies, so match by name, not position:

```
<input ... name="sc" value="TOKEN_HERE" ...>
```

Regex: `name="sc"[^>]+value="([^"]+)"` or `value="([^"]+)"[^>]+name="sc"` -- try both orders.

### 2. Submit search request

Send a POST request to Startpage search endpoint:

```
POST https://www.startpage.com/sp/search
Content-Type: application/x-www-form-urlencoded
```

Required headers (include on all requests):

```
User-Agent: <realistic Chrome/Firefox UA string>
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Origin: https://www.startpage.com
Referer: https://www.startpage.com/
```

Form fields:

- `query=<encoded_query>`
- `cat=web`
- `t=device`
- `sc=<token_from_step_1>`
- `abp=1`
- `abd=1`
- `abe=1`

For page > 1, also include:

- `page=<page_number>`
- `segment=organic`
- `lui=english`
- `language=english`
- `qsr=all`
- `qadf=moderate`
- `with_date=` (empty)

### 3. Handle interstitial response

The first POST often returns a near-empty shell page (empty `<title>`) containing a JavaScript payload instead of search results. This is the interstitial challenge.

Detect it by looking for a JSON object assigned to `var data`:

```
var data = {"abd":"1","abe":"1","abp":"1","cat":"web", ...}
```

When found:

1. Parse the JSON object (it is valid JSON)
2. URL-encode it as `application/x-www-form-urlencoded` form data
3. POST it to the same endpoint: `POST https://www.startpage.com/sp/search`
4. The second response will contain the actual search results

The interstitial JSON includes an `sgt` field (a signed timestamp token) and `segment` field -- include these as-is.

## Parse results

Parse HTML and extract each result from anchor elements:

```
a.result-title.result-link
```

### Structure of one result

The actual HTML for each result looks like:

```html
<a class="result-title result-link css-<hash>" href="https://example.com/page" ...>
  <style>...</style>
  <h2 class="wgl-title css-<hash>">Page Title</h2>
</a>
<style>...</style>
<p class="description css-<hash>">Snippet with <b>highlighted</b> terms</p>
```

Key points:

- The anchor has classes `result-title` and `result-link` (plus Emotion CSS hashes)
- The `h2` is a child of the anchor
- The `p.description` is a **sibling after** the anchor's closing `</a>`, with a `<style>` block in between
- Snippets contain `<b>` tags for query-term highlighting and `&nbsp;` entities

### Extraction steps

For each `a.result-title.result-link`:

1. **Title**: text content of child `h2` element -- decode HTML entities (`&#39;` -> `'`, etc.)
2. **URL**: `href` attribute on the anchor (these are direct URLs, not proxied)
3. **Snippet**: text content of the next sibling `p.description` element
   - When using regex, match `class="description` and skip past interleaved `<style>` tags
   - Strip all HTML tags (`<b>`, `<span>`, etc.) from snippet text
   - Decode HTML entities (`&nbsp;` -> space, `&amp;` -> `&`, `&#39;` -> `'`, etc.)
   - Normalize whitespace (collapse multiple spaces, trim)

Normalize whitespace and skip entries where title or URL is empty.

Optionally deduplicate by URL.

## Captcha/verification detection

Before parsing, detect anti-bot pages. Consider it blocked if HTML includes indicators like:

- `/sp/captcha`
- forms targeting `/sp/captcha`
- elements with `captcha` in id/class
- text such as `verify you are human`, `human verification`, or `security check`

If detected, return an explicit error instead of empty results.

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
- Use this skill directly when the user explicitly requests Startpage or names `web-search-startpage`.

Do not use this skill merely because information is current, unavailable locally, or the user asks to search the web. Do not use it for information already available in the local codebase or conversation context.

## Limitations

- This relies on Startpage HTML structure and form flow. If markup or parameters change, parsing may fail.
- Startpage may return captcha/verification pages when traffic appears automated.
- No API rate-limit contract is provided; aggressive requests may be throttled or blocked.

## Maintenance

Startpage updates their HTML markup and form parameters periodically. When the skill stops returning results (empty array, parse errors, or captcha on every request), it likely needs updating. To diagnose and fix:

1. **Save the raw response**: Fetch the search results page and save the HTML to a local file for inspection.
2. **Check the interstitial**: If the first POST returns an empty `<title>`, the interstitial flow still works. If it returns a captcha page, headers or frequency may be the issue.
3. **Inspect the markup**: Search the saved HTML for `result-link`, `result-title`, `description`, and `wgl-title` class names. If any are missing or renamed, update the extraction selectors accordingly.
4. **Check form fields**: Look at `<form action="/sp/search">` blocks in the HTML. Compare the hidden `<input>` fields against the form fields listed above -- new required fields may have been added.
5. **Verify the sc token**: Ensure the token regex still matches the `<input name="sc">` element on the home page.
6. **Test pagination**: If page 2+ returns no results, compare the pagination form's hidden inputs against the documented fields (especially `segment`, `qsr`, `qadf`).

When updating the skill, save a raw HTML response first so you can verify selectors against real data.
