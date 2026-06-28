<#
.SYNOPSIS
    Zero-dependency, self-contained script to scrape newly added Netflix South Korea titles from uNoGS.com.
.DESCRIPTION
    Replicates the entire scraping and rendering logic for newly added titles (last 30 days) without Node.js.
    Uses native PowerShell WebCmdlets for HTTP calls, fetches genres/details, embeds boxart, and renders a CSR HTML dashboard.
.NOTES
    Copyright (c) 2026 @thejjw. All rights reserved.
    Last Updated: June 28, 2026
.EXAMPLE
    .\Netflix-KR-new-tracker.ps1
#>

# Force TLS 1.2 and 1.3 for web queries
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13

# Load System.Web assembly for HTML entity decoding
Add-Type -AssemblyName System.Web

$ErrorActionPreference = "Stop"

# Configuration
$CountryCode = "348"
$CountryName = "South Korea"
$UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
$Referrer = "https://unogs.com/countrydetail"
$Origin = "https://unogs.com"
$DevDate = "June 28, 2026"

# Ensure directories exist
if (-not (Test-Path "data")) {
    New-Item -ItemType Directory -Path "data" | Out-Null
}

$Now = Get-Date
$DateSuffix = $Now.ToString("yyyy-MM-dd")
$JsonPath = "data\unogs-new-kr-$DateSuffix.json"
$HtmlPath = "data\unogs-new-kr-$DateSuffix.html"

Write-Host "=== Starting Zero-Dependency Netflix South Korea Newly Added Scraper ===" -ForegroundColor Cyan


# Helper to download an image and return its Base64 data URI
function Get-Base64Image {
    param (
        [string]$Url
    )
    if (-not $Url) { return "" }
    try {
        $contentType = "image/jpeg"
        if ($Url -match "\.png") {
            $contentType = "image/png"
        } elseif ($Url -match "\.webp") {
            $contentType = "image/webp"
        } elseif ($Url -match "\.gif") {
            $contentType = "image/gif"
        }

        # Query web response
        $response = Invoke-WebRequest -Uri $Url -UserAgent $UserAgent -UseBasicParsing -TimeoutSec 10
        if ($response.Content) {
            $base64 = [System.Convert]::ToBase64String($response.Content)
            return "data:$contentType;base64,$base64"
        }
    } catch {
        # Fallback to the original URL if download fails
    }
    return $Url
}

try {
    # 1. Fetch Auth Token
    Write-Host "Step 1: Requesting auth token from /api/user..."
    $epochMs = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
    $userName = ($epochMs / 1000.0).ToString("F3", [System.Globalization.CultureInfo]::InvariantCulture)

    $authHeaders = @{
        "User-Agent" = $UserAgent
        "Accept" = "application/json"
        "X-Requested-With" = "XMLHttpRequest"
        "Referer" = $Referrer
        "Origin" = $Origin
    }
    $authBody = "user_name=$userName"

    $authRes = Invoke-RestMethod -Uri "https://unogs.com/api/user" -Method Post -Headers $authHeaders -Body $authBody -ContentType "application/x-www-form-urlencoded; charset=UTF-8"
    $token = $authRes.token.access_token

    if (-not $token) {
        throw "Failed to acquire JWT token from uNoGS."
    }
    Write-Host "Successfully acquired JWT token." -ForegroundColor Green

    # 2. Fetch New Titles (last 30 days) in Korea
    Write-Host "`nStep 2: Querying new titles (last 30 days) for South Korea (Country ID 348)..."
    $searchHeaders = @{
        "User-Agent" = $UserAgent
        "Authorization" = "Bearer $token"
        "Accept" = "application/json, text/plain, */*"
        "Referer" = $Referrer
        "REFERRER" = "http://unogs.com"
        "Origin" = $Origin
    }

    # Query new last 30 days in South Korea with exact URL parameters
    $searchUrl = "https://unogs.com/api/search?limit=100&offset=0&query=new%20last%2030%20days&countrylist=$CountryCode&country_andorunique=or&start_year=1900&end_year=2026&start_rating=0&end_rating=10&genrelist=&type=&audio=&subtitle=&audiosubtitle_andor=or&person=&personid=&filterby=&orderby=Date"
    $searchRes = Invoke-RestMethod -Uri $searchUrl -Headers $searchHeaders -Method Get

    if (-not $searchRes -or -not $searchRes.results) {
        Write-Host "No search results returned." -ForegroundColor Yellow
        $results = @()
    } else {
        $results = $searchRes.results
    }

    Write-Host "Found $($results.Count) new titles added to South Korea in the last 30 days. Resolving metadata..." -ForegroundColor Green

    # 3. Process each title sequentially (Fetch genres, details, and boxart)
    Write-Host "`nStep 3: Fetching detailed metadata and embedding boxart images..."
    $items = @()
    $count = 0
    foreach ($res in $results) {
        $count++
        $addedDate = $res.cbdate
        Write-Host " [$count/$($results.Count)] Processing: $($res.title) (Added: $addedDate)..." -ForegroundColor Gray

        # B. Fetch Genres
        $genres = @()
        try {
            $genreUrl = "https://unogs.com/api/title/genres?netflixid=$($res.nfid)"
            $genreHeaders = @{
                "User-Agent" = $UserAgent
                "Authorization" = "Bearer $token"
                "Referer" = "https://unogs.com/title/$($res.nfid)"
            }
            $genresRes = Invoke-RestMethod -Uri $genreUrl -Headers $genreHeaders -Method Get
            if ($genresRes) {
                $genres = @($genresRes | ForEach-Object { [System.Web.HttpUtility]::HtmlDecode($_.genre) })
            }
        } catch {
            # Silently proceed
        }

        # C. Fetch details (Maturity Rating, runtime, etc.)
        $detail = $null
        try {
            $detailUrl = "https://unogs.com/api/title/detail?netflixid=$($res.nfid)"
            $detailHeaders = @{
                "User-Agent" = $UserAgent
                "Authorization" = "Bearer $token"
                "Referer" = "https://unogs.com/title/$($res.nfid)"
            }
            $detailsRes = Invoke-RestMethod -Uri $detailUrl -Headers $detailHeaders -Method Get
            if ($detailsRes -and $detailsRes.Count -gt 0) {
                $detail = $detailsRes[0]
            }
        } catch {
            # Silently proceed
        }

        # D. Download and embed Boxart image
        $boxartEmbedded = ""
        if ($res.img) {
            $boxartEmbedded = Get-Base64Image -Url $res.img
        }

        # E. Normalize item structure
        $urlPath = "/$($res.vtype)/$($res.nfid)/$($res.slug)"
        $normalized = [PSCustomObject]@{
            title = [System.Web.HttpUtility]::HtmlDecode($res.title)
            netflixId = [string]$res.nfid
            url = "https://unogs.com$urlPath"
            addedDate = $addedDate
            addedText = "Added on $addedDate"
            type = $res.vtype
            year = [string]$res.year
            synopsis = [System.Web.HttpUtility]::HtmlDecode($res.synopsis)
            runtime = if ($detail.imdbruntime) { $detail.imdbruntime } elseif ($res.runtime) { "$($res.runtime)m" } else { "--" }
            imdbId = $res.imdbid
            posterUrl = $res.poster
            boxartUrl = $res.img
            boxartEmbedded = $boxartEmbedded
            genres = $genres
            maturityRating = if ($detail.matlabel) { $detail.matlabel } else { "" }
            imdbRated = if ($detail.imdbrated) { $detail.imdbrated } else { "" }
            imdbCountry = if ($detail.imdbcountry) { $detail.imdbcountry } else { "" }
            imdbLanguage = if ($detail.imdblanguage) { $detail.imdblanguage } else { "" }
        }
        $items += $normalized
    }

    # Sort items newest to oldest by addedDate
    $items = $items | Sort-Object { [DateTime]$_.addedDate } -Descending
    $collectedAt = (Get-Date).ToString("yyyy-MM-ddTHH:mm:sszzz") -replace '(\d{2})(\d{2})$', '$1:$2'
    $outputData = [PSCustomObject]@{
        source = "unogs"
        sourceUrl = "https://unogs.com/search/new%20last%2030%20days?country_andorunique=or&start_year=1900&end_year=2026&end_rating=10&genrelist=&audiosubtitle_andor=or&countrylist=348"
        country = $CountryCode
        countryName = $CountryName
        collectedAt = $collectedAt
        candidatesAnalyzed = $results.Count
        items = $items
    }

    Write-Host "`nSaving JSON snapshot to $JsonPath..." -ForegroundColor Gray
    # Force high Depth serialization to avoid nested arrays truncation
    $JsonContent = ConvertTo-Json $outputData -Depth 100
    [System.IO.File]::WriteAllText($JsonPath, $JsonContent, [System.Text.Encoding]::UTF8)

    # 4. Render HTML Dashboard using Client-Side Javascript
    Write-Host "Rendering HTML output to $HtmlPath..." -ForegroundColor Gray

    # HTML template with Client-Side Rendering placeholder
    $HtmlTemplate = @'
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Netflix South Korea - Newly Added</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@400;600;700;900&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg-main: #0c0c0e;
      --bg-card: #141418;
      --bg-input: #1a1a20;
      --text-main: #f5f5f7;
      --text-muted: #9e9ea7;
      --netflix-red: #e50914;
      --netflix-red-hover: #b80710;
      --accent-gold: #f5c518;
      --border-color: #24242d;
      --transition: all 0.25s cubic-bezier(0.4, 0, 0.2, 1);
    }

    * {
      box-sizing: border-box;
      margin: 0;
      padding: 0;
    }

    body {
      background-color: var(--bg-main);
      color: var(--text-main);
      font-family: 'Outfit', sans-serif;
      padding: 2rem 1.5rem;
      min-height: 100vh;
      line-height: 1.4;
    }

    .container {
      max-width: 1200px;
      margin: 0 auto;
    }

    .header {
      text-align: center;
      margin-bottom: 2.5rem;
    }

    .title {
      font-size: 2.5rem;
      font-weight: 900;
      letter-spacing: -0.5px;
      background: linear-gradient(135deg, #fff 0%, var(--text-muted) 100%);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      margin-bottom: 0.5rem;
    }

    .subtitle {
      color: var(--text-muted);
      font-size: 1rem;
    }

    .stats-grid {
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 1rem;
      margin-bottom: 2.5rem;
    }

    .stat-card {
      background-color: var(--bg-card);
      border: 1px solid var(--border-color);
      border-radius: 12px;
      padding: 1.5rem;
      text-align: center;
      transition: var(--transition);
    }

    .stat-card:hover {
      transform: translateY(-2px);
      border-color: #32323e;
      box-shadow: 0 8px 24px rgba(0,0,0,0.4);
    }

    .stat-val {
      font-size: 2rem;
      font-weight: 700;
      color: var(--accent-gold);
      margin-bottom: 0.25rem;
    }

    .stat-lbl {
      color: var(--text-muted);
      font-size: 0.85rem;
      text-transform: uppercase;
      font-weight: 600;
      letter-spacing: 0.5px;
    }

    .control-row {
      display: flex;
      flex-wrap: wrap;
      justify-content: space-between;
      align-items: center;
      gap: 1rem;
      margin-bottom: 2rem;
    }

    .search-container {
      flex: 1;
      min-width: 300px;
      position: relative;
    }

    .search-input {
      width: 100%;
      background-color: var(--bg-input);
      border: 1px solid var(--border-color);
      border-radius: 8px;
      padding: 0.8rem 1.2rem;
      color: var(--text-main);
      font-family: inherit;
      font-size: 0.95rem;
      transition: var(--transition);
    }

    .search-input:focus {
      outline: none;
      border-color: var(--accent-gold);
      box-shadow: 0 0 0 3px rgba(245, 197, 24, 0.15);
    }

    .tabs {
      display: flex;
      background-color: var(--bg-input);
      border: 1px solid var(--border-color);
      border-radius: 8px;
      padding: 0.25rem;
      gap: 0.25rem;
    }

    .tab-btn {
      background: none;
      border: none;
      color: var(--text-muted);
      padding: 0.55rem 1.2rem;
      font-family: inherit;
      font-size: 0.9rem;
      font-weight: 600;
      border-radius: 6px;
      cursor: pointer;
      transition: var(--transition);
    }

    .tab-btn:hover {
      color: var(--text-main);
    }

    .tab-btn.active {
      background-color: var(--accent-gold);
      color: #000;
    }

    .titles-grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(360px, 1fr));
      gap: 1.5rem;
    }

    .title-card {
      background-color: var(--bg-card);
      border: 1px solid var(--border-color);
      border-radius: 16px;
      overflow: hidden;
      display: flex;
      flex-direction: column;
      height: 100%;
      transition: var(--transition);
    }

    .title-card:hover {
      transform: translateY(-4px);
      border-color: #32323e;
      box-shadow: 0 12px 32px rgba(0,0,0,0.5);
    }

    .card-top {
      display: flex;
      padding: 1.2rem;
      gap: 1rem;
      align-items: flex-start;
    }

    .boxart-container {
      width: 110px;
      height: 154px;
      border-radius: 8px;
      overflow: hidden;
      background-color: #000;
      flex-shrink: 0;
      border: 1px solid rgba(255,255,255,0.05);
    }

    .boxart {
      width: 100%;
      height: 100%;
      object-fit: cover;
    }

    .card-meta {
      display: flex;
      flex-direction: column;
      min-height: 154px;
      flex: 1;
      min-width: 0;
      justify-content: space-between;
    }

    .badge-row {
      display: flex;
      flex-wrap: wrap;
      gap: 0.4rem;
    }

    .badge {
      font-size: 0.75rem;
      font-weight: 700;
      padding: 0.25rem 0.6rem;
      border-radius: 4px;
      text-transform: uppercase;
    }

    .badge-movie {
      background-color: rgba(26, 115, 232, 0.2);
      color: #7baaf7;
      border: 1px solid rgba(26, 115, 232, 0.4);
    }

    .badge-series {
      background-color: rgba(15, 157, 88, 0.2);
      color: #57bb8a;
      border: 1px solid rgba(15, 157, 88, 0.4);
    }

    .badge-new {
      background-color: rgba(245, 197, 24, 0.15);
      color: var(--accent-gold);
      border: 1px solid rgba(245, 197, 24, 0.3);
    }

    .card-title {
      font-size: 1.15rem;
      font-weight: 700;
      line-height: 1.3;
      margin: 0.4rem 0;
      display: -webkit-box;
      -webkit-line-clamp: 2;
      -webkit-box-orient: vertical;
      overflow: hidden;
    }

    .year-runtime {
      font-size: 0.85rem;
      color: var(--text-muted);
      margin-bottom: 0.2rem;
    }

    .maturity-rating-badge {
      background-color: #2b2b2b;
      border: 1px solid #444;
      color: var(--text-main);
      padding: 0.05rem 0.35rem;
      border-radius: 4px;
      font-size: 0.72rem;
      font-weight: 700;
      text-transform: uppercase;
      display: inline-block;
      vertical-align: middle;
      line-height: 1.2;
    }

    .genres {
      font-size: 0.82rem;
      color: var(--text-muted);
      margin-top: 0.2rem;
      margin-bottom: 0.2rem;
      font-weight: 400;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
      width: 100%;
    }

    .imdb-rating {
      font-size: 0.85rem;
      color: var(--accent-gold);
      display: flex;
      align-items: center;
      gap: 0.25rem;
      font-weight: 600;
    }

    .imdb-rating a {
      color: var(--accent-gold);
      text-decoration: none;
      transition: var(--transition);
    }

    .imdb-rating a:hover {
      text-decoration: underline;
    }

    .card-bottom {
      padding: 0 1.2rem 1.2rem 1.2rem;
      flex-grow: 1;
      display: flex;
      flex-direction: column;
      justify-content: space-between;
    }

    .synopsis {
      font-size: 0.88rem;
      color: var(--text-muted);
      line-height: 1.5;
      margin-bottom: 1.2rem;
      display: -webkit-box;
      -webkit-line-clamp: 3;
      -webkit-box-orient: vertical;
      overflow: hidden;
      flex-grow: 1;
    }

    .actions-row {
      display: flex;
      gap: 0.8rem;
    }

    .btn {
      flex: 1;
      text-align: center;
      text-decoration: none;
      font-size: 0.85rem;
      font-weight: 700;
      padding: 0.7rem 1rem;
      border-radius: 8px;
      transition: var(--transition);
      cursor: pointer;
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 0.3rem;
    }

    .btn-netflix {
      background-color: var(--netflix-red);
      color: #fff;
      border: none;
    }

    .btn-netflix:hover {
      background-color: var(--netflix-red-hover);
    }

    .btn-unogs {
      background-color: #2b2b2b;
      color: var(--text-main);
      border: 1px solid #3d3d3d;
    }

    .btn-unogs:hover {
      background-color: #3d3d3d;
    }

    .no-results {
      grid-column: 1 / -1;
      text-align: center;
      padding: 4rem 2rem;
      color: var(--text-muted);
      font-size: 1.2rem;
    }

    footer {
      text-align: center;
      margin-top: 5rem;
      padding-top: 2rem;
      border-top: 1px solid #2a2a2a;
      color: var(--text-muted);
      font-size: 0.85rem;
    }

    footer a {
      color: var(--netflix-red);
      text-decoration: none;
    }

    footer a:hover {
      text-decoration: underline;
    }
  </style>
</head>
<body>
  <div class="container">
    <header class="header">
      <h1 class="title">Netflix South Korea &mdash; Newly Added</h1>
      <p class="subtitle">Scraped and analyzed /*CANDIDATES_COUNT*/ candidate titles from uNoGS on <span id="generationDate">--</span></p>
    </header>

    <div class="stats-grid">
      <div class="stat-card">
        <div class="stat-val" id="totalCount">0</div>
        <div class="stat-lbl">Newly Added (30d)</div>
      </div>
      <div class="stat-card">
        <div class="stat-val" id="moviesCount">0</div>
        <div class="stat-lbl">Movies</div>
      </div>
      <div class="stat-card">
        <div class="stat-val" id="seriesCount">0</div>
        <div class="stat-lbl">Series</div>
      </div>
    </div>

    <div class="control-row">
      <div class="search-container">
        <input type="text" class="search-input" id="searchInput" placeholder="Search by title, synopsis, or genre..." oninput="filterTitles()">
      </div>
      <div class="tabs">
        <button class="tab-btn active" id="tab-all" onclick="setFilter('all')">All</button>
        <button class="tab-btn" id="tab-movie" onclick="setFilter('movie')">Movies</button>
        <button class="tab-btn" id="tab-series" onclick="setFilter('series')">Series</button>
      </div>
    </div>

    <main class="titles-grid" id="titlesGrid">
      <!-- Injected dynamically -->
    </main>

    <footer>
      <p>Data provided by <a href="https://unogs.com" target="_blank">uNoGS.com</a>. Developed offline with zero-dependencies by @thejjw on /*DEV_DATE*/.</p>
    </footer>
  </div>

  <script>
    // Injected by PowerShell
    const data = /*JSON_DATA_PLACEHOLDER*/;

    let activeFilter = 'all';

    function setFilter(type) {
      activeFilter = type;

      document.getElementById('tab-all').classList.remove('active');
      document.getElementById('tab-movie').classList.remove('active');
      document.getElementById('tab-series').classList.remove('active');

      if (type === 'all') document.getElementById('tab-all').classList.add('active');
      if (type === 'movie') document.getElementById('tab-movie').classList.add('active');
      if (type === 'series') document.getElementById('tab-series').classList.add('active');

      filterTitles();
    }

    function filterTitles() {
      const searchVal = document.getElementById('searchInput').value.toLowerCase().trim();
      const grid = document.getElementById('titlesGrid');

      const filtered = data.items.filter(item => {
        const title = (item.title || '').toLowerCase();
        const synopsis = (item.synopsis || '').toLowerCase();
        const genres = (item.genres || []).join(', ').toLowerCase();
        const type = (item.type || '').toLowerCase();

        const matchesSearch = title.includes(searchVal) || synopsis.includes(searchVal) || genres.includes(searchVal);
        const matchesFilter = activeFilter === 'all' || type === activeFilter;
        return matchesSearch && matchesFilter;
      });

      if (filtered.length === 0) {
        grid.innerHTML = '<div class="no-results">No titles match your criteria.</div>';
      } else {
        grid.innerHTML = filtered.map(item => {
          const isMovie = item.type.toLowerCase() === 'movie';
          const badgeClass = isMovie ? 'badge-movie' : 'badge-series';
          const displayType = isMovie ? 'Movie' : 'TV Series';
          const netflixLink = `https://www.netflix.com/title/${item.netflixId}`;
          const genresList = item.genres ? item.genres.join(', ') : '';
          const boxartSrc = item.boxartEmbedded || item.boxartUrl || '';

          const ratingBadge = item.imdbRated
            ? `&bull; <span class="maturity-rating-badge" title="${escapeHtml(item.maturityRating)}">${escapeHtml(item.imdbRated)}</span>`
            : (item.maturityRating ? `&bull; <span class="maturity-rating-badge" title="${escapeHtml(item.maturityRating)}">${escapeHtml(item.maturityRating)}</span>` : '');

          const imdbLink = item.imdbId
            ? `<a href="https://www.imdb.com/title/${item.imdbId}/" target="_blank">${item.imdbId}</a>`
            : 'N/A';

          return `
            <div class="title-card">
              <div class="card-top">
                <div class="boxart-container">
                  <img class="boxart" src="${boxartSrc}" alt="${escapeHtml(item.title)} boxart" loading="lazy">
                </div>
                <div class="card-meta">
                  <div class="badge-row">
                    <span class="badge ${badgeClass}">${displayType}</span>
                    <span class="badge badge-new">${escapeHtml(item.addedText || 'New')}</span>
                  </div>
                  <h2 class="card-title" title="${escapeHtml(item.title)}">${escapeHtml(item.title)}</h2>
                  <div class="year-runtime">
                    ${escapeHtml(item.year)} &bull; ${escapeHtml(item.runtime)}
                    ${ratingBadge}
                  </div>
                  <div class="genres" title="${escapeHtml(genresList)}">${escapeHtml(genresList || 'No genres listed')}</div>
                  <div class="country-origin" title="${escapeHtml(item.imdbCountry ? item.imdbCountry.replace(/\s+/g, ', ') : 'N/A')}" style="font-size: 0.82rem; color: var(--text-muted); margin-top: 0.2rem; margin-bottom: 0.2rem; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">
                    Country: ${escapeHtml(item.imdbCountry ? item.imdbCountry.replace(/\s+/g, ', ') : 'N/A')}
                  </div>
                  <div class="imdb-rating">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor" style="vertical-align:-2px">
                      <path d="M12 .587l3.668 7.431 8.2 1.191-5.934 5.787 1.4 8.168L12 18.896l-7.334 3.857 1.4-8.168L.166 9.209l8.2-1.191z"/>
                    </svg>
                    IMDb ID: ${imdbLink}
                  </div>
                </div>
              </div>
              <div class="card-bottom">
                <p class="synopsis">${escapeHtml(item.synopsis || 'No synopsis available.')}</p>
                <div class="actions-row">
                  <a class="btn btn-netflix" href="${netflixLink}" target="_blank">
                    <svg width="12" height="12" viewBox="0 0 24 24" fill="currentColor" style="margin-right:2px">
                      <path d="M8 5v14l11-7z"/>
                    </svg>
                    Play on Netflix
                  </a>
                  <a class="btn btn-unogs" href="${item.url}" target="_blank">Details</a>
                </div>
              </div>
            </div>
          `;
        }).join('');
      }

      // Update counters
      document.getElementById('totalCount').innerText = filtered.length;
      document.getElementById('moviesCount').innerText = filtered.filter(i => i.type.toLowerCase() === 'movie').length;
      document.getElementById('seriesCount').innerText = filtered.filter(i => i.type.toLowerCase() === 'series').length;
    }

    function escapeHtml(str) {
      if (!str) return '';
      return str.replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;')
                .replace(/'/g, '&#039;');
    }

    // Initialize rendering
    document.addEventListener('DOMContentLoaded', () => {
      // Set Scrape Date
      if (data.collectedAt) {
        document.getElementById('generationDate').innerText = new Date(data.collectedAt).toLocaleDateString(undefined, {
          year: 'numeric',
          month: 'long',
          day: 'numeric'
        });
      }
      filterTitles();
    });
  </script>
</body>
</html>
'@

    # Inject the JSON content and development date into the HTML template placeholders
    $FinalHtml = $HtmlTemplate.Replace("/*JSON_DATA_PLACEHOLDER*/", $JsonContent).Replace("/*DEV_DATE*/", $DevDate).Replace("/*CANDIDATES_COUNT*/", $results.Count)

    Write-Host "Saving HTML dashboard to $HtmlPath..." -ForegroundColor Gray
    [System.IO.File]::WriteAllText($HtmlPath, $FinalHtml, [System.Text.Encoding]::UTF8)
    Write-Host "Success! Rendered HTML output saved to: $HtmlPath" -ForegroundColor Green

    # 5. Print Trimmed Terminal Summary (first 5 and last 5)
    Write-Host "`nStep 4: Newly Added Titles Summary List (Last 30 Days)" -ForegroundColor Cyan
    Write-Host "==========================================================" -ForegroundColor Cyan

    $TotalCount = $items.Count

    if ($TotalCount -eq 0) {
        Write-Host "No new titles found for the last 30 days." -ForegroundColor Gray
    } else {
        $IndexesToDisplay = @()
        $ShowOmissionMessage = $false

        if ($TotalCount -le 10) {
            for ($i = 0; $i -lt $TotalCount; $i++) {
                $IndexesToDisplay += $i
            }
        } else {
            $ShowOmissionMessage = $true
            for ($i = 0; $i -lt 5; $i++) {
                $IndexesToDisplay += $i
            }
            for ($i = $TotalCount - 5; $i -lt $TotalCount; $i++) {
                $IndexesToDisplay += $i
            }
        }

        for ($idx = 0; $idx -lt $IndexesToDisplay.Count; $idx++) {
            $i = $IndexesToDisplay[$idx]
            $item = $items[$i]

            if ($ShowOmissionMessage -and $idx -eq 5) {
                Write-Host "  ... [$($TotalCount - 10) middle entries omitted, see full HTML report] ..." -ForegroundColor DarkGray
                Write-Host "----------------------------------------------------------" -ForegroundColor DarkGray
            }

            $TypeColor = "Cyan"
            if ($item.type -eq "series") {
                $TypeColor = "Green"
            }

            $NetflixUrl = "https://www.netflix.com/title/$($item.netflixId)"
            $GenresStr = ""
            if ($item.genres) {
                $GenresStr = " | Genres: " + ($item.genres -join ", ")
            }

            Write-Host " - " -NoNewline
            Write-Host "$($item.title) " -ForegroundColor White -NoNewline
            Write-Host "($($item.type))" -ForegroundColor $TypeColor -NoNewline
            Write-Host " | Added: " -NoNewline
            Write-Host "$($item.addedDate)" -ForegroundColor Yellow -NoNewline
            Write-Host " | Length: " -NoNewline
            Write-Host "$($item.runtime)$GenresStr" -ForegroundColor Gray

            Write-Host "   Netflix: " -NoNewline
            Write-Host "$NetflixUrl" -ForegroundColor DarkGray
            Write-Host "   uNoGS  : " -NoNewline
            Write-Host "$($item.url)" -ForegroundColor DarkGray
            Write-Host "----------------------------------------------------------" -ForegroundColor DarkGray
        }
    }

    Write-Host "Total New Titles (last 30 days): $TotalCount" -ForegroundColor Cyan
    Write-Host "==========================================================" -ForegroundColor Cyan

    # 6. Provide pointers to open the HTML
    $ResolvedHtmlPath = (Resolve-Path $HtmlPath).Path
    Write-Host "`nHTML Report generated at: " -NoNewline
    Write-Host $ResolvedHtmlPath -ForegroundColor Green
    Write-Host "To open the interactive dashboard in your browser, run:" -ForegroundColor Gray
    Write-Host "Start-Process `"$ResolvedHtmlPath`"" -ForegroundColor Yellow
    Write-Host "==========================================================" -ForegroundColor Cyan

} catch {
    Write-Host "`n[ERROR] Pipeline Execution Failed:" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    Write-Host $_.ScriptStackTrace -ForegroundColor Red
    Exit 1
}
