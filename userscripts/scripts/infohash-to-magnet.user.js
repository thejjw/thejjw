// ==UserScript==
// @name         Infohash to Magnet Link
// @namespace    https://github.com/thejjw/userscripts
// @version      1.0.0
// @description  Convert plain-text BitTorrent infohashes in .infohash-box into clickable magnet links.
// @author       thejjw
// @match        https://*/torrent/*
// @run-at       document-end
// @grant        none
// ==/UserScript==

(function () {
    'use strict';

    // Match standard BEP 9 v1 infohashes (40-char hex or 32-char Base32).
    const INFOHASH_RE = /^(?:[a-fA-F0-9]{40}|[A-Za-z2-7]{32})$/;

    document.querySelectorAll('.infohash-box span').forEach((span) => {
        const hash = span.textContent.trim();
        if (!INFOHASH_RE.test(hash)) {
            return;
        }

        const link = document.createElement('a');
        link.href = `magnet:?xt=urn:btih:${hash}`;
        link.textContent = hash;
        link.style.color = '#1a0dab';
        link.style.textDecoration = 'underline';
        span.replaceWith(link);
    });
})();