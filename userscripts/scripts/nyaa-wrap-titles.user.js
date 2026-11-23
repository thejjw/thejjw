// ==UserScript==
// @name         Nyaa Wrap Torrent Titles
// @namespace    https://github.com/thejjw/userscripts
// @version      1.0.0
// @description  Allow long torrent titles on nyaa.si and subdomains to wrap across multiple lines.
// @author       thejjw
// @match        https://nyaa.si/*
// @match        https://*.nyaa.si/*
// @run-at       document-start
// @grant        GM_addStyle
// ==/UserScript==

(function () {
    'use strict';

    // Keep !important on all declarations because document-start styles load before site CSS.
    GM_addStyle(`
    .torrent-list > tbody > tr,
    .torrent-list > tbody > tr > td {
      height: auto !important;
    }

    .torrent-list > tbody > tr > td {
      vertical-align: middle !important;
      white-space: normal !important;
      overflow: visible !important;
      overflow-wrap: break-word !important;
      word-break: break-word !important;
      max-width: 603px !important;
    }

    .torrent-list > tbody > tr > td a {
      display: inline !important;
      height: auto !important;
      max-height: none !important;
      overflow: visible !important;
    }
  `);
})();