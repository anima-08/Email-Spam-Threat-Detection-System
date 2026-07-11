# AntiGravity Task Prompt — Email Spam & Threat Detection Chrome Extension

## Context
I'm building a college capstone project: a Chrome extension that detects spam
and phishing threats in Gmail emails in real time, using a trained ML model
(Random Forest, ~97% accuracy) served by a Flask backend.

I've already built and tested the Flask backend — it's included in this
upload under `backend/`. **Read `PROJECT_CONTEXT.md` first** for the full
technical background (how the model was trained, the exact preprocessing
pipeline, and the API contract). Do not rebuild the backend; extend it only
if a task below explicitly requires it.

## Your task
Build the Chrome Extension (Manifest V3) that talks to this backend.

### 1. `manifest.json`
- Manifest V3
- Permissions: `activeTab`, `scripting`, `storage`
- Host permissions for `https://mail.google.com/*` and the backend URL
  (`http://localhost:5000/*` for now, but keep it easy to swap for a deployed URL)
- Background: service worker (not a persistent background page)
- Content script injected on `https://mail.google.com/*`
- Popup: `popup.html` + `popup.js`
- Extension icon (any simple placeholder is fine — I'll swap it later)

### 2. Content script (`content.js`)
- Detects when an email is open in Gmail's reading pane
- Extracts the subject and body text
- Do this defensively — Gmail's DOM changes over time and across accounts, so
  use multiple fallback selectors and fail with a clear "couldn't read this
  email" state rather than throwing
- Sends the extracted `{subject, body}` to the background service worker on
  request (message passing), not via direct network calls from the content
  script

### 3. Background service worker (`background.js`)
- Receives extraction requests from the popup
- Asks the content script (in the active Gmail tab) for the current email
- Calls the backend's `POST /predict` with `{subject, body}`
- Returns the result to the popup
- Handle errors: backend unreachable (show a clear message), no email open,
  empty body

### 4. Popup UI (`popup.html`, `popup.css`, `popup.js`)
Show, for the currently analyzed email:
- **Prediction**: Spam / Ham, with a clear visual distinction (color-coded)
- **Spam probability** and **confidence** as percentages
- **Threat score** (0–100) as a simple visual meter/gauge
- **Risk level** badge: Low / Medium / High / Critical, color-coded
  (green/yellow/orange/red)
- **Suspicious keywords**: list the matched keywords, and also show a short
  preview of the email text with those keywords highlighted inline
- **URLs found**: list each URL with its reputation verdict (Suspicious /
  Likely Safe) and the reasons why
- A "Re-scan" button to re-run analysis on the currently open email
- A clear empty/loading/error state (don't just show a blank popup)

### 5. Config
- Put the backend base URL in one place (e.g. `config.js`) so it's a single
  line to change when I deploy the backend somewhere other than localhost

## What I need from you at the end
1. All extension files, ready to load unpacked via `chrome://extensions`
2. A short `EXTENSION_README.md`: how to load it unpacked, how to point it at
   a different backend URL, and known limitations (e.g. Gmail DOM
   selectors may need updating if Google changes their UI)
3. Point out anywhere you had to guess at Gmail's current DOM structure, so I
   know what to double check manually

## Priorities if you have to cut scope
1. Core flow working end-to-end (extract → predict → display) beats extra
   polish
2. Graceful error handling beats more features
3. Visual polish is lowest priority — functional and readable is enough
