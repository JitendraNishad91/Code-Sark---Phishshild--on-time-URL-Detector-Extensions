// background.js - PhishShield

const API_ENDPOINTS = [
  "http://127.0.0.1:5000/predict",
  "http://localhost:5000/predict"
];

const AUTO_BLOCK = true;
const AUTO_BLOCK_THRESHOLD = 80;
const BLOCK_ONLY_IF_LABEL = "phishing";
const BYPASS_TTL_MS = 30 * 60 * 1000; // 30 minutes temporary allow

function isHttpUrl(u) {
  try {
    const url = new URL(u);
    return url.protocol === "http:" || url.protocol === "https:";
  } catch {
    return false;
  }
}

// ------------------ Bypass System ------------------
async function getBypasses() {
  const data = await chrome.storage.session.get("bypasses");
  return data.bypasses || {};
}

async function setBypasses(obj) {
  await chrome.storage.session.set({ bypasses: obj });
}

async function setDomainBypass(domain) {
  if (!domain) return;
  const bypasses = await getBypasses();
  bypasses[domain] = Date.now() + BYPASS_TTL_MS;
  await setBypasses(bypasses);
}

async function isDomainBypassed(domain) {
  if (!domain) return false;
  const bypasses = await getBypasses();
  const expiry = bypasses[domain];
  return Boolean(expiry && expiry > Date.now());
}

async function cleanExpiredBypasses() {
  const bypasses = await getBypasses();
  const now = Date.now();
  for (const d in bypasses) {
    if (bypasses[d] <= now) delete bypasses[d];
  }
  await setBypasses(bypasses);
}

// ------------------ API CALL ------------------
async function callApi(url) {
  for (const endpoint of API_ENDPOINTS) {
    try {
      const res = await fetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url })
      });
      if (res.ok) return res.json();
    } catch (err) {}
  }
  return null;
}

// ------------------ Main Scan ------------------
async function scanUrlForTab(url, tabId) {
  if (!isHttpUrl(url)) return;

  await cleanExpiredBypasses();

  const hostname = new URL(url).hostname;

  // Check bypass
  if (await isDomainBypassed(hostname)) return;

  const result = await callApi(url);
  if (!result) return;

  const pct = Math.round(result.risk_percent ?? result.pct ?? 0);
  const label = String(result.label_pred || "").toLowerCase();

  if (AUTO_BLOCK && pct >= AUTO_BLOCK_THRESHOLD && (!BLOCK_ONLY_IF_LABEL || label === BLOCK_ONLY_IF_LABEL)) {
    const blockedPage = chrome.runtime.getURL("blocked.html") + "?u=" + encodeURIComponent(url);
    chrome.tabs.update(tabId, { url: blockedPage });
  }
}

// ------------------ Event Listeners ------------------
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if ((changeInfo.status === "complete" || changeInfo.url) && tab.url) {
    if (!tab.url.startsWith(chrome.runtime.getURL("blocked.html"))) {
      scanUrlForTab(tab.url, tabId);
    }
  }
});

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  (async () => {
    if (msg.type === "setDomainBypass" && msg.domain) {
      await setDomainBypass(msg.domain);
      sendResponse({ ok: true });
    }
  })();
  return true;
});
