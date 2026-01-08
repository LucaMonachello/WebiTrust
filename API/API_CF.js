// API_CF.js
const fetch = require("node-fetch"); // npm install node-fetch@2

// ===============================
// CONFIG
// ===============================
const CF_API_TOKEN = "stTBE7TzitSNZ9QAciyNOhzVq5sXQFGp_7HLb0da"; // TEST ONLY
const ACCOUNT_ID   = "17ecf198b86d88bf24c61bb4ca53f27c";
const BASE_URL     = `https://api.cloudflare.com/client/v4/accounts/${ACCOUNT_ID}/urlscanner/v2`;

// ===============================
// FONCTIONS API internes
// ===============================

async function createScan(url) {
  const res = await fetch(`${BASE_URL}/scan`, {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${CF_API_TOKEN}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({ url })
  });

  const text = await res.text();
  if (!res.ok) {
    throw new Error(`Erreur création scan: ${res.status} ${res.statusText} - ${text}`);
  }

  const data = JSON.parse(text);
  const scanId = data.uuid;
  if (!scanId) {
    throw new Error("Impossible de trouver l'ID du scan (uuid) dans la réponse");
  }
  return scanId;
}

async function getScanResult(scanId) {
  while (true) {
    const res = await fetch(`${BASE_URL}/result/${scanId}`, {
      method: "GET",
      headers: {
        "Authorization": `Bearer ${CF_API_TOKEN}`
      }
    });

    if (res.status === 404) {
      await new Promise(r => setTimeout(r, 3000));
      continue;
    }

    if (!res.ok) {
      const text = await res.text();
      throw new Error(`Erreur résultat scan: ${res.status} ${res.statusText} - ${text}`);
    }

    const data = await res.json();
    const status = data.task?.status;
    if (status && status.toLowerCase() !== "finished") {
      await new Promise(r => setTimeout(r, 3000));
      continue;
    }

    return data;
  }
}

// ===============================
// MAPPING DES VERDICTS
// ===============================

function mapVerdicts(data) {
  const overall    = data.verdicts?.overall || {};
  const categories = overall.categories || [];
  const tags       = overall.tags || [];

  const allLabels = [
    ...categories.map(c => (typeof c === "string" ? c : c.name || "")),
    ...tags.map(t => (typeof t === "string" ? t : t.name || ""))
  ].map(x => x.toLowerCase());

  const malicious = overall.malicious === true;

  const phishing =
    malicious && allLabels.some(l => l.includes("phish"));

  const malware =
    malicious && allLabels.some(l => l.includes("malware") || l.includes("virus") || l.includes("trojan"));

  const spam =
    malicious && allLabels.some(l => l.includes("spam") || l.includes("bulk"));

  const crypto_mining =
    malicious && allLabels.some(l => l.includes("crypto") || l.includes("mining"));

  const command_and_control =
    malicious && allLabels.some(l => l.includes("c2") || l.includes("command and control") || l.includes("botnet"));

  return {
    malicious,
    phishing,
    malware,
    spam,
    crypto_mining,
    command_and_control
  };
}

// ===============================
// FONCTION MAIN APPELÉE PAR L’APPLI
// ===============================

async function main(url) {
  const scanId   = await createScan(url);
  const raw      = await getScanResult(scanId);
  const verdicts = mapVerdicts(raw);

  const hasIssue = verdicts.malicious ||
                   verdicts.phishing ||
                   verdicts.malware ||
                   verdicts.spam ||
                   verdicts.crypto_mining ||
                   verdicts.command_and_control;

  return {
    isSecure: !hasIssue,
    protocol: new URL(url).protocol.replace(":", ""),
    penaltyScore: hasIssue ? -30 : 0,
    message: hasIssue
      ? "✗ URL détectée comme risquée par Cloudflare Radar"
      : "✓ Aucun signal de menace détecté par Cloudflare Radar",
    severity: hasIssue ? "high" : "safe",
    details: verdicts
  };
}

// ===============================
// EXPORT
// ===============================

module.exports = {
  main,
  createScan,
  getScanResult,
  mapVerdicts
};
