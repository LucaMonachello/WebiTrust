// API_VT.js (ESM)

// ===============================
// CONFIG
// ===============================
const VT_API_KEY = "3c96eb427a670f6aa49937d9d6652a349efdc8f793ae0d816ccc2b46cafbdf89"; // TEST ONLY (à ne pas hardcoder en prod)

// ===============================
// FONCTIONS INTERNES
// ===============================

// Base64url (RFC 4648) sans padding, compatible navigateur (pas de Buffer)
function encodeUrl(url) {
  const bytes = new TextEncoder().encode(url);
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);

  // btoa => base64, puis conversion base64url + suppression "="
  return btoa(binary).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}

async function getScores(id) {
  const res = await fetch(`https://www.virustotal.com/api/v3/urls/${id}`, {
    headers: {
      "x-apikey": VT_API_KEY,
      "accept": "application/json",
    },
  });

  if (!res.ok) {
    const t = await res.text();
    throw new Error(`Erreur VT GET: ${res.status} ${t}`);
  }

  const data = await res.json();
  const attrs = data.data.attributes;
  const stats = attrs.last_analysis_stats;

  const x = (stats.malicious || 0) + (stats.suspicious || 0);
  const y = Object.values(stats).reduce((a, b) => a + b, 0);
  const vtScore = `${x}/${y}`;

  const reputation = attrs.reputation ?? 0;
  return { vtScore, reputation };
}

// ===============================
// MAIN
// ===============================
export async function scanVirusTotal(url) {
  const id = encodeUrl(url);
  const { vtScore, reputation } = await getScores(id);
  return { vtScore, reputation };
}

export { encodeUrl, getScores };