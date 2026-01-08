// API_VT.js (ES module)
import fetch from "node-fetch"; // npm install node-fetch@2

// ===============================
// CONFIG
// ===============================
const VT_API_KEY = "3c96eb427a670f6aa49937d9d6652a349efdc8f793ae0d816ccc2b46cafbdf89"; // TEST ONLY

// ===============================
// FONCTIONS INTERNES
// ===============================

export function encodeUrl(url) {
  return Buffer.from(url)
    .toString("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

export async function getScores(id) {
  const res = await fetch(`https://www.virustotal.com/api/v3/urls/${id}`, {
    headers: { "x-apikey": VT_API_KEY }
  });

  if (!res.ok) {
    const t = await res.text();
    throw new Error(`Erreur VT GET: ${res.status} ${t}`);
  }

  const data  = await res.json();
  const attrs = data.data.attributes;
  const stats = attrs.last_analysis_stats;

  const x = (stats.malicious || 0) + (stats.suspicious || 0);
  const y = Object.values(stats).reduce((a, b) => a + b, 0);
  const vtScore = `${x}/${y}`;

  const reputation = attrs.reputation ?? 0;

  return { vtScore, reputation };
}

// ===============================
// FONCTION MAIN APPELÉE PAR L’APPLI
// ===============================

export async function main(url) {
  const id = encodeUrl(url);
  const { vtScore, reputation } = await getScores(id);
  return { vtScore, reputation };
}
