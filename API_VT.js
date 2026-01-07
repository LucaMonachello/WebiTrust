const fetch = require("node-fetch");

const VT_API_KEY = "3c96eb427a670f6aa49937d9d6652a349efdc8f793ae0d816ccc2b46cafbdf89"; //à modifier avec une variable avantt la publication
const lien = "https://perfectdeal.su/"; //à modifier avec la variable de l'url

function encodeUrl(url) {
  return Buffer.from(url)
    .toString("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

async function getScores(id) {
  const res = await fetch(`https://www.virustotal.com/api/v3/urls/${id}`, {
    headers: { "x-apikey": VT_API_KEY }
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

(async () => {
  try {
    const id = encodeUrl(lien);
    const { vtScore, reputation } = await getScores(id);

    console.log("VT score       :", vtScore);
    console.log("Reputation     :", reputation);
  } catch (e) {
    console.error(e.message || e);
  }
})();
