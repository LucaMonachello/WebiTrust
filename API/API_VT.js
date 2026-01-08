// API_VT.js
const fetch = require("node-fetch"); // npm install node-fetch@2

// ===============================
// CONFIG
	@@ -10,15 +10,15 @@ const VT_API_KEY = "3c96eb427a670f6aa49937d9d6652a349efdc8f793ae0d816ccc2b46cafb
// FONCTIONS INTERNES
// ===============================

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
	@@ -45,19 +45,8 @@ async function getScores(id) {
// FONCTION MAIN APPELÉE PAR L’APPLI
// ===============================

async function main(url) {
  const id = encodeUrl(url);
  const { vtScore, reputation } = await getScores(id);
  // on ne renvoie QUE ces deux champs
  return { vtScore, reputation };
}

// ===============================
// EXPORT
// ===============================

module.exports = {
  main,
  encodeUrl,
  getScores
};
