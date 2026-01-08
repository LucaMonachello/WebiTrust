// caller_VT.js
const { main: scanVirusTotal } = require("./API_VT");

async function run() {
  try {
    const url = process.argv[2] || "https://perfectdeal.su/";
    const result = await scanVirusTotal(url);
    console.log(JSON.stringify(result, null, 2));
  } catch (e) {
    console.error("Erreur VirusTotal:", e.message || e);
    process.exit(1);
  }
}

run();


//type de retour:

//{
//  "vtScore": "2/97",
//  "reputation": -43
//}
