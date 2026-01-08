//attention a ne pas mettre en prod, exemple pour tester la fonction sans GUI, en PROD modifier les variable d'appel et de lien

// caller_CF.js
const { main: scanCloudflareRadar } = require("./API_CF");

async function run() {
  try {
    const url = process.argv[2] || "https://polite-puppy-cbadb6.netlify.app/#info@ch.stago.com/";
    const result = await scanCloudflareRadar(url);
    console.log(JSON.stringify(result, null, 2));
  } catch (e) {
    console.error("Erreur Cloudflare Radar:", e.message);
    process.exit(1);
  }
}

run();
