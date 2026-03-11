//const { main: scanVirusTotal } = require("./API/API_VT.js");
//const { main: scanCloudflareRadar } = require("./API_CF");

import { scanVirusTotal } from "./API/API_VT.js";
import { scanCloudflareRadar } from "./API/API_CF.js";

export async function calculateScoreApi(url) {
    let penalty = 0;
    let messages = [];

    try {
        // ✅ Les deux appels en parallèle au lieu de séquentiels
        const [vt, cf] = await Promise.all([
            scanVirusTotal(url),
            scanCloudflareRadar(url)
        ]);

        /* VirusTotal */
        const [malicious, total] = vt.vtScore.split('/').map(Number);

        if (malicious >= 2 && malicious <= 5) penalty -= 10;
        else if (malicious <= 15) penalty -= 25;
        else if (malicious > 15) penalty -= 40;

        // ✅ Bloc reputation séparé (bug corrigé)
        if (vt.reputation < 0 && vt.reputation >= -20) penalty -= 10;
        else if (vt.reputation < -20 && vt.reputation >= -50) penalty -= 20;
        else if (vt.reputation < -50) penalty -= 30;

        if (malicious >= 2) {
            messages.push({
                text: `VirusTotal : ${malicious}/${total} moteurs détectent un risque`,
                severity: "warning"
            });
        }

        /* Cloudflare */
        if (cf.details?.phishing) penalty -= 25;
        if (cf.details?.malware) penalty -= 40;
        if (cf.details?.spam) penalty -= 10;
        if (cf.details?.crypto_mining) penalty -= 20;
        if (cf.details?.command_and_control) penalty -= 50;

        const detectedTypes = [];
        for (const type of ["phishing", "malware", "spam", "crypto_mining", "command_and_control"]) {
            if (cf.details?.[type]) detectedTypes.push(type);
        }
        if (detectedTypes.length > 0) {
            messages.push({
                text: `Cloudflare Radar : ${detectedTypes.join(", ")} détecté(s)`,
                severity: "high"
            });
        }

        return { penalty, messages };

    } catch (e) {
        console.error("Erreur API scoring :", e);
        return { penalty: 0, messages: [] }; // ✅ Format correct au lieu de return 0
    }
    console.log("Penalty after CF:", penalty);

}