//const { main: scanVirusTotal } = require("./API/API_VT.js");
//const { main: scanCloudflareRadar } = require("./API_CF");

import { scanVirusTotal } from "./API/API_VT.js";
import { scanCloudflareRadar } from "./API/API_CF.js";

export async function calculateScoreApi(url) {
    let penalty = 0;
    let messages = [];

    try {
        /* ================= VirusTotal ================= */
        const vt = await scanVirusTotal(url);
        const [malicious, total] = vt.vtScore.split('/').map(Number);

        console.log("VT raw:", vt);
        console.log("malicious:", malicious, "reputation:", vt.reputation);

        // Pénalité malicious (seulement si >= 2 détections)
        if      (malicious >= 2 && malicious <= 5)  penalty -= 10;
        else if (malicious > 5  && malicious <= 15) penalty -= 25;
        else if (malicious > 15)                    penalty -= 40;

        // Pénalité réputation (seulement si 0 ou 1 détection)
        if (malicious <= 1) {
            if      (vt.reputation < -50)                          penalty -= 30;
            else if (vt.reputation < -20 && vt.reputation >= -50)  penalty -= 20;
            else if (vt.reputation < 0   && vt.reputation >= -20)  penalty -= 10;
        }

        if (malicious >= 2) {
        messages.push({
            text: `VirusTotal : ${malicious}/${total} moteurs détectent un risque`,
            severity: "warning"
        });
        }

        console.log("Penalty after VT:", penalty);

        /* ================= Cloudflare ================= */
        const cf = await scanCloudflareRadar(url);

        console.log("CF raw:", cf);

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
        return 0; // fail-safe
    }
    console.log("Penalty after CF:", penalty);

}