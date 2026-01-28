/**
 * Module de calcul du score de fiabilité - Version 100 points
 * Gère la logique mathématique et la catégorisation du niveau de risque
 */

/**
 * Calcule le score final sur 100
 * @param {string} url - URL complète du site
 * @returns {number} Score entier entre 0 et 100
 */


const { main: scanCloudflareRadar } = require("./API/API_CF.js");
const { main: scanVirusTotal } = require("./API/API_VT.js");


export async function calculateScoreApi(url) {

    try {
        // 🔍 Cloudflare Radar
        const resultCF = await scanCloudflareRadar(url);

        // 🔍 VirusTotal
        const resultVT = await scanVirusTotal(url);

        /* =======================
           VIRUSTOTAL
        ======================= */
        if (resultVT?.vtScore) {
            const [detections, total] = resultVT.vtScore
                .split('/')
                .map(Number);

            if (total > 0) {
                const ratio = detections / total;

                // Pénalité proportionnelle
                const vtPenalty = Math.round(ratio * 100);
                score -= vtPenalty;
            }
        }

        /* =======================
           CLOUDFLARE RADAR
        ======================= */
        if (resultCF?.details?.malicious === true) {
            score -= 40;
        }

        /* =======================
           AUTRES SIGNAUX CF (OPTIONNEL)
        ======================= */
        if (resultCF?.details?.phishing === true) {
            score -= 20;
        }

        if (resultCF?.details?.malware === true) {
            score -= 30;
        }

        // Clamp final
        return Math.max(0, Math.min(100, Math.round(score)));

    } catch (e) {
        console.error("Erreur API :", e.message);

        // En cas d’erreur API → score neutre dégradé
        return 50;
    }
}



/** {
  "vtScore": "2/97",
  "reputation": -43
}
{
  "isSecure": false,
  "protocol": "https",
  "penaltyScore": -30,
  "message": "✗ URL détectée comme risquée par Cloudflare Radar",
  "severity": "high",
  "details": {
    "malicious": true,
    "phishing": true,
    "malware": false,
    "spam": false,
    "crypto_mining": false,
    "command_and_control": false
  }
}*/




/**
 * Fournit les textes et styles associés au score
 * param {number} score - Score sur 100
 * param {string[]} matches - Liste des menaces
 * param {Array} securityMessages - Alertes techniques
 * returns {Object} Label, description, classe CSS et tags
 
export function getScoreInfo(score, matches, securityMessages = []) {
    let tags = [];

    // On récupère les messages d'erreur techniques
    if (securityMessages) {
        securityMessages.forEach(msg => {
            if (msg.text) tags.push(msg.text);
        });
    }

    // On ajoute les noms des blocklists détectées
    if (matches.length > 0) {
        tags = [...tags, ...matches];
    }

    // Si le score est parfait et aucun tag n'existe, on valorise le site
    if (tags.length === 0 && score >= 90) {
        tags = ["✓ Site sécurisé", "✓ Connexion chiffrée", "✓ Aucun risque détecté"];
    }

    // Catégorisation pour l'interface
    if (score >= 80) {
        return {
            label: "Très fiable",
            desc: "Ce site présente des garanties de sécurité solides.",
            className: "wt-tag-safe", // Utilise tes classes CSS existantes
            tags: tags
        };
    } else if (score >= 50) {
        return {
            label: "Prudence",
            desc: "Quelques points de vigilance détectés sur ce domaine.",
            className: "wt-tag-warning",
            tags: tags
        };
    } else {
        return {
            label: "Site Risqué",
            desc: "Attention, ce site présente des risques élevés de phishing ou de fraude.",
            className: "wt-tag-risk",
            tags: tags
        };
    }
}




 * Détermine la couleur hexadécimale pour l'anneau de progression
 * param {number} score - Score sur 100
 * returns {string} Code couleur Hex
 
export function getScoreColor(score) {
    if (score >= 80) return '#22c55e'; // Vert (--wt-safe)
    if (score >= 50) return '#f59e0b'; // Orange (--wt-warning)
    return '#ef4444'; // Rouge (--wt-danger)
}
*/