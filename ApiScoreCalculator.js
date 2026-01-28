export async function calculateScoreApi(url) {
    let penalty = 0;
    let messages = [];

    try {
        /* ================= VirusTotal ================= */
        const vt = await scanVirusTotal(url);
        const [malicious, total] = vt.vtScore.split('/').map(Number);

        if (malicious >= 2 && malicious <= 5) penalty += 10;
        else if (malicious <= 15) penalty += 25;
        else if (malicious > 15) penalty += 40;

        if (vt.reputation < 0 && vt.reputation >= -20) penalty += 10;
        else if (vt.reputation >= -50) penalty += 20;
        else if (vt.reputation < -50) penalty += 30;

        /* ================= Cloudflare ================= */
        const cf = await scanCloudflareRadar(url);

        if (cf.details?.malicious) penalty += 30;
        if (cf.details?.phishing) penalty += 25;
        if (cf.details?.malware) penalty += 40;
        if (cf.details?.spam) penalty += 10;
        if (cf.details?.crypto_mining) penalty += 20;
        if (cf.details?.command_and_control) penalty += 50;

        if (malicious >= 2) {
        messages.push({
            text: `VirusTotal : ${malicious}/${total} moteurs détectent un risque`,
            severity: "warning"
        });
        }


        return { penalty, messages };

    } catch (e) {
        console.error("Erreur API scoring :", e);
        return 0; // fail-safe
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