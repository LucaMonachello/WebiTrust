/**
 * Module de calcul du score de fiabilité - Version 100 points
 * Gère la logique mathématique et la catégorisation du niveau de risque
 */

/**
 * Calcule le score final sur 100
 * @param {string[]} matches - Liste des correspondances dans les blocklists
 * @param {number} securityPenalty - Pénalité accumulée (basée sur securityAnalyzer)
 * @returns {number} Score entier entre 0 et 100
 */
export function calculateScore(matches, securityPenalty = 0) {
    let score = 100;

    // 1. Pénalités pour les listes noires (Blocklists)
    // On considère qu'une détection est critique
    if (matches.length === 1) {
        score -= 50; // Chute directe à 50 (Orange)
    } else if (matches.length === 2) {
        score -= 80; // Chute à 20 (Rouge)
    } else if (matches.length >= 3) {
        score -= 100; // Danger immédiat (0)
    }

    // 2. Pénalités techniques (HTTPS, SSL, etc.)
    // Les pénalités venant de securityAnalyzer (ex: -2) sont multipliées par 15
    // pour avoir un impact réel sur une échelle de 100.
    const technicalImpact = Math.abs(securityPenalty);
    score -= technicalImpact;

    // 3. Sécurité : On s'assure que le score reste entre 0 et 100
    return Math.max(0, Math.min(100, Math.round(score)));
}

/**
 * Fournit les textes et styles associés au score
 * @param {number} score - Score sur 100
 * @param {string[]} matches - Liste des menaces
 * @param {Array} securityMessages - Alertes techniques
 * @returns {Object} Label, description, classe CSS et tags
 */
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

/**
 * Détermine la couleur hexadécimale pour l'anneau de progression
 * @param {number} score - Score sur 100
 * @returns {string} Code couleur Hex
 */
export function getScoreColor(score) {
    if (score >= 80) return '#22c55e'; // Vert (--wt-safe)
    if (score >= 50) return '#f59e0b'; // Orange (--wt-warning)
    return '#ef4444'; // Rouge (--wt-danger)
}