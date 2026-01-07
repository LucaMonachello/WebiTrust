/**
 * Module de calcul du score de fiabilité
 * Gère le calcul du score et les informations associées
 */

/**
 * Calcule le score en fonction des matches et de la sécurité
 * @param {string[]} matches - Liste des correspondances dans les blocklists
 * @param {number} securityPenalty - Pénalité due aux problèmes de sécurité
 * @returns {number} Score de 0 à 5
 */
export function calculateScore(matches, securityPenalty = 0) {
    let baseScore = 5.0;
    
    // Pénalité pour les blocklists
    if (matches.length === 1) {
        baseScore -= 2.0; // Une détection = -2 points
    } else if (matches.length === 2) {
        baseScore -= 3.5; // Deux détections = -3.5 points
    } else if (matches.length >= 3) {
        baseScore -= 4.5; // Trois détections ou plus = -4.5 points
    }
    
    // Appliquer la pénalité de sécurité
    baseScore += securityPenalty; // securityPenalty est déjà négatif
    
    // S'assurer que le score reste entre 0 et 5
    return Math.max(0, Math.min(5, baseScore));
}

/**
 * Obtient les informations détaillées sur le score
 * @param {number} score - Score calculé
 * @param {string[]} matches - Liste des correspondances blocklist
 * @param {Array} securityMessages - Messages de sécurité (UNIQUEMENT les problèmes)
 * @returns {Object} Objet contenant label, description, classe CSS et tags
 */
export function getScoreInfo(score, matches, securityMessages = []) {
    const numScore = parseFloat(score);
    let tags = [];
    
    // Ajouter les messages de sécurité problématiques en premier
    if (securityMessages && securityMessages.length > 0) {
        securityMessages.forEach(msg => {
            if (msg.text) {
                tags.push(msg.text);
            }
        });
    }
    
    // Ajouter les tags de blocklist
    if (matches.length > 0) {
        tags = [...tags, ...matches];
    }
    
    // Si aucun problème détecté, ajouter des tags positifs
    if (tags.length === 0) {
        if (numScore >= 4.5) {
            tags = ["✓ HTTPS sécurisé", "✓ Aucune menace détectée", "✓ Domaine fiable"];
        } else if (numScore >= 3.5) {
            tags = ["✓ Aucune menace détectée"];
        }
    }
    
    // Déterminer le niveau de fiabilité
    if (numScore >= 4.5) {
        return {
            label: "Très fiable",
            desc: "Site sécurisé et digne de confiance",
            className: "wt-score-good",
            tags: tags
        };
    } else if (numScore >= 3.5) {
        return {
            label: "Fiable",
            desc: "Site généralement sûr",
            className: "wt-score-good",
            tags: tags
        };
    } else if (numScore >= 2.5) {
        return {
            label: "Attention requise",
            desc: "Éléments suspects détectés",
            className: "wt-score-medium",
            tags: tags
        };
    } else if (numScore >= 1.5) {
        return {
            label: "Potentiellement risqué",
            desc: "Plusieurs risques détectés",
            className: "wt-score-bad",
            tags: tags
        };
    } else {
        return {
            label: "Très risqué",
            desc: "Site potentiellement malveillant",
            className: "wt-score-bad",
            tags: tags
        };
    }
}

/**
 * Détermine la classe de couleur pour les étoiles
 * @param {number} score - Score calculé
 * @returns {string} Classe CSS pour la couleur
 */
export function getStarColorClass(score) {
    const numScore = parseFloat(score);
    
    if (numScore < 2.5) {
        return 'filled-bad';
    } else if (numScore < 4) {
        return 'filled-medium';
    }
    return 'filled-good';
}