/**
 * Module de calcul du score de fiabilité
 * Gère le calcul du score et les informations associées
 */

/**
 * Calcule le score en fonction du nombre de matches
 * @param {string[]} matches - Liste des correspondances dans les blocklists
 * @returns {number} Score de 0 à 5
 */
export function calculateScore(matches) {
    if (matches.length === 0) {
        return 5.0; // Parfait, aucune détection
    } else if (matches.length === 1) {
        return 3.0; // Une détection = attention requise
    } else if (matches.length === 2) {
        return 1.5; // Deux détections = potentiellement risqué
    } else {
        return 0.5; // Trois détections ou plus = très risqué
    }
}

/**
 * Obtient les informations détaillées sur le score
 * @param {number} score - Score calculé
 * @param {string[]} matches - Liste des correspondances
 * @returns {Object} Objet contenant label, description, classe CSS et tags
 */
export function getScoreInfo(score, matches) {
    const numScore = parseFloat(score);
    let tags = [];
    
    if (matches.length > 0) {
        // Ajouter les tags de matches
        tags = [...matches];
    }
    
    if (numScore >= 4.5) {
        if (tags.length === 0) {
            tags = ["✓ Domaine sécurisé", "✓ Aucune menace détectée"];
        }
        return {
            label: "Très fiable",
            desc: "Site sécurisé et digne de confiance",
            className: "wt-score-good",
            tags: tags
        };
    } else if (numScore >= 3.5) {
        if (tags.length === 0) {
            tags = ["✓ Domaine sécurisé"];
        }
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
            tags: tags.length > 0 ? tags : ["⚠ À vérifier"]
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