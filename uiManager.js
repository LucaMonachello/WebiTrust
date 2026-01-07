/**
 * Module de gestion de l'interface utilisateur
 * Gère l'affichage et les mises à jour du popup
 */

import { getStarColorClass, getScoreInfo } from './scoreCalculator.js';

/**
 * Affiche les étoiles en fonction du score
 * @param {number} score - Score à afficher
 */
export function displayStars(score) {
    const numScore = parseFloat(score);
    const stars = document.querySelectorAll('.wt-star');
    const filledStars = Math.round(numScore);
    
    // Déterminer la couleur en fonction du score
    const colorClass = getStarColorClass(score);
    
    stars.forEach((star, index) => {
        // Enlever toutes les classes de couleur
        star.classList.remove('filled-good', 'filled-medium', 'filled-bad');
        
        if (index < filledStars) {
            star.classList.add(colorClass);
        }
    });
}

/**
 * Affiche les tags de sécurité
 * @param {string[]} tags - Liste des tags à afficher
 */
export function displayTags(tags) {
    const container = document.getElementById('wt-tags-container');
    container.innerHTML = '';
    
    tags.forEach(tag => {
        const tagEl = document.createElement('span');
        tagEl.className = 'wt-tag';
        
        if (tag.includes('✓')) {
            tagEl.classList.add('wt-tag-safe');
        } else if (tag.includes('✗')) {
            tagEl.classList.add('wt-tag-risk');
        } else {
            tagEl.classList.add('wt-tag-warning');
        }
        
        tagEl.textContent = tag;
        container.appendChild(tagEl);
    });
}

/**
 * Affiche le score complet avec toutes les informations
 * @param {number} score - Score calculé
 * @param {string[]} matches - Liste des correspondances
 */
export function displayScore(score, matches) {
    const scoreInfo = getScoreInfo(score, matches);
    
    // Afficher les étoiles
    displayStars(score);
    
    // Afficher la valeur numérique
    const scoreValueEl = document.getElementById('wt-score-value');
    scoreValueEl.textContent = score.toFixed(1) + '/5';
    scoreValueEl.className = 'wt-score-value-text ' + scoreInfo.className;
    
    // Afficher le label et la description
    document.getElementById('wt-score-label').textContent = scoreInfo.label;
    document.getElementById('wt-score-desc').textContent = scoreInfo.desc;
    
    // Afficher les tags
    displayTags(scoreInfo.tags);
}

/**
 * Affiche l'URL du site analysé
 * @param {string} hostname - Nom d'hôte à afficher
 */
export function displayURL(hostname) {
    document.getElementById('wt-url-display').textContent = hostname;
}

/**
 * Affiche l'état de chargement
 */
export function showLoadingState() {
    document.getElementById('wt-score-label').textContent = 'Analyse en cours';
    document.getElementById('wt-score-desc').textContent = 'Vérification des listes...';
    displayTags(['⏳ Analyse en cours']);
}

/**
 * Affiche un état d'erreur
 * @param {string} message - Message d'erreur à afficher
 */
export function showErrorState(message = 'Erreur lors de l\'analyse') {
    document.getElementById('wt-url-display').textContent = 'URL invalide';
    document.getElementById('wt-score-label').textContent = 'Erreur';
    document.getElementById('wt-score-desc').textContent = message;
    displayTags(['❌ Erreur']);
}