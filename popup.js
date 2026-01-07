/**
 * Popup principal - Logique d'orchestration
 * Coordonne les modules pour analyser et afficher les résultats
 */

import { analyzeSite } from './blocklist.js';
import { calculateScore } from './scoreCalculator.js';
import { 
    displayURL, 
    displayScore, 
    showLoadingState, 
    showErrorState 
} from './uiManager.js';

// Variable globale pour stocker le hostname actuel
let currentHostname = null;

/**
 * Effectue l'analyse complète d'un site
 * @param {string} hostname - Nom d'hôte à analyser
 */
async function performAnalysis(hostname) {
    // Afficher l'état de chargement
    showLoadingState();
    
    try {
        // Analyser le site avec les blocklists
        const matches = await analyzeSite(hostname);
        
        // Calculer le score
        const score = calculateScore(matches);
        
        // Afficher les résultats
        displayScore(score, matches);
    } catch (error) {
        console.error('Erreur lors de l\'analyse:', error);
        showErrorState('Impossible d\'analyser cette page');
    }
}

/**
 * Récupère et analyse l'URL de l'onglet actif
 */
function getCurrentURL() {
    // Pour Manifest V2, utiliser chrome.tabs.query
    if (typeof chrome !== 'undefined' && chrome.tabs) {
        chrome.tabs.query({ active: true, currentWindow: true }, function(tabs) {
            if (tabs.length > 0) {
                try {
                    const url = new URL(tabs[0].url);
                    currentHostname = url.hostname;
                    displayURL(currentHostname);
                    
                    // Lancer l'analyse automatiquement
                    performAnalysis(currentHostname);
                } catch (error) {
                    console.error('Erreur lors de la récupération de l\'URL:', error);
                    showErrorState('URL invalide ou inaccessible');
                }
            }
        });
    } else {
        // Fallback pour les tests locaux
        currentHostname = 'example.com';
        displayURL(currentHostname);
        performAnalysis(currentHostname);
    }
}

/**
 * Gestionnaire du bouton "Vérifier ce site"
 */
function handleCheckButton() {
    if (currentHostname) {
        performAnalysis(currentHostname);
    } else {
        showErrorState('Aucun site à analyser');
    }
}

/**
 * Gestionnaire du bouton "Signaler"
 */
function handleReportButton() {
    if (currentHostname) {
        alert(`Fonctionnalité de signalement à implémenter pour : ${currentHostname}`);
    } else {
        alert('Aucun site à signaler');
    }
}

/**
 * Initialise l'application
 */
function init() {
    // Récupérer et analyser l'URL actuelle
    getCurrentURL();
    
    // Configurer les gestionnaires d'événements
    const checkBtn = document.getElementById('wt-btn-check');
    const reportBtn = document.getElementById('wt-btn-report');
    
    if (checkBtn) {
        checkBtn.addEventListener('click', handleCheckButton);
    }
    
    if (reportBtn) {
        reportBtn.addEventListener('click', handleReportButton);
    }
}

// Initialiser au chargement du DOM
document.addEventListener('DOMContentLoaded', init);