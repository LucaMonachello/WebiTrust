/**
 * Popup principal - Logique d'orchestration
 * Coordonne les modules pour analyser et afficher les résultats
 */

import { analyzeSite } from './blocklist.js';
import { analyzeSecurityFeatures, checkAccessibility } from './securityAnalyzer.js';
import { calculateScore } from './scoreCalculator.js';
import { calculateScoreApi } from './ApiScoreCalculator.js';
import { 
    displayURL, 
    displayScore, 
    showLoadingState, 
    showErrorState 
} from './uiManager.js';

// Variables globales pour stocker les informations du site
let currentHostname = null;
let currentURL = null;

/**
 * Effectue l'analyse complète d'un site
 * @param {string} url - URL complète du site
 * @param {string} hostname - Nom d'hôte du site
 */

async function performAnalysis(url, hostname, options = {}) {
    const { useApi = false } = options;
    showLoadingState();

    const analysisTimeout = setTimeout(() => {
        showErrorState('Analyse trop longue, veuillez réessayer');
    }, 60000);

    try {
        // 0️⃣ Accessibilité (non-bloquant — l'utilisateur est déjà sur le site)
        const accessibilityCheck = await checkAccessibility(url);
        const accessibilityMessages = !accessibilityCheck.isAccessible 
            ? [{ text: accessibilityCheck.message, severity: accessibilityCheck.severity }] 
            : [];

        // 1️⃣ Blocklists + Sécurité (en parallèle pour aller plus vite)
        const [blocklistMatches, securityResults] = await Promise.all([
            analyzeSite(hostname),
            analyzeSecurityFeatures(url, hostname)
        ]);

        // 2️⃣ API (seulement si bouton "Vérifier")
        if (useApi) {
            const apiResult = await calculateScoreApi(url);
            securityResults.totalPenalty += apiResult.penalty;
            securityResults.messages = [...securityResults.messages, ...(apiResult.messages || [])];
        }

        // 3️⃣ Score final + affichage
        const finalScore = calculateScore(blocklistMatches, securityResults.totalPenalty);
        displayScore(finalScore, blocklistMatches, [...accessibilityMessages, ...securityResults.messages]);

    } catch (error) {
        console.error('Erreur analyse:', error);
        showErrorState('Impossible d\'analyser cette page');
    } finally {
        clearTimeout(analysisTimeout);
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
                    currentURL = tabs[0].url;
                    const urlObj = new URL(currentURL);
                    currentHostname = urlObj.hostname;
                    
                    displayURL(currentHostname);
                    
                    // Lancer l'analyse automatiquement
                    performAnalysis(currentURL, currentHostname);
                } catch (error) {
                    console.error('Erreur lors de la récupération de l\'URL:', error);
                    showErrorState('URL invalide ou inaccessible');
                }
            }
        });
    } else {
        // Fallback pour les tests locaux
        currentURL = 'https://example.com';
        currentHostname = 'example.com';
        displayURL(currentHostname);
        performAnalysis(currentURL, currentHostname);
    }
}

/**
 * Gestionnaire du bouton "Vérifier ce site"
 */
function handleCheckButton() {
    if (currentHostname && currentURL) {
        performAnalysis(currentURL, currentHostname, { useApi: true });
    } else {
        showErrorState('Aucun site à analyser');
    }
}

/**
 * Gestionnaire du bouton "Signaler"
 */
function handleReportButton() {
    if (currentHostname) {
        // Préparer un rapport détaillé
        const reportInfo = {
            url: currentURL,
            hostname: currentHostname,
            timestamp: new Date().toISOString()
        };
        
        alert(`Fonctionnalité de signalement à implémenter.\n\nSite: ${currentHostname}\nURL: ${currentURL}`);
        
        // TODO: Envoyer le rapport à un backend
        console.log('Rapport à envoyer:', reportInfo);
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

    const toggleSwitch = document.querySelector('#checkbox');

    function switchTheme(e) {
        if (e.target.checked) {
            document.body.classList.add('light-theme');
            // Optionnel : enregistre le choix pour la prochaine ouverture
            localStorage.setItem('theme', 'light');
        } else {
            document.body.classList.remove('light-theme');
            localStorage.setItem('theme', 'dark');
        }
    }

    // Écouteur de clic sur le bouton
    if (toggleSwitch) {
        toggleSwitch.addEventListener('change', switchTheme, false);

        // Vérifie si l'utilisateur avait déjà choisi le mode clair auparavant
        const currentTheme = localStorage.getItem('theme');
        if (currentTheme === 'light') {
            toggleSwitch.checked = true;
            document.body.classList.add('light-theme');
        }
    }
}

// Initialiser au chargement du DOM
document.addEventListener('DOMContentLoaded', init);