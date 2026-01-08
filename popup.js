/**
 * Popup principal - Logique d'orchestration
 * Coordonne les modules pour analyser et afficher les résultats
 */

import { analyzeSite } from './blocklist.js';
import { analyzeSecurityFeatures, checkAccessibility } from './securityAnalyzer.js';
import { calculateScore } from './scoreCalculator.js';
import {
  displayURL,
  displayScore,
  showLoadingState,
  showErrorState
} from './uiManager.js';

// Variables globales pour stocker les informations du site
let currentHostname = null;
let currentURL = null;

/* =========================================================
   AJOUT : couche API cross-browser + storage signalements
   ========================================================= */

/**
 * AJOUT : Firefox expose `browser` (Promise-based), Chrome expose `chrome`.
 * On choisit automatiquement l'API dispo.
 */
const hasBrowser = typeof globalThis.browser !== "undefined";
const api = hasBrowser ? globalThis.browser : globalThis.chrome;

/**
 * AJOUT : normalisation du hostname pour éviter les mismatches
 * (majuscules, point final, espaces, etc.).
 */
function normalizeHostname(hostname) {
  return String(hostname || "")
    .trim()
    .toLowerCase()
    .replace(/\.+$/, ""); // enlève les "." finaux éventuels
}

/**
 * AJOUT : clé unique dans storage.local pour stocker les signalements.
 */
const REPORTS_KEY = "reports";

/**
 * AJOUT : storageGet compatible Firefox (Promise) + Chrome (callback).
 */
async function storageGet(key) {
  if (!api?.storage?.local) return {};
  if (hasBrowser) {
    return await api.storage.local.get(key);
  }
  return await new Promise((resolve, reject) => {
    api.storage.local.get(key, (res) => {
      const err = api.runtime?.lastError;
      if (err) reject(err);
      else resolve(res);
    });
  });
}

/**
 * AJOUT : storageSet compatible Firefox (Promise) + Chrome (callback).
 */
async function storageSet(obj) {
  if (!api?.storage?.local) return;
  if (hasBrowser) {
    await api.storage.local.set(obj);
    return;
  }
  await new Promise((resolve, reject) => {
    api.storage.local.set(obj, () => {
      const err = api.runtime?.lastError;
      if (err) reject(err);
      else resolve();
    });
  });
}

/**
 * AJOUT : récupérer la map complète des signalements.
 * Format: { "example.com": { url, hostname, timestamp }, ... }
 */
async function getReportsMap() {
  const data = await storageGet(REPORTS_KEY);
  return data?.[REPORTS_KEY] || {};
}

/**
 * AJOUT : récupérer un signalement (ou null).
 */
async function getReport(hostname) {
  const key = normalizeHostname(hostname);
  const reports = await getReportsMap();
  return reports[key] || null;
}

/**
 * AJOUT : enregistrer / mettre à jour un signalement.
 */
async function saveReport(reportInfo) {
  const reports = await getReportsMap();
  const key = normalizeHostname(reportInfo.hostname);
  reports[key] = reportInfo;
  await storageSet({ [REPORTS_KEY]: reports });
}

/**
 * AJOUT (optionnel) : supprimer un signalement.
 */
async function removeReport(hostname) {
  const reports = await getReportsMap();
  const key = normalizeHostname(hostname);
  delete reports[key];
  await storageSet({ [REPORTS_KEY]: reports });
}

/**
 * AJOUT : récupérer l'onglet actif (Firefox Promise / Chrome callback).
 */
async function getActiveTab() {
  if (!api?.tabs?.query) return null;

  if (hasBrowser) {
    const tabs = await api.tabs.query({ active: true, currentWindow: true });
    return tabs?.[0] || null;
  }

  return await new Promise((resolve) => {
    api.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      resolve(tabs?.[0] || null);
    });
  });
}

/* =========================
   Analyse principale
   ========================= */

/**
 * Effectue l'analyse complète d'un site
 * @param {string} url - URL complète du site
 * @param {string} hostname - Nom d'hôte du site
 */
async function performAnalysis(url, hostname) {
  showLoadingState();

  // AJOUT : message d’alerte si déjà signalé
  const reportedMessages = [];
  try {
    const existingReport = await getReport(hostname);

    // AJOUT : debug utile pour Firefox (à lire dans la console popup)
    console.log("[REPORT] existingReport =", existingReport);

    if (existingReport) {
      const when = existingReport.timestamp
        ? new Date(existingReport.timestamp).toLocaleString()
        : "date inconnue";

      reportedMessages.push({
        text: `⚠️ Ce site a déjà été signalé (${when}).`,
        severity: "warning"
      });
    }
  } catch (e) {
    console.warn("Lecture storage (signalements) impossible:", e);
  }

  try {
    // 0️⃣ Vérification d’accessibilité (DNS / HTTP)
    const accessibilityCheck = await checkAccessibility(url);

    // ❌ Site inaccessible → STOP analyse
    if (!accessibilityCheck.isAccessible) {
      displayScore(
        0,
        [],
        [
          ...reportedMessages,
          {
            text: accessibilityCheck.message,
            severity: accessibilityCheck.severity
          }
        ]
      );
      console.warn('Analyse stoppée : site inaccessible', accessibilityCheck);
      return;
    }

    // 1️⃣ Blocklists
    const blocklistMatches = await analyzeSite(hostname);

    // 2️⃣ Sécurité technique
    const securityResults = await analyzeSecurityFeatures(url, hostname);

    // 3️⃣ Score final
    const finalScore = calculateScore(
      blocklistMatches,
      securityResults.totalPenalty
    );

    // 4️⃣ Affichage
    displayScore(
      finalScore,
      blocklistMatches,
      [...reportedMessages, ...securityResults.messages]
    );

    console.log('Analyse terminée:', {
      score: finalScore,
      blocklistMatches: blocklistMatches.length,
      securityPenalty: securityResults.totalPenalty
    });

  } catch (error) {
    console.error('Erreur analyse:', error);
    showErrorState('Impossible d\'analyser cette page');
  }
}

/**
 * Récupère et analyse l'URL de l'onglet actif
 */
async function getCurrentURL() {
  try {
    const tab = await getActiveTab();

    if (tab?.url) {
      currentURL = tab.url;
      const urlObj = new URL(currentURL);

      // AJOUT : on normalise dès le départ pour avoir la même clé partout
      currentHostname = normalizeHostname(urlObj.hostname);

      displayURL(currentHostname);
      await performAnalysis(currentURL, currentHostname);
      return;
    }

    // Fallback tests
    currentURL = 'https://example.com';
    currentHostname = 'example.com';
    displayURL(currentHostname);
    await performAnalysis(currentURL, currentHostname);

  } catch (error) {
    console.error("Erreur lors de la récupération de l'URL:", error);
    showErrorState("URL invalide ou inaccessible");
  }
}

/**
 * Gestionnaire du bouton "Vérifier ce site"
 */
async function handleCheckButton() {
  if (currentHostname && currentURL) {
    await performAnalysis(currentURL, currentHostname);
  } else {
    showErrorState('Aucun site à analyser');
  }
}

/**
 * Gestionnaire du bouton "Signaler"
 */
async function handleReportButton() {
  if (!currentHostname || !currentURL) {
    alert('Aucun site à signaler');
    return;
  }

  const reportInfo = {
    url: currentURL,
    hostname: currentHostname, // déjà normalisé
    timestamp: new Date().toISOString()
  };

  try {
    await saveReport(reportInfo);

    // AJOUT : debug => relire juste après pour confirmer que Firefox a bien écrit
    const verify = await getReport(currentHostname);
    console.log("[REPORT] verify after save =", verify);

    alert(`Site signalé.\n\nSite: ${currentHostname}\nURL: ${currentURL}`);

    // Relance l'analyse pour afficher l’alerte immédiatement
    await performAnalysis(currentURL, currentHostname);

  } catch (e) {
    console.error("Erreur signalement (storage):", e);
    alert("Erreur: impossible d'enregistrer le signalement (voir console).");
  }
}

/**
 * Initialise l'application
 */
function init() {
  getCurrentURL();

  const checkBtn = document.getElementById('wt-btn-check');
  const reportBtn = document.getElementById('wt-btn-report');

  if (checkBtn) checkBtn.addEventListener('click', handleCheckButton);
  if (reportBtn) reportBtn.addEventListener('click', handleReportButton);

  const toggleSwitch = document.querySelector('#checkbox');

  function switchTheme(e) {
    if (e.target.checked) {
      document.body.classList.add('light-theme');
      localStorage.setItem('theme', 'light');
    } else {
      document.body.classList.remove('light-theme');
      localStorage.setItem('theme', 'dark');
    }
  }

  if (toggleSwitch) {
    toggleSwitch.addEventListener('change', switchTheme, false);

    const currentTheme = localStorage.getItem('theme');
    if (currentTheme === 'light') {
      toggleSwitch.checked = true;
      document.body.classList.add('light-theme');
    }
  }
}

document.addEventListener('DOMContentLoaded', init);