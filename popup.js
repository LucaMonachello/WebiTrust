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

let currentHostname = null;
let currentURL = null;

const hasBrowser = typeof globalThis.browser !== "undefined";


const api = hasBrowser ? globalThis.browser : globalThis.chrome;
function normalizeHostname(hostname) {
  return String(hostname || "")
    .trim()
    .toLowerCase()
    .replace(/\.+$/, "");
}

const REPORTS_KEY = "reports";

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

async function getReportsMap() {
  const data = await storageGet(REPORTS_KEY);
  return data?.[REPORTS_KEY] || {};
}

async function getReport(hostname) {
  const key = normalizeHostname(hostname);
  const reports = await getReportsMap();
  return reports[key] || null;
}

async function saveReport(reportInfo) {
  const reports = await getReportsMap();
  const key = normalizeHostname(reportInfo.hostname);
  reports[key] = reportInfo;
  await storageSet({ [REPORTS_KEY]: reports });
}

async function removeReport(hostname) {
  const reports = await getReportsMap();
  const key = normalizeHostname(hostname);
  delete reports[key];
  await storageSet({ [REPORTS_KEY]: reports });
}

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
    }, 30000);

    const reportedMessages = [];
    try {
        const existingReport = await getReport(hostname);
        console.log("[REPORT] existingReport =", existingReport);
        if (existingReport) {
            const when = existingReport.timestamp
                ? new Date(existingReport.timestamp).toLocaleString()
                : "date inconnue";
            reportedMessages.push({
                text: `⚠️ Ce site a déjà été signalé (${when}).`,
                severity: "warning",
                removable: true
            });
        }
    } catch (e) {
        console.warn("Lecture storage (signalements) impossible:", e);
    }

    try {
        const accessibilityCheck = await checkAccessibility(url);
        const accessibilityMessages = !accessibilityCheck.isAccessible
            ? [{ text: accessibilityCheck.message, severity: accessibilityCheck.severity }]
            : [];

        const [blocklistMatches, securityResults] = await Promise.all([
            analyzeSite(hostname),
            analyzeSecurityFeatures(url, hostname)
        ]);

        if (useApi) {
            const apiResult = await calculateScoreApi(url);
            securityResults.totalPenalty += apiResult.penalty;
            securityResults.messages = [...securityResults.messages, ...(apiResult.messages || [])];
        }

        const finalScore = calculateScore(blocklistMatches, securityResults.totalPenalty);
        displayScore(finalScore, blocklistMatches, [
            ...reportedMessages,
            ...accessibilityMessages,
            ...securityResults.messages
        ]);

        console.log('Analyse terminée:', {
            score: finalScore,
            blocklistMatches: blocklistMatches.length,
            securityPenalty: securityResults.totalPenalty
        });

    } catch (error) {
        console.error('Erreur analyse:', error);
        showErrorState('Impossible d\'analyser cette page');
    } finally {
        clearTimeout(analysisTimeout);
    }
}

function getCurrentURL() {
    if (typeof chrome !== 'undefined' && chrome.tabs) {
        chrome.tabs.query({ active: true, currentWindow: true }, function(tabs) {
            if (tabs.length > 0) {
                try {
                    currentURL = tabs[0].url;
                    const urlObj = new URL(currentURL);
                    currentHostname = urlObj.hostname;
                    
                    displayURL(currentHostname);
                    
                    performAnalysis(currentURL, currentHostname);
                } catch (error) {
                    console.error('Erreur lors de la récupération de l\'URL:', error);
                    showErrorState('URL invalide ou inaccessible');
                }
            }
        });
    } else {
        currentURL = 'https://example.com';
        currentHostname = 'example.com';
        displayURL(currentHostname);
        performAnalysis(currentURL, currentHostname);
    }
}

function handleCheckButton() {
    if (currentHostname && currentURL) {
        performAnalysis(currentURL, currentHostname, { useApi: true });
    } else {
        showErrorState('Aucun site à analyser');
    }
}

async function handleReportButton() {
  if (!currentHostname || !currentURL) {
    alert('Aucun site à signaler');
    return;
  }

  const reportInfo = {
    url: currentURL,
    hostname: currentHostname,
    timestamp: new Date().toISOString()
  };

  try {
    await saveReport(reportInfo);

    const verify = await getReport(currentHostname);
    console.log("[REPORT] verify after save =", verify);

    await performAnalysis(currentURL, currentHostname);

  } catch (e) {
    console.error("Erreur signalement (storage):", e);
    alert("Erreur: impossible d'enregistrer le signalement (voir console).");
  }
}

function init() {
    getCurrentURL();
    
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

window.addEventListener("removeReportRequest", async () => {

    await removeReport(currentHostname)

    await performAnalysis(currentURL, currentHostname)

})

document.addEventListener('DOMContentLoaded', init);
