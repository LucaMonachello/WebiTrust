// Fonction pour charger une liste de blocage depuis un fichier
async function loadBlocklist(filename) {
    try {
        const response = await fetch(`blocklist/${filename}`);
        const text = await response.text();
        
        // Retourner un tableau de domaines (une ligne par domaine)
        const domains = text.split('\n')
            .map(line => line.trim())
            .filter(line => {
                // Ignorer les lignes vides et les commentaires
                if (!line || line.startsWith('#')) {
                    return false;
                }
                // Vérifier si la ligne commence par 0.0.0.0 ou 127.0.0.1
                if (line.startsWith('0.0.0.0 ') || line.startsWith('127.0.0.1 ')) {
                    return true;
                }
                return false;
            })
            .map(line => {
                // Extraire le domaine après l'IP
                if (line.startsWith('0.0.0.0 ')) {
                    return line.substring(8).trim();
                } else if (line.startsWith('127.0.0.1 ')) {
                    return line.substring(10).trim();
                }
                return line.trim();
            });
        
        return domains;
    } catch (error) {
        console.error(`Erreur lors du chargement de ${filename}:`, error);
        return [];
    }
}

// Fonction pour vérifier si un domaine est dans une liste
function isDomainInList(domain, list) {
    // Vérification exacte
    if (list.includes(domain)) {
        return true;
    }
    
    // Vérifier les sous-domaines (ex: sub.example.com correspond à example.com dans la liste)
    const parts = domain.split('.');
    for (let i = 1; i < parts.length; i++) {
        const parentDomain = parts.slice(i).join('.');
        if (list.includes(parentDomain)) {
            return true;
        }
    }
    
    // Vérification avec wildcard (*.example.com dans la liste)
    for (const entry of list) {
        if (entry.startsWith('*.')) {
            const pattern = entry.substring(2); // Enlever le *.
            if (domain.endsWith(pattern) || domain === pattern) {
                return true;
            }
        }
    }
    
    return false;
}

// Fonction pour récupérer tous les fichiers du dossier blocklist
async function getAllBlocklistFiles() {
    try {
        // Récupérer le contenu du dossier blocklist
        const response = await fetch('blocklist/');
        const text = await response.text();
        
        // Parser le HTML pour extraire les noms de fichiers .txt
        const parser = new DOMParser();
        const doc = parser.parseFromString(text, 'text/html');
        const links = doc.querySelectorAll('a');
        
        const files = [];
        links.forEach(link => {
            const href = link.getAttribute('href');
            if (href && href.endsWith('.txt') && !href.startsWith('.')) {
                files.push(href);
            }
        });
        
        return files;
    } catch (error) {
        console.error('Erreur lors de la récupération des fichiers:', error);
        // Si le listing ne fonctionne pas, retourner une liste manuelle
        return [
            'drugs.txt',
            'phishing.txt',
            'malware.txt',
            'fraud.txt',
            'porn.txt',
            'scam.txt',
        ];
    }
}

// Fonction pour analyser le site avec les blocklists
async function analyzeSite(hostname) {
    const matches = [];
    
    // Récupérer tous les fichiers de blocklist
    const files = await getAllBlocklistFiles();
    
    // Charger et vérifier chaque liste
    for (const file of files) {
        const list = await loadBlocklist(file);
        if (list.length > 0 && isDomainInList(hostname, list)) {
            // Extraire le nom sans l'extension .txt
            const listName = file.replace('.txt', '').replace(/-/g, ' ').replace(/_/g, ' ');
            // Mettre la première lettre en majuscule
            const displayName = listName.charAt(0).toUpperCase() + listName.slice(1);
            matches.push(`✗ Matched "${displayName}"`);
        }
    }
    
    return matches;
}

// Fonction pour calculer le score en fonction des matches
function calculateScore(matches) {
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

// Fonction pour afficher les étoiles en fonction du score avec couleurs adaptées
function displayStars(score) {
    const numScore = parseFloat(score);
    const stars = document.querySelectorAll('.wt-star');
    const filledStars = Math.round(numScore);
    
    // Déterminer la couleur en fonction du score
    let colorClass = 'filled-good';
    if (numScore < 2.5) {
        colorClass = 'filled-bad';
    } else if (numScore < 4) {
        colorClass = 'filled-medium';
    }
    
    stars.forEach((star, index) => {
        // Enlever toutes les classes de couleur
        star.classList.remove('filled-good', 'filled-medium', 'filled-bad');
        
        if (index < filledStars) {
            star.classList.add(colorClass);
        }
    });
}

// Fonction pour obtenir le label et la description en fonction du score et des matches
function getScoreInfo(score, matches) {
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

// Fonction pour afficher les tags
function displayTags(tags) {
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

// Fonction pour afficher le score
function displayScore(score, matches) {
    const scoreInfo = getScoreInfo(score, matches);
    
    displayStars(score);
    
    const scoreValueEl = document.getElementById('wt-score-value');
    scoreValueEl.textContent = score.toFixed(1) + '/5';
    scoreValueEl.className = 'wt-score-value-text ' + scoreInfo.className;
    
    document.getElementById('wt-score-label').textContent = scoreInfo.label;
    document.getElementById('wt-score-desc').textContent = scoreInfo.desc;
    
    displayTags(scoreInfo.tags);
}

// Fonction pour effectuer l'analyse complète
async function performAnalysis(hostname) {
    // Afficher l'état de chargement
    document.getElementById('wt-score-label').textContent = 'Analyse en cours';
    document.getElementById('wt-score-desc').textContent = 'Vérification des listes...';
    
    // Analyser le site
    const matches = await analyzeSite(hostname);
    
    // Calculer le score
    const score = calculateScore(matches);
    
    // Afficher les résultats
    displayScore(score, matches);
}

// Variable globale pour stocker le hostname actuel
let currentHostname = null;

// Fonction pour récupérer l'URL de l'onglet actif
function getCurrentURL() {
    // Pour Manifest V2, utiliser chrome.tabs.query
    if (typeof chrome !== 'undefined' && chrome.tabs) {
        chrome.tabs.query({ active: true, currentWindow: true }, function(tabs) {
            if (tabs.length > 0) {
                try {
                    const url = new URL(tabs[0].url);
                    currentHostname = url.hostname;
                    document.getElementById('wt-url-display').textContent = currentHostname;
                    
                    // Lancer l'analyse automatiquement
                    performAnalysis(currentHostname);
                } catch (error) {
                    console.error('Erreur lors de la récupération de l\'URL:', error);
                    document.getElementById('wt-url-display').textContent = 'URL invalide';
                    document.getElementById('wt-score-label').textContent = 'Erreur';
                    document.getElementById('wt-score-desc').textContent = 'Impossible d\'analyser cette page';
                }
            }
        });
    } else {
        // Fallback pour les tests locaux
        currentHostname = 'example.com';
        document.getElementById('wt-url-display').textContent = currentHostname;
        performAnalysis(currentHostname);
    }
}

// Initialiser au chargement
document.addEventListener('DOMContentLoaded', getCurrentURL);

// Gestionnaires de boutons
document.getElementById('wt-btn-check').addEventListener('click', function() {
    if (currentHostname) {
        performAnalysis(currentHostname);
    }
});

document.getElementById('wt-btn-report').addEventListener('click', function() {
    alert('Fonctionnalité de signalement à implémenter');
});