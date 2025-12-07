// Fonction pour récupérer un score aléatoire entre 0 et 5
function getRandomScore() {
    return (Math.random() * 5).toFixed(1);
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

// Fonction pour obtenir le label et la description en fonction du score
function getScoreInfo(score) {
    const numScore = parseFloat(score);
    
    if (numScore >= 4.5) {
        return {
            label: "Très fiable",
            desc: "Site sécurisé et digne de confiance",
            className: "wt-score-good",
            tags: ["✓ Domaine sécurisé", "✓ IP fiable", "✓ Certificat valide"]
        };
    } else if (numScore >= 3.5) {
        return {
            label: "Fiable",
            desc: "Site généralement sûr",
            className: "wt-score-good",
            tags: ["✓ Domaine sécurisé", "⚠ À vérifier"]
        };
    } else if (numScore >= 2.5) {
        return {
            label: "Attention requise",
            desc: "Certains éléments à vérifier",
            className: "wt-score-medium",
            tags: ["⚠ IP suspect", "⚠ Contenu non vérifié"]
        };
    } else if (numScore >= 1.5) {
        return {
            label: "Potentiellement risqué",
            desc: "Plusieurs risques détectés",
            className: "wt-score-bad",
            tags: ["⚠ Réputation faible", "✗ Scripts suspects"]
        };
    } else {
        return {
            label: "Très risqué",
            desc: "Site potentiellement malveillant",
            className: "wt-score-bad",
            tags: ["✗ Domaine malveillant", "✗ IP blacklistée", "✗ Scripts malveillants"]
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
function displayScore(score) {
    const scoreInfo = getScoreInfo(score);
    
    displayStars(score);
    
    const scoreValueEl = document.getElementById('wt-score-value');
    scoreValueEl.textContent = score + '/5';
    scoreValueEl.className = 'wt-score-value-text ' + scoreInfo.className;
    
    document.getElementById('wt-score-label').textContent = scoreInfo.label;
    document.getElementById('wt-score-desc').textContent = scoreInfo.desc;
    
    displayTags(scoreInfo.tags);
}

// Fonction pour récupérer l'URL de l'onglet actif
function getCurrentURL() {
    // Pour Manifest V2, utiliser chrome.tabs.query
    if (typeof chrome !== 'undefined' && chrome.tabs) {
        chrome.tabs.query({ active: true, currentWindow: true }, function(tabs) {
            if (tabs.length > 0) {
                const url = new URL(tabs[0].url);
                const hostname = url.hostname;
                document.getElementById('wt-url-display').textContent = hostname;
                
                // Simuler une analyse et afficher un score aléatoire
                setTimeout(() => {
                    const randomScore = getRandomScore();
                    displayScore(randomScore);
                }, 1000);
            }
        });
    } else {
        // Fallback pour les tests locaux
        document.getElementById('wt-url-display').textContent = 'example.com';
        setTimeout(() => {
            const randomScore = getRandomScore();
            displayScore(randomScore);
        }, 1000);
    }
}

// Initialiser au chargement
document.addEventListener('DOMContentLoaded', getCurrentURL);

// Gestionnaires de boutons
document.getElementById('wt-btn-check').addEventListener('click', function() {
    const randomScore = getRandomScore();
    displayScore(randomScore);
});

document.getElementById('wt-btn-report').addEventListener('click', function() {
    alert('Fonctionnalité de signalement à implémenter');
});