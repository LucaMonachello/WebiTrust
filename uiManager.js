import { getScoreInfo } from './scoreCalculator.js';

/**
 * Anime l'anneau de score
 */
export function updateScoreRing(score) {
    const ring = document.querySelector('.wt-score-ring');
    const valueEl = document.getElementById('wt-score-value');
    
    if (!ring || !valueEl) return;

    // Mise à jour du texte
    valueEl.textContent = score;

    // Détermination de la couleur principale en fonction du score
    let color = "#ef4444"; // Rouge
    if (score >= 50) color = "#f59e0b"; // Orange
    if (score >= 80) color = "#22c55e"; // Vert

    // On met à jour le dégradé conique pour remplir l'anneau
    // from 220deg pour correspondre à ton style CSS
    ring.style.background = `conic-gradient(from 220deg, ${color} ${score}%, #1e293b ${score}%)`;
}

export function displayTags(tags) {
    const container = document.getElementById('wt-tags-container');
    container.innerHTML = '';
    tags.forEach(tag => {
        const tagEl = document.createElement('span');
        tagEl.className = 'wt-tag';
        if (tag.includes('✓')) tagEl.classList.add('wt-tag-safe');
        else if (tag.includes('✗')) tagEl.classList.add('wt-tag-risk');
        else tagEl.classList.add('wt-tag-warning');
        tagEl.textContent = tag;
        container.appendChild(tagEl);
    });
}

export function displayScore(score, matches, securityMessages = []) {
    const problematicMessages = securityMessages.filter(msg => msg.text && !msg.text.includes('✓'));
    const scoreInfo = getScoreInfo(score, matches, problematicMessages);
    
    updateScoreRing(score);
    
    document.getElementById('wt-score-label').textContent = scoreInfo.label;
    document.getElementById('wt-score-desc').textContent = scoreInfo.desc;
    displayTags(scoreInfo.tags);
}

export function displayURL(hostname) {
    document.getElementById('wt-current-url').textContent = hostname;
}

export function showLoadingState() {
    document.getElementById('wt-score-label').textContent = 'Analyse...';
    document.getElementById('wt-loading').classList.remove('hidden');
}

export function showErrorState(message) {
    document.getElementById('wt-score-label').textContent = 'Erreur';
    document.getElementById('wt-score-desc').textContent = message;
    document.getElementById('wt-loading').classList.add('hidden');
}