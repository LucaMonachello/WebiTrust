import { getScoreInfo } from './scoreCalculator.js'

export function updateScoreRing(score) {

    const ring = document.querySelector('.wt-score-ring')
    const valueEl = document.getElementById('wt-score-value')

    if (!ring || !valueEl) return

    valueEl.textContent = score

    let color = "#ef4444"

    if (score >= 50) color = "#f59e0b"
    if (score >= 80) color = "#22c55e"

    ring.style.background =
    `conic-gradient(from 220deg, ${color} ${score}%, #1e293b ${score}%)`
}

export function displayTags(tags) {

    const container = document.getElementById('wt-tags-container')
    container.innerHTML = ''

    tags.forEach(tag => {

        const tagEl = document.createElement('span')
        tagEl.className = 'wt-tag'

        if (tag.includes('✓'))
            tagEl.classList.add('wt-tag-safe')

        else if (tag.includes('✗'))
            tagEl.classList.add('wt-tag-risk')

        else
            tagEl.classList.add('wt-tag-warning')

        tagEl.textContent = tag
        container.appendChild(tagEl)

    })
}


export function displayScore(score, matches, securityMessages = []) {

    const problematicMessages =
    securityMessages.filter(msg => msg.text && !msg.text.includes('✓'))

    const scoreInfo =
    getScoreInfo(score, matches, problematicMessages)

    updateScoreRing(score)

    document.getElementById('wt-score-label').textContent = scoreInfo.label
    document.getElementById('wt-score-desc').textContent = scoreInfo.desc

    displayTags(scoreInfo.tags)

    displayMessages(securityMessages)
}


function displayMessages(messages){ 
    const container = document.getElementById("wt-messages");
    if(!container) return;

    container.innerHTML = "";

    messages.forEach(msg => {
        if (!msg.text.includes("déjà été signalé")) return;

        const div = document.createElement("div");
        div.className = `wt-message wt-${msg.severity}`;

        const btn = document.createElement("button");
        btn.textContent = "Retirer";
        btn.className = "wt-remove-report";

        btn.addEventListener("click", () => {
            window.dispatchEvent(
                new CustomEvent("removeReportRequest")
            );
        });

        div.appendChild(btn);
        container.appendChild(div);
    });
}

export function displayURL(hostname) {

    document.getElementById('wt-current-url').textContent = hostname

}

export function showLoadingState(){

    document.getElementById('wt-score-label').textContent = 'Analyse...'

}

export function showErrorState(message){

    document.getElementById('wt-score-label').textContent = 'Erreur'

    document.getElementById('wt-score-desc').textContent = message

}