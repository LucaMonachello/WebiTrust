/**
 * Charge une liste de blocage depuis un fichier
 * @param {string} filename - Nom du fichier à charger
 * @returns {Promise<string[]>} Liste des domaines bloqués
 */
export async function loadBlocklist(filename) {
    try {
        const response = await fetch(`blocklist/${filename}`);
        const text = await response.text();
        
        const domains = text.split('\n')
        .map(line => line.trim())
        .filter(line => {
            if (!line || line.startsWith('#')) return false;
            return true;
        })
        .map(line => {
            if (line.startsWith('0.0.0.0 ')) return line.substring(8).trim();
            if (line.startsWith('127.0.0.1 ')) return line.substring(10).trim();
            if (line.includes(' ')) return null;
            return line.trim();
        })
        .filter(Boolean);
            
            return domains;
        } catch (error) {
            console.error(`Erreur lors du chargement de ${filename}:`, error);
            return [];
        }
    }

/**
 * Vérifie si un domaine est présent dans une liste
 * @param {string} domain - Domaine à vérifier
 * @param {string[]} list - Liste de domaines
 * @returns {boolean} True si le domaine est dans la liste
 */
export function isDomainInList(domain, list) {
    if (list.includes(domain)) {
        return true;
    }
    
    const parts = domain.split('.');
    for (let i = 1; i < parts.length; i++) {
        const parentDomain = parts.slice(i).join('.');
        if (list.includes(parentDomain)) {
            return true;
        }
    }
    
    for (const entry of list) {
        if (entry.startsWith('*.')) {
            const pattern = entry.substring(2);
            if (domain.endsWith(pattern) || domain === pattern) {
                return true;
            }
        }
    }
    
    return false;
}

/**
 * Récupère tous les fichiers de blocklist disponibles
 * @returns {Promise<string[]>} Liste des noms de fichiers
 */
export async function getAllBlocklistFiles() {
    return [
        'abuse-ags.txt',
        'abuse.txt',
        'adobe-ags.txt',
        'ads-ags.txt',
        'ads.txt',
        'basic-ags.txt',
        'crypto-ags.txt',
        'crypto.txt',
        'drugs-ags.txt',
        'drugs.txt',
        'everything-ags.txt',
        'facebook-ags.txt',
        'fortnite-ags.txt',
        'fraud-ags.txt',
        'fraud.txt',
        'gambling-ags.txt',
        'malware-ags.txt',
        'malware.txt',
        'phishing-ags.txt',
        'phishing.txt',
        'piracy-ags.txt',
        'porn-ags.txt',
        'porn.txt',
        'ransomware-ags.txt',
        'redirect-ags.txt',
        'scam-ags.txt',
        'scam.txt',
        'Signalement.txt',
        'smart-tv-ags.txt',
        'tiktok-ags.txt',
        'torrent-ags.txt',
        'tracking-ags.txt',
        'tracking.txt',
        'twitter-ags.txt',
        'vaping-ags.txt',
        'whatsapp-ags.txt',
        'youtube-ags.txt',
    ];
}
/**
 * Analyse un site en vérifiant toutes les blocklists
 * @param {string} hostname - Nom d'hôte à analyser
 * @returns {Promise<string[]>} Liste des correspondances trouvées
 */
export async function analyzeSite(hostname) {
    const matches = [];
    
    const files = await getAllBlocklistFiles();
    
    for (const file of files) {
        const list = await loadBlocklist(file);
        if (list.length > 0 && isDomainInList(hostname, list)) {
            const listName = file.replace('.txt', '').replace(/-/g, ' ').replace(/_/g, ' ');
            const displayName = listName.charAt(0).toUpperCase() + listName.slice(1);
            matches.push(`✗ Matched "${displayName}"`);
        }
    }
    
    return matches;
}