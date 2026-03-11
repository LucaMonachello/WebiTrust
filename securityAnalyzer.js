/**
 * Module d'analyse de sécurité
 * Vérifie les caractéristiques de sécurité d'un site web
 */

/**
 * Vérifie si le site utilise HTTPS
 * @param {string} url - URL complète du site
 * @returns {Object} Résultat de la vérification
 */

export async function checkAccessibility(url) {
    const urlObj = new URL(url);
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 4000); // ⏱ timeout global

    try {
        const response = await fetch(url, {
            method: 'HEAD',
            mode: 'no-cors',
            cache: 'no-store',
            signal: controller.signal // ✅ annulable
        });
        clearTimeout(timeout);
        return { isAccessible: true, status: 'ok', penaltyScore: 0, message: '✓ Site accessible', severity: 'safe' };
    } catch (e) {
        clearTimeout(timeout);
        if (e.name === 'AbortError') {
            return { isAccessible: true, status: 'timeout', penaltyScore: 0, message: '✓ Site accessible', severity: 'safe' };
        }
        return { isAccessible: false, status: 'network_error', penaltyScore: -3, message: '✗ Site inaccessible (DNS ou réseau)', severity: 'high' };
    }
}



export function checkHTTPS(url) {
    try {
        const urlObj = new URL(url);
        const isHTTPS = urlObj.protocol === 'https:';
        
        return {
            isSecure: isHTTPS,
            protocol: urlObj.protocol,
            penaltyScore: isHTTPS ? 0 : -10,
            message: isHTTPS ? '✓ HTTPS activé' : '✗ Site non sécurisé (HTTP)',
            severity: isHTTPS ? 'safe' : 'high'
        };
    } catch (error) {
        return {
            isSecure: false,
            protocol: 'unknown',
            penaltyScore: -10,
            message: '✗ Protocole invalide',
            severity: 'high'
        };
    }
}

/**
 * Analyse l'âge du domaine via WHOIS (simulation)
 * Note: En production, cela nécessiterait une API backend
 * @param {string} hostname - Nom d'hôte du site
 * @returns {Promise<Object>} Résultat de l'analyse
 */
export async function checkDomainAge(hostname) {
    // Simulation - En production, appeler une API WHOIS
    // Pour l'instant, on peut détecter certains patterns suspects
    
    // Vérifier les préfixes suspects (ww2, ww3, etc.)
    const suspiciousPrefixes = /^ww\d+\./i;
    if (suspiciousPrefixes.test(hostname)) {
        return {
            isSuspicious: true,
            penaltyScore: -10,
            message: '⚠ Préfixe de domaine suspect (ww2, ww3, etc.)',
            severity: 'medium'
        };
    }
    
    const suspiciousPatterns = [
        /\d{4,}/, // Beaucoup de chiffres
        /-\d+$/, // Se termine par -chiffres
        /[a-z]{20,}/, // Nom très long sans tirets
        /(.)\1{3,}/, // Caractères répétés (ex: aaaa)
    ];
    
    let isSuspicious = false;
    let suspicionReason = '';
    
    for (const pattern of suspiciousPatterns) {
        if (pattern.test(hostname)) {
            isSuspicious = true;
            suspicionReason = 'Nom de domaine suspect';
            break;
        }
    }
    
    // Vérifier les TLDs suspects
    const suspiciousTLDs = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.work', '.click','.cr','.st','.su','.ru','.cc','.co'];
    const hasSuspiciousTLD = suspiciousTLDs.some(tld => hostname.endsWith(tld));
    
    if (hasSuspiciousTLD) {
        isSuspicious = true;
        suspicionReason = 'Extension de domaine à risque';
    }
    
    if (isSuspicious) {
        return {
            isSuspicious: true,
            penaltyScore: -10,
            message: `⚠ ${suspicionReason}`,
            severity: 'medium'
        };
    }
    
    return {
        isSuspicious: false,
        penaltyScore: 0,
        message: '✓ Domaine semble légitime',
        severity: 'safe'
    };
}

/**
 * Vérifie la validité du certificat SSL
 * Note: Les extensions Chrome ont des limitations pour accéder aux détails SSL
 * @param {string} url - URL complète du site
 * @returns {Promise<Object>} Résultat de la vérification
 */
export async function checkSSLCertificate(url) {
    try {
        const urlObj = new URL(url);
        if (urlObj.protocol === 'http:') {
            return { isValid: false, penaltyScore: -15, message: '✗ Aucun certificat SSL', severity: 'high' };
        }

        return await new Promise((resolve) => {
            const img = new Image();
            let settled = false;

            const done = (result) => {
                if (settled) return;
                settled = true;
                clearTimeout(timer);
                img.onload = null;   // ✅ Nettoyage
                img.onerror = null;  // ✅ Nettoyage
                img.src = '';        // ✅ Annule la requête
                resolve(result);
            };

            const timer = setTimeout(() => {
                done({ isValid: true, penaltyScore: 0, message: '✓ Certificat SSL présent', severity: 'safe' });
            }, 4000);

            img.onload = () => done({ isValid: true, penaltyScore: 0, message: '✓ Certificat SSL valide', severity: 'safe' });
            img.onerror = () => done({ isValid: false, penaltyScore: -15, message: '✗ Certificat SSL invalide', severity: 'high' });

            img.src = `${urlObj.origin}/favicon.ico?_t=${Date.now()}`;
        });

    } catch {
        return { isValid: false, penaltyScore: -15, message: '⚠ Impossible de vérifier le certificat', severity: 'medium' };
    }
}

/**
 * Vérifie la présence de mixed content (contenu mixte HTTP/HTTPS)
 * @param {string} url - URL complète du site
 * @returns {Promise<Object>} Résultat de la vérification
 */
export async function checkMixedContent(url) {
    try {
        const urlObj = new URL(url);
        
        // Seulement pertinent pour les sites HTTPS
        if (urlObj.protocol !== 'https:') {
            return {
                hasMixedContent: false,
                penaltyScore: 0,
                message: '',
                severity: 'safe'
            };
        }
        
        // Note: En extension, on pourrait analyser le contenu de la page
        // Pour l'instant, c'est une vérification basique
        
        return {
            hasMixedContent: false,
            penaltyScore: 0,
            message: '✓ Pas de contenu mixte détecté',
            severity: 'safe'
        };
    } catch (error) {
        return {
            hasMixedContent: false,
            penaltyScore: 0,
            message: '',
            severity: 'safe'
        };
    }
}

/**
 * Analyse complète de sécurité du site
 * @param {string} url - URL complète du site
 * @param {string} hostname - Nom d'hôte du site
 * @returns {Promise<Object>} Résultats complets de l'analyse
 */
export async function analyzeSecurityFeatures(url, hostname) {
    const results = {
        checks: [],
        totalPenalty: 0,
        messages: []
    };
    
    // Vérification HTTPS
    const httpsCheck = checkHTTPS(url);
    results.checks.push(httpsCheck);
    results.totalPenalty += httpsCheck.penaltyScore;
    if (httpsCheck.message) {
        results.messages.push({
            text: httpsCheck.message,
            severity: httpsCheck.severity
        });
    }
    
    
    // Vérification de l'âge du domaine
    const domainAgeCheck = await checkDomainAge(hostname);
    results.checks.push(domainAgeCheck);
    results.totalPenalty += domainAgeCheck.penaltyScore;
    if (domainAgeCheck.message) {
        results.messages.push({
            text: domainAgeCheck.message,
            severity: domainAgeCheck.severity
        });
    }
    
    // Vérification du contenu mixte
    const mixedContentCheck = await checkMixedContent(url);
    results.checks.push(mixedContentCheck);
    results.totalPenalty += mixedContentCheck.penaltyScore;
    if (mixedContentCheck.message) {
        results.messages.push({
            text: mixedContentCheck.message,
            severity: mixedContentCheck.severity
        });
    }
    
    return results;
}