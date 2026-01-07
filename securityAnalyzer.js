/**
 * Module d'analyse de sécurité
 * Vérifie les caractéristiques de sécurité d'un site web
 */

/**
 * Vérifie si le site utilise HTTPS
 * @param {string} url - URL complète du site
 * @returns {Object} Résultat de la vérification
 */
export function checkHTTPS(url) {
    try {
        const urlObj = new URL(url);
        const isHTTPS = urlObj.protocol === 'https:';
        
        return {
            isSecure: isHTTPS,
            protocol: urlObj.protocol,
            penaltyScore: isHTTPS ? 0 : -1,
            message: isHTTPS ? '✓ HTTPS activé' : '✗ Site non sécurisé (HTTP)',
            severity: isHTTPS ? 'safe' : 'high'
        };
    } catch (error) {
        return {
            isSecure: false,
            protocol: 'unknown',
            penaltyScore: -1,
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
    const suspiciousTLDs = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.work', '.click'];
    const hasSuspiciousTLD = suspiciousTLDs.some(tld => hostname.endsWith(tld));
    
    if (hasSuspiciousTLD) {
        isSuspicious = true;
        suspicionReason = 'Extension de domaine à risque';
    }
    
    if (isSuspicious) {
        return {
            isSuspicious: true,
            penaltyScore: -1.0,
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
        
        // Si c'est HTTP, pas de certificat
        if (urlObj.protocol === 'http:') {
            return {
                isValid: false,
                penaltyScore: -1,
                message: '✗ Aucun certificat SSL',
                severity: 'high'
            };
        }
        
        // Pour HTTPS, on peut vérifier si la connexion fonctionne
        // Une tentative de fetch va échouer si le certificat est invalide
        try {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 3000);
            
            await fetch(url, {
                method: 'HEAD',
                mode: 'no-cors', // Éviter les erreurs CORS
                signal: controller.signal
            });
            
            clearTimeout(timeoutId);
            
            return {
                isValid: true,
                penaltyScore: 0,
                message: '✓ Certificat SSL valide',
                severity: 'safe'
            };
        } catch (error) {
            // Si c'est une erreur de certificat, le navigateur bloque
            if (error.name === 'TypeError' || error.message.includes('certificate')) {
                return {
                    isValid: false,
                    penaltyScore: -2.0,
                    message: '✗ Certificat SSL invalide ou expiré',
                    severity: 'critical'
                };
            }
            
            // Timeout ou autre erreur - on considère comme OK
            return {
                isValid: true,
                penaltyScore: 0,
                message: '✓ Certificat SSL présent',
                severity: 'safe'
            };
        }
    } catch (error) {
        return {
            isValid: false,
            penaltyScore: -1.0,
            message: '⚠ Impossible de vérifier le certificat',
            severity: 'medium'
        };
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
    
    // Vérification du certificat SSL (seulement si HTTPS)
    if (httpsCheck.isSecure) {
        const sslCheck = await checkSSLCertificate(url);
        results.checks.push(sslCheck);
        results.totalPenalty += sslCheck.penaltyScore;
        if (sslCheck.message) {
            results.messages.push({
                text: sslCheck.message,
                severity: sslCheck.severity
            });
        }
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