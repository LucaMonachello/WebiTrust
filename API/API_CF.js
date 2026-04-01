const CF_API_TOKEN = "stTBE7TzitSNZ9QAciyNOhzVq5sXQFGp_7HLb0da";
const ACCOUNT_ID   = "17ecf198b86d88bf24c61bb4ca53f27c";
const BASE_URL     = `https://api.cloudflare.com/client/v4/accounts/${ACCOUNT_ID}/urlscanner/v2`;

async function findExistingScan(url) {
    const encoded = encodeURIComponent(url);
    const res = await fetch(`${BASE_URL}/search?q=url%3A"${encoded}"&limit=1`, {
        headers: { Authorization: `Bearer ${CF_API_TOKEN}` }
    });
    if (!res.ok) return null;
    const data = await res.json();
    const result = data.result?.tasks?.[0];
    if (!result) return null;

    const scanTime = new Date(result.time).getTime();
    const age = Date.now() - scanTime;
    if (age > 24 * 60 * 60 * 1000) return null;

    return result.uuid;
}

async function createScan(url) {
    const res = await fetch(`${BASE_URL}/scan`, {
        method: "POST",
        headers: {
            Authorization: `Bearer ${CF_API_TOKEN}`,
            "Content-Type": "application/json",
        },
        body: JSON.stringify({ url }),
    });
    const text = await res.text();
    if (!res.ok) throw new Error(`Erreur création scan: ${res.status} - ${text}`);
    const data = JSON.parse(text);
    if (!data.uuid) throw new Error("UUID manquant dans la réponse");
    return data.uuid;
}

async function getScanResult(scanId) {
    const MAX_ATTEMPTS = 10;
    let attempts = 0;

    while (attempts < MAX_ATTEMPTS) {
        const res = await fetch(`${BASE_URL}/result/${scanId}`, {
            headers: { Authorization: `Bearer ${CF_API_TOKEN}` }
        });

        if (res.status === 404 || !res.ok) {
            await new Promise(r => setTimeout(r, 3000));
            attempts++;
            continue;
        }

        const data = await res.json();
        const status = data.task?.status?.toLowerCase();

        if (status === "finished") return data;

        await new Promise(r => setTimeout(r, 3000));
        attempts++;
    }

    throw new Error("Timeout Cloudflare : scan trop long");
}

function mapVerdicts(data) {
    const overall = data.verdicts?.overall || {};
    const categories = overall.categories || [];
    const tags = overall.tags || [];

    const allLabels = [
        ...categories.map(c => (typeof c === "string" ? c : c.name || "")),
        ...tags.map(t => (typeof t === "string" ? t : t.name || "")),
    ].map(x => x.toLowerCase());

    const malicious = overall.malicious === true;

    return {
        malicious,
        phishing:          malicious && allLabels.some(l => l.includes("phish")),
        malware:           malicious && allLabels.some(l => l.includes("malware") || l.includes("virus") || l.includes("trojan")),
        spam:              malicious && allLabels.some(l => l.includes("spam") || l.includes("bulk")),
        crypto_mining:     malicious && allLabels.some(l => l.includes("crypto") || l.includes("mining")),
        command_and_control: malicious && allLabels.some(l => l.includes("c2") || l.includes("command and control") || l.includes("botnet")),
    };
}

export async function scanCloudflareRadar(url) {
    let scanId = await findExistingScan(url);
    if (!scanId) {
        scanId = await createScan(url);
    }

    const raw = await getScanResult(scanId);
    const verdicts = mapVerdicts(raw);
    const hasIssue = Object.values(verdicts).some(Boolean);

    return {
        isSecure: !hasIssue,
        protocol: new URL(url).protocol.replace(":", ""),
        penaltyScore: hasIssue ? -30 : 0,
        message: hasIssue
            ? "✗ URL détectée comme risquée par Cloudflare Radar"
            : "✓ Aucun signal de menace détecté par Cloudflare Radar",
        severity: hasIssue ? "high" : "safe",
        details: verdicts,
    };
}

export { createScan, getScanResult, mapVerdicts };