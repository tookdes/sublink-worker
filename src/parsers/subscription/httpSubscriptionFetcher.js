import { decodeBase64 } from '../../utils.js';
import { parseSubscriptionContent } from './subscriptionContentParser.js';

const SUBSCRIPTION_URI_PATTERN = /^(ss|vmess|vless|hysteria|hysteria2|hy2|trojan|tuic|anytls|http|https):\/\//i;

function hasSubscriptionUriLine(content) {
    return content
        .split(/\r?\n/)
        .map(line => line.trim())
        .filter(Boolean)
        .some(line => SUBSCRIPTION_URI_PATTERN.test(line));
}

function isLikelyTomlConfig(content) {
    return /^\s*\[[^\]]+\]\s*$/m.test(content) && /^\s*[A-Za-z0-9_.-]+\s*=/.test(content);
}

function isPlainSubscriptionContent(content) {
    if (!content || typeof content !== 'string') {
        return false;
    }
    return detectFormat(content) !== 'unknown' ||
        hasSubscriptionUriLine(content) ||
        isLikelyTomlConfig(content);
}

function decodeUriComponentIfNeeded(text) {
    const trimmed = text.trim();
    if (!trimmed.includes('%')) {
        return trimmed;
    }

    try {
        return decodeURIComponent(trimmed).trim();
    } catch (urlError) {
        console.warn('Failed to URL decode the text:', urlError);
        return trimmed;
    }
}

function normalizeBase64Candidate(text) {
    const compact = text.replace(/\s+/g, '');
    if (!compact || !/^[A-Za-z0-9+/_-]*={0,2}$/.test(compact)) {
        return null;
    }
    if (/=/.test(compact.replace(/={0,2}$/, ''))) {
        return null;
    }

    const withoutPadding = compact.replace(/=+$/, '');
    if (withoutPadding.length % 4 === 1) {
        return null;
    }

    const normalized = withoutPadding.replace(/-/g, '+').replace(/_/g, '/');
    return normalized + '='.repeat((4 - normalized.length % 4) % 4);
}

/**
 * Decode content only when the payload proves it is an encoded subscription.
 * @param {string} text - Raw text content
 * @returns {string} - Decoded content
 */
function decodeContent(text) {
    const urlDecodedText = decodeUriComponentIfNeeded(text);
    if (isPlainSubscriptionContent(urlDecodedText)) {
        return urlDecodedText;
    }

    const base64Candidate = normalizeBase64Candidate(urlDecodedText);
    if (!base64Candidate) {
        return urlDecodedText;
    }

    try {
        const decodedText = decodeUriComponentIfNeeded(decodeBase64(base64Candidate));
        if (isPlainSubscriptionContent(decodedText)) {
            return decodedText;
        }
    } catch (e) {
        return urlDecodedText;
    }

    return urlDecodedText;
}

/**
 * Detect the format of subscription content
 * @param {string} content - Decoded subscription content
 * @returns {'clash'|'singbox'|'surge'|'unknown'} - Detected format
 */
function detectFormat(content) {
    const trimmed = content.trim();

    // Try JSON (Sing-Box format)
    if (trimmed.startsWith('{')) {
        try {
            const parsed = JSON.parse(trimmed);
            if (parsed.outbounds || parsed.inbounds || parsed.route) {
                return 'singbox';
            }
        } catch {
            // Not valid JSON
        }
    }

    // Try YAML (Clash format) - check for proxies: key
    if (trimmed.includes('proxies:')) {
        return 'clash';
    }

    if (/\[(General|Proxy|Rule|Proxy Group)\]/i.test(trimmed)) {
        return 'surge';
    }

    return 'unknown';
}

const MAX_SUBSCRIPTION_BYTES = 4 * 1024 * 1024;
const FETCH_TIMEOUT_MS = 10000;
const MAX_REDIRECTS = 5;

function isPrivateOrReservedHost(hostname) {
    const host = String(hostname || '').toLowerCase().replace(/^\[|\]$/g, '');
    if (!host) return true;
    if (host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.local')) return true;
    if (host === '::1' || host === '::' || /^f[cd][0-9a-f:]*$/i.test(host) || /^fe[89ab][0-9a-f:]*$/i.test(host)) return true;

    const match = host.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
    if (!match) return false;
    const octets = match.slice(1).map(Number);
    if (octets.some(v => v > 255)) return true;
    const [a, b] = octets;
    return a === 0 || a === 10 || a === 127 ||
        (a === 100 && b >= 64 && b <= 127) ||
        (a === 169 && b === 254) ||
        (a === 172 && b >= 16 && b <= 31) ||
        (a === 192 && b === 0) ||
        (a === 192 && b === 168) ||
        (a === 198 && (b === 18 || b === 19)) ||
        a >= 224;
}

export function validateSubscriptionUrl(rawUrl) {
    let parsed;
    try {
        parsed = new URL(rawUrl);
    } catch {
        throw new Error('Invalid subscription URL');
    }
    if (!['http:', 'https:'].includes(parsed.protocol)) {
        throw new Error('Unsupported subscription URL scheme');
    }
    if (isPrivateOrReservedHost(parsed.hostname)) {
        throw new Error('Private or reserved subscription hosts are not allowed');
    }
    return parsed;
}

async function fetchBoundedResponse(rawUrl, headers) {
    let currentUrl = validateSubscriptionUrl(rawUrl);
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
    try {
        for (let redirectCount = 0; redirectCount <= MAX_REDIRECTS; redirectCount++) {
            const response = await fetch(currentUrl.toString(), {
                method: 'GET',
                headers,
                redirect: 'manual',
                signal: controller.signal
            });

            if ([301, 302, 303, 307, 308].includes(response.status)) {
                if (redirectCount === MAX_REDIRECTS) throw new Error('Too many subscription redirects');
                const location = response.headers.get('location');
                if (!location) throw new Error('Subscription redirect missing Location header');
                currentUrl = validateSubscriptionUrl(new URL(location, currentUrl).toString());
                continue;
            }

            if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
            const declaredSize = Number(response.headers.get('content-length') || 0);
            if (declaredSize > MAX_SUBSCRIPTION_BYTES) throw new Error('Subscription response is too large');

            let text;
            if (typeof response.arrayBuffer === 'function') {
                const buffer = await response.arrayBuffer();
                if (buffer.byteLength > MAX_SUBSCRIPTION_BYTES) throw new Error('Subscription response is too large');
                text = new TextDecoder().decode(buffer);
            } else {
                text = await response.text();
                if (new TextEncoder().encode(text).byteLength > MAX_SUBSCRIPTION_BYTES) {
                    throw new Error('Subscription response is too large');
                }
            }
            return { text, headers: response.headers, url: currentUrl.toString() };
        }
        throw new Error('Unable to fetch subscription');
    } finally {
        clearTimeout(timeout);
    }
}

export async function fetchSubscriptionText(url, userAgent) {
    const headers = new Headers();
    if (userAgent) headers.set('User-Agent', userAgent);
    return fetchBoundedResponse(url, headers);
}

/**
 * Fetch subscription content from a URL and parse it.
 */
export async function fetchSubscription(url, userAgent) {
    try {
        const result = await fetchSubscriptionText(url, userAgent);
        return parseSubscriptionContent(decodeContent(result.text));
    } catch (error) {
        console.error('Error fetching or parsing HTTP(S) content:', error);
        return null;
    }
}

/**
 * Fetch subscription content and detect its format without parsing.
 */
export async function fetchSubscriptionWithFormat(url, userAgent) {
    try {
        const result = await fetchSubscriptionText(url, userAgent);
        const content = decodeContent(result.text);
        const format = detectFormat(content);
        const subscriptionUserinfo = result.headers.get('subscription-userinfo') || undefined;
        return { content, format, url: result.url, subscriptionUserinfo };
    } catch (error) {
        console.error('Error fetching subscription:', error);
        return null;
    }
}
