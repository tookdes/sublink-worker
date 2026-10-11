import { generateWebPath } from '../utils.js';
import { MissingDependencyError, ConflictError } from './errors.js';

export class ShortLinkService {
    constructor(kv, options = {}) {
        this.kv = kv;
        this.options = options;
    }

    ensureKv() {
        if (!this.kv) {
            throw new MissingDependencyError('Short link service requires a KV store');
        }
        return this.kv;
    }

    async createShortLink(queryString, providedCode) {
        const kv = this.ensureKv();
        const ttl = this.options.shortLinkTtlSeconds;
        const putOptions = ttl ? { expirationTtl: ttl } : undefined;

        if (providedCode) {
            const existing = await kv.get(providedCode);
            if (existing !== null && existing !== queryString) {
                throw new ConflictError('Short code already exists');
            }
            if (existing === queryString) return providedCode;
            await kv.put(providedCode, queryString, putOptions);
            return providedCode;
        }

        for (let attempt = 0; attempt < 8; attempt++) {
            const shortCode = generateWebPath();
            if (await kv.get(shortCode) !== null) continue;
            await kv.put(shortCode, queryString, putOptions);
            return shortCode;
        }
        throw new Error('Unable to allocate a unique short code');
    }

    async resolveShortCode(code) {
        const kv = this.ensureKv();
        return kv.get(code);
    }
}
