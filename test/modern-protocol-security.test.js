import { describe, expect, it } from 'vitest';
import { parseVless } from '../src/parsers/protocols/vlessParser.js';
import { parseTuic } from '../src/parsers/protocols/tuicParser.js';
import { parseHysteria2 } from '../src/parsers/protocols/hysteria2Parser.js';
import { ClashConfigBuilder } from '../src/builders/ClashConfigBuilder.js';
import { SingboxConfigBuilder } from '../src/builders/SingboxConfigBuilder.js';
import { validateSubscriptionUrl } from '../src/parsers/subscription/httpSubscriptionFetcher.js';

describe('modern protocol and security compatibility', () => {
    it('preserves VLESS ML-KEM, XHTTP, ALPN and packet encoding', () => {
        const proxy = parseVless('vless://00000000-0000-4000-8000-000000000001@example.com:443?encryption=mlkem768x25519plus.native.0rtt.test&security=reality&sni=example.com&fp=firefox&pbk=pk&sid=sid&type=xhttp&path=test-xh&mode=auto&alpn=h2,h3&packet_encoding=xudp#pq');
        expect(proxy.encryption).toContain('mlkem768x25519plus');
        expect(proxy.transport).toMatchObject({ type: 'xhttp', path: '/test-xh', mode: 'auto' });
        expect(proxy.tls.utls.fingerprint).toBe('firefox');
        expect(proxy.alpn).toEqual(['h2', 'h3']);
        expect(proxy.packet_encoding).toBe('xudp');

        const clash = ClashConfigBuilder.prototype.convertProxy.call({}, proxy);
        expect(clash.encryption).toBe(proxy.encryption);
        expect(clash['xhttp-opts']).toMatchObject({ path: '/test-xh', mode: 'auto' });
        expect(clash['skip-cert-verify']).toBe(false);
    });

    it('parses insecure=0 as secure for VLESS, TUIC and Hysteria2', () => {
        const vless = parseVless('vless://u@example.com:443?security=tls&sni=example.com&insecure=0&type=tcp#v');
        const tuic = parseTuic('tuic://u%3Ap@example.com:443?sni=example.com&insecure=0#t');
        const hy2 = parseHysteria2('hysteria2://p@example.com:443?sni=example.com&insecure=0#h');
        expect(vless.tls.insecure).toBe(false);
        expect(tuic.tls.insecure).toBe(false);
        expect(hy2.tls.insecure).toBe(false);
    });

    it('round-trips Hysteria2 certificate pin to Clash and sing-box', () => {
        const pin = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
        const proxy = parseHysteria2(`hysteria2://p@example.com:443?sni=example.com&pinSHA256=${pin}#h`);
        expect(proxy.tls.pinSHA256).toBe(pin);
        const clash = ClashConfigBuilder.prototype.convertProxy.call({}, proxy);
        expect(clash.fingerprint).toBe(pin);
        const singbox = SingboxConfigBuilder.prototype.convertProxy.call({}, proxy);
        expect(singbox.tls.certificate_hash[0]).toContain(':');
        expect(singbox.tls).not.toHaveProperty('pinSHA256');
    });

    it('blocks explicit private and loopback subscription targets', () => {
        expect(() => validateSubscriptionUrl('http://127.0.0.1/sub')).toThrow();
        expect(() => validateSubscriptionUrl('http://169.254.169.254/latest/meta-data')).toThrow();
        expect(() => validateSubscriptionUrl('http://[::1]/sub')).toThrow();
        expect(() => validateSubscriptionUrl('https://example.com/sub')).not.toThrow();
    });
});
