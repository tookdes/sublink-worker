import { parseServerInfo, parseUrlParams, createTlsConfig, createTransportConfig, parseBool } from '../../utils.js';

export function parseVless(url) {
    const { addressPart, params, name } = parseUrlParams(url);
    const [uuid, serverInfo] = addressPart.split('@');
    const { host, port } = parseServerInfo(serverInfo);

    const tls = createTlsConfig(params);
    if (tls.enabled) {
        const fingerprint = params.fp || params.fingerprint || (tls.reality ? 'chrome' : undefined);
        if (fingerprint) {
            tls.utls = {
                enabled: true,
                fingerprint
            };
        }
    }
    const transport = params.type && params.type !== 'tcp' ? createTransportConfig(params) : undefined;

    // `udp` is a Clash-only flag; ClashConfigBuilder reads it, SingboxConfigBuilder strips it.
    const udp = params.udp !== undefined ? parseBool(params.udp) : undefined;
    const encryption = params.encryption && params.encryption !== 'none' ? params.encryption : undefined;
    const alpn = params.alpn ? params.alpn.split(',').map(item => item.trim()).filter(Boolean) : undefined;
    const packetEncoding = params.packet_encoding || params['packet-encoding'];

    return {
        type: 'vless',
        tag: name,
        server: host,
        server_port: port,
        uuid: decodeURIComponent(uuid),
        tcp_fast_open: false,
        tls,
        transport,
        flow: params.flow ?? undefined,
        ...(encryption ? { encryption } : {}),
        ...(alpn ? { alpn } : {}),
        ...(packetEncoding ? { packet_encoding: packetEncoding } : {}),
        ...(udp !== undefined ? { udp } : {})
    };
}
