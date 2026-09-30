import { frameBytes, sendableCloseCode, WebSocketFrames } from './frames';

const VERSION = 0;
// Protocol version, then addons length 0.
const RESPONSE_HEADER = new Uint8Array([VERSION, 0]);

const COMMAND_TCP = 0x01;
const COMMAND_UDP = 0x02;

const DNS_PORT = 53;
// VLESS frames UDP packets with a 2-byte big-endian length, exactly as DNS over
// TCP frames messages, so UDP/53 can be bridged verbatim to a TCP resolver.
const DNS_OVER_TCP_HOST = '8.8.8.8';

const ADDRESS_IPV4 = 0x01;
const ADDRESS_DOMAIN = 0x02;
const ADDRESS_IPV6 = 0x03;

// A header is at most 1 + 16 + 1 + 1 + 2 + 1 + 1 + 255 bytes: version, UUID,
// addons length, command, port, address type, domain length, domain. Anything
// past this is a client that will never finish the header.
const MAX_HEADER = 2048;

// Xray's own handshake timeout.
const HANDSHAKE_TIMEOUT = 60_000;

type Header = { status: 'incomplete' } | { status: 'invalid' } | { status: 'ok'; destination: string; consumed: number };

/**
 * Parse a VLESS request header off the front of the byte stream into a
 * `host:port` destination. The UUID is read but not checked: any credential is
 * accepted.
 */
function parseHeader(buf: Uint8Array): Header {
	let offset = 0;
	// `subarray` on a short buffer silently yields fewer bytes than asked for.
	const take = (n: number): Uint8Array | null => {
		if (buf.length - offset < n) return null;
		const slice = buf.subarray(offset, offset + n);
		offset += n;
		return slice;
	};

	const version = take(1);
	if (version === null) return { status: 'incomplete' };
	if (version[0] !== VERSION) return { status: 'invalid' };

	if (take(16) === null) return { status: 'incomplete' };

	const addonsLength = take(1);
	if (addonsLength === null) return { status: 'incomplete' };
	if (take(addonsLength[0]) === null) return { status: 'incomplete' };
	// Only `xtls-rprx-vision` writes addons, and it needs a raw TLS stream.
	if (addonsLength[0] !== 0) return { status: 'invalid' };

	const command = take(1);
	if (command === null) return { status: 'incomplete' };
	// The bastion only dials TCP, so the only UDP carried is DNS, over TCP.
	if (command[0] !== COMMAND_TCP && command[0] !== COMMAND_UDP) return { status: 'invalid' };

	const portBytes = take(2);
	if (portBytes === null) return { status: 'incomplete' };
	const port = (portBytes[0] << 8) | portBytes[1];
	const udp = command[0] === COMMAND_UDP;
	if (udp && port !== DNS_PORT) return { status: 'invalid' };

	const addressType = take(1);
	if (addressType === null) return { status: 'incomplete' };

	let host: string;
	switch (addressType[0]) {
		case ADDRESS_IPV4: {
			const bytes = take(4);
			if (bytes === null) return { status: 'incomplete' };
			host = bytes.join('.');
			break;
		}
		case ADDRESS_IPV6: {
			const bytes = take(16);
			if (bytes === null) return { status: 'incomplete' };
			const groups: string[] = [];
			for (let i = 0; i < 16; i += 2) {
				groups.push(((bytes[i] << 8) | bytes[i + 1]).toString(16));
			}
			host = `[${groups.join(':')}]`;
			break;
		}
		case ADDRESS_DOMAIN: {
			const length = take(1);
			if (length === null) return { status: 'incomplete' };
			const domain = take(length[0]);
			if (domain === null) return { status: 'incomplete' };
			host = new TextDecoder().decode(domain);
			break;
		}
		default:
			return { status: 'invalid' };
	}

	// Whatever resolver the client asked for, DNS goes to one that accepts TCP.
	if (udp) host = DNS_OVER_TCP_HOST;

	return { status: 'ok', destination: `${host}:${port}`, consumed: offset };
}

/**
 * Xray clients configured with `ed` send the first bytes of the VLESS stream in
 * the `Sec-WebSocket-Protocol` header, base64url-encoded and unpadded, and
 * expect the header echoed back.
 */
function decodeEarlyData(header: string | null): Uint8Array | null {
	if (!header) return null;
	try {
		const base64 = header.replace(/[-_]/g, (c) => (c === '-' ? '+' : '/'));
		const bytes = Uint8Array.from(atob(base64), (c) => c.charCodeAt(0));
		return bytes.length > 0 ? bytes : null;
	} catch {
		// Not early data: a client using the header for something else.
		return null;
	}
}

function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
	if (a.length === 0) return b;
	const merged = new Uint8Array(a.length + b.length);
	merged.set(a);
	merged.set(b, a.length);
	return merged;
}

function nextFrame(frames: WebSocketFrames, timeout: number): Promise<Uint8Array | null> {
	let timer: ReturnType<typeof setTimeout> | undefined;
	const deadline = new Promise<null>((resolve) => {
		timer = setTimeout(() => resolve(null), timeout);
	});
	return Promise.race([frames.next(), deadline]).finally(() => clearTimeout(timer));
}

/**
 * Open a WebSocket to a cloudflared bastion, which dials `destination` over TCP
 * and then carries raw bytes in binary frames. The bastion only acknowledges
 * the upgrade after its dial succeeds, so a missing WebSocket means the
 * destination was unreachable or the hostname is behind Access.
 */
async function openBastion(bastion: string, destination: string): Promise<WebSocket | null> {
	const response = await fetch(bastion, {
		headers: { Upgrade: 'websocket', 'Cf-Access-Jump-Destination': destination },
		// Access answers an unauthenticated upgrade with a 302 to its login page.
		redirect: 'manual',
	});
	const socket = response.webSocket;
	if (socket === null) {
		console.warn(`bastion ${bastion} refused ${destination}: ${response.status}`);
		return null;
	}
	socket.binaryType = 'arraybuffer';
	socket.accept({ allowHalfOpen: true });
	return socket;
}

/**
 * Pump frames both ways. Both sides are half-open, so a Close from either peer
 * is forwarded and the other direction keeps flowing until that side's Close
 * comes back.
 */
function bridge(client: WebSocketFrames, bastion: WebSocket): void {
	bastion.addEventListener('message', (event) => client.socket.send(frameBytes(event.data)));
	bastion.addEventListener('close', (event) => client.socket.close(sendableCloseCode(event.code)));
	bastion.addEventListener('error', () => client.socket.close(1011));

	void (async () => {
		for (;;) {
			const frame = await client.next();
			if (frame === null) break;
			bastion.send(frame);
		}
		bastion.close(sendableCloseCode(client.closeCode));
	})().catch(() => bastion.close(1011));
}

async function handshake(frames: WebSocketFrames, bastionUrl: string, early: Uint8Array | null): Promise<void> {
	let buf = early ?? new Uint8Array(0);
	let header: Extract<Header, { status: 'ok' }>;

	for (;;) {
		const parsed = parseHeader(buf);
		if (parsed.status === 'ok') {
			header = parsed;
			break;
		}
		if (parsed.status === 'invalid' || buf.length > MAX_HEADER) {
			frames.socket.close(1008);
			return;
		}
		const frame = await nextFrame(frames, HANDSHAKE_TIMEOUT);
		if (frame === null) {
			frames.socket.close(1008);
			return;
		}
		buf = concat(buf, frame);
	}

	const bastion = await openBastion(bastionUrl, header.destination);
	if (bastion === null) {
		frames.socket.close(1011);
		return;
	}

	frames.socket.send(RESPONSE_HEADER);
	const rest = buf.subarray(header.consumed);
	if (rest.length > 0) bastion.send(rest);
	bridge(frames, bastion);
}

/**
 * VLESS over WebSocket, the server side of an Xray `network: ws` outbound, with
 * every connection relayed through the cloudflared bastion at `bastionUrl`.
 */
export function proxyVless(request: Request, bastionUrl: string): Response {
	if (request.headers.get('Upgrade') !== 'websocket') {
		return new Response('expected websocket', { status: 426 });
	}

	const { 0: client, 1: server } = new WebSocketPair();
	server.binaryType = 'arraybuffer';
	server.accept({ allowHalfOpen: true });
	const frames = new WebSocketFrames(server);

	// The 101 has to go back before any frame can arrive, so the handshake runs
	// detached and reports failure by closing the WebSocket.
	const protocol = request.headers.get('Sec-WebSocket-Protocol');
	const early = decodeEarlyData(protocol);
	void handshake(frames, bastionUrl, early).catch((error) => {
		console.error(error);
		server.close(1011);
	});

	const headers = early && protocol ? { 'Sec-WebSocket-Protocol': protocol } : undefined;
	return new Response(null, { status: 101, webSocket: client, headers });
}
