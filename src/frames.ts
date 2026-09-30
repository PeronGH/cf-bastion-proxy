/**
 * Frames read off an accepted WebSocket.
 *
 * workerd dispatches incoming frames straight out of its read loop, so a frame
 * that arrives while no `message` listener is attached is lost. One listener for
 * the connection's lifetime plus this queue keeps frames that arrive while the
 * bastion upgrade is in flight.
 */
export class WebSocketFrames {
	private readonly queue: Uint8Array[] = [];
	private waiter: (() => void) | null = null;
	private ended = false;
	/** Close code from the peer, when it closed cleanly rather than errored. */
	closeCode: number | undefined;

	constructor(readonly socket: WebSocket) {
		socket.addEventListener('message', (event) => {
			this.queue.push(frameBytes(event.data));
			this.wake();
		});
		socket.addEventListener('close', (event) => {
			this.closeCode = event.code;
			this.end();
		});
		socket.addEventListener('error', () => this.end());
	}

	private end(): void {
		this.ended = true;
		this.wake();
	}

	private wake(): void {
		const waiter = this.waiter;
		this.waiter = null;
		waiter?.();
	}

	/** The next frame, or null once the peer has closed or errored. */
	async next(): Promise<Uint8Array | null> {
		for (;;) {
			const frame = this.queue.shift();
			if (frame !== undefined) return frame;
			if (this.ended) return null;
			await new Promise<void>((resolve) => {
				this.waiter = resolve;
			});
		}
	}
}

/** Requires `binaryType = 'arraybuffer'`; a `Blob` would need an async read and could reorder frames. */
export function frameBytes(data: string | ArrayBuffer): Uint8Array {
	return typeof data === 'string' ? new TextEncoder().encode(data) : new Uint8Array(data);
}

/**
 * 1005, 1006 and 1015 are reserved for reporting and must not be sent in a
 * Close frame, so they are forwarded as a close without a code.
 */
export function sendableCloseCode(code: number | undefined): number | undefined {
	return code === 1005 || code === 1006 || code === 1015 ? undefined : code;
}
