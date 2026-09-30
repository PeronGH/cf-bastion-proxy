import { proxyVless } from './vless';

const VLESS_PREFIX = '/vless/';

export default {
	async fetch(request): Promise<Response> {
		const { pathname } = new URL(request.url);

		// `/vless/https://bastion.example.com/path`: the rest of the path is the
		// bastion URL. The query string belongs to the client (Xray's `?ed=`).
		if (pathname.startsWith(VLESS_PREFIX)) {
			const bastion = URL.parse(pathname.slice(VLESS_PREFIX.length));
			if (bastion === null || (bastion.protocol !== 'https:' && bastion.protocol !== 'http:')) {
				return new Response('bad bastion url', { status: 400 });
			}
			return proxyVless(request, bastion.href);
		}

		return new Response('not found', { status: 404 });
	},
} satisfies ExportedHandler<Env>;
