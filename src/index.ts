import { Cookie, SetCookie } from "@mjackson/headers";
import { createClient } from "@openauthjs/openauth/client";
import { encodeBase64urlNoPadding } from "@oslojs/encoding";
import { Strategy } from "remix-auth/strategy";

export class OpenAuthStrategy<U> extends Strategy<
	U,
	OpenAuthStrategy.VerifyOptions
> {
	name = "openauth";

	protected client: ReturnType<typeof createClient>;

	constructor(
		protected options: OpenAuthStrategy.ConstructorOptions,
		verify: Strategy.VerifyFunction<U, OpenAuthStrategy.VerifyOptions>,
	) {
		super(verify);

		this.client = createClient(options);
	}

	override async authenticate(request: Request): Promise<U> {
		let url = new URL(request.url);

		let code = url.searchParams.get("code");

		if (!code) {
			let [verifier, redirect] = (await this.client.pkce(
				this.options.redirectURI,
			)) as [string, string];

			let url = new URL(redirect);
			let state = this.generateState();
			url.searchParams.set("state", state);

			let setCookie = new SetCookie({
				name: "openauth",
				path: "/",
				sameSite: "Lax",
				maxAge: 60 * 5, // 5 minutes
				httpOnly: true,
				value: new URLSearchParams({ verifier, state }).toString(),
			});

			let headers = new Headers();
			headers.append("Set-Cookie", setCookie.toString());
			headers.append("Location", redirect);

			throw new Response(null, { status: 302, headers });
		}

		let cookie = new Cookie(request.headers.get("cookie") ?? "");
		let params = new URLSearchParams(cookie.get("openauth"));

		let verifier = params.get("verifier");
		let state = params.get("state");

		if (!state) throw new Error("Missing state");
		if (state !== url.searchParams.get("state")) {
			throw new Error("Invalid state");
		}
		if (!verifier) throw new Error("Missing verifier");

		let tokens = await this.client.exchange(
			code,
			this.options.redirectURI,
			verifier,
		);

		return this.verify({ tokens });
	}

	protected generateState() {
		let randomValues = new Uint8Array(32);
		crypto.getRandomValues(randomValues);
		return encodeBase64urlNoPadding(randomValues);
	}
}

export namespace OpenAuthStrategy {
	export interface ConstructorOptions {
		redirectURI: string;

		clientID: string;
		issuer?: string;
	}

	export interface VerifyOptions {
		tokens: {
			access: string;
			refresh: string;
		};
	}
}
