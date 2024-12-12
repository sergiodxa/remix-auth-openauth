import type { SetCookieInit } from "@mjackson/headers";
import { createClient } from "@openauthjs/openauth/client";
import { encodeBase64urlNoPadding } from "@oslojs/encoding";
import createDebug from "debug";
import { Strategy } from "remix-auth/strategy";
import { redirect } from "./lib/redirect.js";
import { StateStore } from "./lib/store.js";

const debug = createDebug("OAuth2Strategy");

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

		this.client = createClient({
			clientID: options.clientId,
			issuer: options.issuer,
		});
	}

	private get cookieName() {
		if (typeof this.options.cookie === "string") {
			return this.options.cookie || "oauth2";
		}
		return this.options.cookie?.name ?? "oauth2";
	}

	private get cookieOptions() {
		if (typeof this.options.cookie !== "object") return {};
		return this.options.cookie ?? {};
	}

	override async authenticate(request: Request): Promise<U> {
		debug("Request URL", request.url);
		let url = new URL(request.url);

		let code = url.searchParams.get("code");
		let stateUrl = url.searchParams.get("state");
		let error = url.searchParams.get("error");

		if (error) {
			let description = url.searchParams.get("error_description");
			let uri = url.searchParams.get("error_uri");
			throw new OAuth2RequestError(error, description, uri, stateUrl);
		}

		if (!code) {
			debug("No code found in the URL, redirecting to authorization endpoint");

			let { state, codeVerifier, url } = await this.createAuthorizationURL();

			debug("State", state);
			debug("Code verifier", codeVerifier);

			url.search = this.authorizationParams(
				url.searchParams,
				request,
			).toString();

			debug("Authorization URL", url.toString());

			let store = StateStore.fromRequest(request, this.cookieName);
			store.set(state, codeVerifier);

			let setCookie = store.toSetCookie(this.cookieName, this.cookieOptions);

			let headers = new Headers();
			headers.append("Set-Cookie", setCookie.toString());

			throw redirect(url.toString(), { headers });
		}

		let store = StateStore.fromRequest(request);

		if (!stateUrl) throw new ReferenceError("Missing state in URL.");

		if (!store.has()) throw new ReferenceError("Missing state on cookie.");

		if (!store.has(stateUrl)) {
			throw new RangeError("State in URL doesn't match state in cookie.");
		}

		let codeVerifier = store.get(stateUrl);

		if (!codeVerifier) {
			throw new ReferenceError("Missing code verifier on cookie.");
		}

		debug("Validating authorization code");
		let tokens = await this.validateAuthorizationCode(code, codeVerifier);

		debug("Verifying the user profile");
		let user = await this.verify({ request, client: this.client, tokens });

		debug("User authenticated");
		return user;
	}

	protected async createAuthorizationURL() {
		let state = this.generateState();

		let [codeVerifier, redirect] = (await this.client.pkce(
			this.options.redirectUri,
		)) as [string, string];

		let url = new URL(redirect);
		url.searchParams.set("state", state);

		return { state, codeVerifier, url };
	}

	protected validateAuthorizationCode(code: string, codeVerifier: string) {
		return this.client.exchange(code, this.options.redirectUri, codeVerifier);
	}

	protected generateState() {
		let randomValues = new Uint8Array(32);
		crypto.getRandomValues(randomValues);
		return encodeBase64urlNoPadding(randomValues);
	}

	/**
	 * Return extra parameters to be included in the authorization request.
	 *
	 * Some OAuth 2.0 providers allow additional, non-standard parameters to be
	 * included when requesting authorization.  Since these parameters are not
	 * standardized by the OAuth 2.0 specification, OAuth 2.0-based authentication
	 * strategies can override this function in order to populate these
	 * parameters as required by the provider.
	 */
	protected authorizationParams(
		params: URLSearchParams,
		request: Request,
	): URLSearchParams {
		return new URLSearchParams(params);
	}
}

export namespace OpenAuthStrategy {
	export interface ConstructorOptions {
		redirectUri: string;
		clientId: string;
		issuer: string;
		/**
		 * The identity provider already configured in your OpenAuth server you
		 * want to send the user to.
		 *
		 * This can't be changed after the strategy is created, if you have more than one provider create multiple instances of your strategy.
		 *
		 * @example
		 * authenticator.use(
		 *   new OpenAuthStrategy(
		 *   {
		 *       redirectURI,
		 *       clientID,
		 *       issuer,
		 *       provider: "google" // Set it to Google
		 *     },
		 *     verify
		 *   ),
		 *   "google" // Rename the strategy to Google
		 * )
		 * authenticator.use(
		 *   new OpenAuthStrategy(
		 *   {
		 *       redirectURI,
		 *       clientID,
		 *       issuer,
		 *       provider: "github" // Set it to GitHub
		 *     },
		 *     verify
		 *   ),
		 *   "github" // Rename the strategy to GitHub
		 * )
		 */
		provider?: string;

		/**
		 * The name of the cookie used to keep state and code verifier around.
		 *
		 * The OAuth2 flow requires generating a random state and code verifier, and
		 * then checking that the state matches when the user is redirected back to
		 * the application. This is done to prevent CSRF attacks.
		 *
		 * The state and code verifier are stored in a cookie, and this option
		 * allows you to customize the name of that cookie if needed.
		 * @default "oauth2"
		 */
		cookie?: string | (Omit<SetCookieInit, "value"> & { name: string });
	}

	export interface VerifyOptions {
		request: Request;
		client: ReturnType<typeof createClient>;
		tokens: { access: string; refresh: string };
	}
}

export class OAuth2RequestError extends Error {
	code: string;
	description: string | null;
	uri: string | null;
	state: string | null;

	constructor(
		code: string,
		description: string | null,
		uri: string | null,
		state: string | null,
	) {
		super(`OAuth request error: ${code}`);
		this.code = code;
		this.description = description;
		this.uri = uri;
		this.state = state;
	}
}
