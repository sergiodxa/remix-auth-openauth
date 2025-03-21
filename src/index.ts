import type { SetCookieInit } from "@mjackson/headers";
import { type Tokens, createClient } from "@openauthjs/openauth/client";
import * as OpenAuthError from "@openauthjs/openauth/error";
import type { SubjectSchema } from "@openauthjs/openauth/subject";
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
			fetch: options.fetch,
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

			let { state, verifier, url } = await this.createAuthorizationURL();

			debug("State", state);
			debug("Code verifier", verifier);

			url.search = this.authorizationParams(
				url.searchParams,
				request,
			).toString();

			debug("Authorization URL", url.toString());

			let store = StateStore.fromRequest(request, this.cookieName);
			store.set(state, verifier);

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
		let result = await this.validateAuthorizationCode(code, codeVerifier);

		if (result.err) throw result.err;

		let tokens = result.tokens;

		debug("Verifying the user profile");
		let user = await this.verify({ request, client: this.client, tokens });

		debug("User authenticated");
		return user;
	}

	/**
	 * Refreshes the access token using the provided refresh token.
	 *
	 * @param refresh - The refresh token to use for obtaining a new access token.
	 * @param access - An optional access token to validate if it needs to be refreshed.
	 * @returns The new tokens obtained after refreshing.
	 */
	public async refreshToken(
		refresh: string,
		access?: string,
	): Promise<Tokens | undefined> {
		debug("Refreshing tokens");
		let result = await this.client.refresh(refresh, { access });
		if (result.err) throw result.err;
		debug("Tokens refreshed");
		if (!result.tokens && access) return { access, refresh };
		if (!access && !result.tokens) throw new Error("No tokens returned");
		return result.tokens;
	}

	public async verifyToken<T extends SubjectSchema>(
		schema: T,
		token: string,
		options?: { refresh: string; audience?: string },
	) {
		let result = await this.client.verify<T>(schema, token, {
			...options,
			issuer: this.options.issuer,
			fetch: this.options.fetch as typeof fetch,
		});
		if (result.err) throw result.err;
		let { err: _, ...clone } = structuredClone(result);
		return clone;
	}

	protected async createAuthorizationURL() {
		let result = await this.client.authorize(this.options.redirectUri, "code", {
			pkce: true,
			provider: this.options.provider,
		});

		let url = new URL(result.url);
		url.searchParams.set("state", result.challenge.state);

		return { ...result.challenge, url };
	}

	protected validateAuthorizationCode(code: string, codeVerifier: string) {
		return this.client.exchange(code, this.options.redirectUri, codeVerifier);
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
	type FetchLike = NonNullable<Parameters<typeof createClient>["0"]["fetch"]>;

	export interface ConstructorOptions {
		/**
		 * The redirect URI of the application you registered in the OpenAuth
		 * server.
		 *
		 * This is where the user will be redirected after they authenticate.
		 *
		 * @example
		 * "https://example.com/auth/callback"
		 */
		redirectUri: string;

		/**
		 * The client ID of the application you registered in the OpenAuth server.
		 * @example
		 * "my-client-id"
		 */
		clientId: string;

		/**
		 * The issuer of the OpenAuth server you want to use.
		 * This is where your OpenAuth server is hosted.
		 * @example
		 * "https://openauth.example.com"
		 */
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

		/**
		 * A custom fetch implementation to use when making requests to the OAuth2
		 * server. This can be useful when you need to replace the default fetch
		 * to use a proxy, for example.
		 */
		fetch?: FetchLike;
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

export { OpenAuthError };
