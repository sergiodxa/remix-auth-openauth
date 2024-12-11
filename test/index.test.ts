import { afterAll, beforeAll, describe, expect, mock, test } from "bun:test";
import { Cookie, SetCookie } from "@mjackson/headers";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/native";
import { OpenAuthStrategy } from "../src/index";

describe(OpenAuthStrategy.name, () => {
	let server = setupServer();

	beforeAll(() => server.listen());
	afterAll(() => server.close());

	test("#name", () => {
		let verify = mock();

		let strategy = new OpenAuthStrategy(
			{
				clientID: "client-id",
				redirectURI: "redirect-uri",
				issuer: "https://auth.example.com",
			},
			verify,
		);

		expect(strategy.name).toBe("openauth");
	});

	test("#authenticate starts flow", async () => {
		let verify = mock();

		let strategy = new OpenAuthStrategy(
			{
				clientID: "client-id",
				redirectURI: "redirect-uri",
				issuer: "https://auth.example.com",
			},
			verify,
		);

		let request = new Request("https://example.com");

		let response = await catchResponse(strategy.authenticate(request));

		// biome-ignore lint/style/noNonNullAssertion: We are testing the response.
		let url = new URL(response.headers.get("Location")!);

		let setCookie = new SetCookie(response.headers.get("set-cookie") ?? "");

		expect(response.status).toBe(302);

		expect(url.searchParams.get("client_id")).toBe("client-id");
		expect(url.searchParams.get("redirect_uri")).toBe("redirect-uri");
		expect(url.searchParams.get("response_type")).toBe("code");
		expect(url.searchParams.get("code_challenge_method")).toBe("S256");
		expect(url.searchParams.get("code_challenge")).toBeString();

		expect(setCookie.name).toBe("openauth");
		expect(setCookie.path).toBe("/");
		expect(setCookie.sameSite).toBe("Lax");
		expect(setCookie.httpOnly).toBe(true);
		expect(setCookie.value).toBeString();
	});

	test("#authenticate exchanges code", async () => {
		let verify = mock<
			(
				tokens: OpenAuthStrategy.VerifyOptions,
			) => Promise<OpenAuthStrategy.VerifyOptions>
		>().mockImplementation(async (tokens) => tokens);

		let strategy = new OpenAuthStrategy(
			{
				clientID: "client-id",
				redirectURI: "redirect-uri",
				issuer: "https://auth.example.com",
			},
			verify,
		);

		let cookie = new Cookie();
		cookie.set("verifier", "verifier");

		let request = new Request("https://example.com?code=code", {
			headers: { cookie: cookie.toString() },
		});

		server.resetHandlers(
			http.post("https://auth.example.com/token", async ({ request }) => {
				let body = await request.formData();

				expect(body.get("code")).toBe("code");
				expect(body.get("redirect_uri")).toBe("redirect-uri");
				expect(body.get("client_id")).toBe("client-id");
				expect(body.get("code_verifier")).toBe("verifier");

				return HttpResponse.json({
					ok: true,
					access_token: "access",
					refresh_token: "refresh",
				});
			}),
		);

		await strategy.authenticate(request);

		expect(verify).toHaveBeenCalledWith({
			tokens: { access: "access", refresh: "refresh" },
		});
	});
});

async function catchResponse(promise: Promise<unknown>) {
	try {
		await promise;
		throw new Error("The promise didn't throw a response.");
	} catch (error) {
		if (error instanceof Response) return error;
		throw error;
	}
}
