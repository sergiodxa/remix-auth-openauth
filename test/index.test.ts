import {
	afterAll,
	afterEach,
	beforeAll,
	describe,
	expect,
	mock,
	test,
} from "bun:test";
import { Cookie, SetCookie } from "@mjackson/headers";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/native";
import { OpenAuthStrategy } from "../src/index";

describe(OpenAuthStrategy.name, () => {
	const server = setupServer(
		http.post("https://auth.example.com/token", async () => {
			return HttpResponse.json({
				access_token: "access-token",
				refresh_token: "refresh-token",
			});
		}),
	);

	const user = { id: "123" };

	let verify = mock<
		(options: OpenAuthStrategy.VerifyOptions) => Promise<typeof user>
	>().mockImplementation(() => Promise.resolve(user));

	let options = Object.freeze({
		clientId: "client-id",
		redirectUri: "https://example.com/callback",
		issuer: "https://auth.example.com",
	} satisfies OpenAuthStrategy.ConstructorOptions);

	beforeAll(() => server.listen());
	afterEach(() => server.resetHandlers());
	afterAll(() => server.close());

	test("#name is openauth", () => {
		let verify = mock();
		let strategy = new OpenAuthStrategy(options, verify);
		expect(strategy.name).toBe("openauth");
	});

	test("handles complete OAuth2 flow", async () => {
		let strategy = new OpenAuthStrategy<typeof user>(options, verify);

		// We create multiple responses (this ensure we handle race conditions on set-cookie)
		let responses = await Promise.all(
			Array.from({ length: random() }, () =>
				catchResponse(
					strategy.authenticate(new Request("https://example.com/login")),
				),
			),
		);

		// Get the cookies the redirects are setting
		let setCookies: SetCookie[] = responses
			.flatMap((res) => res.headers.getSetCookie())
			.map((header) => new SetCookie(header));

		let cookie = new Cookie();

		for (let setCookie of setCookies) {
			// Add cookies to our cookie object as if we were a browser
			cookie.set(setCookie.name as string, setCookie.value as string);
		}

		// Create a callback URI with the state, and random code and the cookies
		let urls = setCookies.map((setCookie) => {
			let params = new URLSearchParams(setCookie.value);
			let url = new URL("https://example.com/callback");
			url.searchParams.set("state", params.get("state") as string);
			url.searchParams.set("code", crypto.randomUUID());
			return url;
		});

		// Call the strategy with the requests received on the callback
		let users = await Promise.all(
			urls.map((url) => {
				let headers = new Headers();
				headers.append("Cookie", cookie.toString());
				return strategy.authenticate(new Request(url, { headers }));
			}),
		);

		// We expect to have received an array with the same amount of flow we
		// initiated and all of them with the same user
		expect(users).toEqual(Array.from({ length: responses.length }, () => user));

		// We expect verify to have been called once per flow we initiated, and all
		// to receive the request and tokens
		expect(verify).toHaveBeenNthCalledWith(responses.length, {
			request: expect.any(Request),
			tokens: { access: "access-token", refresh: "refresh-token" },
		});
	});
});

function isResponse(value: unknown): value is Response {
	return value instanceof Response;
}

async function catchResponse(promise: Promise<unknown>) {
	try {
		await promise;
		throw new Error("Should have failed.");
	} catch (error) {
		if (isResponse(error)) return error;
		throw error;
	}
}

function random(min = 1, max = 10) {
	return Math.floor(Math.random() * (max - min + 1)) + min;
}
