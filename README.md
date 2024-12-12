# Remix Auth strategy for [OpenAuth.js](https://openauth.js.org)

This is a strategy to use with OpenAuth.js as your identity provider.

## Supported runtimes

| Runtime    | Has Support |
| ---------- | ----------- |
| Node.js    | ✅          |
| Cloudflare | ✅          |

## How to use

Install the strategy

```
npm add remix-auth-openauth
```

Add it to your OpenAuth authenticator

```ts
import { OpenAuth } from "remix-auth-openauth";

authenticator.use(
  new OpenAuth(
    {
      clientId: "client-id",
      redirectUri: "https://example.com/callback",
      issuer: "https://auth.example.com",
    },
    async ({ request, client, tokens }) => {
      // use request and tokens.
    }
  )
);
```

Then call it with `authenticator.authenticate("openauth", request)` and it will redirect to the OpenAuth login page.

### Setup a Specific Provider

You can also pass a `provider` to the OpenAuth configuration to send it to one provider.

```ts
import { OpenAuth } from "remix-auth-openauth";

authenticator.use(
  new OpenAuth(
    {
      clientId: "client-id",
      redirectUri: "https://example.com/callback",
      issuer: "https://auth.example.com",
      provider: "github",
    },
    async ({ request, client, tokens }) => {
      // Use request, client, and tokens to return your user object
    }
  )
);
```

> [!TIP]
> Set the same provider as strategy name, then you can set the OpenAuth strategy multiple times.

```ts
authenticator.use(
  new OpenAuth(
    { ...sharedOptions, provider: "github" },
    async ({ request, client, tokens }) => {
      // Use request, client, and tokens to return your user object
    }
  ),
  "github"
);

authenticator.use(
  new OpenAuth(
    { ...sharedOptions, provider: "google" },
    async ({ request, client, tokens }) => {
      // Use request, client, and tokens to return your user object
    }
  ),
  "google"
);
```
