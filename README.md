# OctoPrint Cloudflare Access SSO

This plugin enables **Single Sign-On (SSO)** for OctoPrint using **Cloudflare Zero Trust Access**.

Instead of authenticating through OctoPrint’s native login system, authentication is delegated to **Cloudflare Access**. The plugin reads a **JWT assertion** injected by Cloudflare into incoming HTTP requests and uses it to authenticate users inside OctoPrint.

If a Cloudflare-authenticated user does not exist in OctoPrint, the plugin creates them on their first visit with OctoPrint's default groups (normally **Operator**) and no password, so they can only sign in through Cloudflare Access. Their groups can follow the roles your identity provider sends (see below), or you manage them in OctoPrint's Access Control settings.

Requires **OctoPrint 2.0** or later.

## Installation

```bash
~/oprint/bin/pip install https://github.com/donfn/Octoprint-Cloudflare-Access-Auto-login/archive/main.zip
```

or from a checkout: `~/oprint/bin/pip install .`. Restart OctoPrint.

## Configuration

In OctoPrint:

- Open `Settings → Plugins → Cloudflare Access SSO`.
- Set **Team Domain**, e.g. `example.cloudflareaccess.com`.
- Set **Audience (AUD)** to the application AUD tag from Cloudflare Zero Trust.
- If `cloudflared` doesn't run on the OctoPrint machine itself, add its address under **Allowed CIDR ranges** (comma, space or line separated).
- If Cloudflare's proxy connects to OctoPrint directly (no tunnel), enable **Allow Cloudflare IP ranges**.

- Set **Roles to groups**, one `role: group` per line (default `admin: admins` and `lab-access: users`). Leave it empty to manage groups in OctoPrint.
- Optionally turn on **Sign in local connections without a Cloudflare token**, pick an existing OctoPrint **Local user**, and list the **Local networks** (default `127.0.0.0/8`, `::1/128`).

Save and restart OctoPrint.

## Local sign-in without a token

Requests from the local networks that carry no valid Cloudflare Access token are signed in as the local user. This is OctoPrint's own autologin (`accessControl.autologinLocal`, `autologinAs`, `localNetworks` in `config.yaml`); the plugin just puts those settings on its page.

- A valid Access token always wins: the visitor signs in as themselves.
- OctoPrint takes the client address from `X-Forwarded-For` when the request comes through a trusted proxy, so visitors through a `cloudflared` tunnel on the same machine show their own public IP and don't match `127.0.0.0/8`. Don't add a network your proxy forwards from without that header.
- Logging out stops it for that browser until someone signs in by hand again.

## Roles to groups

Add `roles` under **OIDC claims** in the Cloudflare identity provider. Cloudflare then passes the claim to OctoPrint in the token's `custom` object. On every sign-in, and whenever a new token carries different roles, the plugin sets the user's OctoPrint groups to the groups their roles map to:

- Roles not in the mapping give no group. A user whose roles map to nothing keeps their account but has no permissions.
- If the token has no `roles` claim (not configured, or Cloudflare dropped it because the custom claims exceeded about 1 KB), the groups are left as they are.
- Groups you change by hand in OctoPrint are overwritten at the next sign-in while a mapping is set.
- Group keys are OctoPrint's: `admins`, `users` (Operator), `readonly`, `guests`, or the key of a group you created.

## How it works

- The plugin adds a request loader to OctoPrint's login manager, next to OctoPrint's own API key and remote user header checks.
- It reads the `Cf-Access-Jwt-Assertion` header, but only from a trusted peer: the address that connected to OctoPrint must be
  - a loopback address (`cloudflared` on the same machine), or
  - within one of the **Allowed CIDR ranges**, or
  - within Cloudflare's published IP ranges (when enabled).
- It verifies the JWT's signature against Cloudflare's keys (`https://<team_domain>/cdn-cgi/access/certs`, refetched when Cloudflare rotates them), audience, issuer and expiry.
- It finds the user named by the `email` claim, creating them if needed, and OctoPrint signs them in.
- When a later request carries a different Access identity, or none, the OctoPrint session ends.

OctoPrint's normal login keeps working for requests without the header, e.g. on the local network.
