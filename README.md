# OctoPrint Cloudflare Access SSO

This plugin enables **Single Sign-On (SSO)** for OctoPrint using **Cloudflare Zero Trust Access**.

Instead of authenticating through OctoPrint’s native login system, authentication is delegated to **Cloudflare Access**. The plugin reads a **JWT assertion** injected by Cloudflare into incoming HTTP requests and uses it to authenticate users inside OctoPrint.

If a Cloudflare-authenticated user does not exist in OctoPrint, the plugin creates them on their first visit with OctoPrint's default groups (normally **Operator**) and no password, so they can only sign in through Cloudflare Access. Promote people to admin in OctoPrint's Access Control settings.

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

Save and restart OctoPrint.

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
