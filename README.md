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
- Optionally turn on **Sign in local connections without a Cloudflare token** and pick an existing OctoPrint **Local user**.

Save and restart OctoPrint.

## Local sign-in without a token

Requests that carry no valid Cloudflare Access token are signed in as the local user only when they come from the lab:

- through the tunnel, when their address (`X-Forwarded-For`) is the printer's own public IPv4 address, i.e. behind the same NAT, or
- directly, by the printer's local IP, from a subnet one of the printer's network interfaces is on, or from the printer itself (loopback).

This is OctoPrint's own autologin (`accessControl.autologinLocal`, `autologinAs`). Every 5 minutes the plugin looks up the public IP (from `https://1.1.1.1/cdn-cgi/trace`) and the interface subnets, and sets `localNetworks` to them, overwriting anything there. Subnets can't be configured, so a whole organisation's network can't be let in, unless the printer's own interface is on one (e.g. a large campus subnet, or a VPN interface such as WireGuard, whose peers would count as local). Addresses under **Allowed CIDR ranges** are left out, so a `cloudflared` elsewhere on the LAN doesn't sign everyone in.

- A valid Access token always wins: the visitor signs in as themselves.
- OctoPrint takes the client address from `X-Forwarded-For` when the request comes through a trusted proxy, so visitors through a `cloudflared` tunnel show their own public IP.
- If the lookup fails, nobody is signed in this way until it succeeds again.
- Tunnel visitors reaching Cloudflare over IPv6 don't match the public IP.
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
- Logging out of OctoPrint after signing in through Access sends the browser to `/cdn-cgi/access/logout`, which ends the Cloudflare Access session (for all Access applications); otherwise the next request would sign them straight back in.

OctoPrint's normal login keeps working for requests without the header, e.g. on the local network.
