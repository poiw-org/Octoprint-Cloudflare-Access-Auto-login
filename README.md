# OctoPrint Cloudflare Access SSO

This plugin enables **Single Sign-On (SSO)** for OctoPrint using **Cloudflare Zero Trust Access**.

Instead of authenticating through OctoPrint’s native login system, authentication is delegated to **Cloudflare Access**. The plugin reads a **JWT assertion** injected by Cloudflare into incoming HTTP requests and uses it to authenticate users inside OctoPrint.

If a Cloudflare-authenticated user does not exist in OctoPrint, the plugin automatically creates the user and assigns them the **operator** role.

## Installation

1. Ensure you are running OctoPrint (Python 3).
2. Install the plugin from source:

```bash
cd /path/to/Octoprint-Cloudflare-Access-Auto-login
~/OctoPrint/venv/bin/pip install .
```

3. Restart OctoPrint.

## Configuration

In OctoPrint:

- Open `Settings → Plugins → Cloudflare Access SSO`.
- Set **Team Domain**, e.g. `example.cloudflareaccess.com`.
- Set **Audience (AUD)** to the application AUD tag from Cloudflare Zero Trust.
- Optionally set **Allowed CIDR ranges** for additional trusted networks (comma, space or line separated).
- Optionally enable **Allow Cloudflare IP ranges** to trust requests coming from Cloudflare's published IPv4/IPv6 ranges.

Save and restart OctoPrint.

## How it works

- For each HTTP request, the plugin runs a `before_request` hook.
- It only processes requests if the client IP is:
  - a loopback address (`127.0.0.1` / `::1`), or
  - within one of the configured **Allowed CIDR ranges**, or
  - within Cloudflare's published IP ranges (when enabled in settings).
- It reads the `Cf-Access-Jwt-Assertion` header.
- The JWT is validated using Cloudflare’s JWKS (`https://<team_domain>/cdn-cgi/access/certs`), audience, and issuer.
- On successful validation it:
  - Extracts the `email` and `name` claims.
  - Creates a user (if missing) with the `operator` role.
  - Logs the user in via Flask-Login.

OctoPrint’s normal permission system then applies.

