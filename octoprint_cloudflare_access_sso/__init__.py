import ipaddress
from datetime import datetime
from typing import Any, Dict, List, Optional

import jwt
import requests
from flask import request, session

import octoprint.plugin
import octoprint.server
from octoprint.util import RepeatedTimer
from octoprint.access.users import UserAlreadyExists
from octoprint.server.util.flask import server_side_logout

JWT_HEADER = "Cf-Access-Jwt-Assertion"
# Stored in the session like OctoPrint's own login mechanisms (password, apikey, remote_user).
LOGIN_MECHANISM = "cloudflare_access"
# Cloudflare's resolver echoes the caller's address; 1.1.1.1 forces the IPv4 one.
PUBLIC_IP_URL = "https://1.1.1.1/cdn-cgi/trace"
PUBLIC_IP_REFRESH_SECONDS = 300


class CloudflareAccessSSOPlugin(
    octoprint.plugin.StartupPlugin,
    octoprint.plugin.SettingsPlugin,
    octoprint.plugin.TemplatePlugin,
):
    def __init__(self) -> None:
        self._jwks: Optional[jwt.PyJWKClient] = None
        self._allowed_networks: List[Any] = []
        self._cloudflare_networks: List[Any] = []

    ##~~ SettingsPlugin mixin

    def get_settings_defaults(self) -> Dict[str, Any]:
        return {
            "team_domain": "",
            "audience": "",
            "allowed_cidrs": "",
            "allow_cloudflare_ips": False,
            # "role: group" per line. Empty turns group syncing off.
            "role_groups": "admin: admins\nlab-access: users",
        }

    # Local sign-in without a token is OctoPrint's own autologin (accessControl.autologinLocal),
    # which only runs when nobody is signed in, so a valid Access token always wins, and which
    # respects logging out. The plugin gives its settings a page and keeps localNetworks set to
    # the printer's own public IP only (see _refresh_lab_ip), never a configurable subnet.
    def on_settings_load(self) -> Dict[str, Any]:
        data = octoprint.plugin.SettingsPlugin.on_settings_load(self)
        data["local_autologin"] = self._settings.global_get_boolean(["accessControl", "autologinLocal"])
        data["local_autologin_as"] = self._settings.global_get(["accessControl", "autologinAs"]) or ""
        return data

    def on_settings_save(self, data: Dict[str, Any]) -> None:
        if "local_autologin" in data:
            self._settings.global_set_boolean(
                ["accessControl", "autologinLocal"], bool(data.pop("local_autologin"))
            )
        if "local_autologin_as" in data:
            username = (data.pop("local_autologin_as") or "").strip()
            if username and octoprint.server.userManager.find_user(userid=username) is None:
                self._logger.warning("Local sign-in user %s doesn't exist in OctoPrint", username)
            self._settings.global_set(["accessControl", "autologinAs"], username or None)

        octoprint.plugin.SettingsPlugin.on_settings_save(self, data)
        self._jwks = None
        self._load_network_configuration()

    ##~~ TemplatePlugin mixin

    def get_template_configs(self):
        return [
            {
                "type": "settings",
                "name": "Cloudflare Access SSO",
                "template": "cloudflare_access_sso_settings.jinja2",
                "custom_bindings": False,
            }
        ]

    def is_template_autoescaped(self):
        return True

    ##~~ StartupPlugin mixin

    def on_startup(self, host, port):
        # Plug into OctoPrint's own login manager, after its API key, Basic Auth and remote user
        # header checks. Flask no longer lets plugins add app-wide before_request handlers once
        # the server runs, and a loader is how OctoPrint itself signs in proxy-authenticated users.
        login_manager = octoprint.server.loginManager
        from_request = login_manager._request_callback
        from_session = login_manager._user_callback
        login_manager.request_loader(lambda req: from_request(req) or self._user_from_jwt())
        login_manager.user_loader(
            lambda userid: from_session(userid) if self._session_still_valid(userid) else None
        )
        self._load_network_configuration()
        RepeatedTimer(PUBLIC_IP_REFRESH_SECONDS, self._refresh_lab_ip, run_first=True, daemon=True).start()

    # ---- Sign-in --------------------------------------------------------

    def _user_from_jwt(self):
        try:
            claims = self._verified_claims()
            if not claims:
                return None
            email = claims["email"]

            users = octoprint.server.userManager
            user = users.find_user(userid=email)
            if user is None:
                try:
                    # No password: this user can only sign in through Cloudflare Access.
                    users.add_user(email, None, active=True)
                    self._logger.info("Created OctoPrint user %s from Cloudflare Access", email)
                except UserAlreadyExists:
                    pass  # another request created it first
                user = users.find_user(userid=email)
            if user is None:
                return None
            self._sync_groups(email, claims)
            if not user.is_active:
                return None

            session["login_mechanism"] = LOGIN_MECHANISM
            session["credentials_seen"] = datetime.now().timestamp()
            return user
        except Exception:
            # Never break the request: OctoPrint's normal login still works.
            self._logger.exception("Cloudflare Access sign-in failed")
            return None

    def _session_still_valid(self, userid: str) -> bool:
        """A session this plugin started ends once the request's Access identity no longer matches,
        the same way OctoPrint treats its remote user header (OctoPrint issue #5279)."""
        if session.get("login_mechanism") != LOGIN_MECHANISM:
            return True
        try:
            claims = self._verified_claims()
            if claims and claims["email"] == userid:
                # Roles are fixed when the person signs in to Cloudflare Access; a new Access
                # sign-in brings a new token, so keep the groups current within the session too.
                self._sync_groups(userid, claims)
                return True
        except Exception:
            self._logger.exception("Could not check the Cloudflare Access identity")
        server_side_logout(userid, sessionid=session.get("usersession.id"))
        return False

    def _sync_groups(self, userid: str, claims: Dict[str, Any]) -> None:
        """Sets the user's OctoPrint groups from the token's `roles` claim, which Cloudflare passes
        on from the identity provider under `custom`."""
        mapping = {}
        for line in (self._settings.get(["role_groups"]) or "").splitlines():
            role, _, group = line.partition(":")
            if role.strip() and group.strip():
                mapping[role.strip()] = group.strip()
        roles = (claims.get("custom") or {}).get("roles")
        if not mapping or not isinstance(roles, list):
            # Off, or Cloudflare left the claim out (it drops custom claims over ~1 KB):
            # keep the groups as they are rather than take everyone's access away.
            return

        groups = sorted({mapping[role] for role in roles if role in mapping})
        users = octoprint.server.userManager
        user = users.find_user(userid=userid)
        if user is None or sorted(g.key for g in user.groups) == groups:
            return
        users.change_user_groups(userid, groups)
        self._logger.info("Set %s's groups to %s from roles %s", userid, groups, roles)

    def _verified_claims(self) -> Optional[Dict[str, Any]]:
        """The verified token's claims, with `email` present, or None."""
        token = request.headers.get(JWT_HEADER)
        if not token or not self._from_trusted_peer():
            return None

        team_domain = (self._settings.get(["team_domain"]) or "").strip()
        team_domain = team_domain.removeprefix("https://").rstrip("/")
        audience = (self._settings.get(["audience"]) or "").strip()
        if not team_domain or not audience:
            self._logger.debug("Cloudflare Access SSO is not configured")
            return None

        if self._jwks is None:
            # Caches Cloudflare's keys and refetches when a token names a key it hasn't seen,
            # so key rotation needs no restart.
            self._jwks = jwt.PyJWKClient(f"https://{team_domain}/cdn-cgi/access/certs", timeout=5)
        try:
            key = self._jwks.get_signing_key_from_jwt(token)
            claims = jwt.decode(
                token,
                key.key,
                algorithms=["RS256"],
                audience=audience,
                issuer=f"https://{team_domain}",
                options={"require": ["exp", "iat", "aud", "iss"]},
            )
        except jwt.PyJWTError as exc:
            self._logger.warning("Rejected Cloudflare Access token: %s", exc)
            return None

        email = claims.get("email")
        if not isinstance(email, str) or not email.strip():
            self._logger.warning("Cloudflare Access token has no email; service tokens can't sign in")
            return None
        return {**claims, "email": email.strip()}

    # ---- Network configuration ------------------------------------------

    def _load_network_configuration(self) -> None:
        """Parse user-defined CIDRs and, if enabled, fetch Cloudflare IP ranges."""
        self._allowed_networks = self._parse_networks(self._settings.get(["allowed_cidrs"]) or "")
        self._cloudflare_networks = (
            self._fetch_cloudflare_networks()
            if self._settings.get_boolean(["allow_cloudflare_ips"])
            else []
        )
        self._logger.info(
            "Cloudflare Access SSO network config: %d user CIDR(s), %d Cloudflare CIDR(s)",
            len(self._allowed_networks),
            len(self._cloudflare_networks),
        )

    def _parse_networks(self, text: str) -> List[Any]:
        networks = []
        # Comma, space or newline separated
        for cidr in text.replace(",", " ").split():
            try:
                networks.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError:
                self._logger.warning("Ignoring invalid CIDR '%s' in Cloudflare Access SSO settings", cidr)
        return networks

    def _from_trusted_peer(self) -> bool:
        # The peer that connected to OctoPrint (cloudflared, or Cloudflare's edge), not the client
        # address OctoPrint reads from X-Forwarded-For, which cloudflared sets to the visitor's IP.
        peer = request.environ.get("ORIG_REMOTE_ADDR") or request.remote_addr
        try:
            ip = ipaddress.ip_address(peer)
        except (TypeError, ValueError):
            return False
        return ip.is_loopback or any(
            ip in net for net in self._allowed_networks + self._cloudflare_networks
        )

    def _refresh_lab_ip(self) -> None:
        """Points OctoPrint's local autologin at the printer's public IPv4 address, so only visitors
        whose X-Forwarded-For address is that same IP (behind the lab's NAT) are signed in."""
        try:
            resp = requests.get(PUBLIC_IP_URL, timeout=5)
            resp.raise_for_status()
            fields = dict(line.partition("=")[::2] for line in resp.text.splitlines())
            networks = [f"{ipaddress.IPv4Address(fields.get('ip', '').strip())}/32"]
        except Exception as exc:
            # Fail closed: an unknown lab IP signs nobody in.
            self._logger.warning("Could not look up the printer's public IP: %s", exc)
            networks = []

        if self._settings.global_get(["accessControl", "localNetworks"]) == networks:
            return
        self._settings.global_set(["accessControl", "localNetworks"], networks)
        self._settings.save()
        # OctoPrint parses localNetworks once; drop its copy so the change applies without a restart.
        octoprint.server.util.flask._cached_local_networks = None
        self._logger.info("Local sign-in now limited to the lab IP %s", networks or "(none)")

    def _fetch_cloudflare_networks(self) -> List[Any]:
        url = "https://api.cloudflare.com/client/v4/ips"
        try:
            resp = requests.get(url, timeout=5)
            resp.raise_for_status()
            result = resp.json().get("result") or {}
            cidrs = (result.get("ipv4_cidrs") or []) + (result.get("ipv6_cidrs") or [])
        except Exception as exc:
            self._logger.warning("Failed to fetch Cloudflare IP ranges from %s: %s", url, exc)
            return []
        return self._parse_networks(" ".join(cidrs))


__plugin_name__ = "Cloudflare Access SSO"
__plugin_pythoncompat__ = ">=3.9,<4"


def __plugin_load__():
    global __plugin_implementation__
    __plugin_implementation__ = CloudflareAccessSSOPlugin()
