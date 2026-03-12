import ipaddress
import logging
from typing import Any, Dict, List, Optional

import jwt
import requests
from flask import request
from flask_login import login_user

import octoprint.plugin
from octoprint.server import userManager


class CloudflareAccessSSOPlugin(
    octoprint.plugin.StartupPlugin,
    octoprint.plugin.SettingsPlugin,
    octoprint.plugin.TemplatePlugin,
    octoprint.plugin.AssetPlugin,
):
    def __init__(self) -> None:
        self._logger = logging.getLogger("octoprint.plugins.cloudflare_access_sso")
        self._jwks_cache: Optional[Dict[str, Any]] = None
        self._allowed_networks: List[ipaddress._BaseNetwork] = []
        self._cloudflare_networks: List[ipaddress._BaseNetwork] = []

    ##~~ SettingsPlugin mixin

    def get_settings_defaults(self) -> Dict[str, Any]:
        return {
            "team_domain": "",
            "audience": "",
            "allowed_cidrs": "",
            "allow_cloudflare_ips": False,
        }

    def on_settings_save(self, data: Dict[str, Any]) -> None:
        octoprint.plugin.SettingsPlugin.on_settings_save(self, data)
        self._load_network_configuration()

    ##~~ TemplatePlugin mixin

    def get_template_configs(self):
        return [
            dict(
                type="settings",
                custom_bindings=True,
                name="Cloudflare Access SSO",
                template="cloudflare_access_sso_settings.jinja2",
            )
        ]

    ##~~ AssetPlugin mixin

    def get_assets(self):
        return {
            "js": ["js/cloudflare_access_sso.js"],
        }

    ##~~ StartupPlugin mixin

    def on_after_startup(self):
        self._logger.info("Cloudflare Access SSO plugin initialized")

        flask_app = self._plugin_manager.get_plugin("octoprint").implementation._app
        # Register a before_request handler that runs early
        flask_app.before_request(self._handle_before_request)
        self._load_network_configuration()

    # ---- Core SSO logic -------------------------------------------------

    def _handle_before_request(self):
        try:
            self._process_request()
        except Exception as exc:  # noqa: BLE001
            self._logger.exception(
                "Unexpected error while processing Cloudflare Access SSO: %s", exc
            )

    def _process_request(self) -> None:
        # 1. Extract JWT from Cloudflare header
        token = request.headers.get("Cf-Access-Jwt-Assertion")
        if not token:
            # No Cloudflare JWT present: fall back to OctoPrint's default behaviour
            return

        # 2. Enforce request origin only when we are handling a Cloudflare JWT
        remote_addr = request.remote_addr
        if not self._is_request_ip_allowed(remote_addr):
            return

        team_domain = self._settings.get(["team_domain"]).strip()
        audience = self._settings.get(["audience"]).strip()

        if not team_domain or not audience:
            self._logger.debug(
                "Cloudflare Access SSO not configured (team_domain/audience missing)"
            )
            return

        payload = self._verify_jwt(token, team_domain=team_domain, audience=audience)
        if not payload:
            return

        email = payload.get("email")
        name = payload.get("name")

        if not email:
            self._logger.warning(
                "Cloudflare Access JWT is missing 'email' claim; cannot authenticate user"
            )
            return

        self._ensure_and_login_user(username=email, full_name=name)

    # ---- Network configuration & validation ------------------------------

    def _load_network_configuration(self) -> None:
        """Parse user-defined CIDRs and, if enabled, fetch Cloudflare IP ranges."""
        cidr_text = (self._settings.get(["allowed_cidrs"]) or "").strip()
        self._allowed_networks = self._parse_networks_from_text(cidr_text)

        if self._settings.get_boolean(["allow_cloudflare_ips"]):
            self._cloudflare_networks = self._fetch_cloudflare_networks()
        else:
            self._cloudflare_networks = []

        self._logger.info(
            "Cloudflare Access SSO network config: %d user CIDR(s), %d Cloudflare CIDR(s)",
            len(self._allowed_networks),
            len(self._cloudflare_networks),
        )

    def _parse_networks_from_text(
        self, text: str
    ) -> List[ipaddress._BaseNetwork]:
        networks: List[ipaddress._BaseNetwork] = []
        if not text:
            return networks

        # Allow comma, space, or newline separated CIDRs
        raw_items = []
        for part in text.replace(",", " ").split():
            item = part.strip()
            if item:
                raw_items.append(item)

        for cidr in raw_items:
            try:
                net = ipaddress.ip_network(cidr, strict=False)
                networks.append(net)
            except ValueError:
                self._logger.warning(
                    "Ignoring invalid CIDR '%s' in Cloudflare Access SSO settings",
                    cidr,
                )

        return networks

    def _is_request_ip_allowed(self, remote_addr: Optional[str]) -> bool:
        if not remote_addr:
            return False

        try:
            ip = ipaddress.ip_address(remote_addr)
        except ValueError:
            self._logger.warning(
                "Received invalid remote_addr '%s', rejecting for SSO", remote_addr
            )
            return False

        # Always allow loopback to preserve previous behavior
        if ip.is_loopback:
            return True

        for net in self._allowed_networks:
            if ip in net:
                return True

        for net in self._cloudflare_networks:
            if ip in net:
                return True

        return False

    def _fetch_jwks(self, team_domain: str) -> Optional[Dict[str, Any]]:
        if self._jwks_cache is not None:
            return self._jwks_cache

        jwks_url = f"https://{team_domain}/cdn-cgi/access/certs"
        try:
            resp = requests.get(jwks_url, timeout=5)
            resp.raise_for_status()
            data = resp.json()
            if not isinstance(data, dict) or "keys" not in data:
                self._logger.warning(
                    "Unexpected JWKS response from Cloudflare: %r", data
                )
                return None
            self._jwks_cache = data
            return data
        except Exception as exc:  # noqa: BLE001
            self._logger.warning(
                "Failed to fetch Cloudflare JWKS from %s: %s", jwks_url, exc
            )
            return None

    def _fetch_cloudflare_networks(self) -> List[ipaddress._BaseNetwork]:
        """Fetch and cache Cloudflare IPv4/IPv6 CIDR ranges."""
        url = "https://api.cloudflare.com/client/v4/ips"
        networks: List[ipaddress._BaseNetwork] = []

        try:
            resp = requests.get(url, timeout=5)
            resp.raise_for_status()
            data = resp.json()

            cidrs: List[str] = []
            result = data.get("result") if isinstance(data, dict) else None
            if isinstance(result, dict):
                cidrs.extend(result.get("ipv4_cidrs", []) or [])
                cidrs.extend(result.get("ipv6_cidrs", []) or [])
            else:
                # Fallback if Cloudflare returns flat structure
                cidrs.extend(data.get("ipv4_cidrs", []) or [])
                cidrs.extend(data.get("ipv6_cidrs", []) or [])

            for cidr in cidrs:
                try:
                    networks.append(ipaddress.ip_network(cidr, strict=False))
                except ValueError:
                    self._logger.warning(
                        "Ignoring invalid Cloudflare CIDR '%s' from %s", cidr, url
                    )

            self._logger.info(
                "Loaded %d Cloudflare IP CIDR(s) from %s", len(networks), url
            )
        except Exception as exc:  # noqa: BLE001
            self._logger.warning(
                "Failed to fetch Cloudflare IP ranges from %s: %s", url, exc
            )

        return networks

    def _verify_jwt(
        self, token: str, team_domain: str, audience: str
    ) -> Optional[Dict[str, Any]]:
        try:
            unverified_header = jwt.get_unverified_header(token)
        except jwt.InvalidTokenError as exc:
            self._logger.warning(
                "Invalid Cloudflare Access JWT header, aborting authentication: %s",
                exc,
            )
            return None

        kid = unverified_header.get("kid")
        if not kid:
            self._logger.warning(
                "Cloudflare Access JWT missing 'kid' header, aborting authentication"
            )
            return None

        jwks = self._fetch_jwks(team_domain)
        if not jwks:
            return None

        key_data = None
        for key in jwks.get("keys", []):
            if key.get("kid") == kid:
                key_data = key
                break

        if not key_data:
            self._logger.warning(
                "No matching JWK found for kid=%s in Cloudflare JWKS", kid
            )
            return None

        try:
            public_key = jwt.algorithms.RSAAlgorithm.from_jwk(key_data)
            payload = jwt.decode(
                token,
                key=public_key,
                audience=audience,
                issuer=f"https://{team_domain}",
                algorithms=["RS256"],
            )
            return payload
        except jwt.ExpiredSignatureError:
            self._logger.info("Cloudflare Access JWT has expired")
        except jwt.InvalidTokenError as exc:
            self._logger.warning(
                "Failed to validate Cloudflare Access JWT: %s", exc
            )

        return None

    def _ensure_and_login_user(self, username: str, full_name: Optional[str]) -> None:
        try:
            user = userManager.findUser(username)
        except Exception:  # noqa: BLE001
            user = None

        if user is None:
            try:
                user = userManager.addUser(
                    username,
                    password="",
                    active=True,
                    roles=["operator"],
                    name=full_name or username,
                )
                self._logger.info(
                    "Created new OctoPrint user '%s' with operator role "
                    "via Cloudflare Access SSO",
                    username,
                )
            except Exception as exc:  # noqa: BLE001
                self._logger.warning(
                    "Failed to create OctoPrint user '%s' from Cloudflare Access JWT: %s",
                    username,
                    exc,
                )
                return

        try:
            login_user(user, remember=False)
            self._logger.debug(
                "Authenticated user '%s' via Cloudflare Access SSO", username
            )
        except Exception as exc:  # noqa: BLE001
            self._logger.warning(
                "Failed to log in user '%s' via Cloudflare Access SSO: %s",
                username,
                exc,
            )


__plugin_name__ = "Cloudflare Access SSO"
__plugin_pythoncompat__ = ">=3.7,<4"


def __plugin_load__():
    global __plugin_implementation__
    __plugin_implementation__ = CloudflareAccessSSOPlugin()

