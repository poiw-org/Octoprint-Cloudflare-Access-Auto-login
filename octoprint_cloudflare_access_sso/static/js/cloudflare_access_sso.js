(function () {
  function CloudflareAccessSSOViewModel(parameters) {
    var self = this;

    self.settingsViewModel = parameters[0];

    self.team_domain = self.settingsViewModel.settings.plugins.cloudflare_access_sso.team_domain;
    self.audience = self.settingsViewModel.settings.plugins.cloudflare_access_sso.audience;
    self.allowed_cidrs = self.settingsViewModel.settings.plugins.cloudflare_access_sso.allowed_cidrs;
    self.allow_cloudflare_ips = self.settingsViewModel.settings.plugins.cloudflare_access_sso.allow_cloudflare_ips;
  }

  OCTOPRINT_VIEWMODELS.push({
    construct: CloudflareAccessSSOViewModel,
    dependencies: ["settingsViewModel"],
    elements: ["#settings_plugin_cloudflare_access_sso"],
  });
})();
