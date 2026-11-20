$(function () {
    // Logging out of OctoPrint alone doesn't help an Access user: Cloudflare sends the token again
    // with the next request and they are signed straight back in. End the Access session too.
    function CloudflareAccessSSOViewModel(parameters) {
        var loginState = parameters[0];
        var lastMechanism = null;

        loginState.currentLoginMechanism.subscribe(function (mechanism) {
            if (mechanism) lastMechanism = mechanism;
        });

        this.onUserLoggedOut = function () {
            if (lastMechanism === "cloudflare_access") {
                window.location.href = "/cdn-cgi/access/logout";
            }
        };
    }

    OCTOPRINT_VIEWMODELS.push({
        construct: CloudflareAccessSSOViewModel,
        dependencies: ["loginStateViewModel"]
    });
});
