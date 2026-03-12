from setuptools import setup

plugin_identifier = "cloudflare_access_sso"
plugin_package = "octoprint_cloudflare_access_sso"
plugin_name = "Cloudflare Access SSO"
plugin_version = "0.1.0"
plugin_description = "Authenticate OctoPrint users via Cloudflare Zero Trust Access JWTs."
plugin_author = "Auto-generated"
plugin_author_email = "noreply@example.com"
plugin_url = "https://github.com/donfn/Octoprint-Cloudflare-Access-Auto-login"
plugin_license = "AGPLv3"
plugin_requires = ["octoprint>=1.8.0", "PyJWT>=2.8.0", "requests>=2.31.0"]

plugin_additional_data = []

plugin_additional_packages = []

plugin_ignored_packages = []

plugin_additional_setup_parameters = {}


def create_setup_parameters():
    from octoprint.setuptools import create_plugin_setup_parameters

    setup_parameters = create_plugin_setup_parameters(
        identifier=plugin_identifier,
        package=plugin_package,
        name=plugin_name,
        version=plugin_version,
        description=plugin_description,
        author=plugin_author,
        mail=plugin_author_email,
        url=plugin_url,
        license=plugin_license,
        requires=plugin_requires,
        additional_data=plugin_additional_data,
        additional_packages=plugin_additional_packages,
        ignored_packages=plugin_ignored_packages,
    )

    from octoprint.util import dict_merge

    return dict_merge(setup_parameters, plugin_additional_setup_parameters)


if __name__ == "__main__":
    setup(**create_setup_parameters())

