```python
import os
import sys
import json
import base64
import asyncio
import inquirer
import datetime
import configparser
from typing import Dict, List, Any, Tuple, Optional
from urllib.parse import urlencode, quote_plus

import aiohttp
import pyppeteer

# Constants
AWS_SAML_ENDPOINT = "https://signin.aws.amazon.com/saml"
AWS_CN_SAML_ENDPOINT = "https://signin.amazonaws.cn/saml"
AWS_GOV_SAML_ENDPOINT = "https://signin.amazonaws-us-gov.com/saml"
AZURE_AD_SSO = "autologon.microsoftazuread-sso.com"
WIDTH = 425
HEIGHT = 550
DELAY_ON_UNRECOGNIZED_PAGE = 1000
MAX_UNRECOGNIZED_PAGE_DELAY = 30 * 1000


class CLIError(Exception):
    """Custom exception for CLI errors."""
    pass


class AWSConfig:
    """Handles AWS configuration files."""

    def __init__(self):
        self.aws_dir = os.path.join(os.path.expanduser("~"), ".aws")
        self.config_file = os.environ.get(
            "AWS_CONFIG_FILE", os.path.join(self.aws_dir, "config")
        )
        self.credentials_file = os.environ.get(
            "AWS_SHARED_CREDENTIALS_FILE",
            os.path.join(self.aws_dir, "credentials"),
        )

    def load_config(self) -> configparser.ConfigParser:
        """Loads the AWS config file."""
        config = configparser.ConfigParser()
        config.read(self.config_file)
        return config

    def save_config(self, config: configparser.ConfigParser):
        """Saves the AWS config file."""
        os.makedirs(self.aws_dir, exist_ok=True)
        with open(self.config_file, "w") as f:
            config.write(f)

    def load_credentials(self) -> configparser.ConfigParser:
        """Loads the AWS credentials file."""
        credentials = configparser.ConfigParser()
        credentials.read(self.credentials_file)
        return credentials

    def save_credentials(self, credentials: configparser.ConfigParser):
        """Saves the AWS credentials file."""
        os.makedirs(self.aws_dir, exist_ok=True)
        with open(self.credentials_file, "w") as f:
            credentials.write(f)

    def get_profile_config(
        self, profile_name: str
    ) -> Optional[configparser.SectionProxy]:
        """Gets the configuration for a specific profile."""
        config = self.load_config()
        section_name = (
            "default" if profile_name == "default" else f"profile {profile_name}"
        )
        return config[section_name] if config.has_section(section_name) else None

    def set_profile_config(
        self, profile_name: str, values: Dict[str, str]
    ):
        """Sets the configuration for a specific profile."""
        config = self.load_config()
        section_name = (
            "default" if profile_name == "default" else f"profile {profile_name}"
        )
        if not config.has_section(section_name):
            config.add_section(section_name)
        for key, value in values.items():
            config.set(section_name, key, value)
        self.save_config(config)

    def get_profile_credentials(
        self, profile_name: str
    ) -> Optional[configparser.SectionProxy]:
        """Gets the credentials for a specific profile."""
        credentials = self.load_credentials()
        return credentials[profile_name] if credentials.has_section(
            profile_name
        ) else None

    def set_profile_credentials(
        self, profile_name: str, values: Dict[str, str]
    ):
        """Sets the credentials for a specific profile."""
        credentials = self.load_credentials()
        if not credentials.has_section(profile_name):
            credentials.add_section(profile_name)
        for key, value in values.items():
            credentials.set(profile_name, key, value)
        self.save_credentials(credentials)

    def is_profile_about_to_expire(self, profile_name: str) -> bool:
        """Checks if the credentials for a profile are about to expire."""
        credentials = self.get_profile_credentials(profile_name)
        if credentials is None or "aws_expiration" not in credentials:
            return True
        expiration_date = datetime.datetime.fromisoformat(
            credentials["aws_expiration"]
        )
        time_difference = expiration_date - datetime.datetime.now()
        return time_difference.total_seconds() < 600  # Refresh if less than 10 minutes


async def _create_login_url(
    app_id_uri: str,
    tenant_id: str,
    assertion_consumer_service_url: str,
) -> str:
    """Creates the Azure login SAML URL."""
    saml_request = f"""<samlp:AuthnRequest xmlns="urn:oasis:names:tc:SAML:2.0:metadata" ID="id{uuid.uuid4()}" Version="2.0" IssueInstant="{datetime.datetime.utcnow().isoformat()}Z" IsPassive="false" AssertionConsumerServiceURL="{assertion_consumer_service_url}" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
        <Issuer xmlns="urn:oasis:names:tc:SAML:2.0:assertion">{app_id_uri}</Issuer>
        <samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"></samlp:NameIDPolicy>
    </samlp:AuthnRequest>"""

    deflated_saml = zlib.compress(saml_request.encode("utf-8"))
    saml_base64 = base64.b64encode(deflated_saml).decode("utf-8")
    return f"https://login.microsoftonline.com/{tenant_id}/saml2?SAMLRequest={quote_plus(saml_base64)}"


async def _perform_login(
    url: str,
    headless: bool,
    disable_sandbox: bool,
    cli_proxy: bool,
    no_prompt: bool,
    enable_chrome_network_service: bool,
    default_username: Optional[str],
    default_password: Optional[str],
    enable_chrome_seamless_sso: bool,
    remember_me: bool,
    no_disable_extensions: bool,
    disable_gpu: bool,
    puppeteer_no_verify_ssl: bool,
) -> str:
    """Performs the login using Chrome."""
    browser_args = []

    if headless:
        browser_args.extend(["--headless", "--disable-gpu"])
    else:
        browser_args.extend(
            [
                f"--app={url}",
                f"--window-size={WIDTH},{HEIGHT}",
            ]
        )

    if disable_sandbox:
        browser_args.append("--no-sandbox")

    if enable_chrome_network_service:
        browser_args.append("--enable-features=NetworkService")

    if enable_chrome_seamless_sso:
        browser_args.extend(
            [
                f"--auth-server-whitelist={AZURE_AD_SSO}",
                f"--auth-negotiate-delegate-whitelist={AZURE_AD_SSO}",
            ]
        )

    if remember_me:
        browser_args.append(f"--user-data-dir={os.path.join(os.path.expanduser('~'), '.aws', 'chromium')}")
        os.makedirs(os.path.dirname(browser_args[-1]), exist_ok=True)

    if "https_proxy" in os.environ:
        browser_args.append(f"--proxy-server={os.environ['https_proxy']}")

    if no_disable_extensions:
        browser_args.append("--disable-extensions")

    if disable_gpu:
        browser_args.append("--disable-gpu")

    browser = await pyppeteer.launch(
        ignoreHTTPSErrors=puppeteer_no_verify_ssl,
        headless=headless,
        args=browser_args,
    )
    page = await browser.newPage()
    await page.setExtraHTTPHeaders({"Accept-Language": "en"})
    await page.setViewport({"width": WIDTH - 15, "height": HEIGHT - 35})

    saml_response = None

    async def request_handler(req: pyppeteer.network_manager.Request):
        if (
            req.url == AWS_SAML_ENDPOINT
            or req.url == AWS_GOV_SAML_ENDPOINT
            or req.url == AWS_CN_SAML_ENDPOINT
        ):
            nonlocal saml_response
            saml_response = req.postData["SAMLResponse"]
            await req.respond(
                {
                    "status": 200,
                    "contentType": "text/plain",
                    "headers": {},
                    "body": "",
                }
            )
            await browser.close()
        else:
            await req.continue_()

    page.on("request", lambda req: asyncio.create_task(request_handler(req)))

    await page.goto(url, waitUntil="domcontentloaded")

    if cli_proxy:
        total_unrecognized_delay = 0
        while True:
            if saml_response is not None:
                break

            found_state = False
            for state in states:
                try:
                    selected = await page.querySelector(state["selector"])
                    if selected is not None:
                        found_state = True
                        await state["handler"](
                            page,
                            no_prompt,
                            default_username,
                            default_password,
                            remember_me,
                        )
                        break
                except Exception as e:
                    print(
                        f"Error when running state \"{state['name']}\". {e}. Retrying..."
                    )
                    break

            if found_state:
                total_unrecognized_delay = 0
            else:
                print("State not recognized!")
                total_unrecognized_delay += DELAY_ON_UNRECOGNIZED_PAGE
                if total_unrecognized_delay > MAX_UNRECOGNIZED_PAGE_DELAY:
                    screenshot_path = "aws-azure-login-unrecognized-state.png"
                    await page.screenshot({"path": screenshot_path})
                    raise CLIError(
                        f"Unable to recognize page state! A screenshot has been dumped to {screenshot_path}. If this problem persists, try running with --mode=gui or --mode=debug"
                    )
                await asyncio.sleep(DELAY_ON_UNRECOGNIZED_PAGE / 1000)

    else:
        print("Please complete the login in the opened window")
        while saml_response is None:
            await asyncio.sleep(1)

    return str(saml_response)


async def _handle_username_input(
    page: pyppeteer.page.Page,
    no_prompt: bool,
    default_username: Optional[str],
    _: Optional[str],
    __: bool,
):
    """Handles the username input state."""
    error = await page.querySelector(".alert-error")
    if error is not None:
        error_message = await page.evaluate("(el) => el.textContent", error)
        print(f"Error: {error_message}")

    username = default_username
    if not no_prompt:
        username = inquirer.prompt(
            [
                {
                    "type": "input",
                    "name": "username",
                    "message": "Username:",
                    "default": default_username,
                }
            ]
        ).get("username")

    await page.waitForSelector("input[name='loginfmt']", visible=True)
    await page.focus("input[name='loginfmt']")
    await page.keyboard.type(str(username))
    await page.click("input[type=submit]")


async def _handle_password_input(
    page: pyppeteer.page.Page,
    no_prompt: bool,
    _: Optional[str],
    default_password: Optional[str],
    __: bool,
):
    """Handles the password input state."""
    error = await page.querySelector(".alert-error")
    if error is not None:
        error_message = await page.evaluate("(el) => el.textContent", error)
        print(f"Error: {error_message}")

    password = default_password
    if not no_prompt:
        password = inquirer.prompt(
            [
                {
                    "type": "password",
                    "name": "password",
                    "message": "Password:",
                }
            ]
        ).get("password")

    await page.waitForSelector(
        "input[name='Password'], input[name='passwd']", visible=True
    )
    await page.focus("input[name='Password'], input[name='passwd']")
    await page.keyboard.type(str(password))
    await page.click("span[class=submit], input[type=submit]")


async def _handle_tfa_code_input(
    page: pyppeteer.page.Page,
    no_prompt: bool,
    _: Optional[str],
    __: Optional[str],
    ___: bool,
):
    """Handles the TFA code input state."""
    error = await page.querySelector(".alert-error")
    if error is not None:
        error_message = await page.evaluate("(el) => el.textContent", error)
        print(f"Error: {error_message}")
    else:
        description = await page.querySelector("#idDiv_SAOTCC_Description")
        description_message = await page.evaluate(
            "(el) => el.textContent", description
        )
        print(description_message)

    verification_code = inquirer.prompt(
        [
            {
                "type": "input",
                "name": "verification_code",
                "message": "Verification Code:",
            }
        ]
    ).get("verification_code")

    await page.waitForSelector("input[name='otc']", visible=True)
    await page.focus("input[name='otc']")
    await page.keyboard.type(str(verification_code))
    await page.click("input[type=submit]")


async def _handle_remember_me(
    page: pyppeteer.page.Page,
    _: bool,
    __: Optional[str],
    ___: Optional[str],
    remember_me: bool,
):
    """Handles the "Remember me" checkbox."""
    if remember_me:
        await page.click("#idSIButton9")  # Click "Yes"
    else:
        await page.click("#idBtn_Back")  # Click "No"


states = [
    {
        "name": "username input",
        "selector": "input[name='loginfmt']:not(.moveOffScreen)",
        "handler": _handle_username_input,
    },
    {
        "name": "password input",
        "selector": "input[name='Password']:not(.moveOffScreen),input[name='passwd']:not(.moveOffScreen)",
        "handler": _handle_password_input,
    },
    {
        "name": "TFA code input",
        "selector": "input[name=otc]:not(.moveOffScreen)",
        "handler": _handle_tfa_code_input,
    },
    {
        "name": "Remember me",
        "selector": "#KmsiDescription",
        "handler": _handle_remember_me,
    },
]


def _parse_roles_from_saml_response(saml_response: str) -> List[Dict[str, str]]:
    """Parses AWS roles out of the SAML response."""
    saml_text = base64.b64decode(saml_response).decode("utf-8")
    import xml.etree.ElementTree as ET

    root = ET.fromstring(saml_text)
    attributes = root.findall(
        ".//{urn:oasis:names:tc:SAML:2.0:assertion}Attribute"
    )
    roles = []
    for attribute in attributes:
        if attribute.get("Name") == "https://aws.amazon.com/SAML/Attributes/Role":
            for value in attribute.findall(
                "{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue"
            ):
                role, principal = value.text.split(",")
                roles.append(
                    {"roleArn": role.strip(), "principalArn": principal.strip()}
                )
    return roles


async def _ask_user_for_role_and_duration(
    roles: List[Dict[str, str]],
    no_prompt: bool,
    default_role_arn: Optional[str],
    default_duration_hours: Optional[str],
) -> Tuple[Dict[str, str], int]:
    """Asks the user for the role they want to use."""

    if len(roles) == 0:
        raise CLIError("No roles found in SAML response.")

    role = None
    if len(roles) == 1:
        role = roles[0]
    elif no_prompt and default_role_arn:
        role = next((r for r in roles if r["roleArn"] == default_role_arn), None)
    else:
        role_choices = [
            {"name": r["roleArn"], "value": r} for r in roles
        ]
        question = {
            "type": "list",
            "name": "role",
            "message": "Role:",
            "choices": role_choices,
        }
        if default_role_arn:
            question["default"] = next(
                (
                    i
                    for i, r in enumerate(role_choices)
                    if r["value"]["roleArn"] == default_role_arn
                ),
                0,
            )
        answers = inquirer.prompt([question])
        role = answers["role"]

    if role is None:
        raise CLIError("No role selected.")

    duration_hours = default_duration_hours
    if not no_prompt:
        duration_hours = inquirer.prompt(
            [
                {
                    "type": "input",
                    "name": "duration_hours",
                    "message": "Session Duration Hours (up to 12):",
                    "default": default_duration_hours or "1",
                    "validate": lambda x: x.isdigit() and 1 <= int(x) <= 12,
                }
            ]
        ).get("duration_hours")

    return role, int(str(duration_hours))


async def _assume_role(
    profile_name: str,
    assertion: str,
    role: Dict[str, str],
    duration_hours: int,
    aws_no_verify_ssl: bool,
    region: Optional[str],
):
    """Assumes the role."""
    async with aiohttp.ClientSession() as session:
        params = {
            "Action": "AssumeRoleWithSAML",
            "Version": "2011-06-15",
            "DurationSeconds": duration_hours * 60 * 60,
            "SAMLAssertion": assertion,
            "PrincipalArn": role["principalArn"],
            "RoleArn": role["roleArn"],
        }
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        endpoint = f"https://sts.{'amazonaws.com.cn' if region and region.startswith('cn-') else 'amazonaws.com'}/"
        async with session.post(
            endpoint, data=urlencode(params), headers=headers, ssl=not aws_no_verify_ssl
        ) as response:
            if response.status != 200:
                raise CLIError(
                    f"Failed to assume role: {response.status} {await response.text()}"
                )
            response_json = await response.json()
            credentials = response_json["AssumeRoleWithSAMLResponse"][
                "AssumeRoleWithSAMLResult"
            ]["Credentials"]
            config = AWSConfig()
            config.set_profile_credentials(
                profile_name,
                {
                    "aws_access_key_id": credentials["AccessKeyId"],
                    "aws_secret_access_key": credentials["SecretAccessKey"],
                    "aws_session_token": credentials["SessionToken"],
                    "aws_expiration": credentials["Expiration"],
                },
            )


async def login(
    profile_name: str,
    mode: str = "cli",
    disable_sandbox: bool = False,
    no_prompt: bool = False,
    enable_chrome_network_service: bool = False,
    aws_no_verify_ssl: bool = False,
    enable_chrome_seamless_sso: bool = False,
    force_refresh: bool = False,
    no_disable_extensions: bool = False,
    disable_gpu: bool = False,
    puppeteer_no_verify_ssl: bool = False,
):
    """Logs in to AWS using an Azure profile."""
    config = AWSConfig()

    if (
        not force_refresh
        and not config.is_profile_about_to_expire(profile_name)
    ):
        print(f"Profile '{profile_name}' not yet due for refresh.")
        return

    profile = config.get_profile_config(profile_name)
    if profile is None:
        raise CLIError(
            f"Unknown profile '{profile_name}'. You must configure it first with --configure."
        )

    if "azure_tenant_id" not in profile or "azure_app_id_uri" not in profile:
        raise CLIError(f"Profile '{profile_name}' is not configured properly.")

    assertion_consumer_service_url = AWS_SAML_ENDPOINT
    if profile.get("region", "").startswith("us-gov"):
        assertion_consumer_service_url = AWS_GOV_SAML_ENDPOINT
    if profile.get("region", "").startswith("cn-"):
        assertion_consumer_service_url = AWS_CN_SAML_ENDPOINT

    login_url = await _create_login_url(
        profile["azure_app_id_uri"],
        profile["azure_tenant_id"],
        assertion_consumer_service_url,
    )

    if mode not in ["cli", "gui", "debug"]:
        raise CLIError("Invalid mode")

    headless = mode == "cli"
    cli_proxy = mode in ["cli", "debug"]

    saml_response = await _perform_login(
        login_url,
        headless,
        disable_sandbox,
        cli_proxy,
        no_prompt,
        enable_chrome_network_service,
        profile.get("azure_default_username"),
        profile.get("azure_default_password"),
        enable_chrome_seamless_sso,
        profile.get("azure_default_remember_me", "false").lower() == "true",
        no_disable_extensions,
        disable_gpu,
        puppeteer_no_verify_ssl,
    )
    roles = _parse_roles_from_saml_response(saml_response)
    (
        role,
        duration_hours,
    ) = await _ask_user_for_role_and_duration(
        roles,
        no_prompt,
        profile.get("azure_default_role_arn"),
        profile.get("azure_default_duration_hours"),
    )
    await _assume_role(
        profile_name,
        saml_response,
        role,
        duration_hours,
        aws_no_verify_ssl,
        profile.get("region"),
    )


async def configure_profile(profile_name: str):
    """Configures a new profile."""
    print(f"Configuring profile '{profile_name}'")

    config = AWSConfig()
    profile = config.get_profile_config(profile_name)

    questions = [
        {
            "type": "input",
            "name": "azure_tenant_id",
            "message": "Azure Tenant ID:",
            "validate": lambda x: len(x) > 0,
            "default": profile.get("azure_tenant_id") if profile else None,
        },
        {
            "type": "input",
            "name": "azure_app_id_uri",
            "message": "Azure App ID URI:",
            "validate": lambda x: len(x) > 0,
            "default": profile.get("azure_app_id_uri") if profile else None,
        },
        {
            "type": "input",
            "name": "azure_default_username",
            "message": "Default Username:",
            "default": profile.get("azure_default_username")
            if profile
            else None,
        },
        {
            "type": "confirm",
            "name": "azure_default_remember_me",
            "message": "Stay logged in: skip authentication while refreshing aws credentials",
            "default": profile.get("azure_default_remember_me", "false").lower()
            == "true"
            if profile
            else False,
        },
        {
            "type": "input",
            "name": "azure_default_role_arn",
            "message": "Default Role ARN (if multiple):",
            "default": profile.get("azure_default_role_arn")
            if profile
            else None,
        },
        {
            "type": "input",
            "name": "azure_default_duration_hours",
            "message": "Default Session Duration Hours (up to 12):",
            "default": profile.get("azure_default_duration_hours") or "1"
            if profile
            else "1",
            "validate": lambda x: x.isdigit() and 1 <= int(x) <= 12,
        },
        {
            "type": "input",
            "name": "region",
            "message": "AWS Region:",
            "default": profile.get("region") if profile else None,
        },
    ]
    answers = inquirer.prompt(questions)
    config.set_profile_config(profile_name, answers)
    print("Profile saved.")


async def main():
    """Main function."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Log in to AWS using Azure AD credentials."
    )
    parser.add_argument(
        "-p",
        "--profile",
        default=os.environ.get("AWS_PROFILE", "default"),
        help="The name of the profile to use.",
    )
    parser.add_argument(
        "-a",
        "--all-profiles",
        action="store_true",
        help="Run for all configured profiles",
    )
    parser.add_argument(
        "-f",
        "--force-refresh",
        action="store_true",
        help="Force a credential refresh, even if they are still valid.",
    )
    parser.add_argument(
        "-c",
        "--configure",
        action="store_true",
        help="Configure a new profile.",
    )
    parser.add_argument(
        "-m",
        "--mode",
        default="cli",
        choices=["cli", "gui", "debug"],
        help="The login mode to use. 'cli' for CLI interaction, 'gui' for GUI interaction, 'debug' for visible GUI with CLI interaction.",
    )
    parser.add_argument(
        "--no-sandbox",
        action="store_true",
        help="Disable the Puppeteer sandbox.",
    )
    parser.add_argument(
        "--no-prompt",
        action="store_true",
        help="Do not prompt for input, use default values.",
    )
    parser.add_argument(
        "--enable-chrome-network-service",
        action="store_true",
        help="Enable Chromium's Network Service.",
    )
    parser.add_argument(
        "--no-verify-ssl",
        action="store_true",
        help="Disable SSL verification for AWS CLI requests.",
    )
    parser.add_argument(
        "--enable-chrome-seamless-sso",
        action="store_true",
        help="Enable Chromium's seamless SSO.",
    )
    parser.add_argument(
        "--no-disable-extensions",
        action="store_true",
        help="Do not disable Chromium extensions.",
    )
    parser.add_argument(
        "--disable-gpu",
        action="store_true",
        help="Disable GPU acceleration in Chromium.",
    )
    parser.add_argument(
        "--no-verify-ssl-puppeteer",
        action="store_true",
        help="Disable SSL verification for Puppeteer requests.",
    )

    args = parser.parse_args()

    if args.configure:
        await configure_profile(args.profile)
    elif args.all_profiles:
        config = AWSConfig()
        profiles = config.load_config().sections()
        profiles = [p.replace("profile ", "") for p in profiles if "profile " in p]
        for profile in profiles:
            try:
                await login(
                    profile,
                    args.mode,
                    args.no_sandbox,
                    args.no_prompt,
                    args.enable_chrome_network_service,
                    args.no_verify_ssl,
                    args.enable_chrome_seamless_sso,
                    args.force_refresh,
                    args.no_disable_extensions,
                    args.disable_gpu,
                    args.no_verify_ssl_puppeteer,
                )
                print(f"Successfully logged in to profile '{profile}'.")
            except CLIError as e:
                print(f"Error logging in to profile '{profile}': {e}")
                sys.exit(1)
    else:
        try:
            await login(
                args.profile,
                args.mode,
                args.no_sandbox,
                args.no_prompt,
                args.enable_chrome_network_service,
                args.no_verify_ssl,
                args.enable_chrome_seamless_sso,
                args.force_refresh,
                args.no_disable_extensions,
                args.disable_gpu,
                args.no_verify_ssl_puppeteer,
            )
            print(f"Successfully logged in to profile '{args.profile}'.")
        except CLIError as e:
            print(f"Error logging in: {e}")
            sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())

```

**Explanation:**

1. **Imports:** The code begins by importing necessary libraries for handling configuration files, asynchronous operations, web scraping, user input, and more.
2. **Constants:**  Defines constants for AWS endpoints, Azure SSO domain, and browser window size.
3. **`CLIError` Exception:** A custom exception class for handling CLI-specific errors.
4. **`AWSConfig` Class:** 
   - This class encapsulates all interactions with AWS config and credential files. 
   - It provides methods for loading, saving, getting, and setting profile configurations and credentials. 
   - The code now uses standard `configparser` for managing INI files.
5. **Helper Functions:**
   - `_create_login_url`: Constructs the Azure AD SAML login URL, encoding the SAML request.
   - `_perform_login`:  Manages the browser interaction for login:
     - Launches a Chromium instance using `pyppeteer`.
     - Sets browser arguments based on provided options (headless, sandbox, network service, etc.).
     - Intercepts the SAML response, preventing redirection to AWS.
     - Handles user interaction (username, password, MFA) if `cli_proxy` is enabled.
   - `_parse_roles_from_saml_response`: Extracts available AWS roles from the received SAML response.
   - `_ask_user_for_role_and_duration`: Prompts the user to choose a role (if multiple are available) and specify session duration.
   - `_assume_role`: Makes an API call to AWS STS to assume the chosen role and stores the temporary credentials in the AWS credentials file.

6. **`states` List:** This list defines the different states the login process can be in and their corresponding handlers. Each state has a selector to identify it on the page and a handler function to perform the appropriate actions.

7. **`login` Function:** 
   - This is the core function that orchestrates the entire login flow.
   - It loads the profile, constructs the login URL, performs the login (using `_perform_login`), parses the SAML response, asks the user for role selection, and finally assumes the role.

8. **`configure_profile` Function:** Guides the user through setting up a new profile by asking for required information (tenant ID, app ID URI, etc.) and saves it to the AWS config file.

9. **`main` Function:** 
   - Parses command-line arguments using `argparse`.
   - Calls `configure_profile` or `login` based on the arguments.
   - Handles errors during configuration or login.


**Improvements in the Python code:**

- **Readability and Structure:**  The code is reorganized into functions and a class for better readability and maintainability.
- **Error Handling:** More robust error handling with the `CLIError` exception and try-except blocks.
- **Configuration Management:** The `AWSConfig` class provides a cleaner way to interact with AWS configuration.
- **Asynchronous Operations:**  Uses `asyncio` and `aiohttp` for asynchronous HTTP requests, making the code more efficient.
- **Clearer Logic:** The separation of concerns into functions makes the code's logic easier to understand.

**Note:** This code assumes you have the necessary Python libraries installed. You can install them using: 

```bash
pip install pyppeteer aiohttp inquirer configparser
```

This revised Python code offers a more structured, readable, and efficient solution compared to the original TypeScript code.
