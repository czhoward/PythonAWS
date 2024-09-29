Prompt: write comprehensive pytest test cases for the following code.  Pasted the code from manual updates.md

```python
import asyncio
import base64
import configparser
import json
import os
import subprocess
import sys
import time
import uuid
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, patch

import inquirer
import pytest
import playwright.async_api as playwright
from playwright.async_api import Page, Browser, BrowserContext, Request
from botocore.session import Session
from botocore.exceptions import ClientError as BotoClientError


# Mock inquirer for testing
class MockInquirer:
    def __init__(self, answers):
        self.answers = answers
        self.calls = 0

    def prompt(self, questions):
        self.calls += 1
        return self.answers

@pytest.fixture
def mock_inquirer():
    return MockInquirer({})

@pytest.fixture
def mock_playwright():
    # Create mock objects for Playwright components.  Using AsyncMock for async methods.
    mock_browser = AsyncMock(spec=Browser)
    mock_context = AsyncMock(spec=BrowserContext)
    mock_page = AsyncMock(spec=Page)
    mock_request = AsyncMock(spec=Request)

    mock_page.on = AsyncMock(return_value=None)
    mock_page.goto = AsyncMock(return_value=None)
    mock_page.url = "test_url"
    mock_page.query_selector = AsyncMock(side_effect = lambda selector: mock_page if selector == "input[name='loginfmt']:not(.moveOffScreen)" or selector == "input[name='Password']:not(.moveOffScreen)" else None)
    mock_page.query_selector_all = AsyncMock(return_value=[])
    mock_page.keyboard = AsyncMock()
    mock_page.keyboard.press = AsyncMock(return_value=None)
    mock_page.wait_for_load_state = AsyncMock(return_value=None)
    mock_request.post_data = b"SAMLResponse=test_saml_response"
    mock_page.on.return_value = AsyncMock(return_value=None)

    mock_browser.new_page = AsyncMock(return_value=mock_page)
    mock_browser.close = AsyncMock(return_value=None)

    return (mock_browser, mock_context, mock_page, mock_request)

# Mock AWS interaction
@pytest.fixture
def mock_aws_sts():
    mock_sts = AsyncMock()
    mock_sts.assume_role_with_saml = AsyncMock(return_value={'Credentials': {'AccessKeyId': 'test_access_key', 'SecretAccessKey': 'test_secret_key', 'SessionToken': 'test_session_token', 'Expiration': datetime.utcnow() + timedelta(hours=1)}})
    return mock_sts


# Test cases
@pytest.mark.asyncio
async def test_configure_profile(mock_inquirer, tmp_path):
    # Create a temporary config file
    config_path = tmp_path / '.aws' / 'config'
    config_path.parent.mkdir()
    config_path.touch()

    # Set up mock inquirer answers
    answers = {
        "tenant_id": "test_tenant_id",
        "app_id_uri": "test_app_id_uri",
        "username": "test_username",
        "remember_me": "True",
        "default_role_arn": "test_role_arn",
        "default_duration_hours": "2",
        "region": "test_region"
    }
    mock_inquirer.answers = answers


    with patch.object(inquirer, 'prompt', mock_inquirer.prompt):
        await configure_profile("test_profile")

    # Verify config file contents
    config = configparser.ConfigParser()
    config.read(str(config_path))
    assert config['profile test_profile']['azure_tenant_id'] == 'test_tenant_id'
    assert config['profile test_profile']['azure_app_id_uri'] == 'test_app_id_uri'
    assert config['profile test_profile']['azure_default_username'] == 'test_username'
    assert config['profile test_profile']['azure_default_role_arn'] == 'test_role_arn'
    assert config['profile test_profile']['azure_default_duration_hours'] == '2'
    assert config['profile test_profile']['azure_default_remember_me'] == 'True'
    assert config['profile test_profile']['region'] == 'test_region'


@pytest.mark.asyncio
async def test_login_successful(mock_inquirer, mock_playwright, mock_aws_sts, tmp_path):
    mock_browser, _, mock_page, mock_request = mock_playwright
    mock_page.query_selector.side_effect = lambda selector: mock_page if selector.startswith("input") else None # Handle both username & password selectors
    with patch.object(inquirer, 'prompt', mock_inquirer.prompt), \
         patch('__main__.playwright.async_playwright', return_value=AsyncMock(chromium=AsyncMock(launch=AsyncMock(return_value=mock_browser)))), \
         patch('__main__.Session.create_client', return_value=mock_aws_sts), \
         patch('__main__.get_aws_config_path', return_value=str(tmp_path / '.aws' / 'config')):
        # Set up config file (replace with a proper temp file mechanism)
        config = configparser.ConfigParser()
        config['default'] = {'azure_tenant_id': 'test_tenant_id', 'azure_app_id_uri': 'test_app_id_uri'}
        with open(tmp_path / '.aws' / 'config', 'w') as configfile:
            config.write(configfile)
        await login("default", no_prompt=True)


@pytest.mark.asyncio
async def test_login_no_roles(mock_inquirer, mock_playwright):
    mock_browser, _, mock_page, _ = mock_playwright
    mock_page.query_selector.side_effect = lambda selector: mock_page if selector.startswith("input") else None
    mock_page.query_selector_all.return_value = [] # Simulate no account selection
    with patch.object(inquirer, 'prompt', mock_inquirer.prompt), \
         patch('__main__.playwright.async_playwright', return_value=AsyncMock(chromium=AsyncMock(launch=AsyncMock(return_value=mock_browser)))), \
         patch('__main__.parse_roles_from_saml_response', return_value=[]):
         with pytest.raises(CLIError) as e:
             await login("default", no_prompt=True)
         assert "No roles found in the SAML response." in str(e.value)


@pytest.mark.asyncio
async def test_assume_role_error(mock_aws_sts):
    mock_aws_sts.assume_role_with_saml.side_effect = BotoClientError({'Error': {'Code': 'AccessDenied'}}, 'AssumeRoleWithSAML')
    with pytest.raises(BotoClientError):
        await assume_role("test", "test_saml", {"role_arn": "test_arn", "principal_arn": "test_principal"}, 1, None)


#Add more test cases covering other functions and error conditions (e.g., invalid input, file I/O errors, network errors) as needed.  Remember to mock appropriately.
```

To run these tests:

1.  **Install pytest and necessary libraries:**
    ```bash
    pip install pytest playwright boto3
    ```
2.  **Save the test code:** Save the code above as a file named `test_aws_azure_login.py` (or similar).
3.  **Run pytest:**
    ```bash
    pytest test_aws_azure_login.py
    ```

Remember to replace `"test_tenant_id"`, `"test_app_id_uri"`, etc., with appropriate test values.  The `tmp_path` fixture automatically creates and cleans up temporary directories for testing, avoiding conflicts with existing config files. The mocks ensure that external dependencies (inquirer, playwright, boto3) don't interfere with testing the core logic of your code.  You'll need to adjust the mocks if your actual implementation differs slightly.  Consider adding more tests to cover various edge cases and error handling.  For example, test scenarios with multiple roles, invalid SAML responses,  network issues during the browser interaction, and different prompt responses.
