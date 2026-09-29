# StellicAuth

Log into Princeton's [Stellic](https://stellic.princeton.edu/) from the command line and get the session cookies, without a browser.

The script does the full sign-in over plain HTTP:

1. It follows Stellic's SAML redirect to Princeton CAS (`fed.princeton.edu`) and submits your netid and password.
2. It uses the Duo Universal Prompt's API to send a Duo Push to your phone.
3. After you approve the push, it finishes the Duo → CAS → SAML redirects back to Stellic.
4. It saves the Stellic session cookies to a JSON file. It also reads your current semester's courses back as a check that the session works.

## Requirements

- Python 3
- `requests`

```sh
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Usage

```sh
python stellic_login.py [netid] [-o OUTPUT] [--timeout SECONDS]
```

| Option | Default | Description |
| --- | --- | --- |
| `netid` | prompted | Your Princeton netid |
| `-o`, `--output` | `stellic_cookies.json` | Where to write the cookies |
| `--timeout` | `30` | HTTP and push-approval timeout, in seconds |

The script always asks for your password interactively and never echoes it. It is not accepted as an argument.

### Example

```text
$ python stellic_login.py jdoe
Password:
Signing in to CAS...
Duo Push sent to iPhone.
Approve it on your phone, then press Enter...
Saved 3 Stellic cookies to stellic_cookies.json
Cookie header:
<name>=<value>; ...

Current semester courses (4):
  COS 226       1 u  Algorithms and Data Structures
  ...
```

If Duo shows a verification code, the script prints it next to the push message. Type that code into the Duo app when you approve.

## Output

`stellic_cookies.json` is a list of cookie objects:

```json
[
  {
    "name": "...",
    "value": "...",
    "domain": "stellic.princeton.edu",
    "path": "/",
    "expires": 1234567890,
    "secure": true
  }
]
```

The script also prints the cookies as a ready-to-use `Cookie:` header value. For example:

```sh
curl -H "Cookie: <header from script>" https://stellic.princeton.edu/...
```

## Using it from Python

```python
from stellic_login import StellicLogin

login = StellicLogin("jdoe", "password", timeout=30)
device, code = login.start()   # sends the Duo push
input(f"Approve the push on {device}, then press Enter")
cookies = login.finish()       # list of cookie dicts
courses = login.current_courses()

# login.session is an authenticated requests.Session
r = login.session.get("https://stellic.princeton.edu/")
```

`start()` and `finish()` raise `StellicLoginError` if a step of the login fails. Network errors come through as `requests.RequestException`.

## Security

The cookie file is a live login to your Stellic account. Treat it like a password.

`.gitignore` already excludes `stellic_cookies.json`, any `*cookies*.json` file, and `*.har` captures. HAR files hold your credentials in plain text. Never commit them.
