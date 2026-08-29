# Standard Library Inventory

Vault has no third-party runtime or test dependencies. It uses only modules included with Python 3.7+.

| Module | Used for |
|---|---|
| `base64` | Encoding salted password verifier records for JSON storage |
| `hashlib` | PBKDF2-HMAC-SHA256 password verification |
| `hmac` | Constant-time comparison of password verifier digests |
| `http.server` | Local web server and request handler |
| `json` | Vault persistence and API request/response data |
| `os` | Checking whether `wallet.json` exists |
| `secrets` | Cryptographic salts, entry IDs, and password generation |
| `string` | Password generator character sets |
| `threading` | Opening the browser shortly after startup |
| `time` | Entry update dates |
| `unittest` | Test runner and assertions in `tests/test_password_wallet.py` |
| `urllib.parse` | Parsing request paths |
| `webbrowser` | Opening the local vault in the default browser |

## Dependency Proof

From a clean Python installation, these commands verify the project without installing packages:

```bash
python -m unittest discover -s tests -v
python -m py_compile password_wallet.py
python -c "import ast, pathlib; ast.parse(pathlib.Path('password_wallet.py').read_text(encoding='utf-8'))"
```

The repository includes an intentionally empty `requirements.txt` and has no package installation step. There is no `pyproject.toml` or `Pipfile`; the project is dependency-free by design.

## Package Substitution Log

| Normally used | Instead used | Purpose |
|---|---|---|
| Flask | `http.server` | Local HTTP server and routing |
| Requests | No outbound client dependency; `http.server` handles local requests | Local JSON API |
| SQLAlchemy | `json` | Small local persistent store |
| bcrypt | `hashlib.pbkdf2_hmac` | Slow password verification |
| cryptography | `hashlib.pbkdf2_hmac` | One-way password verifiers without custom encryption |
| pytest | `unittest` | Automated tests |
| Jinja2 | Embedded HTML template | Single-file UI delivery |
| JavaScript bundler | Browser-native JavaScript | Client-side interactions |
| clipboard.js | Browser Clipboard API | Copying usernames and URLs |
| Faker | `secrets` and `string` | Random password generation |
| gunicorn | `ThreadingHTTPServer` | Simple concurrent local serving |
| python-dotenv | `os` | Process and file environment access |

## Security Scope

The vault does not implement encryption. It uses PBKDF2-HMAC-SHA256 to create salted, one-way password verifiers. This prevents the app from recovering saved passwords and is not a replacement for a professionally reviewed password manager.
