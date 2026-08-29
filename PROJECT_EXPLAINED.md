# Project Explained Simply

## What Is This?

Vault is a small password security wallet that runs on your own computer. It opens a web page in your browser, but the server is written in one Python file.

It helps you:

- Create a protected local vault
- Generate strong passwords
- Check password strength while typing
- Organize entries by category
- Search and edit entry information
- Verify a password without revealing the saved password

## How Do I Run It?

Open a terminal in the project folder and run:

```text
python password_wallet.py
```

Then open `http://localhost:5743` in a browser. Python's built-in `http.server` provides the local website, and `ThreadingHTTPServer` can handle multiple local requests.

## What Happens When I Create the Vault?

1. You enter a master password.
2. The program runs that password through PBKDF2-HMAC-SHA256 many times.
3. It stores only the resulting verifier in `wallet.json`.
4. The original master password is never saved.

When you unlock the vault later, the program reads the stored salt, repeats the calculation, and compares the result. If the results match, the vault opens.

## What Happens When I Save an Entry?

1. You enter a password or generate one.
2. The browser sends it to the local Python server.
3. Python creates a salted, one-way PBKDF2 verifier.
4. The original password is discarded after the request.
5. `wallet.json` keeps the verifier, password length, and non-secret details such as title, username, URL, notes, and category.

A verifier is like a test result. It can tell the program whether a future password matches, but it cannot be used by this app to display the original password.

## Why Is There a Verify Button?

Because saved passwords are not recoverable, the app cannot show them again. The **Verify** button lets you enter a password you already know and checks it against the saved verifier.

The server returns only one answer:

- `true`: the password matches
- `false`: the password does not match

The verifier itself is not sent to the browser.

## What Is Stored on Disk?

The local `wallet.json` file contains:

- A verifier for the master password
- Entry titles and other metadata
- Salted password verifiers
- Password lengths

It does not contain the original entry passwords.

Every save replaces `wallet.json` atomically. This means a complete temporary file is written first, then moved into place, reducing the chance of a half-written vault after an interruption. Files from the older encrypted format are rejected with a clear migration message.

Do not put real production passwords into this educational project. Use fake data for demonstrations and testing.

## How Is the Project Dependency-Free?

The project does not install packages. It uses Python features that are already included with Python:

- `http.server` creates the local web server
- `json` stores structured data
- `hashlib` creates PBKDF2 verifiers
- `hmac` performs safe digest comparisons
- `secrets` generates salts and passwords
- `unittest` runs the tests
- Browser-native HTML, CSS, and JavaScript create the interface

The empty `requirements.txt` proves that no third-party Python package is required.

## How Is It Tested?

Run:

```text
python -m unittest discover -s tests -v
```

The tests check password verification, malformed input, master-password hashing, password generation, file storage, legacy-file detection, and the HTTP API lifecycle.

The live server can also be tested manually by creating a vault, adding an entry, verifying correct and incorrect passwords, editing metadata, locking, and unlocking again.

## Important Limitation

This wallet intentionally uses one-way password verification instead of encryption. That follows the project's zero-dependency and no-custom-cryptography direction, but it means the app cannot recover a saved password after it has been discarded.

This is a learning and hackathon project, not a replacement for a professionally reviewed password manager.
