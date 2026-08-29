# Five-Minute Demo Script

Use a clean temporary folder for the recording so no personal passwords appear on screen.

## 0:00-0:30: Project and dependency proof

Show the repository files and open `STDLIB.md`. Point out that the app is one Python file, the test suite is stdlib `unittest`, and `requirements.txt` is intentionally empty.

Run:

```bash
python -m unittest discover -s tests -v
```

Mention that all tests pass.

The expected result is `Ran 13 tests` followed by `OK`.

## 0:30-1:00: One-command launch

Run:

```bash
python password_wallet.py
```

Show the terminal URL and the browser opening at `http://localhost:5743`.

Capture the working interface for the README while the demo data is visible, using fake data only.

## 1:00-1:45: Create and unlock the vault

Create a memorable demo-only master password with at least six characters. Lock the vault, then unlock it again to show the verifier-based login flow.

## 1:45-3:00: Add an entry and generate a password

Click **+ Add**, enter a service name and username, then use the generator. Toggle character options, change the length, apply the generated password, and save the entry. Show the strength meter, category badge, verifier-only password record, and copy controls for non-secret fields.

## 3:00-4:00: Search, edit, and delete

Add a second demo entry. Search by title or username, open an entry, use **Verify** with the correct and incorrect demo passwords, edit its notes, and save. Open the delete confirmation, then cancel it to show the safety check.

## 4:00-4:30: One-way storage

Stop the server and open `wallet.json` in a text editor. Show that entries contain metadata and salted verifier strings, not plaintext passwords. Explain that saved passwords cannot be recovered by this app. Do not reveal the demo master password in the recording.

## 4:30-5:00: Integrity and close

Run the tests again, briefly show the wrong-password, malformed-request, and legacy-format tests. Show the empty `requirements.txt`, confirm `wallet.json` is ignored, and close with the repository checklist: public source, working implementation, one-command run, empty dependency manifest, dependency proof, `README.md`, `STDLIB.md`, tests, screenshot, and this demo script.
