# Security

Bisel holds passwords, so security reports are the most useful thing you can send. Thank you for looking.

## Reporting a vulnerability

Report privately through GitHub: [open a security advisory](https://github.com/handlemotion/bisel/security/advisories/new) (the repo's Security tab, "Report a vulnerability"). Please don't open a public issue, pull request or discussion for anything you think could be exploited.

Include what you found, where (file and line, or the request), how to reproduce it, and what an attacker gains. A proof of concept against a local build is welcome. You'll get an answer within a week. Bisel is maintained by one person, so a fix can take longer; you'll hear how it's going, and you'll be credited in the advisory unless you'd rather not be.

## In scope

- The Mac app and `BiselCore` (`apps/mac`): cryptography, key handling, the Secure Enclave and keychain use, the local store, sync and conflict handling, recovery and backup files, import, autofill and clipboard handling.
- Anything that lets a sync lane (CloudKit or the server) read, forge, roll back, replay or silently drop box contents, or that breaks the zero-knowledge model in [docs/SPEC.md](docs/SPEC.md) §4.
- The server (`apps/server`): request signing, tenancy between boxes, the dashboard and passkey sign-in, rate limits. The server is deferred but still maintained for security.
- Secrets or credentials committed to this repository.

Known, accepted issues are listed in [docs/SECURITY-REVIEW.md](docs/SECURITY-REVIEW.md); a new way to exploit one of them is still in scope.

## What the Chrome extension exposes

The Chrome extension can see passwords as you type them: to offer to save a login it reads the form you submit, on every https site, in the browser, outside the box and outside Touch ID. Anyone who controls the extension, for example through a malicious update, could take every password you type in Chrome. Install it only if you accept that, and install only Bisel's. It does not run in private windows or in frames from another site. A password it is holding stays in Chrome's memory, never on disk, until you answer or for 2 minutes at most.

The link back to Bisel is write-only. The extension asks the app to save a login, and the app does that only after Touch ID, which shows the username and site. Replacing a password takes your choice of Update and keeps the old version in the local trash for 30 days. No message reads a password, an item, a title or a list.

It does tell one thing about what is stored: whether a site and username are in the box, and whether a given password is the stored one. Bisel needs that to stay quiet when you sign in normally, and to offer Save or Update. A compromised extension, or any program running as you (it can run the signed host just as Chrome does; the extension ID pinned in the manifest is no barrier to that, and neither is the signature check), could use this to test guesses without Touch ID. So it is rationed: 3 wrong answers per login and 20 in all per hour while the app runs, and after that no answer says anything. Nothing is answered while the box is locked. The same program could also ask to save a login, and you would see a Touch ID prompt you did not expect. If you do, cancel it.

The signature checks on both ends of the socket are there so a password goes only to the real app, and so the app knows the prompt came through the real host. Touch ID is the access control.

## What AutoFill exposes

System AutoFill needs a list of what it may offer, and the system keeps that list (`ASCredentialIdentityStore`) as plaintext outside the box. While the box is unlocked it holds, for each login with a password: the site's host, the username and the item's random id; for each passkey, also its credential ID and the site's user handle, which are public identifiers; for each login with a one-time code, a second entry with the same host, username and id. It never holds a title, password, private key, note, one-time code or setup key. A process running as you, or someone with your unlocked Mac, may be able to read which sites you have logins on, under which usernames, and which of them use a one-time code. The list is emptied when the box locks, resets or quits; after a crash it stays until the next launch. Details are in [docs/SPEC.md](docs/SPEC.md) §8, "AutoFill".

The AutoFill extension itself holds no keys and cannot open the box. It gets one password or one one-time code at a time from the app, after Touch ID, and only for a login whose address matches the site. A code is made in the app, so the setup key never reaches the extension. For a passkey the app signs and returns the signature, after Touch ID and only for that passkey's exact site, so the private key never reaches the extension.

If you choose Bisel in "Set Up Codes In", `otpauth://` links open in Bisel. Any app or web page can send one, so a link only fills the new login form; nothing is saved until you save it.

## Please don't report

- Attacks that need an unlocked Mac in the attacker's hands, root or malware on the device, or a compromised Apple ID and its devices, unless Bisel makes them worse than the platform already does.
- Findings from automated scanners without a working impact, missing headers on pages that serve no user data, or version banners.
- Denial of service by volume against `box.bisel.app` or any other deployment. Don't load-test, scan or attack infrastructure you don't own; test against a local build (`pnpm dev`, see [apps/server/README.md](apps/server/README.md)).
- Social engineering, and anything that needs access to someone else's box or account.

## Supported versions

Bisel is alpha and has no releases yet. Only `main` is supported.
