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

## Please don't report

- Attacks that need an unlocked Mac in the attacker's hands, root or malware on the device, or a compromised Apple ID and its devices, unless Bisel makes them worse than the platform already does.
- Findings from automated scanners without a working impact, missing headers on pages that serve no user data, or version banners.
- Denial of service by volume against `box.bisel.app` or any other deployment. Don't load-test, scan or attack infrastructure you don't own; test against a local build (`pnpm dev`, see [apps/server/README.md](apps/server/README.md)).
- Social engineering, and anything that needs access to someone else's box or account.

## Supported versions

Bisel is alpha and has no releases yet. Only `main` is supported.
