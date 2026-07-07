# Release signing key

Before tagging, generate the project key once on an offline trusted system:

```sh
minisign -G -p minisign.pub -s vaultlink-release.key
```

Commit the public key as `release/minisign.pub`. Store the complete private key only in the GitHub Actions secret `MINISIGN_SECRET_KEY`; store its password in `MINISIGN_PASSWORD`. Never place the private key in the repository, VM, release artifact, or logs. The release workflow intentionally fails when the public key or either secret is absent.
