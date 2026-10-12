# CI workflow security policy

Prism's CI is part of the trusted build boundary. The workflow must keep its behavior reviewable even when Cargo or Nix cannot start.

## Required policy

- Pin every external GitHub Action to the full 40-character commit SHA taken from that action's upstream repository.
- Retain the upstream release tag in a trailing comment (for example, `uses: owner/action@<full-sha> # v1.2.3`) so humans can audit and update pins.
- Pin container actions to an immutable `sha256` image digest.
- Declare the narrowest workflow-level token baseline. The ordinary build and test workflow currently needs only `contents: read`.
- Set `persist-credentials: false` for checkouts that do not push commits or create authenticated git operations.
- Keep policy tests independent from Cargo, Nix, and network access; run them before build/test jobs.
- Use explicit job timeouts so a stuck tool cannot consume a runner indefinitely.

## Verified action pins used by CI

The references below were resolved through the corresponding upstream Git tag reference endpoints and matched to those upstream release versions on 2026-10-11.

| Action | Version | Commit SHA |
|---|---|---|
| `actions/checkout` | `v7.0.1` | `3d3c42e5aac5ba805825da76410c181273ba90b1` |
| `actions/cache` | `v5.0.4` | `668228422ae6a00e4ad889ee87cd7109ec5666a7` |
| `cachix/install-nix-action` | `v31.10.6` | `8aa03977d8d733052d78f4e008a241fd1dbf36b3` |

Sources: [checkout v7.0.1](https://github.com/actions/checkout/releases/tag/v7.0.1), [cache v5.0.4](https://github.com/actions/cache/releases/tag/v5.0.4), and [install-nix-action v31.10.6](https://github.com/cachix/install-nix-action/releases/tag/v31.10.6). Cache v5 runs on Node.js 24 and requires a GitHub Actions runner at version 2.327.1 or newer; Prism uses GitHub-hosted `ubuntu-latest` runners.

## Local verification

Run the standard-library-only checks before relying on the CI result:

```sh
python3 scripts/test_workflow_security.py
python3 scripts/check_workflow_security.py
```

The guard intentionally fails closed if a workflow action is mutable, its release comment is absent, a Docker action lacks an immutable digest, the workflow has no action references, or the workflow-level permission baseline is anything other than `contents: read`.

This static check is a policy guard, not a full YAML parser, third-party action code audit, signature verifier, or proof that the referenced release is safe. Upstream owners, release signatures, commit identities, dependency changes, and changelogs still need review when a pin is updated.

## Updating action pins

1. Select a release from the action's canonical upstream repository, not a fork.
2. Resolve the tag to its full commit SHA using the upstream GitHub API, for example `GET /repos/actions/checkout/git/ref/tags/v7.0.1`.
3. Verify the returned commit belongs to that action repository and review the release/change notes and signature status.
4. Change the SHA and version comment together. Do not replace a pin with a major-version tag.
5. Run the policy unit tests and real workflow scan, then review the workflow diff and the checks run on that exact PR commit.

Dependabot is configured to propose GitHub Actions updates weekly. Its proposed changes must still pass the pin guard and receive human review.
