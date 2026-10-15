# Release provenance and verification

The first distribution is the self-hosted Python alpha, `0.1.0a1`. Its version has
one source, `src/mcp_auth_bridge/_version.py`; Hatchling and the runtime read it.
The Git tag must be the same version prefixed by `v`. Package metadata, imported
version, wheel, and source-distribution metadata must agree.

## Build and verify locally

From a checkout with `uv` and the requested Python interpreter available:

```sh
uv run python -m scripts.verify_release --python 3.12
uv run python -m scripts.verify_release --python 3.10 --output-dir dist/release-310 --report artifacts/release-310.json
```

The verifier builds an allow-listed sdist and wheel, checks names, metadata,
licenses, and the typed-package marker, and rebuilds the wheel from the sdist in
a temporary directory. A matching wheel SHA-256 is required. It then installs the
rebuilt wheel with runtime dependencies into a new environment outside the checkout,
constructs the app, checks the three public exports, and exercises `check-config`
and `print-metadata`. No server, browser, or container is started.

The output contains the wheel, sdist, `runtime-requirements.txt`,
`runtime-sbom.cdx.json`, `release-manifest.json`, and `SHA256SUMS`. The CycloneDX
inventory records the packages actually installed for that Python/platform verification; it is not a
universal lock or a vulnerability result. Runtime requirements remain ranges,
so future installations may resolve differently. The manifest records the revision,
dirty-source flag, version, checks, and artifact digests. A dirty-source local result is useful for development
but cannot be published as release evidence. The report and local build information
are not cryptographic attestations.

The sdist deliberately includes the runtime package, packaging metadata, license
notices, and selected public documentation. Demos and tests are available from
the source repository but are not bundled into the runtime package. Research
notes, machine handoffs, hosted experiments, caches, credentials, and generated
evidence are excluded from the public release snapshot and its distributions.

## Publication gate

This public release starts from a sanitized source snapshot with fresh history.
The original development history and research remain private. Review every file,
commit, candidate Actions log/artifact, attribution, license notice, and personal
path before publication. Rotate any discovered credentials before cleaning their
history. Preserve a private recovery bundle. A clean current tree does not prove a
safe history. Enable private vulnerability reporting, dependency alerts, and the
intended branch/tag protections. Confirm no paid feature is required.

Publication is a manual GitHub release operation. There is no PyPI publishing job,
package-index upload, required-reviewer environment, or paid feature prerequisite.
The maintainer reviews the candidate and its evidence before dispatching the
`Release` workflow on the matching version tag. Preparing artifacts is separate
from explicitly requesting publication.

Before the workflow may create a prerelease, it must establish that:

- The version tag resolves to the selected source revision and agrees with package
  metadata; the release source is clean.
- The complete `CI` and `Security` workflows passed for that exact commit in the
  public repository. A previous development run or another revision is insufficient.
- Source/history and candidate logs/artifacts have been reviewed for credentials,
  personal data, generated evidence, and licensing issues.
- The wheel and sdist pass the release verifier, including rebuilding from the
  sdist and installing outside the checkout with runtime dependencies only.
- Release notes identify tested versions, recorded native-client evidence,
  limitations, and the public checks for the tagged revision.

Pull-request jobs receive no release credentials. The publishing workflow uses
GitHub's short-lived workflow identity for attestations and the permissions needed
to attach verified artifacts to the GitHub prerelease. It does not rebuild those
artifacts in a separate publishing job. Once published, test the downloaded wheel
again outside the checkout and record the public release and verification links.

The public release workflow is required to produce GitHub/Sigstore build
provenance and SBOM attestations. Their presence is verified after the release
workflow succeeds; this document alone does not assert that a release exists.
Download all checksum-listed assets from the same versioned release, then verify:

```sh
gh attestation verify mcp_auth_bridge-0.1.0a1-py3-none-any.whl --repo anilpervaiz/mcp-auth-bridge
shasum -a 256 -c SHA256SUMS
```

Checksums detect changed bytes when the checksum file is trusted; attestations
bind artifacts to the publishing workflow identity. Neither proves code safety.
Attestations are available for public repositories on GitHub Free; private
preparation does not claim them. See [GitHub's attestation documentation](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations).

## Publication status and package indexes

`0.1.0a1` is the initial release candidate. Public release status is established
by the matching [GitHub release](https://github.com/anilpervaiz/mcp-auth-bridge/releases)
and its public workflow results, not by this version number or a local build.
At snapshot preparation, public CI, attestations, and release download verification
remain unverified until executed. Record those results in the release notes.

PyPI and TestPyPI publication are deferred. No Trusted Publisher, index credential,
or index installation is required for this alpha; install the reviewed GitHub
release wheel or use the source checkout.
