# Supply-chain security & verifying released images

Every Mir[AI]ge service image published to GHCR on a `v*` tag is, before being
pushed, **scanned, then signed and attested** by the release pipeline
(`.github/workflows/ci.yml`):

- **Vulnerability gate** — Trivy scans the image and the release is blocked on
  any *fixable* `CRITICAL`/`HIGH` CVE.
- **SBOM** — a CycloneDX SBOM is generated (Syft) and attached to the image as a
  signed attestation.
- **Signature** — the image is signed keyless with [cosign]/Sigstore using the
  workflow's OIDC identity (no long-lived keys).
- **Provenance** — a SLSA build-provenance attestation is generated and pushed to
  the registry.

Images are referenced as `ghcr.io/<owner>/miraige-<service>` (e.g.
`miraige-api`, `miraige-sentinel`, …).

> **Tip:** for the strongest guarantee, verify by **digest** rather than tag
> (`ghcr.io/<owner>/miraige-api@sha256:…`) — a tag is mutable, a digest is the
> exact signed artifact. The version tag, `latest`, and `sha-<commit>` all
> resolve to the same signed digest.

> The full CI pipeline (lint, SAST/CodeQL, dependency & secret scanning,
> Dockerfile lint, image scan) is described in
> [Development & testing](development.md). Note that the Ghost Shell and Fake
> Portal intentionally ship synthetic honeytokens; the secret scanner allowlists
> them — see [`SECURITY.md`](../../SECURITY.md).

## Verify the signature

```bash
IMAGE=ghcr.io/<owner>/miraige-api:<tag>

cosign verify "$IMAGE" \
  --certificate-identity-regexp "^https://github.com/<owner>/<repo>/.github/workflows/ci.yml@.*" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com"
```

## Verify the SBOM attestation

```bash
cosign verify-attestation "$IMAGE" \
  --type cyclonedx \
  --certificate-identity-regexp "^https://github.com/<owner>/<repo>/.github/workflows/ci.yml@.*" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  | jq -r '.payload | @base64d | fromjson | .predicate' > sbom.cdx.json
```

## Verify the build provenance

```bash
gh attestation verify "oci://$IMAGE" --owner <owner>
```

[cosign]: https://github.com/sigstore/cosign
