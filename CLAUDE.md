# Ironclad

Secure file packaging system with AES-256-GCM encryption, dual-signature verification (developer ECDSA + distributor Vault Transit), and license management with configurable grace periods and renewal chains.

## Architecture

Three Go modules in one repo, each for a different audience:

- **`sdk/`** (`github.com/trendvidia/ironclad/sdk`) — Consumer apps. Open, validate, decrypt containers. Secure plugin loader. No Vault dependency.
- **`admin/`** (`github.com/trendvidia/ironclad/admin`) — Platform tooling. Create containers, sign, issue licenses, CLI. Depends on Vault.
- **`devsdk/`** (`github.com/trendvidia/ironclad/devsdk`) — Third-party developers. Sign artifacts, create submission bundles. No Vault dependency.

The parent go.work at `github.com/trendvidia/go.work` includes all three modules. The admin module uses a `replace` directive for the SDK (`replace github.com/trendvidia/ironclad/sdk => ../sdk`).

## Build & Test

```bash
# From the workspace root (github.com/trendvidia/)
go build ./ironclad/sdk/... ./ironclad/admin/... ./ironclad/devsdk/...
go test ./ironclad/sdk/... ./ironclad/admin/... ./ironclad/devsdk/... -count=1

# With coverage
go test ./ironclad/sdk/... ./ironclad/admin/... ./ironclad/devsdk/... -coverprofile=coverage.out
go tool cover -func=coverage.out

# From within a module directory (uses GOWORK=off for admin since SDK is local)
cd ironclad/sdk && go test ./...
cd ironclad/devsdk && GOWORK=off go test ./...
cd ironclad/admin && GOWORK=off go test ./...
```

## Container Format (.tcn)

Binary format with magic bytes `0x89 T C N`. Sections: Envelope (encrypted payload + dual signatures), License (signed JSON), Renewals (append-only chain).

Two signature domains:
- **Developer signature** (ECDSA P-256) covers content hash + metadata. Created before encryption.
- **Distributor signature** (Vault Transit) covers the full envelope including developer signature. Created after encryption.

## Submission Bundle Format (.tcsb)

Binary format with magic bytes `0x89 T S B`. Contains raw artifact + signed manifest + developer certificate. Developers create these, platform verifies and packages into .tcn containers.

## Key Vault Transit Keys

- `ironclad-dek` — AES-256-GCM96, wraps Data Encryption Keys
- `ironclad-sign` — ECDSA P-256, signs envelopes/licenses/renewals

## CLI

```bash
ironclad pack <file> -o <output.tcn> --license-subject "customer" --renewal-endpoint "https://..."
ironclad inspect <file.tcn>
ironclad verify <file.tcn>
ironclad renew <file.tcn>
```
