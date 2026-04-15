# Ironclad

Secure file packaging system with AES-256-GCM encryption, dual-signature verification (developer ECDSA + distributor Vault Transit), license management, and streaming encryption support.

## Architecture

Three Go modules in one repo, each for a different audience:

- **`sdk/`** (`github.com/trendvidia/ironclad/sdk`) — Consumer apps. Open, validate, decrypt containers. Secure plugin loader and executable loader. No Vault dependency.
- **`admin/`** (`github.com/trendvidia/ironclad/admin`) — Platform tooling. Create containers, sign, issue licenses, CLI. Depends on Vault.
- **`devsdk/`** (`github.com/trendvidia/ironclad/devsdk`) — Third-party developers. Sign artifacts, create submission bundles. No Vault dependency.

The parent go.work at `github.com/trendvidia/go.work` includes all three modules. The admin and devsdk modules use `replace` directives for local SDK reference.

## Build & Test

```bash
# From the workspace root (github.com/trendvidia/)
go build ./ironclad/sdk/... ./ironclad/admin/... ./ironclad/devsdk/...
go test ./ironclad/sdk/... ./ironclad/admin/... ./ironclad/devsdk/... -count=1

# With coverage
go test ./ironclad/sdk/... ./ironclad/admin/... ./ironclad/devsdk/... -coverprofile=coverage.out
go tool cover -func=coverage.out
```

## Serialization

All section payloads use **protowire** (`github.com/trendvidia/protowire/encoding/pb`) with struct tags. File headers and section index entries remain fixed-width `encoding/binary` for seekability.

Key type conventions from protowire migration:
- `uuid.UUID` stored as `[]byte` with accessor methods (e.g., `ContentUUID()`)
- `time.Time` stored as `int64` Unix seconds with accessor methods (e.g., `ExpiresAt()`)
- `ContentHash` stored as `[]byte` with `ContentHashArray()` accessor

## Container Format (.tcn)

Format version 2. Binary with magic bytes `0x89 T C N`. Section index entries are 24 bytes (uint64 offsets, supports >4GB containers).

Sections: Envelope (protowire), License (protowire), Renewals (protowire, append-only chain).

Two signature domains:
- **Developer signature** (ECDSA P-256, ASN.1 DER only) covers `DeveloperManifest` bytes — the exact bytes the developer signed
- **Distributor signature** (Vault Transit) covers the full envelope including developer signature

## Submission Bundle Format (.tcsb)

Format version 2. Binary with magic bytes `0x89 T S B`. Contains raw artifact + protowire-encoded signed manifest + developer certificate.

## Streaming Encryption

For large files, `ChunkedEncryption: true` enables per-chunk AES-256-GCM encryption. Each chunk has a unique nonce derived from `baseNonce XOR chunkCounter`. Chunk format: `[uint32 ciphertext_length][ciphertext+tag]`, sentinel `[uint32 0]`.

## Secure Executable Loader

`sdk/loader/executable.go` provides `SecureExecutable` for loading and running encrypted executables from `.tcn` containers. Uses a **decrypt-per-run** model to minimize disk exposure:

1. `OpenExecutable()` validates signatures + license, caches only the 32-byte DEK
2. Each `Run()`/`Command()` call decrypts the payload, writes it to a secure platform-specific location, starts the subprocess, and immediately removes the file
3. `Close()` zeros the cached DEK

Content type `executable` (`0x04`) is enforced — `OpenExecutable` rejects non-executable containers.

Platform-specific execution:
- **Linux**: memfd (sealed, never touches real filesystem)
- **macOS**: temp file with ad-hoc codesign, unlinked after process start
- **Windows**: temp `.exe` file, removed after process exits

`Command()` returns `(*exec.Cmd, func(), error)` — the cleanup function must be called after the process completes.

## Certificate Revocation

`sdk/verify/revocation.go` provides `RevocationChecker` interface with CRL-based implementation (`CRLChecker`). Integrated into the validator via `WithRevocationChecker()` option. CRLs are fetched from certificate distribution points and cached with configurable TTL.

## Key Vault Transit Keys

- `ironclad-dek` — AES-256-GCM96, wraps Data Encryption Keys
- `ironclad-sign` — ECDSA P-256, signs envelopes/licenses/renewals

## CLI

```bash
ironclad pack <file> -o <output.tcn> --content-type executable --license-subject "customer" --renewal-endpoint "https://..."
ironclad pack <file> -o <output.tcn> --license-subject "customer" --renewal-endpoint "https://..."
ironclad inspect <file.tcn>
ironclad verify <file.tcn>
ironclad renew <file.tcn>
```
