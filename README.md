# ironclad

**Encrypted, signed and licensed containers for distributing software.**

ironclad packages a file, such as an executable, a Go plugin or plain
data, into a container (`.tcn`) that a consumer application can open only
if three checks pass. The developer's signature must be valid, the
distributor's signature must be valid, and the license must allow it. The
payload is encrypted with AES-256-GCM. Keys are wrapped and signatures made
through HashiCorp Vault Transit on the distributor's side. The consumer
side needs no Vault: it takes interfaces for verifying and unwrapping, so
any key backend fits.

## Three modules, three audiences

| module | for | what it does | needs Vault |
|---|---|---|---|
| `github.com/belluikit/ironclad/sdk` | applications that consume containers | open, validate and decrypt `.tcn` containers; load an encrypted executable or Go plugin | no |
| `github.com/belluikit/ironclad/admin` | the distributing platform | create and sign containers, issue licenses, renew them; the `ironclad` CLI | yes |
| `github.com/belluikit/ironclad/devsdk` | third-party developers | sign an artifact and package it as a submission bundle (`.tcsb`) | no |

## How a file travels

1. **The developer signs.** With an ECDSA P-256 key and a certificate from
   the platform's CA, `devsdk` signs the artifact's manifest and writes a
   submission bundle (`.tcsb`): the raw artifact, the signed manifest and
   the developer's certificate.
2. **The platform packages.** `admin` checks the developer's identity and
   signature, encrypts the artifact with a fresh data encryption key, wraps
   that key with Vault Transit (`ironclad-dek`), and signs the whole
   envelope, developer signature included (`ironclad-sign`). It issues a
   license with the container.
3. **The consumer opens.** `sdk` verifies both signatures and the
   license, unwraps the key through the application's own
   `verify.DEKUnwrapper`, and decrypts. Given a revocation checker
   (`WithRevocationChecker`), it also checks the developer's certificate
   against its CRL.

## Running what it carries

`sdk/loader` runs an encrypted executable without leaving it on disk:

- `OpenExecutable` validates the signatures and the license, and keeps only
  the 32-byte data key.
- Each `Run` or `Command` decrypts the payload, starts the process, and
  removes the decrypted file at once: a sealed memfd on Linux, which never
  touches the filesystem; a temporary file with an ad-hoc code signature on
  macOS, unlinked once the process starts; a temporary `.exe` on Windows,
  removed when the process exits.
- `Close` zeroes the key.

`loader.Open` loads a Go plugin the same way. A developer can tie symbols
to features: `Lookup` refuses a symbol whose feature isn't in the license's
entitlements.

```go
exe, err := loader.OpenExecutable(ctx, "tool.tcn", verifier, unwrapper,
	loader.WithSigningKey("ironclad-sign"),
	loader.WithEnvelopeKey("ironclad-sign"),
	loader.WithDEKKeyName("ironclad-dek"),
)
if err != nil {
	log.Fatal(err)
}
defer exe.Close()

if err := exe.Run(ctx, "--version"); err != nil {
	log.Fatal(err)
}
```

## Formats

**Container (`.tcn`), format version 2.**
- **Header:** magic bytes `0x89 T C N`, then a section index. Index
  entries are 24 bytes with 64-bit offsets, so a container can exceed 4 GB.
- **Sections:** the envelope, the license, and the renewals, an
  append-only chain.
- **Developer signature:** ECDSA P-256, ASN.1 DER. It covers the exact
  bytes the developer signed.
- **Distributor signature:** Vault Transit. It covers the whole envelope,
  the developer's signature included.

**Submission bundle (`.tcsb`), format version 2.** Magic bytes
`0x89 T S B`. It holds the raw artifact, the signed manifest and the
developer's certificate.

**Encoding.** Section payloads are encoded with
[protowire-go](https://github.com/trendvidia/protowire-go)
(`encoding/pb`). Headers and index entries are fixed-width
`encoding/binary`, so a reader can seek.

**Large files.** With `ChunkedEncryption`, each chunk is encrypted on its
own with AES-256-GCM. Its nonce is the base nonce XOR the chunk's counter.
A chunk is `[uint32 length][ciphertext and tag]`, and `[uint32 0]` ends
the stream.

## The CLI

```
ironclad pack <file> -o <out.tcn> --license-subject <customer> --renewal-endpoint <url> [--content-type executable]
ironclad inspect <file.tcn>
ironclad verify <file.tcn>
ironclad renew <file.tcn>
```

## Building

`admin` and `devsdk` use the `sdk` in this repository through a `replace`
directive, so build from a clone:

```
git clone https://github.com/belluikit/ironclad
cd ironclad/admin && go build ./cmd/ironclad
```

Each module tests on its own: `go test ./...` in `sdk`, `admin` and
`devsdk`. `go run scripts/headers.go` checks that every source file
carries its license header.

## License

MIT. See [LICENSE.txt](LICENSE.txt).
