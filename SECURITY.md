# Security

## Reporting a vulnerability

Report it privately through GitHub: **Security → Report a vulnerability**
on this repository, or <https://github.com/belluikit/ironclad/security/advisories/new>.
Please don't open a public issue for it. Include what you observed, how to
reproduce it, and the module version or commit.

## What ironclad protects, and what it does not

ironclad keeps a payload encrypted and authenticated until a consumer that
passes every check opens it: the developer's signature, the distributor's
signature, and the license. Within that:

- **Keys live with the key backend.** The data encryption key is wrapped by
  Vault Transit (`ironclad-dek`) and unwrapped only through the
  application's own `verify.DEKUnwrapper`. ironclad never holds the
  wrapping key.
- **A decrypted payload exists only as long as it must**, and where it
  exists depends on the platform:
  - **Linux:** in a sealed memfd, never on a filesystem, for executables
    and plugins alike.
  - **macOS:** on disk, briefly, in a per-process directory with restrictive
    permissions, because macOS runs and loads only code-signed files. An
    executable's file is unlinked once the process starts; a plugin's once
    it is loaded.
  - **Windows:** on disk as a temporary file for as long as the executable
    runs, since Windows locks a running executable; removal afterwards is
    best effort.
- **The data key is zeroed** when a `SecureExecutable` is closed.

It does not protect a payload from the machine running it: code that runs
as the same user, or as root, can read the process's memory, and on macOS
and Windows the temporary file while it exists. A license check runs in the
consumer application, so it binds an application that enforces it, not one
modified to skip it.

## Dependencies

A vulnerability in a dependency is fixed here by moving to a fixed version
and tagging the affected modules. If one affects ironclad, report it as
above, or open an issue asking for the update if it is already public.
