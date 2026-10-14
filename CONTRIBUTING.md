# Contributing to ironclad

## Building

```
git clone https://github.com/belluikit/ironclad
cd ironclad
```

The repository holds three Go modules, `sdk`, `admin` and `devsdk`.
`go.work` builds `admin` and `devsdk` against the `sdk` beside them, so a
change to `sdk` is tested with its users before it is tagged.

## Before a pull request

CI runs these, on Linux and macOS:

```
(cd sdk && go vet ./... && go test -race ./...)      # and the same in admin and devsdk
gofmt -l .                                           # prints nothing
go run scripts/headers.go                            # every source file has its license header
(cd sdk && CGO_ENABLED=0 GOOS=windows go vet ./...)  # the loader's Windows path, in each module
```

A new source file starts with the license header:

```
// SPDX-License-Identifier: MIT
// Copyright (c) 2026 TrendVidia, LLC.
```

## What makes a good change

- **An issue first** for anything beyond a small fix: the problem, the
  evidence, and what "done" means. The pull request closes it.
- **Tests with the change**, and a test that fails if the change is
  reverted.
- **A CHANGELOG entry** under Unreleased for anything a user would notice,
  naming the module it changes.
- **Format changes are versioned.** A change to the `.tcn` or `.tcsb`
  layout bumps its format version, and readers say what they do with the
  versions before it.

## Releasing

Each module is tagged on its own, with its directory as the prefix:
`sdk/v0.2.1`, `admin/v0.1.0`, `devsdk/v0.1.0`. When `sdk` changes in a
way `admin` or `devsdk` need, tag `sdk` first, then raise their
requirement and tag them.

## Reporting

Bugs and ideas go to [issues](https://github.com/belluikit/ironclad/issues).
Security reports go privately, as [SECURITY.md](SECURITY.md) says.
