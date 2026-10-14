# Changelog

Each module is versioned and tagged on its own (`sdk/v0.2.1`), so each
entry names the modules it changes.

## Unreleased

## admin v0.1.0, devsdk v0.1.0 — 2026-10-14

- **admin, devsdk: installable and usable as dependencies.** They required
  `sdk v0.0.0` through a `replace`, so `go install` of the CLI failed and
  no other module could depend on them. They now require `sdk v0.2.1`, and
  `go.work` keeps a clone building them against the `sdk` beside them
  (#5).

## sdk v0.2.1 — 2026-10-14

- **The module path is `github.com/belluikit/ironclad/sdk`.** ironclad
  moved from `trendvidia` to `belluikit`, and its three modules moved with
  it. The old URL redirects.
- **Open source, under the MIT license.** Each module carries the license
  as `LICENSE.txt`, and every source file has an SPDX header.
- **v0.2.0 is retracted.** It cannot be downloaded: the repository's
  `LICENSE` and the `license/` package collided in its zip on
  case-insensitive file systems (#7).
- **admin, devsdk:** their tests build again; testify was missing from
  their `go.mod` (#3).

## sdk v0.2.0 — 2026-10-14 (retracted)

The first tag under the new module path. Retracted by v0.2.1: it cannot be
downloaded.

## sdk v0.1.0 — 2026-06-23

Released as `github.com/trendvidia/ironclad/sdk`, before ironclad moved
and was open-sourced.
