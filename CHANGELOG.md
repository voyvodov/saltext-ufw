The changelog format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

This project uses [Semantic Versioning](https://semver.org/) - MAJOR.MINOR.PATCH

# Changelog

## 0.6.1 (2026-01-21)


### Fixed

- Adding error message in case app is set together with ports.
  Adding error message in case app is set, but no from_ip/to_ip.
- Fixing `remove_rule` execution module to correctly support deleting rules at specific position.

## 0.6.0 (2026-01-15)


### Added

- Add support for reset the ufw rules via `ufw.reset` execution module.

## 0.5.1 (2026-01-15)

No significant changes.
