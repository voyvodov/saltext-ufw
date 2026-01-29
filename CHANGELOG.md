The changelog format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

This project uses [Semantic Versioning](https://semver.org/) - MAJOR.MINOR.PATCH

# Changelog

## 0.8.0 (2026-01-29)


### Breaking changes

- Refactor of the rules and parameters.
  This is a breaking change as source and destination parameters are now renamed.
  And since this is still beta version, no backward compatibility.


### Changed

- Removed dependency on grep binary for parsing the rules files.
  Now files are directly loaded and parsed in python.


### Added

- Added execution modules to add and remove forwarding rules
  Added state modules to ensure forwarding rules are present or absent [#1](https://github.com/voyvodov/saltext-ufw/issues/1)
- Added execution module to list current rules as a list
  Added execution module to get rules in dict format for easier filtering.
- Added support for port ranges for the source and destination ports

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
