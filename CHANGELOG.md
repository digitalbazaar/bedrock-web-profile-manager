# bedrock-web-profile-manager ChangeLog

## 4.3.2 - 2020-06-26

### Fixed
- Move `capabilityAgents` into `_cacheContainer`.

## 4.3.1 - 2020-06-26

### Fixed
- Adjust and correct cache implementation.

## 4.3.0 - 2020-06-24

### Added
- Add LRU cache to improve performance of some operations.

### Changed
- Use webkms-client@2.3.0 which features a cache for improving performance
  for HMAC operations.

## 4.2.0 - 2020-05-18

### Added
- Add support for `did:v1` based profiles.

## 4.1.0 - 2020-04-14

### Added
- Parameter validation on some APIs.
- Improve test coverage.

## 4.0.1 - 2020-04-03

### Changed
- Fix internal issues with capability delegation.

## 4.0.0 - 2020-04-02

### Changed
- **BREAKING**: Many breaking API changes. See code/docs for details.

## 3.0.0 - 2020-03-24

### Changed
- **BREAKING**: Many breaking API changes. See code/docs for details.

## 2.0.0 - 2020-03-19

### Changed
- **BREAKING**: Many breaking API changes. See code/docs for details.

## 1.0.0 - 2020-03-06

### Changed
- Update to latest web-profile APIs.

## 0.6.0 - 2020-02-14 15:30:52

### Changed
- Use webkms-client@2.

## 0.5.0 - 2020-02-14

### Changed
- Use jsonld-signatures@5.

## 0.4.0 - 2020-01-17

### Added
- **BREAKING**: `invocationTarget.verificationMethod` is required when
  `invocationTarget.type` is `Ed25519VerificationKey2018` in
  `delegateCapability` API.

## 0.3.0 - 2020-01-12

### Added
- Add support for delegatable and webkms-authorizations zcaps.

## 0.2.0 - 2020-01-10

### Added
- Add support for edv document collection and authorization zcaps.

## 0.1.0 - 2020-01-04

- See git history for changes previous to this release.
