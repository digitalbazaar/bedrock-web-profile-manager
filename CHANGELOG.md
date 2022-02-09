# bedrock-web-profile-manager ChangeLog

## 11.0.0 - 2022-xx-xx

### Changed
- **BREAKING**: Require `meterId` as a parameter for `createProfileEdv`. Must
  use bedrock-profile@13 and use bedrock-profile-http@10.
- **BREAKING**: `ProfileManager.getAgentCapability` must be passed a zcap
  `referenceId`, not its `id`.
- **BREAKING**: `ProfileManager.delegateEdvCapabilities` now returns `{zcaps}`
  where `zcaps` is an object with keys that are reference IDs and values that
  are the matching zcaps.

## 10.1.0 - 2021-10-06

### Changed
- Add support for Node.js via `isomorphic-webcrypto`.

## 10.0.1 - 2021-10-05

### Fixed
- Fix destructuring of `keystoreId` in `delegateCapability()`. Previously
  `keystoreAgent` had `keystore` property which provided the id, but now
  it no longer has the `keystore` property, instead it has the `keystoreId`
  property.
- Update `bedrock-profile-http` in test.

## 10.0.0 - 2021-09-03

### Changed
- **BREAKING**: No changes to the public API. Must use bedrock-kms-http@9,
  bedrock-meter-http@2, bedrock-meter-usage-reporter@4, bedrock-profile@12,
  and bedrock-profile-http@8.

## 9.0.0 - 2021-08-24

### Changed
- **BREAKING**: Use webkms-client@7. Most changes are internal, but this
  version of the library must be used against a WebKMS server that requires
  authz for fetching keystore configurations.

## 8.0.3 - 2021-08-19

### Fixed
- Update dependencies to pull in fixed ed25519* modules.

## 8.0.2 - 2021-08-17

### Fixed
- Fix error message that is thrown when `publicAlias` is missing.

## 8.0.1 - 2021-06-02

### Changed
- Update did-veres-one dep to latest beta.

## 8.0.0 - 2021-05-21

### Changed
- **BREAKING**: Temporarily remove veres-one DID support.
- Supports `ed25519-2020` signature suite and verification keys.
- Supports `X25519KAK2020` key type.
- Update deps.
  - Use [`@digitalbazaar/zcapld@4.0`](https://github.com/digitalbazaar/zcapld/blob/main/CHANGELOG.md).
    - ocapld lib has been renamed to @digitalbazaar/zcapld and uses the new
      zcap-context.
  - Use [`jsonld-signatures@9.0.2`](https://github.com/digitalbazaar/jsonld-signatures/blob/master/CHANGELOG.md)
  - Use [`@digitalbazaar/webkms-client@6.0`](https://github.com/digitalbazaar/webkms-client/blob/main/CHANGELOG.md).
    - webkms-client has been renamed to @digitalbazaar/webkms-client and uses
      the new webkms-context.
  - Use [`bedrock-web-profile@3.0`](https://github.com/digitalbazaar/bedrock-web-profile/blob/main/CHANGELOG.md#300---2021-05-06).
    - Replaced `axios` with `http-client`.
- Update test deps.

## 7.0.0 - 2021-03-09

### Changed
- **BREAKING**: Remove same origin requirement in key resolver.
- Remove unused dependencies.

## 6.2.2 - 2020-12-14

### Fix
- Pass `doc` parameter to `edvDoc.delete` in `remove` api.
### Added
- Test for `Collection.js` apis.

## 6.2.1 - 2020-10-21

### Fixed
- Remove use of assert-plus.

## 6.2.0 - 2020-10-07

### Added
- A configurable profileService parameter to ProfileManager.

## 6.1.0 - 2020-10-06

### Changed
- Use edv-client@6.

## 6.0.0 - 2020-09-25

### Changed
- **BREAKING**: Make `keyResolver` more restrictive. Only support KMS systems
  with a same origin policy and `did:key` and `did:v1`.

## 5.3.1 - 2020-09-25

### Fixed
- Correctly handle `expires`.

## 5.3.0 - 2020-07-24

### Changed
- Validate the `parentCapabilities` param to the `delegateEdvCapabilities` API.
- Improve test coverage.

## 5.2.0 - 2020-07-07

### Changed
- Reduce extra map lookups.
- Update peer deps and test deps.

## 5.1.0 - 2020-07-02

### Changed
- Update deps.
- Update test deps.
- Update CI workflow.

## 5.0.2 - 2020-06-26

### Fixed
- Move `capabilityAgents` into `_cacheContainer`.

## 5.0.1 - 2020-06-26

### Fixed
- Adjust and correct cache implementation.

## 5.0.0 - 2020-06-24

### Changed
- **BREAKING**: Use edv-client@4. This is a breaking change here because of
  changes in how edv-client serializes documents.

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
