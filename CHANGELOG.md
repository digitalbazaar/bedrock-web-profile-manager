# bedrock-web-profile-manager ChangeLog

## 18.0.0 - 2022-xx-xx

### Changed
- **BREAKING**: Use `exports` instead of `module`.
- **BREAKING**: Use `globalThis` for browser crypto.
- **BREAKING**: Require Web Crypto API. Older browsers and Node.js 14 users
  need to install an appropriate polyfill.
- Update dependencies.
- Lint module.

## 17.2.0 - 2022-05-29

### Added
- Add `getProfileIds()` method to fetch profile IDs without fetching
  profile contents.

## 17.1.0 - 2022-05-17

### Added
- Add optional cache for profiles and profile agent records. The cache can be
  used by passing `useCache: true` to `getProfile()` or `getProfiles()`.

## 17.0.0 - 2022-05-05

### Changed
- **BREAKING**: Use `@digitalbazaar/edv-client@14` with new blind attribute
  version. This version must be paired against
  `@bedrock/profile@19` and `@bedrock/profile-http@18` and is incompatible
  with previous versions without performing a migration of all EDV documents
  from blind attribute version 1 to version 2.

## 16.0.1 - 2022-04-18

### Fixed
- Normalize `allowedAction` to `allowedActions` in delegate API.

## 16.0.0 - 2022-04-18

### Added
- Add option to specify an `id` and `mutator` function to the Collection
  API and to `updateUser` on `AccessManager`.
- Automatically add profile EDV access zcaps to the local profile agent when
  a new profile EDV is created.
- Add profile EDV access zcaps on demand to the local profile agent when an
  existing profile EDV is first accessed.

### Changed
- **BREAKING**: `Collection` API no longer accepts `capability` nor
  `invocationSigner`; these must be set on the `edvClient` that is passed
  to the constructor.
- **BREAKING**: `AccessManager` `createUser` is presently disabled and will
  throw a `Not Implemented` error, properly reflecting its currently broken
  state. A future version will eventually address this.
- **BREAKING**: `getAccessManager` returns an object with `accessManager` ste
  to the access manager instance and `profile` and `profileAgent` set to the
  profile and profile agent used.

### Removed
- **BREAKING**: Remove `initializeAccessManagement`. Access management for
  profiles must now be handled during profile provisioning on the backend
  system. Use at least `@bedrock/profile@17` and `@bedrock/profile-http@16`
  on a backend system to provide this functionality.

## 15.0.1 - 2022-04-11

### Fixed
- Fix browser alias in `package.json`.

## 15.0.0 - 2022-04-10

### Changed
- **BREAKING**: Rename package to `@bedrock/web-profile-manager`.
- **BREAKING**: Convert to module (ESM).

## 14.0.1 - 2022-03-18

### Fixed
- Ensure root profile agent stores user EDV key agreement key
  zcap in backend record.

## 14.0.0 - 2022-03-18

### Changed
- **BREAKING**: Update root profile agent zcap TTLs to be 1y.
- **BREAKING**: Consolidate zcap for user EDV key agreement key.

## 13.1.0 - 2022-03-17

### Added
- Add key resolver cache.
- Add dependency `@digitalbazaar/lru-memoize@2.2`.

## 13.0.0 - 2022-03-01

### Changed
- **BREAKING**: Use `@digitalbazaar/webkms-client@10` and
  `@digitalbazaar/edv-client@13`.

## 12.0.0 - 2022-02-23

### Changed
- **BREAKING**: Use `@digitalbazaar/edv-client@12`. This new
  version computes encrypted indexes for EDVs differently (more privacy
  preserving) and is therefore incompatible with previous versions.

## 11.1.1 - 2022-02-23

### Added
- Expose new method `getProfileMeters` to get the meters for a profile.

### Fixed
- Exposing `profileMeters` in `profileAgent` was a mistake. This quick bug
  fix remedies that and instead exposes `getProfileMeters`.

## 11.1.0 - 2022-02-23

### Added
- Include `profileMeters` in `profileAgent` returned from `getAgent`.

## 11.0.0 - 2022-02-10

### Changed
- **BREAKING**: Require `meterId` as a parameter for `createProfileEdv`. Must
  use bedrock-profile@13 and use bedrock-profile-http@10.
- **BREAKING**: `ProfileManager.getAgentCapability` has been renamed to
  `ProfileManager.getDelegatedAgentCapability` and always delegates the
  requested zcap to an ephemeral capability agent.
- **BREAKING**: `ProfileManager.delegateEdvCapabilities` now returns `{zcaps}`
  where `zcaps` is an object with keys that are reference IDs and values that
  are the matching zcaps.
- **BREAKING**: Always delegate zcaps to an ephemeral capability agent; do
  not invoke any profile agent zcaps directly.

### Removed
- Remove `edvRevocation` and any other zcaps for performing revocations; these
  are no longer needed to revoke zcaps.
- Remove `kmsModule` parameter; it is no longer used as the KMS module is
  already set in a profile / profile agent's keystore via the backend service.

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
