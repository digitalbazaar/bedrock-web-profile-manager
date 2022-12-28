/*!
 * Copyright (c) 2019-2022 Digital Bazaar, Inc. All rights reserved.
 */
import {mockData} from './mock.data.js';
import {ProfileManager} from '@bedrock/web-profile-manager';
import {ProfileService} from '@bedrock/web-profile';
import sinon from 'sinon';

const ACCOUNT_ID = 'urn:uuid:ffaf5d84-7dc2-4f7b-9825-cc8d2e5a5d06';
const EDV_BASE_URL = `${window.location.origin}/edvs`;

describe('Profile Manager API', () => {
  describe('createProfile API', () => {
    it('should create a profile', async () => {
      const profileManager = new ProfileManager({
        edvBaseUrl: EDV_BASE_URL
      });

      await profileManager.setSession({
        session: {
          data: {
            account: {
              id: ACCOUNT_ID
            }
          },
          on: () => {},
        }
      });

      let error;
      let result;
      try {
        result = await profileManager.createProfile(
          {didMethod: 'v1', didOptions: {mode: 'test'}});
      } catch(e) {
        error = e;
      }
      should.not.exist(error);
      should.exist(result);
      result.should.have.property('id');
      result.id.should.be.a('string');
      result.id.should.match(/^did\:v1\:test\:/);
    });
    it('should create a profile with a custom ProfileService',
      async () => {
        // using the mock we can have a deterministic profileDid
        const profileDid = 'did:v1:test:mock';
        const didOptions = {mode: 'test'};
        const profileService = new ProfileService();
        const mock = sinon.mock(profileService);
        mock.expects('create').once().withExactArgs({
          // the thing most likely to fail is this.accountId
          // is not set correctly in the profileManager
          account: ACCOUNT_ID,
          didMethod: 'v1',
          didOptions
        }).returns({id: profileDid});
        const profileManager = new ProfileManager({
          edvBaseUrl: EDV_BASE_URL,
          profileService
        });

        await profileManager.setSession({
          session: {
            data: {
              account: {
                id: ACCOUNT_ID
              }
            },
            on: () => {},
          }
        });

        let error;
        let result;
        try {
          result = await profileManager.createProfile(
            {didMethod: 'v1', didOptions});
        } catch(e) {
          error = e;
        }
        should.not.exist(error);
        should.exist(result);
        result.should.have.property('id');
        result.id.should.be.a('string');
        result.id.should.equal(profileDid);
        mock.verify();
      });
  });

  describe('getProfileSigner api', () => {
    let profileManager;
    beforeEach(async () => {
      profileManager = new ProfileManager({
        edvBaseUrl: EDV_BASE_URL
      });

      await profileManager.setSession({
        session: {
          data: {
            account: {
              id: ACCOUNT_ID
            }
          },
          on: () => {},
        }
      });
    });
    it('should pass if profile exists', async () => {
      let error;
      let result;
      try {
        const {id: profileId} = await profileManager.createProfile(
          {didMethod: 'v1', didOptions: {mode: 'test'}});
        result = await profileManager.getProfileSigner({profileId});
      } catch(e) {
        error = e;
      }
      should.not.exist(error);
      should.exist(result);
      result.should.have.property('invocationSigner');
      result.invocationSigner.id.should.contain('did:v1:');
      result.invocationSigner.type.should.contain('Ed25519VerificationKey2020');
      result.invocationSigner.should.have.property('sign');
    });
    it('should fail if profileId is undefined', async () => {
      let error;
      let result;
      try {
        result = await profileManager.getProfileSigner({profileId: undefined});
      } catch(e) {
        error = e;
      }
      should.not.exist(result);
      should.exist(error);
      error.name.should.equal('TypeError');
      error.message.should.contain('profileId');
    });
    it('should fail if profileId is an empty string', async () => {
      let error;
      let result;
      try {
        result = await profileManager.getProfileSigner({profileId: ''});
      } catch(e) {
        error = e;
      }
      should.not.exist(result);
      should.exist(error);
      error.name.should.equal('TypeError');
      error.message.should.contain('profileId');
    });
  });

  describe('getAgent api', () => {
    let profileManager;
    beforeEach(async () => {
      profileManager = new ProfileManager({
        edvBaseUrl: EDV_BASE_URL
      });

      await profileManager.setSession({
        session: {
          data: {
            account: {
              id: ACCOUNT_ID
            }
          },
          on: () => {},
        }
      });
    });
    it('should pass if profile exists', async () => {
      let error;
      let result;
      try {
        const {id: profileId} = await profileManager.createProfile(
          {didMethod: 'v1', didOptions: {mode: 'test'}});
        result = await profileManager.getAgent({profileId});
      } catch(e) {
        error = e;
      }
      should.not.exist(error);
      should.exist(result);
      result.should.have.property('id');
      result.id.should.contain('did:key:');
      result.should.have.property('zcaps');
    });
    it('should fail if profileId is undefined', async () => {
      let error;
      let result;
      try {
        result = await profileManager.getAgent({profileId: undefined});
      } catch(e) {
        error = e;
      }
      should.not.exist(result);
      should.exist(error);
      error.name.should.equal('TypeError');
      error.message.should.contain('profileId');
    });
    it('should fail if profileId is an empty string', async () => {
      let error;
      let result;
      try {
        result = await profileManager.getAgent({profileId: ''});
      } catch(e) {
        error = e;
      }
      should.not.exist(result);
      should.exist(error);
      error.name.should.equal('TypeError');
      error.message.should.contain('profileId');
    });
  });

  describe('getProfile api', () => {
    let profileManager;
    beforeEach(async () => {
      profileManager = new ProfileManager({
        edvBaseUrl: EDV_BASE_URL
      });

      await profileManager.setSession({
        session: {
          data: {
            account: {
              id: ACCOUNT_ID
            }
          },
          on: () => {},
        }
      });
    });
    it('should pass', async () => {
      let error;
      let result;
      try {
        const {id: profileId} = await profileManager.createProfile(
          {didMethod: 'v1', didOptions: {mode: 'test'}});
        result = await profileManager.getProfile({id: profileId});
      } catch(e) {
        error = e;
      }
      should.not.exist(error);
      should.exist(result);
    });
    it('should use cache', async () => {
      let error;
      let result1;
      let result2;
      try {
        const {id: profileId} = await profileManager.createProfile(
          {didMethod: 'v1', didOptions: {mode: 'test'}});
        result1 = await profileManager.getProfile({id: profileId});
        result2 = await profileManager.getProfile(
          {id: profileId, useCache: true});
      } catch(e) {
        error = e;
      }
      should.not.exist(error);
      should.exist(result1);
      should.exist(result2);
      // do not deep compare; asserting same object instances
      result1.should.equal(result2);
    });
    it('should fail if profileId is undefined', async () => {
      let error;
      let result;
      try {
        result = await profileManager.getProfile({id: undefined});
      } catch(e) {
        error = e;
      }
      should.not.exist(result);
      should.exist(error);
      error.name.should.equal('TypeError');
      error.message.should.contain('id');
    });
    it('should fail if profileId is an empty string', async () => {
      let error;
      let result;
      try {
        result = await profileManager.getProfile({id: ''});
      } catch(e) {
        error = e;
      }
      should.not.exist(result);
      should.exist(error);
      error.name.should.equal('TypeError');
      error.message.should.contain('id');
    });
  });

  describe('getProfiles api', () => {
    let profileManager;
    beforeEach(async () => {
      profileManager = new ProfileManager({
        edvBaseUrl: EDV_BASE_URL
      });

      await profileManager.setSession({
        session: {
          data: {
            account: {
              id: ACCOUNT_ID
            }
          },
          on: () => {},
        }
      });
    });
    it('should pass', async () => {
      let error;
      let result;
      let profileId;
      try {
        ({id: profileId} = await profileManager.createProfile(
          {didMethod: 'v1', didOptions: {mode: 'test'}}));
        result = await profileManager.getProfiles();
      } catch(e) {
        error = e;
      }
      should.not.exist(error);
      should.exist(result);
      should.exist(profileId);
      result.should.be.an('array');
      result.length.should.greaterThan(0);
      const profile = result.find(p => p.id === profileId);
      should.exist(profile, `Expected to find a profile for ${profileId}`);
      profile.should.be.an('object');
    });
    it('should use cache', async () => {
      let error;
      let result1;
      let result2;
      try {
        await profileManager.createProfile(
          {didMethod: 'v1', didOptions: {mode: 'test'}});
        result1 = await profileManager.getProfiles();
        result2 = await profileManager.getProfiles({useCache: true});
      } catch(e) {
        error = e;
      }
      should.not.exist(error);
      should.exist(result1);
      should.exist(result2);
      result1.should.be.an('array');
      result2.should.be.an('array');
      result1.length.should.equal(result2.length);
      result1.length.should.be.greaterThan(0);
      // do not deep compare; asserting same object instances
      for(let i = 0; i < result1.length; ++i) {
        result1[i].should.equal(result2[i]);
      }
    });
  });

  describe('getProfileIds api', () => {
    let profileManager;
    beforeEach(async () => {
      profileManager = new ProfileManager({
        edvBaseUrl: EDV_BASE_URL
      });

      await profileManager.setSession({
        session: {
          data: {
            account: {
              id: ACCOUNT_ID
            }
          },
          on: () => {},
        }
      });
    });
    it('should pass', async () => {
      let error;
      let result;
      let profileId;
      try {
        ({id: profileId} = await profileManager.createProfile(
          {didMethod: 'v1', didOptions: {mode: 'test'}}));
        result = await profileManager.getProfileIds();
      } catch(e) {
        error = e;
      }
      should.not.exist(error);
      should.exist(result);
      should.exist(profileId);
      result.should.be.an('array');
      result.length.should.greaterThan(0);
      result.should.include(profileId);
    });
    it('should use cache', async () => {
      let error;
      let result1;
      let result2;
      try {
        await profileManager.createProfile(
          {didMethod: 'v1', didOptions: {mode: 'test'}});
        result1 = await profileManager.getProfileIds();
        result2 = await profileManager.getProfileIds({useCache: true});
      } catch(e) {
        error = e;
      }
      should.not.exist(error);
      should.exist(result1);
      should.exist(result2);
      result1.should.be.an('array');
      result2.should.be.an('array');
      result1.length.should.equal(result2.length);
      result1.length.should.be.greaterThan(0);
      for(let i = 0; i < result1.length; ++i) {
        result1[i].should.equal(result2[i]);
      }
    });
  });

  describe('getProfileKeystoreAgent api', () => {
    let profileManager;
    beforeEach(async () => {
      profileManager = new ProfileManager({
        edvBaseUrl: EDV_BASE_URL
      });

      await profileManager.setSession({
        session: {
          data: {
            account: {
              id: ACCOUNT_ID
            }
          },
          on: () => {},
        }
      });
    });
    it('should pass if profile exists', async () => {
      let error;
      let result;
      try {
        const {id: profileId} = await profileManager.createProfile(
          {didMethod: 'v1', didOptions: {mode: 'test'}});
        result = await profileManager.getProfileKeystoreAgent({profileId});
      } catch(e) {
        error = e;
      }
      should.not.exist(error);
      should.exist(result);
      result.should.have.property('capabilityAgent');
      result.capabilityAgent.should.have.property('id');
      result.capabilityAgent.id.should.contain('did:v1:');
      result.should.have.property('keystoreId');
      result.should.have.property('kmsClient');
    });
    it('should fail if profileId is undefined', async () => {
      let error;
      let result;
      try {
        result = await profileManager.getProfileKeystoreAgent(
          {profileId: undefined});
      } catch(e) {
        error = e;
      }
      should.not.exist(result);
      should.exist(error);
      error.name.should.equal('TypeError');
      error.message.should.contain('profileId');
    });
    it('should fail if profileId is an empty string', async () => {
      let error;
      let result;
      try {
        result = await profileManager.getProfileKeystoreAgent({profileId: ''});
      } catch(e) {
        error = e;
      }
      should.not.exist(result);
      should.exist(error);
      error.name.should.equal('TypeError');
      error.message.should.contain('profileId');
    });
  });

  describe('getProfileMeters api', () => {
    let profileManager;
    beforeEach(async () => {
      profileManager = new ProfileManager({
        edvBaseUrl: EDV_BASE_URL
      });

      await profileManager.setSession({
        session: {
          data: {
            account: {
              id: ACCOUNT_ID
            }
          },
          on: () => {},
        }
      });
    });
    it('should pass if profile exists', async () => {
      let error;
      let result;
      try {
        const {id: profileId} = await profileManager.createProfile(
          {didMethod: 'v1', didOptions: {mode: 'test'}});
        result = await profileManager.getProfileMeters({profileId});
      } catch(e) {
        error = e;
      }
      should.not.exist(error);
      should.exist(result);
      result.should.be.an('array');
      result.some(m => m.referenceId = 'profile:core:edv').should.equal(true);
      result.some(m => m.referenceId = 'profile:core:credentials')
        .should.equal(true);
    });
    it('should fail if profileId is undefined', async () => {
      let error;
      let result;
      try {
        result = await profileManager.getProfileMeters({profileId: undefined});
      } catch(e) {
        error = e;
      }
      should.not.exist(result);
      should.exist(error);
      error.name.should.equal('TypeError');
      error.message.should.contain('profileId');
    });
    it('should fail if profileId is an empty string', async () => {
      let error;
      let result;
      try {
        result = await profileManager.getProfileMeters({profileId: ''});
      } catch(e) {
        error = e;
      }
      should.not.exist(result);
      should.exist(error);
      error.name.should.equal('TypeError');
      error.message.should.contain('profileId');
    });
  });

  describe('createProfileEdv api', () => {
    let profileManager;
    beforeEach(async () => {
      profileManager = new ProfileManager({
        edvBaseUrl: EDV_BASE_URL
      });

      await profileManager.setSession({
        session: {
          data: {
            account: {
              id: ACCOUNT_ID
            }
          },
          on: () => {},
        }
      });
    });
    it('should succeed if profile exists', async () => {
      let error;
      let result;
      try {
        const {id: profileId, meters} = await profileManager.createProfile(
          {didMethod: 'v1', didOptions: {mode: 'test'}});
        const {meter: edvMeter} = meters.find(
          m => m.meter.referenceId === 'profile:core:edv');

        result = await profileManager.createProfileEdv(
          {profileId, meterId: edvMeter.id, referenceId: 'example'});
      } catch(e) {
        error = e;
      }
      should.not.exist(error);
      should.exist(result);
      result.should.have.property('edvClient');
      result.edvClient.should.have.property('id');
      result.edvClient.should.have.property('keyAgreementKey');
      result.edvClient.should.have.property('hmac');
    });
    it('should fail if profileId is undefined', async () => {
      let error;
      let result;
      try {
        result = await profileManager.createProfileEdv({
          profileId: undefined,
          referenceId: 'test.org:test-edv'
        });
      } catch(e) {
        error = e;
      }
      should.not.exist(result);
      should.exist(error);
      error.name.should.equal('TypeError');
      error.message.should.contain('profileId');
    });
    it('should fail if profileId is an empty string', async () => {
      let error;
      let result;
      try {
        result = await profileManager.createProfileEdv({
          profileId: '',
          referenceId: 'test.org:test-edv'
        });
      } catch(e) {
        error = e;
      }
      should.not.exist(result);
      should.exist(error);
      error.name.should.equal('TypeError');
      error.message.should.contain('profileId');
    });
  });

  describe('AccessManager', () => {
    let profileManager;
    beforeEach(async () => {
      profileManager = new ProfileManager({
        edvBaseUrl: EDV_BASE_URL
      });

      await profileManager.setSession({
        session: {
          data: {
            account: {
              id: ACCOUNT_ID
            }
          },
          on: () => {},
        }
      });
    });
    it('should pass', async () => {
      let error;
      let result;
      try {
        const {id: profileId} = await profileManager.createProfile(
          {didMethod: 'v1', didOptions: {mode: 'test'}});
        const {accessManager} = await profileManager.getAccessManager(
          {profileId});
        result = accessManager;
      } catch(e) {
        error = e;
      }
      should.not.exist(error);
      should.exist(result);
      result.should.have.property('profile');
      result.profile.should.have.property('id');
      result.profile.id.should.contain('did:v1:');
      result.profile.should.have.property('accessManagement');
      result.should.have.property('profileManager');
      result.should.have.property('users');
    });
    it('should add access when creating an EDV', async () => {
      let error;
      let result;
      try {
        const {id: profileId, meters} = await profileManager.createProfile(
          {didMethod: 'v1', didOptions: {mode: 'test'}});
        const {meter: edvMeter} = meters.find(
          m => m.meter.referenceId === 'profile:core:edv');

        const referenceId = 'example';
        const {user} = await profileManager.createProfileEdv(
          {profileId, meterId: edvMeter.id, referenceId});
        result = user;
      } catch(e) {
        error = e;
      }
      should.not.exist(error);
      should.exist(result);
      result.should.include.keys(['id', 'zcaps']);
      result.id.should.contain('did:key:');
      result.zcaps.should.be.an('object');
      result.zcaps.should.include.keys([
        'example-edv-hmac', 'example-edv-kak', 'example-edv-documents'
      ]);
    });
    it('should not add access when creating an EDV', async () => {
      let error;
      let result;
      try {
        const {id: profileId, meters} = await profileManager.createProfile(
          {didMethod: 'v1', didOptions: {mode: 'test'}});
        const {meter: edvMeter} = meters.find(
          m => m.meter.referenceId === 'profile:core:edv');

        const referenceId = 'example';
        const {user} = await profileManager.createProfileEdv(
          {profileId, meterId: edvMeter.id, referenceId, addAccess: false});
        result = user;
      } catch(e) {
        error = e;
      }
      should.not.exist(error);
      should.not.exist(result);
    });
    it('should add access after creating an EDV', async () => {
      const referenceId = 'example';
      let profileId;
      let error;
      let result;
      try {
        const {id, meters} = await profileManager.createProfile(
          {didMethod: 'v1', didOptions: {mode: 'test'}});
        profileId = id;
        const {meter: edvMeter} = meters.find(
          m => m.meter.referenceId === 'profile:core:edv');

        const {user} = await profileManager.createProfileEdv(
          {profileId, meterId: edvMeter.id, referenceId, addAccess: false});
        result = user;
      } catch(e) {
        error = e;
      }
      should.not.exist(error);
      should.not.exist(result);

      // now add access on demand
      try {
        result = await profileManager.getProfileEdvAccess(
          {profileId, referenceId});
      } catch(e) {
        error = e;
        console.log('error', e);
      }
      should.not.exist(error);
      should.exist(result);
    });
    it('should fail if profileId is undefined', async () => {
      let error;
      let result;
      try {
        result = await profileManager.getAccessManager({profileId: undefined});
      } catch(e) {
        error = e;
      }
      should.not.exist(result);
      should.exist(error);
      error.name.should.equal('TypeError');
      error.message.should.contain('profileId');
    });
    it('should fail if profileId is an empty string', async () => {
      let error;
      let result;
      try {
        result = await profileManager.getAccessManager({profileId: ''});
      } catch(e) {
        error = e;
      }
      should.not.exist(result);
      should.exist(error);
      error.name.should.equal('TypeError');
      error.message.should.contain('profileId');
    });
  });

  describe('delegateCapability api', () => {
    let profileManager;
    beforeEach(async () => {
      profileManager = new ProfileManager({
        edvBaseUrl: EDV_BASE_URL
      });
    });
    it('should fail if profileId is undefined', async () => {
      let error;
      let result;
      const delegateRequest = {
        referenceId: 'test.org:test-edv',
        allowedAction: ['read', 'write'],
        controller: 'did:key:sadsdasdasd'
      };
      try {
        result = await profileManager.delegateCapability({
          profileId: undefined,
          request: delegateRequest
        });
      } catch(e) {
        error = e;
      }
      should.not.exist(result);
      should.exist(error);
      error.name.should.equal('TypeError');
      error.message.should.contain('profileId');
    });
    it('should fail if profileId is an empty string', async () => {
      let error;
      let result;
      const delegateRequest = {
        referenceId: 'test.org:test-edv',
        allowedAction: ['read', 'write'],
        controller: 'did:key:sadsdasdasd'
      };
      try {
        result = await profileManager.delegateCapability({
          profileId: '',
          request: delegateRequest
        });
      } catch(e) {
        error = e;
      }
      should.not.exist(result);
      should.exist(error);
      error.name.should.equal('TypeError');
      error.message.should.contain('profileId');
    });
    it('should fail after parentCapabilities assertion', async () => {
      const {
        parentCapabilities,
        edvId,
        hmac,
        keyAgreementKey
      } = mockData;
      let error = null;
      let result = null;
      try {
        result = await profileManager.delegateEdvCapabilities({
          parentCapabilities, edvId, hmac, keyAgreementKey
        });
      } catch(e) {
        error = e;
      }
      should.not.exist(result);
      should.exist(error);
      error.name.should.equal('TypeError');
    });
    it('should fail if no edvId', async () => {
      const {
        parentCapabilities,
        hmac,
        keyAgreementKey
      } = mockData;
      delete parentCapabilities.edv;
      let error = null;
      let result = null;
      try {
        result = await profileManager.delegateEdvCapabilities({
          parentCapabilities, hmac, keyAgreementKey
        });
      } catch(e) {
        error = e;
      }
      should.not.exist(result);
      should.exist(error);
      error.name.should.equal('TypeError');
      error.message.should.contain('edvId');
    });
    it('should fail if no hmac', async () => {
      const {
        parentCapabilities,
        edvId,
        keyAgreementKey
      } = mockData;
      delete parentCapabilities.hmac;
      let error = null;
      let result = null;
      try {
        result = await profileManager.delegateEdvCapabilities({
          parentCapabilities, edvId, keyAgreementKey
        });
      } catch(e) {
        error = e;
      }
      should.not.exist(result);
      should.exist(error);
      error.name.should.equal('TypeError');
      error.message.should.contain('hmac');
    });
    it('should fail if no keyAgreementKey', async () => {
      const {
        parentCapabilities,
        edvId,
        hmac
      } = mockData;
      delete parentCapabilities.keyAgreementKey;
      let error;
      let result;
      try {
        result = await profileManager.delegateEdvCapabilities({
          parentCapabilities, edvId, hmac
        });
      } catch(e) {
        error = e;
      }
      should.not.exist(result);
      should.exist(error);
      error.name.should.equal('TypeError');
      error.message.should.contain('keyAgreementKey');
    });
  });

  describe('getCollection api', () => {
    let profileManager;
    beforeEach(() => {
      profileManager = new ProfileManager({
        edvBaseUrl: EDV_BASE_URL
      });
    });
    it('should fail if profileId is undefined', async () => {
      let error;
      let result;
      try {
        result = await profileManager.getCollection({
          profileId: undefined,
          referenceIdPrefix: 'test.org:test-edv',
          type: 'test'
        });
      } catch(e) {
        error = e;
      }
      should.not.exist(result);
      should.exist(error);
      error.name.should.equal('TypeError');
      error.message.should.contain('profileId');
    });
    it('should fail if profileId is an empty string', async () => {
      let error;
      let result;
      try {
        result = await profileManager.getCollection({
          profileId: '',
          referenceIdPrefix: 'test.org:test-edv',
          type: 'test'
        });
      } catch(e) {
        error = e;
      }
      should.not.exist(result);
      should.exist(error);
      error.name.should.equal('TypeError');
      error.message.should.contain('profileId');
    });
  });

  describe('getProfileEdvAccess api', () => {
    let profileManager;
    beforeEach(() => {
      profileManager = new ProfileManager({
        edvBaseUrl: EDV_BASE_URL
      });
    });
    it('should fail if profileId is undefined', async () => {
      let error;
      let result;
      try {
        result = await profileManager.getProfileEdvAccess({
          profileId: undefined,
          referenceIdPrefix: 'test.org:test-edv'
        });
      } catch(e) {
        error = e;
      }
      should.not.exist(result);
      should.exist(error);
      error.name.should.equal('TypeError');
      error.message.should.contain('profileId');
    });
    it('should fail if profileId is an empty string', async () => {
      let error;
      let result;
      try {
        result = await profileManager.getProfileEdvAccess({
          profileId: '',
          referenceIdPrefix: 'test.org:test-edv'
        });
      } catch(e) {
        error = e;
      }
      should.not.exist(result);
      should.exist(error);
      error.name.should.equal('TypeError');
      error.message.should.contain('profileId');
    });
  });
});
