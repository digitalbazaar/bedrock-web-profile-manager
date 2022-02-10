/*!
 * Copyright (c) 2019-2022 Digital Bazaar, Inc. All rights reserved.
 */
import {ProfileManager} from 'bedrock-web-profile-manager';
import {ProfileService} from 'bedrock-web-profile';
import sinon from 'sinon';
import {mockData} from './mock.data.js';

const ACCOUNT_ID = 'urn:uuid:ffaf5d84-7dc2-4f7b-9825-cc8d2e5a5d06';
const KMS_BASE_URL = `${window.location.origin}/kms`;
const EDV_BASE_URL = `${window.location.origin}/edvs`;

describe('Profile Manager API', () => {
  describe('createProfile API', () => {
    it('successfully creates a profile', async () => {
      const profileManager = new ProfileManager({
        kmsBaseUrl: KMS_BASE_URL,
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
        const content = {didMethod: 'v1', didOptions: {mode: 'test'}};
        result = await profileManager.createProfile(content);
      } catch(e) {
        error = e;
      }
      should.not.exist(error);
      should.exist(result);
      result.should.have.property('id');
      result.id.should.be.a('string');
      result.id.should.match(/^did\:v1\:test\:/);
    });
    it('successfully creates a profile with a custom ProfileService',
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
          kmsBaseUrl: KMS_BASE_URL,
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
          const content = {didMethod: 'v1', didOptions};
          result = await profileManager.createProfile(content);
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
        kmsBaseUrl: KMS_BASE_URL,
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
        const content = {didMethod: 'v1', didOptions: {mode: 'test'}};
        const {id: profileId} = await profileManager.createProfile(content);
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
        kmsBaseUrl: KMS_BASE_URL,
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
        const content = {didMethod: 'v1', didOptions: {mode: 'test'}};
        const {id: profileId} = await profileManager.createProfile(content);
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
  describe('initializeAccessManagement api', () => {
    let profileManager;
    beforeEach(async () => {
      profileManager = new ProfileManager({
        kmsBaseUrl: KMS_BASE_URL,
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
    it('should successfully initialize', async () => {
      let error;
      const content = {didMethod: 'v1', didOptions: {mode: 'test'}};
      let profileId;
      let meters;
      try {
        ({id: profileId, meters} = await profileManager.createProfile(content));
      } catch(e) {
        error = e;
      }
      should.not.exist(error);

      error = null;
      let edvClient;
      const {meter: edvMeter} = meters.find(
        m => m.meter.referenceId === 'profile:core:edv');
      try {
        ({edvClient} = await profileManager.createProfileEdv(
          {profileId, meterId: edvMeter.id, referenceId: 'example'}));
      } catch(e) {
        error = e;
      }
      should.not.exist(error);

      error = null;
      let result;
      try {
        result = await profileManager.initializeAccessManagement({
          profileId,
          profileContent: {foo: true},
          edvId: edvClient.id,
          hmac: edvClient.hmac,
          keyAgreementKey: edvClient.keyAgreementKey
        });
      } catch(e) {
        error = e;
      }
      should.not.exist(error);
      should.exist(result);
      result.should.have.property('profile');
      result.profile.should.have.property('id');
      result.profile.id.should.be.a('string');
      result.profile.id.should.contain('did:v1:');
      result.profile.should.have.property('accessManagement');
      result.profile.should.have.property('type');
      result.profile.type.should.include.members(['User', 'Profile']);
      result.should.have.property('profileAgent');
      result.profileAgent.should.have.property('id');
      result.profileAgent.id.should.contain('did:key:');
      result.profileAgent.should.have.property('type');
      result.profileAgent.type.should.include.members(['User', 'Agent']);
      result.profileAgent.should.have.property('zcaps');
    });
    it('should fail if profileId is undefined', async () => {
      let error;
      let result;
      try {
        result = await profileManager.initializeAccessManagement({
          profileId: undefined,
          profileContent: {foo: true},
          profileAgentContent: {bar: false},
          edvId: 'testEdvId'
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
        result = await profileManager.initializeAccessManagement({
          profileId: '',
          profileContent: {foo: true},
          profileAgentContent: {bar: false},
          edvId: 'testEdvId'
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
  describe('getProfile api', () => {
    let profileManager;
    beforeEach(async () => {
      profileManager = new ProfileManager({
        kmsBaseUrl: KMS_BASE_URL,
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
    it('should succeed w/ initialized profile', async () => {
      let error;
      let result;
      try {
        const content = {didMethod: 'v1', didOptions: {mode: 'test'}};
        const {id: profileId, meters} = await profileManager.createProfile(
          content);
        const {meter: edvMeter} = meters.find(
          m => m.meter.referenceId === 'profile:core:edv');

        const {edvClient} = await profileManager.createProfileEdv(
          {profileId, meterId: edvMeter.id, referenceId: 'example'});

        result = await profileManager.initializeAccessManagement({
          profileId,
          profileContent: {foo: true},
          edvId: edvClient.id,
          hmac: edvClient.hmac,
          keyAgreementKey: edvClient.keyAgreementKey
        });
        result = await profileManager.getProfile({id: profileId});
      } catch(e) {
        error = e;
      }
      should.not.exist(error);
      should.exist(result);
    });
    it(`should fail w/ uninitialized profile access management`, async () => {
      let error;
      let result;
      try {
        const content = {didMethod: 'v1', didOptions: {mode: 'test'}};
        const {id} = await profileManager.createProfile(content);
        result = await profileManager.getProfile({id});
      } catch(e) {
        error = e;
      }
      should.not.exist(result);
      should.exist(error);
    });
    it(`should fail w/ unintialized profile access management`, async () => {
      let error;
      let result;
      try {
        const content = {didMethod: 'v1', didOptions: {mode: 'test'}};
        const {id} = await profileManager.createProfile(content);
        result = await profileManager.getProfile({id});
      } catch(e) {
        error = e;
      }
      should.not.exist(result);
      should.exist(error);
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
  describe('getProfileKeystoreAgent api', () => {
    let profileManager;
    beforeEach(async () => {
      profileManager = new ProfileManager({
        kmsBaseUrl: KMS_BASE_URL,
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
        const content = {didMethod: 'v1', didOptions: {mode: 'test'}};
        const {id: profileId} = await profileManager.createProfile(content);
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
  describe('getAccessManager api', () => {
    let profileManager;
    beforeEach(async () => {
      profileManager = new ProfileManager({
        kmsBaseUrl: KMS_BASE_URL,
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
    it('should succeed w/ initialized profile access management',
      async () => {
        let error;
        let result;
        try {
          const content = {didMethod: 'v1', didOptions: {mode: 'test'}};
          const {id: profileId, meters} = await profileManager.createProfile(
            content);
          const {meter: edvMeter} = meters.find(
            m => m.meter.referenceId === 'profile:core:edv');

          const {edvClient} = await profileManager.createProfileEdv(
            {profileId, meterId: edvMeter.id, referenceId: 'example'});

          result = await profileManager.initializeAccessManagement({
            profileId,
            profileContent: {foo: true},
            edvId: edvClient.id,
            hmac: edvClient.hmac,
            keyAgreementKey: edvClient.keyAgreementKey
          });
          result = await profileManager.getAccessManager(
            {profileId});
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
    it('should fail w/ uninitialized profile access management', async () => {
      let error;
      let result;
      try {
        const content = {didMethod: 'v1', didOptions: {mode: 'test'}};
        const {id: profileId} = await profileManager.createProfile(content);
        result = await profileManager.getAccessManager(
          {profileId});
      } catch(e) {
        error = e;
      }
      should.not.exist(result);
      should.exist(error);
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
  describe('createProfileEdv api', () => {
    let profileManager;
    beforeEach(async () => {
      profileManager = new ProfileManager({
        kmsBaseUrl: KMS_BASE_URL,
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
        const content = {didMethod: 'v1', didOptions: {mode: 'test'}};
        const {id: profileId, meters} = await profileManager.createProfile(
          content);
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
  describe('delegateCapability api', () => {
    let profileManager;
    beforeEach(async () => {
      profileManager = new ProfileManager({
        kmsBaseUrl: KMS_BASE_URL,
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
        kmsBaseUrl: KMS_BASE_URL,
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
        kmsBaseUrl: KMS_BASE_URL,
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
  describe('zcap expiration', () => {
    it('should delegate a new zcap with new expiration date when a ' +
      'zcap delegated to ephemeral DID has expired', async () => {
      let error;
      let result;
      const profileManager = new ProfileManager({
        kmsBaseUrl: KMS_BASE_URL,
        edvBaseUrl: EDV_BASE_URL,
        // intentionally make zcap expired
        zcapGracePeriod: 100000000000000
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
      const content = {didMethod: 'v1', didOptions: {mode: 'test'}};
      const {id: profileId, meters} = await profileManager.createProfile(
        content);
      const {meter: edvMeter} = meters.find(
        m => m.meter.referenceId === 'profile:core:edv');

      const {edvClient} = await profileManager.createProfileEdv(
        {profileId, meterId: edvMeter.id, referenceId: 'example'});
      try {
        result = await profileManager.initializeAccessManagement({
          profileId,
          profileContent: {foo: true},
          edvId: edvClient.id,
          hmac: edvClient.hmac,
          keyAgreementKey: edvClient.keyAgreementKey
        });
        result = await profileManager.getAccessManager({profileId});
      } catch(e) {
        error = e;
      }
      const capability = result.users.capability;
      should.exist(result);
      should.not.exist(error);
      result.should.have.property('profile');
      result.profile.should.have.property('id');
      result.profile.id.should.contain('did:v1:');
      result.profile.should.have.property('accessManagement');
      result.should.have.property('profileManager');
      result.should.have.property('users');
      capability.should.have.property('expires');
    });
  });
});
