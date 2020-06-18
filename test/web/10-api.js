/*!
 * Copyright (c) 2019-2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

import {ProfileManager} from 'bedrock-web-profile-manager';

const ACCOUNT_ID = 'urn:uuid:ffaf5d84-7dc2-4f7b-9825-cc8d2e5a5d06';
const KMS_MODULE = 'ssm-v1';
const KMS_BASE_URL = `${window.location.origin}/kms`;

describe('Profile Manager API', () => {
  describe('createProfile API', () => {
    it('successfully creates a profile', async () => {
      const profileManager = new ProfileManager({
        kmsModule: KMS_MODULE,
        kmsBaseUrl: KMS_BASE_URL,
        edvBaseUrl: `https://localhost:18443/edvs`,
        recoveryHost: window.location.host
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
  });

  describe('getProfileSigner api', () => {
    let profileManager;
    beforeEach(async () => {
      profileManager = new ProfileManager({
        kmsModule: KMS_MODULE,
        kmsBaseUrl: KMS_BASE_URL,
        edvBaseUrl: `https://localhost:18443/edvs`,
        recoveryHost: window.location.host
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
      let error, result;
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
      result.invocationSigner.type.should.contain('Ed25519VerificationKey2018');
      result.invocationSigner.should.have.property('sign');
    });
    it('should fail if profileId is undefined', async () => {
      let error, result;
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
      let error, result;
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
        kmsModule: KMS_MODULE,
        kmsBaseUrl: KMS_BASE_URL,
        edvBaseUrl: `https://localhost:18443/edvs`,
        recoveryHost: window.location.host
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
      let error, result;
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
      let error, result;
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
      let error, result;
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
        kmsModule: KMS_MODULE,
        kmsBaseUrl: KMS_BASE_URL,
        edvBaseUrl: `https://localhost:18443/edvs`,
        recoveryHost: window.location.host
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
    it('should successfully initialize w/ default invoker', async () => {
      let error, result;
      try {
        const content = {didMethod: 'v1', didOptions: {mode: 'test'}};
        const {id: profileId} = await profileManager.createProfile(content);

        const {edvClient} = await profileManager.createProfileEdv(
          {profileId, referenceId: 'example'});

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
    it('should successfully initialize w/ "local" invoker', async () => {
      let error, result;
      try {
        const content = {didMethod: 'v1', didOptions: {mode: 'test'}};
        const {id: profileId} = await profileManager.createProfile(content);

        const {edvClient} = await profileManager.createProfileEdv(
          {profileId, referenceId: 'example'});

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
    it('should successfully initialize w/ "agent" invoker', async () => {
      let error, result;
      try {
        const content = {didMethod: 'v1', didOptions: {mode: 'test'}};
        const {id: profileId} = await profileManager.createProfile(content);

        const {edvClient} = await profileManager.createProfileEdv(
          {profileId, referenceId: 'example'});

        result = await profileManager.initializeAccessManagement({
          profileId,
          profileContent: {foo: true},
          edvId: edvClient.id,
          hmac: edvClient.hmac,
          keyAgreementKey: edvClient.keyAgreementKey,
          capabilityInvoker: 'agent'
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
      let error, result;
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
      let error, result;
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
        kmsModule: KMS_MODULE,
        kmsBaseUrl: KMS_BASE_URL,
        edvBaseUrl: `https://localhost:18443/edvs`,
        recoveryHost: window.location.host
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
      let error, result;
      try {
        const content = {didMethod: 'v1', didOptions: {mode: 'test'}};
        const {id: profileId} = await profileManager.createProfile(content);

        const {edvClient} = await profileManager.createProfileEdv(
          {profileId, referenceId: 'example'});

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
      let error, result;
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
      let error, result;
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
      let error, result;
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
      let error, result;
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
        kmsModule: KMS_MODULE,
        kmsBaseUrl: KMS_BASE_URL,
        edvBaseUrl: `https://localhost:18443/edvs`,
        recoveryHost: window.location.host
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
      let error, result;
      try {
        const content = {didMethod: 'v1', didOptions: {mode: 'test'}};
        const {id: profileId} = await profileManager.createProfile(content);
        result = await profileManager.getProfileKeystoreAgent(
          {profileId});
      } catch(e) {
        error = e;
      }
      should.not.exist(error);
      should.exist(result);
      result.should.have.property('capabilityAgent');
      result.capabilityAgent.should.have.property('id');
      result.capabilityAgent.id.should.contain('did:v1:');
      result.should.have.property('keystore');
      result.should.have.property('kmsClient');
    });
    it('should fail if profileId is undefined', async () => {
      let error, result;
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
      let error, result;
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
        kmsModule: KMS_MODULE,
        kmsBaseUrl: KMS_BASE_URL,
        edvBaseUrl: `https://localhost:18443/edvs`,
        recoveryHost: window.location.host
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
    it('should succeed w/ initialized profile access management', async () => {
      let error, result;
      try {
        const content = {didMethod: 'v1', didOptions: {mode: 'test'}};
        const {id: profileId} = await profileManager.createProfile(content);

        const {edvClient} = await profileManager.createProfileEdv(
          {profileId, referenceId: 'example'});

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
      result.should.have.property('profile');
      result.profile.should.have.property('id');
      result.profile.id.should.contain('did:v1:');
      result.profile.should.have.property('accessManagement');
      result.should.have.property('profileManager');
      result.should.have.property('users');
      should.not.exist(error);
      should.exist(result);
    });
    it('should fail w/ uninitialized profile access management', async () => {
      let error, result;
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
      let error, result;
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
      let error, result;
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
        kmsModule: KMS_MODULE,
        kmsBaseUrl: KMS_BASE_URL,
        edvBaseUrl: `https://localhost:18443/edvs`,
        recoveryHost: window.location.host
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
      let error, result;
      try {
        const content = {didMethod: 'v1', didOptions: {mode: 'test'}};
        const {id: profileId} = await profileManager.createProfile(content);

        result = await profileManager.createProfileEdv(
          {profileId, referenceId: 'example'});
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
      let error, result;
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
      let error, result;
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
        kmsModule: KMS_MODULE,
        kmsBaseUrl: KMS_BASE_URL,
        edvBaseUrl: `https://localhost:18443/edvs`,
        recoveryHost: window.location.host
      });
    });
    it('should fail if profileId is undefined', async () => {
      let error, result;
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
      let error, result;
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
  });
  describe('getCollection api', () => {
    let profileManager;
    beforeEach(() => {
      profileManager = new ProfileManager({
        kmsModule: KMS_MODULE,
        kmsBaseUrl: KMS_BASE_URL,
        edvBaseUrl: `https://localhost:18443/edvs`,
        recoveryHost: window.location.host
      });
    });
    it('should fail if profileId is undefined', async () => {
      let error, result;
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
      let error, result;
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
        kmsModule: KMS_MODULE,
        kmsBaseUrl: KMS_BASE_URL,
        edvBaseUrl: `https://localhost:18443/edvs`,
        recoveryHost: window.location.host
      });
    });
    it('should fail if profileId is undefined', async () => {
      let error, result;
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
      let error, result;
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
