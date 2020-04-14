/*!
 * Copyright (c) 2019-2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

import {ProfileManager} from 'bedrock-web-profile-manager';

const KMS_MODULE = 'ssm-v1';
const KMS_BASE_URL = `${window.location.origin}/kms`;

describe('Profile Manager API', () => {
  describe('createProfile API', () => {
    it('successfully creates a profile', async () => {
      const profileManager = new ProfileManager({
        kmsModule: KMS_MODULE,
        kmsBaseUrl: KMS_BASE_URL,
        edvBaseUrl: `https://bedrock.localhost:18443/edvs`,
        recoveryHost: window.location.host
      });

      await profileManager.setSession({
        session: {
          data: {
            account: {
              id: 'urn:uuid:ffaf5d84-7dc2-4f7b-9825-cc8d2e5a5d06'
            }
          },
          on: () => {},
        }
      });

      let error;
      let result;
      try {
        result = await profileManager.createProfile({
          type: 'Person',
          content: {name: 'Mike Smith', color: '#000000'}
        });
      } catch(e) {
        error = e;
      }
      should.not.exist(error);
      should.exist(result);
      result.should.have.property('id');
      result.id.should.be.a('string');
    });
  });
  describe('getProfileSigner api', () => {
    let profileManager = null;
    beforeEach(() => {
      profileManager = new ProfileManager({
        kmsModule: KMS_MODULE,
        kmsBaseUrl: KMS_BASE_URL,
        edvBaseUrl: `https://bedrock.localhost:18443/edvs`,
        recoveryHost: window.location.host
      });
    });
    it('should fail if profileId is undefined', async () => {
      let error, result = null;
      try {
        result = await profileManager.getProfileSigner({profileId: undefined});
      } catch(e) {
        error = e;
      }
      should.not.exist(result);
      should.exist(error);
      error.name.should.equal('TypeError');
    });
    it('should fail if profileId is an empty string', async () => {
      let error, result = null;
      try {
        result = await profileManager.getProfileSigner({profileId: ''});
      } catch(e) {
        error = e;
      }
      should.not.exist(result);
      should.exist(error);
      error.name.should.equal('TypeError');
    });
  });
  describe('getAgent api', () => {
    let profileManager = null;
    beforeEach(() => {
      profileManager = new ProfileManager({
        kmsModule: KMS_MODULE,
        kmsBaseUrl: KMS_BASE_URL,
        edvBaseUrl: `https://bedrock.localhost:18443/edvs`,
        recoveryHost: window.location.host
      });
    });
    it('should fail if profileId is undefined', async () => {
      let error, result = null;
      try {
        result = await profileManager.getAgent({profileId: undefined});
      } catch(e) {
        error = e;
      }
      should.not.exist(result);
      should.exist(error);
      error.name.should.equal('TypeError');
    });
    it('should fail if profileId is an empty string', async () => {
      let error, result = null;
      try {
        result = await profileManager.getAgent({profileId: ''});
      } catch(e) {
        error = e;
      }
      should.not.exist(result);
      should.exist(error);
      error.name.should.equal('TypeError');
    });
  });
  describe('initializeAccessManagement api', () => {
    let profileManager = null;
    beforeEach(() => {
      profileManager = new ProfileManager({
        kmsModule: KMS_MODULE,
        kmsBaseUrl: KMS_BASE_URL,
        edvBaseUrl: `https://bedrock.localhost:18443/edvs`,
        recoveryHost: window.location.host
      });
    });
    it('should fail if profileId is undefined', async () => {
      let error, result = null;
      try {
        result = await profileManager.initializeAccessManagement(
          {profileId: undefined});
      } catch(e) {
        error = e;
      }
      should.not.exist(result);
      should.exist(error);
      error.name.should.equal('TypeError');
    });
    it('should fail if profileId is an empty string', async () => {
      let error, result = null;
      try {
        result = await profileManager.initializeAccessManagement(
          {profileId: ''});
      } catch(e) {
        error = e;
      }
      should.not.exist(result);
      should.exist(error);
      error.name.should.equal('TypeError');
    });
  });
  describe('getProfile api', () => {
    let profileManager = null;
    beforeEach(() => {
      profileManager = new ProfileManager({
        kmsModule: KMS_MODULE,
        kmsBaseUrl: KMS_BASE_URL,
        edvBaseUrl: `https://bedrock.localhost:18443/edvs`,
        recoveryHost: window.location.host
      });
    });
    it('should fail if profileId is undefined', async () => {
      let error, result = null;
      try {
        result = await profileManager.getProfile({id: undefined});
      } catch(e) {
        error = e;
      }
      should.not.exist(result);
      should.exist(error);
      error.name.should.equal('TypeError');
    });
    it('should fail if profileId is an empty string', async () => {
      let error, result = null;
      try {
        result = await profileManager.getProfile({id: ''});
      } catch(e) {
        error = e;
      }
      should.not.exist(result);
      should.exist(error);
      error.name.should.equal('TypeError');
    });
  });
  describe('getProfileKeystoreAgent api', () => {
    let profileManager = null;
    beforeEach(() => {
      profileManager = new ProfileManager({
        kmsModule: KMS_MODULE,
        kmsBaseUrl: KMS_BASE_URL,
        edvBaseUrl: `https://bedrock.localhost:18443/edvs`,
        recoveryHost: window.location.host
      });
    });
    it('should fail if profileId is undefined', async () => {
      let error, result = null;
      try {
        result = await profileManager.getProfileKeystoreAgent(
          {profileId: undefined});
      } catch(e) {
        error = e;
      }
      should.not.exist(result);
      should.exist(error);
      error.name.should.equal('TypeError');
    });
    it('should fail if profileId is an empty string', async () => {
      let error, result = null;
      try {
        result = await profileManager.getProfileKeystoreAgent({profileId: ''});
      } catch(e) {
        error = e;
      }
      should.not.exist(result);
      should.exist(error);
      error.name.should.equal('TypeError');
    });
  });
  describe('getAccessManager api', () => {
    let profileManager = null;
    beforeEach(() => {
      profileManager = new ProfileManager({
        kmsModule: KMS_MODULE,
        kmsBaseUrl: KMS_BASE_URL,
        edvBaseUrl: `https://bedrock.localhost:18443/edvs`,
        recoveryHost: window.location.host
      });
    });
    it('should fail if profileId is undefined', async () => {
      let error, result = null;
      try {
        result = await profileManager.getAccessManager({profileId: undefined});
      } catch(e) {
        error = e;
      }
      should.not.exist(result);
      should.exist(error);
      error.name.should.equal('TypeError');
    });
    it('should fail if profileId is an empty string', async () => {
      let error, result = null;
      try {
        result = await profileManager.getAccessManager({profileId: ''});
      } catch(e) {
        error = e;
      }
      should.not.exist(result);
      should.exist(error);
      error.name.should.equal('TypeError');
    });
  });
  describe('createProfileEdv api', () => {
    let profileManager = null;
    beforeEach(() => {
      profileManager = new ProfileManager({
        kmsModule: KMS_MODULE,
        kmsBaseUrl: KMS_BASE_URL,
        edvBaseUrl: `https://bedrock.localhost:18443/edvs`,
        recoveryHost: window.location.host
      });
    });
    it('should fail if profileId is undefined', async () => {
      let error, result = null;
      try {
        result = await profileManager.createProfileEdv({profileId: undefined});
      } catch(e) {
        error = e;
      }
      should.not.exist(result);
      should.exist(error);
      error.name.should.equal('TypeError');
    });
    it('should fail if profileId is an empty string', async () => {
      let error, result = null;
      try {
        result = await profileManager.createProfileEdv({profileId: ''});
      } catch(e) {
        error = e;
      }
      should.not.exist(result);
      should.exist(error);
      error.name.should.equal('TypeError');
    });
  });
  describe('delegateCapability api', () => {
    let profileManager = null;
    beforeEach(() => {
      profileManager = new ProfileManager({
        kmsModule: KMS_MODULE,
        kmsBaseUrl: KMS_BASE_URL,
        edvBaseUrl: `https://bedrock.localhost:18443/edvs`,
        recoveryHost: window.location.host
      });
    });
    it('should fail if profileId is undefined', async () => {
      let error, result = null;
      try {
        result = await profileManager.delegateCapability(
          {profileId: undefined});
      } catch(e) {
        error = e;
      }
      should.not.exist(result);
      should.exist(error);
      error.name.should.equal('TypeError');
    });
    it('should fail if profileId is an empty string', async () => {
      let error, result = null;
      try {
        result = await profileManager.delegateCapability({profileId: ''});
      } catch(e) {
        error = e;
      }
      should.not.exist(result);
      should.exist(error);
      error.name.should.equal('TypeError');
    });
  });
  describe('getCollection api', () => {
    let profileManager = null;
    beforeEach(() => {
      profileManager = new ProfileManager({
        kmsModule: KMS_MODULE,
        kmsBaseUrl: KMS_BASE_URL,
        edvBaseUrl: `https://bedrock.localhost:18443/edvs`,
        recoveryHost: window.location.host
      });
    });
    it('should fail if profileId is undefined', async () => {
      let error, result = null;
      try {
        result = await profileManager.getCollection({profileId: undefined});
      } catch(e) {
        error = e;
      }
      should.not.exist(result);
      should.exist(error);
      error.name.should.equal('TypeError');
    });
    it('should fail if profileId is an empty string', async () => {
      let error, result = null;
      try {
        result = await profileManager.getCollection({profileId: ''});
      } catch(e) {
        error = e;
      }
      should.not.exist(result);
      should.exist(error);
      error.name.should.equal('TypeError');
    });
  });
  describe('getProfileEdvAccess api', () => {
    let profileManager = null;
    beforeEach(() => {
      profileManager = new ProfileManager({
        kmsModule: KMS_MODULE,
        kmsBaseUrl: KMS_BASE_URL,
        edvBaseUrl: `https://bedrock.localhost:18443/edvs`,
        recoveryHost: window.location.host
      });
    });
    it('should fail if profileId is undefined', async () => {
      let error, result = null;
      try {
        result = await profileManager.getProfileEdvAccess(
          {profileId: undefined});
      } catch(e) {
        error = e;
      }
      should.not.exist(result);
      should.exist(error);
      error.name.should.equal('TypeError');
    });
    it('should fail if profileId is an empty string', async () => {
      let error, result = null;
      try {
        result = await profileManager.getProfileEdvAccess({profileId: ''});
      } catch(e) {
        error = e;
      }
      should.not.exist(result);
      should.exist(error);
      error.name.should.equal('TypeError');
    });
  });

});
