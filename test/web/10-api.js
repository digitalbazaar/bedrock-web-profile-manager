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
      result.should.have.property('name');
      result.should.have.property('color');
      result.should.have.property('type');
      result.should.have.property('id');
      result.should.have.property('profileAgentId');
    });
  });
});
