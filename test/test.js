/*!
 * Copyright (c) 2019-2020 Digital Bazaar, Inc. All rights reserved.
 */
const bedrock = require('bedrock');
require('bedrock-mongodb');
require('bedrock-https-agent');
require('bedrock-security-context');
require('bedrock-profile');
require('bedrock-profile-http');
require('bedrock-kms');
require('bedrock-kms-http');
require('bedrock-ssm-mongodb');
require('bedrock-edv-storage');

const brPassport = require('bedrock-passport');
// const mockData = require('./web/mock-data');
brPassport.optionallyAuthenticated = (req, res, next) => {
  req.user = {
    account: {
      id: 'urn:uuid:ffaf5d84-7dc2-4f7b-9825-cc8d2e5a5d06',
    },
    actor: {},
    // actor: mockData.actors.alpha
  };
  next();
};

require('bedrock-test');
require('bedrock-karma');

bedrock.start();
