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
// brPassport.optionallyAuthenticated = (req, res, next) => {
//   req.user = {
//     account: {},
//     actor: mockData.actors.alpha
//   };
//   next();
// };

require('bedrock-test');
require('bedrock-karma');

bedrock.start();
