/*!
 * Copyright (c) 2019-2021 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const {config} = require('bedrock');
const path = require('path');

config.karma.suites['bedrock-web-kms'] = path.join('web', '**', '*.js');

config.karma.config.proxies = {
  '/': {
    target: 'https://localhost:18443',
  }
};
config.karma.config.proxyValidateSSL = false;
// Enable for rapid unit test development
// config.karma.config.singleRun = false;
// config.karma.config.browsers = ['Chrome_special'];
// config.karma.config.customLaunchers = {
//   Chrome_special: {
//     base: 'Chrome',
//     flags: [
//       '--disable-web-security',
//       '--ignore-ssl-errors',
//       '--ignore-certificate-errors',
//       '--remote-debugging-port=9223'
//     ]
//   }
// };

// mongodb config
config.mongodb.name = 'bedrock_web_profile_manager_test';
config.mongodb.host = 'localhost';
config.mongodb.port = 27017;
// drop all collections on initialization
config.mongodb.dropCollections = {};
config.mongodb.dropCollections.onInit = true;
config.mongodb.dropCollections.collections = [];

// allow self-signed certs in test framework
config['https-agent'].rejectUnauthorized = false;

// do not require an authentication session for tests
config['kms-http'].requireAuthentication = false;

config.server.host = 'localhost:9876';
config.kms.allowedHost = config.server.host;

config.profile.kms.baseUrl = `${config.server.baseUri}/kms`;
config.profile.kms.ipAllowList = ['127.0.0.1/32'];

// use session
config.express.useSession = true;
config.express.jsonErrorLevel = 'full';
