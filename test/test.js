/*!
 * Copyright (c) 2019-2021 Digital Bazaar, Inc. All rights reserved.
 */
const bedrock = require('bedrock');
require('bedrock-mongodb');
require('bedrock-https-agent');
require('bedrock-security-context');
require('bedrock-profile');
require('bedrock-profile-http');
require('bedrock-kms');
require('bedrock-kms-http');
require('bedrock-meter');
require('bedrock-meter-usage-reporter');
const {handlers} = require('bedrock-meter-http');
require('bedrock-ssm-mongodb');
require('bedrock-edv-storage');

// mock product IDs and reverse lookup for webkms/edv/etc service products
const productIdMap = new Map([
  // webkms service
  ['webkms', 'urn:uuid:80a82316-e8c2-11eb-9570-10bf48838a41'],
  ['urn:uuid:80a82316-e8c2-11eb-9570-10bf48838a41', 'webkms'],
  // edv service
  ['edv', 'urn:uuid:dbd15f08-ff67-11eb-893b-10bf48838a41'],
  ['urn:uuid:dbd15f08-ff67-11eb-893b-10bf48838a41', 'edv']
]);

bedrock.events.on('bedrock.init', async () => {
  /* Handlers need to be added before `bedrock.start` is called. These are
  no-op handlers to enable meter usage without restriction */
  handlers.setCreateHandler({
    handler({meter} = {}) {
      // use configured meter usage reporter as service ID for tests
      const clientName = productIdMap.get(meter.product.id);
      meter.serviceId = bedrock.config['meter-usage-reporter']
        .clients[clientName].id;
      return {meter};
    }
  });
  handlers.setUpdateHandler({handler: ({meter} = {}) => ({meter})});
  handlers.setRemoveHandler({handler: ({meter} = {}) => ({meter})});
  handlers.setUseHandler({handler: ({meter} = {}) => ({meter})});
});

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
