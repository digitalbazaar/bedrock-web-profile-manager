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
const productIdMap = new Map();

const products = [{
  // eslint-disable-next-line max-len
  // Use product ID found in bedrock-profile-http: https://github.com/digitalbazaar/bedrock-profile-http/blob/ded73027d0ae6db929a543057ec60ad0a58c5da9/lib/http.js#L60
  id: 'urn:uuid:80a82316-e8c2-11eb-9570-10bf48838a41',
  name: 'Example KMS',
  service: {
    // default dev `id` configured in `bedrock-kms-http`
    id: 'did:key:z6MkwZ7AXrDpuVi5duY2qvVSx1tBkGmVnmRjDvvwzoVnAzC4',
    type: 'webkms',
  }
}, {
  // Use default `veres-vault` dev `id` and `serviceId`
  id: 'urn:uuid:dbd15f08-ff67-11eb-893b-10bf48838a41',
  name: 'Example EDV',
  service: {
    // default dev `id` configured in `bedrock-edv-storage`
    id: 'did:key:z6MkhNyDoLpNcPv5grXoJSJVJjvApd46JU5nPL6cwi88caYW',
    type: 'edv',
  }
}];

for(const product of products) {
  productIdMap.set(product.id, product);
  productIdMap.set(product.name, product);
}

bedrock.events.on('bedrock.init', async () => {
  /* Handlers need to be added before `bedrock.start` is called. These are
  no-op handlers to enable meter usage without restriction */
  handlers.setCreateHandler({
    handler({meter} = {}) {
      // use configured meter usage reporter as service ID for tests
      const product = productIdMap.get(meter.product.id);
      if(!product) {
        console.log(`Incorrect test setup. Product not found.`, {meter});
        process.exit(1);
      }
      meter.serviceId = product.service.id;
      return {meter};
    }
  });
  handlers.setUpdateHandler({handler: ({meter} = {}) => ({meter})});
  handlers.setRemoveHandler({handler: ({meter} = {}) => ({meter})});
  handlers.setUseHandler({handler: ({meter} = {}) => ({meter})});
});

const brPassport = require('bedrock-passport');
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
