/*!
 * Copyright (c) 2019-2022 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import {handlers} from '@bedrock/meter-http';
import {passport} from '@bedrock/passport';
import '@bedrock/security-context';
import '@bedrock/edv-storage';
import '@bedrock/https-agent';
import '@bedrock/profile';
import '@bedrock/profile-http';
import '@bedrock/kms';
import '@bedrock/kms-http';
import '@bedrock/mongodb';
import '@bedrock/ssm-mongodb';
import '@bedrock/meter';
import '@bedrock/meter-usage-reporter';

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

passport.authenticate = (strategyName, options, callback) => {
  // eslint-disable-next-line no-unused-vars
  return async function(req, res, next) {
    req._sessionManager = passport._sm;
    req.isAuthenticated = req.isAuthenticated || (() => !!req.user);
    req.login = (user, callback) => {
      req._sessionManager.logIn(req, user, function(err) {
        if(err) {
          req.user = null;
          return callback(err);
        }
        callback();
      });
    };
    const user = {
      account: {id: 'urn:uuid:ffaf5d84-7dc2-4f7b-9825-cc8d2e5a5d06'}
    };
    callback(null, user);
  };
};

import '@bedrock/test';
import '@bedrock/karma';

bedrock.start();
