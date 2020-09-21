/*!
 * Copyright (c) 2020 Digital Bazaar, Inc. All rights reserved.
 */
import {httpClient} from '@digitalbazaar/http-client';
import assert from 'assert-plus';
import didIo from 'did-io';
import {driver as keyDriver} from 'did-method-key';
import {driver as veresDriver} from 'did-method-key';

// config did-io to support did:key and did:v1 drivers
didIo.use('key', keyDriver());
didIo.use('v1', veresDriver());

async function keyResolver({id, didMethod = 'key'} = {}) {
  assert.string(id, 'id');
  assert.string(didMethod, 'didMethod');
  if(id.startsWith('did:')) {
    return didIo.get({did: id});
  }
  const headers = {Accept: 'application/ld+json, application/json'};
  const response = await httpClient.get(id, {
    headers
  });
  return response.data;
}

export default keyResolver;
