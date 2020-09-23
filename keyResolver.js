/*!
 * Copyright (c) 2020 Digital Bazaar, Inc. All rights reserved.
 */
import {httpClient} from '@digitalbazaar/http-client';
import assert from 'assert-plus';
import didIo from 'did-io';
import {driver as keyDriver} from 'did-method-key';
import {driver as veresDriver} from 'did-veres-one';

// config did-io to support did:key and did:v1 drivers
didIo.use('key', keyDriver());
didIo.use('v1', veresDriver());

async function keyResolver({id} = {}) {
  assert.string(id, 'id');
  if(id.startsWith('did:')) {
    return didIo.get({did: id, forceConstruct: true});
  }
  if(id.startsWith(location.origin)) {
    const headers = {Accept: 'application/ld+json, application/json'};
    const response = await httpClient.get(id, {
      headers
    });
    return response.data;
  }
  throw new Error(
    `"id" must start with either "did:" or "${location.origin}".`
  );
}

export default keyResolver;
