/*!
 * Copyright (c) 2020-2021 Digital Bazaar, Inc. All rights reserved.
 */
import didIo from 'did-io';
import {driver as keyDriver} from 'did-method-key';
import {driver as veresDriver} from 'did-veres-one';
import {httpClient} from '@digitalbazaar/http-client';

// config did-io to support did:key and did:v1 drivers
didIo.use('key', keyDriver());
didIo.use('v1', veresDriver());

async function keyResolver({id} = {}) {
  if(typeof id !== 'string') {
    throw new TypeError('"id" string is required.');
  }
  if(id.startsWith('did:')) {
    return didIo.get({did: id, forceConstruct: true});
  }

  const headers = {Accept: 'application/ld+json, application/json'};
  const response = await httpClient.get(id, {
    headers
  });
  return response.data;
}

export default keyResolver;
