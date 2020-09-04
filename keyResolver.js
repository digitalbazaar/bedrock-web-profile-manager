/*!
 * Copyright (c) 2020 Digital Bazaar, Inc. All rights reserved.
 */
import {httpClient} from '@digitalbazaar/http-client';
import assert from 'assert-plus';

async function keyResolver({id, didMethod = 'key'} = {}) {
  assert.string(id, 'id');
  assert.string(didMethod, 'didMethod');
  const SUPPORTED_DID_METHODS = ['key', 'v1'];
  if(!SUPPORTED_DID_METHODS.includes(didMethod)) {
    throw new Error(`Unsupported DID method "${didMethod}".`);
  }
  const headers = {Accept: 'application/ld+json, application/json'};
  const response = await httpClient.get(id, {
    headers
  });
  return response.data;
}

export default keyResolver;
