/*!
 * Copyright (c) 2020-2021 Digital Bazaar, Inc. All rights reserved.
 */
import {documentLoader} from './utils.js';
import {httpClient} from '@digitalbazaar/http-client';

async function keyResolver({id} = {}) {
  if(typeof id !== 'string') {
    throw new TypeError('"id" string is required.');
  }
  let document;
  if(id.startsWith('did:')) {
    ({document} = await documentLoader(id));
  } else {
    const response = await httpClient.get(id);
    document = response.data;
  }

  return document;
}

export default keyResolver;
