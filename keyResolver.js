/*!
 * Copyright (c) 2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

import axios from 'axios';

async function keyResolver({id, didMethod = 'key'} = {}) {
  const SUPPORTED_DID_METHODS = ['key', 'v1'];
  if(!SUPPORTED_DID_METHODS.includes(didMethod)) {
    throw new Error(`Unsupported DID method "${didMethod}".`);
  }
  const headers = {Accept: 'application/ld+json, application/json'};
  const response = await axios.get(id, {
    headers
  });
  return response.data;
}

export default keyResolver;
