/*!
 * Copyright (c) 2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

import axios from 'axios';

// FIXME: make more restrictive, support `did:key` and `did:v1`
// TODO: could be made more restrictive is based on a config option that
//       specifies where the KMS is.
async function keyResolver({id} = {}) {
  const headers = {Accept: 'application/ld+json, application/json'};
  const response = await axios.get(id, {
    headers
  });
  return response.data;
}

export default keyResolver;
