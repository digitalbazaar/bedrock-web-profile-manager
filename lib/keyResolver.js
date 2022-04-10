/*!
 * Copyright (c) 2020-2022 Digital Bazaar, Inc. All rights reserved.
 */
import {documentLoader} from './utils.js';
import {httpClient} from '@digitalbazaar/http-client';
import {LruCache} from '@digitalbazaar/lru-memoize';

// process-wide shared cache for resolved keys
const KEY_DESCRIPTION_CACHE = new LruCache({
  // 1000 keys at ~1 KiB each would be only ~1 MiB cache size
  max: 1000,
  // 5 min TTL (key descriptions rarely, if ever, change)
  maxAge: 1000 * 60 * 5
});

async function keyResolver({id} = {}) {
  if(typeof id !== 'string') {
    throw new TypeError('"id" string is required.');
  }
  return KEY_DESCRIPTION_CACHE.memoize({
    key: id,
    fn: () => _getUncachedKeyDescription({id})
  });
}

async function _getUncachedKeyDescription({id}) {
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
