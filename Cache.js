/*!
 * Copyright (c) 2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

import LRU from 'lru-cache';

class Cache {
  constructor(options) {
    this.cache = new LRU(options);
  }

  set(id, data) {
    this.cache.set(id, data);
    return data;
  }

  get(id) {
    return this.cache.get(id) || null;
  }

  has(id) {
    return this.cache.has(id);
  }

  delete(id) {
    return this.cache.del(id);
  }

  clear() {
    this.cache.reset();
  }
}

const cache = new Cache();

export {Cache};
export default cache;
