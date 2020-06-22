/*!
 * Copyright (c) 2019-2020 Digital Bazaar, Inc. All rights reserved.
 */

import LRU from 'lru-cache';

export default class EdvClientCache {
  constructor() {
    this.cache = new LRU();
  }

  async set(id, client) {
    client.ensureIndex({attribute: 'content.id', unique: true});
    client.ensureIndex({attribute: 'content.type'});
    this.cache.set(id, client);
    return client;
  }

  async get(id) {
    return this.cache.get(id) || null;
  }

  async delete(id) {
    return this.cache.del(id);
  }

  async clear() {
    this.cache.clear();
  }
}
