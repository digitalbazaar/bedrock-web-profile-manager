/*!
 * Copyright (c) 2019-2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

import cache from './Cache';

export default class EdvClientCache {
  constructor() {
    this.cache = cache.set('edv-client-cache', new Map());
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
    return this.cache.delete(id);
  }

  async clear() {
    this.cache.clear();
  }
}
