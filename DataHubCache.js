/*!
 * Copyright (c) 2019 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

export default class DataHubCache {
  constructor() {
    this.cache = new Map();
  }

  async set(id, dataHub) {
    dataHub.ensureIndex({attribute: 'id', unique: true});
    dataHub.ensureIndex({attribute: 'type'});
    this.cache.set(id, dataHub);
    return dataHub;
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
