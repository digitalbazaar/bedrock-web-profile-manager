/*!
 * Copyright (c) 2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

export class Cache {
  constructor() {
    this.cache = new Map();
  }

  set(id, data) {
    this.cache.set(id, data);
    return data;
  }

  get(id) {
    return this.cache.get(id) || null;
  }

  delete(id) {
    return this.cache.delete(id);
  }

  clear() {
    this.cache.clear();
  }
}

const cache = new Cache();

export default cache;
