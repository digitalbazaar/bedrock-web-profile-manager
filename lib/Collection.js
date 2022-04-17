/*!
 * Copyright (c) 2020-2022 Digital Bazaar, Inc. All rights reserved.
 */
import {EdvClient} from '@digitalbazaar/edv-client';

export default class Collection {
  constructor({type, edvClient}) {
    this.type = type;
    this.edvClient = edvClient;
  }

  async create({item, meta} = {}) {
    if(!(item && typeof item === 'object')) {
      throw new TypeError(`"item" must be an object.`);
    }
    if(!(item.type === this.type ||
      (Array.isArray(item.type) && item.type.includes(this.type)))) {
      throw new TypeError(
        `"item.type" (${item.type}) must include "${this.type}".`);
    }
    const {edvClient} = this;
    const id = await EdvClient.generateId();
    return edvClient.update({doc: {id, content: item, meta}});
  }

  async get({id} = {}) {
    if(typeof id !== 'string') {
      throw new TypeError('"id" must be a string.');
    }
    const results = await this._findDocuments({id, limit: 1});
    if(results.length > 0) {
      return results[0];
    }
    return null;
  }

  async getAll() {
    const {type} = this;
    return this._findDocuments({type});
  }

  async update({id, item, meta, mutator} = {}) {
    if(id) {
      if(typeof id !== 'string') {
        throw new TypeError('"id" must be a string.');
      }
    }
    if(item) {
      if(typeof item !== 'object') {
        throw new TypeError('"item" must be an object.');
      }
      if(!(item.type === this.type ||
        (Array.isArray(item.type) && item.type.includes(this.type)))) {
        throw new TypeError(
          `"item.type" (${item.type}) must include "${this.type}".`);
      }
      if(!id) {
        id = item.id;
      }
    } else if(!(mutator && typeof mutator === 'function')) {
      throw new TypeError('"item" is required when "mutator" is not given.');
    }
    if(mutator && typeof mutator !== 'function') {
      throw new TypeError('"mutator" must be a function.');
    }
    const existing = await this.get({id});
    let updatedDoc;
    if(mutator) {
      updatedDoc = await mutator({item, meta, existing});
      if(!updatedDoc) {
        // nothing to update, return existing doc
        return existing;
      }
    } else {
      updatedDoc = {...existing};
      updatedDoc.content = item;
      if(meta) {
        updatedDoc.meta = meta;
      }
    }
    const {edvClient} = this;
    return edvClient.update({doc: updatedDoc});
  }

  async remove({id} = {}) {
    if(typeof id !== 'string') {
      throw new TypeError('"id" must be a string.');
    }
    const existing = await this.get({id});
    if(!existing) {
      return false;
    }
    const {edvClient} = this;
    return edvClient.delete({doc: existing});
  }

  async _findDocuments({id, type, equals, has, limit}) {
    if(!(id || type || equals || has)) {
      throw new TypeError('"id", "type", "equals", or "has" must be given.');
    }
    if(!equals) {
      equals = [];
    } else {
      equals = equals.slice();
    }
    if(id) {
      equals.push({'content.id': id});
    }
    if(type) {
      if(Array.isArray(type)) {
        const query = type.map(type => ({'content.type': type}));
        equals.push(...query);
      } else {
        equals.push({'content.type': type});
      }
    }
    const {edvClient} = this;
    const {documents} = await edvClient.find({equals, has, limit});
    return documents;
  }
}
