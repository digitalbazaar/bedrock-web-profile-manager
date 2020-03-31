/*!
 * Copyright (c) 2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

import {EdvClient, EdvDocument} from 'edv-client';

const JWE_ALG = 'ECDH-ES+A256KW';

export default class Collection {
  constructor({type, capability, client, invocationSigner}) {
    this.type = type;
    this.capability = capability;
    this.client = client;
    this.invocationSigner = invocationSigner;
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
    const edvDoc = await this._getEdvDocument();
    const id = await EdvClient.generateId();
    return await edvDoc.write({doc: {id, content: item, meta}});
  }

  async get({id} = {}) {
    if(typeof id !== 'string') {
      throw new TypeError('"id" or must be given.');
    }
    const results = await this._findDocuments({id});
    if(results.length > 0) {
      return results[0];
    }
    return null;
  }

  async getAll() {
    const {instance, capability} = this;
    const results = await this._findDocuments(
      {instance, type: this.type, capability});
    return results;
  }

  async update({item, meta} = {}) {
    if(!(item && typeof item === 'object')) {
      throw new TypeError(`"item" must be an object.`);
    }
    if(!(item.type === this.type ||
      (Array.isArray(item.type) && item.type.includes(this.type)))) {
      throw new TypeError(
        `"item.type" (${item.type}) must include "${this.type}".`);
    }
    const existing = await this.get({id: item.id});
    const edvDoc = await this._getEdvDocument({id: existing.id});
    const updatedDoc = {
      ...existing
    };
    updatedDoc.content = item;
    if(meta) {
      updatedDoc.meta = meta;
    }
    return await edvDoc.write({
      doc: updatedDoc
    });
  }

  async remove({id} = {}) {
    if(typeof id !== 'string') {
      throw new TypeError('"id" or must be given.');
    }
    const existing = await this.get({id});
    if(!existing) {
      return false;
    }
    const edvDoc = await this._getEdvDocument({id: existing.id});
    return edvDoc.delete();
  }

  async _getEdvDocument({id} = {}) {
    const {capability, client, invocationSigner} = this;
    const {keyResolver, keyAgreementKey, hmac} = client;
    const recipients = [{
      header: {kid: keyAgreementKey.id, alg: JWE_ALG}
    }];
    return new EdvDocument({
      id, recipients, keyResolver, keyAgreementKey, hmac,
      capability, invocationSigner, client
    });
  }

  async _findDocuments({id, type, equals, has}) {
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
    const {capability, client, invocationSigner} = this;
    const results = await client.find(
      {equals, has, capability, invocationSigner});
    return results;
  }
}
