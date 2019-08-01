/*!
 * Copyright (c) 2019 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

import {DidStore} from 'bedrock-web-did-store';
import {LDKeyPair} from 'crypto-ld';
import v1 from 'did-veres-one';

const veresDriver = v1.driver({mode: 'test'});

export async function generateKey(keyType) {
  // FIXME: add support for key generation via web-kms-client
  return LDKeyPair.generate({type: keyType});
}

export async function generateDidDoc({invokeKey, keyType}) {
  return veresDriver.generate({keyType, invokeKey});
}

export async function storeDidDocument({dataHub, didDocument}) {
  const didStore = new DidStore({hub: dataHub});

  // DID store will not store private keys, use KMS instead
  return didStore.insert({doc: didDocument, meta: {}});
}
