/*!
 * Copyright (c) 2019 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

import {DidStore} from 'bedrock-web-did-store';
import v1 from 'did-veres-one';

const veresDriver = v1.driver({mode: 'test'});

export async function generateDidDoc({invokeKey, keyType}) {
  return veresDriver.generate({keyType, invokeKey});
}

export async function storeDidDocument({dataHub, didDoc, invocationSigner}) {

  const didStore = new DidStore({hub: dataHub, invocationSigner});

  return didStore.put({doc: didDoc, meta: {}});
}
