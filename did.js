/*!
 * Copyright (c) 2019 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

import {Store as DidStore} from 'bedrock-web-did-store';
import {LDKeyPair} from 'crypto-ld';
import didv1 from 'did-veres-one';

const {VeresOneDidDoc} = didv1;

export async function generateDid() {
  // TODO: add support for key generation via bedrock-web-kms
  const keyType = 'Ed25519VerificationKey2018';
  const keyPair = await LDKeyPair.generate({type: keyType});
  const v1DidDoc = new VeresOneDidDoc();
  return {
    did: v1DidDoc.generateId({keyPair, didType: 'nym', mode: 'test'}),
    keyPair
  };
}

export async function storeDidDocument({dataHub, keyPair}) {
  const didStore = new DidStore({dataHub});
  // don't store private keys with the DID Document (use KMS instead)
  const keyStore = {
    get: () => {},
    put: () => {}
  };
  // currently there is no usage of the meta store in did-veres-one
  const metaStore = {
    get: () => {},
    put: () => {}
  };
  const invokeKey = keyPair;
  const v1 = didv1.veres({mode: 'test', keyStore, didStore, metaStore});
  return v1.generate({invokeKey});
}
