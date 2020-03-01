/*!
 * Copyright (c) 2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

import {
  AsymmetricKey,
  Hmac,
  Kek,
  KeyAgreementKey,
} from 'webkms-client';

export async function generateKey(
  {type, invocationSigner, kmsClient, kmsModule} = {}) {
  let Class;
  if(type === 'hmac' || type === 'Sha256HmacKey2019') {
    type = 'Sha256HmacKey2019';
    Class = Hmac;
  } else if(type === 'kek' || type === 'AesKeyWrappingKey2019') {
    type = 'AesKeyWrappingKey2019';
    Class = Kek;
  } else if(type === 'Ed25519VerificationKey2018') {
    type = 'Ed25519VerificationKey2018';
    Class = AsymmetricKey;
  } else if(type === 'keyAgreement' || type === 'X25519KeyAgreementKey2019') {
    type = 'X25519KeyAgreementKey2019';
    Class = KeyAgreementKey;
  } else {
    throw new Error(`Unknown key type "${type}".`);
  }

  const keyDescription = await kmsClient.generateKey(
    {kmsModule, type, invocationSigner});
  const {id} = keyDescription;
  return new Class(
    {id, type, invocationSigner, kmsClient, keyDescription});
}

export default {generateKey};
