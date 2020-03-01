/*!
 * Copyright (c) 2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

import {EdvClient} from 'edv-client';
import keyResolver from './keyResolver';
import kms from './kms';

/**
 * Creates a new EDV and returns an EdvClient for it.
 *
 * @returns {Promise<EdvClient>} Resolves to a EdvClient.
 */
export async function create(
  {invocationSigner, kmsClient, referenceId, profileId, kmsModule} = {}) {
  console.log({invocationSigner, kmsClient, referenceId, profileId, kmsModule});
  const [keyAgreementKey, hmac] = await Promise.all([
    kms.generateKey({
      invocationSigner,
      type: 'keyAgreement',
      kmsClient,
      kmsModule
    }),
    kms.generateKey({
      invocationSigner,
      type: 'hmac',
      kmsClient,
      kmsModule
    })
  ]);
  // create edv
  let config = {
    sequence: 0,
    controller: profileId,
    keyAgreementKey: {id: keyAgreementKey.id, type: keyAgreementKey.type},
    hmac: {id: hmac.id, type: hmac.type}
  };
  if(referenceId) {
    config.referenceId = referenceId;
  }
  const headers = {host: window.location.host};
  config = await EdvClient.createEdv({config, invocationSigner, headers});
  return new EdvClient({
    id: config.id,
    keyResolver,
    keyAgreementKey,
    hmac,
    defaultHeaders: headers
  });
}

export async function get(
  {keystoreAgent, referenceId, profileId} = {}) {
  const config = await EdvClient.findConfig({
    controller: profileId,
    referenceId
  });
  if(config === null) {
    throw new Error(
      `Unable to find edv config with reference id: "${referenceId}".`,
      'NotFoundError');
  }
  const [keyAgreementKey, hmac] = await Promise.all([
    keystoreAgent.getKeyAgreementKey({
      id: config.keyAgreementKey.id,
      type: config.keyAgreementKey.type
    }),
    keystoreAgent.getHmac({
      id: config.hmac.id,
      type: config.hmac.type
    })
  ]);
  const defaultHeaders = {host: window.location.host};
  return new EdvClient({
    id: config.id,
    keyResolver,
    keyAgreementKey,
    hmac,
    defaultHeaders
  });
}

export function getReferenceId(name) {
  return `${encodeURIComponent(window.location.hostname)}:` +
    `${encodeURIComponent(name)}`;
}

export default {create, get, getReferenceId};
