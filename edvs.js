/*!
 * Copyright (c) 2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

import {EdvClient} from 'edv-client';
import keyResolver from './keyResolver';

/**
 * Creates a new EDV and returns an EdvClient for it.
 *
 * @returns {Promise<EdvClient>} Resolves to a EdvClient.
 */
export async function create({
  invocationSigner, referenceId, profileId, edvBaseUrl,
  keys: {keyAgreementKey, hmac}
} = {}) {
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
  config = await EdvClient.createEdv(
    {config, invocationSigner, url: edvBaseUrl});
  return new EdvClient({
    id: config.id,
    keyResolver,
    keyAgreementKey,
    hmac,
  });
}

export async function get({
  invocationSigner, keystoreAgent, referenceId, profileId
} = {}) {
  const config = await EdvClient.findConfig({
    controller: profileId,
    invocationSigner,
    referenceId
  });
  if(config === null) {
    throw new Error(
      `Unable to find edv config with reference id: "${referenceId}".`);
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
  return new EdvClient({
    id: config.id,
    keyResolver,
    keyAgreementKey,
    hmac,
  });
}

export function getReferenceId(name) {
  return `${encodeURIComponent(window.location.hostname)}:` +
    `${encodeURIComponent(name)}`;
}

export default {create, get, getReferenceId};
