/*!
 * Copyright (c) 2020-2022 Digital Bazaar, Inc. All rights reserved.
 */
import {Ed25519Signature2018} from '@digitalbazaar/ed25519-signature-2018';
import {Ed25519Signature2020} from '@digitalbazaar/ed25519-signature-2020';
import {EdvClient} from '@digitalbazaar/edv-client';
import {securityLoader} from '@digitalbazaar/security-document-loader';
import zcapCtx from '@digitalbazaar/zcap-context';
import {ZcapClient} from '@digitalbazaar/ezcap';
import webkmsCtx from '@digitalbazaar/webkms-context';
import veresOneCtx from 'veres-one-context';
import * as didVeresOne from 'did-veres-one';

const loader = securityLoader();
loader.addStatic(zcapCtx.CONTEXT_URL, zcapCtx.CONTEXT);
loader.addStatic(webkmsCtx.CONTEXT_URL, webkmsCtx.CONTEXT);
loader.addStatic(veresOneCtx.constants.VERES_ONE_CONTEXT_V1_URL,
  veresOneCtx.contexts.get(veresOneCtx.constants.VERES_ONE_CONTEXT_V1_URL)
);

// TODO: Add options from config file
loader.protocolHandlers.get('did').use(didVeresOne.driver({}));

export const documentLoader = loader.build();

const SUPPORTED_KEY_TYPES = [
  'Ed25519VerificationKey2018',
  'Ed25519VerificationKey2020',
  'Sha256HmacKey2019',
  'X25519KeyAgreementKey2019',
  'X25519KeyAgreementKey2020'
];

export async function delegateCapability({signer, request} = {}) {
  const {controller, expires, parentCapability, type} = request;
  const {invocationTarget} = request;

  const targetType = type;

  if(SUPPORTED_KEY_TYPES.includes(targetType)) {
    if(!invocationTarget) {
      throw new TypeError(
        '"invocationTarget" must be set for Web KMS capabilities.');
    }
    // TODO: fetch `target` from a key mapping document in the profile's
    // edv to get public key ID to set as `referenceId`
  } else if(targetType === 'urn:edv:document') {
    if(invocationTarget) {
      // TODO: handle case where an existing target is requested
    } else {
      throw new Error('Not implemented');
    }
    if(!parentCapability) {
      throw new Error('"parentCapability" must be given.');
    }
  } else if(targetType === 'urn:edv:documents') {
    if(invocationTarget) {
      // TODO: handle case where an existing target is requested
    } else {
      // TODO: note that only the recipient of the zcap will be able
      // to read the documents it writes -- as no recipient is specified
      // here ... could add this to the zcap as a special caveat that
      // requires the recipient always be present for every document written
      //zcap.invocationTarget.id = `${edvClient.id}/documents`;
      throw new Error('Not implemented.');
    }
    if(!parentCapability) {
      throw new Error('"parentCapability" must be given.');
      //parentCapability = `${edvClient.id}/zcaps/documents`;
    }
  } else {
    throw new Error(`Unsupported invocation target type "${targetType}".`);
  }

  return delegate({
    capability: parentCapability, controller, expires, invocationTarget, signer
  });
}

export async function id() {
  return `urn:zcap:${await EdvClient.generateId()}`;
}

export async function delegate({
  capability, controller, expires, invocationTarget, signer
} = {}) {
  let SuiteClass;
  if(signer.type === 'Ed25519VerificationKey2018') {
    SuiteClass = Ed25519Signature2018;
  } else if(signer.type === 'Ed25519VerificationKey2020') {
    SuiteClass = Ed25519Signature2020;
  } else {
    SuiteClass = Ed25519Signature2020;
  }
  if(!expires) {
    const defaultExpires = new Date(Date.now() + 5 * 60 * 1000);
    if(defaultExpires < new Date(capability.expires)) {
      expires = defaultExpires;
    } else {
      expires = capability.expires;
    }
  }
  const zcapClient = new ZcapClient({SuiteClass, delegationSigner: signer});
  return zcapClient.delegate({
    capability,
    controller,
    expires,
    invocationTarget,
  });
}

/**
 * Parses the WebKMS Keystore id from the id of a WebKMS Key.
 *
 * @param {string} keyId - An id of a WebKMS Key.
 *
 * @returns {string} Returns a WebKMS Keystore id.
 */
export function parseKeystoreId(keyId) {
  // key ID format: <baseUrl>/<keystores-path>/<keystore-id>/keys/<key-id>
  const idx = keyId.lastIndexOf('/keys/');
  if(idx === -1) {
    throw new Error(`Invalid key ID "${keyId}".`);
  }
  return keyId.substr(0, idx);
}
// FIXME: Do not introsepect url to get the Keystore ID
export function deriveKeystoreId(id) {
  const urlObj = new URL(id);
  const paths = urlObj.pathname.split('/');
  return urlObj.origin +
    '/' +
    paths[1] + // "kms"
    '/' +
    paths[2] + // "keystores"
    '/' +
    paths[3]; // "<keystore_id>"
}

export default {
  delegateCapability,
  id,
  delegate,
  deriveKeystoreId,
  parseKeystoreId,
};
