/*!
 * Copyright (c) 2020-2022 Digital Bazaar, Inc. All rights reserved.
 */
import * as didVeresOne from 'did-veres-one';
import {Ed25519Signature2018} from '@digitalbazaar/ed25519-signature-2018';
import {Ed25519Signature2020} from '@digitalbazaar/ed25519-signature-2020';
import {EdvClient} from '@digitalbazaar/edv-client';
import {securityLoader} from '@digitalbazaar/security-document-loader';
import zcapCtx from '@digitalbazaar/zcap-context';
import {ZcapClient} from '@digitalbazaar/ezcap';
import webkmsCtx from '@digitalbazaar/webkms-context';
import veresOneCtx from 'veres-one-context';

const loader = securityLoader();
loader.addStatic(zcapCtx.CONTEXT_URL, zcapCtx.CONTEXT);
loader.addStatic(webkmsCtx.CONTEXT_URL, webkmsCtx.CONTEXT);
loader.addStatic(veresOneCtx.constants.VERES_ONE_CONTEXT_V1_URL,
  veresOneCtx.contexts.get(veresOneCtx.constants.VERES_ONE_CONTEXT_V1_URL)
);

// TODO: Add options from config file
loader.protocolHandlers.get('did').use(didVeresOne.driver({}));

export const documentLoader = loader.build();

export async function id() {
  return `urn:zcap:${await EdvClient.generateId()}`;
}

export async function delegate({
  capability, controller, expires, invocationTarget, allowedActions = [],
  allowedAction, signer
}) {
  if(allowedAction) {
    throw new TypeError(
      '"allowedAction" not supported; pass "allowedActions" instead.');
  }
  if(!(capability &&
    (typeof capability === 'string' || typeof capability === 'object'))) {
    throw new TypeError('"capability" must be a string or object.');
  }
  if(!(controller && typeof controller === 'string')) {
    throw new TypeError('"controller" must be a string.');
  }

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
    allowedActions,
    capability,
    controller,
    expires,
    invocationTarget
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
  return keyId.slice(0, idx);
}

// FIXME: Do not introspect url to get the Keystore ID
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
