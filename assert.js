/*!
 * Copyright (c) 2020 Digital Bazaar, Inc. All rights reserved.
 */

/**
  * Ensures an expected string is not empty.
  *
  * @param {string} value - The expected string.
  * @param {string} key - The identifier for the parameter.
  *
  * @throws - If the value is not a string or is empty.
  * @returns {undefined} - No value is returned upon successful execution.
*/
export function nonEmptyString(value, key) {
  if(!(value && typeof value === 'string')) {
    throw new TypeError(`"${key}" must be a non-empty string.`);
  }
}

/**
 * Ensures `parentCapabilities` has all required properties.
 *
 * @param {object} options - The options to use.
 * @param {object} options.parentCapabilities - Contains the properties edvId
 *   and edvRevocations.
 * @param {string} options.edvId - The ID of the EDV that must be
 *   a URL that refers to the EDV's root storage location.
 * @param {object} options.hmac - A default HMAC API for blinding
 *   indexable attributes.
 * @param {object} options.keyAgreementKey - A default
 *   KeyAgreementKey API for deriving shared KEKs for wrapping content
 *   encryption keys.
 *
 * @throws - If both of the required properties are undefined.
 * @returns {undefined} - No value is returned upon successful execution.
 */
export function parentCapabilitiesValidator({
  parentCapabilities, edvId, hmac, keyAgreementKey
}) {
  if(!(edvId || parentCapabilities.edv)) {
    throw new TypeError('"edvId" is required.');
  }
  if(!(hmac || parentCapabilities.hmac)) {
    throw new TypeError('"hmac" is required.');
  }
  if(!(keyAgreementKey || parentCapabilities.keyAgreementKey)) {
    throw new TypeError('"keyAgreementKey" is required.');
  }
}

export default {nonEmptyString, parentCapabilitiesValidator};
