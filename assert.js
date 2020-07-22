/**
  * Ensures an expected string is not empty.
  *
  * @param {string} value - The expected string.
  * @param {string} key - The identifier for the parameter.
  *
  * @throws - If the value is not a string or is empty.
  * @returns {undefined} - It just throws or you are ok.
*/
export function nonEmptyString(value, key) {
  if(!(value && typeof value === 'string')) {
    throw new TypeError(`"${key}" must be a non-empty string.`);
  }
}
/**
  * Ensures `parentCapabilities` has all required properties.
  *
  * @param {object} parentCapabilities - Contains the properties edvId and
  *   edvRevocations.
  * @param {string} edvId - The ID of the EDV that must be a URL
  *   that refers to the EDV's root storage location.
  * @param {object} hmac - A default HMAC API for blinding indexable
  *   attributes.
  * @param {object} keyAgreementKey - A default KeyAgreementKey API for
  *   deriving shared KEKs for wrapping content encryption keys.
  *
  * @throws - If the value is undefined.
  * @returns {undefined} - It just throws or you are ok.
  */
export function parentCapabilitiesValidator(
  parentCapabilities, edvId, hmac, keyAgreementKey
) {
  if(!edvId && !parentCapabilities.edv) {
    throw new TypeError('"edvId" is required.');
  }
  if(!hmac && !parentCapabilities.hmac) {
    throw new TypeError('"hmac" is required.');
  }
  if(!keyAgreementKey && !parentCapabilities.keyAgreementKey) {
    throw new TypeError('"keyAgreementKey" is required.');
  }
}
export default {nonEmptyString, parentCapabilitiesValidator};
