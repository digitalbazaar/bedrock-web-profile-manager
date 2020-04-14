/**
  * Ensures an expected string is not empty.
  *
  * @param {Object} options - Options to use.
  * @param {string} options.value - The expected string.
  * @param {string} options.key - The identifier for the parameter.
  *
  * @throws - If the value is not a string or is empty.
  * @returns {undefined} - It just throws or you are ok.
*/
export function nonEmptyString({value, key}) {
  if(typeof value !== 'string') {
    throw new TypeError(`"${key}" must be a non-empty string.`);
  }
  if(value.length === 0) {
    const DataError = new Error(`"${key}" can not be an empty string`);
    DataError.name = 'DataError';
    throw DataError;
  }
}
export default {notEmptyString};
