/*!
 * Copyright (c) 2019-2022 Digital Bazaar, Inc. All rights reserved.
 */
// FIXME: remove this
import v1 from 'did-veres-one';

const veresDriver = v1.driver({mode: 'test'});

export async function generateDidDoc({invokeKey, keyType}) {
  return veresDriver.generate({keyType, invokeKey});
}
