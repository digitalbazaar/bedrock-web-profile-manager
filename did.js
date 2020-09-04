/*!
 * Copyright (c) 2019-2020 Digital Bazaar, Inc. All rights reserved.
 */
import v1 from 'did-veres-one';

const veresDriver = v1.driver({mode: 'test'});

export async function generateDidDoc({invokeKey, keyType}) {
  return veresDriver.generate({keyType, invokeKey});
}
