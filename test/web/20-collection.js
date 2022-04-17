/*!
 * Copyright (c) 2019-2022 Digital Bazaar, Inc. All rights reserved.
 */
import {ProfileManager} from '@bedrock/web-profile-manager';
import {EdvClient} from '@digitalbazaar/edv-client';

const ACCOUNT_ID = 'urn:uuid:ffaf5d84-7dc2-4f7b-9825-cc8d2e5a5d06';
const EDV_BASE_URL = `${window.location.origin}/edvs`;

describe('Collection API', () => {
  let profileManager;
  beforeEach(async () => {
    profileManager = new ProfileManager({
      edvBaseUrl: EDV_BASE_URL
    });
    await profileManager.setSession({
      session: {
        data: {
          account: {
            id: ACCOUNT_ID
          }
        },
        on: () => {},
      }
    });
  });
  it('should create a doc in a collection', async () => {
    const {id: profileId, meters} = await profileManager.createProfile(
      {didMethod: 'v1', didOptions: {mode: 'test'}});
    const {meter: edvMeter} = meters.find(
      m => m.meter.referenceId === 'profile:core:edv');

    await profileManager.createProfileEdv(
      {profileId, meterId: edvMeter.id, referenceId: 'example'});

    const collection = await profileManager.getCollection({
      profileId,
      referenceId: 'example',
      type: 'test'
    });
    const doc1Id = await EdvClient.generateId();
    const doc1 = {id: doc1Id, type: 'test'};

    let err;
    let result;
    try {
      result = await collection.create({item: doc1});
    } catch(e) {
      err = e;
    }
    should.exist(result);
    should.not.exist(err);
    result.should.be.an('object');
    result.should.have.keys([
      'id', 'sequence', 'indexed', 'jwe', 'content', 'meta']);
    result.id.should.be.a('string');
    result.jwe.should.have.keys([
      'protected', 'recipients', 'iv', 'ciphertext', 'tag']);
    result.indexed.should.be.an('array');
    result.indexed[0].should.be.an('object');
    result.indexed[0].should.have.keys(['hmac', 'sequence', 'attributes']);
    result.content.should.eql(doc1);
  });
  it('should get all docs from a collection', async () => {
    const {id: profileId, meters} = await profileManager.createProfile(
      {didMethod: 'v1', didOptions: {mode: 'test'}});
    const {meter: edvMeter} = meters.find(
      m => m.meter.referenceId === 'profile:core:edv');

    await profileManager.createProfileEdv(
      {profileId, meterId: edvMeter.id, referenceId: 'example'});

    const collection = await profileManager.getCollection({
      profileId,
      referenceId: 'example',
      type: 'test'
    });
    const doc1Id = await EdvClient.generateId();
    const doc1 = {id: doc1Id, type: 'test'};

    const doc2Id = await EdvClient.generateId();
    const doc2 = {id: doc2Id, type: 'test'};
    // create two docs
    await collection.create({item: doc1});
    await collection.create({item: doc2});

    let result;
    let err;
    try {
      result = await collection.getAll();
    } catch(e) {
      err = e;
    }
    should.exist(result);
    should.not.exist(err);
    result.should.be.an('array');
    result.length.should.equal(2);

    const contents = result.map(doc => doc.content);
    contents.should.deep.include(doc1);
    contents.should.deep.include(doc2);
  });
  it('should get a doc from a collection', async () => {
    const {id: profileId, meters} = await profileManager.createProfile(
      {didMethod: 'v1', didOptions: {mode: 'test'}});
    const {meter: edvMeter} = meters.find(
      m => m.meter.referenceId === 'profile:core:edv');

    await profileManager.createProfileEdv(
      {profileId, meterId: edvMeter.id, referenceId: 'example'});

    const collection = await profileManager.getCollection({
      profileId,
      referenceIdPrefix: 'example',
      type: 'test'
    });
    const doc1Id = await EdvClient.generateId();
    const doc1 = {id: doc1Id, type: 'test'};

    const doc2Id = await EdvClient.generateId();
    const doc2 = {id: doc2Id, type: 'test'};
    // create two docs
    await collection.create({item: doc1});
    await collection.create({item: doc2});

    let result;
    let err;
    try {
      // get doc with doc2Id
      result = await collection.get({id: doc2Id});
    } catch(e) {
      err = e;
    }
    should.exist(result);
    should.not.exist(err);
    result.should.be.an('object');
    result.should.have.keys([
      'id', 'sequence', 'indexed', 'jwe', 'content', 'meta']);
    result.id.should.be.a('string');
    result.jwe.should.have.keys([
      'protected', 'recipients', 'iv', 'ciphertext', 'tag']);
    result.indexed.should.be.an('array');
    result.indexed[0].should.be.an('object');
    result.indexed[0].should.have.keys(['hmac', 'sequence', 'attributes']);
    result.content.should.eql(doc2);
  });
  it('should remove a doc from a collection', async () => {
    const {id: profileId, meters} = await profileManager.createProfile(
      {didMethod: 'v1', didOptions: {mode: 'test'}});
    const {meter: edvMeter} = meters.find(
      m => m.meter.referenceId === 'profile:core:edv');

    await profileManager.createProfileEdv(
      {profileId, meterId: edvMeter.id, referenceId: 'example'});

    const collection = await profileManager.getCollection({
      profileId,
      referenceIdPrefix: 'example',
      type: 'test'
    });
    const doc1Id = await EdvClient.generateId();
    const doc1 = {id: doc1Id, type: 'test'};

    await collection.create({item: doc1});

    let result;
    let err;
    try {
      result = await collection.getAll();
    } catch(e) {
      err = e;
    }
    should.exist(result);
    should.not.exist(err);
    result.should.be.an('array');
    result.length.should.equal(1);
    result[0].content.should.eql(doc1);

    // remove doc with doc1Id
    await collection.remove({id: doc1Id});
    // getting all docs again should return an empty array
    let result2;
    let err2;
    try {
      result2 = await collection.getAll();
    } catch(e) {
      err2 = e;
    }
    should.exist(result2);
    should.not.exist(err2);
    result2.should.eql([]);
  });
  it('should update a doc in a collection', async () => {
    const {id: profileId, meters} = await profileManager.createProfile(
      {didMethod: 'v1', didOptions: {mode: 'test'}});
    const {meter: edvMeter} = meters.find(
      m => m.meter.referenceId === 'profile:core:edv');

    await profileManager.createProfileEdv(
      {profileId, meterId: edvMeter.id, referenceId: 'example'});

    const collection = await profileManager.getCollection({
      profileId,
      referenceId: 'example',
      type: 'test'
    });
    const doc1Id = await EdvClient.generateId();
    const doc1 = {id: doc1Id, type: 'test'};

    let result;
    let err;
    try {
      result = await collection.create({item: doc1});
    } catch(e) {
      err = e;
    }
    should.exist(result);
    should.not.exist(err);
    result.content.should.eql(doc1);

    let result1;
    let err1;
    const updatedItem = {
      id: doc1Id,
      type: 'test',
      someKey: '33333'
    };
    try {
      // update the doc with doc1Id
      result1 = await collection.update({
        item: updatedItem
      });
    } catch(e) {
      err1 = e;
    }
    should.exist(result1);
    should.not.exist(err1);
    result1.id.should.equal(result.id);
    result1.content.should.eql(updatedItem);
    result1.content.should.not.eql(result.content);

    let result2;
    let err2;
    try {
      // get doc with doc2Id
      result2 = await collection.get({id: doc1Id});
    } catch(e) {
      err2 = e;
    }
    should.exist(result2);
    should.not.exist(err2);
    result2.should.eql(result1);
    result2.content.should.eql(updatedItem);
  });
});
