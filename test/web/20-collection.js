/*!
 * Copyright (c) 2019-2020 Digital Bazaar, Inc. All rights reserved.
 */
import {ProfileManager} from 'bedrock-web-profile-manager';
import {EdvClient} from 'edv-client';

const ACCOUNT_ID = 'urn:uuid:ffaf5d84-7dc2-4f7b-9825-cc8d2e5a5d06';
const KMS_MODULE = 'ssm-v1';
const KMS_BASE_URL = `${window.location.origin}/kms`;
const EDV_BASE_URL = `${window.location.origin}/edvs`;

describe.only('Collection API', () => {
  let profileManager;
  beforeEach(async () => {
    profileManager = new ProfileManager({
      kmsModule: KMS_MODULE,
      kmsBaseUrl: KMS_BASE_URL,
      edvBaseUrl: EDV_BASE_URL,
      recoveryHost: window.location.host
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
  it('should create a collection successfully', async () => {
    const content = {didMethod: 'v1', didOptions: {mode: 'test'}};
    const {id: profileId} = await profileManager.createProfile(content);
    const {edvClient} = await profileManager.createProfileEdv(
      {profileId, referenceId: 'example'});

    await profileManager.initializeAccessManagement({
      profileId,
      profileContent: {foo: true},
      edvId: edvClient.id,
      hmac: edvClient.hmac,
      keyAgreementKey: edvClient.keyAgreementKey
    });
    const collection = await profileManager.getCollection({
      profileId,
      referenceIdPrefix: 'user',
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
  it('should get all docs successfully', async () => {
    const content = {didMethod: 'v1', didOptions: {mode: 'test'}};
    const {id: profileId} = await profileManager.createProfile(content);
    const {edvClient} = await profileManager.createProfileEdv(
      {profileId, referenceId: 'example'});

    await profileManager.initializeAccessManagement({
      profileId,
      profileContent: {foo: true},
      edvId: edvClient.id,
      hmac: edvClient.hmac,
      keyAgreementKey: edvClient.keyAgreementKey
    });
    const collection = await profileManager.getCollection({
      profileId,
      referenceIdPrefix: 'user',
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
  it('should get a doc successfully', async () => {
    const content = {didMethod: 'v1', didOptions: {mode: 'test'}};
    const {id: profileId} = await profileManager.createProfile(content);
    const {edvClient} = await profileManager.createProfileEdv(
      {profileId, referenceId: 'example'});

    await profileManager.initializeAccessManagement({
      profileId,
      profileContent: {foo: true},
      edvId: edvClient.id,
      hmac: edvClient.hmac,
      keyAgreementKey: edvClient.keyAgreementKey
    });
    const collection = await profileManager.getCollection({
      profileId,
      referenceIdPrefix: 'user',
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
  it('should remove a doc successfully', async () => {
    const content = {didMethod: 'v1', didOptions: {mode: 'test'}};
    const {id: profileId} = await profileManager.createProfile(content);
    const {edvClient} = await profileManager.createProfileEdv(
      {profileId, referenceId: 'example'});

    await profileManager.initializeAccessManagement({
      profileId,
      profileContent: {foo: true},
      edvId: edvClient.id,
      hmac: edvClient.hmac,
      keyAgreementKey: edvClient.keyAgreementKey
    });
    const collection = await profileManager.getCollection({
      profileId,
      referenceIdPrefix: 'user',
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
  xit('should update a doc successfully', async () => {

  });
});
