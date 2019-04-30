/*!
 * Copyright (c) 2019 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

import {AccountMasterKey} from 'bedrock-web-kms';
import {DataHub, DataHubService} from 'bedrock-web-data-hub';
import uuid from 'uuid-random';
import DataHubCache from './DataHubCache.js';
import {generateDid, storeDidDocument} from './did.js';

const kmsPlugin = 'ssm-v1';

export default class ProfileManager {
  /**
   * Creates a new instance of a ProfileManager and attaches it to the given
   * session instance. This ProfileManager will track changes to the given
   * session, creating and/or caching account and profile data hubs as needed.
   *
   * @param {Object} options - The options to use.
   * @param {Object} options.session - A `bedrock-web-session` session instance.
   * @param {string} options.kmsPlugin - The KMS plugin to use.
   *
   * @returns {ProfileManager} - The new instance.
   */
  constructor({kmsPlugin}) {
    this.session = null;
    this.accountId = null;
    this.masterKey = null;
    this.dataHubCache = new DataHubCache();
    this.kmsPlugin = kmsPlugin;
  }

  /**
   * Attaches this instance to the given session. This ProfileManager will
   * track changes to the given session, creating and/or caching account and
   * profile data hubs as needed.
   *
   * @param {Object} options - The options to use.
   * @param {Object} options.session - A `bedrock-web-session` session instance.
   *
   * @returns {Promise} - Resolves once the operation completes.
   */
  async setSession({session}) {
    if(this.session) {
      throw new Error('Already attached to a session.');
    }
    this.session = session;
    this.removeListener = session.on(
      'change', event => this._sessionChanged(event));
    // emulate initial session change event
    await this._sessionChanged({newData: session.data});
  }

  async getAccountDataHub() {
    return this.dataHubCache.get('primary');
  }

  async getProfileDataHub({profileId}) {
    const id = `profile.${profileId}`;
    let dataHub = await this.dataHubCache.get(id);
    if(dataHub) {
      return dataHub;
    }

    const accountDataHub = await this.getAccountDataHub();
    const [doc] = await accountDataHub.find({equals: {id: profileId}});
    if(!doc) {
      // no such profile stored with the given account
      return null;
    }

    // get the profile data hub
    const {content: profile} = doc;
    const dhs = new DataHubService();
    const config = await dhs.get({
      controller: this.accountId,
      id: profile.dataHub
    });
    const [kek, hmac] = await Promise.all([
      this.masterKey.getKek({id: config.kek.id}),
      this.masterKey.getHmac({id: config.hmac.id})
    ]);
    dataHub = new DataHub({config, kek, hmac});
    await this.dataHubCache.set(id, dataHub);
    return dataHub;
  }

  async createProfile({type, ...rest}) {
    // generate a DID for the profile
    const {did, keyPair} = await generateDid();

    // TODO: support making the profile data hub controlled by the profile
    // instead

    // get primary data hub and create an account controlled data hub for
    // the new profile
    const [accountDataHub, profileDataHub] = await Promise.all([
      this.getAccountDataHub(),
      this._createDataHub()
    ]);

    // insert a profile document into the primary data hub
    let profileType = 'Profile';
    if(type) {
      profileType = [profileType, type];
    }
    const doc = {
      id: uuid(),
      content: {
        ...rest,
        id: did,
        type: profileType,
        dataHub: profileDataHub.config.id
      }
    };
    await accountDataHub.insert({doc});

    // cache the profile data hub and store the unregistered DID document in it
    await this.dataHubCache.set(`profile.${did}`, profileDataHub);
    await storeDidDocument({dataHub: profileDataHub, keyPair});

    return doc;
  }

  // TODO: implement adding an existing profile to an account

  async getProfile({profileId}) {
    const dataHub = await this.getAccountDataHub();
    if(!dataHub) {
      return null;
    }
    const [doc = null] = await dataHub.find({equals: {id: profileId}});
    return doc;
  }

  async getProfiles() {
    const dataHub = await this.getAccountDataHub();
    if(!dataHub) {
      return [];
    }
    return dataHub.find({
      equals: {type: 'Profile'}
    });
  }

  async _sessionChanged({authentication, newData}) {
    const newAccountId = (newData.account || {}).id || null;

    // clear cache
    if(this.accountId && this.accountId !== newAccountId) {
      await AccountMasterKey.clearCache({accountId: this.accountId});
      await this.dataHubCache.clear();
    }

    // update state
    this.accountId = newAccountId;
    this.masterKey = null;

    if(!(authentication || newData.account)) {
      // no account in session, return
      return;
    }

    // cache account master key
    const {secret} = (authentication || {});
    this.masterKey = await AccountMasterKey.fromCache(
      {kmsPlugin, accountId: this.accountId, secret});
    if(this.masterKey === null) {
      // could not load from cache and no `secret`, so cannot load data hub
      return;
    }

    // ensure the account's primary data hub exists and cache it
    const dataHub = await this._ensureDataHub();
    await this.dataHubCache.set('primary', dataHub);
  }

  async _createDataHub({primary = false} = {}) {
    // create KEK and HMAC keys for data hub config
    const {masterKey} = this;
    const [kek, hmac] = await Promise.all([
      masterKey.generateKey({type: 'kek'}),
      masterKey.generateKey({type: 'hmac'})
    ]);

    // create data hub
    const dhs = new DataHubService();
    let config = {
      sequence: 0,
      // TODO: need to support using a DID here for profile controlled
      // data hubs as well
      controller: masterKey.accountId,
      kek: {id: kek.id, algorithm: kek.algorithm},
      hmac: {id: hmac.id, algorithm: hmac.algorithm}
    };
    if(primary) {
      config.primary = true;
    }
    config = await dhs.create({config});
    return new DataHub({config, kek, hmac});
  }

  async _ensureDataHub() {
    const {masterKey} = this;
    const dhs = new DataHubService();
    const config = await dhs.getPrimary({controller: masterKey.accountId});
    if(config === null) {
      return await this._createDataHub({primary: true});
    }
    const [kek, hmac] = await Promise.all([
      masterKey.getKek({id: config.kek.id}),
      masterKey.getHmac({id: config.hmac.id})
    ]);
    return new DataHub({config, kek, hmac});
  }
}
