/*!
 * Copyright (c) 2019-2022 Digital Bazaar, Inc. All rights reserved.
 */
import * as utils from './utils.js';
import {AccessManager} from './AccessManager.js';
import assert from './assert.js';
import crypto from './crypto.js';
import {ProfileService} from '@bedrock/web-profile';
import {
  AsymmetricKey,
  CapabilityAgent,
  KeystoreAgent,
  KeyAgreementKey,
  Hmac
} from '@digitalbazaar/webkms-client';
import Collection from './Collection.js';
import {EdvClient, EdvDocument} from '@digitalbazaar/edv-client';
import LRU from 'lru-cache';
import keyResolver from './keyResolver.js';

const ZCAP_REFERENCE_IDS = {
  profileDoc: 'profile-edv-document',
  userDocs: 'user-edv-documents',
  userKak: 'user-edv-kak',
  userHmac: 'user-edv-hmac',
};
// 15 minutes
const DEFAULT_ZCAP_GRACE_PERIOD = 15 * 60 * 1000;
// 24 hours
const DEFAULT_ZCAP_TTL = 24 * 60 * 60 * 1000;
// 365 days
const DEFAULT_PROFILE_AGENT_ZCAP_TTL = 365 * 24 * 60 * 60 * 1000;

export class ProfileManager {
  /**
   * Creates a new instance of a ProfileManager and attaches it to the given
   * session instance. This ProfileManager will track changes to the given
   * session, creating and/or caching account and profile edvs as needed.
   *
   * Some methods delegate profile agent zcaps to an ephemeral capability
   * agent instead of using the profile agent's zcap invocation key directly.
   * This is required because the profile agent's zcap invocation key is IP
   * restricted. It also significantly reduces the number of hits to a WebKMS.
   * The ephemeral capability agent is not long lived and can only be used
   * locally. This helps create a decent security profile.
   *
   * @param {object} options - The options to use.
   * @param {string} options.edvBaseUrl - The base URL for the EDV service,
   *   used to store documents.
   * @param {number} [options.zcapGracePeriod] - Zcap is considered expired if
   *   the zcapTtl is less than or equal to this value.
   * @param {number} [options.zcapTtl] - The time to live for a Zcap.
   * @param {ProfileService} [options.profileService] - A configurable
   *   ProfileService.
   *
   * @returns {ProfileManager} - The new instance.
   */
  constructor({
    edvBaseUrl,
    zcapGracePeriod = DEFAULT_ZCAP_GRACE_PERIOD,
    zcapTtl = DEFAULT_ZCAP_TTL,
    profileService = new ProfileService()
  } = {}) {
    if(typeof edvBaseUrl !== 'string') {
      throw new TypeError('"edvBaseUrl" must be a string.');
    }
    this._profileService = profileService;
    this.session = null;
    this.accountId = null;
    this.edvBaseUrl = edvBaseUrl;
    this._cacheContainer = new Map();
    this.zcapGracePeriod = zcapGracePeriod;
    this.zcapTtl = zcapTtl;
  }

  /**
   * Creates a new profile and a profile agent to control it. The profile
   * agent is assigned to the account associated with the authenticated
   * session.
   *
   * @param {object} options - The options to use.
   * @param {string} [options.didMethod] - The DID method to use to create
   *   the profile's identifier. (Supported: 'key' and 'v1'.).
   * @param {string} [options.didOptions] - Hashmap of optional DID method
   *   options.
   *
   * @returns {object} The profile with an "id" attribute.
   */
  async createProfile({didMethod = 'key', didOptions = {}} = {}) {
    if(!['key', 'v1'].includes(didMethod)) {
      throw new Error(`Unsupported DID method "${didMethod}".`);
    }
    const {id, meters} = await this._profileService.create({
      account: this.accountId, didMethod, didOptions
    });
    // clear profile agent records cache
    const cache = this._getCache('profile-agent-records');
    cache.del(this.accountId);
    return {id, meters};
  }

  /**
   * Gets the profile agent assigned to the account associated with the
   * authenticated session for the profile identified by the given profile ID.
   *
   * @param {object} options - The options to use.
   * @param {string} options.profileId - The ID of the profile to get the
   *   profile agent for.
   *
   * @returns {Promise<object>} The profile agent.
   */
  async getAgent({profileId} = {}) {
    assert.nonEmptyString(profileId, 'profileId');

    // determine if `profileAgent` has a `userDocument` yet by looking for
    // a zcap to access it
    const profileAgentRecord = await this._getAgentRecord({profileId});
    const {profileAgent} = profileAgentRecord;
    const {userDocument: capability} = profileAgent.zcaps;
    if(!capability) {
      // generate content from profile agent record as access management has
      // not been initialized for the profile yet
      const content = {
        id: profileAgent.id,
        zcaps: {}
      };
      for(const [key, zcap] of Object.entries(profileAgent.zcaps)) {
        content.zcaps[key] = zcap;
      }
      return content;
    }
    const content = await this._getAgentContent({profileAgentRecord});
    return content;
  }

  /**
   * Gets a capability that has been delegated from a profile agent's
   * capability. If the delegated zcap is in the cache, it will be returned
   * immediately, otherwise it will be delegated and stored in the cache for
   * later retrieval. The zcap to delegate will be found by its reference ID
   * and this reference ID will be reused to store it in the cache.
   *
   * @param {object} options - The options to use.
   * @param {string} options.referenceId - The reference ID of the zcap.
   * @param {string} options.profileAgent - The profile agent that is the
   *   controller of the zcap that is to be delegated.
   *
   * @returns {Promise<object>} The delegated agent capability for an
   *   ephemeral capability agent to use.
   */
  async getDelegatedAgentCapability({referenceId, profileAgent}) {
    // get specific delegated zcap from the cache
    const cache = this._getCache('agent-delegated-zcaps');
    const cacheKey = `${profileAgent.id}-${referenceId}`;
    const zcap = cache.get(cacheKey);
    if(zcap) {
      return zcap;
    }

    // cache miss, delegate agent capability
    const promise = this._delegateAgentCapability(
      {referenceId, profileAgent});
    try {
      const zcap = await promise;
      const now = Date.now();
      const expiryDate = new Date(zcap.expires || (now + this.zcapTtl));
      const maxAge = Math.max(
        expiryDate.getTime() - now - this.zcapGracePeriod, 0);
      cache.set(cacheKey, promise, maxAge);
      return zcap;
    } catch(e) {
      cache.del(cacheKey);
      throw e;
    }
  }

  /**
   * Gets the meters for a profile.
   *
   * @param {object} options - The options to use.
   * @param {string} options.profileId - The ID of the profile to get the
   *   meters for.
   *
   * @returns {Promise<Array>} The profile meters.
   */
  async getProfileMeters({profileId} = {}) {
    assert.nonEmptyString(profileId, 'profileId');

    const profileAgentRecord = await this._getAgentRecord({profileId});
    const {profileMeters} = profileAgentRecord;
    return profileMeters.map(record => record.meter);
  }

  /**
   * Creates an API for signing using a profile's capability invocation key.
   * The account associated with the authenticated session must have a profile
   * agent that has this capability or an error will be thrown.
   *
   * @param {object} options - The options to use.
   * @param {string} options.profileId - The ID of the target profile.
   *
   * @returns {Promise<object>} Signer API for signing using the profile's
   *   capability invocation key.
   */
  async getProfileSigner({profileId} = {}) {
    assert.nonEmptyString(profileId, 'profileId');

    // get profile agent to be used
    const profileAgent = await this.getAgent({profileId});

    // get profile signer from cache
    const cache = this._getCache('profile-signers');
    const cacheKey = `${profileId}-${profileAgent.id}`;
    let promise = cache.get(cacheKey);
    if(promise) {
      return promise;
    }

    // calculate max age for the profile signer based on `zcap.expires`
    try {
      promise = this._getProfileSigner({profileId, profileAgent});
      // set cached value, then compute max age and reset it
      cache.set(cacheKey, promise);

      const {invocationSigner: {capability: zcap}} = await promise;
      const now = Date.now();
      const expiryDate = new Date(zcap.expires || (now + this.zcapTtl));
      const maxAge = Math.max(
        expiryDate.getTime() - now - this.zcapGracePeriod, 0);
      cache.set(cacheKey, promise, maxAge);
      return promise;
    } catch(e) {
      cache.del(cacheKey);
      throw e;
    }
  }

  /**
   * Gets a profile by ID. A profile can only be retrieved if the account
   * associated with the authenticated session has a profile agent with
   * the capability to read the profile document -- and if the profile
   * has had its access management initialized (i.e., it is not still in
   * the process of being provisioned).
   *
   * @param {object} options - The options to use.
   * @param {string} options.id - The ID of the profile to get.
   *
   * @returns {Promise<object>} Content for the given profile.
   */
  async getProfile({id, useCache = false} = {}) {
    assert.nonEmptyString(id, 'id');

    // check cache for profile document
    const cache = this._getCache('profiles');
    const cacheKey = `${this.accountId}-${id}`;
    let promise = cache.get(cacheKey);
    if(promise && useCache) {
      // only return cached value if `useCache` is set; otherwise get fresh
      // copy below and update the cache
      const {content} = await promise;
      return content;
    }

    try {
      // cache miss, get uncached profile document
      promise = this._getUncachedProfile({id});
      cache.set(cacheKey, promise);
      const {content} = await promise;
      return content;
    } catch(e) {
      cache.del(cacheKey);
      throw e;
    }
  }

  async getProfiles({type, useCache = false} = {}) {
    const {accountId} = this;
    const profileAgentRecords = await this._getProfileAgentRecords(
      {accountId, useCache});
    const promises = profileAgentRecords.map(async ({profileAgent}) =>
      this.getProfile({id: profileAgent.profile, useCache}));

    // TODO: Use proper promise-fun library to limit concurrency
    const profiles = await Promise.all(promises);
    if(!type) {
      return profiles;
    }
    return profiles.filter(profile => profile.type.includes(type));
  }

  async getProfileKeystoreAgent({profileId} = {}) {
    assert.nonEmptyString(profileId, 'profileId');
    // FIXME: getting the keystore for the profile should involve reading the
    // profile to get its ID instead of parsing the ID from its zcap key
    const {invocationSigner} = await this.getProfileSigner({profileId});
    const {capability: zcap} = invocationSigner;

    const keystoreId = _getKeystoreId({zcap});
    const capabilityAgent = new CapabilityAgent(
      {handle: 'primary', signer: invocationSigner});
    return new KeystoreAgent({keystoreId, capabilityAgent});
  }

  async createEdvRecipientKeys({profileId} = {}) {
    const keystoreAgent = await this.getProfileKeystoreAgent({profileId});
    const [keyAgreementKey, hmac] = await Promise.all([
      keystoreAgent.generateKey({type: 'keyAgreement'}),
      keystoreAgent.generateKey({type: 'hmac'})
    ]);
    return {hmac, keyAgreementKey};
  }

  async getAccessManager({profileId, useCache = false} = {}) {
    assert.nonEmptyString(profileId, 'profileId');
    const [profile, profileAgent] = await Promise.all([
      this.getProfile({id: profileId, useCache}),
      this.getAgent({profileId})
    ]);
    // TODO: consider consolidation with `getProfileEdv`
    const referenceIds = [
      ZCAP_REFERENCE_IDS.userDocs,
      ZCAP_REFERENCE_IDS.userKak,
      ZCAP_REFERENCE_IDS.userHmac
    ];
    const promises = referenceIds.map(
      async referenceId => this.getDelegatedAgentCapability(
        {referenceId, profileAgent}));
    const [capability, userKak, userHmac] = await Promise.all(promises);
    const invocationSigner = await this._getEphemeralSigner(
      {profileAgentId: profileAgent.id});

    if(!(capability && userKak && userHmac)) {
      throw new Error(
        `Profile agent "${profileAgent.id}" is not authorized to manage ` +
        `access for profile "${profileId}".`);
    }
    const {indexes} = profile.accessManagement;
    const edvClient = new EdvClient({
      capability,
      invocationSigner,
      keyResolver,
      keyAgreementKey: await KeyAgreementKey.fromCapability({
        capability: userKak,
        invocationSigner
      }),
      hmac: await Hmac.fromCapability({
        capability: userHmac,
        invocationSigner
      })
    });
    for(const index of indexes) {
      edvClient.ensureIndex(index);
    }
    const users = new Collection(
      {type: 'User', edvClient, capability, invocationSigner});
    return {
      accessManager: new AccessManager({profile, profileManager: this, users}),
      profile,
      profileAgent
    };
  }

  async addProfileEdvAccess({profileId, profileAgentId, referenceId}) {
    let invocationSigner;
    try {
      ({invocationSigner} = await this.getProfileSigner({profileId}));
    } catch(e) {
      if(e.name !== 'NotFoundError') {
        throw e;
      }
      // current profile agent is not allowed to use the profile signer
      const error = new Error(
        'Profile agent is not allowed to delegate EDV access.');
      error.name = 'NotAllowedError';
      throw error;
    }
    if(!profileAgentId) {
      const profileAgent = await this.getAgent({profileId});
      profileAgentId = profileAgent.id;
    }

    // get EDV config
    const config = await EdvClient.findConfig({
      url: this.edvBaseUrl, controller: profileId,
      referenceId, invocationSigner
    });

    // add access to profile agent's user doc
    const {zcaps} = await this.delegateEdvCapabilities({
      edvId: config.id,
      hmac: config.hmac,
      keyAgreementKey: config.keyAgreementKey,
      invocationSigner,
      profileAgentId,
      referenceIdPrefix: referenceId
    });
    const {accessManager} = await this.getAccessManager({profileId});
    return accessManager.updateUser({
      id: profileAgentId,
      async mutator({existing}) {
        const updatedDoc = {...existing};
        updatedDoc.content.zcaps = {
          ...updatedDoc.content.zcaps,
          ...zcaps
        };
        return updatedDoc;
      }
    });
  }

  async createProfileEdv({
    profileId, meterId, referenceId, addAccess = true
  } = {}) {
    assert.nonEmptyString(profileId, 'profileId');
    assert.nonEmptyString(meterId, 'meterId');

    const [{invocationSigner}, {hmac, keyAgreementKey}] = await Promise.all([
      this.getProfileSigner({profileId}),
      this.createEdvRecipientKeys({profileId})
    ]);

    // create edv
    let config = {
      sequence: 0,
      controller: profileId,
      referenceId,
      meterId,
      keyAgreementKey: {id: keyAgreementKey.id, type: keyAgreementKey.type},
      hmac: {id: hmac.id, type: hmac.type}
    };
    config = await EdvClient.createEdv(
      {config, invocationSigner, url: this.edvBaseUrl});
    const edvClient = new EdvClient({
      id: config.id,
      keyResolver,
      keyAgreementKey,
      hmac
    });

    let user;
    if(addAccess) {
      user = await this.addProfileEdvAccess({profileId, referenceId});
    }

    return {edvClient, user};
  }

  async delegateEdvCapabilities({
    edvId,
    hmac,
    keyAgreementKey,
    parentCapabilities,
    invocationSigner,
    profileAgentId,
    referenceIdPrefix
  }) {
    assert.parentCapabilitiesValidator({
      parentCapabilities, edvId, hmac, keyAgreementKey
    });
    assert.nonEmptyString(referenceIdPrefix, 'referenceIdPrefix');

    const expires = new Date(Date.now() + DEFAULT_PROFILE_AGENT_ZCAP_TTL);

    const delegateEdvDocumentsRequest = {
      referenceId: `${referenceIdPrefix}-edv-documents`,
      allowedActions: ['read', 'write'],
      controller: profileAgentId,
      expires
    };
    if(edvId) {
      delegateEdvDocumentsRequest.invocationTarget = `${edvId}/documents`;
      delegateEdvDocumentsRequest.capability =
        `urn:zcap:root:${encodeURIComponent(edvId)}`;
    } else {
      const {edv} = parentCapabilities;
      delegateEdvDocumentsRequest.invocationTarget = edv.invocationTarget;
      delegateEdvDocumentsRequest.capability = edv;
    }

    const delegateEdvHmacRequest = {
      referenceId: `${referenceIdPrefix}-edv-hmac`,
      allowedActions: ['sign'],
      controller: profileAgentId,
      expires
    };
    if(hmac) {
      delegateEdvHmacRequest.invocationTarget = hmac.kmsId || hmac.id;
      const keystoreId = utils.parseKeystoreId(
        delegateEdvHmacRequest.invocationTarget);
      const parentZcap = `urn:zcap:root:${encodeURIComponent(keystoreId)}`;
      delegateEdvHmacRequest.capability = parentZcap;
    } else {
      const {hmac} = parentCapabilities;
      delegateEdvHmacRequest.invocationTarget = hmac.invocationTarget;
      delegateEdvHmacRequest.capability = hmac;
    }

    const delegateEdvKakRequest = {
      referenceId: `${referenceIdPrefix}-edv-kak`,
      allowedActions: ['deriveSecret'],
      controller: profileAgentId,
      expires
    };
    if(keyAgreementKey) {
      delegateEdvKakRequest.invocationTarget = keyAgreementKey.kmsId ||
        keyAgreementKey.id;
      const keystoreId = utils.parseKeystoreId(
        delegateEdvKakRequest.invocationTarget);
      const parentZcap = `urn:zcap:root:${encodeURIComponent(keystoreId)}`;
      delegateEdvKakRequest.capability = parentZcap;
    } else {
      const {keyAgreementKey: kak} = parentCapabilities;
      delegateEdvKakRequest.invocationTarget = kak.invocationTarget;
      delegateEdvKakRequest.capability = kak;
    }
    const requests = [
      delegateEdvDocumentsRequest,
      delegateEdvHmacRequest,
      delegateEdvKakRequest,
    ];
    const delegated = await Promise.all(
      requests.map(request => utils.delegate({
        signer: invocationSigner,
        ...request
      })));
    // build zcap referenceId => zcap map
    const zcaps = {};
    for(const [i, zcap] of delegated.entries()) {
      zcaps[requests[i].referenceId] = zcap;
    }
    return {zcaps};
  }

  async delegateCapability({profileId, request}) {
    assert.nonEmptyString(profileId, 'profileId');
    const {invocationSigner: signer} = await this.getProfileSigner({profileId});
    return utils.delegate({signer, ...request});
  }

  async getCollection({
    profileId, referenceIdPrefix, referenceId = referenceIdPrefix, type
  } = {}) {
    assert.nonEmptyString(profileId, 'profileId');
    const {edvClient} = await this.getProfileEdvAccess(
      {profileId, referenceId});
    edvClient.ensureIndex({attribute: 'content.id', unique: true});
    edvClient.ensureIndex({attribute: 'content.type'});
    return new Collection({type, edvClient});
  }

  // FIXME: remove exposure of this?
  async getProfileEdvAccess({
    profileId, referenceIdPrefix, referenceId = referenceIdPrefix,
    addAccess = true
  } = {}) {
    const profileAgent = await this.getAgent({profileId});
    return this._getProfileEdvAccess(
      {profileAgent, profileId, referenceId, addAccess});
  }

  /**
   * Attaches this instance to the given session. This ProfileManager will
   * track changes to the given session, creating and/or caching account and
   * profile edvs as needed.
   *
   * @param {object} options - The options to use.
   * @param {object} options.session - A `bedrock-web-session` session instance.
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

  async _resetCache() {
    this._cacheContainer.clear();
  }

  async _sessionChanged({newData}) {
    const {account = {}} = newData;
    const {id: newAccountId = null} = account;

    // clear cache
    if(this.accountId && this.accountId !== newAccountId) {
      await CapabilityAgent.clearCache({handle: this.accountId});
    }

    // update state
    this.accountId = newAccountId;
    this._resetCache();
  }

  async _delegateAgentCapability({referenceId, profileAgent}) {
    // get original zcap to be delegated
    const {id: profileAgentId} = profileAgent;
    const originalZcap = profileAgent.zcaps[referenceId];
    if(!originalZcap) {
      const error = new Error(
        `The agent "${profileAgentId}" does not have the zcap with ` +
        `reference ID "${referenceId}".`);
      error.name = 'NotFoundError';
      throw error;
    }

    // delegate original zcap to ephemeral capability agent
    const capabilityAgent = await this._getEphemeralCapabilityAgent(
      {profileAgentId});
    const {zcap} = await this._profileService.delegateAgentCapability({
      account: this.accountId,
      controller: capabilityAgent.id,
      profileAgentId,
      zcap: originalZcap
    });
    return zcap;
  }

  async _getEphemeralSigner({profileAgentId}) {
    const capabilityAgent = await this._getEphemeralCapabilityAgent(
      {profileAgentId});
    return capabilityAgent.getSigner();
  }

  async _getAgentRecord({profileId}) {
    // get agent record from cache
    const cache = this._getCache('agent-records');
    const cacheKey = `${this.accountId}-${profileId}`;
    const agentRecord = cache.get(cacheKey);
    if(agentRecord) {
      return agentRecord;
    }

    // cache miss, get using profile service
    const promise = this._profileService.getAgentByProfile({
      profile: profileId,
      account: this.accountId
    });
    cache.set(cacheKey, promise);

    try {
      return await promise;
    } finally {
      // the cache is for concurrent requests only
      cache.del(cacheKey);
    }
  }

  async _getAgentContent({profileAgentRecord}) {
    // get agent content from cache
    const cache = this._getCache('agent-content');
    const {profileAgent} = profileAgentRecord;
    const {id, sequence} = profileAgent;
    const cacheKey = `${id}-${sequence}`;
    const agentContent = cache.get(cacheKey);
    if(agentContent) {
      return agentContent;
    }

    // determine if `profileAgent` has a user doc yet...

    // get zcaps necessary to read from the profile agent's user EDV doc
    let capability;
    let userKak;
    try {
      ([capability, userKak] = await Promise.all([
        this.getDelegatedAgentCapability({
          referenceId: 'userDocument',
          profileAgent
        }),
        this.getDelegatedAgentCapability({
          referenceId: ZCAP_REFERENCE_IDS.userKak,
          profileAgent
        })
      ]));
    } catch(e) {
      if(e.name !== 'NotFoundError') {
        throw e;
      }
      const error = new Error('Profile access management not initialized.');
      error.cause = e;
      throw error;
    }

    const invocationSigner = await this._getEphemeralSigner(
      {profileAgentId: id});
    const edvDocument = new EdvDocument({
      capability,
      keyAgreementKey: await KeyAgreementKey.fromCapability({
        capability: userKak,
        invocationSigner,
      }),
      invocationSigner
    });

    // merge profile agent EDV doc content w/ backend profile agent record
    const promise = this._mergeAgentContent({edvDocument, profileAgent});
    cache.set(cacheKey, promise);

    try {
      return await promise;
    } finally {
      // the cache is for concurrent requests only
      cache.del(cacheKey);
    }
  }

  async _mergeAgentContent({edvDocument, profileAgent}) {
    const {zcaps} = profileAgent;
    const {content} = await edvDocument.read();
    // update zcaps to include zcaps from agent record
    for(const [referenceId, zcap] of Object.entries(zcaps)) {
      if(!content.zcaps[referenceId]) {
        content.zcaps[referenceId] = zcap;
      }
    }
    return content;
  }

  _getCache(key) {
    const cache = this._cacheContainer.get(key);
    if(cache) {
      return cache;
    }

    const newCache = new LRU();
    this._cacheContainer.set(key, newCache);
    return newCache;
  }

  async _getEphemeralCapabilityAgent({profileAgentId}) {
    assert.nonEmptyString(profileAgentId, 'profileAgentId');

    // get ephemeral capability agent from cache
    const cache = this._getCache('capability-agents');
    const cacheKey = profileAgentId;
    let capabilityAgent = cache.get(cacheKey);
    if(capabilityAgent) {
      return capabilityAgent;
    }

    // cache miss, create ephemeral capability agent
    const handle = `${this.accountId}-${profileAgentId}`;
    capabilityAgent = _createCapabilityAgent({handle});
    cache.set(cacheKey, capabilityAgent);

    return capabilityAgent;
  }

  async _getProfileAgentRecords({accountId, useCache = false}) {
    // check cache for profile agent records
    const cache = this._getCache('profile-agent-records');
    const cacheKey = accountId;
    let promise = cache.get(cacheKey);
    if(promise && useCache) {
      // only return cached value if `useCache` is set; otherwise get fresh
      // copy below and update the cache
      return promise;
    }

    try {
      // cache miss, get uncached profile agent records
      promise = this._profileService.getAllAgents({account: accountId});
      cache.set(cacheKey, promise);
      return await promise;
    } catch(e) {
      cache.del(cacheKey);
      throw e;
    }
  }

  async _getProfileSigner({profileId, profileAgent}) {
    // get delegated zcap for profile's zcap invocation key
    const referenceId = _getProfileInvocationZcapKeyReferenceId(
      {zcaps: profileAgent.zcaps, profileId});
    const zcap = await this.getDelegatedAgentCapability(
      {referenceId, profileAgent});
    const invocationSigner = await this._getEphemeralSigner(
      {profileAgentId: profileAgent.id});

    // create key interface
    const asymmetricKey = await AsymmetricKey.fromCapability(
      {capability: zcap, invocationSigner});

    return {invocationSigner: asymmetricKey, profileAgent};
  }

  async _getProfileEdvAccess({
    profileAgent, profileId, referenceId, addAccess = true
  }) {
    assert.nonEmptyString(profileId, 'profileId');
    const refs = {
      documents: `${referenceId}-edv-documents`,
      hmac: `${referenceId}-edv-hmac`,
      kak: `${referenceId}-edv-kak`
    };

    const referenceIds = [refs.documents, refs.kak, refs.hmac];
    const promises = referenceIds.map(async referenceId => {
      try {
        return await this.getDelegatedAgentCapability(
          {referenceId, profileAgent});
      } catch(e) {
        if(e.name !== 'NotFoundError') {
          throw e;
        }
        // do not throw on not found, allow code below to handle missing zcaps
        return null;
      }
    });
    const [documentsZcap, kakZcap, hmacZcap] = await Promise.all(promises);
    if(!(documentsZcap && hmacZcap && kakZcap)) {
      // add access on demand if requested
      if(addAccess) {
        await this.addProfileEdvAccess(
          {profileId, profileAgentId: profileAgent.id, referenceId});
        // refresh profile agent w/new access
        profileAgent = await this.getAgent({profileId});
        return this._getProfileEdvAccess(
          {profileAgent, profileId, referenceId, addAccess: false});
      }
      throw new Error(
        `Profile agent "${profileAgent.id}" is not authorized to access ` +
        `the "${referenceId}" EDV for profile "${profileId}".`);
    }

    const invocationSigner = await this._getEphemeralSigner(
      {profileAgentId: profileAgent.id});

    const edvClient = new EdvClient({
      keyResolver,
      keyAgreementKey: await KeyAgreementKey.fromCapability({
        capability: kakZcap,
        invocationSigner
      }),
      hmac: await Hmac.fromCapability({
        capability: hmacZcap,
        invocationSigner
      }),
      capability: documentsZcap,
      invocationSigner
    });

    // TODO: consider storing indexes for profile EDVs in the profile's
    // user doc based on `referenceId` so that they can always
    // be applied here, similar to what is done with accessManagement

    return {edvClient, capability: documentsZcap, invocationSigner};
  }

  async _getUncachedProfile({id}) {
    // check for at least one zcap for getting the profile:
    // 1. zcap for reading just the profile, or
    // 2. zcap for reading entire user EDV
    const profileAgent = await this.getAgent({profileId: id});
    const [
      {value: profileDocZcap, reason: error1},
      {value: userEdvZcap, reason: error2},
      {value: userKakZcap, reason: error3},
      {value: invocationSigner, reason: error4}
    ] = await Promise.allSettled([
      this.getDelegatedAgentCapability({
        referenceId: ZCAP_REFERENCE_IDS.profileDoc,
        profileAgent
      }),
      this.getDelegatedAgentCapability({
        referenceId: ZCAP_REFERENCE_IDS.userDocs,
        profileAgent
      }),
      this.getDelegatedAgentCapability({
        referenceId: ZCAP_REFERENCE_IDS.userKak,
        profileAgent
      }),
      this._getEphemeralSigner({profileAgentId: profileAgent.id})
    ]);
    const capability = profileDocZcap || userEdvZcap;
    if(!(capability && userKakZcap && invocationSigner)) {
      // if neither of the first EDV zcaps nor the KAK zcap were
      // found, then the agent does not have access
      if((error1.name === 'NotFoundError' &&
        error2.name === 'NotFoundError') ||
        error3.name === 'NotFoundError') {
        throw new Error(
          `Profile agent "${profileAgent.id}" is not authorized to ` +
          `read profile "${id}".`);
      }
      // aggregate and throw other errors.
      const error = new Error('Could not get profile.');
      error.name = 'AggregateError';
      error.errors = [error1, error2, error3, error4];
      throw error;
    }

    // read the profile's user doc
    const edvDocument = new EdvDocument({
      capability,
      keyAgreementKey: await KeyAgreementKey.fromCapability({
        capability: userKakZcap,
        invocationSigner
      }),
      invocationSigner
    });

    return edvDocument.read();
  }
}

function _getKeystoreId({zcap}) {
  const {invocationTarget} = zcap;
  if(!invocationTarget) {
    throw new Error('"invocationTarget" not found on zCap.');
  }
  if(typeof invocationTarget !== 'string') {
    throw new Error('"invocationTarget" must be a string.');
  }

  return utils.deriveKeystoreId(invocationTarget);
}

function _getProfileInvocationZcapKeyReferenceId() {
  return 'profileCapabilityInvocationKey';
}

async function _createCapabilityAgent({handle}) {
  // generate a secret and load a new capability agent
  const secret = new Uint8Array(32);
  crypto.getRandomValues(secret);
  return CapabilityAgent.fromSecret({secret, handle});
}
