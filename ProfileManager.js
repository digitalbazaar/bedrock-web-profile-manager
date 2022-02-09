/*!
 * Copyright (c) 2019-2021 Digital Bazaar, Inc. All rights reserved.
 */
import AccessManager from './AccessManager.js';
import {ProfileService} from 'bedrock-web-profile';
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
import utils from './utils.js';
import assert from './assert.js';
import crypto from './crypto.js';

const JWE_ALG = 'ECDH-ES+A256KW';
const ZCAP_REFERENCE_IDS = {
  profileDoc: 'profile-edv-document',
  userDocs: 'user-edv-documents',
  userKak: 'user-edv-kak',
  userHmac: 'user-edv-hmac',
};
const DEFAULT_ZCAP_GRACE_PERIOD = 15 * 60 * 1000;
const DEFAULT_ZCAP_TTL = 24 * 60 * 60 * 1000;

export default class ProfileManager {
  /**
   * Creates a new instance of a ProfileManager and attaches it to the given
   * session instance. This ProfileManager will track changes to the given
   * session, creating and/or caching account and profile edvs as needed. Some
   * of the methods contain an optional `useEphemeralSigner` parameter that
   * enables invoking the profile's zcap invocation key with an ephemeral
   * capability agent instead of using the profile agent's zcap invocation key
   * directly. This significantly reduces the number of hits to a WebKMS. The
   * ephemeral capability agent is not long lived and can only be used locally.
   * This helps to keep a decent security profile.
   *
   * @param {object} options - The options to use.
   * @param {string} options.kmsModule - The KMS module to use to generate keys.
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
    edvBaseUrl, kmsModule, zcapGracePeriod = DEFAULT_ZCAP_GRACE_PERIOD,
    zcapTtl = DEFAULT_ZCAP_TTL,
    profileService = new ProfileService()
  } = {}) {
    if(typeof kmsModule !== 'string') {
      throw new TypeError('"kmsModule" must be a string.');
    }
    if(typeof edvBaseUrl !== 'string') {
      throw new TypeError('"edvBaseUrl" must be a string.');
    }
    this._profileService = profileService;
    this.session = null;
    this.accountId = null;
    this.kmsModule = kmsModule;
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

    const profileAgentRecord = await this._getAgentRecord({profileId});
    const {profileAgent} = profileAgentRecord;
    // determine if `profileAgent` has a userDocument yet
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
   * Gets a capability specified by its reference ID for profile agent from
   * a cache or delegates one on the fly if it does not exist.
   *
   * @param {object} options - The options to use.
   * @param {string} [options.id] - The ID of the zcap (not supported).
   * @param {string} options.referenceId - The reference ID of the zcap.
   * @param {string} options.profileAgent - The profile agent requesting a zcap.
   * @param {boolean} options.useEphemeralSigner - Flag to enable invoking
   *   capabilities with the ephemeral invocation signer associated with the
   *   currently authenticated session, default `true`. See more in class
   *   description.
   *
   * @returns {Promise<object>} The capability for the profile agent.
   */
  async getAgentCapability({
    id, referenceId, profileAgent, useEphemeralSigner = true
  }) {
    if(id !== undefined) {
      throw new Error('"referenceId" must be provided, not "id".');
    }

    const capabilityCacheKey = `profileAgent-${profileAgent.id}-zcaps`;
    const capabilityKey =
      `${capabilityCacheKey}-${referenceId}-${useEphemeralSigner}`;
    const capabilityCache = this._getCache(capabilityCacheKey);
    let agentZcap = capabilityCache.get(capabilityKey);
    if(agentZcap) {
      return agentZcap;
    }

    const promise = this._getAgentCapability(
      {referenceId, profileAgent, useEphemeralSigner});
    try {
      agentZcap = await promise;
      const now = Date.now();
      const expiryDate = new Date(agentZcap.expires || (now + this.zcapTtl));
      const maxAge = Math.max(
        expiryDate.getTime() - now - this.zcapGracePeriod, 0);
      capabilityCache.set(capabilityKey, promise, maxAge);
      return agentZcap;
    } catch(e) {
      capabilityCache.del(capabilityKey);
      throw e;
    }
  }

  /**
   * Initializes access management for a profile. This method will link the
   * storage location for access management data to the profile and enable
   * its initial profile agent to access its capabilities to use the profile.
   * This method must be called after the profile is created and before it is
   * ready to be used.
   *
   * This method is separate from the `createProfile` call to enable
   * applications to obtain a capability for writing access management data to
   * an EDV or to create that EDV directly after creating profile but before
   * it can be fully initialized.
   *
   * @param {object} options - The options to use.
   * @param {string} options.profileId - The ID of the profile.
   * @param {object} options.profileContent - Any content for the profile.
   * @param {object} options.profileAgentContent - Any content for the initial
   *   profile agent.
   * @param {object} [options.hmac] - An HMAC API for using the EDV; if not
   *   provided, one will be generated for the profile as an EDV recipient.
   * @param {object} [options.keyAgreementKey] - A KAK API for using the EDV;
   *   if not provided, one will be generated for the profile as an EDV
   *   recipient.
   * @param {object} [options.edvId] - The ID of the EDV; either this or a
   *   capability to access the EDV must be given.
   * @param {Array} [options.indexes] - The indexes to be used.
   * @param {object} [options.capability] - The capability to use to access
   *   the EDV; either this or an EDV ID must be given.
   * @param {object} [options.revocationCapability] - The capability to use to
   *   revoke delegated EDV zcaps.
   * @param {boolean} options.useEphemeralSigner - Flag to enable invoking
   *   capabilities with the ephemeral invocation signer associated with the
   *   currently authenticated session, default `true`. See more in class
   *   description.
   *
   * @returns {Promise<object>} An object with the content of the profile and
   *   profile agent documents.
   */
  async initializeAccessManagement({
    profileId,
    profileContent,
    profileAgentContent = {},
    hmac,
    keyAgreementKey,
    edvId,
    capability,
    revocationCapability,
    indexes = [],
    useEphemeralSigner = true
  }) {
    assert.nonEmptyString(profileId, 'profileId');
    if(!!hmac ^ !!keyAgreementKey) {
      throw new TypeError(
        'Both "hmac" and "keyAgreementKey" must be given or neither must ' +
        'be given.');
    }
    if(!!edvId === !!capability) {
      throw new TypeError(
        'Either "edvId" and "capability" must be given, not both.');
    }

    // create EDV keys for accessing users EDV if not given
    const {profileManager} = this;
    if(!hmac) {
      ({hmac, keyAgreementKey} = await profileManager.createEdvRecipientKeys(
        {profileId}));
    }
    // create access management info
    const accessManagement = {
      hmac: {id: hmac.id, type: hmac.type},
      keyAgreementKey: {id: keyAgreementKey.id, type: keyAgreementKey.type},
      indexes: [
        {attribute: 'content.id', unique: true},
        {attribute: 'content.type'},
        ...indexes
      ],
      zcaps: {}
    };
    const profileZcaps = {...profileContent.zcaps};
    if(capability) {
      profileZcaps[capability.referenceId] = capability;
      accessManagement.zcaps = {
        write: capability.referenceId
      };
      if(revocationCapability) {
        accessManagement.zcaps.revoke = revocationCapability.referenceId;
        profileZcaps[revocationCapability.referenceId] = revocationCapability;
      }
    } else {
      // default capability to root zcap
      capability = `urn:zcap:root:${encodeURIComponent(edvId)}`;
      accessManagement.edvId = edvId;
    }

    // create client for accessing users EDV
    const client = new EdvClient({
      id: edvId, keyResolver, keyAgreementKey, hmac
    });
    for(const index of accessManagement.indexes) {
      client.ensureIndex(index);
    }

    // create an invocation signer for signing as the profile when writing
    // to the EDV
    const profileAgentRecord = await this._getAgentRecord({profileId});
    const {
      profileAgent: {
        id: profileAgentId,
        zcaps: {
          profileCapabilityInvocationKey
        }
      }
    } = profileAgentRecord;
    const {invocationSigner} = await this.getProfileSigner(
      {profileId, useEphemeralSigner});
    // create the user document for the profile
    // NOTE: profileContent = {name: 'ACME', color: '#aaaaaa'}
    const recipients = [{
      header: {kid: keyAgreementKey.id, alg: JWE_ALG}
    }];
    const profileDocId = await EdvClient.generateId();
    const profileUserDoc = new EdvDocument({
      id: profileDocId, recipients, keyResolver, keyAgreementKey, hmac,
      capability, invocationSigner, client
    });
    let type = ['User', 'Profile'];
    let {type: profileTypes = []} = profileContent;
    if(!Array.isArray(profileTypes)) {
      profileTypes = [profileTypes];
    }
    for(const t of profileTypes) {
      if(!type.includes(t)) {
        type.push(t);
      }
    }
    const profile = {
      ...profileContent,
      id: profileId,
      type,
      accessManagement,
      zcaps: profileZcaps
    };
    await profileUserDoc.write({
      doc: {
        id: profileDocId,
        content: profile
      }
    });
    // TODO: once delegate on demand is implemented for agents with that
    // capability, remove this unnecessary delegation
    const profileDocZcap = await this._delegateProfileUserDocZcap({
      edvId,
      profileAgentId,
      docId: profileDocId,
      edvParentCapability: capability,
      invocationSigner
    });

    // TODO: once delegate on demand is implemented for agents with that
    // capability, remove these unnecessary delegations
    // TODO: note that `user-edv-kak` will be duplicated here -- future
    // on demand generation of zcaps should try to avoid this
    const {zcaps: userEdvZcaps} = await this.delegateEdvCapabilities({
      edvId,
      hmac,
      keyAgreementKey,
      parentCapabilities: {
        edv: capability,
        edvRevocations: revocationCapability
      },
      invocationSigner,
      profileAgentId,
      referenceIdPrefix: 'user'
    });
    // create the user document for the root profile agent
    const agentDocId = await EdvClient.generateId();
    const agentDoc = new EdvDocument({
      id: agentDocId, recipients, keyResolver, keyAgreementKey, hmac,
      capability, invocationSigner, client
    });
    type = ['User', 'Agent'];
    let {type: agentTypes = []} = profileAgentContent;
    if(!Array.isArray(agentTypes)) {
      agentTypes = [agentTypes];
    }
    for(const t of agentTypes) {
      if(!type.includes(t)) {
        type.push(t);
      }
    }
    const profileAgentZcaps = {};
    for(const [referenceId, zcap] of Object.entries(userEdvZcaps)) {
      profileAgentZcaps[referenceId] = zcap;
    }
    const profileAgent = {
      name: 'root',
      ...profileAgentContent,
      id: profileAgentId,
      type,
      zcaps: {
        profileCapabilityInvocationKey,
        'profile-edv-document': profileDocZcap,
        ...profileAgentZcaps
      },
      authorizedDate: (new Date()).toISOString()
    };
    await agentDoc.write({
      doc: {
        id: agentDocId,
        content: profileAgent
      }
    });
    // create zcaps for accessing profile agent user doc for storage in
    // the agent record
    const agentRecordZcaps = await this._delegateAgentRecordZcaps({
      edvId,
      profileAgentId,
      docId: agentDocId,
      edvParentCapability: capability,
      keyAgreementKey, invocationSigner
    });
    // store capabilities for accessing the profile agent's user document and
    // the kak in the profileAgent record in the backend
    await this._profileService.updateAgentCapabilitySet({
      account: this.accountId,
      profileAgentId,
      // this map includes capabilities for user document and kak
      zcaps: {
        ...profileAgentRecord.profileAgent.zcaps,
        ...agentRecordZcaps
      }
    });
    return {profile, profileAgent};
  }

  /**
   * Creates an API for signing capability invocations and delegations as
   * the a given profile. The account associated with the authenticated
   * session must have a profile agent that has this capability or an error
   * will be thrown.
   *
   * @param {object} options - The options to use.
   * @param {string} options.profileId - The ID of the profile to get a signer
   *   for.
   * @param {boolean} options.useEphemeralSigner - Flag to enable invoking
   *   capabilities with the ephemeral invocation signer associated with the
   *   currently authenticated session, default `true`. See more in class
   *   description.
   *
   * @returns {Promise<object>} Signer API for the profile as
   * `invocationSigner`.
   */
  async getProfileSigner({profileId, useEphemeralSigner = true} = {}) {
    assert.nonEmptyString(profileId, 'profileId');
    // TODO: cache profile signer by profile ID?
    const profileAgent = await this.getAgent({profileId});
    const zcapReferenceId = _getProfileInvocationZcapKeyReferenceId({
      zcaps: profileAgent.zcaps,
      profileId
    });
    const zcap = await this.getAgentCapability({
      referenceId: zcapReferenceId,
      useEphemeralSigner,
      profileId,
      profileAgent
    });

    const invocationSigner = await AsymmetricKey.fromCapability({
      capability: zcap,
      invocationSigner: await this._getAgentSigner({
        useEphemeralSigner,
        profileAgentId: profileAgent.id
      })
    });

    return {invocationSigner};
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
   * @param {boolean} options.useEphemeralSigner - Flag to enable invoking
   *   capabilities with the ephemeral invocation signer associated with the
   *   currently authenticated session, default `true`. See more in class
   *   description.
   *
   * @returns {Promise<object>} Signer API for the profile as
   * `invocationSigner`.
   */
  async getProfile({id, useEphemeralSigner = true} = {}) {
    assert.nonEmptyString(id, 'id');

    // check for a zcap for getting the profile in this order:
    // 1. zcap for reading just the profile
    // 2. zcap for reading entire users EDV
    const profileAgent = await this.getAgent({profileId: id});
    const capability = await this.getAgentCapability({
      referenceId: ZCAP_REFERENCE_IDS.profileDoc,
      useEphemeralSigner,
      profileAgent
    }) || await this.getAgentCapability({
      referenceId: ZCAP_REFERENCE_IDS.userDocs,
      useEphemeralSigner,
      profileAgent
    });
    const userKakZcap = await this.getAgentCapability({
      referenceId: ZCAP_REFERENCE_IDS.userKak,
      useEphemeralSigner,
      profileAgent
    });
    const invocationSigner = await this._getAgentSigner({
      profileAgentId: profileAgent.id,
      useEphemeralSigner
    });
    if(!capability) {
      // TODO: implement on demand delegation; if agent has a zcap for using
      // the profile's zcap delegation key, delegate a zcap for reading from
      // the user's EDV
      throw new Error(
        `Profile agent "${profileAgent.id}" is not authorized to read ` +
        `profile "${id}".`);
    }

    // read the profile's user doc *as* the profile agent
    const edvDocument = new EdvDocument({
      capability,
      keyAgreementKey: await KeyAgreementKey.fromCapability({
        capability: userKakZcap,
        invocationSigner,
      }),
      invocationSigner
    });

    const {content} = await edvDocument.read();

    return content;
  }

  async getProfiles({type} = {}) {
    const profileAgentRecords = await this._profileService.getAllAgents({
      account: this.accountId
    });
    const promises = profileAgentRecords.map(async ({profileAgent}) =>
      this.getProfile({id: profileAgent.profile}));

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

  // FIXME: expose this or not?
  async createEdvRecipientKeys({profileId} = {}) {
    const keystoreAgent = await this.getProfileKeystoreAgent({profileId});
    const [keyAgreementKey, hmac] = await Promise.all([
      keystoreAgent.generateKey({type: 'keyAgreement'}),
      keystoreAgent.generateKey({type: 'hmac'})
    ]);
    return {hmac, keyAgreementKey};
  }

  async getAccessManager({profileId, useEphemeralSigner = true} = {}) {
    assert.nonEmptyString(profileId, 'profileId');
    const [profile, profileAgent] = await Promise.all([
      this.getProfile({id: profileId}),
      this.getAgent({profileId})
    ]);
    // TODO: consider consolidation with `getProfileEdv`
    const referenceIds = [
      ZCAP_REFERENCE_IDS.userDocs,
      ZCAP_REFERENCE_IDS.userKak,
      ZCAP_REFERENCE_IDS.userHmac
    ];
    const promises = referenceIds.map(
      async referenceId => this.getAgentCapability(
        {referenceId, useEphemeralSigner, profileAgent}));
    const [capability, userKak, userHmac] = await Promise.all(promises);
    const invocationSigner = await this._getAgentSigner({
      profileAgentId: profileAgent.id,
      useEphemeralSigner
    });

    if(!(capability && userKak && userHmac)) {
      throw new Error(
        `Profile agent "${profileAgent.id}" is not authorized to manage ` +
        `access for profile "${profileId}".`);
    }
    const {edvId, indexes} = profile.accessManagement;
    const edvClient = new EdvClient({
      id: edvId,
      keyResolver,
      keyAgreementKey: await KeyAgreementKey.fromCapability({
        capability: userKak,
        invocationSigner,
      }),
      hmac: await Hmac.fromCapability({
        capability: userHmac,
        invocationSigner,
      }),
    });
    for(const index of indexes) {
      edvClient.ensureIndex(index);
    }
    const users = new Collection(
      {type: 'User', edvClient, capability, invocationSigner});
    return new AccessManager({profile, profileManager: this, users});
  }

  async createProfileEdv({profileId, meterId, referenceId} = {}) {
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
      hmac,
    });
    return {edvClient};
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

    // 90 day expiration for EDV zcaps
    const expires = new Date();
    expires.setDate(expires.getDate() + 90);

    const delegateEdvDocumentsRequest = {
      referenceId: `${referenceIdPrefix}-edv-documents`,
      allowedAction: ['read', 'write'],
      controller: profileAgentId,
      expires,
      // FIXME: Find proper home for type property
      type: 'urn:edv:documents'
    };
    if(edvId) {
      delegateEdvDocumentsRequest.invocationTarget = `${edvId}/documents`;
      delegateEdvDocumentsRequest.parentCapability =
        `urn:zcap:root:${encodeURIComponent(edvId)}`;
    } else {
      const {edv} = parentCapabilities;
      delegateEdvDocumentsRequest.invocationTarget = edv.invocationTarget;
      delegateEdvDocumentsRequest.parentCapability = edv;
    }

    const delegateEdvHmacRequest = {
      referenceId: `${referenceIdPrefix}-edv-hmac`,
      allowedAction: 'sign',
      controller: profileAgentId,
      expires,
    };
    if(hmac) {
      const keyId = hmac.kmsId ? hmac.kmsId : hmac.id;
      delegateEdvHmacRequest.invocationTarget = keyId;
      delegateEdvHmacRequest.type = hmac.type;
      const keystoreId = utils.parseKeystoreId(keyId);
      const parentZcap = `urn:zcap:root:${encodeURIComponent(keystoreId)}`;
      delegateEdvHmacRequest.parentCapability = parentZcap;
    } else {
      const {hmac} = parentCapabilities;
      delegateEdvHmacRequest.invocationTarget = hmac.invocationTarget;
      delegateEdvHmacRequest.type = hmac.type;
      delegateEdvHmacRequest.parentCapability = hmac;
    }

    const delegateEdvKakRequest = {
      referenceId: `${referenceIdPrefix}-edv-kak`,
      allowedAction: ['deriveSecret', 'sign'],
      controller: profileAgentId,
      expires,
    };
    if(keyAgreementKey) {
      const keyId = keyAgreementKey.kmsId ? keyAgreementKey.kmsId :
        keyAgreementKey.id;
      delegateEdvKakRequest.invocationTarget = keyId;
      delegateEdvKakRequest.type = keyAgreementKey.type;
      const keystoreId = utils.parseKeystoreId(keyId);
      const parentZcap = `urn:zcap:root:${encodeURIComponent(keystoreId)}`;
      delegateEdvKakRequest.parentCapability = parentZcap;
    } else {
      const {keyAgreementKey: kak} = parentCapabilities;
      delegateEdvKakRequest.invocationTarget = kak.invocationTarget;
      delegateEdvKakRequest.type = kak.type;
      delegateEdvKakRequest.parentCapability = kak;
    }
    const requests = [
      delegateEdvDocumentsRequest,
      delegateEdvHmacRequest,
      delegateEdvKakRequest,
    ];
    const delegated = await Promise.all(
      requests.map(request => utils.delegateCapability({
        signer: invocationSigner,
        request,
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
    const keystoreAgent = await this.getProfileKeystoreAgent({profileId});
    const {keystoreId} = keystoreAgent;
    return utils.delegateCapability({signer, keystoreId, request});
  }

  async getCollection({profileId, referenceIdPrefix, type} = {}) {
    assert.nonEmptyString(profileId, 'profileId');
    const {edvClient, capability, invocationSigner} =
      await this.getProfileEdvAccess({profileId, referenceIdPrefix});
    edvClient.ensureIndex({attribute: 'content.id', unique: true});
    edvClient.ensureIndex({attribute: 'content.type'});
    return new Collection({type, edvClient, capability, invocationSigner});
  }

  // FIXME: remove exposure of this?
  async getProfileEdvAccess(
    {profileId, referenceIdPrefix, useEphemeralSigner = true} = {}) {
    assert.nonEmptyString(profileId, 'profileId');
    const refs = {
      documents: `${referenceIdPrefix}-edv-documents`,
      hmac: `${referenceIdPrefix}-edv-hmac`,
      kak: `${referenceIdPrefix}-edv-kak`
    };

    const profileAgent = await this.getAgent({profileId});

    const referenceIds = [refs.documents, refs.kak, refs.hmac];
    const promises = referenceIds.map(
      async referenceId => this.getAgentCapability({
        referenceId, useEphemeralSigner, profileAgent}));
    const [documentsZcap, kakZcap, hmacZcap] = await Promise.all(promises);
    const invocationSigner = await this._getAgentSigner({
      profileAgentId: profileAgent.id,
      useEphemeralSigner
    });

    if(!(documentsZcap && hmacZcap && kakZcap)) {
      throw new Error(
        `Profile agent "${profileAgent.id}" is not authorized to access ` +
        `profile "${profileId}".`);
    }

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
    // user doc based on `referenceIdPrefix` so that they can always
    // be applied here, similar to what is done with accessManagement

    return {edvClient, capability: documentsZcap, invocationSigner};
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

  async _sessionChanged({authentication, newData}) {
    const {account = {}} = newData;
    const {id: newAccountId = null} = account;

    // clear cache
    if(this.accountId && this.accountId !== newAccountId) {
      await CapabilityAgent.clearCache({handle: this.accountId});
    }

    // update state
    this.accountId = newAccountId;
    this._resetCache();

    if(!(authentication || newData.account)) {
      // no account in session, return
      return;
    }
  }

  async _getAgentCapability({referenceId, profileAgent, useEphemeralSigner}) {
    const agentSigner = await this._getAgentSigner(
      {profileAgentId: profileAgent.id, useEphemeralSigner: false});
    const originalZcap = profileAgent.zcaps[referenceId];
    if(!originalZcap) {
      const {id: profileAgentId} = profileAgent;
      throw new Error(
        `The agent "${profileAgentId}" does not have the zcap with ` +
        `reference ID "${referenceId}".`);
    }
    if(!useEphemeralSigner) {
      return originalZcap;
    }
    const ephemeralSigner = await this._getAgentSigner(
      {profileAgentId: profileAgent.id, useEphemeralSigner: true});

    let expires;
    // Ensures the `expires` property in a delegated capability is not less
    // restrictive than its parent.
    if(agentSigner && agentSigner.capability) {
      expires = new Date(agentSigner.capability.expires);
    }

    const originalZcapExpiration = new Date(originalZcap.expires);
    if(originalZcapExpiration < expires) {
      expires = originalZcapExpiration;
    }

    return utils.delegateCapability({
      signer: agentSigner,
      request: {
        ...originalZcap,
        parentCapability: originalZcap,
        controller: ephemeralSigner.id,
        expires,
        type: 'Ed25519VerificationKey2020'
      }
    });
  }

  async _getAgentRecord({profileId}) {
    const recordKey = `agent-records-${profileId}`;
    const agentRecordCache = this._getCache('agent-records');
    const agentRecord = agentRecordCache.get(recordKey);

    if(agentRecord) {
      return agentRecord;
    }

    const promise = this._profileService.getAgentByProfile({
      profile: profileId,
      account: this.accountId
    });

    agentRecordCache.set(recordKey, promise);

    try {
      return await promise;
    } finally {
      // the cache is for concurrent requests only
      agentRecordCache.del(recordKey);
    }
  }

  async _getAgentContent({profileAgentRecord, useEphemeralSigner = true}) {
    const {profileAgent} = profileAgentRecord;

    const {id, account, profile: profileId, sequence} = profileAgent;
    const contentKey = `${id}${account}${profileId}${sequence}`;
    const agentContentCache = this._getCache('agent-content');
    const agentContent = agentContentCache.get(contentKey);
    if(agentContent) {
      return agentContent;
    }
    // determine if `profileAgent` has a userDocument yet
    const capability = await this.getAgentCapability({
      referenceId: 'userDocument',
      useEphemeralSigner,
      profileAgent
    });
    const userKak = await this.getAgentCapability({
      referenceId: 'userKak',
      useEphemeralSigner,
      profileAgent
    });
    const invocationSigner = await this._getAgentSigner({
      profileAgentId: profileAgent.id,
      useEphemeralSigner
    });
    if(!capability) {
      throw new Error('Profile access management not initialized.');
    }

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
    agentContentCache.set(contentKey, promise);

    try {
      return await promise;
    } finally {
      // the cache is for concurrent requests only
      agentContentCache.del(contentKey);
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

  async _getAgentSigner({profileAgentId, useEphemeralSigner}) {
    const cacheKey = `${profileAgentId}-${useEphemeralSigner}`;
    const agentSignersCache = this._getCache('agent-signers');
    let agentSigner = agentSignersCache.get(cacheKey);
    if(agentSigner) {
      return agentSigner;
    }

    const promise = this._createAgentSigner(
      {profileAgentId, useEphemeralSigner});
    try {
      agentSigner = await promise;
      const now = Date.now();

      let expiryDate;
      if(agentSigner && agentSigner.capability) {
        expiryDate = new Date(agentSigner.capability.expires);
      } else {
        expiryDate = new Date(now + this.zcapTtl);
      }
      const maxAge = expiryDate.getTime() - now - this.zcapGracePeriod;
      agentSignersCache.set(cacheKey, promise, maxAge);
      return agentSigner;
    } catch(e) {
      agentSignersCache.del(cacheKey);
      throw e;
    }
  }

  async _createAgentSigner({profileAgentId, useEphemeralSigner}) {
    const capabilityAgent = await this._getCapabilityAgent({profileAgentId});

    if(useEphemeralSigner) {
      return capabilityAgent.getSigner();
    }

    if(!profileAgentId) {
      throw new Error('"profileAgentId" is required for an agent signer.');
    }
    const {zcap} = await this._profileService.delegateAgentCapabilities({
      account: this.accountId,
      invoker: capabilityAgent.id,
      profileAgentId
    });

    // signer for signing with the profileAgent's capability invocation key
    return AsymmetricKey.fromCapability({
      capability: zcap,
      invocationSigner: capabilityAgent.getSigner()
    });
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

  async _getCapabilityAgent({profileAgentId}) {
    assert.nonEmptyString(profileAgentId, 'profileAgentId');

    const capabilityAgentCache = this._getCache('capability-agents');
    const handle = `${this.accountId}-${profileAgentId}`;
    let capabilityAgent = capabilityAgentCache.get(profileAgentId);

    if(!capabilityAgent) {
      capabilityAgent = _createCapabilityAgent({handle});
      capabilityAgentCache.set(profileAgentId, capabilityAgent);
    }

    return capabilityAgent;
  }

  // TODO: delegate this on demand instead, being careful not to create
  // duplicates as a race condition
  async _delegateProfileUserDocZcap({
    edvId, profileAgentId, docId, invocationTarget, edvParentCapability,
    invocationSigner
  }) {
    // 90 day expiration for EDV zcaps
    const expires = new Date();
    expires.setDate(expires.getDate() + 90);

    const delegateUserDocEdvRequest = {
      referenceId: ZCAP_REFERENCE_IDS.profileDoc,
      allowedAction: ['read'],
      controller: profileAgentId,
      parentCapability: edvParentCapability,
      expires,
      type: 'urn:edv:document'
    };
    if(invocationTarget) {
      delegateUserDocEdvRequest.invocationTarget = invocationTarget;
    } else {
      const documentsUrl = edvId ?
        `${edvId}/documents` : edvParentCapability.invocationTarget;
      delegateUserDocEdvRequest.invocationTarget = `${documentsUrl}/${docId}`;
    }
    const profileUserDocZcap = await utils.delegateCapability({
      signer: invocationSigner,
      request: delegateUserDocEdvRequest
    });

    return profileUserDocZcap;
  }

  async _delegateAgentRecordZcaps({
    edvId, profileAgentId, docId, invocationTarget, edvParentCapability,
    keyAgreementKey, invocationSigner
  }) {
    // 90 day expiration for EDV zcaps
    const expires = new Date();
    expires.setDate(expires.getDate() + 90);

    const delegateEdvDocumentRequest = {
      referenceId: `profile-agent-edv-document`,
      // the profile agent is only allowed to read its own doc
      allowedAction: ['read'],
      controller: profileAgentId,
      parentCapability: edvParentCapability,
      type: 'urn:edv:document',
      expires,
    };
    if(invocationTarget) {
      delegateEdvDocumentRequest.invocationTarget = invocationTarget;
    } else {
      const documentsUrl = edvId ?
        `${edvId}/documents` : edvParentCapability.invocationTarget;
      delegateEdvDocumentRequest.invocationTarget = `${documentsUrl}/${docId}`;
    }
    const keyId = keyAgreementKey.kmsId ? keyAgreementKey.kmsId :
      keyAgreementKey.id;
    const keystoreId = utils.parseKeystoreId(keyId);
    const parentZcap = `urn:zcap:root:${encodeURIComponent(keystoreId)}`;
    const delegateEdvKakRequest = {
      referenceId: ZCAP_REFERENCE_IDS.userKak,
      allowedAction: ['deriveSecret', 'sign'],
      controller: profileAgentId,
      invocationTarget: keyId,
      type: keyAgreementKey.type,
      publicAlias: keyAgreementKey.id,
      parentCapability: parentZcap,
      expires,
    };
    const [userDocumentZcap, userKakZcap] = await Promise.all([
      utils.delegateCapability({
        signer: invocationSigner,
        request: delegateEdvDocumentRequest
      }),
      utils.delegateCapability({
        signer: invocationSigner,
        request: delegateEdvKakRequest
      })
    ]);

    return {
      userDocument: userDocumentZcap,
      userKak: userKakZcap
    };
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
