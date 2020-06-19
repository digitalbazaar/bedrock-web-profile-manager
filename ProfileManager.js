/*!
 * Copyright (c) 2019-2020 Digital Bazaar, Inc. All rights reserved.
 */
import AccessManager from './AccessManager.js';
import {ProfileService} from 'bedrock-web-profile';
import {
  AsymmetricKey,
  CapabilityAgent,
  KeystoreAgent,
  KeyAgreementKey,
  Hmac,
  KmsClient
} from 'webkms-client';
import Collection from './Collection.js';
import {EdvClient, EdvDocument} from 'edv-client';
import EdvClientCache from './EdvClientCache.js';
import cache, {Cache} from './cache';
import keyResolver from './keyResolver.js';
import utils from './utils.js';
import assert from './assert.js';

const JWE_ALG = 'ECDH-ES+A256KW';
const PROFILE_INVOCATION_ZCAP_REFERENCE_ID =
  'profile-capability-invocation-key';
const EDVS = {
  profileDoc: 'profile-edv-document',
  userDocs: 'user-edv-documents',
  userKak: 'user-edv-kak',
  userHmac: 'user-edv-hmac',
};

export default class ProfileManager {
  /**
   * Creates a new instance of a ProfileManager and attaches it to the given
   * session instance. This ProfileManager will track changes to the given
   * session, creating and/or caching account and profile edvs as needed.
   *
   * @param {object} options - The options to use.
   * @param {object} options.session - A `bedrock-web-session` session instance.
   * @param {string} options.kmsModule - The KMS module to use to generate keys.
   * @param {string} options.kmsBaseUrl - The base URL for the KMS service,
   *   used to generate keys.
   * @param {string} options.edvBaseUrl - The base URL for the EDV service,
   *   used to store documents.
   *
   * @returns {ProfileManager} - The new instance.
   */
  constructor({edvBaseUrl, kmsModule, kmsBaseUrl} = {}) {
    if(typeof kmsModule !== 'string') {
      throw new TypeError('"kmsModule" must be a string.');
    }
    if(typeof kmsBaseUrl !== 'string') {
      throw new TypeError('"kmsBaseUrl" must be a string.');
    }
    if(typeof edvBaseUrl !== 'string') {
      throw new TypeError('"edvBaseUrl" must be a string.');
    }
    this._requests = new Cache();
    this._profileService = new ProfileService();
    this.session = null;
    this.accountId = null;
    this.capabilityAgent = null;
    this.edvClientCache = new EdvClientCache();
    this.keystoreAgent = null;
    this.kmsModule = kmsModule;
    this.edvBaseUrl = edvBaseUrl;
    this.kmsBaseUrl = kmsBaseUrl;
    this._cache = cache.set('internal-profile-manager-cache', new Cache());
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
    const {id} = await this._profileService.create({
      account: this.accountId, didMethod, didOptions
    });
    return {id};
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
      for(const zcap of Object.values(profileAgent.zcaps)) {
        content.zcaps[zcap.referenceId] = zcap;
      }
      return content;
    }

    return await this._getAgentContent({profileAgentRecord});
  }

  /**
   * Gets the profile agent assigned to the account associated with the
   * authenticated session for the profile identified by the given profile ID.
   *
   * @param {object} options - The options to use.
   * @param {string} options.profileId - The ID of the profile to get the
   *   profile agent for.
   * @param {string} options.capabilityInvoker - The type of invoker to sign
   * capability invocations.
   *
   * @returns {Promise<object>} The profile agent.
   */
  async getCapability(
    {id, profileAgent, profileId, capabilityInvoker = 'local'} = {}) {
    const capabilityCacheKey = `profileAgent-${profileAgent.id}-zcaps`;
    const capabilityKey = `${capabilityCacheKey}-${id}-${capabilityInvoker}`;

    if(!this._cache.has(capabilityCacheKey)) {
      this._cache.set(capabilityCacheKey, new Cache());
    }

    let promise = this._requests.get(capabilityKey);

    if(promise) {
      return promise;
    }

    promise = (async () => {
      const capabilityCache = this._cache.get(capabilityCacheKey);
      let zcap = capabilityCache.get(capabilityKey);
      if(!zcap) {
        const agentSigner = await this._getInvocationSigner(
          {profileAgentId: profileAgent.id, capabilityInvoker: 'agent'});
        if(id === PROFILE_INVOCATION_ZCAP_REFERENCE_ID) {
          assert.nonEmptyString(profileId, 'profileId');
          id = _getProfileInvocationZcapKeyReferenceId({
            zcaps: profileAgent.zcaps,
            profileId
          });
        }
        const originalZcap = profileAgent.zcaps[id];
        if(!originalZcap) {
          const {id: profileAgentId} = profileAgent;
          throw new Error(
            `The agent "${profileAgentId}" does not have the zcap: "${id}"`);
        }
        if(capabilityInvoker === 'local') {
          const localSigner = await this._getInvocationSigner(
            {capabilityInvoker: 'local'});
          zcap = await utils.delegateCapability({
            signer: agentSigner,
            request: {
              ...originalZcap,
              parentCapability: originalZcap,
              controller: localSigner.id
            }
          });
        } else if(capabilityInvoker === 'agent') {
          zcap = originalZcap;
        } else {
          throw new Error('Unsupported invoker for capability.');
        }
        capabilityCache.set(capabilityKey, zcap);
      }
      return zcap;
    })();

    this._requests.set(capabilityKey, promise);

    try {
      return await promise;
    } finally {
      this._requests.delete(capabilityKey);
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
   * @param {object} [options.capability] - The capability to use to access
   *   the EDV; either this or an EDV ID must be given.
   * @param {object} [options.revocationCapability] - The capability to use to
   *   revoke delegated EDV zcaps.
   * @param {string} options.capabilityInvoker - The type of invoker to sign
   * capability invocations.
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
    capabilityInvoker = 'local'
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
      capability = `${edvId}/zcaps/documents`;
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
      {profileId, capabilityInvoker});

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
    for(const zcap of userEdvZcaps) {
      profileAgentZcaps[zcap.referenceId] = zcap;
    }
    const profileAgent = {
      name: 'root',
      ...profileAgentContent,
      id: profileAgentId,
      type,
      zcaps: {
        [profileCapabilityInvocationKey.referenceId]:
          profileCapabilityInvocationKey,
        [profileDocZcap.referenceId]: profileDocZcap,
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
      zcaps: agentRecordZcaps
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
   * @param {string} options.capabilityInvoker - The type of invoker to sign
   *   capability invocations.
   *
   * @returns {Promise<object>} Signer API for the profile as
   * `invocationSigner`.
   */
  async getProfileSigner({profileId, capabilityInvoker = 'local'} = {}) {
    assert.nonEmptyString(profileId, 'profileId');
    // TODO: cache profile signer by profile ID?
    const profileAgent = await this.getAgent({profileId});
    const zcap = await this.getCapability({
      id: PROFILE_INVOCATION_ZCAP_REFERENCE_ID,
      capabilityInvoker,
      profileId,
      profileAgent
    });
    const invocationSigner = new AsymmetricKey({
      capability: zcap,
      invocationSigner: await this._getInvocationSigner({
        capabilityInvoker,
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
   * @param {string} options.capabilityInvoker - The type of invoker to sign
   * capability invocations.
   *
   * @returns {Promise<object>} Signer API for the profile as
   * `invocationSigner`.
   */
  async getProfile({id, capabilityInvoker = 'local'} = {}) {
    assert.nonEmptyString(id, 'id');

    // check for a zcap for getting the profile in this order:
    // 1. zcap for reading just the profile
    // 2. zcap for reading entire users EDV
    const profileAgent = await this.getAgent({profileId: id});
    const capability = await this.getCapability({
      id: EDVS.profileDoc,
      capabilityInvoker,
      profileAgent
    }) || await this.getCapability({
      id: EDVS.userDocs,
      capabilityInvoker,
      profileAgent
    });
    const userKakZcap = await this.getCapability({
      id: EDVS.userKak,
      capabilityInvoker,
      profileAgent
    });
    const invocationSigner = await this._getInvocationSigner(
      {profileAgentId: profileAgent.id, capabilityInvoker});
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
      keyAgreementKey: new KeyAgreementKey({
        id: userKakZcap.invocationTarget.id,
        type: userKakZcap.invocationTarget.type,
        capability: userKakZcap,
        invocationSigner
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
    const keystore = await KmsClient.getKeystore({id: keystoreId});
    const capabilityAgent = new CapabilityAgent(
      {handle: 'primary', signer: invocationSigner});
    return new KeystoreAgent({keystore, capabilityAgent});
  }

  // FIXME: expose this or not?
  async createEdvRecipientKeys({profileId} = {}) {
    const keystoreAgent = await this.getProfileKeystoreAgent({profileId});
    const [keyAgreementKey, hmac] = await Promise.all([
      keystoreAgent.generateKey({
        type: 'keyAgreement',
        kmsModule: this.kmsModule,
      }),
      keystoreAgent.generateKey({
        type: 'hmac',
        kmsModule: this.kmsModule,
      })
    ]);
    return {hmac, keyAgreementKey};
  }

  async getAccessManager({profileId, capabilityInvoker = 'local'} = {}) {
    assert.nonEmptyString(profileId, 'profileId');
    const [profile, profileAgent] = await Promise.all([
      this.getProfile({id: profileId}),
      this.getAgent({profileId})
    ]);
    // TODO: consider consolidation with `getProfileEdv`
    const referenceIds = [EDVS.userDocs, EDVS.userKak, EDVS.userHmac];
    const promises = referenceIds.map(async id =>
      this.getCapability({id, capabilityInvoker, profileAgent}));
    const [capability, userKak, userHmac] = await Promise.all(promises);
    const invocationSigner = await this._getInvocationSigner(
      {profileAgentId: profileAgent.id, capabilityInvoker});

    if(!(capability && userKak && userHmac)) {
      throw new Error(
        `Profile agent "${profileAgent.id}" is not authorized to manage ` +
        `access for profile "${profileId}".`);
    }
    const {edvId, indexes} = profile.accessManagement;
    const edvClient = new EdvClient({
      id: edvId,
      keyResolver,
      keyAgreementKey: new KeyAgreementKey({
        id: userKak.invocationTarget.id,
        type: userKak.invocationTarget.type,
        capability: userKak,
        invocationSigner
      }),
      hmac: new Hmac({
        id: userHmac.invocationTarget.id,
        type: userHmac.invocationTarget.type,
        capability: userHmac,
        invocationSigner
      })
    });
    for(const index of indexes) {
      edvClient.ensureIndex(index);
    }
    const users = new Collection(
      {type: 'User', edvClient, capability, invocationSigner});
    return new AccessManager({profile, profileManager: this, users});
  }

  async createProfileEdv({profileId, referenceId} = {}) {
    assert.nonEmptyString(profileId, 'profileId');
    const [{invocationSigner}, {hmac, keyAgreementKey}] = await Promise.all([
      this.getProfileSigner({profileId}),
      this.createEdvRecipientKeys({profileId})
    ]);

    // create edv
    let config = {
      sequence: 0,
      controller: profileId,
      referenceId,
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
    // TODO: validate `parentCapabilities`
    // if no `edvId` then `parentCapabilities.edv` required
    // if no `hmac` then `parentCapabilities.hmac` required
    // if no `keyAgreement` then `parentCapabilities.keyAgreementKey` required

    const delegateEdvDocumentsRequest = {
      referenceId: `${referenceIdPrefix}-edv-documents`,
      allowedAction: ['read', 'write'],
      controller: profileAgentId
    };
    if(edvId) {
      delegateEdvDocumentsRequest.invocationTarget = {
        id: `${edvId}/documents`,
        type: 'urn:edv:documents'
      };
      delegateEdvDocumentsRequest.parentCapability =
        `${edvId}/zcaps/documents`;
    } else {
      const {edv} = parentCapabilities;
      delegateEdvDocumentsRequest.invocationTarget = {...edv.invocationTarget};
      delegateEdvDocumentsRequest.parentCapability = edv;
    }

    const delegateEdvHmacRequest = {
      referenceId: `${referenceIdPrefix}-edv-hmac`,
      allowedAction: 'sign',
      controller: profileAgentId
    };
    if(hmac) {
      delegateEdvHmacRequest.invocationTarget = {
        id: hmac.id,
        type: hmac.type,
        verificationMethod: hmac.id
      };
      delegateEdvHmacRequest.parentCapability = hmac.id;
    } else {
      const {hmac} = parentCapabilities;
      delegateEdvHmacRequest.invocationTarget = {...hmac.invocationTarget};
      delegateEdvHmacRequest.parentCapability = hmac;
    }

    const delegateEdvKakRequest = {
      referenceId: `${referenceIdPrefix}-edv-kak`,
      allowedAction: ['deriveSecret', 'sign'],
      controller: profileAgentId
    };
    if(keyAgreementKey) {
      delegateEdvKakRequest.invocationTarget = {
        id: keyAgreementKey.id,
        type: keyAgreementKey.type,
        verificationMethod: keyAgreementKey.id
      };
      delegateEdvKakRequest.parentCapability = keyAgreementKey.id;
    } else {
      const {keyAgreementKey: kak} = parentCapabilities;
      delegateEdvKakRequest.invocationTarget = {...kak.invocationTarget};
      delegateEdvKakRequest.parentCapability = kak;
    }

    const zcaps = await Promise.all([
      utils.delegateCapability({
        signer: invocationSigner,
        request: delegateEdvDocumentsRequest
      }),
      utils.delegateCapability({
        signer: invocationSigner,
        request: delegateEdvHmacRequest
      }),
      utils.delegateCapability({
        signer: invocationSigner,
        request: delegateEdvKakRequest
      })
    ]);

    return {zcaps};
  }

  async delegateCapability({profileId, request}) {
    assert.nonEmptyString(profileId, 'profileId');
    const {invocationSigner: signer} = await this.getProfileSigner({profileId});
    const keystoreAgent = await this.getProfileKeystoreAgent({profileId});
    const {id: keystoreId} = keystoreAgent.keystore;
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
    {profileId, referenceIdPrefix, capabilityInvoker = 'local'} = {}) {
    assert.nonEmptyString(profileId, 'profileId');
    const refs = {
      documents: `${referenceIdPrefix}-edv-documents`,
      hmac: `${referenceIdPrefix}-edv-hmac`,
      kak: `${referenceIdPrefix}-edv-kak`
    };

    const profileAgent = await this.getAgent({profileId});

    const referenceIds = [refs.documents, refs.kak, refs.hmac];
    const promises = referenceIds.map(async id =>
      this.getCapability({id, capabilityInvoker, profileAgent}));
    const [documentsZcap, kakZcap, hmacZcap] = await Promise.all(promises);
    const invocationSigner = await this._getInvocationSigner(
      {profileAgentId: profileAgent.id, capabilityInvoker});

    if(!(documentsZcap && hmacZcap && kakZcap)) {
      throw new Error(
        `Profile agent "${profileAgent.id}" is not authorized to access ` +
        `profile "${profileId}".`);
    }

    const edvClient = new EdvClient({
      keyResolver,
      keyAgreementKey: new KeyAgreementKey({
        id: kakZcap.invocationTarget.id,
        type: kakZcap.invocationTarget.type,
        capability: kakZcap,
        invocationSigner
      }),
      hmac: new Hmac({
        id: hmacZcap.invocationTarget.id,
        type: hmacZcap.invocationTarget.type,
        capability: hmacZcap,
        invocationSigner
      })
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
    this._cache.clear();
  }

  async _sessionChanged({authentication, newData}) {
    const {account = {}} = newData;
    const {id: newAccountId = null} = account;

    // clear cache
    if(this.accountId && this.accountId !== newAccountId) {
      await CapabilityAgent.clearCache({handle: this.accountId});
      await this.edvClientCache.clear();
    }

    // update state
    const accountId = this.accountId = newAccountId;
    this.capabilityAgent = null;
    this.keystoreAgent = null;
    this._resetCache();

    if(!(authentication || newData.account)) {
      // no account in session, return
      return;
    }

    this.capabilityAgent = await CapabilityAgent.fromCache({handle: accountId});
    if(this.capabilityAgent === null) {
      // generate a secret and load a new capability agent
      const crypto = (self.crypto || self.msCrypto);
      const secret = new Uint8Array(32);
      crypto.getRandomValues(secret);

      // TODO: support N capability agents, one per profile/profile-agent
      this.capabilityAgent = await CapabilityAgent.fromSecret(
        {secret, handle: accountId});
    }
  }

  async _getAgentRecord({profileId}) {
    if(!this._cache.has('agent-records')) {
      this._cache.set('agent-records', new Cache({maxAge: 250}));
    }

    const recordKey = `agent-records-${profileId}`;
    const agentRecordCache = this._cache.get('agent-records');
    const agentRecord = agentRecordCache.get(recordKey);
    if(agentRecord) {
      return agentRecord;
    }
    let promise = this._requests.get(recordKey);
    if(promise) {
      return promise;
    }
    promise = this._profileService.getAgentByProfile({
      profile: profileId,
      account: this.accountId
    });
    this._requests.set(recordKey, promise);
    try {
      const record = await promise;
      agentRecordCache.set(recordKey, record);
      return record;
    } finally {
      this._requests.delete(recordKey);
    }
  }

  async _getAgentContent({profileAgentRecord, capabilityInvoker = 'local'}) {
    if(!this._cache.has('agent-content')) {
      this._cache.set('agent-content', new Cache());
    }
    const {profileAgent} = profileAgentRecord;

    const {id, account, profile: profileId, sequence} = profileAgent;
    const contentKey = `${id}${account}${profileId}${sequence}`;
    const agentContentCache = this._cache.get('agent-content');
    const agentContent = agentContentCache.get(contentKey);
    if(agentContent) {
      return agentContent;
    }
    const refs = {
      userKak: 'userKak',
      userDocument: 'userDocument'
    };
    // determine if `profileAgent` has a userDocument yet
    const capability = await this.getCapability({
      id: refs.userDocument,
      capabilityInvoker,
      profileAgent
    });
    const userKak = await this.getCapability({
      id: refs.userKak,
      capabilityInvoker,
      profileAgent
    });
    const invocationSigner = await this._getInvocationSigner(
      {profileAgentId: profileAgent.id, capabilityInvoker});
    if(!capability) {
      throw new Error('Profile access management not initialized.');
    }

    let promise = this._requests.get(contentKey);
    if(promise) {
      return promise;
    }
    promise = (async () => {
      const edvDocument = new EdvDocument({
        capability,
        keyAgreementKey: new KeyAgreementKey({
          id: userKak.invocationTarget.id,
          type: userKak.invocationTarget.type,
          capability: userKak,
          invocationSigner
        }),
        invocationSigner
      });

      const {content} = await edvDocument.read();

      // update zcaps to include zcaps from agent record
      for(const zcap of Object.values(profileAgent.zcaps)) {
        const {referenceId} = zcap;
        if(!content.zcaps[referenceId]) {
          content.zcaps[referenceId] = zcap;
        }
      }
      return content;
    })();
    this._requests.set(contentKey, promise);
    try {
      return await promise;
    } finally {
      this._requests.delete(contentKey);
    }
  }

  async _getAgentSigner({id} = {}) {
    if(!this._cache.has('agent-signers')) {
      this._cache.set('agent-signers', new Cache());
    }
    const agentSignersCache = this._cache.get('agent-signers');
    let signer = agentSignersCache.get(id);
    if(!signer) {
      const {zcap} = await this._profileService.delegateAgentCapabilities({
        account: this.accountId,
        invoker: this.capabilityAgent.id,
        profileAgentId: id
      });

      // signer for signing with the profileAgent's capability invocation key
      signer = new AsymmetricKey({
        capability: zcap,
        invocationSigner: await this._getInvocationSigner(
          {capabilityInvoker: 'local'}),
      });
      agentSignersCache.set(id, signer);
    }
    return signer;
  }

  async _getInvocationSigner({profileAgentId, capabilityInvoker}) {
    assert.nonEmptyString(capabilityInvoker, 'capabilityInvoker');
    if(!this._cache.has('invocation-signers')) {
      this._cache.set('invocation-signers', new Cache());
    }
    const invocationSignersCache = this._cache.get('invocation-signers');
    const cacheKey = `${profileAgentId}-${capabilityInvoker}`;

    let invocationSigner = invocationSignersCache.get(cacheKey);
    if(invocationSigner) {
      return invocationSigner;
    }

    if(capabilityInvoker === 'local') {
      invocationSigner = this.capabilityAgent.getSigner();
    } else if(capabilityInvoker === 'agent') {
      if(!profileAgentId) {
        throw new Error('"profileAgentId" is required for an agent signer.');
      }
      const {zcap} = await this._profileService.delegateAgentCapabilities({
        account: this.accountId,
        invoker: this.capabilityAgent.id,
        profileAgentId
      });

      // signer for signing with the profileAgent's capability invocation key
      invocationSigner = new AsymmetricKey({
        capability: zcap,
        invocationSigner: this.capabilityAgent.getSigner()
      });
    } else {
      throw new Error('Unsupported invoker for capability.');
    }
    invocationSignersCache.set(cacheKey, invocationSigner);
    return invocationSigner;
  }

  // TODO: delegate this on demand instead, being careful not to create
  // duplicates as a race condition
  async _delegateProfileUserDocZcap({
    edvId, profileAgentId, docId, invocationTarget, edvParentCapability,
    invocationSigner
  }) {
    const delegateUserDocEdvRequest = {
      referenceId: EDVS.profileDoc,
      allowedAction: ['read'],
      controller: profileAgentId,
      parentCapability: edvParentCapability
    };
    if(invocationTarget) {
      delegateUserDocEdvRequest.invocationTarget = {...invocationTarget};
    } else {
      const documentsUrl = edvId ?
        `${edvId}/documents` : edvParentCapability.invocationTarget.id;
      delegateUserDocEdvRequest.invocationTarget = {
        id: `${documentsUrl}/${docId}`,
        type: 'urn:edv:document'
      };
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
    const delegateEdvDocumentRequest = {
      referenceId: `profile-agent-edv-document`,
      // the profile agent is only allowed to read its own doc
      allowedAction: ['read'],
      controller: profileAgentId,
      parentCapability: edvParentCapability
    };
    if(invocationTarget) {
      delegateEdvDocumentRequest.invocationTarget = {...invocationTarget};
    } else {
      const documentsUrl = edvId ?
        `${edvId}/documents` : edvParentCapability.invocationTarget.id;
      delegateEdvDocumentRequest.invocationTarget = {
        id: `${documentsUrl}/${docId}`,
        type: 'urn:edv:document'
      };
    }
    const delegateEdvKakRequest = {
      referenceId: EDVS.userKak,
      allowedAction: ['deriveSecret', 'sign'],
      controller: profileAgentId,
      invocationTarget: {
        id: keyAgreementKey.id,
        type: keyAgreementKey.type,
        verificationMethod: keyAgreementKey.id
      },
      parentCapability: keyAgreementKey.id
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
  if(typeof invocationTarget === 'string') {
    return utils.deriveKeystoreId(invocationTarget);
  }
  if(invocationTarget.id && typeof invocationTarget.id === 'string') {
    return utils.deriveKeystoreId(invocationTarget.id);
  }
  throw new Error('"invocationTarget" does not contain a proper id.');
}

function _getProfileInvocationZcapKeyReferenceId(
  {profileId, zcaps}) {
  // FIXME: simplify reference ID for this; force only one reference ID
  // for using the agent's profile's capability invocation key using the
  // literal reference ID: 'profile-capability-invocation-key'
  return Object.keys(zcaps).find(referenceId => {
    const capabilityInvokeKeyReference = '-key-capabilityInvocation';
    return referenceId.startsWith(profileId) &&
      referenceId.endsWith(capabilityInvokeKeyReference);
  });
}
