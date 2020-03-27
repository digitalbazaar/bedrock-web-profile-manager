/*!
 * Copyright (c) 2019-2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

import axios from 'axios';
import {AccountService} from 'bedrock-web-account';
import {ProfileService} from 'bedrock-web-profile';
import jsonpatch from 'fast-json-patch';
import {CapabilityDelegation} from 'ocapld';
import {
  AsymmetricKey,
  CapabilityAgent,
  KeystoreAgent,
  KeyAgreementKey,
  KmsClient
} from 'webkms-client';
import {EdvClient, EdvDocument} from 'edv-client';
import jsigs from 'jsonld-signatures';
import kms from './kms';
import EdvClientCache from './EdvClientCache.js';
import edvs from './edvs';
import utils from './utils';

const {SECURITY_CONTEXT_V2_URL, sign, suites} = jsigs;
const {Ed25519Signature2018} = suites;

const DEFAULT_HEADERS = {Accept: 'application/ld+json, application/json'};

const JWE_ALG = 'ECDH-ES+A256KW';

export default class ProfileManager {
  /**
   * Creates a new instance of a ProfileManager and attaches it to the given
   * session instance. This ProfileManager will track changes to the given
   * session, creating and/or caching account and profile edvs as needed.
   *
   * @param {Object} options - The options to use.
   * @param {Object} options.session - A `bedrock-web-session` session instance.
   * @param {string} options.kmsModule - The KMS module to use to generate keys.
   * @param {string} options.kmsBaseUrl - The base URL for the KMS service,
   *   used to generate keys.
   * @param {string} options.edvBaseUrl - The base URL for the EDV service,
   *   used to store documents.
   * @param {string} options.recoveryHost - The recovery host application to
   *   use for keystore configs.
   *
   * @returns {ProfileManager} - The new instance.
   */
  constructor({edvBaseUrl, kmsModule, kmsBaseUrl, recoveryHost} = {}) {
    if(typeof kmsModule !== 'string') {
      throw new TypeError('"kmsModule" must be a string.');
    }
    if(typeof kmsBaseUrl !== 'string') {
      throw new TypeError('"kmsBaseUrl" must be a string.');
    }
    if(typeof edvBaseUrl !== 'string') {
      throw new TypeError('"edvBaseUrl" must be a string.');
    }
    this._profileService = new ProfileService();
    this.session = null;
    this.accountId = null;
    this.capabilityAgent = null;
    this.edvClientCache = new EdvClientCache();
    this.keystoreAgent = null;
    this.kmsModule = kmsModule;
    this.edvBaseUrl = edvBaseUrl;
    this.kmsBaseUrl = kmsBaseUrl;
    if(recoveryHost) {
      this.recoveryHost = recoveryHost.startsWith('https://') ?
        recoveryHost : `https://${recoveryHost}`;
    }
  }

  /**
   * Attaches this instance to the given session. This ProfileManager will
   * track changes to the given session, creating and/or caching account and
   * profile edvs as needed.
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

  async createUser({
    edvClient, invocationSigner, profileAgentId, referenceId,
    content = {}
  }) {
    if(!referenceId) {
      referenceId = edvs.getReferenceId('users');
    }

    edvClient.ensureIndex({attribute: 'content.id'});
    edvClient.ensureIndex({attribute: 'content.type'});
    edvClient.ensureIndex({attribute: 'content.name'});
    edvClient.ensureIndex({attribute: 'content.email'});
    // FIXME: profileAgent needs to be factored out in favor of profileAgentId
    edvClient.ensureIndex({attribute: 'content.profileAgent'});
    edvClient.ensureIndex({attribute: 'content.profileAgentId'});

    if(!content.id) {
      throw new TypeError('"content.id" is required.');
    }

    // create the user document for the profile agent
    const userDocument = await edvClient.insert({
      doc: {
        content: {
          ...content,
          zcaps: content.zcaps || {},
        },
      },
      invocationSigner,
    });

    const delegateEdvDocumentRequest = {
      referenceId: `${referenceId}-edv-document`,
      // the profile agent is only allowed to read its own doc
      allowedAction: ['read'],
      controller: profileAgentId,
      invocationTarget: {
        id: `${edvClient.id}/documents/${userDocument.id}`,
        type: 'urn:edv:document'
      }
    };

    const delegateEdvKakRequest = {
      referenceId: `${referenceId}-kak`,
      allowedAction: ['deriveSecret', 'sign'],
      controller: profileAgentId,
      invocationTarget: {
        id: edvClient.keyAgreementKey.id,
        type: edvClient.keyAgreementKey.type,
        verificationMethod: edvClient.keyAgreementKey.id
      }
    };
    const [userDocumentZcap, userKakZcap] = await Promise.all([
      utils.delegateCapability({
        edvClient,
        signer: invocationSigner,
        request: delegateEdvDocumentRequest
      }),
      utils.delegateCapability({
        signer: invocationSigner,
        request: delegateEdvKakRequest
      })
    ]);

    return {
      userDocument,
      zcaps: {
        userDocument: userDocumentZcap,
        userKak: userKakZcap,
      },
    };
  }

  async delegateEdvCapabilities({
    edvClient,
    invocationSigner,
    profileAgentId,
    referenceId
  }) {
    const delegateEdvConfigurationRequest = {
      referenceId: `${referenceId}-edv-configuration`,
      allowedAction: ['read', 'write'],
      controller: profileAgentId,
      invocationTarget: {
        id: `${edvClient.id}/documents`,
        type: 'urn:edv:documents'
      }
    };
    const delegateEdvHmacRequest = {
      referenceId: `${referenceId}-hmac`,
      allowedAction: 'sign',
      controller: profileAgentId,
      invocationTarget: {
        id: edvClient.hmac.id,
        type: edvClient.hmac.type,
        verificationMethod: edvClient.hmac.id
      }
    };
    const delegateEdvKakRequest = {
      referenceId: `${referenceId}-kak`,
      allowedAction: ['deriveSecret', 'sign'],
      controller: profileAgentId,
      invocationTarget: {
        id: edvClient.keyAgreementKey.id,
        type: edvClient.keyAgreementKey.type,
        verificationMethod: edvClient.keyAgreementKey.id
      }
    };
    const zcaps = await Promise.all([
      utils.delegateCapability({
        edvClient,
        signer: invocationSigner,
        request: delegateEdvConfigurationRequest
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

  async initializeAccessManagement({
    edvClient,
    invocationSigner,
    profileAgentDetails,
    profileAgentId,
    profileAgentZcaps,
    profileDetails,
    profileDocumentReferenceId,
    profileId,
    profileZcaps = {},
  }) {
    // create the user document for the profile
    // NOTE: profileDetails = {name: 'ACME', color: '#aaaaaa'}
    const profileUserDocumentDetails = await this.createUser({
      edvClient, invocationSigner, profileAgentId,
      referenceId: profileDocumentReferenceId,
      // referenceId: config.DEFAULT_EDVS.users,
      content: {
        ...profileDetails,
        id: profileId,
        zcaps: profileZcaps,
      },
    });

    // capablities to enable the profile agent to read the profile's user doc
    for(const capability of Object.values(profileUserDocumentDetails.zcaps)) {
      profileAgentZcaps[capability.referenceId] = capability;
    }

    const profileAgentUserDocumentDetails =
      await this.createUser({
        edvClient, invocationSigner, profileAgentId,
        content: {
          // includes: name, email
          ...profileAgentDetails,
          id: profileAgentId,
          type: ['User', 'Person'],
          // FIXME: remove `profileAgent` and `profileAgentId` completely,
          // these are given via `id`
          profileAgent: profileAgentId,
          profileAgentId,
          access: 'full',
          zcaps: profileAgentZcaps,
          authorizedDate: (new Date()).toISOString(),
        }
      });

    // store capabilities for accessing the profile agent's user document and
    // the kak in the profileAgent record in the backend
    await this._profileService.updateAgentCapabilitySet({
      account: this.accountId,
      profileAgentId,
      // this map includes capabilities for user document and kak
      zcaps: profileAgentUserDocumentDetails.zcaps,
    });

    return {
      profileAgentUserDocumentDetails,
      profileUserDocumentDetails,
    };
  }

  async createEdvRecipientKeys({
    invocationSigner,
    kmsClient,
  }) {
    const [keyAgreementKey, hmac] = await Promise.all([
      kms.generateKey({
        invocationSigner,
        type: 'keyAgreement',
        kmsClient,
        kmsModule: this.kmsModule,
      }),
      kms.generateKey({
        invocationSigner,
        type: 'hmac',
        kmsClient,
        kmsModule: this.kmsModule,
      })
    ]);
    return {
      hmac,
      keyAgreementKey,
    };
  }

  // TODO: add docs
  async createProfileEdv({
    invocationSigner,
    kmsClient,
    profileId,
    referenceId,
  }) {
    const {hmac, keyAgreementKey} = await this.createEdvRecipientKeys({
      invocationSigner,
      kmsClient,
    });
    const edvClient = await edvs.create({
      invocationSigner,
      profileId,
      referenceId,
      edvBaseUrl: this.edvBaseUrl,
      keys: {
        hmac,
        keyAgreementKey,
      }
    });

    return {edvClient};
  }

  async getUsersEdv({referenceId, profileAgent}) {
    const profileId = profileAgent.profile;

    const {kmsClient, invocationSigner, zcaps} = await this.getProfileSigner(
      {profileAgent});

    // FIXME: can this key be contructed without the search?
    // the challenge is that the referenceId (zcaps[referenceId]) is a DID
    // key that includes a hash fragment
    // e.g. did:key:MOCK_KEY#MOCK_KEY-key-capabilityInvocation
    const _zcapMapKey = Object.keys(zcaps).find(referenceId => referenceId
      .endsWith('key-capabilityInvocation'));
    const zcap = zcaps[_zcapMapKey];

    const keystoreId = _getKeystoreId({zcap});
    const keystore = await KmsClient.getKeystore({id: keystoreId});
    const capabilityAgent = new CapabilityAgent(
      {handle: 'primary', signer: invocationSigner});
    const keystoreAgent = new KeystoreAgent(
      {keystore, capabilityAgent, kmsClient});
    const edvClient = await edvs.get({
      invocationSigner,
      keystoreAgent,
      profileId,
      referenceId,
    });

    edvClient.ensureIndex({attribute: 'content.profileAgentId'});
    edvClient.ensureIndex({attribute: 'content.id'});
    edvClient.ensureIndex({attribute: 'content.type'});
    edvClient.ensureIndex({attribute: 'content.name'});
    edvClient.ensureIndex({attribute: 'content.email'});
    // FIXME: profileAgent needs to be factored out in favor of profileAgentId
    edvClient.ensureIndex({attribute: 'content.profileAgent'});

    return {
      edvClient,
      invocationSigner,
    };
  }

  // FIXME: this function is getting called frequently and is expensive
  // consider using EDV Client cache
  async getProfileEdv({profileId, referenceId}) {
    const {profileAgent} = await this._profileService.getAgentByProfile({
      account: this.accountId,
      profile: profileId
    });

    // FIXME: `zcaps` are coming out of the capabilitySet EDV which is
    // read deep in the call stack. Need to clean this up.
    const {kmsClient, invocationSigner, zcaps} = await this.getProfileSigner(
      {profileAgent});

    const edvConfigZcap = zcaps[`${referenceId}-edv-configuration`];
    const edvHmacZcap = zcaps[`${referenceId}-hmac`];

    if(!(edvConfigZcap && edvHmacZcap)) {
      throw new Error(
        `Capabilities not found for accessing EDV: "${referenceId}".`);
    }

    const keystoreId = _getKeystoreId({zcap: edvHmacZcap});
    const keystore = await KmsClient.getKeystore({id: keystoreId});
    const capabilityAgent = new CapabilityAgent(
      {handle: 'primary', signer: invocationSigner});
    const keystoreAgent = new KeystoreAgent(
      {keystore, capabilityAgent, kmsClient});
    const edv = await edvs.get({
      invocationSigner,
      keystoreAgent,
      profileId,
      referenceId
    });
    return {
      edv,
      edvConfigZcap,
      invocationSigner,
      zcaps,
      profileAgentId: profileAgent.id
    };
  }

  async createAgent({profileId, accountId}) {
    return this._profileService.createAgent({
      account: accountId,
      profile: profileId
    });
  }
  async getAgentByProfile({profileId}) {
    return this._profileService.getAgentByProfile({
      profile: profileId,
      account: this.accountId
    });
  }

  async getAgent({id}) {
    return this._profileService.getAgent({
      id,
      account: this.accountId
    });
  }

  async deleteAgent({id}) {
    return this._profileService.deleteAgent({
      id,
      account: this.accountId
    });
  }

  async createProfile({content, type} = {}) {
    let profileType = 'Profile';
    if(type) {
      profileType = [profileType, type];
    }
    const {id: profileId} = await this._profileService.create(
      {account: this.accountId});

    const {profileAgent} = await this._profileService.getAgentByProfile({
      account: this.accountId,
      profile: profileId
    });

    const profileSettings = {
      ...content,
      type: profileType,
      id: profileId,
    };

    return {
      profileAgent,
      profileSettings,
    };
  }

  async getProfile({profileAgent, profileId} = {}) {
    if(!(profileAgent || profileId)) {
      throw new TypeError(
        'One of "profileAgent" or "profileId" parameters is required.');
    }
    if(!profileAgent) {
      // profileId will be defined here
      ({profileAgent} = await this._profileService.getAgentByProfile({
        account: this.accountId,
        profile: profileId
      }));
    }

    const profileAgentDetails = await this.getProfileAgent({profileAgent});
    const documentReferenceId = edvs.getReferenceId('users-edv-document');
    const capability = profileAgentDetails.zcaps[documentReferenceId];

    const invocationSigner = await this.getProfileAgentSigner(
      {profileAgentId: profileAgent.id});

    const edvDocument = new EdvDocument({
      capability,
      keyAgreementKey: _userDocumentKak({invocationSigner, profileAgent}),
      invocationSigner,
    });

    const {content} = await edvDocument.read();

    return content;
  }

  async getProfileAgent({profileAgent} = {}) {
    if(!(profileAgent)) {
      throw new TypeError('"profileAgent" parameter is required.');
    }

    const invocationSigner = await this.getProfileAgentSigner(
      {profileAgentId: profileAgent.id});

    const edvDocument = new EdvDocument({
      capability: profileAgent.zcaps.userDocument,
      keyAgreementKey: _userDocumentKak({invocationSigner, profileAgent}),
      invocationSigner,
    });

    const {content} = await edvDocument.read();

    return content;
  }

  async getProfiles({type} = {}) {
    const profileAgentRecords = await this._profileService.getAllAgents({
      account: this.accountId,
    });
    const promises = profileAgentRecords.map(async ({profileAgent}) =>
      this.getProfile({profileAgent}));

    // TODO: Use proper promise-fun library to limit concurrency
    const profiles = await Promise.all(promises);
    if(!type) {
      return profiles;
    }
    return profiles.filter(profile => profile.type.includes(type));
  }

  async getProfileAgentSigner({profileAgentId}) {
    const {zcap} = await this._profileService.delegateAgentCapabilities({
      account: this.accountId,
      invoker: this.capabilityAgent.id,
      profileAgentId
    });

    // signer for signing with the profileAgent's capability invocation key
    return new AsymmetricKey({
      capability: zcap,
      invocationSigner: this.capabilityAgent.getSigner(),
    });
  }

  async getProfileSigner({profileAgent}) {
    // FIXME: `zcaps` are coming out of the capabilitySet EDV which is
    // read deep in the call stack. Need to clean this up.
    const {zcap, invocationSigner, zcaps} =
      await this._getProfileInvocationKeyZcap({profileAgent});

    // FIXME: remove `kmsClient` here if not needed
    const keystore = _getKeystoreId({zcap});
    const kmsClient = new KmsClient({keystore});
    const profileZcapKey = new AsymmetricKey({
      capability: zcap,
      invocationSigner,
      kmsClient
    });

    return {
      invocationSigner: profileZcapKey,
      kmsClient,
      // FIXME: `zcaps` are coming out of the capabilitySet EDV which is
      // read deep in the call stack. Need to clean this up.
      zcaps
    };
  }

  async updateUser({profileAgent, usersReferenceId, content}) {
    if(!usersReferenceId) {
      usersReferenceId = edvs.getReferenceId('users');
    }
    const {edvClient, invocationSigner} = await this.getUsersEdv(
      {profileAgent, referenceId: usersReferenceId});

    const [userDoc] = await edvClient.find({
      equals: {'content.id': content.id},
      invocationSigner
    });

    const updatedUserDoc = await edvClient.update({
      doc: {
        ...userDoc,
        content: {
          ...userDoc.content,
          ...content
        }
      },
      invocationSigner,
      keyResolver
    });
    return updatedUserDoc.content;
  }

  async getUser({profileAgent, userId, usersReferenceId} = {}) {
    if(!usersReferenceId) {
      usersReferenceId = edvs.getReferenceId('users');
    }
    const {edvClient, invocationSigner} = await this.getUsersEdv(
      {profileAgent, referenceId: usersReferenceId});

    const [userDoc] = await edvClient.find({
      equals: {'content.id': userId},
      invocationSigner
    });
    return userDoc.content;
  }

  async getUsers({profileId, usersReferenceId}) {
    if(!usersReferenceId) {
      usersReferenceId = edvs.getReferenceId('users');
    }

    const {profileAgent} = await this._profileService.getAgentByProfile({
      account: this.accountId,
      profile: profileId
    });

    const {edvClient, invocationSigner} = await this.getUsersEdv(
      {profileAgent, referenceId: usersReferenceId});

    const results = await edvClient.find({
      // FIXME: bug in equals implementation here
      // equals: {'content.type': ['Person', 'User']},
      has: 'content.type',
      invocationSigner
    });
    return results.map(({content}) => content);
  }

  async deleteUser({profileAgent, userId, usersReferenceId} = {}) {
    if(!usersReferenceId) {
      usersReferenceId = edvs.getReferenceId('users');
    }
    const {edvClient, invocationSigner} = await this.getUsersEdv(
      {profileAgent, referenceId: usersReferenceId});

    const [userDoc] = await edvClient.find({
      equals: {'content.id': userId},
      invocationSigner
    });
    return edvClient.delete({
      id: userDoc.id,
      invocationSigner
    });
  }

  async delegateCapability({request}) {
    const {
      invocationTarget, invoker, delegator, referenceId, allowedAction, caveat
    } = request;
    if(!(invocationTarget && typeof invocationTarget === 'object' &&
      invocationTarget.type)) {
      throw new TypeError(
        '"invocationTarget" must be an object that includes a "type".');
    }

    // TODO: delegator should be a profile the user selected and
    // we should use a profile agent to invoke its zcap for delegating
    const signer = this.capabilityAgent.getSigner();

    let zcap = {
      '@context': SECURITY_CONTEXT_V2_URL,
      // use 128-bit random multibase encoded value
      id: `urn:zcap:${await EdvClient.generateId()}`,
      invoker
    };
    if(delegator) {
      zcap.delegator = delegator;
    }
    if(referenceId) {
      zcap.referenceId = referenceId;
    }
    if(allowedAction) {
      zcap.allowedAction = allowedAction;
    }
    if(caveat) {
      zcap.caveat = caveat;
    }
    let {parentCapability} = request;
    const {id: target, type: targetType, verificationMethod} = invocationTarget;
    if(targetType === 'Ed25519VerificationKey2018') {
      if(!target) {
        throw new TypeError(
          '"invocationTarget.id" must be set for Web KMS capabilities.');
      }
      if(!verificationMethod) {
        throw new TypeError(
          '"invocationTarget.verificationMethod" is required when ' +
          '"invocationTarget.type" is "Ed25519VerificationKey2018".');
      }
      // TODO: fetch `target` from a key mapping document in the profile's
      // edv to get public key ID to set as `referenceId`
      zcap.invocationTarget = {
        id: target,
        type: targetType,
        verificationMethod,
      };
      zcap.parentCapability = parentCapability || target;
      zcap = await _delegate({zcap, signer});

      await this.keystoreAgent.kmsClient.enableCapability(
        {capabilityToEnable: zcap, invocationSigner: signer});
    } else if(targetType === 'urn:edv:document') {
      zcap.invocationTarget = {
        id: target,
        type: targetType
      };

      // FIXME: always pass parentCapability
      if(!parentCapability) {
        throw new Error('Not implemented: FIXME, parentCapability required');
        // const idx = zcap.invocationTarget.id.lastIndexOf('/');
        // const docId = zcap.invocationTarget.id.substr(idx + 1);
        //parentCapability = `${edvClient.id}/zcaps/documents/${docId}`;
      }
      zcap.parentCapability = parentCapability;
      zcap = await _delegate({zcap, signer});
    } else if(targetType === 'urn:edv:documents') {
      zcap.invocationTarget = {
        id: target,
        type: targetType
      };

      if(!parentCapability) {
        throw new Error('Not implemented: FIXME, parentCapability required');
        //parentCapability = `${edvClient.id}/zcaps/documents`;
      }
      zcap.parentCapability = parentCapability;
      zcap = await _delegate({zcap, signer});
    } else if(targetType === 'urn:edv:revocations') {
      zcap.invocationTarget = {
        id: target,
        type: targetType
      };

      if(!parentCapability) {
        throw new Error('Not implemented: FIXME, parentCapability required');
        //parentCapability = `${edvClient.id}/zcaps/revocations`;
      }
      zcap.parentCapability = parentCapability;
      zcap = await _delegate({zcap, signer});
    } else if(targetType === 'urn:webkms:revocations') {
      zcap.invocationTarget = {
        id: target,
        type: targetType
      };
      // FIXME: need to get the keystoreAgent associated with a profile
      // that is delegating the zcap
      const keystore = this.keystoreAgent.keystore.id;

      if(target) {
        // TODO: handle case where an existing target is requested
      } else {
        zcap.invocationTarget.id = `${keystore}/revocations`;
      }
      if(!parentCapability) {
        parentCapability = `${keystore}/zcaps/revocations`;
      }
      zcap.parentCapability = parentCapability;
      zcap = await _delegate({zcap, signer});

      // enable zcap via kms client
      await this.keystoreAgent.kmsClient.enableCapability(
        {capabilityToEnable: zcap, invocationSigner: signer});
    } else {
      throw new Error(`Unsupported invocation target type "${targetType}".`);
    }
    return zcap;
  }

  async delegateAgentCapabilities({to, profileAgentId}) {
    return this._profileService.delegateAgentCapabilities({
      account: this.accountId,
      invoker: to,
      profileAgentId
    });
  }

  async updateAgentCapabilitySet({profileAgentId, zcaps}) {
    return this._profileService.updateAgentCapabilitySet({
      account: this.accountId,
      profileAgentId,
      zcaps
    });
  }

  // FIXME: this API is no longer used as currently implemented
  async deleteAgentCapabilitySet({profileAgentId}) {
    return this._profileService.deleteAgentCapabilitySet({
      account: this.accountId,
      profileAgentId
    });
  }

  // check if profileAgent.zcaps.profileCapabilityInvocationKey
  // is present, just return it, otherwise, look for it in the
  // capability set EDV document for the profile agent
  async _getProfileInvocationKeyZcap({profileAgent}) {
    const {id: profileAgentId, profile: profileId} = profileAgent;

    const invocationSigner = await this.getProfileAgentSigner({profileAgentId});

    // return profile capability invocation key if it hasn't been
    // moved to a capability set EDV document yet; this only happens
    // when a new profile is being provisioned
    if(profileAgent.zcaps.profileCapabilityInvocationKey) {
      return {
        zcap: profileAgent.zcaps.profileCapabilityInvocationKey,
        invocationSigner,
        zcaps: {
          [profileAgent.zcaps.profileCapabilityInvocationKey.referenceId]:
            profileAgent.zcaps.profileCapabilityInvocationKey
        }
      };
    }

    const c = new EdvClient({keyResolver});

    const userDocument = await c.get({
      id: profileAgent.zcaps.userDocument.invocationTarget.id,
      capability: profileAgent.zcaps.userDocument,
      invocationSigner,
      keyAgreementKey: _userDocumentKak({invocationSigner, profileAgent}),
    });

    const {content: {zcaps}} = userDocument;

    // FIXME: can this key be contructed without the search?
    // the challenge is that the referenceId (zcaps[referenceId]) is a DID
    // key that includes a hash fragment
    // e.g. did:key:MOCK_KEY#MOCK_KEY-key-capabilityInvocation
    const _zcapMapKey = Object.keys(zcaps).find(referenceId => {
      const capabilityInvokeKeyReference = '-key-capabilityInvocation';
      return referenceId.startsWith(profileId) &&
        referenceId.endsWith(capabilityInvokeKeyReference);
    });

    const profileInvocationKeyZcap = zcaps[_zcapMapKey];
    if(!profileInvocationKeyZcap) {
      throw new Error(`Unable find the profile invocation key zcap` +
        ` for "${profileId}"`);
    }

    return {
      zcaps,
      zcap: profileInvocationKeyZcap,
      invocationSigner
    };
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

  async _createEdv({referenceId} = {}) {
    // create KAK and HMAC keys for edv config
    const {capabilityAgent, keystoreAgent, kmsModule} = this;
    const [keyAgreementKey, hmac] = await Promise.all([
      keystoreAgent.generateKey({type: 'keyAgreement', kmsModule}),
      keystoreAgent.generateKey({type: 'hmac', kmsModule})
    ]);

    // create edv
    let config = {
      sequence: 0,
      controller: capabilityAgent.handle,
      // TODO: add `invoker` and `delegator` using capabilityAgent.id *or*, if
      // this is a profile's edv, the profile ID
      invoker: capabilityAgent.id,
      delegator: capabilityAgent.id,
      keyAgreementKey: {id: keyAgreementKey.id, type: keyAgreementKey.type},
      hmac: {id: hmac.id, type: hmac.type}
    };
    if(referenceId) {
      config.referenceId = referenceId;
    }
    config = await EdvClient.createEdv({config});
    return new EdvClient(
      {id: config.id, keyResolver, keyAgreementKey, hmac});
  }

  async _ensureEdv() {
    const {capabilityAgent, keystoreAgent} = this;
    const config = await EdvClient.findConfig(
      {controller: capabilityAgent.handle, referenceId: 'primary'});
    if(config === null) {
      return await this._createEdv({referenceId: 'primary'});
    }
    const [keyAgreementKey, hmac] = await Promise.all([
      keystoreAgent.getKeyAgreementKey(
        {id: config.keyAgreementKey.id, type: config.keyAgreementKey.type}),
      keystoreAgent.getHmac({id: config.hmac.id, type: config.hmac.type})
    ]);
    return new EdvClient(
      {id: config.id, keyResolver, keyAgreementKey, hmac});
  }

  async _createKeystore({referenceId} = {}) {
    const {capabilityAgent, recoveryHost} = this;

    // create keystore
    const config = {
      sequence: 0,
      controller: capabilityAgent.id,
      invoker: capabilityAgent.id,
      delegator: capabilityAgent.id
    };
    if(recoveryHost) {
      config.invoker = [config.invoker, recoveryHost];
    }
    if(referenceId) {
      config.referenceId = referenceId;
    }
    return await KmsClient.createKeystore({
      url: `${this.kmsBaseUrl}/keystores`,
      config
    });
  }

  async _ensureKeystore({accountId}) {
    const {capabilityAgent} = this;

    // see if there is an existing keystore for the account
    const service = new AccountService();
    const {account: {keystore}} = await service.get({id: accountId});
    if(keystore) {
      // keystore exists, get config and check against capability agent
      let config = await KmsClient.getKeystore({id: keystore});
      const {controller} = config;
      if(controller !== capabilityAgent.id) {
        // keystore does NOT match; perform recovery
        config = await this._recoverKeystore({id: keystore});
        // TODO: handle future case where user has not authorized the
        // host application to perform recovery
      }
      this.keystoreAgent = new KeystoreAgent(
        {keystore: config, capabilityAgent});
      return config;
    }

    // if there is no existing keystore...
    let config = await KmsClient.findKeystore({
      url: `${this.kmsBaseUrl}/keystores`,
      controller: capabilityAgent.id,
      referenceId: 'primary'
    });
    if(config === null) {
      config = await this._createKeystore({referenceId: 'primary'});
    }
    if(config === null) {
      return null;
    }
    this.keystoreAgent = new KeystoreAgent({keystore: config, capabilityAgent});

    await this._addKeystoreToAccount({accountId, keystoreId: config.id});

    return config;
  }

  async _addKeystoreToAccount({accountId, keystoreId}) {
    const service = new AccountService();
    while(true) {
      const {account, meta} = await service.get({id: accountId});
      if(account.keystore === keystoreId) {
        break;
      }

      const {sequence} = meta;
      const observer = jsonpatch.observe(account);
      const patch = jsonpatch.generate(observer);
      account.keystore = keystoreId;
      jsonpatch.unobserve(account, observer);
      try {
        await service.update({id: accountId, sequence, patch});
        break;
      } catch(e) {
        // if e has a conflict response try again, otherwise throw error
        const {response = {}} = e;
        if(response.status !== 409) {
          throw e;
        }
      }
    }
  }

  async _recoverKeystore({id}) {
    // FIXME: this needs to be posted to a different endpoint that is
    // able to authenticate the user and ensure that the controller being
    // updated was under the control of the user's account
    const {capabilityAgent} = this;
    const url = `${id}/recover`;
    const response = await axios.post(url, {
      '@context': 'https://w3id.org/security/v2',
      controller: capabilityAgent.id
    }, {headers: DEFAULT_HEADERS});
    const keystoreConfig = response.data;

    // clear edv client cache so new instances will use new capability agent
    this.edvClientCache.clear();

    // update account edv
    const edvClient = await this._ensureEdv();
    await this.edvClientCache.set('primary', edvClient);
    const config = await EdvClient.getConfig({id: edvClient.id});
    config.sequence++;
    config.invoker = config.delegator = capabilityAgent.id;
    await EdvClient.updateConfig({id: edvClient.id, config});

    // TODO: updating profile edvs should not be required once profile
    // edvs properly use the profile's keys for invoker/delegator
    // instead of the account's capability agent

    // update all profile edvs
    const profiles = await this.getProfiles();
    await Promise.all(profiles.map(async ({content: profile}) => {
      const config = await EdvClient.getConfig({id: profile.edv});
      config.sequence++;
      config.invoker = config.delegator = capabilityAgent.id;
      await EdvClient.updateConfig({id: profile.edv, config});
    }));

    return keystoreConfig;
  }
}

async function _delegate({zcap, signer}) {
  // attach capability delegation proof
  return sign(zcap, {
    // TODO: map `signer.type` to signature suite
    suite: new Ed25519Signature2018({
      signer,
      verificationMethod: signer.id
    }),
    purpose: new CapabilityDelegation({
      capabilityChain: [zcap.parentCapability]
    }),
    compactProof: false
  });
}

function _getKeystoreId({zcap}) {
  const {invocationTarget} = zcap;
  if(!invocationTarget) {
    throw new Error('"invocationTarget" not found on zCap.');
  }
  if(typeof invocationTarget === 'string') {
    return _deriveKeystoreId(invocationTarget);
  }
  if(invocationTarget.id && typeof invocationTarget.id === 'string') {
    return _deriveKeystoreId(invocationTarget.id);
  }
  throw new Error('"invocationTarget" does not contain a proper id.');
}

function _deriveKeystoreId(id) {
  const urlObj = new URL(id);
  const paths = urlObj.pathname.split('/');
  return urlObj.origin +
    '/' +
    paths[1] + // "kms"
    '/' +
    paths[2] + // "keystores"
    '/' +
    paths[3]; // "<keystore_id>"
}

// FIXME: make more restrictive, support `did:key` and `did:v1`
async function keyResolver({id}) {
  const response = await axios.get(id, {
    headers: DEFAULT_HEADERS
  });
  return response.data;
}

function _userDocumentKak({invocationSigner, profileAgent}) {
  return new KeyAgreementKey({
    id: profileAgent.zcaps.userKak.invocationTarget.id,
    type: profileAgent.zcaps.userKak.invocationTarget.type,
    capability: profileAgent.zcaps.userKak,
    invocationSigner,
  });
}
