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
import {EdvClient} from 'edv-client';
import jsigs from 'jsonld-signatures';
import uuid from 'uuid-random';
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

  async createCapabilitySetDocument({
    edvClient, invocationSigner, profileAgentId, referenceId, zcaps = {}
  }) {
    edvClient.ensureIndex({attribute: 'content.profileAgentId'});

    // create the capabilitySet document for the profile agent
    const capabilitySetDocument = await edvClient.insert({
      doc: {
        content: {
          profileAgentId,
          zcaps,
          // FIXME: id and type?
        }
      },
      invocationSigner,
    });

    const delegateEdvDocumentRequest = {
      referenceId: `${referenceId}-edv-document`,
      // the profile agent is only allowed to read its own doc
      allowedAction: ['read'],
      controller: profileAgentId,
      invocationTarget: {
        id: `${edvClient.id}/documents/${capabilitySetDocument.id}`,
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
    const [capabilitySetDocumentZcap, capabilitySetKakZcap] =
      await Promise.all([
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
      capabilitySetDocument,
      zcaps: {
        capabilitySetDocument: capabilitySetDocumentZcap,
        capabilitySetKak: capabilitySetKakZcap,
      },
    };
  }

  // TODO: add docs
  async createProfileEdv({
    invocationSigner, kmsClient, profileAgentId, profileId, referenceId
  }) {
    const edv = await edvs.create({
      invocationSigner,
      kmsClient,
      kmsModule: this.kmsModule,
      profileId,
      referenceId,
      edvBaseUrl: this.edvBaseUrl,
    });
    const delegateEdvConfigurationRequest = {
      referenceId: `${referenceId}-edv-configuration`,
      allowedAction: ['read', 'write'],
      controller: profileAgentId,
      invocationTarget: {
        id: `${edv.id}/documents`,
        type: 'urn:edv:documents'
      }
    };
    const delegateEdvHmacRequest = {
      referenceId: `${referenceId}-hmac`,
      allowedAction: 'sign',
      controller: profileAgentId,
      invocationTarget: {
        id: edv.hmac.id,
        type: edv.hmac.type,
        verificationMethod: edv.hmac.id
      }
    };
    const delegateEdvKakRequest = {
      referenceId: `${referenceId}-kak`,
      allowedAction: ['deriveSecret', 'sign'],
      controller: profileAgentId,
      invocationTarget: {
        id: edv.keyAgreementKey.id,
        type: edv.keyAgreementKey.type,
        verificationMethod: edv.keyAgreementKey.id
      }
    };
    const edvZcaps = await Promise.all([
      utils.delegateCapability({
        edvClient: edv,
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
    return {
      edv,
      edvConfigZcap: edvZcaps[0],
      zcaps: edvZcaps,
    };
  }

  async getCapabilitySetEdv({referenceId, profileAgent}) {
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
        `Capabilties not found for accessing EDV: "${referenceId}".`);
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

  async createProfile({
    type, content, settingsReferenceId, usersReferenceId,
    capabilitySetReferenceId
  } = {}) {
    if(!capabilitySetReferenceId) {
      capabilitySetReferenceId = edvs.getReferenceId('capability-set');
    }
    if(!settingsReferenceId) {
      settingsReferenceId = edvs.getReferenceId('settings');
    }
    if(!usersReferenceId) {
      usersReferenceId = edvs.getReferenceId('users');
    }
    let profileType = 'Profile';
    if(type) {
      profileType = [profileType, type];
    }
    const {id: profileId} = await this._profileService.create(
      {account: this.accountId});

    const referenceIds = [
      // FIXME: only shared profiles need a users EDV so creating this EDV
      // should happen at the appropriate time in the top level app
      usersReferenceId,
      // settings must be the last item in this array
      settingsReferenceId,
    ];

    const {profileAgent} = await this._profileService.getAgentByProfile({
      account: this.accountId,
      profile: profileId
    });

    const {id: profileAgentId} = profileAgent;

    const {invocationSigner, kmsClient} = await this.getProfileSigner(
      {profileAgent});

    const promises = referenceIds.map(async referenceId => {
      return this.createProfileEdv({
        invocationSigner,
        kmsClient,
        profileAgentId,
        profileId,
        referenceId
      });
    });
    // TODO: Use proper promise-fun library to limit concurrency. After
    // the extraneous operations are removed here, this will not be necessary
    const results = await Promise.all(promises);
    const settings = results[results.length - 1];
    const {edv: profileSettingsEdv} = settings;

    // update profile agent capability set with newly created zCaps to access
    // the users EDV and settings EDV
    const newZcaps = {
      [profileAgent.zcaps.profileCapabilityInvocationKey.referenceId]:
        profileAgent.zcaps.profileCapabilityInvocationKey
    };
    for(const r of results) {
      for(const capability of r.zcaps) {
        newZcaps[capability.referenceId] = capability;
      }
    }

    const edvClient = await edvs.create({
      invocationSigner,
      kmsClient,
      kmsModule: this.kmsModule,
      profileId,
      referenceId: capabilitySetReferenceId,
      edvBaseUrl: this.edvBaseUrl,
    });

    // FIXME: enable if field is added
    // edvClient.ensureIndex({attribute: 'content.id'});
    // edvClient.ensureIndex({attribute: 'content.type'});

    const capabilitySetDocumentDetails =
      await this.createCapabilitySetDocument({
        edvClient, invocationSigner, profileAgentId,
        referenceId: capabilitySetReferenceId, zcaps: newZcaps
      });

    const capabilitySetEdvDetails = {
      ...capabilitySetDocumentDetails,
      edvClient,
    };

    await this._profileService.updateAgentCapabilitySet({
      account: this.accountId,
      profileAgentId,
      // this map includes: capabilitySetDocument, capabilitySetKak
      zcaps: capabilitySetEdvDetails.zcaps,
    });
    // TODO: Enable adding newly created agent as
    // add current profile agent to the users edv
    // const userContent = {
    //   name: settings.name,
    //   email: settings.email, // TODO: Get email
    //   profileAgent: profileAgentId
    // };
    // await this.createUser({
    //   profileId: id,
    //   usersReferenceId,
    //   content: userContent
    // });
    // create the settings for the profile
    profileSettingsEdv.ensureIndex({attribute: 'content.id'});
    profileSettingsEdv.ensureIndex({attribute: 'content.type'});
    const res = await profileSettingsEdv.insert({
      doc: {
        id: await EdvClient.generateId(),
        content: {
          ...content,
          type: profileType,
          id: profileId,
        }
      },
      invocationSigner,
      keyResolver
    });

    return {
      capabilitySetEdvDetails,
      invocationSigner,
      kmsClient,
      profileAgent,
      profileSettings: res.content,
    };
  }

  // TODO: implement adding an existing profile to an account
  async getProfile({profileId, settingsReferenceId} = {}) {
    if(!settingsReferenceId) {
      settingsReferenceId = edvs.getReferenceId('settings');
    }

    const {
      edv: settingsEdv,
      invocationSigner,
      profileAgentId
    } = await this.getProfileEdv({
      profileId,
      referenceId: settingsReferenceId
    });

    settingsEdv.ensureIndex({attribute: 'content.id'});
    settingsEdv.ensureIndex({attribute: 'content.type'});
    const [settingsDoc] = await settingsEdv.find({
      equals: {'content.id': profileId},
      invocationSigner
    });

    return {...settingsDoc.content, profileAgentId};
  }

  async getProfiles({type} = {}) {
    const profileAgentRecords = await this._profileService.getAllAgents({
      account: this.accountId,
    });
    const promises = profileAgentRecords.map(async ({profileAgent}) => {
      return this.getProfile({profileId: profileAgent.profile});
    });
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
    const profileId = profileAgent.profile;
    // FIXME: `zcaps` are coming out of the capabilitySet EDV which is
    // read deep in the call stack. Need to clean this up.
    const {zcap, invocationSigner, zcaps} =
      await this._getProfileInvocationKeyZcap({profileAgent, profileId});

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

  // FIXME: split functions up into separate files/services
  async createUser({profileId, usersReferenceId, content}) {
    if(!usersReferenceId) {
      usersReferenceId = edvs.getReferenceId('users');
    }
    const userDoc = {
      id: await EdvClient.generateId(),
      content: {
        ...content,
        id: uuid(),
        type: 'User',
        authorizedDate: (new Date()).toISOString()
      }
    };
    const {edv: usersEdv, invocationSigner} = await this.getProfileEdv({
      profileId,
      referenceId: usersReferenceId
    });
    usersEdv.ensureIndex({attribute: 'content.id'});
    usersEdv.ensureIndex({attribute: 'content.type'});
    usersEdv.ensureIndex({attribute: 'content.name'});
    usersEdv.ensureIndex({attribute: 'content.email'});
    usersEdv.ensureIndex({attribute: 'content.profileAgent'});
    await usersEdv.insert({
      doc: userDoc,
      invocationSigner,
      keyResolver
    });
    return userDoc.content;
  }

  async updateUser({profileId, usersReferenceId, content}) {
    if(!usersReferenceId) {
      usersReferenceId = edvs.getReferenceId('users');
    }
    const {edv: usersEdv, invocationSigner} = await this.getProfileEdv({
      profileId,
      referenceId: usersReferenceId
    });
    const [userDoc] = await usersEdv.find({
      equals: {'content.id': content.id},
      invocationSigner
    });
    usersEdv.ensureIndex({attribute: 'content.id'});
    usersEdv.ensureIndex({attribute: 'content.type'});
    usersEdv.ensureIndex({attribute: 'content.name'});
    usersEdv.ensureIndex({attribute: 'content.email'});
    usersEdv.ensureIndex({attribute: 'content.profileAgent'});
    const updatedUserDoc = await usersEdv.update({
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

  async getUser({profileId, userId, usersReferenceId} = {}) {
    if(!usersReferenceId) {
      usersReferenceId = edvs.getReferenceId('users');
    }
    const {
      edv: usersEdv,
      invocationSigner
    } = await this.getProfileEdv({
      profileId,
      referenceId: usersReferenceId
    });
    usersEdv.ensureIndex({attribute: 'content.id'});
    usersEdv.ensureIndex({attribute: 'content.type'});
    usersEdv.ensureIndex({attribute: 'content.name'});
    usersEdv.ensureIndex({attribute: 'content.email'});
    usersEdv.ensureIndex({attribute: 'content.profileAgent'});
    const [userDoc] = await usersEdv.find({
      equals: {'content.id': userId},
      invocationSigner
    });
    return userDoc.content;
  }

  async getUsers({profileId, usersReferenceId}) {
    if(!usersReferenceId) {
      usersReferenceId = edvs.getReferenceId('users');
    }
    const {edv: usersEdv, invocationSigner} = await this.getProfileEdv({
      profileId,
      referenceId: usersReferenceId
    });
    usersEdv.ensureIndex({attribute: 'content.id'});
    usersEdv.ensureIndex({attribute: 'content.type'});
    usersEdv.ensureIndex({attribute: 'content.name'});
    usersEdv.ensureIndex({attribute: 'content.email'});
    usersEdv.ensureIndex({attribute: 'content.profileAgent'});
    const results = await usersEdv.find({
      equals: {'content.type': 'User'},
      invocationSigner
    });
    return results.map(({content}) => content);
  }

  async deleteUser({profileId, userId, usersReferenceId} = {}) {
    if(!usersReferenceId) {
      usersReferenceId = edvs.getReferenceId('users');
    }
    const {
      edv: usersEdv,
      invocationSigner
    } = await this.getProfileEdv({
      profileId,
      referenceId: usersReferenceId
    });
    usersEdv.ensureIndex({attribute: 'content.id'});
    usersEdv.ensureIndex({attribute: 'content.type'});
    usersEdv.ensureIndex({attribute: 'content.name'});
    usersEdv.ensureIndex({attribute: 'content.email'});
    usersEdv.ensureIndex({attribute: 'content.profileAgent'});
    const [userDoc] = await usersEdv.find({
      equals: {'content.id': userId},
      invocationSigner
    });
    return usersEdv.delete({
      id: userDoc.id,
      invocationSigner
    });
  }

  async delegateCapability({profileId, request}) {
    const {
      invocationTarget, invoker, delegator, referenceId, allowedAction, caveat
    } = request;
    if(!(invocationTarget && typeof invocationTarget === 'object' &&
      invocationTarget.type)) {
      throw new TypeError(
        '"invocationTarget" must be an object that includes a "type".');
    }

    const edvClient = await this.getProfileEdv({profileId});

    // TODO: to reduce correlation between the account and multiple profiles,
    // generate a unique capability agent per profile DID
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

      if(target) {
        // TODO: handle case where an existing target is requested
      } else {
        // use 128-bit random multibase encoded value
        const docId = await EdvClient.generateId();
        zcap.invocationTarget.id = `${edvClient.id}/documents/${docId}`;
        // insert empty doc to establish self as a recipient
        const doc = {
          id: docId,
          content: {}
        };
        // TODO: this is not clean; zcap query needs work! ... another
        // option is to get a `keyAgreement` verification method from
        // the controller of the `invoker`
        const recipients = [{
          header: {
            kid: edvClient.keyAgreementKey.id,
            alg: JWE_ALG
          }
        }];
        if(invocationTarget.recipient) {
          recipients.push(invocationTarget.recipient);
        }
        const invocationSigner = this.capabilityAgent.getSigner();
        await edvClient.insert({doc, recipients, invocationSigner});
      }
      if(!parentCapability) {
        const idx = zcap.invocationTarget.id.lastIndexOf('/');
        const docId = zcap.invocationTarget.id.substr(idx + 1);
        parentCapability = `${edvClient.id}/zcaps/documents/${docId}`;
      }
      zcap.parentCapability = parentCapability;
      zcap = await _delegate({zcap, signer});

      // enable zcap via edv client
      await edvClient.enableCapability(
        {capabilityToEnable: zcap, invocationSigner: signer});
    } else if(targetType === 'urn:edv:documents') {
      zcap.invocationTarget = {
        id: target,
        type: targetType
      };

      if(target) {
        // TODO: handle case where an existing target is requested
      } else {
        // TODO: note that only the recipient of the zcap will be able
        // to read the documents it writes -- as no recipient is specified
        // here ... could add this to the zcap as a special caveat that
        // requires the recipient always be present for every document written
        zcap.invocationTarget.id = `${edvClient.id}/documents`;
      }
      if(!parentCapability) {
        parentCapability = `${edvClient.id}/zcaps/documents`;
      }
      zcap.parentCapability = parentCapability;
      zcap = await _delegate({zcap, signer});

      // enable zcap via edv client
      await edvClient.enableCapability(
        {capabilityToEnable: zcap, invocationSigner: signer});
    } else if(targetType === 'urn:edv:revocations') {
      zcap.invocationTarget = {
        id: target,
        type: targetType
      };

      if(target) {
        // TODO: handle case where an existing target is requested
      } else {
        zcap.invocationTarget.id = `${edvClient.id}/revocations`;
      }
      if(!parentCapability) {
        parentCapability = `${edvClient.id}/zcaps/revocations`;
      }
      zcap.parentCapability = parentCapability;
      zcap = await _delegate({zcap, signer});

      // enable zcap via edv client
      await edvClient.enableCapability(
        {capabilityToEnable: zcap, invocationSigner: signer});
    } else if(targetType === 'urn:webkms:revocations') {
      zcap.invocationTarget = {
        id: target,
        type: targetType
      };
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
  async _getProfileInvocationKeyZcap({profileId, profileAgent}) {
    const {id: profileAgentId} = profileAgent;

    const invocationSigner = await this.getProfileAgentSigner({profileAgentId});

    // return profile capability invocation key if it hasn't been
    // moved to a capability set EDV document yet; this only happens
    // when a new profile is being provisioned
    if(profileAgent.zcaps.profileCapabilityInvocationKey) {
      return {
        zcap: profileAgent.zcaps.profileCapabilityInvocationKey,
        invocationSigner
      };
    }

    const c = new EdvClient({keyResolver});

    const capabilitySetDocument = await c.get({
      id: profileAgent.zcaps.capabilitySetDocument.invocationTarget.id,
      capability: profileAgent.zcaps.capabilitySetDocument,
      invocationSigner,
      keyAgreementKey: new KeyAgreementKey({
        // FIXME: is this the proper way to get this ID?
        id: profileAgent.zcaps.capabilitySetKak.invocationTarget.id,
        type: profileAgent.zcaps.capabilitySetKak.invocationTarget.type,
        capability: profileAgent.zcaps.capabilitySetKak,
        invocationSigner,
      })
    });

    const {zcaps} = capabilitySetDocument.content;

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
