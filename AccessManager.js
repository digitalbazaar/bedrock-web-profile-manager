/*!
 * Copyright (c) 2019-2020 Digital Bazaar, Inc. All rights reserved.
 */
import {ProfileService} from 'bedrock-web-profile';
import {CapabilityDelegation} from 'ocapld';
import {EdvClient} from 'edv-client';
import jsigs from 'jsonld-signatures';
import utils from './utils';

const {SECURITY_CONTEXT_V2_URL, sign, suites} = jsigs;
const {Ed25519Signature2018} = suites;

export default class AccessManager {
  /**
   * Creates a new instance of an AccessManager. Should only be called
   * by ProfileManager.
   *
   * @param {Object} options - The options to use.
   * @param {Object} options.profile - The profile to manage access for.
   * @param {string} options.profileManager - The parent `profileManager`
   *  instance.
   * @param {Object} options.users - A `users` Collection instance.
   *
   * @returns {AccessManager} - The new instance.
   */
  constructor({profile, profileManager, users} = {}) {
    if(!(profile && typeof profile === 'object')) {
      throw new TypeError('"profile" must be an object.');
    }
    if(typeof profileManager !== 'object') {
      throw new TypeError('"profileManager" must be a string.');
    }
    this.profile = profile;
    this.profileManager = profileManager;
    this.users = users;
  }

  async createUser({profileId, content = {}}) {
    // create a profile agent
    const profileService = new ProfileService();
    const {profile, profileManager} = this;
    const {accountId} = profileManager;
    const {profileAgent} = await profileService.createAgent({
      account: accountId,
      profile: profile.id
    });
    const {id: profileAgentId} = profileAgent;

    // get EDV parent capability for upcoming delegations
    const {accessManagement} = profile;
    const invocationSigner = await profileManager.getProfileSigner(
      {profileId});
    let edvParentCapability;
    if(accessManagement.zcaps.write) {
      edvParentCapability = profile.zcaps[accessManagement.zcaps.write];
    } else {
      // default capability to root zcap
      edvParentCapability = `${accessManagement.edvId}/zcaps/documents`;
    }

    // delegate zcap to enable agent to read profile doc
    const {zcaps = {}} = content;
    if(!zcaps['profile-edv-document']) {
      const agent = await profileManager._getAgent({profileId: profile.id});
      const profileDocCapability = agent.zcaps['profile-edv-document'];
      const profileDocZcap = await profileManager._delegateProfileUserDocZcap({
        edvId: accessManagement.edvId,
        profileAgentId,
        docId: profileDocCapability.invocationTarget.id,
        edvParentCapability,
        invocationSigner
      });
      zcaps[profileDocZcap.referenceId] = profileDocZcap;
    }

    // create user doc for profile agent
    const type = ['User', 'Agent'];
    let {type: agentTypes = []} = content;
    if(!Array.isArray(agentTypes)) {
      agentTypes = [agentTypes];
    }
    for(const t of agentTypes) {
      if(!type.includes(t)) {
        type.push(t);
      }
    }
    const agentDoc = await this.users.create({
      item: {
        ...content,
        id: profileAgentId,
        type,
        zcaps,
        authorizedDate: (new Date()).toISOString()
      }
    });

    // create zcaps for accessing profile agent user doc for storage in
    // the agent record
    const {keyAgreementKey} = accessManagement;
    const agentRecordZcaps = await this.profileManager.
      _delegateAgentRecordZcaps({
        profileAgentId,
        docId: agentDoc.id,
        edvParentCapability,
        keyAgreementKey, invocationSigner
      });

    // store capabilities for accessing the profile agent's user document and
    // the kak in the profileAgent record in the backend
    await profileService.updateAgentCapabilitySet({
      account: accountId,
      profileAgentId,
      // this map includes capabilities for user document and kak
      zcaps: agentRecordZcaps
    });

    return {user: agentDoc.content};
  }

  async updateUser({user}) {
    const userDoc = await this.users.update({
      item: user
    });
    return userDoc.content;
  }

  async getUser({id} = {}) {
    const userDoc = await this.users.get({id});
    return userDoc.content;
  }

  async getUsers({}) {
    const results = await this.users.getAll();
    return results.map(({content}) => content);
  }

  async deleteUser({id} = {}) {
    // TODO: handle removal of self
    await this.users.remove({id});

    // remove profile agent record
    // TODO: check authority model on this
    const profileService = new ProfileService();
    await profileService.deleteAgent({
      id,
      account: this.profileManager.accountId
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

    const {profileAgent} = await this.getAgentByProfile({profileId});

    const {kmsClient, invocationSigner} = await this.getProfileSigner(
      {profileAgent});

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
      zcap = await _delegate({zcap, signer: invocationSigner});

      // TODO: only enable zcap for invocation/delegation keys
      // await kmsClient.enableCapability(
      //   {capabilityToEnable: zcap, invocationSigner});
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
      zcap = await _delegate({zcap, signer: invocationSigner});
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
      zcap = await _delegate({zcap, signer: invocationSigner});
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
      zcap = await _delegate({zcap, signer: invocationSigner});
    } else if(targetType === 'urn:webkms:revocations') {
      zcap.invocationTarget = {
        id: target,
        type: targetType
      };
      const {id: keystoreId} = kmsClient.keystore;

      if(target) {
        // TODO: handle case where an existing target is requested
      } else {
        zcap.invocationTarget.id = `${keystoreId}/revocations`;
      }
      if(!parentCapability) {
        parentCapability = `${keystoreId}/zcaps/revocations`;
      }
      zcap.parentCapability = parentCapability;
      zcap = await _delegate({zcap, signer: invocationSigner});

      // enable zcap via kms client
      // TODO: only enable zcap for invocation/delegation keys
      // await kmsClient.enableCapability(
      //   {capabilityToEnable: zcap, invocationSigner});
    } else {
      throw new Error(`Unsupported invocation target type "${targetType}".`);
    }
    return zcap;
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
