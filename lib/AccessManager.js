/*!
 * Copyright (c) 2019-2022 Digital Bazaar, Inc. All rights reserved.
 */
import * as utils from './utils.js';
import {ProfileService} from '@bedrock/web-profile';

// 365 days
const DEFAULT_PROFILE_AGENT_ZCAP_TTL = 365 * 24 * 60 * 60 * 1000;

export class AccessManager {
  /**
   * Creates a new instance of an AccessManager. Should only be called
   * by ProfileManager.
   *
   * @param {object} options - The options to use.
   * @param {object} options.profile - The profile to manage access for.
   * @param {object} options.profileManager - The parent `profileManager`
   *  instance.
   * @param {object} options.users - A `users` Collection instance.
   *
   * @returns {AccessManager} - The new instance.
   */
  constructor({profile, profileManager, users} = {}) {
    if(!(profile && typeof profile === 'object')) {
      throw new TypeError('"profile" must be an object.');
    }
    if(typeof profileManager !== 'object') {
      throw new TypeError('"profileManager" must be an object.');
    }
    this.profile = profile;
    this.profileManager = profileManager;
    this.users = users;
  }

  async createUser({content = {}, token}) {
    // FIXME: no longer implemented, needs updating
    throw new Error('Not implemented');

    // create a profile agent
    const profileService = new ProfileService();
    const {profile, profileManager} = this;
    const {accountId} = profileManager;
    const {profileAgent} = await profileService.createAgent({
      profile: profile.id, token
    });
    const {id: profileAgentId} = profileAgent;

    // get zcap to delegate from
    const {accessManagement} = profile;
    const edvParentCapability =
      `urn:zcap:root:${encodeURIComponent(accessManagement.edvId)}`;
    const {invocationSigner} = await profileManager.getProfileSigner(
      {profileId: profile.id});

    // delegate zcap to enable agent to read profile doc
    const {zcaps = {}} = content;
    if(!zcaps['profile-edv-document']) {
      const agent = await profileManager.getAgent({profileId: profile.id});
      const profileDocCapability = agent.zcaps['profile-edv-document'];
      const profileDocZcap = await _delegateProfileUserDocZcap({
        capability: edvParentCapability,
        controller: profileAgentId,
        invocationTarget: profileDocCapability.invocationTarget,
        invocationSigner
      });
      zcaps['profile-edv-document'] = profileDocZcap;
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
    // FIXME: delegate `user-edv-kak` and `userDocument`
    const agentRecordZcaps = await this.profileManager.
      _delegateAgentRecordZcaps({
        edvId: accessManagement.edvId,
        profileAgentId,
        docId: agentDoc.id,
        edvParentCapability,
        keyAgreementKey,
        invocationSigner
      });

    // store capabilities for accessing the profile agent's user document and
    // the kak in the profileAgent record in the backend
    await profileService.updateAgentCapabilitySet({
      account: accountId,
      profileAgentId,
      // this map includes capabilities for user document and kak
      zcaps: {
        ...profileAgent.zcaps,
        ...agentRecordZcaps
      }
    });

    return agentDoc.content;
  }

  async updateUser({id, user, mutator} = {}) {
    const userDoc = await this.users.update({
      id,
      item: user,
      mutator
    });
    return userDoc.content;
  }

  async getUser({id} = {}) {
    const userDoc = await this.users.get({id});
    return userDoc.content;
  }

  async getUsers({} = {}) {
    const results = await this.users.getAll();
    return results.map(({content}) => content);
  }

  async removeUser({id} = {}) {
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
}

async function _delegateProfileUserDocZcap({
  capability, controller, invocationTarget, invocationSigner
}) {
  const expires = new Date(Date.now() + DEFAULT_PROFILE_AGENT_ZCAP_TTL);

  const profileUserDocZcap = await utils.delegate({
    signer: invocationSigner,
    allowedActions: ['read'],
    capability,
    controller,
    invocationTarget,
    expires
  });

  return profileUserDocZcap;
}
