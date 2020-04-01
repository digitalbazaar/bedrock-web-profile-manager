/*!
 * Copyright (c) 2019-2020 Digital Bazaar, Inc. All rights reserved.
 */
import {ProfileService} from 'bedrock-web-profile';

export default class AccessManager {
  /**
   * Creates a new instance of an AccessManager. Should only be called
   * by ProfileManager.
   *
   * @param {Object} options - The options to use.
   * @param {Object} options.profile - The profile to manage access for.
   * @param {Object} options.profileManager - The parent `profileManager`
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
      throw new TypeError('"profileManager" must be an object.');
    }
    this.profile = profile;
    this.profileManager = profileManager;
    this.users = users;
  }

  async createUser({content = {}}) {
    // create a profile agent
    const profileService = new ProfileService();
    const {profile, profileManager} = this;
    const {accountId} = profileManager;
    const {profileAgent} = await profileService.createAgent({
      profile: profile.id
    });
    const {id: profileAgentId} = profileAgent;

    // get EDV parent capability for upcoming delegations
    const {accessManagement} = profile;
    const {invocationSigner} = await profileManager.getProfileSigner(
      {profileId: profile.id});
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
      const agent = await profileManager.getAgent({profileId: profile.id});
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
      zcaps: agentRecordZcaps
    });

    return agentDoc.content;
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
