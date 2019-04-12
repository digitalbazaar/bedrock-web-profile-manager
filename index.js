/*!
 * Copyright (c) 2019 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

export {default as ProfileManager} from './ProfileManager.js';

/*

How do we want the API to look?

Typically, we'll log a user into an account. So we want to gate on that...
when the account is logged in, we make some call to setup some state that
we are going to clear when we're done. So there *is* state. And that's
true because we're caching stuff.

So, user logs in ... and we still have access to their login secret. We
create a ProfileManager instance and pass that secret when we do so?

Should this hook into sessions then? If a session already has an account
ID, we load a profile manager instance into memory for it? Should there
be a default profile manager in memory ... can we ever have more than one?
Should we have a hook/event for session destruction that we can listen for?

What about an admin or masquerade use case? Will we be covered?

*/
