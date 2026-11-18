# @hobbit254/gatekeeper-sdk

Gatekeeper for TypeScript: verify access tokens and guard routes on Node, sign in from the browser by redirect or headless, and a typed admin client.

```sh
npm install @hobbit254/gatekeeper-sdk
```

```ts
import { createGatekeeper } from "@hobbit254/gatekeeper-sdk";          // servers
import { createBrowserClient } from "@hobbit254/gatekeeper-sdk/browser"; // redirect sign-in
import { startHeadless } from "@hobbit254/gatekeeper-sdk/headless";     // headless sign-in
import { createAdminClient } from "@hobbit254/gatekeeper-sdk/admin";    // admin API
```

See [the examples](https://github.com/hobbit254/gatekeeper-sdk/tree/main/examples) and your dashboard's **Connect** panel. Licence: Apache-2.0.
