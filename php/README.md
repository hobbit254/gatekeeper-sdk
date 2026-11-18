# hobbit254/gatekeeper-laravel

Gatekeeper for PHP and Laravel: verify access tokens, resolve permissions, guard routes, and a typed admin client.

```sh
composer require hobbit254/gatekeeper-laravel
```

Set `GATEKEEPER_ISSUER`, `GATEKEEPER_AUDIENCE`, `GATEKEEPER_CLIENT_ID` and `GATEKEEPER_CLIENT_SECRET`, then use the `gatekeeper` and `gk.can:<permission>` middleware. Your dashboard's **Connect** panel shows the values.

This repository is a read-only copy of `php/` in [hobbit254/gatekeeper-sdk](https://github.com/hobbit254/gatekeeper-sdk); send issues and changes there. Licence: Apache-2.0.
