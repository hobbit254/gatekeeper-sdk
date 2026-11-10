<?php

return [
    'issuer' => env('GATEKEEPER_ISSUER'),          // https://auth.<domain>/t/<tenant>
    'audience' => env('GATEKEEPER_AUDIENCE'),      // this API's identifier
    'client_id' => env('GATEKEEPER_CLIENT_ID'),
    'client_secret' => env('GATEKEEPER_CLIENT_SECRET'),
];
