<?php

declare(strict_types=1);

namespace Gatekeeper;

/**
 * Configures one API. $issuer is https://auth.<domain>/t/<tenant>; $audience is
 * this API's identifier (enforced on every token); $clientId and $clientSecret
 * identify the client whose role map resolves permissions.
 */
final readonly class Config
{
    public string $issuer;

    public function __construct(
        string $issuer,
        public string $audience,
        public string $clientId,
        public string $clientSecret = '',
        /** Clock skew allowed on exp, seconds (default and maximum 60). */
        public int $leewaySec = 60,
        /** This API's external origin (https://api.example.com) for checking DPoP proofs behind a proxy (ADR-0070). */
        public string $publicUrl = '',
    ) {
        $this->issuer = rtrim($issuer, '/');
    }
}
