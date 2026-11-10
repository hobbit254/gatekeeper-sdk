<?php

declare(strict_types=1);

namespace Gatekeeper;

/** The authenticated subject of a request. */
final readonly class Principal
{
    /**
     * @param list<string> $roles
     * @param list<string> $permissions
     * @param list<string> $scopes
     * @param list<string> $amr
     */
    public function __construct(
        public string $sub,
        public string $tenantId,
        public ?string $orgId,
        public string $clientId,
        public array $roles,
        public array $permissions,
        public array $scopes,
        public array $amr,
        public int $authTime,
        public int $rv,
        public string $sid = '',
        public string $jti = '',
        /** The admin acting as $sub, and when that ends (unix); set only on impersonation tokens (ADR-0058). */
        public ?string $actor = null,
        public ?int $impersonationEndsAt = null,
        /** A principal from a gk_live_ API key (ADR-0057); ownerType is "user" or "service_account". */
        public bool $apiKey = false,
        public string $ownerType = '',
    ) {
    }

    /** Exact key match; wildcards are already expanded in the role map. */
    public function can(string $permission): bool
    {
        return in_array($permission, $this->permissions, true);
    }
}
