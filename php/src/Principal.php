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
    ) {
    }

    /** Exact key match; wildcards are already expanded in the role map. */
    public function can(string $permission): bool
    {
        return in_array($permission, $this->permissions, true);
    }
}
