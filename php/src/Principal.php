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
     * @param array<string, int> $stepUp
     * @param array{plan: string, features: list<string>}|null $entitlements
     * @param array<string, array{alone?: int, approves?: int}> $limits
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
        /** The DPoP key the token is bound to (cnf.jkt), or '' (ADR-0070). */
        public string $jkt = '',
        /** Per-permission step-up windows in seconds from the role map (ADR-0097). */
        public array $stepUp = [],
        /** The customer's plan and features, ['plan' => string, 'features' => list<string>], or null (ADR-0098). */
        public ?array $entitlements = null,
        /** The organization's role-map version; 0 outside an organization (ADR-0142). */
        public int $orv = 0,
        /** The most generous amount limit on each held permission that carries one, in minor units; a missing value is no limit (ADR-0143). */
        public array $limits = [],
        /** The currency those limits are counted in (ISO 4217): the organization's, else the tenant's. */
        public string $currency = '',
        /** The support session's mode, 'read' or 'write', or null without an actor; in read mode $permissions holds only read ones (ADR-0146). */
        public ?string $actorMode = null,
    ) {
    }

    public const ACTOR_READ = 'read';
    public const ACTOR_WRITE = 'write';

    public const AMOUNT_ALLOW = 'allow';
    public const AMOUNT_APPROVAL_REQUIRED = 'approval_required';
    public const AMOUNT_DENY = 'deny';

    /**
     * For doing $permission for $amount (minor units): 'allow' within the alone
     * limit, 'approval_required' above it, 'deny' when the permission isn't
     * held. Sees only the token's roles; /v1/authz/check with amount is the
     * authoritative answer (ADR-0143).
     */
    public function canAmount(string $permission, int $amount): string
    {
        if (!$this->can($permission)) {
            return self::AMOUNT_DENY;
        }
        $alone = $this->limits[$permission]['alone'] ?? null;
        return $alone !== null && $amount > $alone ? self::AMOUNT_APPROVAL_REQUIRED : self::AMOUNT_ALLOW;
    }

    /** Exact key match; wildcards are already expanded in the role map. */
    public function can(string $permission): bool
    {
        return in_array($permission, $this->permissions, true);
    }

    /** Whether the token's entitlements include $feature. */
    public function hasFeature(string $feature): bool
    {
        return in_array($feature, $this->entitlements['features'] ?? [], true);
    }

    /** API keys and tokens without amr (client credentials) are machines; step-up doesn't apply to them. */
    public function machine(): bool
    {
        return $this->apiKey || $this->amr === [];
    }
}
