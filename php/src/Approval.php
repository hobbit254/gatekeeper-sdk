<?php

declare(strict_types=1);

namespace Gatekeeper;

/** A second person's approval of one action (FR-Z21, ADR-0145). */
final class Approval
{
    public function __construct(
        public readonly string $id,
        public readonly string $approver,
        public readonly string $requester,
        public readonly string $clientId,
        public readonly string $permission,
        public readonly string $resource,
        /** Minor units; null for a permission without a limit. */
        public readonly ?int $amount,
        public readonly ?string $currency,
        public readonly ?string $orgId,
        public readonly string $method,
        public readonly ?int $expiresAt = null,
    ) {
    }
}
