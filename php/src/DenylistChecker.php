<?php

declare(strict_types=1);

namespace Gatekeeper;

/**
 * Optional revocation check (FR-S7, ADR-0048). Return true to refuse the
 * token; throwing refuses too (fail closed). With Laravel's Redis:
 * fn ($sid, $jti) => Redis::exists("gk:deny:sid:$sid", "gk:deny:jti:$jti") > 0
 */
interface DenylistChecker
{
    public function denied(string $sid, string $jti): bool;
}
