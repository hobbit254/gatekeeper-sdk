<?php

declare(strict_types=1);

namespace Gatekeeper;

/**
 * A second person's approval refused (ADR-0145): code "closed" (already spent,
 * or expired) or "mismatch" (another action, client or requester, or not signed
 * by Gatekeeper).
 */
final class ApprovalException extends \RuntimeException
{
    public function __construct(public readonly string $reason, string $message, ?\Throwable $previous = null)
    {
        parent::__construct($message, 0, $previous);
    }
}
