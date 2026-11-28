<?php

declare(strict_types=1);

namespace Gatekeeper;

/** Routes with no Gatekeeper guard, or unused permissions with $failOnUnused (ADR-0149). */
final class UnguardedRoutesException extends \RuntimeException
{
    /**
     * @param list<string> $unguarded
     * @param list<string> $unused
     */
    public function __construct(public readonly array $unguarded, public readonly array $unused, string $message)
    {
        parent::__construct($message);
    }
}
