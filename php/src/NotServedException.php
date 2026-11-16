<?php

declare(strict_types=1);

namespace Gatekeeper;

/** The user has no live sign-in through this client, so Gatekeeper won't check for them (ADR-0119). */
final class NotServedException extends \RuntimeException
{
}
