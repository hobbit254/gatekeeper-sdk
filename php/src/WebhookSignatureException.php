<?php

declare(strict_types=1);

namespace Gatekeeper;

/** A webhook whose X-Gatekeeper-Signature doesn't verify. */
final class WebhookSignatureException extends \RuntimeException
{
}
