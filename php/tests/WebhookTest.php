<?php

declare(strict_types=1);

namespace Gatekeeper\Tests;

use Gatekeeper\Webhook;
use Gatekeeper\WebhookSignatureException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/** FR-A27 (ADR-0111): verify the webhook, then relay the pending push. */
final class WebhookTest extends TestCase
{
    private const NOW = 1_800_000_000;
    private const BODY = '{"id":"e1","type":"mfa.push_requested","subject":"u1","data":{"user_id":"u1","challenge_id":"c1","expires_at":"2027-01-15T08:02:00Z"}}';

    private static function sign(string $secret, int $at, string $body): string
    {
        return 't=' . $at . ',v1=' . hash_hmac('sha256', $at . '.' . $body, $secret);
    }

    public function testVerifiesAndReadsAPush(): void
    {
        $event = Webhook::verify('whsec_x', self::sign('whsec_x', self::NOW, self::BODY), self::BODY, self::NOW);
        self::assertSame(['user_id' => 'u1', 'challenge_id' => 'c1', 'expires_at' => '2027-01-15T08:02:00Z'], Webhook::pushRequested($event));
        self::assertNull(Webhook::pushRequested(['type' => 'user.created', 'data' => []]));
    }

    /** @return iterable<string, array{string, string, int}> */
    public static function bad(): iterable
    {
        yield 'wrong secret' => [self::sign('whsec_y', self::NOW, self::BODY), self::BODY, self::NOW];
        yield 'edited body' => [self::sign('whsec_x', self::NOW, self::BODY), self::BODY . ' ', self::NOW];
        yield 'too old' => [self::sign('whsec_x', self::NOW - 360, self::BODY), self::BODY, self::NOW];
        yield 'no signature' => ['t=' . self::NOW, self::BODY, self::NOW];
        yield 'empty' => ['', self::BODY, self::NOW];
    }

    #[DataProvider('bad')]
    public function testRefuses(string $header, string $body, int $now): void
    {
        $this->expectException(WebhookSignatureException::class);
        Webhook::verify('whsec_x', $header, $body, $now);
    }
}
