<?php

declare(strict_types=1);

namespace Gatekeeper\Tests;

use Gatekeeper\ArrayCache;
use Gatekeeper\ClientCredentials;
use Gatekeeper\RevocationFeed;
use PHPUnit\Framework\TestCase;

/** The polled revocation feed (FR-S17, ADR-0123). */
final class RevocationFeedTest extends TestCase
{
    /** @param list<array{0: int, 1: string}> $snapshots one per poll */
    private function feed(array &$snapshots, ArrayCache $cache, int &$polls): RevocationFeed
    {
        $fetch = function (string $url, array $headers, ?string $body = null) use (&$snapshots, &$polls): array {
            if (str_ends_with($url, '/oauth2/token')) {
                return [200, json_encode(['access_token' => 't', 'expires_in' => 3600])];
            }
            self::assertSame('https://gk.test/t/a/v1/revocations', $url);
            self::assertSame('Bearer t', $headers['Authorization']);
            $polls++;
            return array_shift($snapshots) ?? [503, ''];
        };
        $cc = new ClientCredentials('https://gk.test/t/a/oauth2/token', 'c', 'x', 'revocations:read', '', $cache, $fetch);
        return new RevocationFeed('https://gk.test/t/a/', $cc, $cache, $fetch, 5, 10);
    }

    public function testFollowsTheSnapshotAndPollsOncePerInterval(): void
    {
        $later = gmdate('c', time() + 3600);
        $snaps = [[200, json_encode(['items' => [['kind' => 'sid', 'value' => 's1', 'until' => $later],
            ['kind' => 'jti', 'value' => 'old', 'until' => gmdate('c', time() - 5)]], 'cursor' => '1-0'])]];
        $polls = 0;
        $cache = new ArrayCache();
        $feed = $this->feed($snaps, $cache, $polls);
        self::assertTrue($feed->denied('s1', 'j'));
        self::assertFalse($feed->denied('s2', 'j'));
        self::assertFalse($feed->denied('', 'old'), 'lapsed');
        self::assertFalse($feed->denied('', ''), 'empty ids match nothing');
        self::assertSame(1, $polls, 'one poll per interval');
    }

    public function testRefusesWhenItCannotReachGatekeeper(): void
    {
        $snaps = [];
        $polls = 0;
        $this->expectException(\RuntimeException::class);
        $this->feed($snaps, new ArrayCache(), $polls)->denied('s', 'j');
    }

    public function testRefusesOnceTheCopyIsStale(): void
    {
        $snaps = [];
        $polls = 0;
        $cache = new ArrayCache();
        $feed = $this->feed($snaps, $cache, $polls);
        $cache->set('gatekeeper.revfeed.' . hash('sha256', 'https://gk.test/t/a'), ['at' => time() - 11, 'set' => []], 3600);
        $this->expectException(\RuntimeException::class);
        $feed->denied('s', 'j'); // the poll fails, and the copy is older than 10 s
    }
}
