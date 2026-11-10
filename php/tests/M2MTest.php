<?php

declare(strict_types=1);

namespace Gatekeeper\Tests;

use Gatekeeper\ArrayCache;
use Gatekeeper\ClientCredentials;
use Gatekeeper\InvalidTokenException;
use PHPUnit\Framework\TestCase;

final class M2MTest extends TestCase
{
    public function testImpersonationExposesTheActorAndEnd(): void
    {
        $f = new Fixtures();
        $p = $f->sdk()->verify($f->v['impersonation']['token']);
        self::assertSame($f->v['impersonation']['actor'], $p->actor);
        self::assertSame($f->v['impersonation']['ends_at'], $p->impersonationEndsAt);
        $plain = $f->sdk()->verify($f->v['impersonation']['plain']);
        self::assertNull($plain->actor);
        self::assertNull($plain->impersonationEndsAt);
    }

    public function testAPIKeyContractCases(): void
    {
        $f = new Fixtures();
        foreach ($f->v['api_keys']['cases'] as $c) {
            try {
                $p = $f->sdk()->verify($c['token']);
                self::assertTrue($p->apiKey, $c['name']);
                self::assertSame($f->v['api_keys']['subject'], $p->sub);
                self::assertSame([], $p->amr, 'an API key can never step up');
                $got = $p->can($c['permission']) ? 'allow' : 'deny';
            } catch (InvalidTokenException) {
                $got = 'reject';
            }
            self::assertSame($c['expect'], $got, $c['name']);
        }
    }

    public function testAPIKeysAreCached(): void
    {
        $f = new Fixtures();
        $cache = new ArrayCache();
        $key = $f->v['api_keys']['cases'][0]['token'];
        $f->sdk(cache: $cache)->verify($key);
        $f->sdk(cache: $cache)->verify($key);
        self::assertSame(1, $f->introspections);
    }

    public function testIntrospectionFailureRefuses(): void
    {
        $f = new Fixtures();
        $this->expectException(InvalidTokenException::class);
        $f->sdk(secret: 'wrong')->verify($f->v['api_keys']['cases'][0]['token']);
    }

    public function testClientCredentialsCachesTheToken(): void
    {
        $calls = 0;
        $fetch = function (string $url, array $headers, ?string $body = null) use (&$calls): array {
            $calls++;
            parse_str((string) $body, $form);
            if (($headers['Authorization'] ?? '') !== 'Basic ' . base64_encode('svc-job:s3cret') || ($form['grant_type'] ?? '') !== 'client_credentials') {
                return [401, '{}'];
            }
            return [200, '{"access_token":"tok-1","token_type":"bearer","expires_in":600}'];
        };
        $cc = new ClientCredentials('https://auth.test/t/acme/oauth2/token', 'svc-job', 's3cret', audience: 'api', fetch: $fetch);
        self::assertSame('tok-1', $cc->token());
        self::assertSame('tok-1', $cc->token());
        self::assertSame(1, $calls);

        $this->expectException(\RuntimeException::class);
        (new ClientCredentials('https://auth.test/t/acme/oauth2/token', 'svc-job', 'nope', fetch: $fetch))->token();
    }
}
