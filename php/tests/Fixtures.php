<?php

declare(strict_types=1);

namespace Gatekeeper\Tests;

use Gatekeeper\Config;
use Gatekeeper\Gatekeeper;

/** Serves sdk/contract/vectors.json the way the server would (ADR-0038). */
final class Fixtures
{
    public int $roleMapFetches = 0;

    /** @var array<string, mixed> */
    public array $v;

    /** @param list<array<string, mixed>>|null $roleMaps successive role-map responses */
    public function __construct(private ?array $roleMaps = null)
    {
        $this->v = json_decode((string) file_get_contents(__DIR__ . '/../../contract/vectors.json'), true, flags: JSON_THROW_ON_ERROR);
        $this->roleMaps ??= [$this->v['role_map']];
    }

    public function sdk(): Gatekeeper
    {
        $v = $this->v;
        return new Gatekeeper(new Config($v['issuer'], $v['audience'], $v['client_id'], $v['client_secret']), null,
            function (string $url, array $headers) use ($v): array {
                if ($url === $v['issuer'] . '/.well-known/jwks.json') {
                    return [200, json_encode($v['jwks'])];
                }
                if ($url === $v['issuer'] . '/v1/clients/' . $v['client_id'] . '/role-map') {
                    if (($headers['Authorization'] ?? '') !== 'Basic ' . base64_encode($v['client_id'] . ':' . $v['client_secret'])) {
                        return [401, '{}'];
                    }
                    $i = min($this->roleMapFetches++, count($this->roleMaps) - 1);
                    return [200, json_encode($this->roleMaps[$i])];
                }
                return [404, '{}'];
            });
    }

    public function token(string $case): string
    {
        foreach ($this->v['cases'] as $c) {
            if ($c['name'] === $case) {
                return $c['token'];
            }
        }
        throw new \LogicException($case);
    }
}
