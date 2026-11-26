<?php

declare(strict_types=1);

namespace Gatekeeper\Tests;

use Gatekeeper\Config;
use Gatekeeper\Gatekeeper;

/** Serves sdk/contract/vectors.json the way the server would (ADR-0038). */
final class Fixtures
{
    public int $roleMapFetches = 0;
    public int $orgMapFetches = 0;
    public int $introspections = 0;

    /** @var array<string, mixed> */
    public array $v;

    /**
     * @param list<array<string, mixed>>|null $roleMaps successive role-map responses
     * @param array<string, list<array<string, mixed>>> $orgMaps successive ?org= responses by slug (ADR-0142)
     */
    public function __construct(private ?array $roleMaps = null, private array $orgMaps = [])
    {
        $this->v = json_decode((string) file_get_contents(__DIR__ . '/../../contract/vectors.json'), true, flags: JSON_THROW_ON_ERROR);
        $this->roleMaps ??= [$this->v['role_map']];
    }

    public function sdk(?\Gatekeeper\DenylistChecker $denylist = null, ?string $secret = null, ?\Psr\SimpleCache\CacheInterface $cache = null): Gatekeeper
    {
        $v = $this->v;
        return new Gatekeeper(new Config($v['issuer'], $v['audience'], $v['client_id'], $secret ?? $v['client_secret']), $cache,
            function (string $url, array $headers, ?string $body = null) use ($v): array {
                if ($url === $v['issuer'] . '/oauth2/introspect' && $body !== null) {
                    $this->introspections++;
                    if (($headers['Authorization'] ?? '') !== 'Basic ' . base64_encode($v['client_id'] . ':' . $v['client_secret'])) {
                        return [401, '{"error":"invalid_client"}'];
                    }
                    parse_str($body, $form);
                    return [200, json_encode($v['api_keys']['introspection'][$form['token'] ?? ''] ?? ['active' => false])];
                }
                $orgPrefix = $v['issuer'] . '/v1/clients/' . $v['client_id'] . '/role-map?org=';
                if (str_starts_with($url, $orgPrefix)) {
                    $org = rawurldecode(substr($url, strlen($orgPrefix)));
                    $maps = $this->orgMaps[$org] ?? (isset($v['org_roles']['role_maps'][$org]) ? [$v['org_roles']['role_maps'][$org]] : null);
                    if ($maps === null) {
                        return [404, '{}'];
                    }
                    $i = min($this->orgMapFetches++, count($maps) - 1);
                    return [200, json_encode($maps[$i])];
                }
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
            }, $denylist);
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
