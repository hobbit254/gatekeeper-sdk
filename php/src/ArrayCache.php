<?php

declare(strict_types=1);

namespace Gatekeeper;

use Psr\SimpleCache\CacheInterface;

/** A per-process PSR-16 cache, used when no cache store is given. */
final class ArrayCache implements CacheInterface
{
    /** @var array<string, array{mixed, ?int}> */
    private array $items = [];

    public function get(string $key, mixed $default = null): mixed
    {
        [$value, $expires] = $this->items[$key] ?? [$default, null];
        if ($expires !== null && $expires < time()) {
            unset($this->items[$key]);
            return $default;
        }
        return $value;
    }

    public function set(string $key, mixed $value, \DateInterval|int|null $ttl = null): bool
    {
        $seconds = $ttl instanceof \DateInterval ? (new \DateTimeImmutable())->add($ttl)->getTimestamp() - time() : $ttl;
        $this->items[$key] = [$value, $seconds === null ? null : time() + $seconds];
        return true;
    }

    public function delete(string $key): bool
    {
        unset($this->items[$key]);
        return true;
    }

    public function clear(): bool
    {
        $this->items = [];
        return true;
    }

    public function getMultiple(iterable $keys, mixed $default = null): iterable
    {
        $out = [];
        foreach ($keys as $k) {
            $out[$k] = $this->get($k, $default);
        }
        return $out;
    }

    /** @param iterable<string, mixed> $values */
    public function setMultiple(iterable $values, \DateInterval|int|null $ttl = null): bool
    {
        foreach ($values as $k => $v) {
            $this->set($k, $v, $ttl);
        }
        return true;
    }

    public function deleteMultiple(iterable $keys): bool
    {
        foreach ($keys as $k) {
            $this->delete($k);
        }
        return true;
    }

    public function has(string $key): bool
    {
        return $this->get($key, $this) !== $this;
    }
}
