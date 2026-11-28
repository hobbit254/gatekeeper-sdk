<?php

declare(strict_types=1);

namespace Gatekeeper\Tests;

use Gatekeeper\ApprovalException;
use Gatekeeper\Principal;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/** ADR-0152: approval tokens and support-session modes, the same in every SDK. */
final class ContractApprovalsTest extends TestCase
{
    /** @return iterable<string, array{array<string, mixed>}> */
    public static function approvals(): iterable
    {
        foreach ((new Fixtures())->v['approvals']['cases'] as $c) {
            yield $c['name'] => [$c];
        }
    }

    /** @param array<string, mixed> $c */
    #[DataProvider('approvals')]
    public function testApproval(array $c): void
    {
        $f = new Fixtures();
        $who = $f->v['approvals']['principal'];
        $p = new Principal($who['sub'], 't', null, $who['client_id'], [], [], [], ['pin', 'hwk'], 0, 0);
        try {
            $a = $f->sdk()->verifyApproval($c['token'], $p);
            $got = 'ok';
        } catch (ApprovalException $e) {
            $got = $e->reason;
        }
        self::assertSame($c['expect'], $got);
        if ($got === 'ok') {
            $w = $c['approval'];
            self::assertSame([$w['id'], $w['approver'], $w['requester'], $w['permission'], $w['resource'], $w['method'], $w['amount'] ?? null, $w['currency'] ?? null],
                [$a->id, $a->approver, $a->requester, $a->permission, $a->resource, $a->method, $a->amount, $a->currency]);
        }
    }

    /** @return iterable<string, array{array<string, mixed>}> */
    public static function supportModes(): iterable
    {
        foreach ((new Fixtures())->v['support_modes']['cases'] as $c) {
            yield $c['name'] => [$c];
        }
    }

    /** @param array<string, mixed> $c */
    #[DataProvider('supportModes')]
    public function testSupportMode(array $c): void
    {
        $base = new Fixtures();
        $f = $c['map'] === 'support' ? new Fixtures([$base->v['support_modes']['role_map']]) : $base;
        $p = $f->sdk()->verify($c['token']);
        self::assertSame($c['actor_mode'] === '' ? null : $c['actor_mode'], $p->actorMode);
        $got = $p->permissions;
        $want = $c['permissions'];
        sort($got);
        sort($want);
        self::assertSame($want, $got);
    }
}
