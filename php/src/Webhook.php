<?php

declare(strict_types=1);

namespace Gatekeeper;

/**
 * Verifies Gatekeeper webhooks (X-Gatekeeper-Signature: t=<unix>,v1=<hex>,
 * HMAC-SHA256 over "t.body") and reads pending pushes to relay to the user's
 * phone (FR-A27, ADR-0111).
 */
final class Webhook
{
    /** How old a signature may be, in seconds (INTEGRATION.md). */
    public const TOLERANCE = 300;

    /**
     * Returns the decoded CloudEvent, or throws when the signature doesn't
     * verify. Pass the raw request body, not a re-encoding.
     *
     * @return array<string, mixed>
     */
    public static function verify(string $secret, string $header, string $body, ?int $now = null): array
    {
        $ts = null;
        $sigs = [];
        foreach (explode(',', $header) as $part) {
            [$k, $v] = array_pad(explode('=', trim($part), 2), 2, '');
            if ($k === 't' && ctype_digit($v)) {
                $ts = $v;
            } elseif ($k === 'v1') {
                $sigs[] = $v;
            }
        }
        $now ??= time();
        if ($ts === null || $sigs === [] || abs($now - (int) $ts) > self::TOLERANCE) {
            throw new WebhookSignatureException('webhook signature missing or too old');
        }
        $want = hash_hmac('sha256', $ts . '.' . $body, $secret);
        $ok = false;
        foreach ($sigs as $s) {
            $ok = hash_equals($want, strtolower($s)) || $ok;
        }
        if (!$ok) {
            throw new WebhookSignatureException('webhook signature not valid');
        }
        $event = json_decode($body, true);
        if (!is_array($event)) {
            throw new WebhookSignatureException('webhook body is not an event');
        }
        return $event;
    }

    /**
     * An mfa.push_requested event's {user_id, challenge_id, expires_at}, or
     * null for other events.
     *
     * @param array<string, mixed> $event
     * @return array{user_id: string, challenge_id: string, expires_at: string}|null
     */
    public static function pushRequested(array $event): ?array
    {
        $d = $event['data'] ?? null;
        if (($event['type'] ?? '') !== 'mfa.push_requested' || !is_array($d)
            || !is_string($d['user_id'] ?? null) || !is_string($d['challenge_id'] ?? null)) {
            return null;
        }
        return ['user_id' => $d['user_id'], 'challenge_id' => $d['challenge_id'], 'expires_at' => (string) ($d['expires_at'] ?? '')];
    }
}
