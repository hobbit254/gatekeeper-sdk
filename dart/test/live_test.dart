// Runs against a real Gatekeeper started by tests/feature/sdk (ADR-0089);
// skipped unless GK_LIVE_ISSUER is set.
import 'dart:io';

import 'package:gatekeeper_sdk/gatekeeper_sdk.dart';
import 'package:test/test.dart';

void main() {
  final env = Platform.environment;
  final skip = env['GK_LIVE_ISSUER'] == null ? 'no live server (GK_LIVE_ISSUER)' : null;
  GatekeeperConfig config() => GatekeeperConfig(
      issuer: env['GK_LIVE_ISSUER']!, clientId: env['GK_LIVE_CLIENT']!, redirectUri: Uri.parse(env['GK_LIVE_REDIRECT']!), scopes: ['openid']);

  test('live: a password ends in tokens (FR-A22)', () async {
    final gk = Gatekeeper(config());
    final h = await gk.startHeadless();
    expect(h.methods, contains('password'));
    final r = await h.password(env['GK_LIVE_EMAIL']!, env['GK_LIVE_PASSWORD']!);
    expect(r, isA<Complete>());
    expect(await gk.accessToken(), (r as Complete).tokens.accessToken);
  }, skip: skip);

  test('live: a wrong password is a typed problem', () async {
    final h = await Gatekeeper(config()).startHeadless();
    await expectLater(h.password(env['GK_LIVE_EMAIL']!, 'wrong password'),
        throwsA(isA<HeadlessProblem>().having((p) => p.type, 'type', 'invalid-credentials')));
  }, skip: skip);
}
