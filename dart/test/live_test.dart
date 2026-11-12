// Runs against a real Gatekeeper started by tests/feature/sdk (ADR-0089);
// skipped unless GK_LIVE_ISSUER is set.
import 'dart:io';

import 'package:gatekeeper_sdk/gatekeeper_sdk.dart';
import 'package:test/test.dart';

import 'dpop_test.dart' show TestSigner;

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

  test('live: push approver enrols and signs requests the server accepts (FR-A27)', () async {
    final r = await (await Gatekeeper(config()).startHeadless()).password(env['GK_LIVE_PUSH_EMAIL_DART']!, env['GK_LIVE_PASSWORD']!);
    final p = PushApprover(issuer: env['GK_LIVE_ISSUER']!, signer: TestSigner());
    expect(await p.enrol((r as Complete).tokens.accessToken, 'Live phone'), hasLength(10));
    expect(await p.pending(), isEmpty);
    await expectLater(p.approve('00000000-0000-0000-0000-000000000000', 10),
        throwsA(isA<PushException>().having((e) => e.status, 'status', 404)));
  }, skip: skip);
}
