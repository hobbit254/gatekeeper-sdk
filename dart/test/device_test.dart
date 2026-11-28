import 'dart:convert';

import 'package:crypto/crypto.dart';
import 'package:gatekeeper_sdk/gatekeeper_sdk.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:test/test.dart';

import 'dpop_test.dart' show TestSigner, part;

// FR-A45, FR-A46, FR-Z21 (ADR-0154): every shared-device request is signed
// over its URL and body, as the server and the TypeScript signer expect.
void main() {
  const issuer = 'https://auth.example.test/t/acme';
  final now = DateTime.utc(2026, 11, 28, 9);
  String b64(List<int> b) => base64Url.encode(b).replaceAll('=', '');

  test('claims, signs staff in, renews, signs out and approves', () async {
    final signer = TestSigner();
    final seen = <http.Request>[];
    final client = MockClient((r) async {
      seen.add(r);
      final path = r.url.path.replaceFirst('/t/acme/v1/devices/', '');
      switch (path) {
        case 'claim':
          expect((jsonDecode(r.body) as Map)['public_jwk'], signer.publicJwk);
          return http.Response(jsonEncode({'device_id': 'd-1', 'name': 'Till 1', 'client_id': 'pos'}), 200);
        case 'pin-sign-in':
        case 'pin-sessions/renew':
          return http.Response(jsonEncode({'access_token': 'at', 'token_type': 'Bearer', 'expires_in': 900, 'sid': 's-1',
              'session_expires_at': '2026-11-28T17:00:00Z'}), 200);
        case 'pin-sign-out':
          return http.Response('', 204);
        default:
          expect(path, 'approvals/a-1/approve');
          return http.Response(jsonEncode({'approval_id': 'a-1', 'status': 'granted', 'approver_id': 'm-1', 'method': 'pin',
              'permission': 'sale:refund', 'amount': 300000, 'approval_token': 'tok'}), 200);
      }
    });
    final d = SharedDevice(issuer: '$issuer/', signer: signer, httpClient: client, clock: () => now);
    await expectLater(d.pinSignIn('u-1', '4829'), throwsA(isA<DeviceException>().having((e) => e.code, 'code', 'not-claimed')));
    expect((await d.claim('K7QM-2XRP'))['device_id'], 'd-1');
    expect(d.deviceId, 'd-1');
    final s = await d.pinSignIn('u-1', '4829');
    expect([s.accessToken, s.sid, s.expiresIn], ['at', 's-1', 900]);
    expect((await d.renewPinSession('s-1')).sid, 's-1');
    await d.pinSignOut('s-1');
    final a = await d.approveWithPin('a-1', 'm-1', '5830');
    expect([a.approvalToken, a.amount, a.status], ['tok', 300000, 'granted']);

    for (final r in seen) {
      final jws = r.headers['Authorization']!.replaceFirst('Device ', '');
      expect(signer.verify(jws), isTrue);
      final h = part(jws, 0), c = part(jws, 1);
      expect(h['alg'], 'ES256');
      expect(h['kid'], r.url.path.endsWith('/claim') ? isNull : 'd-1', reason: 'no kid on the claim, the device id after');
      expect(c['aud'], r.url.toString());
      expect(c['iat'], now.millisecondsSinceEpoch ~/ 1000);
      expect(c['bh'], b64(sha256.convert(r.bodyBytes).bytes), reason: 'the body is covered');
    }
    expect(seen.map((r) => part(r.headers['Authorization']!.replaceFirst('Device ', ''), 1)['jti']).toSet(), hasLength(seen.length));
    expect(jsonDecode(seen.last.body), {'approver_id': 'm-1', 'pin': '5830'});
  });

  test('refusals carry the status, code and retry-after', () async {
    final client = MockClient((r) async => http.Response(jsonEncode({'type': '/errors/pin-locked', 'title': 'PIN locked'}), 423,
        headers: {'retry-after': '120'}));
    final d = SharedDevice(issuer: issuer, signer: TestSigner(), deviceId: 'd-1', httpClient: client);
    await expectLater(
        d.pinSignIn('u-1', '0000'),
        throwsA(isA<DeviceException>()
            .having((e) => e.status, 'status', 423)
            .having((e) => e.code, 'code', 'pin-locked')
            .having((e) => e.retryAfter, 'retryAfter', const Duration(seconds: 120))));
  });

  test('bodyHash is the base64url SHA-256', () {
    expect(bodyHash(utf8.encode('{"pin":"4829"}')), b64(sha256.convert(utf8.encode('{"pin":"4829"}')).bytes));
  });
}
