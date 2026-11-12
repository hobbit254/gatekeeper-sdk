import 'dart:convert';

import 'package:gatekeeper_sdk/gatekeeper_sdk.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:test/test.dart';

import 'dpop_test.dart' show TestSigner, part;

// FR-A27 (ADR-0111): every device request is signed by the approver key.
void main() {
  const issuer = 'https://auth.example.test/t/acme';
  final now = DateTime.utc(2026, 11, 13, 9);

  test('enrols, lists and answers with signed requests', () async {
    final signer = TestSigner();
    final seen = <String>[];
    final client = MockClient((r) async {
      if (r.url.path.endsWith('/v1/me/push-approvers')) {
        expect(r.headers['Authorization'], 'Bearer tok');
        expect((jsonDecode(r.body) as Map)['public_key'], signer.publicJwk);
        return http.Response(jsonEncode({'id': 'a-1', 'name': 'Pixel', 'recovery_codes': ['x']}), 201);
      }
      if (r.url.path.endsWith('/v1/push/pending')) {
        seen.add(r.headers['Authorization']!.replaceFirst('Push ', ''));
        return http.Response(jsonEncode({'challenges': [{'id': 'c-1', 'client_id': 'web', 'device': 'Firefox on macOS', 'numbers': [12, 47, 83], 'created_at': '', 'expires_at': '2026-11-13T09:02:00Z'}]}), 200);
      }
      final answer = (jsonDecode(r.body) as Map)['answer'] as String;
      seen.add(answer);
      return http.Response(jsonEncode({'status': part(answer, 1)['number'] == 47 ? 'approved' : 'denied'}), 200);
    });
    final p = PushApprover(issuer: '$issuer/', signer: signer, httpClient: client, clock: () => now);
    await expectLater(p.pending(), throwsA(isA<PushException>()));
    expect(await p.enrol('tok', 'Pixel'), ['x']);
    expect(p.approverId, 'a-1');
    final c = (await p.pending()).single;
    expect(c.numbers, [12, 47, 83]);
    expect(await p.approve(c.id, 47), 'approved');
    expect(await p.deny(c.id, reported: true), 'denied');

    for (final jws in seen) {
      expect(signer.verify(jws), isTrue);
      expect(part(jws, 0), {'alg': 'ES256', 'kid': 'a-1'});
      expect(part(jws, 1)['aud'], '$issuer/v1/push');
      expect(part(jws, 1)['iat'], now.millisecondsSinceEpoch ~/ 1000);
    }
    expect(seen.map((j) => part(j, 1)['jti']).toSet(), hasLength(3));
    expect(part(seen[1], 1), containsPair('challenge_id', 'c-1'));
    expect(part(seen[2], 1), allOf(containsPair('decision', 'deny'), containsPair('reported', true)));
  });

  test('a refusal is a PushException with the status', () async {
    final client = MockClient((r) async => http.Response(jsonEncode({'title': 'Signature not accepted'}), 401));
    final p = PushApprover(issuer: issuer, signer: TestSigner(), approverId: 'a-1', httpClient: client);
    await expectLater(p.pending(), throwsA(isA<PushException>().having((e) => e.status, 'status', 401)));
  });
}
