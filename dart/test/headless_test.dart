import 'dart:convert';

import 'package:gatekeeper_sdk/gatekeeper_sdk.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:test/test.dart';

const issuer = 'https://auth.example.test/t/acme';

/// A scripted headless server; answers[path] is a function of the body.
MockClient server(Map<String, http.Response Function(Map<String, dynamic>)> answers, List<String> seen) {
  var state = '';
  return MockClient((r) async {
    if (r.url.path.endsWith('/oauth2/token')) {
      seen.add('token:${r.bodyFields['code']}:${r.bodyFields['code_verifier']!.length}');
      return http.Response(jsonEncode({'access_token': 'at', 'refresh_token': 'rt', 'expires_in': 600}), 200);
    }
    final path = r.url.path.replaceFirst('/t/acme/v1/auth/headless', '');
    final body = jsonDecode(r.body) as Map<String, dynamic>;
    seen.add(path);
    if (path == '/start') {
      state = body['state'] as String;
      return http.Response(jsonEncode({'flow_id': 'f1', 'methods': ['password'], 'provider_nonce': 'pn'}), 201);
    }
    final a = answers[path];
    if (a == null) return http.Response('{"type":"/errors/not-found"}', 404);
    final res = a(body);
    return res.statusCode == 299 ? http.Response(jsonEncode({'status': 'complete', 'code': 'c1', 'state': state}), 200) : res;
  });
}

http.Response complete(Map<String, dynamic> _) => http.Response('', 299);
http.Response json(int status, Map<String, dynamic> body, [Map<String, String> headers = const {}]) =>
    http.Response(jsonEncode(body), status, headers: headers);

void main() {
  final config = GatekeeperConfig(issuer: issuer, clientId: 'app', redirectUri: Uri.parse('com.acme.app:/cb'));

  test('a password ends in tokens saved in the store (FR-A22)', () async {
    final seen = <String>[];
    final gk = Gatekeeper(config, httpClient: server({'/password': complete}, seen));
    final h = await gk.startHeadless();
    expect(h.methods, ['password']);
    expect(h.providerNonce, 'pn');
    final r = await h.password('a@b.c', 'pw');
    expect(r, isA<Complete>());
    expect(seen.last, 'token:c1:43');
    expect((await gk.store.read())!.refreshToken, 'rt');
  });

  test('second factor and terms are typed steps', () async {
    final seen = <String>[];
    final gk = Gatekeeper(config, httpClient: server({
      '/password': (_) => json(200, {'status': 'mfa_required', 'factor': 'totp', 'passkey': true}),
      '/mfa/passkey/begin': (_) => json(200, {'options': {'publicKey': {'challenge': 'x'}}}),
      '/mfa': (b) => b['credential'] != null
          ? json(200, {'status': 'terms_required', 'documents': [{'kind': 'terms', 'version': 'v1', 'url': 'https://t'}]})
          : json(400, {}),
      '/terms': complete,
    }, seen));
    final h = await gk.startHeadless();
    final mfa = await h.password('a@b.c', 'pw') as MfaRequired;
    expect([mfa.factor, mfa.passkey], ['totp', true]);
    Map<String, dynamic>? asked;
    final terms = await h.mfaPasskey((o) async {
      asked = o;
      return {'id': 'cred'};
    }) as TermsRequired;
    expect(asked, {'publicKey': {'challenge': 'x'}});
    expect(terms.documents.single.version, 'v1');
    expect(await h.acceptTerms(), isA<Complete>());
  });

  test('link-required is a result; other problems throw HeadlessProblem', () async {
    final gk = Gatekeeper(config, httpClient: server({
      '/social': (_) => json(409, {'type': '/errors/link-required', 'provider': 'google'}),
      '/password': (_) => json(429, {'type': '/errors/locked'}, {'retry-after': '120'}),
    }, []));
    final h = await gk.startHeadless();
    expect((await h.social('google', 'idt') as LinkRequired).provider, 'google');
    await expectLater(h.password('a@b.c', 'pw'),
        throwsA(isA<HeadlessProblem>().having((p) => p.type, 'type', 'locked').having((p) => p.retryAfter, 'retryAfter', const Duration(seconds: 120))));
  });

  test("a code for another request's state is refused", () async {
    final seen = <String>[];
    final gk = Gatekeeper(config, httpClient: server({
      '/password': (_) => json(200, {'status': 'complete', 'code': 'c1', 'state': 'not-ours'}),
    }, seen));
    final h = await gk.startHeadless();
    await expectLater(h.password('a@b.c', 'pw'), throwsA(isA<GatekeeperException>()));
    expect(seen.any((s) => s.startsWith('token')), isFalse);
  });
}
