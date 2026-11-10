import 'dart:convert';
import 'dart:io';

import 'package:crypto/crypto.dart';
import 'package:gatekeeper_sdk/gatekeeper_sdk.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:test/test.dart';

const issuer = 'https://auth.example.test/t/acme';

String jwt(Map<String, dynamic> claims) =>
    'e30.${base64Url.encode(utf8.encode(jsonEncode(claims))).replaceAll('=', '')}.sig';

void main() {
  final config = GatekeeperConfig(issuer: '$issuer/', clientId: 'app', redirectUri: Uri.parse('com.acme.app:/cb'));

  test('authorize URL carries PKCE S256, state, nonce and step-up options', () {
    final req = Gatekeeper(config).authorizationRequest(acrValues: ['mfa'], maxAge: 0, uiLocales: 'sw');
    final q = req.url.queryParameters;
    expect(req.url.toString(), startsWith('$issuer/oauth2/authorize?'));
    expect(q['code_challenge_method'], 'S256');
    expect(q['code_challenge'], base64Url.encode(sha256.convert(ascii.encode(req.codeVerifier)).bytes).replaceAll('=', ''));
    expect(q['state'], req.state);
    expect(q['nonce']!.length, greaterThanOrEqualTo(8));
    expect(q['acr_values'], 'mfa');
    expect(q['max_age'], '0');
    expect(q['ui_locales'], 'sw');
    expect(req.codeVerifier.length, greaterThanOrEqualTo(43));
  });

  test('handleRedirect checks state and exchanges the code', () async {
    late Map<String, String> sent;
    final gk = Gatekeeper(config, httpClient: MockClient((r) async {
      sent = r.bodyFields;
      return http.Response(jsonEncode({'access_token': jwt({'sub': 'u1'}), 'refresh_token': 'rt1', 'expires_in': 600}), 200);
    }));
    final req = gk.authorizationRequest();
    await expectLater(gk.handleRedirect(Uri.parse('com.acme.app:/cb?code=c&state=forged'), req), throwsA(isA<GatekeeperException>()));
    await expectLater(gk.handleRedirect(Uri.parse('com.acme.app:/cb?error=access_denied&state=${req.state}'), req),
        throwsA(isA<GatekeeperException>()));
    final t = await gk.handleRedirect(Uri.parse('com.acme.app:/cb?code=c1&state=${req.state}'), req);
    expect(sent['grant_type'], 'authorization_code');
    expect(sent['code_verifier'], req.codeVerifier);
    expect(sent['redirect_uri'], 'com.acme.app:/cb');
    expect(t.claims['sub'], 'u1');
    expect(t.refreshToken, 'rt1');
  });

  test('refresh is single-flight and keeps rotating', () async {
    var now = DateTime.utc(2030);
    var refreshes = 0;
    final store = MemoryTokenStore();
    await store.write(Tokens(accessToken: jwt({'n': 0}), refreshToken: 'rt0', expiresAt: now.add(const Duration(seconds: 10))));
    final gk = Gatekeeper(config, store: store, clock: () => now, httpClient: MockClient((r) async {
      refreshes++;
      expect(r.bodyFields['refresh_token'], 'rt${refreshes - 1}');
      await Future<void>.delayed(const Duration(milliseconds: 20));
      return http.Response(jsonEncode({'access_token': jwt({'n': refreshes}), 'refresh_token': 'rt$refreshes', 'expires_in': 600}), 200);
    }));
    final tokens = await Future.wait([gk.accessToken(), gk.accessToken(), gk.accessToken()]);
    expect(refreshes, 1, reason: 'three callers, one rotation');
    expect(tokens.toSet().length, 1);
    now = now.add(const Duration(minutes: 11));
    await gk.accessToken();
    expect(refreshes, 2);
    expect((await store.read())!.refreshToken, 'rt2');
  });

  test('a refused refresh signs the user out locally', () async {
    final store = MemoryTokenStore();
    await store.write(Tokens(accessToken: jwt({}), refreshToken: 'dead', expiresAt: DateTime.utc(2000)));
    final gk = Gatekeeper(config, store: store, httpClient: MockClient((_) async =>
        http.Response(jsonEncode({'error': 'invalid_grant'}), 400)));
    await expectLater(gk.accessToken(), throwsA(isA<GatekeeperException>()));
    expect(await store.read(), isNull);
  });

  test('authorizedClient adds the bearer, refreshes on invalid_token and surfaces step-up', () async {
    final store = MemoryTokenStore();
    await store.write(Tokens(accessToken: 'old', refreshToken: 'rt', expiresAt: DateTime.utc(2100)));
    final seen = <String>[];
    final gk = Gatekeeper(config, store: store, httpClient: MockClient((r) async {
      if (r.url.path.endsWith('/oauth2/token')) {
        return http.Response(jsonEncode({'access_token': 'new', 'expires_in': 600}), 200);
      }
      seen.add(r.headers['Authorization']!);
      if (r.url.path == '/payouts') {
        return http.Response('', 401, headers: {'www-authenticate': 'Bearer error="insufficient_user_authentication", max_age="600"'});
      }
      if (r.headers['Authorization'] == 'Bearer old') {
        return http.Response('', 401, headers: {'www-authenticate': 'Bearer error="invalid_token"'});
      }
      return http.Response('ok', 200);
    }));
    final api = gk.authorizedClient();
    final res = await api.get(Uri.parse('https://api.example.test/reports'));
    expect(res.statusCode, 200);
    expect(seen, ['Bearer old', 'Bearer new']);
    await expectLater(api.post(Uri.parse('https://api.example.test/payouts')),
        throwsA(isA<StepUpRequired>().having((e) => e.maxAge, 'maxAge', 600)));
  });

  test('logout URL carries the id token hint', () async {
    final store = MemoryTokenStore();
    await store.write(Tokens(accessToken: 'a', idToken: 'idt', expiresAt: DateTime.utc(2100)));
    final url = await Gatekeeper(config, store: store).logoutUrl(postLogoutRedirect: Uri.parse('com.acme.app:/bye'));
    expect(url.queryParameters['id_token_hint'], 'idt');
    expect(url.path, '/t/acme/oauth2/logout');
  });

  test('contract vectors: claims decode the same as in the other SDKs', () {
    final v = jsonDecode(File('../contract/vectors.json').readAsStringSync()) as Map<String, dynamic>;
    final viewer = (v['cases'] as List).firstWhere((c) => c['name'] == 'viewer may read')['token'] as String;
    final c = decodeClaims(viewer);
    expect(c['sub'], '0192f3a1-7c2e-7d3a-9b1f-3a4c5d6e7f80');
    expect(c['roles'], ['viewer']);
    expect(c['sid'], 'session-1');
    final mfa = (v['step_up'] as List).firstWhere((c) => c['fresh'] == true)['token'] as String;
    expect(decodeClaims(mfa)['amr'], contains('mfa'));
  });
}
