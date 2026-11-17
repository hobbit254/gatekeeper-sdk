import 'dart:convert';

import 'package:flutter/services.dart';
import 'package:flutter/widgets.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:gatekeeper_flutter/gatekeeper_flutter.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';

// FR-A44 (ADR-0125).

const issuer = 'https://auth.test/t/acme';

String jwt(Map<String, dynamic> claims) {
  String part(Object o) => base64Url.encode(utf8.encode(jsonEncode(o))).replaceAll('=', '');
  return '${part({'alg': 'ES256', 'typ': 'at+jwt'})}.${part(claims)}.c2ln';
}

/// A token endpoint that answers every code exchange.
MockClient tokenEndpoint({List<Map<String, String>>? seen}) => MockClient((req) async {
      expect(req.url.toString(), '$issuer/oauth2/token');
      seen?.add(req.bodyFields);
      return http.Response(
          jsonEncode({
            'access_token': jwt({'sub': 'u1', 'amr': ['pwd', 'otp']}),
            'refresh_token': 'rt',
            'id_token': jwt({'sub': 'u1'}),
            'expires_in': 300,
          }),
          200,
          headers: {'content-type': 'application/json'});
    });

/// A fake system browser: records the URLs it opened and answers with [answer].
class FakeBrowser {
  FakeBrowser(this.answer);
  final String Function(Uri opened) answer;
  final opened = <Uri>[];

  Future<String> call({required String url, required String callbackUrlScheme}) async {
    expect(callbackUrlScheme, 'com.example.app');
    final u = Uri.parse(url);
    opened.add(u);
    return answer(u);
  }
}

String redirectWithCode(Uri authorize) => 'com.example.app:/cb?code=c1&state=${authorize.queryParameters['state']}';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  setUp(() => FlutterSecureStorage.setMockInitialValues({}));

  Gatekeeper gatekeeper({MockClient? client}) => Gatekeeper(
        GatekeeperConfig(issuer: issuer, clientId: 'app', redirectUri: Uri.parse('com.example.app:/cb')),
        store: SecureTokenStore(issuer: issuer, clientId: 'app'),
        httpClient: client ?? tokenEndpoint(),
      );

  group('SecureTokenStore', () {
    test('round-trips tokens, deletes on null, drops unreadable entries', () async {
      final store = SecureTokenStore(issuer: issuer, clientId: 'app');
      expect(await store.read(), isNull);
      await store.write(Tokens(accessToken: 'a', refreshToken: 'r', expiresAt: DateTime.utc(2030)));
      expect((await store.read())!.refreshToken, 'r');
      await store.write(null);
      expect(await store.read(), isNull);

      FlutterSecureStorage.setMockInitialValues({'gatekeeper.tokens.$issuer|app': 'not json'});
      expect(await store.read(), isNull);
      expect(await const FlutterSecureStorage().read(key: 'gatekeeper.tokens.$issuer|app'), isNull, reason: 'cleared');
    });
    test('keeps clients apart', () async {
      await SecureTokenStore(issuer: issuer, clientId: 'a').write(Tokens(accessToken: 'x', expiresAt: DateTime.utc(2030)));
      expect(await SecureTokenStore(issuer: issuer, clientId: 'b').read(), isNull);
    });
  });

  group('GatekeeperAuth', () {
    test('signs in through the browser with PKCE and stores the tokens', () async {
      final seen = <Map<String, String>>[];
      final browser = FakeBrowser(redirectWithCode);
      final auth = GatekeeperAuth(gatekeeper(client: tokenEndpoint(seen: seen)), browser: browser.call);
      var notified = 0;
      auth.state.addListener(() => notified++);

      expect(await auth.signIn(), isTrue);
      final q = browser.opened.single.queryParameters;
      expect(browser.opened.single.path, '/t/acme/oauth2/authorize');
      expect(q['code_challenge_method'], 'S256');
      expect(seen.single['code_verifier'], isNotEmpty);
      final s = auth.state.status as SignedIn;
      expect(s.subject, 'u1');
      expect(s.amr, ['pwd', 'otp']);
      expect(notified, 1);

      final restored = GatekeeperAuth(gatekeeper(), browser: browser.call);
      await restored.restore();
      expect(restored.state.status, isA<SignedIn>(), reason: 'the tokens survived in secure storage');
    });

    test('a closed browser leaves the state unchanged', () async {
      final auth = GatekeeperAuth(gatekeeper(),
          browser: ({required url, required callbackUrlScheme}) async => throw PlatformException(code: 'CANCELED'));
      expect(await auth.signIn(), isFalse);
      expect(auth.state.status, isA<SignedOut>());
    });

    test('a redirect with the wrong state is refused', () async {
      final auth = GatekeeperAuth(gatekeeper(), browser: FakeBrowser((_) => 'com.example.app:/cb?code=c1&state=forged').call);
      await expectLater(auth.signIn(), throwsA(isA<GatekeeperException>()));
      expect(auth.state.status, isA<SignedOut>());
      expect(await auth.gatekeeper.store.read(), isNull);
    });

    test('a step-up challenge sets StepUpNeeded; stepUp asks for mfa within maxAge', () async {
      final browser = FakeBrowser(redirectWithCode);
      final auth = GatekeeperAuth(gatekeeper(), browser: browser.call);
      await auth.signIn();
      await expectLater(auth.guard<void>(() async => throw StepUpRequired(300)), throwsA(isA<StepUpRequired>()));
      expect((auth.state.status as StepUpNeeded).maxAge, 300);

      expect(await auth.stepUp(300), isTrue);
      expect(browser.opened.last.queryParameters['acr_values'], 'mfa');
      expect(browser.opened.last.queryParameters['max_age'], '300');
      expect(auth.state.status, isA<SignedIn>());
    });

    test('sign-out clears the tokens and opens the logout page with the hint', () async {
      final browser = FakeBrowser((u) => u.path.endsWith('/logout') ? 'com.example.app:/bye' : redirectWithCode(u));
      final auth = GatekeeperAuth(gatekeeper(), browser: browser.call);
      await auth.signIn();
      await auth.signOut(postLogoutRedirect: Uri.parse('com.example.app:/bye'));
      final logout = browser.opened.last;
      expect(logout.path, '/t/acme/oauth2/logout');
      expect(logout.queryParameters['id_token_hint'], isNotEmpty);
      expect(logout.queryParameters['post_logout_redirect_uri'], 'com.example.app:/bye');
      expect(auth.state.status, isA<SignedOut>());
      expect(await auth.gatekeeper.store.read(), isNull);
    });
  });

  testWidgets('GatekeeperScope rebuilds widgets when the state changes', (tester) async {
    final auth = GatekeeperAuth(gatekeeper(), browser: FakeBrowser(redirectWithCode).call);
    await tester.pumpWidget(GatekeeperScope(
      auth: auth,
      child: Builder(builder: (context) {
        final status = GatekeeperScope.of(context).state.status;
        return Text(status is SignedIn ? 'hello ${status.subject}' : 'signed out', textDirection: TextDirection.ltr);
      }),
    ));
    expect(find.text('signed out'), findsOneWidget);
    await tester.runAsync(() => auth.signIn());
    await tester.pump();
    expect(find.text('hello u1'), findsOneWidget);
  });
}
