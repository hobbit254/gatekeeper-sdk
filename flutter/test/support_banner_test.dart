import 'dart:convert';

import 'package:flutter/widgets.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:gatekeeper_flutter/gatekeeper_flutter.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';

// The support-session banner (FR-M5, ADR-0159).

const issuer = 'https://auth.test/t/acme';
final ends = DateTime.utc(2026, 11, 28, 10, 48);
final start = DateTime.utc(2026, 11, 28, 10);

String jwt(Map<String, dynamic> claims) {
  String part(Object o) => base64Url.encode(utf8.encode(jsonEncode(o))).replaceAll('=', '');
  return '${part({'alg': 'ES256', 'typ': 'at+jwt'})}.${part(claims)}.c2ln';
}

Map<String, dynamic> act({String? mode}) =>
    {'sub': 'admin-1', 'ends_at': ends.millisecondsSinceEpoch ~/ 1000, if (mode != null) 'mode': mode};

/// Signs in with an access token carrying [claims].
Future<GatekeeperAuth> signedIn(WidgetTester tester, Map<String, dynamic> claims) async {
  final client = MockClient((req) async => http.Response(
      jsonEncode({'access_token': jwt({'sub': 'u1', ...claims}), 'id_token': jwt({'sub': 'u1'}), 'expires_in': 300}), 200,
      headers: {'content-type': 'application/json'}));
  final auth = GatekeeperAuth(
    Gatekeeper(GatekeeperConfig(issuer: issuer, clientId: 'app', redirectUri: Uri.parse('com.example.app:/cb')),
        store: SecureTokenStore(issuer: issuer, clientId: 'app'), httpClient: client),
    browser: ({required url, required callbackUrlScheme}) async =>
        'com.example.app:/cb?code=c1&state=${Uri.parse(url).queryParameters['state']}',
  );
  await tester.runAsync(() => auth.signIn());
  return auth;
}

Widget app(GatekeeperAuth auth, Widget child) =>
    Directionality(textDirection: TextDirection.ltr, child: GatekeeperScope(auth: auth, child: child));

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  setUp(() => FlutterSecureStorage.setMockInitialValues({}));

  group('SupportSession.fromClaims', () {
    test('is null without act, or without its actor', () {
      expect(SupportSession.fromClaims({'sub': 'u1'}), isNull);
      expect(SupportSession.fromClaims({'act': {'ends_at': 1}}), isNull);
    });
    test('reads the actor, the mode and the end; no mode is read', () {
      final w = SupportSession.fromClaims({'act': act(mode: 'write')})!;
      expect([w.actor, w.mode, w.readOnly, w.endsAt], ['admin-1', 'write', false, ends]);
      final r = SupportSession.fromClaims({'act': act()})!;
      expect([r.mode, r.readOnly], ['read', true]);
    });
  });

  testWidgets('shows who, how and until when above the app, and Stop calls it', (tester) async {
    final auth = await signedIn(tester, {'act': act()});
    expect((auth.state.status as SignedIn).support?.actor, 'admin-1');
    var stopped = 0;
    await tester.pumpWidget(app(auth, SupportBanner(name: 'Wanjiru', now: () => start, onStop: () => stopped++, child: const Text('the app'))));
    expect(find.text('Support session · Viewing as Wanjiru · Read-only · Ends in 48 min'), findsOneWidget);
    expect(find.text('the app'), findsOneWidget);
    await tester.tap(find.text('Stop'));
    expect(stopped, 1);
  });

  testWidgets('says when the session can change things', (tester) async {
    final auth = await signedIn(tester, {'act': act(mode: 'write')});
    await tester.pumpWidget(app(auth, SupportBanner(now: () => start, child: const Text('the app'))));
    expect(find.text('Support session · Can change things · Ends in 48 min'), findsOneWidget);
  });

  testWidgets('an ordinary session shows only the app', (tester) async {
    final auth = await signedIn(tester, {});
    await tester.pumpWidget(app(auth, SupportBanner(now: () => start, child: const Text('the app'))));
    expect(find.textContaining('Support session'), findsNothing);
    expect(find.text('Stop'), findsNothing);
    expect(find.text('the app'), findsOneWidget);
  });

  testWidgets('counts down, then says it ended, once', (tester) async {
    final auth = await signedIn(tester, {'act': act()});
    var clock = start;
    var ended = 0;
    Widget banner() => app(auth, SupportBanner(now: () => clock, onEnded: () => ended++, child: const Text('the app')));
    await tester.pumpWidget(banner());
    clock = clock.add(const Duration(minutes: 47, seconds: 40));
    await tester.pump(const Duration(seconds: 30));
    expect(find.text('Support session · Read-only · Ends in 1 min'), findsOneWidget);
    clock = clock.add(const Duration(minutes: 1));
    await tester.pump(const Duration(seconds: 30));
    expect(find.text('Support session ended'), findsOneWidget);
    expect(find.text('Stop'), findsNothing);
    await tester.pump(const Duration(seconds: 30));
    await tester.pumpWidget(banner()); // rebuilt from above: still once
    await tester.pump();
    expect(ended, 1);
  });

  testWidgets('takes other words', (tester) async {
    final auth = await signedIn(tester, {'act': act()});
    await tester.pumpWidget(app(
        auth,
        SupportBanner(
          name: 'Wanjiru',
          now: () => start,
          labels: const SupportBannerLabels(
              title: 'Kipindi cha msaada', viewingAs: 'Unaona kama {name}', readOnly: 'Kusoma tu', endsIn: 'Kinaisha baada ya dakika {minutes}', stop: 'Simamisha'),
          child: const Text('the app'),
        )));
    expect(find.text('Kipindi cha msaada · Unaona kama Wanjiru · Kusoma tu · Kinaisha baada ya dakika 48'), findsOneWidget);
    expect(find.text('Simamisha'), findsOneWidget);
  });
}
