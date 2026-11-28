import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:flutter_web_auth_2/flutter_web_auth_2.dart';
import 'package:gatekeeper_sdk/gatekeeper_sdk.dart';

/// Opens [url] in the system browser and returns the URL it was redirected
/// to under [callbackUrlScheme]. The default is flutter_web_auth_2; tests
/// pass a fake.
typedef BrowserLauncher = Future<String> Function({required String url, required String callbackUrlScheme});

Future<String> _flutterWebAuth({required String url, required String callbackUrlScheme}) =>
    FlutterWebAuth2.authenticate(url: url, callbackUrlScheme: callbackUrlScheme);

/// Where the user stands.
sealed class AuthStatus {
  const AuthStatus();
}

/// No tokens.
class SignedOut extends AuthStatus {
  const SignedOut();
}

/// Signed in; [claims] are the access token's, decoded for display only.
class SignedIn extends AuthStatus {
  const SignedIn(this.claims);
  final Map<String, dynamic> claims;
  String get subject => claims['sub'] as String? ?? '';
  List<String> get amr => [for (final m in claims['amr'] as List? ?? const []) m.toString()];

  /// The support session these tokens belong to, or null (ADR-0159).
  SupportSession? get support => SupportSession.fromClaims(claims);
}

/// A support session (impersonation), as the access token's act claim
/// describes it; for display only (FR-M5, ADR-0146, ADR-0159).
class SupportSession {
  const SupportSession({required this.actor, required this.mode, required this.endsAt});

  /// The admin acting as the user.
  final String actor;

  /// "read" unless writing was allowed.
  final String mode;
  final DateTime endsAt;
  bool get readOnly => mode != 'write';

  /// The session in [claims]' act, or null; no mode is read, as on the server.
  static SupportSession? fromClaims(Map<String, dynamic> claims) {
    final act = claims['act'];
    if (act is! Map) return null;
    final actor = act['sub'];
    if (actor is! String || actor.isEmpty) return null;
    final endsAt = act['ends_at'];
    return SupportSession(
      actor: actor,
      mode: act['mode'] == 'write' ? 'write' : 'read',
      endsAt: DateTime.fromMillisecondsSinceEpoch((endsAt is num ? endsAt.toInt() : 0) * 1000, isUtc: true),
    );
  }
}

/// An API asked for a recent second factor: call [GatekeeperAuth.stepUp].
class StepUpNeeded extends AuthStatus {
  const StepUpNeeded(this.maxAge);
  final int maxAge;
}

/// The auth state widgets listen to (through [GatekeeperScope]).
class AuthState extends ChangeNotifier {
  AuthStatus _status = const SignedOut();
  AuthStatus get status => _status;

  void _set(AuthStatus s) {
    _status = s;
    notifyListeners();
  }
}

/// Sign-in, step-up and sign-out through the system browser (RFC 8252), on
/// top of [Gatekeeper]; keeps [state] current.
class GatekeeperAuth {
  GatekeeperAuth(this.gatekeeper, {BrowserLauncher? browser}) : _browser = browser ?? _flutterWebAuth;

  final Gatekeeper gatekeeper;
  final AuthState state = AuthState();
  final BrowserLauncher _browser;

  /// Reads the stored tokens at start-up.
  Future<void> restore() async {
    final t = await gatekeeper.store.read();
    state._set(t == null ? const SignedOut() : SignedIn(t.claims));
  }

  /// Signs in; false when the user closed the browser.
  Future<bool> signIn({String? uiLocales}) => _run(gatekeeper.authorizationRequest(uiLocales: uiLocales));

  /// Signs in again with a second factor no older than [maxAge] seconds (RFC 9470).
  Future<bool> stepUp(int maxAge) => _run(gatekeeper.authorizationRequest(acrValues: ['mfa'], maxAge: maxAge));

  Future<bool> _run(AuthorizationRequest req) async {
    final String redirect;
    try {
      redirect = await _browser(url: req.url.toString(), callbackUrlScheme: gatekeeper.config.redirectUri.scheme);
    } on PlatformException catch (e) {
      if (e.code == 'CANCELED') return false;
      rethrow;
    }
    final tokens = await gatekeeper.handleRedirect(Uri.parse(redirect), req); // checks state; stores the tokens
    state._set(SignedIn(tokens.claims));
    return true;
  }

  /// Forgets the tokens. With [postLogoutRedirect] (registered on the client),
  /// also opens the logout page, which ends the session and its refresh token.
  Future<void> signOut({Uri? postLogoutRedirect}) async {
    final url = postLogoutRedirect == null ? null : await gatekeeper.logoutUrl(postLogoutRedirect: postLogoutRedirect);
    await gatekeeper.signOutLocally();
    state._set(const SignedOut());
    if (url == null) return;
    try {
      await _browser(url: url.toString(), callbackUrlScheme: postLogoutRedirect!.scheme);
    } on PlatformException catch (e) {
      if (e.code != 'CANCELED') rethrow; // signed out locally either way
    }
  }

  /// Runs [call] (an API request through gatekeeper.authorizedClient()); a
  /// step-up challenge sets [StepUpNeeded] before it is rethrown.
  Future<T> guard<T>(Future<T> Function() call) async {
    try {
      return await call();
    } on StepUpRequired catch (e) {
      state._set(StepUpNeeded(e.maxAge));
      rethrow;
    }
  }
}
