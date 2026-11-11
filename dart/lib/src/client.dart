import 'dart:async';
import 'dart:convert';
import 'dart:math';

import 'package:crypto/crypto.dart';
import 'package:http/http.dart' as http;

part 'headless.dart';

/// Configures one app: [issuer] is `https://auth.<domain>/t/<tenant>`,
/// [redirectUri] the app's custom-scheme callback.
class GatekeeperConfig {
  GatekeeperConfig({
    required String issuer,
    required this.clientId,
    required this.redirectUri,
    this.scopes = const ['openid', 'profile'],
    this.audience,
  }) : issuer = issuer.endsWith('/') ? issuer.substring(0, issuer.length - 1) : issuer;

  final String issuer;
  final String clientId;
  final Uri redirectUri;
  final List<String> scopes;
  final String? audience;
}

/// A started sign-in: open [url] in the system browser and keep the rest
/// until the redirect comes back.
class AuthorizationRequest {
  AuthorizationRequest(this.url, this.state, this.codeVerifier);
  final Uri url;
  final String state;
  final String codeVerifier;
}

/// The tokens of a signed-in user.
class Tokens {
  Tokens({required this.accessToken, this.refreshToken, this.idToken, required this.expiresAt});

  factory Tokens.fromJson(Map<String, dynamic> j) => Tokens(
        accessToken: j['access_token'] as String,
        refreshToken: j['refresh_token'] as String?,
        idToken: j['id_token'] as String?,
        expiresAt: DateTime.fromMillisecondsSinceEpoch(j['expires_at'] as int, isUtc: true),
      );

  final String accessToken;
  final String? refreshToken;
  final String? idToken;
  final DateTime expiresAt;

  Map<String, dynamic> toJson() => {
        'access_token': accessToken,
        'refresh_token': refreshToken,
        'id_token': idToken,
        'expires_at': expiresAt.millisecondsSinceEpoch,
      };

  /// The access token's claims, decoded without verification (APIs verify;
  /// the app only reads sub, amr and auth_time for display).
  Map<String, dynamic> get claims => decodeClaims(accessToken);

  /// The admin acting as this user, when the token is an impersonation
  /// (ADR-0058); show the "Viewing as" banner while it is set.
  String? get actor => _act?['sub'] as String?;

  /// When the impersonation ends; null otherwise.
  DateTime? get impersonationEndsAt {
    final end = _act?['ends_at'];
    return end is int ? DateTime.fromMillisecondsSinceEpoch(end * 1000, isUtc: true) : null;
  }

  Map<String, dynamic>? get _act {
    final a = claims['act'];
    return a is Map<String, dynamic> ? a : null;
  }
}

/// Decodes a JWT payload without verifying it.
Map<String, dynamic> decodeClaims(String jwt) {
  final parts = jwt.split('.');
  if (parts.length != 3) throw const FormatException('not a JWT');
  return jsonDecode(utf8.decode(base64Url.decode(base64Url.normalize(parts[1])))) as Map<String, dynamic>;
}

/// Where tokens live; apps plug in flutter_secure_storage.
abstract class TokenStore {
  Future<Tokens?> read();
  Future<void> write(Tokens? tokens);
}

/// Keeps tokens in memory only (tests, short-lived processes).
class MemoryTokenStore implements TokenStore {
  Tokens? _t;
  @override
  Future<Tokens?> read() async => _t;
  @override
  Future<void> write(Tokens? tokens) async => _t = tokens;
}

/// An API asked for a recent second factor (RFC 9470): re-run sign-in with
/// [maxAge] and acr_values=mfa, then retry.
class StepUpRequired implements Exception {
  StepUpRequired(this.maxAge);
  final int maxAge;
  @override
  String toString() => 'StepUpRequired(maxAge: $maxAge)';
}

/// Sign-in failed or was refused.
class GatekeeperException implements Exception {
  GatekeeperException(this.message);
  final String message;
  @override
  String toString() => 'GatekeeperException: $message';
}

/// Signs DPoP proofs (RFC 9449, ADR-0070) with a key the app holds. Back it
/// with the platform keystore (iOS Secure Enclave, Android Keystore) so the
/// key can't leave the device; the SDK never sees the private key.
abstract class DpopSigner {
  /// The public key as a JWK: kty, crv, x, y for ES256 (no private members).
  Map<String, String> get publicJwk;

  /// ES256 (default), RS256 or EdDSA.
  String get alg => 'ES256';

  /// Signs [input], the JWS signing input, and returns the JWS signature
  /// bytes (for ES256 the 64-byte r||s, not DER).
  Future<List<int>> sign(List<int> input);
}

/// The SDK. One per app; safe to share.
class Gatekeeper {
  Gatekeeper(this.config, {TokenStore? store, http.Client? httpClient, DateTime Function()? clock, this.dpop})
      : store = store ?? MemoryTokenStore(),
        _http = httpClient ?? http.Client(),
        _now = clock ?? (() => DateTime.now().toUtc());

  final GatekeeperConfig config;

  /// Binds this app's tokens to a device key with DPoP when set (ADR-0070).
  final DpopSigner? dpop;
  final TokenStore store;
  final http.Client _http;
  final DateTime Function() _now;
  Future<Tokens>? _refreshing;
  static final _rand = Random.secure();

  /// Builds the authorize URL with PKCE S256, state and nonce. [acrValues]
  /// and [maxAge] request step-up; [uiLocales] picks the page language.
  AuthorizationRequest authorizationRequest({List<String>? acrValues, int? maxAge, String? uiLocales, String? prompt}) {
    final verifier = _random(32);
    final state = _random(16);
    final challenge = base64Url.encode(sha256.convert(ascii.encode(verifier)).bytes).replaceAll('=', '');
    final q = <String, String>{
      'client_id': config.clientId,
      'response_type': 'code',
      'redirect_uri': config.redirectUri.toString(),
      'scope': config.scopes.join(' '),
      'state': state,
      'nonce': _random(16),
      'code_challenge': challenge,
      'code_challenge_method': 'S256',
      if (config.audience != null) 'audience': config.audience!,
      if (acrValues != null) 'acr_values': acrValues.join(' '),
      if (maxAge != null) 'max_age': '$maxAge',
      if (uiLocales != null) 'ui_locales': uiLocales,
      if (prompt != null) 'prompt': prompt,
    };
    return AuthorizationRequest(Uri.parse('${config.issuer}/oauth2/authorize').replace(queryParameters: q), state, verifier);
  }

  /// Finishes sign-in from the redirect the browser returned.
  Future<Tokens> handleRedirect(Uri callback, AuthorizationRequest request) async {
    final p = callback.queryParameters;
    if (p['state'] != request.state) throw GatekeeperException('state mismatch');
    if (p['error'] != null) throw GatekeeperException(p['error_description'] ?? p['error']!);
    final code = p['code'];
    if (code == null) throw GatekeeperException('no code in redirect');
    return _token({
      'grant_type': 'authorization_code',
      'client_id': config.clientId,
      'code': code,
      'redirect_uri': config.redirectUri.toString(),
      'code_verifier': request.codeVerifier,
    });
  }

  /// A valid access token, refreshed when it expires within 30 seconds.
  Future<String> accessToken() async {
    final t = await store.read();
    if (t == null) throw GatekeeperException('not signed in');
    if (t.expiresAt.isAfter(_now().add(const Duration(seconds: 30)))) return t.accessToken;
    return (await refresh()).accessToken;
  }

  /// Rotates the refresh token. Concurrent callers share one request, so a
  /// rotation is never replayed (the server would revoke the family).
  Future<Tokens> refresh() {
    return _refreshing ??= () async {
      try {
        final t = await store.read();
        final rt = t?.refreshToken;
        if (rt == null) throw GatekeeperException('no refresh token');
        return await _token({'grant_type': 'refresh_token', 'client_id': config.clientId, 'refresh_token': rt});
      } finally {
        _refreshing = null;
      }
    }();
  }

  /// An HTTP client for the product's API: adds the token (as DPoP with a
  /// fresh proof when a [DpopSigner] is set), refreshes
  /// once on invalid_token, and throws [StepUpRequired] on an RFC 9470 challenge.
  http.Client authorizedClient() => _AuthorizedClient(this, _http);

  /// The RP-initiated logout URL to open in the browser.
  Future<Uri> logoutUrl({Uri? postLogoutRedirect, String? state}) async {
    final t = await store.read();
    return Uri.parse('${config.issuer}/oauth2/logout').replace(queryParameters: {
      if (t?.idToken != null) 'id_token_hint': t!.idToken!,
      if (postLogoutRedirect != null) 'post_logout_redirect_uri': postLogoutRedirect.toString(),
      if (state != null) 'state': state,
    });
  }

  /// Starts a headless sign-in (FR-A22, ADR-0089) for a client with
  /// headless_login: the app shows its own screens and calls the steps.
  Future<HeadlessSignIn> startHeadless({String? organization, String? acrValues, int? maxAge}) async {
    final verifier = _random(32);
    final state = _random(16);
    final out = await _post(this, '/start', {
      'client_id': config.clientId,
      'redirect_uri': config.redirectUri.toString(),
      'scope': config.scopes.join(' '),
      'state': state,
      'nonce': _random(16),
      'code_challenge': base64Url.encode(sha256.convert(ascii.encode(verifier)).bytes).replaceAll('=', ''),
      'code_challenge_method': 'S256',
      if (organization != null) 'organization': organization,
      if (acrValues != null) 'acr_values': acrValues,
      if (maxAge != null) 'max_age': '$maxAge',
    });
    return HeadlessSignIn._(this, verifier, state, out['flow_id'] as String,
        [for (final m in out['methods'] as List) m as String], out['provider_nonce'] as String? ?? '');
  }

  /// Forgets the tokens on this device.
  Future<void> signOutLocally() => store.write(null);

  /// A DPoP proof for [method] on [url] (query and fragment dropped); with
  /// [accessToken] it carries ath, as API requests need.
  Future<String> dpopProof(String method, Uri url, {String? accessToken}) async {
    final signer = dpop;
    if (signer == null) throw GatekeeperException('no DPoP signer configured');
    String b64(List<int> b) => base64Url.encode(b).replaceAll('=', '');
    final header = {'typ': 'dpop+jwt', 'alg': signer.alg, 'jwk': signer.publicJwk};
    final claims = <String, Object>{
      'htm': method,
      'htu': Uri(scheme: url.scheme, host: url.host, port: url.hasPort ? url.port : null, path: url.path).toString(),
      'iat': _now().millisecondsSinceEpoch ~/ 1000,
      'jti': _random(16),
      if (accessToken != null) 'ath': b64(sha256.convert(ascii.encode(accessToken)).bytes),
    };
    final input = '${b64(utf8.encode(jsonEncode(header)))}.${b64(utf8.encode(jsonEncode(claims)))}';
    return '$input.${b64(await signer.sign(ascii.encode(input)))}';
  }

  Future<Tokens> _token(Map<String, String> form) async {
    final tokenUrl = Uri.parse('${config.issuer}/oauth2/token');
    final res = await _http.post(tokenUrl, body: form,
        headers: dpop == null ? null : {'DPoP': await dpopProof('POST', tokenUrl)});
    final body = jsonDecode(res.body) as Map<String, dynamic>;
    if (res.statusCode != 200) {
      if (form['grant_type'] == 'refresh_token') await store.write(null); // a dead family signs the user out
      throw GatekeeperException((body['error_description'] ?? body['error'] ?? 'token request failed').toString());
    }
    final previous = await store.read();
    final t = Tokens(
      accessToken: body['access_token'] as String,
      refreshToken: (body['refresh_token'] as String?) ?? previous?.refreshToken,
      idToken: (body['id_token'] as String?) ?? previous?.idToken,
      expiresAt: _now().add(Duration(seconds: (body['expires_in'] as num?)?.toInt() ?? 600)),
    );
    await store.write(t);
    return t;
  }

  static String _random(int n) =>
      base64Url.encode(List<int>.generate(n, (_) => _rand.nextInt(256))).replaceAll('=', '');
}

class _AuthorizedClient extends http.BaseClient {
  _AuthorizedClient(this._gk, this._inner);
  final Gatekeeper _gk;
  final http.Client _inner;
  static final _maxAge = RegExp(r'max_age="?(\d+)"?');

  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) async {
    final body = request is http.Request ? request.bodyBytes : null;
    var res = await _send(request, await _gk.accessToken(), body);
    var challenge = res.headers['www-authenticate'] ?? '';
    if (res.statusCode == 401 && challenge.contains('invalid_token')) {
      await res.stream.drain<void>();
      res = await _send(request, (await _gk.refresh()).accessToken, body);
      challenge = res.headers['www-authenticate'] ?? '';
    }
    if (res.statusCode == 401 && challenge.contains('insufficient_user_authentication')) {
      await res.stream.drain<void>();
      throw StepUpRequired(int.tryParse(_maxAge.firstMatch(challenge)?.group(1) ?? '') ?? 0);
    }
    return res;
  }

  Future<http.StreamedResponse> _send(http.BaseRequest original, String token, List<int>? body) async {
    final r = http.Request(original.method, original.url)..headers.addAll(original.headers);
    if (_gk.dpop != null) {
      r.headers['Authorization'] = 'DPoP $token';
      r.headers['DPoP'] = await _gk.dpopProof(original.method, original.url, accessToken: token);
    } else {
      r.headers['Authorization'] = 'Bearer $token';
    }
    if (body != null) r.bodyBytes = body;
    return _inner.send(r);
  }
}
