part of 'client.dart';

// Headless sign-in for first-party apps as typed steps (FR-A22, ADR-0089).
// Each step answers a [HeadlessResult]; problems are thrown as
// [HeadlessProblem]; [Complete] has already exchanged the code with the PKCE
// verifier and saved the tokens in the [Gatekeeper]'s store.

/// What a headless step answered.
sealed class HeadlessResult {
  const HeadlessResult();
}

/// Signed in; the tokens are in the store.
class Complete extends HeadlessResult {
  const Complete(this.tokens);
  final Tokens tokens;
}

/// A second factor is needed: a TOTP or recovery code ([factor] `totp`), the
/// emailed risk code (`email`), or the user's passkey when [passkey].
class MfaRequired extends HeadlessResult {
  const MfaRequired(this.factor, {required this.passkey});
  final String factor;
  final bool passkey;
}

/// The user must accept these document versions; show them, then [HeadlessSignIn.acceptTerms].
class TermsRequired extends HeadlessResult {
  const TermsRequired(this.documents);
  final List<LegalDocument> documents;
}

/// The provider's email has an account: sign in to it in this flow to connect [provider].
class LinkRequired extends HeadlessResult {
  const LinkRequired(this.provider);
  final String provider;
}

/// A code was sent (or not: unknown identifiers answer the same).
class CodeSent extends HeadlessResult {
  const CodeSent();
}

/// A terms or privacy policy version.
class LegalDocument {
  LegalDocument(this.kind, this.version, this.url);
  final String kind;
  final String version;
  final Uri url;
}

/// A problem answer (RFC 9457); [type] is its slug, such as `invalid-credentials`.
class HeadlessProblem implements Exception {
  HeadlessProblem(this.status, this.body, String? retryAfter)
      : type = (body['type'] as String? ?? 'http-$status').replaceFirst('/errors/', ''),
        retryAfter = retryAfter == null ? null : Duration(seconds: int.tryParse(retryAfter) ?? 0);

  final int status;
  final String type;
  final Map<String, dynamic> body;
  final Duration? retryAfter;
  String? get siteKey => body['site_key'] as String?;
  String? get ticket => body['ticket'] as String?;
  DateTime? get deletesAt => body['deletes_at'] == null ? null : DateTime.parse(body['deletes_at'] as String);

  @override
  String toString() => 'HeadlessProblem($type, $status)';
}

/// Runs the platform passkey API (Credential Manager, AuthenticationServices)
/// on [options] and returns the credential JSON.
typedef GetAssertion = Future<Map<String, dynamic>> Function(Map<String, dynamic> options);

/// A started headless sign-in; create one with [Gatekeeper.startHeadless].
class HeadlessSignIn {
  HeadlessSignIn._(this._gk, this._verifier, this._state, this.flowId, this.methods, this.providerNonce);

  final Gatekeeper _gk;
  final String _verifier;
  final String _state;
  final String flowId;
  final List<String> methods;

  /// Pass to the provider's native SDK as its nonce before [social].
  final String providerNonce;

  Future<HeadlessResult> password(String identifier, String password, {String? captchaToken}) =>
      _step('/password', {'identifier': identifier, 'password': password, if (captchaToken != null) 'captcha_token': captchaToken});
  Future<HeadlessResult> sendCode(String identifier, String channel, {String? captchaToken}) =>
      _step('/code', {'identifier': identifier, 'channel': channel, if (captchaToken != null) 'captcha_token': captchaToken});
  Future<HeadlessResult> verifyCode(String code) => _step('/code/verify', {'code': code});
  Future<HeadlessResult> passkey(GetAssertion getAssertion) => _withPasskey('/passkey/begin', '/passkey', getAssertion);
  Future<HeadlessResult> social(String provider, String idToken, {String? name}) =>
      _step('/social', {'provider': provider, 'id_token': idToken, if (name != null) 'name': name});
  Future<HeadlessResult> mfa(String code) => _step('/mfa', {'code': code});
  Future<HeadlessResult> mfaPasskey(GetAssertion getAssertion) => _withPasskey('/mfa/passkey/begin', '/mfa', getAssertion);
  Future<HeadlessResult> acceptTerms() => _step('/terms', {});

  /// Keeps an account in its deletion grace period; then sign in again.
  Future<void> keep(String ticket) => _post(_gk, '/keep', {'flow_id': flowId, 'ticket': ticket});

  Future<HeadlessResult> _withPasskey(String begin, String finish, GetAssertion getAssertion) async {
    final out = await _post(_gk, begin, {'flow_id': flowId});
    return _step(finish, {'credential': await getAssertion(out['options'] as Map<String, dynamic>)});
  }

  Future<HeadlessResult> _step(String path, Map<String, dynamic> body) async {
    final Map<String, dynamic> out;
    try {
      out = await _post(_gk, path, {'flow_id': flowId, ...body});
    } on HeadlessProblem catch (e) {
      if (e.type == 'link-required') return LinkRequired(e.body['provider'] as String);
      rethrow;
    }
    switch (out['status']) {
      case 'complete':
        if (!_same(out['state'] as String? ?? '', _state)) throw GatekeeperException('state mismatch');
        return Complete(await _gk._token({
          'grant_type': 'authorization_code',
          'client_id': _gk.config.clientId,
          'code': out['code'] as String,
          'redirect_uri': _gk.config.redirectUri.toString(),
          'code_verifier': _verifier,
        }));
      case 'mfa_required':
        return MfaRequired(out['factor'] as String, passkey: out['passkey'] == true);
      case 'terms_required':
        return TermsRequired([
          for (final d in out['documents'] as List)
            LegalDocument(d['kind'] as String, d['version'] as String, Uri.parse(d['url'] as String)),
        ]);
      case 'code_sent':
        return const CodeSent();
    }
    throw GatekeeperException('unexpected headless status ${out['status']}');
  }
}

Future<Map<String, dynamic>> _post(Gatekeeper gk, String path, Map<String, dynamic> body) async {
  final res = await gk._http.post(Uri.parse('${gk.config.issuer}/v1/auth/headless$path'),
      headers: {'Content-Type': 'application/json'}, body: jsonEncode(body));
  final out = res.body.isEmpty ? <String, dynamic>{} : jsonDecode(res.body) as Map<String, dynamic>;
  if (res.statusCode >= 300) throw HeadlessProblem(res.statusCode, out, res.headers['retry-after']);
  return out;
}

bool _same(String a, String b) {
  if (a.length != b.length) return false;
  var d = 0;
  for (var i = 0; i < a.length; i++) {
    d |= a.codeUnitAt(i) ^ b.codeUnitAt(i);
  }
  return d == 0;
}
