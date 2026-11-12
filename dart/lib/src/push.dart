import 'dart:convert';
import 'dart:math';

import 'package:http/http.dart' as http;

import 'client.dart';

/// Signs push approver requests: the same contract as [DpopSigner], ES256
/// over a P-256 key the platform keystore holds (ADR-0111).
typedef PushSigner = DpopSigner;

/// A pending sign-in, as the phone shows it.
class PushChallenge {
  PushChallenge.fromJson(Map<String, dynamic> j)
      : id = j['id'] as String,
        clientId = j['client_id'] as String,
        clientName = j['client_name'] as String?,
        device = j['device'] as String,
        country = j['country'] as String?,
        numbers = (j['numbers'] as List).cast<int>(),
        expiresAt = DateTime.tryParse(j['expires_at'] as String? ?? '');

  final String id;
  final String clientId;
  final String? clientName;
  final String device;
  final String? country;

  /// The right number and two decoys, shuffled: show all three.
  final List<int> numbers;
  final DateTime? expiresAt;
}

/// A push request the server refused.
class PushException implements Exception {
  PushException(this.status, this.message);
  final int status;
  final String message;
  @override
  String toString() => 'PushException($status): $message';
}

/// Push login approval for this phone (FR-A27): enrol it as an approver,
/// list pending sign-ins, approve with the number the user picks, or deny.
class PushApprover {
  PushApprover({required String issuer, required this.signer, this.approverId, http.Client? httpClient, DateTime Function()? clock})
      : _base = issuer.replaceAll(RegExp(r'/+$'), ''),
        _http = httpClient ?? http.Client(),
        _clock = clock ?? DateTime.now;

  final String _base;
  final http.Client _http;
  final DateTime Function() _clock;
  final PushSigner signer;

  /// Set by [enrol]; keep it with the key.
  String? approverId;

  /// Enrols this phone for the user of [accessToken] (signed in within the
  /// last 5 minutes). Returns recovery codes when this is their first second factor.
  Future<List<String>> enrol(String accessToken, String name) async {
    final r = await _http.post(Uri.parse('$_base/v1/me/push-approvers'),
        headers: {'Content-Type': 'application/json', 'Authorization': 'Bearer $accessToken'},
        body: jsonEncode({'name': name, 'public_key': signer.publicJwk}));
    final j = _json(r);
    approverId = j['id'] as String;
    return ((j['recovery_codes'] as List?) ?? const []).cast<String>();
  }

  Future<List<PushChallenge>> pending() async {
    final r = await _http.get(Uri.parse('$_base/v1/push/pending'), headers: {'Authorization': 'Push ${await _sign({})}'});
    return (_json(r)['challenges'] as List).map((c) => PushChallenge.fromJson(c as Map<String, dynamic>)).toList();
  }

  /// Approves with [number]; a wrong number denies. Returns approved or denied.
  Future<String> approve(String challengeId, int number) =>
      _answer(challengeId, {'decision': 'approve', 'number': number});

  /// Denies; [reported] says "that wasn't me", which makes the user's next sign-ins riskier.
  Future<String> deny(String challengeId, {bool reported = false}) =>
      _answer(challengeId, {'decision': 'deny', 'number': 0, 'reported': reported});

  Future<String> _answer(String id, Map<String, Object> body) async {
    final r = await _http.post(Uri.parse('$_base/v1/push/challenges/${Uri.encodeComponent(id)}'),
        headers: {'Content-Type': 'application/json'},
        body: jsonEncode({'answer': await _sign({'challenge_id': id, ...body})}));
    return _json(r)['status'] as String;
  }

  // The compact JWS every device request carries: kid, aud, iat, a fresh jti.
  Future<String> _sign(Map<String, Object> extra) async {
    final id = approverId;
    if (id == null) throw PushException(0, 'enrol this device first');
    final input = '${_b64(utf8.encode(jsonEncode({'alg': 'ES256', 'kid': id})))}.'
        '${_b64(utf8.encode(jsonEncode({
              'aud': '$_base/v1/push',
              'iat': _clock().millisecondsSinceEpoch ~/ 1000,
              'jti': _b64(List<int>.generate(16, (_) => _rand.nextInt(256))),
              ...extra,
            })))}';
    final sig = await signer.sign(ascii.encode(input));
    if (sig.length != 64) throw PushException(0, 'the signer must return a 64-byte ES256 signature');
    return '$input.${_b64(sig)}';
  }

  Map<String, dynamic> _json(http.Response r) {
    Map<String, dynamic> j;
    try {
      j = jsonDecode(r.body) as Map<String, dynamic>;
    } on FormatException {
      j = {};
    }
    if (r.statusCode >= 300) {
      throw PushException(r.statusCode, (j['detail'] ?? j['title'] ?? 'push request failed').toString());
    }
    return j;
  }

  static final _rand = Random.secure();
  static String _b64(List<int> b) => base64Url.encode(b).replaceAll('=', '');
}
