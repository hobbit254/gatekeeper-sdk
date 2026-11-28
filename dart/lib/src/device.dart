import 'dart:convert';
import 'dart:math';

import 'package:crypto/crypto.dart';
import 'package:http/http.dart' as http;

import 'push.dart';

/// Signs shared-device requests: the same ES256 signer as push approvers, over
/// a P-256 key the platform keystore holds (ADR-0144, ADR-0154).
typedef DeviceSigner = PushSigner;

/// A PIN session's access token. There is no refresh token: renew it with the device.
class PinSession {
  PinSession.fromJson(Map<String, dynamic> j)
      : accessToken = j['access_token'] as String,
        expiresIn = j['expires_in'] as int,
        sid = j['sid'] as String,
        sessionExpiresAt = DateTime.parse(j['session_expires_at'] as String);

  final String accessToken;

  /// Seconds the token lasts: 15 minutes, or less near the session's end.
  final int expiresIn;

  /// The PIN session, for renewal and sign-out.
  final String sid;

  /// When the session ends, renewed or not.
  final DateTime sessionExpiresAt;
}

/// An approval granted on this device by a second person's PIN (ADR-0145).
class DeviceApproval {
  DeviceApproval.fromJson(Map<String, dynamic> j)
      : approvalId = j['approval_id'] as String,
        status = j['status'] as String,
        approverId = j['approver_id'] as String?,
        permission = j['permission'] as String?,
        resource = j['resource'] as String?,
        amount = j['amount'] as int?,
        currency = j['currency'] as String?,
        approvalToken = j['approval_token'] as String;

  final String approvalId;
  final String status;
  final String? approverId;
  final String? permission;
  final String? resource;
  final int? amount;
  final String? currency;

  /// Hand it to your backend, which spends it once.
  final String approvalToken;
}

/// A refused device request. [status] 401 with [code] `not-accepted`: the
/// device, its signature or the PIN wasn't accepted (it never says which);
/// 423 `pin-locked` (see [retryAfter]) or `pin-held` (an org admin must
/// unlock it); 403 `pin-sign-in-off`; 429 `rate-limited`.
class DeviceException implements Exception {
  DeviceException(this.status, this.code, this.message, {this.retryAfter});
  final int status;
  final String code;
  final String message;
  final Duration? retryAfter;
  @override
  String toString() => 'DeviceException($status $code): $message';
}

/// The client for one shared device (FR-A45, FR-A46, FR-Z21): claim it with
/// the org admin's one-time code, then sign staff in with their PIN, renew and
/// end their sessions, and collect a manager's approval by PIN. Every request
/// is signed by [signer]: kid (after the claim), aud, iat, a fresh jti and bh.
class SharedDevice {
  SharedDevice({required String issuer, required this.signer, this.deviceId, http.Client? httpClient, DateTime Function()? clock})
      : _base = issuer.replaceAll(RegExp(r'/+$'), ''),
        _http = httpClient ?? http.Client(),
        _clock = clock ?? DateTime.now;

  final String _base;
  final http.Client _http;
  final DateTime Function() _clock;
  final DeviceSigner signer;

  /// Set by [claim]; keep it with the key.
  String? deviceId;

  /// Redeems the code an org admin got when registering this device.
  Future<Map<String, dynamic>> claim(String code) async {
    final out = await _post('claim', {'code': code, 'public_jwk': signer.publicJwk}, kid: null);
    deviceId = out['device_id'] as String;
    return out;
  }

  Future<PinSession> pinSignIn(String userId, String pin) async =>
      PinSession.fromJson(await _post('pin-sign-in', {'user_id': userId, 'pin': pin}, kid: _needId()));

  Future<PinSession> renewPinSession(String sid) async =>
      PinSession.fromJson(await _post('pin-sessions/renew', {'sid': sid}, kid: _needId()));

  Future<void> pinSignOut(String sid) async {
    await _post('pin-sign-out', {'sid': sid}, kid: _needId());
  }

  /// A second person approves one action with their PIN on this device.
  /// Wrong PINs count toward their lockout.
  Future<DeviceApproval> approveWithPin(String approvalId, String approverId, String pin) async => DeviceApproval.fromJson(
      await _post('approvals/${Uri.encodeComponent(approvalId)}/approve', {'approver_id': approverId, 'pin': pin}, kid: _needId()));

  String _needId() {
    final id = deviceId;
    if (id == null) throw DeviceException(0, 'not-claimed', 'claim the device first');
    return id;
  }

  Future<Map<String, dynamic>> _post(String path, Map<String, Object?> payload, {required String? kid}) async {
    final url = '$_base/v1/devices/$path';
    final body = utf8.encode(jsonEncode(payload));
    final jws = await signDeviceRequest(signer, url, body, deviceId: kid, now: _clock);
    final r = await _http.post(Uri.parse(url),
        headers: {'Content-Type': 'application/json', 'Authorization': 'Device $jws'}, body: body);
    if (r.statusCode == 204) return {};
    Map<String, dynamic> j;
    try {
      j = jsonDecode(r.body) as Map<String, dynamic>;
    } on FormatException {
      j = {};
    }
    if (r.statusCode >= 300) {
      final code = (j['type'] as String? ?? '').replaceFirst('/errors/', '');
      final retry = int.tryParse(r.headers['retry-after'] ?? '');
      throw DeviceException(r.statusCode, code, (j['detail'] ?? j['title'] ?? 'status ${r.statusCode}').toString(),
          retryAfter: retry == null ? null : Duration(seconds: retry));
    }
    return j;
  }
}

/// bh: the base64url SHA-256 of the body the signature covers.
String bodyHash(List<int> body) => _b64(sha256.convert(body).bytes);

/// The device's compact JWS over a request to [url] with [body]: kid the
/// device id (none on a claim), aud the URL, iat now, a fresh jti and bh.
Future<String> signDeviceRequest(DeviceSigner signer, String url, List<int> body,
    {String? deviceId, DateTime Function()? now}) async {
  final header = <String, Object>{'alg': 'ES256', 'typ': 'JWT', if (deviceId != null) 'kid': deviceId};
  final claims = {
    'aud': url,
    'iat': (now ?? DateTime.now)().millisecondsSinceEpoch ~/ 1000,
    'jti': _b64(List<int>.generate(16, (_) => _rand.nextInt(256))),
    'bh': bodyHash(body),
  };
  final input = '${_b64(utf8.encode(jsonEncode(header)))}.${_b64(utf8.encode(jsonEncode(claims)))}';
  final sig = await signer.sign(ascii.encode(input));
  if (sig.length != 64) throw DeviceException(0, 'bad-signer', 'the signer must return a 64-byte ES256 signature');
  return '$input.${_b64(sig)}';
}

final _rand = Random.secure();
String _b64(List<int> b) => base64Url.encode(b).replaceAll('=', '');
