import 'dart:convert';

import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:gatekeeper_sdk/gatekeeper_sdk.dart';

/// A [TokenStore] in the platform's secure storage: the Keychain on iOS and
/// macOS, Keystore-backed encryption on Android. One entry per issuer and client.
class SecureTokenStore implements TokenStore {
  SecureTokenStore({required String issuer, required String clientId, FlutterSecureStorage? storage})
      : _key = 'gatekeeper.tokens.$issuer|$clientId',
        _storage = storage ?? const FlutterSecureStorage();

  final String _key;
  final FlutterSecureStorage _storage;

  @override
  Future<Tokens?> read() async {
    final raw = await _storage.read(key: _key);
    if (raw == null) return null;
    try {
      return Tokens.fromJson(jsonDecode(raw) as Map<String, dynamic>);
    } on Object {
      await _storage.delete(key: _key); // unreadable (an older format, or corrupted): sign in again
      return null;
    }
  }

  @override
  Future<void> write(Tokens? tokens) => tokens == null
      ? _storage.delete(key: _key)
      : _storage.write(key: _key, value: jsonEncode(tokens.toJson()));
}
