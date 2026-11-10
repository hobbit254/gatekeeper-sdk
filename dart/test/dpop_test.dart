import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:gatekeeper_sdk/gatekeeper_sdk.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:pointycastle/export.dart' as pc;
import 'package:test/test.dart';

const issuer = 'https://auth.example.test/t/acme';

String b64(List<int> b) => base64Url.encode(b).replaceAll('=', '');
List<int> unb64(String s) => base64Url.decode(base64Url.normalize(s));
Uint8List be32(BigInt n) {
  final out = Uint8List(32);
  for (var i = 31; i >= 0; i--) {
    out[i] = (n & BigInt.from(0xff)).toInt();
    n = n >> 8;
  }
  return out;
}

BigInt bigOf(List<int> b) => b.fold(BigInt.zero, (a, x) => (a << 8) | BigInt.from(x));

/// A software ES256 signer, as an app would build over the platform keystore.
class TestSigner extends DpopSigner {
  TestSigner() {
    final gen = pc.ECKeyGenerator()
      ..init(pc.ParametersWithRandom(pc.ECKeyGeneratorParameters(pc.ECCurve_secp256r1()), _random()));
    final pair = gen.generateKeyPair();
    priv = pair.privateKey as pc.ECPrivateKey;
    pub = pair.publicKey as pc.ECPublicKey;
  }
  late final pc.ECPrivateKey priv;
  late final pc.ECPublicKey pub;

  static pc.SecureRandom _random() {
    final r = pc.FortunaRandom();
    final s = Random.secure();
    r.seed(pc.KeyParameter(Uint8List.fromList(List<int>.generate(32, (_) => s.nextInt(256)))));
    return r;
  }

  @override
  Map<String, String> get publicJwk => {
        'kty': 'EC',
        'crv': 'P-256',
        'x': b64(be32(pub.Q!.x!.toBigInteger()!)),
        'y': b64(be32(pub.Q!.y!.toBigInteger()!)),
      };

  @override
  Future<List<int>> sign(List<int> input) async {
    final signer = pc.Signer('SHA-256/DET-ECDSA')..init(true, pc.PrivateKeyParameter<pc.ECPrivateKey>(priv));
    final sig = signer.generateSignature(Uint8List.fromList(input)) as pc.ECSignature;
    return [...be32(sig.r), ...be32(sig.s)];
  }

  bool verify(String jws) {
    final parts = jws.split('.');
    final raw = unb64(parts[2]);
    final v = pc.Signer('SHA-256/DET-ECDSA')..init(false, pc.PublicKeyParameter<pc.ECPublicKey>(pub));
    return v.verifySignature(Uint8List.fromList(ascii.encode('${parts[0]}.${parts[1]}')),
        pc.ECSignature(bigOf(raw.sublist(0, 32)), bigOf(raw.sublist(32))));
  }
}

Map<String, dynamic> part(String jws, int i) => jsonDecode(utf8.decode(unb64(jws.split('.')[i]))) as Map<String, dynamic>;

String jwt(Map<String, dynamic> claims) => 'e30.${b64(utf8.encode(jsonEncode(claims)))}.sig';

void main() {
  final config = GatekeeperConfig(issuer: issuer, clientId: 'app', redirectUri: Uri.parse('com.acme.app:/cb'));
  final now = DateTime.utc(2026, 11, 10, 12);

  test('a proof names the method and URL, carries the public key and verifies', () async {
    final signer = TestSigner();
    final gk = Gatekeeper(config, dpop: signer, clock: () => now);
    final proof = await gk.dpopProof('GET', Uri.parse('https://api.acme.test/orders?page=2#top'), accessToken: 'at-1');
    final h = part(proof, 0), c = part(proof, 1);
    expect(h['typ'], 'dpop+jwt');
    expect(h['alg'], 'ES256');
    expect(h['jwk'], signer.publicJwk);
    expect((h['jwk'] as Map).containsKey('d'), isFalse);
    expect(c['htm'], 'GET');
    expect(c['htu'], 'https://api.acme.test/orders', reason: 'no query or fragment');
    expect(c['iat'], now.millisecondsSinceEpoch ~/ 1000);
    expect(c['ath'], b64(sha256.convert(ascii.encode('at-1')).bytes));
    expect((c['jti'] as String).length, greaterThanOrEqualTo(16));
    expect(signer.verify(proof), isTrue);
    final again = await gk.dpopProof('GET', Uri.parse('https://api.acme.test/orders'));
    expect(part(again, 1)['jti'], isNot(c['jti']), reason: 'a fresh jti every time');
    expect(part(again, 1).containsKey('ath'), isFalse);
  });

  test('token requests and API calls carry proofs', () async {
    final signer = TestSigner();
    final seen = <http.BaseRequest>[];
    final at = jwt({'sub': 'u1', 'cnf': {'jkt': 'k'}});
    final gk = Gatekeeper(config, dpop: signer, clock: () => now, httpClient: MockClient((r) async {
      seen.add(r);
      if (r.url.path.endsWith('/oauth2/token')) {
        return http.Response(jsonEncode({'access_token': at, 'token_type': 'DPoP', 'refresh_token': 'rt', 'expires_in': 600}), 200);
      }
      return http.Response('{}', 200);
    }));
    final req = gk.authorizationRequest();
    await gk.handleRedirect(Uri.parse('com.acme.app:/cb?code=c&state=${req.state}'), req);
    final tokenProof = seen.single.headers['DPoP']!;
    expect(part(tokenProof, 1)['htm'], 'POST');
    expect(part(tokenProof, 1)['htu'], '$issuer/oauth2/token');
    expect(signer.verify(tokenProof), isTrue);

    await gk.authorizedClient().get(Uri.parse('https://api.acme.test/orders?page=1'));
    final api = seen.last;
    expect(api.headers['Authorization'], 'DPoP $at');
    final c = part(api.headers['DPoP']!, 1);
    expect(c['htu'], 'https://api.acme.test/orders');
    expect(c['ath'], b64(sha256.convert(ascii.encode(at)).bytes));
  });

  test('without a signer nothing changes', () async {
    final seen = <http.BaseRequest>[];
    final gk = Gatekeeper(config, clock: () => now, httpClient: MockClient((r) async {
      seen.add(r);
      return http.Response(jsonEncode({'access_token': jwt({'sub': 'u1'}), 'expires_in': 600}), 200);
    }));
    final req = gk.authorizationRequest();
    await gk.handleRedirect(Uri.parse('com.acme.app:/cb?code=c&state=${req.state}'), req);
    await gk.authorizedClient().get(Uri.parse('https://api.acme.test/orders'));
    expect(seen.first.headers.containsKey('DPoP'), isFalse);
    expect(seen.last.headers['Authorization'], startsWith('Bearer '));
    await expectLater(gk.dpopProof('GET', Uri.parse('https://x.test/')), throwsA(isA<GatekeeperException>()));
  });
}
