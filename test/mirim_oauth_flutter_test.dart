import 'package:flutter_test/flutter_test.dart';
import 'package:mirim_oauth_flutter/mirim_oauth_flutter.dart';

void main() {
  test('Create MirimOAuth instance', () {
    final mirimOAuth = MirimOAuth(
      clientSecret: 'eaf7f737-c560-40da-9391-78aaf1cf06bd-6800f62a-7773-4717-8e23-907fe604f7f8',
      clientId: '658dd13e-e7ab-4832-9abc-c5584f624a1e',
      redirectUri: 'mirimauth://callback',
      scopes: ['email', 'nickname', 'major'],
    );
    
    expect(mirimOAuth.clientId, equals('test_client_id'));
    expect(mirimOAuth.redirectUri, equals('mirimauth://callback'));
    expect(mirimOAuth.scopes, contains('email'));
  });

  test('AuthTokens check expiry', () {
    final tokens = AuthTokens(
      accessToken: 'access_token_value',
      refreshToken: 'refresh_token_value',
      expiresIn: 3600,
    );
    
    expect(tokens.isExpired, equals(false));
    expect(tokens.accessToken, equals('access_token_value'));
    expect(tokens.refreshToken, equals('refresh_token_value'));
  });
  
  test('MirimUser fromJson', () {
    final userData = {
      'id': '12345',
      'email': 'test@mirim.hs.kr',
      'nickname': 'Test User',
      'major': 'Software',
      'isGraduated': false,
      'admission': '2025',
      'role': 'student',
      'generation': 20
    };
    
    final user = MirimUser.fromJson(userData);
    
    expect(user.id, equals('12345'));
    expect(user.email, equals('test@mirim.hs.kr'));
    expect(user.nickname, equals('Test User'));
    expect(user.major, equals('Software'));
    expect(user.isGraduated, equals(false));
    expect(user.generation, equals(20));
  });
}
