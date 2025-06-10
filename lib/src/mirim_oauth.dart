import 'dart:async';
import 'dart:convert';
import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:http/http.dart' as http;
import 'package:flutter_web_auth_2/flutter_web_auth_2.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:url_launcher/url_launcher.dart';
import 'mirim_oauth_exception.dart';
import 'auth_tokens.dart';
import 'mirim_user.dart';

class MirimOAuth extends ChangeNotifier {
  static const _tokenKey = 'mirim_oauth_tokens';
  static const _userKey = 'mirim_oauth_user';
  
  final String clientId;
  final String clientSecret;
  final String redirectUri;
  final String oauthServerUrl;
  final List<String> scopes;
  final FlutterSecureStorage _secureStorage;

  MirimUser? _currentUser;
  AuthTokens? _tokens;
  bool _isLoading = false;

  MirimOAuth({
    required this.clientId,
    required this.redirectUri,
    this.oauthServerUrl = 'https://api-auth.mmhs.app',
    required this.clientSecret,
    required this.scopes,
  }) : _secureStorage = const FlutterSecureStorage();

  MirimUser? get currentUser => _currentUser;
  bool get isLoggedIn => _currentUser != null && _tokens != null && !(_tokens!.isExpired);
  bool get isLoading => _isLoading;
  String? get accessToken => _tokens?.accessToken;
  String? get refreshToken => _tokens?.refreshToken;

  Future<String> getAccessToken() async {
    final tokens = await _getValidTokens();
    return tokens.accessToken;
  }
  
  Future<MirimUser> logIn() async {
    try {
      _setLoading(true);
      
      final tokens = await _authenticate();
      final user = await _fetchUserInfo(tokens.accessToken);
      
      _tokens = tokens;
      _currentUser = user;
      
      _setLoading(false);
      return user;
    } catch (e) {
      _setLoading(false);
      rethrow;
    }
  }

  Future<void> logOut() async {
    try {
      _setLoading(true);
      
      await _secureStorage.delete(key: _tokenKey);
      await _secureStorage.delete(key: _userKey);
      _currentUser = null;
      _tokens = null;
      
      _setLoading(false);
    } catch (e) {
      _setLoading(false);
      rethrow;
    }
  }

  Future<bool> checkIsLoggedIn() async {
    if (isLoggedIn) return true;
    
    final tokenJson = await _secureStorage.read(key: _tokenKey);
    if (tokenJson == null) {
      return false;
    }

    try {
      final tokens = AuthTokens.fromJson(json.decode(tokenJson));
      if (tokens.isExpired) {
        try {
          _tokens = await _refreshTokens(tokens.refreshToken);
          _currentUser = await _getStoredUser();
          notifyListeners();
          return true;
        } catch (_) {
          await logOut();
          return false;
        }
      }
      _tokens = tokens;
      _currentUser = await _getStoredUser();
      notifyListeners();
      return true;
    } catch (_) {
      await logOut();
      return false;
    }
  }

  Future<MirimUser> refreshUserInfo() async {
    try {
      _setLoading(true);
      
      final tokens = await _getValidTokens();
      final user = await _fetchUserInfo(tokens.accessToken);
      _currentUser = user;
      
      _setLoading(false);
      return user;
    } catch (e) {
      _setLoading(false);
      rethrow;
    }
  }

  Future<AuthTokens> refreshTokens() async {
    if (_tokens == null) {
      throw MirimOAuthException('Not logged in');
    }
    
    try {
      _setLoading(true);
      final tokens = await _refreshTokens(_tokens!.refreshToken);
      _tokens = tokens;
      _setLoading(false);
      return tokens;
    } catch (e) {
      _setLoading(false);
      rethrow;
    }
  }

  Future<Map<String, dynamic>> makeAuthenticatedRequest(
    String endpoint, 
    {
      String method = 'GET',
      Map<String, dynamic>? body,
      Map<String, String>? additionalHeaders
    }
  ) async {
    try {
      final tokens = await _getValidTokens();
      
      final headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ${tokens.accessToken}',
        if (additionalHeaders != null) ...additionalHeaders,
      };

      http.Response response;
      final uri = Uri.parse('$oauthServerUrl$endpoint');
      
      switch (method.toUpperCase()) {
        case 'GET':
          response = await http.get(uri, headers: headers);
          break;
        case 'POST':
          response = await http.post(
            uri, 
            headers: headers,
            body: body != null ? json.encode(body) : null
          );
          break;
        case 'PUT':
          response = await http.put(
            uri, 
            headers: headers,
            body: body != null ? json.encode(body) : null
          );
          break;
        case 'DELETE':
          response = await http.delete(
            uri, 
            headers: headers,
            body: body != null ? json.encode(body) : null
          );
          break;
        default:
          throw MirimOAuthException('Unsupported HTTP method: $method');
      }

      if (response.statusCode != 200) {
        throw MirimOAuthException(
          'Request failed',
          errorCode: response.statusCode,
          data: response.body,
        );
      }

      return json.decode(response.body);
    } catch (e) {
      if (e is MirimOAuthException) rethrow;
      throw MirimOAuthException('Request failed: ${e.toString()}');
    }
  }
    
  void _setLoading(bool loading) {
    _isLoading = loading;
    notifyListeners();
  }
  
  Future<AuthTokens> _getValidTokens() async {
    if (_tokens == null || _tokens!.isExpired) {
      final storedTokenJson = await _secureStorage.read(key: _tokenKey);
      if (storedTokenJson == null) {
        throw MirimOAuthException('Not logged in');
      }
      
      try {
        final storedTokens = AuthTokens.fromJson(json.decode(storedTokenJson));
        if (storedTokens.isExpired) {
          return await _refreshTokens(storedTokens.refreshToken);
        }
        _tokens = storedTokens;
        return storedTokens;
      } catch (e) {
        throw MirimOAuthException('Failed to get valid tokens: ${e.toString()}');
      }
    }
    
    return _tokens!;
  }

  Future<MirimUser?> _getStoredUser() async {
    final userJson = await _secureStorage.read(key: _userKey);
    if (userJson == null) {
      return null;
    }

    try {
      return MirimUser.fromJson(json.decode(userJson));
    } catch (e) {
      throw MirimOAuthException('Failed to get user data: ${e.toString()}');
    }
  }

  Future<AuthTokens> _authenticate() async {
    try {
      final authUrl = Uri.parse('$oauthServerUrl/api/v1/oauth/authorize').replace(
        queryParameters: {
          'client_id': clientId,
          'redirect_uri': redirectUri,
          'response_type': 'code',
          'scope': scopes.join(','),
          'state': 'code',
        },
      );

      if (redirectUri.startsWith('http://') || redirectUri.startsWith('https://')) {
        if (!await launchUrl(
          authUrl,
          mode: LaunchMode.externalApplication,
        )) {
          throw MirimOAuthException('인증 페이지를 열 수 없습니다.');
        }
        
        throw MirimOAuthException(
          '웹 리다이렉션은 현재 지원되지 않습니다. 백엔드에서 커스텀 URL 스킴을 허용하도록 설정하세요.',
          errorCode: 501,
        );
      } 
      else {
        final result = await FlutterWebAuth2.authenticate(
          url: authUrl.toString(),
          callbackUrlScheme: Uri.parse(redirectUri).scheme,
        );

        final uri = Uri.parse(result);
        final code = uri.queryParameters['code'];
        final state = uri.queryParameters['state'];

        if (code == null) {
          throw MirimOAuthException('Authorization code not received');
        }

        return await _exchangeCodeForTokens(code, state);
      }
    } on PlatformException catch (e) {
      throw MirimOAuthException('Authentication failed: ${e.message}');
    } catch (e) {
      if (e is MirimOAuthException) rethrow;
      throw MirimOAuthException('Authentication failed: ${e.toString()}');
    }
  }

  Future<AuthTokens> _exchangeCodeForTokens(String code, String? state) async {
    try {
      final response = await http.post(
        Uri.parse('$oauthServerUrl/api/v1/oauth/token'),
        headers: {'Content-Type': 'application/json'},
        body: json.encode({
          'code': code,
          'state': state,
          'clientId': clientId,
          'clientSecret': clientSecret,
          'redirectUri': redirectUri,
          'scopes': scopes.join(','),
        }),
      );

      if (response.statusCode != 200) {
        throw MirimOAuthException(
          'Failed to exchange code for tokens',
          errorCode: response.statusCode,
          data: response.body,
        );
      }

      final Map<String, dynamic> data = json.decode(response.body);
      if (data['status'] != 200) {
        throw MirimOAuthException(
          data['message'] ?? 'Token exchange failed',
          errorCode: data['status'],
          data: data,
        );
      }

      final tokenData = data['data'];
      final tokens = AuthTokens(
        accessToken: tokenData['access_token'],
        refreshToken: tokenData['refresh_token'],
        expiresIn: tokenData['expires_in'] ?? 3600,
      );

      await _secureStorage.write(
        key: _tokenKey,
        value: json.encode(tokens.toJson()),
      );

      return tokens;
    } catch (e) {
      if (e is MirimOAuthException) rethrow;
      throw MirimOAuthException('Failed to exchange code for tokens: ${e.toString()}');
    }
  }

  Future<AuthTokens> _refreshTokens(String refreshToken) async {
    try {
      final response = await http.post(
        Uri.parse('$oauthServerUrl/api/v1/auth/refresh'),
        headers: {'Content-Type': 'application/json'},
        body: json.encode({
          'refreshToken': refreshToken,
        }),
      );

      if (response.statusCode != 200) {
        throw MirimOAuthException(
          'Token refresh failed',
          errorCode: response.statusCode,
          data: response.body,
        );
      }

      final Map<String, dynamic> data = json.decode(response.body);
      if (data['status'] != 200) {
        throw MirimOAuthException(
          data['message'] ?? 'Token refresh failed',
          errorCode: data['status'],
          data: data,
        );
      }

      final tokenData = data['data'];
      final tokens = AuthTokens(
        accessToken: tokenData['accessToken'],
        refreshToken: refreshToken,
        expiresIn: tokenData['expiresIn'] ?? 3600,
      );

      await _secureStorage.write(
        key: _tokenKey,
        value: json.encode(tokens.toJson()),
      );

      return tokens;
    } catch (e) {
      if (e is MirimOAuthException) rethrow;
      throw MirimOAuthException('Failed to refresh tokens: ${e.toString()}');
    }
  }

  Future<MirimUser> _fetchUserInfo(String accessToken) async {
    try {
      final response = await http.get(
        Uri.parse('$oauthServerUrl/api/v1/user'),
        headers: {
          'Content-Type': 'application/json',
          'Authorization': 'Bearer $accessToken',
        },
      );

      if (response.statusCode != 200) {
        throw MirimOAuthException(
          'Failed to fetch user info',
          errorCode: response.statusCode,
          data: response.body,
        );
      }

      final Map<String, dynamic> data = json.decode(response.body);
      if (data['status'] != 200) {
        throw MirimOAuthException(
          data['message'] ?? 'Failed to fetch user info',
          errorCode: data['status'],
          data: data,
        );
      }

      final userData = data['data'];
      final user = MirimUser.fromJson(userData);

      await _secureStorage.write(
        key: _userKey,
        value: json.encode(user.toJson()),
      );

      return user;
    } catch (e) {
      if (e is MirimOAuthException) rethrow;
      throw MirimOAuthException('Failed to fetch user info: ${e.toString()}');
    }
  }
}