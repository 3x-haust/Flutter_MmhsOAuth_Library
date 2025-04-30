class AuthTokens {
  final String accessToken;
  final String refreshToken;
  final int expiresIn;
  final DateTime issuedAt;

  AuthTokens({
    required this.accessToken,
    required this.refreshToken,
    required this.expiresIn,
    DateTime? issuedAt,
  }) : issuedAt = issuedAt ?? DateTime.now();

  bool get isExpired {
    final expirationDate = issuedAt.add(Duration(seconds: expiresIn));
    return DateTime.now().isAfter(expirationDate);
  }

  Map<String, dynamic> toJson() => {
        'access_token': accessToken,
        'refresh_token': refreshToken,
        'expires_in': expiresIn,
        'issued_at': issuedAt.toIso8601String(),
      };

  factory AuthTokens.fromJson(Map<String, dynamic> json) {
    return AuthTokens(
      accessToken: json['access_token'] as String,
      refreshToken: json['refresh_token'] as String,
      expiresIn: json['expires_in'] as int,
      issuedAt: json['issued_at'] != null
          ? DateTime.parse(json['issued_at'])
          : DateTime.now(),
    );
  }
}