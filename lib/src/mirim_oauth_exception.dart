class MirimOAuthException implements Exception {
  final String message;
  final int? errorCode;
  final dynamic data;

  MirimOAuthException(this.message, {this.errorCode, this.data});

  @override
  String toString() => 'MirimOAuthException: $message (Code: $errorCode)';
}