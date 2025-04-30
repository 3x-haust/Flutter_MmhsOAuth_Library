class MirimUser {
  final String id;
  final String email;
  final String? nickname;
  final String? major;
  final bool? isGraduated;
  final String? admission;
  final String? role;
  final int? generation;

  MirimUser({
    required this.id,
    required this.email,
    this.nickname,
    this.major,
    this.isGraduated,
    this.admission,
    this.role,
    this.generation,
  });

  factory MirimUser.fromJson(Map<String, dynamic> json) {
    return MirimUser(
      id: json['id']?.toString() ?? '',
      email: json['email']?.toString() ?? '',
      nickname: json['nickname']?.toString(),
      major: json['major']?.toString(),
      isGraduated: json['isGraduated'] is bool ? json['isGraduated'] : null,
      admission: json['admission']?.toString(),
      role: json['role']?.toString(),
      generation: json['generation'] is int ? json['generation'] : null,
    );
  }

  Map<String, dynamic> toJson() => {
        'id': id,
        'email': email,
        'nickname': nickname,
        'major': major,
        'isGraduated': isGraduated,
        'admission': admission,
        'role': role,
        'generation': generation,
      };
}