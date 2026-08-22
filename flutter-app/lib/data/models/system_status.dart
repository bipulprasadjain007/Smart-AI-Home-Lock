class SystemStatus {
  const SystemStatus({
    required this.protocolVersion,
    required this.legacyEnabled,
    required this.mediumUnlockEnabled,
    required this.adaptiveLearningEnabled,
    required this.clockSkewSeconds,
    required this.replayTtlSeconds,
  });

  final int protocolVersion;
  final bool legacyEnabled;
  final bool mediumUnlockEnabled;
  final bool adaptiveLearningEnabled;
  final int clockSkewSeconds;
  final int replayTtlSeconds;

  factory SystemStatus.fromJson(Map<String, Object?> json) {
    return SystemStatus(
      protocolVersion: _integer(json['protocol_version'], 0),
      legacyEnabled: json['v1_legacy_enabled'] == true,
      mediumUnlockEnabled: json['v2_allow_medium_unlock'] == true,
      adaptiveLearningEnabled: json['v2_adaptive_learning'] == true,
      clockSkewSeconds: _integer(json['clock_skew_seconds'], 0),
      replayTtlSeconds: _integer(json['replay_ttl_seconds'], 0),
    );
  }

  bool get hardened =>
      protocolVersion == 2 && !legacyEnabled && !mediumUnlockEnabled;

  static int _integer(Object? value, int fallback) {
    return value is num ? value.toInt() : fallback;
  }
}
