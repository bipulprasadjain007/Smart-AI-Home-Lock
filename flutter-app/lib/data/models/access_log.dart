class AccessLog {
  const AccessLog({
    required this.id,
    required this.userId,
    required this.timestamp,
    required this.method,
    this.confidence,
    this.similarity,
    this.success,
  });

  final String id;
  final String userId;
  final DateTime? timestamp;
  final String method;
  final String? confidence;
  final double? similarity;
  final bool? success;

  bool get allowed => method == 'PIN' ? success == true : confidence != null;

  factory AccessLog.fromJson(Map<String, Object?> json) {
    return AccessLog(
      id: json['log_id']?.toString() ?? '',
      userId: json['user_id']?.toString() ?? 'unknown',
      timestamp: _parseTimestamp(json['timestamp']),
      method: json['method']?.toString().toUpperCase() ?? 'UNKNOWN',
      confidence: json['confidence']?.toString(),
      similarity: _asDouble(json['similarity']),
      success: json['success'] is bool ? json['success'] as bool : null,
    );
  }

  static DateTime? _parseTimestamp(Object? value) {
    if (value is num) {
      return DateTime.fromMillisecondsSinceEpoch(
        (value.toDouble() * 1000).round(),
        isUtc: true,
      );
    }
    if (value is String) {
      return DateTime.tryParse(value)?.toUtc();
    }
    return null;
  }

  static double? _asDouble(Object? value) {
    return value is num ? value.toDouble() : null;
  }
}

class AccessLogPage {
  const AccessLogPage({required this.logs, this.nextCursor});

  final List<AccessLog> logs;
  final Object? nextCursor;
}
