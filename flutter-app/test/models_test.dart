import 'package:flutter_test/flutter_test.dart';
import 'package:smart_ai_home_lock_frontend/data/models/access_log.dart';
import 'package:smart_ai_home_lock_frontend/data/models/system_status.dart';

void main() {
  test('access log parses ISO timestamp and numeric similarity', () {
    final AccessLog log = AccessLog.fromJson(<String, Object?>{
      'log_id': 'log-1',
      'user_id': 'alice',
      'timestamp': '2026-08-22T10:00:00Z',
      'method': 'FACE',
      'confidence': 'HIGH',
      'similarity': 0.91,
    });

    expect(log.id, 'log-1');
    expect(log.timestamp, DateTime.utc(2026, 8, 22, 10));
    expect(log.similarity, 0.91);
    expect(log.allowed, isTrue);
  });

  test('PIN denial is not represented as an allowed event', () {
    final AccessLog log = AccessLog.fromJson(<String, Object?>{
      'method': 'PIN',
      'success': false,
    });
    expect(log.allowed, isFalse);
  });

  test('system status identifies hardened production policy', () {
    final SystemStatus status = SystemStatus.fromJson(<String, Object?>{
      'protocol_version': 2,
      'v1_legacy_enabled': false,
      'v2_allow_medium_unlock': false,
      'v2_adaptive_learning': false,
      'clock_skew_seconds': 60,
      'replay_ttl_seconds': 120,
    });
    expect(status.hardened, isTrue);
  });
}
