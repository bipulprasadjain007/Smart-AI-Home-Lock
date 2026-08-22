import 'package:flutter_test/flutter_test.dart';
import 'package:smart_ai_home_lock_frontend/core/validation/validators.dart';

void main() {
  test('user IDs match the server grammar', () {
    expect(validateUserId('bipul_home-1'), isNull);
    expect(validateUserId('../admin'), isNotNull);
    expect(validateUserId(''), isNotNull);
  });

  test('PIN validation accepts exactly six ASCII digits', () {
    expect(validatePin('123456'), isNull);
    expect(validatePin('12345'), isNotNull);
    expect(validatePin('１２３４５６'), isNotNull);
  });

  test('email validation rejects malformed values', () {
    expect(validateEmail('admin@example.com'), isNull);
    expect(validateEmail('not-an-email'), isNotNull);
  });
}
