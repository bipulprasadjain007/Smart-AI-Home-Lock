final RegExp _userIdPattern = RegExp(r'^[A-Za-z0-9_-]{1,100}$');
final RegExp _pinPattern = RegExp(r'^\d{6}$');

String? validateUserId(String? value) {
  final String candidate = value?.trim() ?? '';
  if (!_userIdPattern.hasMatch(candidate)) {
    return 'Use 1–100 letters, numbers, underscores, or hyphens.';
  }
  return null;
}

String? validatePin(String? value) {
  if (!_pinPattern.hasMatch(value ?? '')) {
    return 'Enter exactly six digits.';
  }
  return null;
}

String? validateEmail(String? value) {
  final String candidate = value?.trim() ?? '';
  if (!RegExp(r'^[^@\s]+@[^@\s]+\.[^@\s]+$').hasMatch(candidate)) {
    return 'Enter a valid email address.';
  }
  return null;
}
