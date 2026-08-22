import 'package:flutter/foundation.dart';

class ConfigurationException implements Exception {
  const ConfigurationException(this.message);

  final String message;

  @override
  String toString() => message;
}

class AppConfig {
  const AppConfig._();

  static const String _rawApiBaseUrl = String.fromEnvironment('API_BASE_URL');
  static const bool _allowInsecureLocalhost = bool.fromEnvironment(
    'ALLOW_INSECURE_LOCALHOST',
  );

  static Uri get apiBaseUri {
    final Uri? uri = Uri.tryParse(_rawApiBaseUrl.trim());
    if (uri == null || !uri.hasScheme || uri.host.isEmpty) {
      throw const ConfigurationException(
        'API_BASE_URL must be a complete service URL.',
      );
    }
    if (uri.query.isNotEmpty || uri.fragment.isNotEmpty) {
      throw const ConfigurationException(
        'API_BASE_URL must not contain a query or fragment.',
      );
    }
    if (uri.scheme != 'https' && !_allowedLocalHttp(uri)) {
      throw const ConfigurationException(
        'API_BASE_URL must use HTTPS.',
      );
    }
    return uri.replace(path: uri.path.replaceFirst(RegExp(r'/$'), ''));
  }

  static bool _allowedLocalHttp(Uri uri) {
    if (kReleaseMode || !_allowInsecureLocalhost || uri.scheme != 'http') {
      return false;
    }
    return const <String>{'localhost', '127.0.0.1', '10.0.2.2'}.contains(uri.host);
  }

  static void validate() {
    apiBaseUri;
  }
}
