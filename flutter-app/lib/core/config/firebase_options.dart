import 'package:firebase_core/firebase_core.dart';
import 'package:flutter/foundation.dart';

import 'app_config.dart';

class AppFirebaseOptions {
  const AppFirebaseOptions._();

  static const String _apiKey = String.fromEnvironment('FIREBASE_API_KEY');
  static const String _appId = String.fromEnvironment('FIREBASE_APP_ID');
  static const String _messagingSenderId = String.fromEnvironment(
    'FIREBASE_MESSAGING_SENDER_ID',
  );
  static const String _projectId = String.fromEnvironment('FIREBASE_PROJECT_ID');
  static const String _authDomain = String.fromEnvironment('FIREBASE_AUTH_DOMAIN');
  static const String _storageBucket = String.fromEnvironment(
    'FIREBASE_STORAGE_BUCKET',
  );
  static const String _iosBundleId = String.fromEnvironment(
    'FIREBASE_IOS_BUNDLE_ID',
    defaultValue: 'com.bipulprasadjain.smartAiHomeLock',
  );

  static FirebaseOptions get currentPlatform => FirebaseOptions(
        apiKey: _apiKey,
        appId: _appId,
        messagingSenderId: _messagingSenderId,
        projectId: _projectId,
        authDomain: _authDomain.isEmpty ? null : _authDomain,
        storageBucket: _storageBucket.isEmpty ? null : _storageBucket,
        iosBundleId: defaultTargetPlatform == TargetPlatform.iOS
            ? _iosBundleId
            : null,
      );

  static void validate() {
    final List<String> missing = <String>[
      if (_apiKey.isEmpty) 'FIREBASE_API_KEY',
      if (_appId.isEmpty) 'FIREBASE_APP_ID',
      if (_messagingSenderId.isEmpty) 'FIREBASE_MESSAGING_SENDER_ID',
      if (_projectId.isEmpty) 'FIREBASE_PROJECT_ID',
    ];
    if (missing.isNotEmpty) {
      throw ConfigurationException(
        'Missing Firebase configuration: ${missing.join(', ')}.',
      );
    }
  }
}
