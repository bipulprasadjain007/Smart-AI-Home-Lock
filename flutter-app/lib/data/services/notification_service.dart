import 'dart:async';

import 'package:firebase_messaging/firebase_messaging.dart';
import 'package:flutter/foundation.dart';

class NotificationService {
  NotificationService(this._messaging);

  final FirebaseMessaging _messaging;
  final StreamController<RemoteMessage> _foregroundMessages =
      StreamController<RemoteMessage>.broadcast();
  StreamSubscription<RemoteMessage>? _messageSubscription;

  Stream<RemoteMessage> get foregroundMessages => _foregroundMessages.stream;
  Stream<String> get tokenRefreshes => _messaging.onTokenRefresh;

  Future<void> initialize() async {
    await _messaging.setForegroundNotificationPresentationOptions(
      alert: true,
      badge: true,
      sound: true,
    );
    _messageSubscription ??= FirebaseMessaging.onMessage.listen(
      _foregroundMessages.add,
    );
  }

  Future<String> requestToken() async {
    final NotificationSettings settings = await _messaging.requestPermission(
      alert: true,
      badge: true,
      sound: true,
      provisional: false,
    );
    if (settings.authorizationStatus == AuthorizationStatus.denied) {
      throw StateError('Notification permission was denied.');
    }
    final String? token = await _messaging.getToken();
    if (token == null || token.isEmpty) {
      throw StateError('A notification token is not available yet.');
    }
    return token;
  }

  String get platform {
    if (kIsWeb) {
      return 'web';
    }
    return switch (defaultTargetPlatform) {
      TargetPlatform.iOS => 'ios',
      _ => 'android',
    };
  }

  String get deviceName => switch (defaultTargetPlatform) {
        TargetPlatform.iOS => 'iPhone or iPad',
        TargetPlatform.android => 'Android device',
        _ => 'Flutter client',
      };

  Future<void> dispose() async {
    await _messageSubscription?.cancel();
    await _foregroundMessages.close();
  }
}
