import 'package:firebase_auth/firebase_auth.dart';
import 'package:firebase_core/firebase_core.dart';
import 'package:firebase_messaging/firebase_messaging.dart';
import 'package:flutter/material.dart';

import 'app.dart';
import 'core/config/app_config.dart';
import 'core/config/firebase_options.dart';
import 'data/services/admin_auth_service.dart';
import 'data/services/notification_service.dart';
import 'data/services/smart_lock_api.dart';

@pragma('vm:entry-point')
Future<void> firebaseMessagingBackgroundHandler(RemoteMessage message) async {
  if (Firebase.apps.isEmpty) {
    AppFirebaseOptions.validate();
    await Firebase.initializeApp(options: AppFirebaseOptions.currentPlatform);
  }
}

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  try {
    AppConfig.validate();
    AppFirebaseOptions.validate();
    await Firebase.initializeApp(options: AppFirebaseOptions.currentPlatform);
    FirebaseMessaging.onBackgroundMessage(firebaseMessagingBackgroundHandler);

    final AdminAuthService auth = AdminAuthService(FirebaseAuth.instance);
    final NotificationService notifications = NotificationService(
      FirebaseMessaging.instance,
    );
    await notifications.initialize();
    final SmartLockApi api = SmartLockApi(
      baseUri: AppConfig.apiBaseUri,
      tokenProvider: auth.idToken,
    );
    runApp(SmartLockApp(auth: auth, api: api, notifications: notifications));
  } on ConfigurationException catch (error) {
    runApp(ConfigurationErrorApp(message: error.message));
  } on FirebaseException {
    runApp(
      const ConfigurationErrorApp(
        message: 'Firebase could not initialize. Check the app configuration.',
      ),
    );
  }
}

class ConfigurationErrorApp extends StatelessWidget {
  const ConfigurationErrorApp({required this.message, super.key});

  final String message;

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      debugShowCheckedModeBanner: false,
      home: Scaffold(
        body: Center(
          child: Padding(
            padding: const EdgeInsets.all(24),
            child: ConstrainedBox(
              constraints: const BoxConstraints(maxWidth: 480),
              child: Column(
                mainAxisSize: MainAxisSize.min,
                children: <Widget>[
                  const Icon(Icons.settings_outlined, size: 52),
                  const SizedBox(height: 16),
                  const Text(
                    'App configuration required',
                    style: TextStyle(fontSize: 24, fontWeight: FontWeight.w700),
                  ),
                  const SizedBox(height: 10),
                  Text(message, textAlign: TextAlign.center),
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }
}
