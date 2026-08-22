# Flutter administrator app

This mobile client is the administrative frontend for Smart AI Home Lock. It
supports Firebase email/password sign-in with an `admin: true` custom claim,
cloud health and policy status, five-photo biometric enrollment, PIN setup,
paginated access logs, notification registration, and cascade user deletion.

It intentionally does not implement face unlock, PIN unlock, device-time
bootstrap, or protocol-v2 HMAC signing. Those actuator operations belong only
to provisioned ESP32 devices. No AES key, device HMAC key, service-account key,
or Firebase administrator credential is stored in this app.

## Prerequisites

- Flutter stable with Dart 3.4 or newer
- Android SDK 24+ or iOS 13+
- Firebase Authentication with Email/Password enabled
- Firebase Cloud Messaging configured for the Android/iOS application
- An administrator account with Firebase custom claim `admin: true`
- The deployed cloud function HTTPS URL

Create the standard native platform projects once after cloning:

```bash
cd flutter-app
bash tool/bootstrap_platforms.sh
flutter pub get
```

On macOS, the bootstrap adds the iOS camera and photo-library descriptions.
Enable Push Notifications and Background Modes → Remote notifications for the
Runner target, then connect its APNs key in Firebase. Android notification and
image-picker integration is supplied by the plugins; the bootstrap sets API 24.

## Configuration

Supply public client configuration at build time. Firebase web/client API keys
identify a Firebase project; they are not administrator or server credentials.
Keep environment-specific values outside source control:

```bash
flutter run \
  --dart-define=API_BASE_URL=https://REGION-PROJECT.cloudfunctions.net/smart-lock \
  --dart-define=FIREBASE_API_KEY=... \
  --dart-define=FIREBASE_APP_ID=... \
  --dart-define=FIREBASE_MESSAGING_SENDER_ID=... \
  --dart-define=FIREBASE_PROJECT_ID=... \
  --dart-define=FIREBASE_AUTH_DOMAIN=PROJECT.firebaseapp.com \
  --dart-define=FIREBASE_STORAGE_BUCKET=PROJECT.firebasestorage.app
```

`API_BASE_URL` must use HTTPS in release builds. Emulator-only HTTP can be
enabled for `localhost`, `127.0.0.1`, or Android emulator host `10.0.2.2` with
`--dart-define=ALLOW_INSECURE_LOCALHOST=true`; it is rejected in release mode.

The administrator custom claim must be assigned from a trusted Admin SDK or
Firebase administrative environment. Never let this app assign its own claim.
After changing a claim, sign out and sign in again to refresh the ID token.

## Validation

```bash
flutter pub get
flutter analyze
flutter test
flutter build apk --debug \
  --dart-define=API_BASE_URL=https://example.invalid \
  --dart-define=FIREBASE_API_KEY=test-api-key \
  --dart-define=FIREBASE_APP_ID=1:1:android:test \
  --dart-define=FIREBASE_MESSAGING_SENDER_ID=1 \
  --dart-define=FIREBASE_PROJECT_ID=test-project
```

Before release, test camera capture, Firebase sign-in/custom claims, FCM/APNs,
five-photo enrollment, PIN setup, deletion, and log pagination against a
staging deployment. Biometric photos are held only in memory until upload and
are cleared after successful enrollment.
