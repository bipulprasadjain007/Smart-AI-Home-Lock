import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:smart_ai_home_lock_frontend/main.dart';

void main() {
  testWidgets('configuration failure is actionable', (WidgetTester tester) async {
    await tester.pumpWidget(
      const ConfigurationErrorApp(message: 'Missing FIREBASE_PROJECT_ID.'),
    );

    expect(find.byIcon(Icons.settings_alert), findsOneWidget);
    expect(find.text('App configuration required'), findsOneWidget);
    expect(find.textContaining('FIREBASE_PROJECT_ID'), findsOneWidget);
  });
}
