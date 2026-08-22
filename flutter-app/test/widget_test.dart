import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  testWidgets('Flutter test environment renders Material widgets', (
    WidgetTester tester,
  ) async {
    await tester.pumpWidget(
      const MaterialApp(home: Scaffold(body: Text('Home Lock Admin'))),
    );

    expect(find.text('Home Lock Admin'), findsOneWidget);
  });
}
