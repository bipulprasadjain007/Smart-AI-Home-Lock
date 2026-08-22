import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:smart_ai_home_lock_frontend/data/services/smart_lock_api.dart';

void main() {
  test('health uses the canonical public endpoint', () async {
    final MockClient client = MockClient((http.Request request) async {
      expect(request.url.toString(), 'https://lock.example/api/health');
      expect(request.headers.containsKey('Authorization'), isFalse);
      return http.Response('{"status":"ok"}', 200);
    });
    final SmartLockApi api = SmartLockApi(
      baseUri: Uri.parse('https://lock.example'),
      tokenProvider: () async => 'token',
      client: client,
    );

    expect((await api.health())['status'], 'ok');
  });

  test('logs attach bearer auth and preserve stable cursor JSON', () async {
    final MockClient client = MockClient((http.Request request) async {
      expect(request.headers['Authorization'], 'Bearer admin-token');
      expect(request.url.path, '/api/logs');
      expect(
        jsonDecode(request.url.queryParameters['cursor']!),
        <String, Object?>{'timestamp': '2026-08-22T00:00:00Z', 'log_id': 'abc'},
      );
      return http.Response(
        '{"logs":[{"log_id":"1","user_id":"alice","method":"PIN","success":true}],"next_cursor":null}',
        200,
      );
    });
    final SmartLockApi api = SmartLockApi(
      baseUri: Uri.parse('https://lock.example'),
      tokenProvider: () async => 'admin-token',
      client: client,
    );

    final page = await api.logs(
      cursor: <String, Object?>{
        'timestamp': '2026-08-22T00:00:00Z',
        'log_id': 'abc',
      },
    );
    expect(page.logs.single.allowed, isTrue);
    expect(page.nextCursor, isNull);
  });

  test('server error is surfaced without accepting malformed success', () async {
    final SmartLockApi api = SmartLockApi(
      baseUri: Uri.parse('https://lock.example'),
      tokenProvider: () async => 'token',
      client: MockClient(
        (_) async => http.Response('{"error":"admin authorization required"}', 403),
      ),
    );

    await expectLater(
      api.systemStatus(),
      throwsA(
        isA<ApiException>()
            .having((ApiException error) => error.statusCode, 'statusCode', 403)
            .having(
              (ApiException error) => error.message,
              'message',
              'admin authorization required',
            ),
      ),
    );
  });

  test('PIN update uses administrator TLS payload protection', () async {
    final MockClient client = MockClient((http.Request request) async {
      expect(request.method, 'POST');
      expect(request.url.path, '/api/set_pin');
      expect(request.url.queryParameters['user_id'], 'alice');
      expect(request.headers['Authorization'], 'Bearer admin-token');
      expect(request.headers['X-Admin-Payload-Protection'], 'tls');
      expect(request.headers['Content-Type'], 'application/octet-stream');
      expect(request.body, '123456');
      return http.Response('{"status":"PIN_SET"}', 200);
    });
    final SmartLockApi api = SmartLockApi(
      baseUri: Uri.parse('https://lock.example'),
      tokenProvider: () async => 'admin-token',
      client: client,
    );

    await api.setPin('alice', '123456');
  });

  test('enrollment sends exactly five multipart photos over TLS mode', () async {
    final MockClient client = MockClient((http.Request request) async {
      expect(request.method, 'POST');
      expect(request.url.path, '/api/register');
      expect(request.headers['Authorization'], 'Bearer admin-token');
      expect(request.headers['X-Admin-Payload-Protection'], 'tls');
      expect(request.headers['Content-Type'], startsWith('multipart/form-data;'));
      expect(request.body, contains('name="user_id"'));
      expect(request.body, contains('alice'));
      for (int index = 1; index <= 5; index++) {
        expect(request.body, contains('name="image$index"'));
        expect(request.body, contains('filename="photo$index.jpg"'));
      }
      return http.Response('{"status":"REGISTERED"}', 200);
    });
    final SmartLockApi api = SmartLockApi(
      baseUri: Uri.parse('https://lock.example'),
      tokenProvider: () async => 'admin-token',
      client: client,
    );
    final List<EnrollmentPhoto> photos = List<EnrollmentPhoto>.generate(
      5,
      (int index) => EnrollmentPhoto(
        bytes: Uint8List.fromList(<int>[index + 1, index + 2]),
        filename: 'photo${index + 1}.jpg',
      ),
    );

    await api.registerUser('alice', photos);
  });

  test('enrollment rejects incomplete photo sets before network access', () async {
    final MockClient client = MockClient((http.Request request) async {
      fail('The client must reject incomplete enrollment locally.');
    });
    final SmartLockApi api = SmartLockApi(
      baseUri: Uri.parse('https://lock.example'),
      tokenProvider: () async => 'admin-token',
      client: client,
    );

    await expectLater(
      api.registerUser('alice', const <EnrollmentPhoto>[]),
      throwsA(isA<ApiException>()),
    );
  });
}
