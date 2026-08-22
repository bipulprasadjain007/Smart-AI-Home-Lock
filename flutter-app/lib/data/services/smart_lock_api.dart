import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:http/http.dart' as http;

import '../models/access_log.dart';
import '../models/system_status.dart';

typedef TokenProvider = Future<String?> Function();

class EnrollmentPhoto {
  const EnrollmentPhoto({required this.bytes, required this.filename});

  final Uint8List bytes;
  final String filename;
}

class ApiException implements Exception {
  const ApiException(this.message, {this.statusCode});

  final String message;
  final int? statusCode;

  @override
  String toString() => message;
}

class SmartLockApi {
  SmartLockApi({
    required Uri baseUri,
    required TokenProvider tokenProvider,
    http.Client? client,
    this.timeout = const Duration(seconds: 30),
  })  : _baseUri = baseUri,
        _tokenProvider = tokenProvider,
        _client = client ?? http.Client();

  final Uri _baseUri;
  final TokenProvider _tokenProvider;
  final http.Client _client;
  final Duration timeout;

  Uri _uri(String path, [Map<String, String>? query]) {
    final String root = _baseUri.toString().replaceFirst(RegExp(r'/$'), '');
    return Uri.parse('$root$path').replace(queryParameters: query);
  }

  Future<Map<String, Object?>> health() async {
    final http.Response response = await _client.get(_uri('/api/health')).timeout(timeout);
    return _decode(response);
  }

  Future<SystemStatus> systemStatus() async {
    final http.Response response = await _authorizedGet('/api/system_config');
    return SystemStatus.fromJson(_decode(response));
  }

  Future<AccessLogPage> logs({
    String? userId,
    Object? cursor,
    int limit = 25,
  }) async {
    final Map<String, String> query = <String, String>{'limit': '$limit'};
    if (userId != null && userId.trim().isNotEmpty) {
      query['user_id'] = userId.trim();
    }
    if (cursor != null) {
      query['cursor'] = jsonEncode(cursor);
    }
    final http.Response response = await _authorizedGet('/api/logs', query);
    final Map<String, Object?> body = _decode(response);
    final Object? rawLogs = body['logs'];
    if (rawLogs is! List<Object?>) {
      throw const ApiException('The server returned an invalid log list.');
    }
    return AccessLogPage(
      logs: rawLogs
          .whereType<Map<String, Object?>>()
          .map(AccessLog.fromJson)
          .toList(growable: false),
      nextCursor: body['next_cursor'],
    );
  }

  Future<void> registerUser(String userId, List<EnrollmentPhoto> photos) async {
    if (photos.length != 5) {
      throw const ApiException('Exactly five enrollment photos are required.');
    }
    final http.MultipartRequest request = http.MultipartRequest(
      'POST',
      _uri('/api/register'),
    )..fields['user_id'] = userId;
    await _authorize(request);
    request.headers['X-Admin-Payload-Protection'] = 'tls';
    for (int index = 0; index < photos.length; index++) {
      final EnrollmentPhoto photo = photos[index];
      request.files.add(
        http.MultipartFile.fromBytes(
          'image${index + 1}',
          photo.bytes,
          filename: photo.filename,
        ),
      );
    }
    final http.StreamedResponse streamed = await _client.send(request).timeout(timeout);
    await _decodeStreamed(streamed);
  }

  Future<void> setPin(String userId, String pin) async {
    final http.Request request = http.Request(
      'POST',
      _uri('/api/set_pin', <String, String>{'user_id': userId}),
    )
      ..bodyBytes = ascii.encode(pin)
      ..headers['Content-Type'] = 'application/octet-stream'
      ..headers['X-Admin-Payload-Protection'] = 'tls';
    await _authorize(request);
    final http.StreamedResponse response = await _client.send(request).timeout(timeout);
    await _decodeStreamed(response);
  }

  Future<void> deleteUser(String userId) async {
    final http.Request request = http.Request(
      'DELETE',
      _uri('/api/user', <String, String>{'user_id': userId}),
    );
    await _authorize(request);
    final http.StreamedResponse response = await _client.send(request).timeout(timeout);
    await _decodeStreamed(response);
  }

  Future<void> registerNotificationDevice({
    required String userId,
    required String token,
    required String platform,
    required String deviceName,
  }) async {
    await _postJson('/api/register_device', <String, Object?>{
      'user_id': userId,
      'token': token,
      'platform': platform,
      'device_name': deviceName,
    });
  }

  Future<void> deregisterNotificationDevice({
    required String userId,
    required String token,
    required String platform,
  }) async {
    await _postJson('/api/deregister_device', <String, Object?>{
      'user_id': userId,
      'token': token,
      'platform': platform,
    });
  }

  Future<http.Response> _authorizedGet(
    String path, [
    Map<String, String>? query,
  ]) async {
    final String token = await _token();
    return _client.get(
      _uri(path, query),
      headers: <String, String>{'Authorization': 'Bearer $token'},
    ).timeout(timeout);
  }

  Future<void> _postJson(String path, Map<String, Object?> payload) async {
    final String token = await _token();
    final http.Response response = await _client
        .post(
          _uri(path),
          headers: <String, String>{
            'Authorization': 'Bearer $token',
            'Content-Type': 'application/json',
          },
          body: jsonEncode(payload),
        )
        .timeout(timeout);
    _decode(response);
  }

  Future<void> _authorize(http.BaseRequest request) async {
    request.headers['Authorization'] = 'Bearer ${await _token()}';
  }

  Future<String> _token() async {
    final String? token = await _tokenProvider();
    if (token == null || token.isEmpty) {
      throw const ApiException('Your session has expired. Sign in again.', statusCode: 401);
    }
    return token;
  }

  Map<String, Object?> _decode(http.Response response) {
    return _decodeBody(response.statusCode, response.body);
  }

  Future<Map<String, Object?>> _decodeStreamed(http.StreamedResponse response) async {
    return _decodeBody(response.statusCode, await response.stream.bytesToString());
  }

  Map<String, Object?> _decodeBody(int statusCode, String rawBody) {
    Object? decoded;
    try {
      decoded = rawBody.isEmpty ? <String, Object?>{} : jsonDecode(rawBody);
    } on FormatException {
      throw ApiException('The server returned an invalid response.', statusCode: statusCode);
    }
    final Map<String, Object?> body = decoded is Map<Object?, Object?>
        ? decoded.map(
            (Object? key, Object? value) => MapEntry(key.toString(), value),
          )
        : <String, Object?>{};
    if (statusCode < 200 || statusCode >= 300) {
      final String message = body['error']?.toString() ?? 'Request failed.';
      throw ApiException(message, statusCode: statusCode);
    }
    return body;
  }

  void close() => _client.close();
}
