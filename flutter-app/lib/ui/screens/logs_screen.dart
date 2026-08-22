import 'package:flutter/material.dart';

import '../../core/validation/validators.dart';
import '../../data/models/access_log.dart';
import '../../data/services/smart_lock_api.dart';
import '../widgets/common.dart';

class LogsScreen extends StatefulWidget {
  const LogsScreen({required this.api, super.key});

  final SmartLockApi api;

  @override
  State<LogsScreen> createState() => _LogsScreenState();
}

class _LogsScreenState extends State<LogsScreen> {
  final TextEditingController _filter = TextEditingController();
  final List<AccessLog> _logs = <AccessLog>[];
  Object? _cursor;
  bool _loading = true;
  bool _loadingMore = false;
  String? _error;

  @override
  void initState() {
    super.initState();
    _load(reset: true);
  }

  @override
  void dispose() {
    _filter.dispose();
    super.dispose();
  }

  Future<void> _load({required bool reset}) async {
    if (reset) {
      setState(() {
        _loading = true;
        _error = null;
        _cursor = null;
      });
    } else {
      setState(() => _loadingMore = true);
    }
    try {
      final AccessLogPage page = await widget.api.logs(
        userId: _filter.text.trim().isEmpty ? null : _filter.text.trim(),
        cursor: reset ? null : _cursor,
      );
      if (mounted) {
        setState(() {
          if (reset) {
            _logs.clear();
          }
          _logs.addAll(page.logs);
          _cursor = page.nextCursor;
        });
      }
    } catch (error) {
      if (mounted) {
        setState(() => _error = error.toString());
      }
    } finally {
      if (mounted) {
        setState(() {
          _loading = false;
          _loadingMore = false;
        });
      }
    }
  }

  void _applyFilter() {
    final String value = _filter.text.trim();
    if (value.isNotEmpty && validateUserId(value) != null) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Enter a valid user ID or leave it blank.')),
      );
      return;
    }
    _load(reset: true);
  }

  @override
  Widget build(BuildContext context) {
    return RefreshIndicator(
      onRefresh: () => _load(reset: true),
      child: ListView(
        padding: const EdgeInsets.fromLTRB(20, 12, 20, 32),
        children: <Widget>[
          const PageIntro(
            title: 'Access history',
            description: 'Review face and PIN decisions, newest first.',
          ),
          const SizedBox(height: 20),
          TextField(
            controller: _filter,
            textInputAction: TextInputAction.search,
            onSubmitted: (_) => _applyFilter(),
            decoration: InputDecoration(
              labelText: 'Filter by user ID',
              prefixIcon: const Icon(Icons.search),
              suffixIcon: IconButton(
                tooltip: 'Apply filter',
                onPressed: _applyFilter,
                icon: const Icon(Icons.arrow_forward),
              ),
            ),
          ),
          const SizedBox(height: 16),
          if (_loading)
            const Center(child: Padding(
              padding: EdgeInsets.all(40),
              child: CircularProgressIndicator(),
            ))
          else if (_error != null && _logs.isEmpty)
            ErrorPanel(message: _error!, onRetry: () => _load(reset: true))
          else if (_logs.isEmpty)
            const SectionCard(
              child: Padding(
                padding: EdgeInsets.symmetric(vertical: 24),
                child: Column(
                  children: <Widget>[
                    Icon(Icons.history_toggle_off, size: 40),
                    SizedBox(height: 10),
                    Text('No access events found.'),
                  ],
                ),
              ),
            )
          else ...<Widget>[
            for (final AccessLog log in _logs) ...<Widget>[
              _LogCard(log: log),
              const SizedBox(height: 10),
            ],
            if (_error != null)
              Padding(
                padding: const EdgeInsets.only(bottom: 8),
                child: Text(
                  _error!,
                  textAlign: TextAlign.center,
                  style: TextStyle(color: Theme.of(context).colorScheme.error),
                ),
              ),
            if (_cursor != null)
              OutlinedButton.icon(
                onPressed: _loadingMore ? null : () => _load(reset: false),
                icon: _loadingMore
                    ? const SizedBox.square(
                        dimension: 18,
                        child: CircularProgressIndicator(strokeWidth: 2),
                      )
                    : const Icon(Icons.expand_more),
                label: const Text('Load more'),
              ),
          ],
        ],
      ),
    );
  }
}

class _LogCard extends StatelessWidget {
  const _LogCard({required this.log});

  final AccessLog log;

  @override
  Widget build(BuildContext context) {
    final bool allowed = log.allowed;
    final Color statusColor = allowed ? const Color(0xFF067647) : const Color(0xFFB42318);
    return SectionCard(
      padding: const EdgeInsets.all(16),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: <Widget>[
          CircleAvatar(
            backgroundColor: statusColor.withAlpha(28),
            child: Icon(
              log.method == 'PIN' ? Icons.pin_outlined : Icons.face_outlined,
              color: statusColor,
            ),
          ),
          const SizedBox(width: 14),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: <Widget>[
                Row(
                  children: <Widget>[
                    Expanded(
                      child: Text(log.userId, style: Theme.of(context).textTheme.titleMedium),
                    ),
                    DecoratedBox(
                      decoration: BoxDecoration(
                        color: statusColor.withAlpha(24),
                        borderRadius: BorderRadius.circular(999),
                      ),
                      child: Padding(
                        padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
                        child: Text(
                          allowed ? 'ALLOWED' : 'DENIED',
                          style: TextStyle(
                            color: statusColor,
                            fontSize: 12,
                            fontWeight: FontWeight.w700,
                          ),
                        ),
                      ),
                    ),
                  ],
                ),
                const SizedBox(height: 5),
                Text('${log.method} • ${_formatTime(log.timestamp)}'),
                if (log.similarity != null) ...<Widget>[
                  const SizedBox(height: 4),
                  Text(
                    '${log.confidence ?? 'Unknown'} confidence • ${(log.similarity! * 100).toStringAsFixed(1)}%',
                  ),
                ],
              ],
            ),
          ),
        ],
      ),
    );
  }

  static String _formatTime(DateTime? value) {
    if (value == null) {
      return 'Unknown time';
    }
    final DateTime local = value.toLocal();
    String two(int number) => number.toString().padLeft(2, '0');
    return '${local.year}-${two(local.month)}-${two(local.day)} '
        '${two(local.hour)}:${two(local.minute)}';
  }
}
