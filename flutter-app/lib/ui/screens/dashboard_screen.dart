import 'package:flutter/material.dart';

import '../../data/models/system_status.dart';
import '../../data/services/smart_lock_api.dart';
import '../widgets/common.dart';

class DashboardScreen extends StatefulWidget {
  const DashboardScreen({required this.api, super.key});

  final SmartLockApi api;

  @override
  State<DashboardScreen> createState() => _DashboardScreenState();
}

class _DashboardScreenState extends State<DashboardScreen> {
  SystemStatus? _status;
  bool _healthy = false;
  bool _loading = true;
  String? _error;

  @override
  void initState() {
    super.initState();
    _refresh();
  }

  Future<void> _refresh() async {
    setState(() {
      _loading = true;
      _error = null;
    });
    try {
      final List<Object> results = await Future.wait<Object>(<Future<Object>>[
        widget.api.health(),
        widget.api.systemStatus(),
      ]);
      final Map<String, Object?> health = results[0] as Map<String, Object?>;
      if (mounted) {
        setState(() {
          _healthy = health['status'] == 'ok';
          _status = results[1] as SystemStatus;
        });
      }
    } catch (error) {
      if (mounted) {
        setState(() => _error = error.toString());
      }
    } finally {
      if (mounted) {
        setState(() => _loading = false);
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    return RefreshIndicator(
      onRefresh: _refresh,
      child: ListView(
        padding: const EdgeInsets.fromLTRB(20, 12, 20, 32),
        children: <Widget>[
          const PageIntro(
            title: 'Security overview',
            description: 'Live cloud health and enforced access-control policy.',
          ),
          const SizedBox(height: 20),
          if (_loading)
            const Center(child: Padding(
              padding: EdgeInsets.all(40),
              child: CircularProgressIndicator(),
            ))
          else if (_error != null)
            ErrorPanel(message: _error!, onRetry: _refresh)
          else ...<Widget>[
            _HeroStatus(healthy: _healthy, hardened: _status?.hardened == true),
            const SizedBox(height: 16),
            LayoutBuilder(
              builder: (BuildContext context, BoxConstraints constraints) {
                final int columns = constraints.maxWidth >= 680 ? 3 : 2;
                return GridView.count(
                  crossAxisCount: columns,
                  shrinkWrap: true,
                  physics: const NeverScrollableScrollPhysics(),
                  mainAxisSpacing: 12,
                  crossAxisSpacing: 12,
                  childAspectRatio: columns == 3 ? 1.45 : 1.2,
                  children: <Widget>[
                    _MetricCard(
                      label: 'Protocol',
                      value: 'v${_status!.protocolVersion}',
                      icon: Icons.verified_user_outlined,
                    ),
                    _MetricCard(
                      label: 'Clock window',
                      value: '${_status!.clockSkewSeconds}s',
                      icon: Icons.schedule,
                    ),
                    _MetricCard(
                      label: 'Replay TTL',
                      value: '${_status!.replayTtlSeconds}s',
                      icon: Icons.replay,
                    ),
                    _MetricCard(
                      label: 'Legacy access',
                      value: _status!.legacyEnabled ? 'Enabled' : 'Blocked',
                      icon: Icons.history,
                      positive: !_status!.legacyEnabled,
                    ),
                    _MetricCard(
                      label: 'Medium matches',
                      value: _status!.mediumUnlockEnabled ? 'Allowed' : 'Denied',
                      icon: Icons.face_retouching_off,
                      positive: !_status!.mediumUnlockEnabled,
                    ),
                    _MetricCard(
                      label: 'Adaptive learning',
                      value: _status!.adaptiveLearningEnabled ? 'Enabled' : 'Off',
                      icon: Icons.model_training,
                      positive: !_status!.adaptiveLearningEnabled,
                    ),
                  ],
                );
              },
            ),
          ],
        ],
      ),
    );
  }
}

class _HeroStatus extends StatelessWidget {
  const _HeroStatus({required this.healthy, required this.hardened});

  final bool healthy;
  final bool hardened;

  @override
  Widget build(BuildContext context) {
    final bool ready = healthy && hardened;
    final Color color = ready ? const Color(0xFF067647) : const Color(0xFFB54708);
    return SectionCard(
      child: Row(
        children: <Widget>[
          CircleAvatar(
            radius: 26,
            backgroundColor: color.withAlpha(31),
            child: Icon(ready ? Icons.shield : Icons.warning_amber, color: color),
          ),
          const SizedBox(width: 16),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: <Widget>[
                Text(
                  ready ? 'Service hardened' : 'Review required',
                  style: Theme.of(context).textTheme.titleLarge,
                ),
                const SizedBox(height: 4),
                Text(
                  ready
                      ? 'Cloud health and core production policies are active.'
                      : 'The service is unavailable or a fail-closed policy changed.',
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }
}

class _MetricCard extends StatelessWidget {
  const _MetricCard({
    required this.label,
    required this.value,
    required this.icon,
    this.positive = true,
  });

  final String label;
  final String value;
  final IconData icon;
  final bool positive;

  @override
  Widget build(BuildContext context) {
    return SectionCard(
      padding: const EdgeInsets.all(16),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        mainAxisAlignment: MainAxisAlignment.spaceBetween,
        children: <Widget>[
          Icon(icon, color: positive ? const Color(0xFF0F766E) : Colors.orange),
          Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: <Widget>[
              Text(value, style: Theme.of(context).textTheme.titleLarge),
              Text(label, maxLines: 1, overflow: TextOverflow.ellipsis),
            ],
          ),
        ],
      ),
    );
  }
}
