import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../../core/validation/validators.dart';
import '../../data/services/notification_service.dart';
import '../../data/services/smart_lock_api.dart';
import '../widgets/common.dart';

class ManageUserScreen extends StatefulWidget {
  const ManageUserScreen({
    required this.api,
    required this.notifications,
    super.key,
  });

  final SmartLockApi api;
  final NotificationService notifications;

  @override
  State<ManageUserScreen> createState() => _ManageUserScreenState();
}

class _ManageUserScreenState extends State<ManageUserScreen> {
  final GlobalKey<FormState> _formKey = GlobalKey<FormState>();
  final TextEditingController _userId = TextEditingController();
  final TextEditingController _pin = TextEditingController();
  final TextEditingController _confirmPin = TextEditingController();
  StreamSubscription<String>? _tokenRefreshSubscription;
  String? _registeredToken;
  String? _registeredUserId;
  bool _busy = false;

  @override
  void initState() {
    super.initState();
    _tokenRefreshSubscription = widget.notifications.tokenRefreshes.listen(
      _refreshNotificationToken,
    );
  }

  @override
  void dispose() {
    _tokenRefreshSubscription?.cancel();
    _userId.dispose();
    _pin.dispose();
    _confirmPin.dispose();
    super.dispose();
  }

  Future<void> _refreshNotificationToken(String token) async {
    final String? userId = _registeredUserId;
    if (userId == null) {
      return;
    }
    try {
      await widget.api.registerNotificationDevice(
        userId: userId,
        token: token,
        platform: widget.notifications.platform,
        deviceName: widget.notifications.deviceName,
      );
      _registeredToken = token;
    } on Object {
      // The next explicit registration retries. Do not expose tokens in logs.
    }
  }

  Future<void> _setPin() async {
    if (!_validate(includePin: true)) {
      return;
    }
    await _run(() async {
      await widget.api.setPin(_userId.text.trim(), _pin.text);
      _pin.clear();
      _confirmPin.clear();
      _show('PIN updated.');
    });
  }

  Future<void> _enableNotifications() async {
    if (!_validate()) {
      return;
    }
    await _run(() async {
      final String token = await widget.notifications.requestToken();
      final String userId = _userId.text.trim();
      await widget.api.registerNotificationDevice(
        userId: userId,
        token: token,
        platform: widget.notifications.platform,
        deviceName: widget.notifications.deviceName,
      );
      _registeredToken = token;
      _registeredUserId = userId;
      _show('Unlock notifications enabled for $userId.');
      if (mounted) {
        setState(() {});
      }
    });
  }

  Future<void> _disableNotifications() async {
    final String? token = _registeredToken;
    final String? userId = _registeredUserId;
    if (token == null || userId == null) {
      _show('Notifications are not registered in this session.');
      return;
    }
    await _run(() async {
      await widget.api.deregisterNotificationDevice(
        userId: userId,
        token: token,
        platform: widget.notifications.platform,
      );
      _registeredToken = null;
      _registeredUserId = null;
      _show('Notifications disabled.');
      if (mounted) {
        setState(() {});
      }
    });
  }

  Future<void> _deleteUser() async {
    if (!_validate()) {
      return;
    }
    final String userId = _userId.text.trim();
    final bool confirmed = await showDialog<bool>(
          context: context,
          builder: (BuildContext context) => AlertDialog(
            title: const Text('Delete biometric profile?'),
            content: Text(
              'This removes $userId, the PIN, notification devices, logs, and private biometric objects. This action cannot be undone.',
            ),
            actions: <Widget>[
              TextButton(
                onPressed: () => Navigator.pop(context, false),
                child: const Text('Cancel'),
              ),
              FilledButton(
                style: FilledButton.styleFrom(
                  backgroundColor: Theme.of(context).colorScheme.error,
                ),
                onPressed: () => Navigator.pop(context, true),
                child: const Text('Delete user'),
              ),
            ],
          ),
        ) ??
        false;
    if (!confirmed) {
      return;
    }
    await _run(() async {
      await widget.api.deleteUser(userId);
      if (_registeredUserId == userId) {
        _registeredToken = null;
        _registeredUserId = null;
      }
      _userId.clear();
      _show('User $userId deleted.');
      if (mounted) {
        setState(() {});
      }
    });
  }

  bool _validate({bool includePin = false}) {
    final String? userError = validateUserId(_userId.text);
    if (userError != null) {
      _formKey.currentState!.validate();
      return false;
    }
    if (includePin) {
      if (!_formKey.currentState!.validate()) {
        return false;
      }
      if (_pin.text != _confirmPin.text) {
        _show('PINs do not match.');
        return false;
      }
    }
    return true;
  }

  Future<void> _run(Future<void> Function() action) async {
    setState(() => _busy = true);
    try {
      await action();
    } catch (error) {
      if (mounted) {
        _show(error.toString());
      }
    } finally {
      if (mounted) {
        setState(() => _busy = false);
      }
    }
  }

  void _show(String message) {
    ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(message)));
  }

  @override
  Widget build(BuildContext context) {
    final bool notificationsEnabled = _registeredToken != null;
    return ListView(
      padding: const EdgeInsets.fromLTRB(20, 12, 20, 32),
      children: <Widget>[
        const PageIntro(
          title: 'Manage user',
          description: 'Update a PIN, bind this phone to alerts, or remove a profile.',
        ),
        const SizedBox(height: 20),
        Form(
          key: _formKey,
          child: Column(
            children: <Widget>[
              SectionCard(
                child: TextFormField(
                  controller: _userId,
                  enabled: !_busy,
                  validator: validateUserId,
                  autocorrect: false,
                  decoration: const InputDecoration(
                    labelText: 'User ID',
                    prefixIcon: Icon(Icons.person_outline),
                  ),
                ),
              ),
              const SizedBox(height: 16),
              SectionCard(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.stretch,
                  children: <Widget>[
                    Text('Change PIN', style: Theme.of(context).textTheme.titleMedium),
                    const SizedBox(height: 14),
                    TextFormField(
                      controller: _pin,
                      enabled: !_busy,
                      onChanged: (_) => setState(() {}),
                      validator: (String? value) {
                        if ((value ?? '').isEmpty) {
                          return null;
                        }
                        return validatePin(value);
                      },
                      keyboardType: TextInputType.number,
                      obscureText: true,
                      maxLength: 6,
                      inputFormatters: <TextInputFormatter>[FilteringTextInputFormatter.digitsOnly],
                      decoration: const InputDecoration(labelText: 'New six-digit PIN'),
                    ),
                    const SizedBox(height: 12),
                    TextFormField(
                      controller: _confirmPin,
                      enabled: !_busy,
                      validator: (String? value) {
                        if (_pin.text.isEmpty && (value ?? '').isEmpty) {
                          return null;
                        }
                        return validatePin(value);
                      },
                      keyboardType: TextInputType.number,
                      obscureText: true,
                      maxLength: 6,
                      inputFormatters: <TextInputFormatter>[FilteringTextInputFormatter.digitsOnly],
                      decoration: const InputDecoration(labelText: 'Confirm new PIN'),
                    ),
                    const SizedBox(height: 10),
                    FilledButton.icon(
                      onPressed: _busy || _pin.text.isEmpty ? null : _setPin,
                      icon: const Icon(Icons.password),
                      label: const Text('Update PIN'),
                    ),
                  ],
                ),
              ),
              const SizedBox(height: 16),
              SectionCard(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.stretch,
                  children: <Widget>[
                    ListTile(
                      contentPadding: EdgeInsets.zero,
                      leading: Icon(
                        notificationsEnabled
                            ? Icons.notifications_active
                            : Icons.notifications_none,
                      ),
                      title: const Text('Unlock notifications'),
                      subtitle: Text(
                        notificationsEnabled
                            ? 'Enabled for $_registeredUserId'
                            : 'Receive face and PIN unlock alerts on this device.',
                      ),
                    ),
                    FilledButton.tonalIcon(
                      onPressed: _busy
                          ? null
                          : notificationsEnabled
                              ? _disableNotifications
                              : _enableNotifications,
                      icon: Icon(
                        notificationsEnabled
                            ? Icons.notifications_off_outlined
                            : Icons.notifications_active_outlined,
                      ),
                      label: Text(
                        notificationsEnabled
                            ? 'Disable notifications'
                            : 'Enable notifications',
                      ),
                    ),
                  ],
                ),
              ),
              const SizedBox(height: 16),
              SectionCard(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.stretch,
                  children: <Widget>[
                    Text('Danger zone', style: Theme.of(context).textTheme.titleMedium),
                    const SizedBox(height: 6),
                    const Text('Deletion cascades through the user PIN, devices, logs, and stored event images.'),
                    const SizedBox(height: 14),
                    OutlinedButton.icon(
                      style: OutlinedButton.styleFrom(
                        foregroundColor: Theme.of(context).colorScheme.error,
                      ),
                      onPressed: _busy ? null : _deleteUser,
                      icon: const Icon(Icons.delete_forever_outlined),
                      label: const Text('Delete user'),
                    ),
                  ],
                ),
              ),
            ],
          ),
        ),
      ],
    );
  }
}
