import 'dart:async';

import 'package:firebase_messaging/firebase_messaging.dart';
import 'package:flutter/material.dart';

import '../../data/services/admin_auth_service.dart';
import '../../data/services/notification_service.dart';
import '../../data/services/smart_lock_api.dart';
import 'dashboard_screen.dart';
import 'enrollment_screen.dart';
import 'logs_screen.dart';
import 'manage_user_screen.dart';

class HomeShell extends StatefulWidget {
  const HomeShell({
    required this.api,
    required this.auth,
    required this.notifications,
    super.key,
  });

  final SmartLockApi api;
  final AdminAuthService auth;
  final NotificationService notifications;

  @override
  State<HomeShell> createState() => _HomeShellState();
}

class _HomeShellState extends State<HomeShell> {
  late final List<Widget> _pages;
  StreamSubscription<RemoteMessage>? _messageSubscription;
  int _index = 0;

  @override
  void initState() {
    super.initState();
    _pages = <Widget>[
      DashboardScreen(api: widget.api),
      EnrollmentScreen(api: widget.api),
      LogsScreen(api: widget.api),
      ManageUserScreen(api: widget.api, notifications: widget.notifications),
    ];
    _messageSubscription = widget.notifications.foregroundMessages.listen(
      _showNotification,
    );
  }

  @override
  void dispose() {
    _messageSubscription?.cancel();
    super.dispose();
  }

  void _showNotification(RemoteMessage message) {
    if (!mounted) {
      return;
    }
    final String title = message.notification?.title ?? 'Lock activity';
    final String body = message.notification?.body ?? 'A new access event was received.';
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(content: Text('$title — $body')),
    );
  }

  @override
  Widget build(BuildContext context) {
    const List<String> titles = <String>['Overview', 'Enroll', 'Access logs', 'Manage'];
    return Scaffold(
      appBar: AppBar(
        title: Text(titles[_index]),
        actions: <Widget>[
          PopupMenuButton<String>(
            tooltip: 'Account menu',
            onSelected: (String value) {
              if (value == 'sign_out') {
                widget.auth.signOut();
              }
            },
            itemBuilder: (BuildContext context) => <PopupMenuEntry<String>>[
              PopupMenuItem<String>(
                enabled: false,
                child: Text(
                  widget.auth.currentUser?.email ?? 'Administrator',
                  overflow: TextOverflow.ellipsis,
                ),
              ),
              const PopupMenuDivider(),
              const PopupMenuItem<String>(
                value: 'sign_out',
                child: ListTile(
                  contentPadding: EdgeInsets.zero,
                  leading: Icon(Icons.logout),
                  title: Text('Sign out'),
                ),
              ),
            ],
            icon: const Icon(Icons.account_circle_outlined),
          ),
        ],
      ),
      body: IndexedStack(index: _index, children: _pages),
      bottomNavigationBar: NavigationBar(
        selectedIndex: _index,
        onDestinationSelected: (int value) => setState(() => _index = value),
        destinations: const <NavigationDestination>[
          NavigationDestination(
            icon: Icon(Icons.shield_outlined),
            selectedIcon: Icon(Icons.shield),
            label: 'Overview',
          ),
          NavigationDestination(
            icon: Icon(Icons.person_add_alt),
            label: 'Enroll',
          ),
          NavigationDestination(
            icon: Icon(Icons.receipt_long_outlined),
            selectedIcon: Icon(Icons.receipt_long),
            label: 'Logs',
          ),
          NavigationDestination(
            icon: Icon(Icons.manage_accounts_outlined),
            selectedIcon: Icon(Icons.manage_accounts),
            label: 'Manage',
          ),
        ],
      ),
    );
  }
}
