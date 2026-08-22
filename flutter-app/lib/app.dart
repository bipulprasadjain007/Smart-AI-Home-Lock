import 'package:firebase_auth/firebase_auth.dart';
import 'package:flutter/material.dart';

import 'data/services/admin_auth_service.dart';
import 'data/services/notification_service.dart';
import 'data/services/smart_lock_api.dart';
import 'ui/screens/home_shell.dart';
import 'ui/screens/sign_in_screen.dart';
import 'ui/theme/app_theme.dart';

class SmartLockApp extends StatelessWidget {
  const SmartLockApp({
    required this.auth,
    required this.api,
    required this.notifications,
    super.key,
  });

  final AdminAuthService auth;
  final SmartLockApi api;
  final NotificationService notifications;

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Home Lock Admin',
      debugShowCheckedModeBanner: false,
      theme: AppTheme.light(),
      home: _AuthGate(auth: auth, api: api, notifications: notifications),
    );
  }
}

class _AuthGate extends StatefulWidget {
  const _AuthGate({
    required this.auth,
    required this.api,
    required this.notifications,
  });

  final AdminAuthService auth;
  final SmartLockApi api;
  final NotificationService notifications;

  @override
  State<_AuthGate> createState() => _AuthGateState();
}

class _AuthGateState extends State<_AuthGate> {
  String? _checkedUid;
  Future<bool>? _claimCheck;

  Future<bool> _claimFor(User user) {
    if (_checkedUid != user.uid || _claimCheck == null) {
      _checkedUid = user.uid;
      _claimCheck = widget.auth.hasAdminClaim(user);
    }
    return _claimCheck!;
  }

  @override
  Widget build(BuildContext context) {
    return StreamBuilder<User?>(
      stream: widget.auth.userChanges,
      builder: (BuildContext context, AsyncSnapshot<User?> snapshot) {
        if (snapshot.connectionState == ConnectionState.waiting) {
          return const _LoadingScreen();
        }
        final User? user = snapshot.data;
        if (user == null) {
          _checkedUid = null;
          _claimCheck = null;
          return SignInScreen(auth: widget.auth);
        }
        return FutureBuilder<bool>(
          future: _claimFor(user),
          builder: (BuildContext context, AsyncSnapshot<bool> claimSnapshot) {
            if (claimSnapshot.connectionState != ConnectionState.done) {
              return const _LoadingScreen();
            }
            if (claimSnapshot.data != true) {
              return _AccessDeniedScreen(onSignOut: widget.auth.signOut);
            }
            return HomeShell(
              api: widget.api,
              auth: widget.auth,
              notifications: widget.notifications,
            );
          },
        );
      },
    );
  }
}

class _LoadingScreen extends StatelessWidget {
  const _LoadingScreen();

  @override
  Widget build(BuildContext context) {
    return const Scaffold(body: Center(child: CircularProgressIndicator()));
  }
}

class _AccessDeniedScreen extends StatelessWidget {
  const _AccessDeniedScreen({required this.onSignOut});

  final Future<void> Function() onSignOut;

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: Center(
        child: Padding(
          padding: const EdgeInsets.all(24),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: <Widget>[
              Icon(Icons.gpp_bad, size: 52, color: Theme.of(context).colorScheme.error),
              const SizedBox(height: 16),
              Text('Administrator access required', style: Theme.of(context).textTheme.headlineSmall),
              const SizedBox(height: 8),
              const Text(
                'Ask the Firebase project owner to assign the admin custom claim, then sign in again.',
                textAlign: TextAlign.center,
              ),
              const SizedBox(height: 18),
              FilledButton(onPressed: onSignOut, child: const Text('Sign out')),
            ],
          ),
        ),
      ),
    );
  }
}
