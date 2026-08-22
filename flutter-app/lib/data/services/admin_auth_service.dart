import 'package:firebase_auth/firebase_auth.dart';

class AuthenticationException implements Exception {
  const AuthenticationException(this.message);

  final String message;

  @override
  String toString() => message;
}

class AdminAuthService {
  AdminAuthService(this._auth);

  final FirebaseAuth _auth;

  Stream<User?> get userChanges => _auth.userChanges();
  User? get currentUser => _auth.currentUser;

  Future<void> signIn(String email, String password) async {
    try {
      final UserCredential credential = await _auth.signInWithEmailAndPassword(
        email: email.trim(),
        password: password,
      );
      final IdTokenResult token = await credential.user!.getIdTokenResult(true);
      if (token.claims?['admin'] != true) {
        await _auth.signOut();
        throw const AuthenticationException(
          'This account does not have administrator access.',
        );
      }
    } on FirebaseAuthException catch (error) {
      throw AuthenticationException(_messageFor(error.code));
    }
  }

  Future<bool> hasAdminClaim(User user) async {
    try {
      final IdTokenResult token = await user.getIdTokenResult();
      return token.claims?['admin'] == true;
    } on FirebaseAuthException {
      return false;
    }
  }

  Future<String?> idToken() async => _auth.currentUser?.getIdToken();

  Future<void> sendPasswordReset(String email) async {
    try {
      await _auth.sendPasswordResetEmail(email: email.trim());
    } on FirebaseAuthException catch (error) {
      throw AuthenticationException(_messageFor(error.code));
    }
  }

  Future<void> signOut() => _auth.signOut();

  static String _messageFor(String code) {
    return switch (code) {
      'invalid-email' => 'Enter a valid email address.',
      'invalid-credential' || 'user-not-found' || 'wrong-password' =>
        'The email or password is incorrect.',
      'too-many-requests' => 'Too many attempts. Try again later.',
      'network-request-failed' => 'Check your internet connection and retry.',
      _ => 'Authentication failed. Please retry.',
    };
  }
}
