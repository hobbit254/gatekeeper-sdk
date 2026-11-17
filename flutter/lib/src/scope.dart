import 'package:flutter/widgets.dart';

import 'auth.dart';

/// Puts a [GatekeeperAuth] above the widgets that need it. Widgets that call
/// [of] rebuild when its state changes.
class GatekeeperScope extends InheritedNotifier<AuthState> {
  GatekeeperScope({super.key, required this.auth, required super.child}) : super(notifier: auth.state);

  final GatekeeperAuth auth;

  static GatekeeperAuth of(BuildContext context) {
    final scope = context.dependOnInheritedWidgetOfExactType<GatekeeperScope>();
    assert(scope != null, 'no GatekeeperScope above this widget');
    return scope!.auth;
  }
}
