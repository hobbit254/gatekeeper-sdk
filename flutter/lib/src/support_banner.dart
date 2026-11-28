import 'dart:async';

import 'package:flutter/widgets.dart';

import 'auth.dart';
import 'scope.dart';

/// The banner's words; {name} and {minutes} are filled in.
class SupportBannerLabels {
  const SupportBannerLabels({
    this.title = 'Support session',
    this.viewingAs = 'Viewing as {name}',
    this.readOnly = 'Read-only',
    this.canChange = 'Can change things',
    this.endsIn = 'Ends in {minutes} min',
    this.ended = 'Support session ended',
    this.stop = 'Stop',
  });
  final String title, viewingAs, readOnly, canChange, endsIn, ended, stop;
}

/// Shows a red strip above [child] while the signed-in session is a support
/// session (FR-M5, ADR-0159): who is being viewed, whether it can change
/// things, the minutes left, and Stop. Needs a [GatekeeperScope] above it.
class SupportBanner extends StatefulWidget {
  const SupportBanner({
    super.key,
    required this.child,
    this.name,
    this.onStop,
    this.onEnded,
    this.labels = const SupportBannerLabels(),
    this.now,
  });

  final Widget child;

  /// Whose account is being viewed, as the app names them.
  final String? name;

  /// Stop pressed; the default signs out on this device.
  final VoidCallback? onStop;

  /// Called once when the session's time is up.
  final VoidCallback? onEnded;
  final SupportBannerLabels labels;
  final DateTime Function()? now;

  @override
  State<SupportBanner> createState() => _SupportBannerState();
}

class _SupportBannerState extends State<SupportBanner> {
  Timer? _timer;
  bool _ended = false;

  DateTime _now() => (widget.now ?? DateTime.now)();

  @override
  void initState() {
    super.initState();
    _timer = Timer.periodic(const Duration(seconds: 30), (_) => setState(() {}));
  }

  @override
  void dispose() {
    _timer?.cancel();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final auth = GatekeeperScope.of(context);
    final status = auth.state.status;
    final session = status is SignedIn ? status.support : null;
    if (session == null) return widget.child;
    final w = widget.labels;
    final left = session.endsAt.difference(_now());
    final over = left <= Duration.zero;
    if (over && !_ended) {
      _ended = true;
      _timer?.cancel();
      final ended = widget.onEnded;
      if (ended != null) scheduleMicrotask(ended);
    }
    final text = over
        ? w.ended
        : [
            w.title,
            if (widget.name != null) w.viewingAs.replaceAll('{name}', widget.name!),
            session.readOnly ? w.readOnly : w.canChange,
            w.endsIn.replaceAll('{minutes}', '${(left.inSeconds / 60).ceil()}'),
          ].join(' · ');
    const red = Color(0xFFB42318), white = Color(0xFFFFFFFF);
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Semantics(
          liveRegion: true,
          container: true,
          child: Container(
            color: red,
            padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
            child: Row(
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                Flexible(child: Text(text, style: const TextStyle(color: white, fontWeight: FontWeight.w600, fontSize: 14))),
                if (!over) ...[
                  const SizedBox(width: 12),
                  Semantics(
                    button: true,
                    child: GestureDetector(
                      onTap: widget.onStop ?? () => auth.signOut(),
                      child: Container(
                        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 2),
                        decoration: BoxDecoration(color: white, borderRadius: BorderRadius.circular(999)),
                        child: Text(w.stop, style: const TextStyle(color: red, fontWeight: FontWeight.w600, fontSize: 14)),
                      ),
                    ),
                  ),
                ],
              ],
            ),
          ),
        ),
        Expanded(child: widget.child),
      ],
    );
  }
}
