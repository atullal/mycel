package dev.mycel.host

/**
 * The decisions [MycelService] and [CatchUpWorker] make, kept apart from
 * Android (no Android or native calls here) so the JVM unit tests in
 * src/test cover them.
 */

/** What a start of [MycelService] does once the runtime opened (or didn't). */
enum class AfterStart {
  /** Keep running (the app opens the runtime, or the service is foreground). */
  STAY,
  /** No profile yet: nothing to keep alive until the app makes one. */
  STOP,
  /** Android refused a foreground service: catch up once, then stop. */
  CATCH_UP_THEN_STOP,
}

/**
 * The starts [MycelService] received, so a start that finishes late (a
 * 45 s catch-up, say) never stops the service a newer start kept, or made
 * foreground: once foreground with a runtime running, the service stays
 * until Android or the user stops it. Thread-safe: starts arrive on the
 * main thread, their callbacks finish on worker threads.
 */
class ServiceStarts {
  private var latest = 0
  private var foreground = false
  private var fromApp = false
  private var running = false

  /**
   * Start `startId` arrived; `foreground`: it made the service foreground;
   * `fromApp`: the app sent it (the app opens the runtime itself).
   */
  @Synchronized
  fun begin(startId: Int, foreground: Boolean, fromApp: Boolean = false) {
    latest = maxOf(latest, startId)
    this.foreground = this.foreground || foreground
    this.fromApp = this.fromApp || fromApp
  }

  /**
   * What a start does next, once the runtime opened (`running`) or didn't;
   * `foreground`: that start made the service foreground.
   */
  @Synchronized
  fun after(fromApp: Boolean, running: Boolean, foreground: Boolean): AfterStart {
    this.running = this.running || running
    return when {
      // The app opens (or is creating) the profile itself.
      fromApp -> AfterStart.STAY
      !running -> AfterStart.STOP
      // Android 12+ refuses a foreground service started from the
      // background unless Mycel may ignore battery optimisation, but lets
      // it run a little as a background service.
      !foreground && !this.foreground -> AfterStart.CATCH_UP_THEN_STOP
      else -> AfterStart.STAY
    }
  }

  /**
   * Whether start `startId` may stop the service now: only if no newer
   * start arrived, the app never started it, and either no runtime runs
   * (no profile, or it couldn't open: a foreground service then has
   * nothing to keep alive and must not sit there saying "connected") or
   * the service isn't foreground. (Android's `stopSelfResult(startId)`
   * checks the first again.)
   */
  @Synchronized
  fun mayStop(startId: Int): Boolean = startId == latest && !fromApp && (!running || !foreground)
}

/** What one [CatchUpWorker] run does. */
enum class CatchUpPlan {
  /** Stopped already, no profile yet, or the runtime can't open. */
  NOTHING,
  /** Android let the service start: it keeps Mycel connected from here on. */
  SERVICE,
  /** One bounded catch-up. */
  CATCH_UP,
}

/**
 * Decide a [CatchUpWorker] run: open the runtime (`openRuntime`, blocking),
 * then prefer restarting the service (`startService`) over a catch-up.
 * `stopped` is read before each step: WorkManager may take the time back
 * at any moment.
 */
fun planCatchUp(stopped: () -> Boolean, openRuntime: () -> Boolean, startService: () -> Boolean): CatchUpPlan = when {
  stopped() || !openRuntime() || stopped() -> CatchUpPlan.NOTHING
  startService() -> CatchUpPlan.SERVICE
  else -> CatchUpPlan.CATCH_UP
}
