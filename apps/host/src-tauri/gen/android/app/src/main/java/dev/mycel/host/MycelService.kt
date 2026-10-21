package dev.mycel.host

import android.Manifest
import android.app.ForegroundServiceStartNotAllowedException
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.util.Log
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.app.ServiceCompat
import androidx.core.content.ContextCompat

/**
 * Keeps Mycel's process, and with it the runtime's connections, alive while
 * the app is in the background, so messages and calls still arrive (there is
 * no push server to wake it). Android requires a visible notification for
 * this; it sits in the least intrusive channel and opens the app.
 *
 * Started by [MainActivity], by [BootReceiver] after a reboot or an update,
 * by [CatchUpWorker] when the phone stopped it, and by Android itself
 * (sticky) after it killed the process. Without an activity it opens the
 * runtime itself ([MycelRuntime]), for an existing profile only.
 */
class MycelService : Service() {
  override fun onBind(intent: Intent?): IBinder? = null

  /** Every start so far: a late start never stops what a newer one kept. */
  private val starts = ServiceStarts()

  override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
    // A null intent is Android restarting the sticky service.
    val fromApp = intent?.getBooleanExtra(EXTRA_FROM_APP, false) ?: false
    val foreground = goForeground()
    starts.begin(startId, foreground)
    MycelRuntime.startAsync(this) { running ->
      when (starts.after(fromApp, running, foreground)) {
        AfterStart.STAY -> {}
        AfterStart.STOP -> stopOnMain(startId)
        // Catch up once while Android lets this background service run.
        AfterStart.CATCH_UP_THEN_STOP -> {
          MycelRuntime.catchUp(MycelRuntime.beginCatchUp(), CATCH_UP_SECONDS)
          stopOnMain(startId)
        }
      }
    }
    // Android restarts the service if it kills the process, and the runtime
    // is opened again above (before, nothing restarted it).
    return START_STICKY
  }

  /**
   * Stop for start `startId`, unless a newer start arrived meanwhile (the
   * user opened Mycel during a catch-up, say) or one made the service
   * foreground: plain `stopSelf()` would stop it regardless, and a service
   * stopped that way is never restarted as sticky.
   */
  private fun stopOnMain(startId: Int) {
    Handler(Looper.getMainLooper()).post {
      if (starts.mayStop(startId)) stopSelfResult(startId)
    }
  }

  /** Show the "connected" notification and become a foreground service. */
  private fun goForeground(): Boolean {
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
      val channel = NotificationChannel(CHANNEL, "Staying connected", NotificationManager.IMPORTANCE_MIN).apply {
        description = "Shown while Mycel keeps receiving messages in the background"
        setShowBadge(false)
      }
      getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
    }
    val open = PendingIntent.getActivity(
      this, 0,
      Intent(this, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP),
      PendingIntent.FLAG_IMMUTABLE,
    )
    val notification = NotificationCompat.Builder(this, CHANNEL)
      .setSmallIcon(R.drawable.ic_stat_mycel)
      .setContentTitle("Mycel is connected")
      .setContentText("Receiving messages in the background")
      .setContentIntent(open)
      .setOngoing(true)
      .setSilent(true)
      .setPriority(NotificationCompat.PRIORITY_MIN)
      .build()
    // "Connected device": keeping connections to other devices running Mycel
    // on the same Wi-Fi or LAN (found by mDNS) and the phones and computers
    // reached through them. (Mycel has no Bluetooth link on Android yet.)
    // No daily time limit (unlike "data sync", capped at 6 h a day from
    // Android 15), and it may start after a reboot. Its prerequisite is a
    // Wi-Fi or network permission in the manifest. docs/PLATFORMS.md has the
    // Play Console declaration, and the "special use" fallback.
    val type = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE else 0
    return try {
      ServiceCompat.startForeground(this, NOTIFICATION_ID, notification, type)
      // A user restriction in Settings ("background usage: restricted")
      // makes Android ignore the call without an exception (it logs "not
      // allowed due to bg restriction"): ask whether it took.
      val took = Build.VERSION.SDK_INT < Build.VERSION_CODES.Q || foregroundServiceType != 0
      if (!took) Log.w("Mycel", "not allowed to stay connected: background use is restricted")
      took
    } catch (e: Exception) {
      // ForegroundServiceStartNotAllowedException (Android 12+, started from
      // the background) or a missing prerequisite (SecurityException).
      val refused = Build.VERSION.SDK_INT >= Build.VERSION_CODES.S && e is ForegroundServiceStartNotAllowedException
      Log.w("Mycel", if (refused) "not allowed to stay connected from the background" else "can't stay connected: ${e.javaClass.simpleName}")
      false
    }
  }

  companion object {
    /** Set by [MainActivity]: the app opens the runtime itself. */
    const val EXTRA_FROM_APP = "dev.mycel.host.FROM_APP"
    /** One catch-up when Android won't let the service stay (seconds). */
    const val CATCH_UP_SECONDS = 45
    const val CHANNEL = "mycel-connection"
    const val NOTIFICATION_ID = 1
    const val MESSAGES = "mycel-messages"
    private var next = 100

    /**
     * Start the service with no activity: after a reboot or an update
     * ([BootReceiver]), or from [CatchUpWorker]. False if Android refused
     * (Android 12+ allows it after a reboot or an update, or when Mycel may
     * ignore battery optimisation).
     */
    fun startFromBackground(context: Context): Boolean =
      try {
        ContextCompat.startForegroundService(context, Intent(context, MycelService::class.java))
        true
      } catch (e: IllegalStateException) {
        // ForegroundServiceStartNotAllowedException is one.
        Log.w("Mycel", "not allowed to start in the background")
        false
      }

    /**
     * A new message or call (called from Rust, src/android.rs). Uses the
     * application context, so it works with no activity (swiped away, or
     * started in the background). The title and text are one fixed sentence
     * per kind (src/notify.rs): never names or message text.
     */
    @JvmStatic
    fun notify(context: Context, title: String, body: String) {
      if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
        ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
      ) {
        return
      }
      if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
        val channel = NotificationChannel(MESSAGES, "Messages and calls", NotificationManager.IMPORTANCE_HIGH)
        context.getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
      }
      val open = PendingIntent.getActivity(
        context, 0,
        Intent(context, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP),
        PendingIntent.FLAG_IMMUTABLE,
      )
      val notification = NotificationCompat.Builder(context, MESSAGES)
        .setSmallIcon(R.drawable.ic_stat_mycel)
        .setContentTitle(title)
        .setContentText(body)
        .setStyle(NotificationCompat.BigTextStyle().bigText(body))
        .setContentIntent(open)
        .setAutoCancel(true)
        .setPriority(NotificationCompat.PRIORITY_HIGH)
        .setCategory(NotificationCompat.CATEGORY_MESSAGE)
        .build()
      NotificationManagerCompat.from(context).notify(next++, notification)
    }
  }
}
