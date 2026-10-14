package dev.mycel.host

import android.Manifest
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.app.ServiceCompat
import androidx.core.content.ContextCompat

/**
 * Keeps Mycel's process, and with it the runtime's connections, alive while
 * the app is in the background, so messages and calls still arrive (there is
 * no push server to wake it). Android requires a visible notification for
 * this; it sits in the least intrusive channel and opens the app.
 */
class MycelService : Service() {
  override fun onBind(intent: Intent?): IBinder? = null

  override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
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
    // "Connected device": talking to nearby devices over Wi-Fi, peer-to-peer
    // Wi-Fi and Bluetooth (no time limit, unlike "data sync").
    val type = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE else 0
    ServiceCompat.startForeground(this, NOTIFICATION_ID, notification, type)
    // The runtime lives in the app process: if Android kills that, there's
    // nothing for a restarted service to keep alive.
    return START_NOT_STICKY
  }

  companion object {
    const val CHANNEL = "mycel-connection"
    const val NOTIFICATION_ID = 1
    const val MESSAGES = "mycel-messages"
    private var next = 100

    /**
     * A new message or call (called from Rust, src/notify.rs). Uses the
     * application context, so it works with no activity (swiped away).
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
        .build()
      NotificationManagerCompat.from(context).notify(next++, notification)
    }
  }
}
