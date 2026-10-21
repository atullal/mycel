package dev.mycel.host

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

/**
 * Stay connected after the phone restarts or Mycel is updated, without the
 * user opening it first. Android 12+ lets an app start a foreground service
 * from these two broadcasts, and the "connected device" type may start after
 * a reboot (Android 15 forbids it only for types such as "data sync"). Android
 * delivers neither to an app that was never opened or that the user force
 * stopped, and the service stops again at once if there's no profile yet.
 */
class BootReceiver : BroadcastReceiver() {
  override fun onReceive(context: Context, intent: Intent) {
    when (intent.action) {
      Intent.ACTION_BOOT_COMPLETED, Intent.ACTION_MY_PACKAGE_REPLACED -> {
        MycelService.startFromBackground(context)
        // The backstop for when the phone stops the service anyway.
        CatchUpWorker.schedule(context)
      }
    }
  }
}
