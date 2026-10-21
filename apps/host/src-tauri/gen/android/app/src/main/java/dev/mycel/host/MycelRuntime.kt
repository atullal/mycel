package dev.mycel.host

import android.annotation.SuppressLint
import android.app.ActivityManager
import android.app.usage.UsageStatsManager
import android.content.ActivityNotFoundException
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.PowerManager
import android.provider.Settings
import android.util.Log
import org.json.JSONObject
import kotlin.concurrent.thread

/**
 * The Rust runtime without a window (src/android.rs). Tauri opens it when the
 * first activity is created; after a reboot, an update, a sticky restart of
 * [MycelService] or a [CatchUpWorker] run there is no activity, so these open
 * the same runtime, for an existing profile only (a new one is made in the
 * app). A window opened later adopts it.
 */
object MycelRuntime {
  init {
    // Also loaded by Tauri's activity; loading twice is a no-op.
    System.loadLibrary("mycel_host")
  }

  /** Open the runtime for `dataDir` (blocks: never on the main thread). */
  @JvmStatic private external fun start(context: Context, dataDir: String): Boolean

  /**
   * A ticket for one catch-up: take it before anything that may be
   * cancelled, pass it to [catchUp], and [cancelCatchUp] it to stop that
   * catch-up (also before it began) without touching any other.
   */
  @JvmStatic external fun beginCatchUp(): Long

  /** One catch-up round of at most `seconds` (blocks). */
  @JvmStatic external fun catchUp(ticket: Long, seconds: Int): Boolean

  /** Stop the [catchUp] holding `ticket` now, or as soon as it begins. */
  @JvmStatic external fun cancelCatchUp(ticket: Long)

  /**
   * Called by [MainActivity] before Tauri's activity setup: the runtime
   * stops sharing its own Android context with Rust libraries, because
   * Tauri's setup provides it from then on and refuses to find one there.
   */
  @JvmStatic external fun handOverContext()

  /** The folder Tauri gives the runtime (its `app_data_dir` on Android). */
  private fun dataDir(context: Context): String = context.applicationContext.dataDir.absolutePath

  /** Open the runtime, blocking. True once one is running in this process. */
  fun startBlocking(context: Context): Boolean =
    try {
      start(context.applicationContext, dataDir(context))
    } catch (e: UnsatisfiedLinkError) {
      Log.w("Mycel", "runtime library unavailable")
      false
    }

  /** Open the runtime on a worker thread, then `done(running)` there. */
  fun startAsync(context: Context, done: (Boolean) -> Unit = {}) {
    val app = context.applicationContext
    thread(name = "mycel-start") { done(startBlocking(app)) }
  }

  /**
   * What the Profile panel shows about running in the background (read by
   * src/android.rs, shown by apps/host/src/backgroundStatus.ts).
   */
  @JvmStatic
  fun backgroundStatus(context: Context): String {
    val power = context.getSystemService(PowerManager::class.java)
    val activities = context.getSystemService(ActivityManager::class.java)
    val usage = context.getSystemService(UsageStatsManager::class.java)
    return JSONObject().apply {
      put("batteryUnrestricted", power?.isIgnoringBatteryOptimizations(context.packageName) ?: false)
      activities?.let { put("backgroundRestricted", it.isBackgroundRestricted) }
      usage?.let { put("standbyBucket", bucketName(it.appStandbyBucket)) }
      put("manufacturer", Build.MANUFACTURER ?: "")
    }.toString()
  }

  private fun bucketName(bucket: Int): String = when (bucket) {
    UsageStatsManager.STANDBY_BUCKET_ACTIVE -> "active"
    UsageStatsManager.STANDBY_BUCKET_WORKING_SET -> "working_set"
    UsageStatsManager.STANDBY_BUCKET_FREQUENT -> "frequent"
    UsageStatsManager.STANDBY_BUCKET_RARE -> "rare"
    UsageStatsManager.STANDBY_BUCKET_RESTRICTED -> "restricted"
    else -> "other"
  }

  /**
   * Ask the user to let Mycel run unrestricted in the background (the
   * Profile panel explains why first, and only offers this while it's
   * restricted). Mycel has no push server to wake it, which is the case
   * Google's policy allows this request for. Falls back to the list of apps
   * where the phone shows no prompt.
   */
  @JvmStatic
  @SuppressLint("BatteryLife")
  fun requestBatteryExemption(context: Context) {
    val prompt = Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS, Uri.parse("package:${context.packageName}"))
    val list = Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS)
    for (intent in listOf(prompt, list)) {
      try {
        context.startActivity(intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
        return
      } catch (e: ActivityNotFoundException) {
        // Some vendors remove the prompt: try the list.
      } catch (e: SecurityException) {
        Log.w("Mycel", "battery setting refused")
      }
    }
  }
}
