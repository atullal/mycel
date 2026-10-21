package dev.mycel.host

import android.content.Context
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.Worker
import androidx.work.WorkerParameters
import java.util.concurrent.TimeUnit

/**
 * A backstop, not the delivery path: [MycelService] keeps Mycel connected,
 * but some phones stop it anyway (vendor battery managers, the "restricted"
 * standby bucket after days unopened). Every few hours this restarts the
 * service if Android allows it, or else opens the runtime for one bounded
 * catch-up (sync, wait for deliveries, save). WorkManager runs it when the
 * system chooses: Android 16 holds jobs to a runtime quota per standby
 * bucket, even alongside a foreground service, so it stays short and
 * occasional. No network constraint: Mycel also reaches peers on a Wi-Fi
 * with no internet, which Android doesn't count as "connected".
 */
class CatchUpWorker(context: Context, params: WorkerParameters) : Worker(context, params) {
  override fun doWork(): Result {
    if (!MycelRuntime.startBlocking(applicationContext)) {
      // No profile yet (or the runtime can't open): nothing to catch up on.
      return Result.success()
    }
    // Allowed when Mycel may ignore battery optimisation: then the service
    // keeps it connected from here on.
    if (MycelService.startFromBackground(applicationContext)) {
      return Result.success()
    }
    MycelRuntime.catchUp(CATCH_UP_SECONDS)
    return Result.success()
  }

  /** WorkManager took the time back: end the catch-up now. */
  override fun onStopped() {
    MycelRuntime.cancelCatchUp()
  }

  companion object {
    private const val NAME = "mycel-catch-up"
    /** Well inside WorkManager's 10-minute limit and the Android 16 quotas. */
    private const val CATCH_UP_SECONDS = 60
    private const val EVERY_HOURS = 3L

    /** Keep one periodic catch-up scheduled (idempotent). */
    fun schedule(context: Context) {
      val request = PeriodicWorkRequestBuilder<CatchUpWorker>(EVERY_HOURS, TimeUnit.HOURS).build()
      WorkManager.getInstance(context.applicationContext)
        .enqueueUniquePeriodicWork(NAME, ExistingPeriodicWorkPolicy.KEEP, request)
    }
  }
}
