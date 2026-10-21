package dev.mycel.host

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** The background decisions of MycelService and CatchUpWorker (BackgroundPolicy.kt). */
class BackgroundPolicyTest {
  @Test
  fun theAppsStartAlwaysStays() {
    val starts = ServiceStarts()
    starts.begin(1, foreground = true)
    assertEquals(AfterStart.STAY, starts.after(fromApp = true, running = false, foreground = true))
    assertFalse(starts.mayStop(1))
  }

  @Test
  fun aBackgroundStartWithNoProfileStops() {
    val starts = ServiceStarts()
    starts.begin(1, foreground = true)
    assertEquals(AfterStart.STAY, starts.after(fromApp = false, running = true, foreground = true))
    val fresh = ServiceStarts()
    fresh.begin(1, foreground = false)
    assertEquals(AfterStart.STOP, fresh.after(fromApp = false, running = false, foreground = false))
    assertTrue(fresh.mayStop(1))
  }

  @Test
  fun aRefusedForegroundRestartCatchesUpThenStops() {
    val starts = ServiceStarts()
    starts.begin(1, foreground = false)
    assertEquals(AfterStart.CATCH_UP_THEN_STOP, starts.after(fromApp = false, running = true, foreground = false))
    assertTrue(starts.mayStop(1))
  }

  /**
   * Regression: a sticky restart that Android refused to make foreground
   * catches up for 45 s; the user opens Mycel meanwhile (a newer start that
   * is foreground). The old catch-up's stop must not end the service.
   */
  @Test
  fun aLateCatchUpNeverStopsTheServiceTheAppStarted() {
    val starts = ServiceStarts()
    starts.begin(1, foreground = false)
    assertEquals(AfterStart.CATCH_UP_THEN_STOP, starts.after(fromApp = false, running = true, foreground = false))
    starts.begin(2, foreground = true)
    assertEquals(AfterStart.STAY, starts.after(fromApp = true, running = true, foreground = true))
    assertFalse("start 1 finishing late must not stop the service", starts.mayStop(1))
    assertFalse(starts.mayStop(2))
  }

  /** The same for the "no profile" stop, and for a newer start that wasn't foreground. */
  @Test
  fun onlyTheLatestStartMayStop() {
    val starts = ServiceStarts()
    starts.begin(1, foreground = false)
    starts.begin(2, foreground = false)
    assertFalse(starts.mayStop(1))
    assertTrue(starts.mayStop(2))
  }

  /** Once foreground, a later start that Android refused doesn't demote it to a catch-up. */
  @Test
  fun aForegroundServiceStaysWhenALaterStartIsRefused() {
    val starts = ServiceStarts()
    starts.begin(1, foreground = true)
    starts.begin(2, foreground = false)
    assertEquals(AfterStart.STAY, starts.after(fromApp = false, running = true, foreground = false))
    assertFalse(starts.mayStop(2))
  }

  private class Calls {
    val log = mutableListOf<String>()
  }

  private fun plan(calls: Calls, stopped: List<Boolean>, profile: Boolean, service: Boolean): CatchUpPlan {
    val stops = stopped.iterator()
    return planCatchUp(
      stopped = { (if (stops.hasNext()) stops.next() else stopped.last()).also { calls.log += "stopped=$it" } },
      openRuntime = { calls.log += "open"; profile },
      startService = { calls.log += "service"; service },
    )
  }

  @Test
  fun theWorkerRestartsTheServiceWhenAndroidAllows() {
    val calls = Calls()
    assertEquals(CatchUpPlan.SERVICE, plan(calls, listOf(false), profile = true, service = true))
    assertEquals(listOf("stopped=false", "open", "stopped=false", "service"), calls.log)
  }

  @Test
  fun theWorkerCatchesUpWhenTheServiceIsRefused() {
    assertEquals(CatchUpPlan.CATCH_UP, plan(Calls(), listOf(false), profile = true, service = false))
  }

  @Test
  fun theWorkerDoesNothingWithoutAProfile() {
    val calls = Calls()
    assertEquals(CatchUpPlan.NOTHING, plan(calls, listOf(false), profile = false, service = true))
    assertFalse("never starts the service for no profile", "service" in calls.log)
  }

  /** Regression: a stop that arrives before or while the runtime opens ends the run. */
  @Test
  fun aStoppedWorkerDoesNothing() {
    val before = Calls()
    assertEquals(CatchUpPlan.NOTHING, plan(before, listOf(true), profile = true, service = true))
    assertEquals(listOf("stopped=true"), before.log)
    val whileOpening = Calls()
    assertEquals(CatchUpPlan.NOTHING, plan(whileOpening, listOf(false, true), profile = true, service = true))
    assertFalse("service" in whileOpening.log)
  }
}
