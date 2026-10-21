#include "bindings/bindings.h"

#import <BackgroundTasks/BackgroundTasks.h>
#import <UIKit/UIKit.h>
#include <atomic>
#include <memory>

// Mycel's "slow mode" on iPhone and iPad: with no push server, nothing can
// wake a suspended app the moment a message is sent. iOS can lend it time
// on its own schedule, though: app refresh (short, a few times a day for an
// app used regularly) and processing (longer, usually while charging). Each
// launch catches up (src/background.rs): sync every conversation, wait a
// little for deliveries from keepers and store-and-forward peers, save.
// Neither runs after the user swipes Mycel away in the app switcher, until
// they open it again.
//
// Registered here, before the app finishes launching (iOS requires it), with
// the identifiers in Info.plist's BGTaskSchedulerPermittedIdentifiers.

extern "C" uint64_t mycel_background_begin(void);
extern "C" bool mycel_background_catch_up(uint64_t ticket, uint32_t seconds);
extern "C" void mycel_background_cancel(uint64_t ticket);

static NSString *const MycelRefreshTask = @"dev.mycel.refresh";
static NSString *const MycelProcessingTask = @"dev.mycel.processing";

/// What each kind may use (seconds). iOS documents no exact budget for app
/// refresh (about 30 s in practice); a processing task can be stopped any
/// time, which the expiration handler handles.
static const uint32_t MycelRefreshSeconds = 25;
static const uint32_t MycelProcessingSeconds = 120;

/// Ask for the next launches. iOS decides when (or whether) they happen; the
/// Simulator never runs them and refuses the request.
static void MycelScheduleBackgroundTasks(void) {
  BGTaskScheduler *scheduler = [BGTaskScheduler sharedScheduler];
  NSError *error = nil;
  BGAppRefreshTaskRequest *refresh = [[BGAppRefreshTaskRequest alloc] initWithIdentifier:MycelRefreshTask];
  refresh.earliestBeginDate = [NSDate dateWithTimeIntervalSinceNow:15 * 60];
  if (![scheduler submitTaskRequest:refresh error:&error]) {
    NSLog(@"mycel: background refresh not scheduled: %@", error.localizedDescription);
  }
  BGProcessingTaskRequest *processing = [[BGProcessingTaskRequest alloc] initWithIdentifier:MycelProcessingTask];
  processing.earliestBeginDate = [NSDate dateWithTimeIntervalSinceNow:60 * 60];
  processing.requiresNetworkConnectivity = NO; // peers may be on a Wi-Fi with no internet
  processing.requiresExternalPower = NO;
  error = nil;
  if (![scheduler submitTaskRequest:processing error:&error]) {
    NSLog(@"mycel: background processing not scheduled: %@", error.localizedDescription);
  }
}

/// Catch up for at most `seconds`, off the main thread; completes the task
/// exactly once, early if iOS takes the time back.
static void MycelRunBackgroundTask(BGTask *task, uint32_t seconds) {
  // Schedule the next launch first, so one stays queued even if this one
  // is cut short.
  MycelScheduleBackgroundTasks();
  auto done = std::make_shared<std::atomic<bool>>(false);
  // This launch's catch-up, taken before the expiration handler is set: a
  // cancel stops it even before the queued block starts, and never stops
  // another launch's.
  uint64_t ticket = mycel_background_begin();
  // Weak: the task holds its expiration handler.
  __weak BGTask *expiring = task;
  task.expirationHandler = ^{
    mycel_background_cancel(ticket);
    if (!done->exchange(true)) {
      [expiring setTaskCompletedWithSuccess:NO];
    }
  };
  dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
    bool ok = mycel_background_catch_up(ticket, seconds);
    if (!done->exchange(true)) {
      [task setTaskCompletedWithSuccess:ok];
    }
  });
}

static void MycelRegisterBackgroundTasks(void) {
  BGTaskScheduler *scheduler = [BGTaskScheduler sharedScheduler];
  [scheduler registerForTaskWithIdentifier:MycelRefreshTask
                                usingQueue:nil
                             launchHandler:^(__kindof BGTask *task) {
                               MycelRunBackgroundTask(task, MycelRefreshSeconds);
                             }];
  [scheduler registerForTaskWithIdentifier:MycelProcessingTask
                                usingQueue:nil
                             launchHandler:^(__kindof BGTask *task) {
                               MycelRunBackgroundTask(task, MycelProcessingSeconds);
                             }];
  // Ask again every time the user leaves the app.
  [[NSNotificationCenter defaultCenter] addObserverForName:UIApplicationDidEnterBackgroundNotification
                                                    object:nil
                                                     queue:nil
                                                usingBlock:^(NSNotification *note) {
                                                  MycelScheduleBackgroundTasks();
                                                }];
}

int main(int argc, char * argv[]) {
	@autoreleasepool {
		MycelRegisterBackgroundTasks();
	}
	ffi::start_app();
	return 0;
}
