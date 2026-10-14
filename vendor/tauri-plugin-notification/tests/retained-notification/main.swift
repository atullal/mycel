import UserNotifications

let content = UNMutableNotificationContent()
content.title = "Mycel"
content.body = "New message"
content.categoryIdentifier = ""
let request = UNNotificationRequest(identifier: "42", content: content, trigger: nil)

// A fresh handler represents a cold launch after the OS retained an alert.
let restarted = NotificationHandler()
let retained = restarted.toActiveNotification(request)
precondition(retained.id == 42)
precondition(retained.title == "Mycel" && retained.body == "New message")
precondition(retained.sound == "" && retained.attachments == nil)
// A cold-launch tap arrives before listeners; it remains consumable once.
restarted.rememberAction("tap", id: 42)
precondition(restarted.takePendingAction() == 42)
precondition(restarted.takePendingAction() == nil)
restarted.rememberAction("dismiss", id: 42)
precondition(restarted.takePendingAction() == nil)

let warm = NotificationHandler()
warm.saveNotification("42", Notification(sound: "Ping"))
precondition(warm.toActiveNotification(request).sound == "Ping")
// Fresh notification IDs for successive chat alerts must not retain forever.
for id in 0..<1_000 { warm.saveNotification(String(id), Notification(sound: "Ping")) }
precondition(warm.cachedNotificationCount == 256)
precondition(warm.toActiveNotification(request).sound == "") // safely evicted
warm.removeSavedNotifications(["999"])
precondition(warm.cachedNotificationCount == 255)
warm.removeSavedNotifications()
precondition(warm.cachedNotificationCount == 0)
precondition(warm.toActiveNotification(request).body == "New message")
let encoded = try JSONEncoder().encode(ReceivedNotification(actionId: "tap", inputValue: nil, notification: retained))
precondition(String(data: encoded, encoding: .utf8)!.contains("tap"))
print("PASS: retained notification conversion and tap payload after process restart")
