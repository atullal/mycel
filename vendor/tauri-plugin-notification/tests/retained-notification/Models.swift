// Minimal plugin model declarations allow the actual handler to be exercised
// against Apple's UserNotifications on macOS without linking the iOS UIKit host.
struct NotificationAttachment: Codable {}
struct Notification {
  var silent: Bool? = nil
  var sound: String? = nil
  var attachments: [NotificationAttachment]? = nil
}
