// Copyright 2019-2023 Tauri Programme within The Commons Conservancy
// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: MIT

import Tauri
import UserNotifications

public class NotificationHandler: NSObject, NotificationHandlerProtocol {

  public weak var plugin: Plugin?

  private var notificationsMap = [String: Notification]()
  private var notificationOrder = [String]()
  private let notificationsLock = NSLock()
  private let pendingActionLock = NSLock()
  private var pendingTapId: Int?

  // The OS may deliver the launch tap before the webview installs listeners.
  func rememberAction(_ actionId: String, id: Int) {
    guard actionId == "tap" else { return }
    pendingActionLock.lock()
    pendingTapId = id
    pendingActionLock.unlock()
  }

  func takePendingAction() -> Int? {
    pendingActionLock.lock()
    defer { pendingActionLock.unlock() }
    let id = pendingTapId
    pendingTapId = nil
    return id
  }

  internal func saveNotification(_ key: String, _ notification: Notification) {
    notificationsLock.lock()
    defer { notificationsLock.unlock() }
    if notificationsMap[key] == nil { notificationOrder.append(key) }
    notificationsMap.updateValue(notification, forKey: key)
    while notificationOrder.count > 256 {
      notificationsMap.removeValue(forKey: notificationOrder.removeFirst())
    }
  }

  internal var cachedNotificationCount: Int {
    notificationsLock.lock()
    defer { notificationsLock.unlock() }
    return notificationsMap.count
  }

  internal func removeSavedNotifications(_ identifiers: [String]? = nil) {
    notificationsLock.lock()
    defer { notificationsLock.unlock() }
    guard let identifiers = identifiers else {
      notificationsMap.removeAll()
      notificationOrder.removeAll()
      return
    }
    let removed = Set(identifiers)
    for id in removed { notificationsMap.removeValue(forKey: id) }
    notificationOrder.removeAll { removed.contains($0) }
  }

  private func savedNotification(_ identifier: String) -> Notification? {
    notificationsLock.lock()
    defer { notificationsLock.unlock() }
    return notificationsMap[identifier]
  }

  public func requestPermissions(with completion: ((Bool, Error?) -> Void)? = nil) {
    let center = UNUserNotificationCenter.current()
    center.requestAuthorization(options: [.badge, .alert, .sound]) { (granted, error) in
      completion?(granted, error)
    }
  }

  public func checkPermissions(with completion: ((UNAuthorizationStatus) -> Void)? = nil) {
    let center = UNUserNotificationCenter.current()
    center.getNotificationSettings { settings in
      completion?(settings.authorizationStatus)
    }
  }

  public func willPresent(notification: UNNotification) -> UNNotificationPresentationOptions {
    let notificationData = toActiveNotification(notification.request)
    try? self.plugin?.trigger("notification", data: notificationData)

    if let options = savedNotification(notification.request.identifier) {
      if options.silent ?? false {
        return UNNotificationPresentationOptions.init(rawValue: 0)
      }
    }

    return [
      .badge,
      .sound,
      .alert,
    ]
  }

  public func didReceive(response: UNNotificationResponse) {
    let originalNotificationRequest = response.notification.request
    let actionId = response.actionIdentifier

    var actionIdValue: String
    // We turn the two default actions (open/dismiss) into generic strings
    if actionId == UNNotificationDefaultActionIdentifier {
      actionIdValue = "tap"
    } else if actionId == UNNotificationDismissActionIdentifier {
      actionIdValue = "dismiss"
    } else {
      actionIdValue = actionId
    }

    var inputValue: String? = nil
    // If the type of action was for an input type, get the value
    if let inputType = response as? UNTextInputNotificationResponse {
      inputValue = inputType.userText
    }

    rememberAction(actionIdValue, id: Int(originalNotificationRequest.identifier) ?? -1)
    try? self.plugin?.trigger(
      "actionPerformed",
      data: ReceivedNotification(
        actionId: actionIdValue,
        inputValue: inputValue,
        notification: toActiveNotification(originalNotificationRequest)
      ))
  }

  func toActiveNotification(_ request: UNNotificationRequest) -> ActiveNotification {
    // Delivered notifications survive a process restart; this map does not.
    // The OS request remains authoritative for retained notification content.
    let notificationRequest = savedNotification(request.identifier)
    return ActiveNotification(
      id: Int(request.identifier) ?? -1,
      title: request.content.title,
      body: request.content.body,
      sound: notificationRequest?.sound ?? "",
      actionTypeId: request.content.categoryIdentifier,
      attachments: notificationRequest?.attachments
    )
  }

  func toPendingNotification(_ request: UNNotificationRequest) -> PendingNotification {
    return PendingNotification(
      id: Int(request.identifier) ?? -1,
      title: request.content.title,
      body: request.content.body
    )
  }
}

struct PendingNotification: Encodable {
  let id: Int
  let title: String
  let body: String
}

struct ActiveNotification: Encodable {
  let id: Int
  let title: String
  let body: String
  let sound: String
  let actionTypeId: String
  let attachments: [NotificationAttachment]?
}

struct ReceivedNotification: Encodable {
  let actionId: String
  let inputValue: String?
  let notification: ActiveNotification
}
