import Foundation
public class Plugin: NSObject {
  public func trigger<T: Encodable>(_ name: String, data: T) throws {}
}
