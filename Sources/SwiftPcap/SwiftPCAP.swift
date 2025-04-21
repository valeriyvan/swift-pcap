// https://github.com/OperatorFoundation/SwiftPCAP/blob/main/Sources/SwiftPCAP/SwiftPCAP.swift

import Foundation
import CPcap

///
/// Struct defines the SwiftPCAP Module
///
public struct SwiftPCAP {

  ///
  /// Errors specific to this module
  ///
  public enum Errors: Error {
    case errorMessage(msg: String)
    case warningMessage(msg: String)
    case unknownError
  }
  
  ///
  /// SwiftPCAP base class
  ///
  public class Base {

    /// the libpcap pcap_t handle
    var pcapDevice: OpaquePointer? = nil

    /// packet header
    public var currentHeader: pcap_pkthdr

    /// base class initializer
    init() {
      // initialize memory for the pcap_pkthdr struct
      let ptr = UnsafeMutablePointer<pcap_pkthdr>.allocate(capacity: MemoryLayout<pcap_pkthdr>.size)
      currentHeader = ptr.pointee
      ptr.deinitialize(count: 1)
    }

    ///
    /// Get the next packet, if available. This function should not block.
    ///
    public func nextPacket() -> Data?
    {
        // get the next packet, should not block
        
        guard let pkt = pcap_next(pcapDevice, &currentHeader)
        else
        {
          if let error = pcap_geterr(pcapDevice)
          {
              print(error)
            if UnsafePointer<CChar>(error) != nil
              {
                  let errorString = String(cString: UnsafePointer<CChar>(error)!)
                  print("Bad pcap_next \(errorString)")
              }
          }

          return nil
        }
        
        let unsafePacket = UnsafeBufferPointer(start: pkt, count: Int(currentHeader.len))
        return Data(unsafePacket)
    }

    public func close()
    {
      pcap_close(pcapDevice)
    }

    ///
    /// Handle error return codes (defined in pcap.h)
    ///
    /// - parameter rc: An Int return code
    ///
    func handleReturnCode(_ rc: Int32) throws {
      if (rc != 0) {
        switch rc {
        case PCAP_WARNING:
          throw Errors.warningMessage(msg: "generic warning code")
        case PCAP_WARNING_PROMISC_NOTSUP:
          throw Errors.warningMessage(msg: "this device doesn't support promiscuous mode")
        case PCAP_WARNING_TSTAMP_TYPE_NOTSUP:
          throw Errors.warningMessage(msg: "the requested time stamp type is not supported")
        case PCAP_ERROR:
          throw Errors.errorMessage(msg: "generic error code")
        case PCAP_ERROR_BREAK:
          throw Errors.errorMessage(msg: "loop terminated by pcap_breakloop")
        case PCAP_ERROR_NOT_ACTIVATED:
          throw Errors.errorMessage(msg: "the capture needs to be activated")
        case PCAP_ERROR_ACTIVATED:
          throw Errors.errorMessage(msg: "the operation can't be performed on already activated captures")
        case PCAP_ERROR_NO_SUCH_DEVICE:
          throw Errors.errorMessage(msg: "no such device exists")
        case PCAP_ERROR_RFMON_NOTSUP:
          throw Errors.errorMessage(msg: "this device doesn't support rfmon (monitor) mode")
        case PCAP_ERROR_NOT_RFMON:
          throw Errors.errorMessage(msg: "operation supported only in monitor mode")
        case PCAP_ERROR_PERM_DENIED:
          throw Errors.errorMessage(msg: "no permission to open the device")
        case PCAP_ERROR_IFACE_NOT_UP:
          throw Errors.errorMessage(msg: "interface isn't up")
        case PCAP_ERROR_CANTSET_TSTAMP_TYPE:
          throw Errors.errorMessage(msg: "this device doesn't support setting the time stamp type")
        case PCAP_ERROR_PROMISC_PERM_DENIED:
          throw Errors.errorMessage(msg: "you don't have permission to capture in promiscuous mode")
        case PCAP_ERROR_TSTAMP_PRECISION_NOTSUP:
          throw Errors.errorMessage(msg: "the requested time stamp precision is not supported")
        default:
          throw Errors.unknownError
        }
      }
    }
  }

}
