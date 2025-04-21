// https://github.com/OperatorFoundation/SwiftPCAP/blob/main/Sources/SwiftPCAP/SwiftPCAPLive.swift

import Foundation
import CPcap

extension SwiftPCAP {
  ///
  /// Class implementing live packet capture using libpcap
  ///
  /// Uses libpcap through the CPcap wrapper.
  ///
  public class Live: Base {
      
    /// the libpcap buffer size (default 100MB)
    var bufferSize: Int32
    
    /// the libpcap snaplen
    var snaplen: Int32
      
    ///
    /// Initializer takes the interface name
    ///
    /// - parameter interface: The name of the interface to open
    /// - parameter bufferSize: The size of the libpcap input buffer
    /// - parameter snaplen: The libpcap snaplen parameter (packet size to capture)
    ///
    public init(interface: String, bufferSize: Int32 = 104857600, snaplen: Int32 = 8192) throws
    {
        // initialize Live capture parameters
        self.bufferSize = bufferSize
        self.snaplen = snaplen

        super.init()
        // prepare error buffer for libpcap to use
        let errbuf = UnsafeMutablePointer<Int8>.allocate(capacity: Int(PCAP_ERRBUF_SIZE))

        // create the pcap_t handle for live capture
        pcapDevice = pcap_create(interface, errbuf)

        if (pcapDevice == nil) {
            print("error pcapDevice is nil")
            throw Errors.errorMessage(msg: String(cString: errbuf))
        }

        // private func to set all live capture options
        do {
            try setOptions()
        }
        catch{
            print("Unexpected error setting options: \(error).")
        }
        
        // activate the live capture handle
        do {
            try handleReturnCode(pcap_activate(pcapDevice))
        }
        catch{
            print("Unexpected error activating: \(error).")
        }

        //!!! comment out to set the interface to blocking....
//        do {
//            try handleReturnCode(pcap_setnonblock(pcapDevice, 1, nil))
//        }
//        catch{
//            print("Unexpected error setting non-block: \(error).")
//        }
    }

    ///
    /// Set live-capture libpcap options
    ///
    /// - throws: SwiftPCAP.Errors
    ///
    private func setOptions() throws {
      // libpcap options
      // currently no error handling, may want to add that
      try handleReturnCode(pcap_set_buffer_size(pcapDevice, bufferSize))
      try handleReturnCode(pcap_set_snaplen(pcapDevice, snaplen))
      try handleReturnCode(pcap_set_promisc(pcapDevice, 1))
      try handleReturnCode(pcap_set_timeout(pcapDevice, 1))
    }
  }

}
