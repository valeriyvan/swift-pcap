import CPcap

public struct Pcap {
    
    public static func openOffline(path: String) -> OpaquePointer? {
        var errbuf = [Int8](repeating: 0, count: Int(PCAP_ERRBUF_SIZE))
        return pcap_open_offline(path, &errbuf)
    }

    public static func readPackets(
        from handle: OpaquePointer,
        handler: @escaping (pcap_pkthdr, UnsafeRawPointer) -> Void
    ) {
        // Wrap handler in Unmanaged reference so we can pass it through the C function
        let handlerBox = Unmanaged.passRetained(HandlerBox(handler: handler))

        let callback: pcap_handler = { userData, header, packetData in
            guard
                let userData,
                let header,
                let packetData
            else { return }

            // Unwrap the handler
            let box = Unmanaged<HandlerBox>.fromOpaque(userData).takeUnretainedValue()
            box.handler(header.pointee, packetData)
        }

        pcap_loop(handle, 0, callback, handlerBox.toOpaque())

        // Clean up retained handler box
        handlerBox.release()
    }

}

private final class HandlerBox {
    let handler: (pcap_pkthdr, UnsafeRawPointer) -> Void
    init(handler: @escaping (pcap_pkthdr, UnsafeRawPointer) -> Void) {
        self.handler = handler
    }
}
