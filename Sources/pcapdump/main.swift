import SwiftPcap
import CPcap
import Foundation
import ArgumentParser

struct PcapDump: ParsableCommand {
    static var configuration: CommandConfiguration {
        CommandConfiguration(commandName: "pcapdump")
    }

    @Argument(help: "Path to the pcap or pcapng file")
    var filePath: String

    @Option(name: .long, help: "Start index (0-based) of packets to read")
    var from: Int = 0

    @Option(name: .long, help: "Inclusive end index of packets to read")
    var to: Int?

    func run() throws {
        var errbuf = [Int8](repeating: 0, count: Int(PCAP_ERRBUF_SIZE))

        guard let handle = pcap_open_offline(filePath, &errbuf) else {
            let errString = String(cString: &errbuf)
            throw RuntimeError("Failed to open pcap file: \(errString)")
        }

        defer { pcap_close(handle) }

        var packetIndex = 0

        var headerPointer: UnsafeMutablePointer<pcap_pkthdr>? = nil
        var dataPointer: UnsafePointer<UInt8>? = nil

        var startTs: Double?

        while pcap_next_ex(handle, &headerPointer, &dataPointer) == 1 {
            guard let header = headerPointer, let data = dataPointer else { continue }

            if packetIndex < from - 1 {
                packetIndex += 1
                continue
            }

            if let to = to, packetIndex > to - 1 {
                break
            }

            let ts: Double
            if startTs == nil {
                startTs = Double(header.pointee.ts.tv_sec) + Double(header.pointee.ts.tv_usec) / 1_000_000
                ts = 0
            } else {
                ts = Double(header.pointee.ts.tv_sec) + Double(header.pointee.ts.tv_usec) / 1_000_000 - startTs!
            }

            print("Packet \(packetIndex + 1):")
            print("  Time: \(ts)")
            print("  Length: \(header.pointee.len) bytes")

            // Attempt to detect protocol from Ethernet frame (assumes Ethernet II)
            if header.pointee.caplen >= 14 {
                let etherTypeOffset = 12
                let etherType = UInt16(data[etherTypeOffset]) << 8 | UInt16(data[etherTypeOffset + 1])

                if etherType == 0x0800, header.pointee.caplen >= 23 { // IPv4
                    let ipHeaderStart = 14
                    let protocolByte = data[ipHeaderStart + 9]

                    let protocolName: String
                    switch protocolByte {
                    case 1: protocolName = "ICMP"
                    case 2: protocolName = "IGMP"
                    case 6: protocolName = "TCP"
                    case 17: protocolName = "UDP"
                    case 41: protocolName = "IPv6"
                    case 47: protocolName = "GRE"
                    case 50: protocolName = "ESP"
                    case 51: protocolName = "AH"
                    case 58: protocolName = "ICMPv6"
                    case 89: protocolName = "OSPF"
                    case 132: protocolName = "SCTP"
                    case 137: protocolName = "MPLS-in-IP"
                    default: protocolName = "Other (\(protocolByte))"
                    }

                    print("  Protocol: IPv4/\(protocolName)")
                    let srcIP = (0..<4).map { String(data[ipHeaderStart + 12 + $0]) }.joined(separator: ".")
                    print("  Source: \(srcIP)")
                    let dstIP = (0..<4).map { String(data[ipHeaderStart + 16 + $0]) }.joined(separator: ".")
                    print("  Destination: \(dstIP)")
                } else if etherType == 0x0806 {
                    print("  Protocol: ARP")
                } else if etherType == 0x86DD, header.pointee.caplen >= 54 {
                    let ipHeaderStart = 14
                    let protocolByte = data[ipHeaderStart + 6]

                    let protocolName: String
                    switch protocolByte {
                    case 1: protocolName = "ICMP"
                    case 2: protocolName = "IGMP"
                    case 6: protocolName = "TCP"
                    case 17: protocolName = "UDP"
                    case 41: protocolName = "IPv6"
                    case 47: protocolName = "GRE"
                    case 50: protocolName = "ESP"
                    case 51: protocolName = "AH"
                    case 58: protocolName = "ICMPv6"
                    case 89: protocolName = "OSPF"
                    case 132: protocolName = "SCTP"
                    case 137: protocolName = "MPLS-in-IP"
                    default: protocolName = "Other (\(protocolByte))"
                    }
                    print("  Protocol: IPv6/\(protocolName)")

                    let srcSegments = (0..<8).map {
                        UInt16(data[ipHeaderStart + 8 + $0 * 2]) << 8 | UInt16(data[ipHeaderStart + 8 + $0 * 2 + 1])
                    }
                    let dstSegments = (0..<8).map {
                        UInt16(data[ipHeaderStart + 24 + $0 * 2]) << 8 | UInt16(data[ipHeaderStart + 24 + $0 * 2 + 1])
                    }
                    let srcIP = compressIPv6(srcSegments)
                    let dstIP = compressIPv6(dstSegments)
                    print("  Source: \(srcIP)")
                    print("  Destination: \(dstIP)")
                } else {
                    print(String(format: "  Protocol: Unknown EtherType (0x%04x)", etherType))
                }
            } else {
                print("  Protocol: Unknown (frame too short)")
            }

            let payload = UnsafeBufferPointer(start: data, count: Int(header.pointee.caplen))
            let hexPayload = payload.map { String(format: "%02x", $0) }.joined(separator: " ")
            print("  Data: \(hexPayload)\n")

            packetIndex += 1
        }
    }
}

PcapDump.main()

struct RuntimeError: Error, CustomStringConvertible {
    var message: String
    init(_ message: String) { self.message = message }
    var description: String { message }
}

extension Array {
    func chunked(into size: Int) -> [[Element]] {
        stride(from: 0, to: count, by: size).map {
            Array(self[$0..<Swift.min($0 + size, count)])
        }
    }
}

func compressIPv6(_ segments: [UInt16]) -> String {
    // Find the longest run of 0s
    var bestStart = -1
    var bestLength = 0
    var currentStart = -1
    var currentLength = 0

    for (i, segment) in segments.enumerated() {
        if segment == 0 {
            if currentStart == -1 {
                currentStart = i
                currentLength = 1
            } else {
                currentLength += 1
            }

            if currentLength > bestLength {
                bestStart = currentStart
                bestLength = currentLength
            }
        } else {
            currentStart = -1
            currentLength = 0
        }
    }

    // Build the string
    var result = [String]()
    var i = 0
    while i < segments.count {
        if i == bestStart {
            result.append("")
            i += bestLength
            if i >= segments.count {
                result.append("")
            }
        } else {
            result.append(String(format: "%x", segments[i]))
            i += 1
        }
    }

    return result.joined(separator: ":").replacingOccurrences(of: ":::", with: "::")
}
