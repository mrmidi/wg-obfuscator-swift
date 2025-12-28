import XCTest
import Foundation
@testable import WGObfuscator

/// Performance benchmarks for packet processing pipeline.
/// Run with: swift test --filter PerformanceTests
final class PerformanceTests: XCTestCase {
    
    // MARK: - Constants
    
    /// Typical WireGuard data packet size (MTU 1280 minus overhead)
    static let typicalPacketSize = 1400
    
    /// Number of iterations for throughput tests
    static let iterationCount = 10_000
    
    // MARK: - XOR Engine Benchmarks
    
    /// Benchmark raw XOR obfuscation (the inner loop)
    func testXORObfuscationThroughput() throws {
        let engine = try ObfuscationEngine(key: Data("secretkey123".utf8))
        
        // Create typical data packet
        var basePacket = Data(count: Self.typicalPacketSize)
        basePacket[0] = 4 // WireGuard data type
        
        measure {
            for _ in 0..<Self.iterationCount {
                var packet = basePacket
                engine.xor(&packet)
            }
        }
        
        // Calculate throughput
        let bytes = Self.typicalPacketSize * Self.iterationCount
        print("XOR: \(Self.iterationCount) packets of \(Self.typicalPacketSize) bytes = \(bytes / 1_000_000) MB")
    }
    
    // MARK: - Codec Benchmarks
    
    /// Benchmark full encode path (obfuscate + header manipulation)
    func testCodecEncodeThroughput() throws {
        let codec = try PacketCodec(key: Data("secretkey123".utf8))
        
        var basePacket = Data(count: Self.typicalPacketSize)
        basePacket[0] = 4
        
        measure {
            for _ in 0..<Self.iterationCount {
                _ = try! codec.encode(basePacket, type: .data)
            }
        }
    }
    
    /// Benchmark full decode path (deobfuscate + header restoration)
    func testCodecDecodeThroughput() throws {
        let codec = try PacketCodec(key: Data("secretkey123".utf8))
        
        // First encode a packet to get valid encoded data
        var basePacket = Data(count: Self.typicalPacketSize)
        basePacket[0] = 4
        let encoded = try codec.encode(basePacket, type: .data)
        
        measure {
            for _ in 0..<Self.iterationCount {
                _ = try! codec.decode(encoded)
            }
        }
    }
    
    // MARK: - STUN Masker Benchmarks
    
    /// Benchmark STUN wrap (creating Data Indication packet)
    func testSTUNWrapThroughput() throws {
        let masker = STUNMasker()
        let payload = Data(count: Self.typicalPacketSize)
        
        measure {
            for _ in 0..<Self.iterationCount {
                _ = try! masker.wrap(payload)
            }
        }
    }
    
    /// Benchmark STUN unwrap (fast-path extraction)
    func testSTUNUnwrapThroughput() throws {
        let masker = STUNMasker()
        let payload = Data(count: Self.typicalPacketSize)
        let wrapped = try masker.wrap(payload)
        
        measure {
            for _ in 0..<Self.iterationCount {
                _ = try! masker.unwrap(wrapped)
            }
        }
    }
    
    // MARK: - Full Pipeline Benchmarks
    
    /// Benchmark complete outgoing pipeline: encode + STUN wrap
    func testFullOutgoingPipelineThroughput() throws {
        let codec = try PacketCodec(key: Data("secretkey123".utf8))
        let masker = STUNMasker()
        
        var basePacket = Data(count: Self.typicalPacketSize)
        basePacket[0] = 4
        
        measure {
            for _ in 0..<Self.iterationCount {
                let encoded = try! codec.encode(basePacket, type: .data)
                _ = try! masker.wrap(encoded)
            }
        }
    }
    
    /// Benchmark complete incoming pipeline: STUN unwrap + decode
    func testFullIncomingPipelineThroughput() throws {
        let codec = try PacketCodec(key: Data("secretkey123".utf8))
        let masker = STUNMasker()
        
        // Prepare wrapped packet
        var basePacket = Data(count: Self.typicalPacketSize)
        basePacket[0] = 4
        let encoded = try codec.encode(basePacket, type: .data)
        let wrapped = try masker.wrap(encoded)
        
        measure {
            for _ in 0..<Self.iterationCount {
                let unwrapped = try! masker.unwrap(wrapped)!
                _ = try! codec.decode(unwrapped)
            }
        }
    }
    
    /// Benchmark complete roundtrip: outgoing + incoming
    func testFullRoundtripThroughput() throws {
        let codec = try PacketCodec(key: Data("secretkey123".utf8))
        let masker = STUNMasker()
        
        var basePacket = Data(count: Self.typicalPacketSize)
        basePacket[0] = 4
        
        var totalOperations = 0
        
        measure {
            for _ in 0..<Self.iterationCount {
                // Outgoing
                let encoded = try! codec.encode(basePacket, type: .data)
                let wrapped = try! masker.wrap(encoded)
                
                // Incoming
                let unwrapped = try! masker.unwrap(wrapped)!
                _ = try! codec.decode(unwrapped)
                
                totalOperations += 1
            }
        }
    }
    
    // MARK: - Throughput Calculator
    
    /// Print human-readable throughput metrics
    func testPrintThroughputMetrics() throws {
        let codec = try PacketCodec(key: Data("secretkey123".utf8))
        let masker = STUNMasker()
        
        var basePacket = Data(count: Self.typicalPacketSize)
        basePacket[0] = 4
        
        let iterations = 100_000
        
        // Measure outgoing pipeline
        let startOut = CFAbsoluteTimeGetCurrent()
        for _ in 0..<iterations {
            let encoded = try codec.encode(basePacket, type: .data)
            _ = try masker.wrap(encoded)
        }
        let elapsedOut = CFAbsoluteTimeGetCurrent() - startOut
        
        // Prepare for incoming
        let encoded = try codec.encode(basePacket, type: .data)
        let wrapped = try masker.wrap(encoded)
        
        // Measure incoming pipeline
        let startIn = CFAbsoluteTimeGetCurrent()
        for _ in 0..<iterations {
            let unwrapped = try masker.unwrap(wrapped)!
            _ = try codec.decode(unwrapped)
        }
        let elapsedIn = CFAbsoluteTimeGetCurrent() - startIn
        
        // Calculate metrics
        let ppsOut = Double(iterations) / elapsedOut
        let ppsIn = Double(iterations) / elapsedIn
        let mbpsOut = (ppsOut * Double(Self.typicalPacketSize) * 8) / 1_000_000
        let mbpsIn = (ppsIn * Double(Self.typicalPacketSize) * 8) / 1_000_000
        let usPerPacketOut = (elapsedOut / Double(iterations)) * 1_000_000
        let usPerPacketIn = (elapsedIn / Double(iterations)) * 1_000_000
        
        print("""
        
        ══════════════════════════════════════════════════════════════
        THROUGHPUT METRICS (\(iterations) iterations, \(Self.typicalPacketSize) bytes/packet)
        ══════════════════════════════════════════════════════════════
        
        OUTGOING (encode + STUN wrap):
          - Time: \(String(format: "%.3f", elapsedOut)) seconds
          - Packets/sec: \(String(format: "%.0f", ppsOut))
          - Throughput: \(String(format: "%.1f", mbpsOut)) Mbit/s
          - Latency: \(String(format: "%.2f", usPerPacketOut)) µs/packet
        
        INCOMING (STUN unwrap + decode):
          - Time: \(String(format: "%.3f", elapsedIn)) seconds
          - Packets/sec: \(String(format: "%.0f", ppsIn))
          - Throughput: \(String(format: "%.1f", mbpsIn)) Mbit/s
          - Latency: \(String(format: "%.2f", usPerPacketIn)) µs/packet
        
        ══════════════════════════════════════════════════════════════
        
        """)
    }
}
