# WireGuard Obfuscator - Swift Implementation

[![Build](https://github.com/mrmidi/wg-obfuscator-swift/actions/workflows/build.yml/badge.svg?branch=main)](https://github.com/mrmidi/wg-obfuscator-swift/actions/workflows/build.yml)
[![Tests](https://github.com/mrmidi/wg-obfuscator-swift/actions/workflows/test.yml/badge.svg?branch=main)](https://github.com/mrmidi/wg-obfuscator-swift/actions/workflows/test.yml)

Swift reimplementation of the WireGuard packet obfuscator for iOS/macOS platforms with Network Extension integration.

## Features

- **Swift 6 with Strict Concurrency**: Full actor-based concurrency model
- **Native Swift Testing**: Using Swift Testing framework
- **CMake 4.1**: Xcode project generation and Ninja builds
- **Protocol Masking**: STUN protocol masking for DPI bypass
- **Type-Safe**: No unsafe pointers

## Architecture

```text
WGObfuscator/
├── Core/                  # Core obfuscation algorithm
│   ├── ObfuscationEngine  # XOR + CRC8 cipher
│   ├── PacketCodec        # Encode/decode orchestrator
│   ├── WireGuardTypes     # Message type definitions
│   └── CryptoUtilities    # CRC8/CRC32 implementations
├── Masking/               # Protocol masking
│   ├── MaskingProtocol    # Protocol for maskers
│   ├── STUNMasker         # STUN implementation
│   ├── STUNPacket         # STUN packet structures
│   └── MaskingFactory     # Factory pattern
└── Proxy/                 # Network I/O
    ├── UDPProxy           # Network coordinator
    ├── ClientSession      # Per-client state machine
    └── NATTable           # Port mapping
```

## Building

### Swift Package Manager (Recommended)

```bash
swift build
swift test
```

### CMake + Xcode

```bash
# Generate Xcode project
cmake -G Xcode -S . -B build-xcode

# Open in Xcode
open build-xcode/WGObfuscator.xcodeproj
```

### CMake + Ninja (Fast CI Builds)

```bash
# Configure
cmake -G Ninja -S . -B build-ninja -DCMAKE_BUILD_TYPE=Release

# Build
cmake --build build-ninja --parallel

# Test
ctest --test-dir build-ninja --output-on-failure
```

## Installation

### Via Swift Package Manager

Add to your `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/mrmidi/wg-obfuscator-swift.git", from: "1.0.0")
]
```

### Via CMake

```bash
cmake --install build-ninja --prefix /usr/local
```

## Usage

### Basic Example

```swift
import WGObfuscator

// Create obfuscator
let codec = try PacketCodec(key: Data("your-secret-key".utf8))

// Encode WireGuard packet
let encoded = try await codec.encode(packet, type: .handshake)

// Decode obfuscated packet
let decoded = try await codec.decode(encoded)
```

### With STUN Masking

```swift
let masker = STUNMasker()

// Wrap in STUN
let stunPacket = try await masker.wrap(obfuscatedData)

// Unwrap from STUN
let original = try await masker.unwrap(stunPacket)
```

## Testing

The project uses TDD (Test-Driven Development) approach with comprehensive test coverage:

```bash
# Run all tests
swift test

# Run specific test
swift test --filter ObfuscationEngineTests

# With CMake
ctest --test-dir build-ninja -V
```

## License

Same as original wg-obfuscator project: GPL-3.0 License.

## Credits

- Original C implementation: [ClusterM/wg-obfuscator](https://github.com/ClusterM/wg-obfuscator)
- Swift reimplementation: Type-safe rewrite for iOS/macOS
