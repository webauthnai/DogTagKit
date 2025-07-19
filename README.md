# DogTagKit

A modern FIDO2/WebAuthn server implementation in Swift that is fully compatible with Apple, Google, and Microsoft PassKeys. Created by FIDO3.ai, DogTagKit provides a complete solution for passwordless authentication in your applications.

## 🚀 Features

- **Full FIDO2/WebAuthn Support**: Complete implementation of the WebAuthn specification
- **Legacy U2F Compatibility**: Supports both modern FIDO2 and legacy U2F security keys
- **Universal PassKey Support**: Compatible with Apple PassKeys, Google Password Manager, and Microsoft Authenticator
- **Multi-Platform**: Supports macOS 14+ and iOS 17+
- **Multiple Storage Backends**: Choose between JSON files or SwiftData for credential storage
- **Platform Optimizations**: Browser and OS-specific optimizations for maximum compatibility
- **Built-in HTTP Server**: Ready-to-use HTTP endpoints for registration and authentication
- **JavaScript Client**: Includes complete client-side WebAuthn implementation
- **Security Key Support**: Full support for external FIDO2/U2F security keys
- **Admin Panel Ready**: User management and credential oversight capabilities

## 🔧 Supported Platforms

### Operating Systems
- **macOS 14+**: Full support including Touch ID and external security keys
- **iOS 17+**: Face ID, Touch ID, and external security key support
- **Linux**: Security key support via Firefox and Chrome
- **Windows 11**: Windows Hello and security key support

### Browsers
- **Safari**: Full PassKey and security key support
- **Chrome**: Platform authenticators and security keys
- **Firefox**: Security key support
- **Edge**: Windows Hello and security key support

### Authenticators
- **Apple**: Touch ID, Face ID, Apple PassKeys
- **Google**: Android biometrics, Google Password Manager
- **Microsoft**: Windows Hello, Microsoft Authenticator
- **Security Keys**: YubiKey, Solo, Titan, and other FIDO2/U2F devices

## 📦 Installation

### Swift Package Manager

Add DogTagKit to your `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/FIDO3ai/DogTagKit.git", from: "1.0.0")
]
```

Or add it through Xcode:
1. File → Add Package Dependencies
2. Enter the repository URL
3. Select your version requirements

## 🏃‍♂️ Quick Start

### Basic Setup

```swift
import DogTagKit

// Initialize the WebAuthn manager
let manager = WebAuthnManager(
    rpId: "yourdomain.com",
    rpName: "Your App Name",
    storageBackend: .swiftData("webauthn.db")
)

// Create the HTTP server
let server = WebAuthnServer(manager: manager)
```

### Registration Flow

```swift
// 1. Generate registration options
let registrationOptions = manager.generateRegistrationOptions(
    username: "user@example.com",
    displayName: "John Doe",
    enablePasskeys: true
)

// 2. Send to client, then verify the response
try manager.verifyRegistration(
    username: "user@example.com",
    credential: clientCredential,
    clientIP: "192.168.1.100"
)
```

### Authentication Flow

```swift
// 1. Generate authentication options
let authOptions = try manager.generateAuthenticationOptions(
    username: "user@example.com"
)

// 2. Verify the authentication response
let result = try manager.verifyAuthentication(
    credential: clientAssertion,
    clientIP: "192.168.1.100"
)

print("Authenticated user: \(result.username)")
```

## 🌟 Advanced Configuration

### Storage Backends

#### SwiftData (Recommended)
```swift
let manager = WebAuthnManager(
    rpId: "yourdomain.com",
    storageBackend: .swiftData("path/to/webauthn.db")
)
```

#### JSON Files
```swift
let manager = WebAuthnManager(
    rpId: "yourdomain.com",
    storageBackend: .json("credentials.json")
)
```

### Platform-Specific Options

#### Universal (All Platforms)
```swift
let options = manager.generateHybridRegistrationOptions(
    username: "user@example.com"
)
// Supports both PassKeys and security keys
```

#### Windows 11 Optimized
```swift
let options = manager.generateWindows11CompatibleRegistrationOptions(
    username: "user@example.com"
)
```

#### Linux/Security Key Only
```swift
let options = manager.generateLinuxCompatibleRegistrationOptions(
    username: "user@example.com"
)
```

#### Chrome Optimized
```swift
let options = manager.generateChromeCompatibleRegistrationOptions(
    username: "user@example.com"
)
```

### User Management

```swift
// Check if username is available
let isRegistered = manager.isUsernameRegistered("user@example.com")

// Get all registered users (admin function)
let allUsers = manager.getAllUsers()

// Check if user is enabled
let isEnabled = manager.isUserEnabled(username: "user@example.com")
```

## 🌐 HTTP Server Integration

### Built-in Server

DogTagKit includes a complete HTTP server implementation:

```swift
let server = WebAuthnServer(manager: manager)

// Handle incoming requests
let response = server.handleRequest(HTTPRequest(
    method: "POST",
    path: "/webauthn/register/begin",
    body: requestData
))
```

### API Endpoints

#### Registration
- `POST /webauthn/register/begin` - Start registration
- `POST /webauthn/register/begin/hybrid` - Universal registration (PassKeys + security keys)
- `POST /webauthn/register/begin/linux` - Linux/security key registration
- `POST /webauthn/register/complete` - Complete registration

#### Authentication
- `POST /webauthn/authenticate/begin` - Start authentication
- `POST /webauthn/authenticate/begin/hybrid` - Universal authentication
- `POST /webauthn/authenticate/complete` - Complete authentication

#### Utilities
- `POST /webauthn/username/check` - Check username availability

### Vapor Integration

DogTagKit includes built-in Vapor support:

```swift
import Vapor
import DogTagKit

// Add routes to your Vapor app
server.addVaporRoutes(to: app)
```

## 🎨 Frontend Integration

### JavaScript Client

DogTagKit includes a complete JavaScript client implementation:

```html
<!DOCTYPE html>
<html>
<head>
    <script>
        // Include the DogTagKit JavaScript
        // (Generated by WebAuthnContent.generateWebAuthnJS())
    </script>
</head>
<body>
    <script>
        // Initialize the WebAuthn client
        const webauthn = new WebAuthnClient('yourdomain.com');
        
        // Registration
        async function register() {
            try {
                const result = await webauthn.beginRegistration('user@example.com');
                console.log('Registration successful:', result);
            } catch (error) {
                console.error('Registration failed:', error);
            }
        }
        
        // Authentication
        async function authenticate() {
            try {
                const result = await webauthn.beginAuthentication('user@example.com');
                console.log('Authentication successful:', result);
            } catch (error) {
                console.error('Authentication failed:', error);
            }
        }
        
        // Usernameless authentication (discoverable credentials)
        async function authenticateUsernameless() {
            try {
                const result = await webauthn.beginAuthentication();
                console.log('Usernameless auth successful:', result);
            } catch (error) {
                console.error('Authentication failed:', error);
            }
        }
    </script>
</body>
</html>
```

### React Example

```jsx
import { useState } from 'react';

function WebAuthnComponent() {
    const [webauthn] = useState(new WebAuthnClient('yourdomain.com'));
    const [username, setUsername] = useState('');
    
    const handleRegister = async () => {
        try {
            await webauthn.beginRegistration(username);
            alert('Registration successful!');
        } catch (error) {
            alert(`Registration failed: ${error.message}`);
        }
    };
    
    const handleAuthenticate = async () => {
        try {
            const result = await webauthn.beginAuthentication(username);
            alert(`Welcome back, ${result.username}!`);
        } catch (error) {
            alert(`Authentication failed: ${error.message}`);
        }
    };
    
    return (
        <div>
            <input 
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="Email address"
            />
            <button onClick={handleRegister}>Register with PassKey</button>
            <button onClick={handleAuthenticate}>Sign In</button>
        </div>
    );
}
```

## 🔒 Security Features

- **Attestation Verification**: Supports multiple attestation formats including Apple, TPM, and Android
- **Origin Validation**: Ensures requests come from authorized domains
- **Signature Counter**: Prevents replay attacks with built-in counter verification
- **User Verification**: Configurable biometric and PIN requirements
- **Resident Keys**: Support for discoverable credentials
- **Algorithm Support**: ES256, RS256, EdDSA, ES384, ES512

## 🔧 Configuration Options

### WebAuthn Manager Configuration

```swift
let manager = WebAuthnManager(
    rpId: "yourdomain.com",
    webAuthnProtocol: .fido2CBOR,           // or .u2fV1A for legacy
    storageBackend: .swiftData("webauthn.db"),
    rpName: "Your Application",
    rpIcon: "https://yourdomain.com/icon.png",
    defaultUserIcon: "https://yourdomain.com/user-icon.png",
    adminUsername: "admin@yourdomain.com"   // Auto-promote to admin
)
```

### Registration Options

```swift
let options = WebAuthnRegistrationOptions(
    username: "user@example.com",
    displayName: "John Doe",
    enablePasskeys: true,
    timeout: 300000,  // 5 minutes
    userIcon: "https://example.com/user.png"
)
```

### Authentication Options

```swift
let options = WebAuthnAuthenticationOptions(
    username: "user@example.com",  // nil for usernameless
    timeout: 60000,                // 1 minute
    userVerification: "preferred"   // required, preferred, or discouraged
)
```

## 📊 Testing

Run the comprehensive test suite:

```bash
swift test
```

The test suite includes:
- **WebAuthnManagerTests**: Core functionality testing
- **WebAuthnApplePasskeysTests**: Apple-specific PassKey testing
- **WebAuthnPerformanceTests**: Performance benchmarks
- **WebAuthnSignCountTests**: Security counter validation
- **WebAuthnU2FTests**: Legacy U2F compatibility testing

## 🤝 Contributing

We welcome contributions! Please see our contributing guidelines and submit pull requests to help improve DogTagKit.

## 📄 License

DogTagKit is available under the MIT license. See the LICENSE file for more info.

## 🆘 Support

- **Documentation**: Full API documentation available
- **Issues**: Report bugs and feature requests on GitHub
- **Community**: Join our discussions for help and best practices

## 🏢 About FIDO3.ai

DogTagKit is created and maintained by FIDO3.ai, specialists in FIDO2/WebAuthn authentication solutions. We're committed to making passwordless authentication accessible and secure for everyone.

---

**Ready to go passwordless?** Get started with DogTagKit today and bring modern authentication to your server side Swift applications! 🚀

Copyright 2025 by FIDO3.ai
All rights reserved.
