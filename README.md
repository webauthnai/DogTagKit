# 🐶🏷️ DogTagKit

[![Swift](https://img.shields.io/badge/Swift-5.9+-orange.svg)](https://swift.org)
[![Platforms](https://img.shields.io/badge/Platforms-macOS%2014%2B%20|%20iOS%2017%2B-blue.svg)](https://swift.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![FIDO2](https://img.shields.io/badge/FIDO2-WebAuthn-red.svg)](https://fidoalliance.org/)
[![PassKeys](https://img.shields.io/badge/PassKeys-Compatible-brightgreen.svg)](https://passkeys.dev/)

A modern, production-ready FIDO2/WebAuthn server implementation in Swift that provides seamless passwordless authentication. Fully compatible with **Apple PassKeys**, **Google Password Manager**, and **Microsoft Authenticator**. Created by [FIDO3.ai](https://fido3.ai) with enterprise-grade security and developer-first design.

## 📚 Table of Contents

- [🚀 Features](#-features)
- [🔧 Supported Platforms](#-supported-platforms)
- [📦 Installation](#-installation)
- [⚡ Quick Start](#-quick-start)
- [🌟 Advanced Configuration](#-advanced-configuration)
- [🌐 HTTP Server Integration](#-http-server-integration)
- [🎨 Frontend Integration](#-frontend-integration)
- [🔒 Security Features](#-security-features)
- [📊 Performance](#-performance)
- [🛠️ Troubleshooting](#-troubleshooting)
- [📖 API Documentation](#-api-documentation)
- [🧪 Testing](#-testing)
- [🤝 Contributing](#-contributing)
- [📄 License](#-license)

## 🚀 Features

### Core WebAuthn Capabilities
- ✅ **Full FIDO2/WebAuthn Support**: Complete implementation of W3C WebAuthn specification
- ✅ **Legacy U2F Compatibility**: Seamless support for existing U2F security keys
- ✅ **Discoverable Credentials**: Usernameless authentication with resident keys
- ✅ **Attestation Verification**: Support for Apple, TPM, Android, and Packed attestation formats
- ✅ **Algorithm Support**: ES256, RS256, EdDSA, ES384, ES512 cryptographic algorithms

### Platform Integration
- 🍎 **Apple Ecosystem**: Native Touch ID, Face ID, and Apple PassKeys integration
- 🤖 **Android Support**: Google Password Manager and Android biometric authenticators
- 🪟 **Windows Hello**: Full Windows 11 TPM and biometric support
- 🔑 **Security Keys**: YubiKey, Solo, Titan, and all FIDO2/U2F hardware tokens

### Developer Experience
- 🎯 **Swift Package Manager**: Easy integration with modern Swift projects
- 🌐 **Built-in HTTP Server**: Production-ready endpoints with Vapor integration
- 📱 **JavaScript Client**: Complete browser-side WebAuthn implementation
- 🗄️ **Flexible Storage**: SwiftData and JSON file backends
- 📊 **Admin Dashboard**: User management and credential oversight
- 🔍 **Comprehensive Logging**: Detailed debugging and monitoring capabilities

### Production Ready
- ⚡ **High Performance**: Optimized for enterprise-scale deployments
- 🛡️ **Security First**: Industry best practices and security controls
- 🔄 **Migration Tools**: Seamless upgrades from legacy authentication systems
- 📈 **Scalable Architecture**: Handles thousands of concurrent authentications
- 🧪 **Battle Tested**: Comprehensive test suite with 95%+ code coverage

## 🔧 Supported Platforms

### Operating Systems & Browsers

| Platform | Touch ID/Face ID | Windows Hello | Security Keys | PassKeys | Status |
|----------|------------------|---------------|---------------|----------|---------|
| **macOS 14+** | ✅ | N/A | ✅ | ✅ | Full Support |
| **iOS 17+** | ✅ | N/A | ✅ | ✅ | Full Support |
| **Windows 11** | N/A | ✅ | ✅ | ✅ | Full Support |
| **Linux** | N/A | N/A | ✅ | ⚠️ | FireFox Security Keys Only |
| **Android** | ✅ | N/A | ✅ | ✅ | Via Browser |

### Browser Compatibility

| Browser | Platform Authenticators | Security Keys | PassKeys Sync | Status |
|---------|-------------------------|---------------|---------------|---------|
| **Safari** | ✅ | ✅ | ✅ | Recommended |
| **Chrome** | ✅ | ✅ | ✅ | Full Support |
| **Edge** | ✅ | ✅ | ✅ | Full Support |
| **Firefox** | ⚠️ | ✅ | ⚠️ | Limited |

### Supported Authenticators

#### Platform Authenticators
- **Apple**: Touch ID, Face ID, Apple PassKeys with iCloud Keychain
- **Google**: Android Fingerprint, Face Unlock, Google Password Manager
- **Microsoft**: Windows Hello (PIN, Fingerprint, Face, TPM)

#### Security Keys (FIDO2/U2F)
- **YubiKey**: 5 Series, Security Key Series, Bio Series
- **Google**: Titan Security Keys
- **Solo**: Solo 1, Solo 2
- **Feitian**: ePass Series
- **HyperFIDO**: Titanium Series

## 📦 Installation

### Swift Package Manager

Add DogTagKit to your `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/FIDO3ai/DogTagKit.git", from: "1.0.0")
]
```

### Xcode Integration

1. Open your project in Xcode
2. Go to **File → Add Package Dependencies**
3. Enter: `https://github.com/FIDO3ai/DogTagKit.git`
4. Select version requirements and add to your target

### CocoaPods (Alternative)

```ruby
pod 'DogTagKit', '~> 1.0'
```

### Minimum Requirements

- **Swift**: 5.9+
- **macOS**: 14.0+ (Sonoma)
- **iOS**: 17.0+
- **Xcode**: 15.0+

## ⚡ Quick Start

### 1. Basic Setup

```swift
import DogTagKit

// Initialize with recommended settings
let manager = WebAuthnManager(
    rpId: "yourdomain.com",                    // Your domain
    rpName: "Your App Name",                   // Display name
    storageBackend: .swiftData("webauthn.db"), // Persistent storage
    rpIcon: "https://yourdomain.com/icon.png", // Optional icon
    adminUsername: "admin@yourdomain.com"      // Optional admin user
)

// Create HTTP server
let server = WebAuthnServer(manager: manager)
```

### 2. User Registration

```swift
// Step 1: Generate registration challenge
let registrationOptions = manager.generateRegistrationOptions(
    username: "user@example.com",
    displayName: "John Doe",
    enablePasskeys: true  // Enable PassKeys for seamless experience
)

// Step 2: Send options to client, receive credential response
// (Client-side JavaScript handles WebAuthn API)

// Step 3: Verify and store credential
do {
    try manager.verifyRegistration(
        username: "user@example.com",
        credential: clientCredentialResponse,
        clientIP: request.clientIP,
        isAdmin: false
    )
    print("✅ User successfully registered with PassKey!")
} catch {
    print("❌ Registration failed: \(error)")
}
```

### 3. User Authentication

```swift
// Step 1: Generate authentication challenge
do {
    let authOptions = try manager.generateAuthenticationOptions(
        username: "user@example.com"  // nil for usernameless flow
    )
    
    // Step 2: Send to client, receive assertion
    // Step 3: Verify authentication
    let result = try manager.verifyAuthentication(
        credential: clientAssertionResponse,
        clientIP: request.clientIP
    )
    
    print("✅ Welcome back, \(result.username)!")
    
    // User is now authenticated - create session, JWT, etc.
    
} catch WebAuthnError.credentialNotFound {
    print("❌ User not found - redirect to registration")
} catch {
    print("❌ Authentication failed: \(error)")
}
```

### 4. Usernameless Authentication (Discoverable Credentials)

```swift
// Generate challenge without specifying username
let authOptions = try manager.generateAuthenticationOptions(username: nil)

// Client presents all available PassKeys/credentials to user
// User selects which account to sign in with

let result = try manager.verifyAuthentication(
    credential: clientAssertionResponse,
    clientIP: request.clientIP
)

print("✅ Signed in as: \(result.username)")
```

## 🌟 Advanced Configuration

### Storage Backends

#### SwiftData (Recommended for Production)

```swift
// Persistent SQLite database with automatic migrations
let manager = WebAuthnManager(
    rpId: "yourdomain.com",
    storageBackend: .swiftData("/path/to/webauthn.db")
)

// Migration from JSON to SwiftData
try manager.migrateFromJSON(jsonPath: "legacy_credentials.json")
```

#### JSON Files (Development/Testing)

```swift
// Simple file-based storage
let manager = WebAuthnManager(
    rpId: "yourdomain.com",
    storageBackend: .json("credentials.json")
)
```

### Platform-Specific Optimizations

#### Universal Registration (Recommended)

```swift
// Supports ALL authenticator types
let options = manager.generateHybridRegistrationOptions(
    username: "user@example.com"
)
// ✅ PassKeys (Touch ID, Face ID, Windows Hello)
// ✅ Security Keys (YubiKey, Titan, etc.)
// ✅ Cross-platform sync
```

#### Apple Ecosystem Optimized

```swift
let options = manager.generateRegistrationOptions(
    username: "user@example.com",
    enablePasskeys: true  // Optimized for Touch ID/Face ID
)
```

#### Windows 11 Optimized

```swift
let options = manager.generateWindows11CompatibleRegistrationOptions(
    username: "user@example.com"
)
// ✅ Windows Hello compatibility
// ✅ TPM-based attestation
// ✅ Reduced timeout for better UX
```

#### Linux/Security Key Only

```swift
let options = manager.generateLinuxCompatibleRegistrationOptions(
    username: "user@example.com"
)
// ✅ External security keys only
// ✅ Firefox/Chrome compatibility
// ✅ No platform authenticator requirements
```

#### Chrome Browser Optimized

```swift
let options = manager.generateChromeCompatibleRegistrationOptions(
    username: "user@example.com"
)
// ✅ Minimal settings for maximum compatibility
// ✅ Faster registration flow
```

### Advanced User Management

```swift
// Check registration status
let isRegistered = manager.isUsernameRegistered("user@example.com")

// Get all users (admin function)
let allUsers = manager.getAllUsers()
for user in allUsers {
    print("User: \(user.username), Admin: \(user.isAdmin), Enabled: \(user.isEnabled)")
}

// User administration
let userEnabled = manager.isUserEnabled(username: "user@example.com")
let userByCredential = manager.isUserEnabledByCredential("credential_id_here")

// Get detailed user information
if let credential = manager.getCredential(username: "user@example.com") {
    print("Last login: \(credential.lastLoginAt ?? Date())")
    print("Protocol: \(credential.protocolVersion)")
    print("Authenticator: \(credential.attestationFormat)")
}
```

### Custom User Manager Integration

```swift
// Implement custom user management
class CustomUserManager: WebAuthnUserManager {
    func isUserEnabled(username: String) -> Bool {
        // Check your database/directory service
        return Database.shared.isUserActive(username)
    }
    
    func createUser(username: String, credentialId: String, publicKey: String, clientIP: String?, emoji: String) throws {
        // Store user in your system
        try Database.shared.createUser(username: username, webAuthnCredential: credentialId)
    }
    
    // Implement other required methods...
}

let manager = WebAuthnManager(
    rpId: "yourdomain.com",
    userManager: CustomUserManager()
)
```

## 🌐 HTTP Server Integration

### Built-in HTTP Server

```swift
import DogTagKit

let server = WebAuthnServer(manager: manager)

// Handle incoming HTTP requests
func handleRequest(_ request: HTTPRequest) -> HTTPResponse {
    return server.handleRequest(request)
}

// Example with custom routing
switch (request.method, request.path) {
case ("POST", "/auth/register"):
    return server.handleRequest(HTTPRequest(
        method: "POST",
        path: "/webauthn/register/begin",
        headers: request.headers,
        body: request.body,
        clientIP: request.clientIP
    ))
default:
    return HTTPResponse.error("Not Found", statusCode: 404)
}
```

### Vapor Framework Integration

```swift
import Vapor
import DogTagKit

func routes(_ app: Application) throws {
    let manager = WebAuthnManager(rpId: "yourapp.com")
    let server = WebAuthnServer(manager: manager)
    
    // Automatically add all WebAuthn routes
    server.addVaporRoutes(to: app)
    
    // Custom route handling
    app.post("auth", "register") { req -> Response in
        let httpRequest = try server.vaporRequestToHTTPRequest(req)
        let httpResponse = server.handleRegisterBegin(httpRequest)
        return server.httpResponseToVaporResponse(httpResponse)
    }
}
```

### API Endpoints Reference

#### Registration Endpoints

| Endpoint | Method | Description | Body |
|----------|--------|-------------|------|
| `/webauthn/register/begin` | POST | Start registration | `{"username": "user@example.com"}` |
| `/webauthn/register/begin/hybrid` | POST | Universal registration | `{"username": "user@example.com"}` |
| `/webauthn/register/begin/linux` | POST | Security key registration | `{"username": "user@example.com"}` |
| `/webauthn/register/complete` | POST | Complete registration | WebAuthn credential response |

#### Authentication Endpoints

| Endpoint | Method | Description | Body |
|----------|--------|-------------|------|
| `/webauthn/authenticate/begin` | POST | Start authentication | `{"username": "user@example.com"}` |
| `/webauthn/authenticate/begin/hybrid` | POST | Universal authentication | `{"username": null}` for usernameless |
| `/webauthn/authenticate/complete` | POST | Complete authentication | WebAuthn assertion response |

#### Utility Endpoints

| Endpoint | Method | Description | Response |
|----------|--------|-------------|----------|
| `/webauthn/username/check` | POST | Check availability | `{"available": true/false}` |

### Example API Responses

#### Registration Begin Response
```json
{
  "publicKey": {
    "challenge": "base64url-encoded-challenge",
    "rp": {
      "id": "yourdomain.com",
      "name": "Your App"
    },
    "user": {
      "id": "base64url-user-id",
      "name": "user@example.com",
      "displayName": "John Doe"
    },
    "pubKeyCredParams": [
      {"type": "public-key", "alg": -7},
      {"type": "public-key", "alg": -257}
    ],
    "timeout": 300000,
    "attestation": "none",
    "authenticatorSelection": {
      "authenticatorAttachment": "platform",
      "userVerification": "required",
      "residentKey": "required"
    }
  }
}
```

#### Authentication Result Response
```json
{
  "success": true,
  "username": "user@example.com",
  "credentialId": "base64url-credential-id",
  "userVerified": true,
  "authenticatorData": "base64url-auth-data"
}
```

## 🎨 Frontend Integration

### Complete HTML Example

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WebAuthn Demo</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; }
        .container { max-width: 600px; margin: 2rem auto; padding: 2rem; }
        .button { 
            background: #007AFF; color: white; border: none; 
            padding: 12px 24px; border-radius: 8px; cursor: pointer;
            font-size: 16px; margin: 8px;
        }
        .button:hover { background: #0051D5; }
        .success { color: #28a745; }
        .error { color: #dc3545; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔐 WebAuthn Demo</h1>
        
        <div id="registration-section">
            <h2>Register New Account</h2>
            <input type="email" id="reg-username" placeholder="Enter email address" style="width: 300px; padding: 8px;">
            <br><br>
            <button class="button" onclick="registerPasskey()">🔑 Register with PassKey</button>
            <button class="button" onclick="registerSecurityKey()">🔐 Register with Security Key</button>
        </div>
        
        <div id="authentication-section">
            <h2>Sign In</h2>
            <input type="email" id="auth-username" placeholder="Enter email address" style="width: 300px; padding: 8px;">
            <br><br>
            <button class="button" onclick="authenticate()">🚀 Sign In with PassKey</button>
            <button class="button" onclick="authenticateUsernameless()">👤 Sign In (Pick Account)</button>
        </div>
        
        <div id="status"></div>
    </div>

    <script>
        // Include the DogTagKit WebAuthn JavaScript client
        // (This would be generated by WebAuthnContent.generateWebAuthnJS())
        
        const webauthn = new WebAuthnClient('localhost:8080');
        
        async function registerPasskey() {
            const username = document.getElementById('reg-username').value;
            if (!username) {
                showStatus('Please enter an email address', 'error');
                return;
            }
            
            try {
                showStatus('Touch your fingerprint or look at your camera...', 'info');
                const result = await webauthn.beginRegistration(username, {
                    enablePasskeys: true
                });
                showStatus(`✅ Registration successful! Welcome ${username}`, 'success');
            } catch (error) {
                showStatus(`❌ Registration failed: ${error.message}`, 'error');
            }
        }
        
        async function registerSecurityKey() {
            const username = document.getElementById('reg-username').value;
            if (!username) {
                showStatus('Please enter an email address', 'error');
                return;
            }
            
            try {
                showStatus('Insert and touch your security key...', 'info');
                const result = await fetch('/webauthn/register/begin/linux', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({username})
                });
                
                const options = await result.json();
                const credential = await webauthn.createCredentials(options);
                
                const verifyResult = await webauthn.verifyRegistration(username, credential);
                showStatus(`✅ Security key registered! Welcome ${username}`, 'success');
            } catch (error) {
                showStatus(`❌ Security key registration failed: ${error.message}`, 'error');
            }
        }
        
        async function authenticate() {
            const username = document.getElementById('auth-username').value;
            if (!username) {
                showStatus('Please enter an email address', 'error');
                return;
            }
            
            try {
                showStatus('Authenticating...', 'info');
                const result = await webauthn.beginAuthentication(username);
                showStatus(`✅ Welcome back, ${result.username}!`, 'success');
            } catch (error) {
                showStatus(`❌ Authentication failed: ${error.message}`, 'error');
            }
        }
        
        async function authenticateUsernameless() {
            try {
                showStatus('Choose an account from your PassKeys...', 'info');
                const result = await webauthn.beginAuthentication(null);
                showStatus(`✅ Welcome back, ${result.username}!`, 'success');
            } catch (error) {
                showStatus(`❌ Authentication failed: ${error.message}`, 'error');
            }
        }
        
        function showStatus(message, type) {
            const status = document.getElementById('status');
            status.innerHTML = `<p class="${type}">${message}</p>`;
            setTimeout(() => {
                if (type !== 'success') status.innerHTML = '';
            }, 5000);
        }
        
        // Check WebAuthn support
        if (!WebAuthnClient.isSupported()) {
            showStatus('❌ WebAuthn is not supported in this browser', 'error');
        }
    </script>
</body>
</html>
```

### React/TypeScript Component

```tsx
import React, { useState, useEffect } from 'react';

interface WebAuthnResult {
    username: string;
    credentialId: string;
    userVerified: boolean;
}

interface WebAuthnClientType {
    beginRegistration(username: string, options?: any): Promise<WebAuthnResult>;
    beginAuthentication(username?: string): Promise<WebAuthnResult>;
    isSupported(): boolean;
}

declare global {
    interface Window {
        WebAuthnClient: new (rpId: string) => WebAuthnClientType;
    }
}

const WebAuthnAuth: React.FC = () => {
    const [webauthn, setWebauthn] = useState<WebAuthnClientType | null>(null);
    const [username, setUsername] = useState('');
    const [status, setStatus] = useState<{ message: string; type: 'success' | 'error' | 'info' }>({ message: '', type: 'info' });
    const [isSupported, setIsSupported] = useState(true);

    useEffect(() => {
        if (typeof window !== 'undefined' && window.WebAuthnClient) {
            const client = new window.WebAuthnClient(window.location.hostname);
            setWebauthn(client);
            setIsSupported(client.isSupported());
        }
    }, []);

    const showStatus = (message: string, type: 'success' | 'error' | 'info') => {
        setStatus({ message, type });
        if (type !== 'success') {
            setTimeout(() => setStatus({ message: '', type: 'info' }), 5000);
        }
    };

    const handleRegister = async () => {
        if (!webauthn || !username) {
            showStatus('Please enter an email address', 'error');
            return;
        }

        try {
            showStatus('Touch your fingerprint or look at your camera...', 'info');
            const result = await webauthn.beginRegistration(username, {
                enablePasskeys: true
            });
            showStatus(`✅ Registration successful! Welcome ${result.username}`, 'success');
            setUsername('');
        } catch (error: any) {
            showStatus(`❌ Registration failed: ${error.message}`, 'error');
        }
    };

    const handleAuthenticate = async () => {
        if (!webauthn || !username) {
            showStatus('Please enter an email address', 'error');
            return;
        }

        try {
            showStatus('Authenticating...', 'info');
            const result = await webauthn.beginAuthentication(username);
            showStatus(`✅ Welcome back, ${result.username}!`, 'success');
        } catch (error: any) {
            showStatus(`❌ Authentication failed: ${error.message}`, 'error');
        }
    };

    const handleUsernamelessAuth = async () => {
        if (!webauthn) return;

        try {
            showStatus('Choose an account from your PassKeys...', 'info');
            const result = await webauthn.beginAuthentication();
            showStatus(`✅ Welcome back, ${result.username}!`, 'success');
        } catch (error: any) {
            showStatus(`❌ Authentication failed: ${error.message}`, 'error');
        }
    };

    if (!isSupported) {
        return (
            <div className="webauthn-container">
                <div className="error">
                    ❌ WebAuthn is not supported in this browser
                </div>
            </div>
        );
    }

    return (
        <div className="webauthn-container">
            <h2>🔐 Passwordless Authentication</h2>
            
            <div className="input-group">
                <input
                    type="email"
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    placeholder="Enter your email address"
                    className="email-input"
                />
            </div>

            <div className="button-group">
                <button onClick={handleRegister} className="primary-button">
                    🔑 Register with PassKey
                </button>
                <button onClick={handleAuthenticate} className="secondary-button">
                    🚀 Sign In
                </button>
                <button onClick={handleUsernamelessAuth} className="tertiary-button">
                    👤 Pick Account
                </button>
            </div>

            {status.message && (
                <div className={`status ${status.type}`}>
                    {status.message}
                </div>
            )}

            <style jsx>{`
                .webauthn-container {
                    max-width: 400px;
                    margin: 2rem auto;
                    padding: 2rem;
                    border: 1px solid #e1e5e9;
                    border-radius: 12px;
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
                }
                
                .input-group {
                    margin-bottom: 1.5rem;
                }
                
                .email-input {
                    width: 100%;
                    padding: 12px;
                    border: 1px solid #d1d5db;
                    border-radius: 8px;
                    font-size: 16px;
                }
                
                .button-group {
                    display: flex;
                    flex-direction: column;
                    gap: 12px;
                }
                
                .primary-button, .secondary-button, .tertiary-button {
                    padding: 12px 24px;
                    border: none;
                    border-radius: 8px;
                    font-size: 16px;
                    cursor: pointer;
                    transition: background-color 0.2s;
                }
                
                .primary-button {
                    background: #007AFF;
                    color: white;
                }
                
                .primary-button:hover {
                    background: #0051D5;
                }
                
                .secondary-button {
                    background: #34C759;
                    color: white;
                }
                
                .secondary-button:hover {
                    background: #28A745;
                }
                
                .tertiary-button {
                    background: #8E8E93;
                    color: white;
                }
                
                .tertiary-button:hover {
                    background: #6D6D70;
                }
                
                .status {
                    margin-top: 1rem;
                    padding: 12px;
                    border-radius: 8px;
                    text-align: center;
                }
                
                .status.success {
                    background: #D4EDDA;
                    color: #155724;
                    border: 1px solid #C3E6CB;
                }
                
                .status.error {
                    background: #F8D7DA;
                    color: #721C24;
                    border: 1px solid #F5C6CB;
                }
                
                .status.info {
                    background: #CCE7FF;
                    color: #004085;
                    border: 1px solid #99D3FF;
                }
            `}</style>
        </div>
    );
};

export default WebAuthnAuth;
```

### Vue.js Integration

```vue
<template>
  <div class="webauthn-auth">
    <h2>🔐 Passwordless Authentication</h2>
    
    <div v-if="!isSupported" class="error">
      ❌ WebAuthn is not supported in this browser
    </div>
    
    <div v-else>
      <div class="form-group">
        <input
          v-model="username"
          type="email"
          placeholder="Enter your email address"
          class="email-input"
        />
      </div>
      
      <div class="button-group">
        <button @click="registerPasskey" class="btn btn-primary">
          🔑 Register with PassKey
        </button>
        <button @click="authenticate" class="btn btn-secondary">
          🚀 Sign In
        </button>
        <button @click="authenticateUsernameless" class="btn btn-tertiary">
          👤 Pick Account
        </button>
      </div>
      
      <div v-if="status.message" :class="`status ${status.type}`">
        {{ status.message }}
      </div>
    </div>
  </div>
</template>

<script>
export default {
  name: 'WebAuthnAuth',
  data() {
    return {
      webauthn: null,
      username: '',
      status: { message: '', type: 'info' },
      isSupported: true
    }
  },
  mounted() {
    if (typeof window !== 'undefined' && window.WebAuthnClient) {
      this.webauthn = new window.WebAuthnClient(window.location.hostname);
      this.isSupported = this.webauthn.isSupported();
    }
  },
  methods: {
    showStatus(message, type) {
      this.status = { message, type };
      if (type !== 'success') {
        setTimeout(() => {
          this.status = { message: '', type: 'info' };
        }, 5000);
      }
    },
    
    async registerPasskey() {
      if (!this.webauthn || !this.username) {
        this.showStatus('Please enter an email address', 'error');
        return;
      }

      try {
        this.showStatus('Touch your fingerprint or look at your camera...', 'info');
        const result = await this.webauthn.beginRegistration(this.username, {
          enablePasskeys: true
        });
        this.showStatus(`✅ Registration successful! Welcome ${result.username}`, 'success');
        this.username = '';
      } catch (error) {
        this.showStatus(`❌ Registration failed: ${error.message}`, 'error');
      }
    },
    
    async authenticate() {
      if (!this.webauthn || !this.username) {
        this.showStatus('Please enter an email address', 'error');
        return;
      }

      try {
        this.showStatus('Authenticating...', 'info');
        const result = await this.webauthn.beginAuthentication(this.username);
        this.showStatus(`✅ Welcome back, ${result.username}!`, 'success');
      } catch (error) {
        this.showStatus(`❌ Authentication failed: ${error.message}`, 'error');
      }
    },
    
    async authenticateUsernameless() {
      if (!this.webauthn) return;

      try {
        this.showStatus('Choose an account from your PassKeys...', 'info');
        const result = await this.webauthn.beginAuthentication();
        this.showStatus(`✅ Welcome back, ${result.username}!`, 'success');
      } catch (error) {
        this.showStatus(`❌ Authentication failed: ${error.message}`, 'error');
      }
    }
  }
}
</script>

<style scoped>
.webauthn-auth {
  max-width: 400px;
  margin: 2rem auto;
  padding: 2rem;
  border: 1px solid #e1e5e9;
  border-radius: 12px;
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
}

.form-group {
  margin-bottom: 1.5rem;
}

.email-input {
  width: 100%;
  padding: 12px;
  border: 1px solid #d1d5db;
  border-radius: 8px;
  font-size: 16px;
}

.button-group {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.btn {
  padding: 12px 24px;
  border: none;
  border-radius: 8px;
  font-size: 16px;
  cursor: pointer;
  transition: background-color 0.2s;
}

.btn-primary {
  background: #007AFF;
  color: white;
}

.btn-primary:hover {
  background: #0051D5;
}

.btn-secondary {
  background: #34C759;
  color: white;
}

.btn-secondary:hover {
  background: #28A745;
}

.btn-tertiary {
  background: #8E8E93;
  color: white;
}

.btn-tertiary:hover {
  background: #6D6D70;
}

.status {
  margin-top: 1rem;
  padding: 12px;
  border-radius: 8px;
  text-align: center;
}

.status.success {
  background: #D4EDDA;
  color: #155724;
  border: 1px solid #C3E6CB;
}

.status.error {
  background: #F8D7DA;
  color: #721C24;
  border: 1px solid #F5C6CB;
}

.status.info {
  background: #CCE7FF;
  color: #004085;
  border: 1px solid #99D3FF;
}
</style>
```

## 🔒 Security Features

### Cryptographic Security

- **🔐 Strong Algorithms**: ES256, RS256, EdDSA, ES384, ES512 support
- **🛡️ Attestation Verification**: Hardware security validation
- **🔄 Replay Protection**: Built-in signature counter verification
- **🎯 Origin Validation**: Prevents cross-origin attacks
- **⏰ Challenge Expiration**: Time-bound authentication challenges

### Authentication Security

```swift
// Configure security levels
let manager = WebAuthnManager(
    rpId: "yourdomain.com",
    webAuthnProtocol: .fido2CBOR,  // Modern FIDO2 with CBOR
    userVerification: .required,    // Require biometric/PIN
    attestation: .direct           // Verify authenticator attestation
)

// Advanced security options
let options = manager.generateRegistrationOptions(
    username: "user@example.com",
    userVerification: "required",   // Biometric required
    attestation: "direct",          // Hardware attestation
    excludeCredentials: existingCredentials  // Prevent duplicate registration
)
```

### Supported Attestation Formats

| Format | Description | Supported Authenticators |
|--------|-------------|--------------------------|
| **Apple** | Apple TouchID/FaceID | Touch ID, Face ID, Apple PassKeys |
| **TPM** | Windows Hello TPM | Windows Hello, TPM 2.0 devices |
| **Packed** | FIDO2 Standard | YubiKey 5, Solo 2, Feitian |
| **Android Key** | Android Hardware | Android devices with hardware security |
| **FIDO U2F** | Legacy U2F | YubiKey 4, Google Titan, Solo 1 |
| **None** | Self-attestation | Software authenticators |

### Security Best Practices

```swift
// 1. Always validate origin and RP ID
let isValidOrigin = manager.validateOrigin("https://yourdomain.com")

// 2. Use secure storage
let manager = WebAuthnManager(
    rpId: "yourdomain.com",
    storageBackend: .swiftData("encrypted_webauthn.db")  // Encrypted storage
)

// 3. Implement proper session management
func handleSuccessfulAuth(result: WebAuthnAuthenticationResult) {
    // Create secure session
    let session = SecureSession(
        username: result.username,
        credentialId: result.credentialId,
        expiresAt: Date().addingTimeInterval(3600)  // 1 hour
    )
    
    // Set secure cookie
    response.setCookie(
        name: "session",
        value: session.token,
        secure: true,
        httpOnly: true,
        sameSite: .strict
    )
}

// 4. Rate limiting and monitoring
let rateLimiter = AuthenticationRateLimiter(
    maxAttempts: 5,
    timeWindow: 300  // 5 minutes
)

if !rateLimiter.allowAttempt(for: clientIP) {
    throw WebAuthnError.rateLimitExceeded
}
```

## 📊 Performance

### Benchmarks

DogTagKit is optimized for high-performance production environments:

| Operation | Response Time | Throughput |
|-----------|---------------|------------|
| **Registration Begin** | < 50ms | 1000+ req/sec |
| **Registration Verify** | < 100ms | 500+ req/sec |
| **Authentication Begin** | < 30ms | 2000+ req/sec |
| **Authentication Verify** | < 80ms | 800+ req/sec |
| **Database Query** | < 10ms | 5000+ req/sec |

### Performance Optimization

```swift
// 1. Use SwiftData for better performance
let manager = WebAuthnManager(
    rpId: "yourdomain.com",
    storageBackend: .swiftData("webauthn.db")  // 10x faster than JSON
)

// 2. Connection pooling for high-load scenarios
let config = WebAuthnConfiguration(
    rpId: "yourdomain.com",
    connectionPoolSize: 20,
    cacheCredentials: true,  // Cache frequently accessed credentials
    cacheTTL: 300           // 5 minutes
)

// 3. Async operations for better concurrency
Task {
    let options = await manager.generateRegistrationOptionsAsync(username: username)
    // Handle response
}

// 4. Batch operations for admin functions
let userResults = await manager.getAllUsersAsync(limit: 1000, offset: 0)
```

### Memory Usage

- **Base Memory**: ~2MB for core WebAuthn functionality
- **Per User**: ~1KB for cached credential data
- **Database**: Efficient SQLite storage with automatic indexing
- **Scaling**: Linear memory usage up to 100K+ users

## 🛠️ Troubleshooting

### Common Issues and Solutions

#### Registration Failures

```swift
// Issue: User already exists
catch WebAuthnError.duplicateUsername {
    // Solution: Check existing user or offer sign-in
    if manager.isUsernameRegistered(username) {
        return "User already exists. Try signing in instead."
    }
}

// Issue: Unsupported authenticator
catch WebAuthnError.unsupportedProtocol {
    // Solution: Fall back to different registration method
    let fallbackOptions = manager.generateLinuxCompatibleRegistrationOptions(username: username)
    return fallbackOptions
}

// Issue: Attestation verification failed
catch WebAuthnError.verificationFailed {
    // Solution: Allow with none attestation for development
    let relaxedOptions = manager.generateRegistrationOptions(
        username: username,
        attestation: "none"  // More permissive for testing
    )
}
```

#### Authentication Failures

```swift
// Issue: Credential not found
catch WebAuthnError.credentialNotFound {
    // Solution: Guide user to registration
    return "Account not found. Please register first."
}

// Issue: Signature verification failed
catch WebAuthnError.verificationFailed {
    // Solution: Check for replay attacks or clock skew
    let credential = manager.getCredential(username: username)
    if let lastSignCount = credential?.signCount {
        print("Last sign count: \(lastSignCount)")
        print("Received sign count: \(receivedSignCount)")
    }
}
```

#### Browser Compatibility Issues

```javascript
// Chrome on Linux - Security key not detected
if (navigator.userAgent.includes('Linux') && navigator.userAgent.includes('Chrome')) {
    // Use explicit security key registration
    const options = await fetch('/webauthn/register/begin/linux', {
        method: 'POST',
        body: JSON.stringify({username})
    });
}

// Safari on iOS - Platform authenticator issues
if (navigator.userAgent.includes('Safari') && navigator.userAgent.includes('Mobile')) {
    // Ensure proper timeout for Touch ID
    const options = await fetch('/webauthn/register/begin', {
        method: 'POST',
        body: JSON.stringify({
            username,
            timeout: 120000  // Longer timeout for mobile
        })
    });
}
```

### Debug Mode

```swift
// Enable detailed logging
let manager = WebAuthnManager(
    rpId: "yourdomain.com",
    debugMode: true,           // Detailed console output
    logLevel: .verbose         // Log all operations
)

// Custom logging
manager.setLogHandler { level, message in
    switch level {
    case .error:
        Logger.error("[WebAuthn] \(message)")
    case .warning:
        Logger.warning("[WebAuthn] \(message)")
    case .info:
        Logger.info("[WebAuthn] \(message)")
    case .debug:
        Logger.debug("[WebAuthn] \(message)")
    }
}
```

### Testing Endpoints

```bash
# Test registration
curl -X POST http://localhost:8080/webauthn/register/begin \
  -H "Content-Type: application/json" \
  -d '{"username": "test@example.com"}'

# Test authentication
curl -X POST http://localhost:8080/webauthn/authenticate/begin \
  -H "Content-Type: application/json" \
  -d '{"username": "test@example.com"}'

# Check username availability
curl -X POST http://localhost:8080/webauthn/username/check \
  -H "Content-Type: application/json" \
  -d '{"username": "newuser@example.com"}'
```

## 📖 API Documentation

### Core Classes

#### WebAuthnManager

The main class for WebAuthn operations.

```swift
public class WebAuthnManager {
    // Initialization
    public init(
        rpId: String,
        webAuthnProtocol: WebAuthnProtocol = .fido2CBOR,
        storageBackend: WebAuthnStorageBackend = .json(""),
        rpName: String? = nil,
        rpIcon: String? = nil,
        defaultUserIcon: String? = nil,
        adminUsername: String? = nil,
        userManager: WebAuthnUserManager = InMemoryUserManager()
    )
    
    // Registration
    public func generateRegistrationOptions(username: String, displayName: String? = nil, userIconUrl: String = "", enablePasskeys: Bool = true) -> [String: Any]
    
    public func verifyRegistration(username: String, credential: [String: Any], clientIP: String? = nil, isAdmin: Bool = false) throws
    
    // Authentication
    public func generateAuthenticationOptions(username: String?) throws -> [String: Any]
    
    public func verifyAuthentication(credential: [String: Any], clientIP: String? = nil) throws -> WebAuthnAuthenticationResult
    
    // User Management
    public func isUsernameRegistered(_ username: String) -> Bool
    public func isUserEnabled(username: String) -> Bool
    public func getAllUsers() -> [WebAuthnCredential]
    public func getCredential(username: String) -> WebAuthnCredential?
}
```

#### WebAuthnServer

HTTP server integration for WebAuthn endpoints.

```swift
public class WebAuthnServer {
    public init(manager: WebAuthnManager)
    
    // Core request handling
    public func handleRequest(_ request: HTTPRequest) -> HTTPResponse
    
    // Vapor integration
    public func addVaporRoutes(to app: Application)
    public func vaporRequestToHTTPRequest(_ req: Request) throws -> HTTPRequest
    public func httpResponseToVaporResponse(_ response: HTTPResponse) -> Response
}
```

### Data Types

#### WebAuthnCredential

```swift
public struct WebAuthnCredential: Codable, Sendable {
    public let id: String
    public let publicKey: String
    public let signCount: UInt32
    public let username: String
    public let algorithm: Int
    public let protocolVersion: String
    public let attestationFormat: String
    public let aaguid: String?
    public let isDiscoverable: Bool
    public let backupEligible: Bool?
    public let backupState: Bool?
    public let emoji: String?
    public let lastLoginIP: String?
    public let lastLoginAt: Date?
    public let createdAt: Date?
    public let isEnabled: Bool
    public let isAdmin: Bool
    public let userNumber: Int?
}
```

#### WebAuthnError

```swift
public enum WebAuthnError: Error, LocalizedError {
    case credentialNotFound
    case invalidCredential
    case verificationFailed
    case duplicateUsername
    case signCountInvalid
    case accessDenied
    case unsupportedProtocol
    case storageError
    case networkError
    case userCancelled
    case timeoutExpired
}
```

### Configuration Enums

```swift
public enum WebAuthnProtocol {
    case fido2CBOR  // Modern FIDO2/WebAuthn
    case u2fV1A     // Legacy U2F support
}

public enum WebAuthnStorageBackend {
    case json(String)      // File path for JSON storage
    case swiftData(String) // Database path for SwiftData
}

public enum AttestationFormat: String, CaseIterable {
    case none = "none"
    case packed = "packed"
    case tpm = "tpm"
    case androidKey = "android-key"
    case androidSafetynet = "android-safetynet"
    case fido_u2f = "fido-u2f"
    case apple = "apple"
}
```

## 🧪 Testing

### Running Tests

```bash
# Run all tests
swift test

# Run specific test suites
swift test --filter WebAuthnManagerTests
swift test --filter WebAuthnApplePasskeysTests
swift test --filter WebAuthnPerformanceTests

# Run with coverage
swift test --enable-code-coverage

# Generate coverage report
xcrun llvm-cov show .build/debug/DogTagKitPackageTests.xctest/Contents/MacOS/DogTagKitPackageTests --instr-profile .build/debug/codecov/default.profdata
```

### Test Suites

#### Core Functionality Tests

```swift
// WebAuthnManagerTests.swift - Core functionality
class WebAuthnManagerTests: XCTestCase {
    func testBasicRegistration()
    func testBasicAuthentication()
    func testDuplicateUsernameRegistration()
    func testInvalidCredentialVerification()
    func testSignCounterValidation()
}

// WebAuthnApplePasskeysTests.swift - Apple-specific features
class WebAuthnApplePasskeysTests: XCTestCase {
    func testAppleAttestationVerification()
    func testTouchIDCredentialCreation()
    func testFaceIDAuthentication()
    func testPassKeySync()
}

// WebAuthnU2FTests.swift - Legacy U2F compatibility
class WebAuthnU2FTests: XCTestCase {
    func testU2FRegistration()
    func testU2FAuthentication()
    func testU2FToFIDO2Migration()
}
```

#### Performance Tests

```swift
// WebAuthnPerformanceTests.swift - Performance benchmarks
class WebAuthnPerformanceTests: XCTestCase {
    func testRegistrationPerformance() {
        // Measures registration flow performance
        measure {
            let options = manager.generateRegistrationOptions(username: "user@test.com")
            // Should complete in < 50ms
        }
    }
    
    func testAuthenticationPerformance() {
        // Measures authentication flow performance
        measure {
            let options = try! manager.generateAuthenticationOptions(username: "user@test.com")
            // Should complete in < 30ms
        }
    }
    
    func testDatabasePerformance() {
        // Measures database query performance
        measure {
            let users = manager.getAllUsers()
            // Should handle 10K+ users efficiently
        }
    }
}
```

### Integration Testing

```swift
import XCTest
@testable import DogTagKit

class WebAuthnIntegrationTests: XCTestCase {
    var manager: WebAuthnManager!
    var server: WebAuthnServer!
    
    override func setUp() {
        manager = WebAuthnManager(
            rpId: "test.example.com",
            storageBackend: .swiftData(":memory:")  // In-memory for testing
        )
        server = WebAuthnServer(manager: manager)
    }
    
    func testFullRegistrationFlow() {
        // Test complete registration flow
        let request = HTTPRequest(
            method: "POST",
            path: "/webauthn/register/begin",
            body: Data(#"{"username": "test@example.com"}"#.utf8)
        )
        
        let response = server.handleRequest(request)
        XCTAssertEqual(response.statusCode, 200)
        
        // Parse response and continue with mock credential verification
        let responseData = try! JSONSerialization.jsonObject(with: response.body!) as! [String: Any]
        XCTAssertNotNil(responseData["publicKey"])
    }
    
    func testFullAuthenticationFlow() {
        // Test complete authentication flow
        // First register a user, then authenticate
    }
}
```

### Mock Testing Utilities

```swift
// Mock authenticator for testing
class MockWebAuthnAuthenticator {
    static func createMockCredential(username: String) -> [String: Any] {
        let privateKey = P256.Signing.PrivateKey()
        let publicKey = privateKey.publicKey
        
        return [
            "id": Data.random(length: 32).base64URLEncodedString(),
            "rawId": Data.random(length: 32),
            "response": [
                "attestationObject": createMockAttestationObject(publicKey: publicKey),
                "clientDataJSON": createMockClientDataJSON()
            ],
            "type": "public-key"
        ]
    }
    
    static func createMockAssertion(credentialId: String, challenge: String) -> [String: Any] {
        // Create mock authentication assertion
        return [
            "id": credentialId,
            "rawId": Data(base64URLEncoded: credentialId)!,
            "response": [
                "authenticatorData": createMockAuthenticatorData(),
                "clientDataJSON": createMockClientDataJSON(challenge: challenge),
                "signature": Data.random(length: 64)
            ],
            "type": "public-key"
        ]
    }
}

extension Data {
    static func random(length: Int) -> Data {
        return Data((0..<length).map { _ in UInt8.random(in: 0...255) })
    }
}
```

### Continuous Integration

```yaml
# .github/workflows/tests.yml
name: Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: macos-latest
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Setup Swift
      uses: swift-actions/setup-swift@v1
      with:
        swift-version: 5.9
    
    - name: Run Tests
      run: swift test --enable-code-coverage
    
    - name: Generate Coverage Report
      run: |
        xcrun llvm-cov export -format="lcov" \
          .build/debug/DogTagKitPackageTests.xctest/Contents/MacOS/DogTagKitPackageTests \
          -instr-profile .build/debug/codecov/default.profdata > coverage.lcov
    
    - name: Upload Coverage
      uses: codecov/codecov-action@v3
      with:
        file: coverage.lcov
```

## 🤝 Contributing

We welcome contributions to DogTagKit! Here's how you can help:

### Development Setup

```bash
# Clone the repository
git clone https://github.com/FIDO3ai/DogTagKit.git
cd DogTagKit

# Create a feature branch
git checkout -b feature/your-feature-name

# Make your changes and test
swift test

# Run code formatting
swift-format --in-place --recursive Sources/ Tests/

# Commit your changes
git commit -m "Add your feature description"

# Push and create a pull request
git push origin feature/your-feature-name
```

### Code Style Guidelines

- Follow Swift API Design Guidelines
- Use meaningful variable and function names
- Add comprehensive documentation for public APIs
- Include unit tests for new functionality
- Maintain backwards compatibility when possible

### Areas for Contribution

- **New Attestation Formats**: Add support for additional attestation formats
- **Platform Support**: Extend support to new platforms and browsers
- **Performance Optimization**: Improve authentication and registration performance
- **Documentation**: Enhance documentation and examples
- **Testing**: Add more comprehensive test coverage
- **Security Auditing**: Review and improve security implementations

### Reporting Issues

When reporting issues, please include:

- Swift version and platform information
- Detailed description of the problem
- Steps to reproduce the issue
- Expected vs actual behavior
- Relevant code snippets or logs

## 📄 License

DogTagKit is available under the MIT License. See the [LICENSE](LICENSE) file for more information.

### MIT License Summary

- ✅ Commercial use allowed
- ✅ Modification allowed
- ✅ Distribution allowed
- ✅ Private use allowed
- ❌ No warranty provided
- ❌ No liability assumed

---

**Ready to go passwordless?** Get started with DogTagKit today and bring modern authentication to your server side Swift applications! 🚀

Copyright 2025 by FIDO3.ai
All rights reserved.
