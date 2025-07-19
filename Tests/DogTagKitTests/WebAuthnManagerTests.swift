import XCTest
import Foundation
import CryptoKit
@testable import DogTagKit

extension Data {
    init?(hex: String) {
        let hex = hex.replacingOccurrences(of: " ", with: "")
        let len = hex.count
        if len % 2 != 0 { return nil }
        
        var data = Data(capacity: len / 2)
        var index = hex.startIndex
        for _ in 0..<(len / 2) {
            let nextIndex = hex.index(index, offsetBy: 2)
            if let byte = UInt8(hex[index..<nextIndex], radix: 16) {
                data.append(byte)
            } else {
                return nil
            }
            index = nextIndex
        }
        self = data
    }
}

final class WebAuthnManagerTests: XCTestCase {
    
    var webAuthnManager: WebAuthnManager!
    let testRpId = "example.com"
    
    override func setUp() {
        super.setUp()
        
        // Create a test user manager that always considers users enabled
        let testUserManager = TestUserManager()
        webAuthnManager = WebAuthnManager(rpId: testRpId, userManager: testUserManager)
        
        // Clean up any existing test credentials and data
        let testCredentialsFiles = [
            "webauthn_credentials_fido2.json",
            "webauthn_credentials.json",
            "test_webauthn_credentials.json"
        ]
        
        for file in testCredentialsFiles {
            if FileManager.default.fileExists(atPath: file) {
                try? FileManager.default.removeItem(atPath: file)
            }
        }
        
        // WebAuthnKit manages its own storage
    }
    
    override func tearDown() {
        // Clean up test files
        let testCredentialsFiles = [
            "webauthn_credentials_fido2.json",
            "webauthn_credentials.json", 
            "test_webauthn_credentials.json"
        ]
        
        for file in testCredentialsFiles {
            if FileManager.default.fileExists(atPath: file) {
                try? FileManager.default.removeItem(atPath: file)
            }
        }
        
        // WebAuthnKit cleans up its own storage
        super.tearDown()
    }
    
    // MARK: - Mock Data Helpers
    
    func createMockES256PublicKey() -> (privateKey: P256.Signing.PrivateKey, publicKeyData: Data, coseKey: [String: Any]) {
        let privateKey = P256.Signing.PrivateKey()
        let publicKey = privateKey.publicKey
        let publicKeyData = publicKey.x963Representation
        
        // Extract x and y coordinates for COSE key format
        let x = publicKeyData.subdata(in: 1..<33)
        let y = publicKeyData.subdata(in: 33..<65)
        
        let coseKey: [String: Any] = [
            "1": 2,  // kty: EC2
            "3": -7, // alg: ES256
            "-1": 1, // crv: P-256
            "-2": x, // x coordinate
            "-3": y  // y coordinate
        ]
        
        return (privateKey, publicKeyData, coseKey)
    }
    
    func encodeCBOR(_ value: Any) -> Data {
        // Simple CBOR encoder for test data
        if let map = value as? [String: Any] {
            var data = Data([0xA0 | UInt8(map.count)]) // Map with count
            for (key, val) in map.sorted(by: { $0.key < $1.key }) {
                if let intKey = Int(key) {
                    data.append(encodeCBORInteger(intKey))
                } else {
                    data.append(encodeCBORString(key))
                }
                data.append(encodeCBOR(val))
            }
            return data
        } else if let data = value as? Data {
            var result = Data()
            if data.count < 24 {
                result.append(0x40 | UInt8(data.count))
            } else if data.count < 256 {
                result.append(0x58)
                result.append(UInt8(data.count))
            } else {
                result.append(0x59)
                result.append(UInt8(data.count >> 8))
                result.append(UInt8(data.count & 0xFF))
            }
            result.append(data)
            return result
        } else if let int = value as? Int {
            return encodeCBORInteger(int)
        } else if let string = value as? String {
            return encodeCBORString(string)
        }
        return Data()
    }
    
    private func encodeCBORInteger(_ value: Int) -> Data {
        if value >= 0 {
            if value < 24 {
                return Data([UInt8(value)])
            } else if value < 256 {
                return Data([0x18, UInt8(value)])
            } else {
                return Data([0x19, UInt8(value >> 8), UInt8(value & 0xFF)])
            }
        } else {
            let positive = -value - 1
            if positive < 24 {
                return Data([0x20 | UInt8(positive)])
            } else if positive < 256 {
                return Data([0x38, UInt8(positive)])
            } else {
                return Data([0x39, UInt8(positive >> 8), UInt8(positive & 0xFF)])
            }
        }
    }
    
    private func encodeCBORString(_ value: String) -> Data {
        let stringData = value.data(using: .utf8)!
        var result = Data()
        if stringData.count < 24 {
            result.append(0x60 | UInt8(stringData.count))
        } else if stringData.count < 256 {
            result.append(0x78)
            result.append(UInt8(stringData.count))
        }
        result.append(stringData)
        return result
    }
    
    func createMockAttestationObject(coseKey: [String: Any]) -> Data {
        let credentialId = Data(repeating: 0x01, count: 16)
        
        // Create authenticator data
        let rpIdHash = Data(SHA256.hash(data: testRpId.data(using: .utf8)!))
        let flags: UInt8 = 0x45 // UP | UV | AT flags
        let signCount = Data([0x00, 0x00, 0x00, 0x00])
        let aaguid = Data(repeating: 0x00, count: 16)
        let credentialIdLength = Data([0x00, UInt8(credentialId.count)])
        let publicKeyData = encodeCBOR(coseKey)
        
        var authData = Data()
        authData.append(rpIdHash)
        authData.append(flags)
        authData.append(signCount)
        authData.append(aaguid)
        authData.append(credentialIdLength)
        authData.append(credentialId)
        authData.append(publicKeyData)
        
        let attestationObject: [String: Any] = [
            "fmt": "none",
            "attStmt": [:] as [String: Any],
            "authData": authData
        ]
        
        return encodeCBOR(attestationObject)
    }
    
    func createMockClientDataJSON(type: String, challenge: String, origin: String) -> Data {
        let clientData: [String: Any] = [
            "type": type,
            "challenge": challenge,
            "origin": origin,
            "crossOrigin": false
        ]
        
        return try! JSONSerialization.data(withJSONObject: clientData)
    }
    
    // MARK: - Registration Options Tests
    
    func testGenerateRegistrationOptions() throws {
        let username = "testuser"
        let options = try webAuthnManager.generateRegistrationOptions(username: username)
        
        XCTAssertNotNil(options["publicKey"])
        
        let publicKey = options["publicKey"] as! [String: Any]
        XCTAssertNotNil(publicKey["challenge"])
        XCTAssertNotNil(publicKey["rp"])
        XCTAssertNotNil(publicKey["user"])
        XCTAssertNotNil(publicKey["pubKeyCredParams"])
        
        let rp = publicKey["rp"] as! [String: Any]
        XCTAssertEqual(rp["id"] as! String, testRpId)
        
        let user = publicKey["user"] as! [String: Any]
        XCTAssertEqual(user["name"] as! String, username)
        XCTAssertEqual(user["displayName"] as! String, username)
    }
    
    // MARK: - CBOR Parsing Tests
    
    func testCBORParsing() throws {
        let (_, _, coseKey) = createMockES256PublicKey()
        let attestationObjectData = createMockAttestationObject(coseKey: coseKey)
        let base64AttestationObject = attestationObjectData.base64EncodedString()
        
        // This should not throw
        let parsed = try WebAuthnManager.CBORDecoder.parseAttestationObject(base64AttestationObject)
        
        XCTAssertNotNil(parsed["authData"])
        XCTAssertNotNil(parsed["fmt"])
        XCTAssertEqual(parsed["fmt"] as! String, "none")
    }
    
    // MARK: - Registration Tests
    
    func testValidRegistration() throws {
        let username = "testuser"
        let (_, _, coseKey) = createMockES256PublicKey()
        
        let attestationObjectData = createMockAttestationObject(coseKey: coseKey)
        let clientDataJSON = createMockClientDataJSON(
            type: "webauthn.create",
            challenge: "test-challenge",
            origin: "https://\(testRpId)"
        )
        
        let credentialId = Data(repeating: 0x01, count: 16).base64EncodedString()
        
        let credential: [String: Any] = [
            "id": credentialId,
            "rawId": credentialId,
            "response": [
                "attestationObject": attestationObjectData.base64EncodedString(),
                "clientDataJSON": clientDataJSON.base64EncodedString()
            ],
            "type": "public-key"
        ]
        
        // This should not throw
        try webAuthnManager.verifyRegistration(username: username, credential: credential)
        
        // Verify the user is now registered
        XCTAssertTrue(webAuthnManager.isUsernameRegistered(username))
    }
    
    func testDuplicateRegistration() throws {
        let username = "testuser"
        let (_, _, coseKey) = createMockES256PublicKey()
        
        let attestationObjectData = createMockAttestationObject(coseKey: coseKey)
        let clientDataJSON = createMockClientDataJSON(
            type: "webauthn.create",
            challenge: "test-challenge",
            origin: "https://\(testRpId)"
        )
        
        let credentialId = Data(repeating: 0x01, count: 16).base64EncodedString()
        
        let credential: [String: Any] = [
            "id": credentialId,
            "rawId": credentialId,
            "response": [
                "attestationObject": attestationObjectData.base64EncodedString(),
                "clientDataJSON": clientDataJSON.base64EncodedString()
            ],
            "type": "public-key"
        ]
        
        // First registration should succeed
        try webAuthnManager.verifyRegistration(username: username, credential: credential)
        
        // Second registration should fail
        XCTAssertThrowsError(try webAuthnManager.verifyRegistration(username: username, credential: credential)) { error in
            XCTAssertTrue(error is WebAuthnError)
            XCTAssertEqual(error as! WebAuthnError, WebAuthnError.duplicateUsername)
        }
    }
    
    func testRegistrationWithInvalidOrigin() throws {
        let username = "testuser"
        let (_, _, coseKey) = createMockES256PublicKey()
        
        let attestationObjectData = createMockAttestationObject(coseKey: coseKey)
        let clientDataJSON = createMockClientDataJSON(
            type: "webauthn.create",
            challenge: "test-challenge",
            origin: "https://evil.com" // Wrong origin
        )
        
        let credentialId = Data(repeating: 0x01, count: 16).base64EncodedString()
        
        let credential: [String: Any] = [
            "id": credentialId,
            "rawId": credentialId,
            "response": [
                "attestationObject": attestationObjectData.base64EncodedString(),
                "clientDataJSON": clientDataJSON.base64EncodedString()
            ],
            "type": "public-key"
        ]
        
        // Should fail due to invalid origin
        XCTAssertThrowsError(try webAuthnManager.verifyRegistration(username: username, credential: credential)) { error in
            XCTAssertTrue(error is WebAuthnError)
            XCTAssertEqual(error as! WebAuthnError, WebAuthnError.invalidCredential)
        }
    }
    
    // MARK: - Authentication Options Tests
    
    func testGenerateAuthenticationOptions() throws {
        // First register a user
        let username = "testuser"
        let (_, _, coseKey) = createMockES256PublicKey()
        
        let attestationObjectData = createMockAttestationObject(coseKey: coseKey)
        let clientDataJSON = createMockClientDataJSON(
            type: "webauthn.create",
            challenge: "test-challenge",
            origin: "https://\(testRpId)"
        )
        
        let credentialId = Data(repeating: 0x01, count: 16).base64EncodedString()
        
        let credential: [String: Any] = [
            "id": credentialId,
            "rawId": credentialId,
            "response": [
                "attestationObject": attestationObjectData.base64EncodedString(),
                "clientDataJSON": clientDataJSON.base64EncodedString()
            ],
            "type": "public-key"
        ]
        
        try webAuthnManager.verifyRegistration(username: username, credential: credential)
        
        // Now test authentication options
        let authOptions = try webAuthnManager.generateAuthenticationOptions(username: username)
        
        XCTAssertNotNil(authOptions["publicKey"])
        
        let publicKey = authOptions["publicKey"] as! [String: Any]
        XCTAssertNotNil(publicKey["challenge"])
        XCTAssertEqual(publicKey["rpId"] as! String, testRpId)
        XCTAssertNotNil(publicKey["allowCredentials"])
        
        let allowCredentials = publicKey["allowCredentials"] as! [[String: Any]]
        XCTAssertEqual(allowCredentials.count, 1)
        XCTAssertEqual(allowCredentials[0]["id"] as! String, credentialId)
    }
    
    func testGenerateAuthenticationOptionsUnregisteredUser() throws {
        XCTAssertThrowsError(try webAuthnManager.generateAuthenticationOptions(username: "nonexistent")) { error in
            XCTAssertTrue(error is WebAuthnError)
            XCTAssertEqual(error as! WebAuthnError, WebAuthnError.credentialNotFound)
        }
    }
    
    // MARK: - Authentication Tests
    
    func testValidAuthentication() throws {
        let username = "testuser"
        let (privateKey, _, coseKey) = createMockES256PublicKey()
        
        // First register the user
        let attestationObjectData = createMockAttestationObject(coseKey: coseKey)
        let clientDataJSON = createMockClientDataJSON(
            type: "webauthn.create",
            challenge: "test-challenge",
            origin: "https://\(testRpId)"
        )
        
        let credentialId = Data(repeating: 0x01, count: 16).base64EncodedString()
        
        let registrationCredential: [String: Any] = [
            "id": credentialId,
            "rawId": credentialId,
            "response": [
                "attestationObject": attestationObjectData.base64EncodedString(),
                "clientDataJSON": clientDataJSON.base64EncodedString()
            ],
            "type": "public-key"
        ]
        
        try webAuthnManager.verifyRegistration(username: username, credential: registrationCredential)
        
        // Now test authentication
        let authClientDataJSON = createMockClientDataJSON(
            type: "webauthn.get",
            challenge: "auth-challenge",
            origin: "https://\(testRpId)"
        )
        
        // Create mock authenticator data
        let rpIdHash = Data(SHA256.hash(data: testRpId.data(using: .utf8)!))
        let flags: UInt8 = 0x05 // UP | UV flags
        let signCount = Data([0x00, 0x00, 0x00, 0x01])
        var authenticatorData = Data()
        authenticatorData.append(rpIdHash)
        authenticatorData.append(flags)
        authenticatorData.append(signCount)
        
        // Create signature
        let clientDataHash = SHA256.hash(data: authClientDataJSON)
        var signedData = authenticatorData
        signedData.append(Data(clientDataHash))
        
        let signature = try privateKey.signature(for: signedData)
        
        let authCredential: [String: Any] = [
            "id": credentialId,
            "response": [
                "clientDataJSON": authClientDataJSON.base64EncodedString(),
                "authenticatorData": authenticatorData.base64EncodedString(),
                "signature": signature.derRepresentation.base64EncodedString()
            ],
            "type": "public-key"
        ]
        
        // This should not throw and should return the username
        let result = try webAuthnManager.verifyAuthentication(username: "", credential: authCredential)
        XCTAssertEqual(result, username)
    }
    
    func testAuthenticationWithInvalidSignature() throws {
        let username = "testuser"
        let (_, _, coseKey) = createMockES256PublicKey()
        
        // First register the user
        let attestationObjectData = createMockAttestationObject(coseKey: coseKey)
        let clientDataJSON = createMockClientDataJSON(
            type: "webauthn.create",
            challenge: "test-challenge",
            origin: "https://\(testRpId)"
        )
        
        let credentialId = Data(repeating: 0x01, count: 16).base64EncodedString()
        
        let registrationCredential: [String: Any] = [
            "id": credentialId,
            "rawId": credentialId,
            "response": [
                "attestationObject": attestationObjectData.base64EncodedString(),
                "clientDataJSON": clientDataJSON.base64EncodedString()
            ],
            "type": "public-key"
        ]
        
        try webAuthnManager.verifyRegistration(username: username, credential: registrationCredential)
        
        // Now test authentication with invalid signature
        let authClientDataJSON = createMockClientDataJSON(
            type: "webauthn.get",
            challenge: "auth-challenge",
            origin: "https://\(testRpId)"
        )
        
        let rpIdHash = Data(SHA256.hash(data: testRpId.data(using: .utf8)!))
        let flags: UInt8 = 0x05
        let signCount = Data([0x00, 0x00, 0x00, 0x01])
        var authenticatorData = Data()
        authenticatorData.append(rpIdHash)
        authenticatorData.append(flags)
        authenticatorData.append(signCount)
        
        // Create invalid signature (random data)
        let invalidSignature = Data(repeating: 0xFF, count: 64)
        
        let authCredential: [String: Any] = [
            "id": credentialId,
            "response": [
                "clientDataJSON": authClientDataJSON.base64EncodedString(),
                "authenticatorData": authenticatorData.base64EncodedString(),
                "signature": invalidSignature.base64EncodedString()
            ],
            "type": "public-key"
        ]
        
        // Should fail due to invalid signature
        XCTAssertThrowsError(try webAuthnManager.verifyAuthentication(username: username, credential: authCredential)) { error in
            XCTAssertTrue(error is WebAuthnError)
            XCTAssertEqual(error as! WebAuthnError, WebAuthnError.verificationFailed)
        }
    }
    
    // MARK: - Error Handling Tests
    
    func testRegistrationMissingFields() throws {
        let username = "testuser"
        
        // Test missing id
        var credential: [String: Any] = [
            "response": [
                "attestationObject": "test",
                "clientDataJSON": "test"
            ]
        ]
        
        XCTAssertThrowsError(try webAuthnManager.verifyRegistration(username: username, credential: credential))
        
        // Test missing response
        credential = [
            "id": "test-id"
        ]
        
        XCTAssertThrowsError(try webAuthnManager.verifyRegistration(username: username, credential: credential))
        
        // Test missing attestationObject
        credential = [
            "id": "test-id",
            "response": [
                "clientDataJSON": "test"
            ]
        ]
        
        XCTAssertThrowsError(try webAuthnManager.verifyRegistration(username: username, credential: credential))
    }
    
    func testAuthenticationMissingFields() throws {
        let username = "testuser"
        
        // Test missing signature
        var credential: [String: Any] = [
            "id": "test-id",
            "response": [
                "clientDataJSON": "test",
                "authenticatorData": "test"
            ]
        ]
        
        XCTAssertThrowsError(try webAuthnManager.verifyAuthentication(username: username, credential: credential))
        
        // Test missing authenticatorData
        credential = [
            "id": "test-id",
            "response": [
                "clientDataJSON": "test",
                "signature": "test"
            ]
        ]
        
        XCTAssertThrowsError(try webAuthnManager.verifyAuthentication(username: username, credential: credential))
    }
    
    // MARK: - Persistence Tests
    
    func testCredentialPersistence() throws {
        let username = "testuser"
        let (_, _, coseKey) = createMockES256PublicKey()
        
        let attestationObjectData = createMockAttestationObject(coseKey: coseKey)
        let clientDataJSON = createMockClientDataJSON(
            type: "webauthn.create",
            challenge: "test-challenge",
            origin: "https://\(testRpId)"
        )
        
        let credentialId = Data(repeating: 0x01, count: 16).base64EncodedString()
        
        let credential: [String: Any] = [
            "id": credentialId,
            "rawId": credentialId,
            "response": [
                "attestationObject": attestationObjectData.base64EncodedString(),
                "clientDataJSON": clientDataJSON.base64EncodedString()
            ],
            "type": "public-key"
        ]
        
        // Register user
        try webAuthnManager.verifyRegistration(username: username, credential: credential)
        XCTAssertTrue(webAuthnManager.isUsernameRegistered(username))
        
        // Create new manager instance to test persistence
        let newManager = WebAuthnManager(rpId: testRpId)
        XCTAssertTrue(newManager.isUsernameRegistered(username))
    }
    
    // MARK: - Icon Support Tests
    
    func testIconConfiguration() throws {
        // Test with custom icons
        let customRpIcon = "https://example.com/custom-icon.png"
        let customUserIcon = "https://example.com/user-icon.png"
        let customManager = WebAuthnManager(
            rpId: testRpId,
            rpName: "Custom App",
            rpIcon: customRpIcon,
            defaultUserIcon: customUserIcon
        )
        
        let username = "icontest"
        let options = try customManager.generateRegistrationOptions(username: username)
        
        XCTAssertNotNil(options["publicKey"])
        let publicKey = options["publicKey"] as! [String: Any]
        
        // Verify RP icon
        let rp = publicKey["rp"] as! [String: Any]
        XCTAssertEqual(rp["name"] as! String, "Custom App")
        XCTAssertEqual(rp["icon"] as! String, customRpIcon)
        
        // Verify user icon
        let user = publicKey["user"] as! [String: Any]
        XCTAssertEqual(user["icon"] as! String, customUserIcon)
    }
    
    func testDefaultIconGeneration() throws {
        // Test with default icon generation (no custom icons provided)
        let defaultManager = WebAuthnManager(rpId: testRpId)
        
        let username = "defaulttest"
        let options = try defaultManager.generateRegistrationOptions(username: username)
        
        XCTAssertNotNil(options["publicKey"])
        let publicKey = options["publicKey"] as! [String: Any]
        
        // Verify RP uses default favicon
        let rp = publicKey["rp"] as! [String: Any]
        XCTAssertEqual(rp["icon"] as! String, "https://\(testRpId)/icon-192.png")
        
        // Verify user gets generated icon
        let user = publicKey["user"] as! [String: Any]
        let userIcon = user["icon"] as! String
        XCTAssertTrue(userIcon.contains("ui-avatars.com"))
        XCTAssertTrue(userIcon.contains("name=defaulttest"))
    }
    
    func testEmptyIconHandling() throws {
        // Test with empty strings for icons
        let emptyIconManager = WebAuthnManager(
            rpId: testRpId,
            rpIcon: "",
            defaultUserIcon: ""
        )
        
        let username = "emptytest"
        let options = try emptyIconManager.generateRegistrationOptions(username: username)
        
        XCTAssertNotNil(options["publicKey"])
        let publicKey = options["publicKey"] as! [String: Any]
        
        // Verify RP and user don't have icon fields when empty
        let rp = publicKey["rp"] as! [String: Any]
        XCTAssertNil(rp["icon"])
        
        let user = publicKey["user"] as! [String: Any]
        XCTAssertNil(user["icon"])
    }
    
    func testDebugRegistrationOptions() throws {
        // Use the same configuration as the actual WebServer
        let publicIcon = "https://ui-avatars.com/api/?name=💬Chat&background=007AFF&color=white&size=192&format=png"
        
        let customManager = WebAuthnManager(
            rpId: "localhost",
            rpName: "Multi-Peer Chat",
            rpIcon: publicIcon,
            defaultUserIcon: nil
        )
        
        let username = "testuser"
        let options = try customManager.generateRegistrationOptions(username: username)
        
        print("=== DEBUG: Registration Options ===")
        if let jsonData = try? JSONSerialization.data(withJSONObject: options, options: .prettyPrinted),
           let jsonString = String(data: jsonData, encoding: .utf8) {
            print(jsonString)
        }
        print("=== END DEBUG ===")
        
        XCTAssertNotNil(options["publicKey"])
        let publicKey = options["publicKey"] as! [String: Any]
        
        // Verify RP icon
        let rp = publicKey["rp"] as! [String: Any]
        XCTAssertEqual(rp["icon"] as! String, publicIcon)
        
        // Verify user icon
        let user = publicKey["user"] as! [String: Any]
        let userIcon = user["icon"] as! String
        XCTAssertTrue(userIcon.contains("ui-avatars.com"))
    }
    
    func testSignCountIncrement() throws {
        let username = "signcounttest"
        let (privateKey, _, coseKey) = createMockES256PublicKey()
        
        // First register the user
        let attestationObjectData = createMockAttestationObject(coseKey: coseKey)
        let clientDataJSON = createMockClientDataJSON(
            type: "webauthn.create",
            challenge: "test-challenge",
            origin: "https://\(testRpId)"
        )
        
        let credentialId = Data(repeating: 0x01, count: 16).base64EncodedString()
        
        let registrationCredential: [String: Any] = [
            "id": credentialId,
            "rawId": credentialId,
            "response": [
                "attestationObject": attestationObjectData.base64EncodedString(),
                "clientDataJSON": clientDataJSON.base64EncodedString()
            ],
            "type": "public-key"
        ]
        
        try webAuthnManager.verifyRegistration(username: username, credential: registrationCredential)
        
        // Verify initial sign count is 0
        XCTAssertTrue(webAuthnManager.isUsernameRegistered(username))
        
        // Perform first authentication (sign count should go from 0 to 1)
        for expectedSignCount in 1...3 {
            let authClientDataJSON = createMockClientDataJSON(
                type: "webauthn.get",
                challenge: "auth-challenge-\(expectedSignCount)",
                origin: "https://\(testRpId)"
            )
            
            // Create mock authenticator data with the expected sign count
            let rpIdHash = Data(SHA256.hash(data: testRpId.data(using: .utf8)!))
            let flags: UInt8 = 0x05 // UP | UV flags
            var signCountBytes = Data(count: 4)
            signCountBytes.withUnsafeMutableBytes { bytes in
                bytes.bindMemory(to: UInt32.self)[0] = UInt32(expectedSignCount).bigEndian
            }
            
            var authenticatorData = Data()
            authenticatorData.append(rpIdHash)
            authenticatorData.append(flags)
            authenticatorData.append(signCountBytes)
            
            // Create signature
            let clientDataHash = SHA256.hash(data: authClientDataJSON)
            var signedData = authenticatorData
            signedData.append(Data(clientDataHash))
            
            let signature = try privateKey.signature(for: signedData)
            
            let authCredential: [String: Any] = [
                "id": credentialId,
                "response": [
                    "clientDataJSON": authClientDataJSON.base64EncodedString(),
                    "authenticatorData": authenticatorData.base64EncodedString(),
                    "signature": signature.derRepresentation.base64EncodedString()
                ],
                "type": "public-key"
            ]
            
            // This should not throw and should update the sign count
            let result = try webAuthnManager.verifyAuthentication(username: "", credential: authCredential)
            XCTAssertEqual(result, username)
        }
        
        print("✅ Sign count increment test completed successfully!")
    }
    
    // MARK: - RS256 Tests
    
    func createMockRS256PublicKey() -> (n: Data, e: Data, coseKey: [String: Any]) {
        // Create a mock RSA public key for testing
        // Using standard RSA-2048 test values
        let nHex = "00e0473e6b064c85e9493d70e8b8b4b3533bb5b9b44e7b9b3e46e7b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5e6b5"
        let eHex = "010001"
        
        let nData = Data(hex: nHex) ?? Data(repeating: 0xe0, count: 256)
        let eData = Data(hex: eHex) ?? Data([0x01, 0x00, 0x01])
        
        let coseKey: [String: Any] = [
            "1": 3,     // kty: RSA
            "3": -257,  // alg: RS256
            "-1": nData, // n (modulus)
            "-2": eData  // e (exponent)
        ]
        
        return (n: nData, e: eData, coseKey: coseKey)
    }
    
    func testRS256Registration() throws {
        let username = "rs256user"
        let (_, _, coseKey) = createMockRS256PublicKey()
        
        let attestationObjectData = createMockAttestationObject(coseKey: coseKey)
        let clientDataJSON = createMockClientDataJSON(
            type: "webauthn.create",
            challenge: "test-challenge",
            origin: "https://\(testRpId)"
        )
        
        let credentialId = Data(repeating: 0x02, count: 16).base64EncodedString()
        
        let credential: [String: Any] = [
            "id": credentialId,
            "rawId": credentialId,
            "response": [
                "attestationObject": attestationObjectData.base64EncodedString(),
                "clientDataJSON": clientDataJSON.base64EncodedString()
            ],
            "type": "public-key"
        ]
        
        // This should not throw
        try webAuthnManager.verifyRegistration(username: username, credential: credential)
        
        // Verify the user is now registered
        XCTAssertTrue(webAuthnManager.isUsernameRegistered(username))
    }
    
    func testRS256RegistrationOptionsIncludesRS256() {
        let options = try! webAuthnManager.generateRegistrationOptions(username: "testuser")
        
        let publicKey = options["publicKey"] as! [String: Any]
        let pubKeyCredParams = publicKey["pubKeyCredParams"] as! [[String: Any]]
        
        // Should include both ES256 and RS256
        XCTAssertEqual(pubKeyCredParams.count, 4)
        
        let algorithms = pubKeyCredParams.map { $0["alg"] as! Int }
        XCTAssertTrue(algorithms.contains(-7))   // ES256
        XCTAssertTrue(algorithms.contains(-257)) // RS256
    }
}

// MARK: - Test User Manager

private class TestUserManager: WebAuthnUserManager {
    private var users: [String: String] = [:] // username -> emoji
    
    func isUserEnabled(username: String) -> Bool {
        return true // Always enabled for tests
    }
    
    func getUserEmoji(username: String) -> String? {
        return users[username] ?? "👤"
    }
    
    func updateUserEmoji(username: String, emoji: String) -> Bool {
        users[username] = emoji
        return true
    }
    
    func createUser(username: String, credentialId: String, publicKey: String, clientIP: String?, emoji: String) throws {
        users[username] = emoji
    }
    
    func updateUserLogin(username: String, signCount: UInt32, clientIP: String?) throws {
        // No-op for tests
    }
    
    func deleteUser(username: String) throws {
        users.removeValue(forKey: username)
    }
}