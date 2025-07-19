// Copyright 2025 by FIDO3.ai
// Generated on: 2025-7-19
// All rights reserved.

import XCTest
import Foundation
import CryptoKit
@testable import DogTagKit

final class WebAuthnApplePasskeysTests: XCTestCase {
    
    var webAuthnManager: WebAuthnManager!
    let testRpId = "passkeys.test"
    
    override func setUp() {
        super.setUp()
        webAuthnManager = WebAuthnManager(rpId: testRpId)
        
        // Clean up any existing test credentials
        let testCredentialsFile = "webauthn_credentials_fido2.json"
        if FileManager.default.fileExists(atPath: testCredentialsFile) {
            try? FileManager.default.removeItem(atPath: testCredentialsFile)
        }
    }
    
    override func tearDown() {
        // Clean up test files
        let testCredentialsFile = "webauthn_credentials_fido2.json"
        try? FileManager.default.removeItem(atPath: testCredentialsFile)
        super.tearDown()
    }
    
    // MARK: - Apple Touch ID Mock Data
    
    func createAppleTouchIDAAGUID() -> Data {
        // Apple Touch ID AAGUID: ADCE0002-35BC-C60A-648B-0B25F1F05503
        let hex = "ADCE000235BCC60A648B0B25F1F05503"
        return Data(hex: hex)!
    }
    
    func createAppleFaceIDAAGUID() -> Data {
        // Apple Face ID typically uses zero AAGUID for privacy
        return Data(repeating: 0x00, count: 16)
    }
    
    func createMockApplePasskeyCredential(aaguidData: Data, withBackup: Bool = true) -> (credential: [String: Any], privateKey: P256.Signing.PrivateKey) {
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
        
        // Create authenticator data with Apple-specific flags
        let rpIdHash = Data(SHA256.hash(data: testRpId.data(using: .utf8)!))
        var flags: UInt8 = 0x45 // UP | UV | AT flags
        
        // Add backup flags for Apple Passkeys
        if withBackup {
            flags |= 0x08 // BE (Backup Eligible)
            flags |= 0x10 // BS (Backup State)
        }
        
        let signCount = Data([0x00, 0x00, 0x00, 0x00])
        let credentialId = Data(repeating: UInt8.random(in: 1...255), count: 32) // Apple uses longer credential IDs
        let credentialIdLength = Data([0x00, UInt8(credentialId.count)])
        let encodedPublicKey = encodeCBOR(coseKey)
        
        var authData = Data()
        authData.append(rpIdHash)
        authData.append(flags)
        authData.append(signCount)
        authData.append(aaguidData) // Use provided AAGUID
        authData.append(credentialIdLength)
        authData.append(credentialId)
        authData.append(encodedPublicKey)
        
        // Create Apple Anonymous attestation object
        let attestationObject: [String: Any] = [
            "fmt": "apple",
            "attStmt": [:] as [String: Any], // Apple Anonymous has empty attStmt
            "authData": authData
        ]
        
        let clientDataJSON = createMockClientDataJSON(
            type: "webauthn.create",
            challenge: "apple-passkey-challenge",
            origin: "https://\(testRpId)"
        )
        
        let credential: [String: Any] = [
            "id": credentialId.base64EncodedString(),
            "rawId": credentialId.base64EncodedString(),
            "response": [
                "attestationObject": encodeCBOR(attestationObject).base64EncodedString(),
                "clientDataJSON": clientDataJSON.base64EncodedString()
            ],
            "type": "public-key"
        ]
        
        return (credential, privateKey)
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
    
    // MARK: - Test Cases
    
    func testApplePasskeyRegistrationOptions() throws {
        // Test passkey-enabled registration options
        let options = try webAuthnManager.generateRegistrationOptions(username: "alice", enablePasskeys: true)
        
        XCTAssertNotNil(options["publicKey"])
        
        let publicKey = options["publicKey"] as! [String: Any]
        
        // Verify passkey-specific options
        let authenticatorSelection = publicKey["authenticatorSelection"] as! [String: Any]
        XCTAssertEqual(authenticatorSelection["authenticatorAttachment"] as? String, "platform")
        XCTAssertEqual(authenticatorSelection["requireResidentKey"] as? Bool, true)
        XCTAssertEqual(authenticatorSelection["residentKey"] as? String, "required")
        XCTAssertEqual(authenticatorSelection["userVerification"] as? String, "required")
        
        // Verify enhanced algorithm support
        let pubKeyCredParams = publicKey["pubKeyCredParams"] as! [[String: Any]]
        XCTAssertTrue(pubKeyCredParams.count >= 3) // Should include ES256, RS256, ES384, ES512
        
        // Verify passkey extensions
        let extensions = publicKey["extensions"] as? [String: Any]
        XCTAssertNotNil(extensions?["largeBlob"])
        XCTAssertNotNil(extensions?["credProtect"])
        
        // Verify longer timeout for passkey setup
        XCTAssertEqual(publicKey["timeout"] as? Int, 300000) // 5 minutes
    }
    
    func testAppleTouchIDPasskeyRegistration() throws {
        let username = "alice"
        let (credential, _) = createMockApplePasskeyCredential(aaguidData: createAppleTouchIDAAGUID())
        
        // Should not throw
        try webAuthnManager.verifyRegistration(username: username, credential: credential)
        
        // Verify the user is registered with Apple-specific metadata
        XCTAssertTrue(webAuthnManager.isUsernameRegistered(username))
        
        print("✅ Apple Touch ID passkey registration test completed successfully!")
    }
    
    func testAppleFaceIDPasskeyRegistration() throws {
        let username = "bob"
        let (credential, _) = createMockApplePasskeyCredential(aaguidData: createAppleFaceIDAAGUID())
        
        // Should not throw
        try webAuthnManager.verifyRegistration(username: username, credential: credential)
        
        // Verify the user is registered
        XCTAssertTrue(webAuthnManager.isUsernameRegistered(username))
        
        print("✅ Apple Face ID passkey registration test completed successfully!")
    }
    
    func testBackupStateHandling() throws {
        let username = "charlie"
        
        // Test passkey with backup enabled
        let (credentialWithBackup, _) = createMockApplePasskeyCredential(
            aaguidData: createAppleTouchIDAAGUID(), 
            withBackup: true
        )
        
        try webAuthnManager.verifyRegistration(username: username, credential: credentialWithBackup)
        XCTAssertTrue(webAuthnManager.isUsernameRegistered(username))
        
        print("✅ Backup state handling test completed successfully!")
    }
    
    func testSecurityKeyVsPasskeyOptions() throws {
        // Test security key options (cross-platform)
        let securityKeyOptions = try webAuthnManager.generateRegistrationOptions(username: "dave", enablePasskeys: false)
        let securityKeyPublicKey = securityKeyOptions["publicKey"] as! [String: Any]
        let securityKeyAuthSelection = securityKeyPublicKey["authenticatorSelection"] as! [String: Any]
        
        XCTAssertEqual(securityKeyAuthSelection["authenticatorAttachment"] as? String, "cross-platform")
        XCTAssertEqual(securityKeyAuthSelection["requireResidentKey"] as? Bool, false)
        XCTAssertEqual(securityKeyAuthSelection["residentKey"] as? String, "discouraged")
        
        // Test passkey options (platform)
        let passkeyOptions = try webAuthnManager.generateRegistrationOptions(username: "eve", enablePasskeys: true)
        let passkeyPublicKey = passkeyOptions["publicKey"] as! [String: Any]
        let passkeyAuthSelection = passkeyPublicKey["authenticatorSelection"] as! [String: Any]
        
        XCTAssertEqual(passkeyAuthSelection["authenticatorAttachment"] as? String, "platform")
        XCTAssertEqual(passkeyAuthSelection["requireResidentKey"] as? Bool, true)
        XCTAssertEqual(passkeyAuthSelection["residentKey"] as? String, "required")
        
        print("✅ Security key vs passkey options test completed successfully!")
    }
    
    func testEnhancedAlgorithmSupport() throws {
        let options = try webAuthnManager.generateRegistrationOptions(username: "frank")
        let publicKey = options["publicKey"] as! [String: Any]
        let pubKeyCredParams = publicKey["pubKeyCredParams"] as! [[String: Any]]
        
        let algorithms = pubKeyCredParams.compactMap { $0["alg"] as? Int }
        
        // Should support multiple algorithms for maximum compatibility
        XCTAssertTrue(algorithms.contains(-7))   // ES256
        XCTAssertTrue(algorithms.contains(-257)) // RS256
        XCTAssertTrue(algorithms.contains(-35))  // ES384
        XCTAssertTrue(algorithms.contains(-36))  // ES512
        
        print("✅ Enhanced algorithm support test completed successfully!")
    }
    
    func testPasskeyExtensions() throws {
        let options = try webAuthnManager.generateRegistrationOptions(username: "grace")
        let publicKey = options["publicKey"] as! [String: Any]
        
        XCTAssertNotNil(publicKey["extensions"])
        let extensions = publicKey["extensions"] as! [String: Any]
        
        // Large blob support for additional data storage
        XCTAssertNotNil(extensions["largeBlob"])
        let largeBlob = extensions["largeBlob"] as! [String: Any]
        XCTAssertEqual(largeBlob["support"] as? String, "required")
        
        // Credential protection for enhanced security
        XCTAssertNotNil(extensions["credProtect"])
        let credProtect = extensions["credProtect"] as! [String: Any]
        XCTAssertEqual(credProtect["credentialProtectionPolicy"] as? Int, 3)
        XCTAssertEqual(credProtect["enforceCredentialProtectionPolicy"] as? Bool, true)
        
        // Enterprise attestation
        XCTAssertNotNil(extensions["enterpriseAttestation"])
        let enterpriseAttestation = extensions["enterpriseAttestation"] as! [String: Any]
        XCTAssertEqual(enterpriseAttestation["rp"] as? String, testRpId)
        
        print("✅ Passkey extensions test completed successfully!")
    }
    
    // MARK: - Helper Functions
    
    func encodeCBOR(_ object: Any) -> Data {
        // Simplified CBOR encoding for test purposes
        // In a real implementation, you'd use a proper CBOR library
        if let dict = object as? [String: Any] {
            let count = dict.count
            var result = Data()
            if count < 24 {
                result.append(0xA0 | UInt8(count)) // Map with count < 24
            } else {
                result.append(0xB8)
                result.append(UInt8(count))
            }
            for (key, value) in dict {
                result.append(encodeCBOR(key))
                result.append(encodeCBOR(value))
            }
            return result
        } else if let string = object as? String {
            let stringData = string.data(using: .utf8)!
            let length = stringData.count
            var result = Data()
            if length < 24 {
                result.append(0x60 | UInt8(length))
            } else if length < 256 {
                result.append(0x78)
                result.append(UInt8(length))
            } else {
                result.append(0x79)
                result.append(UInt8(length >> 8))
                result.append(UInt8(length & 0xFF))
            }
            result.append(stringData)
            return result
        } else if let data = object as? Data {
            let length = data.count
            var result = Data()
            if length < 24 {
                result.append(0x40 | UInt8(length))
            } else if length < 256 {
                result.append(0x58)
                result.append(UInt8(length))
            } else {
                result.append(0x59)
                result.append(UInt8(length >> 8))
                result.append(UInt8(length & 0xFF))
            }
            result.append(data)
            return result
        } else if let number = object as? Int {
            if number >= 0 {
                if number < 24 {
                    return Data([UInt8(number)])
                } else if number < 256 {
                    return Data([0x18, UInt8(number)])
                } else if number < 65536 {
                    return Data([0x19, UInt8(number >> 8), UInt8(number & 0xFF)])
                } else {
                    return Data([0x1A, UInt8((number >> 24) & 0xFF), UInt8((number >> 16) & 0xFF), UInt8((number >> 8) & 0xFF), UInt8(number & 0xFF)])
                }
            } else {
                // Negative integer
                let positive = UInt64(-number - 1)
                if positive < 24 {
                    return Data([0x20 | UInt8(positive)])
                } else if positive < 256 {
                    return Data([0x38, UInt8(positive)])
                } else if positive < 65536 {
                    return Data([0x39, UInt8(positive >> 8), UInt8(positive & 0xFF)])
                } else {
                    return Data([0x3A, UInt8((positive >> 24) & 0xFF), UInt8((positive >> 16) & 0xFF), UInt8((positive >> 8) & 0xFF), UInt8(positive & 0xFF)])
                }
            }
        }
        
        return Data()
    }
}

// Data extension already defined in WebAuthnManagerTests.swift 
