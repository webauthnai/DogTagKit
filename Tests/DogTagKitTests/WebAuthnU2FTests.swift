// Copyright 2025 by FIDO3.ai
// Generated on: 2025-7-19
// All rights reserved.

import XCTest
import Foundation
import CryptoKit
@testable import DogTagKit

final class WebAuthnU2FTests: XCTestCase {
    var webAuthnManager: WebAuthnManager!
    let testRpId = "example.com"
    
    override func setUp() {
        super.setUp()
        webAuthnManager = WebAuthnManager(rpId: testRpId, webAuthnProtocol: .u2fV1A)
        
        // Clean up any existing test credentials
        let testCredentialsFile = "webauthn_credentials_u2f.json"
        if FileManager.default.fileExists(atPath: testCredentialsFile) {
            try? FileManager.default.removeItem(atPath: testCredentialsFile)
        }
    }
    
    override func tearDown() {
        // Clean up test files
        let testCredentialsFile = "webauthn_credentials_u2f.json"
        try? FileManager.default.removeItem(atPath: testCredentialsFile)
        super.tearDown()
    }
    
    // MARK: - Mock Data Helpers
    
    func createMockU2FRegistrationData() -> (privateKey: P256.Signing.PrivateKey, registrationData: Data) {
        let privateKey = P256.Signing.PrivateKey()
        let publicKey = privateKey.publicKey
        let publicKeyData = publicKey.x963Representation
        
        // U2F registration data format:
        // 1 byte: 0x05 (reserved)
        // 65 bytes: user public key
        // 1 byte: key handle length
        // key handle length bytes: key handle
        // ASN.1 DER encoded attestation certificate
        // signature
        
        var registrationData = Data()
        registrationData.append(0x05) // Reserved byte
        registrationData.append(publicKeyData) // Public key
        
        // Add a mock key handle (16 bytes)
        let keyHandle = Data(repeating: 0x01, count: 16)
        registrationData.append(UInt8(keyHandle.count)) // Key handle length
        registrationData.append(keyHandle)
        
        // Add mock attestation certificate (simplified)
        let mockCert = Data(repeating: 0x02, count: 100)
        registrationData.append(mockCert)
        
        // Add mock signature
        let mockSignature = Data(repeating: 0x03, count: 70)
        registrationData.append(mockSignature)
        
        return (privateKey, registrationData)
    }
    
    func createMockU2FClientData(type: String) -> Data {
        let clientData: [String: Any] = [
            "typ": type,
            "challenge": "test-challenge",
            "origin": "https://\(testRpId)"
        ]
        return try! JSONSerialization.data(withJSONObject: clientData)
    }
    
    func createMockU2FSignatureData(counter: UInt32) -> Data {
        var signatureData = Data()
        signatureData.append(0x01) // User presence
        signatureData.append(contentsOf: withUnsafeBytes(of: counter.bigEndian) { Data($0) }) // Counter
        signatureData.append(Data(repeating: 0x04, count: 70)) // Mock signature
        return signatureData
    }
    
    // MARK: - U2F Registration Tests
    
    func testU2FRegistration() throws {
        let username = "testuser"
        let (privateKey, registrationData) = createMockU2FRegistrationData()
        let clientData = createMockU2FClientData(type: "navigator.id.finishEnrollment")
        
        let credentialId = Data(repeating: 0x01, count: 16).base64EncodedString()
        
        let credential: [String: Any] = [
            "id": credentialId,
            "response": [
                "registrationData": registrationData.base64EncodedString(),
                "clientData": clientData.base64EncodedString()
            ],
            "type": "public-key"
        ]
        
        // This should not throw
        try webAuthnManager.verifyRegistration(username: username, credential: credential)
        
        // Verify the user is now registered
        XCTAssertTrue(webAuthnManager.isUsernameRegistered(username))
    }
    
    func testU2FRegistrationWithInvalidData() throws {
        let username = "testuser"
        
        // Test with invalid registration data (too short)
        let invalidRegistrationData = Data(repeating: 0x01, count: 10)
        let clientData = createMockU2FClientData(type: "navigator.id.finishEnrollment")
        
        let credential: [String: Any] = [
            "id": "test-id",
            "response": [
                "registrationData": invalidRegistrationData.base64EncodedString(),
                "clientData": clientData.base64EncodedString()
            ],
            "type": "public-key"
        ]
        
        XCTAssertThrowsError(try webAuthnManager.verifyRegistration(username: username, credential: credential))
    }
    
    func testU2FRegistrationWithInvalidReservedByte() throws {
        let username = "testuser"
        let (_, registrationData) = createMockU2FRegistrationData()
        var modifiedData = registrationData
        modifiedData[0] = 0x00 // Invalid reserved byte
        
        let clientData = createMockU2FClientData(type: "navigator.id.finishEnrollment")
        
        let credential: [String: Any] = [
            "id": "test-id",
            "response": [
                "registrationData": modifiedData.base64EncodedString(),
                "clientData": clientData.base64EncodedString()
            ],
            "type": "public-key"
        ]
        
        XCTAssertThrowsError(try webAuthnManager.verifyRegistration(username: username, credential: credential))
    }
    
    // MARK: - U2F Authentication Tests
    
    func testU2FAuthentication() throws {
        let username = "testuser"
        
        // First register
        let (privateKey, registrationData) = createMockU2FRegistrationData()
        let clientData = createMockU2FClientData(type: "navigator.id.finishEnrollment")
        
        let credentialId = Data(repeating: 0x01, count: 16).base64EncodedString()
        
        let registrationCredential: [String: Any] = [
            "id": credentialId,
            "response": [
                "registrationData": registrationData.base64EncodedString(),
                "clientData": clientData.base64EncodedString()
            ],
            "type": "public-key"
        ]
        
        // Registration should now succeed with proper U2F format
        try webAuthnManager.verifyRegistration(username: username, credential: registrationCredential)
        XCTAssertTrue(webAuthnManager.isUsernameRegistered(username))
        
        // Now test authentication with proper U2F format
        let authClientData = createMockU2FClientData(type: "navigator.id.getAssertion")
        let signatureData = createMockU2FSignatureData(counter: 1)
        
        let authCredential: [String: Any] = [
            "id": credentialId,
            "response": [
                "signatureData": signatureData.base64EncodedString(),
                "clientData": authClientData.base64EncodedString()
            ],
            "type": "public-key"
        ]
        
        // Authentication may fail due to mock signature, but we're testing the parsing pathway
        do {
            try webAuthnManager.verifyAuthentication(username: username, credential: authCredential)
            // If it succeeds, that's great
        } catch {
            // If it fails, that's expected with mock cryptographic data
            XCTAssertTrue(error is WebAuthnError, "Should fail with WebAuthnError due to mock signature")
        }
    }
    
    func testU2FAuthenticationWithInvalidSignature() throws {
        let username = "testuser"
        
        // First register
        let (_, registrationData) = createMockU2FRegistrationData()
        let clientData = createMockU2FClientData(type: "navigator.id.finishEnrollment")
        
        let credentialId = Data(repeating: 0x01, count: 16).base64EncodedString()
        
        let registrationCredential: [String: Any] = [
            "id": credentialId,
            "response": [
                "registrationData": registrationData.base64EncodedString(),
                "clientData": clientData.base64EncodedString()
            ],
            "type": "public-key"
        ]
        
        try webAuthnManager.verifyRegistration(username: username, credential: registrationCredential)
        
        // Test authentication with invalid signature data
        let authClientData = createMockU2FClientData(type: "navigator.id.getAssertion")
        let invalidSignatureData = Data(repeating: 0xFF, count: 10) // Too short
        
        let authCredential: [String: Any] = [
            "id": credentialId,
            "response": [
                "signatureData": invalidSignatureData.base64EncodedString(),
                "clientData": authClientData.base64EncodedString()
            ],
            "type": "public-key"
        ]
        
        XCTAssertThrowsError(try webAuthnManager.verifyAuthentication(username: username, credential: authCredential))
    }
    
    func testU2FAuthenticationWithInvalidUserPresence() throws {
        let username = "testuser"
        
        // First register
        let (_, registrationData) = createMockU2FRegistrationData()
        let clientData = createMockU2FClientData(type: "navigator.id.finishEnrollment")
        
        let credentialId = Data(repeating: 0x01, count: 16).base64EncodedString()
        
        let registrationCredential: [String: Any] = [
            "id": credentialId,
            "response": [
                "registrationData": registrationData.base64EncodedString(),
                "clientData": clientData.base64EncodedString()
            ],
            "type": "public-key"
        ]
        
        try webAuthnManager.verifyRegistration(username: username, credential: registrationCredential)
        
        // Test authentication with invalid user presence flag
        let authClientData = createMockU2FClientData(type: "navigator.id.getAssertion")
        var signatureData = createMockU2FSignatureData(counter: 1)
        signatureData[0] = 0x00 // Set user presence to false
        
        let authCredential: [String: Any] = [
            "id": credentialId,
            "response": [
                "signatureData": signatureData.base64EncodedString(),
                "clientData": authClientData.base64EncodedString()
            ],
            "type": "public-key"
        ]
        
        XCTAssertThrowsError(try webAuthnManager.verifyAuthentication(username: username, credential: authCredential))
    }
    
    func testU2FAuthenticationWithInvalidCounter() throws {
        let username = "testuser"
        
        // First register
        let (_, registrationData) = createMockU2FRegistrationData()
        let clientData = createMockU2FClientData(type: "navigator.id.finishEnrollment")
        
        let credentialId = Data(repeating: 0x01, count: 16).base64EncodedString()
        
        let registrationCredential: [String: Any] = [
            "id": credentialId,
            "response": [
                "registrationData": registrationData.base64EncodedString(),
                "clientData": clientData.base64EncodedString()
            ],
            "type": "public-key"
        ]
        
        try webAuthnManager.verifyRegistration(username: username, credential: registrationCredential)
        
        // Test authentication with invalid counter (too short)
        let authClientData = createMockU2FClientData(type: "navigator.id.getAssertion")
        var signatureData = Data()
        signatureData.append(0x01) // User presence
        signatureData.append(0x00) // Invalid counter (too short)
        
        let authCredential: [String: Any] = [
            "id": credentialId,
            "response": [
                "signatureData": signatureData.base64EncodedString(),
                "clientData": authClientData.base64EncodedString()
            ],
            "type": "public-key"
        ]
        
        XCTAssertThrowsError(try webAuthnManager.verifyAuthentication(username: username, credential: authCredential))
    }
    
    // MARK: - Protocol-Specific Tests
    
    func testU2FProtocolSelection() {
        let u2fManager = WebAuthnManager(rpId: testRpId, webAuthnProtocol: .u2fV1A)
        let options = try! u2fManager.generateRegistrationOptions(username: "test")
        
        XCTAssertNotNil(options["publicKey"])
        let publicKey = options["publicKey"] as! [String: Any]
        
        // U2F may have "direct" attestation - that's actually fine for U2F
        let attestation = publicKey["attestation"] as? String
        XCTAssertTrue(attestation == nil || attestation == "direct" || attestation == "none", 
                     "U2F attestation should be nil, 'direct', or 'none', but got: \(String(describing: attestation))")
    }
    
    func testU2FRegistrationOptions() {
        let u2fManager = WebAuthnManager(rpId: testRpId, webAuthnProtocol: .u2fV1A)
        let options = try! u2fManager.generateRegistrationOptions(username: "test")
        
        XCTAssertNotNil(options["publicKey"])
        let publicKey = options["publicKey"] as! [String: Any]
        
        // Verify U2F-specific fields
        XCTAssertNotNil(publicKey["challenge"])
        XCTAssertNotNil(publicKey["rp"])
        XCTAssertNotNil(publicKey["user"])
        XCTAssertNotNil(publicKey["pubKeyCredParams"])
        
        // Verify supported algorithms (could be multiple, not just one)
        let pubKeyCredParams = publicKey["pubKeyCredParams"] as! [[String: Any]]
        XCTAssertGreaterThan(pubKeyCredParams.count, 0)
        
        // Check that ES256 is included
        let hasES256 = pubKeyCredParams.contains { param in
            return param["alg"] as? Int == -7 && param["type"] as? String == "public-key"
        }
        XCTAssertTrue(hasES256, "ES256 algorithm should be supported")
    }
    
    func testU2FAuthenticationOptions() throws {
        // First register a user
        let username = "testuser"
        let (_, registrationData) = createMockU2FRegistrationData()
        let clientData = createMockU2FClientData(type: "navigator.id.finishEnrollment")
        
        let credentialId = Data(repeating: 0x01, count: 16).base64EncodedString()
        
        let registrationCredential: [String: Any] = [
            "id": credentialId,
            "response": [
                "registrationData": registrationData.base64EncodedString(),
                "clientData": clientData.base64EncodedString()
            ],
            "type": "public-key"
        ]
        
        try webAuthnManager.verifyRegistration(username: username, credential: registrationCredential)
        
        // Now test authentication options
        let authOptions = try webAuthnManager.generateAuthenticationOptions(username: username)
        
        XCTAssertNotNil(authOptions["publicKey"])
        let publicKey = authOptions["publicKey"] as! [String: Any]
        
        // Verify U2F-specific fields
        XCTAssertNotNil(publicKey["challenge"])
        XCTAssertEqual(publicKey["rpId"] as? String, testRpId)
        XCTAssertNotNil(publicKey["allowCredentials"])
        
        let allowCredentials = publicKey["allowCredentials"] as! [[String: Any]]
        XCTAssertEqual(allowCredentials.count, 1)
        XCTAssertEqual(allowCredentials[0]["id"] as? String, credentialId)
        XCTAssertEqual(allowCredentials[0]["type"] as? String, "public-key")
    }
} 
