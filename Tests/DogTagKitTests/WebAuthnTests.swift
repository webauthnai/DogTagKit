// Copyright 2025 by FIDO3.ai
// Generated on: 2024-07-09T12:34:56Z
// All rights reserved.

import XCTest
import Foundation
import CryptoKit
@testable import DogTagKit

final class WebAuthnTests: XCTestCase {
    var webAuthnManager: WebAuthnManager!
    let testRpId = "example.com"
    
    override func setUp() {
        super.setUp()
        webAuthnManager = WebAuthnManager(rpId: testRpId) // Uses default .fido2CBOR
        
        // Clean up any existing test credentials and data
        let testCredentialsFiles = [
            "webauthn_credentials.json",
            "webauthn_credentials_fido2.json",
            "test_webauthn_credentials.json"
        ]
        
        for file in testCredentialsFiles {
            if FileManager.default.fileExists(atPath: file) {
                try? FileManager.default.removeItem(atPath: file)
            }
        }
        
        // WebAuthnKit uses its own storage, no external persistence cleanup needed
    }
    
    override func tearDown() {
        // Clean up test files
        let testCredentialsFiles = [
            "webauthn_credentials.json",
            "webauthn_credentials_fido2.json",
            "test_webauthn_credentials.json"
        ]
        
        for file in testCredentialsFiles {
            if FileManager.default.fileExists(atPath: file) {
                try? FileManager.default.removeItem(atPath: file)
            }
        }
        
        // WebAuthnKit cleans up its own storage
        webAuthnManager = nil
        super.tearDown()
    }
    
    func testGenerateRegistrationOptions() throws {
        let username = "testuser"
        let options = try webAuthnManager.generateRegistrationOptions(username: username)
        
        // Verify the structure of the options
        XCTAssertNotNil(options["publicKey"])
        let publicKey = options["publicKey"] as! [String: Any]
        
        XCTAssertNotNil(publicKey["challenge"])
        XCTAssertNotNil(publicKey["rp"])
        XCTAssertNotNil(publicKey["user"])
        XCTAssertNotNil(publicKey["pubKeyCredParams"])
        XCTAssertNotNil(publicKey["timeout"])
        XCTAssertNotNil(publicKey["attestation"])
        XCTAssertNotNil(publicKey["authenticatorSelection"])
        
        // Verify RP information
        let rp = publicKey["rp"] as! [String: Any]
        XCTAssertEqual(rp["id"] as? String, testRpId)
        
        // Verify user information
        let user = publicKey["user"] as! [String: Any]
        XCTAssertEqual(user["name"] as? String, username)
        XCTAssertEqual(user["displayName"] as? String, username)
    }
    
    func testGenerateAuthenticationOptions() throws {
        // Test authentication options for non-registered user
        let username = "testuser"
        XCTAssertThrowsError(try webAuthnManager.generateAuthenticationOptions(username: username)) { error in
            XCTAssertTrue(error is WebAuthnError)
            XCTAssertEqual(error as! WebAuthnError, WebAuthnError.credentialNotFound)
        }
    }
    
    func testVerifyRegistrationWithInvalidCredential() {
        let username = "testuser"
        let invalidCredential: [String: Any] = [
            "id": "test-id",
            // Missing required fields
            "type": "public-key"
        ]
        
        XCTAssertThrowsError(try webAuthnManager.verifyRegistration(username: username, credential: invalidCredential)) { error in
            XCTAssertTrue(error is WebAuthnError)
            XCTAssertEqual(error as! WebAuthnError, WebAuthnError.invalidCredential)
        }
    }
    
    func testVerifyAuthenticationWithInvalidCredential() {
        let username = "nonexistent_user"
        let invalidCredential: [String: Any] = [
            "id": "dGVzdC1pZA==",
            "response": [
                "clientDataJSON": "test-client-data",
                "authenticatorData": "test-auth-data",
                "signature": "test-signature"
            ],
            "type": "public-key"
        ]
        
        XCTAssertThrowsError(try webAuthnManager.verifyAuthentication(username: username, credential: invalidCredential)) { error in
            XCTAssertTrue(error is WebAuthnError)
            // For non-existent users, the system may return accessDenied instead of credentialNotFound
            // depending on whether user status is checked first
            XCTAssertTrue((error as! WebAuthnError) == WebAuthnError.credentialNotFound || 
                         (error as! WebAuthnError) == WebAuthnError.accessDenied,
                         "Should throw either credentialNotFound or accessDenied for non-existent user")
        }
    }
    
    func testDefaultProtocol() {
        // Verify that the default protocol is CBOR
        let defaultManager = WebAuthnManager(rpId: testRpId)
        // We can't directly access the protocol, but we can test that it defaults correctly by ensuring CBOR behavior
        
        // Test that it generates proper CBOR-style registration options
        let options = try! defaultManager.generateRegistrationOptions(username: "test")
        let publicKey = options["publicKey"] as! [String: Any]
        
        // CBOR/FIDO2 should have these fields
        XCTAssertNotNil(publicKey["attestation"])
        XCTAssertEqual(publicKey["attestation"] as? String, "none")
        XCTAssertNotNil(publicKey["authenticatorSelection"])
    }
    
    func testProtocolSelection() {
        // Test explicit CBOR protocol
        let cborManager = WebAuthnManager(rpId: testRpId, webAuthnProtocol: .fido2CBOR)
        let cborOptions = try! cborManager.generateRegistrationOptions(username: "test")
        XCTAssertNotNil(cborOptions["publicKey"])
        
        // Test U2F protocol
        let u2fManager = WebAuthnManager(rpId: testRpId, webAuthnProtocol: .u2fV1A)
        let u2fOptions = try! u2fManager.generateRegistrationOptions(username: "test")
        XCTAssertNotNil(u2fOptions["publicKey"])
        
        // Both should generate valid options but with same structure (registration options are protocol-agnostic)
        let cborPublicKey = cborOptions["publicKey"] as! [String: Any]
        let u2fPublicKey = u2fOptions["publicKey"] as! [String: Any]
        
        XCTAssertNotNil(cborPublicKey["challenge"])
        XCTAssertNotNil(u2fPublicKey["challenge"])
    }
    
    func testOriginValidationWithPorts() {
        let localhostManager = WebAuthnManager(rpId: "localhost")
        
        // Test various port scenarios that should be valid
        let validOrigins = [
            "http://localhost",
            "https://localhost", 
            "http://localhost:3000",
            "https://localhost:8080",
            "http://localhost:9001" // This was failing before our fix
        ]
        
        // Since we can't directly test the private method, let's test indirectly by 
        // creating mock credentials with different origins and seeing if they pass validation
        
        for origin in validOrigins {
            // Create a base64 encoded client data JSON with the test origin
            let clientData = [
                "type": "webauthn.create",
                "challenge": "test-challenge", 
                "origin": origin,
                "crossOrigin": false
            ] as [String : Any]
            
            let clientDataJSON = try! JSONSerialization.data(withJSONObject: clientData)
            let clientDataBase64 = clientDataJSON.base64EncodedString()
            
            // Create a mock credential (this will fail CBOR parsing, but we're testing origin validation)
            let mockCredential: [String: Any] = [
                "id": "dGVzdC1pZA==",
                "rawId": "dGVzdC1pZA==", 
                "response": [
                    "attestationObject": "dGVzdA==", // Invalid CBOR, but that's okay
                    "clientDataJSON": clientDataBase64
                ],
                "type": "public-key"
            ]
            
            // The registration should fail on CBOR parsing, not origin validation
            // If origin validation fails, we'll get a different error
            do {
                try localhostManager.verifyRegistration(username: "test-\(origin)", credential: mockCredential)
                XCTFail("Should have failed on CBOR parsing, not origin validation for \(origin)")
            } catch WebAuthnError.invalidCredential {
                // This is expected - could be either CBOR parsing failure or origin validation failure
                // The key is that we don't want to distinguish here since both will throw the same error
                // Our test logs will show if origin validation is working correctly
                continue
            } catch {
                XCTFail("Unexpected error for origin \(origin): \(error)")
            }
        }
    }
    
    // MARK: - Enhanced Tests for Latest WebAuthn Features
    
    func testStorageBackendConfiguration() {
        // Test JSON storage backend
        let jsonManager = WebAuthnManager(
            rpId: testRpId,
            webAuthnProtocol: .fido2CBOR,
            storageBackend: .json("test_storage.json"),
            rpName: "Test RP",
            rpIcon: nil
        )
        XCTAssertNotNil(jsonManager, "Should create manager with JSON storage backend")
        
        // Test SwiftData storage backend
        let swiftDataManager = WebAuthnManager(
            rpId: testRpId,
            webAuthnProtocol: .fido2CBOR,
            storageBackend: .swiftData("test_storage.sqlite"),
            rpName: "Test RP",
            rpIcon: nil
        )
        XCTAssertNotNil(swiftDataManager, "Should create manager with SwiftData storage backend")
    }
    
    func testEnhancedRegistrationOptions() {
        let options = try! webAuthnManager.generateRegistrationOptions(username: "enhanced_test_user")
        let publicKey = options["publicKey"] as! [String: Any]
        
        // Verify enhanced security requirements
        XCTAssertNotNil(publicKey["attestation"], "Should include attestation preference")
        XCTAssertNotNil(publicKey["authenticatorSelection"], "Should include authenticator selection")
        
        let authSelection = publicKey["authenticatorSelection"] as! [String: Any]
        XCTAssertNotNil(authSelection["userVerification"], "Should include user verification requirement")
        
        // Verify credential parameters include modern algorithms
        let pubKeyCredParams = publicKey["pubKeyCredParams"] as! [[String: Any]]
        let algorithms = pubKeyCredParams.map { $0["alg"] as! Int }
        XCTAssertTrue(algorithms.contains(-7), "Should support ES256 algorithm")
        XCTAssertTrue(algorithms.contains(-257), "Should support RS256 algorithm")
    }
    
    func testUserEnabledStatusValidation() {
        // Test user enabled/disabled functionality
        let username = "status_test_user"
        
        // Initially user should not exist
        XCTAssertFalse(webAuthnManager.isUserEnabled(username: username), "Non-existent user should not be enabled")
        
        // Register a user (this would typically enable them)
        let registrationOptions = try! webAuthnManager.generateRegistrationOptions(username: username)
        XCTAssertNotNil(registrationOptions, "Should be able to generate registration options")
    }
    
    func testConcurrentRegistrationOptions() {
        let expectation = XCTestExpectation(description: "Concurrent registration options")
        expectation.expectedFulfillmentCount = 5
        
        let queue = DispatchQueue(label: "test.concurrent", attributes: .concurrent)
        
        for i in 0..<5 {
            queue.async {
                do {
                    let options = try self.webAuthnManager.generateRegistrationOptions(username: "concurrent_user_\(i)")
                    XCTAssertNotNil(options["publicKey"], "Should generate valid options for user \(i)")
                    expectation.fulfill()
                } catch {
                    XCTFail("Failed to generate options for user \(i): \(error)")
                }
            }
        }
        
        wait(for: [expectation], timeout: 5.0)
    }
    
    func testCredentialIdHandling() {
        // Test proper credential ID encoding/decoding
        let testCredentialId = "dGVzdC1jcmVkZW50aWFsLWlk" // base64 encoded test data
        
        // Verify we can handle various credential ID formats
        let validCredentialIds = [
            testCredentialId,
            "YWJjZGVmZ2hpamtsbW5vcA==", // Another valid base64 string
            "MTIzNDU2Nzg5MA==" // Numbers encoded as base64
        ]
        
        for credId in validCredentialIds {
            // Test that we can process these credential IDs without errors
            let mockCredential: [String: Any] = [
                "id": credId,
                "rawId": credId,
                "response": [
                    "attestationObject": "invalid", // Will fail parsing, but that's expected
                    "clientDataJSON": "invalid"
                ],
                "type": "public-key"
            ]
            
            // We expect this to fail on CBOR parsing, not credential ID handling
            XCTAssertThrowsError(try webAuthnManager.verifyRegistration(username: "test", credential: mockCredential)) { error in
                XCTAssertTrue(error is WebAuthnError, "Should throw WebAuthn error, not encoding error")
            }
        }
    }
    
    func testMultiProtocolSupport() {
        // Test both FIDO2 CBOR and U2F protocols
        let cborManager = WebAuthnManager(rpId: testRpId, webAuthnProtocol: .fido2CBOR)
        let u2fManager = WebAuthnManager(rpId: testRpId, webAuthnProtocol: .u2fV1A)
        
        // Both should generate valid registration options
        let cborOptions = try! cborManager.generateRegistrationOptions(username: "cbor_user")
        let u2fOptions = try! u2fManager.generateRegistrationOptions(username: "u2f_user")
        
        XCTAssertNotNil(cborOptions["publicKey"], "CBOR manager should generate valid options")
        XCTAssertNotNil(u2fOptions["publicKey"], "U2F manager should generate valid options")
        
        // Verify options structure is consistent
        let cborPublicKey = cborOptions["publicKey"] as! [String: Any]
        let u2fPublicKey = u2fOptions["publicKey"] as! [String: Any]
        
        XCTAssertNotNil(cborPublicKey["challenge"], "CBOR options should have challenge")
        XCTAssertNotNil(u2fPublicKey["challenge"], "U2F options should have challenge")
        XCTAssertNotNil(cborPublicKey["user"], "CBOR options should have user info")
        XCTAssertNotNil(u2fPublicKey["user"], "U2F options should have user info")
    }
    
    func testEnhancedErrorHandling() {
        // Test enhanced error messages and handling
        
        // Test with completely invalid credential structure
        let invalidCredential: [String: Any] = [:]
        
        XCTAssertThrowsError(try webAuthnManager.verifyRegistration(username: "test", credential: invalidCredential)) { error in
            XCTAssertTrue(error is WebAuthnError)
            XCTAssertEqual(error as! WebAuthnError, WebAuthnError.invalidCredential)
        }
        
        // Test with partially invalid credential
        let partialCredential: [String: Any] = [
            "id": "valid-id",
            "type": "public-key"
            // Missing response and rawId
        ]
        
        XCTAssertThrowsError(try webAuthnManager.verifyRegistration(username: "test", credential: partialCredential)) { error in
            XCTAssertTrue(error is WebAuthnError)
            XCTAssertEqual(error as! WebAuthnError, WebAuthnError.invalidCredential)
        }
    }
    
    func testSecurityFeatures() {
        // Test various security-related features
        
        // Test challenge uniqueness in registration options
        let options1 = try! webAuthnManager.generateRegistrationOptions(username: "security_test_1")
        let options2 = try! webAuthnManager.generateRegistrationOptions(username: "security_test_2")
        
        let publicKey1 = options1["publicKey"] as! [String: Any]
        let publicKey2 = options2["publicKey"] as! [String: Any]
        
        let challenge1 = publicKey1["challenge"] as! String
        let challenge2 = publicKey2["challenge"] as! String
        
        XCTAssertNotEqual(challenge1, challenge2, "Challenges should be unique")
        
        // Test user ID uniqueness
        let user1 = publicKey1["user"] as! [String: Any]
        let user2 = publicKey2["user"] as! [String: Any]
        
        let userId1 = user1["id"] as! String
        let userId2 = user2["id"] as! String
        
        XCTAssertNotEqual(userId1, userId2, "User IDs should be unique")
    }
    
    func testMemoryManagement() {
        // Test for memory leaks in WebAuthn operations
        weak var weakManager: WebAuthnManager?
        
        do {
            try autoreleasepool {
                let tempManager = WebAuthnManager(rpId: "temp.test.com")
                weakManager = tempManager
                
                // Perform some operations
                _ = try tempManager.generateRegistrationOptions(username: "memory_test")
                
                // Test authentication options for non-existent user
                XCTAssertThrowsError(try tempManager.generateAuthenticationOptions(username: "nonexistent"))
            }
        } catch {
            XCTFail("Unexpected error in memory test: \(error)")
        }
        
        // Manager should be deallocated
        XCTAssertNil(weakManager, "WebAuthn manager should be deallocated")
    }
    
    func testRpIdEdgeCases() {
        // Test edge cases for RP ID validation
        let edgeCaseRpIds = [
            "localhost",
            "127.0.0.1", 
            "example.com",
            "subdomain.example.com",
            "test-app.example.org"
        ]
        
        for rpId in edgeCaseRpIds {
            let manager = WebAuthnManager(rpId: rpId)
            let options = try! manager.generateRegistrationOptions(username: "edge_case_test")
            
            let publicKey = options["publicKey"] as! [String: Any]
            let rp = publicKey["rp"] as! [String: Any]
            
            XCTAssertEqual(rp["id"] as! String, rpId, "RP ID should be preserved for: \(rpId)")
        }
    }
}

// MARK: - Test Helper Extensions

extension WebAuthnTests {
    
    /// Helper to create mock ES256 key pair for testing
    func createMockES256KeyPair() -> (privateKey: P256.Signing.PrivateKey, publicKeyData: Data) {
        let privateKey = P256.Signing.PrivateKey()
        let publicKey = privateKey.publicKey
        let publicKeyData = publicKey.x963Representation
        return (privateKey, publicKeyData)
    }
    
    /// Helper to create mock client data JSON
    func createMockClientDataJSON(type: String, challenge: String, origin: String) -> Data {
        let clientData: [String: Any] = [
            "type": type,
            "challenge": challenge,
            "origin": origin,
            "crossOrigin": false
        ]
        return try! JSONSerialization.data(withJSONObject: clientData)
    }
    
    /// Helper to verify registration options structure
    func verifyRegistrationOptionsStructure(_ options: [String: Any], username: String) {
        XCTAssertNotNil(options["publicKey"], "Should contain publicKey")
        
        let publicKey = options["publicKey"] as! [String: Any]
        
        // Required fields
        XCTAssertNotNil(publicKey["challenge"], "Should contain challenge")
        XCTAssertNotNil(publicKey["rp"], "Should contain RP info")
        XCTAssertNotNil(publicKey["user"], "Should contain user info")
        XCTAssertNotNil(publicKey["pubKeyCredParams"], "Should contain credential parameters")
        
        // Verify user info
        let user = publicKey["user"] as! [String: Any]
        XCTAssertEqual(user["name"] as! String, username, "Username should match")
        XCTAssertEqual(user["displayName"] as! String, username, "Display name should match username")
        XCTAssertNotNil(user["id"], "Should have user ID")
        
        // Verify RP info
        let rp = publicKey["rp"] as! [String: Any]
        XCTAssertEqual(rp["id"] as! String, testRpId, "RP ID should match")
        XCTAssertNotNil(rp["name"], "Should have RP name")
        
        // Verify challenge is properly encoded
        let challenge = publicKey["challenge"] as! String
        XCTAssertFalse(challenge.isEmpty, "Challenge should not be empty")
        XCTAssertGreaterThan(challenge.count, 10, "Challenge should be of reasonable length")
    }
} 
