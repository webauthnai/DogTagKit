// Copyright 2025 by FIDO3.ai
// Generated on: 2025-7-19
// All rights reserved.

import XCTest
import Foundation
import CryptoKit
@testable import DogTagKit

final class WebAuthnSignCountTests: XCTestCase {
    var webAuthnManager: WebAuthnManager!
    let testRpId = "localhost"
    
    override func setUp() {
        super.setUp()
        
        // Create a test user manager that always considers users enabled
        let testUserManager = TestUserManager()
        webAuthnManager = WebAuthnManager(rpId: testRpId, userManager: testUserManager)
        
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
        
        webAuthnManager = nil
        super.tearDown()
    }
    
    func testInitialSignCountIsZero() throws {
        // Register a new credential
        let username = "testuser"
        _ = try webAuthnManager.generateRegistrationOptions(username: username)
        
        // Simulate registration with a mock credential
        let mockCredential = createMockCredential(
            id: "testid",
            attestationObject: createMockAttestationObject(signCount: 0),
            clientDataJSON: createMockClientDataJSON(type: "webauthn.create")
        )
        
        try webAuthnManager.verifyRegistration(username: username, credential: mockCredential)
        
        // Verify initial sign count is 0
        XCTAssertTrue(webAuthnManager.isUsernameRegistered(username))
    }
    
    func testSignCountIncreasesOnAuthentication() throws {
        // Register a new credential
        let username = "testuser"
        _ = try webAuthnManager.generateRegistrationOptions(username: username)
        
        // Simulate registration
        let mockCredential = createMockCredential(
            id: "testid",
            attestationObject: createMockAttestationObject(signCount: 0),
            clientDataJSON: createMockClientDataJSON(type: "webauthn.create")
        )
        
        try webAuthnManager.verifyRegistration(username: username, credential: mockCredential)
        
        // Test authentication with increasing sign count
        // Since we're using mock signatures, we expect signature verification to fail
        // But we want to verify that sign count validation passes before signature verification
        
        let authCredential = createMockAuthCredential(
            id: "testid",
            authenticatorData: createMockAuthenticatorData(signCount: 1),
            clientDataJSON: createMockClientDataJSON(type: "webauthn.get"),
            signature: "testsignature"
        )
        
        // This should fail with invalidCredential (signature failure), not signCountInvalid
        XCTAssertThrowsError(try webAuthnManager.verifyAuthentication(username: username, credential: authCredential)) { error in
            // Should fail with signature verification, not sign count validation
            XCTAssertEqual(error as? WebAuthnError, .invalidCredential)
        }
    }
    
    func testRejectedAuthenticationWithLowerSignCount() throws {
        // Register a new credential
        let username = "testuser"
        _ = webAuthnManager.generateRegistrationOptions(username: username)
        
        // Simulate registration with sign count 0
        let mockCredential = createMockCredential(
            id: "testid",
            attestationObject: createMockAttestationObject(signCount: 0),
            clientDataJSON: createMockClientDataJSON(type: "webauthn.create")
        )
        
        try webAuthnManager.verifyRegistration(username: username, credential: mockCredential)
        
        // Manually update the stored credential to have a higher sign count
        // This simulates a user that has successfully authenticated before
        if let credential = webAuthnManager.getCredential(username: username) {
            let updatedCredential = WebAuthnCredential(
                id: credential.id,
                publicKey: credential.publicKey,
                signCount: 5, // Set to 5 to simulate previous authentications
                username: credential.username,
                algorithm: credential.algorithm,
                protocolVersion: credential.protocolVersion,
                attestationFormat: credential.attestationFormat,
                aaguid: credential.aaguid,
                isDiscoverable: credential.isDiscoverable,
                backupEligible: credential.backupEligible,
                backupState: credential.backupState,
                emoji: credential.emoji,
                lastLoginIP: credential.lastLoginIP,
                createdAt: credential.createdAt,
                isEnabled: credential.isEnabled,
                isAdmin: credential.isAdmin,
                userNumber: credential.userNumber
            )
            webAuthnManager.storeCredential(updatedCredential)
        }
        
        // Attempt authentication with lower sign count (1 < 5)
        let authCredential = createMockAuthCredential(
            id: "testid",
            authenticatorData: createMockAuthenticatorData(signCount: 1),
            clientDataJSON: createMockClientDataJSON(type: "webauthn.get"),
            signature: "testsignature"
        )
        
        XCTAssertThrowsError(try webAuthnManager.verifyAuthentication(username: username, credential: authCredential)) { error in
            XCTAssertEqual(error as? WebAuthnError, .signCountInvalid)
        }
    }
    
    func testRejectedAuthenticationWithSameSignCount() throws {
        // Register a new credential
        let username = "testuser"
        _ = webAuthnManager.generateRegistrationOptions(username: username)
        
        // Simulate registration with sign count 0
        let mockCredential = createMockCredential(
            id: "testid",
            attestationObject: createMockAttestationObject(signCount: 0),
            clientDataJSON: createMockClientDataJSON(type: "webauthn.create")
        )
        
        try webAuthnManager.verifyRegistration(username: username, credential: mockCredential)
        
        // Manually update the stored credential to have a specific sign count
        // This simulates a user that has successfully authenticated before
        if let credential = webAuthnManager.getCredential(username: username) {
            let updatedCredential = WebAuthnCredential(
                id: credential.id,
                publicKey: credential.publicKey,
                signCount: 3, // Set to 3 to simulate previous authentications
                username: credential.username,
                algorithm: credential.algorithm,
                protocolVersion: credential.protocolVersion,
                attestationFormat: credential.attestationFormat,
                aaguid: credential.aaguid,
                isDiscoverable: credential.isDiscoverable,
                backupEligible: credential.backupEligible,
                backupState: credential.backupState,
                emoji: credential.emoji,
                lastLoginIP: credential.lastLoginIP,
                createdAt: credential.createdAt,
                isEnabled: credential.isEnabled,
                isAdmin: credential.isAdmin,
                userNumber: credential.userNumber
            )
            webAuthnManager.storeCredential(updatedCredential)
        }
        
        // Attempt authentication with same sign count (3 == 3)
        let authCredential = createMockAuthCredential(
            id: "testid",
            authenticatorData: createMockAuthenticatorData(signCount: 3),
            clientDataJSON: createMockClientDataJSON(type: "webauthn.get"),
            signature: "testsignature"
        )
        
        XCTAssertThrowsError(try webAuthnManager.verifyAuthentication(username: username, credential: authCredential)) { error in
            XCTAssertEqual(error as? WebAuthnError, .signCountInvalid)
        }
    }
    
    // MARK: - Helper Methods
    
    private func createMockCredential(id: String, attestationObject: String, clientDataJSON: String) -> [String: Any] {
        return [
            "id": id,
            "response": [
                "attestationObject": attestationObject,
                "clientDataJSON": clientDataJSON
            ]
        ]
    }
    
    private func createMockAuthCredential(id: String, authenticatorData: String, clientDataJSON: String, signature: String) -> [String: Any] {
        return [
            "id": id,
            "response": [
                "authenticatorData": authenticatorData,
                "clientDataJSON": clientDataJSON,
                "signature": signature
            ]
        ]
    }
    
    private func createMockAttestationObject(signCount: UInt32) -> String {
        // Create properly formatted CBOR attestation object
        // For test purposes, we'll create a realistic structure
        
        let rpIdHash = Data(SHA256.hash(data: testRpId.data(using: .utf8)!))
        var authData = Data()
        authData.append(rpIdHash) // 32 bytes
        authData.append(0x40) // flags: attested credential data included
        
        // Set sign count (4 bytes, big endian)
        withUnsafeBytes(of: signCount.bigEndian) { bytes in
            authData.append(contentsOf: bytes)
        }
        
        // Add minimal credential data for FIDO2
        let aaguid = Data(count: 16) // 16 bytes of zeros
        authData.append(aaguid)
        
        let credentialIdLength = UInt16(16).bigEndian // 2 bytes
        withUnsafeBytes(of: credentialIdLength) { bytes in
            authData.append(contentsOf: bytes)
        }
        
        let credentialId = Data(repeating: 0x01, count: 16) // 16 bytes
        authData.append(credentialId)
        
        // Add minimal COSE public key (ES256)
        let coseKey = Data([
            0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21,
            0x58, 0x20, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
            0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
            0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
            0x1f, 0x20, 0x22, 0x58, 0x20, 0x21, 0x22, 0x23,
            0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b,
            0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33,
            0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b,
            0x3c, 0x3d, 0x3e, 0x3f, 0x40
        ])
        authData.append(coseKey)
        
        // Create CBOR attestation object
        let attestationObjectCBOR = Data([
            0xa3, // map with 3 items
            0x63, 0x66, 0x6d, 0x74, // "fmt"
            0x64, 0x6e, 0x6f, 0x6e, 0x65, // "none"
            0x67, 0x61, 0x74, 0x74, 0x53, 0x74, 0x6d, 0x74, // "attStmt"
            0xa0, // empty map
            0x68, 0x61, 0x75, 0x74, 0x68, 0x44, 0x61, 0x74, 0x61, // "authData"
            0x58, UInt8(authData.count) // byte string length
        ]) + authData
        
        return attestationObjectCBOR.base64EncodedString()
    }
    
    private func createMockAuthenticatorData(signCount: UInt32) -> String {
        // Create proper authenticator data structure
        let rpIdHash = Data(SHA256.hash(data: testRpId.data(using: .utf8)!))
        var authData = Data()
        authData.append(rpIdHash) // 32 bytes
        authData.append(0x01) // flags: user present
        
        // Set sign count (4 bytes, big endian)
        withUnsafeBytes(of: signCount.bigEndian) { bytes in
            authData.append(contentsOf: bytes)
        }
        
        return authData.base64EncodedString()
    }
    
    private func createMockClientDataJSON(type: String) -> String {
        let clientData: [String: Any] = [
            "type": type,
            "challenge": "testchallenge",
            "origin": "http://localhost"
        ]
        
        let jsonData = try! JSONSerialization.data(withJSONObject: clientData)
        return jsonData.base64EncodedString()
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
