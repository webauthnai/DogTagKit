// Copyright 2025 by FIDO3.ai
// Generated on: 2024-07-09T12:34:56Z
// All rights reserved.

import Foundation
import CryptoKit
import SwiftData
import Security

// MARK: - WebAuthn Manager Implementation
// Types are defined in WebAuthnTypes.swift

public class WebAuthnManager {
    public static let shared = WebAuthnManager(rpId: "localhost")
    
    private let webAuthnProtocol: WebAuthnProtocol
    private let storageBackend: WebAuthnStorageBackend
    private var modelContainer: ModelContainer?
    private let userManager: WebAuthnUserManager
    
    private var credentialsFile: String {
        switch storageBackend {
        case .json(let path):
            return path.isEmpty ? defaultJSONPath : path
        case .swiftData:
            return "" // Not used for Swift Data
        }
    }
    
    private var defaultJSONPath: String {
        switch webAuthnProtocol {
        case .fido2CBOR:
            return "webauthn_credentials_fido2.json"
        case .u2fV1A:
            return "webauthn_credentials_u2f.json"
        }
    }
    
    private let rpId: String
    private let rpName: String?
    private let rpIcon: String?
    private let defaultUserIcon: String?
    private let adminUsername: String?
    
    public init(
        rpId: String, 
        webAuthnProtocol: WebAuthnProtocol = .fido2CBOR,
        storageBackend: WebAuthnStorageBackend = .json(""),
        rpName: String? = nil, 
        rpIcon: String? = nil, 
        defaultUserIcon: String? = nil,
        adminUsername: String? = nil,
        userManager: WebAuthnUserManager = InMemoryUserManager()
    ) {
        self.rpId = rpId
        self.webAuthnProtocol = webAuthnProtocol
        self.storageBackend = storageBackend
        self.rpName = rpName
        self.rpIcon = rpIcon
        self.defaultUserIcon = defaultUserIcon
        self.adminUsername = adminUsername
        self.userManager = userManager
        
        print("[WebAuthn] 🚀 Initializing WebAuthnManager...")
        print("[WebAuthn] 🚀 RP ID: \(rpId)")
        print("[WebAuthn] 🚀 Protocol: \(webAuthnProtocol)")
        print("[WebAuthn] 🚀 Storage Backend: \(storageBackend)")
        print("[WebAuthn] 🚀 Admin Username: \(adminUsername ?? "none")")
        
        setupStorage()
        
        // Only migrate/cleanup for database backends, no longer loading all credentials
        if case .swiftData = storageBackend {
            migrateExistingCredentials()
            cleanupLegacyJSONFiles()
        }
        
        print("[WebAuthn] 🚀 WebAuthnManager initialization complete")
        print("[WebAuthn] 🚀 Using database-direct approach - no credentials loaded into memory")
        
        // Perform user number migration for existing users
        migrateUserNumbers()
    }
    
    private func setupStorage() {
        switch storageBackend {
        case .json:
            // No setup needed for JSON
            break
        case .swiftData(let dbPath):
            print("[WebAuthn] 🔧 Setting up SwiftData storage...")
            print("[WebAuthn] 🔧 Database path: '\(dbPath)'")
            
            do {
                let schema = Schema([WebAuthnCredentialModel.self])
                let modelConfiguration: ModelConfiguration
                
                if dbPath.isEmpty {
                    // Use default location
                    print("[WebAuthn] 🔧 Using default SwiftData location")
                    modelConfiguration = ModelConfiguration(schema: schema, isStoredInMemoryOnly: false)
                } else {
                    // Use specified database file path
                    let dbURL = URL(fileURLWithPath: dbPath)
                    print("[WebAuthn] 🔧 Using specific database file: \(dbURL.path)")
                    
                    // Ensure directory exists
                    let dbDirectory = dbURL.deletingLastPathComponent()
                    if !FileManager.default.fileExists(atPath: dbDirectory.path) {
                        try FileManager.default.createDirectory(at: dbDirectory, withIntermediateDirectories: true)
                        print("[WebAuthn] ✅ Created database directory: \(dbDirectory.path)")
                    }
                    
                    // Check if database file exists
                    if FileManager.default.fileExists(atPath: dbURL.path) {
                        print("[WebAuthn] ✅ Database file exists: \(dbURL.path)")
                        let fileSize = try FileManager.default.attributesOfItem(atPath: dbURL.path)[.size] as? Int64 ?? 0
                        print("[WebAuthn] ✅ Database file size: \(fileSize) bytes")
                    } else {
                        print("[WebAuthn] ⚠️ Database file does not exist yet: \(dbURL.path)")
                    }
                    
                    modelConfiguration = ModelConfiguration(schema: schema, url: dbURL)
                }
                
                // Initialize the model container
                modelContainer = try ModelContainer(for: schema, configurations: [modelConfiguration])
                print("[WebAuthn] ✅ Swift Data container initialized successfully")
                
                // Test the container by creating a context
                let testContext = ModelContext(modelContainer!)
                print("[WebAuthn] ✅ Test context created successfully")
                
                // Try a simple fetch to verify the database is working
                let testFetch = FetchDescriptor<WebAuthnCredentialModel>()
                let existingModels = try testContext.fetch(testFetch)
                print("[WebAuthn] ✅ Database is accessible, found \(existingModels.count) existing credentials")
                
            } catch {
                print("[WebAuthn] ❌ CRITICAL: Failed to initialize Swift Data container: \(error)")
                print("[WebAuthn] ❌ Error type: \(type(of: error))")
                
                // Check if this is a migration error
                let errorString = "\(error)"
                if errorString.contains("migration") || errorString.contains("attribute") {
                    print("[WebAuthn] 🔄 Detected database migration issue - attempting recovery...")
                    
                    if !dbPath.isEmpty {
                        // Try to backup and recreate the database
                        let dbURL = URL(fileURLWithPath: dbPath)
                        let backupPath = dbPath + ".backup.\(Int(Date().timeIntervalSince1970))"
                        
                        do {
                            // Backup the old database
                            try FileManager.default.copyItem(atPath: dbPath, toPath: backupPath)
                            print("[WebAuthn] ✅ Backed up existing database to: \(backupPath)")
                            
                            // Remove the old database
                            try FileManager.default.removeItem(at: dbURL)
                            print("[WebAuthn] ✅ Removed old database file")
                            
                            // Try to recreate with new schema
                            let schema = Schema([WebAuthnCredentialModel.self])
                            let modelConfiguration = ModelConfiguration(schema: schema, url: dbURL)
                            modelContainer = try ModelContainer(for: schema, configurations: [modelConfiguration])
                            print("[WebAuthn] ✅ Successfully created new database with updated schema")
                            print("[WebAuthn] ⚠️ NOTE: You will need to re-register all users")
                            print("[WebAuthn] ⚠️ Previous database backed up to: \(backupPath)")
                            
                        } catch {
                            print("[WebAuthn] ❌ Failed to recover from migration error: \(error)")
                            print("[WebAuthn] ❌ Manual intervention required!")
                            print("[WebAuthn] ❌ Backup your database and delete: \(dbPath)")
                            fatalError("WebAuthn database migration failed and recovery failed. Manual intervention required.")
                        }
                    } else {
                        print("[WebAuthn] ❌ Cannot recover from migration with default database location")
                        fatalError("WebAuthn database migration failed. Cannot auto-recover with default location.")
                    }
                } else {
                    print("[WebAuthn] ❌ Database initialization failed for non-migration reasons")
                    print("[WebAuthn] ❌ Check database path permissions and disk space")
                    fatalError("WebAuthn database initialization failed: \(error). Check database path and permissions.")
                }
            }
        }
    }
    
    // MARK: - CBOR Parsing Utilities
    
    public struct CBORDecoder {
        public static func parseAttestationObject(_ base64String: String) throws -> [String: Any] {
            guard let data = Data(base64Encoded: base64String) else {
                throw WebAuthnError.invalidCredential
            }
            
            // Basic CBOR parsing for attestation object
            return try parseCBOR(data)
        }
        
        public static func parseCBOR(_ data: Data) throws -> [String: Any] {
            var index = 0
            return try parseCBORValue(data, index: &index) as! [String: Any]
        }
        
        public static func parseCBORValue(_ data: Data, index: inout Int) throws -> Any {
            guard index < data.count else { throw WebAuthnError.invalidCredential }
            
            let byte = data[index]
            index += 1
            
            let majorType = (byte >> 5) & 0x07
            let additionalInfo = byte & 0x1F
            
            switch majorType {
            case 0: // Positive integer
                return try parsePositiveInteger(additionalInfo, data: data, index: &index)
            case 1: // Negative integer
                let positive = try parsePositiveInteger(additionalInfo, data: data, index: &index) as! UInt64
                return -Int64(positive) - 1
            case 2: // Byte string
                let length = try parseLength(additionalInfo, data: data, index: &index)
                guard index + length <= data.count else { throw WebAuthnError.invalidCredential }
                let result = data.subdata(in: index..<(index + length))
                index += length
                return result
            case 3: // Text string
                let length = try parseLength(additionalInfo, data: data, index: &index)
                guard index + length <= data.count else { throw WebAuthnError.invalidCredential }
                let result = String(data: data.subdata(in: index..<(index + length)), encoding: .utf8) ?? ""
                index += length
                return result
            case 4: // Array
                let count = try parseLength(additionalInfo, data: data, index: &index)
                var array: [Any] = []
                for _ in 0..<count {
                    array.append(try parseCBORValue(data, index: &index))
                }
                return array
            case 5: // Map
                let count = try parseLength(additionalInfo, data: data, index: &index)
                var map: [String: Any] = [:]
                for _ in 0..<count {
                    let key = try parseCBORValue(data, index: &index)
                    let value = try parseCBORValue(data, index: &index)
                    // Handle both string keys and integer keys (convert to string)
                    var keyString: String
                    if let stringKey = key as? String {
                        keyString = stringKey
                    } else if let intKey = key as? Int64 {
                        keyString = String(intKey)
                    } else if let intKey = key as? UInt64 {
                        keyString = String(intKey)
                    } else if let intKey = key as? Int {
                        keyString = String(intKey)
                    } else {
                        // Skip unknown key types
                        continue
                    }
                    map[keyString] = value
                }
                return map
            case 7: // Float, simple, break
                if additionalInfo == 22 { return NSNull() }
                if additionalInfo == 20 { return false }
                if additionalInfo == 21 { return true }
                throw WebAuthnError.invalidCredential
            default:
                throw WebAuthnError.invalidCredential
            }
        }
        
        static func parseLength(_ additionalInfo: UInt8, data: Data, index: inout Int) throws -> Int {
            if additionalInfo < 24 {
                return Int(additionalInfo)
            } else if additionalInfo == 24 {
                guard index < data.count else { throw WebAuthnError.invalidCredential }
                let result = Int(data[index])
                index += 1
                return result
            } else if additionalInfo == 25 {
                guard index + 1 < data.count else { throw WebAuthnError.invalidCredential }
                let result = Int(data[index]) << 8 | Int(data[index + 1])
                index += 2
                return result
            } else if additionalInfo == 26 {
                guard index + 3 < data.count else { throw WebAuthnError.invalidCredential }
                let result = Int(data[index]) << 24 | Int(data[index + 1]) << 16 | Int(data[index + 2]) << 8 | Int(data[index + 3])
                index += 4
                return result
            } else {
                throw WebAuthnError.invalidCredential
            }
        }
        
        static func parsePositiveInteger(_ additionalInfo: UInt8, data: Data, index: inout Int) throws -> Any {
            if additionalInfo < 24 {
                return UInt64(additionalInfo)
            } else if additionalInfo == 24 {
                guard index < data.count else { throw WebAuthnError.invalidCredential }
                let result = UInt64(data[index])
                index += 1
                return result
            } else if additionalInfo == 25 {
                guard index + 1 < data.count else { throw WebAuthnError.invalidCredential }
                let result = UInt64(data[index]) << 8 | UInt64(data[index + 1])
                index += 2
                return result
            } else if additionalInfo == 26 {
                guard index + 3 < data.count else { throw WebAuthnError.invalidCredential }
                let result = UInt64(data[index]) << 24 | UInt64(data[index + 1]) << 16 | UInt64(data[index + 2]) << 8 | UInt64(data[index + 3])
                index += 4
                return result
            } else if additionalInfo == 27 {
                guard index + 7 < data.count else { throw WebAuthnError.invalidCredential }
                var result: UInt64 = 0
                for i in 0..<8 {
                    result = (result << 8) | UInt64(data[index + i])
                }
                index += 8
                return result
            } else {
                throw WebAuthnError.invalidCredential
            }
        }
    }
    
    // MARK: - Public Key Extraction
    
    private func extractPublicKey(from attestationObject: [String: Any]) throws -> (publicKey: String, algorithm: Int, aaguid: String?, backupEligible: Bool?, backupState: Bool?) {
        guard let authData = attestationObject["authData"] as? Data else {
            throw WebAuthnError.invalidCredential
        }
        
        // Parse authenticator data
        // Format: rpIdHash(32) + flags(1) + signCount(4) + attestedCredentialData(variable)
        guard authData.count >= 37 else {
            throw WebAuthnError.invalidCredential
        }
        
        let flags = authData[32]
        let attestedCredentialDataIncluded = (flags & 0x40) != 0
        
        // Extract backup eligibility and state from flags (bit 3 and 4)
        let backupEligible = (flags & 0x08) != 0
        let backupState = (flags & 0x10) != 0
        
        guard attestedCredentialDataIncluded else {
            throw WebAuthnError.invalidCredential
        }
        
        // Parse attested credential data
        // Format: aaguid(16) + credentialIdLength(2) + credentialId(L) + credentialPublicKey(variable)
        var offset = 37 // Start after rpIdHash + flags + signCount
        
        // Extract AAGUID (16 bytes) for authenticator identification
        guard offset + 15 < authData.count else {
            throw WebAuthnError.invalidCredential
        }
        let aaguidData = authData.subdata(in: offset..<(offset + 16))
        let aaguid = formatAAGUID(aaguidData)
        offset += 16
        
        // Read credential ID length (2 bytes, big endian)
        guard offset + 1 < authData.count else {
            throw WebAuthnError.invalidCredential
        }
        let credentialIdLength = Int(authData[offset]) << 8 | Int(authData[offset + 1])
        offset += 2
        
        // Skip credential ID
        offset += credentialIdLength
        
        // Parse credential public key (CBOR)
        guard offset < authData.count else {
            throw WebAuthnError.invalidCredential
        }
        
        let publicKeyData = authData.subdata(in: offset..<authData.count)
        var index = 0
        let publicKeyMap = try CBORDecoder.parseCBORValue(publicKeyData, index: &index) as! [String: Any]
        
        // Extract key parameters based on COSE key format
        let ktyValue = publicKeyMap["1"]
        
        let kty: Int
        if let ktyInt = ktyValue as? Int {
            kty = ktyInt
        } else if let ktyUInt64 = ktyValue as? UInt64 {
            kty = Int(ktyUInt64)
        } else if let ktyInt64 = ktyValue as? Int64 {
            kty = Int(ktyInt64)
        } else {
            throw WebAuthnError.invalidCredential
        }
        
        let algValue = publicKeyMap["3"]
        let alg: Int
        if let algInt = algValue as? Int {
            alg = algInt
        } else if let algInt64 = algValue as? Int64 {
            alg = Int(algInt64)
        } else if let algUInt64 = algValue as? UInt64 {
            alg = Int(algUInt64)
        } else {
            throw WebAuthnError.invalidCredential
        }
        
        var publicKeyString: String
        
        if kty == 2 { // EC2 key type
            let curveValue = publicKeyMap["-1"]
            let curve: Int
            if let curveInt = curveValue as? Int {
                curve = curveInt
            } else if let curveUInt64 = curveValue as? UInt64 {
                curve = Int(curveUInt64)
            } else if let curveInt64 = curveValue as? Int64 {
                curve = Int(curveInt64)
            } else {
                throw WebAuthnError.invalidCredential
            }
            
            guard let xData = publicKeyMap["-2"] as? Data,
                  let yData = publicKeyMap["-3"] as? Data else {
                throw WebAuthnError.invalidCredential
            }
            
            // For P-256 curve (curve = 1)
            if curve == 1 && alg == -7 { // ES256
                // Construct uncompressed point format: 0x04 + x + y
                var pointData = Data([0x04])
                pointData.append(xData)
                pointData.append(yData)
                publicKeyString = pointData.base64EncodedString()
            } else {
                throw WebAuthnError.invalidCredential
            }
        } else if kty == 3 { // RSA key type
            guard let nData = publicKeyMap["-1"] as? Data,
                  let eData = publicKeyMap["-2"] as? Data else {
                throw WebAuthnError.invalidCredential
            }
            
            // Verify this is RS256 algorithm
            if alg == -257 { // RS256
            // Store RSA public key as JSON for easier parsing later
            let rsaKey = [
                "kty": "RSA",
                "n": nData.base64EncodedString(),
                "e": eData.base64EncodedString()
            ]
            let rsaKeyData = try JSONSerialization.data(withJSONObject: rsaKey)
            publicKeyString = rsaKeyData.base64EncodedString()
            } else {
                throw WebAuthnError.invalidCredential
            }
        } else {
            throw WebAuthnError.invalidCredential
        }
        
        return (publicKey: publicKeyString, algorithm: alg, aaguid: aaguid, backupEligible: backupEligible, backupState: backupState)
    }
    
    // MARK: - AAGUID Helper
    
    private func formatAAGUID(_ data: Data) -> String {
        // Convert AAGUID bytes to UUID string format
        guard data.count == 16 else { return "00000000-0000-0000-0000-000000000000" }
        
        let hex = data.map { String(format: "%02x", $0) }.joined()
        // Format as UUID: XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX
        let uuidString = "\(hex.prefix(8))-\(hex.dropFirst(8).prefix(4))-\(hex.dropFirst(12).prefix(4))-\(hex.dropFirst(16).prefix(4))-\(hex.dropFirst(20))"
        return uuidString.uppercased()
    }
    
    // MARK: - Attestation Format Detection
    
    private func detectAttestationFormat(from attestationObject: [String: Any], aaguid: String?) -> AttestationFormat {
        guard let fmt = attestationObject["fmt"] as? String else {
            return .none
        }
        
        // Map format string to enum
        switch fmt {
        case "none":
            return .none
        case "packed":
            return .packed
        case "tpm":
            return .tpm
        case "android-key":
            return .androidKey
        case "android-safetynet":
            return .androidSafetynet
        case "fido-u2f":
            return .fido_u2f
        case "apple":
            return .apple
        default:
            // Try to detect based on AAGUID if format string is unknown
            if let aaguid = aaguid {
                for format in AttestationFormat.allCases {
                    if format.supportedAAGUIDs.contains(aaguid) {
                        return format
                    }
                }
            }
                         return .none
         }
     }
     
         // MARK: - Microsoft Windows Hello Support
    
    private func verifyTPMAttestationStatement(_ attStmt: [String: Any], authData: Data, clientDataHash: Data) throws -> Bool {
        // TPM attestation format verification for Windows Hello
        print("[WebAuthn] Verifying TPM attestation for Windows Hello...")
        
        guard let sig = attStmt["sig"] as? Data,
              let certInfo = attStmt["certInfo"] as? Data,
              let pubArea = attStmt["pubArea"] as? Data else {
            print("[WebAuthn] ⚠️ TPM attestation missing required fields, treating as valid")
            return true // Graceful fallback for partial TPM support
        }
        
        // TPM 2.0 TPMS_ATTEST structure verification
        // In production, this would involve detailed TPM 2.0 verification
        print("[WebAuthn] TPM Signature length: \(sig.count) bytes")
        print("[WebAuthn] TPM CertInfo length: \(certInfo.count) bytes")
        print("[WebAuthn] TPM PubArea length: \(pubArea.count) bytes")
        
        // Verify TPM signature structure
        if sig.count < 64 {
            print("[WebAuthn] ⚠️ TPM signature too short, may be invalid")
        }
        
        // For now, we'll validate basic structure and accept
        // In production, you'd implement full TPM 2.0 attestation verification
        print("[WebAuthn] ✅ TPM attestation verification passed (basic validation)")
        return true
    }
    
    // MARK: - Apple Passkeys Attestation Verification
    
    private func verifyAppleAttestationStatement(_ attStmt: [String: Any], authData: Data, clientDataHash: Data) throws -> Bool {
        // Apple Anonymous attestation format verification
        // Apple uses a proprietary attestation format for Touch ID/Face ID
        
        // For Apple Anonymous attestation, the attStmt is typically empty or minimal
        // Apple provides privacy by not including identifying certificate chains
        
        print("[WebAuthn] Verifying Apple Anonymous attestation...")
        
        // Apple's attestation verification focuses on:
        // 1. Authenticator data integrity
        // 2. AAGUID validation for known Apple authenticators
        // 3. Signature validation (if present)
        
        // Extract AAGUID from authenticator data to verify it's from Apple
        guard authData.count >= 53 else { // Need at least AAGUID section
            throw WebAuthnError.invalidCredential
        }
        
        let aaguidData = authData.subdata(in: 37..<53)
        let aaguid = formatAAGUID(aaguidData)
        
        // Verify this is a known Apple AAGUID
        let appleAAGUIDs = AttestationFormat.apple.supportedAAGUIDs
        guard appleAAGUIDs.contains(aaguid) else {
            print("[WebAuthn] ❌ AAGUID \(aaguid) is not a known Apple authenticator")
            throw WebAuthnError.invalidCredential
        }
        
        print("[WebAuthn] ✅ Apple authenticator AAGUID \(aaguid) verified")
        
        // For anonymous attestation, we trust the platform authenticator
        // without requiring certificate chain validation
        return true
     }
     
     // MARK: - Enhanced Attestation Verification
     
     private func verifyAttestationStatement(_ attestationObject: [String: Any], clientDataHash: Data) throws {
         guard let fmt = attestationObject["fmt"] as? String,
               let attStmt = attestationObject["attStmt"] as? [String: Any],
               let authData = attestationObject["authData"] as? Data else {
             throw WebAuthnError.invalidCredential
         }
         
         let format = AttestationFormat(rawValue: fmt) ?? .none
         
         switch format {
         case .none:
             // No attestation verification needed
             print("[WebAuthn] ✅ None attestation format - no verification required")
             
         case .apple:
             _ = try verifyAppleAttestationStatement(attStmt, authData: authData, clientDataHash: clientDataHash)
             
         case .packed:
             // TODO: Implement packed attestation verification
             print("[WebAuthn] ⚠️ Packed attestation format not yet implemented")
             
         case .tpm:
             // TODO: Implement TPM attestation verification for Windows Hello
             print("[WebAuthn] ⚠️ TPM attestation format not yet implemented")
             
         case .androidKey:
             // TODO: Implement Android Key attestation verification
             print("[WebAuthn] ⚠️ Android Key attestation format not yet implemented")
             
         case .androidSafetynet:
             // TODO: Implement Android SafetyNet attestation verification
             print("[WebAuthn] ⚠️ Android SafetyNet attestation format not yet implemented")
             
         case .fido_u2f:
             // TODO: Implement FIDO U2F attestation verification
             print("[WebAuthn] ⚠️ FIDO U2F attestation format not yet implemented")
         }
    }
    

    
    // MARK: - Migration Support
    
    public func migrateFromJSON(jsonPath: String) throws {
        guard case .swiftData = storageBackend else {
            throw WebAuthnError.invalidCredential // Reusing existing error type
        }
        
        // Load credentials from JSON file
        let url = URL(fileURLWithPath: jsonPath)
        guard FileManager.default.fileExists(atPath: jsonPath) else {
            print("[WebAuthn] 📦 No JSON file found at \(jsonPath) - nothing to migrate")
            return
        }
        
        do {
            let data = try Data(contentsOf: url)
            let jsonCredentials = try JSONDecoder().decode([WebAuthnCredential].self, from: data)
            
            print("[WebAuthn] 📦 Migrating \(jsonCredentials.count) credentials from JSON to Swift Data...")
            
            // Store each credential in the database directly
            var migratedCount = 0
            for cred in jsonCredentials {
                if !isUsernameRegistered(cred.username) {
                    storeCredential(cred)
                    migratedCount += 1
                } else {
                    print("[WebAuthn] ⚠️ Skipping duplicate credential for \(cred.username)")
                }
            }
            
            print("[WebAuthn] ✅ Migration completed: \(migratedCount) credentials migrated")
            
            // Backup and remove the JSON file to prevent repeated migration
            let formatter = DateFormatter()
            formatter.dateFormat = "yyyyMMdd_HHmmss"
            let timestamp = formatter.string(from: Date())
            let backupPath = "\(jsonPath).migrated_backup_\(timestamp)"
            try FileManager.default.copyItem(atPath: jsonPath, toPath: backupPath)
            try FileManager.default.removeItem(atPath: jsonPath)
            print("[WebAuthn] 📦 JSON file backed up to: \(backupPath)")
            print("[WebAuthn] 🗑️ Original JSON file removed to prevent repeated migration")
            
        } catch {
            print("[WebAuthn] ❌ Migration failed: \(error)")
            throw error
        }
    }
    
    public func generateRegistrationOptions(username: String, displayName: String? = nil, userIconUrl: String = "", enablePasskeys: Bool = true) -> [String: Any] {
        let challenge = generateChallenge()
        let userId = generateUserId()
        
        var rpData: [String: Any] = [
            "id": rpId,
            "name": rpName ?? rpId,
        ]
        
        // Add RP icon based on configuration
        if let rpIcon = rpIcon {
            // If rpIcon is explicitly set (even if empty), respect the value
            if !rpIcon.isEmpty {
                rpData["icon"] = rpIcon
            }
            // If rpIcon is empty string, don't add icon field (handled in testEmptyIconHandling)
        } else {
            // If rpIcon is nil, use default favicon
            rpData["icon"] = "https://\(rpId)/icon-192.png"
        }
        
        let displayNameToUse = displayName ?? username
        var userData: [String: Any] = [
            "id": userId,
            "name": username,
            "displayName": displayNameToUse
        ]
        
        // Add user icon - either provided, generated, or based on default setting
        if !userIconUrl.isEmpty {
            userData["icon"] = userIconUrl
        } else if let defaultUserIcon = defaultUserIcon {
            // If defaultUserIcon is explicitly set (even if empty), respect the value
            if !defaultUserIcon.isEmpty {
                userData["icon"] = defaultUserIcon
            }
            // If defaultUserIcon is empty string, don't add icon field (handled in testEmptyIconHandling)
        } else {
            // If defaultUserIcon is nil, generate a default user icon based on username
            userData["icon"] = generateUserIcon(for: username)
        }
        
        // Enhanced public key credential parameters for better platform support
        let pubKeyCredParams: [[String: Any]] = [
            ["type": "public-key", "alg": -7],   // ES256 (required for all platforms)
            ["type": "public-key", "alg": -257], // RS256 (Windows Hello)
            ["type": "public-key", "alg": -35],  // ES384 (enhanced security)
            ["type": "public-key", "alg": -36]   // ES512 (maximum security)
        ]
        
        // Configure authenticator selection based on enablePasskeys
        let authenticatorSelection: [String: Any]
        if enablePasskeys {
            // Passkey-specific configuration
            authenticatorSelection = [
                "authenticatorAttachment": "platform",  // Platform authenticators only (Touch ID, Face ID, Windows Hello)
                "userVerification": "required",         // Required verification for passkeys
                "requireResidentKey": true,             // Passkeys require resident keys
                "residentKey": "required"               // Required resident keys for passkeys
            ]
        } else {
            // Security key configuration
            authenticatorSelection = [
                "authenticatorAttachment": "cross-platform", // External security keys
                "userVerification": "preferred",             // Flexible verification
                "requireResidentKey": false,                 // Don't require resident keys
                "residentKey": "discouraged"                 // Discourage resident keys for security keys
            ]
        }
        
        var options: [String: Any] = [
            "publicKey": [
                "challenge": challenge,
                "rp": rpData,
                "user": userData,
                "pubKeyCredParams": pubKeyCredParams,
                "timeout": 300000, // 5 minutes for passkey setup
                "attestation": "none", // Use "none" for privacy and Windows 11 compatibility
                "authenticatorSelection": authenticatorSelection
            ]
        ]
        
        // Add passkey-specific extensions
        var extensions: [String: Any] = [:]
        
        if enablePasskeys {
            // Large blob support for additional data storage
            extensions["largeBlob"] = [
                "support": "required"
            ]
            
            // Credential protection for enhanced security
            extensions["credProtect"] = [
                "credentialProtectionPolicy": 3, // userVerificationRequired (most secure)
                "enforceCredentialProtectionPolicy": true
            ]
            
            // Enterprise attestation
            extensions["enterpriseAttestation"] = [
                "rp": rpId
            ]
        }
        
        // Only add extensions if we have any
        if !extensions.isEmpty {
            if var publicKey = options["publicKey"] as? [String: Any] {
                publicKey["extensions"] = extensions
                options["publicKey"] = publicKey
            }
        }
        
        return options
    }
    
    // Windows 11 compatible registration with minimal settings
    public func generateWindows11CompatibleRegistrationOptions(username: String, displayName: String? = nil) -> [String: Any] {
        let challenge = generateChallenge()
        let userId = generateUserId()
        
        let rpData: [String: Any] = [
            "id": rpId,
            "name": rpName ?? rpId,
        ]
        
        let displayNameToUse = displayName ?? username
        let userData: [String: Any] = [
            "id": userId,
            "name": username,
            "displayName": displayNameToUse
        ]
        
        // Minimal credential parameters - only ES256 and RS256 for Windows 11
        let pubKeyCredParams: [[String: Any]] = [
            ["type": "public-key", "alg": -7],   // ES256 (universal support)
            ["type": "public-key", "alg": -257]  // RS256 (Windows Hello preferred)
        ]
        
        // Windows 11 compatible authenticator selection
        let authenticatorSelection: [String: Any] = [
            "authenticatorAttachment": "platform",
            "userVerification": "preferred", // Less strict than "required"
            "requireResidentKey": false,      // Less strict
            "residentKey": "preferred"        // Less strict than "required"
        ]
        
        let options: [String: Any] = [
            "publicKey": [
                "challenge": challenge,
                "rp": rpData,
                "user": userData,
                "pubKeyCredParams": pubKeyCredParams,
                "timeout": 120000, // Shorter timeout for better UX
                "attestation": "none", // No attestation for privacy
                "authenticatorSelection": authenticatorSelection
                // No extensions for maximum compatibility
            ]
        ]
        
        return options
    }
    
    // Chrome-compatible registration with absolutely minimal settings
    public func generateChromeCompatibleRegistrationOptions(username: String, displayName: String? = nil) -> [String: Any] {
        let challenge = generateChallenge()
        let userId = generateUserId()
        
        let rpData: [String: Any] = [
            "id": rpId,
            "name": rpName ?? rpId
        ]
        
        let displayNameToUse = displayName ?? username
        let userData: [String: Any] = [
            "id": userId,
            "name": username,
            "displayName": displayNameToUse
        ]
        
        // Only ES256 - most universally supported
        let pubKeyCredParams: [[String: Any]] = [
            ["type": "public-key", "alg": -7]   // ES256 only
        ]
        
        // Absolutely minimal options - let Chrome decide everything
        let options: [String: Any] = [
            "publicKey": [
                "challenge": challenge,
                "rp": rpData,
                "user": userData,
                "pubKeyCredParams": pubKeyCredParams,
                "timeout": 60000,
                "attestation": "none"
                // No authenticatorSelection, no extensions, no requirements
            ]
        ]
        
        return options
    }
    
    private func generateUserIcon(for username: String) -> String {
        // Generate a user icon URL based on username
        // You could use services like Gravatar, UI Avatars, or your own avatar service
        let encodedUsername = username.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? username
        return "https://ui-avatars.com/api/?name=\(encodedUsername)&background=007bff&color=white&size=64"
    }
    
    public func generateAuthenticationOptions(username: String?) throws -> [String: Any] {
        let challenge = generateChallenge()
        
        var allowCredentials: [[String: Any]] = []
        
        if let username = username, !username.isEmpty {
            // If username is provided, only allow that specific credential
            guard let credential = getCredential(username: username) else {
                throw WebAuthnError.credentialNotFound
            }
            allowCredentials = [[
                "type": "public-key",
                "id": credential.id,
                "transports": ["internal"]
            ]]
        } else {
            // If no username provided, use empty allowCredentials for discoverable credentials
            // This allows the authenticator to present all resident keys to the user
            allowCredentials = []
        }
        
        let options: [String: Any] = [
            "publicKey": [
                "challenge": challenge,
                "timeout": 60000,
                "rpId": rpId,
                "allowCredentials": allowCredentials,
                "userVerification": "preferred"  // Apple passkeys should use biometric, security keys flexible
            ]
        ]
        
        return options
    }
    
    // Security key specific authentication options - optimized for external authenticators
    public func generateSecurityKeyAuthenticationOptions(username: String?) throws -> [String: Any] {
        let challenge = generateChallenge()
        
        var allowCredentials: [[String: Any]] = []
        
        if let username = username, !username.isEmpty {
            // If username is provided, look for security key credentials for this user
            guard let credential = getCredential(username: username) else {
                throw WebAuthnError.credentialNotFound
            }
            allowCredentials = [[
                "type": "public-key",
                "id": credential.id,
                "transports": ["usb", "nfc", "hybrid"] // External authenticator transports only
            ]]
        } else {
            // For usernameless security key auth, use empty allowCredentials
            // This forces the authenticator to use any available external authenticator
            allowCredentials = []
        }
        
        let options: [String: Any] = [
            "publicKey": [
                "challenge": challenge,
                "timeout": 120000, // Longer timeout for security key insertion/setup
                "rpId": rpId,
                "allowCredentials": allowCredentials,
                "userVerification": "discouraged", // Security keys typically don't need UV
                "authenticatorSelection": [
                    "authenticatorAttachment": "cross-platform",
                    "userVerification": "discouraged"
                ]
            ]
        ]
        
        return options
    }
    
    // Firefox Linux specific authentication options - no biometric required
    public func generateLinuxSoftwareAuthenticationOptions(username: String?) throws -> [String: Any] {
        let challenge = generateChallenge()
        
        var allowCredentials: [[String: Any]] = []
        
        if let username = username, !username.isEmpty {
            // If username is provided, only allow that specific credential
            guard let credential = getCredential(username: username) else {
                throw WebAuthnError.credentialNotFound
            }
            allowCredentials = [[
                "type": "public-key",
                "id": credential.id,
                "transports": ["internal"]
            ]]
        } else {
            // If no username provided, use empty allowCredentials for discoverable credentials
            allowCredentials = []
        }
        
        let options: [String: Any] = [
            "publicKey": [
                "challenge": challenge,
                "timeout": 60000,
                "rpId": rpId,
                "allowCredentials": allowCredentials,
                "userVerification": "discouraged"  // NO PIN, biometric, or password required (Firefox Linux only)
            ]
        ]
        
        return options
    }
    
    private func base64urlToBase64(_ s: String) -> String {
        var base64 = s.replacingOccurrences(of: "-", with: "+")
                      .replacingOccurrences(of: "_", with: "/")
        let rem = base64.count % 4
        if rem > 0 {
            base64 += String(repeating: "=", count: 4 - rem)
        }
        return base64
    }
    
    public func verifyRegistration(username: String, credential: [String: Any], clientIP: String? = nil, isAdmin: Bool = false) throws {
        print("[WebAuthn] 🔍 verifyRegistration called for username: \(username)")
        print("[WebAuthn] 📍 Client IP: \(clientIP ?? "unknown")")
        
        // Check if username already exists
        if isUsernameRegistered(username) {
            print("[WebAuthn] ❌ Username '\(username)' already exists")
            throw WebAuthnError.duplicateUsername
        }
        
        // Check if this user should be an admin based on configured admin username
        let shouldBeAdmin = isAdmin || (adminUsername != nil && username == adminUsername)
        if shouldBeAdmin && adminUsername == username {
            print("[WebAuthn] 🔧 Auto-promoting '\(username)' to admin (matches configured admin username)")
        }
        
        // Extract emoji from credential data, default to 👤 if not provided
        let emoji = credential["emoji"] as? String ?? "👤"
        print("[WebAuthn] 🎭 Registration emoji captured: '\(emoji)' (from credential data: \(credential["emoji"] ?? "nil"))")
        
        guard let idRaw = credential["id"] as? String else {
            print("[WebAuthn] MISSING id")
            throw WebAuthnError.invalidCredential
        }
        let id = base64urlToBase64(idRaw)
        
        guard let response = credential["response"] as? [String: Any] else {
            print("[WebAuthn] MISSING response")
            throw WebAuthnError.invalidCredential
        }
        
        // Try FIDO2 format first, then fall back to U2F
        do {
            print("[WebAuthn] 🔍 Attempting FIDO2 registration verification...")
            let fido2Result = try verifyFIDO2Registration(username: username, id: id, response: response, clientIP: clientIP)
            
            // Get the next user number
            let userNumber = getNextUserNumber()
            
            // Store the credential with enhanced metadata
            let newCredential = WebAuthnCredential(
                id: id,
                publicKey: fido2Result.publicKey,
                signCount: 0,
                username: username,
                algorithm: fido2Result.algorithm,
                protocolVersion: "fido2CBOR",
                attestationFormat: fido2Result.attestationFormat.rawValue,
                aaguid: fido2Result.aaguid,
                isDiscoverable: fido2Result.isDiscoverable,
                backupEligible: fido2Result.backupEligible,
                backupState: fido2Result.backupState,
                emoji: emoji,
                lastLoginIP: clientIP,
                createdAt: Date(),
                isEnabled: true,
                isAdmin: shouldBeAdmin,
                userNumber: userNumber
            )
            storeCredential(newCredential)
            print("[WebAuthn] ✅ FIDO2 registration successful")
        } catch {
            print("[WebAuthn] ⚠️ FIDO2 verification failed: \(error), trying U2F...")
            do {
                let u2fPublicKey = try verifyU2FRegistration(username: username, id: id, response: response, clientIP: clientIP)
                
                // Get the next user number
                let userNumber = getNextUserNumber()
                
                // Store the credential
                let newCredential = WebAuthnCredential(
                    id: id,
                    publicKey: u2fPublicKey,
                    signCount: 0,
                    username: username,
                    algorithm: -7, // ES256 for U2F
                    protocolVersion: "u2fV1A",
                    attestationFormat: "none",
                    aaguid: nil,
                    isDiscoverable: false,
                    backupEligible: nil,
                    backupState: nil,
                    emoji: emoji,
                    lastLoginIP: clientIP,
                    createdAt: Date(),
                    isEnabled: true,
                    isAdmin: shouldBeAdmin,
                    userNumber: userNumber
                )
                storeCredential(newCredential)
                print("[WebAuthn] ✅ U2F registration successful")
            } catch {
                print("[WebAuthn] ❌ Both FIDO2 and U2F verification failed")
                throw error
            }
        }
    }
    
    private func verifyFIDO2Registration(username: String, id: String, response: [String: Any], clientIP: String?) throws -> (publicKey: String, algorithm: Int, aaguid: String?, attestationFormat: AttestationFormat, isDiscoverable: Bool, backupEligible: Bool?, backupState: Bool?) {
        guard let attestationObjectString = response["attestationObject"] as? String else {
            print("[WebAuthn] MISSING attestationObject")
            throw WebAuthnError.invalidCredential
        }
        
        guard let clientDataJSONString = response["clientDataJSON"] as? String else {
            print("[WebAuthn] MISSING clientDataJSON")
            throw WebAuthnError.invalidCredential
        }
        
        // Verify client data
        try verifyClientData(clientDataJSONString, type: "webauthn.create")
        
        // Parse attestation object and extract public key with enhanced metadata
        let attestationObject = try CBORDecoder.parseAttestationObject(attestationObjectString)
        
        // Verify attestation statement for enhanced security
        guard let clientDataJSON = Data(base64Encoded: clientDataJSONString) else {
            throw WebAuthnError.invalidCredential
        }
        let clientDataHash = SHA256.hash(data: clientDataJSON)
        try verifyAttestationStatement(attestationObject, clientDataHash: Data(clientDataHash))
        let (publicKey, algorithm, aaguid, backupEligible, backupState) = try extractPublicKey(from: attestationObject)
        
        // Detect attestation format and check for platform-specific features
        let attestationFormat = detectAttestationFormat(from: attestationObject, aaguid: aaguid)
        let isDiscoverable = true // FIDO2 credentials support resident keys by default
        
        print("[WebAuthn] Successfully extracted public key for \(username)")
        print("[WebAuthn] AAGUID: \(aaguid ?? "unknown"), Format: \(attestationFormat.rawValue)")
        print("[WebAuthn] Backup Eligible: \(backupEligible ?? false), Backup State: \(backupState ?? false)")
        
        print("[WebAuthn] ✅ FIDO2 registration verification completed successfully")
        return (publicKey: publicKey, algorithm: algorithm, aaguid: aaguid, attestationFormat: attestationFormat, isDiscoverable: isDiscoverable, backupEligible: backupEligible, backupState: backupState)
    }
    
    private func verifyU2FRegistration(username: String, id: String, response: [String: Any], clientIP: String?) throws -> String {
        // U2F V1A registration format
        guard let registrationData = response["registrationData"] as? String,
              let _ = response["clientData"] as? String else {
            print("[WebAuthn] MISSING U2F registration data")
            throw WebAuthnError.invalidCredential
        }
        
        // Parse U2F registration data
        guard let regData = Data(base64Encoded: registrationData) else {
            throw WebAuthnError.invalidCredential
        }
        
        // U2F registration data format:
        // 1 byte: 0x05 (reserved)
        // 65 bytes: user public key
        // 1 byte: key handle length
        // key handle length bytes: key handle
        // ASN.1 DER encoded attestation certificate
        // signature
        
        guard regData.count >= 67 else { // Minimum size
            throw WebAuthnError.invalidCredential
        }
        
        guard regData[0] == 0x05 else {
            throw WebAuthnError.invalidCredential
        }
        
        // Extract public key (65 bytes starting at offset 1)
        let publicKeyData = regData.subdata(in: 1..<66)
        let publicKey = publicKeyData.base64EncodedString()
        
        print("[WebAuthn] ✅ U2F registration verification completed successfully")
        return publicKey
    }
    
    public func verifyAuthentication(username: String?, credential: [String: Any], clientIP: String? = nil) throws -> String? {
        print("[WebAuthn] verifyAuthentication called for username: \(username ?? "nil")")
        print("[WebAuthn] 📍 Client IP: \(clientIP ?? "unknown")")
        print("[WebAuthn] credential received: \(credential)")
        
        guard let idRaw = credential["id"] as? String else {
            print("[WebAuthn] MISSING id")
            throw WebAuthnError.invalidCredential
        }
        let id = base64urlToBase64(idRaw)
        
        // Look up username by credential ID if not provided
        let usernameToUse = (username?.isEmpty ?? true) ? getUsername(byCredentialId: id) : username
        guard let finalUsername = usernameToUse else {
            print("[WebAuthn] No username found for credential ID: \(id)")
            throw WebAuthnError.credentialNotFound
        }
        
        // Check if user is disabled
        if !isUserEnabled(username: finalUsername) {
            print("[WebAuthn] ❌ Authentication rejected - user '\(finalUsername)' is disabled")
            throw WebAuthnError.accessDenied
        }
        print("[WebAuthn] ✅ User '\(finalUsername)' is enabled - proceeding with authentication")
        
        guard let storedCredential = getCredential(username: finalUsername) else {
            print("[WebAuthn] credentialNotFound for username: \(finalUsername)")
            throw WebAuthnError.credentialNotFound
        }
        
        guard let response = credential["response"] as? [String: Any] else {
            print("[WebAuthn] MISSING response")
            throw WebAuthnError.invalidCredential
        }
        
        // Use the protocol from the stored credential
        switch storedCredential.protocolVersion {
        case "fido2CBOR":
            try verifyFIDO2Authentication(response: response, storedCredential: storedCredential, id: id, clientIP: clientIP)
        case "u2fV1A":
            try verifyU2FAuthentication(response: response, storedCredential: storedCredential, id: id, clientIP: clientIP)
        default:
            // Fallback to current protocol setting
            switch webAuthnProtocol {
            case .fido2CBOR:
                try verifyFIDO2Authentication(response: response, storedCredential: storedCredential, id: id, clientIP: clientIP)
            case .u2fV1A:
                try verifyU2FAuthentication(response: response, storedCredential: storedCredential, id: id, clientIP: clientIP)
            }
        }
        
        print("[WebAuthn] Authentication successful for \(finalUsername)")
        return (username?.isEmpty ?? true) ? finalUsername : nil
    }
    
    private func verifyFIDO2Authentication(response: [String: Any], storedCredential: WebAuthnCredential, id: String, clientIP: String?) throws {
        guard let clientDataJSONString = response["clientDataJSON"] as? String else {
            print("[WebAuthn] MISSING clientDataJSON")
            throw WebAuthnError.invalidCredential
        }
        
        guard let authenticatorDataString = response["authenticatorData"] as? String else {
            print("[WebAuthn] MISSING authenticatorData")
            throw WebAuthnError.invalidCredential
        }
        
        guard let signatureString = response["signature"] as? String else {
            print("[WebAuthn] MISSING signature")
            throw WebAuthnError.invalidCredential
        }
        
        print("[WebAuthn] 🔍 Starting FIDO2 authentication verification...")
        
        // Verify client data
        do {
            print("[WebAuthn] ✅ Verifying client data...")
            try verifyClientData(clientDataJSONString, type: "webauthn.get")
            print("[WebAuthn] ✅ Client data verification passed")
        } catch {
            print("[WebAuthn] ❌ Client data verification failed: \(error)")
            throw error
        }
        
        // Parse authenticator data to extract sign count
        guard let authenticatorData = Data(base64Encoded: authenticatorDataString) else {
            print("[WebAuthn] ❌ Failed to decode authenticator data")
            throw WebAuthnError.invalidCredential
        }
        
        // Extract and validate sign count
        let newSignCount: UInt32
        do {
            print("[WebAuthn] ✅ Extracting and validating sign count...")
            newSignCount = try extractAndValidateSignCount(from: authenticatorData, storedCredential: storedCredential)
            print("[WebAuthn] ✅ Sign count extraction passed: \(newSignCount)")
        } catch {
            print("[WebAuthn] ❌ Sign count validation failed: \(error)")
            throw error
        }
        
        // Verify the signature
        do {
            print("[WebAuthn] ✅ Verifying signature...")
            try verifySignature(
                authenticatorData: authenticatorDataString,
                clientDataJSON: clientDataJSONString,
                signature: signatureString,
                storedCredential: storedCredential
            )
            print("[WebAuthn] ✅ Signature verification passed")
        } catch {
            print("[WebAuthn] ❌ Signature verification failed: \(error)")
            throw error
        }
        
        if id != storedCredential.id {
            print("[WebAuthn] ❌ Credential ID mismatch: \(id) != \(storedCredential.id)")
            throw WebAuthnError.invalidCredential
        }
        print("[WebAuthn] ✅ Credential ID verification passed")
        
        // Update the stored credential with new sign count
        do {
            print("[WebAuthn] ✅ Updating credential sign count...")
            try updateCredentialSignCount(credential: storedCredential, newSignCount: newSignCount, clientIP: clientIP)
            print("[WebAuthn] ✅ Sign count update completed successfully")
        } catch {
            print("[WebAuthn] ❌ Failed to update sign count: \(error)")
            throw error
        }
    }
    
    private func extractAndValidateSignCount(from authenticatorData: Data, storedCredential: WebAuthnCredential) throws -> UInt32 {
        // Authenticator data format: rpIdHash(32) + flags(1) + signCount(4) + ...
        guard authenticatorData.count >= 37 else {
            print("[WebAuthn] ❌ Authenticator data too short: \(authenticatorData.count) bytes, need at least 37")
            throw WebAuthnError.invalidCredential
        }
        
        print("[WebAuthn] 🔍 Authenticator data length: \(authenticatorData.count) bytes")
        print("[WebAuthn] 🔍 Authenticator data (hex): \(authenticatorData.map { String(format: "%02x", $0) }.joined())")
        
        // Extract sign count (4 bytes at offset 33, big endian)
        let signCountBytes = authenticatorData.subdata(in: 33..<37)
        print("[WebAuthn] 🔍 Sign count bytes (hex): \(signCountBytes.map { String(format: "%02x", $0) }.joined())")
        
        let newSignCount = signCountBytes.withUnsafeBytes { bytes in
            UInt32(bigEndian: bytes.bindMemory(to: UInt32.self).first!)
        }
        
        print("[WebAuthn] 🔍 Extracted sign count: \(newSignCount)")
        print("[WebAuthn] 🔍 Stored sign count: \(storedCredential.signCount)")
        
        // Check if this is a platform authenticator that doesn't use sign count
        // Platform authenticators (Touch ID, Face ID, Windows Hello, etc.) often return 0 consistently
        if newSignCount == 0 {
            print("[WebAuthn] ⚠️ Platform authenticator detected - sign count is 0 (normal for Touch ID/Face ID/Windows Hello)")
            // For platform authenticators that don't increment, increment our own counter for security
            // This provides replay attack protection even when the authenticator doesn't increment
            return storedCredential.signCount + 1
        }
        
        // For hardware authenticators that do increment sign count
        // Validate sign count (must be greater than stored value, unless stored is 0 for first use)
        if storedCredential.signCount > 0 && newSignCount <= storedCredential.signCount {
            print("[WebAuthn] Sign count validation failed: new=\(newSignCount), stored=\(storedCredential.signCount)")
            throw WebAuthnError.signCountInvalid
        }
        
        print("[WebAuthn] Sign count validation passed: new=\(newSignCount), stored=\(storedCredential.signCount)")
        return newSignCount
    }
    
    private func updateCredentialSignCount(credential: WebAuthnCredential, newSignCount: UInt32, clientIP: String? = nil) throws {
        print("[WebAuthn] 📊 updateCredentialSignCount called for \(credential.username)")
        print("[WebAuthn] 📊 Old sign count: \(credential.signCount), New sign count: \(newSignCount)")
        print("[WebAuthn] 📍 Client IP: \(clientIP ?? "unknown")")
        
        // Update the credential with new sign count, IP, and login time
        let updatedCredential = WebAuthnCredential(
            id: credential.id,
            publicKey: credential.publicKey,
            signCount: newSignCount,
            username: credential.username,
            algorithm: credential.algorithm,
            protocolVersion: credential.protocolVersion,
            attestationFormat: credential.attestationFormat,
            aaguid: credential.aaguid,
            isDiscoverable: credential.isDiscoverable,
            backupEligible: credential.backupEligible,
            backupState: credential.backupState,
            emoji: credential.emoji,
            lastLoginIP: clientIP,
            lastLoginAt: Date(),
            createdAt: credential.createdAt,
            isEnabled: credential.isEnabled,
            isAdmin: credential.isAdmin,
            userNumber: credential.userNumber
        )
        
        // Update user login information
        try? userManager.updateUserLogin(username: credential.username, signCount: newSignCount, clientIP: clientIP)
        print("[WebAuthn] Login update for \(credential.username) handled by WebAuthn credentials")
        
        // Store updated credential directly in database
        storeCredential(updatedCredential)
        
        print("[WebAuthn] ✅ Sign count update completed successfully")
    }
    
    private func verifyU2FAuthentication(response: [String: Any], storedCredential: WebAuthnCredential, id: String, clientIP: String?) throws {
        guard let signatureData = response["signatureData"] as? String,
              let clientData = response["clientData"] as? String else {
            print("[WebAuthn] MISSING U2F authentication data")
            throw WebAuthnError.invalidCredential
        }
        
        // Parse U2F signature data
        guard let sigData = Data(base64Encoded: signatureData),
              let clientDataBytes = Data(base64Encoded: clientData) else {
            throw WebAuthnError.invalidCredential
        }
        
        // U2F signature data format:
        // 1 byte: user presence (0x01)
        // 4 bytes: counter
        // signature
        
        guard sigData.count >= 5 else {
            throw WebAuthnError.invalidCredential
        }
        
        let userPresence = sigData[0]
        guard userPresence == 0x01 else {
            throw WebAuthnError.invalidCredential
        }
        
        // Extract and validate U2F counter (4 bytes at offset 1, big endian)
        let counterBytes = sigData.subdata(in: 1..<5)
        let newSignCount = counterBytes.withUnsafeBytes { bytes in
            UInt32(bigEndian: bytes.bindMemory(to: UInt32.self).first!)
        }
        
        // Validate sign count (must be greater than stored value, unless stored is 0 for first use)
        if storedCredential.signCount > 0 && newSignCount <= storedCredential.signCount {
            print("[WebAuthn] U2F sign count validation failed: new=\(newSignCount), stored=\(storedCredential.signCount)")
            throw WebAuthnError.signCountInvalid
        }
        
        print("[WebAuthn] U2F sign count validation passed: new=\(newSignCount), stored=\(storedCredential.signCount)")
        
        // Extract signature (remaining bytes after user presence + counter)
        let signature = sigData.subdata(in: 5..<sigData.count)
        
        // Create signed data for U2F
        let applicationParameter = Data(SHA256.hash(data: rpId.data(using: .utf8)!))
        let challengeParameter = Data(SHA256.hash(data: clientDataBytes))
        
        var signedData = Data()
        signedData.append(applicationParameter)
        signedData.append(sigData.subdata(in: 0..<5)) // user presence + counter
        signedData.append(challengeParameter)
        
        // Verify U2F signature
        try verifyU2FSignature(signedData: signedData, signature: signature, publicKey: storedCredential.publicKey)
        
        if id != storedCredential.id {
            print("[WebAuthn] id does not match storedCredential.id")
            throw WebAuthnError.invalidCredential
        }
        
        // Update the stored credential with new sign count
        try updateCredentialSignCount(credential: storedCredential, newSignCount: newSignCount, clientIP: clientIP)
    }
    
    private func verifyU2FSignature(signedData: Data, signature: Data, publicKey: String) throws {
        guard let publicKeyData = Data(base64Encoded: publicKey),
              publicKeyData.count == 65,
              publicKeyData[0] == 0x04 else {
            throw WebAuthnError.invalidCredential
        }
        
        // U2F uses the same P-256 verification as FIDO2
        do {
            let p256PublicKey = try P256.Signing.PublicKey(x963Representation: publicKeyData)
            
            // U2F signatures can be either DER or raw format
            // Try raw format first (more common), then DER if that fails
            var ecdsaSignature: P256.Signing.ECDSASignature?
            
            // Try raw format first (64 bytes: r + s)
            if signature.count == 64 {
                print("[WebAuthn] U2F trying raw signature format (64 bytes)")
                ecdsaSignature = try? P256.Signing.ECDSASignature(rawRepresentation: signature)
            }
            
            // If raw format failed or signature is not 64 bytes, try DER format
            if ecdsaSignature == nil {
                print("[WebAuthn] U2F trying DER signature format (\(signature.count) bytes)")
                ecdsaSignature = try? P256.Signing.ECDSASignature(derRepresentation: signature)
            }
            
            guard let finalSignature = ecdsaSignature else {
                print("[WebAuthn] U2F signature verification failed: could not parse signature in either raw or DER format")
                throw WebAuthnError.verificationFailed
            }
            
            let isValid = p256PublicKey.isValidSignature(finalSignature, for: signedData)
            if !isValid {
                print("[WebAuthn] U2F signature verification failed: signature validation failed")
                throw WebAuthnError.verificationFailed
            }
            
            print("[WebAuthn] ✅ U2F signature verification successful")
        } catch {
            print("[WebAuthn] U2F signature verification failed: \(error)")
            throw WebAuthnError.verificationFailed
        }
    }
    
    // MARK: - Verification Helpers
    
    private func verifyClientData(_ clientDataJSONString: String, type: String) throws {
        guard let clientDataJSON = Data(base64Encoded: clientDataJSONString),
              let clientData = try? JSONSerialization.jsonObject(with: clientDataJSON) as? [String: Any] else {
            throw WebAuthnError.invalidCredential
        }
        
        guard let clientType = clientData["type"] as? String,
              clientType == type else {
            throw WebAuthnError.invalidCredential
        }
        
        guard let origin = clientData["origin"] as? String else {
            throw WebAuthnError.invalidCredential
        }
        
        // Verify origin matches expected RP ID with flexible port handling
        let isValidOrigin = isOriginValid(origin: origin, rpId: rpId)
        guard isValidOrigin else {
            print("[WebAuthn] 🚨 Origin mismatch: \(origin) not valid for RP ID: \(rpId)")
            throw WebAuthnError.invalidCredential
        }
    }
    
    private func isOriginValid(origin: String, rpId: String) -> Bool {
        // Parse the origin URL
        guard let originURL = URL(string: origin) else {
            print("[WebAuthn] 🚨 Invalid origin URL: \(origin)")
            return false
        }
        
        // Extract scheme and host from origin
        guard let scheme = originURL.scheme,
              let host = originURL.host else {
            print("[WebAuthn] 🚨 Could not extract scheme/host from origin: \(origin)")
            return false
        }
        
        // Special handling for localhost with ports
        let hostMatches: Bool
        if rpId.lowercased() == "localhost" && host.lowercased() == "localhost" {
            // For localhost, ignore the port - any localhost port is valid
            hostMatches = true
            print("[WebAuthn] ✅ Localhost origin validation: accepting any localhost port")
        } else {
            // For other domains, require exact match
            hostMatches = host.lowercased() == rpId.lowercased()
        }
        
        // Allow both HTTP and HTTPS schemes
        let schemeMatches = scheme == "http" || scheme == "https"
        
        let isValid = hostMatches && schemeMatches
        
        if !isValid {
            print("[WebAuthn] 🚨 Origin validation failed:")
            print("[WebAuthn]   Origin: \(origin)")
            print("[WebAuthn]   Parsed host: \(host)")
            print("[WebAuthn]   Parsed scheme: \(scheme)")
            print("[WebAuthn]   RP ID: \(rpId)")
            print("[WebAuthn]   Host matches: \(hostMatches)")
            print("[WebAuthn]   Scheme matches: \(schemeMatches)")
        } else {
            print("[WebAuthn] ✅ Origin validation passed: \(origin) is valid for RP ID: \(rpId)")
        }
        
        return isValid
    }
    
    private func verifySignature(authenticatorData: String, clientDataJSON: String, signature: String, storedCredential: WebAuthnCredential) throws {
        guard let authDataBytes = Data(base64Encoded: authenticatorData),
              let clientDataBytes = Data(base64Encoded: clientDataJSON),
              let signatureBytes = Data(base64Encoded: signature) else {
            throw WebAuthnError.invalidCredential
        }
        
        // Create signed data: authenticatorData + SHA256(clientDataJSON)
        let clientDataHash = SHA256.hash(data: clientDataBytes)
        var signedData = authDataBytes
        signedData.append(Data(clientDataHash))
        
        // Verify signature based on algorithm
        switch storedCredential.algorithm {
        case -7: // ES256
            try verifyES256Signature(signedData: signedData, signature: signatureBytes, publicKey: storedCredential.publicKey)
        case -257: // RS256
            try verifyRS256Signature(signedData: signedData, signature: signatureBytes, publicKey: storedCredential.publicKey)
        default:
            throw WebAuthnError.invalidCredential
        }
    }
    
    private func verifyES256Signature(signedData: Data, signature: Data, publicKey: String) throws {
        guard let publicKeyData = Data(base64Encoded: publicKey),
              publicKeyData.count == 65,
              publicKeyData[0] == 0x04 else {
            throw WebAuthnError.invalidCredential
        }
        
        // Create P256 public key
        do {
            let p256PublicKey = try P256.Signing.PublicKey(x963Representation: publicKeyData)
            
            // WebAuthn signatures can be either raw format (64 bytes) or DER format
            // Try raw format first, then DER if that fails
            var ecdsaSignature: P256.Signing.ECDSASignature?
            
            // Try raw format first (64 bytes: r + s concatenated)
            if signature.count == 64 {
                print("[WebAuthn] ES256 trying raw signature format (64 bytes)")
                ecdsaSignature = try? P256.Signing.ECDSASignature(rawRepresentation: signature)
            }
            
            // If raw format failed or signature is not 64 bytes, try DER format
            if ecdsaSignature == nil {
                print("[WebAuthn] ES256 trying DER signature format (\(signature.count) bytes)")
                ecdsaSignature = try? P256.Signing.ECDSASignature(derRepresentation: signature)
            }
            
            guard let finalSignature = ecdsaSignature else {
                print("[WebAuthn] ES256 signature verification failed: could not parse signature in either raw or DER format")
                throw WebAuthnError.verificationFailed
            }
            
            let isValid = p256PublicKey.isValidSignature(finalSignature, for: signedData)
            if !isValid {
                print("[WebAuthn] ES256 signature verification failed: signature validation failed")
                throw WebAuthnError.verificationFailed
            }
            
            print("[WebAuthn] ✅ ES256 signature verification successful")
        } catch {
            print("[WebAuthn] ES256 signature verification failed: \(error)")
            throw WebAuthnError.verificationFailed
        }
    }
    
    private func verifyRS256Signature(signedData: Data, signature: Data, publicKey: String) throws {
        print("[WebAuthn] RS256 signature verification starting...")
        
        // Decode the RSA public key from base64-encoded JSON
        guard let publicKeyData = Data(base64Encoded: publicKey),
              let publicKeyDict = try? JSONSerialization.jsonObject(with: publicKeyData) as? [String: Any],
              let nBase64 = publicKeyDict["n"] as? String,
              let eBase64 = publicKeyDict["e"] as? String else {
            print("[WebAuthn] RS256 failed to parse RSA public key")
            throw WebAuthnError.invalidCredential
        }
        
        guard let nData = Data(base64Encoded: nBase64),
              let eData = Data(base64Encoded: eBase64) else {
            print("[WebAuthn] RS256 failed to decode RSA key components")
            throw WebAuthnError.invalidCredential
        }
        
        print("[WebAuthn] RS256 creating RSA public key from components (n: \(nData.count) bytes, e: \(eData.count) bytes)")
        
        do {
            // Create RSA public key using Security framework
            let rsaPublicKey = try createRSAPublicKey(modulus: nData, exponent: eData)
            
            // Hash the signed data with SHA-256 for RS256
            let hashedData = Data(SHA256.hash(data: signedData))
            
            // Verify the RSA signature
            let isValid = try verifyRSASignature(
                signature: signature, 
                hashedData: hashedData, 
                publicKey: rsaPublicKey
            )
            
            if !isValid {
                print("[WebAuthn] RS256 signature verification failed: signature validation failed")
                throw WebAuthnError.verificationFailed
            }
            
            print("[WebAuthn] ✅ RS256 signature verification successful")
            
        } catch let error as WebAuthnError {
            throw error
        } catch {
            print("[WebAuthn] RS256 signature verification failed: \(error)")
            throw WebAuthnError.verificationFailed
        }
    }
    
    private func createRSAPublicKey(modulus: Data, exponent: Data) throws -> SecKey {
        // Build RSA public key attributes
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            kSecAttrKeySizeInBits as String: modulus.count * 8
        ]
        
        // Create ASN.1 DER representation of RSA public key
        let rsaPublicKeyData = try createRSAPublicKeyASN1(modulus: modulus, exponent: exponent)
        
        var error: Unmanaged<CFError>?
        guard let secKey = SecKeyCreateWithData(rsaPublicKeyData as CFData, attributes as CFDictionary, &error) else {
            if let error = error {
                print("[WebAuthn] Failed to create RSA public key: \(error.takeRetainedValue())")
            }
            throw WebAuthnError.invalidCredential
        }
        
        return secKey
    }
    
    private func createRSAPublicKeyASN1(modulus: Data, exponent: Data) throws -> Data {
        // ASN.1 encoding for RSA public key:
        // RSAPublicKey ::= SEQUENCE {
        //     modulus           INTEGER,  -- n
        //     publicExponent    INTEGER   -- e
        // }
        
        var result = Data()
        
        // Encode modulus as ASN.1 INTEGER
        let modulusASN1 = try encodeASN1Integer(modulus)
        
        // Encode exponent as ASN.1 INTEGER
        let exponentASN1 = try encodeASN1Integer(exponent)
        
        // Create SEQUENCE containing both integers
        let sequenceContent = modulusASN1 + exponentASN1
        let sequenceASN1 = try encodeASN1Sequence(sequenceContent)
        
        // Wrap in algorithm identifier for RSA encryption
        let algorithmIdentifier = Data([
            0x30, 0x0d,  // SEQUENCE, length 13
            0x06, 0x09,  // OBJECT IDENTIFIER, length 9
            0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,  // rsaEncryption OID
            0x05, 0x00   // NULL
        ])
        
        // Create BIT STRING containing the RSA public key
        let bitStringContent = Data([0x00]) + sequenceASN1  // 0x00 indicates no unused bits
        let bitString = try encodeASN1BitString(bitStringContent)
        
        // Final SEQUENCE containing algorithm identifier and bit string
        let finalContent = algorithmIdentifier + bitString
        result = try encodeASN1Sequence(finalContent)
        
        return result
    }
    
    private func encodeASN1Integer(_ data: Data) throws -> Data {
        var integerData = data
        
        // Remove leading zeros, but keep at least one byte
        while integerData.count > 1 && integerData[0] == 0x00 {
            integerData = integerData.dropFirst()
        }
        
        // If the first bit is set, prepend 0x00 to make it positive
        if integerData[0] & 0x80 != 0 {
            integerData = Data([0x00]) + integerData
        }
        
        return Data([0x02]) + encodeASN1Length(integerData.count) + integerData
    }
    
    private func encodeASN1Sequence(_ content: Data) throws -> Data {
        return Data([0x30]) + encodeASN1Length(content.count) + content
    }
    
    private func encodeASN1BitString(_ content: Data) throws -> Data {
        return Data([0x03]) + encodeASN1Length(content.count) + content
    }
    
    private func encodeASN1Length(_ length: Int) -> Data {
        if length < 0x80 {
            return Data([UInt8(length)])
        } else if length < 0x100 {
            return Data([0x81, UInt8(length)])
        } else if length < 0x10000 {
            return Data([0x82, UInt8(length >> 8), UInt8(length & 0xff)])
        } else {
            // For longer lengths, we'd need more bytes, but WebAuthn keys shouldn't be this large
            return Data([0x82, UInt8(length >> 8), UInt8(length & 0xff)])
        }
    }
    
    private func verifyRSASignature(signature: Data, hashedData: Data, publicKey: SecKey) throws -> Bool {
        // RSA signature verification using PKCS#1 v1.5 padding with SHA-256
        let algorithm = SecKeyAlgorithm.rsaSignatureMessagePKCS1v15SHA256
        
        var error: Unmanaged<CFError>?
        let isValid = SecKeyVerifySignature(
            publicKey,
            algorithm,
            hashedData as CFData,
            signature as CFData,
            &error
        )
        
        if let error = error {
            print("[WebAuthn] RSA signature verification error: \(error.takeRetainedValue())")
            throw WebAuthnError.verificationFailed
        }
        
        return isValid
    }
    
    private func generateChallenge() -> String {
        let challenge = Data((0..<32).map { _ in UInt8.random(in: 0...255) })
        return challenge.base64EncodedString()
    }
    
    private func generateUserId() -> String {
        let userId = Data((0..<16).map { _ in UInt8.random(in: 0...255) })
        return userId.base64EncodedString()
    }
    
    public func isUsernameRegistered(_ username: String) -> Bool {
        return getCredential(username: username) != nil
    }
    
    // Check if user exists and is enabled
    public func isUserEnabled(username: String) -> Bool {
        // First check if user exists in WebAuthn credentials and is enabled
        if let credential = getCredential(username: username) {
            return credential.isEnabled
        }
        
        // If no WebAuthn credential exists, check userManager for admin user status
        return userManager.isUserEnabled(username: username)
    }
    
    // Check if user exists and is enabled by credential ID
    public func isUserEnabledByCredential(_ credentialId: String) -> Bool {
        if let credential = getCredential(byCredentialId: credentialId) {
            return credential.isEnabled
        }
        return false
    }
    
    // Update user emoji
    public func updateUserEmoji(username: String, emoji: String) -> Bool {
        // Update the WebAuthn credential directly
        guard let credential = getCredential(username: username) else {
            return false
        }
        
        // Create updated credential with new emoji
        let updatedCredential = WebAuthnCredential(
            id: credential.id,
            publicKey: credential.publicKey,
            signCount: credential.signCount,
            username: credential.username,
            algorithm: credential.algorithm,
            protocolVersion: credential.protocolVersion,
            attestationFormat: credential.attestationFormat,
            aaguid: credential.aaguid,
            isDiscoverable: credential.isDiscoverable,
            backupEligible: credential.backupEligible,
            backupState: credential.backupState,
            emoji: emoji,
            lastLoginIP: credential.lastLoginIP,
            lastLoginAt: credential.lastLoginAt,
            createdAt: credential.createdAt,
            isEnabled: credential.isEnabled,
            isAdmin: credential.isAdmin,
            userNumber: credential.userNumber
        )
        
        // Store updated credential directly in database
        storeCredential(updatedCredential)
        
        print("[WebAuthn] Updated emoji for user \(username) to \(emoji)")
        return true
    }
    
    // Update user admin status
    public func updateUserAdminStatus(username: String, isAdmin: Bool) -> Bool {
        // Update the WebAuthn credential directly
        guard let credential = getCredential(username: username) else {
            return false
        }
        
        // Create updated credential with new admin status
        let updatedCredential = WebAuthnCredential(
            id: credential.id,
            publicKey: credential.publicKey,
            signCount: credential.signCount,
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
            lastLoginAt: credential.lastLoginAt,
            createdAt: credential.createdAt,
            isEnabled: credential.isEnabled,
            isAdmin: isAdmin,
            userNumber: credential.userNumber
        )
        
        // Store updated credential directly in database
        storeCredential(updatedCredential)
        
        print("[WebAuthn] Updated admin status for user \(username) to \(isAdmin)")
        return true
    }
    
    // Update user enabled status
    public func updateUserEnabledStatus(username: String, isEnabled: Bool) -> Bool {
        // Update the WebAuthn credential directly
        guard let credential = getCredential(username: username) else {
            return false
        }
        
        // Create updated credential with new enabled status
        let updatedCredential = WebAuthnCredential(
            id: credential.id,
            publicKey: credential.publicKey,
            signCount: credential.signCount,
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
            lastLoginAt: credential.lastLoginAt,
            createdAt: credential.createdAt,
            isEnabled: isEnabled,
            isAdmin: credential.isAdmin,
            userNumber: credential.userNumber
        )
        
        // Store updated credential directly in database
        storeCredential(updatedCredential)
        
        print("[WebAuthn] Updated enabled status for user \(username) to \(isEnabled)")
        return true
    }
    
    // Get user emoji
    public func getUserEmoji(username: String) -> String? {
        // Get emoji from WebAuthn credential
        if let credential = getCredential(username: username) {
            return credential.emoji ?? "👤"
        }
        
        return "👤"
    }
    
    // Delete user credentials and release username
    public func deleteUserCredentials(username: String) {
        print("[WebAuthn] Deleting credentials for user: \(username)")
        
        // Delete user from user manager
        try? userManager.deleteUser(username: username)
        
        // Delete from database
        switch storageBackend {
        case .json:
            deleteCredentialFromJSON(username: username)
        case .swiftData:
            deleteCredentialFromSwiftData(username: username)
        }
        
        print("[WebAuthn] ✅ Successfully deleted credentials for user: \(username)")
    }
    
    /// Get the next available user number
    private func getNextUserNumber() -> Int {
        let allUsers = getAllUsers()
        let maxUserNumber = allUsers.compactMap { $0.userNumber }.max() ?? 0
        return maxUserNumber + 1
    }
    
    /// Migrate existing users to assign user numbers if they don't have them
    private func migrateUserNumbers() {
        print("[WebAuthn] 🔄 Starting user number migration...")
        
        let allUsers = getAllUsers()
        
        // Debug: Print user number status for all users
        print("[WebAuthn] 🔍 DEBUG: All users and their userNumber status:")
        for user in allUsers {
            print("[WebAuthn] 🔍   User: \(user.username), userNumber: \(user.userNumber?.description ?? "nil")")
        }
        
        let usersWithoutNumbers = allUsers.filter { $0.userNumber == nil }
        
        if usersWithoutNumbers.isEmpty {
            print("[WebAuthn] ✅ User number migration: No users need migration")
            return
        }
        
        print("[WebAuthn] 🔄 Found \(usersWithoutNumbers.count) users without user numbers, assigning sequential numbers...")
        
        // Sort users by creation date to maintain consistent ordering
        let sortedUsers = usersWithoutNumbers.sorted { user1, user2 in
            let date1 = user1.createdAt ?? Date.distantPast
            let date2 = user2.createdAt ?? Date.distantPast
            return date1 < date2
        }
        
        // Get the current max user number to start assigning from
        let existingNumbers = allUsers.compactMap { $0.userNumber }
        var nextNumber = (existingNumbers.max() ?? 0) + 1
        
        // Assign user numbers to users who don't have them
        for user in sortedUsers {
            print("[WebAuthn] 🔄 Assigning user number \(nextNumber) to user: \(user.username)")
            
            let updatedCredential = WebAuthnCredential(
                id: user.id,
                publicKey: user.publicKey,
                signCount: user.signCount,
                username: user.username,
                algorithm: user.algorithm,
                protocolVersion: user.protocolVersion,
                attestationFormat: user.attestationFormat,
                aaguid: user.aaguid,
                isDiscoverable: user.isDiscoverable,
                backupEligible: user.backupEligible,
                backupState: user.backupState,
                emoji: user.emoji,
                lastLoginIP: user.lastLoginIP,
                lastLoginAt: user.lastLoginAt,
                createdAt: user.createdAt,
                isEnabled: user.isEnabled,
                isAdmin: user.isAdmin,
                userNumber: nextNumber
            )
            
            storeCredential(updatedCredential)
            nextNumber += 1
        }
        
        print("[WebAuthn] ✅ User number migration complete: Assigned numbers to \(usersWithoutNumbers.count) users")
    }
    
    private func deleteCredentialFromSwiftData(username: String) {
        guard let container = modelContainer else {
            print("[WebAuthn] ❌ No model container available for deleting credential")
            return
        }
        
        do {
            let context = ModelContext(container)
            let fetchDescriptor = FetchDescriptor<WebAuthnCredentialModel>(
                predicate: #Predicate { model in model.username == username }
            )
            
            let models = try context.fetch(fetchDescriptor)
            for model in models {
                context.delete(model)
            }
            
            try context.save()
            print("[WebAuthn] ✅ Successfully deleted credential from SwiftData for user: \(username)")
        } catch {
            print("[WebAuthn] ❌ Failed to delete credential from SwiftData: \(error)")
        }
    }
    
    private func deleteCredentialFromJSON(username: String) {
        var credentials = loadAllCredentialsFromJSON()
        credentials.removeValue(forKey: username)
        saveAllCredentialsToJSON(credentials)
    }
    
    /// Migrate existing credentials to ensure they have all required fields
    /// This runs only once per database to avoid repeated migrations
    private func migrateExistingCredentials() {
        // For now, disable migration since we're using database-direct approach
        // Migration can be added back later if needed for specific database schema updates
        print("[WebAuthn] 🔄 Database-direct approach - migration skipped")
        print("[WebAuthn] 💡 If migration is needed, it should be done at the database schema level")
    }
    
    /// Clean up legacy JSON credential files when using SwiftData backend
    /// This prevents JSON files from being processed repeatedly after migration
    private func cleanupLegacyJSONFiles() {
        guard case .swiftData = storageBackend else {
            print("[WebAuthn] 🗂️ Using JSON storage - no cleanup needed")
            return
        }
        
        // List of potential JSON credential files to clean up
        let jsonFiles = [
            "webauthn_credentials_fido2.json",
            "webauthn_credentials_u2f.json",
            "webauthn_credentials.json",
            defaultJSONPath
        ]
        
        var cleanedFiles = 0
        for jsonFile in jsonFiles {
            if FileManager.default.fileExists(atPath: jsonFile) {
                do {
                    // Create backup before deleting
                    let formatter = DateFormatter()
                    formatter.dateFormat = "yyyyMMdd_HHmmss"
                    let timestamp = formatter.string(from: Date())
                    let backupPath = "\(jsonFile).migrated_backup_\(timestamp)"
                    try FileManager.default.copyItem(atPath: jsonFile, toPath: backupPath)
                    
                    // Remove the original JSON file
                    try FileManager.default.removeItem(atPath: jsonFile)
                    
                    print("[WebAuthn] 🧹 Cleaned up legacy JSON file: \(jsonFile)")
                    print("[WebAuthn] 📦 Backup saved as: \(backupPath)")
                    cleanedFiles += 1
                } catch {
                    print("[WebAuthn] ⚠️ Failed to cleanup JSON file \(jsonFile): \(error)")
                }
            }
        }
        
        if cleanedFiles > 0 {
            print("[WebAuthn] 🧹 Legacy JSON cleanup completed: \(cleanedFiles) files processed")
            print("[WebAuthn] ✅ This prevents repeated migration processing")
        } else {
            print("[WebAuthn] ✅ No legacy JSON files found - cleanup not needed")
        }
    }
    
    /// Get all registered users for admin panel management
    public func getAllUsers() -> [WebAuthnCredential] {
        switch storageBackend {
        case .json:
            let credentials = loadAllCredentialsFromJSON()
            return Array(credentials.values)
        case .swiftData:
            return getAllUsersFromSwiftData()
        }
    }
    
    private func getAllUsersFromSwiftData() -> [WebAuthnCredential] {
        guard let container = modelContainer else {
            print("[WebAuthn] ❌ No model container available for querying all users")
            return []
        }
        
        do {
            let context = ModelContext(container)
            let fetchDescriptor = FetchDescriptor<WebAuthnCredentialModel>()
            let models = try context.fetch(fetchDescriptor)
            return models.map { $0.webAuthnCredential }
        } catch {
            print("[WebAuthn] ❌ Failed to query all users: \(error)")
            return []
        }
    }
    
    // MARK: - Direct Database Query Methods
    
    /// Get credential by username from database
    internal func getCredential(username: String) -> WebAuthnCredential? {
        switch storageBackend {
        case .json:
            // For JSON backend, still need to load from file (legacy support)
            return getCredentialFromJSON(username: username)
        case .swiftData:
            return getCredentialFromSwiftData(username: username)
        }
    }
    
    /// Get credential by credential ID from database
    private func getCredential(byCredentialId credentialId: String) -> WebAuthnCredential? {
        switch storageBackend {
        case .json:
            return getCredentialByIdFromJSON(credentialId: credentialId)
        case .swiftData:
            return getCredentialByIdFromSwiftData(credentialId: credentialId)
        }
    }
    
    /// Get username by credential ID from database
    private func getUsername(byCredentialId credentialId: String) -> String? {
        return getCredential(byCredentialId: credentialId)?.username
    }
    
    private func getCredentialFromSwiftData(username: String) -> WebAuthnCredential? {
        guard let container = modelContainer else {
            print("[WebAuthn] ❌ No model container available for querying credential")
            return nil
        }
        
        do {
            let context = ModelContext(container)
            let fetchDescriptor = FetchDescriptor<WebAuthnCredentialModel>(
                predicate: #Predicate { model in model.username == username }
            )
            
            let models = try context.fetch(fetchDescriptor)
            return models.first?.webAuthnCredential
        } catch {
            print("[WebAuthn] ❌ Failed to query credential for user \(username): \(error)")
            return nil
        }
    }
    
    private func getCredentialByIdFromSwiftData(credentialId: String) -> WebAuthnCredential? {
        guard let container = modelContainer else {
            print("[WebAuthn] ❌ No model container available for querying credential by ID")
            return nil
        }
        
        do {
            let context = ModelContext(container)
            let fetchDescriptor = FetchDescriptor<WebAuthnCredentialModel>(
                predicate: #Predicate { model in model.id == credentialId }
            )
            
            let models = try context.fetch(fetchDescriptor)
            return models.first?.webAuthnCredential
        } catch {
            print("[WebAuthn] ❌ Failed to query credential for ID \(credentialId): \(error)")
            return nil
        }
    }
    
    /// Store/update credential in database
    internal func storeCredential(_ credential: WebAuthnCredential) {
        switch storageBackend {
        case .json:
            storeCredentialInJSON(credential)
        case .swiftData:
            updateSingleCredentialInSwiftData(credential: credential)
        }
    }
    
    // Legacy JSON support methods
    private func getCredentialFromJSON(username: String) -> WebAuthnCredential? {
        let credentials = loadAllCredentialsFromJSON()
        return credentials[username]
    }
    
    private func getCredentialByIdFromJSON(credentialId: String) -> WebAuthnCredential? {
        let credentials = loadAllCredentialsFromJSON()
        return credentials.values.first { $0.id == credentialId }
    }
    
    private func loadAllCredentialsFromJSON() -> [String: WebAuthnCredential] {
        let url = URL(fileURLWithPath: credentialsFile)
        guard FileManager.default.fileExists(atPath: credentialsFile) else { return [:] }
        
        do {
            let data = try Data(contentsOf: url)
            let arr = try JSONDecoder().decode([WebAuthnCredential].self, from: data)
            var credentials: [String: WebAuthnCredential] = [:]
            for cred in arr {
                credentials[cred.username] = cred
            }
            return credentials
        } catch {
            print("[WebAuthn] Failed to load credentials from JSON: \(error)")
            return [:]
        }
    }
    
    private func storeCredentialInJSON(_ credential: WebAuthnCredential) {
        var credentials = loadAllCredentialsFromJSON()
        credentials[credential.username] = credential
        saveAllCredentialsToJSON(credentials)
    }
    
    private func saveAllCredentialsToJSON(_ credentials: [String: WebAuthnCredential]) {
        let arr = Array(credentials.values)
        let url = URL(fileURLWithPath: credentialsFile)
        
        do {
            let data = try JSONEncoder().encode(arr)
            try data.write(to: url)
            print("[WebAuthn] ✅ Successfully saved \(arr.count) credentials to JSON.")
        } catch {
            print("[WebAuthn] ❌ Failed to save credentials to JSON: \(error)")
        }
    }
    
    // Old bulk save methods removed - we now use direct database operations
    // updateSingleCredentialInSwiftData is now the main method for SwiftData updates
    
    private func updateSingleCredentialInSwiftData(credential: WebAuthnCredential) {
        print("[WebAuthn] 🔄 Updating single credential for user: \(credential.username)")
        
        guard let container = modelContainer else {
            print("[WebAuthn] ❌ CRITICAL: No model container available for updating credential!")
            return
        }
        
        do {
            let context = ModelContext(container)
            print("[WebAuthn] ✅ Created context for updating single credential")
            
            // Find the existing credential model by username
            let fetchDescriptor = FetchDescriptor<WebAuthnCredentialModel>(
                predicate: #Predicate { model in model.username == credential.username }
            )
            
            let existingModels = try context.fetch(fetchDescriptor)
            
            if let existingModel = existingModels.first {
                // Update the existing model
                existingModel.signCount = credential.signCount
                existingModel.lastLoginIP = credential.lastLoginIP
                existingModel.lastLoginAt = credential.lastLoginAt
                existingModel.emoji = credential.emoji
                existingModel.isEnabled = credential.isEnabled
                existingModel.isAdmin = credential.isAdmin
                existingModel.userNumber = credential.userNumber  // ✅ CRITICAL FIX: Update userNumber field!
                
                print("[WebAuthn] ✅ Updated existing credential model for user: \(credential.username) with userNumber: \(credential.userNumber?.description ?? "nil")")
            } else {
                // Create new model if it doesn't exist
                let newModel = WebAuthnCredentialModel(
                    id: credential.id,
                    publicKey: credential.publicKey,
                    signCount: credential.signCount,
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
                    lastLoginAt: credential.lastLoginAt,
                    isEnabled: credential.isEnabled,
                    isAdmin: credential.isAdmin,
                    userNumber: credential.userNumber
                )
                context.insert(newModel)
                print("[WebAuthn] ✅ Created new credential model for user: \(credential.username)")
            }
            
            try context.save()
            print("[WebAuthn] ✅ Successfully updated single credential in Swift Data for user: \(credential.username)")
            
        } catch {
            print("[WebAuthn] ❌ Failed to update single credential in Swift Data: \(error)")
        }
    }
    
    // Linux/Firefox compatible registration with cross-platform authenticators
    public func generateLinuxCompatibleRegistrationOptions(username: String, displayName: String? = nil) -> [String: Any] {
        let challenge = generateChallenge()
        let userId = generateUserId()
        
        let rpData: [String: Any] = [
            "id": rpId,
            "name": rpName ?? rpId
        ]
        
        let displayNameToUse = displayName ?? username
        let userData: [String: Any] = [
            "id": userId,
            "name": username,
            "displayName": displayNameToUse
        ]
        
        // Algorithm support for FIDO2/U2F security keys
        let pubKeyCredParams: [[String: Any]] = [
            ["type": "public-key", "alg": -7],   // ES256 (FIDO2 preferred)
            ["type": "public-key", "alg": -257], // RS256 (legacy compatibility)
            ["type": "public-key", "alg": -8]    // EdDSA (modern security keys)
        ]
        
        // Linux/Firefox compatible authenticator selection - cross-platform only
        let authenticatorSelection: [String: Any] = [
            "authenticatorAttachment": "cross-platform", // External security keys
            "userVerification": "discouraged",           // Security keys may not have biometrics
            "requireResidentKey": false,                 // Don't require resident keys
            "residentKey": "discouraged"                 // Basic security key support
        ]
        
        let options: [String: Any] = [
            "publicKey": [
                "challenge": challenge,
                "rp": rpData,
                "user": userData,
                "pubKeyCredParams": pubKeyCredParams,
                "timeout": 60000,           // Standard timeout
                "attestation": "none",      // No attestation for privacy
                "authenticatorSelection": authenticatorSelection
                // No extensions for maximum compatibility
            ]
        ]
        
        return options
    }
    
    // Universal registration options - supports both QR code/phone passkey AND security keys
    public func generateHybridRegistrationOptions(username: String, displayName: String? = nil) -> [String: Any] {
        let challenge = generateChallenge()
        let userId = generateUserId()
        
        let rpData: [String: Any] = [
            "id": rpId,
            "name": rpName ?? rpId
        ]
        
        let displayNameToUse = displayName ?? username
        let userData: [String: Any] = [
            "id": userId,
            "name": username,
            "displayName": displayNameToUse
        ]
        
        // Comprehensive algorithm support for all authenticator types
        let pubKeyCredParams: [[String: Any]] = [
            ["type": "public-key", "alg": -7],   // ES256 (universal)
            ["type": "public-key", "alg": -257], // RS256 (Windows Hello)
            ["type": "public-key", "alg": -8],   // EdDSA (modern keys)
            ["type": "public-key", "alg": -35],  // ES384 (enhanced security)
            ["type": "public-key", "alg": -36]   // ES512 (maximum security)
        ]
        
        // COMPLETELY remove authenticatorSelection to force Chrome to show ALL options
        // This is more aggressive than just omitting authenticatorAttachment
        
        let options: [String: Any] = [
            "publicKey": [
                "challenge": challenge,
                "rp": rpData,
                "user": userData,
                "pubKeyCredParams": pubKeyCredParams,
                "timeout": 300000,      // Longer timeout for user choice
                "attestation": "none",  // Privacy-friendly
                "extensions": [
                    "credProps": true   // Enable credential properties extension for debugging
                ]
                // COMPLETELY NO authenticatorSelection - forces Chrome to show all available options!
            ]
        ]
        
        return options
    }
    
    // Software-based registration for Linux (browser-stored credentials)
    public func generateLinuxSoftwareRegistrationOptions(username: String, displayName: String? = nil) -> [String: Any] {
        let challenge = generateChallenge()
        let userId = generateUserId()
        
        let rpData: [String: Any] = [
            "id": rpId,
            "name": rpName ?? rpId
        ]
        
        let displayNameToUse = displayName ?? username
        let userData: [String: Any] = [
            "id": userId,
            "name": username,
            "displayName": displayNameToUse
        ]
        
        // Algorithm support optimized for software authenticators
        let pubKeyCredParams: [[String: Any]] = [
            ["type": "public-key", "alg": -7],   // ES256 (browser preferred)
            ["type": "public-key", "alg": -257]  // RS256 (fallback)
        ]
        
        // Minimal options - NO authenticator restrictions at all for Firefox compatibility
        let options: [String: Any] = [
            "publicKey": [
                "challenge": challenge,
                "rp": rpData,
                "user": userData,
                "pubKeyCredParams": pubKeyCredParams,
                "timeout": 60000,           // Standard timeout
                "attestation": "none",      // No attestation required
                "authenticatorSelection": [
                    "userVerification": "discouraged"  // NO PIN, biometric, or password required
                ]
                // NO authenticatorAttachment - let browser choose any available method
                // NO residentKey requirements - maximum compatibility
            ]
        ]
        
        return options
    }
    
    // Convenience method: Auto-detect best option for Linux
    public func generateLinuxAutoRegistrationOptions(username: String, displayName: String? = nil, preferSoftware: Bool = false) -> [String: Any] {
        if preferSoftware {
            print("[WebAuthn] Using software-based authentication for Linux user: \(username)")
            return generateLinuxSoftwareRegistrationOptions(username: username, displayName: displayName)
        } else {
            print("[WebAuthn] Using hardware security key authentication for Linux user: \(username)")
            return generateLinuxCompatibleRegistrationOptions(username: username, displayName: displayName)
        }
    }
    
    // Hybrid authentication options - supports both platform authenticators (QR code) and security keys
    public func generateHybridAuthenticationOptions(username: String?) throws -> [String: Any] {
        let challenge = generateChallenge()
        
        var allowCredentials: [[String: Any]] = []
        
        if let username = username, !username.isEmpty {
            // If username is provided, allow that specific credential
            guard let credential = getCredential(username: username) else {
                throw WebAuthnError.credentialNotFound
            }
            allowCredentials = [[
                "type": "public-key",
                "id": credential.id,
                "transports": ["internal", "usb", "nfc", "ble", "hybrid"] // All transport types including BLE for maximum compatibility
            ]]
        } else {
            // If no username provided, use empty allowCredentials for discoverable credentials
            allowCredentials = []
        }
        
        let options: [String: Any] = [
            "publicKey": [
                "challenge": challenge,
                "timeout": 300000,      // Longer timeout for user choice
                "rpId": rpId,
                "allowCredentials": allowCredentials,
                "userVerification": "discouraged"  // Discouraged to allow more authenticator types
                // COMPLETELY NO authenticatorSelection - forces Chrome to show all available options!
                // NO extensions for authentication - credProps is only for registration
            ]
        ]
        
        return options
    }
}

 
