// Copyright 2025 by FIDO3.ai
// Generated on: 2025-7-19
// All rights reserved.

import Foundation
import Network

// MARK: - HTTP Request/Response Types

public struct HTTPRequest {
    public let method: String
    public let path: String
    public let headers: [String: String]
    public let body: Data?
    public let clientIP: String?
    
    public init(method: String, path: String, headers: [String: String] = [:], body: Data? = nil, clientIP: String? = nil) {
        self.method = method
        self.path = path
        self.headers = headers
        self.body = body
        self.clientIP = clientIP
    }
}

public struct HTTPResponse {
    public let statusCode: Int
    public let headers: [String: String]
    public let body: Data?
    
    public init(statusCode: Int, headers: [String: String] = [:], body: Data? = nil) {
        self.statusCode = statusCode
        self.headers = headers
        self.body = body
    }
    
    public static func json(_ object: Any, statusCode: Int = 200) -> HTTPResponse {
        do {
            let data = try JSONSerialization.data(withJSONObject: object)
            return HTTPResponse(
                statusCode: statusCode,
                headers: ["Content-Type": "application/json"],
                body: data
            )
        } catch {
            return HTTPResponse.error("Invalid JSON", statusCode: 500)
        }
    }
    
    public static func success(_ message: String = "Success") -> HTTPResponse {
        return HTTPResponse.json(["success": true, "message": message])
    }
    
    public static func error(_ message: String, statusCode: Int = 400) -> HTTPResponse {
        return HTTPResponse.json(["success": false, "error": message], statusCode: statusCode)
    }
}

// MARK: - WebAuthn HTTP Server

public class WebAuthnServer {
    private let manager: WebAuthnManager
    
    public init(manager: WebAuthnManager) {
        self.manager = manager
    }
    
    // MARK: - Main Route Handler
    
    public func handleRequest(_ request: HTTPRequest) -> HTTPResponse {
        print("[WebAuthnServer] \(request.method) \(request.path)")
        
        switch (request.method, request.path) {
        case ("POST", "/webauthn/register/begin"):
            return handleRegisterBegin(request)
        case ("POST", "/webauthn/register/begin/linux"):
            return handleRegisterBeginLinux(request)
        case ("POST", "/webauthn/register/begin/linux-software"):
            return handleRegisterBeginLinuxSoftware(request)
        case ("POST", "/webauthn/register/begin/universal"):
            return handleRegisterBeginUniversal(request)
        case ("POST", "/webauthn/register/begin/hybrid"):
            return handleRegisterBeginHybrid(request)
        case ("POST", "/webauthn/register/complete"):
            return handleRegisterComplete(request)
        case ("POST", "/webauthn/authenticate/begin"):
            return handleAuthenticateBegin(request)
        case ("POST", "/webauthn/authenticate/begin/linux-software"):
            return handleAuthenticateBeginLinuxSoftware(request)
        case ("POST", "/webauthn/authenticate/begin/hybrid"):
            return handleAuthenticateBeginHybrid(request)
        case ("POST", "/webauthn/authenticate/complete"):
            return handleAuthenticateComplete(request)
        case ("POST", "/webauthn/username/check"):
            return handleUsernameCheck(request)
        default:
            return HTTPResponse.error("Not Found", statusCode: 404)
        }
    }
    
    // MARK: - Registration Routes
    
    private func handleRegisterBegin(_ request: HTTPRequest) -> HTTPResponse {
        guard let body = request.body,
              let json = try? JSONSerialization.jsonObject(with: body) as? [String: Any],
              let username = json["username"] as? String else {
            print("[WebAuthnServer] Registration begin: Invalid request body")
            return HTTPResponse.error("Invalid request body - username required")
        }
        
        // Check browser type and use compatible options
        let userAgent = request.headers["user-agent"] ?? ""
        let isChrome = userAgent.contains("Chrome"); // && !userAgent.contains("Edge") // Chrome but not Edge
        let isWindows11 = userAgent.contains("Windows NT 10.0")
        
        let options: [String: Any]
        if isChrome {
            print("[WebAuthnServer] Using Chrome-compatible registration options for: \(username)")
            options = manager.generateChromeCompatibleRegistrationOptions(username: username)
        } else if isWindows11 {
            print("[WebAuthnServer] Using Windows 11 compatible registration options for: \(username)")
            options = manager.generateWindows11CompatibleRegistrationOptions(username: username)
        } else {
            options = manager.generateRegistrationOptions(username: username)
        }
        
        print("[WebAuthnServer] Registration options generated for: \(username)")
        return HTTPResponse.json(options)
    }
    
    private func handleRegisterBeginLinux(_ request: HTTPRequest) -> HTTPResponse {
        guard let body = request.body,
              let json = try? JSONSerialization.jsonObject(with: body) as? [String: Any],
              let username = json["username"] as? String else {
            print("[WebAuthnServer] Linux registration begin: Invalid request body")
            return HTTPResponse.error("Invalid request body - username required")
        }
        
        print("[WebAuthnServer] Using Linux-compatible registration options for: \(username)")
        let options = manager.generateLinuxCompatibleRegistrationOptions(username: username)
        
        print("[WebAuthnServer] Linux registration options generated for: \(username)")
        return HTTPResponse.json(options)
    }
    
    private func handleRegisterBeginLinuxSoftware(_ request: HTTPRequest) -> HTTPResponse {
        guard let body = request.body,
              let json = try? JSONSerialization.jsonObject(with: body) as? [String: Any],
              let username = json["username"] as? String else {
            print("[WebAuthnServer] Linux software registration begin: Invalid request body")
            return HTTPResponse.error("Invalid request body - username required")
        }
        
        print("[WebAuthnServer] Using Linux software-based registration options for: \(username)")
        let options = manager.generateLinuxSoftwareRegistrationOptions(username: username)
        
        print("[WebAuthnServer] Linux software registration options generated for: \(username)")
        return HTTPResponse.json(options)
    }
    
    private func handleRegisterBeginUniversal(_ request: HTTPRequest) -> HTTPResponse {
        guard let body = request.body,
              let json = try? JSONSerialization.jsonObject(with: body) as? [String: Any],
              let username = json["username"] as? String else {
            print("[WebAuthnServer] Universal registration begin: Invalid request body")
            return HTTPResponse.error("Invalid request body - username required")
        }
        
        print("[WebAuthnServer] Using hybrid registration options for: \(username)")
        let options = manager.generateHybridRegistrationOptions(username: username)
        
        print("[WebAuthnServer] Hybrid registration options generated for: \(username)")
        return HTTPResponse.json(options)
    }
    
    private func handleRegisterBeginHybrid(_ request: HTTPRequest) -> HTTPResponse {
        guard let body = request.body,
              let json = try? JSONSerialization.jsonObject(with: body) as? [String: Any],
              let username = json["username"] as? String else {
            print("[WebAuthnServer] Hybrid registration begin: Invalid request body")
            return HTTPResponse.error("Invalid request body - username required")
        }
        
        print("[WebAuthnServer] Using hybrid registration options for: \(username)")
        let options = manager.generateHybridRegistrationOptions(username: username)
        
        print("[WebAuthnServer] Hybrid registration options generated for: \(username)")
        return HTTPResponse.json(options)
    }
    
    private func handleRegisterComplete(_ request: HTTPRequest) -> HTTPResponse {
        guard let body = request.body,
              let json = try? JSONSerialization.jsonObject(with: body) as? [String: Any],
              let username = json["username"] as? String else {
            print("[WebAuthnServer] Registration complete: Invalid request body")
            return HTTPResponse.error("Invalid request body - username required")
        }
        
        do {
            try manager.verifyRegistration(username: username, credential: json, clientIP: request.clientIP)
            print("[WebAuthnServer] Registration completed successfully for: \(username)")
            return HTTPResponse.success("Registration successful")
        } catch {
            print("[WebAuthnServer] Registration verification failed: \(error)")
            return HTTPResponse.error("Registration verification failed: \(error.localizedDescription)")
        }
    }
    
    // MARK: - Authentication Routes
    
    private func handleAuthenticateBegin(_ request: HTTPRequest) -> HTTPResponse {
        guard let body = request.body,
              let json = try? JSONSerialization.jsonObject(with: body) as? [String: Any] else {
            print("[WebAuthnServer] Authentication begin: Invalid request body")
            return HTTPResponse.error("Invalid request body")
        }
        
        let username = json["username"] as? String // Optional for usernameless flow
        let securityKeyOnly = json["securityKeyOnly"] as? Bool ?? false
        
        do {
            let options: [String: Any]
            if securityKeyOnly {
                // Generate security key specific authentication options
                options = try manager.generateSecurityKeyAuthenticationOptions(username: username)
                print("[WebAuthnServer] Security key authentication options generated for: \(username ?? "usernameless")")
            } else {
                options = try manager.generateAuthenticationOptions(username: username)
                print("[WebAuthnServer] Standard authentication options generated for: \(username ?? "usernameless")")
            }
            return HTTPResponse.json(options)
        } catch {
            print("[WebAuthnServer] Authentication begin failed: \(error)")
            return HTTPResponse.error("Failed to generate authentication options: \(error.localizedDescription)")
        }
    }
    
    private func handleAuthenticateBeginLinuxSoftware(_ request: HTTPRequest) -> HTTPResponse {
        guard let body = request.body,
              let json = try? JSONSerialization.jsonObject(with: body) as? [String: Any] else {
            print("[WebAuthnServer] Firefox Linux authentication begin: Invalid request body")
            return HTTPResponse.error("Invalid request body")
        }
        
        let username = json["username"] as? String // Optional for usernameless flow
        
        do {
            let options = try manager.generateLinuxSoftwareAuthenticationOptions(username: username)
            print("[WebAuthnServer] Firefox Linux authentication options generated for: \(username ?? "usernameless")")
            return HTTPResponse.json(options)
        } catch {
            print("[WebAuthnServer] Firefox Linux authentication begin failed: \(error)")
            return HTTPResponse.error("Failed to generate authentication options: \(error.localizedDescription)")
        }
    }
    
    private func handleAuthenticateBeginHybrid(_ request: HTTPRequest) -> HTTPResponse {
        guard let body = request.body,
              let json = try? JSONSerialization.jsonObject(with: body) as? [String: Any] else {
            print("[WebAuthnServer] Hybrid authentication begin: Invalid request body")
            return HTTPResponse.error("Invalid request body")
        }
        
        let username = json["username"] as? String // Optional for usernameless flow
        
        do {
            let options = try manager.generateHybridAuthenticationOptions(username: username)
            print("[WebAuthnServer] Hybrid authentication options generated for: \(username ?? "usernameless")")
            return HTTPResponse.json(options)
        } catch {
            print("[WebAuthnServer] Hybrid authentication begin failed: \(error)")
            return HTTPResponse.error("Failed to generate authentication options: \(error.localizedDescription)")
        }
    }
    
    private func handleAuthenticateComplete(_ request: HTTPRequest) -> HTTPResponse {
        guard let body = request.body,
              let json = try? JSONSerialization.jsonObject(with: body) as? [String: Any] else {
            print("[WebAuthnServer] Authentication complete: Invalid request body")
            return HTTPResponse.error("Invalid request body")
        }
        
        let username = json["username"] as? String // Optional for usernameless flow
        
        do {
            let foundUsername = try manager.verifyAuthentication(username: username, credential: json, clientIP: request.clientIP)
            print("[WebAuthnServer] Authentication completed successfully for: \(foundUsername ?? username ?? "usernameless")")
            
            let response: [String: Any] = [
                "success": true,
                "username": foundUsername ?? username ?? ""
            ]
            return HTTPResponse.json(response)
        } catch {
            print("[WebAuthnServer] Authentication verification failed: \(error)")
            return HTTPResponse.error("\(error.localizedDescription)")
        }
    }
    
    // MARK: - Utility Routes
    
    private func handleUsernameCheck(_ request: HTTPRequest) -> HTTPResponse {
        guard let body = request.body,
              let json = try? JSONSerialization.jsonObject(with: body) as? [String: Any],
              let username = json["username"] as? String else {
            print("[WebAuthnServer] Username check: Invalid request body")
            return HTTPResponse.error("Invalid request body - username required")
        }
        
        let isRegistered = manager.isUsernameRegistered(username)
        var response: [String: Any] = [
            "available": !isRegistered,
            "username": username
        ]
        
        if isRegistered {
            response["error"] = "Username already registered"
        }
        
        print("[WebAuthnServer] Username check for '\(username)': \(isRegistered ? "taken" : "available")")
        return HTTPResponse.json(response)
    }
}

// MARK: - Integration Helpers

extension WebAuthnServer {
    
    // Helper for parsing raw HTTP requests
    public static func parseHTTPRequest(_ rawRequest: String, connection: NWConnection? = nil) -> HTTPRequest? {
        let lines = rawRequest.components(separatedBy: "\r\n")
        guard let requestLine = lines.first else { return nil }
        
        let requestParts = requestLine.components(separatedBy: " ")
        guard requestParts.count >= 2 else { return nil }
        
        let method = requestParts[0]
        let path = requestParts[1]
        
        var headers: [String: String] = [:]
        var bodyStart = -1
        
        for (index, line) in lines.enumerated() {
            if line.isEmpty {
                bodyStart = index + 1
                break
            }
            
            if let colonRange = line.range(of: ":") {
                let key = String(line[..<colonRange.lowerBound]).trimmingCharacters(in: .whitespaces)
                let value = String(line[colonRange.upperBound...]).trimmingCharacters(in: .whitespaces)
                headers[key.lowercased()] = value
            }
        }
        
        var body: Data? = nil
        if bodyStart >= 0 && bodyStart < lines.count {
            let bodyLines = Array(lines[bodyStart...])
            let bodyString = bodyLines.joined(separator: "\r\n")
            body = bodyString.data(using: .utf8)
        }
        
        // Extract client IP from connection or headers
        let clientIP = extractClientIP(from: headers, connection: connection)
        
        return HTTPRequest(method: method, path: path, headers: headers, body: body, clientIP: clientIP)
    }
    
    // Helper for extracting client IP
    private static func extractClientIP(from headers: [String: String], connection: NWConnection?) -> String? {
        // Try X-Forwarded-For header first
        if let forwardedFor = headers["x-forwarded-for"] {
            return forwardedFor.components(separatedBy: ",").first?.trimmingCharacters(in: .whitespaces)
        }
        
        // Try X-Real-IP header
        if let realIP = headers["x-real-ip"] {
            return realIP.trimmingCharacters(in: .whitespaces)
        }
        
        // Try to get from connection
        if let connection = connection {
            switch connection.endpoint {
            case .hostPort(let host, _):
                return "\(host)"
            default:
                break
            }
        }
        
        return nil
    }
    
    // Helper for generating HTTP response string
    public static func formatHTTPResponse(_ response: HTTPResponse) -> String {
        let statusText: String
        switch response.statusCode {
        case 200: statusText = "OK"
        case 400: statusText = "Bad Request"
        case 404: statusText = "Not Found"
        case 500: statusText = "Internal Server Error"
        default: statusText = "Unknown"
        }
        
        var httpResponse = "HTTP/1.1 \(response.statusCode) \(statusText)\r\n"
        
        // Add headers
        for (key, value) in response.headers {
            httpResponse += "\(key): \(value)\r\n"
        }
        
        // Add Content-Length if body exists
        if let body = response.body {
            httpResponse += "Content-Length: \(body.count)\r\n"
        }
        
        // Add CORS headers for browser compatibility
        httpResponse += "Access-Control-Allow-Origin: *\r\n"
        httpResponse += "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n"
        httpResponse += "Access-Control-Allow-Headers: Content-Type, Authorization\r\n"
        
        httpResponse += "\r\n"
        
        // Add body if exists
        if let body = response.body, let bodyString = String(data: body, encoding: .utf8) {
            httpResponse += bodyString
        }
        
        return httpResponse
    }
}

// MARK: - Framework Integration Extensions

#if canImport(Vapor)
import Vapor

extension WebAuthnServer {
    public func addVaporRoutes(to app: Application) {
        app.post("webauthn", "register", "begin") { req -> Response in
            let httpRequest = try self.vaporRequestToHTTPRequest(req)
            let httpResponse = self.handleRequest(httpRequest)
            return self.httpResponseToVaporResponse(httpResponse)
        }
        
        app.post("webauthn", "register", "begin", "linux") { req -> Response in
            let httpRequest = try self.vaporRequestToHTTPRequest(req)
            let httpResponse = self.handleRequest(httpRequest)
            return self.httpResponseToVaporResponse(httpResponse)
        }
        
        app.post("webauthn", "register", "begin", "linux-software") { req -> Response in
            let httpRequest = try self.vaporRequestToHTTPRequest(req)
            let httpResponse = self.handleRequest(httpRequest)
            return self.httpResponseToVaporResponse(httpResponse)
        }
        
        app.post("webauthn", "register", "begin", "universal") { req -> Response in
            let httpRequest = try self.vaporRequestToHTTPRequest(req)
            let httpResponse = self.handleRequest(httpRequest)
            return self.httpResponseToVaporResponse(httpResponse)
        }
        
        app.post("webauthn", "register", "begin", "hybrid") { req -> Response in
            let httpRequest = try self.vaporRequestToHTTPRequest(req)
            let httpResponse = self.handleRequest(httpRequest)
            return self.httpResponseToVaporResponse(httpResponse)
        }
        
        app.post("webauthn", "register", "complete") { req -> Response in
            let httpRequest = try self.vaporRequestToHTTPRequest(req)
            let httpResponse = self.handleRequest(httpRequest)
            return self.httpResponseToVaporResponse(httpResponse)
        }
        
        app.post("webauthn", "authenticate", "begin") { req -> Response in
            let httpRequest = try self.vaporRequestToHTTPRequest(req)
            let httpResponse = self.handleRequest(httpRequest)
            return self.httpResponseToVaporResponse(httpResponse)
        }
        
        app.post("webauthn", "authenticate", "begin", "linux-software") { req -> Response in
            let httpRequest = try self.vaporRequestToHTTPRequest(req)
            let httpResponse = self.handleRequest(httpRequest)
            return self.httpResponseToVaporResponse(httpResponse)
        }
        
        app.post("webauthn", "authenticate", "begin", "hybrid") { req -> Response in
            let httpRequest = try self.vaporRequestToHTTPRequest(req)
            let httpResponse = self.handleRequest(httpRequest)
            return self.httpResponseToVaporResponse(httpResponse)
        }
        
        app.post("webauthn", "authenticate", "complete") { req -> Response in
            let httpRequest = try self.vaporRequestToHTTPRequest(req)
            let httpResponse = self.handleRequest(httpRequest)
            return self.httpResponseToVaporResponse(httpResponse)
        }
        
        app.post("webauthn", "username", "check") { req -> Response in
            let httpRequest = try self.vaporRequestToHTTPRequest(req)
            let httpResponse = self.handleRequest(httpRequest)
            return self.httpResponseToVaporResponse(httpResponse)
        }
    }
    
    private func vaporRequestToHTTPRequest(_ req: Request) throws -> HTTPRequest {
        let body = req.body.data
        let headers = req.headers.reduce(into: [String: String]()) { result, header in
            result[header.name] = header.value
        }
        
        return HTTPRequest(
            method: req.method.string,
            path: req.url.path,
            headers: headers,
            body: body,
            clientIP: req.remoteAddress?.description
        )
    }
    
    private func httpResponseToVaporResponse(_ httpResponse: HTTPResponse) -> Response {
        let response = Response(status: HTTPResponseStatus(statusCode: httpResponse.statusCode))
        
        for (key, value) in httpResponse.headers {
            response.headers.add(name: key, value: value)
        }
        
        if let body = httpResponse.body {
            response.body = .init(data: body)
        }
        
        return response
    }
}
#endif

// MARK: - Generic Router Protocol

public protocol WebAuthnRouter {
    func addRoute(method: String, path: String, handler: @escaping (HTTPRequest) -> HTTPResponse)
}

extension WebAuthnServer {
    public func addRoutes<T: WebAuthnRouter>(to router: T) {
        router.addRoute(method: "POST", path: "/webauthn/register/begin") { request in
            return self.handleRequest(request)
        }
        
        router.addRoute(method: "POST", path: "/webauthn/register/begin/linux") { request in
            return self.handleRequest(request)
        }
        
        router.addRoute(method: "POST", path: "/webauthn/register/begin/linux-software") { request in
            return self.handleRequest(request)
        }
        
        router.addRoute(method: "POST", path: "/webauthn/register/begin/universal") { request in
            return self.handleRequest(request)
        }
        
        router.addRoute(method: "POST", path: "/webauthn/register/begin/hybrid") { request in
            return self.handleRequest(request)
        }
        
        router.addRoute(method: "POST", path: "/webauthn/register/complete") { request in
            return self.handleRequest(request)
        }
        
        router.addRoute(method: "POST", path: "/webauthn/authenticate/begin") { request in
            return self.handleRequest(request)
        }
        
        router.addRoute(method: "POST", path: "/webauthn/authenticate/begin/linux-software") { request in
            return self.handleRequest(request)
        }
        
        router.addRoute(method: "POST", path: "/webauthn/authenticate/begin/hybrid") { request in
            return self.handleRequest(request)
        }
        
        router.addRoute(method: "POST", path: "/webauthn/authenticate/complete") { request in
            return self.handleRequest(request)
        }
        
        router.addRoute(method: "POST", path: "/webauthn/username/check") { request in
            return self.handleRequest(request)
        }
    }
} 
