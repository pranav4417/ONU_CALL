//
//  Registration.swift
//  ONU CALL - registers this phone with the JioFiber router (OTP flow).
//
import Foundation
import Network

struct HTTPResult {
    var status = 0
    var headers: [String: [String]] = [:]
    var body = ""
    func header(_ k: String) -> String? { headers[k.lowercased()]?.first }
}

/// Minimal HTTPS GET to the router (port 8443, self-signed certificate).
final class RouterHTTP {
    private let conn: NWConnection
    private let q = DispatchQueue(label: "onu.http")
    private let request: String
    private var completion: ((Result<HTTPResult, Error>) -> Void)?
    private var buf = [UInt8]()
    private var done = false
    private var selfRef: RouterHTTP?

    static func get(router: String, pathAndQuery: String, headers: [String] = [],
                    completion: @escaping (Result<HTTPResult, Error>) -> Void) {
        RouterHTTP(router: router, pathAndQuery: pathAndQuery, headers: headers,
                   completion: completion).start()
    }

    private init(router: String, pathAndQuery: String, headers: [String],
                 completion: @escaping (Result<HTTPResult, Error>) -> Void) {
        conn = makeTLSConnection(host: router, port: 8443)
        let lines = ["GET \(pathAndQuery) HTTP/1.0", "Host: \(router):8443",
                     "Connection: close"] + headers
        request = lines.joined(separator: "\r\n") + "\r\n\r\n"
        self.completion = completion
    }

    private func start() {
        selfRef = self
        conn.stateUpdateHandler = { [weak self] st in
            guard let self = self else { return }
            switch st {
            case .ready:
                self.conn.send(content: Data(self.request.utf8), completion: .contentProcessed({ _ in }))
                self.readMore()
            case .failed(let e): self.finish(.failure(e))
            default: break      // .waiting covers the Local Network permission prompt
            }
        }
        conn.start(queue: q)
        q.asyncAfter(deadline: .now() + 20) { [weak self] in
            self?.finish(.failure(NSError(domain: "onu", code: -1, userInfo: [
                NSLocalizedDescriptionKey: "The router did not answer."])))
        }
    }

    private func readMore() {
        conn.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak self] data, _, isComplete, error in
            guard let self = self else { return }
            if let d = data, !d.isEmpty { self.buf.append(contentsOf: d) }
            if isComplete || error != nil { self.parse(); return }
            self.readMore()
        }
    }

    private func parse() {
        let text = String(decoding: buf, as: UTF8.self)
        guard let r = text.range(of: "\r\n\r\n") else {
            finish(.failure(NSError(domain: "onu", code: -2, userInfo: [
                NSLocalizedDescriptionKey: "Empty reply from the router."])))
            return
        }
        var res = HTTPResult()
        res.body = String(text[r.upperBound...])
        let lines = String(text[..<r.lowerBound]).components(separatedBy: "\r\n")
        let first = lines.first ?? ""
        res.status = Int(first.split(separator: " ").dropFirst().first ?? "") ?? 0
        for ln in lines.dropFirst() {
            if let i = ln.firstIndex(of: ":") {
                let k = ln[..<i].trimmingCharacters(in: .whitespaces).lowercased()
                let v = ln[ln.index(after: i)...].trimmingCharacters(in: .whitespaces)
                res.headers[k, default: []].append(v)
            }
        }
        finish(.success(res))
    }

    private func finish(_ r: Result<HTTPResult, Error>) {
        if done { return }
        done = true
        conn.cancel()
        let c = completion
        completion = nil
        selfRef = nil
        c?(r)
    }
}

// MARK: - Registration

enum CheckResult {
    case registered(line: String)
    case unregistered
    case failed(String)
}

struct OTPTicket {
    var masked: String
    var cookie: String
}

func parseParmValues(_ text: String) -> [String: String] {
    var vals = [String: String]()
    for tag in regexMatches("<parm\\b[^>]*>", in: text) {
        guard let t = tag.first else { continue }
        let n = regexMatches("\\sname\\s*=\\s*[\"']([^\"']*)[\"']", in: t).first?[1]
        let v = regexMatches("\\svalue\\s*=\\s*[\"']([^\"']*)[\"']", in: t).first?[1]
        if let n = n, let v = v { vals[n] = v }
    }
    return vals
}

enum Registrar {
    static func params(device: String) -> [(String, String)] {
        let mac = jfcMac(device)
        return [
            ("terminal_sw_version", "RCSAndrd"), ("terminal_vendor", device),
            ("terminal_model", device), ("SMS_port", "0"), ("act_type", "volatile"),
            ("IMSI", ""), ("msisdn", ""), ("IMEI", ""), ("vers", "0"), ("token", ""),
            ("rcs_state", "0"), ("rcs_version", "5.1B"), ("rcs_profile", "joyn_blackbird"),
            ("client_vendor", "JUIC"), ("default_sms_app", "2"), ("default_vvm_app", "0"),
            ("device_type", "vvm"), ("client_version", "JSEAndrd-1.0"),
            ("mac_address", mac), ("alias", device), ("nwk_intf", "wifi")]
    }

    static func encodedQuery(_ p: [(String, String)]) -> String {
        let ok = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~")
        return p.map { $0.0 + "=" + ($0.1.addingPercentEncoding(withAllowedCharacters: ok) ?? $0.1) }
            .joined(separator: "&")
    }

    /// Is this phone registered? Also returns the line's phone number.
    static func check(router: String, device: String, completion: @escaping (CheckResult) -> Void) {
        let path = "/?" + encodedQuery(params(device: device))
        RouterHTTP.get(router: router, pathAndQuery: path) { result in
            switch result {
            case .failure(let e):
                completion(.failed(e.localizedDescription))
            case .success(let r):
                if r.status == 200 {
                    let v = parseParmValues(r.body)
                    if let u = v["username"], v["userpwd"] != nil {
                        completion(.registered(line: "+" + (u.components(separatedBy: "@").first ?? u)))
                    } else {
                        completion(.unregistered)
                    }
                } else if r.status == 407 {
                    completion(.unregistered)
                } else {
                    completion(.failed("The router replied with status \(r.status)."))
                }
            }
        }
    }

    /// Ask the router to send an OTP to the mobile number linked to the line.
    static func sendOTP(router: String, device: String,
                        completion: @escaping (Result<OTPTicket, Error>) -> Void) {
        let raw = (params(device: device) + [("op_type", "add")])
            .map { "\($0.0)=\($0.1)" }.joined(separator: "&") + "&"
        RouterHTTP.get(router: router, pathAndQuery: "/?" + raw) { result in
            switch result {
            case .failure(let e):
                completion(.failure(e))
            case .success(let r):
                let cookie = (r.headers["set-cookie"] ?? [])
                    .compactMap { $0.components(separatedBy: ";").first?.trimmingCharacters(in: .whitespaces) }
                    .joined(separator: "; ")
                if cookie.isEmpty {
                    completion(.failure(NSError(domain: "onu", code: r.status, userInfo: [
                        NSLocalizedDescriptionKey: "The router did not start an OTP session (status \(r.status)). Make sure you're on JioFiber Wi-Fi."])))
                    return
                }
                completion(.success(OTPTicket(masked: r.header("x-amn") ?? "", cookie: cookie)))
            }
        }
    }

    /// Submit the OTP. Retries once without leading zeros in case the router expects a number.
    static func verify(router: String, otp: String, cookie: String,
                       completion: @escaping (Bool) -> Void) {
        func attempt(_ code: String, retry: String?) {
            RouterHTTP.get(router: router, pathAndQuery: "/?OTP=\(code)",
                           headers: ["Cookie: \(cookie)"]) { result in
                if case .success(let r) = result, (200..<300).contains(r.status) {
                    completion(true)
                } else if let again = retry {
                    attempt(again, retry: nil)
                } else {
                    completion(false)
                }
            }
        }
        let stripped = String(otp.drop(while: { $0 == "0" }))
        attempt(otp, retry: (otp.hasPrefix("0") && !stripped.isEmpty) ? stripped : nil)
    }
}
