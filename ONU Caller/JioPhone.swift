//
//  JioPhone.swift
//  ONU CALL - call engine (registration, signalling, media).
//
import Foundation
import Network
import CryptoKit
import Darwin
import AVFoundation

// MARK: - Small helpers

func md5hex(_ s: String) -> String {
    Insecure.MD5.hash(data: Data(s.utf8)).map { String(format: "%02x", $0) }.joined()
}

func randHex(_ n: Int) -> String {
    String(UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased().prefix(n))
}

func newBranch() -> String { "z9hG4bK" + randHex(12) }

/// Same hostname -> MAC logic as jfc_configure.py
func jfcMac(_ hostname: String) -> String {
    var h: UInt32 = 0
    for b in hostname.utf8 { h = h &* 33 &+ UInt32(b) }
    let chars = Array(String(format: "%08X", h))
    var pairs = [String]()
    var i = 0
    while i + 1 < chars.count { pairs.append(String(chars[i...(i + 1)])); i += 2 }
    var s = pairs.reversed().joined().lowercased()
    if s.count < 12 { s = String(repeating: "0", count: 12 - s.count) + s }
    let c = Array(s)
    var out = [String]()
    i = 0
    while i + 1 < 12 { out.append(String(c[i...(i + 1)])); i += 2 }
    return out.joined(separator: ":")
}

func normNumber(_ s: String) -> String {
    var d = s.filter { $0.isNumber }
    if d.count == 12 && d.hasPrefix("91") { d = String(d.dropFirst(2)) }
    if !d.hasPrefix("0") { d = "0" + d }
    return d
}

func regexMatches(_ pattern: String, in s: String) -> [[String]] {
    guard let re = try? NSRegularExpression(pattern: pattern) else { return [] }
    let ns = s as NSString
    return re.matches(in: s, range: NSRange(location: 0, length: ns.length)).map { m in
        (0..<m.numberOfRanges).map { i in
            m.range(at: i).location == NSNotFound ? "" : ns.substring(with: m.range(at: i))
        }
    }
}

// MARK: - SIP message

struct SipMsg {
    let raw: String
    var start = ""
    var headers: [String: [String]] = [:]
    var body = ""
    var isResponse = false
    var code = 0
    var reason = ""
    var method = ""

    init(raw text: String) {
        raw = text
        var head = text
        if let r = text.range(of: "\r\n\r\n") {
            head = String(text[..<r.lowerBound])
            body = String(text[r.upperBound...])
        }
        let lines = head.components(separatedBy: "\r\n")
        start = lines.first ?? ""
        for ln in lines.dropFirst() {
            if let idx = ln.firstIndex(of: ":") {
                let k = ln[..<idx].trimmingCharacters(in: .whitespaces).lowercased()
                let v = ln[ln.index(after: idx)...].trimmingCharacters(in: .whitespaces)
                headers[k, default: []].append(v)
            }
        }
        isResponse = start.hasPrefix("SIP/2.0")
        if isResponse {
            let p = start.split(separator: " ", maxSplits: 2).map(String.init)
            code = p.count > 1 ? (Int(p[1]) ?? 0) : 0
            reason = p.count > 2 ? p[2] : ""
        } else {
            method = start.split(separator: " ").first.map(String.init) ?? ""
        }
    }

    func get(_ k: String) -> String? { headers[k.lowercased()]?.first }
    func all(_ k: String) -> [String] { headers[k.lowercased()] ?? [] }

    var cseq: (Int, String)? {
        guard let v = get("cseq") else { return nil }
        let p = v.split(separator: " ").map(String.init)
        guard p.count >= 2, let n = Int(p[0]) else { return nil }
        return (n, p[1])
    }
}

// MARK: - Digest auth

func parseAuth(_ s: String) -> [String: String] {
    var out = [String: String]()
    for m in regexMatches("(\\w+)=\"?([^\",]+)\"?", in: s) where m.count >= 3 {
        out[m[1].lowercased()] = m[2]
    }
    return out
}

func digestHeader(_ name: String, authid: String, password: String,
                  method: String, uri: String, challenge: String) -> String? {
    let p = parseAuth(challenge)
    guard let realm = p["realm"], let nonce = p["nonce"] else { return nil }
    let ha1 = md5hex("\(authid):\(realm):\(password)")
    let ha2 = md5hex("\(method):\(uri)")
    var resp = md5hex("\(ha1):\(nonce):\(ha2)")
    var extra = ""
    if let qop = p["qop"], qop.contains("auth") {
        let nc = "00000001", cn = randHex(16)
        resp = md5hex("\(ha1):\(nonce):\(nc):\(cn):auth:\(ha2)")
        extra = ",qop=auth,nc=\(nc),cnonce=\"\(cn)\""
    }
    return "\(name): Digest username=\"\(authid)\",realm=\"\(realm)\",nonce=\"\(nonce)\","
         + "uri=\"\(uri)\",response=\"\(resp)\",algorithm=MD5\(extra)"
}

// MARK: - SDP

struct AudioCfg { var ip: String; var port: UInt16; var pt: Int; var wb: Bool; var aligned: Bool }

func parseSDP(_ body: String) -> AudioCfg? {
    var ip: String?
    var port: UInt16 = 0
    var pts = [Int]()
    var rtpmap = [Int: String](), fmtp = [Int: String]()
    for line in body.replacingOccurrences(of: "\r", with: "").components(separatedBy: "\n") {
        if line.hasPrefix("c=IN IP") {
            ip = line.split(separator: " ").last.map(String.init)
        } else if line.hasPrefix("m=audio") {
            let f = line.split(separator: " ")
            if f.count >= 4 {
                port = UInt16(f[1]) ?? 0
                pts = f[3...].compactMap { Int($0) }
            }
        } else if line.hasPrefix("a=rtpmap:") {
            let parts = line.dropFirst(9).split(separator: " ", maxSplits: 1)
            if parts.count == 2, let n = Int(parts[0]) { rtpmap[n] = String(parts[1]) }
        } else if line.hasPrefix("a=fmtp:") {
            let parts = line.dropFirst(7).split(separator: " ", maxSplits: 1)
            if parts.count == 2, let n = Int(parts[0]) { fmtp[n] = String(parts[1]) }
        }
    }
    for pt in pts {
        let name = (rtpmap[pt] ?? "").uppercased()
        if name.hasPrefix("AMR") {
            return AudioCfg(ip: ip ?? "", port: port, pt: pt, wb: name.contains("WB"),
                            aligned: (fmtp[pt] ?? "").contains("octet-align=1"))
        }
    }
    return nil
}

// MARK: - TLS connection helper (accepts the router's self-signed certificate)

func makeTLSConnection(host: String, port: UInt16) -> NWConnection {
    let tls = NWProtocolTLS.Options()
    sec_protocol_options_set_verify_block(tls.securityProtocolOptions,
                                          { _, _, complete in complete(true) },
                                          DispatchQueue.global())
    let tcp = NWProtocolTCP.Options()
    tcp.noDelay = true
    let params = NWParameters(tls: tls, tcp: tcp)
    return NWConnection(host: NWEndpoint.Host(host),
                        port: NWEndpoint.Port(rawValue: port)!, using: params)
}

// MARK: - Provisioning (HTTPS GET to router :8443, raw HTTP/1.0 over TLS)

final class Provisioner {
    private let conn: NWConnection
    private let q = DispatchQueue(label: "jio.prov")
    private let request: String
    private let completion: (Result<[String: String], Error>) -> Void
    private var buf = [UInt8]()
    private var done = false

    init(router: String, request: String,
         completion: @escaping (Result<[String: String], Error>) -> Void) {
        self.conn = makeTLSConnection(host: router, port: 8443)
        self.request = request
        self.completion = completion
    }

    func start() {
        conn.stateUpdateHandler = { [weak self] st in
            guard let self = self else { return }
            switch st {
            case .ready:
                self.conn.send(content: Data(self.request.utf8), completion: .contentProcessed({ _ in }))
                self.readMore()
            case .failed(let e): self.finish(.failure(e))
            default: break          // .waiting = e.g. Local Network prompt; the timeout covers it
            }
        }
        conn.start(queue: q)
        q.asyncAfter(deadline: .now() + 20) { [weak self] in
            self?.finish(.failure(NSError(domain: "jio", code: 1,
                userInfo: [NSLocalizedDescriptionKey: "timed out talking to the router"])))
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
        let statusLine = text.components(separatedBy: "\r\n").first ?? ""
        if !statusLine.contains(" 200") {
            let status = Int(statusLine.split(separator: " ").dropFirst().first ?? "") ?? 0
            finish(.failure(NSError(domain: "jio", code: status, userInfo: [NSLocalizedDescriptionKey:
                "router replied \"\(statusLine)\""])))
            return
        }
        var vals = [String: String]()
        for tag in regexMatches("<parm\\b[^>]*>", in: text) {
            guard let t = tag.first else { continue }
            let n = regexMatches("\\sname\\s*=\\s*[\"']([^\"']*)[\"']", in: t).first?[1]
            let v = regexMatches("\\svalue\\s*=\\s*[\"']([^\"']*)[\"']", in: t).first?[1]
            if let n = n, let v = v { vals[n] = v }
        }
        finish(.success(vals))
    }

    private func finish(_ r: Result<[String: String], Error>) {
        if done { return }
        done = true
        conn.cancel()
        completion(r)
    }
}

// MARK: - RTP media (BSD UDP socket, silent AMR "NO_DATA" frames, counts what arrives)

final class RTPMedia {
    private var fd: Int32 = -1
    private(set) var port: UInt16 = 0
    private let lock = NSLock()
    private var remote: sockaddr_in?
    private var cfg: AudioCfg?
    private var running = false
    private var _tx = 0, _rx = 0
    private var seq = UInt16.random(in: 0...65535)
    private var ts = UInt32.random(in: 0...UInt32.max)
    private let ssrc = UInt32.random(in: 0...UInt32.max)
    private var marker = true
    var onPayload: (([UInt8], AudioCfg) -> Void)?
    private var txQueue = [[UInt8]]()

    private var _good = 0, _otherPT = -1
    var good: Int { lock.lock(); defer { lock.unlock() }; return _good }
    var otherPT: Int { lock.lock(); defer { lock.unlock() }; return _otherPT }
    var tx: Int { lock.lock(); defer { lock.unlock() }; return _tx }
    var rx: Int { lock.lock(); defer { lock.unlock() }; return _rx }

    init?(preferredPort: UInt16) {
        fd = socket(AF_INET, SOCK_DGRAM, 0)
        if fd < 0 { return nil }
        for p in [preferredPort, 0] {
            var a = sockaddr_in()
            a.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
            a.sin_family = sa_family_t(AF_INET)
            a.sin_port = p.bigEndian
            a.sin_addr.s_addr = INADDR_ANY
            let ok = withUnsafePointer(to: &a) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }
            if ok == 0 { break }
        }
        var bound = sockaddr_in()
        var len = socklen_t(MemoryLayout<sockaddr_in>.size)
        _ = withUnsafeMutablePointer(to: &bound) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &len) }
        }
        port = UInt16(bigEndian: bound.sin_port)
    }

    func setRemote(_ c: AudioCfg) -> Bool {
        var a = sockaddr_in()
        a.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        a.sin_family = sa_family_t(AF_INET)
        a.sin_port = c.port.bigEndian
        guard c.port != 0, inet_pton(AF_INET, c.ip, &a.sin_addr) == 1 else { return false }
        lock.lock(); remote = a; cfg = c; lock.unlock()
        return true
    }

    func start() {
        running = true
        Thread.detachNewThread { [weak self] in self?.loop() }
    }

    func stop() { running = false }

    func enqueueTx(_ p: [UInt8]) {
        lock.lock()
        txQueue.append(p)
        if txQueue.count > 5 { txQueue.removeFirst(txQueue.count - 5) }
        lock.unlock()
    }

    private func loop() {
        var next = Date().timeIntervalSince1970
        var buf = [UInt8](repeating: 0, count: 4096)
        while running {
            var pfd = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
            if poll(&pfd, 1, 5) > 0 && (pfd.revents & Int16(POLLIN)) != 0 {
                let n = recv(fd, &buf, buf.count, 0)
                if n >= 12 {
                    lock.lock(); _rx += 1; let c = cfg; lock.unlock()
                    var hl = 12 + 4 * Int(buf[0] & 0x0F)
                    if (buf[0] & 0x10) != 0, n >= hl + 4 {
                        hl += 4 + 4 * ((Int(buf[hl + 2]) << 8) | Int(buf[hl + 3]))
                    }
                    let ptv = Int(buf[1] & 0x7F)
                    if let c = c, n > hl {
                        if ptv == c.pt || (ptv >= 96 && ptv != 122 && ptv != 121 && ptv != 101) {
                            lock.lock(); _good += 1; lock.unlock()
                            onPayload?(Array(buf[hl..<n]), c)
                        } else { lock.lock(); _otherPT = ptv; lock.unlock() }
                    }
                }
            }
            let now = Date().timeIntervalSince1970
            if now >= next {
                sendFrame()
                next += 0.02
                if now - next > 0.2 { next = now }
            }
        }
        close(fd)
    }

    private func sendFrame() {
        lock.lock()
        guard var dst = remote, let c = cfg else { lock.unlock(); return }
        lock.unlock()
        lock.lock()
        let queued: [UInt8]? = txQueue.isEmpty ? nil : txQueue.removeFirst()
        lock.unlock()
        let payload: [UInt8] = queued ?? (c.aligned ? [0xF0, 0x7C] : [0xF7, 0xC0])   // else AMR NO_DATA
        var pkt: [UInt8] = [0x80, (marker ? 0x80 : 0) | UInt8(c.pt & 0x7F)]
        marker = false
        pkt += [UInt8(seq >> 8), UInt8(seq & 0xFF)]
        pkt += [UInt8(ts >> 24), UInt8((ts >> 16) & 0xFF), UInt8((ts >> 8) & 0xFF), UInt8(ts & 0xFF)]
        pkt += [UInt8(ssrc >> 24), UInt8((ssrc >> 16) & 0xFF), UInt8((ssrc >> 8) & 0xFF), UInt8(ssrc & 0xFF)]
        pkt += payload
        let sent = withUnsafePointer(to: &dst) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                sendto(fd, pkt, pkt.count, 0, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        if sent > 0 { lock.lock(); _tx += 1; lock.unlock() }
        seq &+= 1
        ts &+= c.wb ? 320 : 160
    }
}

// MARK: - The phone

final class JioPhone {
    enum Phase { case idle, fetching, connecting, regChallenge, regAuth, calling, finished }

    // callbacks, always delivered on the main queue
    var onLog: ((String) -> Void)?
    var onStatus: ((String) -> Void)?
    var onFinished: (() -> Void)?
    var onNeedsRegistration: (() -> Void)?

    private let q = DispatchQueue(label: "jio.phone")
    private var phase: Phase = .idle
    private var conn: NWConnection?
    private var prov: Provisioner?
    private var rxbuf = [UInt8]()
    private var timer: DispatchSourceTimer?
    private var ticks = 0
    private let t0 = Date()

    // account
    private var router = "192.168.29.1"
    private let sipPort: UInt16 = 5068
    private var hostname = "", number = ""
    private var user = "", domain = "", authid = "", password = "", inst = ""
    private var pani: String?
    private var lip = "", lport = 0
    private var regCid = "", regTag = "", regCseq = 1

    // dialog
    private var cid = "", ftag = "", cseq = 1, branch = "", toHdr = "", ruri = ""
    private var target: String?
    private var routes = [String]()
    private var answered = false, ending = false, authed = false
    private var pracked = Set<String>()
    private var tStart = Date(), tAnswer: Date?, tEnd: Date?
    private var media: RTPMedia?
    private var mediaLogged = false
    private var audio: AudioIO?
    private var ringPlayer: AVAudioPlayer?
    private var curCfg: AudioCfg?
    private var muted = false
    private var speakerOn = true

    // MARK: public API

    func call(number: String, hostname: String, router: String) {
        q.async {
            self.number = normNumber(number)
            self.hostname = hostname.trimmingCharacters(in: .whitespaces)
            self.router = router.trimmingCharacters(in: .whitespaces)
            self.begin()
        }
    }

    func hangup() { q.async { self.doHangup("hang up pressed") } }

    func setMute(_ on: Bool) { q.async { self.muted = on; self.audio?.muted = on } }

    func setSpeaker(_ on: Bool) { q.async { self.speakerOn = on; self.audio?.setSpeaker(on) } }

    // MARK: logging / status

    private func log(_ s: String) {
        let line = String(format: "[%5.1fs] ", Date().timeIntervalSince(t0)) + s
        DispatchQueue.main.async { self.onLog?(line) }
    }

    private func status(_ s: String) {
        DispatchQueue.main.async { self.onStatus?(s) }
    }

    private func finish(_ why: String) {
        if phase == .finished { return }
        phase = .finished
        log(why)
        status(why)
        timer?.cancel(); timer = nil
        ringPlayer?.stop(); ringPlayer = nil
        audio?.stop(); audio = nil
        if let m = media { log("RTP sent \(m.tx) packets, received \(m.rx) packets"); m.stop() }
        conn?.cancel()
        DispatchQueue.main.async { self.onFinished?() }
    }

    // MARK: step 1 - credentials from the router

    private func begin() {
        phase = .fetching
        status("Getting credentials…")
        let mac = jfcMac(hostname)
        log("device \(hostname)  (\(mac))")
        let params: [(String, String)] = [
            ("terminal_sw_version", "RCSAndrd"), ("terminal_vendor", hostname),
            ("terminal_model", hostname), ("SMS_port", "0"), ("act_type", "volatile"),
            ("IMSI", ""), ("msisdn", ""), ("IMEI", ""), ("vers", "0"), ("token", ""),
            ("rcs_state", "0"), ("rcs_version", "5.1B"), ("rcs_profile", "joyn_blackbird"),
            ("client_vendor", "JUIC"), ("default_sms_app", "2"), ("default_vvm_app", "0"),
            ("device_type", "vvm"), ("client_version", "JSEAndrd-1.0"),
            ("mac_address", mac), ("alias", hostname), ("nwk_intf", "wifi")]
        let allowed = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~")
        let query = params.map { k, v in
            k + "=" + (v.addingPercentEncoding(withAllowedCharacters: allowed) ?? v)
        }.joined(separator: "&")
        let req = "GET /?\(query) HTTP/1.0\r\nHost: \(router):8443\r\nConnection: close\r\n\r\n"
        let p = Provisioner(router: router, request: req) { [weak self] result in
            guard let self = self else { return }
            self.q.async { self.provisioned(result, mac: mac) }
        }
        prov = p
        p.start()
    }

    private func provisioned(_ r: Result<[String: String], Error>, mac: String) {
        switch r {
        case .failure(let e):
            let ns = e as NSError
            if ns.domain == "jio" && ns.code == 407 {
                finish("This phone isn't registered yet")
                DispatchQueue.main.async { self.onNeedsRegistration?() }
            } else {
                finish("Could not reach the router. Check you're on JioFiber Wi-Fi and Local Network access is allowed.")
            }
        case .success(let v):
            guard let uname = v["username"], let pwd = v["userpwd"] else {
                finish("The router gave no calling credentials. Please register this phone again.")
                DispatchQueue.main.async { self.onNeedsRegistration?() }
                return
            }
            authid = uname
            password = pwd
            let parts = uname.components(separatedBy: "@")
            user = "+" + parts[0]
            domain = v["home_network_domain_name"] ?? (parts.count > 1 ? parts[1] : "")
            inst = v["uuid_value"] ?? ("00000000-0000-1000-8000-" + mac.replacingOccurrences(of: ":", with: "").uppercased())
            if let ps = v["psoltid"], !ps.isEmpty { pani = "GPON;PSAPId=\(ps)" }
            log("credentials OK for \(user)")
            connectSip()
        }
    }

    // MARK: step 2 - TLS + REGISTER

    private func connectSip() {
        phase = .connecting
        status("Connecting…")
        let c = makeTLSConnection(host: router, port: sipPort)
        conn = c
        c.stateUpdateHandler = { [weak self] st in
            guard let self = self else { return }
            switch st {
            case .ready:
                if self.phase == .connecting { self.onConnected() }
            case .failed(let e): self.finish("Connection failed: \(e)")
            default: break
            }
        }
        c.start(queue: q)
        q.asyncAfter(deadline: .now() + 20) { [weak self] in
            if let self = self, self.phase == .connecting {
                self.finish("Cannot reach the router's SIP port. Check Wi-Fi and Local Network permission.")
            }
        }
    }

    private func onConnected() {
        if let ep = conn?.currentPath?.localEndpoint, case let .hostPort(host, port) = ep {
            lport = Int(port.rawValue)
            lip = "\(host)".components(separatedBy: "%")[0]
        }
        if lip.isEmpty || lip.contains(":") {
            finish("Need an IPv4 address on Wi-Fi (got \"\(lip)\")")
            return
        }
        log("connected to router from \(lip):\(lport)")
        receiveLoop()
        startTimer()
        regCid = randHex(32) + "@" + lip
        regTag = randHex(8)
        phase = .regChallenge
        status("Registering…")
        sendRegister(auth: nil)
    }

    private func receiveLoop() {
        conn?.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak self] data, _, isComplete, error in
            guard let self = self else { return }
            if let d = data, !d.isEmpty { self.rxbuf.append(contentsOf: d); self.drain() }
            if let e = error { self.finish("Connection error: \(e)"); return }
            if isComplete { self.finish("Router closed the connection"); return }
            if self.phase != .finished { self.receiveLoop() }
        }
    }

    private func drain() {
        while true {
            while let f = rxbuf.first, f == 13 || f == 10 { rxbuf.removeFirst() }
            guard let end = headerEnd(rxbuf) else { return }
            let head = String(decoding: rxbuf[0..<end], as: UTF8.self)
            var cl = 0
            if let m = regexMatches("(?im)^(?:content-length|l)\\s*:\\s*(\\d+)", in: head).first { cl = Int(m[1]) ?? 0 }
            let total = end + 4 + cl
            if rxbuf.count < total { return }
            let raw = String(decoding: rxbuf[0..<total], as: UTF8.self)
            rxbuf.removeFirst(total)
            handle(SipMsg(raw: raw))
        }
    }

    private func headerEnd(_ b: [UInt8]) -> Int? {
        if b.count < 4 { return nil }
        for i in 0...(b.count - 4) where b[i] == 13 && b[i + 1] == 10 && b[i + 2] == 13 && b[i + 3] == 10 {
            return i
        }
        return nil
    }

    private func send(_ text: String) {
        conn?.send(content: Data(text.utf8), completion: .contentProcessed({ [weak self] err in
            if let err = err { self?.q.async { self?.finish("Send failed: \(err)") } }
        }))
    }

    private func sendRegister(auth: String?) {
        let tags = "+g.3gpp.icsi-ref=\"urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel\";video;"
                 + "+g.3gpp.iari-ref=\"urn%3Aurn-7%3A3gpp-application.ims.iari.rcs.jio.eucr\";"
                 + "+g.gsma.rcs.telephony=\"none\";q=0.5"
        var L = [
            "REGISTER sip:\(domain) SIP/2.0",
            "Via: SIP/2.0/TLS \(lip):\(lport);branch=\(newBranch());rkeep=180",
            "Max-Forwards: 70",
            "Contact: <sip:\(user)@\(lip):\(lport);transport=tls>;+sip.instance=\"<\(inst)>\";reg-id=1;\(tags)",
            "To: <sip:\(user)@\(domain)>",
            "From: <sip:\(user)@\(domain)>;tag=\(regTag)",
            "Call-ID: \(regCid)",
            "CSeq: \(regCseq) REGISTER",
            "Expires: 3600",
            "Allow: INVITE, ACK, CANCEL, OPTIONS, BYE, REFER, NOTIFY, SUBSCRIBE, UPDATE, PRACK, INFO",
            "Supported: outbound, path, gruu, replaces, timer, norefersub",
            "User-Agent: RCSAndrd/1.2.4 JUICEJSE/1.4.2.11"]
        if let a = auth { L.append(a) }
        if let p = pani { L.append("P-Access-Network-Info: \(p)") }
        L += ["Content-Length: 0", "", ""]
        regCseq += 1
        send(L.joined(separator: "\r\n"))
    }

    // MARK: timer (1 Hz)

    private func startTimer() {
        let t = DispatchSource.makeTimerSource(queue: q)
        t.schedule(deadline: .now() + 1, repeating: 1.0)
        t.setEventHandler { [weak self] in self?.tick() }
        t.resume()
        timer = t
    }

    private func tick() {
        ticks += 1
        if ticks % 10 == 0 { send("\r\n\r\n") }                       // TLS keep-alive
        guard phase == .calling else { return }
        if answered || (audio?.decodedCount ?? 0) > 10 {
            if ringPlayer != nil || audio != nil { audio?.stopRing(); stopRingTone() }
        }
        if ticks % 3 == 0, let m = media {
            log("RTP tx \(m.tx)  rx \(m.rx)  decodable \(m.good)  other-pt \(m.otherPT)")
        }
        let now = Date()
        if answered, !ending, let ta = tAnswer {
            let s = Int(now.timeIntervalSince(ta))
            status(String(format: "Connected %02d:%02d", s / 60, s % 60))
        }
        if !answered && !ending && now.timeIntervalSince(tStart) >= 45 { doHangup("no answer") }
        if ending, let te = tEnd, now.timeIntervalSince(te) > 5 { finish("Call ended") }
    }

    // MARK: message dispatch

    private func handle(_ m: SipMsg) {
        log("← \(m.start)")
        switch phase {
        case .regChallenge:
            guard m.isResponse else { return }
            if m.code == 401, let ch = m.get("www-authenticate"),
               let auth = digestHeader("Authorization", authid: authid, password: password,
                                       method: "REGISTER", uri: "sip:\(domain)", challenge: ch) {
                phase = .regAuth
                sendRegister(auth: auth)
            } else {
                finish("Registration failed: \(m.code) \(m.reason)")
            }
        case .regAuth:
            guard m.isResponse else { return }
            if m.code == 200 {
                log("registered with Jio")
                startCall()
            } else {
                finish("Registration failed: \(m.code) \(m.reason)")
            }
        case .calling:
            if m.isResponse { onResponse(m) } else { onRequest(m) }
        default:
            break
        }
    }

    // MARK: step 3 - INVITE

    private func startCall() {
        guard let md = RTPMedia(preferredPort: 52000) else { finish("Could not open RTP socket"); return }
        media = md
        md.start()
        phase = .calling
        cid = randHex(16) + "@" + lip
        ftag = randHex(8)
        cseq = 1
        ruri = "sip:\(number)@\(domain)?phone-context=\(domain)&user=phone"
        toHdr = "<\(ruri)>"
        tStart = Date()
        status("Calling \(number)…")
        sendInvite(auth: nil)
    }

    private func makeSDP() -> String {
        let sid = String(Int.random(in: 1_000_000_000_000_000...9_999_999_999_999_999))
        let port = media?.port ?? 52000
        var L = [String]()
        L.append("v=0")
        L.append("o=Juice \(sid) \(sid) IN IP4 \(lip)")
        L.append("s=-")
        L.append("c=IN IP4 \(lip)")
        L.append("t=0 0")
        if let c = curCfg {
            // answer to the network: only the codec it chose
            L.append("m=audio \(port) RTP/AVP \(c.pt) 122")
            L.append("b=AS:37")
            L.append("a=rtpmap:\(c.pt) AMR-WB/16000")
            let oa = c.aligned ? "octet-align=1; " : ""
            L.append("a=fmtp:\(c.pt) \(oa)mode-change-capability=2; max-red=0")
        } else {
            // initial offer: wideband only (the app only has an AMR-WB codec)
            L.append("m=audio \(port) RTP/AVP 126 125 122")
            L.append("b=AS:37")
            L.append("a=rtpmap:126 AMR-WB/16000")
            L.append("a=fmtp:126 mode-change-capability=2; max-red=0")
            L.append("a=rtpmap:125 AMR-WB/16000")
            L.append("a=fmtp:125 octet-align=1; mode-change-capability=2; max-red=0")
        }
        L.append("a=rtpmap:122 telephone-event/16000")
        L.append("a=fmtp:122 0-15")
        L.append("a=ptime:20")
        L.append("a=maxptime:240")
        L.append("a=sendrecv")
        L.append("")
        return L.joined(separator: "\r\n")
    }

    private func paniSpaced() -> String? { pani?.replacingOccurrences(of: ";", with: "; ") }

    private func sendInvite(auth: String?) {
        branch = newBranch()
        let body = makeSDP()
        let contact = "<sip:\(lip):\(lport);transport=tls>;+sip.instance=\"<\(inst)>\";reg-id=1;"
            + "+g.3gpp.icsi-ref=\"urn:urn-7:3gpp-service.ims.icsi.mmtel\";video;"
            + "+g.3gpp.iari-ref=\"urn:urn-7:3gpp-application.ims.iari.rcs.jio.eucr\";"
            + "+g.gsma.rcs.telephony=\"none\";q=0.5"
        var L = [
            "INVITE \(ruri) SIP/2.0",
            "Via: SIP/2.0/TLS \(lip):\(lport);rkeep=180;branch=\(branch)",
            "Max-Forwards: 70",
            "Contact: \(contact)",
            "To: \(toHdr)",
            "From: <sip:\(user)@\(domain)>;tag=\(ftag)",
            "Call-ID: \(cid)",
            "CSeq: \(cseq) INVITE",
            "Session-Expires: 1800", "Min-SE: 90",
            "Allow: INVITE, ACK, CANCEL, OPTIONS, BYE, REFER, NOTIFY, SUBSCRIBE, UPDATE, PRACK, INFO",
            "Content-Type: application/sdp",
            "Supported: outbound, path, gruu, replaces, timer, norefersub, 100rel",
            "User-Agent: JFVoice/1.0",
            "P-Preferred-Identity: <sip:\(user)@\(domain)>"]
        if let a = auth { L.append(a) }
        if let p = paniSpaced() { L.append("P-Access-Network-Info: \(p)") }
        L += ["Content-Length: \(body.utf8.count)", "", body]
        send(L.joined(separator: "\r\n"))
    }

    private func inDialog(_ method: String, extra: [String] = []) {
        cseq += 1
        var L = [
            "\(method) \(target ?? ruri) SIP/2.0",
            "Via: SIP/2.0/TLS \(lip):\(lport);rkeep=180;branch=\(newBranch())",
            "Max-Forwards: 70"]
        L += routes.map { "Route: \($0)" }
        L += ["From: <sip:\(user)@\(domain)>;tag=\(ftag)", "To: \(toHdr)",
              "Call-ID: \(cid)", "CSeq: \(cseq) \(method)", "User-Agent: JFVoice/1.0"]
        if let p = paniSpaced() { L.append("P-Access-Network-Info: \(p)") }
        L += extra
        L += ["Content-Length: 0", "", ""]
        send(L.joined(separator: "\r\n"))
    }

    private func sendAck(cseq n: Int, branch b: String? = nil) {
        var L = [
            "ACK \(target ?? ruri) SIP/2.0",
            "Via: SIP/2.0/TLS \(lip):\(lport);rkeep=180;branch=\(b ?? newBranch())",
            "Max-Forwards: 70"]
        L += routes.map { "Route: \($0)" }
        L += ["From: <sip:\(user)@\(domain)>;tag=\(ftag)", "To: \(toHdr)",
              "Call-ID: \(cid)", "CSeq: \(n) ACK", "Content-Length: 0", "", ""]
        send(L.joined(separator: "\r\n"))
    }

    private func learnDialog(_ m: SipMsg) {
        if let to = m.get("to"), to.contains("tag=") { toHdr = to }
        if let c = m.get("contact"),
           let g = regexMatches("<(sip:[^>]+)>", in: c).first, g.count > 1, !g[1].contains("[") {
            target = g[1]
        }
        var rr = [String]()
        for v in m.all("record-route") { rr += regexMatches("<[^>]+>", in: v).compactMap { $0.first } }
        if !rr.isEmpty { routes = rr.reversed() }
    }

    private func mediaFrom(_ m: SipMsg) {
        guard !m.body.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
              let cfg = parseSDP(m.body), let md = media else { return }
        if cfg.wb { curCfg = cfg; audio?.cfg = cfg }      // network may change codec/format at answer
        if md.setRemote(cfg), !mediaLogged {
            mediaLogged = true
            log("media: \(cfg.wb ? "AMR-WB" : "AMR") pt=\(cfg.pt) -> \(cfg.ip):\(cfg.port)")
            startAudio(cfg)
        }
    }

    private func startAudio(_ cfg: AudioCfg) {
        guard audio == nil else { return }
        guard cfg.wb else { log("network chose narrowband audio; voice needs wideband"); return }
        let a = AudioIO(cfg: cfg)
        a.muted = muted
        a.onLog = { [weak self] s in self?.log(s) }
        a.onEncoded = { [weak self] p in self?.media?.enqueueTx(p) }
        media?.onPayload = { [weak a] p, _ in a?.playRx(p) }
        do {
            try a.start()
            a.setSpeaker(speakerOn)
            audio = a
            log("audio started")
            stopRingTone()
            if !answered { a.startRing() }
        } catch {
            log("audio error: \(error.localizedDescription)")
        }
    }

    // MARK: local ringback tone (AVAudioPlayer, no second AVAudioEngine)

    private func startRingTone(speaker: Bool) {
        stopRingTone()
        guard let data = makeRingWavData() else { return }
        do {
            let player = try AVAudioPlayer(data: data)
            player.numberOfLoops = -1
            player.volume = 1.0
            player.play()
            ringPlayer = player
        } catch {
            log("ring tone error: \(error.localizedDescription)")
        }
    }

    private func stopRingTone() {
        ringPlayer?.stop()
        ringPlayer = nil
    }

    private func makeRingWavData() -> Data? {
        let sr: Double = 16000
        let total = Int(sr * 3.0)
        var samples = [Float](repeating: 0, count: total)
        for i in 0..<total {
            let t = Double(i) / sr
            let on = (t < 0.4) || (t >= 0.6 && t < 1.0)
            samples[i] = on ? Float(0.35 * sin(2 * Double.pi * 400 * t)) : 0
        }
        let byteRate = Int(sr) * 2
        let dataSize = total * 2
        let chunkSize = 36 + dataSize
        var data = Data()
        data.append(contentsOf: "RIFF".utf8)
        data.append(contentsOf: withUnsafeBytes(of: UInt32(chunkSize)) { Array($0) })
        data.append(contentsOf: "WAVE".utf8)
        data.append(contentsOf: "fmt ".utf8)
        data.append(contentsOf: withUnsafeBytes(of: UInt32(16)) { Array($0) })
        data.append(contentsOf: withUnsafeBytes(of: UInt16(1)) { Array($0) })
        data.append(contentsOf: withUnsafeBytes(of: UInt16(1)) { Array($0) })
        data.append(contentsOf: withUnsafeBytes(of: UInt32(sr)) { Array($0) })
        data.append(contentsOf: withUnsafeBytes(of: UInt32(byteRate)) { Array($0) })
        data.append(contentsOf: withUnsafeBytes(of: UInt16(2)) { Array($0) })
        data.append(contentsOf: withUnsafeBytes(of: UInt16(16)) { Array($0) })
        data.append(contentsOf: "data".utf8)
        data.append(contentsOf: withUnsafeBytes(of: UInt32(dataSize)) { Array($0) })
        for sample in samples {
            let int16 = Int16(sample * 32767)
            data.append(contentsOf: withUnsafeBytes(of: int16) { Array($0) })
        }
        return data
    }

    private func doHangup(_ reason: String) {
        if ending || phase == .finished { return }
        ending = true
        tEnd = Date()
        if phase != .calling { finish("Cancelled"); return }
        if answered {
            log("hanging up (\(reason))")
            status("Hanging up…")
            inDialog("BYE")
        } else {
            log("cancelling (\(reason))")
            status("Cancelling…")
            let L = [
                "CANCEL \(ruri) SIP/2.0",
                "Via: SIP/2.0/TLS \(lip):\(lport);rkeep=180;branch=\(branch)",
                "Max-Forwards: 70", "To: <\(ruri)>",
                "From: <sip:\(user)@\(domain)>;tag=\(ftag)",
                "Call-ID: \(cid)", "CSeq: \(cseq) CANCEL", "Content-Length: 0", "", ""]
            send(L.joined(separator: "\r\n"))
        }
    }

    private func onResponse(_ m: SipMsg) {
        guard m.get("call-id") == cid, let (n, meth) = m.cseq else { return }
        if meth == "BYE" { finish("Call ended"); return }
        guard meth == "INVITE" else { return }
        let code = m.code
        if code == 100 { return }
        if code < 200 {
            learnDialog(m)
            if code == 180 {
                status("Ringing…")
                if !answered && (audio?.decodedCount ?? 0) < 3 {
                    if let a = audio { a.startRing() }
                    else { startRingTone(speaker: speakerOn) }
                    log("playing local ringback tone")
                }
            }
            if code == 183 { status("Ringing (early media)…") }
            if let rs = m.get("rseq"), (m.get("require") ?? "").lowercased().contains("100rel"),
               let rseq = rs.split(separator: " ").first.map(String.init), !pracked.contains(rseq) {
                pracked.insert(rseq)
                inDialog("PRACK", extra: ["RAck: \(rseq) \(n) INVITE"])
            }
            mediaFrom(m)
        } else if code < 300 {
            if answered { sendAck(cseq: n); return }
            learnDialog(m)
            answered = true
            tAnswer = Date()
            sendAck(cseq: n)
            if ending {
                log("answered just after cancel - hanging up")
                inDialog("BYE")
                tEnd = Date()
                return
            }
            stopRingTone()
            audio?.stopRing()
            log("CALL CONNECTED")
            status("Connected 00:00")
            mediaFrom(m)
            audio?.sendEnabled = true
        } else {
            if (code == 401 || code == 407) && !authed && !ending {
                sendAck(cseq: n, branch: branch)
                authed = true
                let hdr = code == 401 ? "Authorization" : "Proxy-Authorization"
                let ch = m.get("www-authenticate") ?? m.get("proxy-authenticate") ?? ""
                if let a = digestHeader(hdr, authid: authid, password: password,
                                        method: "INVITE", uri: ruri, challenge: ch) {
                    cseq += 1
                    log("\(code) - retrying INVITE with credentials")
                    sendInvite(auth: a)
                    return
                }
            }
            sendAck(cseq: n, branch: branch)
            finish(ending && code == 487 ? "Call cancelled" : "Call failed: \(code) \(m.reason)")
        }
    }

    private func onRequest(_ m: SipMsg) {
        func reply(_ code: Int, _ reason: String, sdp: Bool = false) {
            var L = ["SIP/2.0 \(code) \(reason)"]
            for v in m.all("via") { L.append("Via: \(v)") }
            if let v = m.get("from") { L.append("From: \(v)") }
            if let v = m.get("to") { L.append("To: \(v)") }
            if let v = m.get("call-id") { L.append("Call-ID: \(v)") }
            if let v = m.get("cseq") { L.append("CSeq: \(v)") }
            if sdp {
                let body = makeSDP()
                L += ["Contact: <sip:\(user)@\(lip):\(lport);transport=tls>",
                      "Content-Type: application/sdp", "Content-Length: \(body.utf8.count)", "", body]
            } else {
                L += ["Content-Length: 0", "", ""]
            }
            send(L.joined(separator: "\r\n"))
        }
        let inCall = m.get("call-id") == cid && phase == .calling
        switch m.method {
        case "BYE": reply(200, "OK"); finish("Remote party hung up")
        case "INVITE" where inCall:
            mediaFrom(m)
            reply(200, "OK", sdp: true)
        case "UPDATE" where inCall:
            let hasSDP = !m.body.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            if hasSDP { mediaFrom(m) }
            reply(200, "OK", sdp: hasSDP)
        case "INVITE": reply(486, "Busy Here")
        case "ACK": break
        default: reply(200, "OK")
        }
    }
}
