//
//  AudioIO.swift
//  ONU CALL - microphone -> AMR-WB -> RTP, and RTP -> AMR-WB -> speaker.
//  Needs the AMR libraries from setup_amr.sh (see README).
//
import Foundation
import AVFoundation

// MARK: - AMR-WB payload helpers

let amrwbBits = [132, 177, 253, 285, 317, 365, 397, 461, 477, 40]   // FT 0...9

func getBits(_ d: [UInt8], _ pos: Int, _ n: Int) -> Int {
    var v = 0
    for i in 0..<n {
        let b = pos + i
        v = (v << 1) | Int((d[b >> 3] >> UInt8(7 - (b & 7))) & 1)
    }
    return v
}

func readBitsToBytes(_ d: [UInt8], _ pos: Int, _ nb: Int) -> [UInt8] {
    var out = [UInt8]()
    var p = pos, left = nb
    while left > 0 {
        let take = min(8, left)
        var v = 0
        for _ in 0..<take {
            v = (v << 1) | Int((d[p >> 3] >> UInt8(7 - (p & 7))) & 1)
            p += 1
        }
        out.append(UInt8(v << (8 - take)))
        left -= take
    }
    return out
}

/// Split an RTP AMR-WB payload into frames (frame type, quality bit, speech bytes).
func amrwbFrames(_ p: [UInt8], aligned: Bool) -> [(ft: Int, q: Int, sp: [UInt8])] {
    var out = [(ft: Int, q: Int, sp: [UInt8])]()
    var tocs = [(Int, Int)]()
    if aligned {
        var pos = 1
        while pos < p.count {
            let b = p[pos]; pos += 1
            tocs.append((Int(b >> 3) & 0xF, Int(b >> 2) & 1))
            if b & 0x80 == 0 { break }
        }
        for (ft, q) in tocs {
            let n = ft <= 9 ? (amrwbBits[ft] + 7) / 8 : 0
            if pos + n > p.count { break }
            out.append((ft, q, Array(p[pos..<(pos + n)])))
            pos += n
        }
    } else {
        var pos = 4
        let total = p.count * 8
        while pos + 6 <= total {
            let f = getBits(p, pos, 1)
            let ft = getBits(p, pos + 1, 4)
            let q = getBits(p, pos + 5, 1)
            tocs.append((ft, q))
            pos += 6
            if f == 0 { break }
        }
        for (ft, q) in tocs {
            let nb = ft <= 9 ? amrwbBits[ft] : 0
            if pos + nb > total { break }
            out.append((ft, q, nb > 0 ? readBitsToBytes(p, pos, nb) : []))
            pos += nb
        }
    }
    return out
}

/// One frame -> bandwidth-efficient RTP payload (CMR=15 "no request").
func packBE(ft: Int, q: Int, speech: [UInt8]) -> [UInt8] {
    var bits = [UInt8]()
    func put(_ v: Int, _ n: Int) {
        for i in stride(from: n - 1, through: 0, by: -1) { bits.append(UInt8((v >> i) & 1)) }
    }
    put(15, 4); put(0, 1); put(ft, 4); put(q, 1)
    let nb = ft <= 9 ? amrwbBits[ft] : 0
    if speech.count * 8 >= nb {
        for i in 0..<nb { bits.append((speech[i >> 3] >> UInt8(7 - (i & 7))) & 1) }
    }
    while bits.count % 8 != 0 { bits.append(0) }
    var out = [UInt8]()
    var i = 0
    while i < bits.count {
        var b: UInt8 = 0
        for j in 0..<8 { b = (b << 1) | bits[i + j] }
        out.append(b)
        i += 8
    }
    return out
}

// MARK: - Audio engine

final class AudioIO {
    var cfg: AudioCfg
    private let engine = AVAudioEngine()
    private let player = AVAudioPlayerNode()
    private let ringPlayer = AVAudioPlayerNode()
    private let fmt16 = AVAudioFormat(standardFormatWithSampleRate: 16000, channels: 1)!
    private let outFmt = AVAudioFormat(commonFormat: .pcmFormatInt16, sampleRate: 16000,
                                       channels: 1, interleaved: true)!
    private var monoFmt: AVAudioFormat?
    private var converter: AVAudioConverter?
    private var enc: UnsafeMutableRawPointer?
    private var dec: UnsafeMutableRawPointer?
    private var acc = [Int16]()
    private var pending = 0
    private let lock = NSLock()
    private let codecLock = NSLock()
    private var running = false
    private var observers = [NSObjectProtocol]()
    private var micBufs = 0, encoded = 0, decoded = 0
    private var rxPeak = 0
    private var lastDone = Date()

    var decodedCount: Int { decoded }
    var muted = false
    var sendEnabled = false
    var onEncoded: (([UInt8]) -> Void)?
    var onLog: ((String) -> Void)?

    init(cfg: AudioCfg) { self.cfg = cfg }

    func start() throws {
        let s = AVAudioSession.sharedInstance()
        try s.setCategory(.playAndRecord, mode: .voiceChat, options: [.allowBluetoothHFP])
        try s.setPreferredSampleRate(16000)
        try s.setActive(true)
        onLog?("audio session active, output: \(s.currentRoute.outputs.map { $0.portType.rawValue })")

        codecLock.lock()
        enc = E_IF_init()
        dec = D_IF_init()
        codecLock.unlock()

        // Voice processing must be switched on BEFORE the nodes are wired, otherwise the
        // output/input formats change under us and both directions go silent.
        do { try engine.inputNode.setVoiceProcessingEnabled(true) }
        catch { onLog?("voice processing unavailable: \(error.localizedDescription)") }

        engine.attach(player)
        engine.connect(player, to: engine.mainMixerNode, format: fmt16)
        engine.attach(ringPlayer)
        engine.connect(ringPlayer, to: engine.mainMixerNode, format: fmt16)

        // nil format: use whatever the (voice-processed) mic really delivers
        engine.inputNode.installTap(onBus: 0, bufferSize: 1024, format: nil) { [weak self] buf, _ in
            self?.handleMic(buf)
        }
        player.volume = 1
        engine.mainMixerNode.outputVolume = 1
        engine.prepare()
        try engine.start()
        player.play()
        running = true

        // iOS stops the engine on route/format changes (speaker toggle, Bluetooth...). Restart it.
        observers.append(NotificationCenter.default.addObserver(
            forName: .AVAudioEngineConfigurationChange, object: engine, queue: nil) { [weak self] _ in
            self?.restart()
        })
        observers.append(NotificationCenter.default.addObserver(
            forName: AVAudioSession.interruptionNotification, object: nil, queue: nil) { [weak self] n in
            if let t = n.userInfo?[AVAudioSessionInterruptionTypeKey] as? UInt,
               AVAudioSession.InterruptionType(rawValue: t) == .ended {
                try? AVAudioSession.sharedInstance().setActive(true)
                self?.restart()
            }
        })
    }

    private func restart() {
        guard running else { return }
        if !engine.isRunning {
            do {
                try engine.start()
                onLog?("audio engine restarted")
            } catch {
                onLog?("audio restart failed: \(error.localizedDescription)")
                return
            }
        }
        lock.lock(); pending = 0; lock.unlock()
        player.volume = 1
        engine.mainMixerNode.outputVolume = 1
        player.reset()
        player.play()
        let s = AVAudioSession.sharedInstance()
        onLog?("audio route now: \(s.currentRoute.outputs.map { $0.portType.rawValue })")
    }

    func stop() {
        guard running else { return }
        running = false
        observers.forEach { NotificationCenter.default.removeObserver($0) }
        observers.removeAll()
        engine.inputNode.removeTap(onBus: 0)
        player.stop()
        engine.stop()
        codecLock.lock()
        if let e = enc { E_IF_exit(e) }
        if let d = dec { D_IF_exit(d) }
        enc = nil; dec = nil
        codecLock.unlock()
        try? AVAudioSession.sharedInstance().setActive(false, options: .notifyOthersOnDeactivation)
    }

    func startRing() {
        guard running, !ringPlayer.isPlaying, let b = makeRingBuffer(fmt16) else { return }
        ringPlayer.scheduleBuffer(b, at: nil, options: .loops, completionHandler: nil)
        ringPlayer.play()
    }

    func stopRing() { if ringPlayer.isPlaying { ringPlayer.stop() } }

    func setSpeaker(_ on: Bool) {
        do {
            try AVAudioSession.sharedInstance().overrideOutputAudioPort(on ? .speaker : .none)
        } catch {
            onLog?("speaker switch failed: \(error.localizedDescription)")
        }
        DispatchQueue.global().asyncAfter(deadline: .now() + 0.4) { [weak self] in
            guard let self = self, self.running else { return }
            if !self.engine.isRunning { self.restart() }
            else {
                self.lock.lock(); self.pending = 0; self.lock.unlock()
                if !self.player.isPlaying { self.player.play() }
            }
            let outs = AVAudioSession.sharedInstance().currentRoute.outputs.map { $0.portType.rawValue }
            self.onLog?("speaker \(on ? "ON" : "OFF") -> output \(outs)")
        }
    }

    // MARK: microphone -> RTP

    private func handleMic(_ buf: AVAudioPCMBuffer) {
        guard running, buf.frameLength > 0, let src = buf.floatChannelData else { return }
        let sr = buf.format.sampleRate
        if monoFmt == nil || monoFmt!.sampleRate != sr {
            guard let mf = AVAudioFormat(commonFormat: .pcmFormatFloat32, sampleRate: sr,
                                         channels: 1, interleaved: false) else { return }
            monoFmt = mf
            converter = AVAudioConverter(from: mf, to: outFmt)
            onLog?("mic format: \(Int(sr)) Hz, \(buf.format.channelCount) ch")
        }
        guard let mf = monoFmt, let conv = converter,
              let mono = AVAudioPCMBuffer(pcmFormat: mf, frameCapacity: buf.frameLength) else { return }
        mono.frameLength = buf.frameLength
        mono.floatChannelData![0].update(from: src[0], count: Int(buf.frameLength))   // channel 0 only

        let cap = AVAudioFrameCount(Double(buf.frameLength) * 16000.0 / sr) + 64
        guard let out = AVAudioPCMBuffer(pcmFormat: outFmt, frameCapacity: cap) else { return }
        var given = false
        var err: NSError?
        conv.convert(to: out, error: &err) { _, status in
            if given { status.pointee = .noDataNow; return nil }
            given = true
            status.pointee = .haveData
            return mono
        }
        if err != nil { return }
        guard let ch = out.int16ChannelData else { return }
        micBufs += 1
        if micBufs == 1 { onLog?("mic is delivering audio") }
        acc.append(contentsOf: UnsafeBufferPointer(start: ch[0], count: Int(out.frameLength)))
        while acc.count >= 320 {
            let frame = Array(acc.prefix(320))
            acc.removeFirst(320)
            encodeAndSend(frame)
        }
    }

    private func encodeAndSend(_ pcm: [Int16]) {
        guard sendEnabled, !muted else { return }
        var out = [UInt8](repeating: 0, count: 64)
        codecLock.lock()
        guard let e = enc else { codecLock.unlock(); return }
        let n = Int(E_IF_encode(e, 2, pcm, &out, 0))            // mode 2 = 12.65 kbit/s
        codecLock.unlock()
        guard n > 1 else { return }
        let ft = Int(out[0] >> 3) & 0xF
        let q = Int(out[0] >> 2) & 1
        let speech = Array(out[1..<n])
        let payload: [UInt8] = cfg.aligned
            ? [0xF0, UInt8((ft << 3) | (q << 2))] + speech
            : packBE(ft: ft, q: q, speech: speech)
        encoded += 1
        if encoded == 1 { onLog?("first voice packet encoded (ft \(ft), \(payload.count) bytes)") }
        onEncoded?(payload)
    }

    // MARK: RTP -> speaker

    func playRx(_ payload: [UInt8]) {
        guard running else { return }
        for f in amrwbFrames(payload, aligned: cfg.aligned) {
            if f.ft == 15 { continue }                           // NO_DATA: nothing to play
            let bits: [UInt8] = [UInt8((f.ft << 3) | (f.q << 2))] + f.sp
            var synth = [Int16](repeating: 0, count: 320)
            codecLock.lock()
            guard let d = dec else { codecLock.unlock(); return }
            D_IF_decode(d, bits, &synth, 0)
            codecLock.unlock()
            decoded += 1
            if decoded == 1 { onLog?("first voice packet received (ft \(f.ft))") }
            var pk = 0
            for v in synth { pk = max(pk, abs(Int(v))) }
            rxPeak = max(rxPeak, pk)
            if decoded % 150 == 0 {
                lock.lock(); let pd = pending; lock.unlock()
                onLog?("rx decoded \(decoded), peak level \(rxPeak)/32767, queued \(pd), engine \(engine.isRunning ? "on" : "OFF"), player \(player.isPlaying ? "on" : "OFF")")
                rxPeak = 0
            }
            enqueue(synth)
        }
    }

    private func enqueue(_ s: [Int16]) {
        lock.lock()
        if pending > 12 {
            if Date().timeIntervalSince(lastDone) > 0.5 {         // counter stuck -> reset
                pending = 0
                lock.unlock()
                player.reset(); player.play()
                onLog?("playback queue was stuck, reset")
                lock.lock()
            } else { lock.unlock(); return }                      // keep latency bounded
        }
        pending += 1
        lock.unlock()
        guard let buf = AVAudioPCMBuffer(pcmFormat: fmt16, frameCapacity: 320),
              let p = buf.floatChannelData?[0] else {
            lock.lock(); pending -= 1; lock.unlock()
            return
        }
        buf.frameLength = 320
        for i in 0..<320 { p[i] = Float(s[i]) / 32768.0 }
        if !player.isPlaying && engine.isRunning { player.play() }
        player.scheduleBuffer(buf) { [weak self] in
            self?.lock.lock()
            self?.pending = max(0, (self?.pending ?? 1) - 1)
            self?.lastDone = Date()
            self?.lock.unlock()
        }
    }
}

func makeRingBuffer(_ fmt: AVAudioFormat) -> AVAudioPCMBuffer? {
    let sr = fmt.sampleRate
    let total = Int(sr * 3.0)
    guard let buf = AVAudioPCMBuffer(pcmFormat: fmt, frameCapacity: AVAudioFrameCount(total)),
          let p = buf.floatChannelData?[0] else { return nil }
    buf.frameLength = AVAudioFrameCount(total)
    for i in 0..<total {
        let t = Double(i) / sr
        let on = (t < 0.4) || (t >= 0.6 && t < 1.0)          // Indian ringback cadence
        p[i] = on ? Float(0.35 * sin(2 * Double.pi * 400 * t)) : 0
    }
    return buf
}

// MARK: - Local ringback tone (used when the network sends "ringing" without audio)

final class RingTone {
    private let engine = AVAudioEngine()
    private let player = AVAudioPlayerNode()
    private var running = false

    func start(speaker: Bool) {
        guard !running else { return }
        let s = AVAudioSession.sharedInstance()
        try? s.setCategory(.playAndRecord, mode: .voiceChat, options: [.allowBluetoothHFP])
        try? s.setActive(true)
        try? s.overrideOutputAudioPort(speaker ? .speaker : .none)

        guard let fmt = AVAudioFormat(standardFormatWithSampleRate: 16000, channels: 1),
              let buf = makeRingBuffer(fmt) else { return }
        engine.attach(player)
        engine.connect(player, to: engine.mainMixerNode, format: fmt)
        player.scheduleBuffer(buf, at: nil, options: .loops, completionHandler: nil)
        engine.prepare()
        do { try engine.start(); player.play(); running = true } catch { running = false }
    }

    func setSpeaker(_ on: Bool) {
        if running { try? AVAudioSession.sharedInstance().overrideOutputAudioPort(on ? .speaker : .none) }
    }

    func stop() {
        guard running else { return }
        running = false
        player.stop()
        engine.stop()
    }
}
