//
//  ContentView.swift
//  ONU CALL
//
import SwiftUI
import Combine
import AVFoundation

// MARK: - Registration state

final class AppState: ObservableObject {
    enum Reg { case checking, unregistered, registered, unreachable }

    @Published var reg: Reg = .checking
    @Published var line: String = UserDefaults.standard.string(forKey: "line") ?? ""
    @Published var masked = ""
    @Published var otpSent = false
    @Published var busy = false
    @Published var message = ""
    private var cookie = ""

    static func ensureDeviceName() {
        let d = UserDefaults.standard
        if (d.string(forKey: "deviceName") ?? "").isEmpty {
            let id = String(UUID().uuidString.replacingOccurrences(of: "-", with: "").prefix(6))
            d.set("ONU-iPhone-" + id, forKey: "deviceName")
        }
    }

    private var router: String { UserDefaults.standard.string(forKey: "router") ?? "192.168.29.1" }
    private var device: String { UserDefaults.standard.string(forKey: "deviceName") ?? "" }

    func refresh() {
        reg = .checking
        message = ""
        Registrar.check(router: router, device: device) { [weak self] r in
            DispatchQueue.main.async {
                guard let self = self else { return }
                switch r {
                case .registered(let line):
                    self.line = line
                    UserDefaults.standard.set(line, forKey: "line")
                    self.reg = .registered
                case .unregistered:
                    self.reg = .unregistered
                case .failed:
                    self.reg = .unreachable
                    self.message = "Can't reach your JioFiber router. Connect to your JioFiber Wi-Fi, allow Local Network access, then try again."
                }
            }
        }
    }

    func sendOTP() {
        busy = true
        message = ""
        Registrar.sendOTP(router: router, device: device) { [weak self] r in
            DispatchQueue.main.async {
                guard let self = self else { return }
                self.busy = false
                switch r {
                case .success(let t):
                    self.masked = t.masked
                    self.cookie = t.cookie
                    self.otpSent = true
                case .failure(let e):
                    self.message = e.localizedDescription
                }
            }
        }
    }

    func verify(_ otp: String) {
        busy = true
        message = ""
        Registrar.verify(router: router, otp: otp, cookie: cookie) { [weak self] ok in
            DispatchQueue.main.async {
                guard let self = self else { return }
                self.busy = false
                if ok {
                    self.busy = true
                    Registrar.check(router: self.router, device: self.device) { [weak self] r in
                        DispatchQueue.main.async {
                            guard let self = self else { return }
                            self.busy = false
                            if case .registered(let line) = r {
                                self.line = line
                                UserDefaults.standard.set(line, forKey: "line")
                                self.otpSent = false
                                self.reg = .registered
                            } else {
                                self.message = "That code didn't work. Check it and try again."
                            }
                        }
                    }
                } else {
                    self.message = "That code didn't work. Check it and try again."
                }
            }
        }
    }
}

// MARK: - Call model

final class CallModel: ObservableObject {
    @Published var lines: [String] = []
    @Published var status = "Ready"
    @Published var active = false
    @Published var muted = false
    @Published var speaker = false
    @Published var dialed = ""
    var onNeedsRegistration: (() -> Void)?
    private var phone: JioPhone?

    func call(number: String, hostname: String, router: String) {
        guard !active else { return }
        lines.removeAll()
        status = "Calling…"
        dialed = number
        muted = false
        speaker = false
        active = true
        let p = JioPhone()
        p.onLog = { [weak self] s in self?.lines.append(s) }
        p.onStatus = { [weak self] s in self?.status = s }
        p.onNeedsRegistration = { [weak self] in self?.onNeedsRegistration?() }
        p.onFinished = { [weak self] in
            guard let self = self else { return }
            self.active = false
            self.phone = nil
            self.muted = false
            self.speaker = false
        }
        phone = p
        p.call(number: number, hostname: hostname, router: router)
    }

    func hangup() { phone?.hangup() }
    func toggleMute() { muted.toggle(); phone?.setMute(muted) }
    func toggleSpeaker() { speaker.toggle(); phone?.setSpeaker(speaker) }
}

// MARK: - Theme

private let bg = LinearGradient(
    colors: [Color(red: 0.04, green: 0.06, blue: 0.12), Color(red: 0.07, green: 0.12, blue: 0.22)],
    startPoint: .top, endPoint: .bottom)
private let accent = Color(red: 0.18, green: 0.80, blue: 0.62)

private struct PrimaryButton: View {
    let title: String
    var enabled = true
    let action: () -> Void
    var body: some View {
        Button(action: action) {
            Text(title).font(.headline).foregroundColor(.black)
                .frame(maxWidth: .infinity).padding(.vertical, 15)
                .background(enabled ? accent : Color.gray.opacity(0.4))
                .clipShape(Capsule())
        }
        .disabled(!enabled)
    }
}

// MARK: - Root

struct ContentView: View {
    @StateObject private var model = CallModel()
    @StateObject private var app = AppState()
    @State private var number = ""
    @State private var showSettings = false
    @AppStorage("deviceName") private var deviceName = ""
    @AppStorage("router") private var router = "192.168.29.1"

    init() { AppState.ensureDeviceName() }

    var body: some View {
        ZStack {
            bg.ignoresSafeArea()
            if model.active {
                CallScreen(model: model)
            } else if app.reg == .registered {
                DialScreen(number: $number, model: model, app: app, showSettings: $showSettings,
                           deviceName: deviceName, router: router)
            } else {
                SetupScreen(app: app, showSettings: $showSettings)
            }
        }
        .preferredColorScheme(.dark)
        .sheet(isPresented: $showSettings) {
            SettingsSheet(app: app, lines: model.lines)
        }
        .onAppear {
            AVCaptureDevice.requestAccess(for: .audio) { _ in }
            model.onNeedsRegistration = {
                app.otpSent = false
                app.reg = .unregistered
            }
            app.refresh()
        }
        .onReceive(NotificationCenter.default.publisher(for: UIApplication.didBecomeActiveNotification)) { _ in
            if app.reg != .registered && !model.active { app.refresh() }
        }
    }
}

// MARK: - Setup / OTP

struct SetupScreen: View {
    @ObservedObject var app: AppState
    @Binding var showSettings: Bool
    @State private var otp = ""

    var body: some View {
        VStack(spacing: 18) {
            HStack {
                Spacer()
                Button { showSettings = true } label: {
                    Image(systemName: "gearshape.fill").font(.title3).foregroundColor(.white.opacity(0.7))
                }
            }
            .padding(.horizontal, 24).padding(.top, 12)

            Spacer()

            Text("ONU CALL")
                .font(.system(size: 30, weight: .bold)).tracking(4).foregroundColor(accent)

            switch app.reg {
            case .checking:
                ProgressView().tint(.white).padding(.top, 8)
                Text("Looking for your router…").foregroundColor(.white.opacity(0.7))

            case .unreachable:
                Text(app.message)
                    .multilineTextAlignment(.center).foregroundColor(.white.opacity(0.8))
                    .padding(.horizontal, 32)
                PrimaryButton(title: "Try again") { app.refresh() }.padding(.horizontal, 32)

            default:
                if !app.otpSent {
                    Text("Connect this phone to your JioFiber line.\nWe'll send a one-time code (OTP) to the mobile number linked to it.")
                        .multilineTextAlignment(.center).foregroundColor(.white.opacity(0.8))
                        .padding(.horizontal, 32)
                    PrimaryButton(title: app.busy ? "Sending…" : "Send OTP", enabled: !app.busy) {
                        app.sendOTP()
                    }
                    .padding(.horizontal, 32)
                } else {
                    Text(app.masked.isEmpty ? "Enter the code we sent you."
                                            : "Code sent to \(app.masked)")
                        .foregroundColor(.white.opacity(0.85))
                    TextField("OTP", text: $otp)
                        .keyboardType(.numberPad)
                        .textContentType(.oneTimeCode)
                        .multilineTextAlignment(.center)
                        .font(.system(size: 34, weight: .medium, design: .rounded)).monospacedDigit()
                        .padding(12)
                        .background(Color.white.opacity(0.09))
                        .clipShape(RoundedRectangle(cornerRadius: 14))
                        .padding(.horizontal, 60)
                        .onReceive(Just(otp)) { v in
                            let clean = String(v.filter { $0.isNumber }.prefix(8))
                            if clean != v { otp = clean }
                        }
                    PrimaryButton(title: app.busy ? "Checking…" : "Verify", enabled: otp.count >= 4 && !app.busy) {
                        app.verify(otp)
                    }
                    .padding(.horizontal, 32)
                    Button("Send a new code") { otp = ""; app.sendOTP() }
                        .font(.footnote).foregroundColor(.white.opacity(0.6))
                        .disabled(app.busy)
                }
                if !app.message.isEmpty {
                    Text(app.message).font(.footnote).foregroundColor(.red.opacity(0.9))
                        .multilineTextAlignment(.center).padding(.horizontal, 32)
                }
            }

            Spacer()
            Spacer()
        }
    }
}

// MARK: - Dial screen

struct DialScreen: View {
    @Binding var number: String
    @ObservedObject var model: CallModel
    @ObservedObject var app: AppState
    @Binding var showSettings: Bool
    let deviceName: String
    let router: String

    private let rows = [["1", "2", "3"], ["4", "5", "6"], ["7", "8", "9"]]

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text("ONU CALL")
                        .font(.system(size: 18, weight: .bold)).tracking(3).foregroundColor(accent)
                    if !app.line.isEmpty {
                        Text(app.line).font(.caption).foregroundColor(.white.opacity(0.55))
                    }
                }
                Spacer()
                Button { showSettings = true } label: {
                    Image(systemName: "gearshape.fill").font(.title3).foregroundColor(.white.opacity(0.7))
                }
            }
            .padding(.horizontal, 24).padding(.top, 12)

            Spacer()

            VStack(spacing: 6) {
                Text(number.isEmpty ? " " : number)
                    .font(.system(size: 38, weight: .light, design: .rounded)).monospacedDigit()
                    .lineLimit(1).minimumScaleFactor(0.5).frame(height: 50)
                Text(model.status == "Ready" || model.status.isEmpty ? " " : model.status)
                    .font(.footnote).foregroundColor(.white.opacity(0.6))
            }
            .padding(.horizontal, 24)

            Spacer()

            VStack(spacing: 16) {
                ForEach(rows, id: \.self) { row in
                    HStack(spacing: 22) { ForEach(row, id: \.self) { k in key(k) } }
                }
                HStack(spacing: 22) {
                    Color.clear.frame(width: 78, height: 78)
                    key("0")
                    Button { if !number.isEmpty { number.removeLast() } } label: {
                        Image(systemName: "delete.left")
                            .font(.title2).foregroundColor(.white.opacity(number.isEmpty ? 0.2 : 0.8))
                            .frame(width: 78, height: 78)
                    }
                }
            }

            Button {
                model.call(number: number, hostname: deviceName, router: router)
            } label: {
                Image(systemName: "phone.fill")
                    .font(.system(size: 28)).foregroundColor(.white)
                    .frame(width: 78, height: 78)
                    .background(number.count >= 6 ? accent : Color.gray.opacity(0.35))
                    .clipShape(Circle())
            }
            .disabled(number.count < 6)
            .padding(.top, 22).padding(.bottom, 28)
        }
    }

    private func key(_ k: String) -> some View {
        Button { if number.count < 15 { number.append(k) } } label: {
            Text(k)
                .font(.system(size: 32, weight: .regular, design: .rounded)).foregroundColor(.white)
                .frame(width: 78, height: 78)
                .background(Color.white.opacity(0.09)).clipShape(Circle())
        }
    }
}

// MARK: - Call screen

struct CallScreen: View {
    @ObservedObject var model: CallModel

    var body: some View {
        VStack {
            Spacer().frame(height: 70)
            Image(systemName: "person.fill")
                .font(.system(size: 44)).foregroundColor(.white.opacity(0.85))
                .frame(width: 100, height: 100)
                .background(Color.white.opacity(0.1)).clipShape(Circle())
            Text(model.dialed)
                .font(.system(size: 32, weight: .light, design: .rounded)).monospacedDigit()
                .padding(.top, 18)
            Text(model.status).font(.headline).foregroundColor(accent).padding(.top, 4)
            Text(model.lines.suffix(7).joined(separator: "\n"))
                .font(.system(size: 9, design: .monospaced)).foregroundColor(.white.opacity(0.5))
                .frame(maxWidth: .infinity, alignment: .leading).padding(.horizontal, 16).padding(.top, 12)
            Spacer()
            HStack(spacing: 40) {
                round("mic.slash.fill", "Mute", model.muted) { model.toggleMute() }
                round("speaker.wave.3.fill", "Speaker", model.speaker) { model.toggleSpeaker() }
            }
            Button { model.hangup() } label: {
                Image(systemName: "phone.down.fill")
                    .font(.system(size: 30)).foregroundColor(.white)
                    .frame(width: 80, height: 80).background(Color.red).clipShape(Circle())
            }
            .padding(.top, 36).padding(.bottom, 44)
        }
    }

    private func round(_ icon: String, _ label: String, _ on: Bool, _ action: @escaping () -> Void) -> some View {
        VStack(spacing: 6) {
            Button(action: action) {
                Image(systemName: icon)
                    .font(.system(size: 24)).foregroundColor(on ? .black : .white)
                    .frame(width: 68, height: 68)
                    .background(on ? Color.white : Color.white.opacity(0.12)).clipShape(Circle())
            }
            Text(label).font(.caption).foregroundColor(.white.opacity(0.7))
        }
    }
}

// MARK: - Settings

struct SettingsSheet: View {
    @ObservedObject var app: AppState
    let lines: [String]
    @AppStorage("deviceName") private var deviceName = ""
    @AppStorage("router") private var router = "192.168.29.1"
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationView {
            Form {
                Section(header: Text("Line")) {
                    HStack {
                        Text("Number")
                        Spacer()
                        Text(app.line.isEmpty ? "Not registered" : app.line).foregroundColor(.secondary)
                    }
                    Button("Check registration") { app.refresh(); dismiss() }
                }
                Section(header: Text("Connection"), footer: Text("Only change these if you know you need to.")) {
                    TextField("Router IP", text: $router).keyboardType(.numbersAndPunctuation)
                    TextField("Device name", text: $deviceName)
                        .textInputAutocapitalization(.never).autocorrectionDisabled()
                }
                Section(header: Text("Last call log")) {
                    Button("Copy log") { UIPasteboard.general.string = lines.joined(separator: "\n") }
                    if lines.isEmpty {
                        Text("Nothing yet").foregroundColor(.secondary)
                    } else {
                        ScrollView {
                            Text(lines.joined(separator: "\n"))
                                .font(.system(size: 10, design: .monospaced))
                                .frame(maxWidth: .infinity, alignment: .leading)
                        }
                        .frame(height: 220)
                    }
                }
            }
            .navigationTitle("Settings")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar { ToolbarItem(placement: .confirmationAction) { Button("Done") { dismiss() } } }
        }
    }
}
