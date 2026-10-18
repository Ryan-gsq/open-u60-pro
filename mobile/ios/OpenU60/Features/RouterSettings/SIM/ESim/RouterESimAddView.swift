import SwiftUI
import PhotosUI

struct RouterESimAddView: View {
    @Bindable var viewModel: RouterESimViewModel
    let switchAfterDismiss: (RouterESimProfile) -> Void
    @Environment(\.dismiss) private var dismiss
    @Environment(\.scenePhase) private var scenePhase
    @State private var code = ""
    @State private var confirmationCode = ""
    @State private var inputError: String?
    @State private var manual = false
    @State private var scanner = false
    @State private var photo: PhotosPickerItem?
    @State private var readingPhoto = false
    private var parsed: RouterESimActivationCode? { RouterESimActivationCode.parse(code) }
    private var showsProgress: Bool { !["idle", "cancelled"].contains(viewModel.download.state) }

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 20) {
                    if showsProgress || viewModel.operationInFlight { downloadContent } else { entryContent }
                }.padding(20)
            }
            .background(Color(.systemGroupedBackground))
            .navigationTitle("Add eSIM").navigationBarTitleDisplayMode(.inline)
            .toolbar { ToolbarItem(placement: .topBarTrailing) { Button(viewModel.download.isBusy ? "Close" : "Done") { clearSecrets(); dismiss() } } }
            .sheet(isPresented: $scanner) {
                NavigationStack {
                    RouterESimScanner { value in accept(value); scanner = false }
                        .ignoresSafeArea(edges: .bottom).navigationTitle("Scan eSIM QR code").navigationBarTitleDisplayMode(.inline)
                        .toolbar { ToolbarItem(placement: .topBarTrailing) { Button("Close") { scanner = false } } }
                }
            }
            .task { viewModel.startMonitoring() }
            .onChange(of: scenePhase) { _, phase in
                if phase == .active { viewModel.startMonitoring() }
                else { viewModel.stopMonitoring() }
            }
            .task(id: photo) {
                guard let selection = photo else { return }
                readingPhoto = true
                defer { readingPhoto = false; photo = nil }
                do {
                    guard let data = try await selection.loadTransferable(type: Data.self) else { throw CocoaError(.fileReadCorruptFile) }
                    let values = try await RouterESimScanner.codes(in: data)
                    guard !Task.isCancelled else { return }
                    let valid = Array(Set(values.filter { RouterESimActivationCode.parse($0) != nil }))
                    if valid.count == 1 { accept(valid[0]); UINotificationFeedbackGenerator().notificationOccurred(.success) }
                    else { inputError = valid.isEmpty ? RouterESimActivationCode.invalidMessage : "Choose a photo with one eSIM QR code." }
                } catch {
                    guard !Task.isCancelled else { return }
                    inputError = "Couldn’t read this photo. Choose another image or enter the code manually."
                }
            }
            .onChange(of: viewModel.download.state) { _, state in
                if state == "done" { clearSecrets() }
                if state == "cancelled" { viewModel.resetDownloadResult() }
            }
            .onDisappear { clearSecrets(); photo = nil }
            .privacySensitive()
        }
    }

    private var entryContent: some View {
        VStack(alignment: .leading, spacing: 20) {
            VStack(alignment: .leading, spacing: 10) {
                Image(systemName: "qrcode.viewfinder").font(.largeTitle).foregroundStyle(.teal)
                Text("Add a profile to your router").font(.title2.bold())
                Text("Use the eSIM QR code from your operator. You’ll review the profile before installing it.").font(.subheadline).foregroundStyle(.secondary)
            }
            CardView(padding: 16) {
                VStack(spacing: 12) {
                    Button { scanner = true } label: { Label("Scan QR code", systemImage: "camera.fill").frame(maxWidth: .infinity, minHeight: 30) }
                        .buttonStyle(.borderedProminent).tint(.teal)
                    PhotosPicker(selection: $photo, matching: .images) {
                        Label(readingPhoto ? "Reading photo…" : "Choose QR from Photos", systemImage: "photo").frame(maxWidth: .infinity, minHeight: 30)
                    }.buttonStyle(.bordered).disabled(readingPhoto)
                    Button { manual = true } label: { Label("Enter code manually", systemImage: "keyboard").frame(maxWidth: .infinity, minHeight: 30) }.buttonStyle(.borderless)
                }
            }
            if manual || !code.isEmpty {
                CardView(padding: 16) {
                    VStack(alignment: .leading, spacing: 12) {
                        Label("Activation code", systemImage: "lock.shield").font(.subheadline.weight(.semibold))
                        SecureField("LPA:1$…", text: $code).textInputAutocapitalization(.never).autocorrectionDisabled().textFieldStyle(.roundedBorder)
                            .onChange(of: code) { _, _ in inputError = nil; confirmationCode = "" }
                        if let parsed {
                            Label("Code ready", systemImage: "checkmark.circle.fill").font(.caption).foregroundStyle(.teal)
                            Text("From \(parsed.server)").font(.caption).foregroundStyle(.secondary)
                        }
                        if parsed?.needsConfirmationCode == true {
                            SecureField("Operator confirmation code", text: $confirmationCode).textInputAutocapitalization(.never).autocorrectionDisabled().textFieldStyle(.roundedBorder)
                            Text("Enter the separate confirmation code supplied by your operator (up to 64 characters).").font(.caption).foregroundStyle(.secondary)
                        }
                        Button("Read profile details") {
                            guard let parsed else { inputError = RouterESimActivationCode.invalidMessage; return }
                            guard !parsed.needsConfirmationCode || RouterESimActivationCode.validConfirmationCode(confirmationCode) else {
                                inputError = "Enter the confirmation code from your operator (up to 64 characters)."; return
                            }
                            Task { await viewModel.startDownload(code: parsed.value, confirmationCode: confirmationCode) }
                        }.buttonStyle(.borderedProminent).tint(.teal)
                            .disabled(code.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || viewModel.blocksSwitching || readingPhoto)
                    }
                }
            }
            if let inputError { Label(inputError, systemImage: "exclamationmark.circle").font(.subheadline).foregroundStyle(.orange) }
            if let note = viewModel.downloadNote { Text(note).font(.subheadline).foregroundStyle(.orange).textSelection(.enabled) }
            Label("Your router needs internet to download the profile. Keep its Wi-Fi connected. Downloads usually take 10–60 seconds.", systemImage: "wifi").font(.caption).foregroundStyle(.secondary)
            Label("Your activation code is private and single-use. It is sent only to your router and isn’t saved by OpenU60.", systemImage: "lock").font(.caption).foregroundStyle(.secondary)
        }
    }

    private var downloadContent: some View {
        CardView(padding: 20) {
            VStack(alignment: .leading, spacing: 18) {
                HStack(spacing: 14) {
                    if ["running", "cancelling"].contains(viewModel.download.state) || viewModel.operationInFlight { ProgressView().controlSize(.large) }
                    else { Image(systemName: viewModel.download.state == "confirm" ? "simcard" : (viewModel.download.state == "done" ? "checkmark.circle.fill" : "exclamationmark.circle")).font(.largeTitle).foregroundStyle(["done", "confirm"].contains(viewModel.download.state) ? .teal : .orange) }
                    Text(viewModel.download.progressText).font(.title3.weight(.semibold))
                }
                if viewModel.download.state == "confirm" {
                    Text("Install \(viewModel.download.displayName)?").font(.headline)
                    if let name = viewModel.download.name, name != viewModel.download.displayName { Text(name).font(.subheadline).foregroundStyle(.secondary) }
                    Text("The profile will be installed on your router’s eSIM and stay inactive until you switch to it. Confirm within 2 minutes.").font(.subheadline).foregroundStyle(.secondary)
                    Button("Install profile") { Task { await viewModel.confirmDownload() } }.buttonStyle(.borderedProminent).tint(.teal).disabled(viewModel.operationInFlight)
                } else if viewModel.download.state == "done" {
                    Text("Added to your router. Your current profile is still active.").font(.subheadline).foregroundStyle(.secondary)
                    if let profile = viewModel.profiles.first(where: { $0.iccid == viewModel.download.iccid }), profile.canEnable {
                        Button("Switch to it now") { switchAfterDismiss(profile); clearSecrets(); dismiss() }.buttonStyle(.borderedProminent).tint(.teal).disabled(viewModel.blocksSwitching)
                    } else {
                        Button("Refresh profiles") { Task { await viewModel.refresh() } }.disabled(viewModel.blocksSwitching)
                    }
                    Button("Later") { clearSecrets(); dismiss() }.buttonStyle(.bordered)
                } else if viewModel.download.state == "failed" {
                    Text(viewModel.download.error ?? "The operator couldn’t add this profile.").font(.subheadline).textSelection(.enabled)
                    Button("Try again") { viewModel.resetDownloadResult(); manual = true }.buttonStyle(.borderedProminent)
                } else {
                    Text(viewModel.download.step == "es10b_load_bound_profile_package" ? "Keep the router powered on. Installation can’t be cancelled at this stage." : "Keep your router connected to the internet. You can close this screen and return to check progress.").font(.subheadline).foregroundStyle(.secondary)
                }
                if let note = viewModel.downloadNote {
                    Text(note).font(.subheadline).foregroundStyle(.orange).textSelection(.enabled)
                    Button("Check status") { Task { await viewModel.retryDownloadStatus() } }.disabled(viewModel.operationInFlight)
                }
                if viewModel.download.canCancel {
                    Button("Cancel download", role: .destructive) { Task { await viewModel.cancelDownload() } }.buttonStyle(.bordered).disabled(viewModel.operationInFlight)
                }
            }.frame(maxWidth: .infinity, alignment: .leading)
        }
    }
    private func accept(_ value: String) {
        guard let parsed = RouterESimActivationCode.parse(value) else { inputError = RouterESimActivationCode.invalidMessage; return }
        code = parsed.value; confirmationCode = ""; inputError = nil; manual = true
    }
    private func clearSecrets() { code = ""; confirmationCode = "" }
}
