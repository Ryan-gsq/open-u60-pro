import SwiftUI
import UniformTypeIdentifiers

struct B1ESimManagementView: View {
    let controller: B1ESimController
    @State private var adding = false
    @State private var renaming: B1ESimProfile?
    @State private var removing: B1ESimProfile?
    @State private var exportDocument: B1ESimDocument?
    @State private var exportFilename = "b1-profile-metadata.json"
    @State private var exportType: UTType = .json
    @State private var exporting = false
    @State private var exportMessage: String?

    var body: some View {
        Group {
            Section("eSIM management") {
                if let card = controller.card {
                    LabeledContent("EID", value: card.eid).textSelection(.enabled)
                }
                if controller.phase == .opening || controller.phase == .busy { ProgressView("Working with the card…") }
                if let message = controller.message { Text(message).font(.footnote).foregroundStyle(.secondary) }
                if let warning = controller.journalWarning { Text(warning).font(.footnote).foregroundStyle(.orange) }
                if controller.phase == .disconnected { Text("Connect to your B1 to read its eSIM profiles.").font(.footnote) }
                Button("Refresh profile list", systemImage: "arrow.clockwise") { Task { await controller.refresh() } }
                    .disabled(!controller.canRefresh)
                Button("Add eSIM", systemImage: "plus") { adding = true }
                    .disabled(!controller.supports(.download) || controller.journalWarning != nil)
                Button("Export profile metadata", systemImage: "square.and.arrow.up") {
                    do { prepareExport(try controller.exportMetadata()) }
                    catch { exportMessage = "Connect and refresh profiles before exporting metadata." }
                }.disabled(!controller.canOperate)
                if let exportMessage { Text(exportMessage).font(.footnote).foregroundStyle(.secondary) }
            }

            Section("Installed profiles") {
                if controller.canOperate && controller.profiles.isEmpty {
                    Text("No profiles are installed on this card.").foregroundStyle(.secondary)
                }
                ForEach(controller.profiles) { profile in
                    VStack(alignment: .leading, spacing: 8) {
                        Text(profile.displayName).font(.headline)
                        Text(profile.iccid).font(.caption.monospaced()).textSelection(.enabled)
                        if let provider = profile.provider { Text(provider).font(.caption) }
                        Text(profile.state.rawValue.capitalized).font(.caption).foregroundStyle(.secondary)
                        Button(profile.state == .enabled ? "Already active" : "Use this profile") {
                            Task { await controller.enable(profile.iccid) }
                        }.disabled(!controller.supports(.enable) || profile.state == .enabled)
                        Button("Disable profile") { Task { await controller.disable(profile.iccid) } }
                            .disabled(!controller.supports(.disable) || profile.canDisable == false || profile.state == .disabled)
                        Button("Rename profile") { renaming = profile }.disabled(!controller.supports(.rename))
                        Button("Remove profile", role: .destructive) { removing = profile }
                            .disabled(!controller.supports(.delete) || profile.canDelete == false)
                        Button("Export transfer package") {
                            Task { if let artifact = await controller.exportTransfer(profile.iccid) { prepareExport(artifact) } }
                        }.disabled(!controller.supports(.exportTransfer))
                    }
                    .buttonStyle(.borderless)
                }
                Text("Metadata export contains profile details. Transfer-package export requires explicit support from the card adapter.")
                    .font(.footnote).foregroundStyle(.secondary)
            }

            if !controller.pendingNotifications.isEmpty {
                Section("Pending download notifications") {
                    Text("\(controller.notificationsForCard.count) pending for this card; \(controller.pendingNotifications.count) retained in total.")
                        .font(.footnote)
                    Text("Reconnect the matching card to complete server notifications. Installed profiles will not be downloaded again.")
                        .font(.footnote).foregroundStyle(.secondary)
                    Button("Complete pending notifications") { Task { await controller.retryNotifications() } }
                        .disabled(!controller.supports(.notify) || controller.notificationsForCard.isEmpty)
                }
            }
        }
        .sheet(isPresented: $adding) {
            B1AddESimSheet { request in Task { await controller.download(request) } }
        }
        .sheet(item: $renaming) { profile in
            B1RenameESimSheet(profile: profile) { name in Task { await controller.rename(profile.iccid, nickname: name) } }
        }
        .confirmationDialog("Remove eSIM profile?", isPresented: Binding(
            get: { removing != nil }, set: { if !$0 { removing = nil } }
        ), titleVisibility: .visible) {
            if let profile = removing {
                Button("Remove \(profile.displayName)", role: .destructive) {
                    removing = nil
                    Task { await controller.delete(profile.iccid) }
                }
            }
            Button("Cancel", role: .cancel) { removing = nil }
        } message: {
            Text("Removing a profile can interrupt router service. You may need a new activation code to install it again.")
        }
        .fileExporter(isPresented: $exporting, document: exportDocument, contentType: exportType,
                      defaultFilename: exportFilename) { result in
            exportDocument = nil
            if case .failure = result { exportMessage = "Export was canceled or could not be saved." }
        }
        .onChange(of: controller.card?.eid) {
            adding = false
            renaming = nil
            removing = nil
        }
    }

    private func prepareExport(_ artifact: B1ExportArtifact) {
        exportMessage = nil
        exportDocument = B1ESimDocument(data: artifact.data)
        exportFilename = artifact.filename
        exportType = artifact.isTransferPackage ? .data : .json
        exporting = true
    }
}

private struct B1ESimDocument: FileDocument {
    static var readableContentTypes: [UTType] { [.json, .data] }
    let data: Data
    init(data: Data) { self.data = data }
    init(configuration: ReadConfiguration) throws { data = configuration.file.regularFileContents ?? Data() }
    func fileWrapper(configuration: WriteConfiguration) throws -> FileWrapper { FileWrapper(regularFileWithContents: data) }
}

private struct B1AddESimSheet: View {
    let submit: (B1DownloadRequest) -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var activationCode = ""
    @State private var confirmationCode = ""
    @State private var errorMessage: String?

    var body: some View {
        NavigationStack {
            Form {
                TextField("LPA:1$ activation code", text: $activationCode, axis: .vertical)
                    .textInputAutocapitalization(.never).autocorrectionDisabled().privacySensitive()
                SecureField("Confirmation code (if required)", text: $confirmationCode)
                    .textInputAutocapitalization(.never).autocorrectionDisabled()
                Text("Provisioning credentials remain in memory and are excluded from profile exports.").font(.footnote)
                if let errorMessage { Text(errorMessage).foregroundStyle(.red) }
            }
            .navigationTitle("Add eSIM")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Download") {
                        do {
                            let request = try B1DownloadRequest(activationCode: activationCode, confirmationCode: confirmationCode)
                            activationCode = ""
                            confirmationCode = ""
                            submit(request)
                            dismiss()
                        } catch { errorMessage = (error as? B1ESimError)?.localizedDescription ?? "Invalid activation code." }
                    }.disabled(activationCode.isEmpty)
                }
            }
        }
    }
}

private struct B1RenameESimSheet: View {
    let profile: B1ESimProfile
    let submit: (String) -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var name: String

    init(profile: B1ESimProfile, submit: @escaping (String) -> Void) {
        self.profile = profile
        self.submit = submit
        _name = State(initialValue: profile.nickname ?? "")
    }
    var body: some View {
        NavigationStack {
            Form {
                Text(profile.iccid).font(.caption.monospaced())
                TextField("Nickname", text: $name)
            }
            .navigationTitle("Rename profile")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Save") { submit(name); dismiss() }.disabled(name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                }
            }
        }
    }
}
