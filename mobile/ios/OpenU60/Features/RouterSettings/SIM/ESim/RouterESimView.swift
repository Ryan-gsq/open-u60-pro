import SwiftUI
import UIKit

struct RouterESimView: View {
    @Bindable var viewModel: RouterESimViewModel
    @Environment(\.scenePhase) private var scenePhase
    @State private var isVisible = false
    @State private var adding = false
    @State private var addedSwitch: RouterESimProfile?

    private var otherProfiles: [RouterESimProfile] { viewModel.profiles.filter { !$0.isEnabled } }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                if !viewModel.hasLoaded && viewModel.profiles.isEmpty {
                    loadingCard
                } else {
                    if let message = viewModel.message {
                        ESimMessageCard(message: message, isError: viewModel.messageIsError,
                                        canRetry: !viewModel.blocksSwitching, retry: refresh)
                    }
                    if viewModel.download.state != "idle" {
                        Button { adding = true } label: {
                            CardView(padding: 16) {
                                HStack(spacing: 12) {
                                    Image(systemName: viewModel.download.isBusy ? "arrow.down.circle" : "simcard").font(.title2)
                                    VStack(alignment: .leading, spacing: 4) {
                                        Text(viewModel.download.progressText).font(.subheadline.weight(.semibold))
                                        Text("Tap to view progress and next steps").font(.caption).foregroundStyle(.secondary)
                                    }
                                    Spacer(minLength: 0)
                                    Image(systemName: "chevron.right").font(.caption)
                                }.foregroundStyle(.primary)
                            }
                        }.buttonStyle(.plain)
                    }
                    if viewModel.profiles.isEmpty {
                        if viewModel.message == nil && !viewModel.download.isBusy { emptyCard }
                    } else {
                        profilesContent
                    }
                    if viewModel.chip != .empty { ESimChipCard(chip: viewModel.chip) }
                }
            }
            .padding(16)
        }
        .background(Color(.systemGroupedBackground))
        .navigationTitle("eSIM Profiles")
        .navigationBarTitleDisplayMode(.inline)
        .refreshable { await viewModel.refresh() }
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                Button { viewModel.resetDownloadResult(); adding = true } label: { Image(systemName: "plus") }
                    .disabled(viewModel.blocksSwitching).accessibilityLabel("Add eSIM")
            }
            ToolbarItem(placement: .topBarTrailing) {
                Button(action: refresh) {
                    if viewModel.isLoading { ProgressView() }
                    else { Image(systemName: "arrow.clockwise") }
                }
                .disabled(viewModel.isLoading || viewModel.isSwitching || viewModel.operationInFlight)
                .accessibilityLabel(viewModel.download.isBusy ? "Refresh download status" : "Refresh profiles and connection")
            }
        }
        .sheet(isPresented: $adding, onDismiss: {
            if let profile = addedSwitch { addedSwitch = nil; viewModel.requestSwitch(to: profile) }
        }) {
            RouterESimAddView(viewModel: viewModel, switchAfterDismiss: { addedSwitch = $0 })
        }
        .task {
            isVisible = true
            await viewModel.refresh()
            if !Task.isCancelled && scenePhase == .active { viewModel.startMonitoring() }
        }
        .onDisappear { isVisible = false; viewModel.stopMonitoring() }
        .onChange(of: scenePhase) { _, phase in
            if phase == .active && isVisible { viewModel.startMonitoring() }
            else { viewModel.stopMonitoring() }
        }
        .confirmationDialog(
            viewModel.pendingDelete.map { "Delete \($0.displayName) permanently?" } ?? "Delete profile?",
            isPresented: Binding(get: { viewModel.pendingDelete != nil }, set: { if !$0 { viewModel.pendingDelete = nil } }),
            titleVisibility: .visible, presenting: viewModel.pendingDelete
        ) { profile in
            Button("Delete \(profile.displayName)", role: .destructive) { Task { await viewModel.confirmDelete(profile) } }
            Button("Cancel", role: .cancel) {}
        } message: { profile in
            Text("This can’t be undone. You’d need a new QR code from \(profile.provider.isEmpty ? profile.displayName : profile.provider) to get this eSIM back.")
        }
        .confirmationDialog(
            viewModel.pendingSwitch.map { "Switch to \($0.displayName)?" } ?? "Switch profile?",
            isPresented: Binding(get: { viewModel.pendingSwitch != nil },
                                 set: { if !$0 { viewModel.pendingSwitch = nil } }),
            titleVisibility: .visible,
            presenting: viewModel.pendingSwitch
        ) { profile in
            Button("Switch to \(profile.displayName)") { Task { await viewModel.confirmSwitch(to: profile) } }
            Button("Cancel", role: .cancel) {}
        } message: { profile in
            Text("The router disconnects from \(viewModel.enabledProfile?.displayName ?? "the current profile") and connects with \(profile.displayName). Internet is down for about a minute. Wi-Fi stays on.")
        }
    }

    private var profilesContent: some View {
        VStack(alignment: .leading, spacing: 20) {
            if let active = viewModel.enabledProfile {
                VStack(alignment: .leading, spacing: 10) {
                    sectionHeading("Active profile")
                    ESimProfileCard(profile: active, canSwitch: false, onSwitch: {})
                }
            }

            ESimConnectionCard(phase: viewModel.connectionPhase, target: viewModel.switchingTo,
                               operatorName: viewModel.operatorName, networkType: viewModel.networkType,
                               signalBars: viewModel.signalBars, note: viewModel.connectionNote,
                               checkConnection: refresh)

            if !otherProfiles.isEmpty {
                VStack(alignment: .leading, spacing: 10) {
                    HStack {
                        sectionHeading(viewModel.enabledProfile == nil ? "Profiles on this card" : "Other profiles")
                        Spacer()
                        Text("\(otherProfiles.count)")
                            .font(.caption.monospacedDigit())
                            .foregroundStyle(.secondary)
                    }
                    ForEach(otherProfiles) { profile in
                        ESimProfileCard(profile: profile, canSwitch: !viewModel.blocksSwitching) {
                            viewModel.requestSwitch(to: profile)
                        }
                        .contextMenu {
                            Button("Delete profile", systemImage: "trash", role: .destructive) { viewModel.requestDelete(profile) }.disabled(viewModel.blocksSwitching)
                        }
                        .accessibilityAction(named: "Delete profile") { viewModel.requestDelete(profile) }
                    }
                    Text("Touch and hold a stored profile to delete it.").font(.caption).foregroundStyle(.secondary)
                }
            }
            Button { viewModel.resetDownloadResult(); adding = true } label: {
                Label("Add eSIM", systemImage: "plus.circle.fill").frame(maxWidth: .infinity, minHeight: 32)
            }.buttonStyle(.bordered).disabled(viewModel.blocksSwitching)

            HStack(alignment: .top, spacing: 10) {
                Image(systemName: "clock.arrow.circlepath").foregroundStyle(.orange)
                VStack(alignment: .leading, spacing: 3) {
                    Text("Switching pauses internet").font(.subheadline.weight(.medium))
                    Text("About a minute offline. Your router’s Wi-Fi stays on.")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(12)
            .background(.orange.opacity(0.08), in: .rect(cornerRadius: 12))
        }
    }

    private func sectionHeading(_ title: String) -> some View {
        Text(title).font(.subheadline.weight(.semibold)).foregroundStyle(.secondary)
            .accessibilityAddTraits(.isHeader)
    }

    private var loadingCard: some View {
        CardView {
            HStack(spacing: 14) {
                ProgressView()
                VStack(alignment: .leading, spacing: 4) {
                    Text("Reading profiles").font(.headline)
                    Text("Checking the eSIM in your router…").font(.subheadline).foregroundStyle(.secondary)
                }
                Spacer(minLength: 0)
            }
            .padding(.vertical, 12)
        }
    }

    private var emptyCard: some View {
        CardView {
            VStack(spacing: 14) {
                Image(systemName: "simcard.2").font(.largeTitle).foregroundStyle(.secondary)
                    .padding(16).background(.secondary.opacity(0.08), in: .rect(cornerRadius: 16))
                Text("No profiles yet").font(.headline)
                Text("Add one with the QR code from your operator.")
                    .font(.subheadline).foregroundStyle(.secondary).multilineTextAlignment(.center)
                Button("Add eSIM") { viewModel.resetDownloadResult(); adding = true }.buttonStyle(.borderedProminent).tint(.teal).disabled(viewModel.blocksSwitching)
            }
            .frame(maxWidth: .infinity).padding(.vertical, 18)
        }
    }

    private func refresh() { Task { await viewModel.refresh() } }
}

private struct ESimProfileCard: View {
    let profile: RouterESimProfile
    let canSwitch: Bool
    let onSwitch: () -> Void

    private var subtitle: String {
        if !profile.provider.isEmpty && profile.provider.caseInsensitiveCompare(profile.displayName) != .orderedSame {
            return profile.provider
        }
        if !profile.name.isEmpty && profile.name.caseInsensitiveCompare(profile.displayName) != .orderedSame {
            return profile.name
        }
        return profile.isEnabled ? "Active on your eSIM card" : "Stored on your eSIM card"
    }

    var body: some View {
        Group {
            if profile.canEnable {
                Button(action: onSwitch) { content }.buttonStyle(.plain).disabled(!canSwitch)
                    .accessibilityHint("Switch profile. Internet pauses for about a minute; Wi-Fi stays on.")
            } else { content }
        }
        .background(profile.isEnabled ? Color.teal.opacity(0.08) : Color(.secondarySystemGroupedBackground),
                    in: .rect(cornerRadius: 16))
        .overlay {
            RoundedRectangle(cornerRadius: 16)
                .strokeBorder(profile.isEnabled ? .teal.opacity(0.35) : Color.primary.opacity(0.07), lineWidth: 1)
        }
    }

    private var content: some View {
        HStack(alignment: .center, spacing: 12) {
            Image(systemName: profile.isEnabled ? "simcard.fill" : "simcard")
                .font(.title2).foregroundStyle(profile.isEnabled ? .teal : .blue)
                .frame(width: 46, height: 50)
                .background((profile.isEnabled ? Color.teal : .blue).opacity(0.1), in: .rect(cornerRadius: 12))
            VStack(alignment: .leading, spacing: 5) {
                Text(profile.displayName.isEmpty ? "Unnamed profile" : profile.displayName)
                    .font(profile.isEnabled ? .title3.weight(.semibold) : .body.weight(.semibold))
                    .foregroundStyle(.primary).fixedSize(horizontal: false, vertical: true)
                Text(subtitle).font(.caption).foregroundStyle(.secondary)
                Text("Profile · …\(profile.iccid.suffix(4))")
                    .font(.caption2.monospacedDigit()).foregroundStyle(.tertiary)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            if profile.isEnabled {
                Label("Active", systemImage: "checkmark.circle.fill")
                    .font(.caption.weight(.semibold)).foregroundStyle(.teal)
            } else if profile.canEnable {
                Image(systemName: "arrow.triangle.2.circlepath")
                    .font(.body.weight(.medium)).foregroundStyle(canSwitch ? .blue : .secondary)
                    .frame(width: 34, height: 34)
                    .background(.blue.opacity(canSwitch ? 0.1 : 0.03), in: Circle())
                    .accessibilityHidden(true)
            } else {
                Label("Unavailable", systemImage: "lock.fill")
                    .font(.caption2).foregroundStyle(.secondary)
            }
        }
        .padding(14)
        .contentShape(.rect)
        .accessibilityElement(children: .combine)
    }
}

private struct ESimConnectionCard: View {
    let phase: RouterESimConnectionPhase
    let target: String?
    let operatorName: String
    let networkType: String
    let signalBars: Int
    let note: String?
    let checkConnection: () -> Void

    private var isProgress: Bool { phase.blocksSwitching }
    private var title: String {
        switch phase {
        case .checking: "Checking connection"
        case .switching: "Switching to \(target ?? "profile")"
        case .reloading: "Reloading SIM"
        case .registering: "Registering on network"
        case .connected: "Mobile internet connected"
        case .disconnected: "Mobile internet offline"
        case .waiting: "Still waiting for internet"
        case .unavailable: "Connection status unavailable"
        }
    }
    private var detail: String {
        if let note { return note }
        switch phase {
        case .switching, .reloading, .registering:
            return "Internet usually returns in about a minute. Wi-Fi stays on."
        case .waiting: return "The profile is active. First network registration can take longer."
        case .disconnected: return "Mobile data is not connected. Your router’s Wi-Fi stays on."
        case .checking: return "Reading live status from your router."
        case .unavailable: return "Refresh to check the router’s mobile data connection."
        case .connected:
            return [operatorName, networkType].filter { !$0.isEmpty }.joined(separator: " · ")
        }
    }

    var body: some View {
        CardView(padding: 14) {
            VStack(alignment: .leading, spacing: 12) {
                HStack(alignment: .top, spacing: 10) {
                    Group {
                        if isProgress || phase == .checking { ProgressView().controlSize(.small) }
                        else { Image(systemName: phase == .connected ? "checkmark.circle.fill" : "antenna.radiowaves.left.and.right.slash")
                                .foregroundStyle(phase == .connected ? .teal : .secondary) }
                    }.frame(width: 22, height: 22)
                    VStack(alignment: .leading, spacing: 4) {
                        Text(title).font(.subheadline.weight(.semibold))
                        if !detail.isEmpty { Text(detail).font(.caption).foregroundStyle(.secondary).textSelection(.enabled) }
                    }
                    Spacer(minLength: 0)
                    if phase == .connected {
                        Image(systemName: "cellularbars", variableValue: Double(signalBars) / 5)
                            .foregroundStyle(.teal).accessibilityLabel("Signal \(signalBars) of 5")
                    }
                }
                if target != nil && (isProgress || phase == .connected || phase == .waiting) {
                    VStack(alignment: .leading, spacing: 7) {
                        step("Switch profile", index: 0)
                        step("Reload SIM", index: 1)
                        step("Connect to network", index: 2)
                    }
                    .padding(.leading, 32)
                }
                if phase == .waiting || phase == .unavailable {
                    Button("Check again", action: checkConnection).font(.caption.weight(.semibold)).buttonStyle(.bordered)
                }
            }
        }
        .accessibilityElement(children: .contain)
    }

    private func step(_ label: String, index: Int) -> some View {
        let current = phase == .switching ? 0 : (phase == .reloading ? 1 : 2)
        let complete = phase == .connected || index < current
        return Label(label, systemImage: complete ? "checkmark.circle.fill" : (index == current ? "circle.inset.filled" : "circle"))
            .font(.caption).foregroundStyle(complete ? .teal : .secondary)
    }
}

private struct ESimMessageCard: View {
    let message: String
    let isError: Bool
    let canRetry: Bool
    let retry: () -> Void

    var body: some View {
        CardView(padding: 14) {
            VStack(alignment: .leading, spacing: 10) {
                Label(message.localizedCaseInsensitiveContains("busy") ? "Card is busy" : (isError ? "Couldn’t complete the request" : "Profile updated"),
                      systemImage: isError ? "exclamationmark.circle" : "checkmark.circle")
                    .font(.subheadline.weight(.semibold)).foregroundStyle(isError ? .orange : .teal)
                Text(message).font(.caption).foregroundStyle(.secondary).textSelection(.enabled)
                if isError { Button("Try again", action: retry).buttonStyle(.bordered).disabled(!canRetry) }
            }.frame(maxWidth: .infinity, alignment: .leading)
        }
    }
}

private struct ESimChipCard: View {
    let chip: RouterESimChip
    @Environment(\.scenePhase) private var scenePhase
    @State private var expanded = false
    @State private var revealed = false
    @State private var copied = false

    var body: some View {
        CardView(padding: 14) {
            VStack(alignment: .leading, spacing: 12) {
                Button { expanded.toggle() } label: {
                    HStack(spacing: 10) {
                        Image(systemName: "simcard.2").foregroundStyle(.blue)
                        VStack(alignment: .leading, spacing: 3) {
                            Text("eSIM card").font(.subheadline.weight(.semibold)).foregroundStyle(.primary)
                            Text("Card details & identifiers").font(.caption).foregroundStyle(.secondary)
                        }
                        Spacer()
                        Image(systemName: expanded ? "chevron.up" : "chevron.down").font(.caption.weight(.semibold)).foregroundStyle(.secondary)
                    }.frame(minHeight: 32).contentShape(.rect)
                }.buttonStyle(.plain).accessibilityValue(expanded ? "Expanded" : "Collapsed")
                if expanded {
                    Divider()
                    if !chip.firmware.isEmpty { LabeledContent("Firmware", value: chip.firmware).font(.caption) }
                    if let free = chip.freeMemoryBytes {
                        LabeledContent("Free memory", value: ByteCountFormatter.string(fromByteCount: Int64(max(0, free)), countStyle: .memory)).font(.caption)
                    }
                    if !chip.eid.isEmpty {
                        VStack(alignment: .leading, spacing: 6) {
                            HStack {
                                Label("EID", systemImage: "lock.shield").font(.caption).foregroundStyle(.secondary)
                                Spacer()
                                Button { revealed.toggle(); copied = false } label: {
                                    Image(systemName: revealed ? "eye.slash" : "eye").frame(minWidth: 44, minHeight: 44)
                                }.accessibilityLabel(revealed ? "Hide EID" : "Reveal EID")
                                if revealed {
                                    Button {
                                        UIPasteboard.general.string = chip.eid
                                        copied = true
                                    } label: {
                                        Image(systemName: copied ? "checkmark" : "doc.on.doc").frame(minWidth: 44, minHeight: 44)
                                    }.accessibilityLabel(copied ? "EID copied" : "Copy EID")
                                }
                            }
                            if revealed { Text(chip.eid).font(.caption.monospaced()).textSelection(.enabled).fixedSize(horizontal: false, vertical: true) }
                            else { Text("•••• •••• •••• …\(chip.eid.suffix(4))").font(.caption.monospaced()).foregroundStyle(.secondary) }
                        }
                    }
                }
            }
        }
        .onChange(of: scenePhase) { _, phase in if phase != .active { revealed = false; copied = false } }
        .onChange(of: expanded) { _, value in if !value { revealed = false; copied = false } }
    }
}
