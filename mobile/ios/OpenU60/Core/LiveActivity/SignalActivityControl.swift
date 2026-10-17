import SwiftUI

struct SignalActivityControl: View {
    @Environment(SignalActivityManager.self) private var manager
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Label("Live signal", systemImage: "antenna.radiowaves.left.and.right")
                    .font(.headline)
                Spacer()
                if manager.isBusy { ProgressView() }
                Button(manager.activity == nil ? "Start" : "Stop") {
                    Task {
                        if manager.activity == nil { await manager.start() }
                        else { await manager.stop() }
                    }
                }
                .buttonStyle(.bordered)
                .disabled(manager.isBusy)
                .accessibilityIdentifier("live-signal-toggle")
            }
            Text(manager.message).font(.caption).foregroundStyle(.secondary)
            if let error = manager.errorMessage {
                Text(error).font(.caption).foregroundStyle(.orange)
                if manager.activity != nil {
                    Button("Retry") { Task { await manager.resume() } }
                        .font(.caption)
                }
            }
            if let sampled = manager.displayedSampleAt {
                HStack {
                    Text(manager.isStale ? "Phone sample · Stale" : "Phone sample")
                    Text(sampled, style: .time)
                }
                .font(.caption2)
                .foregroundStyle(manager.isStale ? Color.orange : Color.secondary)
            }
            if let accepted = manager.lastAcceptedAt {
                Text("Apple accepted an update \(accepted, style: .relative) ago")
                    .font(.caption2).foregroundStyle(.secondary)
            }
        }
        .padding()
        .background(Color(.secondarySystemGroupedBackground), in: RoundedRectangle(cornerRadius: 20))
        .task(id: manager.activity?.id) {
            guard manager.activity != nil else { return }
            while !Task.isCancelled {
                await manager.refreshStatus()
                do { try await Task.sleep(for: .seconds(15)) } catch { return }
            }
        }
    }
}
