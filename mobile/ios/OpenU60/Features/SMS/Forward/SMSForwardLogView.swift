import SwiftUI

struct SMSForwardLogView: View {
    @Bindable var viewModel: SMSForwardViewModel

    /// One shared formatter: building a `DateFormatter` costs more than formatting with one,
    /// and a per-row instance is rebuilt on every render pass.
    private static let timestampFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.dateStyle = .short
        formatter.timeStyle = .medium
        return formatter
    }()

    var body: some View {
        List {
            ForEach(Array(viewModel.log.enumerated()), id: \.element.id) { index, entry in
                VStack(alignment: .leading, spacing: 4) {
                    HStack {
                        Text(entry.sender)
                            .font(.headline)
                        Spacer()
                        if entry.pending {
                            // Held while the router had no link; the agent sends it on its own.
                            Label("Held, will retry", systemImage: "clock.arrow.circlepath")
                                .font(.caption)
                                .foregroundStyle(.orange)
                        } else {
                            Image(systemName: entry.success ? "checkmark.circle.fill" : "xmark.circle.fill")
                                .foregroundStyle(entry.success ? .green : .red)
                                .accessibilityLabel(entry.success ? "Forwarded" : "Failed")
                        }
                    }
                    Text("\(entry.ruleName) → \(entry.destinationType)")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    Text(entry.contentPreview)
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                    if let error = entry.error {
                        Text(error)
                            .font(.caption)
                            .foregroundStyle(entry.pending ? Color.secondary : Color.red)
                    }
                    Text(formatTimestamp(entry.timestamp))
                        .font(.caption2)
                        .foregroundStyle(.tertiary)
                }
                .padding(.vertical, 2)
                .swipeActions(edge: .trailing) {
                    // The agent refuses a manual retry of a held entry (it would send twice).
                    if !entry.success && !entry.pending {
                        Button {
                            Task { await viewModel.retryForward(index: index) }
                        } label: {
                            Label("Retry", systemImage: "arrow.clockwise")
                        }
                        .tint(.orange)
                    }
                }
            }
        }
        .navigationTitle("Forward Log")
        .toolbar {
            Button("Clear") {
                Task { await viewModel.clearLog() }
            }
        }
        .overlay {
            if viewModel.log.isEmpty && !viewModel.isLoading {
                ContentUnavailableView("No Log Entries", systemImage: "doc.text",
                                       description: Text("Forwarded messages will appear here"))
            }
        }
        .task { await viewModel.fetchLog() }
    }

    private func formatTimestamp(_ ts: Int) -> String {
        Self.timestampFormatter.string(from: Date(timeIntervalSince1970: TimeInterval(ts)))
    }
}
