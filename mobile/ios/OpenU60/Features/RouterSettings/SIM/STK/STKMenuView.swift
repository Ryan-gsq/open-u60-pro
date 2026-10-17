import SwiftUI

struct STKMenuView: View {
    @Bindable var viewModel: STKViewModel

    var body: some View {
        List {
            if let msg = viewModel.message {
                Section {
                    Text(msg)
                        .font(.subheadline)
                        .foregroundStyle(viewModel.messageIsError ? .red : .green)
                        .textSelection(.enabled)
                }
            }

            ussdSection

            if viewModel.showUssdResponse {
                ussdResponseSection
            }

            stkSection
        }
        .navigationTitle("SIM Services")
        .overlay {
            if viewModel.isLoading {
                ProgressView()
                    .padding()
                    .background(Color(.systemBackground).opacity(0.85), in: RoundedRectangle(cornerRadius: 8))
            }
        }
        .task { await viewModel.watchSTK() }
    }

    // MARK: - USSD

    private var ussdSection: some View {
        Section {
            HStack {
                TextField("USSD code (e.g. *100#)", text: $viewModel.ussdCode)
                    .keyboardType(.phonePad)
                    .autocorrectionDisabled()
                    .textInputAutocapitalization(.never)

                Button {
                    Task { await viewModel.sendUSSD() }
                } label: {
                    Image(systemName: "paperplane.fill")
                }
                .disabled(viewModel.ussdCode.isEmpty || viewModel.isLoading)
            }
        } header: {
            Text("USSD")
        } footer: {
            Text("Send carrier service codes to check balance, data plans, etc.")
        }
    }

    private var ussdResponseSection: some View {
        Section("Response") {
            Text(viewModel.ussdResponse.response.isEmpty
                 ? viewModel.ussdResponse.rawResponse
                 : viewModel.ussdResponse.response)
                .font(.body)
                .textSelection(.enabled)

            if viewModel.ussdResponse.sessionActive {
                HStack {
                    TextField("Reply", text: $viewModel.ussdReply)
                        .keyboardType(.phonePad)

                    Button {
                        Task { await viewModel.respondUSSD() }
                    } label: {
                        Image(systemName: "arrow.up.circle.fill")
                    }
                    .disabled(viewModel.ussdReply.isEmpty || viewModel.isLoading)
                }

                Button(role: .destructive) {
                    Task { await viewModel.cancelUSSD() }
                } label: {
                    Label("End Session", systemImage: "xmark.circle")
                }
            }
        }
    }

    // MARK: - STK

    private var stkSection: some View {
        Section {
            if !viewModel.stkReason.isEmpty {
                Text(viewModel.stkReason).foregroundStyle(.secondary)
            }
            if !viewModel.stkText.isEmpty {
                Text(viewModel.stkText).textSelection(.enabled)
            }
            ForEach(viewModel.stkMenu.items) { item in
                Button(item.label) {
                    Task { await viewModel.selectSTKItem(item) }
                }
                .disabled(viewModel.isLoading || viewModel.stkBusy)
            }
            if viewModel.stkType == "input" {
                if viewModel.stkYesNo {
                    HStack {
                        Button("Yes") { Task { await viewModel.respondSTK(yes: true) } }
                        Spacer()
                        Button("No") { Task { await viewModel.respondSTK(yes: false) } }
                    }
                } else {
                    Group {
                        if viewModel.stkHidden {
                            SecureField("SIM response", text: $viewModel.stkReply)
                        } else {
                            TextField("SIM response", text: $viewModel.stkReply)
                        }
                    }
                    .keyboardType(viewModel.stkDigitsOnly ? .phonePad : .default)
                    .autocorrectionDisabled()
                    .textInputAutocapitalization(.never)
                    Text("Enter \(viewModel.stkMin)–\(viewModel.stkMax) characters")
                        .font(.caption).foregroundStyle(.secondary)
                    Button("Send Response") { Task { await viewModel.respondSTK() } }
                }
            } else if viewModel.stkType == "display" {
                Button("Continue") { Task { await viewModel.respondSTK() } }
            }
            if !viewModel.stkRootMenu && viewModel.stkType != "status" {
                Button("Back") { Task { await viewModel.goBackSTK() } }
                Button("End SIM Session", role: .destructive) { Task { await viewModel.cancelSTK() } }
            }
            if viewModel.stkMenu.items.isEmpty && viewModel.stkType == "status" {
                Button("Reload SIM Menu") { Task { await viewModel.loadSTKMenu() } }
            }
        } header: {
            Text(viewModel.stkMenu.title.isEmpty ? "SIM Toolkit" : viewModel.stkMenu.title)
        } footer: {
            Text("Carrier-provided services from your SIM card")
        }
        .disabled(viewModel.isLoading || viewModel.stkBusy)
    }
}
