import Foundation

/// Uses the reported serving mode, never residual signal values from a previous connection.
enum SignalActivityMode: Equatable {
    case lte, lteCA, nsa, sa, noService, unknown

    init(networkType: String?, lteCarrierCount: Int?) {
        let raw = (networkType ?? "").uppercased().trimmingCharacters(in: .whitespacesAndNewlines)
        let words = raw.replacingOccurrences(of: "_", with: " ").replacingOccurrences(of: "-", with: " ")
        if words.contains("NO SERVICE") || words.contains("LIMITED SERVICE") || words == "NONE" {
            self = .noService
        } else if words.contains("NSA") || words == "ENDC" || words == "EN DC" {
            self = .nsa
        } else if words == "SA" || words.hasSuffix(" SA") {
            self = .sa
        } else if words.contains("LTE") || words == "4G" || words == "4G+" {
            self = (lteCarrierCount ?? 0) > 1 || words.contains("CA") || words == "LTE A"
                || words == "4G+" || words == "LTE+" ? .lteCA : .lte
        } else {
            self = .unknown
        }
    }

    var label: String {
        switch self {
        case .lte: "4G LTE"
        case .lteCA: "4G+"
        case .nsa: "5G NSA"
        case .sa: "5G SA"
        case .noService: "No service"
        case .unknown: "Mode unknown"
        }
    }
    var showsLTE: Bool { self == .lte || self == .lteCA || self == .nsa }
    var showsNR: Bool { self == .nsa || self == .sa }
}
