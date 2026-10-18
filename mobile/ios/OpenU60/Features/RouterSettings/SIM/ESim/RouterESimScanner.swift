import SwiftUI
import AVFoundation
import VisionKit
import Vision

struct RouterESimScanner: UIViewControllerRepresentable {
    let onCode: (String) -> Void

    func makeUIViewController(context: Context) -> ESimScannerController {
        ESimScannerController(onCode: onCode)
    }
    func updateUIViewController(_ controller: ESimScannerController, context: Context) {}
    static func dismantleUIViewController(_ controller: ESimScannerController, coordinator: ()) { controller.stop() }

    static func codes(in data: Data) async throws -> [String] {
        try await Task.detached(priority: .userInitiated) {
            let request = VNDetectBarcodesRequest()
            request.symbologies = [.qr]
            try VNImageRequestHandler(data: data).perform([request])
            return request.results?.compactMap(\.payloadStringValue) ?? []
        }.value
    }
}

final class ESimScannerController: UIViewController, DataScannerViewControllerDelegate, AVCaptureMetadataOutputObjectsDelegate {
    private let onCode: (String) -> Void
    private var scanner: DataScannerViewController?
    private let session = AVCaptureSession()
    private let captureQueue = DispatchQueue(label: "com.openu60.esim-camera")
    private var preview: AVCaptureVideoPreviewLayer?
    private var finished = false
    private var stopped = false
    private let instruction = UILabel()
    private let frameView = UIView()
    private let torchButton = UIButton(type: .system)

    init(onCode: @escaping (String) -> Void) { self.onCode = onCode; super.init(nibName: nil, bundle: nil) }
    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .black
        instruction.text = "Place the operator’s eSIM QR code inside the frame"
        instruction.numberOfLines = 0
        instruction.textAlignment = .center
        instruction.textColor = .white
        instruction.font = .preferredFont(forTextStyle: .body)
        instruction.adjustsFontForContentSizeCategory = true
        instruction.backgroundColor = UIColor.black.withAlphaComponent(0.6)
        instruction.layer.cornerRadius = 12
        instruction.clipsToBounds = true
        frameView.layer.borderWidth = 2
        frameView.layer.borderColor = UIColor.white.cgColor
        frameView.layer.cornerRadius = 24
        frameView.isUserInteractionEnabled = false
        torchButton.setImage(UIImage(systemName: "flashlight.off.fill"), for: .normal)
        torchButton.tintColor = .white
        torchButton.backgroundColor = UIColor.black.withAlphaComponent(0.65)
        torchButton.layer.cornerRadius = 26
        torchButton.accessibilityLabel = "Turn flashlight on"
        torchButton.addTarget(self, action: #selector(toggleTorch), for: .touchUpInside)
        [frameView, instruction, torchButton].forEach { $0.translatesAutoresizingMaskIntoConstraints = false; view.addSubview($0) }
        NSLayoutConstraint.activate([
            frameView.centerXAnchor.constraint(equalTo: view.centerXAnchor), frameView.centerYAnchor.constraint(equalTo: view.centerYAnchor),
            frameView.widthAnchor.constraint(equalTo: view.widthAnchor, multiplier: 0.72), frameView.heightAnchor.constraint(equalTo: frameView.widthAnchor),
            instruction.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 24), instruction.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -24),
            instruction.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor, constant: 24), instruction.heightAnchor.constraint(greaterThanOrEqualToConstant: 72),
            torchButton.centerXAnchor.constraint(equalTo: view.centerXAnchor), torchButton.bottomAnchor.constraint(equalTo: view.safeAreaLayoutGuide.bottomAnchor, constant: -24),
            torchButton.widthAnchor.constraint(equalToConstant: 52), torchButton.heightAnchor.constraint(equalToConstant: 52)
        ])
        Task { @MainActor [weak self] in
            let allowed = await AVCaptureDevice.requestAccess(for: .video)
            guard let self, !self.stopped else { return }
            if allowed { self.configure() }
            else {
                self.instruction.text = "Camera access is off. Allow it in Settings, or close this scanner to choose a photo or enter a code."
                self.frameView.isHidden = true
                self.torchButton.isHidden = true
            }
        }
    }

    override func viewDidLayoutSubviews() { super.viewDidLayoutSubviews(); preview?.frame = view.bounds }
    override func viewDidDisappear(_ animated: Bool) { super.viewDidDisappear(animated); stop() }

    private func configure() {
        if DataScannerViewController.isSupported && DataScannerViewController.isAvailable {
            let child = DataScannerViewController(recognizedDataTypes: [.barcode(symbologies: [.qr])], qualityLevel: .balanced,
                recognizesMultipleItems: false, isHighFrameRateTrackingEnabled: false, isPinchToZoomEnabled: true,
                isGuidanceEnabled: true, isHighlightingEnabled: true)
            child.delegate = self
            addChild(child)
            child.view.frame = view.bounds
            child.view.autoresizingMask = [.flexibleWidth, .flexibleHeight]
            view.insertSubview(child.view, at: 0)
            child.didMove(toParent: self)
            scanner = child
            do { try child.startScanning() }
            catch { child.willMove(toParent: nil); child.view.removeFromSuperview(); child.removeFromParent(); scanner = nil; configureFallback() }
        } else { configureFallback() }
        torchButton.isHidden = AVCaptureDevice.default(for: .video)?.hasTorch != true
    }

    private func configureFallback() {
        guard let device = AVCaptureDevice.default(for: .video), let input = try? AVCaptureDeviceInput(device: device), session.canAddInput(input) else {
            instruction.text = "Camera unavailable. Close the scanner to choose a photo or enter a code."
            return
        }
        session.addInput(input)
        let output = AVCaptureMetadataOutput()
        guard session.canAddOutput(output) else { return }
        session.addOutput(output)
        output.setMetadataObjectsDelegate(self, queue: .main)
        output.metadataObjectTypes = [.qr]
        let layer = AVCaptureVideoPreviewLayer(session: session)
        layer.videoGravity = .resizeAspectFill
        layer.frame = view.bounds
        view.layer.insertSublayer(layer, at: 0)
        preview = layer
        let session = session
        captureQueue.async { session.startRunning() }
    }

    func stop() {
        guard !stopped else { return }
        stopped = true
        scanner?.stopScanning()
        setTorch(false)
        let session = session
        captureQueue.async { if session.isRunning { session.stopRunning() } }
    }

    @objc private func toggleTorch() {
        let on = AVCaptureDevice.default(for: .video)?.isTorchActive != true
        setTorch(on)
        torchButton.setImage(UIImage(systemName: on ? "flashlight.on.fill" : "flashlight.off.fill"), for: .normal)
        torchButton.accessibilityLabel = on ? "Turn flashlight off" : "Turn flashlight on"
    }
    private func setTorch(_ on: Bool) {
        guard let device = AVCaptureDevice.default(for: .video), device.hasTorch else { return }
        do { try device.lockForConfiguration(); defer { device.unlockForConfiguration() }; device.torchMode = on ? .on : .off } catch {}
    }
    private func found(_ value: String) {
        guard !finished else { return }
        guard let code = RouterESimActivationCode.parse(value) else { instruction.text = RouterESimActivationCode.invalidMessage; return }
        finished = true
        stop()
        UINotificationFeedbackGenerator().notificationOccurred(.success)
        onCode(code.value)
    }
    func dataScanner(_ dataScanner: DataScannerViewController, didAdd addedItems: [RecognizedItem], allItems: [RecognizedItem]) {
        for item in addedItems { if case .barcode(let barcode) = item, let value = barcode.payloadStringValue { found(value) } }
    }
    func dataScanner(_ dataScanner: DataScannerViewController, didTapOn item: RecognizedItem) {
        if case .barcode(let barcode) = item, let value = barcode.payloadStringValue { found(value) }
    }
    func metadataOutput(_ output: AVCaptureMetadataOutput, didOutput metadataObjects: [AVMetadataObject], from connection: AVCaptureConnection) {
        for case let barcode as AVMetadataMachineReadableCodeObject in metadataObjects { if let value = barcode.stringValue { found(value) } }
    }
}
