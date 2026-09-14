import Foundation
import CryptoKit

enum HelperError: Error { case invalidRequest, unavailable, missingKey }

func readExact(_ n: Int) throws -> Data {
    var result = Data()
    while result.count < n {
        let part = try FileHandle.standardInput.read(upToCount: n - result.count) ?? Data()
        if part.isEmpty { throw HelperError.invalidRequest }
        result.append(part)
    }
    return result
}

@available(macOS 26.0, *)
func run() throws {
    var identity: SecureEnclave.MLDSA87.PrivateKey?
    var kem: SecureEnclave.MLKEM1024.PrivateKey?
    while true {
        let header = try readExact(4)
        let size = header.reduce(0) { ($0 << 8) | Int($1) }
        guard size > 0 && size <= 32768 else { throw HelperError.invalidRequest }
        let request = try readExact(size)
        let op = request[0]
        let body = Data(request.dropFirst())
        var response = Data([0])
        do {
            guard SecureEnclave.isAvailable else { throw HelperError.unavailable }
            switch op {
            case 1:
                guard body.isEmpty else { throw HelperError.invalidRequest }
                let key = try SecureEnclave.MLDSA87.PrivateKey()
                identity = key
                response.append(key.dataRepresentation)
            case 2:
                identity = try SecureEnclave.MLDSA87.PrivateKey(dataRepresentation: body)
            case 3:
                guard body.isEmpty, let key = identity else { throw HelperError.missingKey }
                response.append(key.publicKey.rawRepresentation)
            case 4:
                guard let key = identity, let count = body.first, body.count >= 1 + Int(count) else { throw HelperError.invalidRequest }
                let context = body.subdata(in: 1..<(1 + Int(count)))
                let message = body.dropFirst(1 + Int(count))
                response.append(try key.signature(for: message, context: context))
            case 5:
                guard body.isEmpty else { throw HelperError.invalidRequest }
                kem = try SecureEnclave.MLKEM1024.PrivateKey.generate()
            case 6:
                guard body.isEmpty, let key = kem else { throw HelperError.missingKey }
                response.append(key.publicKey.rawRepresentation)
            case 7:
                guard body.count == 1568, let key = kem else { throw HelperError.invalidRequest }
                defer { kem = nil }
                let secret = try key.decapsulate(body)
                response.append(secret.withUnsafeBytes { Data($0) })
            case 8:
                guard body.isEmpty else { throw HelperError.invalidRequest }
                kem = nil
            case 9:
                guard body.isEmpty else { throw HelperError.invalidRequest }
                // Probe each algorithm; platform availability alone is insufficient.
                _ = try SecureEnclave.MLDSA87.PrivateKey()
                _ = try SecureEnclave.MLKEM1024.PrivateKey.generate()
                response.append(Data("secure_enclave=true ml_dsa_87=true ml_kem_1024=true".utf8))
            default: throw HelperError.invalidRequest
            }
        } catch {
            response = Data([1])
            response.append(Data(String(describing: error).prefix(1024).utf8))
        }
        let n = UInt32(response.count)
        let prefix = Data([UInt8(n >> 24), UInt8((n >> 16) & 255), UInt8((n >> 8) & 255), UInt8(n & 255)])
        try FileHandle.standardOutput.write(contentsOf: prefix + response)
    }
}

do {
    if #available(macOS 26.0, *) { try run() }
    else { throw HelperError.unavailable }
} catch {
    // stdout is strictly framed; EOF terminates the helper and destroys handles.
    exit(1)
}
