//
//  NetworkManager.swift
//  SSLPinningDemo
//
//  Created by 郭景豪 on 2020/11/26.
//

import UIKit


final class NetworkManager: NSObject {
    
    static let sharedInstance = NetworkManager()
    
    let session: URLSession
    let delegate = SessionDelegate()

    private override init() {
        session = URLSession(configuration: URLSessionConfiguration.default, delegate: delegate, delegateQueue: nil)
        super.init()

    }
    
    fileprivate static func dictionaryToString(_ params:Dictionary<String,String>)->String {
        
        var string :String = ""
        
        for(key,value) in params {
            
            if key != "" {
                
                string += "\(key)=\(value)&"
                
            }
        }
        if string.count > 0 {
            string.remove(at: string.index(before: string.endIndex))
        }
        
        return string
    }
    
    @discardableResult func postSSL<T: Codable>(_ params : Dictionary<String, String>, urlString : String ,handler:@escaping (_ responseJSON : T)->(),failError:@escaping (_ failError : String)->()) -> URLSessionDataTask {
                  
         let url = URL(string: urlString)
         
         var request = URLRequest(url: url!)
         
         request.httpMethod = "POST"
         
        let paramsString = NetworkManager.dictionaryToString(params)
     
         request.httpBody = paramsString.data(using: String.Encoding.utf8)
     
         let dataTask = session.dataTask(with: request) { (data, response, error) in
      
             DispatchQueue.main.async(execute: { () -> Void in
                 
                 print(paramsString)
                guard data?.count ?? 0 > 0 else {
                     failError("no data")
                     return
                 }

                 do {
                     if let _ = try JSONSerialization.jsonObject(with: data!, options: []) as? NSDictionary {
                        let json = try JSONDecoder().decode(T.self, from: data ?? Data())
                         handler(json)
                     }else if let jsonString = String(data: data!, encoding: String.Encoding.utf8) {
                        failError(jsonString)
                    }
                 }catch _ {
                     if let jsonString = String(data: data!, encoding: String.Encoding.utf8) {
                         failError(jsonString)
                         print(jsonString)
                     }else{
                         failError("unknown")
                     }
                 }
             })
         }
         dataTask.resume()
         return dataTask
     }
    
}
class SessionDelegate: NSObject, URLSessionDelegate {
    
    let publicKeyPinner = PublicKeyPinner(hashes: ["nrchUevZ8rzeGaki7/k7G5E3Zd6+WKjEzfTXG3+En0U="])
    
    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        
        guard let trust = challenge.protectionSpace.serverTrust else {
            // 沒有憑證 默認執行
            completionHandler(.performDefaultHandling,nil)
            return
        }
        
        //public Key 方式
        if publicKeyPinner.validate(serverTrust: trust, domain: challenge.protectionSpace.host) {
            let certificate = URLCredential(trust: trust)
            completionHandler(.useCredential, certificate)
        } else {
            completionHandler(.cancelAuthenticationChallenge,nil)
        }
        
        //憑證認證方式
        certificatePolicy(trust: trust, challenge: challenge, completionHandler: completionHandler)
        
    }
    
    private func certificatePolicy(trust: SecTrust, challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        //1. 定義策略
        var policies = [SecPolicy]()
        // Set SSL policies for domain name check
        // 返回用于评估 SSL 证书链的策略对象
        // 第一个参数：server，如果传 true，则代表是在客户端上验证 SSL 服务器证书
        // 第二个参数：hostname，如果传非 nil，则代表会验证 hostname
        policies.append(SecPolicyCreateSSL(true, challenge.protectionSpace.host as CFString?))
        // set SSL policies for CRL or OCSP check
        policies.append(SecPolicyCreateRevocation(kSecRevocationUseAnyAvailableMethod)!)
        
        //2. 開始檢查憑證
        SecTrustSetPolicies(trust, policies as CFTypeRef);
        
        //3. 憑證是否正確邏輯
        if #available(iOS 12, macOS 10.14, tvOS 12, watchOS 5, *) {
            var error: CFError?
            let evaluationSucceeded = SecTrustEvaluateWithError(trust, &error)
            if evaluationSucceeded {
                // 評估通過
                checkCertificate(trust: trust, completionHandler: completionHandler)
            } else {
                // 評估不通過，error 包含了錯誤信息
                completionHandler(.cancelAuthenticationChallenge,nil)
            }
        } else {
            var result = SecTrustResultType.invalid
            let status = SecTrustEvaluate(trust, &result)
            if status == errSecSuccess && (result == .unspecified || result == .proceed) {
                // 評估通過
                checkCertificate(trust: trust, completionHandler: completionHandler)
            } else {
                // 評估不通過，result 和 status 包含了錯誤信息
                completionHandler(.cancelAuthenticationChallenge,nil)
            }
        }
    }
    
    private func checkCertificate(trust: SecTrust, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        //取得憑證
        let certificate = SecTrustGetCertificateAtIndex(trust, 0)
        let remoteCertificateData = SecCertificateCopyData(certificate!)

        let certificatePath = Bundle.main.path(forResource: "appstoreconnect.apple.com", ofType: "der")
        let certificatePathURL = URL(fileURLWithPath: certificatePath!)
        let certificateData = try! Data(contentsOf:certificatePathURL)

        if (certificateData == remoteCertificateData as Data) {
            let certificate = URLCredential(trust: trust)
            completionHandler(.useCredential, certificate)
        } else {
            completionHandler(.cancelAuthenticationChallenge, nil)
        }
        
    }
    
}

import CryptoSwift
import CommonCrypto

#if canImport(CryptoKit)
import CryptoKit
#endif

public final class PublicKeyPinner {
    /// Stored public key hashes
    private let hashes: [String]
    
    public init(hashes: [String]) {
        self.hashes = hashes
    }
    
    /// ASN1 header for our public key to re-create the subject public key info 公鑰的開頭固定格式
        private let rsa2048Asn1Header: [UInt8] = [
            0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
            0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00
        ]
    
    /// Validates an object used to evaluate trust's certificates by comparing their public key hashes
    /// to the known, trused key hashes stored in the app.
    /// - Parameter serverTrust: The object used to evaluate trust.
    /// - Parameter domain: The domain from where we expect our trust object to come from.
    public func validate(serverTrust: SecTrust, domain: String?) -> Bool {
        if let domain = domain {
            let policies = NSMutableArray()
            policies.add(SecPolicyCreateSSL(true, domain as CFString))
            SecTrustSetPolicies(serverTrust, policies)
            
            // Check if the trust is valid
            
            if #available(iOS 12, macOS 10.14, tvOS 12, watchOS 5, *) {
                var error: CFError?
                let evaluationSucceeded = SecTrustEvaluateWithError(serverTrust, &error)
                guard evaluationSucceeded else { return false }
            } else {
                var secResult = SecTrustResultType.invalid
                let status = SecTrustEvaluate(serverTrust, &secResult)
                guard status == errSecSuccess else { return false }
                
            }
            
            // For each certificate in the valid trust:
            for index in 0..<SecTrustGetCertificateCount(serverTrust) {
              // Get the public key data for the certificate at the current index of the loop.
              guard let certificate = SecTrustGetCertificateAtIndex(serverTrust, index),
                let publicKey = SecCertificateCopyPublicKey(certificate),
                let publicKeyData = SecKeyCopyExternalRepresentation(publicKey, nil) else {
                  return false
              }
              // Hash the key, and check it's validity.
              let keyHash = hash(data: (publicKeyData as NSData) as Data)
              if hashes.contains(keyHash) {
                // Success! This is our server!
                return true
              }
            }
        }
        return false
    }
    
    /// Creates a hash from the received data using the `sha256` algorithm.
    /// `Returns` the `base64` encoded representation of the hash.
    ///
    /// To replicate the output of the `openssl dgst -sha256` command, an array of specific bytes need to be appended to
    /// the beginning of the data to be hashed.
    /// - Parameter data: The data to be hashed.
    private func hash(data: Data) -> String {
        // Add the missing ASN1 header for public keys to re-create the subject public key info
        var keyWithHeader = Data(rsa2048Asn1Header)
        keyWithHeader.append(data)
        // Check if iOS 13 is available, and use CryptoKit's hasher 新的api
        if #available(iOS 13, *) {
            return Data(SHA256.hash(data: keyWithHeader)).base64EncodedString()
        } else {
            // Using CommonCrypto's CC_SHA256 method 舊的api
//            var hash = [UInt8](repeating: 0,  count: Int(CC_SHA256_DIGEST_LENGTH))
//            _ = keyWithHeader.withUnsafeBytes {
//                CC_SHA256($0.baseAddress!, CC_LONG(keyWithHeader.count), &hash)
//            }
//            return Data(hash).base64EncodedString()
            // Using CryptoSwift's Data.sha256() method 套件的api
            return keyWithHeader.sha256().base64EncodedString()
        }
    }
}

