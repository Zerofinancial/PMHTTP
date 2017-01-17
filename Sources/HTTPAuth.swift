//
//  HTTPAuth.swift
//  PMHTTP
//
//  Created by Evan Kimia on 1/16/17.
//  Copyright © 2017 Postmates. All rights reserved.
//

import Foundation

public class HTTPAuth {
    func generateRequest(urlRequest: URLRequest, completion: @escaping (_ processedRequest: URLRequest) -> Void) {
        preconditionFailure("This method must be overridden")
    }
    
    var authHeaderValue: String? {
        preconditionFailure("This method must be overridden")
    }
    
    func updateHeaders(forRequest request: URLRequest) -> URLRequest {
        return request
    }
}

public class HTTPStandardOAuth2Auth: HTTPAuth {
    public let username: String
    public let password: String
    public let accessTokenURL: URL
    public let clientID: String
    public let clientSecret: String
    public let grantType: String
    
    private var token: String?
    var retryBehavior: HTTPManagerRetryBehavior?
    
    public init(accessTokenURL: URL, clientID: String, clientSecret: String, username: String, password: String, grantType: String, retryBehavior: HTTPManagerRetryBehavior?, token: String? = nil) {
        self.accessTokenURL = accessTokenURL
        self.clientID = clientID
        self.clientSecret = clientSecret
        self.username = username
        self.password = password
        self.grantType = grantType
        self.retryBehavior = retryBehavior
    }
    
    override var authHeaderValue: String? {
        if let token = token {
            return "Bearer \(token)"
        } else {
            return nil
        }
    }
    
    override func generateRequest(urlRequest: URLRequest, completion: @escaping (_ processedRequest: URLRequest) -> Void) {
        func injectToken(token: String) -> URLRequest {
            var dict: [String: String] = [:]
            dict["Authorization"] = "Bearer \(token)"
            var mutableReq = urlRequest
            mutableReq.allHTTPHeaderFields = dict
            
            return mutableReq
        }
        if let token = token {
            completion(injectToken(token: token))
        } else {
            refreshToken() { token in
                completion(injectToken(token: token!))
            }
        }
    }
    
    override func updateHeaders(forRequest request: URLRequest) -> URLRequest {
        var mutableReq = request
        if let token = token {
            mutableReq.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        }
        
        return mutableReq
    }
    
    private func refreshToken(completion: @escaping (_ token: String?) -> Void) {
        // Let's get a token!
        let auth = clientID + ":" + clientSecret
        let aData = auth.data(using: .utf8)!
        let aVal = "Basic \(aData.base64EncodedString())"

        let task = HTTP.request(POST: accessTokenURL.absoluteString,
                                parameters: ["username": username, "password": password, "grant_type": grantType])

        task?.headerFields = ["Authorization" : aVal]
        task?.parseAsJSON()
            .performRequest(withCompletionQueue: .main, completion: { task, result in
            switch result {
            case let .success(_, payload):
                self.token = try! payload?.getStringOrNil("access_token")
                print("self.token \(self.token)")
                completion(self.token)
                
            default:
                print("error!")
                completion(self.token)
            }
        })
    }
}
