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
        completion(urlRequest)
    }
}

public class HTTPStandardOAuth2Auth: HTTPAuth {
    public let username: String
    public let password: String
    public let accessTokenURL: URL
    public let clientID: String
    public let clientSecret: String
    public let credential: URLCredential
    
    private var token: String?
    
    init(accessTokenURL: URL, clientID: String, clientSecret: String,
         credential: URLCredential, username: String, password: String, token: String? = nil) {
        self.accessTokenURL = accessTokenURL
        self.clientID = clientID
        self.clientSecret = clientSecret
        self.username = username
        self.password = password
        self.credential = credential
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
            // Let's get a token!
            HTTP.request(POST: accessTokenURL.absoluteString,
                                           parameters: ["username": username, "password": password])
                .parseAsJSON()
                .performRequest(withCompletionQueue: .main, completion: { task, result in
                    switch result {
                    case let .success(_, payload):
                        self.token = try! payload?.getStringOrNil("token")
                        completion(injectToken(token: self.token!))
                    default:
                        print("error!")
                    }
            })
        }
    }
}
