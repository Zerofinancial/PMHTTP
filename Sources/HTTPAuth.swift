//
//  HTTPAuth.swift
//  PMHTTP
//
//  Created by Evan Kimia on 1/16/17.
//  Copyright © 2017 Postmates. All rights reserved.
//

import Foundation


public protocol HTTPAuth {
    var headers: [String: String]? { get }
    
    func handleAuthFailure(task: HTTPManagerTask, completion: @escaping  (_ succeeded: Bool) -> Void)
    
    func authFailureMessage(response: HTTPURLResponse, body: Data, json: JSON?) -> String?
}

// WIP crappy and incomplete example OAuth2 implementation

public class HTTPStandardOAuth2Auth: HTTPAuth {
    public let username: String
    public let password: String
    public let accessTokenURL: URL
    public let clientID: String
    public let clientSecret: String
    public let grantType: String
    private var token: String?
    
    public init(accessTokenURL: URL, clientID: String, clientSecret: String,
                username: String, password: String,
                grantType: String, token: String? = nil) {
        self.accessTokenURL = accessTokenURL
        self.clientID = clientID
        self.clientSecret = clientSecret
        self.username = username
        self.password = password
        self.grantType = grantType
    }
    
    public var headers: [String: String]? {
        if let token = token {
            return ["Authorization": "Bearer \(token)"]
        } else {
            return nil
        }
    }
    
    public func handleAuthFailure(task: HTTPManagerTask, completion: @escaping  (_ succeeded: Bool) -> Void) {
        if token != nil {
            completion(true)
        } else {
            refreshToken() { token, error in
                completion(error != nil)
            }
        }
    }
    
    public func authFailureMessage(response: HTTPURLResponse, body: Data, json: JSON?) -> String? {
        return "unauthorized!"
    }

    private func refreshToken(completion: @escaping (_ token: String?, _ error: Error?) -> Void) {
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
                completion(self.token, nil)
            case let .error(_, error):
                completion(self.token, error)
            default:
                completion(self.token, nil)
            }
        })
    }
}
