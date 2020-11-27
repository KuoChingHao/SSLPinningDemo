//
//  SSLPinningDemoTests.swift
//  SSLPinningDemoTests
//
//  Created by 郭景豪 on 2020/11/26.
//

import XCTest
@testable import SSLPinningDemo

class SSLPinningDemoTests: XCTestCase {

    override func setUpWithError() throws {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }

    override func tearDownWithError() throws {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }

    func testExample() throws {
        // This is an example of a functional test case.
        // Use XCTAssert and related functions to verify your tests produce the correct results.
    }

    func testPerformanceExample() throws {
        // This is an example of a performance test case.
        self.measure {
            // Put the code you want to measure the time of here.
        }
    }

    func test_network() throws {
        
        let expectation:XCTestExpectation? = self.expectation(description: "not receive results")

        class Model: Codable {
            
        }
        
        NetworkManager.sharedInstance.postSSL([:], urlString: "https://appstoreconnect.apple.com") { (data: Model) in
            print("success")
            XCTAssert(true)
            expectation?.fulfill()

        } failError: { (error) in
            print(error)
            XCTAssert(false)
            expectation?.fulfill()

        }
        self.waitForExpectations(timeout: 5, handler: nil)
        
    }
    
}
