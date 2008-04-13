//
//  AppController.m
//  Endpointr
//
//  Copyright 2007, 2008 Jon Crosby. All rights reserved.
//  Created 11/10/07.
//
//  Permission is hereby granted, free of charge, to any person obtaining a copy
//  of this software and associated documentation files (the "Software"), to deal
//  in the Software without restriction, including without limitation the rights
//  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//  copies of the Software, and to permit persons to whom the Software is
//  furnished to do so, subject to the following conditions:
//
//  The above copyright notice and this permission notice shall be included in
//  all copies or substantial portions of the Software.
//
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
//  THE SOFTWARE.

// TODO: query string input in UI
// TODO: green/red indicators in UI
// TODO: show response codes for requests
// TODO: remember URL/token values from previous runs


#import "AppController.h"


@implementation AppController

- (void)awakeFromNib {
    [signatureBaseString alignLeft:nil];
    [header alignLeft:nil];
    [signatureBaseString setString:@""];
    [header setString:@""];
    [response setString:@""];
}

- (IBAction)getRequestTokenClicked:(id)sender {
    OAConsumer *consumer = [[OAConsumer alloc] initWithKey:[consumerKey stringValue]
                                                    secret:[consumerSecret stringValue]];
    NSURL *url = [NSURL URLWithString:[requestTokenURL stringValue]];
    id <OASignatureProviding> *signatureProvider = nil;
    
    if ([[[requestTokenSignatureMethod selectedItem] title] isEqualToString:@"PLAINTEXT"]) {
        signatureProvider = [[OAPlaintextSignatureProvider alloc] init];
    }
    
    OAMutableURLRequest *request = [[OAMutableURLRequest alloc] initWithURL:url
                                                                   consumer:consumer
                                                                      token:nil
                                                                      realm:nil
                                                          signatureProvider:signatureProvider];
    [request setHTTPMethod:[[requestTokenMethod selectedItem] title]];
    
    OADataFetcher *fetcher = [[OADataFetcher alloc] init];
    [fetcher fetchDataWithRequest:request
                         delegate:self
                didFinishSelector:@selector(tokenTicket:didFinishWithData:)
                  didFailSelector:@selector(tokenTicket:didFailWithError:)];
    [signatureBaseString setString:[request _signatureBaseString]];
    NSString *headerContent = [NSString stringWithFormat:@"Authorization: %@",
                               [request valueForHTTPHeaderField:@"Authorization"]];
    [header setString:headerContent];
}

- (void)tokenTicket:(OAServiceTicket *)ticket didFinishWithData:(NSData *)data {
    NSString *responseBody;
    
    if (data != nil) {
        responseBody = [[NSString alloc] initWithData:data
                                             encoding:NSUTF8StringEncoding];
    } else {
        responseBody = @"";
    }
    
    if (ticket.didSucceed) {
        OAToken *token = [[OAToken alloc] initWithHTTPResponseBody:responseBody];
        
        if (token.key != nil) {
            // TODO: remove check when term.io gets error codes
            [[tokenKey cell] setStringValue:token.key];
        }
        
        if (token.secret != nil) {
            // TODO: remove check when term.io gets error codes
            [[tokenSecret cell] setStringValue:token.secret];
        }
        
        [response setString:responseBody];
    } else {
        NSLog(@"error code ( >= 400) was returned by endpoint");
        [response setString:responseBody];
    }
}

- (void)tokenTicket:(OAServiceTicket *)ticket didFailWithError:(NSError *)error {
    NSLog(@"token transaction failed");
    NSRunAlertPanel(@"Token Request Error",
                     [NSString stringWithFormat:@"The Token Request transaction failed with this error: %@",
                     [error localizedFailureReason]],
                     nil,
                     nil,
                     nil);
}

- (IBAction)openAuthorizationURLClicked:(id)sender {
    NSString *urlWithQuery = [NSString stringWithFormat:@"%@?oauth_token=%@",
                              [authorizationURL stringValue],
                              [[tokenKey stringValue] encodedURLParameterString]];
    NSURL *url = [NSURL URLWithString:urlWithQuery];
    [[NSWorkspace sharedWorkspace] openURL:url];	
}

- (IBAction)getAccessTokenClicked:(id)sender {
    OAConsumer *consumer = [[OAConsumer alloc] initWithKey:[consumerKey stringValue]
                                                    secret:[consumerSecret stringValue]];
    OAToken *requestToken = [[OAToken alloc] initWithKey:[tokenKey stringValue]
                                                  secret:[tokenSecret stringValue]];
    NSURL *url = [NSURL URLWithString:[accessTokenURL stringValue]];
    id <OASignatureProviding> *signatureProvider = nil;
    
    if ([[[accessTokenSignatureMethod selectedItem] title] isEqualToString:@"PLAINTEXT"]) {
        signatureProvider = [[OAPlaintextSignatureProvider alloc] init];
    }
    
    OAMutableURLRequest *request = [[OAMutableURLRequest alloc] initWithURL:url
                                                                   consumer:consumer
                                                                      token:requestToken
                                                                      realm:nil
                                                          signatureProvider:signatureProvider];
    [request setHTTPMethod:[[accessTokenMethod selectedItem] title]];
    
    OADataFetcher *fetcher = [[OADataFetcher alloc] init];
    [fetcher fetchDataWithRequest:request
                         delegate:self
                didFinishSelector:@selector(tokenTicket:didFinishWithData:)
                  didFailSelector:@selector(tokenTicket:didFailWithError:)];
    [signatureBaseString setString:[request _signatureBaseString]];
    NSString *headerContent = [NSString stringWithFormat:@"Authorization: %@",
                               [request valueForHTTPHeaderField:@"Authorization"]];
    [header setString:headerContent];
}

- (IBAction)accessProtectedResourceClicked:(id)sender {
    OAConsumer *consumer = [[OAConsumer alloc] initWithKey:[consumerKey stringValue]
                                                    secret:[consumerSecret stringValue]];
    OAToken *requestToken = [[OAToken alloc] initWithKey:[tokenKey stringValue]
                                                  secret:[tokenSecret stringValue]];
    NSURL *url = [NSURL URLWithString:[protectedResourceURL stringValue]];
    id <OASignatureProviding> *signatureProvider = nil;
    if ([[[protectedResourceSignatureMethod selectedItem] title] isEqualToString:@"PLAINTEXT"]) {
        signatureProvider = [[OAPlaintextSignatureProvider alloc] init];
    }
    
    OAMutableURLRequest *request = [[OAMutableURLRequest alloc] initWithURL:url
                                                                   consumer:consumer
                                                                      token:requestToken
                                                                      realm:nil
                                                          signatureProvider:signatureProvider];
    [request setHTTPMethod:[[protectedResourceMethod selectedItem] title]];
    
    OADataFetcher *fetcher = [[OADataFetcher alloc] init];
    [fetcher fetchDataWithRequest:request
                         delegate:self
                didFinishSelector:@selector(resourceTicket:didFinishWithData:)
                  didFailSelector:@selector(resourceTicket:didFailWithError:)];
    [signatureBaseString setString:[request _signatureBaseString]];
    NSString *headerContent = [NSString stringWithFormat:@"Authorization: %@",
                               [request valueForHTTPHeaderField:@"Authorization"]];
    [header setString:headerContent];    
}

- (void)resourceTicket:(OAServiceTicket *)ticket didFinishWithData:(NSData *)data {
    NSString *responseBody;
    
    if (data != nil) {
        responseBody = [[NSString alloc] initWithData:data
                                             encoding:NSUTF8StringEncoding];
    } else {
        responseBody = @"";
    }
    
    if (!ticket.didSucceed) {
        NSLog(@"error code ( >= 400) was returned by endpoint");
    }

    [response setString:responseBody];
}

- (void)resourceTicket:(OAServiceTicket *)ticket didFailWithError:(NSError *)error {
    NSRunAlertPanel(@"Protected Resource Request Error",
                    [NSString stringWithFormat:@"The Protected Resource Request transaction failed with this error: %@",
                     [error localizedFailureReason]],
                    nil,
                    nil,
                    nil);
}

@end
