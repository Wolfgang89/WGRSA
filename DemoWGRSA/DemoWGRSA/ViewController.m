//
//  ViewController.m
//  DemoWGRSA
//
//  Created by panwg on 2018/6/29.
//  Copyright © 2018年 wolfgang. All rights reserved.
//

#import "ViewController.h"
#import "HBRSAHandler.h"
#import "WGRSA.h"

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
/********************示例代码***************/
    
    
    
    /*******HB*******/
    
    HBRSAHandler *handler = [HBRSAHandler new];

    NSString *privateKeyFilePath = [[NSBundle mainBundle] pathForResource:@"rsa_private_key.pem" ofType:nil];
    
    BOOL priflag = [handler importKeyWithType:KeyTypePrivate andPath:privateKeyFilePath];
    
    NSLog(@"--priflag-----%d",priflag);
    
    NSString *publicKeyFilePath = [[NSBundle mainBundle] pathForResource:@"rsa_public_key.pem" ofType:nil];
    
    BOOL flag = [handler importKeyWithType:KeyTypePublic andPath:publicKeyFilePath];
    
    NSLog(@"--flag-----%d",flag);

    // 加密 解密。验签 签名 ---->>>>>>>>>>>>------
    
    
    
    /********WGRSA*******/
    
    WGRSA *rsa = [[WGRSA alloc]init];
    
    /*注意秘钥文件在点m中 修改 */
    //加密
    NSString *reStr = [rsa signTheDataSHA1WithRSA:@"123456"];
    
    NSLog(@"--------%@--------re",reStr);
    
    NSData *data =  [@"123456"   dataUsingEncoding:NSUTF8StringEncoding];

    
    NSString *signString= @"v4r3nQRvU/r8KVYGaxFcsNSJ2rp6aIAWAYMUNVHRoDyLT7RIMmvIB+Qq0rkb9Kx/xlGrrbT8xqBkgLTQFhBfZPKbAdPk1coJxvGEWLC/YfA/e+E+JveLBbnoD0Yuwt7AkXbAuzgNJ6YK5Ls0AQkrmALljNZ+9g6xQqGL7YSccv2poeMHHbgSTMx+kG7lB97F+3wIPhHUYVcpFmjbPhppzJYvFdM13vwRNh5qLfdzy/JXR/2qQRh6eGvR4zeVLuI/pxvk7ZXvvoUlTyDoYo3G0QYHM2gO1UhwFbwdxPPiecvQN2586V5O/6SjXbr1PYx6QyLmzMfp5jB5cSqRR6IhnQ==";
    
    //验签
    NSData *signatureData = [[NSData alloc]initWithBase64EncodedString:signString options:0];
    
    //
    BOOL flagw = PKCSVerifyBytesSHA1withRSA(data, signatureData, [rsa getPublicKey]);
    
    NSLog(@"----flagw------%d----",flagw);

    
}



@end
