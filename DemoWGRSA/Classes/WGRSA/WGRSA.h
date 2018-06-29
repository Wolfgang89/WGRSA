//
//  WGRSA.h
//  Pods
//
//  Created by panwg on 2018/6/29.
//

#import <Foundation/Foundation.h>

@interface WGRSA : NSObject

/**
 使用私钥进行签名 算法是SHA1WithRSA ，注意 RSA算法因为传入的参数不同可能会有不同，这个地方一定要和后台一致，在该方法中将证书加载写在了一起

 @param plainText 明文字符串
 @return 签名字符串（base64编码过的）
 */
- (NSString *)signTheDataSHA1WithRSA:(NSString *)plainText;

/**
 @param plainData 明文
 @param signature 签名 此处的签名需要的是 这样的 [[NSData alloc]initWithBase64EncodedString:signString options:0]
 @param publicKey 公钥
 @return 验签结果
 */
BOOL PKCSVerifyBytesSHA1withRSA(NSData* plainData, NSData* signature, SecKeyRef publicKey);


/**
 加载公钥

 @return 公钥引用 传入上面的函数参数中
 */
- (SecKeyRef)getPublicKey;

@end
