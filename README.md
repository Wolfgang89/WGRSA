# WGRSA
WGRSA是支持pfx私钥签名，cer公钥验签的开源工具类
### WGRSA的m文件中将私钥的密码和文件名写死的，需要的时候自己修改。

# HBRSAHandler

### HBRSAHandler是支持私钥公钥都是pem格式的签名验签，加密解密的工具类（不是我写的，加密算法和支付宝一致，大神的github是[HBRSAHandler](https://github.com/shafujiu/HBRSAHandlerLib)，静态库也是大神编译的（😓））

### 在使用静态库的点a的时候，会出现这个错```<openssl/rsa.h> file not found```的错误，如果你是在工程中直接使用，只需要配置好HEADER_SEARCH_PATHS，如果是pod打包库套在库中，需要在spec中配置```#s.xcconfig = { 'USER_HEADER_SEARCH_PATHS' => '路径/*.{h}' }```，并且关闭bitcode。

# 具体的使用方式 请看代码。



