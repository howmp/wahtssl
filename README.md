# whatssl

识别客户端是否使用OpenSSL,检测网站 <https://whatssl.guage.cool:8443/> 

由于Python,PHP等都使用OpenSSL，也会这可以成为反爬的一个特征

## 原理

当tls密钥协商结束(ChangeCipherSpec)，开始进入加密通信后

如果使用AEAD算法(这也是推荐算法)

1. 那么使用sequence number(64bit)作为nonce
1. sequence number也会发送，作为Record数据的前8个字节
1. sequence number必须从0开始

由于OpenSSL的sequence number没有从0开始，导致其可以轻松被识别

<https://www.rfc-editor.org/rfc/rfc5246#page-19>

> Each connection state contains a sequence number, which is
> maintained separately for read and write states.  The sequence
> number MUST be set to zero whenever a connection state is made the
> active state.  Sequence numbers are of type uint64 and may not
> exceed 2^64-1.  Sequence numbers do not wrap.  If a TLS
> implementation would need to wrap a sequence number, it must
> renegotiate instead.  A sequence number is incremented after each
> record: specifically, the first record transmitted under a
> particular connection state MUST use sequence number 0.



## 测试

| Name       | OpenSSL | Note      |
|------------|---------|-----------|
| chrome     | N       | boringssl |
| powershell | N       | schannel? |
| Java       | N       | JSSE      |
| python     | Y       | OpenSSL   |
| php        | Y       | OpenSSL   |
| curl       | Y       | OpenSSL   |


### powershell

```ps
Invoke-WebRequest https://whatssl.guage.cool:8443/ | Select -ExpandProperty Content
```

### python

```sh
python -c "print(__import__('requests').get('https://whatssl.guage.cool:8443/').text)"
```

### php

```php
<?php
echo file_get_contents("https://whatssl.guage.cool:8443/");
```

### curl

```sh
curl  https://whatssl.guage.cool:8443/
```