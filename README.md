# KuroyamaRC5
A simple RC5 bytes encryption wrapper.

# How to use
Don't forget to include `EncryptValue.h`
**Initializing the Encryption**
```
CEncrypt<int> Foo = new CEncrypt<int>(256);
```
**Using it as normal Variable**
```
printf("%d", Foo); 
// Output 256
Foo += 1;
// Foo now is 257
CEncrypt<int> Bar = new CEncrypt<int>(100);
Foo += Bar;
// Foo now is 357
```
