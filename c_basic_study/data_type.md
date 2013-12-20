### c data_type类型
####字节型 注释：没有特定指明unsigned，则为有符号数
1. char 1字节 -127 ～ 127 
2. unsigned char  1 0 ~ 255

> 输出符 %c 字符输出， %d（有符号十进制）%o 无符号8进制 %x 无符号16进制 %u 无符号10进制
> 整形前缀 h- short ，l - long

###整数型
1. short 2字节 
2. unsigned short 2字节 0 - 65536
3. int 2或4 理论上是不小于short字节数 跟特定机型有关
4. unsigned int
5. long 至少4 不会比int 字节少
6. long long 8个字节

###浮点型
1. float 4
2. double 8
3. long double 12 在limit.h 和 float.h都有详细介绍

###[浮点数表示]（http://www.cnblogs.com/FlyingBread/archive/2009/02/15/660206.html）
