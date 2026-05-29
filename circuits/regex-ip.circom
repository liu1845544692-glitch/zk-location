/*
 * 文件功能：
 * - IPv4 字符串格式零知识验证电路。
 * - 客户端把用户输入的 IPv4 每段左补零为固定格式 ddd.ddd.ddd.ddd，再把 15 个 ASCII 字节作为私有输入 msg[15]。
 * - 电路约束数字位必须是 '0'..'9'，点号位置必须是 '.'，并约束每个三位段解析后的数值在 0..255。
 *
 * 执行流程：
 * 1. 客户端输入如 192.168.1.12。
 * 2. 客户端预处理为 192.168.001.012。
 * 3. 电路读取 15 个 ASCII 字节。
 * 4. DigitByte 约束数字字符并输出数字值。
 * 5. DotByte 约束固定点号位置。
 * 6. Octet 解析三位十进制数，并通过 LessEqThan 约束 <= 255。
 * 7. valid 输出恒为 1；如果任一约束失败，则无法生成有效 witness/proof。
 */
pragma circom 2.0.0;

include "node_modules/circomlib/circuits/comparators.circom";

/*
 * @title DigitByte
 * @description 约束输入字节为 ASCII 数字字符，并输出对应十进制数字 0..9。
 */
template DigitByte() {
    signal input char;   // char：一个 ASCII 字节，期望在 '0'..'9'。
    signal output digit; // digit：char - '0' 后得到的数字值。

    component byte_bits = Num2Bits(8);     // byte_bits：约束 char 是 8-bit 字节。
    component lower_bound = LessEqThan(8); // lower_bound：约束 48 <= char。
    component upper_bound = LessEqThan(8); // upper_bound：约束 char <= 57。

    byte_bits.in <== char;

    lower_bound.in[0] <== 48;
    lower_bound.in[1] <== char;
    lower_bound.out === 1;

    upper_bound.in[0] <== char;
    upper_bound.in[1] <== 57;
    upper_bound.out === 1;

    digit <== char - 48;
}

/*
 * @title DotByte
 * @description 约束输入字节为 ASCII 点号 '.'。
 */
template DotByte() {
    signal input char; // char：一个 ASCII 字节，必须等于 46。

    component byte_bits = Num2Bits(8); // byte_bits：约束 char 是 8-bit 字节。
    component is_dot = IsEqual();      // is_dot：检查 char == 46。

    byte_bits.in <== char;

    is_dot.in[0] <== char;
    is_dot.in[1] <== 46;
    is_dot.out === 1;
}

/*
 * @title Octet
 * @description 解析一个三位十进制 IPv4 段，并约束其数值在 0..255。
 */
template Octet() {
    signal input chars[3]; // chars：三位 ASCII 数字字符。
    signal output value;   // value：100*d0 + 10*d1 + d2。

    component digits[3];          // digits：三个数字字符约束器。
    component max_255 = LessEqThan(10); // max_255：约束三位十进制数 <= 255。

    for (var i = 0; i < 3; i++) {
        digits[i] = DigitByte();
        digits[i].char <== chars[i];
    }

    value <== digits[0].digit * 100 + digits[1].digit * 10 + digits[2].digit;

    max_255.in[0] <== value;
    max_255.in[1] <== 255;
    max_255.out === 1;
}

/*
 * @title IPv4RegexRange
 * @description 验证规范化 IPv4 字符串 ddd.ddd.ddd.ddd。
 */
template IPv4RegexRange() {
    signal input msg[15]; // msg：私有输入，固定 15 个 ASCII 字节。
    signal output valid;  // valid：公开输出，证明通过时为 1。

    component dot0 = DotByte(); // dot0：第一个点号，位置 3。
    component dot1 = DotByte(); // dot1：第二个点号，位置 7。
    component dot2 = DotByte(); // dot2：第三个点号，位置 11。
    component octets[4];        // octets：四个 IPv4 数字段。

    dot0.char <== msg[3];
    dot1.char <== msg[7];
    dot2.char <== msg[11];

    for (var i = 0; i < 4; i++) {
        octets[i] = Octet();
    }

    octets[0].chars[0] <== msg[0];
    octets[0].chars[1] <== msg[1];
    octets[0].chars[2] <== msg[2];

    octets[1].chars[0] <== msg[4];
    octets[1].chars[1] <== msg[5];
    octets[1].chars[2] <== msg[6];

    octets[2].chars[0] <== msg[8];
    octets[2].chars[1] <== msg[9];
    octets[2].chars[2] <== msg[10];

    octets[3].chars[0] <== msg[12];
    octets[3].chars[1] <== msg[13];
    octets[3].chars[2] <== msg[14];

    valid <== 1;
}

component main = IPv4RegexRange();
