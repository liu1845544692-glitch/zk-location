/*
 * 文件功能：
 * - 通用固定长度十进制数字字段验证模板。
 * - 供 Port、Trans、Unit 等字段入口电路复用。
 * - 模板参数 DIGITS 决定输入固定长度，MAX_VALUE 决定解析后整数的最大合法值。
 *
 * 执行流程：
 * 1. 入口电路通过 component main = UintDecimalField(DIGITS, MAX_VALUE) 固定字段长度和范围。
 * 2. Android 端把用户输入左补零为 DIGITS 位，再传入 msg[DIGITS]。
 * 3. DigitByte 约束每个字节是 ASCII '0'..'9'。
 * 4. UintDecimalField 按十进制解析数值，并约束 value <= MAX_VALUE。
 * 5. valid 输出恒为 1；如果格式或范围不满足约束，则无法生成有效 witness/proof。
 */
pragma circom 2.0.0;

include "node_modules/circomlib/circuits/comparators.circom";

/*
 * @title Pow10
 * @description 返回 10 的 exp 次方，供固定长度十进制解析使用。
 */
function Pow10(exp) {
    var result = 1;
    for (var i = 0; i < exp; i++) {
        result *= 10;
    }
    return result;
}

/*
 * @title BitsForMax
 * @description 返回能覆盖 maxValue 的比较器位宽，并额外留 1 bit 避免 LessEqThan 边界不足。
 */
function BitsForMax(maxValue) {
    var bits = 1;
    var capacity = 2;
    while (capacity <= maxValue) {
        bits += 1;
        capacity *= 2;
    }
    return bits + 1;
}

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
 * @title UintDecimalField
 * @description 验证固定 DIGITS 位数字字符串，并约束解析后的整数在 0..MAX_VALUE。
 */
template UintDecimalField(DIGITS, MAX_VALUE) {
    signal input msg[DIGITS]; // msg：私有输入，固定 DIGITS 个 ASCII 数字字节。
    signal output valid;      // valid：公开输出，证明通过时为 1。

    component digits[DIGITS];                    // digits：逐字节数字约束器。
    component max_value = LessEqThan(BitsForMax(MAX_VALUE)); // max_value：约束 value <= MAX_VALUE。

    signal value; // value：按十进制解析得到的字段数值。
    var weighted_sum = 0;

    for (var i = 0; i < DIGITS; i++) {
        digits[i] = DigitByte();
        digits[i].char <== msg[i];
        weighted_sum += digits[i].digit * Pow10(DIGITS - 1 - i);
    }

    value <== weighted_sum;

    max_value.in[0] <== value;
    max_value.in[1] <== MAX_VALUE;
    max_value.out === 1;

    valid <== 1;
}
