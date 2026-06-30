/*
 * 文件功能：
 * - Unit 字段十进制数字格式和范围验证入口电路。
 * - 复用 uint_decimal_field.circom 中的 UintDecimalField 模板。
 * - Unit 当前按 1 字节设备编号处理，范围为 0..255。
 *
 * 执行流程：
 * 1. 用户输入 Unit，例如 0 或 12。
 * 2. Android 端检查 1 到 3 位数字，并左补零为固定 3 位。
 * 3. 本入口把通用模板实例化为 UintDecimalField(3, 255)。
 * 4. 电路证明字段是数字，且解析值在 0..255。
 */
pragma circom 2.0.0;

include "uint_decimal_field.circom";

component main = UintDecimalField(3, 255);
