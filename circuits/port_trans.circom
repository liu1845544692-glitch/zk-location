/*
 * 文件功能：
 * - Port/Trans 共用的 16-bit 十进制数字字段入口电路。
 * - 复用 uint_decimal_field.circom 中的 UintDecimalField 模板。
 * - Android 端 Port 和 Trans 都链接到本入口生成的 port_trans_final.zkey。
 *
 * 执行流程：
 * 1. 用户输入 Port 或 Trans，例如 502 或 19164。
 * 2. Android 端检查 1 到 5 位数字，并左补零为固定 5 位。
 * 3. 本入口把通用模板实例化为 UintDecimalField(5, 65535)。
 * 4. 电路证明字段是数字，且解析值在 0..65535。
 */
pragma circom 2.0.0;

include "uint_decimal_field.circom";

component main = UintDecimalField(5, 65535);
