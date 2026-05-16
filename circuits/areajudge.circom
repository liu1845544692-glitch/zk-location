/*
 * 文件功能：
 * - ZK-Location 主电路，证明私有坐标 (x, y) 与 salt 生成的 Poseidon commitment 正确。
 * - 同时证明该私有坐标落在服务端公开指定的 H3 cell 六条半平面约束内。
 *
 * 执行流程：
 * 1. 私有 witness 输入 x、y、salt。
 * 2. 公开输入 public_commitment 和六条边的 left/right 非负系数。
 * 3. 电路内部计算 Poseidon(x, y, salt)，约束等于 public_commitment。
 * 4. 对六条边分别计算 left_side 和 right_side。
 * 5. 使用 LessEqThan(128) 约束 left_side <= right_side。
 */
pragma circom 2.0.0;

// 引入 circomlib 中的比较器库，用于处理 "<=" 逻辑
include "node_modules/circomlib/circuits/comparators.circom";
include "node_modules/circomlib/circuits/poseidon.circom";

/*
 * @title Hexagon Location Verifier
 * @description 验证一个私密坐标 (x, y) 是否绑定到公开承诺，并位于由 6 条直线构成的 H3 正六边形内。
 * @param nBits 坐标和系数的最大比特长度，防止乘法和加法过程中溢出。通常 64 位足够处理高精度缩放后的经纬度。
 */
template HexagonLocationVerifier(nBits) {
    // nBits：LessEqThan 比较器位数，必须覆盖半平面计算后的整数范围。
    // === 1. 私有输入 (Private Witnesses) ===
    // 用户的真实投影坐标 (在移动端本地生成，绝不上链或发送给服务器)
    signal input x;    // x：私有经度全局定点整数。
    signal input y;    // y：私有纬度全局定点整数。
    signal input salt; // salt：私有随机盲化值。

    // === 2. 公开输入 (Public Statements) ===
    // TEE 签名的公开位置承诺：Poseidon(x, y, salt)
    signal input public_commitment; // public_commitment：公开 Poseidon commitment。

    // 目标六边形的 6 条边界线参数 (全部移项转化为正整数)
    // 方程形式: Ax_left * x + By_left * y + C_left <= Ax_right * x + By_right * y + C_right
    signal input Ax_left[6]; // Ax_left：left side 的 x 系数。
    signal input By_left[6]; // By_left：left side 的 y 系数。
    signal input C_left[6];  // C_left：left side 的常数项。
    
    signal input Ax_right[6]; // Ax_right：right side 的 x 系数。
    signal input By_right[6]; // By_right：right side 的 y 系数。
    signal input C_right[6];  // C_right：right side 的常数项。

// === 3. 中间信号与组件 ===
    component commitment_hasher = Poseidon(3); // commitment_hasher：计算 Poseidon(x,y,salt)。
    component comparators[6];                  // comparators：六条边各一个 <= 比较器。
    
    // 【新增】：为了拆分多次乘法而定义的中间信号
    signal left_termX[6];  // left_termX：Ax_left[i] * x 的中间乘法结果。
    signal left_termY[6];  // left_termY：By_left[i] * y 的中间乘法结果。
    signal right_termX[6]; // right_termX：Ax_right[i] * x 的中间乘法结果。
    signal right_termY[6]; // right_termY：By_right[i] * y 的中间乘法结果。

    signal left_side[6];  // left_side：left_termX + left_termY + C_left。
    signal right_side[6]; // right_side：right_termX + right_termY + C_right。

    // === 4. 核心约束逻辑 (Constraints) ===
    commitment_hasher.inputs[0] <== x;
    commitment_hasher.inputs[1] <== y;
    commitment_hasher.inputs[2] <== salt;
    commitment_hasher.out === public_commitment;

    for (var i = 0; i < 6; i++) {
        // i：当前处理的 H3 边编号。
        // 第一步：将“信号相乘”单独提取出来，每个等式只有一个乘法，符合 R1CS 规范
        left_termX[i] <== Ax_left[i] * x;
        left_termY[i] <== By_left[i] * y;
        
        right_termX[i] <== Ax_right[i] * x;
        right_termY[i] <== By_right[i] * y;

        // 第二步：由于 termX 和 termY 已经是计算好的信号了，这里只有纯粹的加法（线性组合）
        left_side[i] <== left_termX[i] + left_termY[i] + C_left[i];
        right_side[i] <== right_termX[i] + right_termY[i] + C_right[i];

        // 实例化比较器，并输入最终两侧的值
        comparators[i] = LessEqThan(nBits);
        comparators[i].in[0] <== left_side[i];
        comparators[i].in[1] <== right_side[i];

        // 断言：约束比较结果必须为 True
        comparators[i].out === 1;
    }
}

// === 5. 实例化 Main 组件 ===
// 声明哪些输入是 public 的 (位置承诺 + 六边形边界参数)，剩余的 x, y, salt 默认作为 private
component main {public [public_commitment, Ax_left, By_left, C_left, Ax_right, By_right, C_right]} = HexagonLocationVerifier(128);
