"use strict";

// =============================================================================
// proof-format.js —— ZK Proof 格式规范化与验证
// =============================================================================
// 负责从 HTTP 请求中提取 public signals 和 proof 对象，
// 兼容 snarkjs 和 mopro 两种 proof 格式，调用 snarkjs 进行 Groth16 验证。

const snarkjs = require("snarkjs");

// ---- 从请求 payload 中提取 public signals ----
// 兼容多种命名惯例：publicSignals / public_inputs / inputs / proofResult.inputs
// public signals 顺序（对应 areajudge.circom 的 main 组件声明）：
//   [0] public_commitment (Poseidon 承诺值)
//   [1..6]   Ax_left
//   [7..12]  By_left
//   [13..18] C_left
//   [19..24] Ax_right
//   [25..30] By_right
//   [31..36] C_right
// 共 1 + 6*6 = 37 个 public signals
function normalizePublicSignals(payload) {
  // publicSignals: 从请求中提取公开输入数组，兼容 4 种可能的字段名
  //   publicSignals → snarkjs 标准命名
  //   public_inputs → mopro/Arkworks 命名
  //   inputs → 通用命名
  //   proofResult.inputs → mopro 包装格式
  const publicSignals =
    payload.publicSignals ??
    payload.public_inputs ??
    payload.inputs ??
    payload.proofResult?.inputs;

  if (!Array.isArray(publicSignals)) {
    throw new Error("Missing publicSignals/public_inputs/inputs array");
  }

  // snarkjs 需要字符串形式的 public signals
  return publicSignals.map((value) => value.toString());
}

// ---- 构造 proof 候选列表，兼容两种 proof 格式 ----
// snarkjs 格式: { pi_a: [x,y,z], pi_b: [[x1,x2],[y1,y2],[z1,z2]], pi_c: [x,y,z] }
//   → 直接可用，返回单一候选
// mopro 格式: { a: {x,y,z}, b: {x:[a,b],y:[a,b],z:[a,b]}, c: {x,y,z} }
//   → 需要转换为 snarkjs 格式
//   → 额外生成 G2 备选：
//      1. Fp2 pair 内部元素交换（同时覆盖 z 坐标是否也需要交换）
//      2. G2 x/y 坐标交换
//      3. 两者同时交换
//     因为不同库对 G2 点的 Fp2 元素和坐标顺序可能不一致。
function proofCandidates(payload) {
  // proof: 从请求中提取 proof 对象，兼容直接传 proof 或 mopro 的 proofResult.proof
  const proof = payload.proof ?? payload.proofResult?.proof;
  if (!proof || typeof proof !== "object") {
    throw new Error("Missing proof object");
  }

  // snarkjs 格式直接返回
  if (Array.isArray(proof.pi_a) && Array.isArray(proof.pi_b) && Array.isArray(proof.pi_c)) {
    return [
      {
        format: "snarkjs",
        proof,
      },
    ];
  }

  if (!proof.a || !proof.b || !proof.c) {
    throw new Error("Unsupported proof shape. Expected snarkjs pi_* or mopro a/b/c proof");
  }

  // 将 mopro 格式的 a/b/c 三点转换为 snarkjs 格式的 [x,y,z] 数组
  // a: G1 点，用于 proof 的 pi_a
  const a = normalizeG1(proof.a, "proof.a");
  // b: G2 点（Fp² 扩域），用于 proof 的 pi_b
  const b = normalizeG2(proof.b, "proof.b");
  // c: G1 点，用于 proof 的 pi_c
  const c = normalizeG1(proof.c, "proof.c");
  // protocol: 证明协议名称，默认 groth16
  const protocol = proof.protocol || "groth16";
  // curve: 椭圆曲线名称，默认 bn128
  const curve = proof.curve || "bn128";

  // base: G1 点 a/c 的 snarkjs 格式表示，G2 点 b 的两种排列方式后续构造
  const base = {
    pi_a: a,
    pi_c: c,
    protocol,
    curve,
  };

  // 返回多个候选：标准格式、Fp2 pair 内部交换、G2 x/y 坐标交换、两者同时交换。
  // 旧 mopro 位置 proof 多数 z 为 [1,0]；regex_record 真机 proof 可能带非仿射 z，
  // 因此 pair 交换候选必须覆盖 z 坐标，否则 snarkjs 服务端验证会失败。
  return [
    {
      format: "mopro",
      proof: {
        ...base,
        pi_b: [b.x, b.y, b.z],
      },
    },
    {
      format: "mopro_g2_pair_swapped",
      proof: {
        ...base,
        pi_b: [swapPair(b.x), swapPair(b.y), b.z],
      },
    },
    {
      format: "mopro_g2_pair_swapped_with_z",
      proof: {
        ...base,
        pi_b: [swapPair(b.x), swapPair(b.y), swapPair(b.z)],
      },
    },
    {
      format: "mopro_g2_xy_swapped",
      proof: {
        ...base,
        pi_b: [b.y, b.x, b.z],
      },
    },
    {
      format: "mopro_g2_xy_pair_swapped",
      proof: {
        ...base,
        pi_b: [swapPair(b.y), swapPair(b.x), b.z],
      },
    },
    {
      format: "mopro_g2_xy_pair_swapped_with_z",
      proof: {
        ...base,
        pi_b: [swapPair(b.y), swapPair(b.x), swapPair(b.z)],
      },
    },
  ];
}

// ---- 验证 proof payload ----
// 遍历所有格式候选，任一种验证通过即返回 valid: true
// 所有候选都失败则返回 valid: false，附带每次尝试的结果
async function verifyPayload(verificationKey, payload) {
  // publicSignals: 电路的 37 个公开输入（commitment + 6 个六边形边的坐标）
  const publicSignals = normalizePublicSignals(payload);
  // candidates: proof 格式候选列表（snarkjs、mopro、mopro_g2_swapped）
  const candidates = proofCandidates(payload);
  // attempts: 每次验证尝试的结果数组，所有候选都失败时返回
  const attempts = [];

  for (const candidate of candidates) {
    try {
      const valid = await snarkjs.groth16.verify(
        verificationKey,
        publicSignals,
        candidate.proof
      );
      attempts.push({ format: candidate.format, valid });
      if (valid) {
        return {
          valid: true,
          publicInputCount: publicSignals.length,
          acceptedFormat: candidate.format,
          attempts,
        };
      }
    } catch (error) {
      attempts.push({
        format: candidate.format,
        valid: false,
        error: error.message || String(error),
      });
    }
  }

  return {
    valid: false,
    publicInputCount: publicSignals.length,
    acceptedFormat: null,
    attempts,
  };
}

// ---- 将 G1 点（支持 {x,y,z} 对象或 [x,y,z] 数组）转为 snarkjs 的 [x, y, z] 字符串数组 ----
function normalizeG1(value, label) {
  // value: G1 点，可以是数组 [x,y,z] 或对象 {x,y,z}，两种输入格式都支持
  // label: 用于错误信息中的字段名标识
  if (Array.isArray(value)) {
    if (value.length < 2) {
      throw new Error(`${label} must contain at least x/y`);
    }
    // 数组格式：z 分量可省略（默认为 "1"，即仿射坐标的无穷远点）
    return [value[0].toString(), value[1].toString(), (value[2] ?? "1").toString()];
  }

  if (!value.x || !value.y) {
    throw new Error(`${label} must contain x/y`);
  }

  // 对象格式：z 可省略，默认为 "1"
  return [value.x.toString(), value.y.toString(), (value.z ?? "1").toString()];
}

// ---- 将 G2 点转为 snarkjs 的 { x: [a,b], y: [a,b], z: [a,b] } 结构 ----
// G2 点在 BN254 曲线上是 Fp² 扩域上的点，所以每个坐标为两个大整数
function normalizeG2(value, label) {
  if (Array.isArray(value)) {
    if (value.length < 2) {
      throw new Error(`${label} must contain x/y pairs`);
    }
    return {
      x: normalizePair(value[0], `${label}.x`),
      y: normalizePair(value[1], `${label}.y`),
      z: normalizePair(value[2] ?? ["1", "0"], `${label}.z`),
    };
  }

  return {
    x: normalizePair(value.x, `${label}.x`),
    y: normalizePair(value.y, `${label}.y`),
    z: normalizePair(value.z ?? ["1", "0"], `${label}.z`),
  };
}

// ---- 将 G2 的一个坐标分量（两元素数组）转为字符串数组 ----
// G2 点坐标在 Fp² 扩域上，每个坐标为两个大整数（c0 + c1·u 表示）
// value: [c0, c1] 数组，分别对应扩域的两个分量
// label: 错误信息中的字段名
function normalizePair(value, label) {
  if (!Array.isArray(value) || value.length !== 2) {
    throw new Error(`${label} must be a two-element array`);
  }
  return [value[0].toString(), value[1].toString()];
}

// ---- 交换二维数组的两个元素（用于 G2 坐标备选格式）----
// 不同 ZK 库对 G2 点的 x, y 分量顺序可能不一致，
// 交换 x 和 y 分量可以兼容这种差异
function swapPair(pair) {
  return [pair[1], pair[0]];
}

module.exports = {
  normalizePublicSignals,
  proofCandidates,
  verifyPayload,
};
