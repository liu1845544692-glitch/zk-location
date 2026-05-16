"use strict";

// =============================================================================
// report-generator.js —— 实验报告导出与性能统计
// =============================================================================
// 从交互日志中提取统计数据，生成性能概览和实验报告，支持 JSON / Markdown 输出

// ---- 从交互日志中统计 proof 验证和 key 注册的性能数据 ----
function buildPerformanceStats(entries) {
  // proofVerifies: 日志中类型为 "proof.verify" 的条目（proof 验证请求）
  const proofVerifies = entries.filter((entry) => entry.type === "proof.verify");
  // keyRegisters: 日志中类型为 "key.register" 的条目（key 注册请求）
  const keyRegisters = entries.filter((entry) => entry.type === "key.register");
  return {
    generatedAt: new Date().toISOString(),
    counts: {
      totalEntries: entries.length,
      proofVerify: proofVerifies.length,
      keyRegister: keyRegisters.length,
    },
    // proofVerifyDurationMs: proof 验证耗时的 min/max/avg 统计
    proofVerifyDurationMs: summarizeNumbers(proofVerifies.map((entry) => entry.durationMs)),
    // keyRegisterDurationMs: key 注册耗时的 min/max/avg 统计
    keyRegisterDurationMs: summarizeNumbers(keyRegisters.map((entry) => entry.durationMs)),
    // validProofVerifyCount: 验证通过的 proof 请求数
    validProofVerifyCount: proofVerifies.filter((entry) => entry.responseSummary?.valid === true).length,
    // failedProofVerifyCount: 验证失败的 proof 请求数
    failedProofVerifyCount: proofVerifies.filter((entry) => entry.responseSummary?.valid === false).length,
    // signatureValidCount: 签名验证通过的次数
    signatureValidCount: proofVerifies.filter(
      (entry) => entry.responseSummary?.signature?.signatureValid === true
    ).length,
    // nonceConsumedCount: nonce 成功消费的次数（即完整验证通过且 nonce 被消耗）
    nonceConsumedCount: proofVerifies.filter(
      (entry) => entry.responseSummary?.nonce?.consumed === true
    ).length,
  };
}

// ---- 构建完整实验报告，包含最新一次 key 注册和 proof 验证详情 ----
function buildExperimentReport(entries, options = {}) {
  // limit: 只取最近 N 条日志进行分析，未指定则全量
  const limit = Number(options.limit || entries.length || 0);
  // selected: 截取后的日志条目（取最后 limit 条）
  const selected = limit > 0 ? entries.slice(-limit) : entries;
  // stats: 从截取日志中统计的性能数据
  const stats = buildPerformanceStats(selected);
  // latestKeyRegister: 最近一次 key 注册记录（从末尾反向查找）
  const latestKeyRegister = [...selected].reverse().find((entry) => entry.type === "key.register");
  // latestProofVerify: 最近一次 proof 验证记录（从末尾反向查找）
  const latestProofVerify = [...selected].reverse().find((entry) => entry.type === "proof.verify");
  return {
    generatedAt: new Date().toISOString(),
    sourceEntryCount: selected.length,
    stats,
    latestKeyRegister: latestKeyRegister
      ? {
          ts: latestKeyRegister.ts,
          statusCode: latestKeyRegister.statusCode,
          username: latestKeyRegister.responseSummary?.username || null,
          keyId: latestKeyRegister.responseSummary?.keyId || null,
          publicKeyFingerprint: latestKeyRegister.responseSummary?.publicKeyFingerprint || null,
          attestation: latestKeyRegister.responseSummary?.attestation || null,
        }
      : null,
    latestProofVerify: latestProofVerify
      ? {
          ts: latestProofVerify.ts,
          statusCode: latestProofVerify.statusCode,
          publicCommitment: latestProofVerify.requestSummary?.publicCommitment || null,
          proofValid: latestProofVerify.responseSummary?.proofValid ?? null,
          valid: latestProofVerify.responseSummary?.valid ?? null,
          signature: latestProofVerify.responseSummary?.signature || null,
          nonce: latestProofVerify.responseSummary?.nonce || null,
          durationMs: latestProofVerify.durationMs,
        }
      : null,
  };
}

// ---- 将报告对象转为 Markdown 格式字符串 ----
function reportToMarkdown(report) {
  // lines: 累积 Markdown 每一行的数组，最后用 \n 拼接
  const lines = [];
  lines.push("# ZK-Location Experiment Report");
  lines.push("");
  lines.push(`Generated at: ${report.generatedAt}`);
  lines.push(`Source entries: ${report.sourceEntryCount}`);
  lines.push("");
  lines.push("## Performance");
  lines.push("");
  lines.push(`- Proof verify count: ${report.stats.counts.proofVerify}`);
  lines.push(`- Key register count: ${report.stats.counts.keyRegister}`);
  lines.push(`- Proof verify duration: ${formatStats(report.stats.proofVerifyDurationMs)}`);
  lines.push(`- Key register duration: ${formatStats(report.stats.keyRegisterDurationMs)}`);
  lines.push(`- Valid proof verifies: ${report.stats.validProofVerifyCount}`);
  lines.push(`- Signature valid count: ${report.stats.signatureValidCount}`);
  lines.push(`- Nonce consumed count: ${report.stats.nonceConsumedCount}`);
  lines.push("");
  lines.push("## Latest Key Register");
  lines.push("");
  lines.push(formatObject(report.latestKeyRegister));
  lines.push("");
  lines.push("## Latest Proof Verify");
  lines.push("");
  lines.push(formatObject(report.latestProofVerify));
  lines.push("");
  return lines.join("\n");
}

// ---- 对数值数组统计 min/max/avg ----
function summarizeNumbers(values) {
  // nums: 过滤后只保留有限数值（排除 NaN, Infinity, null 等）
  const nums = values
    .map((value) => Number(value))
    .filter((value) => Number.isFinite(value));
  if (nums.length === 0) {
    return { count: 0, min: null, max: null, avg: null };
  }
  // sum: 所有数值的总和，用于计算平均值
  const sum = nums.reduce((acc, value) => acc + value, 0);
  return {
    count: nums.length,
    min: Math.min(...nums),
    max: Math.max(...nums),
    avg: Math.round((sum / nums.length) * 100) / 100,
  };
}

// ---- 将 stats 对象格式化为可读字符串 ----
function formatStats(stats) {
  if (!stats || stats.count === 0) {
    return "n/a";
  }
  return `count=${stats.count}, avg=${stats.avg}ms, min=${stats.min}ms, max=${stats.max}ms`;
}

// ---- 将任意值格式化为 Markdown 代码块 ----
function formatObject(value) {
  if (!value) {
    return "_None_";
  }
  return `\`\`\`json\n${JSON.stringify(value, null, 2)}\n\`\`\``;
}

module.exports = {
  buildExperimentReport,
  buildPerformanceStats,
  reportToMarkdown,
};
