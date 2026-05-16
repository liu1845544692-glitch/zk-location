/*
 * 文件功能：
 * - 将 Android GNSS 经纬度转换为 Circom areajudge 电路输入。
 * - 使用 H3 计算目标 cell 边界，使用全局绝对定点坐标构造半平面约束。
 * - 使用 Poseidon(x, y, salt) 生成 public_commitment，避免服务端看到明文位置。
 *
 * 执行流程：
 * 1. 校验经纬度和 H3 resolution。
 * 2. 经纬度转 H3 cell，读取 5/6 个边界顶点。
 * 3. 将用户点和顶点映射到非负全局整数坐标。
 * 4. 为每条边生成 left <= right 形式的公开约束系数。
 * 5. 生成随机 salt，计算 Poseidon commitment。
 * 6. 输出 Android/mopro/Circom 可使用的 JSON input。
 */
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use h3o::{CellIndex, LatLng, Resolution};
use light_poseidon::{Poseidon, PoseidonHasher};
use num_bigint::BigUint;
use serde_json::json;
use std::str::FromStr;

/// 缩放因子：将经纬度放大为整数
const SCALE: f64 = 1e7;

/// 电路当前固定需要 6 条边约束
const CIRCOM_EDGE_COUNT: usize = 6;

/// 电路输入的各个部分
#[derive(Debug, Clone)]
struct CircuitInputParts {
    /// x：用户经度转换后的全局非负整数坐标。
    x: String,
    /// y：用户纬度转换后的全局非负整数坐标。
    y: String,
    /// ax_left：每条边左侧 x 系数的非负拆分结果。
    ax_left: Vec<String>,
    /// by_left：每条边左侧 y 系数的非负拆分结果。
    by_left: Vec<String>,
    /// c_left：每条边左侧常数项的非负拆分结果。
    c_left: Vec<String>,
    /// ax_right：每条边右侧 x 系数的非负拆分结果。
    ax_right: Vec<String>,
    /// by_right：每条边右侧 y 系数的非负拆分结果。
    by_right: Vec<String>,
    /// c_right：每条边右侧常数项的非负拆分结果。
    c_right: Vec<String>,
}

/// 核心函数：给定经纬度和 H3 分辨率，生成 circom 电路的 input JSON
///
/// 流程：
/// 1. 经纬度 → H3 cell → 边界顶点 (CCW 排序)
/// 2. 使用全局绝对定点坐标：x=(lon+180)*SCALE, y=(lat+90)*SCALE
/// 3. 用户点和 H3 顶点都进入同一个绝对正整数坐标系
/// 4. 对每条边构造半平面不等式，并拆成 left <= right
/// 5. 若为 pentagon，则补恒真约束凑齐 6 条
/// 6. 生成高熵 salt，并计算 public_commitment = Poseidon(x, y, salt)
pub fn generate_circuit_input(lat: f64, lon: f64, resolution: u8) -> Result<String, String> {
    // salt：本次 proof 的随机盲化值，防止 commitment 被离线枚举。
    let salt = generate_salt()?;
    generate_circuit_input_with_salt(lat, lon, resolution, &salt)
}

/// 使用调用方指定的 salt 生成电路输入。主要用于可复现测试和跨语言测试向量。
pub fn generate_circuit_input_with_salt(
    lat: f64,
    lon: f64,
    resolution: u8,
    salt: &str,
) -> Result<String, String> {
    // parts：不含 salt 和 commitment 的坐标/边界约束输入。
    let parts = generate_location_parts(lat, lon, resolution)?;
    // public_commitment：公开承诺，服务端和 TEE 签名都绑定这个值。
    let public_commitment = poseidon_commitment(&parts.x, &parts.y, salt)?;

    // input：最终写入 Circom witness 的 JSON 对象。
    let input = json!({
        "public_commitment": public_commitment,
        "x": parts.x,
        "y": parts.y,
        "salt": salt,
        "Ax_left": parts.ax_left,
        "By_left": parts.by_left,
        "C_left": parts.c_left,
        "Ax_right": parts.ax_right,
        "By_right": parts.by_right,
        "C_right": parts.c_right,
    });

    serde_json::to_string_pretty(&input).map_err(|e| format!("JSON 序列化失败: {e}"))
}

/// 生成与电路同源的 H3 cell 边界，用于 Android 地图展示。
pub fn generate_cell_boundary(lat: f64, lon: f64, resolution: u8) -> Result<String, String> {
    // coord：h3o 使用的 WGS84 经纬度对象。
    let coord = LatLng::new(lat, lon).map_err(|e| format!("无效坐标: {e}"))?;
    // res：h3o resolution 类型，限制输入必须是有效 H3 分辨率。
    let res = Resolution::try_from(resolution).map_err(|e| format!("无效分辨率: {e}"))?;
    // cell：定位点所在 H3 cell。
    let cell: CellIndex = coord.to_cell(res);
    // boundary：cell 的边界顶点，用于地图展示和约束一致性检查。
    let boundary = cell.boundary();

    reject_antimeridian_spanning_cell(&boundary)?;

    // vertices：JSON 中返回给 Android 地图的 WGS84 顶点数组。
    let vertices: Vec<_> = boundary
        .iter()
        .map(|v| {
            json!({
                "lat": v.lat(),
                "lon": v.lng(),
            })
        })
        .collect();

    // output：Android 地图层消费的 cell 边界描述。
    let output = json!({
        "resolution": resolution,
        "cell": cell.to_string(),
        "center": {
            "lat": lat,
            "lon": lon,
        },
        "vertices": vertices,
    });

    serde_json::to_string_pretty(&output).map_err(|e| format!("JSON 序列化失败: {e}"))
}

fn generate_location_parts(
    lat: f64,
    lon: f64,
    resolution: u8,
) -> Result<CircuitInputParts, String> {
    // ---- 第 1 步：H3 索引与边界 ----
    // coord：用户 GNSS 坐标对应的 h3o LatLng。
    let coord = LatLng::new(lat, lon).map_err(|e| format!("无效坐标: {e}"))?;
    // res：本次 proof 使用的 H3 resolution。
    let res = Resolution::try_from(resolution).map_err(|e| format!("无效分辨率: {e}"))?;
    // cell：用户点所在的 H3 cell。
    let cell: CellIndex = coord.to_cell(res);

    // 获取边界顶点（CCW）
    let boundary = cell.boundary();
    // n：边界顶点数量，普通 hexagon 为 6，pentagon 为 5。
    let n = boundary.len();

    // 当前电路只支持 pentagon(5) / hexagon(6)
    if n != 5 && n != 6 {
        return Err(format!("当前电路只支持 5/6 边 cell, 实际顶点数为 {n}"));
    }

    reject_antimeridian_spanning_cell(&boundary)?;

    // ---- 第 2 步：全局绝对整数坐标 ----
    // user_x/user_y：进入电路的私有位置坐标。
    let user_x = global_lon_int(lon)? as i128;
    let user_y = global_lat_int(lat)? as i128;

    // verts：H3 顶点在同一全局整数坐标系下的坐标。
    let verts: Vec<(i128, i128)> = boundary
        .iter()
        .map(|v| {
            // vx/vy：单个 H3 顶点转换后的整数坐标。
            let vx = global_lon_int(v.lng())? as i128;
            let vy = global_lat_int(v.lat())? as i128;
            Ok((vx, vy))
        })
        .collect::<Result<_, String>>()?;

    // ---- 第 3 步：构造半平面不等式 ----
    //
    // 对于 CCW 排序的凸多边形，边 V_i -> V_{i+1}，
    // 点 P 在多边形内部的条件为：
    //   (x1 - x0) * (py - y0) - (y1 - y0) * (px - x0) >= 0
    //
    // 展开得：
    //   A*px + B*py + C >= 0
    // 其中：
    //   A = -(y1 - y0) = y0 - y1
    //   B =  (x1 - x0)
    //   C = -(A*x0 + B*y0)
    //
    // 再拆成电路里的：
    //   left <= right
    //
    // 即：
    //   (-A if A<0)*x + (-B if B<0)*y + (-C if C<0)
    //   <=
    //   ( A if A>0)*x + ( B if B>0)*y + ( C if C>0)

    // ax_left/by_left/c_left：电路 left side 的 6 条边系数。
    let mut ax_left = Vec::with_capacity(CIRCOM_EDGE_COUNT);
    let mut by_left = Vec::with_capacity(CIRCOM_EDGE_COUNT);
    let mut c_left = Vec::with_capacity(CIRCOM_EDGE_COUNT);
    // ax_right/by_right/c_right：电路 right side 的 6 条边系数。
    let mut ax_right = Vec::with_capacity(CIRCOM_EDGE_COUNT);
    let mut by_right = Vec::with_capacity(CIRCOM_EDGE_COUNT);
    let mut c_right = Vec::with_capacity(CIRCOM_EDGE_COUNT);

    for i in 0..n {
        // x0/y0 和 x1/y1：当前边的起点和终点。
        let (x0, y0) = verts[i];
        let (x1, y1) = verts[(i + 1) % n];

        // a/b/c：半平面 A*x + B*y + C >= 0 的有符号系数。
        let a = y0 - y1;
        let b = x1 - x0;
        let c = -(a * x0 + b * y0);

        // al/ar、bl/br、cl/cr：将有符号系数拆到 left/right 两侧。
        let (al, ar) = split_coeff(a);
        let (bl, br) = split_coeff(b);
        let (cl, cr) = split_coeff(c);

        ax_left.push(al.to_string());
        ax_right.push(ar.to_string());
        by_left.push(bl.to_string());
        by_right.push(br.to_string());
        c_left.push(cl.to_string());
        c_right.push(cr.to_string());
    }

    // pentagon 补一条恒真约束：0 <= 0
    while ax_left.len() < CIRCOM_EDGE_COUNT {
        ax_left.push("0".to_string());
        ax_right.push("0".to_string());
        by_left.push("0".to_string());
        by_right.push("0".to_string());
        c_left.push("0".to_string());
        c_right.push("0".to_string());
    }

    debug_assert_eq!(ax_left.len(), CIRCOM_EDGE_COUNT);
    debug_assert_eq!(ax_right.len(), CIRCOM_EDGE_COUNT);

    Ok(CircuitInputParts {
        x: user_x.to_string(),
        y: user_y.to_string(),
        ax_left,
        by_left,
        c_left,
        ax_right,
        by_right,
        c_right,
    })
}

fn generate_salt() -> Result<String, String> {
    loop {
        // bytes：32 字节系统随机数候选值。
        let mut bytes = [0u8; 32];
        getrandom::getrandom(&mut bytes).map_err(|e| format!("系统随机数生成失败: {e}"))?;
        // candidate：转换为大整数后检查是否落在 BN254 标量域内。
        let candidate = BigUint::from_bytes_be(&bytes);
        if candidate < BigUint::from(Fr::MODULUS) {
            return Ok(candidate.to_string());
        }
    }
}

fn poseidon_commitment(x: &str, y: &str, salt: &str) -> Result<String, String> {
    // x/y/salt：十进制字符串转换后的 BN254 字段元素。
    let x = field_from_decimal(x)?;
    let y = field_from_decimal(y)?;
    let salt = field_from_decimal(salt)?;

    // poseidon：与 Circom Poseidon(3) 参数一致的哈希器。
    let mut poseidon =
        Poseidon::<Fr>::new_circom(3).map_err(|e| format!("Poseidon 初始化失败: {e}"))?;
    // commitment：Poseidon(x, y, salt) 的字段元素结果。
    let commitment = poseidon
        .hash(&[x, y, salt])
        .map_err(|e| format!("Poseidon 哈希失败: {e}"))?;

    Ok(field_to_decimal(&commitment))
}

fn field_from_decimal(value: &str) -> Result<Fr, String> {
    Fr::from_str(value).map_err(|_| format!("字段元素不是合法十进制数: {value}"))
}

fn field_to_decimal(value: &Fr) -> String {
    BigUint::from_bytes_be(&value.into_bigint().to_bytes_be()).to_string()
}

fn global_lat_int(lat: f64) -> Result<u64, String> {
    if !lat.is_finite() || !(-90.0..=90.0).contains(&lat) {
        return Err(format!("无效纬度: {lat}"));
    }
    Ok(((lat + 90.0) * SCALE).round() as u64)
}

fn global_lon_int(lon: f64) -> Result<u64, String> {
    if !lon.is_finite() || !(-180.0..=180.0).contains(&lon) {
        return Err(format!("无效经度: {lon}"));
    }
    Ok(((lon + 180.0) * SCALE).round() as u64)
}

fn reject_antimeridian_spanning_cell(boundary: &[LatLng]) -> Result<(), String> {
    // min_lng/max_lng：用于检测 H3 cell 是否跨越 180 度经线。
    let min_lng = boundary
        .iter()
        .map(|v| v.lng())
        .fold(f64::INFINITY, f64::min);
    let max_lng = boundary
        .iter()
        .map(|v| v.lng())
        .fold(f64::NEG_INFINITY, f64::max);

    if max_lng - min_lng > 180.0 {
        return Err(
            "当前全局绝对坐标半平面模型不支持跨 180° 经线的 H3 cell，需要拆分或采用服务端一致的经线规范化方案"
                .to_string(),
        );
    }

    Ok(())
}

/// 拆分系数：
/// - v >= 0: (0, v)
/// - v < 0 : (-v, 0)
fn split_coeff(v: i128) -> (u128, u128) {
    if v >= 0 {
        (0, v as u128)
    } else {
        ((-v) as u128, 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn parse_i128_field(v: &Value, key: &str) -> i128 {
        v[key]
            .as_str()
            .unwrap_or_else(|| panic!("{key} 不是字符串"))
            .parse::<i128>()
            .unwrap_or_else(|_| panic!("{key} 不是合法 i128"))
    }

    fn parse_u128_array(v: &Value, key: &str) -> Vec<u128> {
        v[key]
            .as_array()
            .unwrap_or_else(|| panic!("{key} 不是数组"))
            .iter()
            .map(|x| {
                x.as_str()
                    .unwrap_or_else(|| panic!("{key} 数组元素不是字符串"))
                    .parse::<u128>()
                    .unwrap_or_else(|_| panic!("{key} 数组元素不是合法 u128"))
            })
            .collect()
    }

    fn assert_constraints_hold(json_str: &str) {
        let parsed: Value = serde_json::from_str(json_str).unwrap();

        let x = parse_i128_field(&parsed, "x");
        let y = parse_i128_field(&parsed, "y");
        let salt = parsed["salt"]
            .as_str()
            .unwrap_or_else(|| panic!("salt 不是字符串"));
        let public_commitment = parsed["public_commitment"]
            .as_str()
            .unwrap_or_else(|| panic!("public_commitment 不是字符串"));

        assert!(x >= 0, "x 为负: {}", x);
        assert!(y >= 0, "y 为负: {}", y);
        assert!(!salt.is_empty(), "salt 为空");
        assert!(!public_commitment.is_empty(), "public_commitment 为空");
        assert_eq!(
            poseidon_commitment(&x.to_string(), &y.to_string(), salt).unwrap(),
            public_commitment
        );

        let ax_left = parse_u128_array(&parsed, "Ax_left");
        let by_left = parse_u128_array(&parsed, "By_left");
        let c_left = parse_u128_array(&parsed, "C_left");
        let ax_right = parse_u128_array(&parsed, "Ax_right");
        let by_right = parse_u128_array(&parsed, "By_right");
        let c_right = parse_u128_array(&parsed, "C_right");

        assert_eq!(ax_left.len(), CIRCOM_EDGE_COUNT);
        assert_eq!(by_left.len(), CIRCOM_EDGE_COUNT);
        assert_eq!(c_left.len(), CIRCOM_EDGE_COUNT);
        assert_eq!(ax_right.len(), CIRCOM_EDGE_COUNT);
        assert_eq!(by_right.len(), CIRCOM_EDGE_COUNT);
        assert_eq!(c_right.len(), CIRCOM_EDGE_COUNT);

        let x_u = x as u128;
        let y_u = y as u128;

        for i in 0..CIRCOM_EDGE_COUNT {
            let left = ax_left[i] * x_u + by_left[i] * y_u + c_left[i];
            let right = ax_right[i] * x_u + by_right[i] * y_u + c_right[i];
            assert!(
                left <= right,
                "第 {} 条约束不满足: left={} > right={}",
                i,
                left,
                right
            );
        }
    }

    fn public_fence_fields(parts: &CircuitInputParts) -> Vec<Vec<String>> {
        vec![
            parts.ax_left.clone(),
            parts.by_left.clone(),
            parts.c_left.clone(),
            parts.ax_right.clone(),
            parts.by_right.clone(),
            parts.c_right.clone(),
        ]
    }

    #[test]
    fn test_generate_known_location() {
        let result = generate_circuit_input(39.9042, 116.3974, 9);
        assert!(result.is_ok(), "生成失败: {:?}", result.err());

        let json_str = result.unwrap();
        assert_constraints_hold(&json_str);
    }

    #[test]
    fn test_poseidon_commitment_matches_circom_vector() {
        assert_eq!(
            poseidon_commitment("2963974000", "1299042000", "987654321").unwrap(),
            "20511144390652962277497955662858711904480985876830485470236603349520058278022"
        );
    }

    #[test]
    fn test_public_fence_coefficients_do_not_depend_on_user_point() {
        let coord = LatLng::new(39.9042, 116.3974).unwrap();
        let cell = coord.to_cell(Resolution::try_from(9).unwrap());
        let center: LatLng = cell.into();

        let center_parts = generate_location_parts(center.lat(), center.lng(), 9).unwrap();
        let nearby_parts =
            generate_location_parts(center.lat() + 0.000001, center.lng() + 0.000001, 9).unwrap();

        assert_ne!(center_parts.x, nearby_parts.x);
        assert_ne!(center_parts.y, nearby_parts.y);
        assert_eq!(
            public_fence_fields(&center_parts),
            public_fence_fields(&nearby_parts)
        );
    }

    #[test]
    fn test_generate_known_location2() {
        let result = generate_circuit_input(30.749125, 103.931633, 10);
        assert!(result.is_ok(), "生成失败: {:?}", result.err());

        let json_str = result.unwrap();
        assert_constraints_hold(&json_str);
    }

    #[test]
    fn test_equator_location() {
        let result = generate_circuit_input(0.001, 0.001, 9);
        assert!(result.is_ok(), "生成失败: {:?}", result.err());

        let json_str = result.unwrap();
        assert_constraints_hold(&json_str);
    }

    #[test]
    fn test_antimeridian_location() {
        let result = generate_circuit_input(-17.7765, 177.9885, 9);
        assert!(result.is_ok(), "非跨经线 cell 生成失败: {:?}", result.err());
        assert_constraints_hold(&result.unwrap());

        let result2 = generate_circuit_input(-17.7765, -179.9, 9);
        assert!(result2.is_ok(), "-179° 侧生成失败: {:?}", result2.err());
        assert_constraints_hold(&result2.unwrap());
    }

    #[test]
    fn test_reject_antimeridian_spanning_cell() {
        let boundary = vec![
            LatLng::new(0.0, 179.9).unwrap(),
            LatLng::new(0.0, -179.9).unwrap(),
        ];
        assert!(reject_antimeridian_spanning_cell(&boundary).is_err());
    }

    #[test]
    fn test_supported_resolution_range() {
        for res in 6..=15 {
            let result = generate_circuit_input(39.9042, 116.3974, res);
            assert!(
                result.is_ok(),
                "分辨率 {} 生成失败: {:?}",
                res,
                result.err()
            );

            let json_str = result.unwrap();
            assert_constraints_hold(&json_str);
        }
    }

    #[test]
    fn test_unsupported_low_resolution_can_exceed_six_edges() {
        let result = generate_circuit_input(39.9042, 116.3974, 1);
        assert!(result.is_err(), "固定 6 边电路不应接受 7 顶点 cell");
    }

    #[test]
    fn test_global_coordinate_mapping() {
        assert_eq!(global_lat_int(-90.0).unwrap(), 0);
        assert_eq!(global_lat_int(90.0).unwrap(), 1_800_000_000);
        assert_eq!(global_lon_int(-180.0).unwrap(), 0);
        assert_eq!(global_lon_int(180.0).unwrap(), 3_600_000_000);
        assert_eq!(global_lat_int(39.9042).unwrap(), 1_299_042_000);
        assert_eq!(global_lon_int(116.3974).unwrap(), 2_963_974_000);
    }

    #[test]
    fn test_generate_cell_boundary() {
        let boundary = generate_cell_boundary(30.75316, 103.92829, 15).unwrap();
        let parsed: Value = serde_json::from_str(&boundary).unwrap();
        assert_eq!(parsed["resolution"], 15);
        assert_eq!(parsed["vertices"].as_array().unwrap().len(), 6);
    }
}
