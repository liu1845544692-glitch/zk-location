pub use paste;
pub use serde_json;
use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};

pub mod convert_type;
pub use convert_type::*;

#[doc(hidden)]
pub mod __macro_deps {
    pub use anyhow;
}

/// Macro to generate a witness for a given circuit
#[macro_export]
macro_rules! witness {
    ($x: ident) => {
        $crate::paste::paste! {
            #[allow(non_upper_case_globals)]
            const [<$x _CIRCUIT_DATA>]: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/witnesscalc/src/", stringify!($x), ".dat"));
            #[link(name = "witnesscalc_" [<$x>], kind = "static")]
            extern "C" {
                fn [<witnesscalc_ $x>](
                    circuit_buffer: *const std::os::raw::c_char,
                    circuit_size: std::ffi::c_ulong,
                    json_buffer: *const std::os::raw::c_char,
                    json_size: std::ffi::c_ulong,
                    wtns_buffer: *mut std::os::raw::c_char,
                    wtns_size: *mut std::ffi::c_ulong,
                    error_msg: *mut std::os::raw::c_char,
                    error_msg_maxsize: std::ffi::c_ulong,
                ) -> std::ffi::c_int;
            }
        }
        $crate::paste::item! {
            pub fn [<$x _witness>](json_input: &str) -> $crate::__macro_deps::anyhow::Result<Vec<u8>> {
                // FFI return codes
                const WITNESSCALC_OK: std::ffi::c_int = 0x0;
                const WITNESSCALC_ERROR_SHORT_BUFFER: std::ffi::c_int = 0x2;

                println!("Generating witness for circuit {}", stringify!($x));
                unsafe {
                    let json_input = std::ffi::CString::new(json_input).map_err(|e| $crate::__macro_deps::anyhow::anyhow!("Failed to convert JSON input to CString: {}", e))?;
                    let json_size = json_input.as_bytes().len() as std::ffi::c_ulong;

                    let circuit_buffer = [<$x _CIRCUIT_DATA>].as_ptr() as *const std::ffi::c_char;
                    let circuit_size = [<$x _CIRCUIT_DATA>].len() as std::ffi::c_ulong;

                    let mut error_msg = vec![0u8; 256]; // Error message buffer
                    let error_msg_ptr = error_msg.as_mut_ptr() as *mut std::ffi::c_char;

                    // Two-pass dynamic allocation:
                    // Pass 1: Probe with small buffer to query required size
                    // The witnesscalc FFI mutates calculator state during generation.
                    // Use a practical first-pass buffer so medium circuits do not need
                    // a stateful retry after a short-buffer response.
                    let mut probe_buffer = vec![0u8; 1024 * 1024];
                    let mut wtns_size: std::ffi::c_ulong = probe_buffer.len() as std::ffi::c_ulong;

                    let result = [<witnesscalc_ $x>](
                        circuit_buffer,
                        circuit_size,
                        json_input.as_ptr(),
                        json_size,
                        probe_buffer.as_mut_ptr() as *mut _,
                        &mut wtns_size as *mut _,
                        error_msg_ptr,
                        error_msg.len() as u64,
                    );

                    // Pass 2: If buffer too small, allocate exact size and retry
                    let final_buffer = if result == WITNESSCALC_ERROR_SHORT_BUFFER {
                        // wtns_size now contains the required minimum size
                        let required_size = wtns_size as usize;
                        println!("Witness requires {} bytes, allocating and retrying...", required_size);

                        let mut wtns_buffer = vec![0u8; required_size];
                        let mut wtns_size: std::ffi::c_ulong = required_size as std::ffi::c_ulong;

                        let result = [<witnesscalc_ $x>](
                            circuit_buffer,
                            circuit_size,
                            json_input.as_ptr(),
                            json_size,
                            wtns_buffer.as_mut_ptr() as *mut _,
                            &mut wtns_size as *mut _,
                            error_msg_ptr,
                            error_msg.len() as u64,
                        );

                        if result != WITNESSCALC_OK {
                            let error_string = std::ffi::CStr::from_ptr(error_msg_ptr)
                                .to_string_lossy()
                                .into_owned();
                            return Err($crate::__macro_deps::anyhow::anyhow!("Witness generation failed: {}", error_string));
                        }

                        wtns_buffer[..wtns_size as usize].to_vec()
                    } else if result == WITNESSCALC_OK {
                        // Success on first try with probe buffer (small witness)
                        probe_buffer[..wtns_size as usize].to_vec()
                    } else {
                        // Other error
                        let error_string = std::ffi::CStr::from_ptr(error_msg_ptr)
                            .to_string_lossy()
                            .into_owned();
                        return Err($crate::__macro_deps::anyhow::anyhow!("Witness generation failed: {}", error_string));
                    };

                    Ok(final_buffer)
                }
            }
        }
    };
}

const WITNESSCALC_BUILD_SCRIPT: &str = include_str!("../clone_witnesscalc.sh");

pub fn build_and_link(circuits_dir: &str) {
    if Path::new(circuits_dir).join("calcwit.cpp").exists()
        && Path::new(circuits_dir).join("circom.hpp").exists()
        && Path::new(circuits_dir).join("fr.cpp").exists()
    {
        build_standalone_and_link(circuits_dir);
        return;
    }

    let target = env::var("TARGET").expect("Cargo did not provide the TARGET environment variable");

    let out_dir = env::var("OUT_DIR").expect("OUT_DIR not set");
    let lib_dir = Path::new(&out_dir)
        .join("witnesscalc")
        .join("package")
        .join("lib");

    if !Path::is_dir(Path::new(circuits_dir)) {
        panic!("circuits_dir must be a directory");
    }
    println!("cargo:rerun-if-changed={}", circuits_dir);

    let witnesscalc_path = Path::new(&out_dir).join(Path::new("witnesscalc"));
    // If the witnesscalc repo is not cloned, clone it
    if !witnesscalc_path.exists() {
        let witnesscalc_script_path = Path::new(&out_dir).join(Path::new("clone_witnesscalc.sh"));
        fs::write(&witnesscalc_script_path, WITNESSCALC_BUILD_SCRIPT)
            .expect("Failed to write build script");
        Command::new("sh")
            .arg(witnesscalc_script_path.to_str().unwrap())
            .spawn()
            .expect("Failed to spawn witnesscalc build")
            .wait()
            .expect("witnesscalc build errored");
    }
    patch_circom_2_2_runtime(&witnesscalc_path);

    println!("Detected target: {}", target);
    //For possible options see witnesscalc/build_gmp.sh
    let gmp_build_target = match target.as_str() {
        "aarch64-apple-ios" => "ios",
        "aarch64-apple-ios-sim" => "ios_simulator",
        "x86_64-apple-ios" => "ios_simulator",
        "x86_64-linux-android" => "android_x86_64",
        "i686-linux-android" => "android_x86_64",
        "armv7-linux-androideabi" => "android",
        "aarch64-linux-android" => "android",
        "aarch64-apple-darwin" => "host", //Use "host" for M Macs, macos_arm64 would fail the subsequent build
        _ => "host",
    };

    let gmp_lib_folder = match target.as_str() {
        "aarch64-apple-ios" => "package_ios_arm64",
        "aarch64-apple-ios-sim" => "package_iphone_simulator_arm64",
        "x86_64-apple-ios" => "package_iphone_simulator_x86_64",
        "x86_64-linux-android" => "package_android_x86_64",
        "i686-linux-android" => "package_android_x86_64",
        "armv7-linux-androideabi" => "package_android_arm64",
        "aarch64-linux-android" => "package_android_arm64",
        _ => "package",
    };
    //For possible options see witnesscalc/Makefile
    let witnesscalc_build_target = match target.as_str() {
        "aarch64-apple-ios" => "ios",
        "aarch64-apple-ios-sim" => "ios_simulator_arm64",
        "x86_64-apple-ios" => "ios_simulator_x86_64",
        "x86_64-linux-android" => "android_x86_64",
        "i686-linux-android" => "android_x86_64",
        "armv7-linux-androideabi" => "android",
        "aarch64-linux-android" => "android",
        "aarch64-apple-darwin" => "arm64_host",
        _ => "host",
    };

    // If the witnesscalc library is not built, build it
    let gmp_dir = witnesscalc_path.join("depends").join("gmp");
    let target_dir = gmp_dir.join(gmp_lib_folder);
    if !target_dir.exists() {
        Command::new("bash")
            .current_dir(&witnesscalc_path)
            .arg("./build_gmp.sh")
            .arg(gmp_build_target)
            .spawn()
            .expect("Failed to spawn build_gmp.sh")
            .wait()
            .expect("build_gmp.sh errored");
    }

    //find all the .cpp files in the circuits_dir
    let circuit_files = fs::read_dir(circuits_dir)
        .expect("Failed to read circuits directory")
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some() && path.extension().unwrap() == "cpp")
        .collect::<Vec<_>>();

    let mut v2_1_0_circuit_files: Vec<PathBuf> = Vec::new();
    let mut v2_2_0_circuit_files: Vec<PathBuf> = Vec::new();

    // Copy each circuit .cpp and .dat into witnesscalc/src, replacing any existing files
    circuit_files.iter().for_each(|path| {
        let circuit_name = path.file_stem().unwrap().to_str().unwrap();
        let circuit_dat = path.with_extension("dat");
        let circuit_dat_name = circuit_dat.file_name().unwrap().to_str().unwrap();
        let circuit_dat_dest = witnesscalc_path.join("src").join(circuit_dat_name);
        fs::copy(&circuit_dat, &circuit_dat_dest).expect("Failed to copy circuit .dat file");
        //For each .cpp file, do the following: find the last include statement (should be #include "calcwit.hpp") and insert the following on the next line: namespace CIRCUIT_NAME {. Then, insert the closing } at the end of the file:
        let circuit_cpp = fs::read_to_string(path).expect("Failed to read circuit .cpp file");
        let circuit_cpp = circuit_cpp.replace(
            "#include \"calcwit.hpp\"",
            "#include \"calcwit.hpp\"\nnamespace CIRCUIT_NAME {",
        );
        let circuit_cpp = circuit_cpp + "\n}";
        let circuit_cpp_name = witnesscalc_path.join("src").join(circuit_name);
        let circuit_cpp_dest = circuit_cpp_name.with_extension("cpp");
        fs::write(&circuit_cpp_dest, &circuit_cpp).expect("Failed to write circuit .cpp file");

        let circuit_cpp_str = &circuit_cpp;
        if circuit_cpp_str.contains("uint get_size_of_bus_field_map() {return 0;}") {
            v2_2_0_circuit_files.push(path.clone());
        } else {
            v2_1_0_circuit_files.push(path.clone());
        }
    });

    build_for_circuits_with_different_versions(
        &v2_1_0_circuit_files,
        &witnesscalc_path,
        &witnesscalc_build_target,
    );
    if v2_2_0_circuit_files.len() > 0 {
        Command::new("git")
            .arg("checkout")
            .arg("v2.2.0")
            .current_dir(&witnesscalc_path)
            .spawn()
            .expect("Failed to spawn git checkout v2.2.0")
            .wait()
            .expect("git checkout v2.2.0 errored");
        build_for_circuits_with_different_versions(
            &v2_2_0_circuit_files,
            &witnesscalc_path,
            &witnesscalc_build_target,
        );
    }

    // Link the C++ standard library. This is necessary for Rust tests to run on the host,
    // non-host targets may require a specific way of linking (e.g., through linking flags in xcode)
    #[cfg(target_os = "macos")]
    {
        println!("cargo:rustc-link-lib=c++"); // macOS default
    }
    #[cfg(not(target_os = "macos"))]
    {
        println!("cargo:rustc-link-lib=stdc++"); // Linux or other platforms
    }
    // Link the gmp and fr libraries
    println!("cargo:rustc-link-lib=static=gmp");
    println!("cargo:rustc-link-lib=static=fr");
    // Specify the path to the witnesscalc library for the linker
    println!(
        "cargo:rustc-link-search=native={}",
        lib_dir.to_string_lossy()
    );

    if !(env::var("CARGO_CFG_TARGET_OS").unwrap().contains("ios")
        || env::var("CARGO_CFG_TARGET_OS").unwrap().contains("android"))
    {
        println!("cargo:rustc-link-lib=dylib=fr");
        println!("cargo:rustc-link-lib=dylib=gmp");
    }
}

fn build_standalone_and_link(circuits_dir: &str) {
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR not set"));
    let src_out = out_dir.join("witnesscalc").join("src");
    let lib_out = out_dir.join("witnesscalc").join("package").join("lib");
    fs::create_dir_all(&src_out).expect("Failed to create standalone witnesscalc src dir");
    fs::create_dir_all(&lib_out).expect("Failed to create standalone witnesscalc lib dir");

    println!("cargo:rerun-if-changed={}", circuits_dir);

    let circuits_path = Path::new(circuits_dir);
    let circuit_files = fs::read_dir(circuits_path)
        .expect("Failed to read circuits directory")
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some() && path.extension().unwrap() == "cpp")
        .filter(|path| {
            let stem = path.file_stem().unwrap().to_string_lossy();
            !matches!(stem.as_ref(), "calcwit" | "fr" | "main")
        })
        .filter(|path| path.with_extension("dat").exists())
        .collect::<Vec<_>>();

    let fr_asm_obj = src_out.join("fr_asm.o");
    run_command(
        Command::new("nasm")
            .arg("-felf64")
            .arg("-DPIC")
            .arg(circuits_path.join("fr.asm"))
            .arg("-o")
            .arg(&fr_asm_obj),
        "nasm fr.asm",
    );

    for circuit in circuit_files {
        let circuit_name = circuit.file_stem().unwrap().to_str().unwrap();
        let dat_path = circuit.with_extension("dat");
        fs::copy(&dat_path, src_out.join(dat_path.file_name().unwrap()))
            .expect("Failed to copy circuit .dat file");

        let wrapper_path = src_out.join(format!("witnesscalc_{}.cpp", circuit_name));
        fs::write(&wrapper_path, standalone_wrapper_source(circuit_name))
            .expect("Failed to write standalone witnesscalc wrapper");

        let sources = [
            circuits_path.join("fr.cpp"),
            circuits_path.join("calcwit.cpp"),
            circuit.clone(),
            wrapper_path,
        ];

        let mut objects = Vec::new();
        for source in sources {
            let object = src_out.join(format!(
                "{}.{}.o",
                circuit_name,
                source.file_stem().unwrap().to_string_lossy()
            ));
            run_command(
                Command::new("g++")
                    .arg("-c")
                    .arg(&source)
                    .arg("-std=c++11")
                    .arg("-O3")
                    .arg("-fPIC")
                    .arg("-I")
                    .arg(circuits_path)
                    .arg("-o")
                    .arg(&object),
                "g++ compile standalone witnesscalc source",
            );
            objects.push(object);
        }
        objects.push(fr_asm_obj.clone());

        let lib_path = lib_out.join(format!("libwitnesscalc_{}.a", circuit_name));
        let mut ar = Command::new("ar");
        ar.arg("crus").arg(&lib_path);
        for object in &objects {
            ar.arg(object);
        }
        run_command(&mut ar, "ar standalone witnesscalc library");

        println!("cargo:rustc-link-lib=static=witnesscalc_{}", circuit_name);
    }

    println!("cargo:rustc-link-search=native={}", lib_out.to_string_lossy());
    println!("cargo:rustc-link-lib=stdc++");
    println!("cargo:rustc-link-lib=gmp");
}

fn run_command(command: &mut Command, label: &str) {
    let output = command
        .output()
        .unwrap_or_else(|e| panic!("Failed to execute {label}: {e}"));
    if !output.status.success() {
        panic!(
            "{label} failed with status {}\nstdout: {}\nstderr: {}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

fn standalone_wrapper_source(circuit_name: &str) -> String {
    format!(
        r#"
#include <assert.h>
#include <iomanip>
#include <iostream>
#include <nlohmann/json.hpp>
#include <sstream>
#include <string.h>
#include <vector>

#include "calcwit.hpp"
#include "circom.hpp"

using json = nlohmann::json;

static Circom_Circuit* loadCircuitFromBuffer(const char *circuit_buffer, unsigned long buffer_size) {{
    Circom_Circuit *circuit = new Circom_Circuit;
    u8* bdata = (u8*)circuit_buffer;

    circuit->InputHashMap = new HashSignalInfo[get_size_of_input_hashmap()];
    uint dsize = get_size_of_input_hashmap()*sizeof(HashSignalInfo);
    memcpy((void *)(circuit->InputHashMap), (void *)bdata, dsize);

    circuit->witness2SignalList = new u64[get_size_of_witness()];
    uint inisize = dsize;
    dsize = get_size_of_witness()*sizeof(u64);
    memcpy((void *)(circuit->witness2SignalList), (void *)(bdata+inisize), dsize);

    circuit->circuitConstants = new FrElement[get_size_of_constants()];
    if (get_size_of_constants()>0) {{
      inisize += dsize;
      dsize = get_size_of_constants()*sizeof(FrElement);
      memcpy((void *)(circuit->circuitConstants), (void *)(bdata+inisize), dsize);
    }}

    std::map<u32,IOFieldDefPair> templateInsId2IOSignalInfo1;
    IOFieldDefPair* busInsId2FieldInfo1 = nullptr;
    if (get_size_of_io_map()>0) {{
      u32 index[get_size_of_io_map()];
      inisize += dsize;
      dsize = get_size_of_io_map()*sizeof(u32);
      memcpy((void *)index, (void *)(bdata+inisize), dsize);
      inisize += dsize;
      u32 dataiomap[(buffer_size-inisize)/sizeof(u32)];
      memcpy((void *)dataiomap, (void *)(bdata+inisize), buffer_size-inisize);
      u32* pu32 = dataiomap;
      for (int i = 0; i < get_size_of_io_map(); i++) {{
        u32 n = *pu32;
        IOFieldDefPair p;
        p.len = n;
        IOFieldDef defs[n];
        pu32 += 1;
        for (u32 j = 0; j < n; j++){{
          defs[j].offset=*pu32;
          u32 len = *(pu32+1);
          defs[j].len = len;
          defs[j].lengths = new u32[len];
          memcpy((void *)defs[j].lengths,(void *)(pu32+2),len*sizeof(u32));
          pu32 += len + 2;
          defs[j].size=*pu32;
          defs[j].busId=*(pu32+1);
          pu32 += 2;
        }}
        p.defs = (IOFieldDef*)calloc(p.len, sizeof(IOFieldDef));
        for (u32 j = 0; j < p.len; j++){{
          p.defs[j] = defs[j];
        }}
        templateInsId2IOSignalInfo1[index[i]] = p;
      }}
      busInsId2FieldInfo1 = (IOFieldDefPair*)calloc(get_size_of_bus_field_map(), sizeof(IOFieldDefPair));
      for (int i = 0; i < get_size_of_bus_field_map(); i++) {{
        u32 n = *pu32;
        IOFieldDefPair p;
        p.len = n;
        IOFieldDef defs[n];
        pu32 += 1;
        for (u32 j = 0; j < n; j++){{
          defs[j].offset=*pu32;
          u32 len = *(pu32+1);
          defs[j].len = len;
          defs[j].lengths = new u32[len];
          memcpy((void *)defs[j].lengths,(void *)(pu32+2),len*sizeof(u32));
          pu32 += len + 2;
          defs[j].size=*pu32;
          defs[j].busId=*(pu32+1);
          pu32 += 2;
        }}
        p.defs = (IOFieldDef*)calloc(p.len, sizeof(IOFieldDef));
        for (u32 j = 0; j < p.len; j++){{
          p.defs[j] = defs[j];
        }}
        busInsId2FieldInfo1[i] = p;
      }}
    }}
    circuit->templateInsId2IOSignalInfo = std::move(templateInsId2IOSignalInfo1);
    circuit->busInsId2FieldInfo = busInsId2FieldInfo1;
    return circuit;
}}

static bool check_valid_number(std::string & s, uint base){{
  bool is_valid = true;
  if (base == 16){{
    for (uint i = 0; i < s.size(); i++){{
      is_valid &= (('0' <= s[i] && s[i] <= '9') || ('a' <= s[i] && s[i] <= 'f') || ('A' <= s[i] && s[i] <= 'F'));
    }}
  }} else {{
    for (uint i = 0; i < s.size(); i++){{
      is_valid &= ('0' <= s[i] && s[i] < char(int('0') + base));
    }}
  }}
  return is_valid;
}}

static void json2FrElements (json val, std::vector<FrElement> & vval){{
  if (!val.is_array()) {{
    FrElement v;
    std::string s_aux, s;
    uint base;
    if (val.is_string()) {{
      s_aux = val.get<std::string>();
      std::string possible_prefix = s_aux.substr(0, 2);
      if (possible_prefix == "0b" || possible_prefix == "0B"){{ s = s_aux.substr(2, s_aux.size() - 2); base = 2; }}
      else if (possible_prefix == "0o" || possible_prefix == "0O"){{ s = s_aux.substr(2, s_aux.size() - 2); base = 8; }}
      else if (possible_prefix == "0x" || possible_prefix == "0X"){{ s = s_aux.substr(2, s_aux.size() - 2); base = 16; }}
      else{{ s = s_aux; base = 10; }}
      if (!check_valid_number(s, base)){{ throw std::runtime_error("Invalid number in JSON input: " + s_aux); }}
    }} else if (val.is_number()) {{
      double vd = val.get<double>();
      std::stringstream stream;
      stream << std::fixed << std::setprecision(0) << vd;
      s = stream.str();
      base = 10;
    }} else {{
      throw std::runtime_error("Invalid JSON type");
    }}
    Fr_str2element (&v, s.c_str(), base);
    vval.push_back(v);
  }} else {{
    for (uint i = 0; i < val.size(); i++) {{
      json2FrElements (val[i], vval);
    }}
  }}
}}

static json::value_t check_type(std::string prefix, json in){{
  if (!in.is_array()) {{
    if (in.is_number_integer() || in.is_number_unsigned() || in.is_string()) return json::value_t::number_integer;
    return in.type();
  }}
  if (in.size() == 0) return json::value_t::null;
  json::value_t t = check_type(prefix, in[0]);
  for (uint i = 1; i < in.size(); i++) {{
    if (t != check_type(prefix, in[i])) throw std::runtime_error("Types are not the same in key " + prefix);
  }}
  return t;
}}

static void qualify_input(std::string prefix, json &in, json &in1);
static void qualify_input_list(std::string prefix, json &in, json &in1){{
  if (in.is_array()) {{
    for (uint i = 0; i<in.size(); i++) {{
      std::string new_prefix = prefix + "[" + std::to_string(i) + "]";
      qualify_input_list(new_prefix,in[i],in1);
    }}
  }} else {{
    qualify_input(prefix,in,in1);
  }}
}}

static void qualify_input(std::string prefix, json &in, json &in1) {{
  if (in.is_array()) {{
    if (in.size() > 0) {{
      json::value_t t = check_type(prefix,in);
      if (t == json::value_t::object) qualify_input_list(prefix,in,in1);
      else in1[prefix] = in;
    }} else {{
      in1[prefix] = in;
    }}
  }} else if (in.is_object()) {{
    for (json::iterator it = in.begin(); it != in.end(); ++it) {{
      std::string new_prefix = prefix.length() == 0 ? it.key() : prefix + "." + it.key();
      qualify_input(new_prefix,it.value(),in1);
    }}
  }} else {{
    in1[prefix] = in;
  }}
}}

static void loadJson(Circom_CalcWit *ctx, const char *json_buffer, unsigned long buffer_size) {{
  json jin = json::parse(json_buffer, json_buffer + buffer_size);
  json j;
  std::string prefix = "";
  qualify_input(prefix, jin, j);
  if (j.size() == 0) ctx->tryRunCircuit();
  for (json::iterator it = j.begin(); it != j.end(); ++it) {{
    u64 h = fnv1a(it.key());
    std::vector<FrElement> v;
    json2FrElements(it.value(),v);
    uint signalSize = ctx->getInputSignalSize(h);
    if (v.size() < signalSize) throw std::runtime_error("Error loading signal " + it.key() + ": Not enough values");
    if (v.size() > signalSize) throw std::runtime_error("Error loading signal " + it.key() + ": Too many values");
    for (uint i = 0; i<v.size(); i++) {{
      try {{
        ctx->setInputSignal(h,i,v[i]);
      }} catch (std::runtime_error &e) {{
        throw std::runtime_error("Error setting signal: " + it.key() + "\n" + e.what());
      }}
    }}
  }}
}}

static char *appendBuffer(char *buffer, const void *src, unsigned long src_size) {{
  memcpy(buffer, src, src_size);
  return buffer + src_size;
}}

static unsigned long getBinWitnessSize() {{
  uint Nwtns = get_size_of_witness();
  return 44 + Fr_N64*8 * (Nwtns + 1);
}}

static void storeBinWitness(Circom_CalcWit *ctx, char *wtns_buffer) {{
  char *buffer = wtns_buffer;
  buffer = appendBuffer(buffer, "wtns", 4);
  u32 version = 2;
  buffer = appendBuffer(buffer, &version, 4);
  u32 nSections = 2;
  buffer = appendBuffer(buffer, &nSections, 4);
  u32 idSection1 = 1;
  buffer = appendBuffer(buffer, &idSection1, 4);
  u32 n8 = Fr_N64*8;
  u64 idSection1length = 8 + n8;
  buffer = appendBuffer(buffer, &idSection1length, 8);
  buffer = appendBuffer(buffer, &n8, 4);
  buffer = appendBuffer(buffer, Fr_q.longVal, Fr_N64*8);
  u32 nVars = (u32)get_size_of_witness();
  buffer = appendBuffer(buffer, &nVars, 4);
  u32 idSection2 = 2;
  buffer = appendBuffer(buffer, &idSection2, 4);
  u64 idSection2length = (u64)n8*(u64)nVars;
  buffer = appendBuffer(buffer, &idSection2length, 8);
  FrElement v;
  for (u32 i=0; i<nVars; i++) {{
    ctx->getWitness(i, &v);
    Fr_toLongNormal(&v, &v);
    buffer = appendBuffer(buffer, v.longVal, Fr_N64*8);
  }}
}}

extern "C" int witnesscalc_{0}(
    const char *circuit_buffer, unsigned long circuit_size,
    const char *json_buffer, unsigned long json_size,
    char *wtns_buffer, unsigned long *wtns_size,
    char *error_msg, unsigned long error_msg_maxsize) {{
  const int WITNESSCALC_OK = 0x0;
  const int WITNESSCALC_ERROR = 0x1;
  const int WITNESSCALC_ERROR_SHORT_BUFFER = 0x2;
  try {{
    Circom_Circuit *circuit = loadCircuitFromBuffer(circuit_buffer, circuit_size);
    Circom_CalcWit *ctx = new Circom_CalcWit(circuit);
    loadJson(ctx, json_buffer, json_size);
    if (ctx->getRemaingInputsToBeSet()!=0) {{
      throw std::runtime_error("Not all inputs have been set");
    }}
    unsigned long required_size = getBinWitnessSize();
    if (*wtns_size < required_size) {{
      *wtns_size = required_size;
      return WITNESSCALC_ERROR_SHORT_BUFFER;
    }}
    storeBinWitness(ctx, wtns_buffer);
    *wtns_size = required_size;
    return WITNESSCALC_OK;
  }} catch (std::exception &e) {{
    if (error_msg != nullptr && error_msg_maxsize > 0) {{
      strncpy(error_msg, e.what(), error_msg_maxsize - 1);
      error_msg[error_msg_maxsize - 1] = 0;
    }}
    return WITNESSCALC_ERROR;
  }}
}}
"#,
        circuit_name
    )
}

fn patch_circom_2_2_runtime(witnesscalc_path: &Path) {
    let src_dir = witnesscalc_path.join("src");
    let circom_hpp_path = src_dir.join("circom.hpp");
    let calcwit_cpp_path = src_dir.join("calcwit.cpp");
    let witnesscalc_cpp_path = src_dir.join("witnesscalc.cpp");

    let mut circom_hpp =
        fs::read_to_string(&circom_hpp_path).expect("Failed to read witnesscalc circom.hpp");
    if !circom_hpp.contains("struct IOFieldDef") {
        circom_hpp = circom_hpp.replace("struct IODef {", "struct IOFieldDef {");
        circom_hpp = circom_hpp.replace(
            "    u32 *lengths = nullptr;\n};",
            "    u32 *lengths = nullptr;\n    u32 size;\n    u32 busId;\n};",
        );
        circom_hpp = circom_hpp.replace("struct IODefPair {", "struct IOFieldDefPair {");
        circom_hpp = circom_hpp.replace("IODef* defs = nullptr;", "IOFieldDef* defs = nullptr;");
        circom_hpp = circom_hpp.replace(
            "std::map<u32,IODefPair> templateInsId2IOSignalInfo;",
            "std::map<u32,IOFieldDefPair> templateInsId2IOSignalInfo;\n  IOFieldDefPair* busInsId2FieldInfo = nullptr;",
        );
        fs::write(&circom_hpp_path, circom_hpp).expect("Failed to patch circom.hpp");
    }

    let mut calcwit_cpp =
        fs::read_to_string(&calcwit_cpp_path).expect("Failed to read witnesscalc calcwit.cpp");
    if !calcwit_cpp.contains("busInsId2FieldInfo = circuit -> busInsId2FieldInfo;") {
        calcwit_cpp = calcwit_cpp.replace(
            "templateInsId2IOSignalInfo = circuit -> templateInsId2IOSignalInfo;\n",
            "templateInsId2IOSignalInfo = circuit -> templateInsId2IOSignalInfo;\n  busInsId2FieldInfo = circuit -> busInsId2FieldInfo;\n",
        );
        fs::write(&calcwit_cpp_path, calcwit_cpp).expect("Failed to patch calcwit.cpp");
    }

    let mut witnesscalc_cpp =
        fs::read_to_string(&witnesscalc_cpp_path).expect("Failed to read witnesscalc.cpp");
    if witnesscalc_cpp.contains("std::map<u32,IODefPair>") {
        witnesscalc_cpp = witnesscalc_cpp.replace("IODefPair", "IOFieldDefPair");
        witnesscalc_cpp = witnesscalc_cpp.replace("IODef", "IOFieldDef");
        witnesscalc_cpp = witnesscalc_cpp.replace(
            "          memcpy((void *)defs[j].lengths,(void *)(pu32+2),len*sizeof(u32));\n          pu32 += len + 2;\n",
            "          memcpy((void *)defs[j].lengths,(void *)(pu32+2),len*sizeof(u32));\n          pu32 += len + 2;\n          defs[j].size=*pu32;\n          defs[j].busId=*(pu32+1);\n          pu32 += 2;\n",
        );
        witnesscalc_cpp = witnesscalc_cpp.replace(
            "    circuit->templateInsId2IOSignalInfo = std::move(templateInsId2IOSignalInfo1);\n\n    return circuit;",
            "    circuit->templateInsId2IOSignalInfo = std::move(templateInsId2IOSignalInfo1);\n\n    circuit->busInsId2FieldInfo = (IOFieldDefPair*)calloc(get_size_of_bus_field_map(), sizeof(IOFieldDefPair));\n    for (int i = 0; i < get_size_of_bus_field_map(); i++) {\n      u32 n = *pu32;\n      IOFieldDefPair p;\n      p.len = n;\n      IOFieldDef defs[n];\n      pu32 += 1;\n      for (u32 j = 0; j < n; j++){\n        defs[j].offset=*pu32;\n        u32 len = *(pu32+1);\n        defs[j].len = len;\n        defs[j].lengths = new u32[len];\n        memcpy((void *)defs[j].lengths,(void *)(pu32+2),len*sizeof(u32));\n        pu32 += len + 2;\n        defs[j].size=*pu32;\n        defs[j].busId=*(pu32+1);\n        pu32 += 2;\n      }\n      p.defs = (IOFieldDef*)calloc(p.len, sizeof(IOFieldDef));\n      for (u32 j = 0; j < p.len; j++){\n        p.defs[j] = defs[j];\n      }\n      circuit->busInsId2FieldInfo[i] = p;\n    }\n\n    return circuit;",
        );
        fs::write(&witnesscalc_cpp_path, witnesscalc_cpp)
            .expect("Failed to patch witnesscalc.cpp");
    }
}

fn build_for_circuits_with_different_versions(
    circuit_files: &Vec<PathBuf>,
    witnesscalc_path: &Path,
    witnesscalc_build_target: &str,
) {
    circuit_files.iter().for_each(|path| {
        let circuit_name = path.file_stem().unwrap().to_str().unwrap();
        //Find a witnesscalc_template.cpp template file in the src. Replace all the @CIRCUIT_NAME@ inside it with the circuit name and write it to the src directory, replacing "template" in the name with the circuit name
        let template_path = witnesscalc_path
            .join("src")
            .join("witnesscalc_template.cpp");
        let template = fs::read_to_string(&template_path).expect("Failed to read template file");
        let template = template.replace("@CIRCUIT_NAME@", circuit_name);
        let template_dest = witnesscalc_path
            .join("src")
            .join(format!("witnesscalc_{}.cpp", circuit_name));
        fs::write(&template_dest, template).expect("Failed to write the templated .cpp file");
        //Find a witnesscalc_template.h template file in the src. Replace all the @CIRCUIT_NAME@ inside it with the circuit name, @CIRCUIT_NAME_CAPS@ with the capitalized name, and write it to the src directory, replacing "template" in the name with the circuit name
        let template_path = witnesscalc_path.join("src").join("witnesscalc_template.h");
        let template = fs::read_to_string(&template_path).expect("Failed to read template file");
        let template = template
            .replace("@CIRCUIT_NAME@", circuit_name)
            .replace("@CIRCUIT_NAME_CAPS@", &circuit_name.to_uppercase());
        let template_dest = witnesscalc_path
            .join("src")
            .join(format!("witnesscalc_{}.h", circuit_name));
        fs::write(&template_dest, template).expect("Failed to write the templated .h file");
    });

    //the circuit name list would look like "circuit1;circuit2;circuit3"
    let circuit_names = circuit_files
        .iter()
        .map(|path| path.file_stem().unwrap().to_str().unwrap())
        .collect::<Vec<_>>();

    let circuit_names_semicolon = circuit_names.join(";");

    let make_process = Command::new("make")
        .env("CIRCUIT_NAMES", circuit_names_semicolon)
        .arg(witnesscalc_build_target)
        .current_dir(&witnesscalc_path)
        .output()
        .expect("Failed to execute make arm64_host");

    if !make_process.status.success() {
        eprintln!(
            "Make command failed with exit code: {}",
            make_process.status
        );
        eprintln!("stdout: {}", String::from_utf8_lossy(&make_process.stdout));
        eprintln!("stderr: {}", String::from_utf8_lossy(&make_process.stderr));

        // Check if any of the required libraries were actually built despite the error
        let lib_dir = witnesscalc_path.join("package").join("lib");
        let mut all_libs_exist = true;

        for circuit_name in &circuit_names {
            let lib_path = lib_dir.join(format!("libwitnesscalc_{}.a", circuit_name));
            if !lib_path.exists() {
                eprintln!("Warning: Library {} was not built", lib_path.display());
                all_libs_exist = false;
            }
        }

        if !all_libs_exist {
            panic!("Make command failed and required libraries are missing");
        } else {
            eprintln!("Warning: Make command failed but required libraries exist. Continuing...");
        }
    }

    // Link the witnesscalc library for the circuit
    circuit_names.iter().for_each(|circuit_name| {
        println!("cargo:rustc-link-lib=static=witnesscalc_{}", circuit_name);
    });

    if !(env::var("CARGO_CFG_TARGET_OS").unwrap().contains("ios")
        || env::var("CARGO_CFG_TARGET_OS").unwrap().contains("android"))
    {
        circuit_names.iter().for_each(|circuit_name| {
            println!("cargo:rustc-link-lib=dylib=witnesscalc_{}", circuit_name);
        });
    }
}
