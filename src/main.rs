use std::{collections::HashSet, env, fs, io::Write, mem, path::Path, sync::atomic::{AtomicBool, Ordering}, time::{Duration, SystemTime}};
const VERSION: &str = "1.6.3";
const BASE_CPUSET: &str = "/dev/cpuset/AppOpt";
const LOG_FILE: &str = "/sdcard/Android/Aether/threads_log.txt";
fn wlog(level: &str, msg: &str) {
  let mut now: libc::time_t = 0;
  unsafe { libc::time(&mut now); }
  let mut tm: libc::tm = unsafe { mem::zeroed() };
  unsafe { libc::localtime_r(&now, &mut tm); }
  let line = format!("[{:02}:{:02}:{:02}][{}] {}\n", tm.tm_hour, tm.tm_min, tm.tm_sec, level, msg);
  let _ = std::io::stderr().write_all(line.as_bytes());
  if let Ok(mut f) = fs::OpenOptions::new().create(true).append(true).open(LOG_FILE) {
    let _ = f.write_all(line.as_bytes());
  }
}
macro_rules! i { ($($a:tt)*) => { wlog("INFO", &format!($($a)*)) }; }
macro_rules! e { ($($a:tt)*) => { wlog("ERROR", &format!($($a)*)) }; }
#[derive(Clone)]
struct R { p: String, t: String, c: String, pr: i32 }
fn rp(pat: &str) -> i32 {
  if pat.is_empty() { return 200; }
  if !pat.contains('*') && !pat.contains('?') { return 1000 + pat.len() as i32; }
  let nw = pat.chars().filter(|c| !matches!(c, '*' | '?' | '[' | ']')).count() as i32;
  if pat.contains('[') { 500 + nw } else if pat.contains('?') { 300 + nw } else { 100 + nw }
}
fn mt(p: &str, n: &str) -> bool {
  if p.is_empty() { return false; }
  match p.find('*') {
    None => p == n,
    Some(pos) => n.starts_with(&p[..pos]) && (p[pos+1..].is_empty() || n[pos..].ends_with(&p[pos+1..]))
  }
}
struct C { r: Vec<R>, s: HashSet<String>, m: SystemTime, ebpf: bool, auto_for_none: bool }
impl C {
  fn load(p: &str) -> Option<Self> {
    let d = fs::read_to_string(p).ok()?;
    let root = json::parse(&d).ok()?;
    let ebpf = root["features"]["ebpf"].as_bool().unwrap_or(true);
    let auto_for_none = root["features"]["auto-for-none"].as_bool().unwrap_or(false);
    let entries = if root.is_array() { &root } else { &root["rules"] };
    if !entries.is_array() { return None; }
    let mut r = Vec::new(); let mut s = HashSet::new();
    for e in entries.members() {
      let pl: Vec<String> = e["packages"].members().filter_map(|v| v.as_str().map(String::from)).collect();
      if pl.is_empty() { continue; }
      let o = e["cpuset"]["other"].as_str().unwrap_or("0");
      for pk in &pl { s.insert(pk.clone()); }
      r.push(R { p: pl[0].clone(), t: String::new(), c: o.to_string(), pr: 200 });
      if e["cpuset"]["comm"].is_object() {
        for (cpus, ns) in e["cpuset"]["comm"].entries() {
          for nv in ns.members() { if let Some(n) = nv.as_str() { r.push(R { p: pl[0].clone(), t: n.to_string(), c: cpus.to_string(), pr: rp(n) }); } }
        }
      }
    }
    let mt = fs::metadata(p).ok()?.modified().ok()?;
    let ebpf = root["features"]["ebpf"].as_bool().unwrap_or(true);
    let auto_for_none = root["features"]["auto-for-none"].as_bool().unwrap_or(false);
    Some(C { r, s, m: mt, ebpf, auto_for_none })
  }
}
fn sp2(r: &[R], s: &HashSet<String>) -> Vec<(i32, String, Vec<(i32, String, String)>)> {
  let mut v = Vec::new();
  let d = match fs::read_dir("/proc") { Ok(x) => x, Err(_) => return v };
  for e in d.flatten() {
    let pid: i32 = match e.file_name().to_string_lossy().parse() { Ok(p) => p, Err(_) => continue };
    if pid < 1000 { continue; }
    let cl = fs::read_to_string(e.path().join("cmdline")).unwrap_or_default();
    let pkg = cl.split('\0').next().unwrap_or("").trim_end_matches('\0').to_string();
    if pkg.is_empty() || !s.contains(&pkg) { continue; }
    let mut th = Vec::new();
    if let Ok(tk) = fs::read_dir(e.path().join("task")) {
      for t in tk.flatten() {
        let tid: i32 = t.file_name().to_string_lossy().parse().unwrap_or(0);
        let comm = fs::read_to_string(t.path().join("comm")).unwrap_or_default().trim().to_string();
        let mut bc = String::new(); let mut bp = -1i32;
        for ru in r {
          if ru.p != pkg { continue; }
          if ru.t.is_empty() { if 200 > bp { bc = ru.c.clone(); bp = 200; } }
          else if mt(&ru.t, &comm) && ru.pr > bp { bc = ru.c.clone(); bp = ru.pr; }
        }
        th.push((tid, comm, bc));
      }
    }
    if th.is_empty() { continue; }
    v.push((pid, pkg, th));
  }
  v
}
fn sa(tid: i32, c: &str, _cp: &str) -> bool {
  let mut set: libc::cpu_set_t = unsafe { mem::zeroed() };
  unsafe { libc::CPU_ZERO(&mut set); }
  for part in c.split(',') {
    let part = part.trim();
    if part.is_empty() { continue; }
    if let Some((s, e)) = part.split_once('-') {
      let start: usize = match s.trim().parse() { Ok(v) => v, Err(_) => continue };
      let end: usize = match e.trim().parse() { Ok(v) => v, Err(_) => continue };
      for cpu in start..=end { unsafe { libc::CPU_SET(cpu, &mut set); } }
    } else if let Ok(cpu) = part.parse::<usize>() {
      unsafe { libc::CPU_SET(cpu, &mut set); }
    }
  }
  unsafe {
    if libc::sched_setaffinity(tid, mem::size_of::<libc::cpu_set_t>(), &set) != 0 {
      if std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) { return true; }
    }
  }
  false
}
fn aa(v: &[(i32, String, Vec<(i32, String, String)>)], rf: &AtomicBool) {
  let mut n = 0usize;
  for (_, _, th) in v { for (tid, _, cpus) in th { if !cpus.is_empty() { n += 1; if sa(*tid, cpus, "") { rf.store(true, Ordering::Release); } } } }
  i!("已绑核 {} 进程 {} 线程", v.len(), n);
}
const CACHE_FILE: &str = "/sdcard/Android/Aether/threads_cache";
const AETHER_DIR: &str = "/sdcard/Android/Aether";
fn load_cache(s: &mut HashSet<String>, r: &mut Vec<R>) {
  let d = match fs::read_to_string(CACHE_FILE) { Ok(x) => x, Err(_) => return };
  let j = match json::parse(&d) { Ok(x) => x, Err(_) => return };
  if !j.is_array() { return; }
  let entries: Vec<&json::JsonValue> = j.members().collect();
  let count = entries.len();
  for entry in entries {
    let pl: Vec<String> = entry["packages"].members().filter_map(|v| v.as_str().map(String::from)).collect();
    if pl.is_empty() { continue; }
    if is_system_pkg(&pl[0]) { continue; }
    let o = entry["cpuset"]["other"].as_str().unwrap_or("0");
    let o_norm = compress_cpus(o);
    for pk in &pl { s.insert(pk.clone()); }
    r.push(R { p: pl[0].clone(), t: String::new(), c: o_norm.clone(), pr: 200 });
    if entry["cpuset"]["comm"].is_object() {
      for (cpus, names) in entry["cpuset"]["comm"].entries() {
        let cpus_norm = compress_cpus(&cpus);
        for nv in names.members() {
          if let Some(n) = nv.as_str() {
            if !n.is_empty() {
              r.push(R { p: pl[0].clone(), t: n.to_string(), c: cpus_norm.clone(), pr: rp(n) });
            }
          }
        }
      }
    }
  }
  i!("已加载 {} 条缓存", count);
}
fn est_load(name: &str) -> i32 {
  if name.contains("Render") || name.contains("Gfx") || name.contains("GL") || name.contains("Vulkan") { return 10; }
  if name.contains("Decode") || name.contains("Codec") || name.contains("Video") || name.contains("Audio") { return 8; }
  if name.contains("Main") || name.contains("Unity") || name.contains("Game") { return 9; }
  if name.contains("Worker") || name.contains("Thread") || name.contains("Job") { return 5; }
  if name.contains("Io") || name.contains("Network") || name.contains("Http") { return 3; }
  if name.contains("Background") || name.contains("Idle") || name.contains("Pool") { return 1; }
  4
}
fn compress_cpus(s: &str) -> String {
  let nums: Vec<usize> = s.split(',').filter_map(|x| x.trim().parse().ok()).collect();
  if nums.is_empty() { return s.to_string(); }
  let mut parts = Vec::new();
  let mut i = 0;
  while i < nums.len() {
    let start = nums[i];
    let mut end = start;
    while i + 1 < nums.len() && nums[i + 1] == end + 1 { i += 1; end = nums[i]; }
    if start == end { parts.push(start.to_string()); } else { parts.push(format!("{}-{}", start, end)); }
    i += 1;
  }
  parts.join(",")
}
fn detect_clusters() -> (String, String, String) {
  let mut cls: Vec<(u64, Vec<usize>)> = Vec::new();
  if let Ok(dir) = fs::read_dir("/sys/devices/system/cpu/cpufreq") {
    for e in dir.flatten() {
      let name = e.file_name().to_string_lossy().to_string();
      if !name.starts_with("policy") { continue; }
      let rel = match fs::read_to_string(e.path().join("related_cpus")) { Ok(x) => x.trim().to_string(), Err(_) => continue };
      let f_str = match fs::read_to_string(e.path().join("cpuinfo_max_freq")) { Ok(x) => x.trim().to_string(), Err(_) => continue };
      let freq: u64 = match f_str.parse() { Ok(f) => f, Err(_) => continue };
      let mut cpus = Vec::new();
      for part in rel.split(|c: char| c == ',' || c == ' ') {
        let part = part.trim(); if part.is_empty() { continue; }
        if let Some((a, b)) = part.split_once('-') {
          let s: usize = a.parse().unwrap_or(0); let e: usize = b.parse().unwrap_or(s);
          for cpu in s..=e { cpus.push(cpu); }
        } else if let Ok(c) = part.parse::<usize>() { cpus.push(c); }
      }
      if !cpus.is_empty() { cls.push((freq, cpus)); }
    }
  }
  if cls.len() < 2 {
    cls.clear();
    for cpu in 0..128 {
      let freq_path = format!("/sys/devices/system/cpu/cpu{}/cpufreq/cpuinfo_max_freq", cpu);
      let f_str = match fs::read_to_string(&freq_path) { Ok(x) => x.trim().to_string(), Err(_) => break };
      let freq: u64 = match f_str.parse() { Ok(f) => f, Err(_) => continue };
      let mut found = false;
      for (f, cpus) in &mut cls {
        if *f == freq { cpus.push(cpu); found = true; break; }
      }
      if !found { cls.push((freq, vec![cpu])); }
    }
  }
  cls.sort_by(|a, b| b.0.cmp(&a.0));
  if cls.is_empty() { return ("0".into(), "0".into(), "1".into()); }
  let big = compress_cpus(&cls[0].1.iter().map(|c| c.to_string()).collect::<Vec<_>>().join(","));
  let little = compress_cpus(&cls.last().unwrap().1.iter().map(|c| c.to_string()).collect::<Vec<_>>().join(","));
  let topo = cls.iter().map(|(_, cpus)| cpus.len().to_string()).collect::<Vec<_>>().join("+");
  (big, little, topo)
}
fn is_system_pkg(pkg: &str) -> bool {
  pkg.starts_with("com.miui.") || pkg.starts_with("com.xiaomi.") ||
  pkg.starts_with("android.") || pkg.starts_with("com.android.") ||
  pkg.starts_with("vendor.") || pkg.starts_with("com.qualcomm.") ||
  pkg.starts_with("com.qti.") || pkg.starts_with("org.codeaurora.") ||
  pkg.starts_with("com.st.android.") || pkg.starts_with("media.") ||
  pkg.starts_with("audio") || pkg.starts_with("com.milink.") ||
  pkg.starts_with(".qti") || pkg.starts_with(".qms") ||
  pkg.starts_with(".cacert") || pkg.starts_with(".dataservices") ||
  pkg.starts_with("com.lbe.") ||
  pkg.ends_with(":widgetProvider") || pkg.ends_with(":searchDataService") ||
  pkg.ends_with(":coreService") || pkg.ends_with(":cognitionService") ||
  pkg.ends_with(":bertAlgo") || pkg.ends_with(":bert") ||
  pkg.ends_with(":privacy") || pkg.ends_with(":kit7") ||
  pkg.ends_with(":services") || pkg.ends_with(":daemon")
}
fn auto_alloc(pkg: &str, procs: &[(i32, String, Vec<(i32, String)>)], big: &str, little: &str) {
  if is_system_pkg(pkg) { return; }
  let mut big_names = Vec::new();
  let mut lil_names = Vec::new();
  for (_, n, th) in procs.iter().filter(|(_, n, _)| n == pkg) {
    for (_, comm) in th {
      let load = est_load(comm);
      if load >= 8 { big_names.push(comm.clone()); } else { lil_names.push(comm.clone()); }
    }
  }
  let mut big_map: std::collections::BTreeMap<String, Vec<String>> = std::collections::BTreeMap::new();
  let mut lil_map: std::collections::BTreeMap<String, Vec<String>> = std::collections::BTreeMap::new();
  for (_, n, th) in procs.iter().filter(|(_, n, _)| n == pkg) {
    for (_, comm) in th {
      let load = est_load(comm);
      if load >= 8 { big_map.entry(big.to_string()).or_default().push(comm.clone()); }
      else { lil_map.entry(little.to_string()).or_default().push(comm.clone()); }
    }
  }
  let mut cm_parts = Vec::new();
  for (cpus, names) in &big_map {
    let arr = names.iter().map(|n| format!("\"{}\"", n)).collect::<Vec<_>>().join(",\n        ");
    cm_parts.push(format!("        \"{}\": [\n        {}\n        ]", cpus, arr));
  }
  for (cpus, names) in &lil_map {
    if names.is_empty() { continue; }
    if *cpus == little { continue; }
    let arr = names.iter().map(|n| format!("\"{}\"", n)).collect::<Vec<_>>().join(",\n        ");
    cm_parts.push(format!("        \"{}\": [\n        {}\n        ]", cpus, arr));
  }
  let comm_body = if cm_parts.is_empty() { "        ".to_string() } else { cm_parts.join(",\n") };
  let entry = format!(
    "  {{\n    \"friendly\": \"[auto] {}\",\n    \"packages\": [\"{}\"],\n    \"cpuset\": {{\n      \"other\": \"{}\",\n      \"comm\": {{\n{}\n      }}\n    }}\n  }}",
    pkg, pkg, little, comm_body
  );
  let _ = fs::create_dir_all(AETHER_DIR);
  let old = fs::read_to_string(CACHE_FILE).unwrap_or_default();
  let new = if old.trim().is_empty() || !old.trim_start().starts_with('[') {
    format!("[\n{}\n]\n", entry)
  } else {
    let t = old.trim_end();
    if t.ends_with(']') {
      format!("{},\n{}\n]", t[..t.len()-1].trim_end(), entry)
    } else {
      format!("[\n{}\n]\n", entry)
    }
  };
  let _ = fs::write(CACHE_FILE, new.as_bytes());
  i!("已自动分配: {} (大核线程 {})", pkg, big_names.len());
}
fn scan_unknown(s: &HashSet<String>) -> Vec<(i32, String, Vec<(i32, String)>)> {
  let mut v = Vec::new();
  let d = match fs::read_dir("/proc") { Ok(x) => x, Err(_) => return v };
  for e in d.flatten() {
    let pid: i32 = match e.file_name().to_string_lossy().parse() { Ok(p) => p, Err(_) => continue };
    if pid < 1000 { continue; }
    let mut is_user = false;
    if let Ok(st) = fs::read_to_string(e.path().join("status")) {
      for line in st.lines() {
        if line.starts_with("Uid:") {
          if let Some(uid_s) = line.split_whitespace().nth(1) {
            if let Ok(uid) = uid_s.parse::<u32>() { is_user = uid >= 10000; }
          }
          break;
        }
      }
    }
    if !is_user { continue; }
    let cl = fs::read_to_string(e.path().join("cmdline")).unwrap_or_default();
    let pkg = cl.split('\0').next().unwrap_or("").trim_end_matches('\0').to_string();
    if pkg.is_empty() || pkg.contains('/') { continue; }
    if s.contains(&pkg) { continue; }
    if !pkg.contains('.') { continue; }
    let mut th = Vec::new();
    if let Ok(tk) = fs::read_dir(e.path().join("task")) {
      for t in tk.flatten() {
        let tid: i32 = t.file_name().to_string_lossy().parse().unwrap_or(0);
        let comm = fs::read_to_string(t.path().join("comm")).unwrap_or_default().trim().to_string();
        th.push((tid, comm));
      }
    }
    if th.is_empty() { continue; }
    v.push((pid, pkg, th));
  }
  v
}
fn probe_ebpf() -> (bool, i32, i32) {
  #[repr(C, packed)]
  struct M { mt: u32, ks: u32, vs: u32, me: u32, mf: u32, pad: [u32;6] }
  #[repr(C, packed)]
  struct P { pt: u32, ic: u32, ins: u64, lic: u64, ll: u32, ls: u32, lb: u64, kv: u32, pad: u32 }
  unsafe {
    let ma = M { mt: 1, ks: 4, vs: 4, me: 256, mf: 0, pad: [0;6] };
    let mfd = libc::syscall(280, 0, &ma as *const _, mem::size_of::<M>()) as i32;
    if mfd < 0 { i!("eBPF: HASH_MAP 失败 (errno={})", std::io::Error::last_os_error().raw_os_error().unwrap_or(0)); return (false, -1, -1); }
    let mut ins: [u64; 16] = [
      0x00000000000016bf, 0x0000000e00000085, 0x00000000000007bf,
      0x0000002000000077, 0x00000000fffc0a63, 0x0000000000001118,
      0x0000000000000000, 0x000000000000a2bf, 0xfffffffc00000207,
      0x00000001000000b7, 0x00000000fff80a63, 0x000000000000a3bf,
      0xfffffff800000307, 0x0000000200000085, 0x00000000000000b7,
      0x0000000000000095,
    ];
    ins[5] = 0x18u64 | (1u64 << 8) | (1u64 << 12) | ((mfd as u64 & 0xFFFFFFFF) << 32);
    let lic: [u8; 4] = [71, 80, 76, 0];
    let mut vlog = [0u8; 1024];
    let pa = P { pt: 5, ic: 16, ins: &ins as *const _ as u64, lic: lic.as_ptr() as u64, ll: 0, ls: 0, lb: 0, kv: 0, pad: 0 };
    let pfd = libc::syscall(280, 5, &pa as *const _, mem::size_of::<P>()) as i32;
    if pfd < 0 {
      let vs = std::str::from_utf8(&vlog).unwrap_or("");
      i!("eBPF: PROG_LOAD 失败 (errno={})", std::io::Error::last_os_error().raw_os_error().unwrap_or(0));
      if vs.len() > 2 { i!("eBPF 日志: {}", vs.trim_end_matches(char::from(0))); }
      libc::close(mfd); return (false, -1, -1);
    }
    i!("eBPF: HASH 程序已挂载到 sched_process_exec");
    (true, mfd, pfd)
  }
}
fn read_bpf_map(map_fd: i32) -> Vec<u32> {
  let mut pids = Vec::new();
  let mut key: u32 = 0;
  loop {
    let mut nk: u32 = 0;
    let attr: [u64; 4] = [map_fd as u64, &key as *const _ as u64, &mut nk as *mut _ as u64, 0];
    if unsafe { libc::syscall(280, 3, &attr as *const _, mem::size_of::<[u64;4]>()) as i32 } != 0 { break; }
    pids.push(nk);
    key = nk;
  }
  for pid in &pids {
    let a: [u64; 3] = [map_fd as u64, pid as *const u32 as u64, 0];
    unsafe { libc::syscall(280, 4, &a as *const _, mem::size_of::<[u64;3]>()); }
  }
  pids
}
fn main() {
  let a: Vec<String> = env::args().collect();
  let mut cp = "/sdcard/Android/Aether/threads.json".to_string();
  let mut iv = 2u64; let mut i = 1;
  while i < a.len() {
    match a[i].as_str() {
      "-c" => { i += 1; if i < a.len() { cp = a[i].clone(); } }
      "-s" => { i += 1; if i < a.len() { iv = a[i].parse().unwrap_or(2); } }
      _ => {}
    } i += 1;
  }
  if iv < 1 { iv = 1; }
  let p = fs::read_to_string("/sys/devices/system/cpu/present").unwrap_or_default().trim().to_string();
  i!("CPU: {} cpuset={}", p, Path::new("/dev/cpuset").exists());
  if let Ok(ctx) = fs::read_to_string("/proc/self/attr/current") { i!("SELinux: {}", ctx.trim()); }
  let cfg = match C::load(&cp) { Some(c) => c, None => { e!("配置失败"); return; } };
  i!("已加载 {} 条规则", cfg.r.len());
  let mut all_r = cfg.r.clone();
  let mut all_s = cfg.s.clone();
  load_cache(&mut all_s, &mut all_r);
  i!("共 {} 条规则 (含缓存)", all_r.len());
  let (big_cluster, little_cluster, topo_str) = detect_clusters();
  i!("拓扑: {} (大核={} 小核={})", topo_str, big_cluster, little_cluster);
  let mut bpf_map_fd = -1i32;
  let mut bpf_prog_fd = -1i32;
  if cfg.ebpf {
    let (ok, mfd, pfd) = probe_ebpf();
    bpf_map_fd = mfd; bpf_prog_fd = pfd;
    i!("eBPF: {}", if ok { "可用" } else { "不可用" });
  }
  let _ = fs::create_dir_all(AETHER_DIR);
  let unknown = scan_unknown(&all_s);
  for (pid, pkg, th) in &unknown {
    i!("发现新应用: {} ({} 线程, PID {})", pkg, th.len(), pid);
    auto_alloc(pkg, &unknown, &big_cluster, &little_cluster);
  }
  if !unknown.is_empty() { i!("自动分配完成: {} 个", unknown.len()); }
  if !unknown.is_empty() { load_cache(&mut all_s, &mut all_r); i!("重新加载缓存: {} 条", all_r.len()); }
  let merged_c = C { r: all_r.clone(), s: all_s.clone(), m: cfg.m, ebpf: cfg.ebpf, auto_for_none: cfg.auto_for_none };
  let mut cache: Vec<(i32, String, Vec<(i32, String, String)>)> = Vec::new();
  let mut lc = 0i32; let mut cnt = 0i32;
  let rf = AtomicBool::new(false);
  let mut cache_scan_cnt = 0i32;
    if bpf_map_fd >= 0 {
      for pid in read_bpf_map(bpf_map_fd) {
        let cl = fs::read_to_string(format!("/proc/{}/cmdline", pid)).unwrap_or_default();
        let pkg = cl.split(' ').next().unwrap_or("").trim_end_matches(' ').to_string();
        if !pkg.is_empty() && all_s.contains(&pkg) {
          i!("eBPF: 新进程 {} ({})", pid, pkg);
        }
      }
    }
    let mut nr = false;
    cache_scan_cnt += 1;
    if cache_scan_cnt >= 30 {
      cache_scan_cnt = 0;
      let unknown = scan_unknown(&all_s);
      for (pid, pkg, th) in &unknown {
        i!("发现新应用: {} ({} 线程)", pkg, th.len());
        auto_alloc(pkg, &unknown, &big_cluster, &little_cluster);
      }
      if !unknown.is_empty() { load_cache(&mut all_s, &mut all_r); i!("缓存已更新: {} 条规则", all_r.len()); }
    }
    let mut nr = false;
    let mut si: libc::sysinfo = unsafe { mem::zeroed() };
    if unsafe { libc::sysinfo(&mut si) } != 0 { nr = true; }
    else { let cur = si.procs as i32; if cur > lc + 10 { nr = true; } else if cur > lc { cnt = 0; } lc = cur; }
    if !nr { for (pid, _, _) in &cache { if unsafe { libc::kill(*pid, 0) } != 0 { nr = true; break; } } }
    if nr { cache = sp2(&merged_c.r, &merged_c.s); rf.store(false, Ordering::Release); }
    cnt -= 1;
    if cnt < 1 {
      aa(&cache, &rf);
      if rf.load(Ordering::Acquire) { cache = sp2(&merged_c.r, &merged_c.s); rf.store(false, Ordering::Release); }
      cnt = 5;
    }
    std::thread::sleep(Duration::from_secs(iv));
  }
