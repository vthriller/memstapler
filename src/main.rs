use std::fs::*;
use unwrap_or::*;
use std::io::*;
use std::collections::*;

fn main() {
	let mut files = HashSet::new();
	for f in read_dir("/proc/").unwrap() {
		let f = unwrap_ok_or!(f, _, continue);

		let pid = f.file_name();
		let pid = unwrap_some_or!(pid.to_str(), continue);
		let _pid: usize = unwrap_ok_or!(pid.parse(), _, continue);

		let f = f.path();
		let maps = unwrap_ok_or!(File::open(f.join("maps")), _, continue);
		let maps = BufReader::new(maps);
		for l in maps.lines() {
			let l = unwrap_ok_or!(l, _, continue);
			// "7fbe11954000-7fbe11978000 r--p 00000000 fd:00 27526017                   /usr/lib64/libc.so.6"
			let mut l = l.splitn(6, " ");
			l.next();
			let perms = unwrap_some_or!(l.next(), continue);
			if ! perms.contains('x') {
				continue;
			}
			l.next();
			l.next();
			l.next();
			let path = unwrap_some_or!(l.next(), continue).trim_start();
			if ! path.starts_with('/') {
				// e.g. "[vdso]" or "" for anon mappings
				continue;
			}
			files.insert(path.to_string());
		}
	}
	dbg!(files);
}
