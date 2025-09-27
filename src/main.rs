use std::fs::*;
use unwrap_or::*;
use std::io::*;
use std::collections::*;
use nix::sys::mman::*;
use anyhow::Context;

fn main() {
	let mut args = std::env::args();
	args.next();
	if args.next().is_some() {
		return locker();
	}

	let child = std::env::current_exe().context("I don't even know who I am")
		.and_then(|exe| std::process::Command::new(exe)
			.args(["-"])
			.stdin(std::process::Stdio::piped())
			.spawn().context("while spawning child"));
	let mut child = unwrap_ok_or!(child, err, {
		eprintln!("fatal: {:#}", err);
		return;
	});
	let mut stdin = unwrap_some_or!(child.stdin.take(), {
		eprintln!("fatal: can't write to child");
		return;
	});

	loop {
	let mut files = HashSet::new();
	let proc = unwrap_ok_or!(read_dir("/proc/"), err, {
		eprintln!("/proc: cannot open: {}", err);
		return;
	});
	for f in proc {
		let f = unwrap_ok_or!(f, err, {
			eprintln!("/proc: while scanning: {}", err);
			continue;
		});

		let pid = f.file_name();
		// not a number in any case, don't bother spamming stderr about that
		let pid = unwrap_some_or!(pid.to_str(), continue);
		let _pid: usize = unwrap_ok_or!(pid.parse(), _, continue);

		let f = f.path();
		let maps = unwrap_ok_or!(File::open(f.join("maps")), err, {
			eprintln!("{}/maps: failed to read: {}", f.to_string_lossy(), err);
			continue;
		});
		let maps = BufReader::new(maps);
		for line in maps.lines() {
			let line = unwrap_ok_or!(line, err, {
				eprintln!("{}/maps: while reading maps: {}", f.to_string_lossy(), err);
				continue;
			});
			// "7fbe11954000-7fbe11978000 r--p 00000000 fd:00 27526017                   /usr/lib64/libc.so.6"
			let mut l = line.splitn(6, " ");
			l.next();
			let perms = unwrap_some_or!(l.next(), {
				eprintln!("{}/maps: malformed line: {}", f.to_string_lossy(), line);
				continue;
			});
			if ! perms.contains('x') {
				continue;
			}
			l.next();
			l.next();
			l.next();
			let path = unwrap_some_or!(l.next(), {
				eprintln!("{}/maps: malformed line: {}", f.to_string_lossy(), line);
				continue;
			}).trim_start();
			if ! path.starts_with('/') {
				// e.g. "[vdso]" or "" for anon mappings
				continue;
			}
			files.insert(path.to_string());
		}
	}

	for f in files {
		if stdin.write(f.as_bytes()).is_err() {
			break;
		}
		if stdin.write(b"\n").is_err() {
			break;
		}
	}

	std::thread::sleep(std::time::Duration::new(5, 0));
	}
}

fn locker() {
	if let Err(err) = mlockall(MlockAllFlags::MCL_CURRENT | MlockAllFlags::MCL_FUTURE) {
		eprintln!("mlockall: {}", err);
		return;
	}

	let mut maps = HashSet::new();

	let stdin = std::io::stdin();
	let stdin = stdin.lock();

	for fname in stdin.lines() {
		let fname = unwrap_ok_or!(fname, err, {
			eprintln!("failed to read stdin: {}", err);
			continue;
		});

		if maps.contains(&fname) {
			continue;
		}

		let fname = fname.trim_end_matches('\n');
		let mut f = unwrap_ok_or!(File::open(&fname), err, {
			eprintln!("{}: failed to open: {}", &fname, err);
			continue;
		});

		let map = f
			.seek(SeekFrom::End(0)).context("failed to seek")
			.and_then(|len| len.try_into().context("file size too large for mmap"))
			.and_then(|len| std::num::NonZeroUsize::new(len).context("empty file"))
			.and_then(|len| unsafe { mmap(
				None, // addr
				len,
				ProtFlags::PROT_READ,
				MapFlags::MAP_SHARED,
				f,
				0, // offset
			).context("mmap") })
			;
		match map {
		Ok(_) => {
			eprintln!("added {}", &fname);
			maps.insert(fname.to_string());
		},
		Err(err) => {
			eprintln!("{}: {:#}", &fname, err);
			continue;
		}
		}
	}
}
