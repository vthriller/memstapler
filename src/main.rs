use std::fs::*;
use unwrap_or::*;
use std::io::*;
use std::collections::*;
use nix::sys::mman::*;
use anyhow::Context;

fn main() {
	let mut args = std::env::args();
	args.next();
	if let Some(ns) = args.next() {
		return locker(&ns);
	}

	let exe = unwrap_ok_or!(std::env::current_exe(), err, {
		eprintln!("fatal: I don't even know who I am: {}", err);
		return;
	});
	let mut children = HashMap::new();

	loop {
		// clean up dead children
		children.retain(|_, child: &mut std::process::Child| {
			! child.try_wait().ok().map(|status| status.is_some()).unwrap_or(false)
		});

		let mut files: HashMap<_, HashSet<_>> = HashMap::new();
		let mut own_ns = None;

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
			let pid: u32 = unwrap_ok_or!(pid.parse(), _, continue);

			let f = f.path();

			let pexe = unwrap_ok_or!(f.join("exe").read_link(), err, {
				// ENOENT usually means it's a zombie, kthread or some other thing that has no meaningful maps
				if err.kind() != ErrorKind::NotFound {
					eprintln!("{}: failed to look up ns: {}", f.to_string_lossy(), err);
				}
				continue;
			});

			let ns = unwrap_ok_or!(f.join("ns/mnt").read_link(), err, {
				if err.kind() != ErrorKind::NotFound {
					eprintln!("{}: failed to look up ns: {}", f.to_string_lossy(), err);
				}
				continue;
			});
			let ns = ns.into_os_string();
			if pid == std::process::id() {
				own_ns = Some(ns.clone());
			}

			if pexe == exe {
				/*
				skip our own binary:
				- we already mlockall() ourselves, no need to pollute address space
				- because we inject ourselves into other namespaces, maps still refer to files in the root ns,
				  which means ns-specific children fail to read memstapler and its libraries
				*/
				continue;
			}

			let maps = unwrap_ok_or!(File::open(f.join("maps")), err, {
				if err.kind() != ErrorKind::NotFound {
					eprintln!("{}/maps: failed to open: {}", f.to_string_lossy(), err);
				}
				continue;
			});
			let maps = BufReader::new(maps);
			let ns_files = files.entry(ns).or_default();
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
				ns_files.insert(path.to_string());
			}
		}

		for (ns, files) in files {
		let ns = if own_ns.as_ref().map(|ons| *ons == ns).unwrap_or(false) {
			"-".into()
		} else {
			ns
		};
		let entry = children.entry(ns.clone());
		let mut entry = match entry {
			hash_map::Entry::Vacant(_) => {
				let child = std::process::Command::new(&exe)
					.args([ns])
					.stdin(std::process::Stdio::piped())
					.spawn();
				let child = unwrap_ok_or!(child, err, {
					eprintln!("failed to spawn child: {}", err);
					continue;
				});
				entry.insert_entry(child)
			},
			hash_map::Entry::Occupied(entry) => entry,
		};
		let child = entry.get_mut();
		let mut child = child.stdin.as_ref().unwrap(); // should always be Some()

		for f in files {
			if child.write(f.as_bytes()).is_err() {
				break;
			}
			if child.write(b"\n").is_err() {
				break;
			}
		}
		child.write(b".\n"); // signal that another scanning is done
		child.flush();
		}

		std::thread::sleep(std::time::Duration::new(5, 0));
	}
}

struct Map {
	addr: std::ptr::NonNull<std::ffi::c_void>,
	len: std::num::NonZero<usize>,
	last_seen_ago: u8,
}

fn locker(target_ns: &str) {
	if let Err(err) = mlockall(MlockAllFlags::MCL_CURRENT | MlockAllFlags::MCL_FUTURE) {
		eprintln!("mlockall: {}", err);
		return;
	}

	if target_ns != "-" {
		/*
		Parent process is busy scanning processes and their maps;
		by the time it's done, processes might already be gone, pids could get recycled etc.
		Start our own parallel scan instead.
		*/
		let proc = unwrap_ok_or!(read_dir("/proc/"), err, {
			eprintln!("/proc: cannot open: {}", err);
			return;
		});
		let mut changed = false;
		for f in proc {
			let f = unwrap_ok_or!(f, err, {
				eprintln!("/proc: while scanning: {}", err);
				continue;
			});
			let nsfile = f.path().join("ns/mnt");
			let f = unwrap_ok_or!(File::open(&nsfile), _, continue);
			let ns = unwrap_ok_or!(nsfile.read_link(), _, continue);
			if ns.into_os_string() != target_ns {
				continue;
			};

			match nix::sched::setns(f, nix::sched::CloneFlags::CLONE_NEWNS) {
				Ok(()) => {
					changed = true;
					break;
				},
				Err(err) => {
					eprintln!("{}: failed to change namespace via {:?}: {}", target_ns, nsfile, err);
					continue;
				}
			}
		}
		if ! changed {
			eprintln!("{}: failed to change namespace, aborting", target_ns);
			return;
		}
	}

	let mut maps: HashMap<String, Map> = HashMap::new();

	let stdin = std::io::stdin();
	let stdin = stdin.lock();

	for fname in stdin.lines() {
		let fname = unwrap_ok_or!(fname, err, {
			eprintln!("failed to read stdin: {}", err);
			continue;
		});

		if fname == "." {
			// parent stopped scanning, look for outdated maps
			maps.retain(|fname, map| {
				if map.last_seen_ago < 5 { // TODO configurable
					// only recently disappeared, wait in case it's going to return
					// (service respawn, cron script etc)
					map.last_seen_ago += 1;
					return true;
				}
				match unsafe { munmap(map.addr, map.len.into()) } {
					Ok(()) => {
						eprintln!("removed {}", &fname);
						false
					},
					Err(err) => {
						eprintln!("{}: failed to unmap: {}", &fname, err);
						// will try again later
						true
					},
				}
			});
			continue;
		}

		let entry = maps.entry(fname.clone());
		if let hash_map::Entry::Occupied(mut map) = entry {
			map.get_mut().last_seen_ago = 0;
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
			).context("mmap") }.map(|addr| Map {
				addr, len,
				last_seen_ago: 0,
			}))
			;
		match map {
			Ok(map) => {
				eprintln!("added {}", &fname);
				maps.insert(fname.to_string(), map);
			},
			Err(err) => {
				eprintln!("{}: {:#}", &fname, err);
				continue;
			}
		}
	}
}
