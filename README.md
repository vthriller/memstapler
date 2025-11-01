# memstapler

Locks executable files into memory, preventing them from being paged out in memory pressure situations.

## Comparison to other tools

| | memstapler | [memlockd](http://www.coker.com.au/memlockd/) | [prelockd](https://github.com/hakavlad/prelockd) |
|--|--|--|--|
| Can lock all files that are mapped as executable by any process in the system | ✅ | 🚫 | ✅ |
| Can lock predefined list of files | 🚫 | ✅ | ✅ |
| Namespace-aware: easily locks files from within running lxc/docker/podman/nspawn/... containers | ✅ | 🚫 | 🚫 |

## Caveats

- This does not lock deleted files.
- Scanning intervals are not configurable.
