# memstapler

Locks executable files into memory, preventing them from being paged out in memory pressure situations.

## Comparison to other tools

| | memstapler | [memlockd](http://www.coker.com.au/memlockd/) | [prelockd](https://github.com/hakavlad/prelockd) |
|--|--|--|--|
| Can lock all files that are mapped as executable by any process in the system | Y | n | Y |
| Can lock predefined list of files | n | Y | Y |
| Namespace-aware: easily locks files from within running lxc/docker/podman/nspawn/... containers | Y | n | n |

## Caveats

- This does not lock deleted files.
- Scanning intervals are not configurable.
