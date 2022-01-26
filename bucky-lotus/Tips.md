# cli
```sh
./lotus daemon --lotus-make-genesis=devgen.car --genesis-template=localnet.json --bootstrap=false


RUST_LOG=Trace ./lotus-miner run --nosync

BELLMAN_NO_GPU=1 RUST_LOG=Trace ./lotus-worker run --listen=192.168.100.199:2333 --wdpost=true --precommit1=true --precommit2=true --commit=true --addpiece=true --parallel-fetch-limit=1 --unseal=true


# dlv 调式工具
(dlv) b(break) main.main：设置断点，还可以根据行号设置断点 b 或者 main.go:9

(dlv) bp：查找已经设置的断点， clear 1 /clearall 清除断点

(dlv) c：该命令是让程序运行起来，遇到设置的断点会停止

(dlv) r：重新开始下一轮的调试

(dlv) config source-list-line-count   32

(dlv) n：下一步，不会陷入内部

(dlv) s：进入某个函数的内部，源码函数也跟踪进去

(dlv) so：如果用s陷入到内部函数，可以快速使用该命令跳出来，回到进入点

(dlv) p [var_name]：打印变量的值

(dlv) gr and grs：这两个命令是用来查看goroutine的

(dlv) help：使用过程中随时通过help查看命令

# 附件本地程序
dlv attach pid

# dlv server 远程调试
dlv attach $PID --headless --api-version=2 --log --listen=:1234

# dlv 帮助
dlv help help/core


# 调试本地go程序
## 调试 lotus-worker
export WORKER_NAME="8m-worker"
export PERF_API_INFO="filecoin3:9000"
export FIL_PROOFS_PARAMETER_CACHE="/filecoin/cache/parameters"
export FIL_PROOFS_PARENT_CACHE="/filecoin/cache/parent"
export FIL_PROOFS_USE_GPU_TREE_BUILDER=1
export FIL_PROOFS_USE_GPU_COLUMN_BUILDER=1
export FIL_PROOFS_USE_MULTICORE_SDR=1
export RUST_LOG=Debug
export LOTUS_WORKER_PATH=/filecoin/cache/8m_worker_repo
export MINER_API_INFO="MINER_API_INFO=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJBbGxvdyI6WyJyZWFkIiwid3JpdGUiLCJzaWduIiwiYWRtaW4iXX0.r7ytHJbexe778NfhhctMVpFp1r-HkBFp55wvB5u47vQ:/ip4/127.0.0.1/tcp/2345/http"

dlv exec ./lotus-worker -- run --wdpost=true   --listen=0.0.0.0:3456

## 调试 lotus-miner
export FIL_PROOFS_PARAMETER_CACHE="/filecoin/parameters"
export FIL_PROOFS_PARENT_CACHE="/filecoin/parent"
export FIL_PROOFS_USE_GPU_TREE_BUILDER=1
export FIL_PROOFS_USE_GPU_COLUMN_BUILDER=1
export FIL_PROOFS_USE_MULTICORE_SDR=1
export LOTUS_MINER_PATH="/filecoin/8m_miner_repo"
export LOTUS_API_LISTENADDRESS="/ip4/0.0.0.0/tcp/2345/http"
export LOTUS_STORAGE_ALLOWADDPIECE=false
export LOTUS_STORAGE_ALLOWPRECOMMIT1=false
export LOTUS_STORAGE_ALLOWPRECOMMIT2=false
export LOTUS_STORAGE_ALLOWCOMMIT=false
export LOTUS_STORAGE_ALLOWUNSEAL=false
export LOTUS_SEALING_BATCHPRECOMMITS=false
export LOTUS_SEALING_AGGREGATECOMMITS=false
export PERF_API_INFO="filecoin3:9000"
export FULLNODE_API_INFO="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJBbGxvdyI6WyJyZWFkIiwid3JpdGUiLCJzaWduIiwiYWRtaW4iXX0.R12gBm9K_H6q6Yl91NVX9n3lehe5MTGfAntyX_lqgMw:/ip4/127.0.0.1/tcp/1234/http"

dlv exec ./lotus-miner -- --actor=f01000  run --wdpost=false --wnpost=true --nosync
```