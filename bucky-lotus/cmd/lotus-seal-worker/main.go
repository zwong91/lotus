package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/filecoin-project/lotus/api/v1api"
	"github.com/filecoin-project/lotus/node"
	"github.com/filecoin-project/lotus/node/config"
	"github.com/filecoin-project/lotus/node/modules/dtypes"
	"go.opencensus.io/stats"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/ipfs/go-datastore/namespace"
	logging "github.com/ipfs/go-log/v2"
	manet "github.com/multiformats/go-multiaddr/net"
	"github.com/urfave/cli/v2"
	"go.opencensus.io/stats/view"
	"go.opencensus.io/tag"
	"golang.org/x/xerrors"

	"github.com/filecoin-project/go-jsonrpc"
	"github.com/filecoin-project/go-jsonrpc/auth"
	paramfetch "github.com/filecoin-project/go-paramfetch"
	"github.com/filecoin-project/go-statestore"

	"github.com/filecoin-project/lotus/api"
	"github.com/filecoin-project/lotus/build"
	lcli "github.com/filecoin-project/lotus/cli"
	cliutil "github.com/filecoin-project/lotus/cli/util"
	sectorstorage "github.com/filecoin-project/lotus/extern/sector-storage"
	"github.com/filecoin-project/lotus/extern/sector-storage/sealtasks"
	"github.com/filecoin-project/lotus/extern/sector-storage/stores"
	"github.com/filecoin-project/lotus/lib/lotuslog"
	"github.com/filecoin-project/lotus/lib/rpcenc"
	"github.com/filecoin-project/lotus/metrics"
	"github.com/filecoin-project/lotus/metrics/proxy"
	"github.com/filecoin-project/lotus/node/modules"
	"github.com/filecoin-project/lotus/node/repo"
)

var log = logging.Logger("main")

const (
	FlagWorkerRepo = "worker-repo"
	FlagMinerRepo  = "miner-repo"
)

// TODO remove after deprecation period
const FlagWorkerRepoDeprecation = "workerrepo"

const peerFile = "peerid.json"

func main() {
	api.RunningNodeType = api.NodeWorker

	lotuslog.SetupLogLevels()

	local := []*cli.Command{
		runCmd,
		infoCmd,
		storageCmd,
		setCmd,
		waitQuietCmd,
		tasksCmd,
	}

	app := &cli.App{
		Name:                 "lotus-worker",
		Usage:                "Remote miner worker",
		Version:              build.UserVersion(),
		EnableBashCompletion: true,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    FlagWorkerRepo,
				Aliases: []string{FlagWorkerRepoDeprecation},
				EnvVars: []string{"LOTUS_WORKER_PATH", "WORKER_PATH"},
				Value:   "~/.lotusworker", // TODO: Consider XDG_DATA_HOME
				Usage:   fmt.Sprintf("Specify worker repo path. flag %s and env WORKER_PATH are DEPRECATION, will REMOVE SOON", FlagWorkerRepoDeprecation),
			},
			&cli.StringFlag{
				Name:    "panic-reports",
				EnvVars: []string{"LOTUS_PANIC_REPORT_PATH"},
				Hidden:  true,
				Value:   "~/.lotusworker", // should follow --repo default
			},
			&cli.StringFlag{
				Name:    FlagMinerRepo,
				Aliases: []string{"storagerepo"},
				EnvVars: []string{"LOTUS_MINER_PATH", "LOTUS_STORAGE_PATH"},
				Value:   "~/.lotusminer", // TODO: Consider XDG_DATA_HOME
				Usage:   fmt.Sprintf("Specify miner repo path. flag %s and env LOTUS_STORAGE_PATH are DEPRECATION, will REMOVE SOON", FlagMinerRepo),
			},
			&cli.BoolFlag{
				Name:  "enable-gpu-proving",
				Usage: "enable use of GPU for mining operations",
				Value: true,
			},
		},

		After: func(c *cli.Context) error {
			if r := recover(); r != nil {
				// Generate report in LOTUS_PATH and re-raise panic
				build.GeneratePanicReport(c.String("panic-reports"), c.String(FlagWorkerRepo), c.App.Name)
				panic(r)
			}
			return nil
		},
		Commands: local,
	}
	app.Setup()
	app.Metadata["repoType"] = repo.Worker

	// add by <wangzhi@buckyos.com> 2022-01-18
	os.Setenv("LOTUS_WDPOST", "true")
	os.Setenv("LOTUS_WNPOST", "false")

	if err := app.Run(os.Args); err != nil {
		log.Warnf("%+v", err)
		return
	}
}

var runCmd = &cli.Command{
	Name:  "run",
	Usage: "Start lotus worker",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:  "listen",
			Usage: "host address and port the worker api will listen on",
			Value: "0.0.0.0:3456",
		},
		&cli.StringFlag{
			Name:   "address",
			Hidden: true,
		},
		&cli.BoolFlag{
			Name:  "no-local-storage",
			Usage: "don't use storageminer repo for sector storage",
		},
		&cli.BoolFlag{
			Name:  "no-swap",
			Usage: "don't use swap",
			Value: false,
		},
		&cli.BoolFlag{
			Name:  "addpiece",
			Usage: "enable addpiece",
			Value: true,
		},
		&cli.BoolFlag{
			Name:  "precommit1",
			Usage: "enable precommit1 (32G sectors: 1 core, 128GiB Memory)",
			Value: true,
		},
		&cli.BoolFlag{
			Name:  "unseal",
			Usage: "enable unsealing (32G sectors: 1 core, 128GiB Memory)",
			Value: true,
		},
		&cli.BoolFlag{
			Name:  "precommit2",
			Usage: "enable precommit2 (32G sectors: all cores, 96GiB Memory)",
			Value: true,
		},
		&cli.BoolFlag{
			Name:  "commit",
			Usage: "enable commit (32G sectors: all cores or GPUs, 128GiB Memory + 64GiB swap)",
			Value: true,
		},
		// add by <wangzhi@buckyos.com> 2022-01-18
		&cli.BoolFlag{
			Name:  "wdpost",
			Usage: "enable windowPoSt",
			Value: true,
		},
		&cli.BoolFlag{
			Name:  "wnpost",
			Usage: "enable winningPoSt",
			Value: false,
		},
		&cli.StringFlag{
			Name:  "workername",
			Usage: "worker name will display on jobs list",
			Value: "",
		},
		&cli.IntFlag{
			Name:  "parallel-fetch-limit",
			Usage: "maximum fetch operations to run in parallel",
			Value: 5,
		},
		&cli.StringFlag{
			Name:  "timeout",
			Usage: "used when 'listen' is unspecified. must be a valid duration recognized by golang's time.ParseDuration function",
			Value: "30m",
		},
	},
	Before: func(cctx *cli.Context) error {
		if cctx.IsSet("address") {
			log.Warnf("The '--address' flag is deprecated, it has been replaced by '--listen'")
			if err := cctx.Set("listen", cctx.String("address")); err != nil {
				return err
			}
		}

		return nil
	},
	Action: func(cctx *cli.Context) error {
		log.Info("Starting lotus worker")

		if !cctx.Bool("enable-gpu-proving") {
			if err := os.Setenv("BELLMAN_NO_GPU", "true"); err != nil {
				return xerrors.Errorf("could not set no-gpu env: %+v", err)
			}
		}
		// add by <wangzhi@buckyos.com> 2022-01-18
		if cctx.Bool("wdpost") {
			os.Setenv("LOTUS_WDPOST", "true")
		} else {
			os.Unsetenv("LOTUS_WDPOST")
		}
		if cctx.Bool("wnpost") {
			os.Setenv("LOTUS_WNPOST", "true")
		} else {
			os.Unsetenv("LOTUS_WNPOST")
		}
		if cctx.String("workername") != "" {
			os.Setenv("WORKER_NAME", cctx.String("workername"))
		}

		// Connect to storage-miner
		ctx := lcli.ReqContext(cctx)

		var minerapi api.StorageMiner
		var closer func()
		var err error
		for {
			minerapi, closer, err = lcli.GetStorageMinerAPI(cctx, cliutil.StorageMinerUseHttp)
			if err == nil {
				_, err = minerapi.Version(ctx)
				if err == nil {
					break
				}
			}
			fmt.Printf("\r\x1b[0KConnecting to miner API... (%s)", err)
			time.Sleep(time.Second)
			continue
		}

		defer closer()
		ctx, cancel := context.WithCancel(ctx)
		defer cancel()

		// Register all metric views
		if err := view.Register(
			metrics.DefaultViews...,
		); err != nil {
			log.Fatalf("Cannot register the view: %v", err)
		}

		v, err := minerapi.Version(ctx)
		if err != nil {
			return err
		}
		if v.APIVersion != api.MinerAPIVersion0 {
			return xerrors.Errorf("lotus-miner API version doesn't match: expected: %s", api.APIVersion{APIVersion: api.MinerAPIVersion0})
		}
		log.Infof("Remote version %s", v)

		// Check params

		act, err := minerapi.ActorAddress(ctx)
		if err != nil {
			return err
		}
		ssize, err := minerapi.ActorSectorSize(ctx, act)
		if err != nil {
			return err
		}

		if cctx.Bool("commit") {
			if err := paramfetch.GetParams(ctx, build.ParametersJSON(), build.SrsJSON(), uint64(ssize)); err != nil {
				return xerrors.Errorf("get params: %w", err)
			}
		}

		var taskTypes []sealtasks.TaskType

		taskTypes = append(taskTypes, sealtasks.TTFetch, sealtasks.TTCommit1, sealtasks.TTFinalize)

		if cctx.Bool("addpiece") {
			taskTypes = append(taskTypes, sealtasks.TTAddPiece)
		}
		if cctx.Bool("precommit1") {
			taskTypes = append(taskTypes, sealtasks.TTPreCommit1)
		}
		if cctx.Bool("unseal") {
			taskTypes = append(taskTypes, sealtasks.TTUnseal)
		}
		if cctx.Bool("precommit2") {
			taskTypes = append(taskTypes, sealtasks.TTPreCommit2)
		}
		if cctx.Bool("commit") {
			taskTypes = append(taskTypes, sealtasks.TTCommit2)
		}
		if cctx.Bool("wdpost") {
			taskTypes = append(taskTypes, sealtasks.TTWPoSt)
		}

		if len(taskTypes) == 0 {
			return xerrors.Errorf("no task types specified")
		}

		// Open repo
		repoPath := cctx.String(FlagWorkerRepo)
		r, err := repo.NewFS(repoPath)
		if err != nil {
			return err
		}

		ok, err := r.Exists()
		if err != nil {
			return err
		}
		if !ok {
			if err := r.Init(repo.Worker); err != nil {
				return err
			}

			lr, err := r.Lock(repo.Worker)
			if err != nil {
				return err
			}

			var localPaths []stores.LocalPath

			if !cctx.Bool("no-local-storage") {
				b, err := json.MarshalIndent(&stores.LocalStorageMeta{
					ID:       stores.ID(uuid.New().String()),
					Weight:   10,
					CanSeal:  true,
					CanStore: false,
				}, "", "  ")
				if err != nil {
					return xerrors.Errorf("marshaling storage config: %w", err)
				}

				if err := ioutil.WriteFile(filepath.Join(lr.Path(), "sectorstore.json"), b, 0644); err != nil {
					return xerrors.Errorf("persisting storage metadata (%s): %w", filepath.Join(lr.Path(), "sectorstore.json"), err)
				}

				localPaths = append(localPaths, stores.LocalPath{
					Path: lr.Path(),
				})
			}

			if err := lr.SetStorage(func(sc *stores.StorageConfig) {
				sc.StoragePaths = append(sc.StoragePaths, localPaths...)
			}); err != nil {
				return xerrors.Errorf("set storage config: %w", err)
			}

			{
				// init datastore for r.Exists
				_, err := lr.Datastore(context.Background(), "/metadata")
				if err != nil {
					return err
				}
			}
			if err := lr.Close(); err != nil {
				return xerrors.Errorf("close repo: %w", err)
			}
		}

		lr, err := r.Lock(repo.Worker)
		if err != nil {
			return err
		}
		defer func() {
			if err := lr.Close(); err != nil {
				log.Error("closing repo", err)
			}
		}()
		ds, err := lr.Datastore(context.Background(), "/metadata")
		if err != nil {
			return err
		}

		log.Info("Opening local storage; connecting to master")
		const unspecifiedAddress = "0.0.0.0"
		address := cctx.String("listen")
		addressSlice := strings.Split(address, ":")
		if ip := net.ParseIP(addressSlice[0]); ip != nil {
			if ip.String() == unspecifiedAddress {
				timeout, err := time.ParseDuration(cctx.String("timeout"))
				if err != nil {
					return err
				}
				rip, err := extractRoutableIP(timeout)
				if err != nil {
					return err
				}
				address = rip + ":" + addressSlice[1]
			}
		}

		localStore, err := stores.NewLocal(ctx, lr, minerapi, []string{"http://" + address + "/remote"})
		if err != nil {
			return err
		}

		// setup worker peerid
		setPeerId(address, lr.Path())

		if cctx.Bool("wdpost") {
			log.Info("Opening worker wdpost")
			go switchWPoSt(cctx)
		}

		// Setup remote sector store
		sminfo, err := lcli.GetAPIInfo(cctx, repo.StorageMiner)
		if err != nil {
			return xerrors.Errorf("could not get api info: %w", err)
		}

		remote := stores.NewRemote(localStore, minerapi, sminfo.AuthHeader(), cctx.Int("parallel-fetch-limit"),
			&stores.DefaultPartialFileHandler{})

		fh := &stores.FetchHandler{Local: localStore, PfHandler: &stores.DefaultPartialFileHandler{}}
		remoteHandler := func(w http.ResponseWriter, r *http.Request) {
			if !auth.HasPerm(r.Context(), nil, api.PermAdmin) {
				w.WriteHeader(401)
				_ = json.NewEncoder(w).Encode(struct{ Error string }{"unauthorized: missing admin permission"})
				return
			}

			fh.ServeHTTP(w, r)
		}

		// Create / expose the worker

		wsts := statestore.New(namespace.Wrap(ds, modules.WorkerCallsPrefix))

		workerApi := &worker{
			LocalWorker: sectorstorage.NewLocalWorker(sectorstorage.WorkerConfig{
				TaskTypes: taskTypes,
				NoSwap:    cctx.Bool("no-swap"),
			}, remote, localStore, minerapi, minerapi, wsts),
			localStore: localStore,
			ls:         lr,
		}

		mux := mux.NewRouter()

		log.Info("Setting up control endpoint at " + address)

		readerHandler, readerServerOpt := rpcenc.ReaderParamDecoder()
		rpcServer := jsonrpc.NewServer(readerServerOpt)
		rpcServer.Register("Filecoin", api.PermissionedWorkerAPI(proxy.MetricedWorkerAPI(workerApi)))

		mux.Handle("/rpc/v0", rpcServer)
		mux.Handle("/rpc/streams/v0/push/{uuid}", readerHandler)
		mux.PathPrefix("/remote").HandlerFunc(remoteHandler)
		mux.PathPrefix("/").Handler(http.DefaultServeMux) // pprof

		ah := &auth.Handler{
			Verify: minerapi.AuthVerify,
			Next:   mux.ServeHTTP,
		}

		srv := &http.Server{
			Handler: ah,
			BaseContext: func(listener net.Listener) context.Context {
				ctx, _ := tag.New(context.Background(), tag.Upsert(metrics.APIInterface, "lotus-worker"))
				return ctx
			},
		}

		go func() {
			<-ctx.Done()
			log.Warn("Shutting down...")
			if err := srv.Shutdown(context.TODO()); err != nil {
				log.Errorf("shutting down RPC server failed: %s", err)
			}
			log.Warn("Graceful shutdown successful")
		}()

		nl, err := net.Listen("tcp", address)
		if err != nil {
			return err
		}

		{
			a, err := net.ResolveTCPAddr("tcp", address)
			if err != nil {
				return xerrors.Errorf("parsing address: %w", err)
			}

			ma, err := manet.FromNetAddr(a)
			if err != nil {
				return xerrors.Errorf("creating api multiaddress: %w", err)
			}

			if err := lr.SetAPIEndpoint(ma); err != nil {
				return xerrors.Errorf("setting api endpoint: %w", err)
			}

			ainfo, err := lcli.GetAPIInfo(cctx, repo.StorageMiner)
			if err != nil {
				return xerrors.Errorf("could not get miner API info: %w", err)
			}

			// TODO: ideally this would be a token with some permissions dropped
			if err := lr.SetAPIToken(ainfo.Token); err != nil {
				return xerrors.Errorf("setting api token: %w", err)
			}
		}

		minerSession, err := minerapi.Session(ctx)
		if err != nil {
			return xerrors.Errorf("getting miner session: %w", err)
		}

		waitQuietCh := func() chan struct{} {
			out := make(chan struct{})
			go func() {
				workerApi.LocalWorker.WaitQuiet()
				close(out)
			}()
			return out
		}

		go func() {
			heartbeats := time.NewTicker(stores.HeartbeatInterval)
			defer heartbeats.Stop()

			var redeclareStorage bool
			var readyCh chan struct{}
			for {
				// If we're reconnecting, redeclare storage first
				if redeclareStorage {
					log.Info("Redeclaring local storage")

					if err := localStore.Redeclare(ctx); err != nil {
						log.Errorf("Redeclaring local storage failed: %+v", err)

						select {
						case <-ctx.Done():
							return // graceful shutdown
						case <-heartbeats.C:
						}
						continue
					}
				}

				// TODO: we could get rid of this, but that requires tracking resources for restarted tasks correctly
				if readyCh == nil {
					log.Info("Making sure no local tasks are running")
					readyCh = waitQuietCh()
				}

				for {
					curSession, err := minerapi.Session(ctx)
					if err != nil {
						log.Errorf("heartbeat: checking remote session failed: %+v", err)
					} else {
						if curSession != minerSession {
							minerSession = curSession
							break
						}
					}

					select {
					case <-readyCh:
						if err := minerapi.WorkerConnect(ctx, "http://"+address+"/rpc/v0"); err != nil {
							log.Errorf("Registering worker failed: %+v", err)
							cancel()
							return
						}

						log.Info("Worker registered successfully, waiting for tasks")

						readyCh = nil
					case <-heartbeats.C:
					case <-ctx.Done():
						return // graceful shutdown
					}
				}

				log.Errorf("LOTUS-MINER CONNECTION LOST")

				redeclareStorage = true
			}
		}()

		return srv.Serve(nl)
	},
}

func extractRoutableIP(timeout time.Duration) (string, error) {
	minerMultiAddrKey := "MINER_API_INFO"
	deprecatedMinerMultiAddrKey := "STORAGE_API_INFO"
	env, ok := os.LookupEnv(minerMultiAddrKey)
	if !ok {
		// TODO remove after deprecation period
		_, ok = os.LookupEnv(deprecatedMinerMultiAddrKey)
		if ok {
			log.Warnf("Using a deprecated env(%s) value, please use env(%s) instead.", deprecatedMinerMultiAddrKey, minerMultiAddrKey)
		}
		return "", xerrors.New("MINER_API_INFO environment variable required to extract IP")
	}
	minerAddr := strings.Split(env, "/")
	conn, err := net.DialTimeout("tcp", minerAddr[2]+":"+minerAddr[4], timeout)
	if err != nil {
		return "", err
	}
	defer conn.Close() //nolint:errcheck

	localAddr := conn.LocalAddr().(*net.TCPAddr)

	return strings.Split(localAddr.IP.String(), ":")[0], nil
}

func setPeerId(address string, path string) error {
	_, err := os.Stat(filepath.Join(path, peerFile))
	if !os.IsNotExist(err) {
		if err == nil {
			log.Debugf("%s is already initialized", peerFile)
		}
		return err
	} else {
		type LocalNodeInfo struct {
			ID    string
			Alias string
		}

		hostname, err := os.Hostname() // TODO: allow overriding from config
		if err != nil {
			panic(err)
		}
		split := "+"
		var build strings.Builder
		build.WriteString(hostname)
		build.WriteString(split)
		build.WriteString(address)
		build.WriteString(split)
		build.WriteString(path)
		alias := build.String()
		b, err := json.MarshalIndent(&LocalNodeInfo{
			ID:    uuid.New().String(),
			Alias: alias,
		}, "", "  ")
		if err != nil {
			return xerrors.Errorf("marshaling peerid config: %w", err)
		}

		if err := ioutil.WriteFile(filepath.Join(path, peerFile), b, 0644); err != nil {
			return xerrors.Errorf("persisting peerid config (%s): %w", filepath.Join(path, peerFile), err)
		}
	}

	return nil
}

func switchWPoSt(cctx *cli.Context) error {
	ctx, _ := tag.New(lcli.DaemonContext(cctx),
		tag.Insert(metrics.Version, build.BuildVersion),
		tag.Insert(metrics.Commit, build.CurrentCommit),
		tag.Insert(metrics.NodeType, "wdpost-miner"),
	)
	// Register all metric views
	if err := view.Register(
		metrics.MinerNodeViews...,
	); err != nil {
		log.Fatalf("Cannot register the view: %v", err)
	}
	// Set the metric to one so it is published to the exporter
	stats.Record(ctx, metrics.LotusInfo.M(1))

	os.Setenv("LOTUS_WDPOSTONLY", "true")

	nodeApi, ncloser, err := lcli.GetFullNodeAPIV1(cctx)
	if err != nil {
		return xerrors.Errorf("getting full node api: %w", err)
	}
	defer ncloser()

	v, err := nodeApi.Version(ctx)
	if err != nil {
		return err
	}

	if v.APIVersion != api.FullAPIVersion1 {
		return xerrors.Errorf("lotus-daemon API version doesn't match: expected: %s", api.APIVersion{APIVersion: api.FullAPIVersion1})
	}

	minerRepoPath := cctx.String(FlagMinerRepo)
	r, err := repo.NewFS(minerRepoPath)
	if err != nil {
		return err
	}

	ok, err := r.Exists()
	if err != nil {
		return err
	}
	if !ok {
		return xerrors.Errorf("repo at '%s' is not initialized, run 'lotus-miner init' to set it up", minerRepoPath)
	}

	lr, err := r.Lock(repo.StorageMiner)
	if err != nil {
		return err
	}
	c, err := lr.Config()
	if err != nil {
		return err
	}
	cfg, ok := c.(*config.StorageMiner)
	if !ok {
		return xerrors.Errorf("invalid config for repo, got: %T", c)
	}

	err = lr.Close()
	if err != nil {
		return err
	}

	shutdownChan := make(chan struct{})

	var minerapi api.StorageMiner
	stop, err := node.New(ctx,
		node.StorageMiner(&minerapi, cfg.Subsystems),
		node.Override(new(dtypes.ShutdownChan), shutdownChan),
		node.Base(),
		node.Repo(r),
		node.Override(new(v1api.FullNode), nodeApi),
	)
	if err != nil {
		return xerrors.Errorf("creating node: %w", err)
	}

	log.Infof("wdpost worker Remote version %s", v)

	// Monitor for shutdown.
	finishCh := node.MonitorShutdown(shutdownChan,
		node.ShutdownHandler{Component: "wdpost worker", StopFunc: stop},
	)

	<-finishCh
	return nil
}
