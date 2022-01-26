package tracing

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-resty/resty/v2"
	"github.com/google/uuid"
	"golang.org/x/xerrors"
)

type ErrMsg struct {
	Error string `json:"error"`
}

func (err *ErrMsg) Err() error {
	return errors.New(err.Error)
}

var (
	ErrDataNotExists    = errors.New("data not exists")
	ErrSystemExecFailed = errors.New("program execution error")
)

const EmptyString = ""
const peerFile = "peerid.json"

type LocalNodeInfo struct {
	ID    string `json:"ID"`
	Alias string `json:"Alias"`
}

type WorkTaskRequest struct {
	UUID     string `form:"uuid" json:"uuid" binding:"required"`
	Alias    string `form:"alias" json:"alias"`
	SectorID string `form:"sectorid" json:"sectorid"`
	TaskType string `form:"taskType" json:"taskType"`
	Status   string `form:"status" json:"status"`
	Duration int64  `form:"duration" json:"duration"`
	EndTs    int64  `form:"endts" json:"endts"`
}

type WorkTaskResponse struct {
	Msg string `json:"msg"`
}

type PerfTrait interface {
	WorkerTask(actorID, sectorNumber string, taskType, status string, duration, endTs int64) (string, error)
}

type PerfClient struct {
	cli    *resty.Client
	peerid LocalNodeInfo
}

func NewPerfClient(cfg []string) (*PerfClient, error) {
	var node LocalNodeInfo
	for _, path := range cfg {
		err := touch(path)
		if err == nil {
			fdata, err := ioutil.ReadFile(filepath.Join(path, peerFile))
			if err != nil {
				return nil, err
			}
			if err := json.Unmarshal(fdata, &node); err != nil {
				return nil, err
			}
			break
		}
	}

	perfApiAddrKey := "PERF_API_INFO"
	env, ok := os.LookupEnv(perfApiAddrKey)
	if !ok {
		env = "http://localhost:9000"
		log.Errorf("PERF_API_INFO environment variable required to extract IP")
	}
	perfAddr := strings.Split(env, ":")
	if len(perfAddr) != 2 {
		return nil, xerrors.New("PERF_API_INFO environment variable format is invalid")
	}

	log.Infof("perf client url: %s, peerid: %+v", env, node)
	client := resty.New().
		SetBaseURL("http://"+env).
		SetHeader("Accept", "application/json")
	return &PerfClient{cli: client, peerid: node}, nil
}

func touch(path string) error {
	_, err := os.Stat(filepath.Join(path, peerFile))
	notexist := os.IsNotExist(err)
	if notexist {
		err = nil
	}

	if !notexist && err == nil {
		// already initialized peerFile
		return err
	}
	// setup worker peerid
	type LocalNodeInfo struct {
		ID    string
		Alias string
	}

	hostname, err := os.Hostname() // TODO: allow overriding from config
	if err != nil {
		return xerrors.Errorf("os hostname: %w", err)
	}
	// add by <wangzhi@buckyos.com> 2022-01-18
	var work_name string

	if env, ok := os.LookupEnv("WORKER_NAME"); ok {
		work_name = env
	}
	split := "+"
	var build strings.Builder
	build.WriteString(hostname)
	build.WriteString(split)
	build.WriteString(work_name)
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

	log.Infof("touch %s/%s", filepath.Join(path, peerFile), peerFile)

	return err

}

func (lc *PerfClient) WorkerTask(actorID, sectorNumber string, taskType, status string, duration, endTs int64) (string, error) {
	if lc == nil {
		return EmptyString, nil
	}
	split := "+"
	var build strings.Builder
	build.WriteString(actorID)
	build.WriteString(split)
	build.WriteString(sectorNumber)
	sectorid := build.String()
	resp, err := lc.cli.R().SetBody(WorkTaskRequest{
		UUID:     lc.peerid.ID,
		Alias:    lc.peerid.Alias,
		SectorID: sectorid,
		Duration: duration,
		EndTs:    endTs,
		TaskType: taskType,
		Status:   status,
	}).SetResult(&WorkTaskResponse{}).SetError(&ErrMsg{}).Post("/lotusWorkAgent")
	if err != nil {
		return EmptyString, err
	}
	if resp.StatusCode() == http.StatusOK {
		res := resp.Result().(*WorkTaskResponse)
		return res.Msg, nil
	}

	log.Errorf("perf %s, %s work task err %s", lc.peerid.ID, lc.peerid.Alias, err)
	return EmptyString, resp.Error().(*ErrMsg).Err()
}
