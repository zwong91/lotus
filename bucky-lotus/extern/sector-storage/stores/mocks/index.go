// Code generated by MockGen. DO NOT EDIT.
// Source: index.go

// Package mocks is a generated GoMock package.
package mocks

import (
	context "context"
	reflect "reflect"

	abi "github.com/filecoin-project/go-state-types/abi"
	fsutil "github.com/filecoin-project/lotus/extern/sector-storage/fsutil"
	stores "github.com/filecoin-project/lotus/extern/sector-storage/stores"
	storiface "github.com/filecoin-project/lotus/extern/sector-storage/storiface"
	gomock "github.com/golang/mock/gomock"
)

// MockSectorIndex is a mock of SectorIndex interface.
type MockSectorIndex struct {
	ctrl     *gomock.Controller
	recorder *MockSectorIndexMockRecorder
}

// MockSectorIndexMockRecorder is the mock recorder for MockSectorIndex.
type MockSectorIndexMockRecorder struct {
	mock *MockSectorIndex
}

// NewMockSectorIndex creates a new mock instance.
func NewMockSectorIndex(ctrl *gomock.Controller) *MockSectorIndex {
	mock := &MockSectorIndex{ctrl: ctrl}
	mock.recorder = &MockSectorIndexMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockSectorIndex) EXPECT() *MockSectorIndexMockRecorder {
	return m.recorder
}

// StorageAttach mocks base method.
func (m *MockSectorIndex) StorageAttach(arg0 context.Context, arg1 stores.StorageInfo, arg2 fsutil.FsStat) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "StorageAttach", arg0, arg1, arg2)
	ret0, _ := ret[0].(error)
	return ret0
}

// StorageAttach indicates an expected call of StorageAttach.
func (mr *MockSectorIndexMockRecorder) StorageAttach(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "StorageAttach", reflect.TypeOf((*MockSectorIndex)(nil).StorageAttach), arg0, arg1, arg2)
}

// StorageBestAlloc mocks base method.
func (m *MockSectorIndex) StorageBestAlloc(ctx context.Context, allocate storiface.SectorFileType, ssize abi.SectorSize, pathType storiface.PathType) ([]stores.StorageInfo, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "StorageBestAlloc", ctx, allocate, ssize, pathType)
	ret0, _ := ret[0].([]stores.StorageInfo)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// StorageBestAlloc indicates an expected call of StorageBestAlloc.
func (mr *MockSectorIndexMockRecorder) StorageBestAlloc(ctx, allocate, ssize, pathType interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "StorageBestAlloc", reflect.TypeOf((*MockSectorIndex)(nil).StorageBestAlloc), ctx, allocate, ssize, pathType)
}

// StorageDeclareSector mocks base method.
func (m *MockSectorIndex) StorageDeclareSector(ctx context.Context, storageID stores.ID, s abi.SectorID, ft storiface.SectorFileType, primary bool) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "StorageDeclareSector", ctx, storageID, s, ft, primary)
	ret0, _ := ret[0].(error)
	return ret0
}

// StorageDeclareSector indicates an expected call of StorageDeclareSector.
func (mr *MockSectorIndexMockRecorder) StorageDeclareSector(ctx, storageID, s, ft, primary interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "StorageDeclareSector", reflect.TypeOf((*MockSectorIndex)(nil).StorageDeclareSector), ctx, storageID, s, ft, primary)
}

// StorageDropSector mocks base method.
func (m *MockSectorIndex) StorageDropSector(ctx context.Context, storageID stores.ID, s abi.SectorID, ft storiface.SectorFileType) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "StorageDropSector", ctx, storageID, s, ft)
	ret0, _ := ret[0].(error)
	return ret0
}

// StorageDropSector indicates an expected call of StorageDropSector.
func (mr *MockSectorIndexMockRecorder) StorageDropSector(ctx, storageID, s, ft interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "StorageDropSector", reflect.TypeOf((*MockSectorIndex)(nil).StorageDropSector), ctx, storageID, s, ft)
}

// StorageFindSector mocks base method.
func (m *MockSectorIndex) StorageFindSector(ctx context.Context, sector abi.SectorID, ft storiface.SectorFileType, ssize abi.SectorSize, allowFetch bool) ([]stores.SectorStorageInfo, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "StorageFindSector", ctx, sector, ft, ssize, allowFetch)
	ret0, _ := ret[0].([]stores.SectorStorageInfo)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// StorageFindSector indicates an expected call of StorageFindSector.
func (mr *MockSectorIndexMockRecorder) StorageFindSector(ctx, sector, ft, ssize, allowFetch interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "StorageFindSector", reflect.TypeOf((*MockSectorIndex)(nil).StorageFindSector), ctx, sector, ft, ssize, allowFetch)
}

// StorageInfo mocks base method.
func (m *MockSectorIndex) StorageInfo(arg0 context.Context, arg1 stores.ID) (stores.StorageInfo, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "StorageInfo", arg0, arg1)
	ret0, _ := ret[0].(stores.StorageInfo)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// StorageInfo indicates an expected call of StorageInfo.
func (mr *MockSectorIndexMockRecorder) StorageInfo(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "StorageInfo", reflect.TypeOf((*MockSectorIndex)(nil).StorageInfo), arg0, arg1)
}

// StorageList mocks base method.
func (m *MockSectorIndex) StorageList(ctx context.Context) (map[stores.ID][]stores.Decl, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "StorageList", ctx)
	ret0, _ := ret[0].(map[stores.ID][]stores.Decl)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// StorageList indicates an expected call of StorageList.
func (mr *MockSectorIndexMockRecorder) StorageList(ctx interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "StorageList", reflect.TypeOf((*MockSectorIndex)(nil).StorageList), ctx)
}

// StorageLock mocks base method.
func (m *MockSectorIndex) StorageLock(ctx context.Context, sector abi.SectorID, read, write storiface.SectorFileType) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "StorageLock", ctx, sector, read, write)
	ret0, _ := ret[0].(error)
	return ret0
}

// StorageLock indicates an expected call of StorageLock.
func (mr *MockSectorIndexMockRecorder) StorageLock(ctx, sector, read, write interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "StorageLock", reflect.TypeOf((*MockSectorIndex)(nil).StorageLock), ctx, sector, read, write)
}

// StorageReportHealth mocks base method.
func (m *MockSectorIndex) StorageReportHealth(arg0 context.Context, arg1 stores.ID, arg2 stores.HealthReport) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "StorageReportHealth", arg0, arg1, arg2)
	ret0, _ := ret[0].(error)
	return ret0
}

// StorageReportHealth indicates an expected call of StorageReportHealth.
func (mr *MockSectorIndexMockRecorder) StorageReportHealth(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "StorageReportHealth", reflect.TypeOf((*MockSectorIndex)(nil).StorageReportHealth), arg0, arg1, arg2)
}

// StorageTryLock mocks base method.
func (m *MockSectorIndex) StorageTryLock(ctx context.Context, sector abi.SectorID, read, write storiface.SectorFileType) (bool, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "StorageTryLock", ctx, sector, read, write)
	ret0, _ := ret[0].(bool)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// StorageTryLock indicates an expected call of StorageTryLock.
func (mr *MockSectorIndexMockRecorder) StorageTryLock(ctx, sector, read, write interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "StorageTryLock", reflect.TypeOf((*MockSectorIndex)(nil).StorageTryLock), ctx, sector, read, write)
}
