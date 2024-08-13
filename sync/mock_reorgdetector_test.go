// Code generated by mockery v2.22.1. DO NOT EDIT.

package sync

import (
	context "context"

	common "github.com/ethereum/go-ethereum/common"

	mock "github.com/stretchr/testify/mock"

	reorgdetector "github.com/0xPolygon/cdk/reorgdetector"
)

// ReorgDetectorMock is an autogenerated mock type for the ReorgDetector type
type ReorgDetectorMock struct {
	mock.Mock
}

// AddBlockToTrack provides a mock function with given fields: ctx, id, blockNum, blockHash
func (_m *ReorgDetectorMock) AddBlockToTrack(ctx context.Context, id string, blockNum uint64, blockHash common.Hash) error {
	ret := _m.Called(ctx, id, blockNum, blockHash)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string, uint64, common.Hash) error); ok {
		r0 = rf(ctx, id, blockNum, blockHash)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// Subscribe provides a mock function with given fields: id
func (_m *ReorgDetectorMock) Subscribe(id string) (*reorgdetector.Subscription, error) {
	ret := _m.Called(id)

	var r0 *reorgdetector.Subscription
	var r1 error
	if rf, ok := ret.Get(0).(func(string) (*reorgdetector.Subscription, error)); ok {
		return rf(id)
	}
	if rf, ok := ret.Get(0).(func(string) *reorgdetector.Subscription); ok {
		r0 = rf(id)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*reorgdetector.Subscription)
		}
	}

	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(id)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

type mockConstructorTestingTNewReorgDetectorMock interface {
	mock.TestingT
	Cleanup(func())
}

// NewReorgDetectorMock creates a new instance of ReorgDetectorMock. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
func NewReorgDetectorMock(t mockConstructorTestingTNewReorgDetectorMock) *ReorgDetectorMock {
	mock := &ReorgDetectorMock{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
