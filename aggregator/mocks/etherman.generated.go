// Code generated by mockery v2.45.1. DO NOT EDIT.

package mocks

import (
	context "context"

	common "github.com/ethereum/go-ethereum/common"

	ethmantypes "github.com/0xPolygon/cdk/aggregator/ethmantypes"

	mock "github.com/stretchr/testify/mock"

	types "github.com/ethereum/go-ethereum/core/types"
)

// EthermanMock is an autogenerated mock type for the Etherman type
type EthermanMock struct {
	mock.Mock
}

type EthermanMock_Expecter struct {
	mock *mock.Mock
}

func (_m *EthermanMock) EXPECT() *EthermanMock_Expecter {
	return &EthermanMock_Expecter{mock: &_m.Mock}
}

// BuildTrustedVerifyBatchesTxData provides a mock function with given fields: lastVerifiedBatch, newVerifiedBatch, inputs, beneficiary
func (_m *EthermanMock) BuildTrustedVerifyBatchesTxData(lastVerifiedBatch uint64, newVerifiedBatch uint64, inputs *ethmantypes.FinalProofInputs, beneficiary common.Address) (*common.Address, []byte, error) {
	ret := _m.Called(lastVerifiedBatch, newVerifiedBatch, inputs, beneficiary)

	if len(ret) == 0 {
		panic("no return value specified for BuildTrustedVerifyBatchesTxData")
	}

	var r0 *common.Address
	var r1 []byte
	var r2 error
	if rf, ok := ret.Get(0).(func(uint64, uint64, *ethmantypes.FinalProofInputs, common.Address) (*common.Address, []byte, error)); ok {
		return rf(lastVerifiedBatch, newVerifiedBatch, inputs, beneficiary)
	}
	if rf, ok := ret.Get(0).(func(uint64, uint64, *ethmantypes.FinalProofInputs, common.Address) *common.Address); ok {
		r0 = rf(lastVerifiedBatch, newVerifiedBatch, inputs, beneficiary)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*common.Address)
		}
	}

	if rf, ok := ret.Get(1).(func(uint64, uint64, *ethmantypes.FinalProofInputs, common.Address) []byte); ok {
		r1 = rf(lastVerifiedBatch, newVerifiedBatch, inputs, beneficiary)
	} else {
		if ret.Get(1) != nil {
			r1 = ret.Get(1).([]byte)
		}
	}

	if rf, ok := ret.Get(2).(func(uint64, uint64, *ethmantypes.FinalProofInputs, common.Address) error); ok {
		r2 = rf(lastVerifiedBatch, newVerifiedBatch, inputs, beneficiary)
	} else {
		r2 = ret.Error(2)
	}

	return r0, r1, r2
}

// EthermanMock_BuildTrustedVerifyBatchesTxData_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'BuildTrustedVerifyBatchesTxData'
type EthermanMock_BuildTrustedVerifyBatchesTxData_Call struct {
	*mock.Call
}

// BuildTrustedVerifyBatchesTxData is a helper method to define mock.On call
//   - lastVerifiedBatch uint64
//   - newVerifiedBatch uint64
//   - inputs *ethmantypes.FinalProofInputs
//   - beneficiary common.Address
func (_e *EthermanMock_Expecter) BuildTrustedVerifyBatchesTxData(lastVerifiedBatch interface{}, newVerifiedBatch interface{}, inputs interface{}, beneficiary interface{}) *EthermanMock_BuildTrustedVerifyBatchesTxData_Call {
	return &EthermanMock_BuildTrustedVerifyBatchesTxData_Call{Call: _e.mock.On("BuildTrustedVerifyBatchesTxData", lastVerifiedBatch, newVerifiedBatch, inputs, beneficiary)}
}

func (_c *EthermanMock_BuildTrustedVerifyBatchesTxData_Call) Run(run func(lastVerifiedBatch uint64, newVerifiedBatch uint64, inputs *ethmantypes.FinalProofInputs, beneficiary common.Address)) *EthermanMock_BuildTrustedVerifyBatchesTxData_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(uint64), args[1].(uint64), args[2].(*ethmantypes.FinalProofInputs), args[3].(common.Address))
	})
	return _c
}

func (_c *EthermanMock_BuildTrustedVerifyBatchesTxData_Call) Return(to *common.Address, data []byte, err error) *EthermanMock_BuildTrustedVerifyBatchesTxData_Call {
	_c.Call.Return(to, data, err)
	return _c
}

func (_c *EthermanMock_BuildTrustedVerifyBatchesTxData_Call) RunAndReturn(run func(uint64, uint64, *ethmantypes.FinalProofInputs, common.Address) (*common.Address, []byte, error)) *EthermanMock_BuildTrustedVerifyBatchesTxData_Call {
	_c.Call.Return(run)
	return _c
}

// GetBatchAccInputHash provides a mock function with given fields: ctx, batchNumber
func (_m *EthermanMock) GetBatchAccInputHash(ctx context.Context, batchNumber uint64) (common.Hash, error) {
	ret := _m.Called(ctx, batchNumber)

	if len(ret) == 0 {
		panic("no return value specified for GetBatchAccInputHash")
	}

	var r0 common.Hash
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, uint64) (common.Hash, error)); ok {
		return rf(ctx, batchNumber)
	}
	if rf, ok := ret.Get(0).(func(context.Context, uint64) common.Hash); ok {
		r0 = rf(ctx, batchNumber)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(common.Hash)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, uint64) error); ok {
		r1 = rf(ctx, batchNumber)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// EthermanMock_GetBatchAccInputHash_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetBatchAccInputHash'
type EthermanMock_GetBatchAccInputHash_Call struct {
	*mock.Call
}

// GetBatchAccInputHash is a helper method to define mock.On call
//   - ctx context.Context
//   - batchNumber uint64
func (_e *EthermanMock_Expecter) GetBatchAccInputHash(ctx interface{}, batchNumber interface{}) *EthermanMock_GetBatchAccInputHash_Call {
	return &EthermanMock_GetBatchAccInputHash_Call{Call: _e.mock.On("GetBatchAccInputHash", ctx, batchNumber)}
}

func (_c *EthermanMock_GetBatchAccInputHash_Call) Run(run func(ctx context.Context, batchNumber uint64)) *EthermanMock_GetBatchAccInputHash_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(uint64))
	})
	return _c
}

func (_c *EthermanMock_GetBatchAccInputHash_Call) Return(_a0 common.Hash, _a1 error) *EthermanMock_GetBatchAccInputHash_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *EthermanMock_GetBatchAccInputHash_Call) RunAndReturn(run func(context.Context, uint64) (common.Hash, error)) *EthermanMock_GetBatchAccInputHash_Call {
	_c.Call.Return(run)
	return _c
}

// GetLatestBlockHeader provides a mock function with given fields: ctx
func (_m *EthermanMock) GetLatestBlockHeader(ctx context.Context) (*types.Header, error) {
	ret := _m.Called(ctx)

	if len(ret) == 0 {
		panic("no return value specified for GetLatestBlockHeader")
	}

	var r0 *types.Header
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context) (*types.Header, error)); ok {
		return rf(ctx)
	}
	if rf, ok := ret.Get(0).(func(context.Context) *types.Header); ok {
		r0 = rf(ctx)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*types.Header)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context) error); ok {
		r1 = rf(ctx)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// EthermanMock_GetLatestBlockHeader_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetLatestBlockHeader'
type EthermanMock_GetLatestBlockHeader_Call struct {
	*mock.Call
}

// GetLatestBlockHeader is a helper method to define mock.On call
//   - ctx context.Context
func (_e *EthermanMock_Expecter) GetLatestBlockHeader(ctx interface{}) *EthermanMock_GetLatestBlockHeader_Call {
	return &EthermanMock_GetLatestBlockHeader_Call{Call: _e.mock.On("GetLatestBlockHeader", ctx)}
}

func (_c *EthermanMock_GetLatestBlockHeader_Call) Run(run func(ctx context.Context)) *EthermanMock_GetLatestBlockHeader_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context))
	})
	return _c
}

func (_c *EthermanMock_GetLatestBlockHeader_Call) Return(_a0 *types.Header, _a1 error) *EthermanMock_GetLatestBlockHeader_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *EthermanMock_GetLatestBlockHeader_Call) RunAndReturn(run func(context.Context) (*types.Header, error)) *EthermanMock_GetLatestBlockHeader_Call {
	_c.Call.Return(run)
	return _c
}

// GetLatestVerifiedBatchNum provides a mock function with given fields:
func (_m *EthermanMock) GetLatestVerifiedBatchNum() (uint64, error) {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for GetLatestVerifiedBatchNum")
	}

	var r0 uint64
	var r1 error
	if rf, ok := ret.Get(0).(func() (uint64, error)); ok {
		return rf()
	}
	if rf, ok := ret.Get(0).(func() uint64); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(uint64)
	}

	if rf, ok := ret.Get(1).(func() error); ok {
		r1 = rf()
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// EthermanMock_GetLatestVerifiedBatchNum_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetLatestVerifiedBatchNum'
type EthermanMock_GetLatestVerifiedBatchNum_Call struct {
	*mock.Call
}

// GetLatestVerifiedBatchNum is a helper method to define mock.On call
func (_e *EthermanMock_Expecter) GetLatestVerifiedBatchNum() *EthermanMock_GetLatestVerifiedBatchNum_Call {
	return &EthermanMock_GetLatestVerifiedBatchNum_Call{Call: _e.mock.On("GetLatestVerifiedBatchNum")}
}

func (_c *EthermanMock_GetLatestVerifiedBatchNum_Call) Run(run func()) *EthermanMock_GetLatestVerifiedBatchNum_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *EthermanMock_GetLatestVerifiedBatchNum_Call) Return(_a0 uint64, _a1 error) *EthermanMock_GetLatestVerifiedBatchNum_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *EthermanMock_GetLatestVerifiedBatchNum_Call) RunAndReturn(run func() (uint64, error)) *EthermanMock_GetLatestVerifiedBatchNum_Call {
	_c.Call.Return(run)
	return _c
}

// GetRollupId provides a mock function with given fields:
func (_m *EthermanMock) GetRollupId() uint32 {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for GetRollupId")
	}

	var r0 uint32
	if rf, ok := ret.Get(0).(func() uint32); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(uint32)
	}

	return r0
}

// EthermanMock_GetRollupId_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetRollupId'
type EthermanMock_GetRollupId_Call struct {
	*mock.Call
}

// GetRollupId is a helper method to define mock.On call
func (_e *EthermanMock_Expecter) GetRollupId() *EthermanMock_GetRollupId_Call {
	return &EthermanMock_GetRollupId_Call{Call: _e.mock.On("GetRollupId")}
}

func (_c *EthermanMock_GetRollupId_Call) Run(run func()) *EthermanMock_GetRollupId_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *EthermanMock_GetRollupId_Call) Return(_a0 uint32) *EthermanMock_GetRollupId_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *EthermanMock_GetRollupId_Call) RunAndReturn(run func() uint32) *EthermanMock_GetRollupId_Call {
	_c.Call.Return(run)
	return _c
}

// NewEthermanMock creates a new instance of EthermanMock. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewEthermanMock(t interface {
	mock.TestingT
	Cleanup(func())
}) *EthermanMock {
	mock := &EthermanMock{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
