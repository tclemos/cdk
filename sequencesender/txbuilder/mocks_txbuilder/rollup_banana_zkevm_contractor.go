// Code generated by mockery. DO NOT EDIT.

package mocks_txbuilder

import (
	bind "github.com/ethereum/go-ethereum/accounts/abi/bind"
	common "github.com/ethereum/go-ethereum/common"

	mock "github.com/stretchr/testify/mock"

	polygonvalidiumetrog "github.com/0xPolygon/cdk-contracts-tooling/contracts/banana/polygonvalidiumetrog"

	types "github.com/ethereum/go-ethereum/core/types"
)

// RollupBananaZKEVMContractor is an autogenerated mock type for the rollupBananaZKEVMContractor type
type RollupBananaZKEVMContractor struct {
	mock.Mock
}

type RollupBananaZKEVMContractor_Expecter struct {
	mock *mock.Mock
}

func (_m *RollupBananaZKEVMContractor) EXPECT() *RollupBananaZKEVMContractor_Expecter {
	return &RollupBananaZKEVMContractor_Expecter{mock: &_m.Mock}
}

// LastAccInputHash provides a mock function with given fields: opts
func (_m *RollupBananaZKEVMContractor) LastAccInputHash(opts *bind.CallOpts) ([32]byte, error) {
	ret := _m.Called(opts)

	var r0 [32]byte
	var r1 error
	if rf, ok := ret.Get(0).(func(*bind.CallOpts) ([32]byte, error)); ok {
		return rf(opts)
	}
	if rf, ok := ret.Get(0).(func(*bind.CallOpts) [32]byte); ok {
		r0 = rf(opts)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([32]byte)
		}
	}

	if rf, ok := ret.Get(1).(func(*bind.CallOpts) error); ok {
		r1 = rf(opts)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// RollupBananaZKEVMContractor_LastAccInputHash_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'LastAccInputHash'
type RollupBananaZKEVMContractor_LastAccInputHash_Call struct {
	*mock.Call
}

// LastAccInputHash is a helper method to define mock.On call
//   - opts *bind.CallOpts
func (_e *RollupBananaZKEVMContractor_Expecter) LastAccInputHash(opts interface{}) *RollupBananaZKEVMContractor_LastAccInputHash_Call {
	return &RollupBananaZKEVMContractor_LastAccInputHash_Call{Call: _e.mock.On("LastAccInputHash", opts)}
}

func (_c *RollupBananaZKEVMContractor_LastAccInputHash_Call) Run(run func(opts *bind.CallOpts)) *RollupBananaZKEVMContractor_LastAccInputHash_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*bind.CallOpts))
	})
	return _c
}

func (_c *RollupBananaZKEVMContractor_LastAccInputHash_Call) Return(_a0 [32]byte, _a1 error) *RollupBananaZKEVMContractor_LastAccInputHash_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *RollupBananaZKEVMContractor_LastAccInputHash_Call) RunAndReturn(run func(*bind.CallOpts) ([32]byte, error)) *RollupBananaZKEVMContractor_LastAccInputHash_Call {
	_c.Call.Return(run)
	return _c
}

// SequenceBatches provides a mock function with given fields: opts, batches, indexL1InfoRoot, maxSequenceTimestamp, expectedFinalAccInputHash, l2Coinbase
func (_m *RollupBananaZKEVMContractor) SequenceBatches(opts *bind.TransactOpts, batches []polygonvalidiumetrog.PolygonRollupBaseEtrogBatchData, indexL1InfoRoot uint32, maxSequenceTimestamp uint64, expectedFinalAccInputHash [32]byte, l2Coinbase common.Address) (*types.Transaction, error) {
	ret := _m.Called(opts, batches, indexL1InfoRoot, maxSequenceTimestamp, expectedFinalAccInputHash, l2Coinbase)

	var r0 *types.Transaction
	var r1 error
	if rf, ok := ret.Get(0).(func(*bind.TransactOpts, []polygonvalidiumetrog.PolygonRollupBaseEtrogBatchData, uint32, uint64, [32]byte, common.Address) (*types.Transaction, error)); ok {
		return rf(opts, batches, indexL1InfoRoot, maxSequenceTimestamp, expectedFinalAccInputHash, l2Coinbase)
	}
	if rf, ok := ret.Get(0).(func(*bind.TransactOpts, []polygonvalidiumetrog.PolygonRollupBaseEtrogBatchData, uint32, uint64, [32]byte, common.Address) *types.Transaction); ok {
		r0 = rf(opts, batches, indexL1InfoRoot, maxSequenceTimestamp, expectedFinalAccInputHash, l2Coinbase)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*types.Transaction)
		}
	}

	if rf, ok := ret.Get(1).(func(*bind.TransactOpts, []polygonvalidiumetrog.PolygonRollupBaseEtrogBatchData, uint32, uint64, [32]byte, common.Address) error); ok {
		r1 = rf(opts, batches, indexL1InfoRoot, maxSequenceTimestamp, expectedFinalAccInputHash, l2Coinbase)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// RollupBananaZKEVMContractor_SequenceBatches_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'SequenceBatches'
type RollupBananaZKEVMContractor_SequenceBatches_Call struct {
	*mock.Call
}

// SequenceBatches is a helper method to define mock.On call
//   - opts *bind.TransactOpts
//   - batches []polygonvalidiumetrog.PolygonRollupBaseEtrogBatchData
//   - indexL1InfoRoot uint32
//   - maxSequenceTimestamp uint64
//   - expectedFinalAccInputHash [32]byte
//   - l2Coinbase common.Address
func (_e *RollupBananaZKEVMContractor_Expecter) SequenceBatches(opts interface{}, batches interface{}, indexL1InfoRoot interface{}, maxSequenceTimestamp interface{}, expectedFinalAccInputHash interface{}, l2Coinbase interface{}) *RollupBananaZKEVMContractor_SequenceBatches_Call {
	return &RollupBananaZKEVMContractor_SequenceBatches_Call{Call: _e.mock.On("SequenceBatches", opts, batches, indexL1InfoRoot, maxSequenceTimestamp, expectedFinalAccInputHash, l2Coinbase)}
}

func (_c *RollupBananaZKEVMContractor_SequenceBatches_Call) Run(run func(opts *bind.TransactOpts, batches []polygonvalidiumetrog.PolygonRollupBaseEtrogBatchData, indexL1InfoRoot uint32, maxSequenceTimestamp uint64, expectedFinalAccInputHash [32]byte, l2Coinbase common.Address)) *RollupBananaZKEVMContractor_SequenceBatches_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*bind.TransactOpts), args[1].([]polygonvalidiumetrog.PolygonRollupBaseEtrogBatchData), args[2].(uint32), args[3].(uint64), args[4].([32]byte), args[5].(common.Address))
	})
	return _c
}

func (_c *RollupBananaZKEVMContractor_SequenceBatches_Call) Return(_a0 *types.Transaction, _a1 error) *RollupBananaZKEVMContractor_SequenceBatches_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *RollupBananaZKEVMContractor_SequenceBatches_Call) RunAndReturn(run func(*bind.TransactOpts, []polygonvalidiumetrog.PolygonRollupBaseEtrogBatchData, uint32, uint64, [32]byte, common.Address) (*types.Transaction, error)) *RollupBananaZKEVMContractor_SequenceBatches_Call {
	_c.Call.Return(run)
	return _c
}

type mockConstructorTestingTNewRollupBananaZKEVMContractor interface {
	mock.TestingT
	Cleanup(func())
}

// NewRollupBananaZKEVMContractor creates a new instance of RollupBananaZKEVMContractor. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
func NewRollupBananaZKEVMContractor(t mockConstructorTestingTNewRollupBananaZKEVMContractor) *RollupBananaZKEVMContractor {
	mock := &RollupBananaZKEVMContractor{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
