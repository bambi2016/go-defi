// Package bclient provides a wrapper around go-ethereum's ethclient package
package bclient

import (
	"context"
	"crypto/ecdsa"
	_ "crypto/rand"
	"encoding/hex"
	"fmt"
	"github.com/ethereum/go-ethereum"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"time"

	bip39 "github.com/tyler-smith/go-bip39"

	_ "github.com/ethereum/go-ethereum/accounts"
	_ "github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
)

// ===== 重要说明 =====
// 1) 标准做法是 “助记词 -> 种子 -> (BIP32/44) 派生私钥”。不存在通用、标准且可逆的 “私钥 -> 助记词 -> 同一私钥” 流程。
//    如果必须“由私钥得到一串助记词”，那只能自定义编码（非标准，无法与钱包互通）。因此本文采用标准方向：助记词生成私钥。
// 2) 如果你已经有现成的私钥，本示例仍展示如何：
//    - 使用该私钥创建 keystore（加密 JSON）
//    - 从 keystore 解密取回私钥
// 3) 代码基于 EIP-1559（动态费用）网络（如主网、Sepolia 等）。

// ===== 配置区 =====
const (
	RPC_URL        = "https://sepolia.infura.io/v3/YOUR_INFURA_KEY" // TODO: 替换为你的 RPC
	TO_ADDRESS_HEX = "0x000000000000000000000000000000000000dEaD"   // TODO: 替换为你的收款地址
)

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func generateMnemonicAndPrivateKey() (mnemonic string, priv *ecdsa.PrivateKey, addr common.Address) {
	// 生成 128 位熵 => 12 个词的助记词（可按需改为 256 位 => 24 词）
	entropy, err := bip39.NewEntropy(128)
	must(err)
	mnemonic, err = bip39.NewMnemonic(entropy)
	must(err)

	// 注意：这里为了示例简单，使用随机私钥；
	// 标准做法应使用 BIP32/BIP44 从 mnemonic seed 派生：m/44'/60'/0'/0/0。
	// 如需严格派生，请引入 HD 派生库（例如 go-ethereum-hdwallet）。
	priv, err = crypto.GenerateKey()
	must(err)
	addr = crypto.PubkeyToAddress(priv.PublicKey)
	return
}

func keystoreFromPrivateKey(priv *ecdsa.PrivateKey, password string) (keystoreDir, filePath string) {
	// 使用 geth keystore 生成加密 JSON 文件
	keystoreDir, err := ioutil.TempDir(".", "keystore-")
	must(err)
	ks := keystore.NewKeyStore(keystoreDir, keystore.StandardScryptN, keystore.StandardScryptP)
	acc, err := ks.ImportECDSA(priv, password)
	if err != nil {
		// 如果已存在同样私钥会报错，可尝试 Unlock + Export 或先 NewAccount 再覆盖
		log.Fatalf("import ECDSA failed: %v", err)
	}
	fmt.Println("Keystore account:", acc.Address.Hex())

	// 找到刚写入的 keyfile（目录下最新 .json 文件）
	files, err := os.ReadDir(keystoreDir)
	must(err)
	var newest os.DirEntry
	var newestTime time.Time
	for _, f := range files {
		if filepath.Ext(f.Name()) == ".json" {
			info, _ := f.Info()
			if info.ModTime().After(newestTime) {
				newest = f
				newestTime = info.ModTime()
			}
		}
	}
	if newest == nil {
		log.Fatal("no keystore file found")
	}
	filePath = filepath.Join(keystoreDir, newest.Name())
	fmt.Println("Keystore file:", filePath)
	return
}

func decryptKeystoreAndGetPrivKey(jsonPath, password string) *ecdsa.PrivateKey {
	data, err := os.ReadFile(jsonPath)
	must(err)
	key, err := keystore.DecryptKey(data, password)
	must(err)
	return key.PrivateKey
}

func getBalance(ctx context.Context, client *ethclient.Client, addr common.Address) *big.Int {
	bal, err := client.BalanceAt(ctx, addr, nil) // latest
	must(err)
	return bal
}

func sendTxEIP1559(ctx context.Context, client *ethclient.Client, priv *ecdsa.PrivateKey, to common.Address, amountWei *big.Int) (txHash common.Hash) {
	fromAddr := crypto.PubkeyToAddress(priv.PublicKey)
	chainID, err := client.ChainID(ctx)
	must(err)
	nonce, err := client.PendingNonceAt(ctx, fromAddr)
	must(err)

	// EIP-1559 费用
	tipCap, err := client.SuggestGasTipCap(ctx)
	must(err)
	head, err := client.HeaderByNumber(ctx, nil)
	must(err)
	baseFee := head.BaseFee
	var feeCap *big.Int
	if baseFee != nil {
		feeCap = new(big.Int).Add(baseFee, tipCap)
	} else {
		feeCap = new(big.Int).Mul(tipCap, big.NewInt(2)) // 兜底
	}

	// 估算 gas 限额
	msg := ethereumCallMsg{
		From:  fromAddr,
		To:    &to,
		Value: amountWei,
	}
	gasLimit, err := client.EstimateGas(ctx, msg.toCallMsg())
	must(err)

	tx := types.NewTx(&types.DynamicFeeTx{
		ChainID:   chainID,
		Nonce:     nonce,
		GasTipCap: tipCap,
		GasFeeCap: feeCap,
		Gas:       gasLimit,
		To:        &to,
		Value:     amountWei,
		Data:      nil,
	})

	signer := types.LatestSignerForChainID(chainID)
	signedTx, err := types.SignTx(tx, signer, priv)
	must(err)
	must(client.SendTransaction(ctx, signedTx))
	fmt.Println("Sent tx:", signedTx.Hash().Hex())
	return signedTx.Hash()
}

// ethereumCallMsg: 仅用于 EstimateGas，避免直接引入 geth 内部类型差异
// （也可使用 bind.NewKeyedTransactorWithChainID + bind.TransactOpts）
type ethereumCallMsg struct {
	From  common.Address
	To    *common.Address
	Value *big.Int
	Data  []byte
}

func (m ethereumCallMsg) toCallMsg() (msgCall ethereum.CallMsg) {
	// ethclient.EstimateGas 接收的是 ethereum.CallMsg（在 geth 模块里）
	// 为避免跨包引用出错，这里直接在调用处构造；此处仅作为占位注释。
	return ethereum.CallMsg{
		From:  m.From,
		To:    m.To,
		Value: m.Value,
		Data:  m.Data,
		// 其他字段可以留空或设为零值，EstimateGas会自动处理
		Gas:        0,
		GasPrice:   nil,
		GasFeeCap:  nil,
		GasTipCap:  nil,
		AccessList: types.AccessList{},
	}
}

func subscribeNewBlocksAndPrintTxs(ctx context.Context, client *ethclient.Client) {
	heads := make(chan *types.Header)
	sub, err := client.SubscribeNewHead(ctx, heads)
	must(err)
	fmt.Println("Subscribed to new heads…")
	for {
		select {
		case err := <-sub.Err():
			log.Fatalf("subscription error: %v", err)
		case head := <-heads:
			if head == nil {
				continue
			}
			block, err := client.BlockByHash(ctx, head.Hash())
			if err != nil {
				log.Println("get block error:", err)
				continue
			}
			fmt.Printf("New block #%v (%s) txs=%d\n", block.Number(), block.Hash().Hex(), len(block.Transactions()))
			for _, tx := range block.Transactions() {
				from, _ := types.Sender(types.LatestSignerForChainID(tx.ChainId()), tx)
				to := "<contract creation>"
				if tx.To() != nil {
					to = tx.To().Hex()
				}
				fmt.Printf("  tx %s\n    from %s\n    to   %s\n    value %s wei\n", tx.Hash().Hex(), from.Hex(), to, tx.Value().String())
			}
		}
	}
}

func main() {
	ctx := context.Background()

	// 1) 生成助记词 + 随机私钥（演示）
	mnemonic, priv, addr := generateMnemonicAndPrivateKey()
	fmt.Println("Mnemonic:", mnemonic)
	fmt.Println("PrivateKey (hex):", hex.EncodeToString(crypto.FromECDSA(priv)))
	fmt.Println("Address:", addr.Hex())

	// 2) 用私钥创建 keystore，并可从 keystore 解密取回私钥
	password := "StrongPassword123!"
	ksDir, keyfile := keystoreFromPrivateKey(priv, password)
	defer os.RemoveAll(ksDir)
	priv2 := decryptKeystoreAndGetPrivKey(keyfile, password)
	fmt.Println("Priv from keystore equals original?", priv.D.Cmp(priv2.D) == 0)

	// 3) 连接节点，查询余额
	client, err := ethclient.DialContext(ctx, RPC_URL)
	must(err)
	defer client.Close()
	bal := getBalance(ctx, client, addr)
	fmt.Printf("Balance(%s): %s wei\n", addr.Hex(), bal.String())

	// 4) 发送一笔转账（演示金额很小，需保证账户在测试网有余额）
	to := common.HexToAddress(TO_ADDRESS_HEX)
	amount := big.NewInt(1_000_000_000_000_000) // 0.001 ETH（单位 wei）
	// 注：确保该地址在 RPC 所指网络（如 Sepolia）上有测试币，否则会报 insufficient funds
	_ = to
	_ = amount
	// txHash := sendTxEIP1559(ctx, client, priv, to, amount)
	// fmt.Println("Tx sent:", txHash.Hex())

	// 5) 订阅新出块并打印区块内交易（阻塞运行）
	// 注：如不想阻塞，可放到 goroutine 中。
	// subscribeNewBlocksAndPrintTxs(ctx, client)
	_ = ksDir // 占位避免未使用报错（若注释掉订阅/转账）
}
