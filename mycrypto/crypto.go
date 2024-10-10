package mycrypto

import (
	"crypto/ecdsa"
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
)

// SDK 结构体
type SDK struct {
	privateKey *ecdsa.PrivateKey
	client     *ethclient.Client
	contract   *bind.BoundContract
}

// NewSDK 创建一个新的SDK实例
func NewSDK(privateKeyHex, rpcURL, contractAddressHex, contractABI string) (*SDK, error) {
	// 解析私钥
	privateKey, err := crypto.HexToECDSA(privateKeyHex)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %v", err)
	}

	// 创建以太坊客户端
	client, err := ethclient.Dial(rpcURL)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to the Ethereum client: %v", err)
	}

	// 解析合约ABI
	parsedABI, err := abi.JSON(strings.NewReader(contractABI))
	if err != nil {
		return nil, fmt.Errorf("failed to parse contract ABI: %v", err)
	}

	// 创建合约实例
	contractAddress := common.HexToAddress(contractAddressHex)
	contract := bind.NewBoundContract(contractAddress, parsedABI, client, client, client)

	return &SDK{
		privateKey: privateKey,
		client:     client,
		contract:   contract,
	}, nil
}

// GetAddress 获取签名者地址
func (sdk *SDK) GetAddress() common.Address {
	publicKey := sdk.privateKey.Public().(*ecdsa.PublicKey)
	return crypto.PubkeyToAddress(*publicKey)
}

// Sign 根据输入内容获取签名结果
func (sdk *SDK) Sign(data string) ([]byte, error) {
	hash := crypto.Keccak256Hash([]byte(data))
	signature, err := crypto.Sign(hash.Bytes(), sdk.privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign data: %v", err)
	}
	return signature, nil
}

// Verify 调用链上合约验证签名
func (sdk *SDK) Verify(data string, signature []byte) (bool, error) {
	signer := sdk.GetAddress()
	var result bool
	err := sdk.contract.Call(&bind.CallOpts{}, &[]interface{}{&result}, "verifySignature", signer, data, signature)
	if err != nil {
		return false, fmt.Errorf("failed to call contract: %v", err)
	}
	return result, nil
}
