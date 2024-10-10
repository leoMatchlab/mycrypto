package main

import (
	"crypto/ecdsa"
	"fmt"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"log"
	"strings"
)

// 私钥
const privateKeyHex = "0c1c14c3267ce0e99a29017f79c2daadee765fdc654244b3147f68c00f17d5af" // 用你的私钥替换这里

// 获取签名者地址
func getAddr() common.Address {
	// 解析私钥
	privateKey, err := crypto.HexToECDSA(privateKeyHex)
	if err != nil {
		log.Fatalf("Failed to parse private key: %v", err)
	}

	// 获取签名者地址
	publicKey := privateKey.Public().(*ecdsa.PublicKey)
	signerAddress := crypto.PubkeyToAddress(*publicKey)
	return signerAddress
}

// 根据输入内容获取签名结果
func sign(data string) []byte {
	// 要签名的数据
	sign_data := []byte(data)

	// 对数据进行哈希处理
	hash := crypto.Keccak256Hash(sign_data)

	// 将私钥解析为ecdsa私钥
	privateKey, err := crypto.HexToECDSA(privateKeyHex)
	if err != nil {
		log.Fatal(err)
	}

	// 对哈希值进行签名
	signature, err := crypto.Sign(hash.Bytes(), privateKey)
	if err != nil {
		log.Fatal(err)
	}

	// 打印签名结果
	fmt.Printf("Signature: %x\n", signature)
	return signature
}

// 调用链上合约验证签名，合约部署在BSC Testnet，地址为0x7eE7291A2BB1FA120F48bDE6E3fFBa0de9C5909B
func verify(data string, signature []byte) bool {
	client, err := ethclient.Dial("https://data-seed-prebsc-1-s1.bnbchain.org:8545")
	if err != nil {
		log.Fatalf("Failed to connect to the Ethereum client: %v", err)
	}
	signer := getAddr()
	contractAddress := common.HexToAddress("0x7eE7291A2BB1FA120F48bDE6E3fFBa0de9C5909B")

	contractABI := "[\n\t{\n\t\t\"inputs\": [\n\t\t\t{\n\t\t\t\t\"internalType\": \"address\",\n\t\t\t\t\"name\": \"signer\",\n\t\t\t\t\"type\": \"address\"\n\t\t\t},\n\t\t\t{\n\t\t\t\t\"internalType\": \"string\",\n\t\t\t\t\"name\": \"data\",\n\t\t\t\t\"type\": \"string\"\n\t\t\t},\n\t\t\t{\n\t\t\t\t\"internalType\": \"bytes\",\n\t\t\t\t\"name\": \"signature\",\n\t\t\t\t\"type\": \"bytes\"\n\t\t\t}\n\t\t],\n\t\t\"name\": \"verifySignature\",\n\t\t\"outputs\": [\n\t\t\t{\n\t\t\t\t\"internalType\": \"bool\",\n\t\t\t\t\"name\": \"\",\n\t\t\t\t\"type\": \"bool\"\n\t\t\t}\n\t\t],\n\t\t\"stateMutability\": \"pure\",\n\t\t\"type\": \"function\"\n\t}\n]"
	parsedABI, err := abi.JSON(strings.NewReader(contractABI))
	if err != nil {
		log.Fatalf("Failed to parse contract ABI: %v", err)
	}
	contract := bind.NewBoundContract(contractAddress, parsedABI, client, client, client)

	var result bool
	err = contract.Call(&bind.CallOpts{}, &[]interface{}{&result}, "verifySignature", signer, data, signature)
	if err != nil {
		log.Fatalf("Failed to call contract: %v", err)
	}
	// 打印验证结果
	fmt.Printf("Signature valid: %v\n", result)
	return result
}

// 测试
func main() {
	data := "Hello, World!"
	signatureResult := sign(data)
	verify(data, signatureResult)
}
