package main

import (
	"fmt"
	"log"
	"mycrypto"
)

package main

import (
"fmt"
"log"
"mycrypto"
)

const (
	privateKeyHex      = "0c1c14c3267ce0e99a29017f79c2daadee765fdc654244b3147f68c00f17d5af" // 用你的私钥替换这里
	rpcURL             = "https://data-seed-prebsc-1-s1.bnbchain.org:8545"
	contractAddressHex = "0x7eE7291A2BB1FA120F48bDE6E3fFBa0de9C5909B"
	contractABI        = 	 "[\n\t{\n\t\t\"inputs\": [\n\t\t\t{\n\t\t\t\t\"internalType\": \"address\",\n\t\t\t\t\"name\": \"signer\",\n\t\t\t\t\"type\": \"address\"\n\t\t\t},\n\t\t\t{\n\t\t\t\t\"internalType\": \"string\",\n\t\t\t\t\"name\": \"data\",\n\t\t\t\t\"type\": \"string\"\n\t\t\t},\n\t\t\t{\n\t\t\t\t\"internalType\": \"bytes\",\n\t\t\t\t\"name\": \"signature\",\n\t\t\t\t\"type\": \"bytes\"\n\t\t\t}\n\t\t],\n\t\t\"name\": \"verifySignature\",\n\t\t\"outputs\": [\n\t\t\t{\n\t\t\t\t\"internalType\": \"bool\",\n\t\t\t\t\"name\": \"\",\n\t\t\t\t\"type\": \"bool\"\n\t\t\t}\n\t\t],\n\t\t\"stateMutability\": \"pure\",\n\t\t\"type\": \"function\"\n\t}\n]"

)

func main() {
	// 创建SDK实例
	sdk, err := mycrypto.NewSDK(privateKeyHex, rpcURL, contractAddressHex, contractABI)
	if err != nil {
		log.Fatalf("Failed to create SDK: %v", err)
	}

	// 签名数据
	data := "Hello, world!"
	signature, err := sdk.Sign(data)
	if err != nil {
		log.Fatalf("Failed to sign data: %v", err)
	}
	fmt.Printf("Signature: %x\n", signature)

	// 验证签名
	valid, err := sdk.Verify(data, signature)
	if err != nil {
		log.Fatalf("Failed to verify signature: %v", err)
	}
	fmt.Printf("Signature valid: %v\n", valid)
}
