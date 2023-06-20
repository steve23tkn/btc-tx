package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"unsafe"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

func main() {
	rawTx, err := CreateTx("076ab82598abe70812f3f2f9538a0c110be578d629e0d678d943c0b10e967691", "tb1qn3jp58hky8myswynwwz9m4nslrduyv2ketzfs8", 6000)

	if err != nil {
		fmt.Println(err)
	}

	fmt.Println(rawTx)
}

func NewTx() (*wire.MsgTx, error) {
	return wire.NewMsgTx(wire.TxVersion), nil
}

func GetUTXO(address string) (string, int64, string, error) {
	var previousTxId string = "72b04869e700e5f30867150105167359a73486e4f7b6fa80630b0dda55000d6d"
	var balance int64 = 6000000
	var pubKeyScript string = "0014e9e1f5225e7f7c7664962d7f5cb730146f5f28a3"
	return previousTxId, balance, pubKeyScript, nil
}

func CreateTx(hexKey string, destination string, amount int64) (string, error) {

	privKeyBytes, err := hex.DecodeString(hexKey)
	if err != nil {
		return "", err
	}

	wif, err := btcutil.NewWIF((*btcec.PrivateKey)(unsafe.Pointer(&privKeyBytes)), &chaincfg.TestNet3Params, true)
	if err != nil {
		return "", err
	}

	addressPubKey, err := btcutil.NewAddressPubKey(wif.PrivKey.PubKey().SerializeUncompressed(), &chaincfg.TestNet3Params)
	if err != nil {
		return "", err
	}

	previousTxId, balance, pkScript, err := GetUTXO(addressPubKey.EncodeAddress())
	if err != nil {
		return "", err
	}

	if balance < amount {
		return "", fmt.Errorf("balance is not enough")
	}

	destinationAddress, err := btcutil.DecodeAddress(destination, &chaincfg.TestNet3Params)
	if err != nil {
		return "", err
	}

	destinationAddrByte, err := txscript.PayToAddrScript(destinationAddress)
	if err != nil {
		return "", err
	}

	//---------------------------------- construct redeemTx ----------------------------------

	redeemTx, err := NewTx()
	if err != nil {
		return "", err
	}

	utxoHash, err := chainhash.NewHashFromStr(previousTxId)
	if err != nil {
		return "", err
	}

	outPoint := wire.NewOutPoint(utxoHash, 1)
	txIn := wire.NewTxIn(outPoint, nil, nil)
	redeemTx.AddTxIn(txIn)

	redeemTxOut := wire.NewTxOut(amount, destinationAddrByte) // (amount, destinationAddrByte)
	redeemTx.AddTxOut(redeemTxOut)

	finalRawTx, err := SignTx(wif.String(), pkScript, redeemTx)
	if err != nil {
		return "", err
	}
	return finalRawTx, nil
}

func SignTx(privKey string, pkScript string, redeemTx *wire.MsgTx) (string, error) {
	wif, err := btcutil.DecodeWIF(privKey)
	if err != nil {
		return "", err
	}

	sourcePkScript, err := hex.DecodeString(pkScript)
	if err != nil {
		return "", err
	}

	signature, err := txscript.SignatureScript(redeemTx, 0, sourcePkScript, txscript.SigHashAll, wif.PrivKey, false)
	if err != nil {
		return "", err
	}

	redeemTx.TxIn[0].SignatureScript = signature

	var signedTx bytes.Buffer
	redeemTx.Serialize(&signedTx)
	hexSignedTx := hex.EncodeToString(signedTx.Bytes())
	return hexSignedTx, nil
}
