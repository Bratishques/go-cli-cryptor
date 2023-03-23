/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"bufio"
	"cli-cryptor/cryptor"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

type Direction string

const (
	DECRYPT Direction = "decrypt"
	ENCRYPT Direction = "encrypt"
)

type InitData struct {
	Id        string    `json:"id"`
	Direction Direction `json:"direction"`
	Data      []string  `json:"data"`
}

type OutputData struct {
	Id     string   `json:"id"`
	Result []string `json:"result"`
}

var Secret string

// cryptorCmd represents the cryptor command
var cryptorCmd = &cobra.Command{
	Use:   "cryptor",
	Short: "Encrypt/decrypt the input",
	Run: func(cmd *cobra.Command, _args []string) {
		condition := true
		for ok := true; ok; ok = condition {
			reader := bufio.NewReader(os.Stdin)
			text, _ := reader.ReadString('\n')
			res := InitData{}
			json.Unmarshal([]byte(text), &res)
			openSSLInst := cryptor.New()
			credsGen := cryptor.BytesToKeyMD5
			sEnc := base64.StdEncoding
			var result []string
			for _, s := range res.Data {
				if res.Direction == DECRYPT {
					decStr, _ := sEnc.DecodeString(s)
					dec, _ := openSSLInst.DecryptBinaryBytes(
						Secret,
						decStr,
						credsGen,
					)
					result = append(result, string(dec))

				}
				if res.Direction == ENCRYPT {
					enc, _ := openSSLInst.EncryptBinaryBytes(
						Secret,
						[]byte(s),
						credsGen,
					)
					result = append(result, sEnc.EncodeToString(enc))
				}
			}
			output := OutputData{
				Id:     res.Id,
				Result: result,
			}
			stringOutput, _ := json.Marshal(output)
			fmt.Println(string(stringOutput))
		}
	},
}

func init() {
	rootCmd.AddCommand(cryptorCmd)
	cryptorCmd.Flags().StringVarP(&Secret, "secret", "s", "", "Your passphrase")
	cryptorCmd.MarkFlagRequired("secret")

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// cryptorCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// cryptorCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
