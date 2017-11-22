package commands

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/naoina/toml"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/tendermint/go-wire/data"
	tcmd "github.com/tendermint/tendermint/cmd/tendermint/commands"
	"github.com/tendermint/tendermint/config"
	"github.com/tendermint/tendermint/types"
	cmn "github.com/tendermint/tmlibs/common"
)

var (
	// InitCmd - node initialization command
	InitCmd    = GetInitCmd("mycoin", []string{})
	InitNetCmd = GetInitCmd("mycoin", []string{})
	//nolint - flags
	FlagChainID = "chain-id" //TODO group with other flags or remove? is this already a flag here?
	FlagDenom   = "denom"    //TODO group with other flags or remove? is this already a flag here?
	FlagOption  = "option"
	FlagStatic  = "static"
	FlagNodes   = "nodes"
	FlagVals    = "vals"
)

type ConfigToml struct {
	Proxy_app, Moniker    string
	Fast_sync             bool
	Db_backend, Log_level string
	Rpc                   Rpc
	P2p                   P2p
}

type Rpc struct {
	Laddr string
}

type P2p struct {
	Laddr string
	Seeds string
}

type GenDoc struct {
	GenTime         time.Time              `json:"genesis_time"`
	ChainID         string                 `json:"chain_id"`
	ConsensusParams *types.ConsensusParams `json:"consensus_params,omitempty"`
	Validators      []GenVal               `json:"validators"`
	AppHash         data.Bytes             `json:"app_hash"`
	AppOptions      map[string]interface{} `json:"app_options,omitempty"`
}

type GenVal struct {
	PubKey string `json:"pub_key"`
	Power  int64  `json:"power"`
	Name   string `json:"name"`
}

// GetInitCmd - get the node initialization command, with a custom genesis account denom
func GetInitCmd(defaultDenom string, options []string) *cobra.Command {
	initCmd := &cobra.Command{
		Use:   "init [address]",
		Short: "Initialize genesis files for a blockchain",
		RunE:  initCmd,
	}
	initCmd.Flags().String(FlagChainID, "test_chain_id", "Chain ID")
	initCmd.Flags().String(FlagDenom, defaultDenom, "Coin denomination for genesis account")
	initCmd.Flags().StringSliceP(FlagOption, "p", options, "Genesis option in the format <app>/<option>/<value>")
	initCmd.Flags().Bool(FlagStatic, false, "use a static private validator")
	return initCmd
}

func GetInitNetCmd(defaultDenom string, options []string) *cobra.Command {
	initNetCmd := &cobra.Command{
		Use:   "initNet [address]",
		Short: "Initialize genesis files for a blockchain",
		RunE:  initNetCmd,
	}
	initNetCmd.Flags().String(FlagNodes, "nodes", "Total number of nodes")
	initNetCmd.Flags().String(FlagVals, "vals", "Number of validator nodes")
	initNetCmd.Flags().String(FlagChainID, "test_chain_id", "Chain ID")
	initNetCmd.Flags().String(FlagDenom, defaultDenom, "Coin denomination for genesis account")
	initNetCmd.Flags().StringSliceP(FlagOption, "p", options, "Genesis option in the format <app>/<option>/<value>")
	initNetCmd.Flags().Bool(FlagStatic, false, "use a static private validator")
	return initNetCmd
}

// returns 1 iff it set a file, otherwise 0 (so we can add them)
func setupFile(path, data string, perm os.FileMode) (int, error) {
	_, err := os.Stat(path)
	if !os.IsNotExist(err) { //note, os.IsExist(err) != !os.IsNotExist(err)
		return 0, nil
	}
	err = ioutil.WriteFile(path, []byte(data), perm)
	if err != nil {
		return 0, err
	}
	return 1, nil
}

func initCmd(cmd *cobra.Command, args []string) error {
	// this will ensure that config.toml is there if not yet created, and create dir
	cfg, err := tcmd.ParseConfig()
	if err != nil {
		return err
	}

	if len(args) != 1 {
		return fmt.Errorf("`init` takes one argument, a basecoin account address. Generate one using `basecli keys new mykey`")
	}
	userAddr := args[0]
	// verify this account is correct
	data, err := hex.DecodeString(cmn.StripHex(userAddr))
	if err != nil {
		return errors.Wrap(err, "Invalid address")
	}
	if len(data) != 20 {
		return errors.New("Address must be 20-bytes in hex")
	}

	var optionsStr string
	optionsRaw := viper.GetStringSlice(FlagOption)
	if len(optionsRaw) > 0 {

		var options []string
		sep := ",\n      "

		for i := 0; i < len(optionsRaw); i++ {
			s := strings.SplitN(optionsRaw[i], "/", 3)
			if len(s) != 3 {
				return errors.New("Genesis option must be in the format <app>/<option>/<value>")
			}

			//Add quotes if the value (s[2]) is not json
			if !strings.Contains(s[2], "\"") {
				s[2] = `"` + s[2] + `"`
			}

			option := `"` + s[0] + `/` + s[1] + `", ` + s[2]
			options = append(options, option)
		}
		optionsStr = sep + strings.Join(options[:], sep)
	}

	var privValJSON, pubkey string
	if viper.GetBool(FlagStatic) {
		privValJSON = StaticPrivValJSON
		pubkey = StaticPK
	} else {

		privVal := types.GenPrivValidatorFS("")
		pubkey = strings.ToUpper(hex.EncodeToString(privVal.PubKey.Bytes()[1:]))
		pvBytes, err := json.Marshal(privVal)
		if err != nil {
			return err
		}
		privValJSON = string(pvBytes)
	}

	genesis := GetGenesisJSON(pubkey, viper.GetString(FlagChainID), viper.GetString(FlagDenom),
		userAddr, optionsStr)
	return CreateGenesisValidatorFiles(cfg, genesis, privValJSON, cmd.Root().Name())
}

func initNetCmd(cmd *cobra.Command, args []string) error {
	laddr := "tcp://0.0.0.0:"
	rpc := 46007
	p2p := 46008

	seedLaddr := p2p

	nodes, err := strconv.Atoi(FlagNodes)
	if err != nil {
		return err
	}
	vals, err := strconv.Atoi(FlagVals)
	if err != nil {
		return err
	}

	var seeds string
	var genFilepaths []string
	var privValBytes []byte

	var genParams GenDoc

	if len(args) != 1 {
		return fmt.Errorf("`init` takes one argument, an account address. Generate one using `gaiacli keys new mykey`")
	}
	userAddr := args[0]
	// verify this account is correct
	data, err := hex.DecodeString(cmn.StripHex(userAddr))
	if err != nil {
		return errors.Wrap(err, "Invalid address")
	}
	if len(data) != 20 {
		return errors.New("Address must be 20-bytes in hex")
	}

	var optionsStr string
	optionsRaw := viper.GetStringSlice(FlagOption)
	if len(optionsRaw) > 0 {

		var options []string
		sep := ",\n      "

		for i := 0; i < len(optionsRaw); i++ {
			s := strings.SplitN(optionsRaw[i], "/", 3)
			if len(s) != 3 {
				return errors.New("Genesis option must be in the format <app>/<option>/<value>")
			}

			//Add quotes if the value (s[2]) is not json
			if !strings.Contains(s[2], "\"") {
				s[2] = `"` + s[2] + `"`
			}

			option := `"` + s[0] + `/` + s[1] + `", ` + s[2]
			options = append(options, option)
		}
		optionsStr = sep + strings.Join(options[:], sep)
	}

	for i := 0; i < nodes; i++ {
		//add seeds
		seeds = seeds + ("0.0.0.0:" + strconv.Itoa(seedLaddr))
		//seperate
		if i < nodes-1 {
			seeds = seeds + ","
		}

		seedLaddr += 10
	}

	cfg := ConfigToml{
		Proxy_app:  "tcp://127.0.0.1:46658",
		Moniker:    "__MONIKER__",
		Fast_sync:  true,
		Db_backend: "leveldb",
		Log_level:  "state:info,*:error",
	}

	for i := 0; i < nodes; i++ {

		dir := "$HOME/.node" + strconv.Itoa(i) + "/"

		err := os.MkdirAll(dir, 0777)
		if err != nil {
			return err
		}

		configFile := dir + "config.toml"
		genesisFile := dir + "genesis.json"
		privValFile := dir + "priv_validator.json"

		genFilepaths = append(genFilepaths, genesisFile)

		for i := 0; i < nodes; i++ {
			//add seeds
			seeds = seeds + ("0.0.0.0:" + strconv.Itoa(seedLaddr))
			//seperate
			if i < nodes-1 {
				seeds = seeds + ","
			}

			seedLaddr += 10
		}

		cfg.Rpc.Laddr = laddr + strconv.Itoa(rpc)
		cfg.P2p.Laddr = laddr + strconv.Itoa(rpc)
		cfg.P2p.Seeds = seeds

		tomlBytes, err := toml.Marshal(cfg)
		if err != nil {
			return err
		}

		ioutil.WriteFile(configFile, tomlBytes, 0777)

		var pubkey string
		if viper.GetBool(FlagStatic) {
			pubkey = StaticPK
		} else {

			privVal := types.GenPrivValidatorFS("")
			pubkey = strings.ToUpper(hex.EncodeToString(privVal.PubKey.Bytes()[1:]))
			privValBytes, err = json.Marshal(privVal)
			if err != nil {
				return err
			}
		}

		ioutil.WriteFile(privValFile, privValBytes, 0777)

		//add correct number of nodes as vals to genesis
		if i < vals {
			//add node to genesis doc struct
			genVal := GenVal{pubkey, 10, ""}
			genParams.Validators = append(genParams.Validators, genVal)
		}

		// increment rpc and p2p for varied addresses
		rpc += 10
		p2p += 10
	}

	//set parameters and write genesis file in each node's directory
	genParams.ChainID = FlagChainID

	appOptionsJson := []byte(fmt.Sprintf(`{
		"app_options": {
    "accounts": [{
      "address": "%s",
      "coins": [
        {
          "denom": "%s",
          "amount": 9007199254740992
        }
      ]
    }],
    "plugin_options": [
      "coin/issuer", {"app": "sigs", "addr": "%s"}%s
    ]
  }
	}`, userAddr, viper.GetString(FlagDenom), userAddr, optionsStr))

	json.Unmarshal(appOptionsJson, genParams.AppOptions)

	genesisBytes, err := json.Marshal(genParams)
	if err != nil {
		return err
	}

	for _, genesisFile := range genFilepaths {
		ioutil.WriteFile(genesisFile, genesisBytes, 0777)
	}

	return err
}

// StaticPK - static public key for test cases
var StaticPK = "7B90EA87E7DC0C7145C8C48C08992BE271C7234134343E8A8E8008E617DE7B30"

// StaticPrivValJSON - static validator private key file contents in json
var StaticPrivValJSON = `{
  "address": "7A956FADD20D3A5B2375042B2959F8AB172A058F",
  "last_height": 0,
  "last_round": 0,
  "last_signature": null,
  "last_signbytes": "",
  "last_step": 0,
  "priv_key": {
    "type": "ed25519",
    "data": "D07ABE82A8B15559A983B2DB5D4842B2B6E4D6AF58B080005662F424F17D68C17B90EA87E7DC0C7145C8C48C08992BE271C7234134343E8A8E8008E617DE7B30"
  },
  "pub_key": {
    "type": "ed25519",
    "data": "7B90EA87E7DC0C7145C8C48C08992BE271C7234134343E8A8E8008E617DE7B30"
  }
}`

// CreateGenesisValidatorFiles creates a genesis file with these
// contents and a private validator file
func CreateGenesisValidatorFiles(cfg *config.Config, genesis, privVal, appName string) error {
	privValFile := cfg.PrivValidatorFile()
	genesisFile := cfg.GenesisFile()

	mod1, err := setupFile(genesisFile, genesis, 0644)
	if err != nil {
		return err
	}
	mod2, err := setupFile(privValFile, privVal, 0400)
	if err != nil {
		return err
	}

	if (mod1 + mod2) > 0 {
		msg := fmt.Sprintf("Initialized %s", appName)
		logger.Info(msg, "genesis", genesisFile, "priv_validator", privValFile)
	} else {
		logger.Info("Already initialized", "priv_validator", privValFile)
	}

	return nil
}

// GetGenesisJSON returns a new tendermint genesis with Basecoin app_options
// that grant a large amount of "mycoin" to a single address
// TODO: A better UX for generating genesis files
func GetGenesisJSON(pubkey, chainID, denom, addr string, options string) string {
	return fmt.Sprintf(`{
  "app_hash": "",
  "chain_id": "%s",
  "genesis_time": "0001-01-01T00:00:00.000Z",
  "validators": [
    {
      "power": 10,
      "name": "",
      "pub_key": {
        "type": "ed25519",
        "data": "%s"
      }
    }
  ],
  "app_options": {
    "accounts": [{
      "address": "%s",
      "coins": [
        {
          "denom": "%s",
          "amount": 9007199254740992
        }
      ]
    }],
    "plugin_options": [
      "coin/issuer", {"app": "sigs", "addr": "%s"}%s
    ]
  }
}`, chainID, pubkey, addr, denom, addr, options)
}
