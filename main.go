package main

import (
	"errors"
	"github.com/idena-lab/relay-tools/contract"
	"github.com/urfave/cli"
	"os"
	"strings"
)

const (
	dataTypeFlag = "t"
	outFileFlag  = "f"
)

func main() {
	app := cli.NewApp()
	app.Name = "relay-tools"
	app.Usage = "Tools for idena ethereum relay"
	app.Commands = []cli.Command{
		{
			Name:    "generate-test",
			Aliases: []string{"gt"},
			Usage:   "Generate data for test",
			Action: generateTestData,
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:        dataTypeFlag,
					Usage:       "Supported data types are: verify, state",
					Value:       "verify",
				},
				cli.StringFlag{
					Name:     outFileFlag,
					Usage:    "File to write the data (default: ${DataType}.json)",
					Value:    "",
				},
			},
		},
	}
	err := app.Run(os.Args)
	if err != nil {
		panic(err)
	}
}

func generateTestData(c *cli.Context) error {
	dt := strings.ToLower(c.String(dataTypeFlag))
	filename := c.String(outFileFlag)
	if filename == "" {
		filename = dt + ".json"
	}
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	switch dt {
	case "verify":
		contract.GenTestsForVerify(f)
	case "state":
		contract.GenTestsForStateChanges(f)
	default:
		return errors.New("unknown data type")
	}
	return nil
}