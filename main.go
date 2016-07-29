package main

import (
    "fmt"
    "os"

    "github.com/codegangsta/cli"
)

func main() {
    app := cli.NewApp()
    app.Name = "tracve"
    app.Usage = "tracking security advisory based on the CVE number."
    app.Version = "0.0.1"

    app.Commands = []cli.Command{
        {
            Name:    "add",
            Aliases: []string{"h"},
            Usage:   "Add the CVE information in the database",
            Action:  addAction,
        },
    }

    app.Run(os.Args)
}


func addAction(ctx *cli.Context) error {
	var cve_num = ""

	if len(ctx.Args()) > 0 {
		cve_num = ctx.Args().First() 
	}

	fmt.Printf("add %s to the databse\n", cve_num)
        return nil
}

