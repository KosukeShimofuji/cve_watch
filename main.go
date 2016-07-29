package main

import (
    "fmt"
    "os"
    "log"
    "database/sql"
    "github.com/codegangsta/cli"
    _ "github.com/mattn/go-sqlite3"
)

const SQLITE_FILE = "tracve.db"

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

        db, err := sql.Open("sqlite3", SQLITE_FILE)
        if err != nil {
            log.Fatal(err)
        }
        defer db.Close()

	sqlStmt := `
	create table cve (number TEXT null primary key, created_at DEFAULT (DATETIME('now','localtime')));
        `

	_, err = db.Exec(sqlStmt)
	if err != nil {
		log.Printf("%q: %s\n", err, sqlStmt)
		return nil
	}

	fmt.Printf("add %s to the databse\n", cve_num)
        return nil
}


