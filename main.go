package main

import (
    "fmt"
    "os"
    "log"
    "database/sql"
    "github.com/codegangsta/cli"
    _ "github.com/mattn/go-sqlite3"
    "regexp"
    "net/http"
    "io/ioutil"
    "crypto/sha256"
)

const SQLITE_FILE = "cve_watch.db?cache=shared&mode=rwc"

func main() {
    app := cli.NewApp()
    app.Name = "cve_watch"
    app.Usage = "watch security advisory based on the CVE number."
    app.Version = "0.0.1"

    app.Commands = []cli.Command{
        {
            Name:    "add",
            Aliases: []string{"h"},
            Usage:   "Add the CVE number in to the database",
            Action:  addAction,
        },
        {
            Name:    "del",
            Aliases: []string{"h"},
            Usage:   "Delete the CVE number related data",
            Action:  delAction,
        },
        {
            Name:    "list",
            Usage:   "list CVE number in the database",
            Action:  listAction,
        },
        {
            Name:    "check",
            Usage:   "check to the security advaisory",
            Action:  checkAction,
        },
    }

    app.Run(os.Args)
}


func db_init(db *sql.DB) error {
    sqlStmt := `
    PRAGMA foreign_keys = ON;

    create table if not exists cve (
        number TEXT null primary key, 
        created_at DEFAULT (DATETIME('now','localtime'))
    );

    create table if not exists watch (
        url text, 
        hash text, 
        cve_number text,
        last_update DEFAULT (DATETIME('now','localtime')),
        FOREIGN KEY(cve_number) REFERENCES cve(number) ON DELETE CASCADE
    );
    `
    _, err := db.Exec(sqlStmt)
    if err != nil {
        log.Printf("%q: %s\n", err, sqlStmt)
        return nil
    }
    return nil
}

func get_hash(html_raw string) string {
    re, _ := regexp.Compile("\\(?i)<script[\\S\\s]+?\\</script\\>")
    html_raw = re.ReplaceAllString(html_raw, "")
    return fmt.Sprintf("%x", sha256.Sum256([]byte(replaced)))
}

func addAction(ctx *cli.Context) error {
	var cve_number = ""

	if len(ctx.Args()) > 0 {
		cve_number = ctx.Args().First() 
	}

        db, err := sql.Open("sqlite3", SQLITE_FILE)
        if err != nil {
            log.Fatal(err)
        }
        defer db.Close()

        db_init(db)

        r := regexp.MustCompile(`(?i)cve-\d+?-\d+?`)

        if r.MatchString(cve_number) == false {
		log.Printf("validation error of cve number\n")
                return nil
        }

	rows, err := db.Query("select number, created_at from cve where number = ?", cve_number)
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()

        if rows.Next() == true {
		log.Printf("Already regist cve number %s\n", cve_number )
		return nil
        }

	err = rows.Err()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Add %s in to the databse\n", cve_number)

        sqlStmt := `
        insert into cve(number) values(?);
        `
	_, err = db.Exec(sqlStmt, cve_number)
	if err != nil {
		log.Printf("%q: %s\n", err, sqlStmt)
		return nil
	}

        watch_url := []string{
            "https://access.redhat.com/security/cve/" + cve_number,
            "https://security-tracker.debian.org/tracker/" + cve_number,
            "https://people.canonical.com/~ubuntu-security/cve/" + cve_number + ".html",
        }

        for _, url := range watch_url{
            resp, err := http.Get(url)
            if err != nil {
		log.Printf("%s\n", err)
		return nil
            }
            defer resp.Body.Close()
            html_raw, _ := ioutil.ReadAll(resp.Body)

            hash := get_hash(html_raw)

            sqlStmt = `
            insert into watch(url, hash, cve_number) values(?, ?, ?);
            `
            _, err = db.Exec(sqlStmt, url, hash, cve_number)
            if err != nil {
                log.Printf("%q: %s\n", err, sqlStmt)
                return nil
            }
        }

        return nil
}

func delAction(ctx *cli.Context) error {
	var cve_number = ""

	if len(ctx.Args()) > 0 {
		cve_number = ctx.Args().First() 
	}

        db, err := sql.Open("sqlite3", SQLITE_FILE)
        if err != nil {
            log.Fatal(err)
        }
        defer db.Close()

        db_init(db)

        r := regexp.MustCompile(`(?i)cve-\d+?-\d+?`)

        if r.MatchString(cve_number) == false {
		log.Printf("validation error of cve number\n")
                return nil
        }

	fmt.Printf("Delete %s related data\n", cve_number)

        sqlStmt := `
        delete from cve where number = ?;
        `
	_, err = db.Exec(sqlStmt, cve_number)
	if err != nil {
		log.Printf("%q: %s\n", err, sqlStmt)
		return nil
	}

        return nil
}

func listAction(ctx *cli.Context) error {
        db, err := sql.Open("sqlite3", SQLITE_FILE)
        if err != nil {
            log.Fatal(err)
        }
        defer db.Close()

        db_init(db)

	rows, err := db.Query("select number, created_at from cve")
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()

        fmt.Printf("CVE_NUMBER\tCREATED_AT\n")

	for rows.Next() {
		var cve_number string
		var created_at string
		err = rows.Scan(&cve_number, &created_at)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%s\t%s\n" , cve_number, created_at)

	}
	err = rows.Err()
	if err != nil {
		log.Fatal(err)
	}

        return nil
}

func checkAction(ctx *cli.Context) error {
        db, err := sql.Open("sqlite3", SQLITE_FILE)
        if err != nil {
            log.Fatal(err)
        }
        defer db.Close()

        db_init(db)

	rows, err := db.Query("select url, hash from watch")
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()

        for rows.Next() {
            var url string
            var saved_hash string
            err = rows.Scan(&url, &saved_hash)
            if err != nil {
                log.Fatal(err)
            }

            resp, err := http.Get(url)
            if err != nil {
                log.Printf("%s\n", err)
                return nil
            }
            defer resp.Body.Close()
            html_raw, _ := ioutil.ReadAll(resp.Body)
            new_hash := get_hash(html_raw)
            fmt.Printf("SAVE %s\n", saved_hash)
            fmt.Printf("NEW  %s\n", new_hash)
       }

	err = rows.Err()
	if err != nil {
		log.Fatal(err)
	}

        return nil
}

