package main

import(
    "fmt"
    "os"
    "log"
    "strings"
    "github.com/codegangsta/cli"
    "database/sql"
    _ "github.com/mattn/go-sqlite3"
    "net/http"
    "io/ioutil"
    "regexp"
    "crypto/sha256"
)

const SQLITE_FILE = "cve_watch.db"

func main(){
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
    }

    return nil
}

func check_sites(cve_number string) map[string]string {

    watch_list := []string{
        "https://access.redhat.com/security/cve/" + cve_number,
        "https://security-tracker.debian.org/tracker/" + cve_number,
        "https://people.canonical.com/~ubuntu-security/cve/" + cve_number + ".html",
    }

    result := make(map[string]string)

    for _, url := range watch_list{
        resp, _ := http.Get(url)
        defer resp.Body.Close()
        byteArray, _ := ioutil.ReadAll(resp.Body)
        html := string(byteArray)

        // all of the tags to lowercase
        re, _ := regexp.Compile(`\<[\S\s]+?\>`)
        html = re.ReplaceAllStringFunc(html, strings.ToLower)

        // delete script tags
        re, _ = regexp.Compile(`\<script[\S\s]+?\</script\>`)
        html = re.ReplaceAllString(html, "")

        // delete comment tags
        re, _ = regexp.Compile(`\<\!-\-[\s\S]*?\-\-\>`)
        html = re.ReplaceAllString(html, "")

        // generate hash
        hash :=  fmt.Sprintf("%x", sha256.Sum256([]byte(html)))

        // save hash
        result[url] = hash
    }

    return result
}

func addAction(ctx *cli.Context) error {
    var cve_number = ""

    // option parser
    if len(ctx.Args()) > 0 {
        cve_number = ctx.Args().First() 
    }

    // option validation
    r := regexp.MustCompile(`(?i)cve-\d+?-\d+?`)

    if r.MatchString(cve_number) == false {
        log.Printf("validation error of cve number\n")
        return nil
    }

    // initialize database
    db, err := sql.Open("sqlite3", SQLITE_FILE)
    if err != nil {
        log.Fatal(err)
    }
    defer db.Close()
    db_init(db)

    // check duplicate record 
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

    // insert cve record
    sql := `
    insert into cve(number) values(?);
    `
    _, err = db.Exec(sql, cve_number)

    if err != nil {
        log.Printf("%q: %s\n", err, sql)
        return nil
    }

    // check target site
    result := check_sites(cve_number)

    // insert watch record
    sql = `
    insert into watch(url, hash, cve_number) values (?, ?, ?);
    `
    for key, val := range result{
        _, err = db.Exec(sql, key, val, cve_number)
        if err != nil {
            log.Printf("%q: %s\n", err, sql)
            return nil
        }
    }

    return nil
}

func delAction(ctx *cli.Context) error {
    var cve_number = ""

    // option parser
    if len(ctx.Args()) > 0 {
        cve_number = ctx.Args().First() 
    }

    // option validation
    r := regexp.MustCompile(`(?i)cve-\d+?-\d+?`)

    if r.MatchString(cve_number) == false {
        log.Printf("validation error of cve number\n")
        return nil
    }

    // initialize database
    db, err := sql.Open("sqlite3", SQLITE_FILE)
    if err != nil {
        log.Fatal(err)
    }
    defer db.Close()
    db_init(db)

    // delete record
    sql := `
    delete from cve where number = ?;
    `
    _, err = db.Exec(sql, cve_number)
    if err != nil {
        log.Printf("%q: %s\n", err, sql)
        return nil
    }

    return nil
}

func listAction(ctx *cli.Context) error {
    // initialize database
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
    update_sites := make(map[string]string)

    // initialize database
    db, err := sql.Open("sqlite3", SQLITE_FILE)
    if err != nil {
        log.Fatal(err)
    }
    defer db.Close()
    db_init(db)

    // select all record of cve table
    cve_rows, err := db.Query("select number from cve")
    if err != nil {
        log.Fatal(err)
    }
    defer cve_rows.Close()

    for cve_rows.Next() {
        var cve_number = ""
        err = cve_rows.Scan(&cve_number)

        if err != nil {
            log.Fatal(err)
        }

        // check site
        result := check_sites(cve_number)

        // select record of watch table 
        watch_rows, err := db.Query("select url, hash from watch where cve_number = ?", cve_number)
        if err != nil {
            log.Fatal(err)
        }
        defer watch_rows.Close()

        for watch_rows.Next() {
            var url = ""
            var saved_hash = ""
            err = watch_rows.Scan(&url, &saved_hash)
            // check hash
            if(saved_hash == result[url]){
                break
            }

            // detect update site
            update_sites[url] = result[url]
        }
    }

    // update watch table
    for url, hash := range update_sites {
        fmt.Printf("UPDATE : %s", url)
        sql := `
        update watch hash = ? where url = ?
        `
        _, err = db.Exec(sql, hash, url)
        if err != nil {
            log.Printf("%q: %s\n", err, sql)
            return nil
        }
    }

    return nil
}


