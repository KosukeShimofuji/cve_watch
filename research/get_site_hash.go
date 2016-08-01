package main

import(
    "fmt"
    "net/http"
    "regexp"
    "crypto/sha256"
    "io/ioutil"
    "strings"
)

func main(){

    cve_number := "CVE-2016-5734"

    watch_url := []string{
        "https://access.redhat.com/security/cve/" + cve_number,
        "https://security-tracker.debian.org/tracker/" + cve_number,
        "https://people.canonical.com/~ubuntu-security/cve/" + cve_number + ".html",
    }

    for _, url := range watch_url{
        resp, _ := http.Get(url)
        defer resp.Body.Close()
        byteArray, _ := ioutil.ReadAll(resp.Body)
        html := string(byteArray)

        //HTMLタグを全て小文字に変換します
        re, _ := regexp.Compile(`\<[\S\s]+?\>`)
        html = re.ReplaceAllStringFunc(html, strings.ToLower)

        //<script>タグを除去
        re, _ = regexp.Compile(`\<script[\S\s]+?\</script\>`)
        html = re.ReplaceAllString(html, "")

        //コメントタグを除去
        re, _ = regexp.Compile(`\<\!-\-[\s\S]*?\-\-\>`)
        html = re.ReplaceAllString(html, "")

        hash :=  fmt.Sprintf("%x", sha256.Sum256([]byte(html)))
        fmt.Printf("%s : %s\n", url, hash)
    }

    return
}


