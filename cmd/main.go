package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"github.com/mccantuta/simple-oauth2-server-go/internal/pages"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

var (
	oauthConfGoogle = &oauth2.Config{
		ClientID:     "CLIENT_ID",
		ClientSecret: "CLIENT_SECRET",
		RedirectURL:  "http://localhost:8080/callback",
		Scopes:       []string{"https://www.googleapis.com/auth/userinfo.email", "https://www.googleapis.com/auth/userinfo.profile"},
		Endpoint:     google.Endpoint,
	}
	oauthStateStringGoogle = "anyExpectedStateValue"
)

func main() {
	fmt.Println("Starting OAuth2 server")
	http.HandleFunc("/", HandleMain)
	http.HandleFunc("/login-google", HandleGoogleLogin)
	http.HandleFunc("/callback", CallBackGoogle)
	http.HandleFunc("/validateToken", ValidateToken)

	http.ListenAndServe(":8080", nil)
}

func HandleMain(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(pages.LoginPage))
}

func HandleGoogleLogin(w http.ResponseWriter, r *http.Request) {
	HandleLogin(w, r, oauthConfGoogle, oauthStateStringGoogle)
}

func HandleLogin(w http.ResponseWriter, r *http.Request, oauthConf *oauth2.Config, oauthStateString string) {
	URL, err := url.Parse(oauthConf.Endpoint.AuthURL)
	if err != nil {
		fmt.Errorf("Parse: " + err.Error())
	}
	fmt.Println(URL.String())
	parameters := url.Values{}
	parameters.Add("client_id", oauthConf.ClientID)
	parameters.Add("scope", strings.Join(oauthConf.Scopes, " "))
	parameters.Add("redirect_uri", oauthConf.RedirectURL)
	parameters.Add("response_type", "code")
	parameters.Add("state", oauthStateString)
	URL.RawQuery = parameters.Encode()
	url := URL.String()
	fmt.Println(url)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func CallBackGoogle(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Callback from Google")

	state := r.FormValue("state")
	fmt.Println("State:" + state)
	if state != oauthStateStringGoogle {
		fmt.Println("invalid oauth state, expected " + oauthStateStringGoogle + ", got " + state + "\n")
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	code := r.FormValue("code")
	fmt.Println("Code:" + code)

	if code == "" {
		fmt.Println("Code not found..")
		w.Write([]byte("Code Not Found to provide AccessToken..\n"))
		reason := r.FormValue("error_reason")
		if reason == "user_denied" {
			w.Write([]byte("User has denied Permission.."))
		}
		// User has denied access..
		// http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
	} else {
		token, err := oauthConfGoogle.Exchange(oauth2.NoContext, code)
		if err != nil {
			fmt.Println("oauthConfGoogle.Exchange() failed with " + err.Error() + "\n")
			return
		}
		fmt.Println("AccessToken:" + token.AccessToken)
		fmt.Println("TokenType:" + token.TokenType)
		fmt.Println("Expiration Time:" + token.Expiry.String())
		fmt.Println("RefreshToken:" + token.RefreshToken)

		resp, err := http.Get("https://www.googleapis.com/oauth2/v2/userinfo?access_token=" + url.QueryEscape(token.AccessToken))
		if err != nil {
			fmt.Println("Get: " + err.Error() + "\n")
			http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
			return
		}
		defer resp.Body.Close()

		response, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			fmt.Println("ReadAll: " + err.Error() + "\n")
			http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
			return
		}

		fmt.Println("parseResponseBody: " + string(response) + "\n")

		w.Write([]byte(string(response)))
		return
	}
}

func ValidateToken(w http.ResponseWriter, r *http.Request) {
	var httpClient = &http.Client{}
	token, _ := r.URL.Query()["token"]
	fmt.Println("Token:" + token[0])
	oauth2Service := oauth2.NewClient(httpClient)
	tokenInfoCall := oauth2Service.Tokeninfo()
	tokenInfoCall.IdToken(token)
	tokenInfo, err := tokenInfoCall.Do()
	if err != nil {
		return nil, err
	}
	fmt.Println(tokenInfo)
	return tokenInfo, nil
}
