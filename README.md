# google-go
Minimal, Production-Ready Google OAuth2 for Go

# Installation
```bash
go get github.com/meszmate/google-go
```

# Quick Start
```go
package main

import (
    "context"
    "log"
    "net/http"

    "github.com/meszmate/google-go"
)

var auth *google.GoogleAuth

func main() {
    auth = google.NewAuth(
        "YOUR_CLIENT_ID",
        "YOUR_CLIENT_SECRET",
        "https://yoursite.com/auth/callback", // must be registered in Google console
        nil, // uses openid + email + profile scopes by default
    )

    http.HandleFunc("/login", loginHandler)
    http.HandleFunc("/auth/callback", callbackHandler)
    log.Fatal(http.ListenAndServe(":8080", nil))
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
    state := "random123" // use secure random + CSRF protection in real apps
    url := auth.AuthURL(state)
    http.Redirect(w, r, url, http.StatusFound)
}

func callbackHandler(w http.ResponseWriter, r *http.Request) {
    if err := r.URL.Query().Get("error"); err != "" {
        http.Error(w, "Denied", http.StatusForbidden)
        return
    }

    code := r.URL.Query().Get("code")
    if code == "" {
        http.Error(w, "Missing code", http.StatusBadRequest)
        return
    }

    token, err := auth.Exchange(r.Context(), code)
    if err != nil {
        http.Error(w, "Exchange failed", http.StatusInternalServerError)
        return
    }

    user, err := auth.GetUserInfo(r.Context(), token)
    if err != nil {
        http.Error(w, "Failed to get user info", http.StatusInternalServerError)
        return
    }

    // token.RefreshToken is ALWAYS present thanks to prompt=consent
    log.Printf("Logged in: %s (%s)", user.Email, user.Sub)
    w.Write([]byte("Hello " + user.Name + "! You are now signed in."))
}
```

# License
MIT
