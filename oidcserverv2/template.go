package oidcserverv2

import "html/template"

type consentData struct {
	AuthID string
	Client string
	Scopes []string
}

var consentTmpl = template.Must(template.New("consent").Parse(`
<html>
<head>
</head>
<body>
  <div>
	<form action="" method="POST">
	  <p>{{ .Client }} requests {{ .Scopes }}</p>
	  <input type="hidden" value="{{ .AuthID }}">
	  <input type="submit" value="Confirm">
	</form>
  </div>
</body>
</html>
`))
