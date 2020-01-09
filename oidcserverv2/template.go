package oidcserverv2

import "html/template"

type consentData struct {
	AuthID     string
	ClientName string
	Offline    bool
}

var consentTmpl = template.Must(template.New("consent").Parse(`
<html>
<head>
</head>
<body>
  <div>
	<form action="" method="POST">
	  <p>{{ .ClientName }} is requesting profile information, and an identity token it can use to verify you.</p>
	  {{ if .Offline }}
	  <p>In addition, the client has requested offline access. This will allow it to transparently obtain new ID tokens in the background.</p>
	  {{ end }}
	  <input type="hidden" value="{{ .AuthID }}">
	  <input type="submit" value="Confirm">
	</form>
  </div>
</body>
</html>
`))
