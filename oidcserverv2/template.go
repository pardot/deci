package oidcserverv2

import "html/template"

type consentData struct {
	AuthID     string
	ClientName string
	Offline    bool

	CSRFField template.HTML
}

var consentTmpl = template.Must(template.New("consent").Parse(`
<html>
<head>
  <script src="/bootstrap/jquery-3.4.1.slim.min.js"></script>
  <script src="/bootstrap/popper-1.16.0.min.js"></script>
  <link rel="stylesheet" href="/bootstrap/bootstrap-4.4.1.min.css">
  <script src="/bootstrap/bootstrap-4.4.1.min.js"></script>

  <style>
    body {
	  padding-top: 5rem;
	  background-color: #f5f5f5;
	}

	.container {
	  display: -ms-flexbox;
	  display: -webkit-box;
	  display: flex;
	  -ms-flex-align: center;
	  -ms-flex-pack: center;
	  -webkit-box-align: center;
	  align-items: center;
	  -webkit-box-pack: center;
	  justify-content: center;
	  padding-top: 40px;
	  padding-bottom: 40px;
	  }
  </style>

  <script type="text/javascript">
    // make pressing enter on the page automatically confirm
    $( document ).ready(function() {
      $('a#confirm').focus();
    });
  </script>

</head>
<body>

  <nav class="navbar navbar-expand-md navbar-dark bg-dark fixed-top">
    <a class="navbar-brand" href="#">Identity Server</a>
  </nav>

  <main role="main" class="container">

    <form class="form-consent" action="/consent" method="POST">
      {{ .CSRFField }}
      <input type="hidden" name="authid" value="{{ .AuthID }}">


      <div class="card" style="width: 36rem;">
        <div class="card-body">
          <h5 class="card-title">{{ .ClientName }}</h5>


   	      <p>This application is requesting profile information, and an identity token it can use to verify you.</p>
   	      {{ if .Offline }}
   	      <p>In addition, the client has requested offline access. This will allow it to transparently obtain new ID tokens in the background.</p>
   	      {{ end }}
   	      <div class="text-center">
   	        <a id="confirm" href="#" class="btn btn-primary" onclick="$(this).closest('form').submit();">Confirm</a>
   	      </div>
        </div>
      </div>
    </form>

  </main>

</body>
</html>
`))
