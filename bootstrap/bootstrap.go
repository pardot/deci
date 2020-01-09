package bootstrap

import "github.com/gobuffalo/packr/v2"

// Bootstrap is a packr box that contains the bootstrap dependencies we use
var Bootstrap = packr.New("bootstrap-assets", "./assets")
