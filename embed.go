package wizard

import "embed"

// TemplatesFS embeds the HTML templates directory.
//
//go:embed templates
var TemplatesFS embed.FS

// StaticFS embeds the static assets directory.
//
//go:embed static
var StaticFS embed.FS
