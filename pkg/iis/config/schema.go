package config

// XML schema for the parts of applicationHost.config hostscope reads.

type xmlConfiguration struct {
	SystemApplicationHost struct {
		Sites struct {
			Sites []xmlSite `xml:"site"`
		} `xml:"sites"`
	} `xml:"system.applicationHost"`

	SystemWebServer xmlWebServer `xml:"system.webServer"`

	Locations []xmlLocation `xml:"location"`
}

type xmlWebServer struct {
	Rewrite xmlRewrite `xml:"rewrite"`
}

type xmlRewrite struct {
	Rules []xmlRewriteRule `xml:"rules>rule"`
}

type xmlRewriteRule struct {
	Name    string        `xml:"name,attr"`
	Enabled string        `xml:"enabled,attr"`
	Action  xmlRuleAction `xml:"action"`
}

type xmlRuleAction struct {
	Type string `xml:"type,attr"`
	URL  string `xml:"url,attr"`
}

type xmlLocation struct {
	Path      string       `xml:"path,attr"`
	WebServer xmlWebServer `xml:"system.webServer"`
}

type xmlSite struct {
	Name         string           `xml:"name,attr"`
	ID           string           `xml:"id,attr"`
	Bindings     []xmlBinding     `xml:"bindings>binding"`
	Applications []xmlApplication `xml:"application"`
}

type xmlApplication struct {
	Path               string                `xml:"path,attr"`
	VirtualDirectories []xmlVirtualDirectory `xml:"virtualDirectory"`
}

type xmlVirtualDirectory struct {
	Path         string `xml:"path,attr"`
	PhysicalPath string `xml:"physicalPath,attr"`
}

type xmlBinding struct {
	Protocol             string `xml:"protocol,attr"`
	BindingInformation   string `xml:"bindingInformation,attr"`
	SSLFlags             string `xml:"sslFlags,attr"`
	CertificateHash      string `xml:"certificateHash,attr"`
	CertificateStoreName string `xml:"certificateStoreName,attr"`
}
