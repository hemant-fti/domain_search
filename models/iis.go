package models

type IISConfiguration struct {
	SystemApplicationHost struct {
		Sites struct {
			Sites []IISSite `xml:"site"`
		} `xml:"sites"`
	} `xml:"system.applicationHost"`

	SystemWebServer IISWebServer `xml:"system.webServer"`

	Locations []IISLocation `xml:"location"`
}

type IISWebServer struct {
	Rewrite IISRewrite `xml:"rewrite"`
}

type IISRewrite struct {
	Rules []IISRewriteRule `xml:"rules>rule"`
}

type IISRewriteRule struct {
	Name    string        `xml:"name,attr"`
	Enabled string        `xml:"enabled,attr"`
	Action  IISRuleAction `xml:"action"`
}

type IISRuleAction struct {
	Type string `xml:"type,attr"`
	URL  string `xml:"url,attr"`
}

type IISLocation struct {
	Path      string       `xml:"path,attr"`
	WebServer IISWebServer `xml:"system.webServer"`
}

type IISSite struct {
	Name         string           `xml:"name,attr"`
	ID           string           `xml:"id,attr"`
	Bindings     IISBindings      `xml:"bindings"`
	Applications []IISApplication `xml:"application"`
}

type IISApplication struct {
	Path               string                `xml:"path,attr"`
	VirtualDirectories []IISVirtualDirectory `xml:"virtualDirectory"`
}

type IISVirtualDirectory struct {
	Path         string `xml:"path,attr"`
	PhysicalPath string `xml:"physicalPath,attr"`
}

type IISBindings struct {
	Bindings []IISBinding `xml:"binding"`
}

type IISBinding struct {
	Protocol             string `xml:"protocol,attr"`
	BindingInformation   string `xml:"bindingInformation,attr"`
	CertificateHash      string `xml:"certificateHash,attr"`
	CertificateStoreName string `xml:"certificateStoreName,attr"`
}
