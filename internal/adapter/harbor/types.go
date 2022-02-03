package harbor

type Response map[string]Report

// Report model for vulnerability scan
type Report struct {
	// Time of generating this report
	GeneratedAt string `json:"generated_at"`
	// A standard scale for measuring the severity of a vulnerability.
	Severity string `json:"severity"`
	// Vulnerability list
	Vulnerabilities []*VulnerabilityItem `json:"vulnerabilities"`

	vulnerabilityItemList *VulnerabilityItemList
}

// VulnerabilityItemList the list can skip the VulnerabilityItem exists in the list when adding
type VulnerabilityItemList struct {
	items   []*VulnerabilityItem
	indexed map[string]*VulnerabilityItem
}

// VulnerabilityItem represents one found vulnerability
type VulnerabilityItem struct {
	// The unique identifier of the vulnerability.
	// e.g: CVE-2017-8283
	ID string `json:"id"`
	// An operating system or software dependency package containing the vulnerability.
	// e.g: dpkg
	Package string `json:"package"`
	// The version of the package containing the vulnerability.
	// e.g: 1.17.27
	Version string `json:"version"`
	// The version of the package containing the fix if available.
	// e.g: 1.18.0
	FixVersion string `json:"fix_version"`
	// A standard scale for measuring the severity of a vulnerability.
	Severity string `json:"severity"`
	// example: dpkg-source in dpkg 1.3.0 through 1.18.23 is able to use a non-GNU patch program
	// and does not offer a protection mechanism for blank-indented diff hunks, which allows remote
	// attackers to conduct directory traversal attacks via a crafted Debian source package, as
	// demonstrated by using of dpkg-source on NetBSD.
	Description string `json:"description"`
	// The list of link to the upstream database with the full description of the vulnerability.
	// Format: URI
	// e.g: List [ "https://security-tracker.debian.org/tracker/CVE-2017-8283" ]
	Links []string `json:"links"`
	// The artifact digests which the vulnerability belonged
	// e.g: sha256@ee1d00c5250b5a886b09be2d5f9506add35dfb557f1ef37a7e4b8f0138f32956
	ArtifactDigests []string `json:"artifact_digests"`
	// The CVSS3 and CVSS2 based scores and attack vector for the vulnerability item
	CVSSDetails CVSS `json:"preferred_cvss"`
	// A separated list of CWE Ids associated with this vulnerability
	// e.g. CWE-465,CWE-124
	CWEIds []string `json:"cwe_ids"`
	// A collection of vendor specific attributes for the vulnerability item
	// with each attribute represented as a key-value pair.
	VendorAttributes map[string]interface{} `json:"vendor_attributes"`
}

// CVSS holds the score and attack vector for the vulnerability based on the CVSS3 and CVSS2 standards
type CVSS struct {
	// The CVSS-3 score for the vulnerability
	// e.g. 2.5
	ScoreV3 *float64 `json:"score_v3"`
	// The CVSS-3 score for the vulnerability
	// e.g. 2.5
	ScoreV2 *float64 `json:"score_v2"`
	// The CVSS-3 attack vector.
	// e.g. CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N
	VectorV3 string `json:"vector_v3"`
	// The CVSS-3 attack vector.
	// e.g. AV:L/AC:M/Au:N/C:P/I:N/A:N
	VectorV2 string `json:"vector_v2"`
}
