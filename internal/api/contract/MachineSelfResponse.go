package contract

type MachineSelfResponse struct {
	Data struct {
		Attributes struct {
			TenantId string `json:"tenant_id"`
		} `json:"attributes"`
	} `json:"data"`
}
