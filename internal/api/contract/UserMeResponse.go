package contract

type Group struct {
	Name string `json:"name"`
	ID   string `json:"id"`
}

type UserMe struct {
	Id       *string `json:"id"`
	Name     *string `json:"name"`
	UserName *string `json:"username"`
	Email    *string `json:"email"`
}
