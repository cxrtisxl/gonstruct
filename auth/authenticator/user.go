package authenticator

import "github.com/markbates/goth"

type User struct {
	ID          string `json:"id"`
	Provider    string `json:"provider"`
	ExternalID  string `json:"external_id"`
	Email       string `json:"email"`
	Name        string `json:"name"`
	FirstName   string `json:"first_name"`
	LastName    string `json:"last_name"`
	NickName    string `json:"nickname"`
	Description string `json:"description"`
	AvatarURL   string `json:"avatar_url"`
	Location    string `json:"location"`
}

func UserFromGoth(gu goth.User) User {
	return User{
		Provider:    gu.Provider,
		ExternalID:  gu.UserID,
		Email:       gu.Email,
		Name:        gu.Name,
		FirstName:   gu.FirstName,
		LastName:    gu.LastName,
		NickName:    gu.NickName,
		Description: gu.Description,
		AvatarURL:   gu.AvatarURL,
		Location:    gu.Location,
	}
}
