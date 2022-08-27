package service

import (
	"context"
	"errors"
	"time"

	"github.com/aemdemir/auth"
	driver "github.com/go-sql-driver/mysql"
)

//
// db
//

type dbAccount struct {
	UserID         int       `db:"user_id"`
	ProviderName   string    `db:"provider_name"`
	ProviderUserID string    `db:"provider_user_id"`
	Created        time.Time `db:"created"`
}

func getAccountsByUser(ctx context.Context, dbx DBTX, id int) ([]dbAccount, error) {
	query := `
	SELECT 
		user_id, 
		provider_name, 
		provider_user_id, 
		created 
	FROM  user_account 
	WHERE user_id = ?
	`

	a := []dbAccount{}

	err := dbx.SelectContext(ctx, &a, query, id)
	return a, err
}

type dbAccountInsert struct {
	UserID         int
	ProviderName   string
	ProviderUserID string
}

func insertAccount(ctx context.Context, dbx DBTX, in dbAccountInsert) error {
	query := `
	INSERT INTO user_account 
	(
		user_id,
		provider_name,
		provider_user_id
	)
	VALUES (:user_id, :provider_name, :provider_user_id)
	`

	a := dbAccount{
		UserID:         in.UserID,
		ProviderName:   in.ProviderName,
		ProviderUserID: in.ProviderUserID,
	}

	_, err := dbx.NamedExecContext(ctx, query, a)
	if err != nil {
		var mysqlErr *driver.MySQLError
		switch {
		case errors.As(err, &mysqlErr) && mysqlErr.Number == 1062:
			return &auth.Error{Code: auth.EUNPROCESSABLE, Message: "duplicate oauth account"}
		default:
			return err
		}
	}
	return nil
}

//
// conversion
//

func toAuthAccount(e *dbAccount) *auth.Account {
	return &auth.Account{
		UserID:         e.UserID,
		ProviderName:   e.ProviderName,
		ProviderUserID: e.ProviderUserID,
		Created:        e.Created,
	}
}

func toAuthAccounts(ss []dbAccount) []auth.Account {
	rr := make([]auth.Account, len(ss))
	for i, e := range ss {
		rr[i] = *toAuthAccount(&e)
	}
	return rr
}
