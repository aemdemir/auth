package service

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/aemdemir/auth"
	driver "github.com/go-sql-driver/mysql"
)

//
// db
//

type dbUser struct {
	ID           int             `db:"id"`
	Username     string          `db:"username"`
	Name         auth.NullString `db:"name"`
	Active       bool            `db:"active"`
	Version      int             `db:"version"`
	Created      time.Time       `db:"created"`
	Updated      time.Time       `db:"updated"`
	PasswordHash []byte          `db:"password_hash"`
}

func getUser(ctx context.Context, dbx DBTX, id int) (*dbUser, error) {
	query := `
	SELECT 
		id,
		username,
		name,
		active,
		version,
		created,
		updated,
		password_hash
	FROM  user
	WHERE id = ?
	`

	u := dbUser{}

	err := dbx.GetContext(ctx, &u, query, id)
	if err != nil {
		switch {
		case errors.Is(err, sql.ErrNoRows):
			return nil, &auth.Error{Code: auth.ENOTFOUND, Message: "no matching user found"}
		default:
			return nil, err
		}
	}
	return &u, nil
}

func getUserByEmail(ctx context.Context, dbx DBTX, address string) (*dbUser, error) {
	query := `
	SELECT 
		u.id,
		u.username,
		u.name,
		u.active,
		u.version,
		u.created,
		u.updated,
		u.password_hash
	FROM  user       AS u
	JOIN  user_email AS e ON u.id = e.user_id
	WHERE e.address = ? 
	`

	u := dbUser{}

	err := dbx.GetContext(ctx, &u, query, address)
	if err != nil {
		switch {
		case errors.Is(err, sql.ErrNoRows):
			return nil, &auth.Error{Code: auth.ENOTFOUND, Message: "no matching user found"}
		default:
			return nil, err
		}
	}
	return &u, nil
}

func getUserByPrimaryEmail(ctx context.Context, dbx DBTX, address string) (*dbUser, error) {
	query := `
	SELECT 
		u.id,
		u.username,
		u.name,
		u.active,
		u.version,
		u.created,
		u.updated,
		u.password_hash
	FROM  user       AS u
	JOIN  user_email AS e ON u.id = e.user_id
	WHERE e.address = ? AND e.is_primary = true
	`

	u := dbUser{}

	err := dbx.GetContext(ctx, &u, query, address)
	if err != nil {
		switch {
		case errors.Is(err, sql.ErrNoRows):
			return nil, &auth.Error{Code: auth.ENOTFOUND, Message: "no matching user found"}
		default:
			return nil, err
		}
	}
	return &u, nil
}

func getUserByAccount(ctx context.Context, dbx DBTX, providerName, providerUID string) (*dbUser, error) {
	query := `
	SELECT
		u.id,
		u.username,
		u.name,
		u.active,
		u.version,
		u.created,
		u.updated,
		u.password_hash
	FROM  user         AS u
	JOIN  user_account AS a ON u.id = a.user_id
	WHERE 
		a.provider_name = ? 
		AND 
		a.provider_user_id = ?
	`

	u := dbUser{}

	err := dbx.GetContext(ctx, &u, query, providerName, providerUID)
	if err != nil {
		switch {
		case errors.Is(err, sql.ErrNoRows):
			return nil, &auth.Error{Code: auth.ENOTFOUND, Message: "no matching user found"}
		default:
			return nil, err
		}
	}
	return &u, nil
}

func getUserByValidToken(ctx context.Context, dbx DBTX, hash []byte, scope string) (*dbUser, error) {
	query := `
	SELECT
		u.id,
		u.username,
		u.name,
		u.active,
		u.version,
		u.created,
		u.updated,
		u.password_hash
	FROM  user  AS u
	JOIN  token AS t ON  u.id = t.user_id
	WHERE 
		t.hash = ? 
		AND 
		t.scope = ? 
		AND 
		t.revoked = false 
		AND 
		t.expiry > ?
	`

	u := dbUser{}

	err := dbx.GetContext(ctx, &u, query, hash, scope, time.Now())
	if err != nil {
		switch {
		case errors.Is(err, sql.ErrNoRows):
			return nil, &auth.Error{Code: auth.ENOTFOUND, Message: "no matching user found"}
		default:
			return nil, err
		}
	}
	return &u, nil
}

type dbUserInsert struct {
	Username     string
	Name         auth.NullString
	PasswordHash []byte
}

func insertUser(ctx context.Context, dbx DBTX, in dbUserInsert) (int, error) {
	query := `
	INSERT INTO user 
	(
		username,
		name,
		password_hash
	)
	VALUES (:username, :name, :password_hash)
	`

	u := dbUser{
		Username:     in.Username,
		Name:         in.Name,
		PasswordHash: in.PasswordHash,
	}

	res, err := dbx.NamedExecContext(ctx, query, u)
	if err != nil {
		var mysqlErr *driver.MySQLError
		switch {
		case errors.As(err, &mysqlErr) && mysqlErr.Number == 1062:
			return -1, &auth.Error{Code: auth.EUNPROCESSABLE, Message: "duplicate username"}
		default:
			return -1, err
		}
	}
	id, err := res.LastInsertId()
	if err != nil {
		return -1, &auth.Error{Code: auth.EINTERNAL, Message: "cant fetch last inserted id"}
	}
	return int(id), nil
}

type dbUserUpdate struct {
	ID           int
	Username     string
	Version      int
	PasswordHash []byte
}

func updateUser(ctx context.Context, dbx DBTX, up dbUserUpdate) error {
	query := `
	UPDATE user
	SET
		username      = :username,
		password_hash = :password_hash,
		version       = version + 1
	WHERE 
		id      = :id AND 
		version = :version
	`

	u := dbUser{
		ID:           up.ID,
		Username:     up.Username,
		Version:      up.Version,
		PasswordHash: up.PasswordHash,
	}

	res, err := dbx.NamedExecContext(ctx, query, u)
	if err != nil {
		var mysqlErr *driver.MySQLError
		switch {
		case errors.As(err, &mysqlErr) && mysqlErr.Number == 1062:
			return &auth.Error{Code: auth.EUNPROCESSABLE, Message: "duplicate username"}
		default:
			return err
		}
	}
	if ra, err := res.RowsAffected(); err == nil && ra == 0 {
		return &auth.Error{Code: auth.ECONFLICT, Message: "unable to update user due to an edit conflict"}
	}
	return nil
}

//
// conversion
//

func toAuthUser(e *dbUser) *auth.User {
	return &auth.User{
		ID:           e.ID,
		Username:     e.Username,
		Name:         e.Name,
		Active:       e.Active,
		Version:      e.Version,
		Created:      e.Created,
		Updated:      e.Updated,
		PasswordHash: e.PasswordHash,
	}
}
