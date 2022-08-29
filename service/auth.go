package service

import (
	"context"

	"github.com/aemdemir/auth"
	"github.com/rs/zerolog"
)

type authService struct {
	db     *DB
	logger zerolog.Logger
	mailer Mailer
}

func NewService(db *DB, logger zerolog.Logger, mailer Mailer) auth.Service {
	return &authService{
		db:     db,
		logger: logger,
		mailer: mailer,
	}
}

func (s *authService) Signup(ctx context.Context, signup auth.SignupInput) error {
	v := auth.NewValidator()
	if signup.Validate(v); !v.Valid() {
		return &auth.Error{Code: auth.EUNPROCESSABLE, Message: "invalid input", Detail: v.Errors}
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	ph, err := signup.HashPassword()
	if err != nil {
		return err
	}
	uid, err := insertUser(ctx, tx, dbUserInsert{
		Username:     signup.Username,
		Name:         auth.NewNullString(signup.Name),
		PasswordHash: ph,
	})
	if err != nil {
		return err
	}

	err = insertEmail(ctx, tx, dbEmailInsert{
		UserID:  uid,
		Address: signup.Email,
		Primary: signup.IsPrimaryEmail(),
	})
	if err != nil {
		return err
	}

	tkn, err := auth.TokenEmailVerification.New(uid, signup.Email)
	if err != nil {
		return err
	}
	err = insertToken(ctx, tx, dbTokenInsert{
		UserID:  tkn.UserID,
		Hash:    tkn.HashToken(),
		Scope:   tkn.Scope,
		Expiry:  tkn.Expiry,
		Payload: tkn.Payload,
	})
	if err != nil {
		return err
	}

	background(s.logger, func() {
		err := s.mailer.SendVerificationEmail(signup.Email, tkn.Text)
		if err != nil {
			s.logger.
				Err(err).
				Int("user_id", uid).
				Str("recipient", signup.Email).
				Msg("failed to send verification email")
		}
	})
	return tx.Commit()
}

func (s *authService) Signin(ctx context.Context, signin auth.SigninInput) (*auth.UserSignin, error) {
	v := auth.NewValidator()
	if signin.Validate(v); !v.Valid() {
		return nil, &auth.Error{Code: auth.EUNPROCESSABLE, Message: "invalid input", Detail: v.Errors}
	}

	du, err := getUserByPrimaryEmail(ctx, s.db, signin.Email)
	if err != nil {
		if auth.ErrorCode(err) != auth.ENOTFOUND {
			return nil, err
		}
		return nil, &auth.Error{Code: auth.EUNAUTHORIZED, Message: "invalid authentication credentials"}
	}
	de, err := getEmail(ctx, s.db, signin.Email)
	if err != nil {
		if auth.ErrorCode(err) != auth.ENOTFOUND {
			return nil, err
		}
		return nil, &auth.Error{Code: auth.EUNAUTHORIZED, Message: "invalid authentication credentials"}
	}
	user := toAuthUser(du)
	ok, err := user.MatchPassword(signin.Password)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, &auth.Error{Code: auth.EUNAUTHORIZED, Message: "invalid authentication credentials"}
	}

	// make sure email and password is already checked.
	// if so, return error details. otherwise we may leak information.
	if !user.Active {
		return nil, &auth.Error{Code: auth.EFORBIDDEN, Message: "this user is deactivated"}
	}
	if !de.Verified {
		return nil, &auth.Error{Code: auth.EUNPROCESSABLE, Message: "this email address has not been verified yet"}
	}

	tkn, err := auth.TokenAuth.New(user.ID, "")
	if err != nil {
		return nil, err
	}
	err = insertToken(ctx, s.db, dbTokenInsert{
		UserID:  tkn.UserID,
		Hash:    tkn.HashToken(),
		Scope:   tkn.Scope,
		Expiry:  tkn.Expiry,
		Payload: tkn.Payload,
	})
	if err != nil {
		return nil, err
	}

	return &auth.UserSignin{
		UserEmail: auth.UserEmail{
			User:  *user,
			Email: *toAuthEmail(de),
		},
		Token: tkn.Text,
	}, nil
}

func (s *authService) SigninSocial(ctx context.Context, signin auth.SigninSocialInput) (*auth.UserSigninSocial, error) {
	v := auth.NewValidator()
	if signin.Validate(v); !v.Valid() {
		return nil, &auth.Error{Code: auth.EUNPROCESSABLE, Message: "invalid input", Detail: v.Errors}
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	var user *auth.User
	if du, err := getUserByAccount(ctx, tx, signin.Account.ProviderName, signin.Account.ProviderUserID); err != nil {
		if auth.ErrorCode(err) != auth.ENOTFOUND {
			return nil, err
		}

		du, err := getUserByPrimaryEmail(ctx, tx, signin.Email.String)
		if err != nil {
			if auth.ErrorCode(err) != auth.ENOTFOUND {
				return nil, err
			}

			id, err := createOAuthUser(ctx, tx, signin)
			if err != nil {
				return nil, err
			}
			du, err := getUser(ctx, tx, id)
			if err != nil {
				return nil, err
			}
			user = toAuthUser(du)
		} else {
			err := linkUserAccount(ctx, tx, du, signin.Account)
			if err != nil {
				return nil, err
			}
			user = toAuthUser(du)
		}
	} else {
		user = toAuthUser(du)
	}

	tkn, err := auth.TokenAuth.New(user.ID, "")
	if err != nil {
		return nil, err
	}
	err = insertToken(ctx, tx, dbTokenInsert{
		UserID:  tkn.UserID,
		Hash:    tkn.HashToken(),
		Scope:   tkn.Scope,
		Expiry:  tkn.Expiry,
		Payload: tkn.Payload,
	})
	if err != nil {
		return nil, err
	}

	return &auth.UserSigninSocial{
		User:  *user,
		Token: tkn.Text,
	}, tx.Commit()
}

func (s *authService) LinkUserAccount(ctx context.Context, link auth.LinkUserAccountInput) error {
	meta := auth.TokenConfirmation

	v := auth.NewValidator()
	if link.Validate(v, meta); !v.Valid() {
		return &auth.Error{Code: auth.EUNPROCESSABLE, Message: "invalid input", Detail: v.Errors}
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	hash := link.Token.HashToken()
	du, err := getUserByValidToken(ctx, tx, hash, meta.Scope)
	if err != nil {
		if auth.ErrorCode(err) != auth.ENOTFOUND {
			return err
		}
		return &auth.Error{Code: auth.EUNPROCESSABLE, Message: "invalid code"}
	}
	err = deleteToken(ctx, tx, hash)
	if err != nil {
		return err
	}

	err = linkUserAccount(ctx, tx, du, link.Account)
	if err != nil {
		return err
	}

	return tx.Commit()
}

func (s *authService) SendVerificationEmail(ctx context.Context, address string) error {
	v := auth.NewValidator()
	if auth.ValidateEmail(v, address); !v.Valid() {
		return &auth.Error{Code: auth.EUNPROCESSABLE, Message: "invalid input", Detail: v.Errors}
	}

	de, err := getEmail(ctx, s.db, address)
	if err != nil {
		return err
	}
	if de.Verified {
		return &auth.Error{Code: auth.EUNPROCESSABLE, Message: "email has already been verified"}
	}

	tkn, err := auth.TokenEmailVerification.New(de.UserID, de.Address)
	if err != nil {
		return err
	}
	err = insertToken(ctx, s.db, dbTokenInsert{
		UserID:  tkn.UserID,
		Hash:    tkn.HashToken(),
		Scope:   tkn.Scope,
		Expiry:  tkn.Expiry,
		Payload: tkn.Payload,
	})
	if err != nil {
		return err
	}

	background(s.logger, func() {
		err := s.mailer.SendVerificationEmail(de.Address, tkn.Text)
		if err != nil {
			s.logger.
				Err(err).
				Int("user_id", de.UserID).
				Str("recipient", de.Address).
				Msg("failed to send verification email")
		}
	})

	return nil
}

func (s *authService) VerifyEmail(ctx context.Context, token auth.TokenInput) error {
	meta := auth.TokenEmailVerification

	v := auth.NewValidator()
	if token.Validate(v, meta); !v.Valid() {
		return &auth.Error{Code: auth.EUNPROCESSABLE, Message: "invalid input", Detail: v.Errors}
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	de, err := getEmailByValidToken(ctx, tx, token.HashToken(), meta.Scope)
	if err != nil {
		if auth.ErrorCode(err) != auth.ENOTFOUND {
			return err
		}
		return &auth.Error{Code: auth.EUNAUTHORIZED, Message: "invalid code"}
	}

	err = updateEmail(ctx, tx, dbEmailUpdate{
		Address:  de.Address,
		Primary:  de.Primary,
		Verified: true,
	})
	if err != nil {
		return err
	}

	err = deleteTokensByUserAndScope(ctx, tx, de.UserID, meta.Scope)
	if err != nil {
		return err
	}

	return tx.Commit()
}

func (s *authService) SendPasswordResetEmail(ctx context.Context, address string) error {
	v := auth.NewValidator()
	if auth.ValidateEmail(v, address); !v.Valid() {
		return &auth.Error{Code: auth.EUNPROCESSABLE, Message: "invalid input", Detail: v.Errors}
	}

	de, err := getEmail(ctx, s.db, address)
	if err != nil {
		return err
	}
	if !de.Primary {
		return &auth.Error{Code: auth.EUNPROCESSABLE, Message: "no matching email found"}
	}
	if !de.Verified {
		return &auth.Error{Code: auth.EUNPROCESSABLE, Message: "email address has not been verified yet"}
	}

	tkn, err := auth.TokenPasswordReset.New(de.UserID, "")
	if err != nil {
		return err
	}
	err = insertToken(ctx, s.db, dbTokenInsert{
		UserID:  tkn.UserID,
		Hash:    tkn.HashToken(),
		Scope:   tkn.Scope,
		Expiry:  tkn.Expiry,
		Payload: tkn.Payload,
	})
	if err != nil {
		return err
	}

	background(s.logger, func() {
		err := s.mailer.SendPasswordResetEmail(de.Address, tkn.Text)
		if err != nil {
			s.logger.
				Err(err).
				Int("user_id", de.UserID).
				Str("recipient", de.Address).
				Msg("failed to send password reset email")
		}
	})

	return nil
}

func (s *authService) ResetPassword(ctx context.Context, reset auth.ResetPasswordInput) error {
	meta := auth.TokenPasswordReset

	v := auth.NewValidator()
	if reset.Validate(v, meta); !v.Valid() {
		return &auth.Error{Code: auth.EUNPROCESSABLE, Message: "invalid input", Detail: v.Errors}
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	du, err := getUserByValidToken(ctx, tx, reset.Token.HashToken(), meta.Scope)
	if err != nil {
		if auth.ErrorCode(err) != auth.ENOTFOUND {
			return err
		}
		return &auth.Error{Code: auth.EUNPROCESSABLE, Message: "invalid code"}
	}

	ph, err := reset.HashPassword()
	if err != nil {
		return err
	}
	err = updateUser(ctx, tx, dbUserUpdate{
		ID:           du.ID,
		Username:     du.Username,
		Version:      du.Version,
		PasswordHash: ph,
	})
	if err != nil {
		return err
	}

	err = deleteTokensByUser(ctx, tx, du.ID)
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (s *authService) UserConfirmation(ctx context.Context, uid int, password string) (string, error) {
	v := auth.NewValidator()
	if auth.ValidatePassword(v, password); !v.Valid() {
		return "", &auth.Error{Code: auth.EUNPROCESSABLE, Message: "invalid input", Detail: v.Errors}
	}

	du, err := getUser(ctx, s.db, uid)
	if err != nil {
		return "", nil
	}
	user := toAuthUser(du)
	ok, err := user.MatchPassword(password)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", &auth.Error{Code: auth.EUNAUTHORIZED, Message: "invalid authentication credentials"}
	}

	tkn, err := auth.TokenConfirmation.New(user.ID, "")
	if err != nil {
		return "", err
	}
	err = insertToken(ctx, s.db, dbTokenInsert{
		UserID:  tkn.UserID,
		Hash:    tkn.HashToken(),
		Scope:   tkn.Scope,
		Expiry:  tkn.Expiry,
		Payload: tkn.Payload,
	})
	if err != nil {
		return "", err
	}

	return tkn.Text, nil
}

func (s *authService) AddEmail(ctx context.Context, uid int, address string) error {
	v := auth.NewValidator()
	if auth.ValidateEmail(v, address); !v.Valid() {
		return &auth.Error{Code: auth.EUNPROCESSABLE, Message: "invalid input", Detail: v.Errors}
	}

	err := insertEmail(ctx, s.db, dbEmailInsert{
		UserID:  uid,
		Address: address,
		Primary: false,
	})
	if err != nil {
		return err
	}

	return s.SendVerificationEmail(ctx, address)
}

func (s *authService) UpdatePrimaryEmail(ctx context.Context, uid int, address string) error {
	v := auth.NewValidator()
	if auth.ValidateEmail(v, address); !v.Valid() {
		return &auth.Error{Code: auth.EUNPROCESSABLE, Message: "invalid input", Detail: v.Errors}
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	de, err := getEmail(ctx, tx, address)
	if err != nil {
		return err
	}
	if de.UserID != uid {
		return &auth.Error{Code: auth.ENOTFOUND, Message: "no matching email found"}
	}
	if !de.Verified {
		return &auth.Error{Code: auth.ENOTFOUND, Message: "this email address has not been verified yet"}
	}

	err = resetPrimaryEmail(ctx, tx, uid)
	if err != nil {
		return err
	}

	err = updateEmail(ctx, tx, dbEmailUpdate{
		Address:  de.Address,
		Primary:  true,
		Verified: de.Verified,
	})
	if err != nil {
		return err
	}

	return tx.Commit()
}

func (s *authService) GetUserSettings(ctx context.Context, uid int) (*auth.UserSettings, error) {
	du, err := getUser(ctx, s.db, uid)
	if err != nil {
		return nil, err
	}

	dee, err := getEmailsByUser(ctx, s.db, uid)
	if err != nil {
		return nil, err
	}

	daa, err := getAccountsByUser(ctx, s.db, uid)
	if err != nil {
		return nil, err
	}

	return &auth.UserSettings{
		User:     *toAuthUser(du),
		Emails:   toAuthEmails(dee),
		Accounts: toAuthAccounts(daa),
	}, nil
}

func (s *authService) UpdateUsername(ctx context.Context, uid int, username string) error {
	v := auth.NewValidator()
	if auth.ValidateUsername(v, username); !v.Valid() {
		return &auth.Error{Code: auth.EUNPROCESSABLE, Message: "invalid input", Detail: v.Errors}
	}

	du, err := getUser(ctx, s.db, uid)
	if err != nil {
		return err
	}

	err = updateUser(ctx, s.db, dbUserUpdate{
		ID:           du.ID,
		Username:     username,
		Version:      du.Version,
		PasswordHash: du.PasswordHash,
	})
	return err
}

func (s *authService) UpdatePassword(ctx context.Context, password auth.UpdatePasswordInput) error {
	v := auth.NewValidator()
	if password.Validate(v); !v.Valid() {
		return &auth.Error{Code: auth.EUNPROCESSABLE, Message: "invalid input", Detail: v.Errors}
	}

	du, err := getUser(ctx, s.db, password.UserID)
	if err != nil {
		return err
	}
	user := toAuthUser(du)
	ok, err := user.MatchPassword(password.OldPassword)
	if err != nil {
		return err
	}
	if !ok {
		return &auth.Error{Code: auth.EUNAUTHORIZED, Message: "invalid authentication credentials"}
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	ph, err := password.HashPassword()
	if err != nil {
		return err
	}
	err = updateUser(ctx, tx, dbUserUpdate{
		ID:           du.ID,
		Username:     du.Username,
		Version:      du.Version,
		PasswordHash: ph,
	})
	if err != nil {
		return err
	}

	err = deleteTokensByUser(ctx, tx, du.ID)
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (s *authService) GetUser(ctx context.Context, token auth.TokenInput) (*auth.User, error) {
	meta := auth.TokenAuth

	v := auth.NewValidator()
	if token.Validate(v, meta); !v.Valid() {
		return nil, &auth.Error{Code: auth.EUNPROCESSABLE, Message: "invalid input", Detail: v.Errors}
	}

	du, err := getUserByValidToken(ctx, s.db, token.HashToken(), meta.Scope)
	if err != nil {
		if auth.ErrorCode(err) != auth.ENOTFOUND {
			return nil, err
		}
		return nil, &auth.Error{Code: auth.EUNAUTHORIZED, Message: "invalid token"}
	}
	return toAuthUser(du), nil
}

//
// db
//

func createOAuthUser(ctx context.Context, tx *Tx, signin auth.SigninSocialInput) (int, error) {
	uid, err := insertUser(ctx, tx, dbUserInsert{
		Username:     signin.Username,
		Name:         signin.Name,
		PasswordHash: signin.PasswordHash(),
	})
	if err != nil {
		return -1, err
	}

	if signin.Email.Valid {
		// it's ok to skip duplicate email error here.
		// but that breaks the transaction. therefore use a savepoint.
		err := tx.WithSavepoint(ctx, func(tx *Tx) error {
			return insertEmail(ctx, tx, dbEmailInsert{
				UserID:  uid,
				Address: signin.Email.String,
				Primary: signin.IsPrimaryEmail(true),
			})
		})
		if err != nil && auth.ErrorCode(err) != auth.EUNPROCESSABLE { // EUNPROCESSABLE maps to duplicate
			return -1, err
		}
	}

	err = insertAccount(ctx, tx, dbAccountInsert{
		UserID:         uid,
		ProviderName:   signin.Account.ProviderName,
		ProviderUserID: signin.Account.ProviderUserID,
	})
	if err != nil {
		return -1, err
	}

	return uid, nil
}

func linkUserAccount(ctx context.Context, tx *Tx, user *dbUser, account auth.AccountInput) error {
	// A malicious person could sign up with an email address of someone else.
	// But, he/she is not be able to verify it.
	// And also, we link accounts to the users based on the email address.
	// So, this can lead giving access to the malicious person since he/she knows the password.
	// To avoid that, we should reset the password for an unverified email when linking accounts.
	if de, err := getEmailByUser(ctx, tx, user.ID); err == nil && de.Primary {
		if !de.Verified {
			if err := updateUser(ctx, tx, dbUserUpdate{
				ID:           user.ID,
				Username:     user.Username,
				Version:      user.Version,
				PasswordHash: nil,
			}); err != nil {
				return err
			}
		}
	}

	err := insertAccount(ctx, tx, dbAccountInsert{
		UserID:         user.ID,
		ProviderName:   account.ProviderName,
		ProviderUserID: account.ProviderUserID,
	})
	return err
}

//
// mailer
//

type Mailer interface {
	SendVerificationEmail(recipient, token string) error
	SendPasswordResetEmail(recipient, token string) error
}
