package controllers

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"

	// "log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/shivarajshanthaiah/unit-testing/models"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// tests struct defines a structure to hold individual test case details//
type tests struct {
	name        string            // Name of the test case
	body        interface{}       // Input data (request body)
	route       string            // URL route to test against
	errorResult map[string]string // Expected error result in case of errors
}
//this
func init() {
	fmt.Println("this is the unit testing of go signup and login")
}

// TestSignup function to test signup functionality
func TestSignup(t *testing.T) {
	// Defined test cases for user signup
	tests := []tests{
		{
			name: "error- binding_error",// Retrieve the value of query parameter "v" from the request.
			body: models.User{

				FirstName: "test_name",
				LastName:  "",
				DoB:       "01/01/2000",
				Gender:    "M",
				Email:     "test@gmail.com",
				Phone:     "7521750433",
				Address:   "15/2, Oz Villa,New California",
				Password:  "12345",
			},
			route:       "/signup",
			errorResult: map[string]string{"error": "validation error"},
		},
		{
			name: "success",
			body: models.User{
				FirstName: "test",
				LastName:  "name",
				DoB:       "01/01/2000",
				Gender:    "M",
				Email:     "test@gmail.com",
				Phone:     "7521750433",
				Address:   "15/2, Oz Villa,New California",
				Password:  "12345",
			},
			route:       "/signup",
			errorResult: nil,
		},
		{
			name: "binding error",
			body: models.User{
				FirstName: "test",
				LastName:  "name",
				DoB:       "01/01/2000",
				Gender:    "M",
				Password:  "12345",
			},
			route:       "/signup",
			errorResult: map[string]string{"error": "validation error"},
		},
	}

	// Loop through each test case
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Mock functions for OTP generation, email sending, Redis operations, etc.
			getOtp = func(length int) string {
				return "1234"
			}
			sendOtp = func(otp string, email string) error {
				return nil
			}
			verifyOtp = func(otp string, userOtp string) bool {
				return true
			}
			setRedis = func(key string, value any, expirationTime time.Duration) error {
				return nil
			}

			// Mocking getUser function to simulate errors
			getUser = func(val string, db *gorm.DB) (*models.User, error) {
				user := &models.User{}
				return user, errors.New("mock error")
			}

			// Convert request body to JSON
			body, err := json.Marshal(tc.body)
			if err != nil {
				require.NoError(t, err)
			}
			r := strings.NewReader(string(body))

			// Setup HTTP request and record response
			w, err := Setup(http.MethodPost, tc.route, r, "")
			if err != nil {
				require.NoError(t, err)

			}

			// Check if errorResult is expected
			if tc.errorResult != nil {
				errValue, _ := json.Marshal(tc.errorResult)
				// require.NoError(t, err)
				require.JSONEq(t, w.Body.String(), string(errValue))
			} else {
				// Compare response with expected JSON data from file
				data, err := readJSON("testdata/user_signup.json")
				if err != nil {
					require.NoError(t, err)
				}
				fmt.Println("helooooooooooooooooooo", data)

				require.JSONEq(t, w.Body.String(), data)
			}

		})

	}
}

func TestSignupEmailerror(t *testing.T) {
	tests := []tests{
		{
			name: "email exists",
			body: models.User{
				FirstName: "test",
				LastName:  "name",
				DoB:       "01/01/2000",
				Gender:    "M",
				Email:     "test122@gmail.com",
				Phone:     "7521750433",
				Address:   "15/2, Oz Villa,New California",
				Password:  "12345",
			},
			route:       "/signup",
			errorResult: map[string]string{"error": "Email already in use"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			getOtp = func(length int) string {
				return "1234"
			}
			sendOtp = func(otp string, email string) error {
				return nil
			}
			verifyOtp = func(otp string, userOtp string) bool {
				return true
			}
			setRedis = func(key string, value any, expirationTime time.Duration) error {
				return nil
			}

			getUser = func(val string, db *gorm.DB) (*models.User, error) {
				user := &models.User{}
				return user, nil
			}
			body, err := json.Marshal(tc.body)
			if err != nil {
				require.NoError(t, err)
			}
			r := strings.NewReader(string(body))

			w, err := Setup(http.MethodPost, tc.route, r, "")
			if err != nil {
				require.NoError(t, err)

			}
			if tc.errorResult != nil {
				errValue, _ := json.Marshal(tc.errorResult)
				// require.NoError(t, err)
				require.JSONEq(t, w.Body.String(), string(errValue))
			} else {
				data, err := readJSON("testdata/user_signup.json")
				if err != nil {
					require.NoError(t, err)
				}
				fmt.Println("helooooooooooooooooooo", data)

				require.JSONEq(t, w.Body.String(), data)
			}

		})

	}
}

func TestSignupRediserror(t *testing.T) {
	tests := []tests{
		{
			name: "redis error",
			body: models.User{
				FirstName: "test",
				LastName:  "name",
				DoB:       "01/01/2000",
				Gender:    "M",
				Email:     "test122@gmail.com",
				Phone:     "7521750433",
				Address:   "15/2, Oz Villa,New California",
				Password:  "12345",
			},
			route: "/signup",
			errorResult: map[string]string{"status": "Failed",
				"message": "Redis error",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			getOtp = func(length int) string {
				return "1234"
			}
			sendOtp = func(otp string, email string) error {
				return nil
			}
			verifyOtp = func(otp string, userOtp string) bool {
				return true
			}
			setRedis = func(key string, value any, expirationTime time.Duration) error {
				return errors.New("mock error")
			}

			getUser = func(val string, db *gorm.DB) (*models.User, error) {
				user := &models.User{}
				return user, errors.New("mock error")
			}
			body, err := json.Marshal(tc.body)
			if err != nil {
				require.NoError(t, err)
			}
			r := strings.NewReader(string(body))

			w, err := Setup(http.MethodPost, tc.route, r, "")
			if err != nil {
				require.NoError(t, err)

			}
			if tc.errorResult != nil {
				errValue, _ := json.Marshal(tc.errorResult)
				// require.NoError(t, err)
				require.JSONEq(t, w.Body.String(), string(errValue))
			} else {
				data, err := readJSON("testdata/user_signup.json")
				if err != nil {
					require.NoError(t, err)
				}
				fmt.Println("helooooooooooooooooooo", data)

				require.JSONEq(t, w.Body.String(), data)
			}

		})

	}
}

/////////////////////////////////////////////

type OTPString struct {
	Email string
	Otp   string
}

func TestSignupVerification(t *testing.T) {
	tests := []tests{
		{
			name: "success",
			body: OTPString{
				Email: "test122@gmail.com",
				Otp:   "12345",
			},
			route:       "/verifyotp",
			errorResult: nil,
		},
		{
			name: "otp not entered",
			body: OTPString{
				Email: "test122@gmail.com",
				Otp:   "",
			},
			route: "/verifyotp",
			errorResult: map[string]string{"status": "Failed",
				"message": "OTP not entered",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			verifyOtp = func(otp string, userOtp string) bool {
				return true
			}
			getRedis = func(key string) (string, error) {
				jsonData, err := json.Marshal(tc.body)
				if err != nil {
					return "", err
				}
				return string(jsonData), nil
			}
			create = func(user *models.User, db *gorm.DB) error {
				return nil
			}
			body, err := json.Marshal(tc.body)
			if err != nil {
				require.NoError(t, err)
			}
			r := strings.NewReader(string(body))

			w, err := Setup(http.MethodPost, tc.route, r, "")
			if err != nil {
				require.NoError(t, err)

			}
			if tc.errorResult != nil {
				errValue, _ := json.Marshal(tc.errorResult)
				// require.NoError(t, err)
				require.JSONEq(t, w.Body.String(), string(errValue))
			} else {
				data, err := readJSON("testdata/user_signupVerification.json")
				if err != nil {
					require.NoError(t, err)
				}
				fmt.Println("helooooooooooooooooooo", data)

				require.JSONEq(t, w.Body.String(), data)
			}

		})

	}
}

func TestSignupVerificationRedisOtpError(t *testing.T) {
	tests := []tests{
		{
			name: "Otp not found",
			body: OTPString{
				Email: "test122@gmail.com",
				Otp:   "12345",
			},
			route: "/verifyotp",
			errorResult: map[string]string{"status": "Failed",
				"message": "otp not found",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			verifyOtp = func(otp string, userOtp string) bool {
				return true
			}
			getRedis = func(key string) (string, error) {
				jsonData, err := json.Marshal(tc.body)
				if err != nil {
					return "", err
				}
				return string(jsonData), errors.New("mocked error")
			}
			create = func(user *models.User, db *gorm.DB) error {
				return nil
			}
			body, err := json.Marshal(tc.body)
			if err != nil {
				require.NoError(t, err)
			}
			r := strings.NewReader(string(body))

			w, err := Setup(http.MethodPost, tc.route, r, "")
			if err != nil {
				require.NoError(t, err)

			}
			if tc.errorResult != nil {
				errValue, _ := json.Marshal(tc.errorResult)
				// require.NoError(t, err)
				require.JSONEq(t, w.Body.String(), string(errValue))
			} else {
				data, err := readJSON("testdata/user_signupVerification.json")
				if err != nil {
					require.NoError(t, err)
				}
				fmt.Println("helooooooooooooooooooo", data)

				require.JSONEq(t, w.Body.String(), data)
			}

		})

	}
}

func TestSignupVerificationOtpError(t *testing.T) {
	tests := []tests{
		{
			name: "Otp mismatch",
			body: OTPString{
				Email: "test122@gmail.com",
				Otp:   "12345",
			},
			route: "/verifyotp",
			errorResult: map[string]string{"status": "Failed",
				"message": "Otp mismatch",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			verifyOtp = func(otp string, userOtp string) bool {
				return false
			}
			getRedis = func(key string) (string, error) {
				jsonData, err := json.Marshal(tc.body)
				if err != nil {
					return "", err
				}
				return string(jsonData), nil
			}
			create = func(user *models.User, db *gorm.DB) error {
				return nil
			}
			body, err := json.Marshal(tc.body)
			if err != nil {
				require.NoError(t, err)
			}
			r := strings.NewReader(string(body))

			w, err := Setup(http.MethodPost, tc.route, r, "")
			if err != nil {
				require.NoError(t, err)

			}
			if tc.errorResult != nil {
				errValue, _ := json.Marshal(tc.errorResult)
				// require.NoError(t, err)
				require.JSONEq(t, w.Body.String(), string(errValue))
			} else {
				data, err := readJSON("testdata/user_signupVerification.json")
				if err != nil {
					require.NoError(t, err)
				}
				fmt.Println("helooooooooooooooooooo", data)

				require.JSONEq(t, w.Body.String(), data)
			}

		})

	}
}

///////////////////////////////////////////////

type login struct {
	Email    string
	Password string
}

func TestLogin(t *testing.T) {
	tests := []tests{
		{
			name: "success",
			body: login{
				Email:    "test122@gmail.com",
				Password: "12345",
			},
			route:       "/login",
			errorResult: nil,
		},
		{
			name: "Validation error",
			body: login{
				Email:    "test122@gmail.com",
				Password: "",
			},
			route: "/login",
			errorResult: map[string]string{"status": "Failed",
				"message": "Please fill all fields",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			getUser = func(val string, db *gorm.DB) (*models.User, error) {
				user := &models.User{}
				return user, nil
			}
			checkPassword = func(user *models.User, providedPassword string) error {
				return nil
			}
			generateToken = func(userID uint64, userEmail, userRole string) (string, error) {
				return "", nil
			}
			body, err := json.Marshal(tc.body)
			if err != nil {
				require.NoError(t, err)
			}
			r := strings.NewReader(string(body))

			w, err := Setup(http.MethodPost, tc.route, r, "")
			if err != nil {
				require.NoError(t, err)

			}
			if tc.errorResult != nil {
				errValue, _ := json.Marshal(tc.errorResult)
				// require.NoError(t, err)
				require.JSONEq(t, w.Body.String(), string(errValue))
			} else {

				require.Equal(t, w.Code, 200)
			}

		})

	}
}

func TestLoginUserError(t *testing.T) {
	tests := []tests{
		{
			name: "User not found",
			body: login{
				Email:    "test122@gmail.com",
				Password: "12345",
			},
			route: "/login",
			errorResult: map[string]string{"status": "Failed",
				"message": "User not found"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			getUser = func(val string, db *gorm.DB) (*models.User, error) {
				return nil, errors.New("mocked error")
			}
			checkPassword = func(user *models.User, providedPassword string) error {
				return nil
			}
			generateToken = func(userID uint64, userEmail, userRole string) (string, error) {
				return "", nil
			}
			body, err := json.Marshal(tc.body)
			if err != nil {
				require.NoError(t, err)
			}
			r := strings.NewReader(string(body))

			w, err := Setup(http.MethodPost, tc.route, r, "")
			if err != nil {
				require.NoError(t, err)

			}
			if tc.errorResult != nil {
				errValue, _ := json.Marshal(tc.errorResult)
				// require.NoError(t, err)
				require.JSONEq(t, w.Body.String(), string(errValue))
			} else {
				data, err := readJSON("testdata/user_login.json")
				if err != nil {
					require.NoError(t, err)
				}
				fmt.Println("helooooooooooooooooooo", data)

				require.JSONEq(t, w.Body.String(), data)
			}

		})

	}
}

func TestLoginPasswordError(t *testing.T) {
	tests := []tests{
		{
			name: "Password wrong",
			body: login{
				Email:    "test122@gmail.com",
				Password: "12345",
			},
			route: "/login",
			errorResult: map[string]string{"status": "Failed",
				"message": "Invalid password"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			getUser = func(val string, db *gorm.DB) (*models.User, error) {
				user := &models.User{}
				return user, nil
			}
			checkPassword = func(user *models.User, providedPassword string) error {
				return errors.New("mocked error")
			}
			generateToken = func(userID uint64, userEmail, userRole string) (string, error) {
				return "", nil
			}
			body, err := json.Marshal(tc.body)
			if err != nil {
				require.NoError(t, err)
			}
			r := strings.NewReader(string(body))

			w, err := Setup(http.MethodPost, tc.route, r, "")
			if err != nil {
				require.NoError(t, err)

			}
			if tc.errorResult != nil {
				errValue, _ := json.Marshal(tc.errorResult)
				// require.NoError(t, err)
				require.JSONEq(t, w.Body.String(), string(errValue))
			} else {
				data, err := readJSON("testdata/user_login.json")
				if err != nil {
					require.NoError(t, err)
				}
				fmt.Println("helooooooooooooooooooo", data)

				require.JSONEq(t, w.Body.String(), data)
			}

		})

	}
}

func TestLoginTokenError(t *testing.T) {
	tests := []tests{
		{
			name: "Token error",
			body: login{
				Email:    "test122@gmail.com",
				Password: "12345",
			},
			route: "/login",
			errorResult: map[string]string{"status": "Failed",
				"message": "Failed to generate token"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			getUser = func(val string, db *gorm.DB) (*models.User, error) {
				user := &models.User{}
				return user, nil
			}
			checkPassword = func(user *models.User, providedPassword string) error {
				return nil
			}
			generateToken = func(userID uint64, userEmail, userRole string) (string, error) {
				return "", errors.New("mocked error")
			}
			body, err := json.Marshal(tc.body)
			if err != nil {
				require.NoError(t, err)
			}
			r := strings.NewReader(string(body))

			w, err := Setup(http.MethodPost, tc.route, r, "")
			if err != nil {
				require.NoError(t, err)

			}
			if tc.errorResult != nil {
				errValue, _ := json.Marshal(tc.errorResult)
				// require.NoError(t, err)
				require.JSONEq(t, w.Body.String(), string(errValue))
			} else {
				data, err := readJSON("testdata/user_login.json")
				if err != nil {
					require.NoError(t, err)
				}
				fmt.Println("helooooooooooooooooooo", data)

				require.JSONEq(t, w.Body.String(), data)
			}

		})

	}
}

// Setup is a helper function to set up HTTP request
func Setup(method, url string, body io.Reader, token string) (*httptest.ResponseRecorder, error) {

	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	engine := gin.Default()

	RegisterUserRoutes(engine)
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}
	if token != "" {
		req.Header.Set("Authorization", token)
	}
	engine.ServeHTTP(w, req)
	return w, nil
}

// readJSON function reads the JSON data from a file and returns it as a string
func readJSON(filePath string) (string, error) {

	file, err := os.Open(filePath)
	if err != nil {
		log.Fatal("error opening file")
	}
	defer file.Close()
	data, err := io.ReadAll(file)
	if err != nil {
		return "", err
	}
	return string(data), nil
}
