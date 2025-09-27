package main

import (
	"context"
	"crypto/sha1"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/go-mysql-org/go-mysql/mysql"
	"github.com/go-mysql-org/go-mysql/server"
	"github.com/jackc/pgx/v5/pgxpool"
)

// CredentialProvider handles plaintext authentication for both MySQL and PostgreSQL.
type CredentialProvider struct {
	userPasswords map[string]string // username -> plaintext password
}

func NewCredentialProvider() *CredentialProvider {
	return &CredentialProvider{
		userPasswords: make(map[string]string),
	}
}

func (p *CredentialProvider) AddUser(username, password string) {
	log.Printf("Adding user '%s' with password '****'", username)
	p.userPasswords[username] = password
}

func (p *CredentialProvider) GetUser(username string) ([]byte, error) {
	log.Printf("Auth: Checking user '%s'", username)
	if username == "" {
		log.Printf("Auth failure: Empty username")
		return nil, mysql.NewError(mysql.ER_ACCESS_DENIED_ERROR, "empty username not allowed")
	}
	password, exists := p.userPasswords[username]
	if !exists {
		log.Printf("Auth failure: User '%s' not found", username)
		return nil, mysql.NewError(mysql.ER_ACCESS_DENIED_ERROR, fmt.Sprintf("unknown user '%s'", username))
	}
	// Simple SHA-1 for MySQL compatibility.
	hash := sha1.Sum([]byte(password))
	hash2 := sha1.Sum(hash[:])
	return hash2[:], nil
}

func (p *CredentialProvider) GetPlaintextPassword(username string) (string, bool) {
	log.Printf("Retrieving plaintext password for '%s'", username)
	password, exists := p.userPasswords[username]
	return password, exists
}

// Handler manages client commands and PostgreSQL connections.
type Handler struct {
	server.Handler
	conn      *server.Conn
	provider  *CredentialProvider
	pgPool    *pgxpool.Pool
	currentDB string
}

func NewHandler(provider *CredentialProvider, username, password, dbName string) (*Handler, error) {
	log.Printf("Creating handler for user '%s', db '%s'", username, dbName)
	h := &Handler{
		provider:  provider,
		currentDB: dbName,
	}

	// Establish PostgreSQL connection early
	if dbName == "" {
		log.Printf("No database specified, using default 'postgres'")
		dbName = "postgres"
	}
	pgConnString := fmt.Sprintf("postgres://%s:%s@192.168.2.254:5432/%s?sslmode=disable", username, password, dbName)
	log.Printf("Attempting early PostgreSQL connection with string: %s (password hidden)", strings.Replace(pgConnString, password, "*****", -1))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, pgConnString)
	if err != nil {
		log.Printf("Early PostgreSQL connection failure: %v", err)
		return nil, fmt.Errorf("failed to connect to PostgreSQL: %v", err)
	}
	log.Printf("Early PostgreSQL connection established for user '%s' to db '%s'", username, dbName)
	h.pgPool = pool
	return h, nil
}

func (h *Handler) setConn(c *server.Conn) {
	log.Printf("Setting connection for user '%s'", getUserSafe(c))
	h.conn = c
}

func (h *Handler) switchPgConnection(dbName string) error {
	log.Printf("Switching PostgreSQL connection to db '%s'", dbName)
	if h.pgPool != nil && h.currentDB == dbName {
		log.Printf("Reusing existing PostgreSQL pool for db '%s'", dbName)
		return nil
	}
	if h.pgPool != nil {
		log.Printf("Closing previous PostgreSQL pool")
		h.pgPool.Close()
		h.pgPool = nil
	}

	user := h.conn.GetUser()
	log.Printf("Using user '%s' for PostgreSQL connection", user)
	if user == "" {
		log.Printf("Failure: No username provided")
		return mysql.NewError(mysql.ER_ACCESS_DENIED_ERROR, "no username provided")
	}
	password, ok := h.provider.GetPlaintextPassword(user)
	if !ok {
		log.Printf("Failure: No password found for user '%s'", user)
		return mysql.NewError(mysql.ER_ACCESS_DENIED_ERROR, fmt.Sprintf("No password for user '%s'", user))
	}
	if dbName == "" {
		log.Printf("Failure: No database selected")
		return mysql.NewError(mysql.ER_NO_DB_ERROR, "No database selected")
	}

	pgConnString := fmt.Sprintf("postgres://%s:%s@192.168.2.254:5432/%s?sslmode=disable", user, password, dbName)
	log.Printf("Attempting PostgreSQL connection with string: %s (password hidden)", strings.Replace(pgConnString, password, "*****", -1))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, pgConnString)
	if err != nil {
		log.Printf("PostgreSQL connection failure: %v", err)
		return mysql.NewError(mysql.ER_ACCESS_DENIED_ERROR, fmt.Sprintf("Access denied for user '%s': %v", user, err))
	}
	log.Printf("PostgreSQL connection established for user '%s' to db '%s'", user, dbName)
	h.pgPool = pool
	h.currentDB = dbName
	return nil
}

func (h *Handler) UseDB(dbName string) error {
	log.Printf("Client requested USE '%s'", dbName)
	if dbName == "" {
		log.Printf("Failure: No database selected")
		return mysql.NewError(mysql.ER_NO_DB_ERROR, "No database selected")
	}
	h.currentDB = dbName
	return h.switchPgConnection(dbName)
}

func (h *Handler) HandleQuery(query string) (*mysql.Result, error) {
	log.Printf("Handling query: '%s'", query)
	lowerQuery := strings.ToLower(strings.TrimSpace(query))

	// Handle MySQL-specific queries without requiring a database
	if lowerQuery == "select @@version_comment limit 1" {
		log.Printf("Returning static response for SELECT @@version_comment")
		resultSet, err := mysql.BuildSimpleTextResultset([]string{"@@version_comment"}, [][]interface{}{{"MySQL-to-PostgreSQL Proxy"}})
		if err != nil {
			log.Printf("Resultset build failure: %v", err)
			return nil, err
		}
		return &mysql.Result{Status: mysql.SERVER_STATUS_AUTOCOMMIT, Resultset: resultSet}, nil
	}

	// Ensure PostgreSQL connection for other queries
	if h.currentDB == "" {
		log.Printf("Query failure: No database selected")
		return nil, mysql.NewError(mysql.ER_NO_DB_ERROR, "No database selected")
	}
	if h.pgPool == nil {
		log.Printf("Query failure: PostgreSQL not connected")
		return nil, mysql.NewError(mysql.ER_ACCESS_DENIED_ERROR, "PostgreSQL connection not established")
	}

	if lowerQuery == "show tabless" && h.currentDB != "" {
		log.Printf("Executing SHOW TABLES on PostgreSQL")
		pgQuery := "SELECT table_name FROM information_schema.tables WHERE table_type = 'BASE TABLE' AND table_schema NOT IN ('pg_catalog', 'information_schema') ORDER BY table_name;"
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		rows, err := h.pgPool.Query(ctx, pgQuery)
		if err != nil {
			log.Printf("PostgreSQL query failure: %v", err)
			return nil, err
		}
		defer rows.Close()
		var resultValues [][]interface{}
		for rows.Next() {
			var tableName string
			if err := rows.Scan(&tableName); err != nil {
				log.Printf("Scan failure: %v", err)
				return nil, err
			}
			resultValues = append(resultValues, []interface{}{tableName})
		}
		if rows.Err() != nil {
			log.Printf("Rows iteration error: %v", rows.Err())
			return nil, rows.Err()
		}
		columnName := fmt.Sprintf("Tables_in_%s", h.currentDB)
		resultSet, err := mysql.BuildSimpleTextResultset([]string{columnName}, resultValues)
		if err != nil {
			log.Printf("Resultset build failure: %v", err)
			return nil, err
		}
		return &mysql.Result{Status: mysql.SERVER_STATUS_AUTOCOMMIT, Resultset: resultSet}, nil
	}

	if strings.HasPrefix(lowerQuery, "select") {
		translatedQuery := strings.ReplaceAll(query, "`", "\"")
		rows, err := h.pgPool.Query(context.Background(), translatedQuery)
		if err != nil {
			return nil, err
		}
		defer rows.Close()

		fieldDescriptions := rows.FieldDescriptions()
		var fields []string
		for _, col := range fieldDescriptions {
			fields = append(fields, string(col.Name))
		}

		var resultValues [][]interface{}
		for rows.Next() {
			rowValues, err := rows.Values()
			if err != nil {
				return nil, err
			}
			// convert boolean to int for MySQL compatibility
			for i, v := range rowValues {
				if b, ok := v.(bool); ok {
					if b {
						rowValues[i] = int8(1)
					} else {
						rowValues[i] = int8(0)
					}
				}
			}
			resultValues = append(resultValues, rowValues)
		}

		resultSet, err := mysql.BuildSimpleTextResultset(fields, resultValues)
		if err != nil {
			return nil, err
		}

		return &mysql.Result{Status: mysql.SERVER_STATUS_AUTOCOMMIT, Resultset: resultSet}, nil
	}

	log.Printf("Unsupported query: '%s'", query)
	return nil, fmt.Errorf("unsupported query: '%s'", query)
}

func (h *Handler) HandleOtherCommand(cmd byte, data []byte) error {
	log.Printf("Handling other command: %d", cmd)
	switch cmd {
	case mysql.COM_PING:
		log.Printf("Handled COM_PING")
		return nil
	case mysql.COM_QUIT:
		log.Printf("Handled COM_QUIT")
		return nil
	default:
		log.Printf("Unsupported command: %d", cmd)
		return fmt.Errorf("unsupported command: %d", cmd)
	}
}

func (h *Handler) Close() {
	log.Printf("Closing handler")
	if h.pgPool != nil {
		log.Printf("Closing PostgreSQL pool")
		h.pgPool.Close()
	}
}

// getUserSafe returns the username or "unknown" if conn is nil
func getUserSafe(conn *server.Conn) string {
	if conn == nil {
		return "unknown"
	}
	return conn.GetUser()
}

func main() {
	provider := NewCredentialProvider()
	provider.AddUser("pguser", "pgpass") // Add test user/password

	listener, err := net.Listen("tcp", "127.0.0.1:3306")
	if err != nil {
		log.Fatalf("Listen failure: %v", err)
	}
	log.Println("Proxy listening on 127.0.0.1:3306")

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Accept failure: %v", err)
			continue
		}
		log.Printf("New client connection from %s", conn.RemoteAddr())

		go func() {
			defer conn.Close()

			// Use hardcoded credentials for early PostgreSQL connection
			username := "pguser"
			password := "pgpass"
			defaultDB := "listmonk" // Default database
			handler, err := NewHandler(provider, username, password, defaultDB)
			if err != nil {
				log.Printf("Failed to create handler with early PostgreSQL connection: %v", err)
				return
			}

			srv := server.NewServer(
				"mysql", // Server version
				mysql.DEFAULT_COLLATION_ID,
				mysql.AUTH_NATIVE_PASSWORD,
				nil, // Public key (not used)
				nil, // TLS config (not used)
			)
			log.Printf("Initializing MySQL connection")
			clientConn, err := srv.NewConn(conn, username, password, handler)
			if err != nil {
				log.Printf("MySQL conn init failure: %v", err)
				handler.Close()
				return
			}
			log.Printf("MySQL connection initialized, user: %s", getUserSafe(clientConn))
			handler.setConn(clientConn)

			// Validate client credentials match PostgreSQL credentials
			clientUser := clientConn.GetUser()
			if clientUser != username {
				log.Printf("Client user '%s' does not match expected user '%s'", clientUser, username)
				//clientConn.WriteErrorPacket(mysql.NewError(mysql.ER_ACCESS_DENIED_ERROR, fmt.Sprintf("user '%s' not allowed", clientUser)))
				handler.Close()
				return
			}

			// Handle default database from handshake
			/*
				if clientConn.Database != "" {
					log.Printf("Client specified default database: '%s'", clientConn.Database)
					if err := handler.UseDB(clientConn.Database); err != nil {
						log.Printf("Default database setup failure: %v", err)
						clientConn.WriteErrorPacket(err)
						handler.Close()
						return
					}
				}*/

			for {
				if err := clientConn.HandleCommand(); err != nil {
					log.Printf("Command handling failure: %v", err)
					handler.Close()
					return
				}
			}
		}()
	}
}
