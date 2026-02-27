package db

import (
	"database/sql"
	"fmt"
	"net"
	"os"

	_ "github.com/lib/pq"
)

func Connect() (*sql.DB, error) {
	// Force IPv4 by resolving hostname to IPv4 address first
	// Docker containers don't have IPv6 routing by default
	host := os.Getenv("DB_HOST")
	ipv4, err := resolveIPv4(host)
	if err != nil {
		// fallback to original host if resolution fails
		ipv4 = host
	}

	dsn := fmt.Sprintf(
		"host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		ipv4,
		os.Getenv("DB_PORT"),
		os.Getenv("DB_USER"),
		os.Getenv("DB_PASSWORD"),
		os.Getenv("DB_NAME"),
		os.Getenv("DB_SSLMODE"),
	)

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)

	return db, nil
}

// resolveIPv4 looks up only the IPv4 address for a hostname
func resolveIPv4(host string) (string, error) {
	addrs, err := net.LookupIP(host)
	if err != nil {
		return "", err
	}
	for _, addr := range addrs {
		if ipv4 := addr.To4(); ipv4 != nil {
			return ipv4.String(), nil
		}
	}
	return "", fmt.Errorf("no IPv4 address found for %s", host)
}