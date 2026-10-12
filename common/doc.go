// Package common provides shared helper functions used across multiple
// cryptographic sub-packages to eliminate code duplication.
//
// This package is a leaf dependency: it must not import any other package in
// this project. That keeps it safe to use from anywhere without creating
// import cycles.
package common
