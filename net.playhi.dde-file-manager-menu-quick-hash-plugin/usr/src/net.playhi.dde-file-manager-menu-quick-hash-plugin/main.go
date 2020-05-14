package main

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/crypto/md4"
	"golang.org/x/crypto/sha3"
)

var mode string

func main() {
	mode = os.Args[1]
	calculate()
}

func walkFn(path string, info os.FileInfo, err error) error {
	if info == nil {
		return nil
	}
	if info.IsDir() {
		return nil
	}
	calculateSingleFile(path)
	return nil
}

func isDir(path string) bool {
	s, err := os.Stat(path)
	if err != nil {
		fmt.Println(path, " get fileInfo failed. ", err)
		return false
	}
	return s.IsDir()
}

func calculate() {
	for _, arg := range os.Args[2:] {
		if isDir(arg) {
			filepath.Walk(arg, walkFn)
		} else {
			calculateSingleFile(arg)
		}
	}
}

func calculateSingleFile(path string) {
	f, err := os.Open(path)
	if err != nil {
		fmt.Println("Open", path, "Failed. ", err)
		return
	}

	defer f.Close()

	switch mode {
	case "MD4":
		fmt.Println(calculateSingleFileMD4(f, path), "|", path)
	case "MD5":
		fmt.Println(calculateSingleFileMD5(f, path), "|", path)
	case "SHA1":
		fmt.Println(calculateSingleFileSHA1(f, path), "|", path)
	case "SHA224":
		fmt.Println(calculateSingleFileSHA224(f, path), "|", path)
	case "SHA256":
		fmt.Println(calculateSingleFileSHA256(f, path), "|", path)
	case "SHA384":
		fmt.Println(calculateSingleFileSHA384(f, path), "|", path)
	case "SHA512":
		fmt.Println(calculateSingleFileSHA512(f, path), "|", path)
	case "SHA3_224":
		fmt.Println(calculateSingleFileSHA3_224(f, path), "|", path)
	case "SHA3_256":
		fmt.Println(calculateSingleFileSHA3_256(f, path), "|", path)
	case "SHA3_384":
		fmt.Println(calculateSingleFileSHA3_384(f, path), "|", path)
	case "SHA3_512":
		fmt.Println(calculateSingleFileSHA3_512(f, path), "|", path)
	default:
		fmt.Println(calculateSingleFileMD5(f, path), "|", path)
	}
}

func calculateSingleFileMD4(f *os.File, path string) string {
	fileHash := md4.New()
	if _, err := io.Copy(fileHash, f); err != nil {
		fmt.Println("Copy", path, "Failed. ", err)
		return "Failed"
	}
	return hex.EncodeToString(fileHash.Sum(nil))
}

func calculateSingleFileMD5(f *os.File, path string) string {
	fileHash := md5.New()
	if _, err := io.Copy(fileHash, f); err != nil {
		fmt.Println("Copy", path, "Failed. ", err)
		return "Failed"
	}
	return hex.EncodeToString(fileHash.Sum(nil))
}

func calculateSingleFileSHA1(f *os.File, path string) string {
	fileHash := sha1.New()
	if _, err := io.Copy(fileHash, f); err != nil {
		fmt.Println("Copy", path, "Failed. ", err)
		return "Failed"
	}
	return hex.EncodeToString(fileHash.Sum(nil))
}

func calculateSingleFileSHA224(f *os.File, path string) string {
	fileHash := sha256.New224()
	if _, err := io.Copy(fileHash, f); err != nil {
		fmt.Println("Copy", path, "Failed. ", err)
		return "Failed"
	}
	return hex.EncodeToString(fileHash.Sum(nil))
}

func calculateSingleFileSHA256(f *os.File, path string) string {
	fileHash := sha256.New()
	if _, err := io.Copy(fileHash, f); err != nil {
		fmt.Println("Copy", path, "Failed. ", err)
		return "Failed"
	}
	return hex.EncodeToString(fileHash.Sum(nil))
}

func calculateSingleFileSHA384(f *os.File, path string) string {
	fileHash := sha512.New384()
	if _, err := io.Copy(fileHash, f); err != nil {
		fmt.Println("Copy", path, "Failed. ", err)
		return "Failed"
	}
	return hex.EncodeToString(fileHash.Sum(nil))
}

func calculateSingleFileSHA512(f *os.File, path string) string {
	fileHash := sha512.New()
	if _, err := io.Copy(fileHash, f); err != nil {
		fmt.Println("Copy", path, "Failed. ", err)
		return "Failed"
	}
	return hex.EncodeToString(fileHash.Sum(nil))
}

func calculateSingleFileSHA3_224(f *os.File, path string) string {
	fileHash := sha3.New224()
	if _, err := io.Copy(fileHash, f); err != nil {
		fmt.Println("Copy", path, "Failed. ", err)
		return "Failed"
	}
	return hex.EncodeToString(fileHash.Sum(nil))
}

func calculateSingleFileSHA3_256(f *os.File, path string) string {
	fileHash := sha3.New256()
	if _, err := io.Copy(fileHash, f); err != nil {
		fmt.Println("Copy", path, "Failed. ", err)
		return "Failed"
	}
	return hex.EncodeToString(fileHash.Sum(nil))
}

func calculateSingleFileSHA3_384(f *os.File, path string) string {
	fileHash := sha3.New384()
	if _, err := io.Copy(fileHash, f); err != nil {
		fmt.Println("Copy", path, "Failed. ", err)
		return "Failed"
	}
	return hex.EncodeToString(fileHash.Sum(nil))
}

func calculateSingleFileSHA3_512(f *os.File, path string) string {
	fileHash := sha3.New512()
	if _, err := io.Copy(fileHash, f); err != nil {
		fmt.Println("Copy", path, "Failed. ", err)
		return "Failed"
	}
	return hex.EncodeToString(fileHash.Sum(nil))
}
