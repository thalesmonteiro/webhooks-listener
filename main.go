package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
)

const message1 = "S2/CgKWlgCaz2U6wLT1tTcMw12d9P3STZ87SaaHuryxGukV9tCwL8DLWPQF67mHxstHUYGCHOO2qy6P9p8BbssPuR7RNhEa1+jl+wTVNZ9ot6ZabQ/p+TOzEwOLwtfsSU2Ng6SYh6Tv2xfwYMavZK4eblMsOtJNuYKz/plnTrXPaX8RlzhVDZkqTVPb43lbDvAMFInAEw0yBq/grdOoq36H1oK0tIl+d+LdJtpeE8+cWBrke5Za7h7OU6G3P+xdI4FNowav+KM25TvHkrL0I6LOQ/DElpWOVMKxzXd7llruwASU/UMeRajh0WypHsgydE0gFNkbY5uA/UwA+LjGu//ncVeZ9IoOZScADZikTnPJF1C8VE/Lfxa/PpVX2Zk152NzVd3gIsP9rLPCERx1GlVtVGwpFf1FxATTJNAL8WgLxZl8wEXYyxwSNmQIAJg6eMNW3gmLytt1FuRs0dLoZVIJPA4afNgye/ydx3WAwRFnL0NOuFW6tONVbXHn7mLGPOlzCuUQq2Sqr4oMSRlrE+z5z1OtGFBIa8/6SQt6vAGRo/uhJ78k34FttuqSMZnn38legIKuzqQbyDSD7TTLmPyeQNxHxKC1i526gRN/ypat6aYJe8pgWDL6iRG1pyTZ/htjIXLHNU2cHOiSM7gf6N9cSKrKU84NlBjbKmG916obKxuKdaXGW9fqd/O6FnYQgIVVm/a4AlVo4YMwqqmmmsUMLZVopSH/j63m/oklRWBF9vi8oC7p9kVElMy8OfjYaK5+hNuZ+gcJTtDkH0hzPJI7Pi9ac88iugdBisDKA9i/dn9lJpVuImiuKk2vmfKFpwQfiY5Qs7mR/jPKWM8q0xWeJlcqUVLf9cdy3TvQ6/ELuhwGXmQQqVGBpoefnRHV3aGn7qSJ9UORdrbA6Bs0pdbBWbu4Fhban3o/tyF5XGVtdfGGKLnZdlFdXWqW1MYbuVyYKRdH1Izm0gSleTQ3XVLTtJ7SpPobhy4rPrQzlnsxRg4XB8T3BV4g5pJ2hGMN2jDhN5e5nhn00SCrbKZEAuO2SPMvrybgErOujG+rMhkN3S7MaQp1nv8G66SaQ1QIM44lRqDQJ1dBrHBV2GPE1PQ"
const message2 = "S2/CgKWlgCaz2U6wLT1tTVoMvwBjT9wkGCcSIWjtNy//zC7q1wSWPbYB3kqk3K4oGl39+k3C4MWjkAEgXQzWD+qMRt/DSUJEWR8L7NU5qJmU3VwWMxbEctNZCIkr3wb1YegompuSP21XMhV+tiXOWsQJomc/34lLGqtW8LujrnXRtMDjzRblyD6HIFdbXJxMElxNDrzgDql6Ys0GyyVumcENu8WVpl59385btXUset06/YoGcRiVJgLYLgiTnHjDUh/NxJpbHTxpXEbHLkEihQUo0kQj46G2gjy1nVz7O6ZsRXVvo/A2J+R3KO3k9DtIV4K7lhhv5iif4qJw4yXUupiKKl6PlB0H+nAMtGs0DSHQxW+/5keSJBQUYfXhKT0ggnchqDUFtfywLKZQ4+TOrCu25sRuFsT/SWKvJggi9hwLaGI9MvI0RR3URR6hu/PbJpq783Cm18qDesvKjQKOcLapo0akznO0+X2cRHzvayXq1v+hEsN63Itsg/JOK4/fgCwW7xyKD3pHFLyKZiDykpreVz3tCsivX4o8gj0D09+HlY5zSgYufO7oNuCLRmvy2qvJlB+D3NO2zyQxgLkw2X7S0L/RFbz2qkmk+3hUu1lKXArjUAKx9s6RDdZQ9APIbzzsuLoFIgXNWi+ClJyLVeZHVdhvxp0QtxiTrG2UYUqibAyn+NJAukuu2xm14PUkTYu64UKroMoyTwYaRgSHsPmDFbmu6aseO3mHaG8kjoCqPI+hGvm3Z1nAsjsV62T5HpxN6T7LobgCCAmzo1/uElZ1d+JYJGpq9VPfRKjMjKOc3Nn4OLRk2P5faf7sgymUHblpFZvnGeINEH78u18kBot3KvM2aMajeps/jgscWm8ekkAYE5385h0Ufb1AigGV0Uw2VIaQ7Pg+gaSmK/ZyxGqqsKpkUqPlhCGo9f7gUyY/gYHZN5Q+RcBMwhYiFQyY1aCu/jfaVxVvYtug5e/aF2g7u4VnnmRl7MA+xpDXqImW6zvfsVz732d+GAwdz807bXqMe1IUVtCclAo93FJ6Ve5f6CATRN8DEabRFtPMrYDKEeogvUhudKIiGqxNQCu1ENkAI4puREFHZN3+2s4oHoCDnN0Ml8FksdW/MC0IDZg"

var keyAES = []byte{131, 86, 03, 162, 131, 192, 224, 01, 209, 18, 215, 21, 21, 137, 210, 84, 52, 65, 133, 120, 80, 109, 39, 112, 225, 81, 01, 193, 211, 104, 74, 41}

func main() {
	fmt.Println("listen on port 3232")
	http.HandleFunc("/person", HandleDecrypt)
	http.ListenAndServe(":3332", nil)
}

func HandleDecrypt(w http.ResponseWriter, r *http.Request) {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	fmt.Println("Encrypted message: ", string(body))
	fmt.Println("Headers: ", r.Header)
	s, e := DecryptWithAES(keyAES, string(body))
	if e != nil {
		fmt.Println(e)
		return
	}
	fmt.Println("Decrypted message: ", s)
	fmt.Print("\n")

}

func DecryptWithAES(aesKey []byte, text string) (string, error) {
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return "", err
	}

	decodedMsg, err := base64.StdEncoding.DecodeString(addBase64Padding(text))
	if err != nil {
		return "", err
	}

	if (len(decodedMsg) % aes.BlockSize) != 0 {
		return "", errors.New("blocksize must be multipe of decoded message length")
	}

	msg := decodedMsg

	cbc := cipher.NewCBCDecrypter(block, make([]byte, aes.BlockSize))
	cbc.CryptBlocks(msg, msg)

	unpadMsg, err := RemovePadding(msg)
	if err != nil {
		return "", err
	}

	return string(unpadMsg), nil
}

func RemovePadding(src []byte) ([]byte, error) {
	length := len(src)
	unpadding := int(src[length-1])

	if unpadding > length {
		return nil, errors.New("unpad error. This could happen when incorrect encryption key is used")
	}

	return src[:(length - unpadding)], nil
}

func addBase64Padding(value string) string {
	m := len(value) % 4
	if m != 0 {
		value += strings.Repeat("=", 4-m)
	}

	return value
}
