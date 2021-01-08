//+build ingore

package main

import (
	"fmt"
	"github.com/meshplus/crypto-gm/internal/sm2"
	"os"
	"strconv"
)

func main() {
	preComputed := sm2.InitTable()
	file, err := os.OpenFile("./sm2/precomputed.h", os.O_TRUNC|os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		fmt.Println(err)
	}
	defer file.Close()
	for i := 0; i < 43; i++ {
		for j := 0; j < 32*8; j++ {
			num := (i*256 + j) * 8
			s := fmt.Sprintf("DATA ·precomputed<>+0x%s(SB)/8, $0x%s\n",
				strconv.FormatInt(int64(num), 16), strconv.FormatUint(preComputed[i][j], 16))
			_, err := file.WriteString(s)
			if err != nil {
				fmt.Println(err)
			}
		}
	}
	file.WriteString("GLOBL ·precomputed<>(SB), RODATA, $" + strconv.FormatInt(int64(43*32*8*8), 10) + "\n")
}
