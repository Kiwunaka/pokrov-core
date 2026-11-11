package transport

func EncodeBatch(pkts [][]byte) []byte { return encodeBatch(pkts) }

func DecodeBatch(data []byte) ([][]byte, error) { return decodeBatch(data) }

func IsBatchFrame(data []byte) bool {
	return len(data) >= 2 && data[0] == batchFormatVersion
}

func compress(data []byte) []byte { return Compress(data) }

func decompress(data []byte) ([]byte, error) { return Decompress(data) }
