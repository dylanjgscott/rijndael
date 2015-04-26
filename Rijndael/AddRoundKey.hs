module Rijndael.AddRoundKey where

import Data.Bits
import qualified Data.ByteString as B

addRoundKey :: B.ByteString -> B.ByteString -> B.ByteString
addRoundKey k x = B.pack $ B.zipWith xor k x
