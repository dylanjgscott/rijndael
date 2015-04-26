module Rijndael.KeyExpansion where

import Data.Bits
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as C
import Data.Word

import Rijndael.Utils

scheduleCore :: Word8 -> B.ByteString -> B.ByteString
scheduleCore i k = f $ B.map sbox $ Rijndael.Utils.rotate 1 $ k
    where
    f x = B.cons (rfAdd (rcon i) (B.head x)) (B.tail x)

addRoundKey128 :: [B.ByteString] -> [B.ByteString]
addRoundKey128 ks = ks ++ [foldl1 B.append [a,b,c,d]]
    where
    i = fromIntegral $ length ks
    a = B.pack $ B.zipWith xor (wn 0) $ scheduleCore i (wn 3)
    b = B.pack $ B.zipWith xor a (wn 1)
    c = B.pack $ B.zipWith xor b (wn 2)
    d = B.pack $ B.zipWith xor c (wn 3)
    wn n = ws lastKey !! n
    ws x = B.take 4 x : ws (B.drop 4 x)
    lastKey = last ks

keys128 :: B.ByteString -> [B.ByteString]
keys128 k = iterate addRoundKey128 [k] !! 10
