module Crypto.Cipher.Block.Rijndael.Utils where

import Data.Bits hiding (rotate)
import qualified Data.ByteString as B
import qualified Data.Map as Map
import Data.Maybe
import Data.Word

rotate :: Int -> B.ByteString -> B.ByteString
rotate 0 x = x
rotate n x | n > 0 = rotate (n-1) $ B.snoc (B.tail x) (B.head x)
           | n < 0 = rotate (n+1) $ B.cons (B.last x) (B.init x)

rfAdd :: Word8 -> Word8 -> Word8
rfAdd = xor

rfSub :: Word8 -> Word8 -> Word8
rfSub = xor

rfMul :: Word8 -> Word8 -> Word8
rfMul 0 _ = 0
rfMul _ 0 = 0
rfMul a b = foldl1 xor $ map snd $ filter fst $ zip (g b) $ iterate f a
    where
    f x = let s = shiftL x 1 in if testBit x 7 then xor s 0x1b else s
    g x = map (testBit x) [0..7]


rfDiv :: Word8 -> Word8 -> Word8
rfDiv a b = rfMul a $ rfInv b

rfExp :: Word8 -> Word8 -> Word8
rfExp b e = iterate (rfMul b) 1 !! fromIntegral e

rfInv :: Word8 -> Word8
rfInv 0 = 0
rfInv x = rfExp x 254

sboxCalc :: Word8 -> Word8
sboxCalc a = rfAdd 0x63 $ foldl1 rfAdd $ take 5 $ iterate f (rfInv a)
    where
    f x = let r = rotateL x 1
          in if testBit x 7 then setBit r 0 else clearBit r 0

sboxMap :: Map.Map Word8 Word8
sboxMap = Map.fromList [(x, sboxCalc x) | x <- [minBound..maxBound]]

unsboxMap :: Map.Map Word8 Word8
unsboxMap = Map.fromList [(sboxCalc x, x) | x <- [minBound..maxBound]]

sbox :: Word8 -> Word8
sbox a = fromJust $ Map.lookup a sboxMap

unsbox :: Word8 -> Word8
unsbox a = fromJust $ Map.lookup a unsboxMap

chop :: Int -> B.ByteString -> [B.ByteString]
chop n x | B.null x    = []
         | otherwise = B.take n x : chop n (B.drop n x)

rcon :: Word8 -> Word8
rcon 0 = rfInv 2
rcon x = rfExp 2 (x-1)
