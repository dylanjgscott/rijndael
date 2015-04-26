module Crypto.Cipher.Block.Rijndael.MixColumns where

import qualified Data.ByteString as B
import Data.Word

import Crypto.Cipher.Block.Rijndael.Utils

matrixMul :: B.ByteString -> B.ByteString -> Word8
matrixMul x y = foldl1 rfAdd $ B.zipWith rfMul x y

matrixGen :: [Word8] -> [B.ByteString]
matrixGen x = map (uncurry rotate) $ zip [0,-1..] $ replicate 4 $ B.pack x

mixBy :: [B.ByteString] -> B.ByteString -> B.ByteString
mixBy m x = B.concat $ map f $ chop 4 x
    where
    f x = B.pack $ map (uncurry matrixMul) $ zip m $ replicate 4 x

mixColumns :: B.ByteString -> B.ByteString
mixColumns = mixBy m
    where
    m = matrixGen [2,3,1,1]

unmixColumns :: B.ByteString -> B.ByteString
unmixColumns = mixBy m
    where
    m = matrixGen [14,11,13,9]
