module Rijndael.ShiftRows where

import qualified Data.ByteString as B

import Rijndael.Utils

shiftRows :: B.ByteString -> B.ByteString
shiftRows x = B.concat $ B.transpose $ map (uncurry rotate) $ zip [0..] $ B.transpose $ chop 4 x

unshiftRows :: B.ByteString -> B.ByteString
unshiftRows x = B.concat $ B.transpose $  map (uncurry rotate) $ zip [0,-1..] $ B.transpose $ chop 4 x
