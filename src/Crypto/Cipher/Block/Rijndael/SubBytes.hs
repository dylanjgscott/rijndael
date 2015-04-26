module Crypto.Cipher.Block.Rijndael.SubBytes where

import qualified Data.ByteString as B

import Crypto.Cipher.Block.Rijndael.Utils

subBytes :: B.ByteString -> B.ByteString
subBytes = B.map sbox

unsubBytes :: B.ByteString -> B.ByteString
unsubBytes = B.map unsbox
