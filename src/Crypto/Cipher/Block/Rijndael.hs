module Crypto.Cipher.Block.Rijndael where

import qualified Data.ByteString as B

import Crypto.Cipher
import Crypto.Cipher.Block
import Crypto.Cipher.Block.Rijndael.AddRoundKey
import Crypto.Cipher.Block.Rijndael.KeyExpansion
import Crypto.Cipher.Block.Rijndael.MixColumns
import Crypto.Cipher.Block.Rijndael.ShiftRows
import Crypto.Cipher.Block.Rijndael.SubBytes
import Crypto.Cipher.Block.Rijndael.Utils
import Prelude hiding (round)

initialRound :: B.ByteString -> B.ByteString -> B.ByteString
initialRound k pt = addRoundKey k pt

uninitialRound :: B.ByteString -> B.ByteString -> B.ByteString
uninitialRound k pt = addRoundKey k pt

round :: B.ByteString -> B.ByteString -> B.ByteString
round k x = addRoundKey k $ mixColumns $ shiftRows $ subBytes x

unround :: B.ByteString -> B.ByteString -> B.ByteString
unround k x = unsubBytes $ unshiftRows $ unmixColumns $ addRoundKey k x

finalRound :: B.ByteString -> B.ByteString -> B.ByteString
finalRound k x = addRoundKey k $ shiftRows $ subBytes x

unfinalRound :: B.ByteString -> B.ByteString -> B.ByteString
unfinalRound k x = unsubBytes $ unshiftRows $ addRoundKey k x

encrypt128 :: B.ByteString -> B.ByteString -> B.ByteString
encrypt128 k pt = finalRound finalKey $ foldl (flip round) (initialRound initialKey pt) roundKeys
    where
    expandedKeys = keys128 k
    initialKey = head $ expandedKeys
    roundKeys = init $ tail $ expandedKeys
    finalKey = last expandedKeys

decrypt128 :: B.ByteString -> B.ByteString -> B.ByteString
decrypt128 k pt = uninitialRound k $ foldl (flip unround) (unfinalRound finalKey pt) roundKeys
    where
    expandedKeys = reverse $ keys128 k
    initialKey = last $ expandedKeys
    roundKeys = init $ tail $ expandedKeys
    finalKey = head expandedKeys

newtype Rijndael128 = Rijndael128 B.ByteString

instance Cipher Rijndael128 where
    cipherKeySize _ = 16
    cipherInit k = Rijndael128 k

instance BlockCipher Rijndael128 where
    blockSize _ = 16
    encrypt (Rijndael128 k) = encrypt128 k
    decrypt (Rijndael128 k) = decrypt128 k
