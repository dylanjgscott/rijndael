module Rijndael where

import qualified Data.ByteString as B

import Rijndael.KeyExpansion
import Rijndael.AddRoundKey
import Rijndael.MixColumns
import Rijndael.ShiftRows
import Rijndael.SubBytes
import Rijndael.Utils

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

encryptBlock128 :: B.ByteString -> B.ByteString -> B.ByteString
encryptBlock128 k pt = finalRound finalKey $ foldl (flip Rijndael.round) (initialRound initialKey pt) roundKeys
    where
    expandedKeys = keys128 k
    initialKey = head $ expandedKeys
    roundKeys = init $ tail $ expandedKeys
    finalKey = last expandedKeys

decryptBlock128 :: B.ByteString -> B.ByteString -> B.ByteString
decryptBlock128 k pt = uninitialRound k $ foldl (flip Rijndael.unround) (unfinalRound finalKey pt) roundKeys
    where
    expandedKeys = reverse $ keys128 k
    initialKey = last $ expandedKeys
    roundKeys = init $ tail $ expandedKeys
    finalKey = head expandedKeys

encrypt128 :: B.ByteString -> B.ByteString -> B.ByteString
encrypt128 k pt = B.concat $ map (encryptBlock128 k) $ chop 16 pt

decrypt128 :: B.ByteString -> B.ByteString -> B.ByteString
decrypt128 k pt = B.concat $ map (decryptBlock128 k) $ chop 16 pt
