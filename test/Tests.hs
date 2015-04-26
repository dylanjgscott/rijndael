module Main where

import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as C
import qualified Data.ByteString.Base16 as B16
import Test.Framework
import Test.Framework.Providers.HUnit
import Test.HUnit

import Rijndael

unhex :: String -> B.ByteString
unhex = fst . B16.decode . C.pack

test1 = TestCase $ assertEqual "AES 128 Encrypt" e o
    where
    i = unhex "00112233445566778899aabbccddeeff"
    k = unhex "000102030405060708090a0b0c0d0e0f"
    e = unhex "69c4e0d86a7b0430d8cdb78070b4c55a"
    o = encryptBlock128 k i

test2 = TestCase $ assertEqual "AES 128 Decrypt" e o
    where
    i = unhex "69c4e0d86a7b0430d8cdb78070b4c55a"
    k = unhex "000102030405060708090a0b0c0d0e0f"
    e = unhex "00112233445566778899aabbccddeeff"
    o = decryptBlock128 k i

tests = hUnitTestToTests $ TestList
    [
        TestLabel "AES 128 Encrypt" test1,
        TestLabel "AES 128 Decrypt" test2
    ]

main = defaultMain tests
