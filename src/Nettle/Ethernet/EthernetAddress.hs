{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE MagicHash #-}
module Nettle.Ethernet.EthernetAddress ( 
  -- * Ethernet address
  EthernetAddress (..)
  , ethernetAddress
  , ethernetAddress64
  , unpack
  , isReserved
  , broadcastAddress
  ) where

import Data.Word
import Data.Bits
import Data.Binary
import Numeric (showHex)
import Data.List (intersperse)
import Data.Binary.Get
import Data.Binary.Put
import Data.Binary
import Data.Generics
import GHC.Base
import GHC.Word


-- | An Ethernet address consists of 6 bytes. It is stored in a single 64-bit value.
newtype EthernetAddress = EthernetAddress { unpackEth64 :: Word64 }
                        deriving (Read,Eq,Ord, Data, Typeable)

instance Show EthernetAddress where
  show eth = concat $
    intersperse ":" (map (\n -> showHex n "") [w0,w1,w2,w3,w4,w5])
      where (w0,w1,w2,w3,w4,w5) = unpack   eth
                                
-- | Builds an ethernet address from a Word64 value. 
-- The two most significant bytes are irrelevant; only the bottom 6 bytes are used.
ethernetAddress64 :: Word64 -> EthernetAddress
ethernetAddress64 w64 = EthernetAddress (w64 `mod` 0x01000000000000)
{-# INLINE ethernetAddress64 #-}

ethernetAddress :: Word8 -> Word8 -> Word8 -> Word8 -> Word8 -> Word8 -> EthernetAddress                                
ethernetAddress w1 w2 w3 w4 w5 w6  
  = let w64 = (shiftL (fromIntegral w1) 40) .|.
              (shiftL (fromIntegral w2) 32) .|.
              (shiftL (fromIntegral w3) 24) .|.                       
              (shiftL (fromIntegral w4) 16) .|.                                              
              (shiftL (fromIntegral w5)  8) .|.                                              
              (fromIntegral w6)
    in EthernetAddress w64
                                
unpack :: EthernetAddress -> (Word8,Word8,Word8,Word8,Word8,Word8)
unpack (EthernetAddress w64) = 
  let a1 = fromIntegral (shiftR w64 40)
      a2 = fromIntegral (shiftR w64 32 `mod` 0x0100)
      a3 = fromIntegral (shiftR w64 24 `mod` 0x0100)
      a4 = fromIntegral (shiftR w64 16 `mod` 0x0100)
      a5 = fromIntegral (shiftR w64 8 `mod` 0x0100)
      a6 = fromIntegral (w64 `mod` 0x0100)
  in (a1,a2,a3,a4,a5,a6)
{-# INLINE unpack #-}

isReserved :: EthernetAddress -> Bool
isReserved e = 
  let (a1, a2, a3, a4, a5, a6) = unpack e
  in 
    a1 == 0x01 && 
    a2 == 0x80 && 
    a3 == 0xc2 && 
    a4 == 0 && 
    ((a5 .&. 0xf0) == 0)

broadcastAddress :: EthernetAddress
broadcastAddress = EthernetAddress 0xffffffffffff

instance Binary EthernetAddress where

  get = do
    w32 <- getWord32be
    w16 <- getWord16be
    let w64 = (fromIntegral w32 `shiftL` 16) .|. fromIntegral w16
    return (EthernetAddress w64)

  put (EthernetAddress w64) = do
    putWord32be (fromIntegral (shiftR w64 16))
    putWord16be (fromIntegral (w64 `mod` 0x010000))